//! Generic, bounded local PHP path-boundary mutation testing.
 //! All seeds and expected responses originate from source-visible project PHP
 //! files and tests. Does not read benchmark ground truth, external secrets,
 //! or invoke a second model.
use serde_json::{json,Value};
use std::{collections::BTreeSet,fs,path::Path};
use crate::agent::php_test;

fn plausible_path(v:&str)->bool{
    if v.len()<8||v.len()>140||v.starts_with('/')||v.contains("..")||v.contains(".php")||v.contains('%'){return false;}
    let parts=v.split('/').collect::<Vec<_>>();
    if parts.len()<3||parts.len()>7{return false;}
    parts.into_iter().all(|part|!part.is_empty() &&
        part.chars().all(|c|c.is_ascii_alphanumeric()||c=='_'||c=='-'))
}
fn collect_source_seeds(root:&Path)->Result<Vec<String>,String>{
    let mut paths=BTreeSet::new();
    let mut dirs=vec![(root.to_path_buf(),0usize)];
    let mut files=0usize;
    while let Some((dir,depth))=dirs.pop(){
        if depth>7||files>=150{continue;}
        let mut entries=fs::read_dir(&dir).map_err(|e|e.to_string())?
           .filter_map(Result::ok).collect::<Vec<_>>();
        entries.sort_by_key(|f|f.file_name());
        for e in entries{
            let name=e.file_name().to_string_lossy().to_string();
            if name.starts_with('.')||matches!(name.as_str(),"vendor"|"data"|"results"|"secrets"){continue;}
            let path=e.path();
            if path.is_dir(){if depth<7{dirs.push((path,depth+1));}continue;}
            if path.extension().and_then(|v|v.to_str())!=Some("php"){continue;}
            if e.metadata().map_err(|x|x.to_string())?.len()>256_000{continue;}
            files+=1;
            let text=fs::read_to_string(&path).map_err(|x|x.to_string())?;
            for quoted in text.split(|c| c=='\'' || c=='"'){
                if plausible_path(quoted){paths.insert(quoted.to_string());}
            }
        }
    }
    Ok(paths.into_iter().take(32).collect())
}
fn input_field(test:&str)->Option<String>{
    // The project's own PHP test must opt into accepting JSON via stdin.
    if !test.contains("STDIN")||!test.contains("$provided["){return None;}
    for part in test.split("$provided['").skip(1){
        if let Some(key)=part.split('\'').next(){
            if key.len()<64 && key.chars().all(|c|c.is_ascii_alphanumeric()||c=='_')
                && ["path","key","file","object"].iter().any(|x|key.contains(x)){
                    return Some(key.to_string());
            }
        }
    }
    None
}
fn run_trial(root:&Path,field:&str,candidate:&str)->Result<Value,String>{
    let request=json!({"path":"tests/probe.php","input":{field:candidate}});
    let result=php_test(root,&request)?;
    // The result is raw captured PHP output, not a self-certified exploit.
    Ok(json!({"input":candidate,"test_output":result,
          "returned_success":result.contains("\"ok\":true")}))
}
fn variants(allowed:&str,foreign:&str)->Vec<String>{
    let base=allowed.split('/').collect::<Vec<_>>();
    if base.len()<3{return Vec::new();}
    let prefix=base[..base.len()-1].join("/");
    let ups=base.len()-1;
    let mut out=Vec::new();
    for up in ["..","%2e%2e","%252e%252e",".%2e","%2e.","%252e."," .%252e"]{
        let p=up.trim();
        let candidate=format!("{prefix}/{}/{}",vec![p;ups].join("/"),foreign);
        out.push(candidate);
    }
    // Encoded separators and mixed encoded dot cases broaden families.
    out.push(format!("{prefix}/{}/{}",vec!["%252e%252e";ups].join("%252f"),foreign));
    out.push(format!("{prefix}/{}/{}",vec![".%252e";ups].join("/"),foreign));
    out.push(format!("{prefix}/{}/{}",vec!["%252e.";ups].join("/"),foreign));
    out
}
pub fn scan(root:&Path)->Result<Value,String>{
    let path=root.join("tests/probe.php");
    if !path.is_file(){return Ok(json!({"enabled":false,"reason":"no project-supplied tests/probe.php"}));}
    let code=fs::read_to_string(&path).map_err(|e|e.to_string())?;
    let Some(field)=input_field(&code) else {
        return Ok(json!({"enabled":false,"reason":"no JSON stdin path field declared by project test"}));
    };
    let seeds=collect_source_seeds(root)?;
    let mut observed=Vec::new();
    let mut allowed:Option<String>=None;
    let mut run_count=0usize;
    for seed in &seeds{
        if run_count>=18{break;}
        let result=run_trial(root,&field,seed)?;
        run_count+=1;
        if result["returned_success"]==true{
            allowed=Some(seed.to_string());
            observed.push(json!({"phase":"authorized_seed","trial":result}));
            break;
        }
    }
    let Some(allowed)=allowed else {
        return Ok(json!({"enabled":true,"test":"tests/probe.php","field":field,
            "seeds_discovered":seeds.len(),"runs":run_count,
            "finding":"no authorized baseline seed found; differential tests inconclusive"}));
    };
    let mut bypasses=Vec::new();
    let mut explored=0usize;
    let allowed_parts=allowed.split('/').collect::<Vec<_>>();
    let mut targets=seeds.iter().collect::<Vec<_>>();
    // Favor distinct trust domains before same-domain directories, but inspect
    // both. This ordering is derived from path segments, never benchmark labels.
    targets.sort_by_key(|p| p.split('/').next()==allowed.split('/').next());
    for target in targets{
        if target==&allowed || run_count>=72 || bypasses.len()>=10{continue;}
        // A different directory/prefix is the unauthorized boundary candidate.
        let t=target.split('/').collect::<Vec<_>>();
        if t.len()<3 || t[..t.len()-1]==allowed_parts[..allowed_parts.len()-1]{continue;}
        let baseline=run_trial(root,&field,target)?;
        run_count+=1;
        if baseline["returned_success"]==true{continue;}
        let mut found_for_target=0usize;
        for candidate in variants(&allowed,target){
            if run_count>=72||bypasses.len()>=10||found_for_target>=3{break;}
            let trial=run_trial(root,&field,&candidate)?;
            run_count+=1;
            explored+=1;
            if trial["returned_success"]==true{
                bypasses.push(json!({"authorized_seed":allowed,"direct_target":target,
                    "baseline_target_denied":true,
                    "mutated_trial":trial}));
                found_for_target+=1;
            }
        }
    }
    Ok(json!({"schema":"@ALEWO-DIFF/1","enabled":true,"test":"tests/probe.php",
      "input_field":field,"seeds_discovered":seeds.len(),
      "trials_executed":run_count,"mutation_trials":explored,
      "baseline":observed,"differential_successes":bypasses,
      "limitations":"A differential success is a runtime observation, not automatically a security finding. Inspect ownership, authorization, and source path before claiming impact."}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn decode_variants_present() {
        let v=variants("north/reports/safe","south/reports/private");
        assert!(v.iter().any(|s|s.contains("%252e%252e")));
        assert!(v.iter().any(|s|s.contains("%2e%2e")));
    }
    #[test] fn only_path_literals(){assert!(plausible_path("north/reports/hello"));assert!(!plausible_path("../etc/passwd"));}
}
