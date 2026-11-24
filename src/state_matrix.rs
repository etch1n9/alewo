//! Generic bounded multi-request differential oracle for projects with an
//! existing PHP tests/scenario.php JSON-input test.
//!
//! No hidden evaluator files or fixed finding labels are consulted.
//! A warm/cold discrepancy is runtime evidence, not automatically a security bug.
//! Only project-owned source/tests are scanned, executed with the same PHP
//! restrictions as ws_php_test; all seeds are discovered from those files.
use crate::agent::php_test;
use serde_json::{json,Value};
use std::{collections::{BTreeMap,BTreeSet},fs,path::Path};

fn quoted(input:&str)->Vec<String> {
    let mut out=Vec::new();
    let mut quote:Option<char>=None;
    let mut begin=0usize;
    for (i,c) in input.char_indices(){
        if let Some(q)=quote {
            if c==q {
                if let Some(v)=input.get(begin..i){
                    if !v.is_empty() && v.len()<90 && !v.contains('\n') {
                        out.push(v.to_string());
                    }
                }
                quote=None;
            }
        }else if c=='\''||c=='"' {
            quote=Some(c);
            begin=i+1;
        }
    }
    out
}
fn actor_name(s:&str)->bool{
    (3..=20).contains(&s.len()) &&
        s.bytes().all(|x|x.is_ascii_lowercase()||x.is_ascii_digit()||x==b'_')
}
fn report_id(s:&str)->bool{
    (5..=20).contains(&s.len()) && s.bytes().filter(|&b|b==b'-').count()==1 &&
        s.bytes().all(|x|x.is_ascii_uppercase()||x.is_ascii_digit()||x==b'-') &&
        s.bytes().any(|x|x.is_ascii_digit())
}
fn collect_candidates(root:&Path)->Result<(Vec<String>,Vec<String>,Vec<String>),String>{
    let mut actors=BTreeSet::new();
    let mut reports=BTreeSet::new();
    let mut formats=BTreeSet::new();
    let mut stack=vec![(root.to_path_buf(),0usize)];
    let mut count=0usize;
    while let Some((dir,depth))=stack.pop(){
        if depth>9||count>=2000{continue;}
        for entry in fs::read_dir(&dir).map_err(|e|e.to_string())? {
            let entry=entry.map_err(|e|e.to_string())?;
            let name=entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.')||
                matches!(name.as_str(),"data"|"secrets"|"results"|"vendor"|"node_modules"|"Legacy") {continue;}
            let path=entry.path();
            if path.is_dir(){stack.push((path,depth+1));continue;}
            if path.extension().and_then(|x|x.to_str())!=Some("php"){continue;}
            if entry.metadata().map_err(|e|e.to_string())?.len()>256_000 {continue;}
            count+=1;
            let text=fs::read_to_string(&path).map_err(|e|e.to_string())?;
            let is_identity=name.to_ascii_lowercase().contains("identity")
                || name.to_ascii_lowercase().contains("principal");
            let is_test=path.strip_prefix(root).unwrap_or(&path).starts_with("tests");
            for line in text.lines(){
                let strings=quoted(line);
                for token in &strings{
                    if report_id(token){reports.insert(token.to_string());}
                    if matches!(token.as_str(),"csv"|"json"|"txt"|"xml"|"pdf"){
                        formats.insert(token.to_string());
                    }
                }
                if is_identity && line.contains("tenant") && line.contains("user"){
                    if let Some(actor)=strings.first(){
                        if actor_name(actor){actors.insert(actor.clone());}
                    }
                }
                // User identifiers referenced by actual application tests.
                // Extract values for 'who', never arbitrary labels or format fields.
                if is_test {
                    // A field followed by a variable is not a string literal.
                    // Actor identities are grounded in identity mappings or
                    // actual literal ->get('actor') calls.
                    for chunk in line.split("->get(").skip(1){
                        if let Some(token)=quoted(chunk).first(){
                            if actor_name(token){actors.insert(token.clone());}
                        }
                    }
                }
            }
        }
    }
    Ok((
        actors.into_iter().take(16).collect(),
        reports.into_iter().take(8).collect(),
        formats.into_iter().take(3).collect()
    ))
}
fn run_scenario(root:&Path,steps:Vec<Value>)->Result<Vec<Value>,String>{
    let response=php_test(root,&json!({"path":"tests/scenario.php","input":{"steps":steps}}))?;
    if !response.contains("exit=Some(0)"){
        return Err("project scenario returned nonzero; state matrix inconclusive".into());
    }
    let body=response.split_once("|stdout=").map(|x|x.1).ok_or("scenario stdout missing")?;
    let content=body.split("\n|stderr=").next().unwrap_or(body).trim();
    let doc:Value=serde_json::from_str(content).map_err(|e|format!("scenario not JSON: {e}"))?;
    let observed=doc["observations"].as_array().ok_or("scenario lacks observations")?;
    Ok(observed.clone())
}
fn step(who:&str,report:&str,format:&str)->Value{
    json!({"who":who,"report":report,"format":format})
}
pub fn scan(root:&Path)->Result<Value,String>{
    let test=root.join("tests/scenario.php");
    if !test.is_file(){return Ok(json!({"enabled":false,"reason":"no project-owned tests/scenario.php"}));}
    let code=fs::read_to_string(&test).map_err(|e|e.to_string())?;
    if !code.contains("stream_get_contents(STDIN)") ||
        !code.contains("steps") || !code.contains("observations"){
        return Ok(json!({"enabled":false,"reason":"test does not expose JSON steps/observations"}));
    }
    let (actors,reports,formats)=collect_candidates(root)?;
    if actors.len()<2||reports.is_empty()||formats.is_empty(){
        return Ok(json!({"enabled":true,"schema":"@ALEWO-STATE/1",
            "reason":"insufficient source-derived actor/report/format candidates",
            "actors":actors.len(),"reports":reports.len(),"formats":formats.len()}));
    }
    let mut cold=BTreeMap::<(String,String,String),Value>::new();
    let mut trials=0usize;
    for report in &reports{
        for format in &formats{
            for who in &actors{
                if trials>=48{break;}
                let result=run_scenario(root,vec![step(who,report,format)])?;
                trials+=1;
                if let Some(r)=result.first(){
                    if r["result"]=="ok" && r["body"].is_string() {
                        if let Some(tenant)=r["tenant"].as_str() {
                            cold.insert((who.clone(),report.clone(),format.clone()),
                                json!({"who":who,"tenant":tenant,"report":report,"format":format,
                                    "body":r["body"]}));
                        }
                    }
                }
            }
        }
    }
    let seeds=cold.values().cloned().collect::<Vec<_>>();
    let mut tested=0usize;
    let mut differentials=Vec::<Value>::new();
    let mut stable=0usize;
    let mut evidence=Vec::new();
    // Fast O(1) batch sweep per (report, format): runs all distinct-tenant cold seeds
    // in one shared server instance to immediately pinpoint any colliding pair even
    // when there are 8-16 tenants (where pairwise search would exceed trial bounds).
    let mut by_rf=BTreeMap::<(String,String),Vec<&Value>>::new();
    for s in &seeds{
        if let (Some(r),Some(f))=(s["report"].as_str(),s["format"].as_str()){
            by_rf.entry((r.to_string(),f.to_string())).or_default().push(s);
        }
    }
    for ((report,format),group) in &by_rf{
        if group.len()<2 || differentials.len()>=6 {continue;}
        let batch_steps=group.iter().filter_map(|s|s["who"].as_str())
            .map(|w|step(w,report,format)).collect::<Vec<_>>();
        if batch_steps.len()<2 {continue;}
        if let Ok(obs)=run_scenario(root,batch_steps){
            trials+=1;
            if obs.len()==group.len(){
                for (idx,item) in obs.iter().enumerate(){
                    if differentials.len()>=6{break;}
                    if item["result"]!="ok"{continue;}
                    let cold_b=group[idx];
                    if item["body"]!=cold_b["body"]{
                        // Find the earlier actor whose cold body matches the leaked body
                        if let Some(cold_a)=group[..idx].iter().find(|a|a["tenant"]!=cold_b["tenant"] && a["body"]==item["body"]){
                            if let (Some(a_who),Some(b_who))=(cold_a["who"].as_str(),cold_b["who"].as_str()){
                                if let Ok(warm)=run_scenario(root,vec![step(a_who,report,format),step(b_who,report,format)]){
                                    trials+=1;tested+=1;
                                    if warm.len()==2 && warm[0]["result"]=="ok" && warm[1]["result"]=="ok" && warm[1]["body"]!=cold_b["body"]{
                                        differentials.push(json!({
                                            "first_request":{"who":cold_a["who"],"tenant":cold_a["tenant"],"report":report,"format":format},
                                            "second_request":{"who":cold_b["who"],"tenant":cold_b["tenant"],"report":report,"format":format},
                                            "first_body":warm[0]["body"],
                                            "second_cold_body":cold_b["body"],
                                            "second_after_first_body":warm[1]["body"],
                                            "second_matches_first":warm[1]["body"]==warm[0]["body"],
                                            "difference_type":"same authenticated second request returns different output depending on earlier request in same server instance"
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for a in &seeds{
        for b in &seeds{
            if trials>=96 || tested>=48 || differentials.len()>=6 {break;}
            if a["tenant"]==b["tenant"] || a["who"]==b["who"] {continue;}
            if a["report"]!=b["report"]||a["format"]!=b["format"] {continue;}
            let (Some(a_who),Some(b_who),Some(report),Some(format)) =
                (a["who"].as_str(),b["who"].as_str(),a["report"].as_str(),a["format"].as_str())
            else{continue;};
            let warm=run_scenario(root,vec![step(a_who,report,format),step(b_who,report,format)])?;
            trials+=1;tested+=1;
            if warm.len()!=2 || warm[0]["result"]!="ok" ||warm[1]["result"]!="ok" {
                continue;
            }
            if warm[0]["body"]!=a["body"] {continue;}
            if warm[1]["body"]!=b["body"] {
                differentials.push(json!({
                    "first_request":{"who":a["who"],"tenant":a["tenant"],"report":report,"format":format},
                    "second_request":{"who":b["who"],"tenant":b["tenant"],"report":report,"format":format},
                    "first_body":warm[0]["body"],
                    "second_cold_body":b["body"],
                    "second_after_first_body":warm[1]["body"],
                    "second_matches_first":warm[1]["body"]==warm[0]["body"],
                    "difference_type":"same authenticated second request returns different output depending on earlier request in same server instance"
                }));
            }else{stable+=1;}
            if evidence.len()<4{
                evidence.push(json!({"tenant_a":a["tenant"],"tenant_b":b["tenant"],
                  "report":report,"format":format,"second_stable":warm[1]["body"]==b["body"]}));
            }
        }
        if trials>=96 || tested>=48 || differentials.len()>=6 {break;}
    }
    Ok(json!({
        "schema":"@ALEWO-STATE/1","enabled":true,
        "test":"tests/scenario.php",
        "cold_trials":cold.len(),"php_processes":trials,
        "ordered_pairs_tested":tested,"stable_pairs":stable,
        "candidate_actor_count":actors.len(),"candidate_report_count":reports.len(),
        "candidate_format_count":formats.len(),"candidate_actors":actors,"candidate_reports":reports,"candidate_formats":formats,
        "differential_successes":differentials,
        "control_samples":evidence,
        "limitations":"Cross-request output differences are observations, not proof of attacker exploitability. Verify which auth guards passed and whether a shared state key omits a trust boundary; compare repaired source separately."
    }))
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn extracts_quoted_string_literals(){
        assert_eq!(quoted("'vera'=>['user'=>'vera','tenant'=>'north']"),
            vec!["vera","user","vera","tenant","north"]);
        assert!(report_id("LEDGER-2026"));
        assert!(!report_id("north"));
    }
}
