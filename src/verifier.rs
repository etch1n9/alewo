//! Transparent finding verifier.
//!
//! Source consistency and runtime exploit verification are deliberately
//! separate. Challenge completion and universal success memory require both a
//! reproduction and a distinct negative control with machine-checked output.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn required_text(args:&Value,key:&str,max:usize)->Result<String,String>{
    let value=args[key].as_str().unwrap_or("").trim();
    if value.is_empty(){return Err(format!("{key} is required"));}
    if value.len()>max{return Err(format!("{key} exceeds {max} bytes"));}
    Ok(value.to_string())
}

fn expectation_schema()->Value{
    json!({"type":"object","properties":{
        "exit":{"type":"integer"},
        "stdout_contains":{"type":"array","items":{"type":"string"}},
        "stdout_not_contains":{"type":"array","items":{"type":"string"}},
        "stderr_contains":{"type":"array","items":{"type":"string"}},
        "stderr_not_contains":{"type":"array","items":{"type":"string"}},
        "json_equals":{"type":"object","description":"Dotted JSON paths mapped to exact expected values, e.g. responses.1.receipt.tenant"}
    }})
}

fn runtime_schema()->Value{
    json!({"type":"object","properties":{
        "adapter":{"type":"string","enum":["php_file","python_file","pytest","node_test","cargo_test","go_test","maven_test","gradle_test","dotnet_test","ruby_file","bash_file","make_test","ctest","native_binary","c_asan_file","cpp_asan_file"]},
        "target":{"type":"string"},"path":{"type":"string"},
        "input":{},"timeout_seconds":{"type":"integer","minimum":1,"maximum":300},
        "expect":expectation_schema()
    },"required":["adapter","target","expect"]})
}

pub fn tool_def()->Value{
    json!({"type":"function","function":{
        "name":"finding_verify",
        "description":"Test exact verbatim source anchors (E2). With runtime adapters, independently execute reproduction and negative control for E3. In read-only repositories without a runtime adapter E2 can close a source candidate, but never implies exploit execution or challenge acceptance.",
        "parameters":{"type":"object","properties":{
            "mode":{"type":"string","enum":["auto","source","runtime"],"description":"source = E2 source anchor consistency; runtime = E3 requires reproduction + independent negative control; auto selects runtime when both specs exist."},
            "invariant":{"type":"string"},
            "impact":{"type":"string"},
            "assumptions":{"type":"array","items":{"type":"string"}},
            "disconfirming_test":{"type":"string"},
            "chain":{"type":"array","minItems":2,"maxItems":12,"items":{
                "type":"object","properties":{
                    "role":{"type":"string","enum":["entry","guard","transform","state","sink","impact"]},
                    "path":{"type":"string"},"line":{"type":"integer","minimum":1},
                    "contains":{"type":"string"}
                },"required":["role","path","line","contains"]
            }},
            "reproduction":runtime_schema(),
            "control":runtime_schema()
        },"required":["invariant","impact","disconfirming_test","chain"]}
    }})
}

fn values<'a>(expect:&'a Value,key:&str)->Vec<&'a str>{
    expect[key].as_array().into_iter().flatten().filter_map(Value::as_str).collect()
}

fn json_line(stdout:&str)->Option<Value>{
    stdout.lines().rev().find_map(|line|{
        let trimmed=line.trim();
        if trimmed.starts_with('{')||trimmed.starts_with('['){
            serde_json::from_str(trimmed).ok()
        }else{None}
    }).or_else(||serde_json::from_str(stdout.trim()).ok())
}

fn lookup<'a>(mut value:&'a Value,path:&str)->Option<&'a Value>{
    for part in path.split('.').filter(|p|!p.is_empty()){
        value=if let Ok(index)=part.parse::<usize>(){
            value.as_array()?.get(index)?
        }else{
            value.as_object()?.get(part)?
        };
    }
    Some(value)
}

fn check_runtime(result:&Value,expect:&Value,label:&str)->Value{
    let stdout=result["stdout"].as_str().unwrap_or("");
    let stderr=result["stderr"].as_str().unwrap_or("");
    let exit=result["exit"].as_i64();
    let mut checks=Vec::new();
    let expected_exit=expect["exit"].as_i64().unwrap_or(0);
    checks.push(json!({"check":"exit","expected":expected_exit,"actual":exit,
        "pass":exit==Some(expected_exit)}));
    let mut semantic=0usize;
    for needle in values(expect,"stdout_contains"){
        semantic+=1;checks.push(json!({"check":"stdout_contains","value":needle,
            "pass":stdout.contains(needle)}));
    }
    for needle in values(expect,"stdout_not_contains"){
        semantic+=1;checks.push(json!({"check":"stdout_not_contains","value":needle,
            "pass":!stdout.contains(needle)}));
    }
    for needle in values(expect,"stderr_contains"){
        semantic+=1;checks.push(json!({"check":"stderr_contains","value":needle,
            "pass":stderr.contains(needle)}));
    }
    for needle in values(expect,"stderr_not_contains"){
        semantic+=1;checks.push(json!({"check":"stderr_not_contains","value":needle,
            "pass":!stderr.contains(needle)}));
    }
    if let Some(expected)=expect["json_equals"].as_object(){
        semantic+=expected.len();
        let parsed=json_line(stdout);
        for (path,want) in expected{
            let actual=parsed.as_ref().and_then(|doc|lookup(doc,path));
            checks.push(json!({"check":"json_equals","path":path,"expected":want,
                "actual":actual,"pass":actual==Some(want)}));
        }
    }
    if semantic==0{
        checks.push(json!({"check":"semantic_assertion_required","pass":false}));
    }
    let passed=result["timed_out"]!=true&&semantic>0&&
        checks.iter().all(|c|c["pass"]==true);
    json!({"label":label,"passed":passed,"semantic_assertions":semantic,
        "checks":checks,"execution":result})
}

pub fn verify(root:&Path,args:&Value)->Result<Value,String>{
    let invariant=required_text(args,"invariant",1200)?;
    let impact=required_text(args,"impact",1600)?;
    let disconfirming=required_text(args,"disconfirming_test",1600)?;
    let chain=args["chain"].as_array().ok_or("chain must be an array")?;
    if !(2..=12).contains(&chain.len()){
        return Err("chain must contain 2..12 exact source anchors".into());
    }
    let mut roles=std::collections::BTreeSet::<String>::new();
    let mut anchors=Vec::new();
    let mut evidence_paths=Vec::new();
    let mut source_failures=Vec::new();
    for (index,step) in chain.iter().enumerate(){
        let role=step["role"].as_str().unwrap_or("").trim();
        let requested=step["path"].as_str().unwrap_or("").trim();
        let line=step["line"].as_u64().unwrap_or(0) as usize;
        let needle=step["contains"].as_str().unwrap_or("");
        if !matches!(role,"entry"|"guard"|"transform"|"state"|"sink"|"impact"){
            source_failures.push(format!("chain[{index}] invalid role"));continue;
        }
        if line==0||needle.trim().len()<3||needle.len()>800{
            source_failures.push(format!("chain[{index}] invalid line/contains"));continue;
        }
        let path=match crate::agent::safe(root,requested){
            Ok(p)=>p,Err(e)=>{source_failures.push(format!("chain[{index}] {e}"));continue;}
        };
        if !path.is_file(){source_failures.push(format!("chain[{index}] not a file"));continue;}
        let source=fs::read_to_string(&path).map_err(|e|e.to_string())?;
        let actual=source.lines().nth(line-1).unwrap_or("");
        let exact=actual.contains(needle);
        if !exact{source_failures.push(format!("chain[{index}] anchor mismatch at {requested}:{line}"));}
        roles.insert(role.to_string());
        evidence_paths.push(requested.to_string());
        anchors.push(json!({"role":role,"path":requested,"line":line,"contains":needle,
            "actual":actual.chars().take(900).collect::<String>(),"matched":exact}));
    }
    let role_complete=roles.contains("entry")&&roles.contains("sink")&&
        (roles.contains("guard")||roles.contains("state")||roles.contains("transform"));
    if !role_complete{
        source_failures.push("chain requires entry + sink + one of guard/state/transform".into());
    }
    let assumptions=args["assumptions"].as_array().map(|a|a.iter()
        .filter_map(Value::as_str).map(|s|s.chars().take(300).collect::<String>())
        .collect::<Vec<_>>()).unwrap_or_default();
    let source_verified=source_failures.is_empty();

    let repro_spec=args.get("reproduction").filter(|v|v.is_object());
    let control_spec=args.get("control").filter(|v|v.is_object());
    let mode=args["mode"].as_str().unwrap_or("auto");
    if !matches!(mode,"auto"|"source"|"runtime") {
        return Err("mode must be auto, source, or runtime".into());
    }
    let adapters_available=!crate::runtime_adapter::discover(root).is_empty();
    let has_runtime_specs=repro_spec.is_some() || control_spec.is_some();
    let attempt_runtime=mode=="runtime" || (mode=="auto" && has_runtime_specs);
    if mode=="source" && has_runtime_specs {
        return Err("source mode does not accept execution specs: choose runtime mode".into());
    }
    let mut runtime_failures=Vec::new();
    let mut reproduction=Value::Null;
    let mut control=Value::Null;
    let mut differential=false;
    if attempt_runtime {
      if let (Some(repro),Some(ctrl))=(repro_spec,control_spec){
        if repro==ctrl{runtime_failures.push("reproduction and control must be distinct".into());}
        let repro_run=crate::runtime_adapter::run(root,repro);
        let control_run=crate::runtime_adapter::run(root,ctrl);
        match repro_run{
            Ok(result)=>reproduction=check_runtime(&result,&repro["expect"],"reproduction"),
            Err(e)=>runtime_failures.push(format!("reproduction failed: {e}"))
        }
        match control_run{
            Ok(result)=>control=check_runtime(&result,&ctrl["expect"],"control"),
            Err(e)=>runtime_failures.push(format!("control failed: {e}"))
        }
        if reproduction.is_object()&&control.is_object(){
            let a=&reproduction["execution"];let b=&control["execution"];
            differential=a["stdout"]!=b["stdout"]||a["stderr"]!=b["stderr"]||a["exit"]!=b["exit"];
            if reproduction["passed"]!=true{runtime_failures.push("reproduction assertions failed".into());}
            if control["passed"]!=true{runtime_failures.push("control assertions failed".into());}
            if !differential{runtime_failures.push("reproduction and control produced no observable differential".into());}
        }
      }else{
        runtime_failures.push("both reproduction and control are required for runtime verification".into());
      }
    }
    let runtime_verified=attempt_runtime && runtime_failures.is_empty();
    let challenge_accepted=source_verified&&runtime_verified;
    let candidate_closable=challenge_accepted ||
        (source_verified && !attempt_runtime && !adapters_available);
    evidence_paths.sort();evidence_paths.dedup();
    let evidence_digest=format!("{:x}",Sha256::digest(
        serde_json::to_vec(&json!({"anchors":anchors,"reproduction":reproduction,
            "control":control})).map_err(|e|e.to_string())?));
    let mut failures=source_failures.clone();failures.extend(runtime_failures.clone());
    Ok(json!({
        "schema":"@ALEWO-VERIFY/2",
        "verified":challenge_accepted,
        "source_verified":source_verified,
        "runtime_verified":runtime_verified,
        "challenge_accepted":challenge_accepted,
        "candidate_closable":candidate_closable,
        "verification_mode":if attempt_runtime{"runtime"}else{"source"},
        "runtime_adapters_available":adapters_available,
        "proof_grade":if challenge_accepted{"E3"}else if source_verified{"E2"}else{"E1"},
        "invariant":invariant,"impact":impact,"assumptions":assumptions,
        "disconfirming_test":disconfirming,
        "roles":roles,"anchors":anchors,"evidence_paths":evidence_paths,
        "evidence_sha256":evidence_digest,
        "runtime":{"reproduction":reproduction,"control":control,"differential":differential},
        "source_failures":source_failures,"runtime_failures":runtime_failures,"failures":failures,
        "oracle":"transparent_repository_only",
        "limitations":"E2 confirms exact source anchors, NOT execution, exploitability, or even semantic correctness of a proposed vulnerability chain. E2 is closable as source_verified only when no runtime adapter is discoverable. E3 requires machine-checked reproduction, negative control, semantic assertions and an observable differential."
    }))
}

#[cfg(test)]
mod tests{
    use super::*;
    use std::time::{SystemTime,UNIX_EPOCH};

    fn temp()->std::path::PathBuf{
        let dir=std::env::temp_dir().join(format!("alewo-verify-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&dir).unwrap();dir
    }

    #[test]
    fn source_chain_alone_cannot_finish_challenge(){
        let dir=temp();
        fs::write(dir.join("x.rs"),"fn entry(){ guard(); sink(); }\nfn guard(){}\nfn sink(){}\n").unwrap();
        let out=verify(&dir,&json!({
            "invariant":"untrusted state must not reach sink","impact":"state change",
            "disconfirming_test":"call guard with a rejected value",
            "chain":[
                {"role":"entry","path":"x.rs","line":1,"contains":"fn entry"},
                {"role":"guard","path":"x.rs","line":2,"contains":"fn guard"},
                {"role":"sink","path":"x.rs","line":3,"contains":"fn sink"}
            ]
        })).unwrap();
        assert_eq!(out["source_verified"],true);
        assert_eq!(out["proof_grade"],"E2");
        assert_eq!(out["challenge_accepted"],false);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn semantic_reproduction_and_control_reach_e3(){
        let dir=temp();fs::create_dir_all(dir.join("tests")).unwrap();
        fs::write(dir.join("app.php"),"<?php\nfunction entry($x){return sink($x);}\nfunction guard($x){return true;}\nfunction sink($x){return $x;}\n").unwrap();
        fs::write(dir.join("tests/scenario.php"),"<?php $i=json_decode(stream_get_contents(STDIN),true); echo json_encode(['tenant'=>($i['mode']==='attack'?'north':'south'),'leak'=>$i['mode']==='attack']).PHP_EOL;").unwrap();
        let base=json!({
            "invariant":"tenant output must remain scoped","impact":"cross tenant disclosure",
            "disconfirming_test":"safe mode returns the south tenant without leak",
            "chain":[
                {"role":"entry","path":"app.php","line":2,"contains":"function entry"},
                {"role":"guard","path":"app.php","line":3,"contains":"function guard"},
                {"role":"sink","path":"app.php","line":4,"contains":"function sink"}
            ],
            "reproduction":{"adapter":"php_file","target":"tests/scenario.php",
                "input":{"mode":"attack"},"expect":{"exit":0,"json_equals":{"tenant":"north","leak":true}}},
            "control":{"adapter":"php_file","target":"tests/scenario.php",
                "input":{"mode":"safe"},"expect":{"exit":0,"json_equals":{"tenant":"south","leak":false}}}
        });
        let out=verify(&dir,&base).unwrap();
        assert_eq!(out["challenge_accepted"],true);
        assert_eq!(out["proof_grade"],"E3");
        assert_eq!(out["runtime"]["differential"],true);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn c_sanitizer_reproduction_and_control_reach_e3(){
        let dir=temp();fs::create_dir_all(dir.join("tests")).unwrap();
        if !crate::runtime_adapter::discover(&dir).contains(&"c_asan_file"){return;}
        fs::write(dir.join("app.c"),
            "int entry(int x){return guard(x)?sink(x):0;}\nint guard(int x){return x>0;}\nint sink(int x){return x;}\n").unwrap();
        fs::write(dir.join("tests/scenario.c"),
            "#include <stdio.h>\n#include <string.h>\nint main(void){char b[256]={0};fread(b,1,255,stdin);int a=strstr(b,\"attack\")!=0;printf(\"{\\\"leak\\\":%s,\\\"tenant\\\":\\\"%s\\\"}\\n\",a?\"true\":\"false\",a?\"north\":\"south\");return 0;}\n").unwrap();
        let out=verify(&dir,&json!({
            "invariant":"tenant output remains scoped","impact":"cross tenant disclosure",
            "disconfirming_test":"safe input returns south without leak",
            "chain":[
                {"role":"entry","path":"app.c","line":1,"contains":"int entry"},
                {"role":"guard","path":"app.c","line":2,"contains":"int guard"},
                {"role":"sink","path":"app.c","line":3,"contains":"int sink"}
            ],
            "reproduction":{"adapter":"c_asan_file","target":"tests/scenario.c",
                "input":{"mode":"attack"},"expect":{"exit":0,"json_equals":{"leak":true,"tenant":"north"}}},
            "control":{"adapter":"c_asan_file","target":"tests/scenario.c",
                "input":{"mode":"safe"},"expect":{"exit":0,"json_equals":{"leak":false,"tenant":"south"}}}
        })).unwrap();
        assert_eq!(out["challenge_accepted"],true);
        assert_eq!(out["proof_grade"],"E3");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn exit_zero_without_semantic_assertions_is_rejected(){
        let dir=temp();fs::create_dir_all(dir.join("tests")).unwrap();
        fs::write(dir.join("x.rs"),"fn entry(){ sink(); }\nfn sink(){}\n").unwrap();
        fs::write(dir.join("tests/ok.php"),"<?php echo 'ok';").unwrap();
        let out=verify(&dir,&json!({
            "invariant":"x","impact":"y","disconfirming_test":"z",
            "chain":[
                {"role":"entry","path":"x.rs","line":1,"contains":"fn entry"},
                {"role":"state","path":"x.rs","line":1,"contains":"sink();"},
                {"role":"sink","path":"x.rs","line":2,"contains":"fn sink"}
            ],
            "reproduction":{"adapter":"php_file","target":"tests/ok.php","input":{"x":1},"expect":{"exit":0}},
            "control":{"adapter":"php_file","target":"tests/ok.php","input":{"x":2},"expect":{"exit":0}}
        })).unwrap();
        assert_eq!(out["challenge_accepted"],false);
        fs::remove_dir_all(dir).unwrap();
    }
}
