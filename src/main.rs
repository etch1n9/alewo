#![recursion_limit="256"]
mod memory;
mod provider;
mod php_ir;
mod agent;
mod chat;
mod source_guard;
mod grounding;
mod flow_index;
mod reachability;
mod path_matrix;
mod state_matrix;
mod tools_ext;
mod polyglot_ast;
mod skeleton;
mod cognitive_vm;
mod learning;
mod config;
mod protocol;
mod controller;
mod reasoning;
mod verifier;
mod runtime_adapter;
mod peer;

use std::{env,fs,path::{Path,PathBuf}};
use serde_json::{json,Value};
use memory::{Episode,Vault};
use provider::{Mode,Arm,Run};

fn arg(args:&[String],key:&str)->Option<String>{
    args.windows(2).find(|pair|pair[0]==key).map(|p|p[1].clone())
}
fn require(args:&[String],key:&str)->Result<String,String>{
    arg(args,key).ok_or(format!("required {key}"))
}
fn int_arg(args:&[String],key:&str,default:usize)->Result<usize,String>{
    arg(args,key).map(|v|v.parse::<usize>().map_err(|_|format!("invalid {key}")))
        .unwrap_or(Ok(default))
}
fn root()->PathBuf{PathBuf::from(env!("CARGO_MANIFEST_DIR"))}
fn dbpath()->PathBuf{
    env::var("ALEWO_DB").map(PathBuf::from)
        .unwrap_or_else(|_|root().join("data/memory.sqlite"))
}
fn json_out(v:&Value){
    println!("{}",serde_json::to_string_pretty(v).unwrap_or_else(|_|v.to_string()));
}
fn memory_cmd(args:&[String])->Result<(),String>{
    if args.is_empty(){return Err("usage: alewo memory add|search|inspect|trace|explain|effect|approve|resolve|revoke|prune|stats".into());}
    let mut db=Vault::open(&dbpath())?;
    match args[0].as_str(){
        "add"=>{
            let file=require(args,"--file")?;
            let data=fs::read(file).map_err(|e|e.to_string())?;
            let event:Episode=serde_json::from_slice(&data).map_err(|e|e.to_string())?;
            let (id,state)=db.add(&event)?;
            json_out(&json!({"id":id,"state":state,"auto_injected":false}));
        }
        "search"=>{
            let q=require(args,"--query")?;
            let scope=arg(args,"--scope").unwrap_or_else(||"default".into());
            json_out(&db.search(&scope,&q,int_arg(args,"--limit",4)?,
                int_arg(args,"--max-chars",1100)?)?);
        }
        "inspect"=>json_out(&db.inspect(&require(args,"--id")?)?),
        "trace"=>json_out(&db.trace(&require(args,"--id")?)?),
        "explain"=>json_out(&db.explain(&require(args,"--id")?)?),
        "effect"=>{
            let id=require(args,"--id")?;
            let applied=int_arg(args,"--applied",0)? as i64;
            let success=int_arg(args,"--success",0)? as i64;
            let failure=int_arg(args,"--failure",0)? as i64;
            let false_lead=int_arg(args,"--false-lead",0)? as i64;
            let coverage=int_arg(args,"--coverage",0)? as i64;
            json_out(&db.record_effect(&id,applied,success,failure,false_lead,coverage)?);
        },
        "approve"=>{
            let id=require(args,"--id")?;
            json_out(&json!({"id":id,"status":db.approve(&id)?}));
        }
        "resolve"=>{
            let id=require(args,"--id")?;
            json_out(&json!({"id":id,"status":db.resolve(&id)?}));
        }
        "revoke"=>{
            let id=require(args,"--id")?;
            json_out(&json!({"id":id,"status":db.revoke(&id)?}));
        }
        "prune"=>json_out(&json!({"expired_deleted":db.purge_expired()?})),
        "feedback"=>{
            let scope=arg(args,"--scope").unwrap_or_else(||"default".into());
            let task=require(args,"--task")?;
            let answer=require(args,"--answer")?;
            let reply=require(args,"--reply")?;
            let ev=arg(args,"--evidence").map(PathBuf::from);
            let mdl=arg(args,"--model").unwrap_or_default();
            json_out(&learning::record_feedback_with_ai(&root(),&mdl,&dbpath(),&scope,&task,&answer,&reply,ev.as_deref())?);
        }
        "stats"=>json_out(&db.stats()?),
        other=>return Err(format!("unknown memory operation {other}"))
    }
    Ok(())
}
fn run_cmd(args:&[String],eval:bool)->Result<(),String>{
    let file=arg(args,"--file");
    let inline=arg(args,"--task");
    if file.is_some()==inline.is_some(){
        return Err("provide exactly one of --file <path> or --task <text>".into());
    }
    if eval && file.is_none(){
        return Err("sealed eval requires exactly one local PHP case via --file".into());
    }
    if eval && file.as_ref().and_then(|x|std::path::Path::new(x).extension())
        .and_then(|x|x.to_str())!=Some("php"){
        return Err("sealed PHP eval only accepts .php fixtures".into());
    }
    let task=if let Some(path)=file {fs::read_to_string(path).map_err(|e|e.to_string())?}
        else {inline.ok_or("missing inline task")?};
    let m=arg(args,"--mode").unwrap_or_else(||"blind".into());
    let mode=match m.as_str(){
        "blind"=>Mode::Blind,"agent"=>Mode::Agent,
        _=>return Err("mode must be blind or agent".into())
    };
    if eval && mode!=Mode::Blind {
        return Err("eval is always blind; --mode agent is forbidden".into());
    }
    if mode==Mode::Agent && arg(args,"--scope").is_none() {
        return Err("one-shot operational agent with memory requires explicit --scope; blind eval never uses memory".into());
    }
    let arm=match arg(args,"--arm").unwrap_or_else(||"native".into()).as_str(){
        "native"=>Arm::Native,"alewo"=>Arm::Alewo,
        _=>return Err("arm must be native or alewo".into())
    };
    let run=Run{
        task,mode,arm,audit_php:eval,raw_blind:false,stream_blind:false,
        scope:arg(args,"--scope").unwrap_or_else(||"default".into()),
        model:arg(args,"--model").unwrap_or_default(),
        output_dir:root().join("data/sessions"),
        workspace:root(),
        db_path:dbpath()
    };
    if eval {
        eprintln!("SEALED BLIND EVAL: one new API session, no memory, no ground truth or previous transcript");
    }
    json_out(&provider::do_run(run)?);
    Ok(())
}
fn blind_cmd(args:&[String])->Result<(),String>{
    // Accuracy benchmark is locked to MiniMax M3.1 Flash on NVIDIA NIM.
    // Never silently switch provider models after a timeout.
    if let Some(model)=arg(args,"--model") {
        if model!="minimaxai/minimax-m3.1-flash" {
            return Err("blind benchmark locked to minimaxai/minimax-m3.1-flash; alternate models are not permitted".into());
        }
    }
    // Minimal-prompt accuracy test. No memory DB access, AST hints, system
    // instructions, prior messages, formatting rubric, or prior case data.
    let path=require(args,"--file")?;
    let source=fs::read_to_string(&path).map_err(|e|e.to_string())?;
    if source.trim().is_empty(){return Err("source file empty".into());}
    eprintln!("ALEWO_BLIND_MINIMAL: new process/request; one user message; no memory, history, AST or answer hints");
    let out=provider::do_run(Run{
        task:source,mode:Mode::Blind,arm:Arm::Alewo,
        audit_php:false,raw_blind:true,stream_blind:args.iter().any(|x|x=="--stream"),
        scope:"blind-isolated".into(),
        model:arg(args,"--model").unwrap_or_default(),
        output_dir:root().join("data/sessions"),
        workspace:root(),db_path:dbpath()
    })?;
    json_out(&out);
    Ok(())
}
fn agent_cmd(args:&[String])->Result<(),String>{
    let project=require(args,"--project")?;
    let project_abs=fs::canonicalize(&project).map_err(|e|e.to_string())?;
    if !project_abs.is_dir(){return Err("--project must be a directory".into());}
    let default_scope=format!("project:{}",sha2_prefix(&project_abs.to_string_lossy()));
    // BEGIN gives a fresh agent turn boundary without naming a target,
    // expected defect, subsystem, or benchmark oracle.
    let task=arg(args,"--task").unwrap_or_else(||"BEGIN".into());
    let rounds=if arg(args,"--max-rounds").is_some() {
        let r=int_arg(args,"--max-rounds",8)?;
        if r==0||r>64{return Err("--max-rounds must be between 1 and 64".into());}
        r
    } else { 0 };
    let scope=arg(args,"--scope").unwrap_or(default_scope);
    let task_clone=task.clone();
    let response=agent::run(agent::AgentConfig {
        workspace:root(),
        project:project_abs,
        db_path:dbpath(),
        task,
        scope:scope.clone(),
        model:arg(args,"--model").unwrap_or_default(),
        allow_write:args.iter().any(|x|x=="--allow-write"),
        learn:args.iter().any(|x|x=="--learn"),
        challenge_mode:args.iter().any(|x|x=="--challenge-mode"),
        max_rounds:rounds
    })?;
    json_out(&response);
    let ask_fb = !args.iter().any(|x|x=="--no-feedback")
        && (args.iter().any(|x|x=="--feedback") || unsafe { libc::isatty(0) == 1 });
    if ask_fb && response["finish_reason"]=="stop" {
        use std::io::{self,Write};
        eprint!("Tugas sudah selesai. Simpan ke memori? (ya [alasan] / tidak [alasan] / skip): ");
        let _=io::stderr().flush();
        let mut fb=String::new();
        if io::stdin().read_line(&mut fb).unwrap_or(0)>0 {
            let ans=response["answer"].as_str().unwrap_or("");
            let mdl=arg(args,"--model").unwrap_or_default();
            match learning::record_feedback_with_ai(&root(),&mdl,&dbpath(),&scope,&task_clone,ans,&fb,None){
                Ok(r)=>eprintln!("[ALEWO-LEARN] {}",r),
                Err(err)=>eprintln!("[ALEWO-LEARN] gagal simpan memori: {err}"),
            }
        }
    }
    Ok(())
}
fn chat_cmd(args:&[String])->Result<(),String>{
    let project=arg(args,"--project").unwrap_or_else(||".".to_string());
    let abs=fs::canonicalize(&project).map_err(|e|e.to_string())?;
    if !abs.is_dir(){return Err("workspace must be a directory".into());}
    let explicit_cfg=arg(args,"--config");
    let mut cfg=config::AlewoConfig::load(&abs, explicit_cfg.as_deref().map(Path::new))?;
    if let Some(r)=arg(args,"--max-rounds"){
        cfg.max_rounds=r.parse::<usize>().map_err(|_|"invalid --max-rounds")?;
    }
    if let Some(c)=arg(args,"--max-cycles"){
        cfg.goal_cycles=c.parse::<usize>().map_err(|_|"invalid --max-cycles")?;
    }
    if let Some(cp)=arg(args,"--checkpoint-rounds"){
        let n=cp.parse::<usize>().map_err(|_|"invalid --checkpoint-rounds")?;
        if n < 2 { return Err("--checkpoint-rounds must be >= 2".into()); }
        cfg.checkpoint_rounds=n;
    }
    let model=arg(args,"--model").or_else(||cfg.model.clone()).unwrap_or_default();
    let scope=if let Some(s)=arg(args,"--scope"){s}
        else{format!("project:{}",sha2_prefix(&abs.to_string_lossy()))};
    let allow_write=!args.iter().any(|x|x=="--read-only");
    let session=chat::ChatSession::new(
        abs,root(),dbpath(),scope,
        model,
        allow_write,
        args.iter().any(|x|x=="--learn"),
        &cfg
    )?;
    chat::repl(session)
}
fn sha2_prefix(s:&str)->String{
    use sha2::{Digest,Sha256};
    format!("{:x}",Sha256::digest(s.as_bytes()))[..16].to_string()
}
fn map_cmd(args:&[String])->Result<(),String>{
    let dir=std::fs::canonicalize(require(args,"--project")?).map_err(|e|e.to_string())?;
    let m=reachability::build(&dir,52000)?;
    json_out(&json!({
        "schema":"@ALEWO-ENTRYGRAPH/1",
        "php_files_scanned":m.files_parsed,
        "candidate_files":m.candidate_files,
        "other_files":m.other_files,
        "selected_source_packet_bytes":m.packet_bytes,
        "warning":"heuristic reference navigation, not formal reachability proof"
    }));
    Ok(())
}
fn check_cmd(args:&[String])->Result<(),String>{
    let source=fs::read_to_string(require(args,"--source")?).map_err(|x|x.to_string())?;
    let text=fs::read_to_string(require(args,"--response")?).map_err(|x|x.to_string())?;
    let answer=serde_json::from_str::<Value>(&text).ok()
        .and_then(|v|v["answer"].as_str().map(str::to_owned))
        .unwrap_or(text);
    json_out(&grounding::inspect(&source,&answer));
    Ok(())
}
fn doctor()->Result<(),String>{
    let root=root();
    let provider_key_count=provider::env_keys(&root).map(|keys|keys.len()).unwrap_or(0);
    let db=Vault::open(&dbpath())?;
    json_out(&json!({
        "program":"alewo","runtime":"Rust",
        "memory":db.stats()?,
        "memory_backend":"SQLite FTS5 + zstd(CBOR) + immutable evidence blobs + durable run/coverage/hypothesis state",
        "memory_path":dbpath(),
        "api_key_available":provider_key_count>0,
        "provider_key_count":provider_key_count,
        "peer_uses_separate_key":provider_key_count>1,
        "api_key_value_exposed":false,
        "blind_policy":"one case per fresh API call; no prior messages or memory",
        "model_facing_tools":["focus_rank","thinking_commit","candidate_close","finding_verify","memory_read","ws_read_multi","ws_grep","ws_callers","ws_paths","ws_mutations"],
        "tool_surface_policy":"mainstream coding CLI primitives; internal adapters and diagnostics are not model-visible",
        "protocols":["@ALEWO-CTRL/1","@ALEWO-SCHEDULE/1","@ALEWO-PEER/1","@ALEWO-VERIFY/2","@ALEWO-RUNTIME/2","@ALEWO-MEM/4","@ALEWO-THINK/2"],
        "ast_native_languages":polyglot_ast::NATIVE_LANGUAGES,
        "ast_universal_fallback":"all other programming, scripting, query, and config languages",
        "runtime_adapters_discovered":runtime_adapter::discover(&root),
        "provider":"NVIDIA NIM","default_model":"minimaxai/minimax-m3.1-flash",
        "reasoning_effort":provider::MAX_REASONING_EFFORT,
        "reasoning_effort_source":"https://docs.api.nvidia.com/nim/reference/minimaxai-minimax-m3-1-flash",
        "sse_timeouts_seconds":{
            "connect":25,
            "header_default":300,
            "idle_read_default":300,
            "body_total_default":1800,
            "overrides":["ALEWO_SSE_HEADER_TIMEOUT_SECONDS","ALEWO_SSE_IDLE_TIMEOUT_SECONDS","ALEWO_SSE_BODY_TIMEOUT_SECONDS"]
        },
        "inference_executed":false
    }));
    Ok(())
}
fn challenge_cmd(args:&[String])->Result<(),String>{
    let mut forwarded=args.to_vec();
    if arg(&forwarded,"--task").is_none(){
        forwarded.push("--task".into());
        forwarded.push("Perform an exhaustive evidence-first security analysis of the complete repository. Map entrypoints, trust boundaries, state transitions, sibling operations over shared state, and externally reachable effects. Challenge every apparent guard with falsifiable counterexamples. Report only source-grounded, reproducible claims; incomplete evidence is not a safe verdict.".into());
    }
    if !forwarded.iter().any(|x|x=="--challenge-mode"){
        forwarded.push("--challenge-mode".into());
    }
    if !forwarded.iter().any(|x|x=="--no-feedback"){
        forwarded.push("--no-feedback".into());
    }
    agent_cmd(&forwarded)
}

fn controller_cmd(args:&[String],hypotheses_only:bool)->Result<(),String>{
    let id=require(args,"--id")?;
    if !id.chars().all(|c|c.is_ascii_alphanumeric()||c=='-'||c=='_'){
        return Err("invalid run id".into());
    }
    let path=root().join("data/sessions").join(format!("controller-{id}.json"));
    let state=match controller::InvestigationController::load(&path){
        Ok(state)=>state,
        Err(file_error)=>Vault::open(&dbpath())?.load_investigation(&id)
            .map_err(|db_error|format!("{file_error}; {db_error}"))?
    };
    if hypotheses_only{
        json_out(&json!({"run_id":state.run_id,"hypotheses":state.hypotheses,
            "phase":state.phase,"verified_finding":state.verified_finding}));
    }else{
        json_out(&json!({"summary":state.summary(),"nodes":state.nodes,"tools":state.tools}));
    }
    Ok(())
}

fn protocol_cmd(args:&[String])->Result<(),String>{
    if args.first().map(String::as_str)!=Some("calibrate"){
        return Err("usage: alewo protocol calibrate [--live] [--only existing|named|positional|json] [--model MODEL]".into());
    }
    let frame=protocol::MemoryFrame{
        addr:"M0013",kind:"success",signature:"security:state:cross_context_reuse",
        detail:"PAIR_SIBLING_OPERATIONS;COLD_WARM_REPLAY;VERIFY_ENTRY_GUARD_STATE_SINK",
        scope_is_global:true,resolved_by:None,parents:Some("M0012,M0005"),proof_grade:"E3"
    };
    let mut report=protocol::calibration_report(&frame,240);
    if args.iter().any(|x|x=="--live"){
        let key=provider::env_key(&root())?;
        let model=arg(args,"--model").unwrap_or_else(provider::default_model);
        let codebooks=std::collections::BTreeMap::from([
            ("existing","FORMAT H|BADGE|REL|INVARIANT|DETAIL|PROOF; [+OK]=success; FROM<-=parents"),
            ("named","FORMAT A4|H=handle|K=kind|S=scope|R=relation|V=proof|I=invariant|D=detail"),
            ("positional","FORMAT A4|handle|kind+scope|relation|proof|invariant|detail"),
            ("json","JSON keys: h=handle,k=kind,s=scope,r=relation,p=proof,i=invariant,d=detail"),
        ]);
        let mut live=Vec::new();
        let only=arg(args,"--only").map(|s|s.to_ascii_lowercase());
        for candidate in protocol::candidates(&frame){
            if only.as_deref().is_some_and(|wanted|wanted!=candidate.encoding){continue;}
            let codebook=codebooks.get(candidate.encoding).copied().unwrap_or("");
            let body=json!({
                "model":model,
                "messages":[
                    {"role":"system","content":"Decode one compact Alewo memory record. Return only JSON with handle, kind, proof, invariant, parents, and next_action. Do not infer fields not encoded."},
                    {"role":"user","content":format!("{codebook}\nRECORD={}",candidate.text)}
                ],
                "temperature":0.0,"top_p":1.0,"seed":0,"reasoning_effort":provider::MAX_REASONING_EFFORT,
                "max_tokens":120,"stream":false
            });
            match provider::send_chat_bounded(&key,&body,std::time::Duration::from_secs(35)){
                Ok((response,seconds))=>{
                    let answer=response["choices"][0]["message"]["content"].as_str().unwrap_or("");
                    let exact=answer.contains("M0013")&&answer.contains("cross_context_reuse")
                        &&answer.contains("E3")&&answer.contains("M0012");
                    live.push(json!({
                        "encoding":candidate.encoding,
                        "prompt_tokens":response["usage"]["prompt_tokens"],
                        "completion_tokens":response["usage"]["completion_tokens"],
                        "total_tokens":response["usage"]["total_tokens"],
                        "seconds":seconds,"semantic_recovery_pass":exact,
                        "answer_sha256":sha2_prefix(answer)
                    }));
                },
                Err(error)=>live.push(json!({"encoding":candidate.encoding,"error":error}))
            }
        }
        report["live_provider_calibration"]=json!(live);
        report["activation_rule"]=json!("candidate must recover semantics and use fewer provider prompt tokens; repository finding ablation is still required before ALEWO_PROTOCOL changes");
    }
    json_out(&report);
    Ok(())
}

fn benchmark_cmd(args:&[String])->Result<(),String>{
    let tokens=|v:&Value|v["usage"]["total_tokens"].as_f64()
        .or_else(||v["token_usage"]["total_tokens"].as_f64())
        .or_else(||v["api_tokens"]["total"].as_f64());
    let wall=|v:&Value|v["total_wall_seconds"].as_f64()
        .or_else(||v["wall_seconds"].as_f64())
        .or_else(||v["api_seconds"].as_f64());
    let verified=|v:&Value|v["investigation"]["verified_finding"].as_bool()
        .or_else(||v["challenge_accepted"].as_bool()).unwrap_or(false);
    let load_path=|path:&Path|->Result<Value,String>{
        let bytes=fs::read(path).map_err(|e|format!("{}: {e}",path.display()))?;
        serde_json::from_slice(&bytes).map_err(|e|format!("{}: {e}",path.display()))
    };
    match args.first().map(String::as_str){
        Some("compare")=>{
            let a_path=require(args,"--a")?;let b_path=require(args,"--b")?;
            let a=load_path(Path::new(&a_path))?;let b=load_path(Path::new(&b_path))?;
            let at=tokens(&a);let bt=tokens(&b);let aw=wall(&a);let bw=wall(&b);
            json_out(&json!({
                "a":{"tokens":at,"seconds":aw,"verified":verified(&a)},
                "b":{"tokens":bt,"seconds":bw,"verified":verified(&b)},
                "b_vs_a":{
                    "token_ratio":match(at,bt){(Some(x),Some(y)) if x>0.0=>json!(y/x),_=>Value::Null},
                    "speed_ratio":match(aw,bw){(Some(x),Some(y)) if y>0.0=>json!(x/y),_=>Value::Null}
                },
                "warning":"Efficiency ratios are causal only for paired runs with identical repository, model, parameters, and task. Use benchmark matrix for contract validation."
            }));
        },
        Some("matrix")=>{
            let manifest_path=PathBuf::from(require(args,"--manifest")?);
            let manifest=load_path(&manifest_path)?;
            let pairs=manifest["pairs"].as_array().ok_or("manifest.pairs must be an array")?;
            if pairs.is_empty(){return Err("manifest.pairs must not be empty".into());}
            let base=manifest_path.parent().unwrap_or(Path::new("."));
            let resolve=|raw:&str|{let p=PathBuf::from(raw);if p.is_absolute(){p}else{base.join(p)}};
            let required_contract=["task_sha256","project_source_sha256",
                "source_fingerprint_complete","source_fingerprint_algorithm",
                "inventory_count","model","reasoning_effort","challenge_mode","seed"];
            let mut rows=Vec::new();let mut compatible_n=0usize;
            let mut baseline_success=0usize;let mut candidate_success=0usize;
            let mut candidate_only=0usize;let mut baseline_only=0usize;
            let mut token_ratios=Vec::<f64>::new();let mut speedups=Vec::<f64>::new();
            for (index,pair) in pairs.iter().enumerate(){
                let baseline_raw=pair["baseline"].as_str().ok_or_else(||format!("pairs[{index}].baseline required"))?;
                let candidate_raw=pair["candidate"].as_str().ok_or_else(||format!("pairs[{index}].candidate required"))?;
                let baseline=load_path(&resolve(baseline_raw))?;
                let candidate=load_path(&resolve(candidate_raw))?;
                let bc=&baseline["benchmark_contract"];let cc=&candidate["benchmark_contract"];
                let mut mismatches=required_contract.iter().filter(|key|
                    bc.get(*key).is_none()||cc.get(*key).is_none()||bc[*key]!=cc[*key]
                ).map(|s|s.to_string()).collect::<Vec<_>>();
                if bc["source_fingerprint_complete"]!=true||
                    cc["source_fingerprint_complete"]!=true{
                    mismatches.push("source_fingerprint_complete".into());
                }
                mismatches.sort();mismatches.dedup();
                let compatible=mismatches.is_empty();
                let bv=verified(&baseline);let cv=verified(&candidate);
                let bt=tokens(&baseline);let ct=tokens(&candidate);
                let bs=wall(&baseline);let cs=wall(&candidate);
                let token_ratio=match(bt,ct){(Some(x),Some(y)) if x>0.0=>Some(y/x),_=>None};
                let speedup=match(bs,cs){(Some(x),Some(y)) if y>0.0=>Some(x/y),_=>None};
                if compatible{
                    compatible_n+=1;
                    baseline_success+=usize::from(bv);candidate_success+=usize::from(cv);
                    candidate_only+=usize::from(cv&&!bv);baseline_only+=usize::from(bv&&!cv);
                    if bv&&cv{
                        if let Some(x)=token_ratio.filter(|x|*x>0.0){token_ratios.push(x);}
                        if let Some(x)=speedup.filter(|x|*x>0.0){speedups.push(x);}
                    }
                }
                rows.push(json!({
                    "case":pair["case"].as_str().map(str::to_owned).unwrap_or_else(||format!("case-{}",index+1)),
                    "contract_compatible":compatible,
                    "efficiency_eligible":compatible&&bv&&cv,
                    "contract_mismatches":mismatches,
                    "baseline":{"verified":bv,"tokens":bt,"seconds":bs},
                    "candidate":{"verified":cv,"tokens":ct,"seconds":cs},
                    "candidate_vs_baseline":{"token_ratio":token_ratio,"speedup":speedup}
                }));
            }
            let geomean=|values:&[f64]|if values.is_empty(){None}else{
                Some((values.iter().map(|x|x.ln()).sum::<f64>()/values.len() as f64).exp())
            };
            let wilson=|success:usize,total:usize|->Value{
                if total==0{return Value::Null;}
                let n=total as f64;let p=success as f64/n;let z=1.959963984540054;
                let d=1.0+z*z/n;let center=(p+z*z/(2.0*n))/d;
                let margin=z*((p*(1.0-p)/n+z*z/(4.0*n*n)).sqrt())/d;
                json!({"rate":p,"low":(center-margin).max(0.0),"high":(center+margin).min(1.0)})
            };
            let discordant=candidate_only+baseline_only;
            let mcnemar_exact=if discordant==0{Value::Null}else{
                let k=candidate_only.min(baseline_only);
                let mut probability=2f64.powi(-(discordant as i32));let mut tail=probability;
                for i in 0..k{
                    probability*=((discordant-i) as f64)/((i+1) as f64);
                    tail+=probability;
                }
                json!((2.0*tail).min(1.0))
            };
            json_out(&json!({
                "schema":"@ALEWO-BENCH/1","pairs_total":pairs.len(),
                "pairs_contract_compatible":compatible_n,"rows":rows,
                "aggregate":{
                    "baseline_accuracy_wilson95":wilson(baseline_success,compatible_n),
                    "candidate_accuracy_wilson95":wilson(candidate_success,compatible_n),
                    "paired_accuracy_delta":if compatible_n>0{
                        json!((candidate_success as f64-baseline_success as f64)/compatible_n as f64)
                    }else{Value::Null},
                    "candidate_only_successes":candidate_only,
                    "baseline_only_successes":baseline_only,
                    "mcnemar_exact_two_sided_p":mcnemar_exact,
                    "candidate_token_ratio_geomean":geomean(&token_ratios),
                    "candidate_speedup_geomean":geomean(&speedups),
                    "token_ratio_sample_size":token_ratios.len(),
                    "speedup_sample_size":speedups.len()
                },
                "acceptance_rule":"Claim improvement only on contract-compatible paired runs; accuracy must not regress, and efficiency ratios are interpreted only when both arms reach the required verifier grade.",
                "warning":"This computes paired evidence; it does not manufacture causality. Repeated seeds and externally curated zero-clue cases are still required."
            }));
        },
        _=>return Err("usage: alewo benchmark compare --a RESULT.json --b RESULT.json | alewo benchmark matrix --manifest PAIRS.json".into())
    }
    Ok(())
}

fn help_core(){
    println!(r#"Alewo 0.1 — mathematical multi-agent coding harness.

Usage:
  alewo [--project PATH] [--model MODEL] [--read-only]
  alewo agent --project PATH [--task TEXT] [--max-rounds N]
  alewo doctor
  alewo help --all

The peer orchestrator, memory retrieval, attention scheduling, reasoning effort,
and tool filtering are automatic. Advanced diagnostic and benchmark commands
remain available under `alewo help --all`."#);
}

fn help(){
    println!(r#"Alewo 0.1 — independent Rust coding-agent harness, evidence-first.
Commands:
  alewo [--model MODEL] [--config FILE] [--max-cycles 10] [--checkpoint-rounds 12] [--max-rounds 0] [--read-only] # interactive CLI + continuous /goal (default 10 cycles, rethink checkpoint every 12 rounds, unlimited rounds)
  alewo doctor
  alewo challenge --project <folder> [--task "zero-clue audit"] # unlimited controller; requires transparent finding_verify
  alewo coverage --id <RUN_ID> | alewo hypothesis --id <RUN_ID>
  alewo protocol calibrate [--live] [--only ENCODING] # bounded token/comprehension calibration
  alewo benchmark compare --a RESULT.json --b RESULT.json
  alewo benchmark matrix --manifest PAIRS.json # paired accuracy/token/latency evidence with contract checks
  alewo path-matrix --project <folder> # offline, project-derived E2E mutation test; no model call
  alewo state-matrix --project <folder> # offline, multi-request cold/warm differential tests; no model call
  alewo blind --file <one_case.php> [--stream] [--model MODEL] # exact user-only prompt; ZERO hints or memory
  alewo check --source <code.php> --response <model-response.json> # offline evidence grounding
  alewo eval --file <one_case.php> [--arm native|alewo] [--model MODEL]
  alewo agent --project <folder> --task "goal" [--scope PROJECT] [--max-rounds 6] [--allow-write] [--learn]
  alewo chat --project <folder> [--scope PROJECT] [--max-rounds 6] [--allow-write] [--learn]
  alewo run --file <task> [--mode blind|agent] [--arm native|alewo] [--scope PROJECT]
  alewo run --task "question" [--mode blind|agent] [--scope PROJECT]
  alewo memory add --file <symbolic_experience.json>
  alewo memory search --scope PROJECT --query "tokens" [--limit 4] [--max-chars 1100]
  alewo memory inspect|trace|explain --id HASH
  alewo memory effect --id HASH [--applied N --success N --failure N --false-lead N --coverage N]
  alewo memory approve --id HASH
  alewo memory resolve --id HASH  # Explicitly choose one conflicting claim
  alewo memory revoke --id HASH
  alewo memory prune
  alewo memory stats
ALEWO_DB overrides the memory database. NVIDIA_API_KEY or .env supplies provider key.
'eval' is always blind: ONE case per new API request; no memory or history.
No artificial max_tokens/context cap; only provider and hardware limits.
Agent tool loop defaults read-only. Source mutations require --allow-write.
--learn enables agent-proposed PENDING symbolic memories; --feedback / TTY auto-prompts Automate Learning (AI-distilled + strict Rust schema).
Env overrides: ALEWO_API_URL, ALEWO_API_KEY (or NVIDIA_API_KEY), ALEWO_MODEL, ALEWO_DB.
Capabilities: SSE streaming tool-loop, 19-language Tree-sitter polyglot AST + universal fallback, persistent coverage controller, transparent source-chain verifier, hybrid universal memory scoring, A4 protocol calibration, @ALEWO-MAP/4 structural radar, and failure->success Mxxxx lineage."#);
}
fn main(){
    #[cfg(unix)]
    unsafe{libc::umask(0o077);}
    let args=env::args().skip(1).collect::<Vec<_>>();
    let result=if args.is_empty(){
        chat_cmd(&[])
    } else if args[0].starts_with("--") && args[0]!="--help" {
        chat_cmd(&args)
    } else {
    let cmd=args[0].as_str();
    match cmd{
        "doctor"|"init"=>doctor(),
        "tool-schema"=>{json_out(&serde_json::json!(agent::orchestrated_tool_defs(&agent::tool_defs(true,true))));Ok(())},
        "challenge"=>challenge_cmd(&args[1..]),
        "coverage"=>controller_cmd(&args[1..],false),
        "hypothesis"=>controller_cmd(&args[1..],true),
        "protocol"=>protocol_cmd(&args[1..]),
        "benchmark"=>benchmark_cmd(&args[1..]),
        "map"=>map_cmd(&args[1..]),
        "path-matrix"=>(|| -> Result<(),String>{
            let root=fs::canonicalize(require(&args[1..],"--project")?).map_err(|e|e.to_string())?;
            json_out(&path_matrix::scan(&root)?);Ok(())
        })(),
        "state-matrix"=>(|| -> Result<(),String>{
            let root=fs::canonicalize(require(&args[1..],"--project")?).map_err(|e|e.to_string())?;
            json_out(&state_matrix::scan(&root)?);Ok(())
        })(),
        "memory"=>memory_cmd(&args[1..]),
        "eval"=>run_cmd(&args[1..],true),
        "blind"=>blind_cmd(&args[1..]),
        "check"=>check_cmd(&args[1..]),
        "run"=>run_cmd(&args[1..],false),
        "agent"=>agent_cmd(&args[1..]),
        "chat"=>chat_cmd(&args[1..]),
        "help"|"--help"|"-h"=>{if args.iter().any(|x|x=="--all"){help()}else{help_core()};Ok(())}
        other=>Err(format!("unknown command {other}; use alewo help"))
    }};
    if let Err(e)=result{eprintln!("ALEWO_ERROR: {e}");std::process::exit(2);}
}
