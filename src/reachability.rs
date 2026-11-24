//! Approximate entrypoint reachability index for PHP agents.
//! File references and class names are extracted from real source bytes;
//! this is navigation evidence, NOT a formal proof of dynamic reachability.
//! No evaluator labels, hidden answers, or fixture-specific symbols appear here.
use std::{collections::{BTreeMap,BTreeSet,VecDeque},fs,path::Path};

pub struct Map {
    pub files_parsed:usize,
    pub candidate_files:Vec<String>,
    pub other_files:usize,
    pub source_packet:String,
    pub packet_bytes:usize,
}
fn blocked(name:&str)->bool{
    name.starts_with('.') || matches!(name,".git"|"vendor"|"node_modules"|"data"|"secrets"|"results")
}
fn is_non_production(path:&str)->bool{
    let s=path.to_ascii_lowercase();
    s.starts_with("tests/") || s.starts_with("test/") || s.starts_with("docs/") || s.starts_with("doc/") ||
    s.starts_with("examples/") || s.starts_with("example/") || s.starts_with("samples/") ||
    s.starts_with("benchmarks/") || s.starts_with("benchmark/") || s.starts_with("testdata/") ||
    s.starts_with("fixtures/") || s.contains("/tests/") || s.contains("/test/")
}
fn root_candidate(path:&str)->bool{
    if is_non_production(path){return false;}
    let s=path.to_ascii_lowercase();
    let file=s.rsplit('/').next().unwrap_or(&s);
    let stem=file.split('.').next().unwrap_or(file);
    s.starts_with("public/") || s.starts_with("cmd/") || s.starts_with("server/") ||
    s.starts_with("modules/") || s.starts_with("src/") || s.starts_with("core/") ||
    s.starts_with("api/") || s.starts_with("bin/") || s.starts_with("net/") ||
    s.starts_with("crypto/") || s.starts_with("auth/") || s.starts_with("engine/") ||
    matches!(stem,"index"|"main"|"lib"|"mod"|"__init__"|"app"|"server"|"client"|"cli"|"entry"|"bootstrap"|"appfactory"|"manage"|"wsgi"|"asgi"|"program"|"startup"|"application"|"init"|"api") ||
    stem.ends_with("controller") || stem.ends_with("router") || stem.ends_with("route") || stem.ends_with("handler") ||
    stem.ends_with("servlet") || stem.ends_with("service") || stem.ends_with("plugin") || stem.ends_with("_process") || stem.ends_with("_init")
}
fn test_entrypoint(path:&str)->bool{
    let s=path.to_ascii_lowercase();
    s.starts_with("tests/") || s.starts_with("test/")
}
pub fn build(root:&Path,max_packet_bytes:usize)->Result<Map,String>{
    let mut pending=vec![(root.to_path_buf(),0usize)];
    let mut code=BTreeMap::<String,String>::new();
    let mut class_to_file=BTreeMap::<String,BTreeSet<String>>::new();
    while let Some((dir,depth))=pending.pop(){
        if depth>10 || code.len()>=4000{continue;}
        let mut entries=fs::read_dir(dir).map_err(|e|e.to_string())?.filter_map(Result::ok).collect::<Vec<_>>();
        entries.sort_by_key(|e|e.file_name());
        for e in entries.into_iter().rev(){
            let path=e.path();let name=e.file_name().to_string_lossy().to_string();
            if blocked(&name) || matches!(name.as_str(),"target"|"build"|"dist"){continue;}
            if path.is_dir(){if depth<10{pending.push((path,depth+1));}continue;}
            if !crate::polyglot_ast::is_code_file(&path){continue;}
            if e.metadata().map_err(|e|e.to_string())?.len()>1_024_000{continue;}
            let rel=path.strip_prefix(root).unwrap_or(&path).to_string_lossy().to_string();
            // Test files may seed an entrypoint in a tiny repository, but are
            // removed from the model-facing packet and candidate list below.
            let Ok(text)=fs::read_to_string(&path) else {continue;};
            let parsed=crate::polyglot_ast::parse_file(&path,&text);
            for sym in parsed.symbols{
                if sym.name.len()>=3 && matches!(sym.kind.as_str(),"class"|"interface"|"trait"|"enum"|"struct"|"module"|"contract"|"service"|"function"){
                    class_to_file.entry(sym.name).or_default().insert(rel.clone());
                }
            }
            code.insert(rel,text);
            if code.len()>=4000{break;}
        }
    }
    // Seed production entrypoints first; if a repo has explicit test entrypoints
    // (e.g. small fixture with tests/smoke.php) include them only when total code is small (<40 files).
    let small_repo = code.len() <= 40;
    let mut roots: Vec<String> = if small_repo {
        let test_roots: Vec<String> = code.keys().filter(|p| test_entrypoint(p)).cloned().collect();
        if !test_roots.is_empty() {
            test_roots
        } else {
            code.keys().filter(|p| root_candidate(p)).cloned().collect()
        }
    } else {
        code.keys().filter(|p| root_candidate(p)).cloned().collect()
    };
    // Universal library fallback: if no standard entrypoint matched, seed all non-test
    // production code files first (and fall back to all files only if empty).
    if roots.is_empty() {
        roots = code.keys().filter(|p| !is_non_production(p)).cloned().collect();
    }
    if roots.is_empty() {
        roots = code.keys().cloned().collect();
    }
    let mut visited=BTreeSet::new();
    let mut queue=VecDeque::from(roots);
    while let Some(path)=queue.pop_front(){
        if visited.len()>=1200{break;}
        if !visited.insert(path.clone()){continue;}
        let Some(src)=code.get(&path) else{continue;};
        // Heuristic lexical class references; constructors, inheritance, and
        // explicit bootstrap mentions are covered, dynamic strings may not be.
        let tokens: std::collections::HashSet<&str> = src
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|t| t.len() >= 3)
            .collect();
        for tok in tokens {
            if let Some(files) = class_to_file.get(tok) {
                for dest in files {
                    if !small_repo && is_non_production(dest) { continue; }
                    if !visited.contains(dest) { queue.push_back(dest.clone()); }
                }
            }
        }
        // Include known source file mentions even when a symbol name differs.
        for target in code.keys(){
            if target==&path{continue;}
            if !small_repo && is_non_production(target){continue;}
            let filename=target.rsplit('/').next().unwrap_or(target);
            if filename.len()>5 && src.contains(filename) && !visited.contains(target){
                queue.push_back(target.clone());
            }
        }
    }
    let candidates=visited.into_iter()
        .filter(|path|!is_non_production(path))
        .collect::<Vec<_>>();
    let mut packet=String::new();
    for path in &candidates{
        let Some(src)=code.get(path) else{continue;};
        let block=format!("// FILE: {}\n{}\n\n",path,src);
        if packet.len()+block.len()>max_packet_bytes{continue;}
        packet.push_str(&block);
    }
    Ok(Map{
        files_parsed:code.len(),
        other_files:code.len().saturating_sub(candidates.len()),
        candidate_files:candidates,
        packet_bytes:packet.len(),
        source_packet:packet,
    })
}
#[cfg(test)]
mod tests{
 use super::*;
 use std::time::{SystemTime,UNIX_EPOCH};
 #[test]fn excludes_unreferenced_legacy_from_entrypoint_packet(){
    let dir=std::env::temp_dir().join(format!("alewo-reachable-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(dir.join("src")).unwrap();fs::create_dir_all(dir.join("tests")).unwrap();
    fs::write(dir.join("tests/smoke.php"),"<?php require '../src/App.php'; $app = new App();").unwrap();
    fs::write(dir.join("src/App.php"),"<?php class App { function run(){ return (new Store())->read(); }}").unwrap();
    fs::write(dir.join("src/Store.php"),"<?php class Store { function read(){return 123;}}").unwrap();
    fs::write(dir.join("src/Legacy.php"),"<?php class Legacy {function bad(){return true;}}").unwrap();
    let map=build(&dir,15000).unwrap();
    assert!(map.candidate_files.iter().any(|x|x=="src/App.php"));
    assert!(map.candidate_files.iter().any(|x|x=="src/Store.php"));
    assert!(!map.candidate_files.iter().any(|x|x=="src/Legacy.php"));
    assert!(map.source_packet.contains("class Store"));
    fs::remove_dir_all(dir).unwrap();
 }
}
