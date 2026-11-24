//! Polyglot source index for agent navigation. Tree-sitter parses declarations and
//! call syntax, but an observed call site is NOT proof of dynamic reachability.
use serde_json::{json,Value};
use std::{fs,path::Path};
use tree_sitter::{Node,Parser};

fn blocked(name:&str)->bool {
    name.starts_with('.') || matches!(name,".env"|"data"|"results"|"secrets"|".git"|"vendor"|"node_modules")
}
fn source_text<'a>(n:Node<'a>, src:&'a str)->&'a str {
    src.get(n.start_byte()..n.end_byte()).unwrap_or("")
}
fn name(n:Node,src:&str)->String{
    n.child_by_field_name("name").map(|c|source_text(c,src).to_owned()).unwrap_or_default()
}
fn index_node(n:Node,src:&str,file:&str,scope:&str,out:&mut Vec<Value>,calls:&mut Vec<Value>,depth:usize) {
    if depth>75 || out.len()>800 || calls.len()>1200{return;}
    let kind=n.kind();
    let class_scope = if matches!(kind,"class_declaration"|"trait_declaration"|"interface_declaration"){
        let class=name(n,src);
        if class.is_empty(){scope.to_string()} else{class}
    }else{scope.to_string()};
    if matches!(kind,"method_declaration"|"function_definition"){
        let fname=name(n,src);
        if !fname.is_empty(){
            let qualified=if class_scope.is_empty(){fname.clone()}else{format!("{class_scope}::{fname}")};
            out.push(json!({"file":file,"line":n.start_position().row+1,
                "symbol":qualified,"kind":kind}));
        }
    }
    if matches!(kind,"member_call_expression"|"scoped_call_expression"|"function_call_expression"|
        "object_creation_expression"|"include_expression"|"require_expression"){
        let raw=source_text(n,src);
        // Only source syntax. Dynamic dispatch must be reviewed independently.
        let snippet=raw.chars().take(140).collect::<String>().replace('\n'," ");
        if !snippet.trim().is_empty(){
            calls.push(json!({"file":file,"line":n.start_position().row+1,
                "scope":class_scope,"syntax":kind,"expression":snippet}));
        }
    }
    let mut cursor=n.walk();
    for child in n.named_children(&mut cursor){
        index_node(child,src,file,&class_scope,out,calls,depth+1);
    }
}
pub fn index(root:&Path,query:&str)->Result<Value,String>{
    let mut parser=Parser::new();
    parser.set_language(&tree_sitter_php::LANGUAGE_PHP.into()).map_err(|e|e.to_string())?;
    let mut stack=vec![(root.to_path_buf(),0usize)];
    let mut symbols=Vec::new();let mut calls=Vec::new();
    let mut scanned=0usize;let mut php_scanned=0usize;let mut parse_errors=0usize;
    while let Some((dir,depth))=stack.pop(){
        if depth>10 || scanned>=2000 {continue;}
        let mut entries=fs::read_dir(&dir).map_err(|e|e.to_string())?.filter_map(Result::ok).collect::<Vec<_>>();
        entries.sort_by_key(|e|e.file_name());
        for entry in entries.into_iter().rev(){
            let path=entry.path();let name=entry.file_name().to_string_lossy().to_string();
            if blocked(&name){continue;}
            if path.is_dir(){if depth<10{stack.push((path,depth+1));}continue;}
            if !crate::polyglot_ast::is_code_file(&path) {continue;}
            if entry.metadata().map_err(|e|e.to_string())?.len()>1_024_000{continue;}
            let Ok(src)=fs::read_to_string(&path) else {continue;};
            scanned+=1;
            let rel=path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
            if path.extension().and_then(|s|s.to_str())==Some("php") {
                php_scanned+=1;
                let tree=match parser.parse(&src,None){Some(tree)=>tree,None=>continue};
                if tree.root_node().has_error(){parse_errors+=1;continue;}
                index_node(tree.root_node(),&src,&rel,"",&mut symbols,&mut calls,0);
            } else {
                let parsed=crate::polyglot_ast::parse_file(&path,&src);
                for sym in parsed.symbols {
                    if symbols.len()>1200 {break;}
                    symbols.push(json!({"file":rel,"line":sym.line,"lang":parsed.lang,"symbol":sym.name,"kind":sym.kind}));
                }
                for call in parsed.calls {
                    if calls.len()>1600 {break;}
                    calls.push(json!({"file":rel,"line":call.line,"lang":parsed.lang,"expression":call.expr}));
                }
            }
        }
    }
    let query=query.to_ascii_lowercase();
    let matching=|v:&Value|{
        query.is_empty() || v.to_string().to_ascii_lowercase().contains(&query)
    };
    let total_symbols=symbols.len();let total_calls=calls.len();
    let symbol_samples=symbols.into_iter().filter(&matching).take(100).collect::<Vec<_>>();
    let call_samples=calls.into_iter().filter(&matching).take(125).collect::<Vec<_>>();
    Ok(json!({
        "schema":"@ALEWO-FLOW/1","interpretation":"Navigation-only: names/call expressions do not establish dynamic reachability or vulnerabilities",
        "files_scanned":scanned,"php_files_parsed":php_scanned,
        "files_with_parse_error":parse_errors,
        "total_symbols":total_symbols,"total_call_expressions":total_calls,
        "query":query,"symbols":symbol_samples,"calls":call_samples,
        "truncated":symbol_samples.len()<total_symbols || call_samples.len()<total_calls
    }))
}
#[cfg(test)]
mod tests{
    use super::*;
    use std::time::{SystemTime,UNIX_EPOCH};
    #[test]
    fn identifies_declarations_and_calls_without_claiming_reachability(){
        let d=std::env::temp_dir().join(format!("alewo-flow-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("x.php"),"<?php class Task { public function run():void { $this->read(); self::audit(); } private function read():void{} private static function audit():void{} }").unwrap();
        let x=index(&d,"").unwrap();
        let symbols=x["symbols"].as_array().unwrap();
        assert!(symbols.iter().any(|v|v["symbol"]=="Task::run"));
        assert!(symbols.iter().any(|v|v["symbol"]=="Task::read"));
        assert!(x["total_call_expressions"].as_u64().unwrap()>=2);
        fs::remove_dir_all(d).unwrap();
    }
}
