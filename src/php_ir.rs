use tree_sitter::{Node,Parser};
use serde_json::{json,Value};
use std::time::Instant;

#[derive(Debug,Clone)]
pub struct Evidence {pub ir:String,pub features:Vec<Value>,pub compile_ns:u128}
fn text<'a>(n:Node<'a>,src:&'a str)->&'a str{
    src.get(n.start_byte()..n.end_byte()).unwrap_or("")
}
fn has_direct_boolean_return(n:Node,src:&str,value:&str)->bool{
    fn is_target(n:Node,src:&str,value:&str)->bool{
        n.kind()=="return_statement" &&
        text(n,src).chars().filter(|c| !c.is_whitespace()).collect::<String>()==format!("return{value};")
    }
    if is_target(n,src,value){return true;}
    if n.kind()=="compound_statement"{
        let mut cur=n.walk();
        return n.named_children(&mut cur).any(|child|is_target(child,src,value));
    }
    false
}
fn visit(n:Node, src:&str, out:&mut Vec<Value>, parent_condition:bool, depth:usize){
    if depth>60{return;}
    if n.kind()=="if_statement"{
        let mut cur=n.walk();
        let children=n.named_children(&mut cur).collect::<Vec<_>>();
        let cond=children.iter().find(|c| c.kind()=="parenthesized_expression");
        if let Some(cond)=cond {
            let mut stack=vec![*cond];
            while let Some(x)=stack.pop() {
                if x.kind()=="assignment_expression" {
                    let mut xc=x.walk();
                    let fields=x.named_children(&mut xc).map(|z|text(z,src).trim().to_string()).collect::<Vec<_>>();
                    let returns_true=children.iter().filter(|z|z.start_byte()>=cond.end_byte())
                        .take(1).any(|z|has_direct_boolean_return(*z,src,"true"));
                    // The nearest function provides the authorization scope and
                    // the actual fallback return. Comments and unrelated functions
                    // cannot satisfy these conditions.
                    let mut parent=n.parent();
                    let mut scope_name=String::new();
                    let mut fallback_false=false;
                    while let Some(a)=parent {
                        if a.kind()=="function_definition" {
                            if let Some(name)=a.child_by_field_name("name") {
                                scope_name=text(name,src).to_string();
                            }
                            let body=a.child_by_field_name("body").or_else(||{
                                let mut cursor=a.walk();
                                let found=a.named_children(&mut cursor).find(|z|z.kind()=="compound_statement");
                                found
                            });
                            fallback_false=body.map(|b|has_direct_boolean_return(b,src,"false")).unwrap_or(false);
                            break;
                        }
                        parent=a.parent();
                    }
                    let rhs=fields.get(1).map(|s|s.trim()).unwrap_or("");
                    let literal_truthy=(rhs.starts_with('\'') && rhs.ends_with('\'')
                          || rhs.starts_with('"') && rhs.ends_with('"'))
                          && rhs.len()>2 && rhs!="\'0\'" && rhs!="\"0\"";
                    out.push(json!({
                       "op":"COND_ASSIGN",
                       "line":x.start_position().row+1,
                       "condition":text(*cond,src),
                       "expression":text(x,src),
                       "operands":fields,
                       "true_branch_returns":returns_true,
                       "function":scope_name,
                       "fallback_returns_false":fallback_false,
                       "rhs_constant_truthy":literal_truthy
                    }));
                }
                let mut c=x.walk();
                for item in x.named_children(&mut c) {stack.push(item);}
            }
        }
    }
    let mut c=n.walk();
    for x in n.named_children(&mut c){ visit(x,src,out,parent_condition || n.kind()=="if_statement",depth+1);}
}
pub fn impact_instruction(ir:&str)->String {
    let facts=ir.lines().filter(|l|l.starts_with("CFG|")).collect::<Vec<_>>().join("\n");
    let compact=facts.replace("CFG|if|","if@")
        .replace("|ASSIGN|"," assigns ")
        .replace("|branch_true=","; return_true=");
    format!(
        "Compiler-parsed PHP syntax facts: {compact} These facts may be empty or incomplete. Use only actual source behavior; trace input through validation, state and sensitive effects. If no demonstrable vulnerability exists, output NONE per the user format. Otherwise choose the CWE for the violated security boundary and explain the exact cause. Never invent a line, exploit, or category not supported by source."
    )
}
pub fn compile(source:&str)->Result<Evidence,String>{
    let start=Instant::now();
    let mut parser=Parser::new();
    parser.set_language(&tree_sitter_php::LANGUAGE_PHP.into()).map_err(|e|e.to_string())?;
    let tree=parser.parse(source,None).ok_or("PHP parse failed")?;
    if tree.root_node().has_error(){return Err("PHP parse tree contains errors".into());}
    let mut features=vec![];
    visit(tree.root_node(),source,&mut features,false,0);
    let mut ir=format!("@ALEWO/2\nLANG|PHP\nLINES|{}\n",source.lines().count());
    for fact in &features {
        let line=fact["line"].as_u64().unwrap_or(0);
        if fact["op"]=="COND_ASSIGN" {
          ir.push_str(&format!("CFG|if|{line}|ASSIGN|{}|branch_true={}\n",
              fact["expression"].as_str().unwrap_or("").trim(),
              fact["true_branch_returns"].as_bool().unwrap_or(false) as u8));
        }
    }
    Ok(Evidence{ir,features,compile_ns:start.elapsed().as_nanos()})
}
#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn detected_assignment_as_condition() {
     let a=compile("<?php\nfunction a($x){ if($x = 'admin') return true; return false; }").unwrap();
     assert_eq!(a.features.len(),1);
     assert_eq!(a.features[0]["op"],"COND_ASSIGN");
     assert_eq!(a.features[0]["line"],2);
 }
 #[test] fn comparison_not_assignment(){
     let a=compile("<?php\nfunction a($x){ if($x === 'admin') return true; return false; }").unwrap();
     assert_eq!(a.features.len(),0);
 }
 #[test] fn ignores_assignment_outside_guard(){
     let a=compile("<?php\nfunction a($x){ $x = 'admin'; if($x === 'admin') return true; return false; }").unwrap();
     assert_eq!(a.features.len(),0);
 }
 #[test] fn ignores_comment(){
     let a=compile("<?php\n// if($x = 'admin')\nreturn true;").unwrap();
     assert_eq!(a.features.len(),0);
 }
}