//! Post-inference source anchoring, without any model prompt modifications.
use serde_json::{json,Value};
use std::collections::BTreeSet;
fn vars(s:&str)->BTreeSet<String>{
 let b=s.as_bytes();let mut out=BTreeSet::new();let mut i=0;
 while i<b.len(){
   if b[i]==b'$'&&i+1<b.len()&&(b[i+1].is_ascii_alphabetic()||b[i+1]==b'_'){
      let start=i;i+=2;
      while i<b.len()&&(b[i].is_ascii_alphanumeric()||b[i]==b'_'){i+=1;}
      out.insert(s[start..i].to_owned());
   }else{i+=1;}
 }
 out
}
fn normalize(s:&str)->String{s.chars().filter(|c|!c.is_whitespace()).collect()}
fn pre_fix_code(answer:&str)->Option<String>{
 let lower=answer.to_ascii_lowercase();
 let end=["### reproduksi","## reproduksi","### reproduction","### exploit",
   "### fix","## fix","### perbaikan","### solusi","**fix**","**perbaikan**"]
   .iter().filter_map(|tag|lower.find(tag)).min().unwrap_or(answer.len());
 let prefix=&answer[..end];
 // Only PHP-tagged fences claim to reproduce source. Textual path
 // diagrams, HTTP transcripts and shell commands are not source quotations.
 let start=lower[..end].find("```php")?;
 let remaining=&prefix[start..];let newline=remaining.find('\n')?;
 let content=&remaining[newline+1..];let finish=content.find("```")?;
 Some(content[..finish].to_owned())
}
pub fn inspect(source:&str,answer:&str)->Value{
 let original_vars=vars(source);
 let snippet=pre_fix_code(answer);
 let mut missing_vars=Vec::new();let mut unmatched_lines=Vec::new();
 let original_lines=source.lines().map(normalize).collect::<Vec<_>>();
 if let Some(ref snippet)=snippet{
   for symbol in vars(snippet){
      if !original_vars.contains(&symbol){missing_vars.push(symbol);}
   }
   for line in snippet.lines(){
      let trim=line.trim();
      if trim.is_empty()||matches!(trim,"{"|"}"|"..."|"<?php")||
         trim.starts_with("//")||trim.starts_with("/*")||trim.starts_with("*")||
         trim.contains("..."){continue;}
      let fixed=normalize(trim.split(" //").next().unwrap_or(trim));
      if fixed.len()<9{continue;}
      if !original_lines.iter().any(|l|l==&fixed || l.contains(&fixed)){
         unmatched_lines.push(trim.chars().take(200).collect::<String>());
      }
   }
 }
 let lower=answer.to_ascii_lowercase();
 let false_identifier_claim=!missing_vars.is_empty() &&
    ["undefined variable","typo","variable naming error","undeclared",
     "variabel tidak ada","salah ketik","not defined"]
     .iter().any(|x|lower.contains(x));
 let contradiction=false_identifier_claim || !unmatched_lines.is_empty();
 let verdict=if contradiction{"contradicted_source"}
     else if snippet.is_some(){"quoted_source_matches"}
     else{"no_source_quote_to_anchor"};
 json!({
     "verdict":verdict,
     "source_quote_found":snippet.is_some(),
     "unanchored_identifiers_in_claimed_code":missing_vars,
     "quoted_lines_not_present_in_source":unmatched_lines,
     "specific_undefined_identifier_claim_refuted":false_identifier_claim,
     "e2e_exploit_proven":false,
     "safe_to_auto_publish":false,
     "limitations":"Only checks the first PHP code quote before reproduction/fix sections against source variables and lines. An exact code match does not prove security impact. Additional PoCs or paraphrased claims need review."
 })
}
#[cfg(test)]
mod tests{
 use super::*;
 #[test]fn fabricated_identifier(){
  let src="<?php\nfunction f(int $amountCents){\nif ($amountCents < 1 || $amountCents > 500000) throw new Exception();\n}";
  let answer="### The Bug\n```php\nif ($amountCents < 1 || $amountCts > 500000) throw new Exception();\n```\nThe undefined variable $amountCts is a typo.";
  let out=inspect(src,answer);
  assert_eq!(out["verdict"],"contradicted_source");
  assert_eq!(out["specific_undefined_identifier_claim_refuted"],true);
 }
 #[test]fn exact_quote_is_not_exploit_proof(){
  let src="<?php\n$org = $this->normalizeOrg($request['organization'] ?? null);";
  let out=inspect(src,"## Bug\n```php\n$org = $this->normalizeOrg($request['organization'] ?? null);\n```\nPotential issue.");
  assert_eq!(out["verdict"],"quoted_source_matches");
  assert_eq!(out["e2e_exploit_proven"],false);
 }
 #[test]fn textual_path_diagram_is_not_claimed_source(){
  let src="<?php\n$path = rawurldecode($input);";
  let ans="Proof:\n```text\nnorth/reports/../../south/private\n→ south/private\n```";
  assert_eq!(inspect(src,ans)["verdict"],"no_source_quote_to_anchor");
 }
 #[test]fn no_quote_needs_review(){
  assert_eq!(inspect("<?php\n$a=1;","There is a bug.")["verdict"],"no_source_quote_to_anchor");
 }
}
