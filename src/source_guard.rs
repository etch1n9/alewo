//! Conservative post-response source-quote verification.
//! Flags near matches in claimed source snippets. Does not decide exploitability.
use serde_json::{json,Value};

fn compact(s:&str)->String{s.chars().filter(|c|!c.is_whitespace()).collect::<String>()}
fn edit_distance(a:&[u8],b:&[u8])->usize{
    let mut prev=(0..=b.len()).collect::<Vec<_>>();
    let mut curr=vec![0; b.len()+1];
    for (i,&ca) in a.iter().enumerate(){
        curr[0]=i+1;
        for (j,&cb) in b.iter().enumerate(){
            let replace=prev[j]+usize::from(ca!=cb);
            let remove=prev[j+1]+1;
            let insert=curr[j]+1;
            curr[j+1]=replace.min(remove).min(insert);
        }
        std::mem::swap(&mut curr,&mut prev);
    }
    prev[b.len()]
}
fn generated_section(header:&str)->bool{
    let h=header.to_ascii_lowercase();
    ["perbaikan","fix","mitigation","remediation","solution",
     "reproduksi","reproduction","poc","proof of concept","regression"]
        .iter().any(|k|h.contains(k))
}
pub fn check(source:&str,answer:&str)->Value{
    let src=source.lines().enumerate()
        .filter_map(|(i,line)|{
            let c=compact(line);
            if c.len()<26 || c.len()>420 {None}else{Some((i+1,line.trim().to_string(),c))}
        }).take(12_000).collect::<Vec<_>>();
    let mut in_fence=false;
    let mut generated=false;
    let mut visited=0usize;
    let mut exact=0usize;
    let mut near=Vec::new();
    for line in answer.lines(){
        let s=line.trim();
        if s.starts_with('#') && s.trim_start_matches('#').starts_with(' ') && generated_section(s){
            generated=true;
        }
        if s.starts_with("\x60\x60\x60"){in_fence=!in_fence;continue;}
        if !in_fence || generated || visited>=50 {continue;}
        if s.len()<30 || s.starts_with("//") || s.starts_with('#') || s=="..." || s=="…" {continue;}
        let text=compact(s);
        if text.len()<26||text.len()>420{continue;}
        visited+=1;
        if src.iter().any(|(_,_,original)|original==&text){
            exact+=1;
            continue;
        }
        let mut best=(0.0f64,0usize,"");
        for (no,orig,original) in &src{
            if original.len().abs_diff(text.len())>32 {continue;}
            if !original.bytes().take(12).eq(text.bytes().take(12)){continue;}
            let denom=original.len().max(text.len());
            let distance=edit_distance(original.as_bytes(),text.as_bytes());
            let score=1.0-distance as f64/denom as f64;
            if score>best.0{best=(score,*no,orig)}
        }
        if best.0>=0.91 {
            near.push(json!({"quoted":s,"closest_source_line":best.1,
                "actual":best.2,"similarity":(best.0*1000.0).round()/1000.0}));
        }
    }
    json!({"quoted_evidence_lines_examined":visited,"exact_matches":exact,
        "near_match_mismatches":near,
        "purpose":"Review flags only. Does not certify exploitability or automatically reject a model answer.",
        "no_prompt_change":true})
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn catches_fabricated_typo(){
        let s="<?php\nif ($amountCents < 1 || $amountCents > 500000) throw new InvalidArgumentException('amount');\n";
        let a="# The bug\n\x60\x60\x60php\nif ($amountCents < 1 || $amountCts > 500000) throw new InvalidArgumentException('amount');\n\x60\x60\x60\n";
        let result=check(s,a);
        assert_eq!(result["exact_matches"],0);
        assert_eq!(result["near_match_mismatches"].as_array().unwrap().len(),1);
    }
    #[test]
    fn does_not_flag_real_quote(){
        let s="<?php\n$org = $this->normalizeOrg($request['organization'] ?? null);\n";
        let a="# Bug\n\x60\x60\x60php\n$org = $this->normalizeOrg($request['organization'] ?? null);\n\x60\x60\x60\n";
        let result=check(s,a);
        assert_eq!(result["exact_matches"],1);
        assert!(result["near_match_mismatches"].as_array().unwrap().is_empty());
    }
    #[test]
    fn remediation_not_a_source_quote(){
        let s="<?php\n$org = $this->normalizeOrg($request['organization'] ?? null);\n";
        let a="### Perbaikan\n\x60\x60\x60php\n$org = $this->normalizeOrg($claims['org'] ?? null);\n\x60\x60\x60\n";
        assert!(check(s,a)["near_match_mismatches"].as_array().unwrap().is_empty());
    }
}
