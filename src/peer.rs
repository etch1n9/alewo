//! Compact two-agent deliberation for Alewo.
//!
//! Agent A owns tools and the durable investigation. Agent B is a skeptical
//! peer: it receives only compact evidence, the mathematical attention
//! schedule, and A's observable actions. It cannot execute tools or assert a
//! finding. Its output is injected back into A as a falsifiable critique.
//! This is deliberately generic and contains no CVE, repository, language, or
//! vulnerability signatures.

use crate::{controller::InvestigationController, provider};
use serde_json::{json, Value};

#[derive(Clone, Debug, Default)]
pub struct PeerUsage {
    pub calls: usize,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub reasoning_tokens: u64,
    pub seconds: f64,
}

pub fn debate_pressure(controller:&InvestigationController)->f64{
    let schedule=controller.attention_schedule(8);
    if schedule.len()<2{return 0.0;}
    let max=schedule.iter().map(|(_,s)|*s).fold(f64::NEG_INFINITY,f64::max);
    let weights=schedule.iter().map(|(_,s)|(*s-max).exp()).collect::<Vec<_>>();
    let z=weights.iter().sum::<f64>().max(1e-12);
    let entropy=weights.iter().map(|w|{
        let p=*w/z;
        if p<=0.0{0.0}else{-p*p.ln()}
    }).sum::<f64>()/(schedule.len() as f64).ln().max(1e-12);
    let stagnation=controller.stagnation as f64/(controller.stagnation as f64+3.0);
    let debt=controller.thinking.debt as f64/(controller.thinking.debt as f64+2.0);
    (0.45*entropy+0.35*stagnation+0.20*debt).clamp(0.0,1.0)
}

pub fn consult_value(
    controller:&InvestigationController,
    calls:usize,
    helped:usize,
    average_tokens:f64,
)->f64{
    let posterior=(helped as f64+1.0)/(calls as f64+2.0);
    let token_cost=0.12*(average_tokens/12_000.0).min(2.0);
    debate_pressure(controller)*posterior-token_cost
}

pub fn should_consult(
    controller:&InvestigationController,
    calls:usize,
    helped:usize,
    average_tokens:f64,
    rounds_since_peer:usize,
)->bool{
    if !controller.focus_ready()||rounds_since_peer<3{return false;}
    if calls==0{
        debate_pressure(controller)>=0.58
    }else{
        consult_value(controller,calls,helped,average_tokens)>=0.18
    }
}

fn compact_recent(messages:&[Value])->String{
    let mut chunks=messages.iter().rev()
        .filter(|m|m["role"]=="tool")
        .filter_map(|m|m["content"].as_str())
        .take(4)
        .map(|s|s.chars().take(1400).collect::<String>())
        .collect::<Vec<_>>();
    chunks.reverse();
    if chunks.is_empty(){"-".into()}else{chunks.join("\n---\n")}
}

pub fn consult(
    key:&str,
    model:&str,
    task:&str,
    controller:&InvestigationController,
    messages:&[Value],
    previous:&str,
)->Result<(String,PeerUsage),String>{
    let pressure=debate_pressure(controller);
    let schedule=controller.attention_schedule(8).into_iter()
        .map(|(p,s)|format!("{p}:{s:.3}")).collect::<Vec<_>>().join(",");
    let system="You are ALEWO Peer B, a skeptical reasoning partner. Agent A owns all tools and execution. You receive only observed evidence and a domain-neutral attention schedule. Challenge anchoring, compare competing explanations, and propose the smallest observation that can falsify the current lead. Never infer a vulnerability from names, never use CVE knowledge, never invent source facts, and never claim a finding. Keep the response under 900 characters and use exactly: @ALEWO-PEER/1|STANCE=approve_or_challenge|RISK=...|ALT=...|FALSIFY=...|STOP=...";
    let user=format!(
        "TASK={task}\nPRESSURE={pressure:.3}\n{}\nSCHEDULE={schedule}\nPREVIOUS_PEER={}\nRECENT_OBSERVED_TOOL_EVIDENCE:\n{}",
        controller.packet(),
        if previous.is_empty(){"-"}else{previous},
        compact_recent(messages)
    );
    let body=json!({
        "model":model,
        "messages":[
            {"role":"system","content":system},
            {"role":"user","content":user}
        ],
        "temperature":1.0,
        "top_p":0.95,
        "seed":1,
        "reasoning_effort":provider::MAX_REASONING_EFFORT,
        "stream":true,
        "stream_options":{"include_usage":true}
    });
    let (res,seconds)=provider::send_chat_stream(key,&body)?;
    let choice=res["choices"].get(0).ok_or("peer response missing choices")?;
    let raw=choice["message"]["content"].as_str().unwrap_or("").trim();
    if raw.is_empty(){return Err("peer returned empty advice".into());}
    let advice=if raw.starts_with("@ALEWO-PEER/1|"){
        raw.chars().take(1400).collect::<String>()
    }else{
        format!("@ALEWO-PEER/1|STANCE=challenge|RISK=nonconforming_peer_output|ALT=-|FALSIFY={}|STOP=-",
            raw.chars().take(700).collect::<String>().replace('\n'," "))
    };
    let usage=&res["usage"];
    Ok((advice,PeerUsage{
        calls:1,
        prompt_tokens:usage["prompt_tokens"].as_u64().unwrap_or(0),
        completion_tokens:usage["completion_tokens"].as_u64().unwrap_or(0),
        total_tokens:usage["total_tokens"].as_u64().unwrap_or(0),
        reasoning_tokens:usage["completion_tokens_details"]["reasoning_tokens"].as_u64().unwrap_or(0),
        seconds,
    }))
}

#[cfg(test)]
mod tests{
    use super::*;
    use serde_json::json;

    #[test]
    fn debate_pressure_is_mathematical_and_domain_neutral(){
        let mut c=InvestigationController::new("peer",&[],&["a.c".into(),"b.c".into()]);
        assert_eq!(debate_pressure(&c),0.0);
        c.record_focus(&json!({"items":[
            {"p":"a.c","e":3,"m":3,"c":3,"u":3,"k":2,"w":"A"},
            {"p":"b.c","e":3,"m":3,"c":3,"u":3,"k":2,"w":"B"}
        ]})).unwrap();
        assert!(debate_pressure(&c)>0.40);
        assert!(!should_consult(&c,0,0,0.0,2));
        c.stagnation=3;
        c.thinking.debt=2;
        assert!(should_consult(&c,0,0,0.0,3));
        assert!(consult_value(&c,2,2,2_000.0)>consult_value(&c,2,0,20_000.0));
    }

    #[test]
    fn recent_evidence_is_bounded(){
        let messages=vec![
            json!({"role":"tool","content":"x".repeat(5000)}),
            json!({"role":"assistant","content":"ignored"}),
        ];
        assert!(compact_recent(&messages).len()<=1400);
    }
}
