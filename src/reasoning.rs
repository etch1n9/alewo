//! Evidence-grounded symbolic reasoning ledger (@ALEWO-THINK/2).
//!
//! This is deliberately not a vulnerability scanner. The model records only
//! source observations it has already read, in a compact, domain-neutral
//! transition language. The ledger then ranks *questions* by information gain
//! per cost; it never labels code vulnerable and never matches CVE patterns.
//!
//! A fact is (anchor, state, role, delta, guard):
//!   role: R=read, W=write, G=guard, C=cleanup/rollback, E=external boundary.
//! Repeated state across different anchors creates a contrast obligation.
//!
//! Priority is an operational allocation score, not a probability of a bug:
//!   IG/C = H(p_s) * N(a_s) * D(r_s) * X(s) / (1 + K)
//!   p_s=(n_s+0.5)/(n_s+1), H=-p ln p-(1-p) ln(1-p)
//!   N=1-exp(-a_s/2) anchor novelty; D=0.25+role diversity
//!   X=1+weighted cross-role interaction; K=facts/8 cost proxy
//! A high score requests the smallest discriminating next observation.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_FACTS: usize = 12;
const MAX_COMMITS: usize = 96;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fact {
    pub a: String,
    pub s: String,
    pub r: String,
    pub d: String,
    pub g: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StateLedger {
    pub observations: usize,
    pub commits: usize,
    pub debt: usize,
    pub facts: Vec<Fact>,
}

fn compact(value: &str, field: &str, max: usize) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.contains('\n') || value.contains('\r') {
        return Err(format!("thinking_commit {field} must be non-empty, single-line, and <= {max} chars"));
    }
    Ok(value.to_owned())
}

fn read_facts(args: &Value) -> Result<Vec<Fact>, String> {
    let rows = args["f"].as_array().ok_or("thinking_commit requires f: non-empty fact array")?;
    if rows.is_empty() || rows.len() > MAX_FACTS {
        return Err(format!("thinking_commit f must contain 1..{MAX_FACTS} facts"));
    }
    let mut facts = Vec::with_capacity(rows.len());
    for row in rows {
        let a = compact(row["a"].as_str().ok_or("fact.a missing")?, "fact.a", 180)?;
        let s = compact(row["s"].as_str().ok_or("fact.s missing")?, "fact.s", 120)?;
        let r = row["r"].as_str().unwrap_or("");
        if !matches!(r, "R" | "W" | "G" | "C" | "E") {
            return Err("fact.r must be one of R,W,G,C,E".into());
        }
        let d = compact(row["d"].as_str().unwrap_or("-"), "fact.d", 160)?;
        let g = compact(row["g"].as_str().unwrap_or("-"), "fact.g", 160)?;
        facts.push(Fact { a, s, r: r.into(), d, g });
    }
    Ok(facts)
}

impl StateLedger {
    pub fn note_source_observation(&mut self, tool: &str) {
        if matches!(tool, "ws_read" | "ws_read_multi" | "ws_read_symbol" | "ws_slice") {
            self.observations += 1;
            self.debt = self.debt.saturating_add(1);
        }
    }

    pub fn commit(&mut self, args: &Value) -> Result<String, String> {
        if self.commits >= MAX_COMMITS {
            return Err(format!("thinking_commit limit reached ({MAX_COMMITS}); synthesize or start a new cycle"));
        }
        let facts = read_facts(args)?;
        let q = compact(args["q"].as_str().ok_or("thinking_commit requires q: smallest discriminating next question")?, "q", 240)?;
        let n = compact(args["n"].as_str().ok_or("thinking_commit requires n: next tool/action code")?, "n", 240)?;
        let mut states = BTreeSet::new();
        let mut roles = BTreeMap::<String, BTreeSet<String>>::new();
        let mut anchors = BTreeMap::<String, BTreeSet<String>>::new();
        for fact in &self.facts {
            roles.entry(fact.s.clone()).or_default().insert(fact.r.clone());
            anchors.entry(fact.s.clone()).or_default().insert(fact.a.clone());
        }
        for fact in &facts {
            states.insert(fact.s.clone());
            roles.entry(fact.s.clone()).or_default().insert(fact.r.clone());
            anchors.entry(fact.s.clone()).or_default().insert(fact.a.clone());
        }

        let mut highest = 0.0f64;
        let mut ranked = Vec::<(String,f64)>::new();
        let mut coupled = Vec::new();
        for state in &states {
            let r = roles.get(state).map_or(0, BTreeSet::len);
            let a = anchors.get(state).map_or(0, BTreeSet::len);
            let role_set = roles.get(state).cloned().unwrap_or_default();
            let prior = self.facts.iter().filter(|f| f.s == *state).count() as f64;
            // Bayesian uncertainty × binary entropy: uncertainty is high for a
            // state seen once, while entropy avoids over-rewarding already settled
            // states. Novelty and cross-role interaction estimate information gain.
            let posterior=(prior+0.5)/(prior+1.0);
            let entropy=-(posterior*posterior.ln()+(1.0-posterior)*(1.0-posterior).ln());
            let novelty=1.0-(-(a as f64)/2.0).exp();
            let diversity=0.25+((r.saturating_sub(1)) as f64/4.0).min(1.0);
            let interaction=1.0
                + if role_set.contains("W") { 0.35 } else { 0.0 }
                + if role_set.contains("C") { 0.55 } else { 0.0 }
                + if role_set.contains("E") { 0.45 } else { 0.0 }
                + if a >= 2 { 0.35 } else { 0.0 };
            let cost=1.0+facts.len() as f64/8.0;
            let score=entropy*novelty*diversity*interaction/cost;
            if score>highest {highest=score;}
            ranked.push((state.clone(),score));
            if a >= 2 && role_set.contains("W") && (role_set.contains("C") || role_set.contains("R")) {
                coupled.push(state.clone());
            }
        }
        ranked.sort_by(|a,b|b.1.total_cmp(&a.1).then_with(||a.0.cmp(&b.0)));
        self.facts.extend(facts);
        if self.facts.len() > 384 {
            let excess = self.facts.len() - 384;
            self.facts.drain(0..excess);
        }
        self.commits += 1;
        self.debt = 0;
        let coupling = if coupled.is_empty() { "-".into() } else { coupled.join(",") };
        let rank = ranked.into_iter().take(6)
            .map(|(state,score)|format!("{state}:{score:.3}")).collect::<Vec<_>>().join(",");
        Ok(format!(
            "@ALEWO-THINK/2|F={}|S={}|IGC={:.3}|RANK={}|COUPLED={}|Q={}|NEXT={}",
            self.facts.len(), states.len(), highest, rank, coupling, q, n
        ))
    }

    pub fn directive(&self) -> Option<String> {
        if self.debt < 2 {
            return None;
        }
        let known_states = self.facts.iter().map(|f| f.s.as_str()).collect::<BTreeSet<_>>();
        Some(format!(
            "@ALEWO-THINK/2|DEBT={}|KNOWN={}|ACT=commit source-derived transition facts before pivoting. Encode f=[{{a,s,r,d,g}}], r∈R/W/G/C/E; choose Q as the smallest observation that can disprove the current relation. No prose, no verdict.",
            self.debt,
            if known_states.is_empty() { "-".into() } else { known_states.into_iter().take(12).collect::<Vec<_>>().join(",") }
        ))
    }

    pub fn summary(&self) -> Value {
        json!({
            "schema": "@ALEWO-THINK/2",
            "commits": self.commits,
            "source_observations": self.observations,
            "uncommitted_observations": self.debt,
            "facts": self.facts.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_ledger_detects_relation_without_classifying_a_bug() {
        let mut ledger = StateLedger::default();
        ledger.note_source_observation("ws_read_symbol");
        ledger.note_source_observation("ws_read_symbol");
        assert!(ledger.directive().unwrap().contains("DEBT=2"));
        let output = ledger.commit(&json!({
            "f":[
                {"a":"a.c:10","s":"conn.credit","r":"W","d":"-n","g":"n<=credit"},
                {"a":"b.c:20","s":"conn.credit","r":"C","d":"+refund","g":"cleanup"}
            ],
            "q":"is refund bounded by the pre-send debit?",
            "n":"read sibling cleanup and limit guards"
        })).unwrap();
        assert!(output.contains("COUPLED=conn.credit"));
        assert!(output.contains("IGC="));
        assert_eq!(ledger.debt, 0);
    }

    #[test]
    fn rejects_unanchored_or_non_symbolic_roles() {
        let mut ledger=StateLedger::default();
        assert!(ledger.commit(&json!({"f":[{"a":"","s":"x","r":"W","d":"1","g":"-"}],"q":"q","n":"n"})).is_err());
        assert!(ledger.commit(&json!({"f":[{"a":"x:1","s":"x","r":"X","d":"1","g":"-"}],"q":"q","n":"n"})).is_err());
    }
}
