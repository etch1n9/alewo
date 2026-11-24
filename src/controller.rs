//! Deterministic investigation state outside the model context.
//!
//! The controller does not decide that code is safe. It records what the model
//! inspected, exposes silent coverage gaps, and emits compact pivot directives.

use crate::reasoning::StateLedger;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Unseen,
    Mapped,
    Inspected,
    Tested,
    EvidenceComplete,
    Unresolved,
}

impl CoverageStatus {
    fn rank(self) -> u8 {
        match self {
            Self::Unseen => 0,
            Self::Mapped => 1,
            Self::Inspected => 2,
            Self::Tested => 3,
            Self::EvidenceComplete => 4,
            Self::Unresolved => 1,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Unseen => "U",
            Self::Mapped => "M",
            Self::Inspected => "I",
            Self::Tested => "T",
            Self::EvidenceComplete => "E",
            Self::Unresolved => "?",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageNode {
    pub path: String,
    pub status: CoverageStatus,
    pub touches: u64,
    pub last_tool: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub statement: String,
    pub invariant: String,
    pub disconfirming_test: String,
    pub status: String,
    pub evidence: Vec<String>,
    pub resolved_by: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolObservation {
    pub round: usize,
    pub tool: String,
    pub path: Option<String>,
    pub ok: bool,
    pub bytes: usize,
    pub new_coverage: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FocusPriority {
    pub path: String,
    pub external_reachability: u8,
    pub state_mutation: u8,
    pub structural_centrality: u8,
    pub uncertainty: u8,
    pub read_cost: u8,
    pub score: f64,
    pub why: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvestigationController {
    pub schema: String,
    pub run_id: String,
    pub created_at: i64,
    pub phase: String,
    pub nodes: BTreeMap<String, CoverageNode>,
    pub hypotheses: Vec<Hypothesis>,
    pub tools: Vec<ToolObservation>,
    pub stagnation: usize,
    pub verified_finding: bool,
    pub inventory_truncated: bool,
    #[serde(default)]
    pub thinking: StateLedger,
    #[serde(default)]
    pub focus: BTreeMap<String, FocusPriority>,
    /// The first focus-ranked source unit actually read by the model.
    /// Navigation may stay within its immediate source directory until the
    /// candidate is verified or explicitly disproved.
    #[serde(default)]
    pub active_candidate: Option<String>,
    #[serde(default)]
    pub candidate_closed: bool,
    #[serde(default)]
    pub source_verified_candidate: Option<String>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn clean_path(raw: &str) -> Option<String> {
    let value = raw.trim().replace('\\', "/");
    if value.is_empty() || value == "." || value.starts_with('/') || value.contains("..") {
        None
    } else {
        Some(value)
    }
}

/// Information-allocation score. The axes are supplied by the model from its
/// structural reading; this function never inspects source text or recognizes
/// vulnerability signatures. Binary entropy rewards unresolved questions while
/// the interaction term rewards candidates whose dimensions reinforce one
/// another. The super-linear cost keeps expensive reads from dominating.
fn attention_priority(e: u8, m: u8, c: u8, u: u8, k: u8) -> f64 {
    let (e,m,c,u)=(e as f64/4.0,m as f64/4.0,c as f64/4.0,u as f64/4.0);
    let p=(u*4.0+1.0)/6.0;
    let entropy=-(p*p.ln()+(1.0-p)*(1.0-p).ln());
    let interaction=1.0+(m*c+e*u)/2.0;
    let gain=(1.0+e)*(1.0+m)*(1.0+c)*(1.0+u)
        *(1.0+entropy)*interaction;
    gain/(1.0+k as f64).powf(1.5)
}

impl InvestigationController {
    pub fn new(
        run_id: impl Into<String>,
        candidates: &[String],
        other_files: &[String],
    ) -> Self {
        let mut nodes = BTreeMap::new();
        for path in candidates {
            nodes.insert(
                path.clone(),
                CoverageNode {
                    path: path.clone(),
                    status: CoverageStatus::Mapped,
                    touches: 0,
                    last_tool: "entrygraph".into(),
                },
            );
        }
        for path in other_files {
            nodes.entry(path.clone()).or_insert_with(|| CoverageNode {
                path: path.clone(),
                status: CoverageStatus::Unseen,
                touches: 0,
                last_tool: String::new(),
            });
        }
        Self {
            schema: "@ALEWO-CTRL/1".into(),
            run_id: run_id.into(),
            created_at: now(),
            phase: "inventory".into(),
            nodes,
            hypotheses: Vec::new(),
            tools: Vec::new(),
            stagnation: 0,
            verified_finding: false,
            inventory_truncated: false,
            thinking: StateLedger::default(),
            focus: BTreeMap::new(),
            active_candidate: None,
            candidate_closed: false,
            source_verified_candidate: None,
        }
    }

    fn touch_node(&mut self,path:&str,status:CoverageStatus,tool:&str)->bool{
        let node=self.nodes.entry(path.to_string()).or_insert_with(||CoverageNode{
            path:path.to_string(),status:CoverageStatus::Unseen,touches:0,last_tool:String::new()
        });
        let advanced=status.rank()>node.status.rank();
        if advanced{node.status=status;}
        node.touches+=1;
        node.last_tool=tool.to_string();
        advanced
    }

    pub fn record_tool(
        &mut self,
        round: usize,
        name: &str,
        args: &Value,
        ok: bool,
        result_bytes: usize,
    ) {
        let target_status = match name {
            "ws_php_test" | "ws_path_matrix" | "ws_state_matrix" => CoverageStatus::Tested,
            "ws_read" | "ws_read_multi" | "ws_read_symbol" | "ws_slice" | "ws_file_outline" => {
                CoverageStatus::Inspected
            }
            "ws_list" | "ws_tree" | "ws_search" | "ws_grep" | "ws_symbol_index"
            | "ws_callers" | "ws_paths" | "ws_flow_map" | "ws_ast_scan" | "ws_mutations" => {
                CoverageStatus::Mapped
            }
            _ => CoverageStatus::Unseen,
        };
        let mut paths=Vec::<String>::new();
        if let Some(path)=args.get("path").and_then(Value::as_str).and_then(clean_path){
            paths.push(path);
        }
        if name=="ws_read_multi"{
            if let Some(slices)=args["slices"].as_array().or_else(||args["paths"].as_array()){
                for item in slices{
                    let raw=item["path"].as_str().or_else(||item.as_str());
                    if let Some(path)=raw.and_then(clean_path){paths.push(path);}
                }
            }
        }
        if name=="ws_read_symbol"{
            if let (Some(path),Some(symbol))=(args["path"].as_str().and_then(clean_path),
                args["symbol"].as_str().map(str::trim).filter(|s|!s.is_empty())){
                paths.push(format!("symbol::{path}#{}",symbol.chars().take(120).collect::<String>()));
            }
        }else if name=="ws_callers"{
            if let Some(symbol)=args["symbol"].as_str().map(str::trim).filter(|s|!s.is_empty()){
                paths.push(format!("symbol::{}",symbol.chars().take(160).collect::<String>()));
            }
        }else if name=="ws_paths"{
            if let (Some(from),Some(to))=(args["from"].as_str(),args["to"].as_str()){
                paths.push(format!("flow::{}->{}",from.chars().take(100).collect::<String>(),
                    to.chars().take(100).collect::<String>()));
            }
        }
        paths.sort();paths.dedup();
        let path=paths.first().cloned();
        let mut new_coverage = false;
        if ok {
            self.thinking.note_source_observation(name);
            if let Some(path) = paths.iter().find(|path| self.focus.contains_key(*path)) {
                if self.active_candidate.is_none() || self.candidate_closed {
                    self.active_candidate=Some(path.clone());
                    self.candidate_closed=false;
                    self.source_verified_candidate=None;
                }
            }
            for item in &paths{
                new_coverage|=self.touch_node(item,target_status,name);
            }
            if paths.is_empty()&&matches!(name, "ws_ast_scan" | "ws_flow_map") {
                for node in self.nodes.values_mut() {
                    if node.status == CoverageStatus::Unseen {
                        node.status = CoverageStatus::Mapped;
                        new_coverage = true;
                    }
                }
            }
        }
        self.stagnation = if new_coverage { 0 } else { self.stagnation + 1 };
        self.phase = if self.tools.is_empty() {
            "entrypoint_map".into()
        } else if self.tested_count() > 0 {
            "adversarial_verification".into()
        } else {
            "hypothesis_generation".into()
        };
        self.tools.push(ToolObservation {
            round,
            tool: name.to_string(),
            path,
            ok,
            bytes: result_bytes,
            new_coverage,
        });
    }

    pub fn add_hypothesis(
        &mut self,
        statement: &str,
        invariant: &str,
        disconfirming_test: &str,
    ) -> String {
        let digest = format!(
            "{:x}",
            Sha256::digest(
                format!("{statement}\n{invariant}\n{disconfirming_test}").as_bytes()
            )
        );
        let id = format!("H{}", &digest[..8]);
        if !self.hypotheses.iter().any(|h| h.id == id) {
            self.hypotheses.push(Hypothesis {
                id: id.clone(),
                statement: statement.chars().take(300).collect(),
                invariant: invariant.chars().take(240).collect(),
                disconfirming_test: disconfirming_test.chars().take(240).collect(),
                status: "open".into(),
                evidence: Vec::new(),
                resolved_by: None,
            });
        }
        id
    }

    #[allow(dead_code)]
    pub fn resolve_hypothesis(
        &mut self,
        id: &str,
        status: &str,
        evidence: &[String],
        resolved_by: Option<String>,
    ) -> Result<(), String> {
        let h = self
            .hypotheses
            .iter_mut()
            .find(|h| h.id == id)
            .ok_or_else(|| format!("hypothesis not found: {id}"))?;
        h.status = status.to_string();
        h.evidence = evidence.iter().take(12).cloned().collect();
        h.resolved_by = resolved_by;
        Ok(())
    }

    pub fn record_focus(&mut self, args: &Value) -> Result<String, String> {
        let items=args["items"].as_array().ok_or("focus_rank requires items")?;
        if items.is_empty() || items.len()>32 {
            return Err("focus_rank requires 1..32 ranked production candidates".into());
        }
        let axis=|row:&Value,key:&str,min:u64|->Result<u8,String>{
            let value=row[key].as_u64().ok_or_else(||format!("focus_rank item missing {key}"))?;
            if value<min || value>4 {return Err(format!("focus_rank {key} must be {min}..4"));}
            Ok(value as u8)
        };
        let mut accepted=Vec::new();
        for row in items {
            let path=clean_path(row["p"].as_str().ok_or("focus_rank item missing p")?)
                .ok_or("focus_rank p must be a relative workspace path")?;
            if !self.nodes.contains_key(&path) {
                return Err(format!("focus_rank path is not in the structural inventory: {path}"));
            }
            let e=axis(row,"e",0)?;
            let m=axis(row,"m",0)?;
            let c=axis(row,"c",0)?;
            let u=axis(row,"u",0)?;
            let k=axis(row,"k",1)?;
            let why=row["w"].as_str().unwrap_or("-").trim();
            if why.is_empty() || why.len()>120 || why.contains('\n') {
                return Err("focus_rank w must be a compact single-line evidence code".into());
            }
            // Attention priority, not defect probability:
            // P=[Π(1+x/4)]·[1+H((U+1)/6)]·[1+(M·C+E·U)/2]/(1+K)^1.5.
            let score=attention_priority(e,m,c,u,k);
            self.focus.insert(path.clone(),FocusPriority{
                path:path.clone(),external_reachability:e,state_mutation:m,
                structural_centrality:c,uncertainty:u,read_cost:k,
                score,why:why.to_string()
            });
            accepted.push((path,score));
        }
        accepted.sort_by(|a,b|b.1.total_cmp(&a.1).then_with(||a.0.cmp(&b.0)));
        Ok(format!("@ALEWO-FOCUS/1|N={}|TOP={}",
            accepted.len(),accepted.into_iter().take(12)
                .map(|(p,s)|format!("{p}:{s:.2}")).collect::<Vec<_>>().join(",")))
    }

    pub fn focus_ready(&self)->bool{!self.focus.is_empty()}

    pub fn focus_directive(&self)->Option<String>{
        if self.focus_ready(){return None;}
        Some("@ALEWO-FOCUS/1|ACT=focus_rank|SHAPE={items:[{p,e,m,c,u,k,w}]}|RULE=Before source reads, select 8..24 production candidates from the structural map. AI supplies E,M,C,U in 0..4 and read cost K in 1..4; controller computes P from normalized axes, binary entropy H((U+1)/6), cross-axis interaction, and super-linear read cost: P=[Π(1+x/4)]·[1+H]·[1+(M·C+E·U)/2]/(1+K)^1.5. Rank attention only; do not claim a defect. Do not follow alphabetical inventory order.".into())
    }

    /// Navigation is gated only on completing the model's structural ranking.
    /// Candidate allocation itself is soft and mathematical: a wrong first lead
    /// must remain cheap to park, while unresolved high-value leads accumulate
    /// closure debt and return to the schedule.
    pub fn navigation_guard(&self, name: &str, _args: &Value) -> Result<(), String> {
        if name.starts_with("ws_") && self.focus.is_empty() {
            Err("@ALEWO-FOCUS/1 required before workspace navigation; call focus_rank from the structural map".into())
        } else {
            Ok(())
        }
    }

    /// A score for the next observation, not vulnerability probability.
    /// A_i = .60 B_i + sqrt(2 ln(2+N)/(1+n_i))
    ///       + .40/sqrt(1+n_i) + .40 ln(1+n_i) * inspected_i
    ///       + 1.10 * active_open_i - .08 K_i.
    /// Smooth diminishing novelty plus completion reward avoid the sharp
    /// inspected/unseen cliff; active commitment survives incidental cross-file
    /// reads. Closing a candidate releases that commitment.
    pub fn attention_schedule(&self, limit: usize) -> Vec<(String,f64)> {
        if self.focus.is_empty() { return Vec::new(); }
        let max_base=self.focus.values().map(|x|x.score).fold(0.0f64,f64::max).max(1e-9);
        let total=self.focus.values().map(|x|self.nodes.get(&x.path).map_or(0,|n|n.touches)).sum::<u64>();
        let mut ranked=self.focus.values().filter_map(|item|{
            let node=self.nodes.get(&item.path)?;
            if node.status==CoverageStatus::EvidenceComplete { return None; }
            let visits=node.touches as f64;
            let base=0.60*item.score/max_base;
            let explore=(2.0*((total+2) as f64).ln()/(1.0+visits)).sqrt();
            let novelty=0.40/(1.0+visits).sqrt();
            let is_closed_active = self.candidate_closed
                && self.active_candidate.as_deref() == Some(item.path.as_str());
            let debt=if node.status==CoverageStatus::Inspected && !is_closed_active {
                0.40*(1.0+visits).ln()
            } else {0.0};
            let commitment=if self.candidate_open() &&
                self.active_candidate.as_deref()==Some(item.path.as_str()) {
                1.10
            } else {0.0};
            let cost=0.08*item.read_cost as f64;
            Some((item.path.clone(),base+explore+novelty+debt+commitment-cost))
        }).collect::<Vec<_>>();
        ranked.sort_by(|a,b|b.1.total_cmp(&a.1).then_with(||a.0.cmp(&b.0)));
        ranked.truncate(limit);
        ranked
    }

    pub fn close_candidate(&mut self, args: &Value) -> Result<String, String> {
        let active = self.active_candidate.clone().ok_or("candidate_close requires an active focus-ranked source")?;
        let requested = clean_path(args["path"].as_str().unwrap_or(""))
            .ok_or("candidate_close path must be a relative workspace path")?;
        if requested != active {
            return Err(format!("candidate_close path must match active candidate {active}"));
        }
        let status = args["status"].as_str().unwrap_or("");
        match status {
            "verified" if self.verified_finding => {}
            "verified" => return Err("candidate_close verified requires E3 runtime-verified finding".into()),
            "source_verified" if self.source_verified_candidate.as_deref()==Some(active.as_str()) => {}
            "source_verified" => return Err("candidate_close source_verified requires E2 source verification for this active candidate and no runtime adapter".into()),
            "disproved" | "inconclusive" if !args["evidence"].as_str().unwrap_or("").trim().is_empty() => {}
            "disproved" | "inconclusive" => return Err("candidate_close requires explicit source-backed evidence or an unresolved limitation".into()),
            _ => return Err("candidate_close status must be verified, source_verified, disproved, or inconclusive".into()),
        }
        self.candidate_closed = true;
        self.phase = format!("candidate_{status}");
        Ok(format!("@ALEWO-CANDIDATE/1|CLOSED=1|STATUS={status}|PATH={active}"))
    }

    pub fn candidate_open(&self) -> bool {
        self.active_candidate.is_some() && !self.candidate_closed
    }

    pub fn record_thinking(&mut self, args: &Value) -> Result<String, String> {
        self.thinking.commit(args)
    }

    pub fn thinking_directive(&self) -> Option<String> {
        self.thinking.directive()
    }

    /// E2 proves anchor consistency, not execution or exploitability. It can
    /// release the active candidate, but must not set verified_finding or E3.
    #[allow(dead_code)]
    pub fn mark_source_verified(&mut self, evidence_paths: &[String]) {
        if self.active_candidate.as_ref().is_some_and(|p|evidence_paths.contains(p)) {
            self.source_verified_candidate=self.active_candidate.clone();
            self.phase="source_verified_e2".into();
        }
    }

    pub fn mark_verified_finding(&mut self, evidence_paths: &[String]) {
        self.verified_finding = true;
        if self.active_candidate.is_none() {
            self.active_candidate = evidence_paths.iter()
                .find(|path| self.focus.contains_key(*path)).cloned();
        }
        self.candidate_closed = true;
        self.phase = "finding_verified".into();
        for p in evidence_paths {
            if let Some(node) = self.nodes.get_mut(p) {
                node.status = CoverageStatus::EvidenceComplete;
            }
        }
    }

    pub fn unseen_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|n| n.status == CoverageStatus::Unseen)
            .count()
    }

    pub fn inspected_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|n| n.status.rank() >= CoverageStatus::Inspected.rank())
            .count()
    }

    pub fn tested_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|n| n.status.rank() >= CoverageStatus::Tested.rank())
            .count()
    }

    pub fn next_unseen(&self, limit: usize) -> Vec<String> {
        if self.focus.is_empty(){return Vec::new();}
        let mut ranked=self.focus.values()
            .filter(|item|self.nodes.get(&item.path)
                .is_some_and(|node|node.status.rank()<CoverageStatus::Inspected.rank()))
            .collect::<Vec<_>>();
        ranked.sort_by(|a,b|b.score.total_cmp(&a.score).then_with(||a.path.cmp(&b.path)));
        ranked.into_iter().take(limit).map(|item|item.path.clone()).collect()
    }

    pub fn packet(&self) -> String {
        let counts = self
            .nodes
            .values()
            .fold(BTreeMap::<&str, usize>::new(), |mut acc, node| {
                *acc.entry(node.status.code()).or_default() += 1;
                acc
            });
        let gaps = self.next_unseen(8);
        let schedule=self.attention_schedule(8);
        let open = self
            .hypotheses
            .iter()
            .filter(|h| h.status == "open")
            .map(|h| h.id.as_str())
            .collect::<Vec<_>>();
        format!(
            "@ALEWO-CTRL/1|RUN={}|PH={}|C={}|H={}|STAG={}|TRUNC={}|TH=C{}:D{}:F{}|CAND={}|CLOSED={}|SCHED={}|NEXT={}",
            self.run_id,
            self.phase,
            counts
                .iter()
                .map(|(k, v)| format!("{k}{v}"))
                .collect::<Vec<_>>()
                .join(","),
            if open.is_empty() { "-".into() } else { open.join(",") },
            self.stagnation,
            self.inventory_truncated,
            self.thinking.commits,
            self.thinking.debt,
            self.thinking.facts.len(),
            self.active_candidate.as_deref().unwrap_or("-"),
            self.candidate_closed as u8,
            if schedule.is_empty(){"-".into()}else{schedule.iter().map(|(p,s)|format!("{p}:{s:.2}")).collect::<Vec<_>>().join(",")},
            if self.focus.is_empty() {
                "FOCUS_RANK_REQUIRED".into()
            } else if gaps.is_empty() {
                "-".into()
            } else {
                gaps.join(",")
            }
        )
    }

    pub fn pivot_directive(&self) -> Option<String> {
        if self.stagnation < 3 {
            return None;
        }
        let schedule=self.attention_schedule(6);
        if schedule.is_empty() {
            Some("STAGNATION: challenge current assumptions with the smallest disconfirming observation; do not repeat the same read.".into())
        } else {
            Some(format!(
                "@ALEWO-PIVOT/1|NEXT={}|RULE=challenge the current hypothesis with the smallest discriminating source observation; close active candidate as verified, disproved, or inconclusive before switching investigations. Cross-file dependency tracing is allowed.",
                schedule.iter().map(|(p,s)|format!("{p}:{s:.2}")).collect::<Vec<_>>().join(",")
            ))
        }
    }

    pub fn summary(&self) -> Value {
        let unresolved = self
            .hypotheses
            .iter()
            .filter(|h| h.status == "open")
            .count();
        json!({
            "schema": self.schema,
            "run_id": self.run_id,
            "phase": self.phase,
            "coverage": {
                "total": self.nodes.len(),
                "unseen": self.unseen_count(),
                "inspected": self.inspected_count(),
                "tested": self.tested_count(),
            },
            "hypotheses": {
                "total": self.hypotheses.len(),
                "unresolved": unresolved,
            },
            "tool_observations": self.tools.len(),
            "stagnation": self.stagnation,
            "verified_finding": self.verified_finding,
            "active_candidate": self.active_candidate,
            "candidate_closed": self.candidate_closed,
            "source_verified_candidate": self.source_verified_candidate,
            "inventory_truncated":self.inventory_truncated,
            "thinking": self.thinking.summary(),
            "focus": {
                "ranked": self.focus.len(),
                "ready": self.focus_ready(),
                "formula": "P=[prod(1+x/4)]*[1+H((U+1)/6)]*[1+(M*C+E*U)/2]/(1+K)^1.5",
            },
            "attention_schedule":self.attention_schedule(20),
            "attention_policy":"A_i=.60*normalized_base+sqrt(2ln(2+N)/(1+n_i))+.40/sqrt(1+n_i)+.40ln(1+n_i)*inspected+1.10*active_open-.08*cost",
            "next_unseen": self.next_unseen(20),
        })
    }

    pub fn persist(&self, sessions_dir: &Path) -> Result<PathBuf, String> {
        fs::create_dir_all(sessions_dir).map_err(|e| e.to_string())?;
        let path = sessions_dir.join(format!("controller-{}.json", self.run_id));
        let tmp = sessions_dir.join(format!("controller-{}.tmp", self.run_id));
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }

    pub fn skepticism_contract() -> &'static str {
        "@ALEWO-SKEPTIC/1 Each hypothesis must specify invariant, source anchors, assumptions, discriminating observation, competing explanations and evidence gaps. A failed probe disproves that probe only. Close a disproved hypothesis when a source-backed counterexample exists; close as inconclusive when the evidence cannot decide. Neither means the whole codebase is safe. E2 means matching source anchors only; E3 means independently executed differential."
    }
}

pub fn inventory_paths(root: &Path, max_files: usize) -> (Vec<String>,bool) {
    let mut out = BTreeSet::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 32 || out.len() >= max_files {
            continue;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.')
                || matches!(
                    name.as_str(),
                    "target" | "dist" | "build" | "__pycache__"
                )
            {
                continue;
            }
            let path = entry.path();
            if crate::agent::blocked(&path)
                || matches!(name.as_str(), "test"|"tests"|"testdata"|"fixtures") { continue; }
            if path.is_dir() {
                stack.push((path, depth + 1));
            } else if let Ok(rel) = path.strip_prefix(root) {
                out.insert(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let truncated=out.len()>=max_files;
    (out.into_iter().take(max_files).collect(),truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_never_silently_disappears() {
        let mut c = InvestigationController::new(
            "r1",
            &["src/a.rs".into()],
            &["src/b.rs".into()],
        );
        assert_eq!(c.unseen_count(), 1);
        c.record_tool(
            1,
            "ws_read",
            &json!({"path":"src/b.rs"}),
            true,
            120,
        );
        assert_eq!(c.unseen_count(), 0);
        assert_eq!(c.inspected_count(), 1);
        assert!(c.packet().contains("@ALEWO-CTRL/1"));
    }

    #[test]
    fn batched_and_symbol_reads_create_granular_coverage() {
        let mut c=InvestigationController::new("granular",&[],
            &["src/a.rs".into(),"src/b.rs".into()]);
        c.record_tool(1,"ws_read_multi",&json!({"slices":[
            {"path":"src/a.rs","line":1},{"path":"src/b.rs","line":7}
        ]}),true,400);
        assert_eq!(c.inspected_count(),2);
        assert_eq!(c.unseen_count(),0);
        c.record_tool(2,"ws_read_symbol",
            &json!({"path":"src/a.rs","symbol":"authorize"}),true,200);
        assert_eq!(c.nodes["symbol::src/a.rs#authorize"].status,CoverageStatus::Inspected);
        c.record_tool(3,"ws_paths",
            &json!({"from":"entry","to":"sink"}),true,120);
        assert_eq!(c.nodes["flow::entry->sink"].status,CoverageStatus::Mapped);
    }

    #[test]
    fn focus_ranking_replaces_alphabetical_unseen_order() {
        let mut c=InvestigationController::new("focus",
            &["src/core.c".into(),"src/net.c".into()],
            &["auto/cc/acc".into()]);
        assert!(c.packet().contains("NEXT=FOCUS_RANK_REQUIRED"));
        assert!(!c.packet().contains("auto/cc/acc"));
        c.record_focus(&json!({"items":[
            {"p":"src/net.c","e":4,"m":3,"c":4,"u":3,"k":2,"w":"ENTRY+STATE"},
            {"p":"src/core.c","e":2,"m":2,"c":4,"u":2,"k":1,"w":"CENTRAL"},
            {"p":"auto/cc/acc","e":0,"m":0,"c":0,"u":1,"k":4,"w":"LOW"}
        ]})).unwrap();
        let next=c.next_unseen(3);
        assert_eq!(next[0],"src/net.c");
        assert_eq!(next[1],"src/core.c");
        assert_eq!(next[2],"auto/cc/acc");
    }

    #[test]
    fn source_reads_create_symbolic_reasoning_debt_then_commit_clears_it() {
        let mut c=InvestigationController::new("think",&[],&[]);
        c.record_tool(1,"ws_read_symbol",&json!({"path":"a.c","symbol":"f"}),true,100);
        c.record_tool(1,"ws_read_symbol",&json!({"path":"b.c","symbol":"g"}),true,100);
        assert!(c.thinking_directive().unwrap().contains("@ALEWO-THINK/2"));
        let result=c.record_thinking(&json!({
            "f":[
                {"a":"a.c:10","s":"object.state","r":"W","d":"-n","g":"n<=state"},
                {"a":"b.c:20","s":"object.state","r":"C","d":"+n","g":"cleanup"}
            ],
            "q":"does every cleanup refund correspond to a prior debit?",
            "n":"ws_read_symbol:b.c#cleanup"
        })).unwrap();
        assert!(result.contains("COUPLED=object.state"));
        assert!(c.thinking_directive().is_none());
        assert!(c.packet().contains("TH=C1:D0:F2"));
    }

    #[test]
    fn attention_priority_is_bounded_monotone_and_cost_sensitive() {
        let base=attention_priority(2,2,2,2,2);
        assert!(base.is_finite() && base>0.0);
        for axis in 0..4 {
            let mut low=[2u8;4];
            let mut high=[2u8;4];
            low[axis]=0; high[axis]=4;
            assert!(attention_priority(low[0],low[1],low[2],low[3],2)
                <= attention_priority(high[0],high[1],high[2],high[3],2));
        }
        assert!(attention_priority(2,2,2,2,1)>attention_priority(2,2,2,2,4));
        for e in 0..=4 { for m in 0..=4 { for c in 0..=4 { for u in 0..=4 {
            for k in 1..=4 {
                assert!(attention_priority(e,m,c,u,k).is_finite());
            }
        }}}}
    }

    #[test]
    fn candidate_portfolio_rotates_attention_without_hard_locking_first_read() {
        let mut c=InvestigationController::new("candidate",&[],
            &["src/http/v2/filter.c".into(),"src/core/proxy.c".into()]);
        c.record_focus(&json!({"items":[
            {"p":"src/http/v2/filter.c","e":4,"m":4,"c":4,"u":4,"k":1,"w":"boundary+state"},
            {"p":"src/core/proxy.c","e":3,"m":3,"c":3,"u":3,"k":2,"w":"secondary"}
        ]})).unwrap();
        assert_eq!(c.attention_schedule(2)[0].0,"src/http/v2/filter.c");
        c.record_tool(1,"ws_read",&json!({"path":"src/http/v2/filter.c"}),true,100);
        c.record_tool(2,"ws_read",&json!({"path":"src/http/v2/filter.c"}),true,100);
        assert_eq!(c.active_candidate.as_deref(),Some("src/http/v2/filter.c"));
        assert!(c.navigation_guard("ws_read",&json!({"path":"src/core/proxy.c"})).is_ok());
        c.close_candidate(&json!({"path":"src/http/v2/filter.c","status":"disproved","evidence":"bounds verified"})).unwrap();
        let schedule=c.attention_schedule(2);
        assert_eq!(schedule.len(),2);
        assert_eq!(schedule[0].0,"src/core/proxy.c");
        c.record_tool(3,"ws_read",&json!({"path":"src/core/proxy.c"}),true,100);
        assert_eq!(c.active_candidate.as_deref(),Some("src/core/proxy.c"));
    }

    #[test]
    fn hypothesis_requires_disconfirming_test() {
        let mut c = InvestigationController::new("r2", &[], &[]);
        let id = c.add_hypothesis(
            "cache omits tenant",
            "cache identity must include tenant",
            "compare cold and warm cross-tenant requests",
        );
        assert!(id.starts_with('H'));
        assert_eq!(c.hypotheses[0].status, "open");
    }

    #[test]
    fn controller_state_round_trips_for_cli_inspection() {
        let dir=std::env::temp_dir().join(format!("alewo-controller-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let c=InvestigationController::new("roundtrip",&["src/main.rs".into()],&[]);
        let path=c.persist(&dir).unwrap();
        let loaded=InvestigationController::load(&path).unwrap();
        assert_eq!(loaded.run_id,"roundtrip");
        assert_eq!(loaded.nodes.len(),1);
        let _=fs::remove_dir_all(dir);
    }
}

