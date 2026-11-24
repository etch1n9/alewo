//! Automate Learning (AL) Feedback & Memory Classification Engine for Alewo.
//! After a task finishes, Alewo asks:
//!   "Tugas sudah selesai. Simpan ke memori? (ya [alasan] / tidak [alasan] / skip)"
//! Both positive ("ya") and negative ("tidak") feedback are classified into
//! compact symbolic atoms (SUCCESS, FAILURE, PARTIAL, CORRECTION) and stored in
//! SQLite FTS5 + zstd(CBOR) so future sessions reuse winning patterns and avoid
//! past mistakes without wasting prompt tokens.
use crate::memory::{Episode, Evidence, Vault};
use crate::provider;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackClass {
    Success,
    Failure,
    Partial,
    Correction,
    Skip,
}

impl FeedbackClass {
    pub fn kind_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Partial => "partial",
            Self::Correction => "correction",
            Self::Skip => "skip",
        }
    }

    pub fn tag_str(self) -> &'static str {
        match self {
            Self::Success => "CLS:SUCCESS",
            Self::Failure => "CLS:FAILURE",
            Self::Partial => "CLS:PARTIAL",
            Self::Correction => "CLS:CORRECTION",
            Self::Skip => "CLS:SKIP",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedFeedback {
    pub class: FeedbackClass,
    pub accepted: bool,
    pub reason: String,
}

/// Parses natural Indonesian/English user feedback such as:
///   "ya", "ya, PoC akurat", "tidak", "tidak, salah file seharusnya di Pool",
///   "tidak, baru sebagian benar", "skip"
pub fn parse_feedback(raw: &str) -> ParsedFeedback {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ParsedFeedback {
            class: FeedbackClass::Skip,
            accepted: false,
            reason: String::new(),
        };
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(lower.as_str(), "skip" | "lewati" | "batal" | "cancel" | "-") {
        return ParsedFeedback {
            class: FeedbackClass::Skip,
            accepted: false,
            reason: String::new(),
        };
    }

    // Split leading verdict token on the FIRST whitespace or punctuation separator
    // so colons/dashes later in the reason (e.g. `Init/gs_fonts.ps:1025-1035`) never break `head`.
    let (head, rest) = if let Some(pos) = trimmed.find(|c: char| {
        c.is_whitespace() || matches!(c, ',' | ':' | ';' | '-' | '—' | '–' | '!')
    }) {
        let h = trimmed[..pos].trim();
        let r = trimmed[pos..]
            .trim_start_matches(|c: char| {
                c.is_whitespace() || matches!(c, ',' | ':' | ';' | '-' | '—' | '–' | '!')
            })
            .trim();
        (h, r)
    } else {
        (trimmed, "")
    };

    let head_l = head.to_ascii_lowercase();
    let rest_l = rest.to_ascii_lowercase();

    let is_yes = matches!(head_l.as_str(), "ya" | "y" | "yes" | "ok" | "oke" | "benar" | "berhasil" | "setuju");
    let is_no = matches!(head_l.as_str(), "tidak" | "tdk" | "no" | "n" | "gagal" | "salah" | "belum" | "bukan");

    let has_partial_cue = rest_l.contains("sebagian")
        || rest_l.contains("hampir")
        || rest_l.contains("kurang")
        || rest_l.contains("partial")
        || rest_l.contains("belum lengkap");

    let has_correction_cue = rest_l.contains("seharusnya")
        || rest_l.contains("koreksi")
        || rest_l.contains("bukan ")
        || rest_l.contains("harusnya")
        || rest_l.contains("instead")
        || rest_l.contains("should be")
        || rest_l.contains("salah di");

    let class = if is_yes {
        if has_partial_cue {
            FeedbackClass::Partial
        } else {
            FeedbackClass::Success
        }
    } else if is_no {
        if has_correction_cue {
            FeedbackClass::Correction
        } else if has_partial_cue {
            FeedbackClass::Partial
        } else {
            FeedbackClass::Failure
        }
    } else if has_correction_cue {
        FeedbackClass::Correction
    } else if has_partial_cue {
        FeedbackClass::Partial
    } else {
        // Default: treat free-form note without yes/no as a correction/observation
        FeedbackClass::Correction
    };

    let reason = if rest.is_empty() && !is_yes && !is_no {
        trimmed.to_string()
    } else {
        rest.to_string()
    };

    ParsedFeedback {
        class,
        accepted: is_yes,
        reason,
    }
}

fn sanitize_atom(s: &str, max_len: usize) -> String {
    s.replace(['\n', '\r', '|'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max_len)
        .collect()
}

fn extract_keywords(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    for tok in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.') {
        let t = tok.trim_matches('.');
        if t.len() >= 3 && t.len() <= 36 {
            let low = t.to_ascii_lowercase();
            if matches!(
                low.as_str(),
                "yang" | "dan" | "ini" | "itu" | "dari" | "untuk" | "pada" | "dengan" | "tidak"
                    | "sudah" | "atau" | "bisa" | "dalam" | "the" | "and" | "for" | "with" | "this" | "that"
            ) {
                continue;
            }
            if !out.contains(&low) {
                out.push(low);
                if out.len() >= max {
                    break;
                }
            }
        }
    }
    out
}

fn build_signature(class: FeedbackClass, task: &str, answer: &str, reason: &str) -> String {
    let combined = format!("{reason} {answer} {task}");
    let kws = extract_keywords(&combined, 4);
    let tail = if kws.is_empty() {
        "general".to_string()
    } else {
        kws.join("_")
    };
    let sig = format!("al:{}:{tail}", class.kind_str());
    sig.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'))
        .take(120)
        .collect()
}

/// Distills task + answer + user feedback into a compact symbolic Episode
/// (strictly bounded so future prompt injection stays ultra-small) and stores
/// it in Vault as an operator-confirmed `approved` memory record.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AiDistilledMemory {
    /// "global" for reusable cross-project engineering/audit patterns, or "project" for local facts.
    #[serde(default)]
    scope: String,
    /// Machine-readable slug, e.g. "c_uaf:reentrancy:callback_before_detach".
    sig: String,
    #[serde(default)]
    obs: Vec<String>,
    #[serde(default)]
    actions: Vec<String>,
    #[serde(default)]
    outcomes: Vec<String>,
    #[serde(default)]
    corrections: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    if end > start { Some(&raw[start..=end]) } else { None }
}

fn distill_with_ai(
    workspace: &Path,
    model: &str,
    scope: &str,
    class: FeedbackClass,
    task: &str,
    answer: &str,
    reason: &str,
) -> Option<AiDistilledMemory> {
    let key = provider::env_key(workspace).ok()?;
    let mdl = if model.trim().is_empty() {
        provider::default_model()
    } else {
        model.to_string()
    };
    let ans_clip: String = answer.chars().take(4000).collect();
    let sys = r#"You are Alewo's Automate Learning Memory Distiller. Output ONLY a single strict JSON object matching these exact keys (no markdown fences, no extra keys): {"scope":"global"|"project","sig":"domain:pattern:slug","obs":["<=3 concise facts <=160 chars"],"actions":["<=3 reusable audit steps <=160 chars"],"outcomes":["<=2 concise verdicts <=160 chars"],"corrections":["<=3 fix/rethink rules <=160 chars"],"tags":["<=10 lowercase technical keywords"]}. Use scope="global" when the technical pattern generalizes across codebases; otherwise "project". Never include secrets, tokens, or prose filler."#;
    let usr = format!(
        "SCOPE={scope}
CLASS={}
TASK={}
USER_REASON={}
ASSISTANT_ANSWER_EXCERPT:
{}",
        class.kind_str(),
        sanitize_atom(task, 240),
        sanitize_atom(reason, 280),
        ans_clip
    );
    let body = json!({
        "model": mdl,
        "messages": [
            {"role": "system", "content": sys},
            {"role": "user", "content": usr}
        ],
        "temperature": 0.2,
        "stream": true,
        "stream_options": {"include_usage": true}
    });
    let (res, _sec) = provider::send_chat_stream(&key, &body).ok()?;
    let text = res["choices"][0]["message"]["content"].as_str()?;
    let json_slice = extract_json_object(text)?;
    serde_json::from_str::<AiDistilledMemory>(json_slice).ok()
}

/// Interactive/CLI Automate Learning entry point: asks the active AI model to distill
/// the completed session + user feedback into a strict Rust-validated symbolic Episode,
/// falling back cleanly to the deterministic Rust extractor when offline or unavailable.
pub fn record_feedback_with_ai(
    workspace: &Path,
    model: &str,
    db_path: &Path,
    scope: &str,
    task: &str,
    answer: &str,
    user_reply: &str,
    evidence_file: Option<&Path>,
) -> Result<Value, String> {
    let parsed = parse_feedback(user_reply);
    if parsed.class == FeedbackClass::Skip {
        return Ok(json!({
            "saved": false,
            "class": "skip",
            "distiller": "none",
            "message": "Feedback dilewati; tidak disimpan ke memori."
        }));
    }

    if let Some(ai) = distill_with_ai(workspace, model, scope, parsed.class, task, answer, &parsed.reason) {
        let final_scope = if ai.scope.eq_ignore_ascii_case("global") {
            "global".to_string()
        } else {
            scope.to_string()
        };
        let sig_clean: String = ai.sig.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/'))
            .take(100)
            .collect();
        let sig = if sig_clean.len() >= 4 {
            sig_clean
        } else {
            build_signature(parsed.class, task, answer, &parsed.reason)
        };
        let obs: Vec<String> = ai.obs.into_iter().map(|s| sanitize_atom(&s, 170)).filter(|s| !s.is_empty()).take(3).collect();
        let actions: Vec<String> = ai.actions.into_iter().map(|s| sanitize_atom(&s, 170)).filter(|s| !s.is_empty()).take(3).collect();
        let mut outcomes: Vec<String> = ai.outcomes.into_iter().map(|s| sanitize_atom(&s, 170)).filter(|s| !s.is_empty()).take(2).collect();
        if outcomes.is_empty() {
            outcomes.push(format!("VERDICT:{}", parsed.class.kind_str().to_ascii_uppercase()));
        }
        let mut corrections: Vec<String> = ai.corrections.into_iter().map(|s| sanitize_atom(&s, 170)).filter(|s| !s.is_empty()).take(3).collect();
        if corrections.is_empty() && parsed.class == FeedbackClass::Failure {
            corrections.push("RETHINK:prior_attempt_failed_diagnose_why_do_not_skip".into());
        }
        let mut tags = vec![parsed.class.tag_str().to_string(), "SRC:AI_DISTILLED".to_string()];
        for t in ai.tags {
            let clean = sanitize_atom(&t, 36).to_ascii_lowercase();
            if !clean.is_empty() && !tags.contains(&clean) && tags.len() < 12 {
                tags.push(clean);
            }
        }
        let evidence = if let Some(p) = evidence_file.filter(|p| p.is_file()) {
            let bytes = std::fs::read(p).map_err(|e| e.to_string())?;
            let h = format!("{:x}", Sha256::digest(&bytes));
            vec![Evidence { path: p.to_string_lossy().into_owned(), sha256: h }]
        } else {
            let h = format!("{:x}", Sha256::digest(format!("{task}
{answer}
{user_reply}").as_bytes()));
            vec![Evidence { path: format!("feedback://{final_scope}/{}", &h[..12]), sha256: h }]
        };
        let episode = Episode {
            scope: final_scope.clone(),
            kind: parsed.class.kind_str().to_string(),
            sig: sig.clone(),
            obs,
            actions,
            outcomes,
            corrections,
            tags,
            evidence,
            expires_at: None,
        };
        let mut vault = Vault::open(db_path)?;
        let topic_query = format!("{task} {} {sig}", parsed.reason);
        let (id, addr, state, resolved_addrs) = vault.add_confirmed_feedback(&episode, &topic_query)?;
        return Ok(json!({
            "saved": true,
            "distiller": "ai_schema_gated",
            "id": id,
            "addr": addr,
            "scope": final_scope,
            "state": state,
            "class": parsed.class.kind_str(),
            "sig": sig,
            "reason": parsed.reason,
            "resolved_prior_addrs": resolved_addrs
        }));
    }

    // Fallback: deterministic Rust distillation (never loses feedback if offline/provider error)
    let mut res = record_feedback(db_path, scope, task, answer, user_reply, evidence_file)?;
    res["distiller"] = json!("deterministic_fallback");
    Ok(res)
}

pub fn record_feedback(
    db_path: &Path,
    scope: &str,
    task: &str,
    answer: &str,
    user_reply: &str,
    evidence_file: Option<&Path>,
) -> Result<Value, String> {
    let parsed = parse_feedback(user_reply);
    if parsed.class == FeedbackClass::Skip {
        return Ok(json!({
            "saved": false,
            "class": "skip",
            "message": "Feedback dilewati; tidak disimpan ke memori."
        }));
    }

    let sig = build_signature(parsed.class, task, answer, &parsed.reason);
    let task_atom = format!("TASK:{}", sanitize_atom(task, 110));
    let ans_first = answer
        .lines()
        .find(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && !t.starts_with("---")
        })
        .or_else(|| answer.lines().find(|l| !l.trim().is_empty()))
        .unwrap_or(answer);
    let ans_atom = format!("ANS:{}", sanitize_atom(ans_first, 130));

    let mut obs = vec![task_atom, ans_atom];
    let mut outcomes = vec![format!("VERDICT:{}", parsed.class.kind_str().to_ascii_uppercase())];
    let mut corrections = Vec::new();

    if !parsed.reason.is_empty() {
        let r = sanitize_atom(&parsed.reason, 180);
        match parsed.class {
            FeedbackClass::Success => outcomes.push(format!("WHY:{r}")),
            FeedbackClass::Failure => {
                corrections.push(format!("RETHINK:{r}"));
            }
            FeedbackClass::Partial | FeedbackClass::Correction => {
                corrections.push(format!("REFINE:{r}"));
            }
            FeedbackClass::Skip => {}
        }
    } else if parsed.class == FeedbackClass::Failure {
        corrections.push("RETHINK:prior_attempt_incomplete_or_failed_diagnose_why_do_not_skip".into());
    }

    let mut tags = vec![parsed.class.tag_str().to_string(), "SRC:USER_FEEDBACK".to_string()];
    for kw in extract_keywords(&format!("{task} {} {answer}", parsed.reason), 6) {
        if tags.len() < 12 {
            tags.push(kw);
        }
    }

    // Bind evidence: either a real project file SHA-256 or a deterministic
    // transcript digest marker (`feedback://<sha>`) accepted for operator-confirmed lessons.
    let evidence = if let Some(p) = evidence_file {
        if p.is_file() {
            let bytes = std::fs::read(p).map_err(|e| e.to_string())?;
            let h = format!("{:x}", Sha256::digest(&bytes));
            vec![Evidence {
                path: p.to_string_lossy().into_owned(),
                sha256: h,
            }]
        } else {
            let h = format!("{:x}", Sha256::digest(format!("{task}\n{answer}\n{user_reply}").as_bytes()));
            vec![Evidence {
                path: format!("feedback://{scope}/{}", &h[..12]),
                sha256: h,
            }]
        }
    } else {
        let h = format!("{:x}", Sha256::digest(format!("{task}\n{answer}\n{user_reply}").as_bytes()));
        vec![Evidence {
            path: format!("feedback://{scope}/{}", &h[..12]),
            sha256: h,
        }]
    };

    // Keep obs short & clean
    obs.retain(|s| !s.trim().is_empty());

    let episode = Episode {
        scope: scope.to_string(),
        kind: parsed.class.kind_str().to_string(),
        sig: sig.clone(),
        obs,
        actions: vec![format!("USER_FEEDBACK:{}", if parsed.accepted { "YES" } else { "NO" })],
        outcomes,
        corrections,
        tags,
        evidence,
        expires_at: None,
    };

    let mut vault = Vault::open(db_path)?;
    let topic_query = format!("{task} {} {answer}", parsed.reason);
    let (id, addr, state, resolved_addrs) = vault.add_confirmed_feedback(&episode, &topic_query)?;
    Ok(json!({
        "saved": true,
        "id": id,
        "addr": addr,
        "state": state,
        "class": parsed.class.kind_str(),
        "sig": sig,
        "reason": parsed.reason,
        "resolved_prior_addrs": resolved_addrs
    }))
}


/// Automatically convert a transparent verifier result into a universal lesson.
/// Failed verifier attempts are retained as corrections; a later verified success
/// links them through Vault's existing resolved_by/parent_addr lineage.
pub fn record_verifier_outcome(
    db_path:&Path,
    verdict:&Value,
)->Result<Value,String>{
    let schema=verdict["schema"].as_str().unwrap_or("");
    if !matches!(schema,"@ALEWO-VERIFY/1"|"@ALEWO-VERIFY/2"){
        return Err("unsupported verifier result".into());
    }
    // V1 remains readable for historical ledgers, but it can never create a
    // success lesson because it did not prove a machine-checked control.
    let source_verified=verdict["source_verified"].as_bool()
        .unwrap_or(verdict["verified"]==true);
    let runtime_verified=verdict["runtime_verified"]==true;
    let challenge_accepted=schema=="@ALEWO-VERIFY/2"
        && verdict["challenge_accepted"]==true
        && source_verified
        && runtime_verified;
    let episode_kind=if challenge_accepted{"success"}
        else if source_verified{"partial"}else{"correction"};
    let invariant=verdict["invariant"].as_str().unwrap_or("unknown invariant");
    let impact=verdict["impact"].as_str().unwrap_or("unverified impact");
    let disconfirming=verdict["disconfirming_test"].as_str().unwrap_or("missing disconfirming test");
    let failure_text=verdict["failures"].as_array().into_iter().flatten()
        .filter_map(Value::as_str).collect::<Vec<_>>().join(";");
    let keywords=extract_keywords(&format!("{invariant} {impact} {disconfirming}"),5);
    let slug=if keywords.is_empty(){"general".into()}else{keywords.join("_")};
    let sig=format!("universal:e2e:{}",slug.chars().take(96).collect::<String>());
    let proof=verdict["proof_grade"].as_str().unwrap_or("E1");
    let roles=verdict["roles"].as_array().into_iter().flatten()
        .filter_map(Value::as_str).collect::<Vec<_>>().join(">");
    let raw=serde_json::to_vec(verdict).map_err(|e|e.to_string())?;
    let digest=format!("{:x}",Sha256::digest(&raw));
    let episode=Episode{
        scope:"global".into(),
        kind:episode_kind.into(),
        sig:sig.clone(),
        obs:vec![
            format!("INV:{}",sanitize_atom(invariant,170)),
            format!("CHAIN:{}",sanitize_atom(&roles,120)),
        ],
        actions:vec![format!("DISCONFIRM:{}",sanitize_atom(disconfirming,170))],
        outcomes:if challenge_accepted{vec![
            "VERDICT:CHALLENGE_ACCEPTED".into(),
            format!("IMPACT:{}",sanitize_atom(impact,170)),
        ]}else if source_verified{vec![
            "VERDICT:SOURCE_ONLY_NOT_CHALLENGE_SUCCESS".into(),
        ]}else{vec!["VERDICT:VERIFIER_REJECTED".into()]},
        corrections:if challenge_accepted{vec![]}else{vec![
            format!("RETHINK:{}",sanitize_atom(
                if failure_text.is_empty(){
                    "execute a distinct reproduction and negative control with semantic assertions"
                }else{&failure_text},170))
        ]},
        tags:vec![
            format!("PROOF:{proof}"),
            "SRC:TRANSPARENT_VERIFIER".into(),
            if challenge_accepted{"CLS:SUCCESS".into()}
                else if source_verified{"CLS:PARTIAL".into()}else{"CLS:CORRECTION".into()},
        ],
        evidence:vec![Evidence{
            path:format!("verifier://{}",&digest[..16]),
            sha256:digest,
        }],
        expires_at:None,
    };
    let mut vault=Vault::open(db_path)?;
    let topic=format!("{invariant} {impact} {disconfirming}");
    let (id,addr,state,resolved)=vault.add_confirmed_feedback(&episode,&topic)?;
    Ok(json!({
        "saved":true,"id":id,"addr":addr,"state":state,"class":episode.kind,
        "scope":"global","sig":sig,"proof_grade":proof,
        "resolved_prior_addrs":resolved,"source":"transparent_verifier",
        "source_verified":source_verified,"runtime_verified":runtime_verified,
        "challenge_accepted":challenge_accepted
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn classifies_yes_no_partial_correction_and_skip() {
        assert_eq!(parse_feedback("ya").class, FeedbackClass::Success);
        assert_eq!(parse_feedback("ya, PoC akurat dan cepat").class, FeedbackClass::Success);
        assert_eq!(parse_feedback("tidak").class, FeedbackClass::Failure);
        assert_eq!(parse_feedback("tidak, salah file seharusnya DirectMappedPool").class, FeedbackClass::Correction);
        assert_eq!(parse_feedback("tidak, baru sebagian benar").class, FeedbackClass::Partial);
        assert_eq!(parse_feedback("ya, tapi masih kurang lengkap").class, FeedbackClass::Partial);
        assert_eq!(parse_feedback("skip").class, FeedbackClass::Skip);
        let with_colon = parse_feedback("ya — tepat! Bug di Init/gs_fonts.ps:1025-1035 ditemukan");
        assert_eq!(with_colon.class, FeedbackClass::Success);
        assert!(with_colon.accepted);
    }

    #[test]
    fn saves_and_retrieves_both_success_and_failure_compactly() {
        let db = std::env::temp_dir().join(format!(
            "alewo-al-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        // Step 1: Initial attempt fails/needs correction -> M0001
        let r1 = record_feedback(
            &db,
            "proj_al",
            "Audit cache DirectMappedPool",
            "Menebak pasangan adi dan budi",
            "tidak, salah di pasangan tenant seharusnya verifikasi runtime dulu",
            None,
        )
        .unwrap();
        assert_eq!(r1["saved"], true);
        assert_eq!(r1["addr"], "M0001");
        assert_eq!(r1["class"], "correction");

        // Step 2: User directs retry, AI succeeds -> M0002 links & resolves M0001
        // without overwriting M0001's original classification!
        let r2 = record_feedback(
            &db,
            "proj_al",
            "Audit cache DirectMappedPool",
            "Ditemukan collision slot 32 tanpa cek fullKey",
            "ya, tepat dan PoC gita-indra berhasil",
            None,
        )
        .unwrap();
        assert_eq!(r2["saved"], true);
        assert_eq!(r2["addr"], "M0002");
        assert_eq!(r2["class"], "success");
        assert_eq!(r2["resolved_prior_addrs"], json!(["M0001"]));

        // Step 3: Inspect by short address M0001 — still `correction`, now pointing to M0002!
        let vault = Vault::open(&db).unwrap();
        let m1 = vault.inspect("M0001").unwrap();
        assert_eq!(m1["episode"]["kind"], "correction");
        assert_eq!(m1["resolved_by"], "M0002");

        let found = vault.search("proj_al", "DirectMappedPool cache", 4, 750).unwrap();
        let recs = found["records"].as_array().unwrap();
        assert_eq!(recs.len(), 2);
        let joined = recs
            .iter()
            .filter_map(|x| x["packed"].as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("M0002|[+OK]|FROM<-M0001"));
        assert!(joined.contains("M0001|[~REFINE]|RESOLVED_BY->M0002"));
        assert!(found["chars"].as_u64().unwrap() <= 750);

        // Step 4: Unrelated failure in same scope (AuthGuard) must NOT be falsely resolved
        let r_unrel = record_feedback(
            &db,
            "proj_al",
            "Audit AuthGuard token expiry",
            "Melewatkan cek clock skew",
            "tidak, cek AuthGuard expiry",
            None,
        )
        .unwrap();
        assert_eq!(r_unrel["addr"], "M0003");
        let r_succ2 = record_feedback(
            &db,
            "proj_al",
            "Audit StorageKeyMapper double decode",
            "Ditemukan urldecode ganda",
            "ya, tepat pada StorageKeyMapper",
            None,
        )
        .unwrap();
        assert_eq!(r_succ2["resolved_prior_addrs"], json!([]));
        let m3 = vault.inspect("M0003").unwrap();
        assert!(m3["resolved_by"].is_null());

        drop(vault);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn source_only_verifier_result_is_partial_not_success() {
        let db=std::env::temp_dir().join(format!("alewo-verifier-e2-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let source_only=json!({
            "schema":"@ALEWO-VERIFY/2","verified":false,"source_verified":true,
            "runtime_verified":false,"challenge_accepted":false,"proof_grade":"E2",
            "invariant":"tenant scoped output","impact":"possible disclosure",
            "disconfirming_test":"execute a distinct safe tenant control",
            "roles":["entry","state","sink"],
            "failures":["both reproduction and control are required for challenge acceptance"]
        });
        let saved=record_verifier_outcome(&db,&source_only).unwrap();
        assert_eq!(saved["class"],"partial");
        assert_eq!(saved["challenge_accepted"],false);
        let vault=Vault::open(&db).unwrap();
        assert_eq!(vault.inspect(saved["addr"].as_str().unwrap()).unwrap()["episode"]["kind"],"partial");
        let _=std::fs::remove_file(db);
    }

    #[test]
    fn transparent_verifier_links_failure_to_later_success() {
        let db = std::env::temp_dir().join(format!(
            "alewo-verifier-lineage-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let failed=json!({
            "schema":"@ALEWO-VERIFY/2","verified":false,"source_verified":false,
            "runtime_verified":false,"challenge_accepted":false,"proof_grade":"E1",
            "invariant":"cache identity includes tenant context",
            "impact":"cross tenant response reuse",
            "disconfirming_test":"compare cold and warm distinct tenant requests",
            "roles":["entry","state"],"failures":["sink anchor missing"]
        });
        let f=record_verifier_outcome(&db,&failed).unwrap();
        assert_eq!(f["addr"],"M0001");
        let success=json!({
            "schema":"@ALEWO-VERIFY/2","verified":true,"source_verified":true,
            "runtime_verified":true,"challenge_accepted":true,"proof_grade":"E3",
            "invariant":"cache identity includes tenant context",
            "impact":"cross tenant response reuse",
            "disconfirming_test":"compare cold and warm distinct tenant requests",
            "roles":["entry","state","sink"],"failures":[]
        });
        let s=record_verifier_outcome(&db,&success).unwrap();
        assert_eq!(s["addr"],"M0002");
        assert_eq!(s["resolved_prior_addrs"],json!(["M0001"]));
        let vault=Vault::open(&db).unwrap();
        assert_eq!(vault.inspect("M0001").unwrap()["resolved_by"],"M0002");
        assert_eq!(vault.trace("M0001").unwrap()["edges"].as_array().unwrap().len(),1);
        let _=std::fs::remove_file(db);
    }
}

