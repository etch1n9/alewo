//! Versioned compact protocol used between Alewo and the model.
//!
//! The existing @ALEWO-* representation remains the compatibility baseline.
//! Candidate encodings are always semantically equivalent; callers may select a
//! denser form only after calibration proves that the target model understands it.

use serde::{Deserialize, Serialize};
use serde_json::json;

pub const PROTOCOL_VERSION: &str = "A4";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encoding {
    Existing,
    Named,
    Positional,
    Json,
}

impl Encoding {
    pub fn label(self) -> &'static str {
        match self {
            Self::Existing => "existing",
            Self::Named => "named",
            Self::Positional => "positional",
            Self::Json => "json",
        }
    }
}

#[derive(Clone, Debug)]
pub struct MemoryFrame<'a> {
    pub addr: &'a str,
    pub kind: &'a str,
    pub signature: &'a str,
    pub detail: &'a str,
    pub scope_is_global: bool,
    pub resolved_by: Option<&'a str>,
    pub parents: Option<&'a str>,
    pub proof_grade: &'a str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub encoding: &'static str,
    pub text: String,
    pub chars: usize,
    /// Explicitly a proxy. Provider-reported prompt_tokens remains authoritative.
    pub token_proxy: usize,
}

fn kind_code(kind: &str) -> &'static str {
    match kind {
        "success" | "bug" | "repair" | "workflow" | "tool-result" => "S",
        "failure" | "agent-failure" => "F",
        "correction" => "C",
        "partial" => "P",
        _ => "U",
    }
}

fn escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('|', "\\p")
        .replace(';', "\\s")
        .replace('\n', " ")
        .replace('\r', " ")
}

pub fn encode_memory(frame: &MemoryFrame<'_>, encoding: Encoding) -> String {
    let relation = if let Some(target) = frame.resolved_by.filter(|s| !s.is_empty()) {
        format!("R>{}", escape(target))
    } else if let Some(parents) = frame.parents.filter(|s| !s.is_empty()) {
        format!("P<{}", escape(parents))
    } else {
        "-".into()
    };
    let global = if frame.scope_is_global { "G" } else { "L" };
    let kind = kind_code(frame.kind);
    match encoding {
        Encoding::Existing => {
            let badge = match kind {
                "F" => "[!RETHINK]",
                "C" | "P" => "[~REFINE]",
                _ => "[+OK]",
            };
            let link = if let Some(target)=frame.resolved_by.filter(|s|!s.is_empty()) {
                format!("|RESOLVED_BY->{}",escape(target))
            } else if let Some(parents)=frame.parents.filter(|s|!s.is_empty()) {
                format!("|FROM<-{}",escape(parents))
            } else { String::new() };
            format!(
                "{}|{}{}|{}|{}|{}",
                frame.addr,
                badge,
                link,
                frame.signature,
                frame.detail,
                frame.proof_grade
            )
        }
        Encoding::Named => format!(
            "{PROTOCOL_VERSION}|H={}|K={}|S={}|R={}|V={}|I={}|D={}",
            escape(frame.addr),
            kind,
            global,
            relation,
            escape(frame.proof_grade),
            escape(frame.signature),
            escape(frame.detail)
        ),
        Encoding::Positional => format!(
            "{PROTOCOL_VERSION}|{}|{}{}|{}|{}|{}|{}",
            escape(frame.addr),
            kind,
            global,
            relation,
            escape(frame.proof_grade),
            escape(frame.signature),
            escape(frame.detail)
        ),
        Encoding::Json => serde_json::to_string(&json!({
            "v": PROTOCOL_VERSION,
            "h": frame.addr,
            "k": kind,
            "s": global,
            "r": relation,
            "p": frame.proof_grade,
            "i": frame.signature,
            "d": frame.detail,
        }))
        .unwrap_or_default(),
    }
}

pub fn token_proxy(text: &str) -> usize {
    // Only a stable comparison fallback. Never report this as provider tokens.
    (text.chars().count() + 3) / 4
}

pub fn candidates(frame: &MemoryFrame<'_>) -> Vec<Candidate> {
    [
        Encoding::Existing,
        Encoding::Named,
        Encoding::Positional,
        Encoding::Json,
    ]
    .into_iter()
    .map(|encoding| {
        let text = encode_memory(frame, encoding);
        Candidate {
            encoding: encoding.label(),
            chars: text.chars().count(),
            token_proxy: token_proxy(&text),
            text,
        }
    })
    .collect()
}

pub fn configured_encoding() -> Encoding {
    match std::env::var("ALEWO_PROTOCOL")
        .unwrap_or_else(|_| "existing".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "named" | "a4" => Encoding::Named,
        "positional" | "a4p" => Encoding::Positional,
        "json" => Encoding::Json,
        // Auto deliberately keeps the proven baseline until protocol calibrate
        // records provider-token and comprehension dominance.
        _ => Encoding::Existing,
    }
}

pub fn calibration_report(frame: &MemoryFrame<'_>, codebook_chars: usize) -> serde_json::Value {
    let variants = candidates(frame);
    let existing = variants
        .iter()
        .find(|v| v.encoding == "existing")
        .map(|v| v.token_proxy)
        .unwrap_or(0);
    let rows = variants
        .iter()
        .map(|v| {
            let saving = existing.saturating_sub(v.token_proxy);
            let break_even = if saving == 0 {
                None
            } else {
                Some((token_proxy(&"x".repeat(codebook_chars)) + saving - 1) / saving)
            };
            json!({
                "encoding": v.encoding,
                "chars": v.chars,
                "token_proxy": v.token_proxy,
                "break_even_events_proxy": break_even,
                "text": v.text,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "protocol": PROTOCOL_VERSION,
        "authoritative_metric": "provider prompt_tokens plus comprehension accuracy",
        "proxy_warning": "token_proxy is not a model tokenizer",
        "candidates": rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame<'a>() -> MemoryFrame<'a> {
        MemoryFrame {
            addr: "M0013",
            kind: "success",
            signature: "security:toctou:double-fetch",
            detail: "PAIR_CONTEXTS;VERIFY_REFETCH",
            scope_is_global: true,
            resolved_by: None,
            parents: Some("M0012,M0005"),
            proof_grade: "E3",
        }
    }

    #[test]
    fn all_encodings_preserve_core_atoms() {
        for candidate in candidates(&frame()) {
            assert!(candidate.text.contains("M0013"));
            assert!(candidate.text.contains("double-fetch"));
            assert!(candidate.text.contains("E3"));
        }
    }

    #[test]
    fn calibration_never_calls_proxy_real_tokens() {
        let report = calibration_report(&frame(), 120);
        assert_eq!(report["authoritative_metric"], "provider prompt_tokens plus comprehension accuracy");
        assert!(report["proxy_warning"].as_str().unwrap().contains("not a model tokenizer"));
    }
}
