//! Defensive Polyglot Structural Invariant Analyzer (@ALEWO-INVARIANT/1).
//! Inspects reachable source files for structural software invariant violations
//! (multi-stage decoding, truncated/unverified cache slot lookups, reversed
//! config merge precedence, and loose/assignment guards) in <20ms with 0 AI tokens.
//!
//! IMPORTANT: Findings are non-exhaustive structural review hypotheses, NEVER
//! verdicts. An empty invariant list is NEVER proof that a codebase is safe.
use serde_json::{json, Value};
use std::{fs, path::Path};

fn has_decode_call(line: &str) -> Option<&'static str> {
    for pat in [
        "rawurldecode(",
        "urldecode(",
        "decodeURIComponent(",
        "decodeURI(",
        "urllib.parse.unquote(",
        "unquote_plus(",
        "QueryUnescape(",
        "PathUnescape(",
        "URLDecoder.decode(",
    ] {
        if line.contains(pat) {
            return Some(pat.trim_end_matches('('));
        }
    }
    None
}

pub fn scan(root: &Path, candidate_files: &[String]) -> Value {
    let mut findings = Vec::<Value>::new();
    let mut decode_sites = Vec::<Value>::new();

    for rel in candidate_files {
        let path = root.join(rel);
        let Ok(src) = fs::read_to_string(&path) else { continue; };
        let lower_path = rel.to_ascii_lowercase();
        let is_cache_or_key = lower_path.contains("cache")
            || lower_path.contains("pool")
            || lower_path.contains("key")
            || lower_path.contains("memo")
            || lower_path.contains("store");

        let mut file_has_slot_trunc = false;
        let mut trunc_line = 0usize;
        let mut trunc_expr = String::new();
        let mut file_checks_full_key = false;

        for (idx, raw) in src.lines().enumerate() {
            let line_no = idx + 1;
            let t = raw.trim();
            if t.is_empty() || t.starts_with("//") || t.starts_with('*') || t.starts_with('#') {
                continue;
            }

            // 1. Track all decode/unescape layers across reachable files
            if let Some(fn_name) = has_decode_call(t) {
                decode_sites.push(json!({"file": rel, "line": line_no, "fn": fn_name}));
            }

            // 2. Truncated/masked hash or fixed-slot modulo in cache/key modules
            if is_cache_or_key {
                if (t.contains("& 0x")
                    || (t.contains("hexdec(substr(") && t.contains('%'))
                    || (t.contains("crc32(") && (t.contains('&') || t.contains('%'))))
                    && !file_has_slot_trunc
                {
                    file_has_slot_trunc = true;
                    trunc_line = line_no;
                    trunc_expr = t.chars().take(120).collect();
                }
                if t.contains("=== $fullKey")
                    || t.contains("===$fullKey")
                    || t.contains("hash_equals(")
                    || t.contains("['key'] ===")
                {
                    file_checks_full_key = true;
                }
            }

            // 3. Reversed config merge precedence (overrides before base/defaults)
            if t.contains("array_merge(") {
                let low = t.to_ascii_lowercase();
                if let (Some(o_pos), Some(b_pos)) = (
                    low.find("override").or_else(|| low.find("security")),
                    low.find("base").or_else(|| low.find("default")),
                ) {
                    if o_pos < b_pos {
                        findings.push(json!({
                            "invariant": "CONFIG_MERGE_PRECEDENCE",
                            "file": rel,
                            "line": line_no,
                            "evidence": t.chars().take(120).collect::<String>(),
                            "hypothesis": "Security/override config appears before base/defaults in merge; later argument overwrites earlier keys."
                        }));
                    }
                }
            }

            // 4. Loose equality on secret/token/signature/hash comparisons (exclude config enums like server_tokens == NGX_*)
            let low = t.to_ascii_lowercase();
            let is_enum_cmp = low.contains("server_tokens")
                || t.contains("== NGX_")
                || t.contains("== HTTP_")
                || t.contains("== ARES_")
                || t.contains("== NULL")
                || t.contains("== 0")
                || t.contains("== 1");
            if !is_enum_cmp
                && (low.contains("token") || low.contains("ticket") || low.contains("signature") || low.contains("hmac"))
                && t.contains(" == ")
                && !t.contains("===")
            {
                findings.push(json!({
                    "invariant": "LOOSE_SECRET_COMPARISON",
                    "file": rel,
                    "line": line_no,
                    "evidence": t.chars().take(120).collect::<String>(),
                    "hypothesis": "Loose equality (==) on auth/signature value; verify strict constant-time comparison."
                }));
            }
        }

        if file_has_slot_trunc && !file_checks_full_key {
            findings.push(json!({
                "invariant": "TRUNCATED_OR_UNVERIFIED_SLOT_KEY",
                "file": rel,
                "line": trunc_line,
                "evidence": trunc_expr,
                "hypothesis": "Hash/key is truncated or folded into fixed slots without observing full-key equality check on read; verify collision isolation across tenants/keys."
            }));
        }

        // 5. Polyglot C/C++/Rust memory lifecycle: callback invoked in same file as free/destroy/unlink
        let ext = Path::new(rel).extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
        if matches!(ext.as_str(), "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "rs") {
            let mut cb_lines = Vec::new();
            let mut free_lines = Vec::new();
            for (idx, line) in src.lines().enumerate() {
                let t = line.trim();
                if t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") { continue; }
                if t.contains("->callback(") || t.contains("callback(") || t.contains("->cb(") {
                    cb_lines.push(idx + 1);
                }
                if t.contains("free(") || t.contains("_free(") || t.contains("delete ") || t.contains("destroy(") || t.contains("unlink") || t.contains("detach") {
                    free_lines.push(idx + 1);
                }
            }
            if !cb_lines.is_empty() && !free_lines.is_empty() && findings.len() < 24 {
                findings.push(json!({
                    "invariant": "MEMORY_CALLBACK_REENTRANCY_SURFACE",
                    "file": rel,
                    "callback_lines": cb_lines.iter().take(6).collect::<Vec<_>>(),
                    "free_lines": free_lines.iter().take(6).collect::<Vec<_>>(),
                    "hypothesis": "Callback invoked in same file as free/destroy/unlink; verify object is detached from all containers BEFORE invoking callback (UAF/double-free check)."
                }));
            }
        }

        // 6. Polyglot unsafe deserialization & unvalidated server-side URL fetch
        for (idx, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with('#') || t.starts_with('*') { continue; }
            if (t.contains("pickle.loads(") || t.contains("unserialize(") || t.contains("ObjectInputStream") || (t.contains("yaml.load(") && !t.contains("SafeLoader")))
                && findings.len() < 28
            {
                findings.push(json!({
                    "invariant": "UNSAFE_DESERIALIZATION_SINK",
                    "file": rel,
                    "line": idx + 1,
                    "evidence": t.chars().take(120).collect::<String>(),
                    "hypothesis": "Unsafe deserialization sink; verify trust boundary, authentication, and codec allowlist."
                }));
                break;
            }
        }
        for (idx, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with('#') || t.starts_with('*') { continue; }
            if (t.contains("client.get(") || t.contains("requests.get(") || t.contains("urlopen(") || t.contains("http.Get("))
                && (lower_path.contains("serde") || lower_path.contains("upload") || lower_path.contains("file") || lower_path.contains("proxy") || lower_path.contains("fetch"))
                && findings.len() < 32
            {
                findings.push(json!({
                    "invariant": "SERVER_SIDE_URL_FETCH_SURFACE",
                    "file": rel,
                    "line": idx + 1,
                    "evidence": t.chars().take(120).collect::<String>(),
                    "hypothesis": "Server-side URL fetch in request/file handler; verify scheme/host allowlist, resolved-IP private/metadata blocking, timeout, and size limits."
                }));
                break;
            }
        }
        // 7. Universal dual-path bounded window/counter accounting (unsigned subtraction + unchecked += refund)
        let mut bound_sub_lines = Vec::new();
        let mut inc_lines = Vec::new();
        for (idx, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with('*') || t.starts_with('#') { continue; }
            if (t.contains("MAX_WINDOW") || t.contains("MAX_SIZE") || t.contains("MAX_LIMIT") || t.contains("MAX_CREDIT"))
                && t.contains(" - ")
            {
                bound_sub_lines.push(idx + 1);
            }
            if t.contains("+=") && (t.contains("window") || t.contains("credit") || t.contains("quota") || t.contains("budget")) {
                inc_lines.push(idx + 1);
            }
        }
        if (!bound_sub_lines.is_empty() || inc_lines.len() >= 2) && !inc_lines.is_empty() && findings.len() < 32 {
            findings.push(json!({
                "invariant": "DUAL_PATH_BOUNDED_ACCOUNTING",
                "file": rel,
                "bound_sub_lines": bound_sub_lines.iter().take(6).collect::<Vec<_>>(),
                "increment_lines": inc_lines.iter().take(6).collect::<Vec<_>>(),
                "hypothesis": "Bounded window/quota/credit counter is incremented via += alongside upper-bound subtraction; verify whether a secondary path (e.g. cleanup/cancel/refund) can push the counter past MAX and trigger unsigned underflow."
            }));
        }

        // Universal structural Check-Then-Refetch TOCTOU surface (polyglot: PHP/Py/TS/JS/Go/Rust/Java/C):
        // Flags a validation/check call followed within 12 lines by a fresh record fetch + state mutation
        // without an enclosing transaction or row-lock primitive.
        let src_lines: Vec<&str> = src.lines().collect();
        let lower = src.to_ascii_lowercase();
        let has_tx_or_lock = lower.contains("transaction(")
            || lower.contains("begintransaction")
            || lower.contains("forupdate")
            || lower.contains("for update")
            || lower.contains("select_for_update")
            || lower.contains("mutex")
            || lower.contains("rwlock");
        if !has_tx_or_lock && findings.len() < 32 {
            let mut toctou_hits = Vec::new();
            for i in 0..src_lines.len() {
                let tl = src_lines[i].trim().to_ascii_lowercase();
                if tl.starts_with("//") || tl.starts_with('*') || tl.starts_with('#') {
                    continue;
                }
                let is_check = (tl.contains("validate") || tl.contains("verify") || tl.contains("checkauth") || tl.contains("check_"))
                    && tl.contains('(')
                    && !tl.starts_with("function ")
                    && !tl.starts_with("public function ")
                    && !tl.starts_with("private function ")
                    && !tl.starts_with("protected function ")
                    && !tl.starts_with("def ")
                    && !tl.starts_with("fn ");
                if !is_check {
                    continue;
                }
                let end = (i + 12).min(src_lines.len());
                let mut refetch_line = None;
                let mut mutate_line = None;
                for j in (i + 1)..end {
                    let jl = src_lines[j].trim().to_ascii_lowercase();
                    if jl.starts_with("//") || jl.starts_with('*') || jl.starts_with('#') {
                        continue;
                    }
                    if refetch_line.is_none()
                        && (jl.contains("getsecret(")
                            || jl.contains("get_secret(")
                            || jl.contains("find(")
                            || jl.contains("findby")
                            || jl.contains("load(")
                            || jl.contains("fetch(")
                            || jl.contains("->get(")
                            || jl.contains(".get(")
                            || jl.contains("select("))
                        && (jl.contains('=') || jl.contains("->"))
                    {
                        refetch_line = Some(j + 1);
                    } else if refetch_line.is_some()
                        && (jl.contains("update(")
                            || jl.contains("save(")
                            || jl.contains("setstate(")
                            || jl.contains("set_state(")
                            || jl.contains("delete(")
                            || jl.contains("write(")
                            || jl.contains("commit("))
                    {
                        mutate_line = Some(j + 1);
                        break;
                    }
                }
                if let (Some(rf), Some(mt)) = (refetch_line, mutate_line) {
                    toctou_hits.push(json!({"check_line": i + 1, "refetch_line": rf, "mutate_line": mt}));
                    if toctou_hits.len() >= 4 {
                        break;
                    }
                }
            }
            if !toctou_hits.is_empty() {
                findings.push(json!({
                    "invariant": "CHECK_THEN_REFETCH_TOCTOU_SURFACE",
                    "file": rel,
                    "sites": toctou_hits,
                    "hypothesis": "Validation/check call is followed by a separate record re-fetch and state mutation without an enclosing DB transaction or lock; verify whether a concurrent request/endpoint can replace or mutate the backing record between check and re-fetch (TOCTOU)."
                }));
            }
        }
    }

    // Structural multi-stage decoding check (covers ALL layered/half/mixed encodings structurally!)
    if decode_sites.len() >= 2 {
        findings.push(json!({
            "invariant": "MULTI_STAGE_DECODE_PIPELINE",
            "sites": decode_sites,
            "hypothesis": "Multiple decode/unescape stages exist in reachable code (violates single-decode idempotence); verify whether validation runs before final decode/canonicalization."
        }));
    }

    json!({
        "schema": "@ALEWO-INVARIANT/1",
        "files_checked": candidate_files.len(),
        "hypothesis_count": findings.len(),
        "hypotheses": findings,
        "non_exhaustive_warning": "These are structural hypotheses only. Zero hypotheses NEVER implies the codebase is safe; always trace full control/data flow and adversarial edge cases."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn detects_multi_stage_decode_and_unverified_slot_and_config_merge() {
        let dir = std::env::temp_dir().join(format!(
            "alewo-inv-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(dir.join("src/Policy")).unwrap();
        fs::create_dir_all(dir.join("src/Storage")).unwrap();
        fs::create_dir_all(dir.join("src/Cache")).unwrap();
        fs::create_dir_all(dir.join("src/Config")).unwrap();

        fs::write(dir.join("src/Policy/V.php"), "<?php $a = rawurldecode($x);").unwrap();
        fs::write(dir.join("src/Storage/M.php"), "<?php $b = urldecode($a);").unwrap();
        fs::write(dir.join("src/Cache/Pool.php"), "<?php $idx = hexdec(substr($k,0,4)) % 32;").unwrap();
        fs::write(dir.join("src/Config/Cfg.php"), "<?php return array_merge($overrides, $base);").unwrap();

        let res = scan(
            &dir,
            &[
                "src/Policy/V.php".into(),
                "src/Storage/M.php".into(),
                "src/Cache/Pool.php".into(),
                "src/Config/Cfg.php".into(),
            ],
        );
        let text = res.to_string();
        assert!(text.contains("MULTI_STAGE_DECODE_PIPELINE"));
        assert!(text.contains("TRUNCATED_OR_UNVERIFIED_SLOT_KEY"));
        assert!(text.contains("CONFIG_MERGE_PRECEDENCE"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detects_check_then_refetch_toctou_surface() {
        let dir = std::env::temp_dir().join(format!(
            "alewo-inv-toctou-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(dir.join("lib/Service")).unwrap();
        fs::write(
            dir.join("lib/Service/Auth.php"),
            "<?php
class Auth {
  public function enable($u, $k) {
    if (!$this->validateToken($u, $k)) { return false; }
    $rec = $this->mapper->find($u);
    $rec->setState(2);
    $this->mapper->update($rec);
    return true;
  }
}
",
        )
        .unwrap();
        let res = scan(&dir, &["lib/Service/Auth.php".into()]);
        assert!(res.to_string().contains("CHECK_THEN_REFETCH_TOCTOU_SURFACE"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
