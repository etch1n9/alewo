//! Cognitive Offloading VM (@ALEWO-VM/1) for Alewo v3.
//! Moves deterministic graph tracing (ws_paths) and targeted program slicing
//! (ws_slice) out of LLM chain-of-thought into fast local Rust execution.
use crate::{
    agent::{blocked, safe},
    polyglot_ast,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn contains_ident(haystack: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    for (idx, _) in haystack.match_indices(ident) {
        let b = haystack[..idx].chars().last();
        let a = haystack[idx + ident.len()..].chars().next();
        if b.map_or(true, |c| !is_ident_char(c)) && a.map_or(true, |c| !is_ident_char(c)) {
            return true;
        }
    }
    false
}

fn collect_code_files(root: &Path, max_files: usize, include_tests:bool) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 10 || out.len() >= max_files {
            continue;
        }
        let mut entries = fs::read_dir(&dir)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries.into_iter().rev() {
            let name = entry.file_name();
            let ns = name.to_string_lossy();
            if ns.starts_with('.')
                || blocked(Path::new(&name))
                || matches!(ns.as_ref(), "vendor" | "node_modules" | "target" | "dist" | "build")
                || (!include_tests&&matches!(ns.as_ref(),"test"|"tests"|"docs"|"examples"|"benchmarks"))
            {
                continue;
            }
            let p = entry.path();
            if p.is_dir() {
                stack.push((p, depth + 1));
                continue;
            }
            if !polyglot_ast::is_code_file(&p) {
                continue;
            }
            out.push(p);
            if out.len() >= max_files {
                break;
            }
        }
    }
    Ok(out)
}

/// ws_paths: Deterministic BFS shortest symbol/file reference paths between
/// `from` and `to` across up to 2,000 polyglot files.
pub fn ws_paths(root: &Path, args: &Value) -> Result<String, String> {
    let from_q = args["from"].as_str().unwrap_or("").trim();
    let to_q = args["to"].as_str().unwrap_or("").trim();
    if from_q.is_empty() || to_q.is_empty() {
        return Err("both 'from' and 'to' symbols or filenames are required".into());
    }
    let max_depth = args["max_depth"].as_u64().unwrap_or(6).clamp(1, 10) as usize;
    let include_tests=args["include_tests"].as_bool().unwrap_or(false);

    let files = collect_code_files(root, 2000,include_tests)?;
    let mut file_text: BTreeMap<String, String> = BTreeMap::new();
    let mut sym_to_files: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for path in &files {
        let Ok(meta) = fs::metadata(path) else { continue; };
        if meta.len() > 1_024_000 {
            continue;
        }
        let Ok(src) = fs::read_to_string(path) else { continue; };
        let rel = path.strip_prefix(root).unwrap_or(path).display().to_string();
        let parsed = polyglot_ast::parse_file(path, &src);
        for sym in parsed.symbols {
            if sym.name.len() >= 3 {
                sym_to_files.entry(sym.name).or_default().insert(rel.clone());
            }
        }
        file_text.insert(rel, src);
    }

    let match_nodes = |q: &str| -> BTreeSet<String> {
        let ql = q.to_ascii_lowercase();
        let mut matched = BTreeSet::new();
        for (rel, src) in &file_text {
            if rel.to_ascii_lowercase().contains(&ql) || contains_ident(src, q) {
                if rel.to_ascii_lowercase().contains(&ql)
                    || sym_to_files.get(q).is_some_and(|set| set.contains(rel))
                {
                    matched.insert(rel.clone());
                }
            }
        }
        if matched.is_empty() {
            for (rel, src) in &file_text {
                if contains_ident(src, q) {
                    matched.insert(rel.clone());
                }
            }
        }
        matched
    };

    let starts = match_nodes(from_q);
    let targets = match_nodes(to_q);
    if starts.is_empty() || targets.is_empty() {
        return Ok(format!(
            "@PATHS/2|from={from_q}|to={to_q}|scanned={}|edges=0|include_tests={include_tests}|paths=0\nNONE",
            file_text.len()
        ));
    }

    // Build an inverted identifier index once. The previous implementation
    // compared every file against every symbol during every BFS expansion.
    let mut adjacency=BTreeMap::<String,BTreeSet<String>>::new();
    let mut edge_count=0usize;
    for (rel,src) in &file_text{
        let identifiers=src.split(|c:char|!is_ident_char(c))
            .filter(|s|s.len()>=3).collect::<BTreeSet<_>>();
        let mut owners=BTreeSet::new();
        for ident in identifiers{
            if let Some(defining)=sym_to_files.get(ident){
                owners.extend(defining.iter().filter(|owner|*owner!=rel).cloned());
            }
        }
        edge_count+=owners.len();
        adjacency.insert(rel.clone(),owners);
    }

    let mut queue: VecDeque<Vec<String>> = starts.iter().map(|s| vec![s.clone()]).collect();
    let mut visited: BTreeSet<String> = starts.clone();
    let mut found_paths: Vec<Vec<String>> = Vec::new();

    while let Some(chain) = queue.pop_front() {
        if found_paths.len() >= 5 {
            break;
        }
        let Some(cur) = chain.last() else { continue; };
        if targets.contains(cur) && chain.len() >= 1 {
            found_paths.push(chain.clone());
            continue;
        }
        if chain.len() > max_depth {
            continue;
        }
        let Some(next_files)=adjacency.get(cur) else{continue;};
        for nf in next_files.iter().cloned() {
            if targets.contains(&nf) {
                let mut done = chain.clone();
                done.push(nf);
                found_paths.push(done);
                if found_paths.len() >= 5 {
                    break;
                }
            } else if visited.insert(nf.clone()) {
                let mut next_chain = chain.clone();
                next_chain.push(nf);
                queue.push_back(next_chain);
            }
        }
    }

    let rendered: Vec<String> = found_paths.iter().map(|p| p.join(" -> ")).collect();
    Ok(format!(
        "@PATHS/2|from={from_q}|to={to_q}|scanned={}|edges={edge_count}|include_tests={include_tests}|paths={}\n{}",
        file_text.len(),
        rendered.len(),
        if rendered.is_empty() {
            "NO_STATIC_PATH_FOUND".to_string()
        } else {
            rendered.join("\n")
        }
    ))
}

/// ws_slice: Deterministic intra-file backward/forward variable & symbol slicer.
/// Returns only the numbered lines in `path` that define, mutate, guard, or use
/// `symbol` (plus optional surrounding context).
pub fn ws_slice(root: &Path, args: &Value) -> Result<String, String> {
    let req = args["path"].as_str().ok_or("missing path")?;
    let symbol = args["symbol"].as_str().unwrap_or("").trim();
    if symbol.is_empty() || symbol.len() > 100 {
        return Err("symbol must be 1..100 chars".into());
    }
    let context = args["context"].as_u64().unwrap_or(1).clamp(0, 3) as usize;
    let path = safe(root, req)?;
    if !path.is_file() {
        return Err("not a regular file".into());
    }
    let src = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = src.lines().collect();
    let mut keep = BTreeSet::new();

    for (idx, line) in lines.iter().enumerate() {
        if contains_ident(line, symbol) || line.contains(symbol) {
            let lo = idx.saturating_sub(context);
            let hi = (idx + context).min(lines.len().saturating_sub(1));
            for k in lo..=hi {
                keep.insert(k);
            }
        }
    }

    let rel = path.strip_prefix(root).unwrap_or(&path).display();
    let sliced: Vec<String> = keep
        .into_iter()
        .take(160)
        .map(|i| format!("L{}:{}", i + 1, lines[i]))
        .collect();
    Ok(format!(
        "@SLICE/1|{}|symbol={}|matched_lines={}|total_lines={}\n{}",
        rel,
        symbol,
        sliced.len(),
        lines.len(),
        sliced.join("\n")
    ))
}

pub fn vm_tool_defs() -> Vec<Value> {
    vec![
        json!({"type":"function","function":{"name":"ws_paths",
            "description":"Shortest static reference paths between two symbols/files.",
            "parameters":{"type":"object","properties":{
                "from":{"type":"string"},"to":{"type":"string"},"max_depth":{"type":"integer","minimum":1,"maximum":10},
                "include_tests":{"type":"boolean","description":"Default false; enable only when test code is part of the requested path."}},
                "required":["from","to"]}}}),
        json!({"type":"function","function":{"name":"ws_slice",
            "description":"Extract numbered lines in a file referencing/mutating a symbol.",
            "parameters":{"type":"object","properties":{
                "path":{"type":"string"},"symbol":{"type":"string"},"context":{"type":"integer","minimum":0,"maximum":3}},
                "required":["path","symbol"]}}}),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn paths_and_slice_trace_cross_file_chains() {
        let dir = std::env::temp_dir().join(format!(
            "alewo-vm-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/Router.php"), "<?php class Router { function go(){ return (new Service())->run(); }}").unwrap();
        fs::write(dir.join("src/Service.php"), "<?php class Service { function run(){ return (new Pool())->fetchSlot($k); }}").unwrap();
        fs::write(dir.join("src/Pool.php"), "<?php class Pool {\n  function fetchSlot($fullKey){\n    $idx = hexdec(substr($fullKey,0,4)) % 32;\n    return $this->slots[$idx] ?? null;\n  }\n}").unwrap();
        fs::create_dir_all(dir.join("tests")).unwrap();
        fs::write(dir.join("tests/Trap.php"),
            "<?php class Trap { function fake(){ return (new Router())->go(); }}").unwrap();

        let p = ws_paths(&dir, &json!({"from": "Router", "to": "Pool"})).unwrap();
        assert!(p.contains("src/Router.php -> src/Service.php -> src/Pool.php"));
        assert!(p.contains("@PATHS/2"));
        let excluded=ws_paths(&dir,&json!({"from":"Trap","to":"Pool"})).unwrap();
        assert!(excluded.contains("paths=0"));
        let included=ws_paths(&dir,&json!({"from":"Trap","to":"Pool","include_tests":true})).unwrap();
        assert!(included.contains("tests/Trap.php -> src/Router.php -> src/Service.php -> src/Pool.php"));

        let s = ws_slice(&dir, &json!({"path": "src/Pool.php", "symbol": "fullKey", "context": 0})).unwrap();
        assert!(s.contains("L2:"));
        assert!(s.contains("L3:"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
