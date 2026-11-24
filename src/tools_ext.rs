//! Extended read-only and gated workspace navigation tools for Alewo.
//! Designed for deep multi-file search, cross-file symbol tracing, and batched
//! slice reading on large repositories with zero external crate dependencies.
use crate::agent::{blocked, safe};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn matches_wildcard(text: &str, pat: &str) -> bool {
    if !pat.contains('*') {
        return text.contains(pat);
    }
    let parts: Vec<&str> = pat.split('*').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }
    let mut pos = 0usize;
    for part in parts {
        if let Some(found) = text[pos..].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}

fn contains_whole_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    for (idx, _) in haystack.match_indices(needle) {
        let before = haystack[..idx].chars().last();
        let after = haystack[idx + needle.len()..].chars().next();
        let ok_b = before.map_or(true, |c| !is_ident_char(c));
        let ok_a = after.map_or(true, |c| !is_ident_char(c));
        if ok_b && ok_a {
            return true;
        }
    }
    false
}

fn collect_files(root: &Path, start: &Path, max_files: usize, ext_filter: Option<&str>) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![(start.to_path_buf(), 0usize)];
    while let Some((path, depth)) = stack.pop() {
        if out.len() >= max_files {
            break;
        }
        if path.is_dir() {
            if depth > 12 {
                continue;
            }
            let mut entries = fs::read_dir(&path)
                .map_err(|e| e.to_string())?
                .filter_map(Result::ok)
                .collect::<Vec<_>>();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries.into_iter().rev() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                let skip_non_prod = start == root && matches!(
                    name_str.to_ascii_lowercase().as_str(),
                    "test" | "tests" | "docs" | "doc" | "examples" | "example" | "benchmarks" | "benchmark" | "testdata" | "fixtures"
                );
                if name_str.starts_with('.') || blocked(Path::new(&name)) || matches!(name_str.as_ref(), "vendor" | "node_modules" | "target") || skip_non_prod {
                    continue;
                }
                if let Ok(canon) = safe(root, &entry.path().to_string_lossy()) {
                    stack.push((canon, depth + 1));
                }
            }
            continue;
        }
        if let Some(ext) = ext_filter {
            let fext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
            if !fext.eq_ignore_ascii_case(ext.trim_start_matches('.')) {
                continue;
            }
        }
        out.push(path);
    }
    Ok(out)
}

/// 1. ws_tree: Recursive directory tree & extension summary in one call.
pub fn ws_tree(root: &Path, args: &Value) -> Result<String, String> {
    let start = safe(root, args["path"].as_str().unwrap_or("."))?;
    if !start.is_dir() {
        return Err("path must be a directory".into());
    }
    let max_depth = args["max_depth"].as_u64().unwrap_or(4).clamp(1, 10) as usize;
    let max_entries = args["max_entries"].as_u64().unwrap_or(200).clamp(10, 500) as usize;
    let ext_filter = args["ext"].as_str().map(str::trim).filter(|s| !s.is_empty());

    let mut lines = Vec::new();
    let mut dirs_total = 0usize;
    let mut files_total = 0usize;
    let mut bytes_total = 0u64;
    let mut by_ext: BTreeMap<String, usize> = BTreeMap::new();

    fn walk(
        root: &Path,
        dir: &Path,
        depth: usize,
        max_depth: usize,
        max_entries: usize,
        ext_filter: Option<&str>,
        lines: &mut Vec<String>,
        dirs_total: &mut usize,
        files_total: &mut usize,
        bytes_total: &mut u64,
        by_ext: &mut BTreeMap<String, usize>,
    ) -> Result<(), String> {
        let mut entries = fs::read_dir(dir)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            if name_s.starts_with('.') || blocked(Path::new(&name)) || matches!(name_s.as_ref(), "vendor" | "node_modules" | "target") {
                continue;
            }
            let Ok(canon) = safe(root, &entry.path().to_string_lossy()) else { continue; };
            let rel = canon.strip_prefix(root).unwrap_or(&canon).display().to_string();
            let meta = match entry.metadata() { Ok(m) => m, Err(_) => continue };
            if meta.is_dir() {
                *dirs_total += 1;
                if depth <= max_depth && lines.len() < max_entries {
                    lines.push(format!("D|{}", rel));
                }
                if depth < max_depth {
                    walk(root, &canon, depth + 1, max_depth, max_entries, ext_filter, lines, dirs_total, files_total, bytes_total, by_ext)?;
                }
            } else {
                let ext = canon.extension().and_then(|x| x.to_str()).unwrap_or("none").to_ascii_lowercase();
                if let Some(want) = ext_filter {
                    if !ext.eq_ignore_ascii_case(want.trim_start_matches('.')) {
                        continue;
                    }
                }
                *files_total += 1;
                *bytes_total += meta.len();
                *by_ext.entry(ext).or_insert(0) += 1;
                if lines.len() < max_entries {
                    lines.push(format!("F|{}|{}", rel, meta.len()));
                }
            }
        }
        Ok(())
    }

    walk(root, &start, 1, max_depth, max_entries, ext_filter, &mut lines, &mut dirs_total, &mut files_total, &mut bytes_total, &mut by_ext)?;
    let ext_summary = by_ext.iter().map(|(k, v)| format!("{k}:{v}")).collect::<Vec<_>>().join(",");
    Ok(format!(
        "@TREE/1|dirs={dirs_total}|files={files_total}|bytes={bytes_total}|shown={}|exts={ext_summary}\n{}",
        lines.len(),
        lines.join("\n")
    ))
}

/// 2. ws_grep: Deep multi-file pattern search (OR `|`, `*` wildcards, case-insensitive,
/// whole-word, extension filter, and context lines) across up to 2,000 files.
pub fn ws_grep(root: &Path, args: &Value) -> Result<String, String> {
    let start = safe(root, args["path"].as_str().unwrap_or("."))?;
    let query = args["query"].as_str().unwrap_or("").trim();
    if query.is_empty() || query.len() > 200 {
        return Err("query must be 1..200 chars".into());
    }
    let case_insensitive = args["case_insensitive"].as_bool().unwrap_or(false);
    let whole_word = args["whole_word"].as_bool().unwrap_or(false);
    let context = args["context"].as_u64().unwrap_or(0).clamp(0, 4) as usize;
    let limit = args["limit"].as_u64().unwrap_or(40).clamp(1, 80) as usize;
    let ext_filter = args["ext"].as_str().map(str::trim).filter(|s| !s.is_empty());

    let terms: Vec<String> = query
        .split('|')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(unescape_regex_literals)
        .map(|s| if case_insensitive { s.to_ascii_lowercase() } else { s })
        .collect();
    if terms.is_empty() {
        return Err("empty query terms".into());
    }

    let files = collect_files(root, &start, 2000, ext_filter)?;
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    let mut bytes_out = 0usize;

    for path in files {
        if hits.len() >= limit || bytes_out > 22_000 {
            break;
        }
        let Ok(meta) = fs::metadata(&path) else { continue; };
        if meta.len() > 1_024_000 {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else { continue; };
        scanned += 1;
        let rel = path.strip_prefix(root).unwrap_or(&path).display().to_string();
        let all_lines: Vec<&str> = content.lines().collect();
        for (idx, line) in all_lines.iter().enumerate() {
            let candidate = if case_insensitive { line.to_ascii_lowercase() } else { (*line).to_string() };
            let matched = terms.iter().any(|t| {
                if whole_word && !t.contains('*') {
                    contains_whole_word(&candidate, t)
                } else {
                    matches_wildcard(&candidate, t)
                }
            });
            if matched {
                let mut block = String::new();
                let lo = idx.saturating_sub(context);
                let hi = (idx + context).min(all_lines.len().saturating_sub(1));
                for k in lo..=hi {
                    let marker = if k == idx { ":" } else { "-" };
                    let snippet: String = all_lines[k].chars().take(220).collect();
                    block.push_str(&format!("{rel}{marker}{}{marker}{snippet}\n", k + 1));
                }
                bytes_out += block.len();
                hits.push(block.trim_end().to_string());
                if hits.len() >= limit || bytes_out > 22_000 {
                    break;
                }
            }
        }
    }

    Ok(format!(
        "@GREP/1|pattern={query}|scanned={scanned}|hits={}\n{}",
        hits.len(),
        hits.join("\n--\n")
    ))
}

/// 3. ws_symbol_index: Cross-file symbol definition indexer (PHP AST + multi-language lexical).
pub fn ws_symbol_index(root: &Path, args: &Value) -> Result<String, String> {
    let start = safe(root, args["path"].as_str().unwrap_or("."))?;
    let query = args["query"].as_str().unwrap_or("").trim().to_ascii_lowercase();
    let ext_filter = args["ext"].as_str().map(str::trim).filter(|s| !s.is_empty());
    let limit = args["limit"].as_u64().unwrap_or(120).clamp(1, 300) as usize;

    let files = collect_files(root, &start, 2000, ext_filter)?;
    let mut rows = Vec::new();
    let mut scanned = 0usize;

    for path in files {
        if rows.len() >= limit {
            break;
        }
        let Ok(meta) = fs::metadata(&path) else { continue; };
        if meta.len() > 1_024_000 {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else { continue; };
        scanned += 1;
        let rel = path.strip_prefix(root).unwrap_or(&path).display().to_string();
        let parsed = crate::polyglot_ast::parse_file(&path, &content);
        for sym in parsed.symbols {
            if !query.is_empty() && !sym.name.to_ascii_lowercase().contains(&query) && !rel.to_ascii_lowercase().contains(&query) {
                continue;
            }
            rows.push(format!("{rel}:{}|{}|{}|{}", sym.line, parsed.lang, sym.kind, sym.name));
            if rows.len() >= limit {
                break;
            }
        }
    }

    Ok(format!(
        "@SYMBOLS/1|scanned={scanned}|matched={}\n{}",
        rows.len(),
        rows.join("\n")
    ))
}

/// 4. ws_callers: Cross-file reference & caller tracer for a symbol identifier.
pub fn ws_callers(root: &Path, args: &Value) -> Result<String, String> {
    let symbol = args["symbol"].as_str().unwrap_or("").trim();
    if symbol.is_empty() || symbol.len() > 100 || !symbol.chars().all(is_ident_char) {
        return Err("symbol must be a valid identifier (1..100 alphanumeric/underscore chars)".into());
    }
    let start = safe(root, args["path"].as_str().unwrap_or("."))?;
    let ext_filter = args["ext"].as_str().map(str::trim).filter(|s| !s.is_empty());
    let limit = args["limit"].as_u64().unwrap_or(60).clamp(1, 150) as usize;

    let files = collect_files(root, &start, 2000, ext_filter)?;
    let mut defs = Vec::new();
    let mut calls = Vec::new();
    let mut refs = Vec::new();
    let mut scanned = 0usize;

    for path in files {
        if defs.len() + calls.len() + refs.len() >= limit {
            break;
        }
        let Ok(meta) = fs::metadata(&path) else { continue; };
        if meta.len() > 1_024_000 {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else { continue; };
        scanned += 1;
        if !content.contains(symbol) {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(&path).display().to_string();
        let parsed=crate::polyglot_ast::parse_file(&path,&content);
        let definition_lines=parsed.symbols.iter().filter(|candidate|
            candidate.name==symbol||candidate.name.ends_with(&format!("::{symbol}"))||
            candidate.name.ends_with(&format!(".{symbol}")))
            .map(|candidate|candidate.line).collect::<BTreeSet<_>>();
        for (idx, line) in content.lines().enumerate() {
            if !contains_whole_word(line, symbol) {
                continue;
            }
            let trim = line.trim();
            let row = format!("{rel}:{}:{}", idx + 1, trim.chars().take(180).collect::<String>());
            if definition_lines.contains(&(idx+1))
                || trim.contains(&format!("function {symbol}"))
                || trim.contains(&format!("class {symbol}"))
                || trim.contains(&format!("fn {symbol}"))
                || trim.contains(&format!("def {symbol}"))
            {
                defs.push(format!("DEF|{row}"));
            } else if trim.contains(&format!("->{symbol}("))
                || trim.contains(&format!("::{symbol}("))
                || trim.contains(&format!("new {symbol}"))
                || trim.contains(&format!("{symbol}("))
            {
                calls.push(format!("CALL|{row}"));
            } else {
                refs.push(format!("REF|{row}"));
            }
            if defs.len() + calls.len() + refs.len() >= limit {
                break;
            }
        }
    }

    let mut all = Vec::new();
    all.extend(defs);
    all.extend(calls);
    all.extend(refs);
    Ok(format!(
        "@CALLERS/1|symbol={symbol}|scanned={scanned}|hits={}\n{}",
        all.len(),
        all.join("\n")
    ))
}

/// 5. ws_read_multi: Batched multi-slice file reader (up to 6 slices in 1 tool call).
pub fn ws_read_multi(root: &Path, args: &Value) -> Result<String, String> {
    let slices = args["slices"].as_array().ok_or("slices must be an array of {path, line?, count?}")?;
    if slices.is_empty() || slices.len() > 6 {
        return Err("slices must contain 1..6 items".into());
    }
    let mut blocks = Vec::new();
    let mut total_bytes = 0usize;

    for item in slices {
        let req_path = item["path"].as_str().ok_or("slice missing path")?;
        let path = safe(root, req_path)?;
        if !path.is_file() {
            return Err(format!("not a regular file: {req_path}"));
        }
        let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
        if meta.len() > 8_000_000 {
            return Err(format!("file too large: {req_path}"));
        }
        let bytes = fs::read(&path).map_err(|e| e.to_string())?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "not UTF-8 text")?;
        let start = item["line"].as_u64().unwrap_or(1).clamp(1, 100_000) as usize;
        let count = item["count"].as_u64().unwrap_or(60).clamp(1, 150) as usize;
        let numbered: Vec<String> = text
            .lines()
            .enumerate()
            .skip(start - 1)
            .take(count)
            .map(|(i, l)| format!("{}|{}", i + 1, l))
            .collect();
        let rel = path.strip_prefix(root).unwrap_or(&path).display();
        let block = format!(
            "@FILE/1|{}|sha256={}|from={}|lines={}|total_lines={}\n{}",
            rel,
            digest(&bytes),
            start,
            numbered.len(),
            text.lines().count(),
            numbered.join("\n")
        );
        total_bytes += block.len();
        if total_bytes > 30_000 {
            return Err("combined multi-slice output exceeds 30KB; reduce slice counts".into());
        }
        blocks.push(block);
    }

    Ok(format!("@MULTI-READ/1|slices={}\n{}", blocks.len(), blocks.join("\n---\n")))
}

/// 6. ws_file_outline: Compact metadata + symbol outline for a single file.
pub fn ws_file_outline(root: &Path, args: &Value) -> Result<String, String> {
    let req_path = args["path"].as_str().ok_or("missing path")?;
    let path = safe(root, req_path)?;
    if !path.is_file() {
        return Err("not a regular file".into());
    }
    let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
    if meta.len() > 8_000_000 {
        return Err("file too large".into());
    }
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "not UTF-8 text")?;
    let parsed = crate::polyglot_ast::parse_file(&path, text);
    let sym_lines: Vec<String> = parsed.symbols.into_iter().map(|s| format!("{}|{}|{}", s.line, s.kind, s.name)).collect();
    let rel = path.strip_prefix(root).unwrap_or(&path).display();
    Ok(format!(
        "@OUTLINE/1|{}|lang={}|engine={}|lines={}|bytes={}|sha256={}|symbols={}\n{}",
        rel,
        parsed.lang,
        parsed.engine,
        text.lines().count(),
        bytes.len(),
        digest(&bytes),
        sym_lines.len(),
        sym_lines.join("\n")
    ))
}

/// 7. ws_create_file: Gated file creation (requires --allow-write, refuses overwrite & secret paths).
pub fn ws_create_file(root: &Path, args: &Value) -> Result<String, String> {
    let req = args["path"].as_str().unwrap_or("").trim();
    let content = args["content"].as_str().ok_or("content must be a string")?;
    if req.is_empty() || content.len() > 200_000 {
        return Err("invalid path or content size (>200KB)".into());
    }
    let rel = Path::new(req);
    if rel.is_absolute() || rel.components().any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_))) {
        return Err("path must be a clean relative path inside project root".into());
    }
    if blocked(rel) {
        return Err("sensitive path denied".into());
    }
    let dest = root.join(rel);
    if dest.exists() {
        return Err("file already exists; use ws_replace to edit existing files".into());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let canon_parent = fs::canonicalize(parent).map_err(|e| e.to_string())?;
        if !canon_parent.starts_with(root) {
            return Err("parent escapes project root".into());
        }
    }
    let mut f = OpenOptions::new().write(true).create_new(true).open(&dest).map_err(|e| e.to_string())?;
    f.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    Ok(format!(
        "@CREATE/1|path={}|bytes={}|sha256={}",
        rel.display(),
        content.len(),
        digest(content.as_bytes())
    ))
}


fn unescape_regex_literals(term: &str) -> String {
    // Models frequently write regex-style escapes like `memcpy\(` or `foo\.bar`.
    // Convert common escaped punctuation back to literal characters so ws_grep
    // never silently returns 0 hits on valid symbol/call queries.
    let mut out = String::with_capacity(term.len());
    let mut chars = term.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if matches!(next, '(' | ')' | '.' | '[' | ']' | '{' | '}' | '+' | '?' | '/' | '^' | '$' | '-') {
                    out.push(next);
                    chars.next();
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

fn structural_braces(line:&str,block_comment:&mut bool,quote:&mut Option<char>,
    escaped:&mut bool)->(i32,bool){
    let mut delta=0i32;let mut saw=false;let mut chars=line.chars().peekable();
    while let Some(ch)=chars.next(){
        if *block_comment{
            if ch=='*'&&chars.peek()==Some(&'/'){chars.next();*block_comment=false;}
            continue;
        }
        if let Some(active)=*quote{
            if *escaped{*escaped=false;continue;}
            if ch=='\\'{*escaped=true;continue;}
            if ch==active{*quote=None;}
            continue;
        }
        if ch=='/'&&chars.peek()==Some(&'/'){break;}
        if ch=='/'&&chars.peek()==Some(&'*'){chars.next();*block_comment=true;continue;}
        if ch=='"'||ch=='`'||(ch=='\''&&chars.clone().any(|c|c=='\'')){
            *quote=Some(ch);*escaped=false;continue;
        }
        if ch=='{'{delta+=1;saw=true;}else if ch=='}'{delta-=1;}
    }
    (delta,saw)
}

pub fn ws_read_symbol(root: &Path, args: &Value) -> Result<String, String> {
    let req_path = args["path"].as_str().ok_or("missing path")?;
    let symbol = args["symbol"].as_str().unwrap_or("").trim();
    if symbol.is_empty() || symbol.len() > 160 {
        return Err("symbol must be 1..160 chars".into());
    }
    let max_lines = args["max_lines"].as_u64().unwrap_or(140).clamp(10, 300) as usize;
    let path = safe(root, req_path)?;
    if !path.is_file() {
        return Err(format!("not a regular file: {req_path}"));
    }
    let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
    if meta.len() > 8_000_000 {
        return Err("file too large (>8MB)".into());
    }
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let all_lines: Vec<&str> = content.lines().collect();
    if all_lines.is_empty() {
        return Err(format!("empty file: {req_path}"));
    }

    let parsed = crate::polyglot_ast::parse_file(&path, &content);
    let mut start_line_1 = parsed
        .symbols
        .iter()
        .find(|s| s.name == symbol)
        .or_else(|| parsed.symbols.iter().find(|s| s.name.ends_with(&format!("::{symbol}")) || s.name.ends_with(&format!(".{symbol}"))))
        .map(|s| s.line);

    if start_line_1.is_none() {
        for (i, line) in all_lines.iter().enumerate() {
            if contains_whole_word(line, symbol) {
                let t = line.trim();
                if !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with('*') && !t.starts_with('#') {
                    start_line_1 = Some(i + 1);
                    break;
                }
            }
        }
    }
    let Some(def_line) = start_line_1 else {
        return Err(format!("symbol '{symbol}' not found in {req_path}"));
    };

    let start_idx = def_line.saturating_sub(1);
    let ctx_start = start_idx.saturating_sub(2);
    let mut end_idx = (start_idx + max_lines).min(all_lines.len());

    let mut brace_depth: i32 = 0;
    let mut saw_open_brace = false;
    let mut block_comment=false;let mut quote=None;let mut escaped=false;
    let scan_limit = (start_idx + max_lines).min(all_lines.len());
    for i in start_idx..scan_limit {
        let (delta,saw)=structural_braces(all_lines[i],&mut block_comment,
            &mut quote,&mut escaped);
        brace_depth+=delta;saw_open_brace|=saw;
        if saw_open_brace && brace_depth <= 0 {
            end_idx = i + 1;
            break;
        }
    }

    if !saw_open_brace {
        let base_indent = all_lines[start_idx].len() - all_lines[start_idx].trim_start().len();
        for i in (start_idx + 1)..scan_limit {
            let line = all_lines[i];
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent <= base_indent && !trimmed.starts_with("elif") && !trimmed.starts_with("else") && !trimmed.starts_with("except") && !trimmed.starts_with("finally") {
                end_idx = i;
                break;
            }
        }
    }

    let mut out = format!(
        "@ALEWO-SYMBOL/1|path={req_path}|symbol={symbol}|lines={}..{}|total_file_lines={}
",
        ctx_start + 1,
        end_idx,
        all_lines.len()
    );
    for i in ctx_start..end_idx {
        out.push_str(&format!("{}|{}
", i + 1, all_lines[i]));
    }
    Ok(out)
}

pub fn ws_mutations(root:&Path,args:&Value)->Result<String,String>{
    let start=safe(root,args["path"].as_str().unwrap_or("."))?;
    let query=args["query"].as_str().unwrap_or("").trim().to_ascii_lowercase();
    let limit=args["limit"].as_u64().unwrap_or(120).clamp(1,300) as usize;
    let files=collect_files(root,&start,3000,None)?;
    let mut rows=Vec::new();let mut scanned=0usize;
    for path in files{
        if rows.len()>=limit{break;}
        let Ok(meta)=fs::metadata(&path) else{continue;};
        if meta.len()>1_024_000{continue;}
        let Ok(content)=fs::read_to_string(&path) else{continue;};
        scanned+=1;
        let rel=path.strip_prefix(root).unwrap_or(&path).display();
        for (index,line) in content.lines().enumerate(){
            let trimmed=line.trim();
            if trimmed.is_empty()||trimmed.starts_with("//")||trimmed.starts_with('#')||
                trimmed.starts_with("/*")||trimmed.starts_with('*'){continue;}
            let lower=trimmed.to_ascii_lowercase();
            if !query.is_empty()&&!lower.contains(&query){continue;}
            let class=if ["memcpy(","memmove(","strcpy(","strcat(","sprintf("]
                .iter().any(|p|lower.contains(p)){"memory_write"}
            else if ["insert ","update ","delete ","file_put_contents(","fwrite(",
                ".write(", "save(", "store(", "remove("].iter().any(|p|lower.contains(p)){
                "persistent_or_state_write"
            }else{
                let assignment=trimmed.contains("+=")||trimmed.contains("-=")||
                    trimmed.contains("*=")||trimmed.contains("/=")||trimmed.contains("++")||
                    trimmed.contains("--")||trimmed.split('=').count()>1&&
                    !["==","!=",">=","<=","=>"].iter().any(|p|trimmed.contains(p));
                if !assignment{continue;}
                "assignment"
            };
            rows.push(format!("{class}|{rel}:{}|{}",
                index+1,trimmed.chars().take(220).collect::<String>()));
            if rows.len()>=limit{break;}
        }
    }
    Ok(format!("@MUTATIONS/1|scanned={scanned}|matched={}|query={}\n{}",
        rows.len(),query,rows.join("\n")))
}

pub fn ext_tool_defs(allow_write: bool) -> Vec<Value> {
    let mut defs = vec![
        json!({"type":"function","function":{"name":"ws_tree",
            "description":"Recursive directory tree & extension counts.",
            "parameters":{"type":"object","properties":{
                "path":{"type":"string"},"max_depth":{"type":"integer","minimum":1,"maximum":10},
                "max_entries":{"type":"integer","minimum":10,"maximum":500},"ext":{"type":"string"}}}}}),
        json!({"type":"function","function":{"name":"ws_grep",
            "description":"Multi-file pattern search ('|' OR, '*' wildcard, auto-unescapes regex punctuation, context, <=2000 files).",
            "parameters":{"type":"object","properties":{
                "query":{"type":"string"},"path":{"type":"string"},"ext":{"type":"string"},
                "case_insensitive":{"type":"boolean"},"whole_word":{"type":"boolean"},
                "context":{"type":"integer","minimum":0,"maximum":4},"limit":{"type":"integer","minimum":1,"maximum":80}},
                "required":["query"]}}}),
        json!({"type":"function","function":{"name":"ws_symbol_index",
            "description":"Polyglot symbol definitions index (<=2000 files).",
            "parameters":{"type":"object","properties":{
                "path":{"type":"string"},"query":{"type":"string"},"ext":{"type":"string"},
                "limit":{"type":"integer","minimum":1,"maximum":300}}}}}),
        json!({"type":"function","function":{"name":"ws_callers",
            "description":"Cross-file definitions, calls & refs for one symbol.",
            "parameters":{"type":"object","properties":{
                "symbol":{"type":"string"},"path":{"type":"string"},"ext":{"type":"string"},
                "limit":{"type":"integer","minimum":1,"maximum":150}},
                "required":["symbol"]}}}),
        json!({"type":"function","function":{"name":"ws_read_multi",
            "description":"Batch-read 1..6 file slices in one call.",
            "parameters":{"type":"object","properties":{
                "slices":{"type":"array","items":{"type":"object","properties":{
                    "path":{"type":"string"},"line":{"type":"integer","minimum":1},"count":{"type":"integer","minimum":1,"maximum":150}},
                    "required":["path"]}}},
                "required":["slices"]}}}),
        json!({"type":"function","function":{"name":"ws_file_outline",
            "description":"Single-file stats & symbol outline with line numbers.",
            "parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}}),
        json!({"type":"function","function":{"name":"ws_read_symbol",
            "description":"Read complete verbatim definition body of a function/struct/class/method by symbol name in one call.",
            "parameters":{"type":"object","properties":{
                "path":{"type":"string"},"symbol":{"type":"string"},
                "max_lines":{"type":"integer","minimum":10,"maximum":300}},
                "required":["path","symbol"]}}}),
        json!({"type":"function","function":{"name":"ws_mutations",
            "description":"Map likely assignments, memory writes, and persistent/state mutations across production source. Navigation evidence only.",
            "parameters":{"type":"object","properties":{
                "path":{"type":"string"},"query":{"type":"string"},
                "limit":{"type":"integer","minimum":1,"maximum":300}}}}}),
    ];
    if allow_write {
        defs.push(json!({"type":"function","function":{"name":"ws_create_file",
            "description":"Create new non-secret file (no overwrite; requires --allow-write).",
            "parameters":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}}}));
    }
    defs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_proj(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "alewo-ext-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/Alpha.php"),
            "<?php\nclass Alpha {\n    public function computeKey($x) { return $x; }\n}\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/Caller.php"),
            "<?php\nfunction run() {\n    $a = new Alpha();\n    return $a->computeKey('hello');\n}\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn tree_grep_symbols_callers_outline_and_multi_read_work() {
        let dir = tmp_proj("all");
        let tree = ws_tree(&dir, &json!({"path": ".", "ext": "php"})).unwrap();
        assert!(tree.contains("files=2"));
        assert!(tree.contains("src/Alpha.php"));

        let grep = ws_grep(&dir, &json!({"query": "computeKey|nonexistent", "context": 1, "ext": "php"})).unwrap();
        assert!(grep.contains("hits=2"));
        assert!(grep.contains("src/Caller.php:4:"));

        let syms = ws_symbol_index(&dir, &json!({"query": "compute"})).unwrap();
        assert!(syms.contains("src/Alpha.php:3|php|method|computeKey"));

        let callers = ws_callers(&dir, &json!({"symbol": "computeKey"})).unwrap();
        assert!(callers.contains("DEF|src/Alpha.php:3:"));
        assert!(callers.contains("CALL|src/Caller.php:4:"));

        let outline = ws_file_outline(&dir, &json!({"path": "src/Alpha.php"})).unwrap();
        assert!(outline.contains("2|class|Alpha"));
        assert!(outline.contains("3|method|computeKey"));

        let multi = ws_read_multi(&dir, &json!({"slices": [
            {"path": "src/Alpha.php", "line": 1, "count": 10},
            {"path": "src/Caller.php", "line": 1, "count": 10}
        ]})).unwrap();
        assert!(multi.contains("@MULTI-READ/1|slices=2"));
        assert!(multi.contains("computeKey"));

        let grep_esc = ws_grep(&dir, &json!({"query": "computeKey\\(|nonexistent", "ext": "php"})).unwrap();
        assert!(grep_esc.contains("hits=2"));
        let sym_body = ws_read_symbol(&dir, &json!({"path": "src/Alpha.php", "symbol": "computeKey"})).unwrap();
        assert!(sym_body.contains("@ALEWO-SYMBOL/1"));
        assert!(sym_body.contains("computeKey"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn c_definitions_mutations_and_structural_symbol_body_are_precise(){
        let dir=tmp_proj("polyglot");
        fs::write(dir.join("src/native.c"),
            "int compute_total(int *x) { *x += 1; return *x; }\nint call_total(void){int x=0;return compute_total(&x);}\n").unwrap();
        fs::write(dir.join("src/Tricky.php"),
            "<?php\nfunction tricky($x) {\n  $text = \"} not structural\"; // } ignored\n  if ($x) { $x += 1; }\n  return $x;\n}\nfunction after() { return 2; }\n").unwrap();
        let callers=ws_callers(&dir,&json!({"symbol":"compute_total"})).unwrap();
        assert!(callers.contains("DEF|src/native.c:1:"));
        assert!(callers.contains("CALL|src/native.c:2:"));
        let mutations=ws_mutations(&dir,&json!({"path":"src","query":"x","limit":20})).unwrap();
        assert!(mutations.contains("assignment|src/native.c:1"));
        let body=ws_read_symbol(&dir,&json!({"path":"src/Tricky.php","symbol":"tricky"})).unwrap();
        assert!(body.contains("5|  return $x;"));
        assert!(!body.contains("7|function after"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn create_file_refuses_overwrite_and_secrets() {
        let dir = tmp_proj("create");
        let created = ws_create_file(&dir, &json!({"path": "src/NewFile.php", "content": "<?php echo 1;\n"})).unwrap();
        assert!(created.contains("@CREATE/1|path=src/NewFile.php"));
        assert!(ws_create_file(&dir, &json!({"path": "src/NewFile.php", "content": "overwrite"})).is_err());
        assert!(ws_create_file(&dir, &json!({"path": ".env", "content": "SECRET=1"})).is_err());
        assert!(ws_create_file(&dir, &json!({"path": "../escape.php", "content": "x"})).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
