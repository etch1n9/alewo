//! Unified Polyglot AST Engine for Alewo.
//! - Tier 1: 19 Native Tree-sitter AST grammars (PHP, JS/JSX, TS, TSX, Python,
//!   Rust, Go, Java, C, C++, C#, Ruby, Bash, HTML, CSS, JSON, Lua, Zig, Elixir).
//! - Tier 2: Universal structural/lexical fallback covering every other
//!   programming, scripting, query, and DSL language so no source file is skipped.
use serde_json::{json, Value};
use std::path::Path;
use tree_sitter::{Language, Node, Parser};

#[derive(Debug, Clone)]
pub struct SymbolDef {
    pub line: usize,
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub line: usize,
    pub expr: String,
}

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub lang: &'static str,
    pub engine: &'static str,
    pub symbols: Vec<SymbolDef>,
    pub calls: Vec<CallSite>,
    #[allow(dead_code)]
    pub imports: Vec<String>,
    pub features: Vec<Value>,
}

pub const NATIVE_LANGUAGES: &[&str] = &[
    "php",
    "javascript",
    "typescript",
    "tsx",
    "python",
    "rust",
    "go",
    "java",
    "c",
    "cpp",
    "csharp",
    "ruby",
    "bash",
    "html",
    "css",
    "json",
    "lua",
    "zig",
    "elixir",
];

fn native_language(lang: &str) -> Option<Language> {
    match lang {
        "php" => Some(tree_sitter_php::LANGUAGE_PHP.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "c" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "csharp" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        "ruby" => Some(tree_sitter_ruby::LANGUAGE.into()),
        "bash" => Some(tree_sitter_bash::LANGUAGE.into()),
        "html" => Some(tree_sitter_html::LANGUAGE.into()),
        "css" => Some(tree_sitter_css::LANGUAGE.into()),
        "json" => Some(tree_sitter_json::LANGUAGE.into()),
        "lua" => Some(tree_sitter_lua::LANGUAGE.into()),
        "zig" => Some(tree_sitter_zig::LANGUAGE.into()),
        "elixir" => Some(tree_sitter_elixir::LANGUAGE.into()),
        _ => None,
    }
}

pub fn detect_language(path: &Path, src: &str) -> &'static str {
    let fname = path
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if fname == "dockerfile" || fname.starts_with("dockerfile.") {
        return "dockerfile";
    }
    if fname == "makefile" || fname == "gnumakefile" {
        return "makefile";
    }
    if fname == "cmakelists.txt" {
        return "cmake";
    }

    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "php" | "phtml" | "php5" | "php8" => "php",
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "ts" | "mts" | "cts" => "typescript",
        "tsx" => "tsx",
        "py" | "pyw" | "pyi" => "python",
        "rs" => "rust",
        "go" => "go",
        "java" => "java",
        "c" | "h" => "c",
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" | "inl" => "cpp",
        "cs" => "csharp",
        "rb" | "rake" | "gemspec" => "ruby",
        "sh" | "bash" | "zsh" | "ksh" => "bash",
        "html" | "htm" | "xhtml" => "html",
        "css" | "scss" | "sass" | "less" => "css",
        "json" | "jsonc" => "json",
        "lua" => "lua",
        "zig" => "zig",
        "ex" | "exs" => "elixir",
        // Tier-2 universal languages
        "kt" | "kts" => "kotlin",
        "swift" => "swift",
        "scala" | "sc" => "scala",
        "dart" => "dart",
        "hs" | "lhs" => "haskell",
        "ml" | "mli" => "ocaml",
        "pl" | "pm" => "perl",
        "r" => "r",
        "jl" => "julia",
        "sol" => "solidity",
        "move" => "move",
        "cairo" => "cairo",
        "sql" => "sql",
        "graphql" | "gql" => "graphql",
        "proto" => "protobuf",
        "tf" | "tfvars" | "hcl" => "hcl",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        "xml" | "xsd" | "xsl" => "xml",
        "nix" => "nix",
        "groovy" | "gradle" => "groovy",
        "ps1" | "psm1" => "powershell",
        "vue" => "vue",
        "svelte" => "svelte",
        "astro" => "astro",
        "erl" | "hrl" => "erlang",
        "clj" | "cljs" | "cljc" => "clojure",
        "nim" => "nim",
        "v" => "vlang",
        "m" | "mm" => "objc",
        "f" | "f90" | "f95" => "fortran",
        "cob" | "cbl" => "cobol",
        "pas" => "pascal",
        "s" | "asm" => "assembly",
        "ps" | "eps" => "postscript",
        "lisp" | "lsp" | "cl" | "el" => "lisp",
        "scm" | "ss" | "rkt" => "scheme",
        "tcl" => "tcl",
        "fth" | "fs" | "4th" => "forth",
        "awk" => "awk",
        "tex" | "sty" | "cls" => "latex",
        "pro" => "prolog",
        "twig" | "blade" | "ejs" | "hbs" => "template",
        _ => {
            // Shebang fallback for extensionless scripts
            if let Some(first) = src.lines().next() {
                if first.starts_with("#!") {
                    let f = first.to_ascii_lowercase();
                    if f.contains("python") {
                        return "python";
                    }
                    if f.contains("node") || f.contains("deno") || f.contains("bun") {
                        return "javascript";
                    }
                    if f.contains("ruby") {
                        return "ruby";
                    }
                    if f.contains("php") {
                        return "php";
                    }
                    if f.contains("bash") || f.contains("/sh") || f.contains("zsh") {
                        return "bash";
                    }
                    if f.contains("perl") {
                        return "perl";
                    }
                    if f.contains("lua") {
                        return "lua";
                    }
                }
            }
            "generic"
        }
    }
}

pub fn is_code_file(path: &Path) -> bool {
    let fname = path
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(fname.as_str(), "dockerfile" | "makefile" | "gnumakefile" | "cmakelists.txt") {
        return true;
    }
    if matches!(
        fname.as_str(),
        "cargo.lock" | "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" | "composer.lock"
    ) {
        return false;
    }
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext.is_empty() {
        return false;
    }
    // Reject obvious binary/media/archive/doc extensions
    if matches!(
        ext.as_str(),
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "svg" | "bmp" | "pdf"
            | "zip" | "tar" | "gz" | "xz" | "7z" | "rar" | "bz2"
            | "wasm" | "so" | "dll" | "dylib" | "exe" | "o" | "a" | "rlib" | "pyc" | "class" | "jar"
            | "mp3" | "mp4" | "wav" | "avi" | "mov" | "mkv" | "woff" | "woff2" | "ttf" | "otf"
            | "sqlite" | "db" | "gguf" | "bin" | "lock" | "log" | "jsonl" | "md" | "txt"
    ) {
        return false;
    }
    true
}

fn node_text<'a>(n: Node<'a>, src: &'a str) -> &'a str {
    src.get(n.start_byte()..n.end_byte()).unwrap_or("")
}

fn extract_name(n: Node, src: &str) -> Option<String> {
    if let Some(child) = n.child_by_field_name("name") {
        let t = node_text(child, src).trim();
        if !t.is_empty() && t.len() <= 120 {
            return Some(t.to_string());
        }
    }
    if let Some(decl) = n.child_by_field_name("declarator") {
        let mut cur = decl;
        for _ in 0..5 {
            if let Some(inner) = cur.child_by_field_name("declarator") {
                cur = inner;
            } else {
                break;
            }
        }
        let t = node_text(cur, src).trim();
        if !t.is_empty() && t.len() <= 120 {
            return Some(t.to_string());
        }
    }
    let mut c = n.walk();
    for ch in n.named_children(&mut c) {
        if matches!(
            ch.kind(),
            "identifier" | "type_identifier" | "field_identifier" | "constant" | "word" | "name" | "property_identifier"
        ) {
            let t = node_text(ch, src).trim();
            if !t.is_empty() && t.len() <= 120 {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn classify_decl(kind: &str) -> Option<&'static str> {
    match kind {
        "class_declaration" | "class_definition" | "class_specifier" | "class" => Some("class"),
        "interface_declaration" | "interface_type" => Some("interface"),
        "trait_declaration" | "trait_item" => Some("trait"),
        "struct_item" | "struct_specifier" | "struct_declaration" | "type_spec" => Some("struct"),
        "enum_declaration" | "enum_item" | "enum_specifier" => Some("enum"),
        "impl_item" => Some("impl"),
        "module" | "mod_item" | "namespace_definition" | "namespace_declaration" => Some("module"),
        "function_definition" | "function_declaration" | "function_item" | "function_statement" | "fn_decl" => {
            Some("function")
        }
        "method_declaration" | "method_definition" | "method" | "singleton_method" => Some("method"),
        _ => None,
    }
}

fn is_call_node(kind: &str) -> bool {
    matches!(
        kind,
        "call_expression"
            | "function_call_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "method_invocation"
            | "invocation_expression"
            | "call"
            | "command"
            | "macro_invocation"
    )
}

fn is_import_node(kind: &str) -> bool {
    matches!(
        kind,
        "import_statement"
            | "import_from_statement"
            | "import_declaration"
            | "use_declaration"
            | "namespace_use_declaration"
            | "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression"
            | "preproc_include"
            | "using_directive"
    )
}

fn visit_ts(
    n: Node,
    src: &str,
    lang: &str,
    symbols: &mut Vec<SymbolDef>,
    calls: &mut Vec<CallSite>,
    imports: &mut Vec<String>,
    features: &mut Vec<Value>,
    depth: usize,
) {
    if depth > 72 {
        return;
    }
    let kind = n.kind();
    let line = n.start_position().row + 1;

    if let Some(sym_kind) = classify_decl(kind) {
        if symbols.len() < 400 {
            if let Some(name) = extract_name(n, src) {
                symbols.push(SymbolDef {
                    line,
                    kind: sym_kind.to_string(),
                    name,
                });
            }
        }
    }

    if is_import_node(kind) && imports.len() < 120 {
        let raw = node_text(n, src).trim();
        if !raw.is_empty() && raw.len() <= 240 {
            imports.push(raw.lines().next().unwrap_or(raw).trim().to_string());
        }
    }

    if is_call_node(kind) && calls.len() < 400 {
        let raw = node_text(n, src).trim();
        if !raw.is_empty() {
            let one_line: String = raw
                .lines()
                .next()
                .unwrap_or(raw)
                .trim()
                .chars()
                .take(160)
                .collect();
            if !one_line.is_empty() {
                calls.push(CallSite { line, expr: one_line });
            }
        }
    }

    // Cross-language syntax fact: assignment directly inside an `if` condition
    if matches!(kind, "if_statement" | "if_expression") && features.len() < 64 {
        let mut cur = n.walk();
        for ch in n.named_children(&mut cur) {
            if matches!(ch.kind(), "parenthesized_expression" | "condition_clause") {
                let mut stack = vec![ch];
                while let Some(x) = stack.pop() {
                    if matches!(x.kind(), "assignment_expression" | "assignment") {
                        features.push(json!({
                            "lang": lang,
                            "op": "COND_ASSIGN",
                            "line": x.start_position().row + 1,
                            "expression": node_text(x, src).trim().chars().take(140).collect::<String>()
                        }));
                    }
                    let mut xc = x.walk();
                    for item in x.named_children(&mut xc) {
                        stack.push(item);
                    }
                }
                break;
            }
        }
    }

    let mut cur = n.walk();
    for ch in n.named_children(&mut cur) {
        visit_ts(ch, src, lang, symbols, calls, imports, features, depth + 1);
    }
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_ps_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '$')
}

fn strip_ps_comment(line: &str) -> &str {
    let mut in_paren = 0usize;
    let mut escaped = false;
    for (i, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_paren > 0 {
            match ch {
                '\\' => escaped = true,
                '(' => in_paren += 1,
                ')' => in_paren -= 1,
                _ => {}
            }
            continue;
        }
        if ch == '(' {
            in_paren = 1;
        } else if ch == '%' {
            return &line[..i];
        }
    }
    line
}

fn is_ps_trivial_op(tok: &str) -> bool {
    matches!(
        tok,
        "pop" | "dup" | "exch" | "roll" | "index" | "copy" | "mark" | "true" | "false" | "null"
            | "def" | "bind" | "begin" | "end" | "dict" | "readonly" | "executeonly" | "noaccess"
            | "if" | "ifelse" | "for" | "forall" | "loop" | "repeat" | "exit" | "stop" | "stopped"
            | "and" | "or" | "not" | "xor" | "eq" | "ne" | "lt" | "gt" | "le" | "ge"
            | "add" | "sub" | "mul" | "div" | "idiv" | "mod" | "neg" | "abs" | "bitshift"
            | "put" | "get" | "known" | "where" | "load" | "store" | "type" | "length" | "count"
            | "cleartomark" | "counttomark" | "aload" | "astore" | "cvx" | "cvlit" | "cvi"
            | "cvn" | "cvs" | "cvr" | "string" | "array" | "matrix" | "currentdict" | "systemdict"
            | "userdict" | "globaldict" | "statusdict" | "nulltype" | "dicttype" | "nametype"
            | "stringtype" | "arraytype" | "integertype" | "realtype" | "booleantype"
            | "operatortype" | "marktype" | "packedarraytype" | "savetype" | "filetype"
            | "putinterval" | "getinterval" | "wcheck" | "rcheck" | "xcheck" | "gcheck"
    )
}

fn parse_postscript_universal(src: &str) -> ParsedFile {
    let mut symbols = Vec::new();
    let mut calls = Vec::new();
    let mut imports = Vec::new();
    let features = Vec::new();

    for (idx, raw_line) in src.lines().enumerate() {
        let line = idx + 1;
        let t = strip_ps_comment(raw_line).trim();
        if t.is_empty() {
            continue;
        }
        if t.contains("runlibfile") && imports.len() < 120 {
            imports.push(t.chars().take(200).collect());
        }
        // Procedure / operator / dictionary definitions: `/name { ...` or `/name ... def` / `odef` / `bind`
        if let Some(rest) = t.strip_prefix('/') {
            let name: String = rest.chars().take_while(|c| is_ps_ident(*c)).collect();
            let after = rest[name.len()..].trim();
            let defines_binding = after.is_empty()
                || after.starts_with('{')
                || after.starts_with('[')
                || after.contains(" def")
                || after.ends_with("def")
                || after.contains(" odef")
                || after.ends_with("odef")
                || after.contains(" bind")
                || after.contains(" dict");
            if name.len() >= 2 && defines_binding && symbols.len() < 400 {
                symbols.push(SymbolDef {
                    line,
                    kind: "procedure".to_string(),
                    name,
                });
            }
        }
        // Executable token call-sites outside `(...)` strings
        if calls.len() < 400 {
            let mut in_paren = 0usize;
            let mut escaped = false;
            let mut tok = String::new();
            let flush_tok = |buf: &mut String, calls: &mut Vec<CallSite>| {
                if buf.is_empty() || calls.len() >= 400 {
                    buf.clear();
                    return;
                }
                let s = buf.as_str();
                let first = s.chars().next().unwrap_or(' ');
                let starts_valid = first.is_ascii_alphabetic() || first == '.' || first == '_';
                if starts_valid
                    && s.len() >= 3
                    && !s.starts_with('/')
                    && !is_ps_trivial_op(s)
                    && s.chars().all(is_ps_ident)
                {
                    calls.push(CallSite {
                        line,
                        expr: s.to_string(),
                    });
                }
                buf.clear();
            };
            for ch in t.chars() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if in_paren > 0 {
                    match ch {
                        '\\' => escaped = true,
                        '(' => in_paren += 1,
                        ')' => in_paren -= 1,
                        _ => {}
                    }
                    continue;
                }
                if ch == '(' {
                    flush_tok(&mut tok, &mut calls);
                    in_paren = 1;
                    continue;
                }
                if ch.is_whitespace() || matches!(ch, '{' | '}' | '[' | ']' | '<' | '>') {
                    flush_tok(&mut tok, &mut calls);
                } else {
                    tok.push(ch);
                }
            }
            flush_tok(&mut tok, &mut calls);
        }
    }

    ParsedFile {
        lang: "postscript",
        engine: "universal-structural",
        symbols,
        calls,
        imports,
        features,
    }
}

fn parse_lisp_universal(lang: &'static str, src: &str) -> ParsedFile {
    let mut symbols = Vec::new();
    let mut calls = Vec::new();
    let mut imports = Vec::new();
    let features = Vec::new();

    for (idx, raw_line) in src.lines().enumerate() {
        let line = idx + 1;
        let t = raw_line.split(';').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        if (t.starts_with("(require") || t.starts_with("(import") || t.starts_with("(use ") || t.starts_with("(ns "))
            && imports.len() < 120
        {
            imports.push(t.chars().take(200).collect());
        }
        for kw in ["(defun ", "(defn ", "(defn- ", "(defmacro ", "(defmethod ", "(define (", "(define ", "(def "] {
            if let Some(rest) = t.strip_prefix(kw) {
                let name: String = rest
                    .trim_start()
                    .chars()
                    .take_while(|c| !c.is_whitespace() && !matches!(*c, '(' | ')' | '[' | ']'))
                    .collect();
                if !name.is_empty() && symbols.len() < 400 {
                    symbols.push(SymbolDef {
                        line,
                        kind: "function".to_string(),
                        name,
                    });
                    break;
                }
            }
        }
        if calls.len() < 400 && t.contains('(') {
            for part in t.split('(').skip(1) {
                let callee: String = part
                    .chars()
                    .take_while(|c| !c.is_whitespace() && !matches!(*c, ')' | '(' | '[' | ']'))
                    .collect();
                if callee.len() >= 3
                    && !matches!(
                        callee.as_str(),
                        "defun" | "defn" | "defn-" | "defmacro" | "defmethod" | "define" | "def"
                            | "let" | "let*" | "cond" | "when" | "unless" | "lambda" | "fn" | "if"
                            | "and" | "or" | "not" | "progn" | "begin" | "quote"
                    )
                    && calls.len() < 400
                {
                    calls.push(CallSite {
                        line,
                        expr: callee,
                    });
                }
            }
        }
    }

    ParsedFile {
        lang,
        engine: "universal-structural",
        symbols,
        calls,
        imports,
        features,
    }
}

fn parse_universal(lang: &'static str, src: &str) -> ParsedFile {
    if lang == "postscript" {
        return parse_postscript_universal(src);
    }
    if matches!(lang, "lisp" | "scheme" | "clojure") {
        return parse_lisp_universal(lang, src);
    }
    let mut symbols = Vec::new();
    let mut calls = Vec::new();
    let mut imports = Vec::new();
    let features = Vec::new();

    let percent_comment = matches!(lang, "erlang" | "latex" | "prolog");
    let semi_comment = lang == "assembly";

    for (idx, raw_line) in src.lines().enumerate() {
        let line = idx + 1;
        let t = raw_line.trim();
        if t.is_empty()
            || t.starts_with("//")
            || t.starts_with('#')
            || t.starts_with("--")
            || t.starts_with("/*")
            || (percent_comment && t.starts_with('%'))
            || (semi_comment && t.starts_with(';'))
        {
            continue;
        }
        // Imports / includes across Kotlin, Swift, Dart, Scala, SQL, Protobuf, HCL, etc.
        if (t.starts_with("import ") || t.starts_with("from ") || t.starts_with("use ") || t.starts_with("include ") || t.starts_with("require"))
            && imports.len() < 120
        {
            imports.push(t.chars().take(200).collect());
        }

        // Declarations across virtually every programming language
        for (kw, kind) in [
            ("class ", "class"),
            ("data class ", "class"),
            ("sealed class ", "class"),
            ("abstract class ", "class"),
            ("public class ", "class"),
            ("final class ", "class"),
            ("struct ", "struct"),
            ("interface ", "interface"),
            ("protocol ", "interface"),
            ("trait ", "trait"),
            ("enum ", "enum"),
            ("object ", "object"),
            ("contract ", "contract"),
            ("module ", "module"),
            ("defmodule ", "module"),
            ("service ", "service"),
            ("message ", "struct"),
            ("fun ", "function"),
            ("suspend fun ", "function"),
            ("func ", "function"),
            ("function ", "function"),
            ("fn ", "function"),
            ("pub fn ", "function"),
            ("def ", "function"),
            ("defp ", "function"),
            ("async def ", "function"),
            ("sub ", "function"),
            ("proc ", "function"),
            ("procedure ", "function"),
            ("let rec ", "function"),
            ("CREATE FUNCTION ", "function"),
            ("CREATE TABLE ", "table"),
            ("resource ", "resource"),
        ] {
            if let Some(rest) = t.strip_prefix(kw) {
                let name: String = rest
                    .trim_start()
                    .trim_matches('"')
                    .chars()
                    .take_while(|c| is_ident(*c) || *c == '.')
                    .collect();
                if !name.is_empty() && symbols.len() < 400 {
                    symbols.push(SymbolDef {
                        line,
                        kind: kind.to_string(),
                        name,
                    });
                    break;
                }
            }
        }

        // Generic call-site extraction: ident(
        if calls.len() < 400 && t.contains('(') && !t.starts_with("if ") && !t.starts_with("for ") && !t.starts_with("while ") {
            if let Some(pos) = t.find('(') {
                let prefix = t[..pos].trim_end();
                if prefix.chars().last().is_some_and(is_ident) {
                    calls.push(CallSite {
                        line,
                        expr: t.chars().take(160).collect(),
                    });
                }
            }
        }
    }

    ParsedFile {
        lang,
        engine: "universal-structural",
        symbols,
        calls,
        imports,
        features,
    }
}

pub fn parse_file(path: &Path, src: &str) -> ParsedFile {
    let lang = detect_language(path, src);
    if let Some(ts_lang) = native_language(lang) {
        let mut parser = Parser::new();
        if parser.set_language(&ts_lang).is_ok() {
            if let Some(tree) = parser.parse(src, None) {
                let mut symbols = Vec::new();
                let mut calls = Vec::new();
                let mut imports = Vec::new();
                let mut features = Vec::new();
                visit_ts(
                    tree.root_node(),
                    src,
                    lang,
                    &mut symbols,
                    &mut calls,
                    &mut imports,
                    &mut features,
                    0,
                );
                return ParsedFile {
                    lang,
                    engine: "tree-sitter",
                    symbols,
                    calls,
                    imports,
                    features,
                };
            }
        }
    }
    parse_universal(lang, src)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_native_languages_with_tree_sitter() {
        let py = parse_file(
            Path::new("app/service.py"),
            "import os\nclass Auth:\n    def check(self, x):\n        return validate(x)\n",
        );
        assert_eq!(py.lang, "python");
        assert_eq!(py.engine, "tree-sitter");
        assert!(py.symbols.iter().any(|s| s.name == "Auth"));
        assert!(py.symbols.iter().any(|s| s.name == "check"));
        assert!(!py.calls.is_empty());

        let ts = parse_file(
            Path::new("src/router.ts"),
            "import { guard } from './guard';\nexport class Router {\n  handle(req: any) { return guard(req); }\n}\n",
        );
        assert_eq!(ts.lang, "typescript");
        assert_eq!(ts.engine, "tree-sitter");
        assert!(ts.symbols.iter().any(|s| s.name == "Router"));
        assert!(ts.symbols.iter().any(|s| s.name == "handle"));

        let go = parse_file(
            Path::new("cmd/main.go"),
            "package main\nfunc main() { serve() }\n",
        );
        assert_eq!(go.lang, "go");
        assert_eq!(go.engine, "tree-sitter");
        assert!(go.symbols.iter().any(|s| s.name == "main"));

        let rs = parse_file(
            Path::new("src/lib.rs"),
            "pub struct Engine;\npub fn boot() { init(); }\n",
        );
        assert_eq!(rs.lang, "rust");
        assert_eq!(rs.engine, "tree-sitter");
        assert!(rs.symbols.iter().any(|s| s.name == "Engine"));
        assert!(rs.symbols.iter().any(|s| s.name == "boot"));

        let java = parse_file(
            Path::new("Main.java"),
            "public class Main { public void run() { start(); } }\n",
        );
        assert_eq!(java.lang, "java");
        assert_eq!(java.engine, "tree-sitter");
        assert!(java.symbols.iter().any(|s| s.name == "Main"));

        let c_code = parse_file(
            Path::new("auth.c"),
            "int verify(int x) { if (x = 1) return 1; return 0; }\n",
        );
        assert_eq!(c_code.lang, "c");
        assert_eq!(c_code.engine, "tree-sitter");
        assert!(c_code.features.iter().any(|f| f["op"] == "COND_ASSIGN"));
    }

    #[test]
    fn parses_tier2_languages_with_universal_fallback() {
        let kt = parse_file(
            Path::new("AuthService.kt"),
            "import com.acme.Token\nclass AuthService {\n  fun verify(t: String) = checkToken(t)\n}\n",
        );
        assert_eq!(kt.lang, "kotlin");
        assert_eq!(kt.engine, "universal-structural");
        assert!(kt.symbols.iter().any(|s| s.name == "AuthService"));
        assert!(kt.symbols.iter().any(|s| s.name == "verify"));

        let sol = parse_file(
            Path::new("Vault.sol"),
            "contract Vault {\n  function withdraw(uint amount) external { send(amount); }\n}\n",
        );
        assert_eq!(sol.lang, "solidity");
        assert_eq!(sol.engine, "universal-structural");
        assert!(sol.symbols.iter().any(|s| s.name == "Vault"));
        assert!(sol.symbols.iter().any(|s| s.name == "withdraw"));

        let ps = parse_file(
            Path::new("Init/fonts.ps"),
            "% Header comment ignored
/.copyhelper { % inline comment
  dup type /stringtype eq { .innerwrite } { pop } ifelse
} bind def
",
        );
        assert_eq!(ps.lang, "postscript");
        assert_eq!(ps.engine, "universal-structural");
        assert!(ps.symbols.iter().any(|s| s.name == ".copyhelper"));
        assert!(ps.calls.iter().any(|c| c.expr == ".innerwrite"));

        let clj = parse_file(
            Path::new("src/core.clj"),
            "; comment
(defn verify-token [t]
  (validate-sig t))
",
        );
        assert_eq!(clj.lang, "clojure");
        assert!(clj.symbols.iter().any(|s| s.name == "verify-token"));
        assert!(clj.calls.iter().any(|c| c.expr == "validate-sig"));
    }
}
