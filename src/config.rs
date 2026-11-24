//! Lightweight zero-dependency configuration loader for Alewo.
//! Reads `~/.alewo/config.toml` or project-local `.alewo.toml` / `alewo.toml`
//! (or explicit `--config` / `ALEWO_CONFIG`).
use std::{
    env, fs,
    path::{Path, PathBuf},
};

pub const DEFAULT_GOAL_CYCLES: usize = 10;
pub const DEFAULT_CHECKPOINT_ROUNDS: usize = 12;
pub const DEFAULT_MAX_ROUNDS: usize = 0; // 0 = unlimited (continuous running)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlewoConfig {
    /// Default number of cycles for `/goal` (default: 10; 0 = unlimited until [GOAL_COMPLETE] / Ctrl+C).
    pub goal_cycles: usize,
    /// Periodic rethink checkpoint interval in rounds (default: 12; min: 2).
    pub checkpoint_rounds: usize,
    /// Hard cap on rounds per normal turn (default: 0 = unlimited).
    pub max_rounds: usize,
    /// Optional default model override.
    pub model: Option<String>,
    /// Path of the config file that was loaded, if any.
    pub source_path: Option<PathBuf>,
}

impl Default for AlewoConfig {
    fn default() -> Self {
        Self {
            goal_cycles: DEFAULT_GOAL_CYCLES,
            checkpoint_rounds: DEFAULT_CHECKPOINT_ROUNDS,
            max_rounds: DEFAULT_MAX_ROUNDS,
            model: None,
            source_path: None,
        }
    }
}

impl AlewoConfig {
    pub fn default_user_config_path() -> Option<PathBuf> {
        env::var("HOME")
            .ok()
            .filter(|h| !h.trim().is_empty())
            .map(|h| PathBuf::from(h).join(".alewo").join("config.toml"))
    }

    pub fn load(project_root: &Path, explicit: Option<&Path>) -> Result<Self, String> {
        if let Some(p) = explicit {
            return Self::from_file(p);
        }
        if let Ok(env_path) = env::var("ALEWO_CONFIG") {
            let trimmed = env_path.trim();
            if !trimmed.is_empty() {
                return Self::from_file(Path::new(trimmed));
            }
        }
        let mut candidates = vec![
            project_root.join(".alewo.toml"),
            project_root.join("alewo.toml"),
        ];
        if let Some(home_cfg) = Self::default_user_config_path() {
            candidates.push(home_cfg);
        }
        for candidate in candidates {
            if candidate.is_file() {
                return Self::from_file(&candidate);
            }
        }
        Ok(Self::default())
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;
        let mut cfg = Self::parse_str(&raw)?;
        cfg.source_path = Some(path.to_path_buf());
        Ok(cfg)
    }

    pub fn parse_str(raw: &str) -> Result<Self, String> {
        let mut cfg = Self::default();
        for (idx, line) in raw.lines().enumerate() {
            let line_no = idx + 1;
            let cleaned = strip_inline_comment(line).trim();
            if cleaned.is_empty() || cleaned.starts_with('[') {
                continue;
            }
            let Some((raw_k, raw_v)) = cleaned.split_once('=') else {
                return Err(format!("config line {line_no}: expected key = value"));
            };
            let key = raw_k.trim().to_ascii_lowercase();
            let val = unquote(raw_v.trim());
            match key.as_str() {
                "goal_cycles" | "default_cycles" | "default_goal_cycles" | "cycles" => {
                    cfg.goal_cycles = val.parse::<usize>().map_err(|_| {
                        format!("config line {line_no}: invalid integer for {key}: {val}")
                    })?;
                }
                "checkpoint_rounds" | "checkpoint_interval" | "rethink_rounds" => {
                    let n = val.parse::<usize>().map_err(|_| {
                        format!("config line {line_no}: invalid integer for {key}: {val}")
                    })?;
                    if n < 2 {
                        return Err(format!(
                            "config line {line_no}: {key} must be >= 2 (got {n})"
                        ));
                    }
                    cfg.checkpoint_rounds = n;
                }
                "max_rounds" | "rounds" => {
                    cfg.max_rounds = val.parse::<usize>().map_err(|_| {
                        format!("config line {line_no}: invalid integer for {key}: {val}")
                    })?;
                }
                "model" => {
                    if !val.is_empty() {
                        cfg.model = Some(val);
                    }
                }
                _ => {
                    // Forward-compatible: ignore unknown keys cleanly.
                }
            }
        }
        Ok(cfg)
    }
}

fn strip_inline_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..i],
            _ => {}
        }
    }
    line
}

fn unquote(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults_and_overrides() {
        let cfg = AlewoConfig::parse_str(
            r#"
            # Comment line
            [goal]
            goal_cycles = 15 # inline comment
            checkpoint_rounds = 12
            max_rounds = 0
            model = "minimaxai/minimax-m3.1-flash"
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.goal_cycles, 15);
        assert_eq!(cfg.checkpoint_rounds, 12);
        assert_eq!(cfg.max_rounds, 0);
        assert_eq!(cfg.model.as_deref(), Some("minimaxai/minimax-m3.1-flash"));
    }

    #[test]
    fn supports_aliases_and_unlimited_cycles() {
        let cfg = AlewoConfig::parse_str("default_cycles = 0\nrethink_rounds = 8\n").expect("parse");
        assert_eq!(cfg.goal_cycles, 0);
        assert_eq!(cfg.checkpoint_rounds, 8);
        assert_eq!(cfg.max_rounds, 0);
    }

    #[test]
    fn rejects_invalid_checkpoint_interval() {
        assert!(AlewoConfig::parse_str("checkpoint_rounds = 1").is_err());
    }
}
