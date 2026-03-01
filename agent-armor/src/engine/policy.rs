// src/engine/policy.rs
//! Policy configuration for AgentArmor.
//!
//! Loaded from `.agent-armor.toml` in the repo root or passed via `--config`.
//! Every rule carries a `Severity` so teams can start in "warn" mode and
//! graduate to "block" once they're confident in their policies.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Emit a warning to stdout but let the code through.
    Warn,
    /// Block the code; fail the CI pipeline.
    Block,
    /// Silently rewrite the offending construct.
    AutoFix,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Warn => write!(f, "WARN"),
            Severity::Block => write!(f, "BLOCK"),
            Severity::AutoFix => write!(f, "AUTO-FIX"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPolicy {
    pub enabled: bool,
    pub severity: Severity,
    /// Minimum entropy bits before a string is considered secret-like.
    pub entropy_threshold: f64,
}

impl Default for SecretPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            severity: Severity::AutoFix,
            entropy_threshold: 3.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousSinkPolicy {
    pub enabled: bool,
    pub severity: Severity,
    /// The list of dangerous function names to block.
    pub blocked_functions: Vec<String>,
}

impl Default for DangerousSinkPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            severity: Severity::Block,
            blocked_functions: vec![
                "eval".into(),
                "exec".into(),
                "compile".into(),
                "__import__".into(),
                "pickle.loads".into(),
                "subprocess.call".into(),
                "os.system".into(),
                "Function".into(), // JS dangerous constructor
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlopsquattingPolicy {
    pub enabled: bool,
    pub severity: Severity,
    /// Flag packages created within this many hours.
    pub new_package_threshold_hours: u64,
    /// Flag packages with fewer than this many downloads.
    pub low_download_threshold: u64,
}

impl Default for SlopsquattingPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            severity: Severity::Block,
            new_package_threshold_hours: 48,
            low_download_threshold: 500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPolicy {
    pub enabled: bool,
    /// Paths that agents are never allowed to write to.
    pub protected_paths: Vec<String>,
    /// Environment variable prefixes an agent cannot read from other domains.
    pub isolated_env_prefixes: Vec<String>,
}

impl Default for McpPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            protected_paths: vec![
                "/etc/passwd".into(),
                "/etc/shadow".into(),
                "/etc/sudoers".into(),
                "~/.ssh/".into(),
                ".env".into(),
                "*.pem".into(),
                "*.key".into(),
            ],
            isolated_env_prefixes: vec![
                "BACKEND_".into(),
                "DB_".into(),
                "SECRET_".into(),
                "PRIVATE_".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPolicy {
    pub enabled: bool,
    /// Embed attestation as a comment in the output file.
    pub embed_in_code: bool,
    /// Also write a `.shadow-chain.json` manifest file alongside the source.
    pub write_shadow_chain: bool,
    /// Fail if an existing attestation doesn't match (tamper detection).
    pub strict_verify: bool,
}

impl Default for AttestationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            embed_in_code: true,
            write_shadow_chain: true,
            strict_verify: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    pub secrets: SecretPolicy,
    pub dangerous_sinks: DangerousSinkPolicy,
    pub slopsquatting: SlopsquattingPolicy,
    pub mcp: McpPolicy,
    pub attestation: AttestationPolicy,
}

impl PolicyConfig {
    /// Load from a TOML config file.  Falls back to defaults if the file
    /// doesn't exist so new users get safe-out-of-the-box behaviour.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        if path.exists() {
            let text = std::fs::read_to_string(path)?;
            let config: PolicyConfig = toml::from_str(&text)?;
            Ok(config)
        } else {
            Ok(PolicyConfig::default())
        }
    }

    /// Persist the default config as a template the user can customise.
    pub fn write_default(path: &std::path::Path) -> anyhow::Result<()> {
        let config = PolicyConfig::default();
        let text = toml::to_string_pretty(&config)?;
        std::fs::write(path, text)?;
        Ok(())
    }
}

/// Canonical list of dangerous imports/functions for fast O(1) lookup.
pub fn dangerous_sink_set(policy: &DangerousSinkPolicy) -> HashSet<&str> {
    policy
        .blocked_functions
        .iter()
        .map(|s| s.as_str())
        .collect()
}
