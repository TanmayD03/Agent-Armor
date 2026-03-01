// src/engine/secret_scrubber.rs
//! Secret Scrubber Module
//!
//! Detects hardcoded secrets in AI-generated code using:
//!  1. Named-pattern regex matching (API keys, JWT tokens, private keys…)
//!  2. Shannon entropy analysis — high-entropy strings that look like secrets
//!     even when not labelled as such.
//!
//! Every detected secret is replaced with a call to `os.getenv()` /
//! `process.env` so the code stays functional without storing credentials.

use regex::Regex;
use serde::{Deserialize, Serialize};

// ── Finding ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub line:    usize,
    pub pattern: String,
    pub snippet: String, // redacted for the report
    pub replaced_with: String,
}

// ── Patterns ─────────────────────────────────────────────────────────────────

struct SecretPattern {
    name:    &'static str,
    regex:   Regex,
    /// How to rewrite the assignment so the code stays runnable.
    replace: &'static str,
}

fn build_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "Generic API Key / Token Assignment",
            regex: Regex::new(
                r#"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|jwt[_-]?secret)\s*=\s*['"][a-zA-Z0-9+/=_\-\.]{16,}['"]"#
            ).unwrap(),
            replace: r#"$1 = os.getenv("AGENT_ARMOR_SECURE_$1")"#,
        },
        SecretPattern {
            name: "AWS Access Key",
            regex: Regex::new(r#"(?:AKIA|ASIA|AROA)[0-9A-Z]{16}"#).unwrap(),
            replace: r#"os.getenv("AWS_ACCESS_KEY_ID")"#,
        },
        SecretPattern {
            name: "AWS Secret Key Assignment",
            regex: Regex::new(
                r#"(?i)aws[_\-]?(secret|access)[_\-]?key\s*=\s*['"][a-zA-Z0-9+/]{40}['"]"#
            ).unwrap(),
            replace: r#"$0_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")"#,
        },
        SecretPattern {
            name: "GitHub PAT",
            regex: Regex::new(r#"ghp_[a-zA-Z0-9]{36}"#).unwrap(),
            replace: r#"os.getenv("GITHUB_TOKEN")"#,
        },
        SecretPattern {
            name: "Stripe Secret Key",
            regex: Regex::new(r#"sk_(live|test)_[a-zA-Z0-9]{24,}"#).unwrap(),
            replace: r#"os.getenv("STRIPE_SECRET_KEY")"#,
        },
        SecretPattern {
            name: "OpenAI API Key",
            regex: Regex::new(r#"sk-[a-zA-Z0-9]{48}"#).unwrap(),
            replace: r#"os.getenv("OPENAI_API_KEY")"#,
        },
        SecretPattern {
            name: "PEM Private Key Block",
            regex: Regex::new(r#"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"#).unwrap(),
            replace: r#"# [AGENT-ARMOR] Private key removed — load from a secure vault"#,
        },
        SecretPattern {
            name: "JWT Token",
            regex: Regex::new(r#"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"#).unwrap(),
            replace: r#"os.getenv("JWT_TOKEN")"#,
        },
    ]
}

// ── Shannon Entropy ───────────────────────────────────────────────────────────

/// Calculate Shannon entropy for a string.
/// High-entropy strings (≥ ~3.5 bits/char) are often secrets.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// A naive heuristic: find quoted string literals with high entropy.
fn find_high_entropy_strings(source: &str, threshold: f64) -> Vec<(usize, String)> {
    let string_regex = Regex::new(r#"['"]([a-zA-Z0-9+/=_\-\.@!$%^&*]{20,})['"]"#).unwrap();
    let mut found = Vec::new();
    for (lineno, line) in source.lines().enumerate() {
        for cap in string_regex.captures_iter(line) {
            let s = &cap[1];
            if shannon_entropy(s) >= threshold {
                found.push((lineno + 1, s.to_string()));
            }
        }
    }
    found
}

// ── Main scrubber ─────────────────────────────────────────────────────────────

pub struct SecretScrubber {
    patterns:          Vec<SecretPattern>,
    entropy_threshold: f64,
}

impl SecretScrubber {
    pub fn new(entropy_threshold: f64) -> Self {
        Self {
            patterns: build_patterns(),
            entropy_threshold,
        }
    }

    /// Run all detection passes and return cleaned code + findings list.
    pub fn scrub(&self, raw_code: &str) -> (String, Vec<SecretFinding>) {
        let mut code = raw_code.to_string();
        let mut findings: Vec<SecretFinding> = Vec::new();

        // Pass 1 — named patterns
        for p in &self.patterns {
            let mut local_findings = Vec::new();
            let replaced = p.regex.replace_all(&code, |caps: &regex::Captures| {
                let original = caps[0].to_string();
                // Redact for the report: show only first 6 chars + asterisks
                let snippet = if original.len() > 10 {
                    format!("{}…{}", &original[..6], "*".repeat(8))
                } else {
                    "*".repeat(original.len())
                };
                // Determine line number
                let line = code[..code.find(&original).unwrap_or(0)]
                    .lines()
                    .count()
                    + 1;
                local_findings.push(SecretFinding {
                    line,
                    pattern: p.name.to_string(),
                    snippet,
                    replaced_with: p.replace.to_string(),
                });
                p.replace.to_string()
            });
            findings.extend(local_findings);
            code = replaced.into_owned();
        }

        // Pass 2 — entropy scan (catch patterns we don't have a regex for)
        let high_entropy = find_high_entropy_strings(&code, self.entropy_threshold);
        for (line, secret) in high_entropy {
            findings.push(SecretFinding {
                line,
                pattern: "High-Entropy String (entropy scan)".into(),
                snippet: format!("{}…", &secret[..secret.len().min(8)]),
                replaced_with: "os.getenv(\"AGENT_ARMOR_SECURE_VALUE\")".into(),
            });
            // Replace in code
            code = code.replace(&format!("\"{}\"", secret), "os.getenv(\"AGENT_ARMOR_SECURE_VALUE\")");
            code = code.replace(&format!("'{}'", secret), "os.getenv(\"AGENT_ARMOR_SECURE_VALUE\")");
        }

        (code, findings)
    }
}
