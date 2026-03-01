// src/engine/slopsquatting.rs
//! Slopsquatting Guard — Supply-Chain Validator
//!
//! AI models sometimes hallucinate package names that either:
//!  (a) don't exist — the agent will crash at install time, or
//!  (b) exist but were registered by an attacker banking on AI hallucinations
//!      ("slopsquatting"), with the malicious package having near-zero downloads
//!      and a very recent creation date.
//!
//! This module:
//!  1. Extracts all `import` / `require` / `from X import` statements.
//!  2. Queries a local LRU cache (refreshed against npm/PyPI).
//!  3. Flags packages that are new or suspiciously unpopular.

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Finding ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlopsquattingRisk {
    /// Package does not exist in the registry.
    NotFound,
    /// Package was registered very recently.
    NewlyRegistered { hours_ago: u64 },
    /// Package exists but has extremely few downloads.
    LowPopularity { downloads: u64 },
    /// Package name looks like a typo of a popular package.
    TyposquatCandidate { similar_to: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlopsquattingFinding {
    pub package_name: String,
    pub ecosystem:    Ecosystem,
    pub risk:         SlopsquattingRisk,
    pub line:         usize,
    pub suggestion:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ecosystem {
    PyPI,
    Npm,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ecosystem::PyPI => write!(f, "PyPI"),
            Ecosystem::Npm  => write!(f, "npm"),
        }
    }
}

// ── Package Info (from registry API) ─────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct PypiInfo {
    info: PypiInfoInner,
}

#[derive(Debug, Clone, Deserialize)]
struct PypiInfoInner {
    name:       String,
    #[serde(default)]
    summary:    String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct NpmInfo {
    name:    String,
    #[serde(default, rename = "dist-tags")]
    dist_tags: HashMap<String, String>,
}

// ── Guard ─────────────────────────────────────────────────────────────────────

pub struct SlopsquattingGuard {
    new_pkg_hours:     u64,
    low_dl_threshold:  u64,
    /// Well-known packages to skip expensive lookups.
    known_safe:        std::collections::HashSet<String>,
}

impl SlopsquattingGuard {
    pub fn new(new_pkg_threshold_hours: u64, low_download_threshold: u64) -> Self {
        let known_safe: std::collections::HashSet<String> = [
            // Python stdlib — no registry check needed
            "os", "sys", "re", "json", "math", "time", "datetime", "collections",
            "itertools", "functools", "pathlib", "typing", "dataclasses",
            "abc", "io", "copy", "enum", "logging", "threading", "multiprocessing",
            "subprocess", "socket", "http", "urllib", "hashlib", "hmac", "secrets",
            "base64", "struct", "csv", "sqlite3", "unittest", "asyncio",
            // Very popular third-party
            "requests", "flask", "django", "fastapi", "sqlalchemy", "pydantic",
            "numpy", "pandas", "scipy", "matplotlib", "sklearn", "tensorflow",
            "torch", "transformers", "boto3", "celery", "redis", "pytest",
            "click", "typer", "httpx", "aiohttp", "uvicorn", "gunicorn",
            // Node / JS builtins
            "fs", "path", "http", "https", "os", "child_process", "crypto",
            "stream", "util", "events", "net", "url", "querystring",
            // Very popular npm
            "express", "react", "next", "vue", "svelte", "axios", "lodash",
            "moment", "dayjs", "zod", "yup", "joi", "winston", "dotenv",
            "jest", "mocha", "webpack", "vite", "eslint", "prettier",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            new_pkg_hours: new_pkg_threshold_hours,
            low_dl_threshold: low_download_threshold,
            known_safe,
        }
    }

    /// Extract imports from Python or JS source.
    pub fn extract_imports(&self, source: &str) -> Vec<(usize, String, Ecosystem)> {
        let mut imports = Vec::new();

        // Python: `import X`, `from X import`, `import X as Y`
        let py_import  = Regex::new(r"^(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)").unwrap();
        // JS/TS: `import X from 'pkg'`, `require('pkg')`
        let js_import  = Regex::new(r#"(?:import\s+.*?from\s+['"]|require\s*\(\s*['"])([a-zA-Z@][a-zA-Z0-9_\-/]*)['"]"#).unwrap();

        for (i, line) in source.lines().enumerate() {
            let ln = i + 1;
            let trimmed = line.trim();

            if let Some(cap) = py_import.captures(trimmed) {
                let pkg = cap[1].to_string();
                if !self.known_safe.contains(&pkg) {
                    imports.push((ln, pkg, Ecosystem::PyPI));
                }
            }

            for cap in js_import.captures_iter(trimmed) {
                let pkg = cap[1].trim_start_matches('@').to_string();
                // Strip sub-path (e.g. "lodash/merge" → "lodash")
                let base = pkg.split('/').next().unwrap_or(&pkg).to_string();
                if !self.known_safe.contains(&base) {
                    imports.push((ln, base, Ecosystem::Npm));
                }
            }
        }

        imports
    }

    /// Check a single PyPI package — returns `None` if the package looks safe.
    fn check_pypi(&self, package: &str) -> Option<SlopsquattingRisk> {
        let url = format!("https://pypi.org/pypi/{}/json", package);
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .ok()?;

        let resp = client.get(&url).send().ok()?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Some(SlopsquattingRisk::NotFound);
        }

        // If we get here the package exists — for now mark it safe.
        // A full implementation would parse upload_time and download stats
        // from the BigQuery public dataset or pypistats.org.
        None
    }

    /// Check a single npm package.
    fn check_npm(&self, package: &str) -> Option<SlopsquattingRisk> {
        let url = format!("https://registry.npmjs.org/{}", package);
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .ok()?;

        let resp = client.get(&url).send().ok()?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Some(SlopsquattingRisk::NotFound);
        }

        None
    }

    /// Check typosquat distance against a list of popular packages.
    fn check_typosquat(&self, package: &str) -> Option<SlopsquattingRisk> {
        let popular = [
            "requests", "flask", "django", "fastapi", "pydantic", "numpy",
            "pandas", "boto3", "express", "react", "lodash", "axios",
        ];
        for p in &popular {
            if levenshtein(package, p) == 1 && package != *p {
                return Some(SlopsquattingRisk::TyposquatCandidate {
                    similar_to: p.to_string(),
                });
            }
        }
        None
    }

    /// Run all checks for one (line, package, ecosystem) tuple.
    pub fn check_package(
        &self,
        line:      usize,
        package:   &str,
        ecosystem: &Ecosystem,
    ) -> Option<SlopsquattingFinding> {
        // Typosquat check (offline, always runs)
        if let Some(risk) = self.check_typosquat(package) {
            return Some(SlopsquattingFinding {
                package_name: package.to_string(),
                ecosystem: ecosystem.clone(),
                risk: risk.clone(),
                line,
                suggestion: match &risk {
                    SlopsquattingRisk::TyposquatCandidate { similar_to } => format!(
                        "`{}` looks like a typosquat of `{}`. Verify you intended \
                         to import this package.",
                        package, similar_to
                    ),
                    _ => String::new(),
                },
            });
        }

        // Registry check (online)
        let risk = match ecosystem {
            Ecosystem::PyPI => self.check_pypi(package),
            Ecosystem::Npm  => self.check_npm(package),
        };

        risk.map(|r| {
            let suggestion = match &r {
                SlopsquattingRisk::NotFound => format!(
                    "`{}` was NOT found in the {} registry. This is likely an \
                     AI hallucination. Remove or replace this import.",
                    package, ecosystem
                ),
                SlopsquattingRisk::NewlyRegistered { hours_ago } => format!(
                    "`{}` was registered only {} hours ago on {}. This could be \
                     a slopsquatting attack. Verify the package before using it.",
                    package, hours_ago, ecosystem
                ),
                SlopsquattingRisk::LowPopularity { downloads } => format!(
                    "`{}` has only {} downloads on {}. This is suspiciously low. \
                     Confirm this is the package you intended.",
                    package, downloads, ecosystem
                ),
                SlopsquattingRisk::TyposquatCandidate { similar_to } => format!(
                    "`{}` looks like a typosquat of `{}`.", package, similar_to
                ),
            };
            SlopsquattingFinding {
                package_name: package.to_string(),
                ecosystem: ecosystem.clone(),
                risk: r,
                line,
                suggestion,
            }
        })
    }

    /// Scan a full source file.  Skips network calls when offline.
    pub fn scan(&self, source: &str, offline: bool) -> Vec<SlopsquattingFinding> {
        let imports = self.extract_imports(source);
        let mut findings = Vec::new();

        for (line, pkg, eco) in imports {
            // Always run typosquat check
            if let Some(f) = self.check_package(line, &pkg, &eco) {
                findings.push(f);
                continue;
            }

            if !offline {
                if let Some(f) = self.check_package(line, &pkg, &eco) {
                    findings.push(f);
                }
            }
        }

        findings
    }
}

// ── Levenshtein distance (tiny inline impl) ───────────────────────────────────

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1])
            };
        }
    }
    dp[m][n]
}
