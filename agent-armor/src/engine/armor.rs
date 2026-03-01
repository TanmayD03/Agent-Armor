// src/engine/armor.rs
//! AgentArmor Orchestrator
//!
//! The master pipeline: Intercept → Scrub → AST-Harden → DTG-Analyse →
//! Slopsquat-Guard → Attest → Report.

use crate::{
    engine::{
        ast_hardener::{AstHardener, SourceLanguage},
        attestation::AttestationRecord,
        dtg::DtgEngine,
        mcp_proxy::{McpProxy, McpToolCall},
        policy::PolicyConfig,
        report_builder::ArmorReport,
        secret_scrubber::SecretScrubber,
        slopsquatting::SlopsquattingGuard,
    },
};
use anyhow::Result;
use colored::Colorize;
use std::path::Path;

pub struct AgentArmor {
    policy: PolicyConfig,
    offline: bool,
}

impl AgentArmor {
    pub fn new(policy: PolicyConfig, offline: bool) -> Self {
        Self { policy, offline }
    }

    /// Process a source file end-to-end.
    /// Returns `(hardened_code, report)`.
    pub fn process_file(&self, path: &Path) -> Result<(String, ArmorReport)> {
        let raw = std::fs::read_to_string(path)?;
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("py");
        let filename = path.to_str().unwrap_or("unknown");
        self.process_source(&raw, ext, filename)
    }

    /// Process a raw source string (used by the MCP proxy and tests).
    pub fn process_source(
        &self,
        raw: &str,
        extension: &str,
        filename: &str,
    ) -> Result<(String, ArmorReport)> {
        let mut report = ArmorReport::new(filename);

        // ── Step 1: Secret scrubber ────────────────────────────────────────
        let scrubber = SecretScrubber::new(self.policy.secrets.entropy_threshold);
        let (scrubbed_code, secret_findings) = scrubber.scrub(raw);
        if !secret_findings.is_empty() {
            println!(
                "{}",
                format!("  [SCRUBBER] {} secret(s) found and auto-fixed.", secret_findings.len())
                    .yellow()
            );
        }
        report.secret_findings = secret_findings;

        // ── Step 2: AST hardener ───────────────────────────────────────────
        let lang = SourceLanguage::from_extension(extension);
        let mut hardener = AstHardener::new(
            lang,
            self.policy.dangerous_sinks.blocked_functions.clone(),
        )?;
        let ast_findings = hardener.analyze(&scrubbed_code);
        if !ast_findings.is_empty() {
            println!(
                "{}",
                format!("  [AST] {} structural issue(s) detected.", ast_findings.len()).red()
            );
        }
        report.ast_findings = ast_findings;

        // ── Step 3: DTG data-flow analysis ─────────────────────────────────
        let dtg = DtgEngine::new();
        let dtg_findings = dtg.analyze(&scrubbed_code);
        if !dtg_findings.is_empty() {
            println!(
                "{}",
                format!("  [DTG] {} unsanitized data-flow path(s).", dtg_findings.len()).yellow()
            );
            // Append auto-fixes as comments into the code
        }
        report.dtg_findings = dtg_findings;

        // Inject auto-fixes from DTG into the code
        let mut hardened = scrubbed_code.clone();
        for finding in &report.dtg_findings {
            if let Some(fix) = &finding.auto_fix {
                hardened = format!("{}\n{}", fix, hardened);
            }
        }

        // ── Step 4: Slopsquatting guard ────────────────────────────────────
        if self.policy.slopsquatting.enabled {
            let guard = SlopsquattingGuard::new(
                self.policy.slopsquatting.new_package_threshold_hours,
                self.policy.slopsquatting.low_dl_threshold,
            );
            let slop_findings = guard.scan(&hardened, self.offline);
            if !slop_findings.is_empty() {
                println!(
                    "{}",
                    format!(
                        "  [SLOPSQUAT] {} suspicious package(s) found.",
                        slop_findings.len()
                    )
                    .red()
                );
            }
            report.slopsquat_findings = slop_findings;
        }

        // ── Step 5: Attestation ────────────────────────────────────────────
        if self.policy.attestation.enabled {
            let invariants = self.collect_invariants(&report);
            let record = AttestationRecord::new(&hardened, invariants, filename);

            // Embed attestation comment
            let attested_code = match extension {
                "js" | "ts" | "jsx" | "tsx" => record.embed_in_js(&hardened),
                _ => record.embed_in_python(&hardened),
            };

            report.attestation = Some(record);
            report.finalize();

            return Ok((attested_code, report));
        }

        report.finalize();
        Ok((hardened, report))
    }

    /// Evaluate an MCP tool call through the proxy.
    pub fn evaluate_mcp(&self, call: &McpToolCall) -> crate::engine::mcp_proxy::McpDecision {
        let proxy = McpProxy::new(
            self.policy.mcp.protected_paths.clone(),
            self.policy.mcp.isolated_env_prefixes.clone(),
        );
        proxy.evaluate(call)
    }

    /// Verify an existing attestation against the current file contents.
    pub fn verify_file(&self, path: &Path) -> Result<bool> {
        let manifest_path = path.with_extension("shadow-chain.json");
        if !manifest_path.exists() {
            anyhow::bail!("No shadow-chain manifest found at {:?}", manifest_path);
        }
        let record = AttestationRecord::load(&manifest_path)?;
        let current = std::fs::read_to_string(path)?;

        // The attestation is embedded in the file — we need to strip it first
        // to get the code-only hash.  We strip the first 8 comment lines.
        let code_only: String = current
            .lines()
            .skip(8)
            .collect::<Vec<_>>()
            .join("\n");

        match record.verify(&code_only) {
            Ok(()) => {
                println!("{}", "  ✅ Attestation verified — code is untampered.".green());
                Ok(true)
            }
            Err(e) => {
                println!("{}", format!("  ❌ Attestation FAILED: {}", e).red());
                Ok(false)
            }
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn collect_invariants(&self, report: &ArmorReport) -> Vec<String> {
        let mut inv = Vec::new();
        inv.push(format!("secrets_scrubbed:{}", report.secret_findings.len()));
        inv.push(format!("ast_checks_passed:{}", report.ast_findings.is_empty()));
        inv.push(format!("dtg_flows_reviewed:{}", report.dtg_findings.len()));
        inv.push(format!(
            "supply_chain_clean:{}",
            report.slopsquat_findings.is_empty()
        ));
        inv.push(format!(
            "dangerous_sinks_clear:{}",
            report.ast_findings.is_empty()
        ));
        inv
    }
}
