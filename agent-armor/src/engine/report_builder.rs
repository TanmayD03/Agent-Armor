// src/engine/report_builder.rs
//! Report Builder
//!
//! Aggregates findings from every engine module into a single `ArmorReport`
//! that can be serialised to JSON (for CI / tooling) or rendered to a
//! human-readable terminal summary.

use crate::engine::{
    ast_hardener::AstFinding,
    attestation::AttestationRecord,
    dtg::DtgFinding,
    slopsquatting::SlopsquattingFinding,
    secret_scrubber::SecretFinding,
    mcp_proxy::McpDecision,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingSummary {
    pub total:      usize,
    pub blocked:    usize,
    pub warned:     usize,
    pub auto_fixed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmorReport {
    pub timestamp:           String,
    pub source_file:         String,
    pub agent_armor_version: String,

    // Per-module findings
    pub secret_findings:        Vec<SecretFinding>,
    pub ast_findings:           Vec<AstFinding>,
    pub dtg_findings:           Vec<DtgFinding>,
    pub slopsquat_findings:     Vec<SlopsquattingFinding>,
    pub mcp_decisions:          Vec<McpDecision>,

    // Attestation
    pub attestation:            Option<AttestationRecord>,

    // High-level summary
    pub summary:                FindingSummary,
    pub passed:                 bool,
}

impl ArmorReport {
    pub fn new(source_file: &str) -> Self {
        Self {
            timestamp:           Utc::now().to_rfc3339(),
            source_file:         source_file.to_string(),
            agent_armor_version: crate::AGENT_ARMOR_VERSION.to_string(),
            secret_findings:     Vec::new(),
            ast_findings:        Vec::new(),
            dtg_findings:        Vec::new(),
            slopsquat_findings:  Vec::new(),
            mcp_decisions:       Vec::new(),
            attestation:         None,
            summary:             FindingSummary::default(),
            passed:              true,
        }
    }

    /// Compute summary counts and the overall pass/fail.
    pub fn finalize(&mut self) {
        let total = self.secret_findings.len()
            + self.ast_findings.len()
            + self.dtg_findings.len()
            + self.slopsquat_findings.len();

        let blocked = self.ast_findings.len() // AST always blocks
            + self.slopsquat_findings.len();  // supply chain blocks

        let auto_fixed = self.secret_findings.len(); // secrets are auto-fixed
        let warned     = self.dtg_findings.len();    // DTG warns + suggests

        self.summary = FindingSummary {
            total,
            blocked,
            warned,
            auto_fixed,
        };

        // Pass only if nothing was blocked and all MCP calls were allowed
        let mcp_blocked = self
            .mcp_decisions
            .iter()
            .any(|d| d.decision == crate::engine::mcp_proxy::Decision::Block);

        self.passed = blocked == 0 && !mcp_blocked;
    }

    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}
