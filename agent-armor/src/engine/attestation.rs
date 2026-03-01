// src/engine/attestation.rs
//! Attestation Shadow-Chain
//!
//! After the code has been fully hardened AgentArmor signs it.  The signature
//! covers:
//!  - The hardened source code (SHA-256)
//!  - The set of security invariants asserted during hardening
//!  - The AgentArmor version and timestamp
//!
//! The resulting `AttestationRecord` is:
//!  1. Embedded as a comment at the top of the output file, so the chain
//!     travels with the code into every Git commit.
//!  2. Written to `<filename>.shadow-chain.json` for tooling / CI to verify.
//!
//! If a downstream commit modifies the hardened file and the comment is still
//! present but the hash no longer matches, the `verify` command will fail.

use crate::AGENT_ARMOR_VERSION;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Record ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRecord {
    /// Hex-encoded SHA-256 of the hardened source code.
    pub code_hash:   String,
    /// Hex-encoded SHA-256 of the JSON-serialised invariants list.
    pub invariant_hash: String,
    /// Combined signature: SHA-256(code_hash + invariant_hash + version + timestamp).
    pub signature:   String,
    /// Human-readable invariants that were verified during hardening.
    pub invariants:  Vec<String>,
    pub version:     String,
    pub timestamp:   String,
    pub source_file: String,
}

impl AttestationRecord {
    pub fn new(
        hardened_code: &str,
        invariants: Vec<String>,
        source_file: &str,
    ) -> Self {
        let timestamp = Utc::now().to_rfc3339();
        let version   = AGENT_ARMOR_VERSION.to_string();

        // Hash the code
        let code_hash = sha256_hex(hardened_code);

        // Hash the invariants list
        let invariants_json = serde_json::to_string(&invariants).unwrap_or_default();
        let invariant_hash = sha256_hex(&invariants_json);

        // Combined signature
        let combined = format!("{}{}{}{}", code_hash, invariant_hash, version, timestamp);
        let signature = sha256_hex(&combined);

        AttestationRecord {
            code_hash,
            invariant_hash,
            signature,
            invariants,
            version,
            timestamp,
            source_file: source_file.to_string(),
        }
    }

    // ── Embed in source ───────────────────────────────────────────────────────

    /// Prepend the attestation as a structured comment block to the source.
    pub fn embed_in_python(&self, source: &str) -> String {
        format!(
            "# ╔══════════════════════════════════════════════════════════════╗\n\
             # ║  @agent-armor-attestation v{}                               ║\n\
             # ║  signature  : {}                ║\n\
             # ║  code-hash  : {}                ║\n\
             # ║  timestamp  : {}            ║\n\
             # ║  invariants : {}              ║\n\
             # ╚══════════════════════════════════════════════════════════════╝\n\
             {}\n",
            self.version,
            self.signature,
            self.code_hash,
            self.timestamp,
            self.invariants.len(),
            source
        )
    }

    pub fn embed_in_js(&self, source: &str) -> String {
        format!(
            "// ╔══════════════════════════════════════════════════════════════╗\n\
             // ║  @agent-armor-attestation v{}                               ║\n\
             // ║  signature  : {}  ║\n\
             // ║  code-hash  : {}  ║\n\
             // ║  timestamp  : {}            ║\n\
             // ║  invariants : {}              ║\n\
             // ╚══════════════════════════════════════════════════════════════╝\n\
             {}\n",
            self.version,
            self.signature,
            self.code_hash,
            self.timestamp,
            self.invariants.len(),
            source
        )
    }

    // ── Shadow-chain manifest ─────────────────────────────────────────────────

    /// Serialise to JSON for the `.shadow-chain.json` sidecar.
    pub fn to_manifest_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Write the sidecar next to the source file.
    pub fn write_manifest(&self, source_path: &std::path::Path) -> anyhow::Result<()> {
        let manifest_path = source_path.with_extension("shadow-chain.json");
        std::fs::write(&manifest_path, self.to_manifest_json()?)?;
        Ok(())
    }

    // ── Verification ─────────────────────────────────────────────────────────

    /// Verify that `current_code` still matches the stored attestation.
    /// Returns `Ok(())` on success, `Err(…)` on tamper detection.
    pub fn verify(&self, current_code: &str) -> anyhow::Result<()> {
        let current_hash = sha256_hex(current_code);
        if current_hash != self.code_hash {
            anyhow::bail!(
                "Attestation mismatch!\n  \
                 Expected code-hash : {}\n  \
                 Got                : {}\n  \
                 The file may have been modified after signing.",
                self.code_hash,
                current_hash
            );
        }

        // Recompute the combined signature (without the timestamp, which is fixed)
        let invariants_json = serde_json::to_string(&self.invariants).unwrap_or_default();
        let invariant_hash = sha256_hex(&invariants_json);
        let combined = format!(
            "{}{}{}{}",
            current_hash, invariant_hash, self.version, self.timestamp
        );
        let expected_sig = sha256_hex(&combined);

        if expected_sig != self.signature {
            anyhow::bail!(
                "Signature verification failed!\n  \
                 The attestation manifest may have been tampered with."
            );
        }

        Ok(())
    }

    // ── Load from manifest ────────────────────────────────────────────────────

    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let record: AttestationRecord = serde_json::from_str(&text)?;
        Ok(record)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}
