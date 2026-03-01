// src/lib.rs
//! AgentArmor — Zero-Trust Middleware for Agentic Coding
//!
//! Intercepts AI-generated code, hardens it through the DTG engine,
//! scrubs secrets, validates supply chain, and produces a cryptographic
//! Attestation Shadow-Chain so CI/CD can verify nothing was silently changed.

pub mod engine;
pub mod report;

pub use engine::armor::AgentArmor;
pub use engine::policy::{PolicyConfig, Severity};
pub use report::ArmorReport;

/// Version baked into every attestation signature so auditors can
/// trace which rule-set was active at signing time.
pub const AGENT_ARMOR_VERSION: &str = env!("CARGO_PKG_VERSION");
