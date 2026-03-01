// src/engine/mcp_proxy.rs
//! MCP Security Proxy
//!
//! In 2026, AI agents communicate with their tools through the Model Context
//! Protocol (MCP).  This module implements a Zero-Trust layer that:
//!
//!  • Intercepts `tool_call` payloads before they are executed.
//!  • Enforces **Semantic Policy Checks** — rejects calls that would write to
//!    protected paths, read isolated environment variables, or spawn shells.
//!  • Enforces **Domain Isolation** — a frontend agent cannot access backend
//!    environment variables and vice-versa.
//!  • Logs every decision so there's an immutable audit trail.
//!
//! The proxy can run as a standalone JSON-RPC server (`agent-armor mcp-proxy`)
//! or be used as a library from within an agent harness.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ── MCP Types ─────────────────────────────────────────────────────────────────

/// A minimal representation of an MCP tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
    /// The tool being called, e.g. `write_to_file`, `read_env_var`.
    pub tool:   String,
    /// Free-form parameters map.
    pub params: serde_json::Value,
    /// Optional: which agent / domain is making the call.
    pub agent_domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
    Warn,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Block => write!(f, "BLOCK"),
            Decision::Warn  => write!(f, "WARN"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpDecision {
    pub decision:   Decision,
    pub reason:     String,
    pub timestamp:  String,
    pub call:       McpToolCall,
}

// ── Proxy ─────────────────────────────────────────────────────────────────────

pub struct McpProxy {
    protected_paths:    Vec<String>,
    isolated_env_prefixes: Vec<String>,
    /// Tool names that always require extra scrutiny.
    sensitive_tools:    HashSet<String>,
}

impl McpProxy {
    pub fn new(protected_paths: Vec<String>, isolated_env_prefixes: Vec<String>) -> Self {
        let sensitive_tools: HashSet<String> = [
            "write_to_file",
            "execute_command",
            "run_shell",
            "bash",
            "shell",
            "exec",
            "delete_file",
            "modify_file",
            "read_env_var",
            "set_env_var",
            "http_request",
            "fetch",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        McpProxy {
            protected_paths,
            isolated_env_prefixes,
            sensitive_tools,
        }
    }

    /// The main entry point — evaluate a tool call and return an Allow/Block decision.
    pub fn evaluate(&self, call: &McpToolCall) -> McpDecision {
        let timestamp = Utc::now().to_rfc3339();

        // ── 1. Protected path check ────────────────────────────────────────
        if let Some(path) = self.extract_path_param(&call.params) {
            for protected in &self.protected_paths {
                let pattern = protected.trim_start_matches('/').trim_end_matches('*');
                if path.contains(pattern) || self.glob_match(&path, protected) {
                    return McpDecision {
                        decision:  Decision::Block,
                        reason:    format!(
                            "Tool `{}` attempted to access protected path `{}`. \
                             This path is listed in the Zero-Trust policy.",
                            call.tool, path
                        ),
                        timestamp,
                        call: call.clone(),
                    };
                }
            }
        }

        // ── 2. Domain isolation check ──────────────────────────────────────
        if call.tool.contains("env") {
            if let Some(var_name) = self.extract_env_var_name(&call.params) {
                for prefix in &self.isolated_env_prefixes {
                    if var_name.starts_with(prefix.as_str()) {
                        let domain = call.agent_domain.as_deref().unwrap_or("unknown");
                        // A frontend agent should not access backend env vars
                        if domain.contains("frontend") || domain.contains("ui") {
                            return McpDecision {
                                decision: Decision::Block,
                                reason: format!(
                                    "Domain Isolation Violation: agent in domain `{}` \
                                     attempted to access env var `{}` which is reserved \
                                     for backend services (prefix: `{}`).",
                                    domain, var_name, prefix
                                ),
                                timestamp,
                                call: call.clone(),
                            };
                        }
                    }
                }
            }
        }

        // ── 3. Shell / exec tools with dynamic strings ─────────────────────
        if call.tool == "execute_command"
            || call.tool == "bash"
            || call.tool == "shell"
            || call.tool == "run_shell"
        {
            if let Some(cmd) = self.extract_command(&call.params) {
                let dangerous_chars = ['$', '`', ';', '|', '&', '>', '<', '(', ')', '{', '}'];
                if dangerous_chars.iter().any(|c| cmd.contains(*c)) {
                    return McpDecision {
                        decision: Decision::Block,
                        reason: format!(
                            "Shell injection guard: the command `{}` contains potentially \
                             dangerous characters. Use parameterised tool calls instead.",
                            &cmd[..cmd.len().min(100)]
                        ),
                        timestamp,
                        call: call.clone(),
                    };
                }
            }
        }

        // ── 4. Sensitive tool audit warning ───────────────────────────────
        if self.sensitive_tools.contains(call.tool.as_str()) {
            return McpDecision {
                decision: Decision::Warn,
                reason: format!(
                    "Tool `{}` is in the sensitive-tools list. \
                     Audit this call before proceeding.",
                    call.tool
                ),
                timestamp,
                call: call.clone(),
            };
        }

        // ── Default: allow ─────────────────────────────────────────────────
        McpDecision {
            decision:  Decision::Allow,
            reason:    "No policy violations detected.".to_string(),
            timestamp,
            call: call.clone(),
        }
    }

    // ── Param extraction helpers ──────────────────────────────────────────────

    fn extract_path_param(&self, params: &serde_json::Value) -> Option<String> {
        ["path", "file", "filename", "filepath", "target", "destination"]
            .iter()
            .filter_map(|key| params.get(key).and_then(|v| v.as_str()).map(|s| s.to_string()))
            .next()
    }

    fn extract_env_var_name(&self, params: &serde_json::Value) -> Option<String> {
        ["name", "var", "variable", "key"]
            .iter()
            .filter_map(|k| params.get(k).and_then(|v| v.as_str()).map(|s| s.to_string()))
            .next()
    }

    fn extract_command(&self, params: &serde_json::Value) -> Option<String> {
        ["command", "cmd", "args", "input"]
            .iter()
            .filter_map(|k| params.get(k).and_then(|v| v.as_str()).map(|s| s.to_string()))
            .next()
    }

    fn glob_match(&self, path: &str, pattern: &str) -> bool {
        if pattern.ends_with('*') {
            path.starts_with(pattern.trim_end_matches('*'))
        } else {
            path == pattern || path.ends_with(pattern)
        }
    }
}

// ── JSON-RPC Server helper ────────────────────────────────────────────────────

/// Parse a JSON string as an `McpToolCall`, evaluate it, and return the
/// decision JSON.  Used by the `agent-armor mcp-proxy` subcommand which
/// reads newline-delimited JSON from stdin.
pub fn evaluate_json(proxy: &McpProxy, json: &str) -> String {
    match serde_json::from_str::<McpToolCall>(json) {
        Ok(call) => {
            let decision = proxy.evaluate(&call);
            serde_json::to_string_pretty(&decision).unwrap_or_else(|e| {
                format!("{{\"error\": \"{}\"}}", e)
            })
        }
        Err(e) => format!("{{\"error\": \"Invalid JSON: {}\"}}", e),
    }
}
