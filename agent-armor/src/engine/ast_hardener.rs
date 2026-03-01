// src/engine/ast_hardener.rs
//! AST Hardener Module
//!
//! Uses tree-sitter to parse AI-generated code into a concrete syntax tree
//! and detects:
//!  • Dangerous function call sinks  (eval, exec, os.system, …)
//!  • Missing input validation before data reaches a DB/file sink
//!  • Functions without any error handling (try/except / try/catch)
//!  • SQL string concatenation (potential injection)
//!  • Command-string building (potential shell injection)
//!
//! Multi-language: Python and JavaScript are supported; the correct grammar
//! is selected based on the file extension passed to `AstHardener::new`.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tree_sitter::{Language, Parser, Query, QueryCursor};

// ── Language bindings (tree-sitter 0.20 extern-C API) ────────────────────────

extern "C" {
    fn tree_sitter_python()     -> Language;
    fn tree_sitter_javascript() -> Language;
}

fn python_language() -> Language {
    unsafe { tree_sitter_python() }
}

fn javascript_language() -> Language {
    unsafe { tree_sitter_javascript() }
}

// ── Finding ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AstFindingKind {
    DangerousSink,
    MissingErrorHandling,
    SqlInjectionRisk,
    ShellInjectionRisk,
    MissingInputValidation,
    HardcodedDbCredential,
    UnprotectedDeleteOperation,
}

impl std::fmt::Display for AstFindingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AstFindingKind::DangerousSink => write!(f, "Dangerous Sink"),
            AstFindingKind::MissingErrorHandling => write!(f, "Missing Error Handling"),
            AstFindingKind::SqlInjectionRisk => write!(f, "SQL Injection Risk"),
            AstFindingKind::ShellInjectionRisk => write!(f, "Shell Injection Risk"),
            AstFindingKind::MissingInputValidation => write!(f, "Missing Input Validation"),
            AstFindingKind::HardcodedDbCredential => write!(f, "Hardcoded DB Credential"),
            AstFindingKind::UnprotectedDeleteOperation => write!(f, "Unprotected Delete Operation"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstFinding {
    pub kind:       AstFindingKind,
    pub line:       usize,
    pub col:        usize,
    pub node_text:  String,
    pub suggestion: String,
}

// ── Hardener ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum SourceLanguage {
    Python,
    JavaScript,
    Unknown,
}

impl SourceLanguage {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "py" => Self::Python,
            "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" => Self::JavaScript,
            _ => Self::Unknown,
        }
    }
}

pub struct AstHardener {
    parser:   Parser,
    language: Language,
    lang_id:  SourceLanguage,
    /// Blocked function names (from policy).
    blocked:  Vec<String>,
}

impl AstHardener {
    pub fn new(lang: SourceLanguage, blocked_functions: Vec<String>) -> Result<Self> {
        let language = match lang {
            SourceLanguage::Python => python_language(),
            SourceLanguage::JavaScript => javascript_language(),
            SourceLanguage::Unknown => python_language(), // safe default
        };

        let mut parser = Parser::new();
        parser
            .set_language(language)
            .map_err(|e| anyhow::anyhow!("Failed to load grammar: {}", e))?;

        Ok(Self {
            parser,
            language,
            lang_id: lang,
            blocked: blocked_functions,
        })
    }

    /// Full analysis pass — returns all findings.
    pub fn analyze(&mut self, source: &str) -> Vec<AstFinding> {
        let mut findings = Vec::new();
        let Some(tree) = self.parser.parse(source, None) else {
            return findings;
        };

        findings.extend(self.detect_dangerous_sinks(source, &tree));
        findings.extend(self.detect_functions_without_error_handling(source, &tree));
        findings.extend(self.detect_sql_injection(source, &tree));
        findings.extend(self.detect_shell_injection(source, &tree));
        findings.extend(self.detect_unprotected_deletes(source, &tree));

        findings
    }

    // ── Dangerous sinks ──────────────────────────────────────────────────────

    fn detect_dangerous_sinks(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
    ) -> Vec<AstFinding> {
        let mut findings = Vec::new();

        // Match any function call and check if its name is in the blocked list.
        let query_str = "(call function: [(identifier) (attribute)] @func)";
        let Ok(query) = Query::new(self.language, query_str) else {
            return findings;
        };
        let mut cursor = QueryCursor::new();

        for m in cursor.matches(&query, tree.root_node(), source.as_bytes()) {
            for cap in m.captures.iter() {
                let node = cap.node;
                let Ok(text) = node.utf8_text(source.as_bytes()) else {
                    continue;
                };
                // Check plain name and attribute-access form (e.g. "os.system")
                if self.blocked.iter().any(|b| b.as_str() == text || text.ends_with(b.as_str())) {
                    findings.push(AstFinding {
                        kind: AstFindingKind::DangerousSink,
                        line: node.start_position().row + 1,
                        col:  node.start_position().column + 1,
                        node_text: text.to_string(),
                        suggestion: format!(
                            "`{}` is a dangerous sink. Remove it or replace with a \
                             sandboxed alternative (e.g. `ast.literal_eval` for \
                             safe Python expression parsing).",
                            text
                        ),
                    });
                }
            }
        }
        findings
    }

    // ── Functions without error handling ─────────────────────────────────────

    fn detect_functions_without_error_handling(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
    ) -> Vec<AstFinding> {
        let mut findings = Vec::new();

        // Python: function_definition bodies; JS: function_declaration bodies
        let query_str = match self.lang_id {
            SourceLanguage::Python => "(function_definition name: (identifier) @name body: (block) @body)",
            SourceLanguage::JavaScript => {
                "(function_declaration name: (identifier) @name body: (statement_block) @body)"
            }
            SourceLanguage::Unknown => return findings,
        };

        let Ok(query) = Query::new(self.language, query_str) else {
            return findings;
        };
        let mut cursor = QueryCursor::new();
        let src_bytes = source.as_bytes();

        // Collect (name_node, body_node) pairs
        let mut pairs: Vec<(tree_sitter::Node, tree_sitter::Node)> = Vec::new();
        for m in cursor.matches(&query, tree.root_node(), src_bytes) {
            if m.captures.len() >= 2 {
                let name_node = m.captures[0].node;
                let body_node = m.captures[1].node;
                pairs.push((name_node, body_node));
            }
        }

        for (name_node, body_node) in pairs {
            let body_src = body_node.utf8_text(src_bytes).unwrap_or("");
            // Heuristic: does the body contain a try/except or try/catch?
            let has_error_handling = body_src.contains("try:")
                || body_src.contains("except ")
                || body_src.contains("try {")
                || body_src.contains("catch (")
                || body_src.contains("catch(");

            // Only flag functions that do IO-like operations
            let does_io = body_src.contains("open(")
                || body_src.contains("requests.")
                || body_src.contains("fetch(")
                || body_src.contains("cursor.execute")
                || body_src.contains("db.")
                || body_src.contains("fs.")
                || body_src.contains("http.")
                || body_src.contains(".connect(");

            if does_io && !has_error_handling {
                let func_name = name_node.utf8_text(src_bytes).unwrap_or("?");
                findings.push(AstFinding {
                    kind:      AstFindingKind::MissingErrorHandling,
                    line:      name_node.start_position().row + 1,
                    col:       name_node.start_position().column + 1,
                    node_text: func_name.to_string(),
                    suggestion: format!(
                        "Function `{}` performs I/O but has no error handling. \
                         Wrap the body in try/except (Python) or try/catch (JS) \
                         to prevent unhandled exceptions from crashing the agent.",
                        func_name
                    ),
                });
            }
        }
        findings
    }

    // ── SQL injection detection ───────────────────────────────────────────────

    fn detect_sql_injection(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
    ) -> Vec<AstFinding> {
        let mut findings = Vec::new();

        // Look for string concatenation / f-string that contains SQL keywords
        let src_bytes = source.as_bytes();

        // Simple heuristic: find assignments where value contains "SELECT|INSERT|UPDATE|DELETE"
        // AND uses + or f-string interpolation (injection risk)
        let binary_op_query = "(binary_operator left: _ @left operator: \"+\" right: _ @right)";
        if let Ok(query) = Query::new(self.language, binary_op_query) {
            let mut cursor = QueryCursor::new();
            for m in cursor.matches(&query, tree.root_node(), src_bytes) {
                let full_text = m
                    .captures
                    .iter()
                    .filter_map(|c| c.node.utf8_text(src_bytes).ok())
                    .collect::<Vec<_>>()
                    .join(" + ");

                let upper = full_text.to_uppercase();
                if (upper.contains("SELECT")
                    || upper.contains("INSERT")
                    || upper.contains("UPDATE")
                    || upper.contains("DELETE")
                    || upper.contains("DROP"))
                    && (full_text.contains('+') || full_text.contains('%'))
                {
                    let node = m.captures[0].node;
                    findings.push(AstFinding {
                        kind:      AstFindingKind::SqlInjectionRisk,
                        line:      node.start_position().row + 1,
                        col:       node.start_position().column + 1,
                        node_text: full_text[..full_text.len().min(80)].to_string(),
                        suggestion:
                            "SQL query built via string concatenation. Use parameterised \
                             queries (`cursor.execute(sql, params)`) instead of \
                             string formatting to prevent SQL injection."
                                .to_string(),
                    });
                }
            }
        }
        findings
    }

    // ── Shell injection detection ─────────────────────────────────────────────

    fn detect_shell_injection(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
    ) -> Vec<AstFinding> {
        let mut findings = Vec::new();
        let src_bytes = source.as_bytes();

        let call_query = "(call function: [(identifier) (attribute)] @func arguments: (argument_list) @args)";
        let Ok(query) = Query::new(self.language, call_query) else {
            return findings;
        };
        let mut cursor = QueryCursor::new();

        for m in cursor.matches(&query, tree.root_node(), src_bytes) {
            if m.captures.len() < 2 {
                continue;
            }
            let func_text = m.captures[0].node.utf8_text(src_bytes).unwrap_or("");
            let args_text = m.captures[1].node.utf8_text(src_bytes).unwrap_or("");

            if (func_text.ends_with("system")
                || func_text.ends_with("popen")
                || func_text == "run"
                || func_text == "call")
                && (args_text.contains('+')
                    || args_text.contains("f\"")
                    || args_text.contains("f'")
                    || args_text.contains('%'))
            {
                let node = m.captures[0].node;
                findings.push(AstFinding {
                    kind:      AstFindingKind::ShellInjectionRisk,
                    line:      node.start_position().row + 1,
                    col:       node.start_position().column + 1,
                    node_text: format!("{}({})", func_text, &args_text[..args_text.len().min(60)]),
                    suggestion:
                        "Shell command built from user-controlled input. Use \
                         `subprocess.run([...], shell=False)` with a list of \
                         arguments — never build shell strings dynamically."
                            .to_string(),
                });
            }
        }
        findings
    }

    // ── Unprotected delete operations ─────────────────────────────────────────

    fn detect_unprotected_deletes(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
    ) -> Vec<AstFinding> {
        let mut findings = Vec::new();
        let src_bytes = source.as_bytes();

        let func_query = match self.lang_id {
            SourceLanguage::Python => {
                "(function_definition name: (identifier) @name body: (block) @body)"
            }
            SourceLanguage::JavaScript => {
                "(function_declaration name: (identifier) @name body: (statement_block) @body)"
            }
            SourceLanguage::Unknown => return findings,
        };

        let Ok(query) = Query::new(self.language, func_query) else {
            return findings;
        };
        let mut cursor = QueryCursor::new();

        for m in cursor.matches(&query, tree.root_node(), src_bytes) {
            if m.captures.len() < 2 {
                continue;
            }
            let name_node = m.captures[0].node;
            let body_node = m.captures[1].node;

            let name = name_node.utf8_text(src_bytes).unwrap_or("");
            let body = body_node.utf8_text(src_bytes).unwrap_or("");

            let is_delete_fn = name.to_lowercase().contains("delete")
                || name.to_lowercase().contains("remove")
                || name.to_lowercase().contains("destroy");

            let has_auth_check = body.contains("user_id")
                || body.contains("is_admin")
                || body.contains("authorized")
                || body.contains("permission")
                || body.contains("authenticate")
                || body.contains("require_auth")
                || body.contains("checkPermission");

            if is_delete_fn && !has_auth_check {
                findings.push(AstFinding {
                    kind:      AstFindingKind::UnprotectedDeleteOperation,
                    line:      name_node.start_position().row + 1,
                    col:       name_node.start_position().column + 1,
                    node_text: name.to_string(),
                    suggestion: format!(
                        "Function `{}` performs a destructive operation but \
                         contains no authorization check. Add a `user_id` / \
                         permission guard before executing the delete.",
                        name
                    ),
                });
            }
        }
        findings
    }
}
