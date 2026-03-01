// src/main.rs
//! AgentArmor CLI
//!
//! Usage:
//!   agent-armor scan <file_or_dir>     — full analysis pipeline
//!   agent-armor verify <file>          — verify attestation
//!   agent-armor mcp-proxy              — read JSON from stdin, evaluate, print decision
//!   agent-armor init                   — write default .agent-armor.toml
//!   agent-armor museum                 — show the vulnerability museum summary

use agent_armor::{engine::policy::PolicyConfig, AgentArmor};
use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use walkdir::WalkDir;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name        = "agent-armor",
    about       = "Zero-Trust Middleware for Agentic Coding",
    long_about  = "Intercepts, hardens, and cryptographically attests AI-generated code\nbefore it ever hits a disk or a Git commit.",
    version,
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to .agent-armor.toml config (default: ./.agent-armor.toml)
    #[arg(long, global = true, env = "AGENT_ARMOR_CONFIG")]
    config: Option<PathBuf>,

    /// Skip registry network calls (useful in air-gapped CI)
    #[arg(long, global = true, default_value = "false")]
    offline: bool,

    /// Output format: human (default) | json
    #[arg(long, global = true, default_value = "human")]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a file or directory through the full AgentArmor pipeline.
    Scan {
        /// File or directory to scan.
        path: PathBuf,
        /// Write hardened output next to each source file (_hardened suffix).
        #[arg(long)]
        write_output: bool,
        /// Write shadow-chain JSON manifests alongside source files.
        #[arg(long, default_value_t = true)]
        write_manifest: bool,
        /// Fail (exit 1) if any blocking findings are detected.
        #[arg(long, default_value_t = true)]
        fail_on_block: bool,
    },
    /// Verify that a file's attestation is still valid.
    Verify {
        /// The hardened file to verify.
        path: PathBuf,
    },
    /// Run the MCP Security Proxy: reads JSON tool-call objects from stdin,
    /// one per line, and writes decision JSON to stdout.
    McpProxy,
    /// Write a default .agent-armor.toml to the current directory.
    Init,
    /// Print a summary of the Vulnerability Museum examples.
    Museum,
    /// Scan a file and print how many lines are currently attested and secure.
    Badge {
        path: PathBuf,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load policy
    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(".agent-armor.toml"));
    let policy = PolicyConfig::load(&config_path)?;

    let armor = AgentArmor::new(policy.clone(), cli.offline);

    match cli.command {
        Commands::Scan {
            path,
            write_output,
            write_manifest,
            fail_on_block,
        } => cmd_scan(&armor, &policy, &path, write_output, write_manifest, fail_on_block, &cli.format)?,

        Commands::Verify { path } => {
            println!("{}", "🔍 AgentArmor — Attestation Verifier".bold().cyan());
            let ok = armor.verify_file(&path)?;
            if !ok {
                std::process::exit(1);
            }
        }

        Commands::McpProxy => cmd_mcp_proxy(&armor)?,

        Commands::Init => {
            let path = PathBuf::from(".agent-armor.toml");
            PolicyConfig::write_default(&path)?;
            println!(
                "{}",
                "✅ Default .agent-armor.toml written. Customise it for your project.".green()
            );
        }

        Commands::Museum => print_museum(),

        Commands::Badge { path } => cmd_badge(&armor, &path)?,
    }

    Ok(())
}

// ── Scan command ──────────────────────────────────────────────────────────────

fn cmd_scan(
    armor:          &AgentArmor,
    _policy:        &PolicyConfig,
    path:           &PathBuf,
    write_output:   bool,
    write_manifest: bool,
    fail_on_block:  bool,
    format:         &str,
) -> Result<()> {
    print_banner();

    let supported_exts = ["py", "js", "ts", "jsx", "tsx", "mjs"];
    let mut files: Vec<PathBuf> = Vec::new();

    if path.is_file() {
        files.push(path.clone());
    } else {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
                if supported_exts.contains(&ext) {
                    files.push(entry.path().to_path_buf());
                }
            }
        }
    }

    if files.is_empty() {
        println!("{}", "No supported source files found.".yellow());
        return Ok(());
    }

    println!(
        "{}",
        format!("🛡️  Scanning {} file(s)…\n", files.len()).bold()
    );

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=> "),
    );

    let mut any_blocked = false;
    let mut all_reports = Vec::new();

    for file in &files {
        pb.set_message(format!("{}", file.display()));
        let result = armor.process_file(file);

        match result {
            Ok((hardened, mut report)) => {
                report.finalize();

                if !report.passed {
                    any_blocked = true;
                }

                if format == "json" {
                    println!("{}", report.to_json()?);
                } else {
                    print_report_human(&report, file);
                }

                if write_output {
                    let out_path = file.with_extension(format!(
                        "hardened.{}",
                        file.extension().unwrap_or_default().to_str().unwrap_or("py")
                    ));
                    std::fs::write(&out_path, &hardened)?;
                }

                if write_manifest {
                    if let Some(rec) = &report.attestation {
                        let manifest_path = file.with_extension("shadow-chain.json");
                        std::fs::write(&manifest_path, rec.to_manifest_json()?)?;
                    }
                }

                all_reports.push(report);
            }
            Err(e) => {
                pb.println(format!("  {} {}: {}", "ERROR".red(), file.display(), e));
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Done");
    println!();

    // ── Overall summary ────────────────────────────────────────────────────
    let total_secrets: usize   = all_reports.iter().map(|r| r.secret_findings.len()).sum();
    let total_ast:     usize   = all_reports.iter().map(|r| r.ast_findings.len()).sum();
    let total_dtg:     usize   = all_reports.iter().map(|r| r.dtg_findings.len()).sum();
    let total_slop:    usize   = all_reports.iter().map(|r| r.slopsquat_findings.len()).sum();
    let attested:      usize   = all_reports.iter().filter(|r| r.attestation.is_some()).count();

    println!("{}", "═══════════════════════════════════════════".cyan());
    println!("{}", "  AgentArmor Scan Summary".bold().cyan());
    println!("{}", "═══════════════════════════════════════════".cyan());
    println!("  Files scanned      : {}", files.len());
    println!("  Secrets scrubbed   : {}", total_secrets.to_string().yellow());
    println!("  AST issues         : {}", if total_ast > 0 { total_ast.to_string().red() } else { total_ast.to_string().green() });
    println!("  DTG taint flows    : {}", if total_dtg > 0 { total_dtg.to_string().yellow() } else { total_dtg.to_string().green() });
    println!("  Suspicious packages: {}", if total_slop > 0 { total_slop.to_string().red() } else { total_slop.to_string().green() });
    println!("  Files attested     : {}", attested.to_string().green());
    println!("{}", "═══════════════════════════════════════════".cyan());

    if any_blocked && fail_on_block {
        println!(
            "{}",
            "\n❌ PIPELINE BLOCKED — Fix the above issues before committing.\n".red().bold()
        );
        std::process::exit(1);
    } else {
        println!("{}", "\n✅ All checks passed — code is attested and secure.\n".green().bold());
    }

    Ok(())
}

// ── MCP Proxy command ─────────────────────────────────────────────────────────

fn cmd_mcp_proxy(armor: &AgentArmor) -> Result<()> {
    use std::io::BufRead;
    println!("{}", "🔌 AgentArmor MCP Proxy — reading tool calls from stdin (CTRL-C to exit)".cyan());

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<agent_armor::engine::mcp_proxy::McpToolCall>(&line) {
            Ok(call) => {
                let decision = armor.evaluate_mcp(&call);
                let icon = match decision.decision {
                    agent_armor::engine::mcp_proxy::Decision::Allow => "✅",
                    agent_armor::engine::mcp_proxy::Decision::Block => "🛑",
                    agent_armor::engine::mcp_proxy::Decision::Warn  => "⚠️ ",
                };
                println!("{} {} — {}", icon, decision.decision, decision.reason);
                println!("{}", serde_json::to_string_pretty(&decision)?);
            }
            Err(e) => {
                eprintln!("{}", format!("Invalid JSON: {}", e).red());
            }
        }
    }
    Ok(())
}

// ── Badge command ─────────────────────────────────────────────────────────────

fn cmd_badge(armor: &AgentArmor, path: &PathBuf) -> Result<()> {
    let src = std::fs::read_to_string(path)?;
    let lines = src.lines().count();
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("py");
    let filename = path.to_str().unwrap_or("unknown");

    let (hardened, report) = armor.process_source(&src, ext, filename)?;
    let attested_lines = hardened.lines().count();

    println!(
        "{{ \"schemaVersion\": 1, \"label\": \"agent-armor\", \"message\": \"{}/{} lines attested\", \"color\": \"{}\" }}",
        attested_lines,
        lines,
        if report.passed { "brightgreen" } else { "red" }
    );
    Ok(())
}

// ── Printing helpers ──────────────────────────────────────────────────────────

fn print_banner() {
    println!("{}", r#"
    ╔═══════════════════════════════════════════════╗
    ║   █████╗  ██████╗ ███████╗███╗   ██╗████████╗║
    ║  ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝║
    ║  ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ║
    ║  ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ║
    ║  ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ║
    ║  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ║
    ║      A R M O R   —  Zero-Trust for AI Code    ║
    ╚═══════════════════════════════════════════════╝
    "#.cyan().bold());
}

fn print_report_human(
    report: &agent_armor::ArmorReport,
    file: &PathBuf,
) {
    let status = if report.passed {
        "✅ PASS".green().bold()
    } else {
        "❌ FAIL".red().bold()
    };

    println!("\n{} {}", status, file.display().to_string().bold());

    for f in &report.secret_findings {
        println!(
            "  {} [Line {:>4}] {} → {}",
            "🔑 SECRET".yellow(),
            f.line,
            f.pattern,
            f.replaced_with
        );
    }

    for f in &report.ast_findings {
        println!(
            "  {} [Line {:>4}] {} — {}",
            "🚨 AST".red(),
            f.line,
            f.kind,
            f.suggestion
        );
    }

    for f in &report.dtg_findings {
        println!(
            "  {} [Line {:>4}→{:>4}] {} → {}",
            "⚡ DTG".yellow(),
            f.source_line,
            f.sink_line,
            f.source_label,
            f.sink_label,
        );
    }

    for f in &report.slopsquat_findings {
        println!(
            "  {} [Line {:>4}] {} ({})",
            "📦 SLOP".red(),
            f.line,
            f.package_name,
            f.suggestion
        );
    }

    if let Some(att) = &report.attestation {
        println!(
            "  {} sig={}…",
            "🔏 ATTESTED".green(),
            &att.signature[..16]
        );
    }
}

fn print_museum() {
    println!("{}", "\n🏛️  AgentArmor Vulnerability Museum".bold().cyan());
    println!("{}", "─────────────────────────────────────────────────────");
    let exhibits = [
        ("01_sql_injection",       "SQL Injection via string concatenation in a search endpoint"),
        ("02_hardcoded_secrets",   "AWS credentials embedded directly in source"),
        ("03_eval_injection",      "eval() called on user-controlled input"),
        ("04_missing_auth_check",  "Delete endpoint with no authorization guard"),
        ("05_path_traversal",      "File download endpoint vulnerable to path traversal"),
    ];
    for (dir, desc) in &exhibits {
        println!("  📁 vulnerability_museum/{:<35} {}", dir, desc);
    }
    println!(
        "\n{}",
        "Each exhibit contains bad.py (the AI-generated code) and fixed.py (AgentArmor output).".italic()
    );
    println!(
        "{}",
        "Run `agent-armor scan vulnerability_museum/` to see all issues caught live.".italic()
    );
    println!();
}
