# 🛡️ AgentArmor — Zero-Trust Middleware for Agentic Coding

[![CI](https://github.com/tanmaydikey/agent-armor/actions/workflows/ci.yml/badge.svg)](https://github.com/tanmaydikey/agent-armor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/agent-armor.svg)](https://crates.io/crates/agent-armor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![agent-armor](https://img.shields.io/badge/agent--armor-attested%20%26%20secure-brightgreen)

> **AgentArmor is the first Zero-Trust security layer for AI-generated code.**  
> It doesn't just scan code. It **intercepts**, **hardens**, and **cryptographically signs** it before it ever hits a disk or a Git commit.

---

## The Problem: Agentic Drift

AI agents have graduated from writing snippets to autonomously managing entire repositories. They move fast — and they introduce **Shadow Vulnerabilities**: code that looks logically sound but silently lacks security invariants.

A single missed `if (user.isAdmin)` check, a hardcoded AWS key, an `eval()` on user input — these are now being shipped at machine speed. Traditional scanners catch known CVEs. **AgentArmor catches the category of vulnerability that AI agents create by default.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI AGENT                                 │
│  (Cursor, GitHub Copilot, Claude, GPT-4, custom MCP agent)     │
└─────────────────────────────┬───────────────────────────────────┘
                              │  raw code / tool_call
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   ★ AgentArmor Zero-Trust Layer ★               │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  MCP Proxy   │  │ Secret       │  │  AST Hardener        │  │
│  │              │  │ Scrubber     │  │  (tree-sitter)       │  │
│  │ Intercepts   │  │              │  │                      │  │
│  │ tool_calls   │  │ Regex +      │  │ Dangerous sinks      │  │
│  │ before exec  │  │ Shannon      │  │ Missing try/except   │  │
│  │              │  │ Entropy      │  │ SQL injection        │  │
│  │ Path guard   │  │              │  │ Shell injection      │  │
│  │ Domain ISO   │  │ Auto-rewrites│  │ Unprotected deletes  │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  DTG Engine  │  │ Slopsquat    │  │  Attestation         │  │
│  │              │  │ Guard        │  │  Shadow-Chain        │  │
│  │ Data-flow    │  │              │  │                      │  │
│  │ taint graph  │  │ npm / PyPI   │  │ SHA-256 hash of      │  │
│  │              │  │ registry     │  │ code + invariants    │  │
│  │ Source→Sink  │  │ validator    │  │                      │  │
│  │ without      │  │              │  │ Embedded in file +   │  │
│  │ sanitizer    │  │ Typosquat    │  │ .shadow-chain.json   │  │
│  │              │  │ detection    │  │                      │  │
│  │ Auto-injects │  │              │  │ CI verifies before   │  │
│  │ Pydantic/Zod │  │              │  │ every deploy         │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────┬───────────────────────────────────┘
                              │  attested, hardened code
                              ▼
                     ✅  Git Commit / Disk
```

---

## Features

### 🔑 Secret Scrubber
Detects and replaces hardcoded credentials using:
- Named regex patterns (AWS keys, Stripe keys, GitHub PATs, JWTs, OpenAI keys…)
- Shannon entropy analysis — catches secrets that don't match known patterns
- Auto-rewrites to `os.getenv()` / `process.env` so the code stays runnable

### 🌳 AST Hardener (tree-sitter)
Parses code into a concrete syntax tree and catches:
- `eval()`, `exec()`, `os.system()`, `pickle.loads()` — dangerous execution sinks
- Functions that do I/O without any `try/except` / `try/catch`
- SQL queries built via string concatenation
- Shell commands built from user input
- Delete/destroy functions with no authorization check

### ⚡ DTG Engine (Data-Transformation Graph)
Traces data flow from **Sources** (HTTP requests, `sys.argv`, env vars) to **Sinks** (DB queries, file writes, shell commands). If no **Sanitizer** node exists on the path, it:
1. Flags the taint flow with line numbers
2. Auto-generates a **Pydantic** (Python) or **Zod** (JS) validation schema to inject

### 📦 Slopsquatting Guard
Validates every `import` / `require` before the code is committed:
- Queries npm / PyPI live (or uses cache in `--offline` mode)
- Flags packages that don't exist (**AI hallucination**)
- Flags newly-registered packages (< 48h — potential slopsquatting attack)
- Flags low-download packages (< 500 — suspicious)
- Levenshtein distance check for typosquats of popular packages

### 🔌 MCP Security Proxy
Sits between the AI agent and its tools (Model Context Protocol):
- Blocks writes to protected paths (`/etc/passwd`, `~/.ssh/`, `.env`…)
- Enforces domain isolation (frontend agents cannot read backend env vars)
- Rejects dynamic shell commands (injection guard)
- Full audit log of every Allow/Block/Warn decision

### 🔏 Attestation Shadow-Chain
Every hardened file receives a cryptographic attestation:
- SHA-256 of the hardened code
- SHA-256 of the verified security invariants
- Combined signature embeds version + timestamp
- Attestation comment embedded in the source file
- `.shadow-chain.json` manifest written alongside the source
- `agent-armor verify <file>` fails CI if the file was modified after signing

---

## Installation

### From source
```bash
git clone https://github.com/tanmaydikey/agent-armor
cd agent-armor
cargo build --release
cp target/release/agent-armor ~/.local/bin/
```

### From crates.io
```bash
cargo install agent-armor
```

---

## Quick Start

```bash
# 1. Initialize config
agent-armor init

# 2. Scan your AI-generated code
agent-armor scan src/

# 3. Scan with hardened output written next to originals
agent-armor scan src/ --write-output

# 4. JSON output for CI
agent-armor scan src/ --format json

# 5. Verify an existing attestation
agent-armor verify src/api.py

# 6. Evaluate MCP tool calls (pipe from your agent harness)
echo '{"tool":"write_to_file","params":{"path":"/etc/passwd","content":"hacked"}}' \
  | agent-armor mcp-proxy

# 7. Explore the vulnerability museum
agent-armor museum
agent-armor scan vulnerability_museum/
```

---

## GitHub Actions Integration

Add to your workflow:

```yaml
- name: AgentArmor Zero-Trust Scan
  run: |
    cargo install agent-armor
    agent-armor scan . --format json --fail-on-block=true
```

Or copy `.github/workflows/agent-armor.yml` from this repo.

---

## Configuration (`.agent-armor.toml`)

```toml
[secrets]
enabled           = true
severity          = "auto-fix"   # auto-fix | warn | block
entropy_threshold = 3.5

[dangerous_sinks]
enabled  = true
severity = "block"
blocked_functions = ["eval", "exec", "os.system", "pickle.loads"]

[slopsquatting]
enabled                     = true
severity                     = "block"
new_package_threshold_hours = 48
low_download_threshold      = 500

[mcp]
enabled         = true
protected_paths = ["/etc/passwd", "~/.ssh/", ".env", "*.key"]

[attestation]
enabled            = true
embed_in_code      = true
write_shadow_chain = true
strict_verify      = true
```

Run `agent-armor init` to generate this file with defaults.

---

## Secure-by-Agent Badge

Add to your `README.md` after running AgentArmor on your project:

```markdown
![agent-armor](https://img.shields.io/badge/agent--armor-attested%20%26%20secure-brightgreen)
```

For a dynamic badge showing attested line count:

```bash
agent-armor badge src/main.py
# Outputs shields.io-compatible JSON
```

---

## 🏛️ Vulnerability Museum

The `vulnerability_museum/` folder contains real AI-generated vulnerable code paired with AgentArmor's output. Every pattern was observed in frontier model outputs:

| Exhibit | Vulnerability | Fix |
|---------|-------------|-----|
| `01_sql_injection` | String concatenation in SQL | Parameterised query + Pydantic |
| `02_hardcoded_secrets` | 5 live credentials in source | `os.getenv()` everywhere |
| `03_eval_injection` | `eval()` on user input | AST-safe expression parser |
| `04_missing_auth_check` | Delete endpoint, no auth | JWT decorator + ownership |
| `05_path_traversal` | `send_file(dir + user_input)` | `safe_join()` with containment |

```bash
agent-armor scan vulnerability_museum/
```

---

## Technical Stack

| Component | Technology | Why |
|-----------|------------|-----|
| Core engine | **Rust** | Memory safety + WASM-compilable + microsecond parsing |
| AST parser | **tree-sitter** | True multi-language structural understanding |
| Crypto | **sha2 + hmac** | Industry-standard, audited crates |
| CLI | **clap** | Professional developer UX |
| HTTP | **reqwest** | Async-ready registry validation |
| Serialization | **serde + serde_json + toml** | Flexible report formats |

---

## Research Foundation

AgentArmor implements two 2025–2026 academic concepts:

**Semantic Over-Confidence Mitigation** — AI models produce "perfect-looking" code that lacks error handling. AgentArmor's AST Hardener specifically hunts for I/O functions without `try/except` blocks and flags them as over-confident.

**Formal Invariant Verification** — Inspired by Rapid Formal Verification methods, the Attestation Shadow-Chain encodes the security invariants that were verified during hardening. If any invariant is later violated (e.g., the `if (user.isAdmin)` check is removed), the attestation breaks and the CI pipeline blocks deployment.

---

## License

MIT — see [LICENSE](LICENSE)

---

*AgentArmor: because AI writes code at machine speed, and security can't be an afterthought.*
