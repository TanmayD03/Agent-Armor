# Building AgentArmor

## Prerequisites

- Rust 1.70+ (install via https://rustup.rs)
- C compiler (for tree-sitter grammar compilation — `gcc` or `clang`)

## Quick Build

```bash
# Install Rust if not present
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build --release

# The binary is at:
./target/release/agent-armor

# Run tests
cargo test

# Install globally
cargo install --path .
```

## First Run

```bash
# Initialize config
agent-armor init

# Scan the vulnerability museum (see all 5 vulnerability categories caught)
agent-armor scan vulnerability_museum/

# Scan your own AI-generated code
agent-armor scan path/to/your/code/
```

## Dependency Notes

- **tree-sitter 0.20** — stable extern-C grammar API, widely supported
- **reqwest 0.11** — blocking HTTP for registry checks (no async complexity)
- If you're in an air-gapped environment, use `--offline` to skip registry calls

## GitHub Actions

Copy `.github/workflows/agent-armor.yml` to your repository to run
AgentArmor on every push and pull request.
