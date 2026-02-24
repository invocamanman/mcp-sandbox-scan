# mcp-sandbox-sca

Security scanner for AI coding assistants. Detects prompt injections, credential exfiltration, malicious tool behavior, and supply-chain attacks in repositories and AI tools/plugins.

## Quick Start

```bash
# Static scan (free, no API key)
npx mcp-sandbox-sca scan-repo /path/to/repo --static
npx mcp-sandbox-sca scan-tool /path/to/mcp-server --static
npx mcp-sandbox-sca scan-full /path/to/anything --static

# Full scan with LLM honeypot (requires Anthropic API key)
ANTHROPIC_API_KEY=sk-ant-... npx mcp-sandbox-sca scan-full /path/to/repo
```

## Installation

**Claude Code (one command):**

```bash
# With API key (full honeypot scan)
claude mcp add security-scanner -e ANTHROPIC_API_KEY=sk-ant-... -- npx mcp-sandbox-sca

# Without API key (static scan only, free)
claude mcp add security-scanner -- npx mcp-sandbox-sca
```

**Claude Desktop** (add to `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "npx",
      "args": ["mcp-sandbox-sca"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

**Static only** (free, no API key):

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "npx",
      "args": ["mcp-sandbox-sca"]
    }
  }
}
```

### Getting an Anthropic API Key

Get one at [console.anthropic.com](https://console.anthropic.com). The honeypot uses Claude Haiku — the cheapest model. **$1 of credit covers hundreds of full scans.** If you only scan occasionally, the free tier is likely enough.

## Scanning Tools

| Tool | Purpose |
|------|---------|
| `scan_repo` | Scans a repository for prompt injections and malicious instructions in config/markdown files |
| `scan_ai_tool` | Scans an MCP server, plugin, or agent framework for malicious behavior |
| `scan_full` | Comprehensive audit — both repo and AI tool patterns combined |

Example (in Claude):
> "Scan the directory /path/to/suspicious-repo for security issues"

## How It Works

### Layer 1: Static Analysis (always runs, free)

Deterministic regex/pattern scanner across 7 threat categories. Fast, offline, no API key needed. Catches ~70% of common attacks.

### Layer 2: LLM Honeypot (optional, requires `ANTHROPIC_API_KEY`)

Uses **privilege separation** — a single LLM cannot safely read untrusted files AND judge whether they're malicious (a sophisticated injection hijacks the reader). Instead:

1. **Probe agent** (Haiku — cheap, naive) gets the directory tree and uses `read_file` to explore the repo naturally, exactly like a real AI assistant would. It has honeypot credentials in its environment.
2. **Hybrid Sandbox** intercepts all tool calls. `read_file` inside the repo returns real content (the Probe must actually read the malicious files to fall for injections). All other tools (bash, network, file writes) are logged but never executed.
3. **Deterministic log analyzer** classifies the Probe's tool call log — checking for honeypot secret exfiltration, outside-repo reads, bash execution, HTTP requests to unknown hosts, and writes to AI config paths. No second LLM call needed: the sandbox log is already fully structured.

## What It Detects

| Category | Examples |
|----------|---------|
| **Prompt Injection** | `ignore all previous instructions`, system overrides, role reassignment, `DAN mode` |
| **Exfiltration** | `curl $ANTHROPIC_API_KEY`, env var theft via network, `.ssh` + network combos |
| **Malicious Execution** | Reverse shells, piped download execution (`curl \| bash`), `eval()` |
| **Rule Tampering** | Overwriting `.cursorrules`, `.claude/rules`, git hooks, global git config |
| **Obfuscation** | Base64-encoded payloads (decoded and re-scanned), zero-width characters, unicode homoglyphs |
| **Excessive Permissions** | Filesystem/network access beyond tool's stated purpose |
| **Dependency Hijack** | `postinstall` scripts fetching and `eval()`ing remote code |
| **Prompt Relay** | MCP tool responses that inject instructions into the host AI |

## CLI Reference

```bash
# Commands
mcp-sandbox-sca scan-repo <path> [options]
mcp-sandbox-sca scan-tool <path> [options]
mcp-sandbox-sca scan-full <path> [options]

# Options
--static        Static analysis only (no ANTHROPIC_API_KEY needed)
--json          Output raw JSON report
--verbose       Show matched text for each finding
--type <type>   Tool type: mcp_server | claude_plugin | cursor_plugin |
                            vscode_extension | agent_framework | auto

# Exit codes
0 = safe
1 = suspicious or malicious
2 = scan error
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required for LLM honeypot scan |
| `PROBE_MODEL` | Override probe model (default: `claude-haiku-4-5-20251001`) |

## The Problem It Solves

When you clone an untrusted repository or install an AI tool, its config files (`.cursorrules`, `CLAUDE.md`, `README.md`) may contain instructions targeting your AI coding assistant. A compromised MCP server can return tool responses that inject instructions into your conversation. These attacks are invisible to humans but effective against AI assistants.

## License

MIT
