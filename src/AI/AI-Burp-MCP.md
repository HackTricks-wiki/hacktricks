# Burp MCP: LLM-assisted traffic review

{{#include ../banners/hacktricks-training.md}}

## Overview

Burp's **MCP Server** extension can expose intercepted HTTP(S) traffic to MCP-capable LLM clients so they can **reason over real requests/responses** for passive vulnerability discovery and report drafting. The intent is evidence-driven review (no fuzzing or blind scanning), keeping Burp as the source of truth.

## Architecture

- **Burp MCP Server (BApp)** listens on `127.0.0.1:9876` and exposes intercepted traffic via MCP.
- **MCP proxy JAR** bridges stdio (client side) to Burp's MCP SSE endpoint.
- **Optional local reverse proxy** (Caddy) normalizes headers for strict MCP handshake checks.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Setup

### 1) Install Burp MCP Server

Install **MCP Server** from the Burp BApp Store and verify it is listening on `127.0.0.1:9876`.

### 2) Extract the proxy JAR

In the MCP Server tab, click **Extract server proxy jar** and save `mcp-proxy.jar`.

### 3) Configure an MCP client (Codex example)

Point the client to the proxy JAR and Burp's SSE endpoint:

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```

Then run Codex and list MCP tools:

```bash
codex
# inside Codex: /mcp
```

### 4) Fix strict Origin/header validation with Caddy (if needed)

If the MCP handshake fails due to strict `Origin` checks or extra headers, use a local reverse proxy to normalize headers (this matches the workaround for the Burp MCP strict validation issue).

```bash
brew install caddy
mkdir -p ~/burp-mcp
cat >~/burp-mcp/Caddyfile <<'EOF'
:19876

reverse_proxy 127.0.0.1:9876 {
  # lock Host/Origin to the Burp listener
  header_up Host "127.0.0.1:9876"
  header_up Origin "http://127.0.0.1:9876"

  # strip client headers that trigger Burp's 403 during SSE init
  header_up -User-Agent
  header_up -Accept
  header_up -Accept-Encoding
  header_up -Connection
}
EOF
```

Start the proxy and the client:

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

## Using different clients

### Codex CLI

- Configure `~/.codex/config.toml` as above.
- Run `codex`, then `/mcp` to verify the Burp tools list.

### Gemini CLI

The **burp-mcp-agents** repo provides launcher helpers:

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (local)

Use the provided launcher helper and select a local model:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Example local models and approximate VRAM needs:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack for passive review

The **burp-mcp-agents** repo includes prompt templates for evidence-driven analysis of Burp traffic:

- `passive_hunter.md`: broad passive vulnerability surfacing.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift and auth mismatches.
- `auth_flow_mapper.md`: compare authenticated vs unauthenticated paths.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect candidates from URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: multi-step logic flaws.
- `session_scope_hunter.md`: token audience/scope misuse.
- `rate_limit_abuse_hunter.md`: throttling/abuse gaps.
- `report_writer.md`: evidence-focused reporting.

## Optional attribution tagging

To tag Burp/LLM traffic in logs, add a header rewrite (proxy or Burp Match/Replace):

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Safety notes

- Prefer **local models** when traffic contains sensitive data.
- Only share the minimum evidence needed for a finding.
- Keep Burp as the source of truth; use the model for **analysis and reporting**, not scanning.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** is a Burp extension that couples local/cloud LLMs with passive/active analysis (62 vulnerability classes) and exposes 53+ MCP tools so external MCP clients can orchestrate Burp. Highlights:

- **Context-menu triage**: capture traffic via Proxy, open **Proxy > HTTP History**, right-click a request → **Extensions > Burp AI Agent > Analyze this request** to spawn an AI chat bound to that request/response.
- **Backends** (selectable per profile):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates auto-installed under `~/.burp-ai-agent/AGENTS/`; drop extra `*.md` files there to add custom analysis/scanning behaviors.
- **MCP server**: enable via **Settings > MCP Server** to expose Burp operations to any MCP client (53+ tools). Claude Desktop can be pointed at the server by editing `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF redact sensitive request data before sending it to remote models; prefer local backends when handling secrets.
- **Audit logging**: JSONL logs with per-entry SHA-256 integrity hashing for tamper-evident traceability of AI/MCP actions.
- **Build/load**: download the release JAR or build with Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operational cautions: cloud backends may exfiltrate session cookies/PII unless privacy mode is enforced; MCP exposure grants remote orchestration of Burp so restrict access to trusted agents and monitor the integrity-hashed audit log.

## References

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
