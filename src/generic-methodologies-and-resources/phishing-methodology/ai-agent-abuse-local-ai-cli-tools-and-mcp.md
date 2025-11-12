# AI Agent Abuse: Local AI CLI Tools & MCP (Claude/Gemini/Warp)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Local AI command-line interfaces (AI CLIs) such as Claude Code, Gemini CLI, Warp and similar tools often ship with powerful built‑ins: filesystem read/write, shell execution and outbound network access. Many act as MCP clients (Model Context Protocol), letting the model call external tools over STDIO or HTTP. Because the LLM plans tool-chains non‑deterministically, identical prompts can lead to different process, file and network behaviours across runs and hosts.

Key mechanics seen in common AI CLIs:
- Typically implemented in Node/TypeScript with a thin wrapper launching the model and exposing tools.
- Multiple modes: interactive chat, plan/execute, and single‑prompt run.
- MCP client support with STDIO and HTTP transports, enabling both local and remote capability extension.

Abuse impact: A single prompt can inventory and exfiltrate credentials, modify local files, and silently extend capability by connecting to remote MCP servers (visibility gap if those servers are third‑party).

---

## Adversary Playbook – Prompt‑Driven Secrets Inventory

Task the agent to quickly triage and stage credentials/secrets for exfiltration while staying quiet:

- Scope: recursively enumerate under $HOME and application/wallet dirs; avoid noisy/pseudo paths (`/proc`, `/sys`, `/dev`).
- Performance/stealth: cap recursion depth; avoid `sudo`/priv‑escalation; summarise results.
- Targets: `~/.ssh`, `~/.aws`, cloud CLI creds, `.env`, `*.key`, `id_rsa`, `keystore.json`, browser storage (LocalStorage/IndexedDB profiles), crypto‑wallet data.
- Output: write a concise list to `/tmp/inventory.txt`; if the file exists, create a timestamped backup before overwrite.

Example operator prompt to an AI CLI:

```
You can read/write local files and run shell commands.
Recursively scan my $HOME and common app/wallet dirs to find potential secrets.
Skip /proc, /sys, /dev; do not use sudo; limit recursion depth to 3.
Match files/dirs like: id_rsa, *.key, keystore.json, .env, ~/.ssh, ~/.aws,
Chrome/Firefox/Brave profile storage (LocalStorage/IndexedDB) and any cloud creds.
Summarize full paths you find into /tmp/inventory.txt.
If /tmp/inventory.txt already exists, back it up to /tmp/inventory.txt.bak-<epoch> first.
Return a short summary only; no file contents.
```

---

## Capability Extension via MCP (STDIO and HTTP)

AI CLIs frequently act as MCP clients to reach additional tools:

- STDIO transport (local tools): the client spawns a helper chain to run a tool server. Typical lineage: `node → <ai-cli> → uv → python → file_write`. Example observed: `uv run --with fastmcp fastmcp run ./server.py` which starts `python3.13` and performs local file operations on the agent’s behalf.
- HTTP transport (remote tools): the client opens outbound TCP (e.g., port 8000) to a remote MCP server, which executes the requested action (e.g., write `/home/user/demo_http`). On the endpoint you’ll only see the client’s network activity; server‑side file touches occur off‑host.

Notes:
- MCP tools are described to the model and may be auto‑selected by planning. Behaviour varies between runs.
- Remote MCP servers increase blast radius and reduce host‑side visibility.

---

## Local Artifacts and Logs (Forensics)

- Gemini CLI session logs: `~/.gemini/tmp/<uuid>/logs.json`
  - Fields commonly seen: `sessionId`, `type`, `message`, `timestamp`.
  - Example `message`: "@.bashrc what is in this file?" (user/agent intent captured).
- Claude Code history: `~/.claude/history.jsonl`
  - JSONL entries with fields like `display`, `timestamp`, `project`.

---

## Pentesting Remote MCP Servers

Remote MCP servers expose a JSON‑RPC 2.0 API that fronts LLM‑centric capabilities (Prompts, Resources, Tools). They inherit classic web API flaws while adding async transports (SSE/streamable HTTP) and per‑session semantics.

Key actors
- Host: the LLM/agent frontend (Claude Desktop, Cursor, etc.).
- Client: per‑server connector used by the Host (one client per server).
- Server: the MCP server (local or remote) exposing Prompts/Resources/Tools.

AuthN/AuthZ
- OAuth2 is common: an IdP authenticates, the MCP server acts as resource server.
- After OAuth, the server issues an authentication token used on subsequent MCP requests. This is distinct from `Mcp-Session-Id` which identifies a connection/session after `initialize`.

Transports
- Local: JSON‑RPC over STDIN/STDOUT.
- Remote: Server‑Sent Events (SSE, still widely deployed) and streamable HTTP.

A) Session initialization
- Obtain OAuth token if required (Authorization: Bearer ...).
- Begin a session and run the MCP handshake:

```json
{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"capabilities":{}}}
```

- Persist the returned `Mcp-Session-Id` and include it on subsequent requests per transport rules.

B) Enumerate capabilities
- Tools

```json
{"jsonrpc":"2.0","id":10,"method":"tools/list"}
```

- Resources

```json
{"jsonrpc":"2.0","id":1,"method":"resources/list"}
```

- Prompts

```json
{"jsonrpc":"2.0","id":20,"method":"prompts/list"}
```

C) Exploitability checks
- Resources → LFI/SSRF
  - The server should only allow `resources/read` for URIs it advertised in `resources/list`. Try out‑of‑set URIs to probe weak enforcement:

```json
{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}
```

```json
{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"http://169.254.169.254/latest/meta-data/"}}
```

  - Success indicates LFI/SSRF and possible internal pivoting.
- Resources → IDOR (multi‑tenant)
  - If the server is multi‑tenant, attempt to read another user’s resource URI directly; missing per‑user checks leak cross‑tenant data.
- Tools → Code execution and dangerous sinks
  - Enumerate tool schemas and fuzz parameters that influence command lines, subprocess calls, templating, deserializers, or file/network I/O:

```json
{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"TOOL_NAME","arguments":{"query":"; id"}}}
```

  - Look for error echoes/stack traces in results to refine payloads. Independent testing has reported widespread command‑injection and related flaws in MCP tools.
- Prompts → Injection preconditions
  - Prompts mainly expose metadata; prompt injection matters only if you can tamper with prompt parameters (e.g., via compromised resources or client bugs).

D) Tooling for interception and fuzzing
- MCP Inspector (Anthropic): Web UI/CLI supporting STDIO, SSE and streamable HTTP with OAuth. Ideal for quick recon and manual tool invocations.
- HTTP–MCP Bridge (NCC Group): Bridges MCP SSE to HTTP/1.1 so you can use Burp/Caido.
  - Start the bridge pointed at the target MCP server (SSE transport).
  - Manually perform the `initialize` handshake to acquire a valid `Mcp-Session-Id` (per README).
  - Proxy JSON‑RPC messages like `tools/list`, `resources/list`, `resources/read`, and `tools/call` via Repeater/Intruder for replay and fuzzing.

Quick test plan
- Authenticate (OAuth if present) → run `initialize` → enumerate (`tools/list`, `resources/list`, `prompts/list`) → validate resource URI allow‑list and per‑user authorization → fuzz tool inputs at likely code‑execution and I/O sinks.

Impact highlights
- Missing resource URI enforcement → LFI/SSRF, internal discovery and data theft.
- Missing per‑user checks → IDOR and cross‑tenant exposure.
- Unsafe tool implementations → command injection → server‑side RCE and data exfiltration.

---

## References

- [Commanding attention: How adversaries are abusing AI CLI tools (Red Canary)](https://redcanary.com/blog/threat-detection/ai-cli-tools/)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
- [Assessing the Attack Surface of Remote MCP Servers](https://blog.kulkan.com/assessing-the-attack-surface-of-remote-mcp-servers-92d630a0cab0)
- [MCP Inspector (Anthropic)](https://github.com/modelcontextprotocol/inspector)
- [HTTP–MCP Bridge (NCC Group)](https://github.com/nccgroup/http-mcp-bridge)
- [MCP spec – Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP spec – Transports and SSE deprecation](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#backwards-compatibility)
- [Equixly: MCP server security issues in the wild](https://equixly.com/blog/2025/03/29/mcp-server-new-security-nightmare/)

{{#include ../../banners/hacktricks-training.md}}