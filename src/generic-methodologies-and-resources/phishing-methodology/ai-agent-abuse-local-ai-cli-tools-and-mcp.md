# AI Agent Abuse: Local AI CLI Tools & MCP (Claude/Gemini/Warp)

{{#include ../../banners/hacktricks-training.md}}

## Overview

Local AI command-line interfaces (AI CLIs) such as Claude Code, Gemini CLI, Warp and similar tools often ship with powerful built‑ins: filesystem read/write, shell execution and outbound network access. Many act as MCP clients (Model Context Protocol), letting the model call external tools over STDIO or HTTP. Because the LLM plans tool-chains non‑deterministically, identical prompts can lead to different process, file and network behaviours across runs and hosts.

Key mechanics seen in common AI CLIs:
- Typically implemented in Node/TypeScript with a thin wrapper launching the model and exposing tools.
- Multiple modes: interactive chat, plan/execute, and single‑prompt run.
- MCP client support with STDIO and HTTP transports, enabling both local and remote capability extension.

Abuse impact: A single prompt can inventory and exfiltrate credentials, modify local files, and silently extend capability by connecting to remote MCP servers (visibility gap if those servers are third‑party).

See also – cross‑agent session smuggling in stateful A2A systems:

{{#ref}}
agent2agent-a2a-session-smuggling.md
{{#endref}}

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
  - Example `message`: `"@.bashrc what is in this file?"` (user/agent intent captured).
- Claude Code history: `~/.claude/history.jsonl`
  - JSONL entries with fields like `display`, `timestamp`, `project`.

Correlate these local logs with requests observed at your LLM gateway/proxy (e.g., LiteLLM) to detect tampering/model‑hijacking: if what the model processed deviates from the local prompt/output, investigate injected instructions or compromised tool descriptors.

---

## Endpoint Telemetry Patterns

Representative chains on Amazon Linux 2023 with Node v22.19.0 and Python 3.13:

1) Built‑in tools (local file access)
- Parent: `node .../bin/claude --model <model>` (or equivalent for the CLI)
- Immediate child action: create/modify a local file (e.g., `demo-claude`). Tie the file event back via parent→child lineage.

2) MCP over STDIO (local tool server)
- Chain: `node → uv → python → file_write`
- Example spawn: `uv run --with fastmcp fastmcp run /home/ssm-user/tools/server.py`

3) MCP over HTTP (remote tool server)
- Client: `node/<ai-cli>` opens outbound TCP to `remote_port: 8000` (or similar)
- Server: remote Python process handles the request and writes `/home/ssm-user/demo_http`.

Because agent decisions differ by run, expect variability in exact processes and touched paths.

---

## Detection Strategy

Telemetry sources
- Linux EDR using eBPF/auditd for process, file and network events.
- Local AI‑CLI logs for prompt/intent visibility.
- LLM gateway logs (e.g., LiteLLM) for cross‑validation and model‑tamper detection.

Hunting heuristics
- Link sensitive file touches back to an AI‑CLI parent chain (e.g., `node → <ai-cli> → uv/python`).
- Alert on access/reads/writes under: `~/.ssh`, `~/.aws`, browser profile storage, cloud CLI creds, `/etc/passwd`.
- Flag unexpected outbound connections from the AI‑CLI process to unapproved MCP endpoints (HTTP/SSE, ports like 8000).
- Correlate local `~/.gemini`/`~/.claude` artifacts with LLM gateway prompts/outputs; divergence indicates possible hijacking.

Example pseudo‑rules (adapt to your EDR):

```yaml
- when: file_write AND path IN ["$HOME/.ssh/*","$HOME/.aws/*","/etc/passwd"]
  and ancestor_chain CONTAINS ["node", "claude|gemini|warp", "python|uv"]
  then: alert("AI-CLI secrets touch via tool chain")

- when: outbound_tcp FROM process_name =~ "node|python" AND parent =~ "claude|gemini|warp"
  and dest_port IN [8000, 3333, 8787]
  then: tag("possible MCP over HTTP")
```

Hardening ideas
- Require explicit user approval for file/system tools; log and surface tool plans.
- Constrain network egress for AI‑CLI processes to approved MCP servers.
- Ship/ingest local AI‑CLI logs and LLM gateway logs for consistent, tamper‑resistant auditing.

---

## Blue‑Team Repro Notes

Use a clean VM with an EDR or eBPF tracer to reproduce chains like:
- `node → claude --model claude-sonnet-4-20250514` then immediate local file write.
- `node → uv run --with fastmcp ... → python3.13` writing under `$HOME`.
- `node/<ai-cli>` establishing TCP to an external MCP server (port 8000) while a remote Python process writes a file.

Validate that your detections tie the file/network events back to the initiating AI‑CLI parent to avoid false positives.

---

## References

- [Commanding attention: How adversaries are abusing AI CLI tools (Red Canary)](https://redcanary.com/blog/threat-detection/ai-cli-tools/)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
- [LiteLLM – LLM Gateway/Proxy](https://docs.litellm.ai)

{{#include ../../banners/hacktricks-training.md}}