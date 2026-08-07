# Burp MCP: LLM-gesteunde traffic review

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Burp se **MCP Server**-extension kan onderskepte HTTP(S)-traffic aan MCP-bekwame LLM-clients blootstel, sodat hulle oor **werklike requests/responses** kan redeneer vir passiewe vulnerability discovery en die opstel van reports. Die doel is evidence-driven review (geen fuzzing of blind scanning nie), met Burp as die source of truth.

## Argitektuur

- **Burp MCP Server (BApp)** luister op `127.0.0.1:9876` en stel onderskepte traffic via MCP bloot.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** verbind stdio (client-kant) met Burp se MCP SSE endpoint.
- **Opsionele plaaslike reverse proxy** (Caddy) normaliseer headers vir streng MCP-handshake checks.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), of Ollama (local).

## Opstelling

### 1) Installeer Burp MCP Server

Installeer **MCP Server** vanaf die Burp BApp Store en verifieer dat dit op `127.0.0.1:9876` luister.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Onttrek die proxy JAR

In die MCP Server-tab, klik **Extract server proxy jar** en stoor `mcp-proxy.jar`.

### 3) Konfigureer 'n MCP-client (Codex-voorbeeld)

Wys die client na die proxy JAR en Burp se SSE endpoint:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Voer daarna Codex uit en lys MCP tools:
```bash
codex
# inside Codex: /mcp
```
### 4) Herstel streng Origin/header validation met Caddy (indien nodig)

As die MCP handshake weens streng `Origin`-kontroles of ekstra headers misluk, gebruik ’n plaaslike reverse proxy om headers te normaliseer (dit stem ooreen met die workaround vir die Burp MCP strict validation issue).<sup>[[1]](#references)[[3]](#references)</sup>
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
Begin die proxy en die client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Gebruik van verskillende kliënte

### Codex CLI

- Konfigureer `~/.codex/config.toml` soos hierbo.
- Begin `codex`, en gebruik dan `/mcp` om die Burp-toolslys te verifieer.

### Gemini CLI

Die **burp-mcp-agents**-repo verskaf launcher-hulpmiddels:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (plaaslik)

Gebruik die verskafde launcher helper en kies ’n plaaslike model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Voorbeeld van plaaslike models en benaderde VRAM-benodigdhede:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt-pakket vir passiewe hersiening

Die **burp-mcp-agents**-repo bevat prompt-sjablone vir bewysgedrewe ontleding van Burp-verkeer:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: breë passiewe opsporing van kwesbaarhede.
- `idor_hunter.md`: IDOR/BOLA/object/tenant-drift en auth-wanpassings.
- `auth_flow_mapper.md`: vergelyk geauthentiseerde en ongeauthentiseerde paaie.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect-kandidate vanaf URL-fetch-parameters/redirect-kettings.
- `logic_flaw_hunter.md`: multi-stap-logikafoute.
- `session_scope_hunter.md`: misbruik van token-audience/scope.
- `rate_limit_abuse_hunter.md`: gapings in throttling/misbruikbeheer.
- `report_writer.md`: bewysgefokusde rapportering.

## Opsionele attribution-tagging

Om Burp/LLM-verkeer in logs te tag, voeg ’n header-rewrite by (proxy of Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Veiligheidsaantekeninge

- Verkies **local models** wanneer verkeer sensitiewe data bevat.
- Deel slegs die minimum bewyse wat vir ’n finding nodig is.
- Hou Burp as die bron van waarheid; gebruik die model vir **analysis and reporting**, nie vir scanning nie.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** is ’n Burp extension wat local/cloud LLMs met passive/active analysis (62 vulnerability classes) kombineer en 53+ MCP tools beskikbaar stel sodat eksterne MCP clients Burp kan orkestreer.<sup>[[5]](#references)</sup> Hoogtepunte:

- **Context-menu triage**: capture traffic via Proxy, open **Proxy > HTTP History**, right-click ’n request → **Extensions > Burp AI Agent > Analyze this request** om ’n AI chat te begin wat aan daardie request/response gekoppel is.
- **Backends** (selectable per profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` of `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates word outomaties onder `~/.burp-ai-agent/AGENTS/` geïnstalleer; plaas addisionele `*.md`-lêers daar om custom analysis/scanning behaviors by te voeg.
- **MCP server**: enable via **Settings > MCP Server** om Burp operations aan enige MCP client bloot te stel (53+ tools). Claude Desktop kan na die server gewys word deur `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) of `%APPDATA%\Claude\claude_desktop_config.json` (Windows) te wysig.
- **Privacy controls**: STRICT / BALANCED / OFF redact sensitive request data voordat dit na remote models gestuur word; verkies local backends wanneer secrets hanteer word.
- **Audit logging**: JSONL logs met per-entry SHA-256 integrity hashing vir tamper-evident traceability van AI/MCP actions.
- **Build/load**: laai die release JAR af of build met Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Bedryfswaarskuwings: cloud backends kan session cookies/PII exfiltreer tensy privacy mode afgedwing word; MCP-blootstelling verleen remote orchestration van Burp, dus beperk toegang tot trusted agents en monitor die integrity-hashed audit log.

## Verwysings

- [1] [Burp MCP + Codex CLI-integrasie en Caddy-handshake-regstelling](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP-server se streng Origin/header-valideringskwessie](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
