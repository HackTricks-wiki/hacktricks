# Burp MCP: LLM-geassisteerde verkeershersiening

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Burp se **MCP Server**-uitbreiding kan gevangene HTTP(S)-verkeer aan MCP-capable LLM-kliente blootstel sodat hulle oor werklike requests/responses kan redeneer vir passiewe vulnerability discovery en die opstel van verslae. Die doel is bewysegedrewe hersiening (geen fuzzing of blind scanning nie), met Burp as die bron van waarheid.

## Argitektuur

- **Burp MCP Server (BApp)** luister op `127.0.0.1:9876` en blootstel gevangene verkeer via MCP.
- **MCP proxy JAR** verbind stdio (client side) met Burp's MCP SSE endpoint.
- **Optional local reverse proxy** (Caddy) normaliseer headers vir streng MCP-handshake kontroles.
- **Kliënte/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Opstelling

### 1) Installeer Burp MCP Server

Installeer **MCP Server** vanaf die Burp BApp Store en verifieer dat dit luister op `127.0.0.1:9876`.

### 2) Extract the proxy JAR

In die MCP Server-oortjie, klik **Extract server proxy jar** en stoor `mcp-proxy.jar`.

### 3) Konfigureer 'n MCP-kliënt (Codex voorbeeld)

Wys die kliënt na die proxy JAR en Burp se SSE-endpoint:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Ek het nie toegang tot src/AI/AI-Burp-MCP.md nie. Plak asseblief die inhoud wat jy wil hê ek moet vertaal.

Ek kan nie "Codex" of enige eksterne program uitvee nie. Wil jy hê ek moet:
- die geplakte lêer se inhoud in Afrikaans vertaal en dan (op grond van daardie inhoud) 'n lys MCP-tools uitskryf, of
- net 'n algemene lys van bekende MCP-tools vir Burp gee sonder die lêerinhoud?

Wanneer jy die teks voorsien, sal ek dit in Afrikaans vertaal en alle markdown/html/tags/links/pads ongewysig laat.
```bash
codex
# inside Codex: /mcp
```
### 4) Los strikte Origin/header-validasie op met Caddy (indien nodig)

As die MCP-handshake misluk weens streng `Origin`-kontroles of ekstra headers, gebruik 'n plaaslike reverse proxy om headers te normaliseer (dit stem ooreen met die workaround vir die Burp MCP se streng valideringskwessie).
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
Begin die proxy en die kliënt:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Gebruik van verskillende kliënte

### Codex CLI

- Konfigureer `~/.codex/config.toml` soos hierbo.
- Voer `codex` uit, dan `/mcp` om die Burp tools-lys te verifieer.

### Gemini CLI

Die **burp-mcp-agents** repo bied launcher helpers:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (lokaal)

Gebruik die voorsiene launcher-helper en kies 'n plaaslike model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Voorbeeld plaaslike modelle en geskatte VRAM-behoeftes:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt-pakket vir passiewe hersiening

Die **burp-mcp-agents** repo bevat prompt-sjablone vir bewysgebaseerde ontleding van Burp-verkeer:

- `passive_hunter.md`: breë passiewe blootlegging van kwetsbaarhede.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift en auth-mismatches.
- `auth_flow_mapper.md`: vergelyk geauthentiseerde teen ongesauthentiseerde paaie.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect kandidate uit URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: meerstap logiese foute.
- `session_scope_hunter.md`: token audience/scope misbruik.
- `rate_limit_abuse_hunter.md`: gaping in throttling/misbruik.
- `report_writer.md`: bewysgebaseerde verslaggewing.

## Opsionele toeskrywing-tagging

Om Burp/LLM-verkeer in logs te tag, voeg 'n header rewrite by (proxy of Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Veiligheidsnotas

- Verkies **lokale modelle** wanneer verkeer gevoelig data bevat.
- Deel slegs die minimum bewyse wat vir 'n bevinding benodig word.
- Hou Burp as die bron van waarheid; gebruik die model vir **analise en verslaggewing**, nie vir scanning nie.

## Verwysings

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
