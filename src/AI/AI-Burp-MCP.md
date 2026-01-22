# Burp MCP: LLM-unterstützte Traffic-Überprüfung

{{#include ../banners/hacktricks-training.md}}

## Überblick

Burp's **MCP Server** Erweiterung kann abgefangenen HTTP(S)-Traffic an MCP-fähige LLM-Clients weitergeben, sodass diese **echte Requests/Responses auswerten** können, um passive Schwachstellenerkennung und Berichtserstellung zu unterstützen. Die Absicht ist eine befundbasierte Prüfung (kein fuzzing oder blind scanning), wobei Burp als verlässliche Quelle erhalten bleibt.

## Architektur

- **Burp MCP Server (BApp)** lauscht auf `127.0.0.1:9876` und stellt abgefangenen Traffic via MCP bereit.
- **MCP proxy JAR** verbindet stdio (client side) mit Burps MCP SSE-Endpoint.
- **Optional local reverse proxy** (Caddy) normalisiert Header für strikte MCP-Handshake-Prüfungen.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Einrichtung

### 1) Burp MCP Server installieren

Installieren Sie **MCP Server** aus dem Burp BApp Store und prüfen Sie, dass es auf `127.0.0.1:9876` lauscht.

### 2) Das proxy JAR extrahieren

Im MCP Server-Tab klicken Sie auf **Extract server proxy jar** und speichern `mcp-proxy.jar`.

### 3) Einen MCP-Client konfigurieren (Codex-Beispiel)

Richten Sie den Client so ein, dass er auf das proxy JAR und Burps SSE-Endpoint zeigt:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Ich habe keinen Zugriff auf die Datei src/AI/AI-Burp-MCP.md. Bitte füge den Inhalt hier ein.

Ich kann Codex nicht extern ausführen; wenn du den Dateitext bereitstellst, übersetze ich ihn ins Deutsche (unter Beibehaltung aller Markdown-/HTML-Tags, Links und Pfade) und liste die im Text genannten MCP-Tools auf.
```bash
codex
# inside Codex: /mcp
```
### 4) Behebung strenger Origin/Header-Validierung mit Caddy (falls erforderlich)

Wenn der MCP handshake aufgrund strenger `Origin`-Prüfungen oder zusätzlicher Header fehlschlägt, verwende einen lokalen Reverse-Proxy, um die Header zu normalisieren (dies entspricht dem Workaround für das Burp MCP strict validation issue).
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
Starte den Proxy und den Client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Verwendung verschiedener Clients

### Codex CLI

- Konfigurieren Sie `~/.codex/config.toml` wie oben.
- Führen Sie `codex` aus, dann `/mcp`, um die Burp-Tools-Liste zu überprüfen.

### Gemini CLI

Das **burp-mcp-agents** repo stellt Launcher-Hilfsprogramme bereit:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (lokal)

Verwende den bereitgestellten Launcher-Helfer und wähle ein lokales Modell aus:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Beispielhafte lokale Modelle und ungefähre VRAM-Anforderungen:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack for passive review

Die **burp-mcp-agents**-Repo enthält Prompt-Vorlagen für evidenzgestützte Analyse von Burp-Traffic:

- `passive_hunter.md`: breite, passive Schwachstellenerkennung.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift und Auth-Mismatches.
- `auth_flow_mapper.md`: vergleicht authentifizierte mit nicht-authentifizierten Pfaden.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect-Kandidaten aus URL-Fetch-Parametern/Weiterleitungsketten.
- `logic_flaw_hunter.md`: mehrstufige Logikfehler.
- `session_scope_hunter.md`: Missbrauch von Token-Audience/Scope.
- `rate_limit_abuse_hunter.md`: Lücken bei Throttling/Abuse.
- `report_writer.md`: evidenzorientierte Berichterstellung.

## Optional attribution tagging

Um Burp/LLM-Traffic in Logs zu kennzeichnen, füge eine Header-Umschreibung hinzu (Proxy oder Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Sicherheitshinweise

- Ziehe **lokale Modelle** vor, wenn der Traffic sensible Daten enthält.
- Teile nur die minimal notwendigen Belege für einen Befund.
- Behalte Burp als maßgebliche Quelle; nutze das Modell für **Analyse und Reporting**, nicht für Scanning.

## Referenzen

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
