# Burp MCP: LLM-gestützte Überprüfung des Datenverkehrs

{{#include ../banners/hacktricks-training.md}}

## Überblick

Die **MCP Server**-Erweiterung von Burp kann abgefangenen HTTP(S)-Datenverkehr für MCP-fähige LLM-Clients bereitstellen, sodass diese **über echte Requests/Responses nachdenken** können, um passive Schwachstellenerkennung und die Erstellung von Berichtsentwürfen zu unterstützen. Ziel ist eine evidenzbasierte Überprüfung (kein Fuzzing oder blindes Scanning), wobei Burp als Quelle der Wahrheit erhalten bleibt.

## Architektur

- **Burp MCP Server (BApp)** lauscht auf `127.0.0.1:9876` und stellt abgefangenen Datenverkehr über MCP bereit.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** verbindet stdio (clientseitig) mit Burps MCP SSE endpoint.
- **Optionaler lokaler Reverse Proxy** (Caddy) normalisiert Header für strenge MCP-Handshake-Prüfungen.
- **Clients/Backends**: Codex CLI (cloud), Gemini CLI (cloud) oder Ollama (lokal).

## Einrichtung

### 1) Burp MCP Server installieren

Installiere **MCP Server** aus dem Burp BApp Store und überprüfe, dass er auf `127.0.0.1:9876` lauscht.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Das proxy JAR extrahieren

Klicke im Tab MCP Server auf **Extract server proxy jar** und speichere `mcp-proxy.jar`.

### 3) Einen MCP-Client konfigurieren (Codex-Beispiel)

Verweise den Client auf das proxy JAR und Burps SSE endpoint:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Dann führe Codex aus und liste die MCP-Tools auf:
```bash
codex
# inside Codex: /mcp
```
### 4) Strikte Origin-/Header-Validierung mit Caddy beheben (falls erforderlich)

Wenn der MCP-Handshake aufgrund strikter `Origin`-Prüfungen oder zusätzlicher Header fehlschlägt, verwenden Sie einen lokalen Reverse-Proxy, um Header zu normalisieren (dies entspricht dem Workaround für das Problem mit der strikten Burp-MCP-Validierung).<sup>[[1]](#references)[[3]](#references)</sup>
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
Starten Sie den Proxy und den Client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Verwendung verschiedener Clients

### Codex CLI

- Konfiguriere `~/.codex/config.toml` wie oben beschrieben.
- Führe `codex` aus und anschließend `/mcp`, um die Liste der Burp-Tools zu überprüfen.

### Gemini CLI

Das Repository **burp-mcp-agents** stellt Launcher-Hilfsprogramme bereit:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (lokal)

Verwende den bereitgestellten Launcher-Helfer und wähle ein lokales Modell:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Beispiele für lokale Modelle und ungefähr benötigten VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt pack für passive Prüfung

Das **burp-mcp-agents**-Repo enthält Prompt-Vorlagen für die evidenzbasierte Analyse von Burp-Traffic:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: umfassendes Aufspüren passiver Schwachstellen.
- `idor_hunter.md`: IDOR/BOLA/Object-/Tenant-Abweichungen und Auth-Abweichungen.
- `auth_flow_mapper.md`: Vergleich authentifizierter und nicht authentifizierter Pfade.
- `ssrf_redirect_hunter.md`: Kandidaten für SSRF/Open Redirects anhand von URL-Fetch-Parametern und Redirect-Ketten.
- `logic_flaw_hunter.md`: mehrstufige Logikfehler.
- `session_scope_hunter.md`: Missbrauch von Token-Audience/Scope.
- `rate_limit_abuse_hunter.md`: Lücken bei Throttling und Abuse-Schutz.
- `report_writer.md`: evidenzorientierte Berichterstattung.

## Optionale Attribution-Kennzeichnung

Um Burp-/LLM-Traffic in Logs zu kennzeichnen, füge ein Header-Rewrite hinzu (Proxy oder Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Sicherheitshinweise

- Bevorzuge **lokale Modelle**, wenn der Datenverkehr sensitive Daten enthält.
- Teile nur die minimal erforderlichen Beweise für einen Befund.
- Betrachte Burp als **source of truth**; verwende das Modell für **Analyse und Reporting**, nicht zum Scanning.

## Burp AI Agent (KI-gestützte Triage + MCP tools)

**Burp AI Agent** ist eine Burp-Erweiterung, die lokale/Cloud-LLMs mit passiver/aktiver Analyse (62 vulnerability classes) koppelt und mehr als 53 MCP tools bereitstellt, sodass externe MCP clients Burp orchestrieren können.<sup>[[5]](#references)</sup> Highlights:

- **Triage über das Kontextmenü**: Erfasse Datenverkehr über Proxy, öffne **Proxy > HTTP History**, klicke mit der rechten Maustaste auf einen Request → **Extensions > Burp AI Agent > Analyze this request**, um einen an diesen Request/Response gebundenen AI chat zu starten.
- **Backends** (pro Profil auswählbar):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` oder `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: Prompt-Vorlagen werden automatisch unter `~/.burp-ai-agent/AGENTS/` installiert; lege dort zusätzliche `*.md`-Dateien ab, um benutzerdefinierte Analyse-/Scanning-Verhaltensweisen hinzuzufügen.
- **MCP server**: Aktiviere ihn über **Settings > MCP Server**, um Burp-Operationen für beliebige MCP clients bereitzustellen (mehr als 53 tools). Claude Desktop kann auf den Server verwiesen werden, indem du `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) oder `%APPDATA%\Claude\claude_desktop_config.json` (Windows) bearbeitest.
- **Privacy controls**: STRICT / BALANCED / OFF schwärzen sensitive Request-Daten, bevor sie an Remote-Modelle gesendet werden; bevorzuge lokale Backends beim Umgang mit Secrets.
- **Audit logging**: JSONL-Logs mit SHA-256-Integritätshashing pro Eintrag für eine manipulationssichere Nachvollziehbarkeit von AI-/MCP-Aktionen.
- **Build/load**: Lade das Release-JAR herunter oder erstelle es mit Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Betriebliche Vorsichtshinweise: Cloud-Backends können Session-Cookies/PII exfiltrieren, sofern der Privacy Mode nicht erzwungen wird; die MCP-Exposition ermöglicht die Remote-Orchestrierung von Burp. Beschränken Sie den Zugriff daher auf vertrauenswürdige Agents und überwachen Sie das Integritäts-Hashing des Audit-Logs.

## Referenzen

- [1] [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
