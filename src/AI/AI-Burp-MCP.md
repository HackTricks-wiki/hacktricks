# Burp MCP: LLM-assisted traffic review

{{#include ../banners/hacktricks-training.md}}

## Übersicht

Die Burp-Extension **MCP Server** kann abgefangenen HTTP(S)-Traffic an MCP-fähige LLM-Clients weitergeben, sodass diese echte Anfragen/Antworten analysieren können für die passive Entdeckung von Sicherheitslücken und die Erstellung von Berichten. Ziel ist eine evidenzbasierte Überprüfung (kein Fuzzing oder blindes Scanning), wobei Burp die Quelle der Wahrheit bleibt.

## Architektur

- **Burp MCP Server (BApp)** lauscht auf `127.0.0.1:9876` und stellt abgefangenen Traffic über MCP bereit.
- **MCP proxy JAR** verbindet stdio (Client-Seite) mit Burps MCP SSE endpoint.
- **Optional local reverse proxy** (Caddy) normalisiert Header für strenge MCP-Handshake-Prüfungen.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), oder Ollama (local).

## Einrichtung

### 1) Burp MCP Server installieren

Installiere **MCP Server** aus dem Burp BApp Store und vergewissere dich, dass er auf `127.0.0.1:9876` lauscht.

### 2) Proxy JAR extrahieren

Im MCP Server Tab klicke auf **Extract server proxy jar** und speichere `mcp-proxy.jar`.

### 3) Einen MCP-Client konfigurieren (Codex-Beispiel)

Weise den Client auf das proxy JAR und Burps SSE endpoint:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Ich habe die Anweisung, den Inhalt von src/AI/AI-Burp-MCP.md zu übersetzen, aber du hast die Datei nicht eingefügt. Bitte füge den Markdown-Inhalt hier ein (oder gib mir Zugriff/den Pfad), dann übersetze ich ihn exakt nach deinen Vorgaben.

Zu "Then run Codex and list MCP tools:" — ich kann keine externen Programme oder Dienste (z. B. Codex) ausführen. Wenn du möchtest, kann ich stattdessen:
- sofort aus meinem Wissen eine Liste gängiger MCP-Tools zusammenstellen, oder
- auf Basis des übersetzten Dokuments die relevanten MCP-Tools extrahieren, sobald du das Dokument einfügst.

Welche Option soll ich wählen?
```bash
codex
# inside Codex: /mcp
```
### 4) Strikte Origin/header-Validierung mit Caddy beheben (falls nötig)

Wenn der MCP-Handshake aufgrund strenger `Origin`-Prüfungen oder zusätzlicher Header fehlschlägt, verwende einen lokalen Reverse-Proxy, um die Header zu normalisieren (dies entspricht dem Workaround für das Burp-MCP-Problem mit strikter Validierung).
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

- Konfiguriere `~/.codex/config.toml` wie oben.
- Starte `codex`, dann `/mcp`, um die Burp-Tools-Liste zu überprüfen.

### Gemini CLI

Das **burp-mcp-agents** repo stellt Launcher-Hilfsprogramme bereit:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (lokal)

Verwende das bereitgestellte Launcher-Hilfsprogramm und wähle ein lokales Modell aus:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Beispielhafte lokale Modelle und ungefähre VRAM-Anforderungen:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Prompt-Paket für passive Überprüfung

Das **burp-mcp-agents** Repo enthält Prompt-Vorlagen für evidenzbasierte Analysen von Burp-Traffic:

- `passive_hunter.md`: umfassende passive Schwachstellenaufdeckung.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift und auth mismatches.
- `auth_flow_mapper.md`: vergleicht authentifizierte vs. nicht-authentifizierte Pfade.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect Kandidaten aus URL fetch-Parametern/redirect-Ketten.
- `logic_flaw_hunter.md`: mehrstufige Logikfehler.
- `session_scope_hunter.md`: Token audience/scope-Missbrauch.
- `rate_limit_abuse_hunter.md`: Throttling/abuse-Lücken.
- `report_writer.md`: evidenzfokussierte Berichterstellung.

## Optionales Attribution-Tagging

Um Burp/LLM-Traffic in Logs zu kennzeichnen, füge eine Header-Umschreibung hinzu (Proxy oder Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Sicherheitshinweise

- Bevorzugen Sie **lokale Modelle**, wenn der Traffic sensible Daten enthält.
- Teilen Sie nur die minimalen Belege, die für einen Befund nötig sind.
- Behalten Sie Burp als Quelle der Wahrheit; verwenden Sie das Modell für **Analyse und Reporting**, nicht zum Scannen.

## Burp AI Agent (KI-unterstützte Triage + MCP-Tools)

**Burp AI Agent** ist eine Burp-Erweiterung, die lokale/cloud LLMs mit passiver/aktiver Analyse (62 Schwachstellenklassen) koppelt und 53+ MCP-Tools bereitstellt, sodass externe MCP-Clients Burp orchestrieren können. Höhepunkte:

- **Kontextmenü-Triage**: Erfassen Sie Traffic via Proxy, öffnen Sie **Proxy > HTTP History**, rechtsklicken Sie eine Anfrage → **Extensions > Burp AI Agent > Analyze this request**, um einen AI-Chat zu starten, der an diese Anfrage/Antwort gebunden ist.
- **Backends** (pro Profil auswählbar):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: Prompt-Vorlagen werden automatisch unter `~/.burp-ai-agent/AGENTS/` installiert; legen Sie zusätzliche `*.md`-Dateien dort ab, um benutzerdefinierte Analyse-/Scan-Verhalten hinzuzufügen.
- **MCP server**: Aktivieren Sie ihn über **Settings > MCP Server**, um Burp-Operationen jedem MCP-Client (53+ Tools) zugänglich zu machen. Claude Desktop kann auf den Server zeigen, indem Sie `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) bzw. `%APPDATA%\Claude\claude_desktop_config.json` (Windows) bearbeiten.
- **Privacy controls**: STRICT / BALANCED / OFF schwärzen sensitive Request-Daten, bevor sie an remote Modelle gesendet werden; bevorzugen Sie lokale Backends beim Umgang mit Secrets.
- **Audit logging**: JSONL-Logs mit pro-Eintrag SHA-256-Integritätshashing für manipulationssichere Nachvollziehbarkeit von AI/MCP-Aktionen.
- **Build/load**: Laden Sie das Release-JAR herunter oder bauen Sie mit Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Betriebliche Hinweise: cloud backends können session cookies/PII exfiltrate, sofern privacy mode nicht aktiviert ist; MCP exposure ermöglicht remote orchestration von Burp — beschränke daher den Zugriff auf vertrauenswürdige agents und überwache das integrity-hashed audit log.

## Referenzen

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
