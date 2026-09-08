# Burp MCP: LLM-gestützte Traffic-Analyse

{{#include ../banners/hacktricks-training.md}}

## Übersicht

Die **MCP Server**-Erweiterung von Burp kann abgefangenen HTTP(S)-Traffic für MCP-fähige LLM-Clients bereitstellen, sodass diese **über reale Requests/Responses nachdenken** können, um Schwachstellen zu entdecken und Berichte zu erstellen. Burp bleibt dabei die maßgebliche Quelle: Verwende passive Analyse oder gezielte Replays mit einer Variablen, statt blind zu scannen.<sup>[[8]](#references)</sup>

## Architektur

- **Burp MCP Server (BApp)** lauscht standardmäßig auf `127.0.0.1:9876` und stellt abgefangenen Traffic über MCP bereit.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** verbindet stdio (Client-seitig) mit Burps MCP SSE endpoint.
- **Optionaler lokaler Reverse Proxy** (Caddy) normalisiert Header für strikte MCP-Handshake-Prüfungen.
- **Clients/Backends**: Codex CLI (Cloud), Gemini CLI (Cloud) oder Ollama (lokal).

## Einrichtung

### 1) Burp MCP Server installieren

Installiere **MCP Server** aus dem Burp BApp Store und überprüfe, dass er auf `127.0.0.1:9876` lauscht.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Das Proxy-JAR extrahieren

Klicke im Tab „MCP Server“ auf **Extract server proxy jar** und speichere `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Einen MCP-Client konfigurieren (Beispiel: Codex)

Verweise den Client auf das Proxy-JAR und Burps direkten SSE endpoint. Das mitgelieferte Proxy dient als stdio-zu-SSE-Bridge; es ersetzt den Burp-Listener nicht.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Der entsprechende Codex-Befehl lautet:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Dann Codex ausführen und MCP-Tools auflisten:
```bash
codex
# inside Codex: /mcp
```
### 4) Strikte Origin-/Header-Validierung mit Caddy beheben (falls erforderlich)

Wenn der MCP-Handshake aufgrund strikter `Origin`-Prüfungen oder zusätzlicher Header fehlschlägt, verwenden Sie einen lokalen Reverse Proxy, um Header zu normalisieren (dies entspricht dem Workaround für das strikte Burp-MCP-Validierungsproblem).<sup>[[1]](#references)[[3]](#references)</sup>
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
Starten Sie den Proxy und den Client und ändern Sie die konfigurierte `--sse-url` nur bei Verwendung dieses Caddy-Listeners zu `http://127.0.0.1:19876`:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Browser state mit Proxy evidence koppeln (Playwright MCP)

Registriere Playwright MCP so, dass der Browser den Proxy von Burp verwendet. Dadurch kann der Agent den gerenderten DOM-/Accessibility-Zustand mit der genauen HTTP-Historie korrelieren, die ihn erzeugt hat.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Passe die Listener-Adresse an, starte Codex neu und verwende `/mcp`, um beide Integrationen zu überprüfen. Das Beispiel deaktiviert Browser-Zertifikatsfehler, damit die HTTPS-Interception nicht durch das lokal von Burp generierte Zertifikat blockiert wird.<sup>[[6]](#references)[[8]](#references)</sup>

## Verschiedene Clients verwenden

### Codex CLI

- Konfiguriere `~/.codex/config.toml` wie oben beschrieben.
- Führe `codex` aus und anschließend `/mcp`, um die Liste der Burp-Tools zu überprüfen.

### Gemini CLI

Das Repository **burp-mcp-agents** stellt Starthelfer bereit:<sup>[[4]](#references)</sup>
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
Beispiele für lokale Modelle und ungefährer VRAM-Bedarf:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Evidenzbasierter Replay und Validierung

Lass den Agenten eine plausible Erklärung oder eine Zwischenantwort nicht als Beweis behandeln. Verwende Burp-Requests/Responses und unabhängig beobachteten Browser-Zustand, um jeden Test falsifizierbar zu machen.<sup>[[8]](#references)</sup>

1. Speichere ein grundlegendes Request/Response-Paar und identifiziere die exakt vom Angreifer kontrollierte Komponente.
2. Erfasse für Autorisierungsvergleiche denselben Workflow unabhängig unter beiden Accounts, bevor du Identifier, Cookies oder Tokens veränderst.
3. Halte vor dem Replay einer Mutation die Hypothese, den Ort der Evidenz, das erwartete Signal und das Ergebnis fest, das sie widerlegen würde.
4. Verändere jeweils nur eine Komponente, bewahre das daraus resultierende Paar auf und kennzeichne direkte Beobachtungen getrennt von Schlussfolgerungen.
5. Verfolge jeden Kandidaten als `open`, `blocked`, `rejected` oder `confirmed`; überprüfe ihn nur erneut, wenn neue Evidenz den Mechanismus oder eine Voraussetzung verändert.
6. Bestätige die Kontrolle durch den Angreifer, die Erreichbarkeit, die Wiederholbarkeit, das Umgehen von Einschränkungen, die Auswirkungen und den endgültigen Anwendungszustand. Eine Weiterleitung oder ein erfolgreicher Tool-Aufruf ist kein Beweis, wenn die behauptete Zustandsänderung nachgelagert erfolgt.

Bewahre die Exploitation-Details auf der relevanten Technikseite auf. Beispielsweise gehören browser-message-Kandidaten zu [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), während das Verhalten bei der Auswahl von Token-Keys zu [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) gehört.<sup>[[8]](#references)</sup>

Ein kompakter Hypothesenvermerk verhindert, dass parallele Agents denselben attraktiven Pfad wiederholen:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Prompt-Paket für passive Überprüfung

Das **burp-mcp-agents**-Repo enthält Prompt-Vorlagen für evidenzbasierte Analysen von Burp-Traffic:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: umfassendes passives Aufspüren von Vulnerabilities.
- `idor_hunter.md`: IDOR/BOLA/Object-/Tenant-Abweichungen und Auth-Mismatches.
- `auth_flow_mapper.md`: Vergleich authentifizierter und nicht authentifizierter Pfade.
- `ssrf_redirect_hunter.md`: Kandidaten für SSRF/Open-Redirects aus URL-Fetch-Parametern und Redirect-Ketten.
- `logic_flaw_hunter.md`: mehrstufige Logic Flaws.
- `session_scope_hunter.md`: Missbrauch von Token-Audience/Scopes.
- `rate_limit_abuse_hunter.md`: Lücken bei Throttling und Abuse-Schutz.
- `report_writer.md`: evidenzorientiertes Reporting.

## Optionale Attribution-Kennzeichnung

Um Burp-/LLM-Traffic in Logs zu kennzeichnen, füge ein Header-Rewrite hinzu (Proxy oder Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Sicherheitshinweise

- Bevorzuge **lokale Modelle**, wenn der Traffic sensible Daten enthält.
- Teile nur die minimal erforderlichen Beweise für einen Fund.
- Behalte Burp als Quelle der Wahrheit bei; verwende das Modell für **Analyse und Reporting**, nicht zum Scannen.

## Burp AI Agent (KI-gestützte Triage + MCP tools)

**Burp AI Agent** ist eine Burp-Erweiterung, die lokale/Cloud-LLMs mit passiver/aktiver Analyse (62 Schwachstellenklassen) kombiniert und mehr als 53 MCP tools bereitstellt, sodass externe MCP clients Burp orchestrieren können.<sup>[[5]](#references)</sup> Highlights:

- **Context-menu triage**: Erfasse Traffic über Proxy, öffne **Proxy > HTTP History**, klicke mit der rechten Maustaste auf eine Anfrage → **Extensions > Burp AI Agent > Analyze this request**, um einen an diese Anfrage/Antwort gebundenen AI chat zu starten.
- **Backends** (pro Profil auswählbar):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** Endpoint (Base-URL + Modellname).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` oder `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (anbieterabhängiger Login).
- **Agent profiles**: Prompt-Vorlagen werden automatisch unter `~/.burp-ai-agent/AGENTS/` installiert; lege dort zusätzliche `*.md`-Dateien ab, um benutzerdefinierte Analyse-/Scanning-Verhaltensweisen hinzuzufügen.
- **MCP server**: Aktiviere ihn über **Settings > MCP Server**, um Burp-Operationen für jeden MCP client bereitzustellen (mehr als 53 tools). Claude Desktop kann auf den Server verwiesen werden, indem du `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) oder `%APPDATA%\Claude\claude_desktop_config.json` (Windows) bearbeitest.
- **Privacy controls**: STRICT / BALANCED / OFF schwärzen sensible Anfrage-Daten, bevor sie an Remote-Modelle gesendet werden; bevorzuge lokale Backends beim Umgang mit Secrets.
- **Audit logging**: JSONL-Logs mit einem SHA-256-Integritäts-Hash pro Eintrag für eine manipulationsnachweisbare Rückverfolgbarkeit von AI/MCP-Aktionen.
- **Build/load**: Lade das Release-JAR herunter oder führe den Build mit Java 21 durch:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Betriebliche Vorsicht: Cloud-Backends können Session-Cookies/PII exfiltrieren, sofern der privacy mode nicht erzwungen wird; die MCP-Exposition ermöglicht die Remote-Orchestrierung von Burp. Beschränke daher den Zugriff auf vertrauenswürdige Agents und überwache die Integrität des mit Hashes versehenen Audit-Logs.

## References

- [1] [Integration von Burp MCP und Codex CLI sowie Behebung des Caddy-Handshakes](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem mit der strikten Origin-/Header-Validierung des PortSwigger MCP-Servers](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (Workflows, Launcher, Prompt-Paket)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Codex für Bug-Bounty-Recherchen verwenden: umfassend erkunden, rigoros validieren](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
