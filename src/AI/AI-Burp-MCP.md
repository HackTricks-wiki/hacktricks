# Burp MCP: LLM-gestützte Datenverkehrsprüfung

{{#include ../banners/hacktricks-training.md}}

## Überblick

Die **MCP Server**-Erweiterung von Burp kann abgefangenen HTTP(S)-Datenverkehr für MCP-fähige LLM-Clients verfügbar machen, sodass diese **über reale Requests/Responses nachdenken** können, um Schwachstellen zu finden und Berichte zu entwerfen. Behalte Burp als maßgebliche Quelle bei: Verwende passive Analysen oder gezielte Wiederholungen mit nur einer Variablen statt blindem Scanning.<sup>[[8]](#references)</sup>

## Architektur

- **Burp MCP Server (BApp)** lauscht standardmäßig auf `127.0.0.1:9876` und stellt abgefangenen Datenverkehr über MCP bereit.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** verbindet stdio (Clientseite) mit Burps MCP SSE-Endpunkt.
- **Optionaler lokaler Reverse Proxy** (Caddy) normalisiert Header für strenge MCP-Handshake-Prüfungen.
- **Clients/Backends**: Codex CLI (cloud), Gemini CLI (cloud) oder Ollama (local).

## Einrichtung

### 1) Burp MCP Server installieren

Installiere **MCP Server** aus dem Burp BApp Store und verifiziere, dass er auf `127.0.0.1:9876` lauscht.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Das proxy JAR extrahieren

Klicke im Tab „MCP Server“ auf **Extract server proxy jar** und speichere `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Einen MCP-Client konfigurieren (Codex-Beispiel)

Verweise den Client auf das proxy JAR und Burps direkten SSE-Endpunkt. Der mitgelieferte Proxy ist eine stdio-zu-SSE-Bridge; er ersetzt den Burp-Listener nicht.<sup>[[7]](#references)</sup>
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
Führe dann Codex aus und liste die MCP-Tools auf:
```bash
codex
# inside Codex: /mcp
```
### 4) Strikte Origin/Header-Validierung mit Caddy beheben (falls erforderlich)

Wenn der MCP-Handshake aufgrund strikter `Origin`-Prüfungen oder zusätzlicher Header fehlschlägt, verwende einen lokalen Reverse Proxy, um Header zu normalisieren (dies entspricht dem Workaround für das Problem mit der strikten Validierung von Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Starten Sie den Proxy und den Client und ändern Sie die konfigurierte `--sse-url` nur bei Verwendung dieses Caddy-Listeners in `http://127.0.0.1:19876`:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Browserzustand mit Proxy-Evidenz verknüpfen (Playwright MCP)

Konfiguriere Playwright MCP so, dass der Browser den Proxy von Burp verwendet. Dadurch kann der Agent den gerenderten DOM-/Accessibility-Zustand mit dem exakten HTTP-Verlauf korrelieren, durch den er erzeugt wurde.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Passe die Listener-Adresse an, starte Codex neu und verwende `/mcp`, um beide Integrationen zu überprüfen. Das Beispiel deaktiviert Browser-Zertifikatsfehler, damit die HTTPS-Interception nicht durch das lokal von Burp generierte Zertifikat blockiert wird.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-aware browser automation (OpenBurp)

Die Burp-MCP-Verbindung und der Pfad des intercepted Browsers sind separate Datenflüsse. Der MCP-Service stellt Burp-Tools unter `127.0.0.1:9876` bereit, während eine dedizierte Chromium-Instanz ihren HTTP(S)-Datenverkehr über den Burp-Proxy unter `127.0.0.1:8080` sendet. Direkt von einem MCP-Tool generierte Requests können daher in **Proxy > HTTP history** fehlen. Verwende den proxied Browser, wenn der Request/Response beobachtbar, bearbeitbar oder als Beweismittel aufbewahrt werden muss.<sup>[[2]](#references)[[9]](#references)</sup>

Ein Client mit SSE-Unterstützung kann Burp direkt registrieren. Ein reiner stdio-Client kann stattdessen PortSwiggers Proxy-JAR starten. Registriere in beiden Fällen ein zweites Browser-Control-MCP und verweise es auf Burps eingebettetes Chromium (`BURP_CHROMIUM` ist ein lokaler Pfad zu einer ausführbaren Datei):<sup>[[9]](#references)</sup>
```bash
# Claude Code: direct SSE plus a proxied browser
claude mcp add -s project -t sse burpsuite http://127.0.0.1:9876/
claude mcp add -s project -t stdio chrome-devtools -- chrome-devtools-mcp \
--executablePath "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
--accept-insecure-certs --isolated

# Codex: SSE-to-stdio bridge plus a proxied browser
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
codex mcp add burp-browser -- npx -y @playwright/mcp@latest \
--executable-path "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors --isolated
```
Das TLS-bypass-Flag akzeptiert von der Interception-Proxy generierte Zertifikate, während `--isolated` verhindert, dass das Assessment das normale Browserprofil des Operators wiederverwendet. Die Isolation schützt den Profilstatus, ist aber **keine Security-Sandbox**: Der Controller kann weiterhin auf authentifizierte Sessions zugreifen, die in diesem Testbrowser geöffnet wurden, und der Burp MCP kann vertrauliche Requests, Responses und Konfigurationen offenlegen.<sup>[[9]](#references)</sup>

Teste den SSE-Listener unabhängig, bevor du die Client-Bridge debuggst:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
Ein funktionierender Listener gibt `Content-Type: text/event-stream` zurück. Ein Timeout nach den Headern ist erwartungsgemäß, da ein SSE-Stream für zukünftige Events geöffnet bleibt. Wenn der Client weiterhin fehlschlägt, bestätige die konfigurierte Route der Extension: PortSwigger weist darauf hin, dass der Endpoint abhängig vom Client und der Extension-Konfiguration der Root-Pfad oder `/sse` sein kann.<sup>[[9]](#references)[[7]](#references)</sup>

## Verschiedene Clients verwenden

### Codex CLI

- Konfiguriere `~/.codex/config.toml` wie oben beschrieben.
- Starte `codex` und anschließend `/mcp`, um die Liste der Burp-Tools zu überprüfen.

### Gemini CLI

Das **burp-mcp-agents**-Repo stellt Launcher-Hilfsfunktionen bereit:<sup>[[4]](#references)</sup>
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
Beispiele für lokale Modelle und ungefähren VRAM-Bedarf:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Evidenzbasierte Wiedergabe und Validierung

Lassen Sie den Agenten eine plausible Erklärung oder eine Zwischenantwort nicht als Beweis behandeln. Verwenden Sie Burp-Requests/-Responses und unabhängig beobachteten Browser-Zustand, damit jeder Test falsifizierbar ist.<sup>[[8]](#references)</sup>

1. Speichern Sie ein Ausgangs-Request/-Response-Paar und identifizieren Sie die exakt vom Angreifer kontrollierte Komponente.
2. Erfassen Sie für Autorisierungsvergleiche denselben Workflow unabhängig unter beiden Accounts, bevor Sie Identifier, Cookies oder Tokens verändern.
3. Dokumentieren Sie vor der Wiedergabe einer Mutation die Hypothese, die Fundstelle der Evidenz, das erwartete Signal und das Ergebnis, das sie widerlegen würde.
4. Verändern Sie jeweils nur eine Komponente, bewahren Sie das resultierende Paar auf und kennzeichnen Sie direkte Beobachtungen getrennt von Schlussfolgerungen.
5. Verfolgen Sie jeden Kandidaten als `open`, `blocked`, `rejected` oder `confirmed`; greifen Sie nur dann erneut darauf zurück, wenn neue Evidenz den Mechanismus oder eine Voraussetzung verändert.
6. Bestätigen Sie die Kontrolle durch den Angreifer, Erreichbarkeit, Wiederholbarkeit, das Umgehen von Einschränkungen, die Auswirkung und den endgültigen Anwendungszustand. Eine Weiterleitung oder ein erfolgreicher Tool-Aufruf ist kein Beweis, wenn die behauptete Zustandsänderung nachgelagert erfolgt.

Bewahren Sie die Exploit-Details auf der relevanten Technikseite auf. Browser-Message-Kandidaten gehören beispielsweise zu [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), während das Verhalten bei der Auswahl von Token-Keys zu [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) gehört.<sup>[[8]](#references)</sup>

Ein kompakter Hypothesen-Datensatz verhindert, dass parallele Agenten denselben attraktiven Pfad wiederholen:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Prompt-Paket für passive Überprüfung

Das **burp-mcp-agents**-Repo enthält Prompt-Vorlagen für die evidenzbasierte Analyse von Burp-Traffic:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: breites passives Aufspüren von Schwachstellen.
- `idor_hunter.md`: IDOR/BOLA/Object-/Tenant-Abweichungen und Auth-Mismatches.
- `auth_flow_mapper.md`: Vergleich authentifizierter und nicht authentifizierter Pfade.
- `ssrf_redirect_hunter.md`: SSRF-/Open-Redirect-Kandidaten aus URL-Fetch-Parametern und Redirect-Ketten.
- `logic_flaw_hunter.md`: mehrstufige Logic-Flaws.
- `session_scope_hunter.md`: Missbrauch von Token-Audience und -Scopes.
- `rate_limit_abuse_hunter.md`: Lücken bei Throttling und Abuse-Schutz.
- `report_writer.md`: evidenzbasierte Berichterstellung.

## Optionales Attribution-Tagging

Um Burp-/LLM-Traffic in Logs zu taggen, füge ein Header-Rewrite hinzu (Proxy oder Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Sicherheitshinweise

- Bevorzuge **lokale Modelle**, wenn der Datenverkehr sensible Daten enthält.
- Teile nur die für einen Fund erforderlichen Belege.
- Behalte Burp als maßgebliche Quelle; verwende das Modell für **Analyse und Reporting**, nicht zum Scannen.

## Burp AI Agent (KI-gestützte Triage + MCP tools)

**Burp AI Agent** ist eine Burp-Erweiterung, die lokale/Cloud-LLMs mit passiver/aktiver Analyse (62 Schwachstellenklassen) verbindet und mehr als 53 MCP tools bereitstellt, sodass externe MCP-Clients Burp orchestrieren können.<sup>[[5]](#references)</sup> Höhepunkte:

- **Triage über das Kontextmenü**: Erfasse Datenverkehr über Proxy, öffne **Proxy > HTTP History**, klicke mit der rechten Maustaste auf eine Anfrage → **Extensions > Burp AI Agent > Analyze this request**, um einen an diese Anfrage/Antwort gebundenen KI-Chat zu starten.
- **Backends** (pro Profil auswählbar):
- Lokales HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-kompatibler** endpoint (Basis-URL + model name).
- Cloud-CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` oder `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-spezifischer Login).
- **Agent-Profile**: Prompt-Vorlagen werden automatisch unter `~/.burp-ai-agent/AGENTS/` installiert; lege dort zusätzliche `*.md`-Dateien ab, um benutzerdefinierte Analyse-/Scanning-Verhaltensweisen hinzuzufügen.
- **MCP server**: Aktiviere ihn über **Settings > MCP Server**, um Burp-Operationen für beliebige MCP-Clients bereitzustellen (mehr als 53 tools). Claude Desktop kann auf den server verwiesen werden, indem du `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) oder `%APPDATA%\Claude\claude_desktop_config.json` (Windows) bearbeitest.
- **Datenschutzkontrollen**: STRICT / BALANCED / OFF schwärzen sensible Request-Daten, bevor sie an Remote-Modelle gesendet werden; bevorzuge lokale Backends beim Umgang mit Secrets.
- **Audit-Logging**: JSONL-Logs mit SHA-256-Integritäts-Hashing pro Eintrag für eine manipulationssichere Nachvollziehbarkeit von KI-/MCP-Aktionen.
- **Build/Load**: Lade das Release-JAR herunter oder baue mit Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Betriebliche Vorsicht: Cloud-Backends können Session-Cookies/PII exfiltrieren, sofern der privacy mode nicht erzwungen wird; die MCP-Exposition ermöglicht die Remote-Orchestrierung von Burp. Beschränke den Zugriff daher auf vertrauenswürdige Agents und überwache das Integritäts-Hashing des Audit-Logs.

## References

- [1] [Burp MCP + Codex CLI-Integration und Caddy-Handshake-Fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem mit der strikten Origin-/Header-Validierung des PortSwigger MCP Servers](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (Workflows, Launcher, Prompt-Paket)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Codex für Bug-Bounty-Recherche verwenden: umfassend erkunden, rigoros validieren](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Burp-Suite-Orchestrierung für Claude Code und Codex](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
