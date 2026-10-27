# Burp MCP: LLM-gestützte Überprüfung des Datenverkehrs

{{#include ../banners/hacktricks-training.md}}

## Überblick

Burps **MCP Server**-Erweiterung kann abgefangenen HTTP(S)-Datenverkehr für MCP-fähige LLM-Clients bereitstellen, damit diese **echte Anfragen und Antworten analysieren** können, um Schwachstellen zu finden und Berichte zu erstellen. Burp bleibt die maßgebliche Quelle: Verwende passive Analysen oder gezielte Wiederholungen mit jeweils nur einer veränderten Variable statt blindem Scannen.<sup>[[8]](#references)</sup>

## Architektur

- **Burp MCP Server (BApp)** lauscht standardmäßig auf `127.0.0.1:9876` und stellt abgefangenen Datenverkehr über MCP bereit.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP-Proxy-JAR** verbindet stdio (Client-Seite) mit Burps MCP-SSE-Endpunkt.
- **Optionaler lokaler Reverse-Proxy** (Caddy) vereinheitlicht Header für strenge MCP-Handshake-Prüfungen.
- **Clients/Backends**: Codex CLI (Cloud), Gemini CLI (Cloud) oder Ollama (lokal).

## Einrichtung

### 1) Burp MCP Server installieren

Installiere **MCP Server** aus dem Burp BApp Store und überprüfe, ob er auf `127.0.0.1:9876` lauscht.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Die Proxy-JAR extrahieren

Klicke im Tab MCP Server auf **Extract server proxy jar** und speichere `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Einen MCP-Client konfigurieren (Beispiel mit Codex)

Verweise den Client auf die Proxy-JAR und Burps direkten SSE-Endpunkt. Der mitgelieferte Proxy ist eine stdio-zu-SSE-Brücke; er ersetzt nicht den Burp-Listener.<sup>[[7]](#references)</sup>

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

Führen Sie anschließend Codex aus und listen Sie die MCP-Tools auf:

```bash
codex
# inside Codex: /mcp
```

### 4) Strenge Origin-/Header-Validierung mit Caddy beheben (falls nötig)

Wenn der MCP-Handshake aufgrund strenger `Origin`-Prüfungen oder zusätzlicher Header fehlschlägt, verwende einen lokalen Reverse Proxy, um die Header zu normalisieren (dies entspricht dem Workaround für das Problem mit der strengen Burp-MCP-Validierung).<sup>[[1]](#references)[[3]](#references)</sup>

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

Starten Sie den Proxy und den Client, und ändern Sie `--sse-url` nur bei Verwendung dieses Caddy-Listeners auf `http://127.0.0.1:19876`:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Browser-Zustand mit Proxy-Nachweisen verknüpfen (Playwright MCP)

Registriere Playwright MCP so, dass der Browser den Proxy von Burp verwendet. So kann der Agent den gerenderten DOM-/Accessibility-Zustand mit dem exakten HTTP-Verlauf verknüpfen, der ihn erzeugt hat.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Passe die Listener-Adresse an, starte Codex neu und verwende `/mcp`, um beide Integrationen zu überprüfen. Im Beispiel werden Browser-Zertifikatsfehler deaktiviert, damit Burps lokal generiertes Zertifikat die HTTPS-Interception nicht verhindert.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-bewusste Browser-Automatisierung (OpenBurp)

Die Burp-MCP-Verbindung und der abgefangene Browser-Datenverkehr sind separate Datenflüsse. Der MCP-Dienst stellt Burp-Tools unter `127.0.0.1:9876` bereit, während eine dedizierte Chromium-Instanz ihren HTTP(S)-Datenverkehr über Burps Proxy unter `127.0.0.1:8080` leitet. Daher können Anfragen, die direkt von einem MCP-Tool erzeugt werden, in **Proxy > HTTP history** fehlen. Verwende den Browser mit Proxy, wenn die Anfrage/Antwort sichtbar, bearbeitbar oder als Beweismittel aufbewahrt werden muss.<sup>[[2]](#references)[[9]](#references)</sup>

Ein Client mit SSE-Unterstützung kann Burp direkt registrieren. Ein Client, der nur stdio unterstützt, kann stattdessen PortsWiggers Proxy-JAR starten. Registriere in beiden Fällen ein zweites Browser-Control-MCP und verweise es auf Burps eingebettetes Chromium (`BURP_CHROMIUM` ist ein lokaler Pfad zur ausführbaren Datei):<sup>[[9]](#references)</sup>

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

Die TLS-bypass-Flag toleriert vom Interception-Proxy generierte Zertifikate, während `--isolated` verhindert, dass das Assessment das normale Browserprofil des Operators wiederverwendet. Die Isolation schützt den Profilstatus, ist aber **keine Sicherheits-Sandbox**: Der Controller kann weiterhin auf authentifizierte Sitzungen zugreifen, die in diesem Testbrowser geöffnet wurden, und das Burp MCP kann sensible Requests, Responses und Konfigurationen offenlegen.<sup>[[9]](#references)</sup>

Teste den SSE-Listener unabhängig, bevor du die Client-Bridge debuggst:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Ein funktionsfähiger Listener gibt `Content-Type: text/event-stream` zurück. Ein Timeout nach den Headern ist erwartungsgemäß, da ein SSE-Stream für zukünftige Ereignisse offen bleibt. Wenn der Client weiterhin fehlschlägt, überprüfe die konfigurierte Route der Extension: PortSwigger weist darauf hin, dass der Endpoint je nach Client und Extension-Konfiguration der Root-Pfad oder `/sse` sein kann.<sup>[[9]](#references)[[7]](#references)</sup>

## Verschiedene Clients verwenden

### Codex CLI

- Konfiguriere `~/.codex/config.toml` wie oben beschrieben.
- Führe `codex` aus und gib dann `/mcp` ein, um die Liste der Burp-Tools zu überprüfen.

### Gemini CLI

Das Repo **burp-mcp-agents** stellt Launcher-Hilfsprogramme bereit:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (lokal)

Verwenden Sie den bereitgestellten Launcher-Helfer und wählen Sie ein lokales Modell aus:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Beispiele für lokale Modelle und ungefähren VRAM-Bedarf:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Beleggestütztes Replay und Validierung

Lass den Agenten eine plausible Erklärung oder eine Zwischenantwort nicht als Beweis behandeln. Verwende Burp-Requests und -Responses sowie unabhängig beobachtete Browserzustände, damit jeder Test falsifizierbar ist.<sup>[[8]](#references)</sup>

1. Speichere ein Baseline-Request/Response-Paar und bestimme die genaue vom Angreifer kontrollierte Komponente.
2. Erfasse für Autorisierungsvergleiche denselben Workflow unabhängig unter beiden Konten, bevor du Kennungen, Cookies oder Tokens änderst.
3. Halte vor dem Replay einer Mutation die Hypothese, den Belegort, das erwartete Signal und das Ergebnis fest, das sie widerlegen würde.
4. Ändere jeweils nur eine Komponente, bewahre das resultierende Paar auf und kennzeichne direkte Beobachtungen getrennt von Schlussfolgerungen.
5. Verfolge jeden Kandidaten mit dem Status `open`, `blocked`, `rejected` oder `confirmed`; prüfe ihn erst erneut, wenn neue Belege den Mechanismus oder eine Voraussetzung ändern.
6. Bestätige die Kontrolle durch den Angreifer, die Erreichbarkeit, Wiederholbarkeit, die Umgehung von Einschränkungen, die Auswirkungen und den endgültigen Anwendungszustand. Eine Weiterleitung oder ein erfolgreicher Tool-Aufruf ist kein Beweis, wenn die behauptete Zustandsänderung nachgelagert erfolgt.

Die Details zur Ausnutzung gehören auf die passende Technikseite. Browser-Message-Kandidaten gehören beispielsweise zu [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), während das Verhalten bei der Schlüsselauswahl von Tokens zu [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) gehört.<sup>[[8]](#references)</sup>

Ein kompakter Hypothesen-Eintrag verhindert, dass parallel arbeitende Agenten denselben verlockenden Ansatz wiederholen:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## WebSocket-Frame-Triage mit Burp MCP

Die offizielle Extension stellt `get_proxy_websocket_history_regex` für schreibgeschützte, paginierte Suchen im WebSocket-Verlauf von Burp bereit. Der Befehl akzeptiert `regex`, `count` und `offset`; anders als `send_http1_request` sendet er keinen WebSocket-Frame. Burp zeichnet beide Nachrichtenrichtungen auf, auch wenn Intercept ausgeschaltet ist. Filtere daher zuerst den Verlauf, bevor du dem Modell eine kleine Auswahl relevanter Frames übergibst.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Führe dieselbe WebSocket-basierte Aktion über den Burp-proxied Browser mit zwei unabhängig authentifizierten Testkonten aus. Halte jeden Upgrade-Handshake und dessen Cookies, die Connection-ID, die Frame-Richtung und die Response-Frames zusammen. Ein Server-to-Client-Ereignis auf der Verbindung des ersten Kontos ist kein Beleg dafür, dass das zweite Konto es erhalten hat.
2. Durchsuche `get_proxy_websocket_history_regex` mit einem engen Ausdruck wie `(?i)(subscribe|room|tenant|objectId)`, `count: 20` und `offset: 0`. Erhöhe `offset`, um spätere Treffer zu prüfen. Vergleiche den Objekt- oder Topic-Identifier des ausgehenden Frames mit der Response auf **derselben Verbindung**.
3. Sende den möglichen ausgehenden Frame unter **Proxy > WebSockets history** an Repeater. Hänge ihn an die passende offene Verbindung an oder stelle die Verbindung mit dem Handshake des zweiten Kontos wieder her. Ändere nur den Objekt-/Topic-Identifier und vergleiche die resultierenden Servernachrichten und den Anwendungsstatus mit beiden Baselines. Das MCP-Verlaufstool kann diese Wiedergabe nicht ausführen; WebSocket Repeater kann Frames bearbeiten, erneut senden und Verbindungen wiederherstellen.

Fahre bei protokollspezifischen Tests wie Cross-Site WebSocket Hijacking und Broker-Topic-Autorisierung mit [WebSocket Attacks](../pentesting-web/websocket-attacks.md) fort. Werte weder einen akzeptierten Upgrade noch ein clientseitiges Echo als Beleg dafür, dass ein geschütztes Abonnement erfolgreich war.

## Gezielte Out-of-Band-Validierung mit Burp MCP

Burp Suite Professional stellt `generate_collaborator_payload` und `get_collaborator_interactions` über die offizielle MCP-Extension bereit. Kombiniere sie mit `get_proxy_http_history_regex` und einer einzelnen `send_http1_request`-Wiedergabe, um einen vermuteten serverseitigen URL-Abruf zu testen, ohne das gesamte Ziel zu scannen. Burp kann eine separate Genehmigung zum Lesen des Verlaufs und zum Senden einer Anfrage erfordern.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtere den Verlauf nach einer möglichen Anfrage mit einer URL, etwa einer Anfrage mit `url=`, `webhook` oder `callback`. Speichere die Originalanfrage und -response. Das Verlaufstool akzeptiert `regex`, `count` und `offset`; blättere durch die Ergebnisse, statt das Modell jeden Eintrag prüfen zu lassen.<sup>[[10]](#references)</sup>
2. Generiere einen neuen Collaborator-Payload und speichere die zurückgegebene **Payload-ID**. Spiele die aufgezeichnete Anfrage an denselben Host und Port erneut ab und ändere nur die mögliche URL in eine HTTPS-URL unter der Payload-Domain. Übergebe `send_http1_request` die vollständige HTTP/1.1-Anfrage als `content` sowie `targetHostname`, `targetPort` und `usesHttps`; die Zielfelder bezeichnen die **Anwendung**, nicht den Collaborator-Host.<sup>[[10]](#references)</sup>
3. Rufe `get_collaborator_interactions` mit dieser Payload-ID wiederholt ab und korreliere den Zeitpunkt der Interaktion mit der Wiedergabe. Eine HTTP-Interaktion spricht für einen Abruf, während DNS allein nur die Auflösung, aber keine abgeschlossene HTTP-Anfrage belegt. Prüfe die Interaktionsquelle und die Request-Header, um serverseitigen Egress von browserseitigem Laden zu unterscheiden. Wiederhole den Test anschließend mit einem neuen Payload, um unabhängigen Traffic auszuschließen.<sup>[[10]](#references)[[11]](#references)</sup>

Das MCP-Request-Tool gibt die Response direkt zurück und muss sie nicht in **Proxy > HTTP history** speichern. Bewahre das Ergebnis aus Anfrage und Response auf oder verwende den proxied Browser oder Repeater für einen im Verlauf gespeicherten Nachweis. Verwende für die Auswahl von SSRF-Payloads und Folgetests das [SSRF-Kapitel](../pentesting-web/ssrf-server-side-request-forgery/), statt einen Out-of-Band-Callback als Beleg für Auswirkungen auf das interne Netzwerk zu werten. Informationen zum Testen des MCP-Servers selbst findest du unter [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Prompt-Sammlung für passive Überprüfungen

Das Repo **burp-mcp-agents** enthält Prompt-Vorlagen für eine evidenzbasierte Analyse von Burp-Traffic:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: breit angelegte passive Erkennung von Schwachstellen.
- `idor_hunter.md`: IDOR/BOLA sowie Abweichungen bei Objekten, Tenants und Authentifizierung.
- `auth_flow_mapper.md`: Vergleich authentifizierter und nicht authentifizierter Pfade.
- `ssrf_redirect_hunter.md`: mögliche SSRF/Open-Redirects anhand von URL-Abrufparametern und Redirect-Ketten.
- `logic_flaw_hunter.md`: mehrstufige Logikfehler.
- `session_scope_hunter.md`: Missbrauch von Token-Audience und -Scope.
- `rate_limit_abuse_hunter.md`: Lücken bei Throttling und Missbrauchsschutz.
- `report_writer.md`: evidenzorientierte Berichterstellung.

## Optionale Attribution-Tags

Um Burp-/LLM-Traffic in Logs zu kennzeichnen, füge eine Header-Umschreibung hinzu (Proxy oder Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Sicherheitshinweise

- Bevorzuge **lokale Modelle**, wenn der Traffic sensible Daten enthält.
- Teile nur die minimal erforderlichen Nachweise für einen Befund.
- Burp bleibt die maßgebliche Quelle; verwende das Modell für **Analysen und Berichte**, nicht zum Scannen.

## Burp AI Agent (KI-gestützte Triage + MCP-Tools)

**Burp AI Agent** ist eine Burp-Erweiterung, die lokale/Cloud-LLMs mit passiver/aktiver Analyse (62 Schwachstellenklassen) kombiniert und mehr als 53 MCP-Tools bereitstellt, mit denen externe MCP-Clients Burp steuern können.<sup>[[5]](#references)</sup> Highlights:

- **Triage über das Kontextmenü**: Erfasse Traffic über Proxy, öffne **Proxy > HTTP History**, klicke mit der rechten Maustaste auf eine Anfrage → **Extensions > Burp AI Agent > Analyze this request**, um einen an diese Anfrage/Antwort gebundenen KI-Chat zu starten.
- **Backends** (pro Profil auswählbar):
  - Lokales HTTP: **Ollama**, **LM Studio**.
  - Remote-HTTP: **OpenAI-kompatibler** Endpunkt (Basis-URL + Modellname).
  - Cloud-CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` oder `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (anbieterabhängige Anmeldung).
- **Agent-Profile**: Prompt-Vorlagen werden automatisch unter `~/.burp-ai-agent/AGENTS/` installiert; lege dort zusätzliche `*.md`-Dateien ab, um benutzerdefinierte Analyse-/Scan-Verhaltensweisen hinzuzufügen.
- **MCP-Server**: Aktiviere ihn über **Settings > MCP Server**, um Burp-Operationen für jeden MCP-Client bereitzustellen (mehr als 53 Tools). Claude Desktop kann mit dem Server verbunden werden, indem du `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) oder `%APPDATA%\Claude\claude_desktop_config.json` (Windows) bearbeitest.
- **Datenschutzkontrollen**: STRICT / BALANCED / OFF schwärzen sensible Anfragedaten, bevor sie an Remote-Modelle gesendet werden; bevorzuge lokale Backends beim Umgang mit Secrets.
- **Audit-Protokollierung**: JSONL-Protokolle mit SHA-256-Integritätshash pro Eintrag sorgen für eine manipulationssichere Nachverfolgbarkeit von KI-/MCP-Aktionen.
- **Erstellen/Laden**: Lade das Release-JAR herunter oder erstelle es mit Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operative Hinweise: Cloud-Backends können Sitzungscookies/PII exfiltrieren, sofern der Datenschutzmodus nicht erzwungen wird; die MCP-Exposition ermöglicht die Remote-Orchestrierung von Burp. Beschränken Sie daher den Zugriff auf vertrauenswürdige Agents und überwachen Sie das Integritäts-Hash-Protokoll.



## References

- [1] [Burp MCP + Codex CLI-Integration und Caddy-Handshake-Fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem mit strikter Origin-/Header-Validierung im PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (Workflows, Launcher, Prompt-Paket)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Codex für Bug-Bounty-Recherchen verwenden: breit erkunden, rigoros validieren](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Burp Suite-Orchestrierung für Claude Code und Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Tool-Implementierungen und Parameter des PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind-SSRF-Schwachstellen](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - WebSockets-Verlauf](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Mit WebSocket-Nachrichten in Burp Repeater arbeiten](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
