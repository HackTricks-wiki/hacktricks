# Burp MCP: LLM-gestützte Traffic-Analyse

{{#include ../banners/hacktricks-training.md}}

## Überblick

Burps **MCP Server**-Erweiterung kann abgefangenen HTTP(S)-Traffic für MCP-fähige LLM-Clients bereitstellen, damit diese **echte Requests/Responses analysieren** und Schwachstellen aufspüren sowie Berichte entwerfen können. Burp bleibt die maßgebliche Datenquelle: Nutze passive Analysen oder gezielte Replays mit nur einer geänderten Variable statt blindem Scanning.<sup>[[8]](#references)</sup>

## Architektur

- **Burp MCP Server (BApp)** lauscht standardmäßig auf `127.0.0.1:9876` und stellt abgefangenen Traffic über MCP bereit.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP-Proxy-JAR** verbindet stdio (Client-Seite) mit Burps MCP-SSE-Endpunkt.
- **Optionaler lokaler Reverse-Proxy** (Caddy) vereinheitlicht Header für strenge MCP-Handshake-Prüfungen.
- **Clients/Backends**: Codex CLI (Cloud), Gemini CLI (Cloud) oder Ollama (lokal).

## Einrichtung

### 1) Burp MCP Server installieren

Installiere **MCP Server** aus dem Burp BApp Store und vergewissere dich, dass er auf `127.0.0.1:9876` lauscht.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Proxy-JAR extrahieren

Klicke im Tab „MCP Server“ auf **Extract server proxy jar** und speichere `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Einen MCP-Client konfigurieren (Codex-Beispiel)

Verweise den Client auf die Proxy-JAR und Burps direkten SSE-Endpunkt. Der mitgelieferte Proxy verbindet stdio mit SSE; er ersetzt nicht den Burp-Listener.<sup>[[7]](#references)</sup>

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

Führen Sie dann Codex aus und listen Sie die MCP-Tools auf:

```bash
codex
# inside Codex: /mcp
```

### 4) Strenge Origin-/Header-Validierung mit Caddy beheben (falls nötig)

Wenn der MCP-Handshake aufgrund strenger `Origin`-Prüfungen oder zusätzlicher Header fehlschlägt, verwende einen lokalen Reverse-Proxy, um Header zu normalisieren (dies entspricht dem Workaround für das strenge Validierungsproblem von Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Starten Sie den Proxy und den Client und ändern Sie die konfigurierte `--sse-url` nur bei Verwendung dieses Caddy-Listeners:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Browser-Status mit Proxy-Belegen verknüpfen (Playwright MCP)

Registriere Playwright MCP so, dass der Browser den Proxy von Burp verwendet. Dadurch kann der Agent den gerenderten DOM-/Accessibility-Status mit dem exakten HTTP-Verlauf verknüpfen, der ihn erzeugt hat.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Passe die Listener-Adresse an, starte Codex neu und verwende `/mcp`, um beide Integrationen zu überprüfen. Das Beispiel deaktiviert Browser-Zertifikatsfehler, damit die HTTPS-Interception nicht durch das lokal von Burp generierte Zertifikat blockiert wird.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-bewusste Browser-Automatisierung (OpenBurp)

Die Burp-MCP-Verbindung und der abgefangene Browser-Datenverkehr sind separate Datenflüsse. Der MCP-Dienst stellt Burp-Tools auf `127.0.0.1:9876` bereit, während eine dedizierte Chromium-Instanz ihren HTTP(S)-Datenverkehr über den Burp-Proxy auf `127.0.0.1:8080` sendet. Direkt von einem MCP-Tool erzeugte Requests erscheinen daher möglicherweise nicht unter **Proxy > HTTP history**. Verwende den Browser mit Proxy, wenn der Request/die Response beobachtbar, bearbeitbar oder als Beleg aufbewahrt werden muss.<sup>[[2]](#references)[[9]](#references)</sup>

Ein Client mit SSE-Unterstützung kann Burp direkt registrieren. Ein Client, der nur stdio unterstützt, kann stattdessen die Proxy-JAR von PortSwigger starten. In beiden Fällen registrierst du ein zweites Browser-Control-MCP und richtest es auf das eingebettete Chromium von Burp aus (`BURP_CHROMIUM` ist ein lokaler ausführbarer Pfad):<sup>[[9]](#references)</sup>

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

Das TLS-Bypass-Flag akzeptiert vom Interception-Proxy generierte Zertifikate, während `--isolated` verhindert, dass die Prüfung das normale Browserprofil des Operators wiederverwendet. Die Isolation schützt den Profilzustand, ist aber **keine Security-Sandbox**: Der Controller kann weiterhin auf authentifizierte Sitzungen zugreifen, die in diesem Testbrowser geöffnet wurden, und das Burp MCP kann sensible Requests, Responses und Konfigurationen offenlegen.<sup>[[9]](#references)</sup>

Teste den SSE-Listener unabhängig, bevor du die Client-Bridge debugst:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Ein funktionierender Listener gibt `Content-Type: text/event-stream` zurück. Ein Timeout nach den Headern ist erwartungsgemäß, da ein SSE-Stream für zukünftige Events offen bleibt. Falls der Client weiterhin fehlschlägt, prüfe den konfigurierten Pfad der Extension: PortSwigger weist darauf hin, dass der Endpoint je nach Client- und Extension-Konfiguration der Root-Pfad oder `/sse` sein kann.<sup>[[9]](#references)[[7]](#references)</sup>

## Verschiedene Clients verwenden

### Codex CLI

- Konfiguriere `~/.codex/config.toml` wie oben.
- Starte `codex` und anschließend `/mcp`, um die Liste der Burp-Tools zu überprüfen.

### Gemini CLI

Das Repo **burp-mcp-agents** stellt Launcher-Helfer bereit:<sup>[[4]](#references)</sup>

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

## Evidenzbasierte Wiederholung und Validierung

Lass den Agenten eine plausible Erklärung oder eine Zwischenantwort nicht als Beweis behandeln. Verwende Burp-Requests/-Responses und unabhängig beobachtete Browser-Zustände, damit jeder Test falsifizierbar ist.<sup>[[8]](#references)</sup>

1. Speichere ein Baseline-Request/Response-Paar und identifiziere die genaue angreiferkontrollierte Komponente.
2. Erfasse für Berechtigungsvergleiche denselben Workflow unabhängig unter beiden Konten, bevor du Bezeichner, Cookies oder Tokens veränderst.
3. Halte vor der Wiederholung einer Mutation die Hypothese, den Speicherort der Evidenz, das erwartete Signal und das Ergebnis fest, das sie widerlegen würde.
4. Verändere jeweils nur eine Komponente, bewahre das resultierende Paar auf und kennzeichne direkte Beobachtungen getrennt von Schlussfolgerungen.
5. Verfolge jeden Kandidaten mit dem Status `open`, `blocked`, `rejected` oder `confirmed`; greife ihn nur dann erneut auf, wenn neue Evidenz den Mechanismus oder eine Voraussetzung verändert.
6. Bestätige die Kontrolle durch den Angreifer, Erreichbarkeit, Wiederholbarkeit, Umgehung von Einschränkungen, Auswirkungen und den endgültigen Anwendungszustand. Eine Weiterleitung oder ein erfolgreicher Tool-Aufruf ist kein Beweis, wenn die behauptete Zustandsänderung erst nachgelagert erfolgt.

Die Details zur Ausnutzung gehören auf die jeweilige Technikseite. Beispielsweise gehören Kandidaten für Browser-Nachrichten zu [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), während das Verhalten bei der Schlüsselauswahl von Tokens zu [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) gehört.<sup>[[8]](#references)</sup>

Ein kompakter Hypotheseneintrag verhindert, dass parallele Agents denselben verlockenden Ansatz wiederholen:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Gezielte Out-of-Band-Validierung mit Burp MCP

Burp Suite Professional stellt über die offizielle MCP-Erweiterung `generate_collaborator_payload` und `get_collaborator_interactions` bereit. Kombinieren Sie diese mit `get_proxy_http_history_regex` und einem einzelnen `send_http1_request`-Replay, um einen vermuteten serverseitigen URL-Abruf zu testen, ohne das gesamte Ziel zu scannen. Burp benötigt möglicherweise separate Genehmigungen zum Lesen des Verlaufs und zum Senden einer Anfrage.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtern Sie den Verlauf nach einer Anfrage mit einer möglichen URL, etwa einer mit `url=`, `webhook` oder `callback`. Speichern Sie die ursprüngliche Anfrage und Antwort. Das Verlaufstool akzeptiert `regex`, `count` und `offset`; blättern Sie durch die Ergebnisse, statt das Modell alle Einträge prüfen zu lassen.<sup>[[10]](#references)</sup>
2. Generieren Sie einen neuen Collaborator-Payload und speichern Sie die zurückgegebene **payload ID**. Senden Sie die erfasste Anfrage erneut an denselben Host und Port und ändern Sie dabei nur die mögliche URL in eine HTTPS-URL unter der Payload-Domain. Für `send_http1_request` übergeben Sie die vollständige HTTP/1.1-Anfrage als `content` sowie `targetHostname`, `targetPort` und `usesHttps`; die Zielfelder bezeichnen die **Anwendung**, nicht den Collaborator-Host.<sup>[[10]](#references)</sup>
3. Fragen Sie `get_collaborator_interactions` mit dieser payload ID ab und korrelieren Sie den Zeitpunkt der Interaktion mit dem Replay. Eine HTTP-Interaktion spricht für einen Abruf, während DNS allein nur die Namensauflösung, aber keine abgeschlossene HTTP-Anfrage belegt. Prüfen Sie die Quelle der Interaktion und die Request-Header, um serverseitigen Egress von browserseitigem Laden zu unterscheiden. Wiederholen Sie den Test anschließend mit einem neuen Payload, um nicht zusammenhängenden Traffic auszuschließen.<sup>[[10]](#references)[[11]](#references)</sup>

Das MCP-Anfragetool gibt die Antwort direkt zurück und muss sie nicht im **Proxy > HTTP history** speichern. Bewahren Sie das Ergebnis der Anfrage und Antwort auf oder verwenden Sie den proxied Browser oder Repeater, um einen im Verlauf gespeicherten Nachweis zu erhalten. Informationen zur Auswahl von SSRF-Payloads und zu Folgetests finden Sie im [SSRF-Kapitel](../pentesting-web/ssrf-server-side-request-forgery/); behandeln Sie einen Out-of-Band-Callback nicht als Beweis für Auswirkungen auf das interne Netzwerk. Informationen zum Testen des MCP-Servers selbst finden Sie unter [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Prompt-Sammlung für passive Überprüfungen

Das Repo **burp-mcp-agents** enthält Prompt-Vorlagen für eine evidenzbasierte Analyse von Burp-Traffic:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: umfassendes passives Aufspüren von Schwachstellen.
- `idor_hunter.md`: IDOR/BOLA, Objekt-/Tenant-Abweichungen und Auth-Abweichungen.
- `auth_flow_mapper.md`: Vergleich authentifizierter und nicht authentifizierter Pfade.
- `ssrf_redirect_hunter.md`: SSRF-/Open-Redirect-Kandidaten anhand von URL-Abrufparametern und Redirect-Ketten.
- `logic_flaw_hunter.md`: mehrstufige Logikfehler.
- `session_scope_hunter.md`: Missbrauch von Token-Audience und -Scope.
- `rate_limit_abuse_hunter.md`: Lücken bei Drosselung und Missbrauchsschutz.
- `report_writer.md`: evidenzorientierte Berichterstellung.

## Optionale Attribution-Tags

Um Burp-/LLM-Traffic in Logs zu kennzeichnen, fügen Sie eine Header-Umschreibung hinzu (Proxy oder Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Sicherheitshinweise

- Bevorzuge **lokale Modelle**, wenn der Traffic sensible Daten enthält.
- Teile nur die minimal erforderlichen Nachweise für einen Befund.
- Burp bleibt die maßgebliche Quelle; verwende das Modell für **Analysen und Berichte**, nicht für Scans.

## Burp AI Agent (KI-gestützte Triage + MCP-Tools)

**Burp AI Agent** ist eine Burp-Erweiterung, die lokale/cloudbasierte LLMs mit passiver/aktiver Analyse (62 Schwachstellenklassen) kombiniert und mehr als 53 MCP-Tools bereitstellt, mit denen externe MCP-Clients Burp steuern können.<sup>[[5]](#references)</sup> Highlights:

- **Triage über das Kontextmenü**: Erfasse Traffic über Proxy, öffne **Proxy > HTTP History**, klicke mit der rechten Maustaste auf eine Anfrage → **Extensions > Burp AI Agent > Analyze this request**, um einen an diese Anfrage/Antwort gebundenen KI-Chat zu starten.
- **Backends** (pro Profil auswählbar):
  - Lokales HTTP: **Ollama**, **LM Studio**.
  - Remote-HTTP: **OpenAI-kompatibler** Endpunkt (Basis-URL + Modellname).
  - Cloud-CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` oder `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (anbieterabhängige Anmeldung).
- **Agent-Profile**: Prompt-Vorlagen werden automatisch unter `~/.burp-ai-agent/AGENTS/` installiert; lege dort zusätzliche `*.md`-Dateien ab, um benutzerdefinierte Analyse-/Scan-Verhaltensweisen hinzuzufügen.
- **MCP-Server**: Aktiviere ihn unter **Settings > MCP Server**, um Burp-Operationen für beliebige MCP-Clients bereitzustellen (mehr als 53 Tools). Claude Desktop kann auf den Server konfiguriert werden, indem du `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) oder `%APPDATA%\Claude\claude_desktop_config.json` (Windows) bearbeitest.
- **Datenschutzkontrollen**: STRICT / BALANCED / OFF schwärzen sensible Anfragedaten, bevor sie an Remote-Modelle gesendet werden; bevorzuge bei der Verarbeitung von Geheimnissen lokale Backends.
- **Audit-Protokollierung**: JSONL-Protokolle mit SHA-256-Integritäts-Hashing pro Eintrag ermöglichen eine manipulationssichere Nachverfolgung von KI-/MCP-Aktionen.
- **Erstellen/Laden**: Lade die Release-JAR herunter oder baue mit Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operative Hinweise: Cloud-Backends können Sitzungscookies/PII exfiltrieren, sofern der Datenschutzmodus nicht erzwungen wird; MCP-Zugriff ermöglicht die Remote-Orchestrierung von Burp. Beschränke ihn daher auf vertrauenswürdige Agents und überwache das Integritätshash-Audit-Log.



## References

- [1] [Burp MCP + Codex CLI-Integration und Caddy-Handshake-Fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Problem mit der strikten Origin-/Header-Validierung im PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (Workflows, Launcher, Prompt-Paket)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Codex für Bug-Bounty-Recherchen verwenden: breit erkunden, sorgfältig validieren](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Burp Suite-Orchestrierung für Claude Code und Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Implementierungen und Parameter der PortSwigger MCP Server-Tools](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy – Blind-SSRF-Schwachstellen](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
