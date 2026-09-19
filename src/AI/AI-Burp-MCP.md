# Burp MCP: LLM-gesteunde verkeershersiening

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Burp se **MCP Server**-uitbreiding kan onderskepte HTTP(S)-verkeer aan MCP-bekwame LLM-kliënte blootstel, sodat hulle oor **werklike versoeke/antwoorde kan redeneer** vir kwesbaarheidsontdekking en verslagsamestelling. Hou Burp as die bron van waarheid: gebruik passiewe analise of doelbewuste herhalings met een veranderlike eerder as blinde scanning.<sup>[[8]](#references)</sup>

## Argitektuur

- **Burp MCP Server (BApp)** luister by verstek op `127.0.0.1:9876` en stel onderskepte verkeer via MCP bloot.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** verbind stdio (kliëntkant) met Burp se MCP SSE-endpoint.
- **Opsionele plaaslike reverse proxy** (Caddy) normaliseer headers vir streng MCP-handdruk-kontroles.
- **Kliënte/backends**: Codex CLI (cloud), Gemini CLI (cloud), of Ollama (plaaslik).

## Opstelling

### 1) Installeer Burp MCP Server

Installeer **MCP Server** vanaf die Burp BApp Store en verifieer dat dit op `127.0.0.1:9876` luister.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Onttrek die proxy JAR

Klik in die MCP Server-oortjie op **Extract server proxy jar** en stoor `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Stel 'n MCP-kliënt op (Codex-voorbeeld)

Wys die kliënt na die proxy JAR en Burp se direkte SSE-endpoint. Die verpakte proxy is 'n stdio-na-SSE-bridge; dit vervang nie die Burp-listener nie.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Die ekwivalente Codex-opdrag is:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
Voer daarna Codex uit en lys MCP-nutsgoed:
```bash
codex
# inside Codex: /mcp
```
### 4) Herstel streng Origin-/header-validering met Caddy (indien nodig)

As die MCP-handdruk misluk weens streng `Origin`-kontroles of ekstra headers, gebruik ’n plaaslike reverse proxy om headers te normaliseer (dit stem ooreen met die workaround vir die Burp MCP-strengvalideringskwessie).<sup>[[1]](#references)[[3]](#references)</sup>
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
Begin die proxy en die client, en verander die gekonfigureerde `--sse-url` na `http://127.0.0.1:19876` slegs wanneer hierdie Caddy listener gebruik word:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Koppel blaaierstatus aan proxy-bewyse (Playwright MCP)

Registreer Playwright MCP sodat sy blaaier Burp se proxy gebruik. Dit stel die agent in staat om die weergegee DOM-/toeganklikheidstatus te korreleer met die presiese HTTP-geskiedenis wat dit voortgebring het.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Pas die listener-adres aan, herbegin Codex, en gebruik `/mcp` om albei integrasies te verifieer. Die voorbeeld deaktiveer blaaier-sertifikaatfoute sodat HTTPS-interception nie deur Burp se plaaslik gegenereerde sertifikaat geblokkeer word nie.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-bewuste blaaier-outomatisering (OpenBurp)

Die Burp MCP-verbinding en die geïntercepteerde blaaierpad is afsonderlike datavloeie. Die MCP-diens stel Burp-nutsgoed op `127.0.0.1:9876` beskikbaar, terwyl ’n toegewyde Chromium-instansie sy HTTP(S)-verkeer deur Burp se proxy op `127.0.0.1:8080` stuur. Versoeke wat direk deur ’n MCP-nutsding gegenereer word, kan dus afwesig wees uit **Proxy > HTTP history**; gebruik die proxied blaaier wanneer die versoek/antwoord waarneembaar, redigeerbaar of as bewyse behou moet word.<sup>[[2]](#references)[[9]](#references)</sup>

’n Kliënt met SSE-ondersteuning kan Burp direk registreer. ’n Slegs-stdio-kliënt kan eerder PortSwigger se proxy JAR begin. In albei gevalle registreer ’n tweede blaaierbeheer-MCP en wys dit na Burp se ingebedde Chromium (`BURP_CHROMIUM` is ’n plaaslike uitvoerbare pad):<sup>[[9]](#references)</sup>
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
Die TLS-bypass-vlag verdra sertifikate wat deur die interception proxy gegenereer word, terwyl `--isolated` voorkom dat die assessment die operateur se gewone browser-profiel hergebruik. Isolasie beskerm profieltoestand, maar is **nie ’n security sandbox nie**: die controller kan steeds toegang verkry tot geauthentiseerde sessies wat in daardie test-browser oopgemaak is, en die Burp MCP kan sensitiewe versoeke, response en konfigurasie blootstel.<sup>[[9]](#references)</sup>

Toets die SSE-listener onafhanklik voordat jy die client bridge debug:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
'n Gesonde listener gee `Content-Type: text/event-stream` terug. 'n Time-out ná die headers is verwag, omdat 'n SSE-stroom oop bly vir toekomstige events. As die client steeds misluk, bevestig die extension se gekonfigureerde route: PortSwigger meld dat die endpoint die root path of `/sse` kan wees, afhangend van die client en extension-konfigurasie.<sup>[[9]](#references)[[7]](#references)</sup>

## Gebruik van verskillende clients

### Codex CLI

- Stel `~/.codex/config.toml` soos hier bo op.
- Run `codex`, en daarna `/mcp` om die Burp tools-lys te verifieer.

### Gemini CLI

Die **burp-mcp-agents** repo verskaf launch-hulpmiddels:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (plaaslik)

Gebruik die verskafde lanseerder-helper en kies ’n plaaslike model:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Voorbeeld van plaaslike models en benaderde VRAM-behoeftes:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Bewysgedrewe herhaling en validering

Moenie toelaat dat die agent ’n aanneemlike verduideliking of ’n tussentydse response as bewys behandel nie. Gebruik Burp-versoeke/-responses en onafhanklik waargenome browser-state om elke toets falsifieerbaar te maak.<sup>[[8]](#references)</sup>

1. Stoor ’n baseline-versoek/-response-paar en identifiseer die presiese aanvaller-beheerde komponent.
2. Vir authorization-vergelykings, vang dieselfde workflow onafhanklik onder albei accounts vas voordat identifiers, cookies of tokens verander word.
3. Teken die hipotese, bewysligging, verwagte sein en die resultaat wat dit sou weerlê aan voordat ’n mutation herhaal word.
4. Verander een komponent op ’n slag, behou die resulterende paar en merk direkte waarnemings afsonderlik van afleidings.
5. Volg elke kandidaat as `open`, `blocked`, `rejected` of `confirmed`; herbesoek dit slegs wanneer nuwe bewyse die meganisme of ’n voorvereiste verander.
6. Bevestig aanvallerbeheer, bereikbaarheid, herhaalbaarheid, constraint-bypass, impak en die finale application-state. ’n Redirect of suksesvolle tool call is nie bewys indien die beweerde state change downstream plaasvind nie.

Hou die exploitation-besonderhede op die relevante technique-bladsy. Browser-message-kandidate hoort byvoorbeeld in [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), terwyl token key-selection-gedrag in [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) hoort.<sup>[[8]](#references)</sup>

’n Kompakte hipoteseverslag voorkom dat parallelle agents dieselfde aantreklike tak herhaal:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Prompt-pakket vir passiewe hersiening

Die **burp-mcp-agents**-repo bevat prompt-sjablone vir bewysgedrewe ontleding van Burp-verkeer:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: breë passiewe identifisering van kwesbaarhede.
- `idor_hunter.md`: IDOR/BOLA/objek-/tenant-verskuiwing en auth-wanpassings.
- `auth_flow_mapper.md`: vergelyk geauthentiseerde en ongeauthentiseerde paaie.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect-kandidate vanaf URL-fetch-parameters/-redirect-kettings.
- `logic_flaw_hunter.md`: multi-stap-logikafoute.
- `session_scope_hunter.md`: token audience/scope-misbruik.
- `rate_limit_abuse_hunter.md`: gapings in throttling/misbruikbeheer.
- `report_writer.md`: bewysgefokusde verslagdoening.

## Opsionele attribution-tagging

Om Burp/LLM-verkeer in logs te tag, voeg ’n header rewrite by (proxy of Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Veiligheidsnotas

- Verkies **local models** wanneer traffic sensitiewe data bevat.
- Deel slegs die minimum bewyse wat vir ’n finding nodig is.
- Hou Burp as die bron van waarheid; gebruik die model vir **analysis and reporting**, nie vir scanning nie.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** is ’n Burp extension wat local/cloud LLMs met passive/active analysis (62 vulnerability classes) koppel en 53+ MCP tools beskikbaar stel sodat eksterne MCP clients Burp kan orkestreer.<sup>[[5]](#references)</sup> Hoogtepunte:

- **Context-menu triage**: capture traffic via Proxy, open **Proxy > HTTP History**, klik met die regtermuisknoppie op ’n request → **Extensions > Burp AI Agent > Analyze this request** om ’n AI chat te begin wat aan daardie request/response gekoppel is.
- **Backends** (selectable per profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` of `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates word outomaties onder `~/.burp-ai-agent/AGENTS/` geïnstalleer; plaas bykomende `*.md`-lêers daar om custom analysis/scanning behaviors by te voeg.
- **MCP server**: enable via **Settings > MCP Server** om Burp operations aan enige MCP client beskikbaar te stel (53+ tools). Claude Desktop kan na die server gewys word deur `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) of `%APPDATA%\Claude\claude_desktop_config.json` (Windows) te wysig.
- **Privacy controls**: STRICT / BALANCED / OFF redigeer sensitiewe request data voordat dit na remote models gestuur word; verkies local backends wanneer secrets hanteer word.
- **Audit logging**: JSONL logs met per-entry SHA-256 integrity hashing vir tamper-evident traceability van AI/MCP actions.
- **Build/load**: laai die release JAR af of build met Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operasionele waarskuwings: cloud backends kan sessiekoekies/PII eksfiltreer tensy privaatheidsmodus afgedwing word; MCP-blootstelling verleen afgeleë orkestrasie van Burp, dus beperk toegang tot vertroude agents en monitor die integriteit-gehashte ouditlogboek.

## References

- [1] [Burp MCP + Codex CLI-integrasie en Caddy-handdrukherstel](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Kwessie met streng Origin-/header-validering in die PortSwigger MCP-server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (werksvloeie, launchers, prompt-pakket)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Hoe om Codex vir Bug Bounty-navorsing te gebruik: verken breed, valideer streng](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Burp Suite-orkestrasie vir Claude Code en Codex](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
