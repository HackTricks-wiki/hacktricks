# Burp MCP: LLM-ondersteunde verkeershersiening

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Burp se **MCP Server**-uitbreiding kan onderskepte HTTP(S)-verkeer beskikbaar stel aan MCP-geskikte LLM-kliënte sodat hulle **oor werklike requests/responses kan redeneer** om kwesbaarhede te ontdek en verslae op te stel. Hou Burp as die bron van waarheid: gebruik passiewe ontleding of doelbewuste herhalings met een veranderlike, eerder as blinde skandering.<sup>[[8]](#references)</sup>

## Argitektuur

- **Burp MCP Server (BApp)** luister by verstek op `127.0.0.1:9876` en stel onderskepte verkeer via MCP beskikbaar.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** oorbrug stdio (kliëntkant) na Burp se MCP SSE-eindpunt.
- **Opsionele plaaslike reverse proxy** (Caddy) normaliseer headers vir streng MCP-handdruktoetse.
- **Kliënte/backends**: Codex CLI (wolk), Gemini CLI (wolk), of Ollama (plaaslik).

## Opstelling

### 1) Installeer Burp MCP Server

Installeer **MCP Server** vanaf die Burp BApp Store en verifieer dat dit op `127.0.0.1:9876` luister.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Onttrek die proxy JAR

Klik in die MCP Server-oortjie op **Extract server proxy jar** en stoor `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Stel ’n MCP-kliënt op (Codex-voorbeeld)

Stel die kliënt in om die proxy JAR en Burp se direkte SSE-eindpunt te gebruik. Die ingeslote proxy is ’n stdio-na-SSE-brug; dit vervang nie die Burp-luisteraar nie.<sup>[[7]](#references)</sup>

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

Voer dan Codex uit en lys MCP-nutsgoed:

```bash
codex
# inside Codex: /mcp
```

### 4) Herstel streng Origin-/header-validering met Caddy (indien nodig)

As die MCP-handdruk misluk weens streng `Origin`-kontroles of ekstra headers, gebruik ’n plaaslike reverse proxy om headers te normaliseer (dit stem ooreen met die tydelike oplossing vir die Burp MCP-strengvalideringsprobleem).<sup>[[1]](#references)[[3]](#references)</sup>

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

Begin die proxy en die client, en verander die gekonfigureerde `--sse-url` na `http://127.0.0.1:19876` slegs wanneer hierdie Caddy-listener gebruik word:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Koppel blaaiertoestand aan proxybewyse (Playwright MCP)

Registreer Playwright MCP sodat die blaaier Burp se proxy gebruik. Dit laat die agent die weergegewe DOM-/toeganklikheidstoestand koppel aan die presiese HTTP-geskiedenis wat dit voortgebring het.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Pas die listeneradres aan, herbegin Codex en gebruik `/mcp` om albei integrasies te verifieer. Die voorbeeld deaktiveer blaaier-sertifikaatfoute sodat HTTPS-onderskepping nie deur Burp se plaaslik gegenereerde sertifikaat geblokkeer word nie.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-bewuste blaaieroutomatisering (OpenBurp)

Die Burp MCP-verbinding en die onderskepte blaaierpad is afsonderlike datavloeie. Die MCP-diens stel Burp-nutsgoed op `127.0.0.1:9876` beskikbaar, terwyl ’n toegewyde Chromium-instansie sy HTTP(S)-verkeer deur Burp se proxy op `127.0.0.1:8080` stuur. Versoeke wat direk deur ’n MCP-nutsding gegenereer word, kan dus afwesig wees in **Proxy > HTTP history**; gebruik die proxied blaaier wanneer die versoek/reaksie waarneembaar, redigeerbaar of as bewyse bewaar moet word.<sup>[[2]](#references)[[9]](#references)</sup>

’n Kliënt met SSE-ondersteuning kan Burp direk registreer. ’n Kliënt wat net stdio ondersteun, kan eerder PortSwigger se proxy-JAR begin. Registreer in albei gevalle ’n tweede blaaierbeheer-MCP en wys dit na Burp se ingebedde Chromium (`BURP_CHROMIUM` is ’n plaaslike uitvoerbare lêerpad):<sup>[[9]](#references)</sup>

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

Die TLS-bypass-vlag aanvaar sertifikate wat deur die interception proxy gegenereer word, terwyl `--isolated` verhoed dat die assessering die operateur se gewone browser-profiel hergebruik. Isolasie beskerm die profieltoestand, maar is **nie ’n security sandbox nie**: die controller kan steeds toegang kry tot geverifieerde sessies wat in daardie toetsbrowser oopgemaak is, en die Burp MCP kan sensitiewe versoeke, response en konfigurasie blootstel.<sup>[[9]](#references)</sup>

Toets die SSE-listener onafhanklik voordat jy die client bridge debug:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

’n Gesonde listener gee `Content-Type: text/event-stream` terug. ’n Time-out ná die headers is verwag, omdat ’n SSE-stroom oop bly vir toekomstige events. As die client steeds misluk, bevestig die uitbreiding se ingestelde roete: PortSwigger merk op dat die endpoint die wortelpad of `/sse` kan wees, afhangend van die client en uitbreiding se konfigurasie.<sup>[[9]](#references)[[7]](#references)</sup>

## Gebruik van verskillende clients

### Codex CLI

- Stel `~/.codex/config.toml` soos hierbo in.
- Begin `codex`, en voer dan `/mcp` uit om die lys Burp-tools te verifieer.

### Gemini CLI

Die **burp-mcp-agents**-repo bied launcher-hulpmiddels:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (plaaslik)

Gebruik die verskafde launcher-helper en kies ’n plaaslike model:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Voorbeeld van plaaslike modelle en benaderde VRAM-vereistes:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Bewysgedrewe replay en validering

Moenie toelaat dat die agent ’n geloofwaardige verduideliking of ’n tussentydse antwoord as bewys beskou nie. Gebruik Burp-versoeke/-antwoorde en onafhanklik waargenome blaaierstatus om elke toets falsifieerbaar te maak.<sup>[[8]](#references)</sup>

1. Stoor ’n basislynversoek/-antwoord-paar en identifiseer die presiese komponent wat deur die aanvaller beheer word.
2. Vir magtigingsvergelykings, neem dieselfde werkvloei onafhanklik onder albei rekeninge vas voordat jy identifiseerders, koekies of tokens wysig.
3. Teken die hipotese, bewysligging, verwagte sein en die resultaat wat dit sou weerlê aan voordat jy ’n wysiging replay.
4. Wysig een komponent op ’n slag, bewaar die resulterende paar en merk direkte waarnemings apart van afleidings.
5. Volg elke kandidaat as `open`, `blocked`, `rejected` of `confirmed`; ondersoek dit weer slegs wanneer nuwe bewyse die meganisme of ’n voorvereiste verander.
6. Bevestig beheer deur die aanvaller, bereikbaarheid, herhaalbaarheid, omseiling van beperkings, impak en die finale toepassingstatus. ’n Herleiding of suksesvolle nutsoproep is nie bewys as die beweerde statusverandering stroomaf plaasvind nie.

Hou die uitbuitingsbesonderhede op die toepaslike tegniekbladsy. Blaaierboodskap-kandidate hoort byvoorbeeld in [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), terwyl token-sleutelkeusegedrag by [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) hoort.<sup>[[8]](#references)</sup>

’n Kompakte hipotese-rekord keer dat parallelle agente dieselfde aanloklike vertakking herhaal:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## WebSocket frame-triage met Burp MCP

Die amptelike uitbreiding stel `get_proxy_websocket_history_regex` beskikbaar vir leesalleen, gepagineerde soektogte deur Burp se WebSocket-geskiedenis. Dit neem `regex`, `count` en `offset`; anders as `send_http1_request`, stuur dit nie ’n WebSocket-frame nie. Burp teken boodskappe in albei rigtings aan, selfs wanneer Intercept af is, so filter die geskiedenis voordat jy die model ’n klein stel relevante frames gee.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Voer dieselfde WebSocket-gesteunde handeling deur die Burp-geproksideerde blaaier uit met twee onafhanklik geverifieerde toetsrekeninge. Hou elke upgrade-handdruk en sy koekies, die verbinding-ID, die frame-rigting en die antwoordframes bymekaar; ’n bediener-na-kliënt-gebeurtenis op die eerste rekening se verbinding is nie bewys dat die tweede rekening dit ontvang het nie.
2. Soek met `get_proxy_websocket_history_regex` deur ’n nou uitdrukking soos `(?i)(subscribe|room|tenant|objectId)`, `count: 20` en `offset: 0` te gebruik. Verhoog `offset` om latere treffers te inspekteer. Vergelyk die uitgaande frame se objek- of onderwerpidentifiseerder met die antwoord op daardie **selfde verbinding**.
3. Stuur die kandidaat-uitgaande frame in **Proxy > WebSockets history** na Repeater. Koppel dit aan die toepaslike oop verbinding, of koppel weer met die tweede rekening se handdruk. Verander net die objek-/onderwerpidentifiseerder en vergelyk die gevolglike bedienerboodskappe en toepassingstoestand met albei basislyne. Die MCP-geskiedenisinstrument kan nie hierdie herhaling uitvoer nie; WebSocket Repeater kan frames wysig, weer stuur en weer koppel.

Gaan vir protokolspesifieke toetse soos cross-site WebSocket hijacking en magtiging vir broker-onderwerpe voort na [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Moenie ’n aanvaarde upgrade of ’n eggo aan die kliëntkant as bewys beskou dat ’n beskermde intekening geslaag het nie.

## Gerigte out-of-band-validering met Burp MCP

Burp Suite Professional stel `generate_collaborator_payload` en `get_collaborator_interactions` deur die amptelike MCP-uitbreiding beskikbaar. Kombineer dit met `get_proxy_http_history_regex` en ’n enkele `send_http1_request`-herhaling om ’n vermoedelike URL-ophaal aan die bedienerkant te toets sonder om die hele teiken te skandeer. Burp kan afsonderlike goedkeuring vereis om geskiedenis te lees en ’n versoek te stuur.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filter die geskiedenis vir ’n moontlike versoek wat ’n URL bevat, soos een met `url=`, `webhook` of `callback`. Stoor die oorspronklike versoek en antwoord. Die geskiedenisinstrument neem `regex`, `count` en `offset`; blaai deur die resultate eerder as om die model te vra om elke inskrywing te inspekteer.<sup>[[10]](#references)</sup>
2. Genereer ’n vars Collaborator-payload en behou die **payload-ID** wat teruggestuur word. Herhaal die vasgelegde versoek na dieselfde gasheer en poort en verander net die kandidaat-URL na ’n HTTPS-URL onder daardie payload-domein. Vir `send_http1_request`, gee die volledige HTTP/1.1-versoek as `content` saam met `targetHostname`, `targetPort` en `usesHttps`; die bestemmingsvelde identifiseer die **toepassing**, nie die Collaborator-gasheer nie.<sup>[[10]](#references)</sup>
3. Doen navraag by `get_collaborator_interactions` met daardie payload-ID en korreleer die interaksietyd met die herhaling. ’n HTTP-interaksie ondersteun dat daar ’n fetch plaasgevind het, terwyl DNS alleen slegs resolusie toon en nie ’n voltooide HTTP-versoek nie. Gaan die interaksiebron en versoekopskrifte na om uitgaande verkeer vanaf die bediener van laaiwerk aan die blaaiërkant te onderskei, en herhaal dan met ’n vars payload om onverwante verkeer uit te sluit.<sup>[[10]](#references)[[11]](#references)</sup>

Die MCP-versoekinstrument gee die antwoord direk terug en hoef dit nie in **Proxy > HTTP history** in te vul nie. Bewaar die versoek-/antwoordresultaat, of gebruik die geproksideerde blaaier of Repeater vir ’n artefak wat deur die geskiedenis ondersteun word. Gebruik vir SSRF-payloadkeuse en opvolgtoetse die [SSRF chapter](../pentesting-web/ssrf-server-side-request-forgery/) eerder as om ’n out-of-band-callback as bewys van impak op die interne netwerk te beskou. Sien [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow) om die MCP-bediener self te toets.<sup>[[7]](#references)[[11]](#references)</sup>

## Vraestel vir passiewe hersiening

Die **burp-mcp-agents**-bewaarplek bevat vraagsjabloon vir bewysgedrewe ontleding van Burp-verkeer:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: breë passiewe identifisering van kwesbaarhede.
- `idor_hunter.md`: IDOR/BOLA/objek-/tenant-afwykings en verifikasie-wanpassings.
- `auth_flow_mapper.md`: vergelyk geverifieerde en ongeverifieerde paaie.
- `ssrf_redirect_hunter.md`: SSRF-/oop-herleidingkandidate uit URL-ophaalparameters/herleidingskettings.
- `logic_flaw_hunter.md`: meerstap-logikafoute.
- `session_scope_hunter.md`: misbruik van token-gehoor/omvang.
- `rate_limit_abuse_hunter.md`: gapings in beperking van versoektempo/misbruik.
- `report_writer.md`: verslagdoening met die fokus op bewyse.

## Opsionele toeskrywingsmerker

Voeg ’n opskrifherskrywing (proxy of Burp Match/Replace) by om Burp-/LLM-verkeer in logs te merk:<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Veiligheidsnotas

- Verkies **plaaslike modelle** wanneer verkeer sensitiewe data bevat.
- Deel slegs die minimum bewyse wat vir ’n bevinding nodig is.
- Hou Burp as die bron van waarheid; gebruik die model vir **ontleding en verslagdoening**, nie vir skandering nie.

## Burp AI Agent (AI-ondersteunde triage + MCP-nutsmiddels)

**Burp AI Agent** is ’n Burp-uitbreiding wat plaaslike/wolk-LLM’s met passiewe/aktiewe ontleding (62 kwesbaarheidsklasse) kombineer en 53+ MCP-nutsmiddels blootstel sodat eksterne MCP-kliënte Burp kan orkestreer.<sup>[[5]](#references)</sup> Hoogtepunte:

- **Kontekskieslys-triage**: neem verkeer vas via Proxy, maak **Proxy > HTTP History** oop, regsklik op ’n request → **Extensions > Burp AI Agent > Analyze this request** om ’n AI-klets te begin wat aan daardie request/response gekoppel is.
- **Backends** (per profiel kiesbaar):
  - Plaaslike HTTP: **Ollama**, **LM Studio**.
  - Afgeleë HTTP: **OpenAI-versoenbare** endpoint (basis-URL + modelnaam).
  - Wolk-CLI’s: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` of `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (verskafferspesifieke aanmelding).
- **Agent-profiele**: prompt-sjablone word outomaties geïnstalleer onder `~/.burp-ai-agent/AGENTS/`; plaas ekstra `*.md`-lêers daar om pasgemaakte ontledings-/skanderingsgedrag by te voeg.
- **MCP-bediener**: aktiveer dit via **Settings > MCP Server** om Burp-bedrywighede aan enige MCP-kliënt beskikbaar te stel (53+ nutsmiddels). Claude Desktop kan na die bediener verwys word deur `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) of `%APPDATA%\Claude\claude_desktop_config.json` (Windows) te wysig.
- **Privaatheidskontroles**: STRICT / BALANCED / OFF redigeer sensitiewe request-data voordat dit na afgeleë modelle gestuur word; verkies plaaslike backends wanneer geheime hanteer word.
- **Ouditregistrasie**: JSONL-logs met SHA-256-integriteitshashing per inskrywing vir peuterwaarneembare naspeurbaarheid van AI/MCP-aksies.
- **Bou/laai**: laai die vrystelling-JAR af of bou met Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operasionele waarskuwings: wolk-agterkante kan sessiekoekies/PII eksfiltreer tensy privaatheidsmodus afgedwing word; MCP-blootstelling verleen afstandsorkestrering van Burp, dus beperk toegang tot vertroude agente en monitor die integriteitshash-ouditlogboek.



## References

- [1] [Burp MCP + Codex CLI-integrasie en Caddy-handdrukoplossing](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Streng Origin-/kopvalidasieprobleem in PortSwigger MCP-bediener](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP-agente (werkvloeie, lanseerders, prompt-pak)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Hoe om Codex vir Bug Bounty-navorsing te gebruik: verken wyd, valideer deeglik](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Burp Suite-orkestrering vir Claude Code en Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server se gereedskapimplementasies en parameters](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blinde SSRF-kwesbaarhede](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - WebSockets-geskiedenis](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Werk met WebSocket-boodskappe in Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
