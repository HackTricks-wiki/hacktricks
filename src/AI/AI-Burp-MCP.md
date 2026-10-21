# Burp MCP: LLM-ondersteunde verkeershersiening

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Burp se **MCP Server**-uitbreiding kan onderskepte HTTP(S)-verkeer aan MCP-geskikte LLM-kliënte beskikbaar stel, sodat hulle oor werklike requests/responses kan **redeneer** om kwesbaarhede te ontdek en verslae op te stel. Hou Burp as die bron van waarheid: gebruik passiewe ontleding of doelbewuste herhalings met een veranderlike eerder as blind scanning.<sup>[[8]](#references)</sup>

## Argitektuur

- **Burp MCP Server (BApp)** luister by verstek op `127.0.0.1:9876` en stel onderskepte verkeer via MCP beskikbaar.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** oorbrug stdio (kliëntkant) na Burp se MCP SSE-endpoint.
- **Opsionele plaaslike reverse proxy** (Caddy) normaliseer headers vir streng MCP-handshake-kontroles.
- **Kliënte/backends**: Codex CLI (cloud), Gemini CLI (cloud) of Ollama (plaaslik).

## Opstelling

### 1) Installeer Burp MCP Server

Installeer **MCP Server** vanaf die Burp BApp Store en bevestig dat dit op `127.0.0.1:9876` luister.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Onttrek die proxy JAR

Klik in die MCP Server-oortjie op **Extract server proxy jar** en stoor `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Stel ’n MCP-kliënt op (Codex-voorbeeld)

Wys die kliënt na die proxy JAR en Burp se direkte SSE-endpoint. Die ingeslote proxy is ’n stdio-na-SSE-oorbrugging; dit vervang nie die Burp-listener nie.<sup>[[7]](#references)</sup>

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

As die MCP-handdruk weens streng `Origin`-kontroles of ekstra headers misluk, gebruik ’n plaaslike reverse proxy om headers te normaliseer (dit stem ooreen met die tydelike oplossing vir die Burp MCP-strengvalideringsprobleem).<sup>[[1]](#references)[[3]](#references)</sup>

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

Begin die proxy en die client, en verander die ingestelde `--sse-url` na `http://127.0.0.1:19876` slegs terwyl jy hierdie Caddy-listener gebruik:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Koppel blaaiertoestand aan proxy-bewyse (Playwright MCP)

Registreer Playwright MCP sodat sy blaaier Burp se proxy gebruik. Dit laat die agent toe om die weergegee DOM-/toeganklikheidstoestand te koppel aan die presiese HTTP-geskiedenis wat dit opgelewer het.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Pas die listener-adres aan, herbegin Codex en gebruik `/mcp` om albei integrasies te verifieer. Die voorbeeld deaktiveer blaaier-sertifikaatfoute sodat Burp se plaaslik gegenereerde sertifikaat nie HTTPS-onderskepping blokkeer nie.<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-bewuste blaaieroutomatisering (OpenBurp)

Die Burp MCP-verbinding en die onderskepte blaaierpad is afsonderlike datavloeie. Die MCP-diens stel Burp-gereedskap beskikbaar op `127.0.0.1:9876`, terwyl ’n toegewyde Chromium-instansie sy HTTP(S)-verkeer deur Burp se proxy op `127.0.0.1:8080` stuur. Versoeke wat direk deur ’n MCP-gereedskap gegenereer word, kan dus afwesig wees uit **Proxy > HTTP history**; gebruik die browser deur die proxy wanneer die versoek/antwoord waarneembaar, redigeerbaar of as bewys behou moet word.<sup>[[2]](#references)[[9]](#references)</sup>

’n Kliënt met SSE-ondersteuning kan Burp direk registreer. ’n Kliënt wat slegs stdio ondersteun, kan eerder PortSwigger se proxy-JAR begin. Registreer in albei gevalle ’n tweede browser-control MCP en wys dit na Burp se ingebedde Chromium (`BURP_CHROMIUM` is ’n plaaslike uitvoerbare lêerpad):<sup>[[9]](#references)</sup>

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

Die TLS-bypass-vlag aanvaar sertifikate wat deur die onderskeppingsproxy gegenereer word, terwyl `--isolated` voorkom dat die assessering die operateur se gewone blaaierprofiel hergebruik. Isolasie beskerm die profieltoestand, maar is **nie ’n sekuriteitsandbox nie**: die beheerder kan steeds toegang kry tot geverifieerde sessies wat in daardie toetsblaaier oopgemaak is, en die Burp MCP kan sensitiewe versoeke, antwoorde en konfigurasie blootlê.<sup>[[9]](#references)</sup>

Toets die SSE-luisteraar onafhanklik voordat jy die kliëntbrug ontfout:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

’n Gesonde listener gee `Content-Type: text/event-stream` terug. ’n Timeout ná die headers is verwag, omdat ’n SSE-stroom oop bly vir toekomstige events. As die kliënt steeds misluk, bevestig die uitbreiding se gekonfigureerde roete: PortSwigger merk op dat die endpoint die wortelpad of `/sse` kan wees, afhangend van die kliënt en die uitbreiding se konfigurasie.<sup>[[9]](#references)[[7]](#references)</sup>

## Gebruik van verskillende kliënte

### Codex CLI

- Stel `~/.codex/config.toml` op soos hierbo.
- Begin `codex`, en gebruik dan `/mcp` om die Burp-nutsgoedlys te verifieer.

### Gemini CLI

Die **burp-mcp-agents**-repo verskaf launcher-hulpmiddels:<sup>[[4]](#references)</sup>

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

Voorbeelde van plaaslike modelle en benaderde VRAM-behoeftes:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Bewysgedrewe herafspeel en validering

Moenie dat die agent ’n geloofwaardige verduideliking of ’n tussentydse antwoord as bewys beskou nie. Gebruik Burp-versoeke/-antwoorde en onafhanklik waargenome blaaierstatus om elke toets falsifiseerbaar te maak.<sup>[[8]](#references)</sup>

1. Stoor ’n basislynversoek/-antwoord-paar en identifiseer die presiese aanvaller-beheerde komponent.
2. Vir magtigingsvergelykings, leg die selfde werkvloei onafhanklik onder albei rekeninge vas voordat jy identifiseerders, koekies of tokens verander.
3. Teken die hipotese, bewysligging, verwagte sein en die resultaat wat dit sou weerlê aan voordat jy ’n verandering herafspeel.
4. Verander een komponent op ’n slag, bewaar die gevolglike paar en merk direkte waarnemings apart van afleidings.
5. Volg elke kandidaat as `open`, `blocked`, `rejected` of `confirmed`; herbesoek dit slegs wanneer nuwe bewyse die meganisme of ’n voorvereiste verander.
6. Bevestig aanvallerbeheer, bereikbaarheid, herhaalbaarheid, omseiling van beperkings, impak en die finale toepassingstatus. ’n Herleiding of suksesvolle tool-oproep is nie bewys as die beweerde statusverandering stroomaf plaasvind nie.

Hou die uitbuitingsbesonderhede op die relevante tegniekbladsy. Kandidate vir blaaierboodskappe hoort byvoorbeeld in [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), terwyl token-sleutelkeusegedrag in [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) hoort.<sup>[[8]](#references)</sup>

’n Kompakte hipotese-aantekening keer dat parallelle agente dieselfde aanloklike vertakking herhaal:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Gerigte buiteband-validering met Burp MCP

Burp Suite Professional stel `generate_collaborator_payload` en `get_collaborator_interactions` deur die amptelike MCP-uitbreiding beskikbaar. Kombineer dit met `get_proxy_http_history_regex` en ’n enkele `send_http1_request`-herhaling om ’n vermoedelike URL-ophaal deur die bedienerkant te toets sonder om die hele teiken te skandeer. Burp kan afsonderlike goedkeuring vereis om geskiedenis te lees en ’n versoek te stuur.<sup>[[2]](#references)[[10]](#references)</sup>

1. Filtreer die geskiedenis vir ’n kandidaatversoek wat ’n URL bevat, soos een met `url=`, `webhook` of `callback`. Stoor die oorspronklike versoek en antwoord. Die geskiedenisinstrument aanvaar `regex`, `count` en `offset`; blaai deur die resultate eerder as om die model elke inskrywing te laat ondersoek.<sup>[[10]](#references)</sup>
2. Genereer ’n nuwe Collaborator-payload en behou die teruggestuurde **payload ID**. Herhaal die vasgelegde versoek na dieselfde host en poort, en verander net die kandidaat-URL na ’n HTTPS-URL onder daardie payloaddomein. Vir `send_http1_request`, stuur die volledige HTTP/1.1-versoek as `content`, plus `targetHostname`, `targetPort` en `usesHttps`; die bestemmingsvelde identifiseer die **toepassing**, nie die Collaborator-host nie.<sup>[[10]](#references)</sup>
3. Vra `get_collaborator_interactions` met daardie payload-ID en korreleer die interaksietyd met die herhaling. ’n HTTP-interaksie ondersteun dat daar data opgehaal is, terwyl DNS alleen net resolusie toon, nie ’n voltooide HTTP-versoek nie. Kontroleer die interaksiebron en versoekkopskrifte om uitgaande verkeer van die bediener te onderskei van laaiaksies aan die blaaierskant, en herhaal dan met ’n nuwe payload om onverwante verkeer uit te sluit.<sup>[[10]](#references)[[11]](#references)</sup>

Die MCP-versoekinstrument gee die antwoord direk terug en hoef dit nie in **Proxy > HTTP history** te plaas nie. Bewaar die versoek-/antwoordresultaat, of gebruik die geproxiede blaaier of Repeater vir ’n artefak wat in die geskiedenis verskyn. Raadpleeg die [SSRF-hoofstuk](../pentesting-web/ssrf-server-side-request-forgery/) vir SSRF-payloadkeuse en opvolgtoetse, eerder as om ’n buiteband-callback as bewys van impak op ’n interne netwerk te beskou. Sien [MCP-bedienertoetsing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow) om die MCP-bediener self te toets.<sup>[[7]](#references)[[11]](#references)</sup>

## Prompt-pakket vir passiewe hersiening

Die **burp-mcp-agents**-bewaarplek bevat prompt-sjablone vir bewysgedrewe ontleding van Burp-verkeer:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: breë passiewe opsporing van kwesbaarhede.
- `idor_hunter.md`: IDOR/BOLA-/objek-/tenant-afwykings en wanpassings in verifikasie.
- `auth_flow_mapper.md`: vergelyk geverifieerde en ongeverifieerde paaie.
- `ssrf_redirect_hunter.md`: SSRF-/oop-herleidingkandidate uit URL-ophaalparameters en herleidingskettings.
- `logic_flaw_hunter.md`: meerstap-logikafoute.
- `session_scope_hunter.md`: misbruik van token-gehoor/scope.
- `rate_limit_abuse_hunter.md`: gapings in beperking en misbruikbeheer.
- `report_writer.md`: bewysgefokusde verslagdoening.

## Opsionele toeskrywingsetikettering

Voeg ’n header-herskrywing by (proxy of Burp Match/Replace) om Burp-/LLM-verkeer in logs te merk:<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Veiligheidsaantekeninge

- Verkies **local models** wanneer traffic sensitiewe data bevat.
- Deel slegs die minimum bewyse wat vir ’n bevinding nodig is.
- Hou Burp as die bron van waarheid; gebruik die model vir **analise en verslagdoening**, nie vir scanning nie.

## Burp AI Agent (AI-ondersteunde triage + MCP tools)

**Burp AI Agent** is ’n Burp-uitbreiding wat local/cloud LLMs met passiewe/aktiewe analise (62 kwesbaarheidsklasse) kombineer en 53+ MCP tools beskikbaar stel sodat eksterne MCP-kliënte Burp kan orkestreer.<sup>[[5]](#references)</sup> Hoogtepunte:

- **Kontekskieslys-triage**: neem traffic vas via Proxy, maak **Proxy > HTTP History** oop, regsklik op ’n versoek → **Extensions > Burp AI Agent > Analyze this request** om ’n AI-klets te begin wat aan daardie versoek/reaksie gekoppel is.
- **Backends** (kiesbaar per profiel):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: **OpenAI-compatible** endpoint (basis-URL + modelnaam).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` of `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (verskafferspesifieke aanmelding).
- **Agent-profiele**: prompt-sjablone word outomaties geïnstalleer onder `~/.burp-ai-agent/AGENTS/`; plaas bykomende `*.md`-lêers daar om pasgemaakte analise-/scanning-gedrag by te voeg.
- **MCP-bediener**: aktiveer via **Settings > MCP Server** om Burp-bedrywighede aan enige MCP-kliënt beskikbaar te stel (53+ tools). Claude Desktop kan met die bediener verbind word deur `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) of `%APPDATA%\Claude\claude_desktop_config.json` (Windows) te wysig.
- **Privaatheidskontroles**: STRICT / BALANCED / OFF redigeer sensitiewe versoekdata voordat dit na remote models gestuur word; verkies local backends wanneer geheime hanteer word.
- **Ouditregistrasie**: JSONL-logboeke met SHA-256-integriteitshashing per inskrywing vir peuterbestande naspeurbaarheid van AI/MCP-aksies.
- **Bou/laai**: laai die JAR-vrystelling af of bou met Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operasionele waarskuwings: cloud backends kan sessiekoekies/PII eksfiltreer tensy privaatheidsmodus afgedwing word; MCP-blootstelling verleen afstandsorkestrasie van Burp, beperk dus toegang tot vertroude agents en monitor die integriteitshashed ouditlogboek.



## References

- [1] [Burp MCP + Codex CLI-integrasie en Caddy-handshake-herstel](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP-bediener se streng Origin-/header-valideringskwessie](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP-agente (werkvloeie, lanseerders, prompt-pakket)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp KI-agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Hoe om Codex vir Bug Bounty-navorsing te gebruik: verken breed, valideer streng](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Burp Suite-orkestrasie vir Claude Code en Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server-gereedskapimplementasies en -parameters](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - blinde SSRF-kwesbaarhede](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
