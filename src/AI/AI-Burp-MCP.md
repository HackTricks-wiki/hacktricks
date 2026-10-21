# Burp MCP: Mapitio ya traffic kwa msaada wa LLM

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Extension ya **MCP Server** ya Burp inaweza kufichua traffic ya HTTP(S) iliyonaswa kwa clients za LLM zinazotumia MCP ili ziweze **kuchanganua requests/responses halisi** kwa ajili ya kugundua vulnerabilities na kuandaa ripoti. Ichukulie Burp kama chanzo cha ukweli: tumia uchanganuzi usioingilia au replay za makusudi za kigezo kimoja badala ya scanning bila mpango.<sup>[[8]](#references)</sup>

## Usanifu

- **Burp MCP Server (BApp)** husikiliza kwenye `127.0.0.1:9876` kwa chaguomsingi na hufichua traffic iliyonaswa kupitia MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** huunganisha stdio (upande wa client) na endpoint ya Burp ya MCP SSE.
- **Reverse proxy ya hiari ya ndani** (Caddy) hurekebisha headers kwa ukaguzi mkali wa handshake ya MCP.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), au Ollama (local).

## Usanidi

### 1) Sakinisha Burp MCP Server

Sakinisha **MCP Server** kutoka Burp BApp Store na uhakikishe inasikiliza kwenye `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Toa proxy JAR

Katika kichupo cha MCP Server, bofya **Extract server proxy jar** na uhifadhi `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Sanidi client ya MCP (mfano wa Codex)

Elekeza client kwenye proxy JAR na endpoint ya moja kwa moja ya Burp ya SSE. Proxy iliyofungashwa ni kiunganishi cha stdio-to-SSE; haichukui nafasi ya listener ya Burp.<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

Amri inayolingana ya Codex ni:<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

Kisha endesha Codex na uorodheshe zana za MCP:

```bash
codex
# inside Codex: /mcp
```

### 4) Rekebisha uthibitishaji mkali wa Origin/header kwa Caddy (ikihitajika)

Ikiwa handshake ya MCP itashindwa kwa sababu ya ukaguzi mkali wa `Origin` au headers za ziada, tumia reverse proxy ya ndani kusawazisha headers (hii ndiyo workaround ya tatizo la uthibitishaji mkali wa Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Anzisha proxy na client, kisha badilisha `--sse-url` iliyosanidiwa iwe `http://127.0.0.1:19876` tu unapotumia listener hii ya Caddy:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Linganisha hali ya kivinjari na ushahidi wa proxy (Playwright MCP)

Sanidi Playwright MCP ili kivinjari chake kitumie proxy ya Burp. Hii humwezesha agent kulinganisha hali ya DOM/accessibility iliyowasilishwa na historia halisi ya HTTP iliyoisababisha.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Rekebisha anwani ya listener, anzisha upya Codex, na utumie `/mcp` kuthibitisha miunganisho yote miwili. Mfano huu huzima makosa ya cheti cha browser ili interception ya HTTPS isizuiwe na cheti kilichozalishwa ndani ya kifaa na Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Otomatiki ya browser inayotambua proxy (OpenBurp)

Muunganisho wa Burp MCP na mtiririko wa browser unaoingiliwa ni njia mbili tofauti za data. Huduma ya MCP hutoa zana za Burp kwenye `127.0.0.1:9876`, huku instance maalum ya Chromium ikituma trafiki yake ya HTTP(S) kupitia proxy ya Burp kwenye `127.0.0.1:8080`. Kwa hiyo, huenda maombi yanayotumwa moja kwa moja na zana ya MCP yasionekane kwenye **Proxy > HTTP history**; tumia browser inayopitia proxy kila wakati ombi/jibu linapohitaji kuonekana, kuhaririwa, au kuhifadhiwa kama ushahidi.<sup>[[2]](#references)[[9]](#references)</sup>

Client inayotumia SSE inaweza kusajili Burp moja kwa moja. Client inayotumia stdio pekee inaweza kuzindua proxy JAR ya PortSwigger badala yake. Katika hali zote mbili, sajili MCP nyingine ya udhibiti wa browser na uielekeze kwenye Chromium iliyopachikwa ndani ya Burp (`BURP_CHROMIUM` ni njia ya ndani ya kifaa ya executable):<sup>[[9]](#references)</sup>

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

Bendera ya TLS-bypass inakubali vyeti vilivyotengenezwa na interception proxy, huku `--isolated` ikizuia assessment kutumia tena wasifu wa kawaida wa kivinjari wa operator. Isolation hulinda hali ya wasifu lakini **si sandbox ya usalama**: controller bado inaweza kufikia vipindi vilivyoidhinishwa vilivyofunguliwa kwenye kivinjari hicho cha majaribio, na Burp MCP inaweza kufichua maombi, majibu na usanidi nyeti.<sup>[[9]](#references)</sup>

Jaribu listener ya SSE kivyake kabla ya kutatua matatizo ya client bridge:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Msikilizaji anayofanya kazi vizuri hurudisha `Content-Type: text/event-stream`. Muda kuisha baada ya vichwa ni jambo linalotarajiwa kwa sababu mkondo wa SSE hubaki wazi kusubiri matukio yajayo. Ikiwa client bado inashindwa, thibitisha route iliyosanidiwa ya extension: PortSwigger inabainisha kuwa endpoint inaweza kuwa njia ya root au `/sse`, kutegemea client na usanidi wa extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Kutumia clients tofauti

### Codex CLI

- Sanidi `~/.codex/config.toml` kama ilivyo hapo juu.
- Endesha `codex`, kisha `/mcp` ili kuthibitisha orodha ya zana za Burp.

### Gemini CLI

Repo ya **burp-mcp-agents** hutoa visaidizi vya launcher:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (ya ndani)

Tumia kisaidizi cha kuzindua kilichotolewa na uchague modeli ya ndani:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Mifano ya local models na makadirio ya mahitaji ya VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Uchezaji upya na uthibitishaji unaoongozwa na ushahidi

Usimruhusu agent achukulie maelezo yanayoonekana kuwa sahihi au jibu la kati kama uthibitisho. Tumia requests/responses za Burp na hali ya browser iliyochunguzwa kwa kujitegemea ili kufanya kila jaribio liweze kukanushwa.<sup>[[8]](#references)</sup>

1. Hifadhi jozi ya baseline request/response na utambue kipengele halisi kinachodhibitiwa na mshambuliaji.
2. Kwa ulinganisho wa authorization, rekodi workflow ileile kivyake chini ya akaunti zote mbili kabla ya kubadilisha identifiers, cookies au tokens.
3. Kabla ya kucheza upya mabadiliko, rekodi hypothesis, mahali ushahidi ulipo, ishara inayotarajiwa na matokeo ambayo yangekanusha hypothesis hiyo.
4. Badilisha kipengele kimoja kwa wakati mmoja, hifadhi jozi inayotokana na utenganishe observations za moja kwa moja na inference.
5. Fuatilia kila candidate kama `open`, `blocked`, `rejected` au `confirmed`; irudie tu pale ushahidi mpya unapobadilisha mechanism au sharti la awali.
6. Thibitisha udhibiti wa mshambuliaji, ufikikaji, kurudiwa, bypass ya vikwazo, athari na hali ya mwisho ya application. Redirect au tool call iliyofaulu si uthibitisho ikiwa mabadiliko ya hali yanayodaiwa hutokea baadaye.

Weka maelezo ya exploitation kwenye ukurasa husika wa technique. Kwa mfano, candidates za browser-message zinahusu [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), huku tabia ya uteuzi wa funguo za token ikihusu [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Rekodi fupi ya hypothesis huzuia agents wanaofanya kazi kwa wakati mmoja kurudia mwelekeo uleule unaovutia:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Uthibitishaji wa out-of-band uliolengwa kwa Burp MCP

Burp Suite Professional hufichua `generate_collaborator_payload` na `get_collaborator_interactions` kupitia extension rasmi ya MCP. Vichanganye na `get_proxy_http_history_regex` na replay moja ya `send_http1_request` ili kupima URL fetch inayoshukiwa kufanywa na server bila kuchanganua target nzima. Huenda Burp ikahitaji idhini tofauti ya kusoma history na kutuma request.<sup>[[2]](#references)[[10]](#references)</sup>

1. Chuja history ili kupata request inayoweza kuwa na URL, kama ile iliyo na `url=`, `webhook`, au `callback`. Hifadhi request na response asilia. Tool ya history hupokea `regex`, `count`, na `offset`; pitia kurasa badala ya kuiomba model ichunguze kila entry.<sup>[[10]](#references)</sup>
2. Tengeneza payload mpya ya Collaborator na uhifadhi **payload ID** iliyorejeshwa. Replay request iliyonaswa kwa host na port ileile, ukibadilisha tu URL inayoshukiwa iwe URL ya HTTPS chini ya domain hiyo ya payload. Kwa `send_http1_request`, pitisha request kamili ya HTTP/1.1 kama `content` pamoja na `targetHostname`, `targetPort`, na `usesHttps`; sehemu za destination hutambulisha **application**, si host ya Collaborator.<sup>[[10]](#references)</sup>
3. Piga kura kwa `get_collaborator_interactions` ukitumia payload ID hiyo, kisha linganisha muda wa interaction na replay. Interaction ya HTTP inaunga mkono uwezekano wa fetch, ilhali DNS pekee huonyesha resolution lakini si kukamilika kwa HTTP request. Kagua chanzo cha interaction na request headers ili kutofautisha egress ya server na upakiaji wa upande wa browser, kisha rudia kwa payload mpya ili kuondoa uwezekano wa traffic isiyohusiana.<sup>[[10]](#references)[[11]](#references)</sup>

Tool ya MCP ya kutuma request hurejesha response moja kwa moja na huenda isiongeze entry kwenye **Proxy > HTTP history**. Hifadhi matokeo yake ya request/response au tumia browser iliyowekwa kupitia proxy au Repeater ili kupata ushahidi unaohifadhiwa kwenye history. Kwa uteuzi wa SSRF payload na majaribio yanayofuata, tumia [sura ya SSRF](../pentesting-web/ssrf-server-side-request-forgery/) badala ya kuchukulia out-of-band callback kama uthibitisho wa athari kwenye mtandao wa ndani. Ili kujaribu MCP server yenyewe, tazama [majaribio ya MCP server](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Seti ya prompt kwa ukaguzi wa passive

Repo ya **burp-mcp-agents** inajumuisha template za prompt za uchanganuzi wa Burp traffic unaotegemea ushahidi:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: Ugunduzi mpana wa vulnerabilities kwa njia ya passive.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift na kutolingana kwa auth.
- `auth_flow_mapper.md`: Linganisha njia za authenticated na zisizo authenticated.
- `ssrf_redirect_hunter.md`: Wagombea wa SSRF/open-redirect kutoka kwenye URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: Kasoro za logic zenye hatua nyingi.
- `session_scope_hunter.md`: Matumizi mabaya ya token audience/scope.
- `rate_limit_abuse_hunter.md`: Mapengo ya throttling/abuse.
- `report_writer.md`: Uandishi wa ripoti unaolenga ushahidi.

## Uwekaji wa hiari wa attribution tag

Ili kuweka tag kwenye Burp/LLM traffic kwenye logs, ongeza header rewrite (proxy au Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Vidokezo vya usalama

- Pendelea **local models** trafiki inapokuwa na data nyeti.
- Shiriki ushahidi wa kiwango cha chini tu unaohitajika kwa finding.
- Tumia Burp kama chanzo cha ukweli; tumia model kwa **uchanganuzi na kuripoti**, si kwa scanning.

## Burp AI Agent (uchanganuzi wa awali unaosaidiwa na AI + zana za MCP)

**Burp AI Agent** ni extension ya Burp inayounganisha LLM za ndani/cloud na uchanganuzi wa passive/active (madarasa 62 ya udhaifu), na hutoa zana 53+ za MCP ili MCP clients za nje ziweze kuendesha Burp.<sup>[[5]](#references)</sup> Mambo muhimu:

- **Uchanganzi wa awali kupitia menyu ya muktadha**: nasa trafiki kupitia Proxy, fungua **Proxy > HTTP History**, bofya kulia ombi → **Extensions > Burp AI Agent > Analyze this request** ili kufungua AI chat inayohusishwa na ombi/jibu hilo.
- **Backends** (zinaweza kuchaguliwa kwa kila profile):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: endpoint inayooana na **OpenAI** (base URL + jina la model).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` au `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (kuingia kulingana na provider).
- **Agent profiles**: prompt templates husakinishwa kiotomatiki chini ya `~/.burp-ai-agent/AGENTS/`; weka faili za ziada za `*.md` hapo ili kuongeza tabia maalum za uchanganuzi/scanning.
- **MCP server**: iwezeshe kupitia **Settings > MCP Server** ili kutoa operesheni za Burp kwa MCP client yoyote (zana 53+). Claude Desktop inaweza kuelekezwa kwenye server kwa kuhariri `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) au `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Vidhibiti vya faragha**: STRICT / BALANCED / OFF huficha data nyeti ya ombi kabla ya kuituma kwa remote models; pendelea backends za ndani unaposhughulikia siri.
- **Ukaguzi wa kumbukumbu**: kumbukumbu za JSONL zenye hashing ya uadilifu ya SHA-256 kwa kila ingizo, kwa ufuatiliaji unaoonyesha ushahidi wa kuchezea wa vitendo vya AI/MCP.
- **Build/load**: pakua JAR ya toleo au build kwa Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Tahadhari za kiutendaji: backend za cloud zinaweza kuiba session cookies/PII isipokuwa privacy mode iwe imewashwa; kufichua MCP huruhusu uendeshaji wa mbali wa Burp, kwa hivyo zuia ufikiaji kwa agents unaowaamini na fuatilia audit log yenye integrity hash.



## References

- [1] [Muunganisho wa Burp MCP + Codex CLI na marekebisho ya Caddy handshake](https://pentestbook.six2dez.com/others/burp)
- [2] [BApp ya Burp MCP Server](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Tatizo la uthibitishaji mkali wa Origin/header katika PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Jinsi ya kutumia Codex kwa utafiti wa Bug Bounty: chunguza kwa upana, thibitisha kwa umakini](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: uratibu wa Burp Suite kwa Claude Code na Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Utekelezaji wa zana na vigezo vya PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Udhaifu wa Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
