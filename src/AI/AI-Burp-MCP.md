# Burp MCP: Ukaguzi wa traffic kwa usaidizi wa LLM

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Extension ya **MCP Server** ya Burp inaweza kufanya traffic ya HTTP(S) iliyonaswa ipatikane kwa wateja wa LLM wanaoweza kutumia MCP, ili waweze **kuchanganua requests/responses halisi** kwa ajili ya kugundua udhaifu na kuandaa ripoti. Ichukulie Burp kama chanzo cha ukweli: tumia uchanganuzi tulivu au urudie requests kwa makusudi, ukibadilisha kigezo kimoja tu, badala ya kufanya scanning bila mpango.<sup>[[8]](#references)</sup>

## Usanifu

- **Burp MCP Server (BApp)** husikiliza `127.0.0.1:9876` kwa chaguomsingi na hufichua traffic iliyonaswa kupitia MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** huunganisha stdio (upande wa client) na endpoint ya MCP SSE ya Burp.
- **Reverse proxy ya ndani ya hiari** (Caddy) hurekebisha headers kwa ukaguzi mkali wa MCP handshake.
- **Wateja/backend**: Codex CLI (cloud), Gemini CLI (cloud), au Ollama (local).

## Usanidi

### 1) Sakinisha Burp MCP Server

Sakinisha **MCP Server** kutoka Burp BApp Store na uthibitishe kuwa inasikiliza kwenye `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Toa proxy JAR

Kwenye kichupo cha MCP Server, bofya **Extract server proxy jar** na uhifadhi `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Sanidi client ya MCP (mfano wa Codex)

Elekeza client kwenye proxy JAR na endpoint ya moja kwa moja ya SSE ya Burp. Proxy iliyofungashwa ni daraja la stdio-to-SSE; haichukui nafasi ya listener ya Burp.<sup>[[7]](#references)</sup>

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

Kisha endesha Codex na uorodheshe MCP tools:

```bash
codex
# inside Codex: /mcp
```

### 4) Rekebisha uthibitishaji mkali wa Origin/header kwa kutumia Caddy (ikihitajika)

Ikiwa handshake ya MCP itashindwa kwa sababu ya ukaguzi mkali wa `Origin` au headers za ziada, tumia reverse proxy ya ndani ili kusawazisha headers (hii inalingana na workaround ya tatizo la uthibitishaji mkali wa Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>

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

Anzisha proxy na client, na ubadilishe `--sse-url` iliyosanidiwa iwe `http://127.0.0.1:19876` wakati tu unapotumia listener hii ya Caddy:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) Oanisha hali ya browser na ushahidi wa proxy (Playwright MCP)

Sajili Playwright MCP ili browser yake itumie proxy ya Burp. Hii humwezesha agent kulinganisha hali ya DOM/accessibility iliyo-renderiwa na historia halisi ya HTTP iliyoizalisha.<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Rekebisha anwani ya listener, anzisha upya Codex, na utumie `/mcp` kuthibitisha integrations zote mbili. Mfano huu huzima ukaguzi wa cheti cha browser ili Burp isizuie interception ya HTTPS kwa sababu ya cheti chake kilichozalishwa ndani.<sup>[[6]](#references)[[8]](#references)</sup>

## Uendeshaji wa kiotomatiki wa browser unaotumia proxy (OpenBurp)

Muunganisho wa Burp MCP na njia ya browser inayointerceptiwa ni mtiririko tofauti wa data. Huduma ya MCP hutoa zana za Burp kwenye `127.0.0.1:9876`, ilhali instance maalum ya Chromium hutuma trafiki yake ya HTTP(S) kupitia proxy ya Burp kwenye `127.0.0.1:8080`. Kwa hiyo, huenda maombi yanayotolewa moja kwa moja na zana ya MCP yasionekane kwenye **Proxy > HTTP history**; tumia browser inayopita kwenye proxy wakati ombi/jibu linahitaji kuonekana, kuhaririwa, au kuhifadhiwa kama ushahidi.<sup>[[2]](#references)[[9]](#references)</sup>

Client inayotumia SSE inaweza kusajili Burp moja kwa moja. Client inayotumia stdio pekee inaweza kuzindua proxy JAR ya PortSwigger badala yake. Katika hali zote mbili, sajili MCP ya pili ya udhibiti wa browser na uielekeze kwenye Chromium iliyopachikwa ndani ya Burp (`BURP_CHROMIUM` ni njia ya executable ya ndani):<sup>[[9]](#references)</sup>

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

Bendera ya TLS-bypass inakubali vyeti vilivyotengenezwa na interception proxy, huku `--isolated` ikizuia tathmini kutumia tena wasifu wa kawaida wa kivinjari wa operator. Isolation hulinda hali ya wasifu lakini **si sandbox ya usalama**: controller bado inaweza kufikia vipindi vilivyoidhinishwa vilivyofunguliwa kwenye kivinjari hicho cha majaribio, na Burp MCP inaweza kufichua maombi, majibu na usanidi nyeti.<sup>[[9]](#references)</sup>

Jaribu SSE listener kivyake kabla ya kutatua matatizo ya client bridge:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

Listener inayofanya kazi vizuri hurudisha `Content-Type: text/event-stream`. Timeout baada ya headers ni jambo linalotarajiwa kwa sababu stream ya SSE hubaki wazi kwa ajili ya events za baadaye. Ikiwa client bado inashindwa, thibitisha route iliyosanidiwa ya extension: PortSwigger inaeleza kuwa endpoint inaweza kuwa root path au `/sse`, kutegemea client na usanidi wa extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Kutumia clients tofauti

### Codex CLI

- Sanidi `~/.codex/config.toml` kama ilivyo hapo juu.
- Endesha `codex`, kisha `/mcp` ili kuthibitisha orodha ya tools za Burp.

### Gemini CLI

Repo ya **burp-mcp-agents** hutoa wasaidizi wa launcher:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (ya ndani)

Tumia launcher helper iliyotolewa na uchague modeli ya ndani:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

Mifano ya local models na mahitaji ya takriban ya VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Uchezaji upya na uthibitishaji unaotegemea ushahidi

Usimruhusu agent achukulie maelezo yanayoonekana kuwa ya kweli au jibu la kati kama uthibitisho. Tumia maombi/majibu ya Burp na hali ya browser uliyoiona kwa kujitegemea ili kufanya kila jaribio liweze kukanushwa.<sup>[[8]](#references)</sup>

1. Hifadhi jozi ya msingi ya ombi/jibu na utambue kipengele halisi kinachodhibitiwa na mshambuliaji.
2. Kwa ulinganisho wa uidhinishaji, rekodi workflow ileile kivyake chini ya akaunti zote mbili kabla ya kubadilisha vitambulishi, cookies au tokens.
3. Kabla ya kucheza upya mabadiliko, rekodi dhana, eneo la ushahidi, ishara inayotarajiwa na matokeo ambayo yangeikanusha.
4. Badilisha kipengele kimoja kwa wakati mmoja, hifadhi jozi inayotokana na utenganishe uchunguzi wa moja kwa moja na makisio.
5. Fuatilia kila mgombea kama `open`, `blocked`, `rejected` au `confirmed`; ichunguze tena tu ushahidi mpya unapobadilisha utaratibu au sharti la awali.
6. Thibitisha udhibiti wa mshambuliaji, ufikikaji, uwezekano wa kurudiwa, kupitishwa kwa kizuizi, athari na hali ya mwisho ya programu. Redirect au mwito wa tool uliofaulu si uthibitisho ikiwa mabadiliko ya hali yanayodaiwa hutokea baadaye.

Hifadhi maelezo ya exploitation katika ukurasa husika wa mbinu. Kwa mfano, wagombea wa browser-message wanahusika na [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), ilhali tabia ya token key-selection inahusika na [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Rekodi fupi ya dhana huzuia agents wanaofanya kazi sambamba kurudia njia ileile inayovutia:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## WebSocket frame triage kwa Burp MCP

Extension rasmi hutoa `get_proxy_websocket_history_regex` kwa utafutaji wa kusoma pekee, wenye pagination, kwenye historia ya WebSocket ya Burp. Inapokea `regex`, `count`, na `offset`; tofauti na `send_http1_request`, haitumi frame ya WebSocket. Burp huhifadhi ujumbe wa pande zote mbili hata Intercept ikiwa imezimwa, kwa hivyo chuja historia kabla ya kumpa model seti ndogo ya frame husika.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Tekeleza kitendo hicho hicho kinachotumia WebSocket kupitia browser inayopita kwenye Burp, ukitumia akaunti mbili za majaribio zilizo-authenticate kivyake. Weka pamoja kila upgrade handshake na cookies zake, connection ID, mwelekeo wa frame, na frame za majibu; tukio la server-to-client kwenye connection ya akaunti ya kwanza si ushahidi kwamba akaunti ya pili ililipokea.
2. Tafuta kwa `get_proxy_websocket_history_regex` ukitumia expression finyu kama `(?i)(subscribe|room|tenant|objectId)`, `count: 20`, na `offset: 0`. Ongeza `offset` ili kuchunguza matches za baadaye. Linganisha kitambulishi cha object au topic kwenye frame ya outbound na jibu kwenye **connection hiyo hiyo**.
3. Kwenye **Proxy > WebSockets history**, tuma frame inayoshukiwa kuwa ya outbound kwenda Repeater. Iambatishe kwenye connection iliyo wazi inayofaa au unganisha tena ukitumia handshake ya akaunti ya pili. Badilisha kitambulishi cha object/topic pekee, kisha linganisha ujumbe wa server na hali ya application inayotokana na jaribio hilo dhidi ya baseline zote mbili. Zana ya historia ya MCP haiwezi kufanya replay hii; WebSocket Repeater inaweza kuhariri, kutuma tena, na kuunganisha upya frame.

Kwa majaribio mahususi ya protocol kama cross-site WebSocket hijacking na uidhinishaji wa broker topic, endelea kwenye [WebSocket Attacks](../pentesting-web/websocket-attacks.md). Usichukulie upgrade iliyokubaliwa au echo ya upande wa client kuwa ushahidi kwamba subscription iliyolindwa ilifaulu.

## Uthibitishaji mahususi wa out-of-band kwa Burp MCP

Burp Suite Professional hutoa `generate_collaborator_payload` na `get_collaborator_interactions` kupitia extension rasmi ya MCP. Zitumie pamoja na `get_proxy_http_history_regex` na replay moja ya `send_http1_request` ili kujaribu URL fetch inayoshukiwa kufanywa upande wa server bila kuchanganua target nzima. Huenda Burp ikahitaji idhini tofauti ya kusoma historia na kutuma request.<sup>[[2]](#references)[[10]](#references)</sup>

1. Chuja historia ili kupata request inayoweza kuwa na URL, kama ile yenye `url=`, `webhook`, au `callback`. Hifadhi request na response ya awali. Zana ya historia inapokea `regex`, `count`, na `offset`; tumia pagination badala ya kumwomba model ichunguze kila entry.<sup>[[10]](#references)</sup>
2. Tengeneza Collaborator payload mpya na uhifadhi **payload ID** inayorejeshwa. Replay request iliyonaswa kwenda host na port ileile, ukibadilisha URL inayoshukiwa pekee iwe URL ya HTTPS chini ya payload domain hiyo. Kwa `send_http1_request`, pitisha request kamili ya HTTP/1.1 kama `content` pamoja na `targetHostname`, `targetPort`, na `usesHttps`; sehemu za destination zinabainisha **application**, si host ya Collaborator.<sup>[[10]](#references)</sup>
3. Kagua `get_collaborator_interactions` kwa kutumia payload ID hiyo na ulinganishe muda wa interaction na replay. Interaction ya HTTP inaunga mkono uwezekano wa fetch, ilhali DNS pekee huonyesha utatuzi wa jina tu, si kukamilika kwa HTTP request. Kagua chanzo cha interaction na request headers ili kutofautisha egress ya server na upakiaji wa upande wa browser, kisha rudia kwa payload mpya ili kuondoa uwezekano wa traffic isiyohusiana.<sup>[[10]](#references)[[11]](#references)</sup>

Zana ya MCP ya request hurejesha response moja kwa moja na si lazima ijaze **Proxy > HTTP history**. Hifadhi matokeo ya request/response au tumia browser inayopita kwenye proxy au Repeater kupata ushahidi unaohifadhiwa kwenye historia. Kwa uteuzi wa SSRF payload na majaribio yanayofuata, tumia [sura ya SSRF](../pentesting-web/ssrf-server-side-request-forgery/) badala ya kuchukulia out-of-band callback kuwa ushahidi wa athari kwenye mtandao wa ndani. Kwa kujaribu server ya MCP yenyewe, angalia [upimaji wa server ya MCP](AI-MCP-Servers.md#remote-mcp-server-testing-workflow).<sup>[[7]](#references)[[11]](#references)</sup>

## Prompt pack ya ukaguzi wa passiv

Repo ya **burp-mcp-agents** ina prompt templates za uchanganuzi wa traffic ya Burp unaotegemea ushahidi:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: ugunduzi mpana wa vulnerabilities kwa njia ya passiv.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift na kutolingana kwa auth.
- `auth_flow_mapper.md`: linganisha njia zenye na zisizo na uthibitishaji.
- `ssrf_redirect_hunter.md`: wagombea wa SSRF/open-redirect wanaotokana na URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: dosari za logic za hatua nyingi.
- `session_scope_hunter.md`: matumizi mabaya ya token audience/scope.
- `rate_limit_abuse_hunter.md`: mapengo ya throttling/abuse.
- `report_writer.md`: uandishi wa ripoti unaozingatia ushahidi.

## Uwekaji wa hiari wa attribution tag

Ili kuweka tag kwenye traffic ya Burp/LLM kwenye logs, ongeza header rewrite (proxy au Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## Maelezo ya usalama

- Pendelea **miundo ya ndani** wakati trafiki ina data nyeti.
- Shiriki ushahidi wa kiwango cha chini tu unaohitajika kuthibitisha matokeo.
- Ichukulie Burp kama chanzo cha ukweli; tumia model kwa **uchanganuzi na kuripoti**, si kwa scanning.

## Burp AI Agent (uchujaji wa awali unaosaidiwa na AI + zana za MCP)

**Burp AI Agent** ni kiendelezi cha Burp kinachounganisha LLM za ndani/wingu na uchanganuzi tulivu/amilifu (madarasa 62 ya udhaifu), na kutoa zana 53+ za MCP ili wateja wa nje wa MCP waweze kuratibu Burp.<sup>[[5]](#references)</sup> Muhimu:

- **Uchujaji wa awali kupitia menyu ya muktadha**: nasa trafiki kupitia Proxy, fungua **Proxy > HTTP History**, bofya ombi kwa kitufe cha kulia → **Extensions > Burp AI Agent > Analyze this request** ili kufungua gumzo la AI linalohusishwa na ombi/jibu hilo.
- **Backends** (zinaweza kuchaguliwa kwa kila profile):
  - HTTP ya ndani: **Ollama**, **LM Studio**.
  - HTTP ya mbali: endpoint inayooana na **OpenAI** (base URL + jina la model).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` au `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (kuingia kunategemea mtoa huduma).
- **Profaili za agent**: violezo vya prompt husakinishwa kiotomatiki chini ya `~/.burp-ai-agent/AGENTS/`; weka faili za ziada za `*.md` hapo ili kuongeza tabia maalum za uchanganuzi/scanning.
- **Seva ya MCP**: iwezeshe kupitia **Settings > MCP Server** ili kuruhusu mteja yeyote wa MCP kutumia utendaji wa Burp (zana 53+). Claude Desktop inaweza kuelekezwa kwenye seva kwa kuhariri `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) au `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Vidhibiti vya faragha**: STRICT / BALANCED / OFF huficha data nyeti ya ombi kabla ya kuituma kwa modeli za mbali; pendelea backends za ndani unaposhughulikia siri.
- **Ukaguzi wa kumbukumbu**: kumbukumbu za JSONL zenye hashing ya uadilifu ya SHA-256 kwa kila ingizo, ili kuwezesha ufuatiliaji unaobaini kuchezea kumbukumbu kwa vitendo vya AI/MCP.
- **Build/load**: pakua JAR ya toleo au build kwa Java 21:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Tahadhari za kiutendaji: backend za cloud zinaweza kuiba session cookies/PII isipotekelezwa privacy mode; kufichua MCP huruhusu uendeshaji wa mbali wa Burp, kwa hivyo zuia ufikiaji kwa agents zinazoaminika na fuatilia logi ya ukaguzi yenye hash ya uadilifu.



## References

- [1] [Muunganisho wa Burp MCP + Codex CLI na marekebisho ya Caddy handshake](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Suala la uthibitishaji mkali wa Origin/header katika PortSwigger MCP server](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Jinsi ya kutumia Codex kwa utafiti wa Bug Bounty: chunguza kwa upana, thibitisha kwa ukali](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: uratibu wa Burp Suite kwa Claude Code na Codex](https://github.com/luispacheco22/OpenBurp)
- [10] [Utekelezaji wa zana na vigezo vya PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Udhaifu wa Blind SSRF](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - Historia ya WebSockets](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Kufanya kazi na ujumbe wa WebSocket katika Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
