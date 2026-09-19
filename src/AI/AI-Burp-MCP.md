# Burp MCP: mapitio ya traffic kwa msaada wa LLM

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Extension ya **MCP Server** ya Burp inaweza kuwasilisha traffic ya HTTP(S) iliyonaswa kwa clients za LLM zenye uwezo wa MCP ili ziweze **kufanya reasoning juu ya requests/responses halisi** kwa ajili ya kugundua vulnerabilities na kuandaa rasimu za reports.<sup>[[8]](#references)</sup> Burp ibaki kuwa chanzo cha ukweli: tumia passive analysis au replays za makusudi za variable moja badala ya blind scanning.

## Muundo

- **Burp MCP Server (BApp)** husikiliza `127.0.0.1:9876` kwa default na huwasilisha traffic iliyonaswa kupitia MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** huunganisha stdio (upande wa client) na Burp's MCP SSE endpoint.
- **Optional local reverse proxy** (Caddy) husawazisha headers kwa ajili ya strict MCP handshake checks.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), au Ollama (local).

## Usanidi

### 1) Install Burp MCP Server

Install **MCP Server** kutoka Burp BApp Store na uhakikishe kuwa inasikiliza `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extract proxy JAR

Katika MCP Server tab, bofya **Extract server proxy jar** na uhifadhi `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configure MCP client (mfano wa Codex)

Elekeza client kwenye proxy JAR na Burp's direct SSE endpoint. Proxy iliyopakiwa ni stdio-to-SSE bridge; haibadilishi Burp listener.<sup>[[7]](#references)</sup>
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
### 4) Rekebisha uthibitishaji mkali wa Origin/header kwa Caddy (ikiwa inahitajika)

Ikiwa MCP handshake itashindwa kwa sababu ya ukaguzi mkali wa `Origin` au headers za ziada, tumia reverse proxy ya ndani ili kurekebisha headers (hii inalingana na workaround ya tatizo la strict validation la Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Anzisha proxy na client, na ubadilishe `--sse-url` iliyosanidiwa kuwa `http://127.0.0.1:19876` wakati wa kutumia Caddy listener hii:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Oanisha hali ya browser na ushahidi wa proxy (Playwright MCP)

Sajili Playwright MCP ili browser yake itumie proxy ya Burp. Hii humwezesha agent kulinganisha hali ya DOM/accessibility iliyotolewa na historia halisi ya HTTP iliyoizalisha.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Rekebisha anwani ya listener, anzisha upya Codex, na utumie `/mcp` kuthibitisha integrations zote mbili. Mfano huu huzima makosa ya browser certificate ili HTTPS interception isizuiwe na certificate inayozalishwa locally na Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Browser automation inayotambua proxy (OpenBurp)

Muunganisho wa Burp MCP na njia ya browser iliyo-interceptiwa ni data flows tofauti. Huduma ya MCP hufichua Burp tools kwenye `127.0.0.1:9876`, ilhali instance maalum ya Chromium hutuma traffic yake ya HTTP(S) kupitia proxy ya Burp kwenye `127.0.0.1:8080`. Kwa hiyo, requests zinazozalishwa moja kwa moja na MCP tool zinaweza zisionekane kwenye **Proxy > HTTP history**; tumia browser inayotumia proxy wakati request/response inapaswa kuonekana, kuhaririwa, au kuhifadhiwa kama evidence.<sup>[[2]](#references)[[9]](#references)</sup>

Client yenye support ya SSE inaweza kusajili Burp moja kwa moja. Client ya stdio-only inaweza kuzindua proxy JAR ya PortSwigger badala yake. Katika hali zote mbili, sajili browser-control MCP ya pili na ielekeze kwenye Chromium iliyopachikwa ndani ya Burp (`BURP_CHROMIUM` ni local executable path):<sup>[[9]](#references)</sup>
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
Bendera ya TLS-bypass inakubali certificates zinazozalishwa na interception proxy, huku `--isolated` ikizuia assessment kutumia tena browser profile ya kawaida ya operator. Isolation inalinda hali ya profile lakini **si security sandbox**: controller bado inaweza kufikia authenticated sessions zilizofunguliwa katika test browser hiyo, na Burp MCP inaweza kufichua requests, responses, na configuration nyeti.<sup>[[9]](#references)</sup>

Test SSE listener kivyake kabla ya kuanza kutatua matatizo ya client bridge:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
Listener inayofanya kazi vizuri hurudisha `Content-Type: text/event-stream`. Timeout baada ya headers ni jambo linalotarajiwa kwa sababu SSE stream hubaki wazi kwa ajili ya events za baadaye. Ikiwa client bado inashindwa, thibitisha route iliyosanidiwa ya extension: PortSwigger inabainisha kuwa endpoint inaweza kuwa root path au `/sse`, kulingana na client na usanidi wa extension.<sup>[[9]](#references)[[7]](#references)</sup>

## Using different clients

### Codex CLI

- Sanidi `~/.codex/config.toml` kama ilivyo hapo juu.
- Endesha `codex`, kisha `/mcp` ili kuthibitisha orodha ya Burp tools.

### Gemini CLI

Repo ya **burp-mcp-agents** hutoa launcher helpers:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (ya ndani)

Tumia msaidizi wa launcher uliotolewa na uchague model ya ndani:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Mifano ya local models na mahitaji ya takriban ya VRAM:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Evidence-driven replay and validation

Usimruhusu agent kuchukulia maelezo yanayoonekana kuwa ya kimantiki au response ya kati kama ushahidi. Tumia requests/responses za Burp na hali ya browser iliyoonekana kwa kujitegemea ili kufanya kila test iweze kukanushwa.<sup>[[8]](#references)</sup>

1. Hifadhi jozi ya baseline request/response na utambue component halisi inayodhibitiwa na attacker.
2. Kwa ulinganishaji wa authorization, capture workflow hiyo hiyo kwa kujitegemea chini ya accounts zote mbili kabla ya kubadilisha identifiers, cookies, au tokens.
3. Kabla ya kureplay mutation, rekodi hypothesis, mahali pa ushahidi, signal inayotarajiwa, na matokeo ambayo yangeikanusha.
4. Badilisha component moja kwa wakati mmoja, hifadhi jozi inayotokana, na tenga observations za moja kwa moja na inference.
5. Fuatilia kila candidate kama `open`, `blocked`, `rejected`, au `confirmed`; irejee tu pale ushahidi mpya unapobadilisha mechanism au prerequisite.
6. Thibitisha attacker control, reachability, repeatability, constraint bypass, impact, na hali ya mwisho ya application. Redirect au tool call iliyofanikiwa si ushahidi ikiwa state change inayodaiwa inategemea hatua ya downstream.

Weka maelezo ya exploitation katika ukurasa wa technique husika. Kwa mfano, candidates za browser-message ni za [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), huku tabia ya token key-selection ikiwa ya [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Rekodi fupi ya hypothesis huwazuia agents wanaofanya kazi sambamba kurudia branch hiyo hiyo inayovutia:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Kifurushi cha prompts kwa passive review

Repo ya **burp-mcp-agents** inajumuisha prompt templates kwa uchanganuzi wa Burp traffic unaoongozwa na ushahidi:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: kuibua vulnerability kwa upana kupitia passive review.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift na auth mismatches.
- `auth_flow_mapper.md`: kulinganisha njia za authenticated na unauthenticated.
- `ssrf_redirect_hunter.md`: wagombea wa SSRF/open-redirect kutoka URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: logic flaws za hatua nyingi.
- `session_scope_hunter.md`: matumizi mabaya ya token audience/scope.
- `rate_limit_abuse_hunter.md`: mapengo ya throttling/abuse.
- `report_writer.md`: uandishi wa report unaozingatia ushahidi.

## Optional attribution tagging

Ili kuweka tag kwenye Burp/LLM traffic katika logs, ongeza header rewrite (proxy au Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Maelezo ya usalama

- Pendelea **local models** wakati traffic ina data nyeti.
- Shiriki ushahidi wa kiwango cha chini tu unaohitajika kwa finding.
- Weka Burp kama chanzo cha ukweli; tumia model kwa **analysis and reporting**, si kwa scanning.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** ni Burp extension inayounganisha local/cloud LLMs na passive/active analysis (madarasa 62 ya vulnerabilities), na kufichua MCP tools zaidi ya 53 ili MCP clients za nje ziweze kuendesha Burp.<sup>[[5]](#references)</sup> Mambo muhimu:

- **Context-menu triage**: capture traffic kupitia Proxy, fungua **Proxy > HTTP History**, bofya-kulia request → **Extensions > Burp AI Agent > Analyze this request** ili kuanzisha AI chat iliyofungwa kwenye request/response hiyo.
- **Backends** (zinazoweza kuchaguliwa kwa kila profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint inayooana na **OpenAI** (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` au `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates huwekwa kiotomatiki chini ya `~/.burp-ai-agent/AGENTS/`; weka faili za ziada za `*.md` hapo ili kuongeza custom analysis/scanning behaviors.
- **MCP server**: iwezeshe kupitia **Settings > MCP Server** ili kufichua Burp operations kwa MCP client yoyote (tools zaidi ya 53). Claude Desktop inaweza kuelekezwa kwenye server kwa kuhariri `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) au `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF huficha request data nyeti kabla ya kuituma kwa remote models; pendelea local backends unaposhughulikia secrets.
- **Audit logging**: JSONL logs zenye SHA-256 integrity hashing kwa kila entry, kwa traceability ya AI/MCP actions inayothibitisha ikiwa imechezewa.
- **Build/load**: pakua release JAR au build kwa kutumia Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Tahadhari za uendeshaji: cloud backends zinaweza ku-exfiltrate session cookies/PII isipokuwa privacy mode iwe imewezeshwa; MCP exposure inaruhusu remote orchestration ya Burp, kwa hivyo zuia access kwa agents unaowaamini na fuatilia audit log yenye integrity hash.

## References

- [1] [Burp MCP + Codex CLI integration na marekebisho ya Caddy handshake](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Tatizo la PortSwigger MCP server la strict Origin/header validation](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Jinsi ya kutumia Codex kwa utafiti wa Bug Bounty: chunguza kwa upana, thibitisha kwa ukali](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: orchestration ya Burp Suite kwa Claude Code na Codex](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
