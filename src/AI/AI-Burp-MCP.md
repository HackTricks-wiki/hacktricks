# Burp MCP: mapitio ya traffic yaliyosaidiwa na LLM

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Extension ya **MCP Server** ya Burp inaweza kufichua traffic ya HTTP(S) iliyonaswa kwa clients za LLM zenye uwezo wa MCP ili ziweze **kufanya reasoning juu ya requests/responses halisi** kwa ajili ya kugundua vulnerabilities na kuandaa ripoti. Iweke Burp kama chanzo cha ukweli: tumia passive analysis au replays za makusudi zenye kubadilisha variable moja badala ya blind scanning.<sup>[[8]](#references)</sup>

## Architecture

- **Burp MCP Server (BApp)** husikiliza kwenye `127.0.0.1:9876` kwa default na hufichua traffic iliyonaswa kupitia MCP.<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** huunganisha stdio (upande wa client) na Burp's MCP SSE endpoint.
- **Optional local reverse proxy** (Caddy) husawazisha headers kwa ukaguzi mkali wa MCP handshake.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), au Ollama (local).

## Usanidi

### 1) Install Burp MCP Server

Install **MCP Server** kutoka Burp BApp Store na uthibitishe kuwa inasikiliza kwenye `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extract proxy JAR

Kwenye MCP Server tab, bofya **Extract server proxy jar** na uhifadhi `mcp-proxy-all.jar`.<sup>[[7]](#references)</sup>

### 3) Configure MCP client (mfano wa Codex)

Elekeza client kwenye proxy JAR na Burp's direct SSE endpoint. Proxy iliyopakiwa ni stdio-to-SSE bridge; haibadilishi Burp listener.<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
Amri ya Codex inayolingana ni:<sup>[[7]](#references)[[8]](#references)</sup>
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

Ikiwa MCP handshake itashindwa kutokana na ukaguzi mkali wa `Origin` au headers za ziada, tumia reverse proxy ya ndani ili kurekebisha headers ziwe katika muundo unaofaa (hii inaendana na workaround ya tatizo la strict validation la Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Anzisha proxy na client, na ubadilishe `--sse-url` iliyosanidiwa kuwa `http://127.0.0.1:19876` tu unapotumia Caddy listener hii:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Oanisha browser state na ushahidi wa proxy (Playwright MCP)

Sajili Playwright MCP ili browser yake itumie proxy ya Burp. Hii humwezesha agent kuoanisha hali ya DOM/accessibility iliyoresishwa na historia halisi ya HTTP iliyoizalisha.<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Rekebisha anwani ya listener, anzisha upya Codex, kisha utumie `/mcp` kuthibitisha integrations zote mbili. Mfano huu huzima makosa ya browser certificate ili HTTPS interception isizuiwe na certificate iliyotengenezwa locally na Burp.<sup>[[6]](#references)[[8]](#references)</sup>

## Kutumia clients tofauti

### Codex CLI

- Sanidi `~/.codex/config.toml` kama ilivyo hapo juu.
- Endesha `codex`, kisha `/mcp` kuthibitisha orodha ya Burp tools.

### Gemini CLI

Repo ya **burp-mcp-agents** hutoa wasaidizi wa kuanzisha:<sup>[[4]](#references)</sup>
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

## Replay na validation inayoongozwa na ushahidi

Usimruhusu agent achukulie maelezo yanayoonekana kuwa sahihi au jibu la kati kama ushahidi. Tumia Burp requests/responses na browser state iliyochunguzwa kwa kujitegemea ili kufanya kila test iweze kuthibitishwa au kukanushwa.<sup>[[8]](#references)</sup>

1. Hifadhi jozi ya baseline request/response na tambua component kamili inayodhibitiwa na attacker.
2. Kwa ulinganishaji wa authorization, capture workflow hiyo hiyo kwa kujitegemea chini ya accounts zote mbili kabla ya kubadilisha identifiers, cookies, au tokens.
3. Kabla ya kureplay mutation, rekodi hypothesis, mahali ushahidi ulipo, signal inayotarajiwa, na matokeo ambayo yangekanusha hypothesis hiyo.
4. Badilisha component moja kwa wakati mmoja, hifadhi jozi inayotokana, na tenga observations za moja kwa moja na inference.
5. Fuatilia kila candidate kama `open`, `blocked`, `rejected`, au `confirmed`; irudie tu ushahidi mpya unapobadilisha mechanism au prerequisite.
6. Thibitisha attacker control, reachability, repeatability, constraint bypass, impact, na application state ya mwisho. Redirect au tool call iliyofaulu si ushahidi ikiwa state inayodaiwa kubadilika inategemea hatua za baadaye.

Weka maelezo ya exploitation kwenye technique page husika. Kwa mfano, browser-message candidates ni za [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md), huku tabia ya token key-selection ikiwa ya [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md).<sup>[[8]](#references)</sup>

Rekodi fupi ya hypothesis huwazuia agents wanaofanya kazi kwa parallel kurudia branch ileile inayovutia:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## Kifurushi cha prompts kwa mapitio ya passive

Repo ya **burp-mcp-agents** inajumuisha templates za prompts kwa uchanganuzi unaotegemea ushahidi wa Burp traffic:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: utafutaji mpana wa vulnerability za passive.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift na kutolingana kwa auth.
- `auth_flow_mapper.md`: kulinganisha njia za authenticated na unauthenticated.
- `ssrf_redirect_hunter.md`: wagombea wa SSRF/open-redirect kutoka kwa URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: logic flaws za hatua nyingi.
- `session_scope_hunter.md`: matumizi yasiyo sahihi ya token audience/scope.
- `rate_limit_abuse_hunter.md`: mapungufu ya throttling/abuse.
- `report_writer.md`: reporting inayolenga ushahidi.

## Tagging ya attribution ya hiari

Ili kuweka tag kwenye Burp/LLM traffic katika logs, ongeza header rewrite (proxy au Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Vidokezo vya usalama

- Pendelea **local models** wakati traffic ina data nyeti.
- Shiriki evidence ya kiwango cha chini kinachohitajika kwa finding.
- Weka Burp kama chanzo cha ukweli; tumia model kwa **analysis and reporting**, si kwa scanning.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** ni Burp extension inayounganisha local/cloud LLMs na passive/active analysis (madarasa 62 ya vulnerability) na kufichua MCP tools zaidi ya 53 ili external MCP clients ziweze ku-orchestrate Burp.<sup>[[5]](#references)</sup> Vipengele muhimu:

- **Context-menu triage**: capture traffic kupitia Proxy, fungua **Proxy > HTTP History**, bofya kulia request → **Extensions > Burp AI Agent > Analyze this request** ili kuanzisha AI chat iliyofungamanishwa na request/response hiyo.
- **Backends** (huchaguliwa kwa kila profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint inayooana na **OpenAI** (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` au `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates huwekwa automatically chini ya `~/.burp-ai-agent/AGENTS/`; weka faili za ziada za `*.md` hapo ili kuongeza custom analysis/scanning behaviors.
- **MCP server**: iwezeshe kupitia **Settings > MCP Server** ili kufichua Burp operations kwa MCP client yoyote (tools zaidi ya 53). Claude Desktop inaweza kuelekezwa kwenye server kwa kuhariri `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) au `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF huficha sensitive request data kabla ya kuituma kwa remote models; pendelea local backends unaposhughulikia secrets.
- **Audit logging**: JSONL logs zenye SHA-256 integrity hashing kwa kila entry, kwa traceability ya AI/MCP actions inayoweza kuthibitisha tampering.
- **Build/load**: pakua release JAR au build kwa Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Tahadhari za uendeshaji: cloud backends zinaweza ku-exfiltrate session cookies/PII isipokuwa privacy mode iwe enforced; MCP exposure inatoa remote orchestration ya Burp, kwa hivyo zuia access kwa agents unaowaamini na fuatilia integrity-hashed audit log.

## References

- [1] [Muunganisho wa Burp MCP + Codex CLI na marekebisho ya Caddy handshake](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Tatizo la PortSwigger MCP server la strict Origin/header validation](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Jinsi ya kutumia Codex kwa utafiti wa Bug Bounty: chunguza kwa mapana, thibitisha kwa ukali](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
