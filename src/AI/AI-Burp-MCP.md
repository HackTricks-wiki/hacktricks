# Burp MCP: traffic review inayosaidiwa na LLM

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

**MCP Server** extension ya Burp inaweza kuweka intercepted HTTP(S) traffic wazi kwa MCP-capable LLM clients ili ziweze **kufanya reasoning juu ya requests/responses halisi** kwa passive vulnerability discovery na kuandaa reports. Lengo ni review inayoongozwa na evidence (bila fuzzing au blind scanning), huku Burp ikiendelea kuwa source of truth.

## Architecture

- **Burp MCP Server (BApp)** husikiliza kwenye `127.0.0.1:9876` na kuweka intercepted traffic wazi kupitia MCP.<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** huunganisha stdio (upande wa client) na Burp's MCP SSE endpoint.
- **Optional local reverse proxy** (Caddy) husawazisha headers kwa strict MCP handshake checks.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), au Ollama (local).

## Usanidi

### 1) Install Burp MCP Server

Install **MCP Server** kutoka Burp BApp Store na uthibitishe kuwa inasikiliza kwenye `127.0.0.1:9876`.<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extract proxy JAR

Katika MCP Server tab, bofya **Extract server proxy jar** na uhifadhi `mcp-proxy.jar`.

### 3) Configure MCP client (Codex example)

Elekeza client kwenye proxy JAR na Burp's SSE endpoint:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Kisha endesha Codex na uorodheshe zana za MCP:
```bash
codex
# inside Codex: /mcp
```
### 4) Rekebisha uthibitishaji mkali wa Origin/header kwa kutumia Caddy (ikiwa inahitajika)

Ikiwa MCP handshake itashindwa kwa sababu ya ukaguzi mkali wa `Origin` au headers za ziada, tumia reverse proxy ya ndani kurekebisha headers (hii inaendana na workaround ya tatizo la strict validation la Burp MCP).<sup>[[1]](#references)[[3]](#references)</sup>
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
Anzisha proxy na client:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## Kutumia clients tofauti

### Codex CLI

- Sanidi `~/.codex/config.toml` kama ilivyo hapo juu.
- Endesha `codex`, kisha `/mcp` ili kuthibitisha orodha ya Burp tools.

### Gemini CLI

Repo ya **burp-mcp-agents** hutoa wasaidizi wa launcher:<sup>[[4]](#references)</sup>
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

## Kifurushi cha prompt kwa passive review

Repo ya **burp-mcp-agents** inajumuisha templates za prompt kwa uchanganuzi wa Burp traffic unaoongozwa na ushahidi:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: kufichua vulnerabilities mbalimbali kupitia passive review.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift na kutolingana kwa auth.
- `auth_flow_mapper.md`: kulinganisha paths zilizo authenticated na zisizo authenticated.
- `ssrf_redirect_hunter.md`: wagombea wa SSRF/open-redirect kutoka URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: logic flaws za hatua nyingi.
- `session_scope_hunter.md`: matumizi yasiyo sahihi ya token audience/scope.
- `rate_limit_abuse_hunter.md`: mapungufu katika throttling/abuse.
- `report_writer.md`: reporting inayolenga ushahidi.

## Optional attribution tagging

Ili kuweka tag kwenye Burp/LLM traffic katika logs, ongeza header rewrite (proxy au Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Maelezo ya usalama

- Pendelea **local models** wakati traffic ina data nyeti.
- Shiriki ushahidi wa kiwango cha chini pekee unaohitajika kwa finding.
- Weka Burp kama chanzo cha ukweli; tumia model kwa **analysis and reporting**, si kwa scanning.

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** ni Burp extension inayounganisha local/cloud LLMs na passive/active analysis (makundi 62 ya vulnerabilities), na kufichua MCP tools zaidi ya 53 ili external MCP clients ziweze kuendesha Burp.<sup>[[5]](#references)</sup> Mambo muhimu:

- **Context-menu triage**: capture traffic kupitia Proxy, fungua **Proxy > HTTP History**, bofya kulia request → **Extensions > Burp AI Agent > Analyze this request** ili kuanzisha AI chat iliyofungamanishwa na request/response hiyo.
- **Backends** (zinazoweza kuchaguliwa kwa kila profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: endpoint inayooana na **OpenAI**, (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` au `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates huwekwa kiotomatiki chini ya `~/.burp-ai-agent/AGENTS/`; weka faili za ziada za `*.md` humo ili kuongeza tabia maalum za analysis/scanning.
- **MCP server**: iwezeshe kupitia **Settings > MCP Server** ili kufichua operations za Burp kwa MCP client yoyote (tools zaidi ya 53). Claude Desktop inaweza kuelekezwa kwenye server kwa kuhariri `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) au `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF huficha request data nyeti kabla ya kuituma kwa remote models; pendelea local backends unaposhughulikia secrets.
- **Audit logging**: JSONL logs zenye SHA-256 integrity hashing kwa kila entry, kwa traceability inayoonyesha ikiwa AI/MCP actions zimechezewa.
- **Build/load**: pakua release JAR au build kwa Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Tahadhari za kiutendaji: cloud backends zinaweza ku-exfiltrate session cookies/PII isipokuwa privacy mode iwe enforced; MCP exposure inaruhusu remote orchestration ya Burp, kwa hivyo zuia access kwa agents zinazoaminika na fuatilia audit log yenye integrity hash.

## Marejeo

- [1] [Burp MCP + Codex CLI integration na marekebisho ya Caddy handshake](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [Tatizo la PortSwigger MCP server la strict Origin/header validation](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
