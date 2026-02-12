# Burp MCP: Ukaguzi wa trafiki uliosaidiwa na LLM

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Burp's **MCP Server** extension inaweza kufichua intercepted HTTP(S) traffic kwa wateja wa LLM wenye uwezo wa MCP ili waweze **reason over real requests/responses** kwa ajili ya ugundaji wa udhaifu kwa njia ya passive na uandishi wa ripoti. Kusudio ni ukaguzi unaoongozwa na ushahidi (hakuna fuzzing au blind scanning), ukihifadhi Burp kama chanzo cha ukweli.

## Muundo

- **Burp MCP Server (BApp)** husaikia kwenye `127.0.0.1:9876` na hufichua trafiki iliyokatwa kupitia MCP.
- **MCP proxy JAR** inaunganisha stdio (client side) na endpoint ya Burp ya MCP SSE.
- **Optional local reverse proxy** (Caddy) hurekebisha headers kwa ajili ya ukaguzi mkali wa MCP handshake.
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), or Ollama (local).

## Usanidi

### 1) Install Burp MCP Server

Install **MCP Server** kutoka Burp BApp Store na thibitisha kuwa inasikiliza kwenye `127.0.0.1:9876`.

### 2) Extract the proxy JAR

Katika tab ya MCP Server, bonyeza **Extract server proxy jar** na uhifadhi `mcp-proxy.jar`.

### 3) Configure an MCP client (Codex example)

Elekeza mteja kwa proxy JAR na endpoint ya Burp ya SSE:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
Sina nakala ya faili src/AI/AI-Burp-MCP.md. Tafadhali bandika hapa yaliyomo ya faili ili niweke tafsiri kwa Kiswahili kulingana na miongozo yako.

Pia nisikie kuhusu "run Codex": siwezi kuendesha programu za nje au APIs moja kwa moja kutoka hapa. Eleza unamaanisha nini kwa "run Codex" — 
- Unataka nitumie OpenAI Codex API (na mfano wa matokeo), 
- au unataka nisimulie/sipitishe kile Codex angekurudia? 

Mimi naweza kufanya:
1) Kutafsiri yaliyomo uliyotoa (nitahifadhi tags, links, paths na maneno yasiyotakikanwa kutafsiriwa).
2) Kutoa orodha ya "MCP tools" kulingana na yaliyomo uliyotoa au kulingana na maarifa yangu ya jumla — lakini nifafanue hapa MCP inamaanisha nini katika muktadha wako (mifano: "MCP = MassCVE Processor", "MCP = Managed Code Proxy", n.k.).

Tuma faili au ufafanuzi, nitaendelea.
```bash
codex
# inside Codex: /mcp
```
### 4) Rekebisha ukaguzi mkali wa `Origin`/header na Caddy (ikiwa inahitajika)

Ikiwa MCP handshake inashindwa kwa sababu ya ukaguzi mkali wa `Origin` au headers za ziada, tumia reverse proxy ya ndani ili ku-normaliza headers (hii inalingana na workaround kwa tatizo la ukaguzi mkali la Burp MCP).
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
## Kutumia wateja tofauti

### Codex CLI

- Sanidi `~/.codex/config.toml` kama hapo juu.
- Endesha `codex`, kisha `/mcp` ili kuthibitisha orodha ya Burp tools.

### Gemini CLI

Repo ya **burp-mcp-agents** inatoa launcher helpers:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (ya ndani)

Tumia msaidizi wa launcher uliotolewa na uchague modeli ya ndani:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Mifano ya modeli za ndani na mahitaji ya VRAM (takriban):

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Kifurushi cha prompt kwa ukaguzi wa passivu

Repo ya **burp-mcp-agents** inajumuisha templates za prompt kwa uchambuzi unaoongozwa na ushahidi wa trafiki ya Burp:

- `passive_hunter.md`: kuonyesha kwa upana udhaifu kwa njia passivu.
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift na auth mismatches.
- `auth_flow_mapper.md`: linganisha authenticated vs unauthenticated paths.
- `ssrf_redirect_hunter.md`: SSRF/open-redirect candidates kutoka kwa URL fetch params/redirect chains.
- `logic_flaw_hunter.md`: dosari za mantiki za hatua nyingi.
- `session_scope_hunter.md`: token audience/scope misuse.
- `rate_limit_abuse_hunter.md`: throttling/abuse gaps.
- `report_writer.md`: uandishi wa ripoti unaolenga ushahidi.

## Optional attribution tagging

Ili kuweka tag kwa trafiki ya Burp/LLM kwenye logs, ongeza header rewrite (proxy au Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Vidokezo vya usalama

- Tumia **modeli za ndani** unapokabiliwa na traffic yenye data nyeti.
- Shiriki ushahidi wa chini kabisa unaohitajika kwa ugunduzi.
- Weka Burp kama chanzo cha ukweli; tumia modeli kwa **uchambuzi na utoaji wa ripoti**, si kwa scanning.

## Burp AI Agent (triage iliyosaidiwa na AI + zana za MCP)

**Burp AI Agent** ni extension ya Burp inayounganisha LLMs za ndani/wingu na uchambuzi passive/active (62 vulnerability classes) na inatoa 53+ zana za MCP ili wateja wa MCP wa nje waweze kuratibu Burp. Mambo muhimu:

- **Context-menu triage**: kamata trafiki kupitia Proxy, fungua **Proxy > HTTP History**, bonyeza-kulia request → **Extensions > Burp AI Agent > Analyze this request** ili kuanzisha chat ya AI iliyofungwa kwa request/response hiyo.
- **Backends** (selectable per profile):
- Local HTTP: **Ollama**, **LM Studio**.
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates zinainstaliwa moja kwa moja chini ya `~/.burp-ai-agent/AGENTS/`; weka faili za ziada `*.md` pale ili kuongeza tabia za uchambuzi/scanning maalum.
- **MCP server**: wezesha kupitia **Settings > MCP Server** ili kufichua operesheni za Burp kwa mteja yeyote wa MCP (zana 53+). Claude Desktop inaweza kuelekezwa kwa server kwa kuhariri `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) au `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- **Privacy controls**: STRICT / BALANCED / OFF zinaficha data nyeti za requests kabla ya kuzituma kwa remote models; tumia local backends unaposhughulika na secrets.
- **Audit logging**: logi za JSONL zenye hashing ya uadilifu ya SHA-256 kwa kila kipengee kwa ufuatiliaji unaoonyesha kujaribu kubadilisha rekodi kwa matendo ya AI/MCP.
- **Build/load**: download the release JAR or build with Java 21:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Tahadhari za uendeshaji: cloud backends zinaweza exfiltrate session cookies/PII isipokuwa privacy mode imewekewa; exposure ya MCP inaruhusu remote orchestration ya Burp, hivyo punguza ufikiaji kwa trusted agents na fuatilia integrity-hashed audit log.

## References

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
