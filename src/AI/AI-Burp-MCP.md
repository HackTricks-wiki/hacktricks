# Burp MCP: LLM-सहायता प्राप्त traffic review

{{#include ../banners/hacktricks-training.md}}

## अवलोकन

Burp का **MCP Server** extension intercepted HTTP(S) traffic को MCP-capable LLM clients के सामने expose कर सकता है, ताकि वे passive vulnerability discovery और report drafting के लिए **वास्तविक requests/responses पर reasoning** कर सकें। उद्देश्य evidence-driven review है (कोई fuzzing या blind scanning नहीं), और Burp को source of truth बनाए रखना है।

## Architecture

- **Burp MCP Server (BApp)** `127.0.0.1:9876` पर सुनता है और intercepted traffic को MCP के माध्यम से expose करता है।<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** stdio (client side) को Burp के MCP SSE endpoint से जोड़ता है।
- **Optional local reverse proxy** (Caddy) strict MCP handshake checks के लिए headers को normalize करता है।
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), या Ollama (local)।

## Setup

### 1) Burp MCP Server install करें

Burp BApp Store से **MCP Server** install करें और verify करें कि यह `127.0.0.1:9876` पर सुन रहा है।<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Proxy JAR extract करें

MCP Server tab में **Extract server proxy jar** पर click करें और `mcp-proxy.jar` save करें।

### 3) MCP client configure करें (Codex example)

Client को proxy JAR और Burp के SSE endpoint पर point करें:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
फिर Codex चलाएँ और MCP tools की सूची बनाएँ:
```bash
codex
# inside Codex: /mcp
```
### 4) Caddy के साथ strict Origin/header validation ठीक करें (यदि आवश्यक हो)

यदि strict `Origin` checks या अतिरिक्त headers के कारण MCP handshake विफल हो जाता है, तो headers को normalize करने के लिए local reverse proxy का उपयोग करें (यह Burp MCP strict validation issue के workaround से मेल खाता है)।<sup>[[1]](#references)[[3]](#references)</sup>
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
Proxy और client शुरू करें:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## अलग-अलग clients का उपयोग

### Codex CLI

- ऊपर बताए अनुसार `~/.codex/config.toml` configure करें।
- `codex` चलाएँ, फिर Burp tools list verify करने के लिए `/mcp` चलाएँ।

### Gemini CLI

**burp-mcp-agents** repo launcher helpers प्रदान करता है:<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

प्रदान किए गए launcher helper का उपयोग करें और एक local model चुनें:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
उदाहरण local models और अनुमानित VRAM आवश्यकताएँ:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## passive review के लिए Prompt pack

**burp-mcp-agents** repo में Burp traffic के evidence-driven analysis के लिए prompt templates शामिल हैं:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: व्यापक passive vulnerability surfacing।
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift और auth mismatches।
- `auth_flow_mapper.md`: authenticated और unauthenticated paths की तुलना।
- `ssrf_redirect_hunter.md`: URL fetch params/redirect chains से SSRF/open-redirect candidates।
- `logic_flaw_hunter.md`: multi-step logic flaws।
- `session_scope_hunter.md`: token audience/scope misuse।
- `rate_limit_abuse_hunter.md`: throttling/abuse gaps।
- `report_writer.md`: evidence-focused reporting।

## Optional attribution tagging

Logs में Burp/LLM traffic को tag करने के लिए header rewrite जोड़ें (proxy या Burp Match/Replace):<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Safety notes

- जब traffic में sensitive data हो, तो **local models** को प्राथमिकता दें।
- किसी finding के लिए केवल आवश्यक न्यूनतम evidence साझा करें।
- Burp को source of truth बनाए रखें; model का उपयोग **analysis और reporting** के लिए करें, scanning के लिए नहीं।

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** एक Burp extension है जो local/cloud LLMs को passive/active analysis (62 vulnerability classes) के साथ जोड़ता है और 53+ MCP tools उपलब्ध कराता है, ताकि external MCP clients Burp को orchestrate कर सकें।<sup>[[5]](#references)</sup> मुख्य विशेषताएं:

- **Context-menu triage**: Proxy के माध्यम से traffic capture करें, **Proxy > HTTP History** खोलें, किसी request पर right-click करें → **Extensions > Burp AI Agent > Analyze this request** चुनें, ताकि उस request/response से bound AI chat शुरू हो सके।
- **Backends** (प्रत्येक profile के लिए selectable):
- Local HTTP: **Ollama**, **LM Studio**।
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name)।
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` या `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login)।
- **Agent profiles**: prompt templates `~/.burp-ai-agent/AGENTS/` के अंतर्गत auto-installed होते हैं; custom analysis/scanning behaviors जोड़ने के लिए वहां अतिरिक्त `*.md` files रखें।
- **MCP server**: किसी भी MCP client के सामने Burp operations expose करने के लिए **Settings > MCP Server** के माध्यम से enable करें (53+ tools)। Claude Desktop को server से जोड़ने के लिए `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) या `%APPDATA%\Claude\claude_desktop_config.json` (Windows) को edit किया जा सकता है।
- **Privacy controls**: STRICT / BALANCED / OFF remote models को भेजने से पहले sensitive request data को redact करते हैं; secrets संभालते समय local backends को प्राथमिकता दें।
- **Audit logging**: AI/MCP actions की tamper-evident traceability के लिए प्रति-entry SHA-256 integrity hashing वाले JSONL logs।
- **Build/load**: release JAR download करें या Java 21 के साथ build करें:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
संचालन संबंधी सावधानियां: privacy mode लागू न होने पर cloud backends session cookies/PII को exfiltrate कर सकते हैं; MCP exposure Burp का remote orchestration सक्षम करता है, इसलिए access को trusted agents तक सीमित रखें और integrity-hashed audit log की निगरानी करें।

## References

- [1] [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
