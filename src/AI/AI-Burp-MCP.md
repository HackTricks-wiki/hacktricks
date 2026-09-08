# Burp MCP: LLM-सहायित ट्रैफ़िक समीक्षा

{{#include ../banners/hacktricks-training.md}}

## अवलोकन

Burp का **MCP Server** extension intercepted HTTP(S) traffic को MCP-capable LLM clients के सामने expose कर सकता है, ताकि वे vulnerability discovery और report drafting के लिए **वास्तविक requests/responses पर reasoning** कर सकें। Burp को source of truth बनाए रखें: blind scanning के बजाय passive analysis या जानबूझकर किए गए one-variable replays का उपयोग करें।<sup>[[8]](#references)</sup>

## आर्किटेक्चर

- **Burp MCP Server (BApp)** डिफ़ॉल्ट रूप से `127.0.0.1:9876` पर सुनता है और intercepted traffic को MCP के माध्यम से expose करता है।<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** stdio (client side) को Burp के MCP SSE endpoint से bridge करता है।
- **Optional local reverse proxy** (Caddy) strict MCP handshake checks के लिए headers को normalize करता है।
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), या Ollama (local)।

## सेटअप

### 1) Burp MCP Server install करें

Burp BApp Store से **MCP Server** install करें और verify करें कि यह `127.0.0.1:9876` पर सुन रहा है।<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JAR extract करें

MCP Server tab में **Extract server proxy jar** पर click करें और `mcp-proxy-all.jar` save करें।<sup>[[7]](#references)</sup>

### 3) MCP client configure करें (Codex example)

Client को proxy JAR और Burp के direct SSE endpoint पर point करें। Packaged proxy एक stdio-to-SSE bridge है; यह Burp listener को replace नहीं करता।<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
समकक्ष Codex command है:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
फिर Codex चलाएँ और MCP tools की सूची बनाएँ:
```bash
codex
# inside Codex: /mcp
```
### 4) Caddy के साथ strict Origin/header validation ठीक करें (यदि आवश्यक हो)

यदि MCP handshake strict `Origin` checks या extra headers के कारण विफल हो, तो headers को normalize करने के लिए local reverse proxy का उपयोग करें (यह Burp MCP strict validation issue के workaround से मेल खाता है)।<sup>[[1]](#references)[[3]](#references)</sup>
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
Proxy और client शुरू करें, और इस Caddy listener का उपयोग करते समय ही configured `--sse-url` को `http://127.0.0.1:19876` में बदलें:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) Browser state को proxy evidence के साथ जोड़ें (Playwright MCP)

Playwright MCP को register करें ताकि उसका browser Burp के proxy का उपयोग करे। इससे agent rendered DOM/accessibility state को उसे उत्पन्न करने वाले exact HTTP history के साथ correlate कर सकता है।<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
Listener address को अनुकूलित करें, Codex को restart करें, और दोनों integrations को verify करने के लिए `/mcp` का उपयोग करें। उदाहरण browser certificate errors को disable करता है, ताकि Burp के locally generated certificate द्वारा HTTPS interception block न हो।<sup>[[6]](#references)[[8]](#references)</sup>

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
स्थानीय models के उदाहरण और अनुमानित VRAM आवश्यकताएँ:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## Evidence-driven replay और validation

Agent को किसी plausible explanation या intermediate response को proof न मानने दें। हर test को falsifiable बनाने के लिए Burp requests/responses और independently observed browser state का उपयोग करें।<sup>[[8]](#references)</sup>

1. एक baseline request/response pair save करें और exact attacker-controlled component पहचानें।
2. Authorization comparisons के लिए, identifiers, cookies या tokens को mutate करने से पहले दोनों accounts के अंतर्गत उसी workflow को independently capture करें।
3. किसी mutation को replay करने से पहले hypothesis, evidence location, expected signal और उस result को record करें जो hypothesis को disprove करेगा।
4. एक समय में केवल एक component mutate करें, resulting pair को preserve करें और direct observations को inference से अलग label करें।
5. प्रत्येक candidate को `open`, `blocked`, `rejected` या `confirmed` के रूप में track करें; केवल तभी revisit करें जब नया evidence mechanism या prerequisite को बदलता हो।
6. Attacker control, reachability, repeatability, constraint bypass, impact और final application state की पुष्टि करें। यदि claimed state change downstream है, तो redirect या successful tool call proof नहीं है।

Exploitation details को संबंधित technique page में रखें। उदाहरण के लिए, browser-message candidates [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md) में, जबकि token key-selection behavior [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) में होना चाहिए।<sup>[[8]](#references)</sup>

एक compact hypothesis record parallel agents को उसी आकर्षक branch को दोहराने से रोकता है:<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
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

## वैकल्पिक attribution tagging

Logs में Burp/LLM traffic को tag करने के लिए header rewrite (proxy या Burp Match/Replace) जोड़ें:<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Safety notes

- जब traffic में sensitive data शामिल हो, तो **local models** को प्राथमिकता दें।
- किसी finding के लिए केवल आवश्यक न्यूनतम evidence साझा करें।
- Burp को source of truth बनाए रखें; model का उपयोग **analysis और reporting** के लिए करें, scanning के लिए नहीं।

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** एक Burp extension है, जो local/cloud LLMs को passive/active analysis (62 vulnerability classes) के साथ जोड़ता है और 53+ MCP tools उपलब्ध कराता है, ताकि external MCP clients Burp को orchestrate कर सकें।<sup>[[5]](#references)</sup> मुख्य विशेषताएँ:

- **Context-menu triage**: Proxy के माध्यम से traffic capture करें, **Proxy > HTTP History** खोलें, किसी request पर right-click करें → **Extensions > Burp AI Agent > Analyze this request** चुनकर उस request/response से bound AI chat शुरू करें।
- **Backends** (प्रति profile चयन योग्य):
- Local HTTP: **Ollama**, **LM Studio**।
- Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name)।
- Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` या `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login)।
- **Agent profiles**: prompt templates स्वतः `~/.burp-ai-agent/AGENTS/` में install होते हैं; custom analysis/scanning behaviors जोड़ने के लिए वहाँ अतिरिक्त `*.md` files रखें।
- **MCP server**: Burp operations को किसी भी MCP client (53+ tools) के लिए expose करने हेतु **Settings > MCP Server** से enable करें। Claude Desktop को server पर point करने के लिए `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) या `%APPDATA%\Claude\claude_desktop_config.json` (Windows) को edit करें।
- **Privacy controls**: STRICT / BALANCED / OFF remote models को भेजने से पहले sensitive request data को redact करते हैं; secrets संभालते समय local backends को प्राथमिकता दें।
- **Audit logging**: AI/MCP actions की tamper-evident traceability के लिए per-entry SHA-256 integrity hashing वाले JSONL logs।
- **Build/load**: release JAR download करें या Java 21 के साथ build करें:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operational सावधानियां: cloud backends privacy mode लागू न होने पर session cookies/PII को exfiltrate कर सकते हैं; MCP exposure Burp का remote orchestration प्रदान करता है, इसलिए access को trusted agents तक सीमित रखें और integrity-hashed audit log की निगरानी करें।

## References

- [1] [Burp MCP + Codex CLI integration और Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty research के लिए Codex का उपयोग कैसे करें: व्यापक रूप से explore करें, कठोरता से validate करें](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
