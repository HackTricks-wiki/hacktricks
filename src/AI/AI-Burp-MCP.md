# Burp MCP: LLM-सहायित ट्रैफ़िक समीक्षा

{{#include ../banners/hacktricks-training.md}}

## अवलोकन

Burp का **MCP Server** extension इंटरसेप्ट किए गए HTTP(S) ट्रैफ़िक को MCP-सक्षम LLM क्लाइंट्स के समक्ष उजागर कर सकता है ताकि वे वास्तविक requests/responses पर तर्क कर सकें और passive vulnerability खोज व रिपोर्ट ड्राफ्ट कर सकें। उद्देश्य evidence-driven समीक्षा है (कोई fuzzing या blind scanning नहीं), और Burp को सत्य का स्रोत बनाए रखा जाता है।

## आर्किटेक्चर

- **Burp MCP Server (BApp)** `127.0.0.1:9876` पर सुनता है और इंटरसेप्ट किए गए ट्रैफ़िक को MCP के माध्यम से एक्सपोज़ करता है।
- **MCP proxy JAR** stdio (client side) को Burp के MCP SSE endpoint से जोड़ता है।
- **Optional local reverse proxy** (Caddy) कड़े MCP handshake checks के लिए headers को सामान्यीकृत करता है।
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), या Ollama (local).

## सेटअप

### 1) Burp MCP Server इंस्टॉल करें

Burp BApp Store से **MCP Server** इंस्टॉल करें और सत्यापित करें कि यह `127.0.0.1:9876` पर सुन रहा है।

### 2) proxy JAR निकालें

MCP Server टैब में, **Extract server proxy jar** पर क्लिक करें और `mcp-proxy.jar` को सेव करें।

### 3) एक MCP क्लाइंट कॉन्फ़िगर करें (Codex उदाहरण)

क्लाइंट को proxy JAR और Burp के SSE endpoint की ओर पॉइंट करें:
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
I don't have access to src/AI/AI-Burp-MCP.md. Please either:

- Paste the file contents you want translated here, or
- Confirm you want me to generate a list of MCP tools from my knowledge (and then translate that generated text to Hindi, preserving markdown/html).

Also clarify what you mean by "run Codex" — do you want me to emulate Codex-style output, or to call an external Codex tool (I can't run external services)?
```bash
codex
# inside Codex: /mcp
```
### 4) कड़े Origin/header validation को Caddy के साथ ठीक करें (यदि आवश्यक हो)

यदि MCP handshake कड़े `Origin` checks या अतिरिक्त headers के कारण असफल होता है, तो headers को सामान्य करने के लिए स्थानीय reverse proxy का उपयोग करें (यह Burp MCP strict validation issue के workaround से मेल खाता है)।
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
प्रॉक्सी और क्लाइंट शुरू करें:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## विभिन्न क्लाइंट्स का उपयोग

### Codex CLI

- ऊपर बताए अनुसार `~/.codex/config.toml` कॉन्फ़िगर करें।
- `codex` चलाएँ, फिर `/mcp` चलाकर Burp tools सूची की पुष्टि करें।

### Gemini CLI

यह **burp-mcp-agents** repo लॉन्चर हेल्पर्स प्रदान करता है:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

प्रदान किए गए लॉन्चर हेल्पर का उपयोग करें और एक स्थानीय मॉडल चुनें:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
Example local models and approximate VRAM needs:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## निष्क्रिय समीक्षा के लिए Prompt पैक

The **burp-mcp-agents** repo में Burp ट्रैफ़िक के evidence-driven विश्लेषण के लिए prompt टेम्पलेट शामिल हैं:

- `passive_hunter.md`: व्यापक passive vulnerability surface करना।
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift और auth mismatches।
- `auth_flow_mapper.md`: authenticated vs unauthenticated paths की तुलना करें।
- `ssrf_redirect_hunter.md`: URL fetch params/redirect chains से SSRF/open-redirect candidates की पहचान।
- `logic_flaw_hunter.md`: multi-step logic flaws।
- `session_scope_hunter.md`: token audience/scope का दुरुपयोग।
- `rate_limit_abuse_hunter.md`: throttling/abuse gaps।
- `report_writer.md`: सबूत-केंद्रित रिपोर्टिंग।

## वैकल्पिक attribution टैगिंग

लॉग में Burp/LLM ट्रैफ़िक को टैग करने के लिए, एक header rewrite जोड़ें (proxy या Burp Match/Replace):
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## सुरक्षा नोट्स

- जब ट्रैफिक में संवेदनशील डेटा हो तो **स्थानीय मॉडल** को प्राथमिकता दें।
- किसी निष्कर्ष के लिए आवश्यक न्यूनतम प्रमाण ही साझा करें।
- Burp को सत्य का स्रोत रखें; मॉडल का उपयोग **विश्लेषण और रिपोर्टिंग** के लिए करें, स्कैनिंग के लिए नहीं।

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** एक Burp extension है जो स्थानीय/क्लाउड LLMs को passive/active analysis (62 vulnerability classes) के साथ जोड़ता है और 53+ MCP tools एक्सपोज़ करता है ताकि external MCP clients Burp को orchestrate कर सकें। मुख्य बातें:

- **Context-menu triage**: Proxy के माध्यम से ट्रैफिक कैप्चर करें, **Proxy > HTTP History** खोलें, किसी request पर राइट-क्लिक करें → **Extensions > Burp AI Agent > Analyze this request** ताकि उस request/response से जुड़ा AI चैट खुले।
- **Backends** (प्रोफ़ाइल के अनुसार चुनने योग्य):
  - Local HTTP: **Ollama**, **LM Studio**.
  - Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name).
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` or `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login).
- **Agent profiles**: prompt templates स्वतः `~/.burp-ai-agent/AGENTS/` के अंतर्गत इंस्टॉल होते हैं; कस्टम analysis/scanning व्यवहार जोड़ने के लिए अतिरिक्त `*.md` फाइलें वहाँ डालें।
- **MCP server**: **Settings > MCP Server** के माध्यम से सक्षम करें ताकि Burp operations किसी भी MCP client को एक्सपोज़ हों (53+ tools)। Claude Desktop को सर्वर की ओर निर्देशित करने के लिए `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) या `%APPDATA%\Claude\claude_desktop_config.json` (Windows) एडिट करें।
- **Privacy controls**: STRICT / BALANCED / OFF संवेदनशील request डेटा को remote models को भेजने से पहले redact करते हैं; secrets के प्रबंधन के लिए स्थानीय backends को प्राथमिकता दें।
- **Audit logging**: AI/MCP क्रियाओं की मैनिपुलेशन का पता चलने लायक ट्रेसबिलिटी के लिए प्रति-एंट्री SHA-256 integrity hashing के साथ JSONL लॉग।
- **Build/load**: रिलीज़ JAR डाउनलोड करें या Java 21 के साथ build करें:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
ऑपरेशनल सावधानियाँ: cloud backends session cookies/PII को exfiltrate कर सकते हैं जब तक privacy mode लागू न हो; MCP exposure Burp की remote orchestration की अनुमति देता है इसलिए access को trusted agents तक सीमित रखें और integrity-hashed audit log की निगरानी करें।

## References

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
