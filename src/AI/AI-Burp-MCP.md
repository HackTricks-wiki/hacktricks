# Burp MCP: LLM-सहायता प्राप्त ट्रैफ़िक समीक्षा

{{#include ../banners/hacktricks-training.md}}

## अवलोकन

Burp का **MCP Server** extension, MCP-सक्षम LLM clients को इंटरसेप्ट किए गए HTTP(S) ट्रैफ़िक तक पहुँच दे सकता है, ताकि वे भेद्यताएँ खोजने और रिपोर्ट का मसौदा तैयार करने के लिए **वास्तविक requests/responses का विश्लेषण कर सकें**। Burp को सत्य का स्रोत बनाए रखें: blind scanning के बजाय passive analysis या जानबूझकर किए गए one-variable replays का उपयोग करें।<sup>[[8]](#references)</sup>

## आर्किटेक्चर

- **Burp MCP Server (BApp)** डिफ़ॉल्ट रूप से `127.0.0.1:9876` पर सुनता है और MCP के ज़रिए इंटरसेप्ट किए गए ट्रैफ़िक को उपलब्ध कराता है।<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**, stdio (client side) को Burp के MCP SSE endpoint से जोड़ता है।
- **वैकल्पिक local reverse proxy** (Caddy), सख्त MCP handshake checks के लिए headers को सामान्य रूप देता है।
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), या Ollama (local)।

## सेटअप

### 1) Burp MCP Server इंस्टॉल करें

Burp BApp Store से **MCP Server** इंस्टॉल करें और पुष्टि करें कि यह `127.0.0.1:9876` पर सुन रहा है।<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JAR निकालें

MCP Server tab में **Extract server proxy jar** पर क्लिक करें और `mcp-proxy-all.jar` सेव करें।<sup>[[7]](#references)</sup>

### 3) MCP client कॉन्फ़िगर करें (Codex उदाहरण)

Client को proxy JAR और Burp के direct SSE endpoint की ओर निर्देशित करें। पैकेज किया गया proxy, stdio-to-SSE bridge है; यह Burp listener की जगह नहीं लेता।<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

समकक्ष Codex कमांड है:<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

फिर Codex चलाएँ और MCP tools की सूची दें:

```bash
codex
# inside Codex: /mcp
```

### 4) Caddy से सख्त Origin/header validation ठीक करें (यदि ज़रूरी हो)

अगर सख्त `Origin` जांच या अतिरिक्त headers के कारण MCP handshake विफल हो, तो headers को सामान्य करने के लिए local reverse proxy का उपयोग करें (यह Burp MCP की सख्त validation समस्या के workaround से मेल खाता है)।<sup>[[1]](#references)[[3]](#references)</sup>

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

प्रॉक्सी और क्लाइंट शुरू करें, और कॉन्फ़िगर किए गए `--sse-url` को केवल इस Caddy listener का उपयोग करते समय `http://127.0.0.1:19876` पर बदलें:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) ब्राउज़र स्टेट को प्रॉक्सी एविडेंस के साथ जोड़ें (Playwright MCP)

Playwright MCP को इस तरह रजिस्टर करें कि उसका ब्राउज़र Burp के प्रॉक्सी का उपयोग करे। इससे एजेंट rendered DOM/accessibility स्टेट को उस सटीक HTTP history से जोड़ सकता है जिसने उसे उत्पन्न किया था।<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Listener address को अनुकूलित करें, Codex रीस्टार्ट करें, और दोनों integrations की पुष्टि करने के लिए `/mcp` का उपयोग करें। इस उदाहरण में browser certificate errors बंद किए गए हैं, ताकि Burp द्वारा स्थानीय रूप से जनरेट किए गए certificate के कारण HTTPS interception अवरुद्ध न हो।<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-aware browser automation (OpenBurp)

Burp MCP connection और intercepted browser path अलग-अलग data flows हैं। MCP service, Burp tools को `127.0.0.1:9876` पर उपलब्ध कराती है, जबकि एक dedicated Chromium instance अपना HTTP(S) traffic Burp के proxy `127.0.0.1:8080` के माध्यम से भेजता है। इसलिए, सीधे MCP tool द्वारा जनरेट की गई requests **Proxy > HTTP history** में दिखाई नहीं दे सकती हैं; जब request/response को देखा, संपादित या साक्ष्य के रूप में सुरक्षित रखना हो, तो proxied browser का उपयोग करें।<sup>[[2]](#references)[[9]](#references)</sup>

SSE support वाला client सीधे Burp को register कर सकता है। केवल stdio support वाला client इसके बजाय PortSwigger का proxy JAR लॉन्च कर सकता है। दोनों ही मामलों में, दूसरा browser-control MCP register करें और उसे Burp के embedded Chromium (`BURP_CHROMIUM` एक स्थानीय executable path है) पर point करें:<sup>[[9]](#references)</sup>

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

TLS-bypass flag interception proxy द्वारा बनाए गए certificates को स्वीकार करता है, जबकि `--isolated` assessment को operator की सामान्य browser profile दोबारा इस्तेमाल करने से रोकता है। Isolation profile state की सुरक्षा करता है, लेकिन यह **security sandbox नहीं है**: controller अब भी उस test browser में खोले गए authenticated sessions तक पहुँच सकता है, और Burp MCP संवेदनशील requests, responses और configuration उजागर कर सकता है।<sup>[[9]](#references)</sup>

Client bridge को debug करने से पहले SSE listener को स्वतंत्र रूप से test करें:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

एक स्वस्थ listener `Content-Type: text/event-stream` लौटाता है। Headers के बाद timeout होना अपेक्षित है, क्योंकि SSE stream भविष्य के events के लिए खुली रहती है। अगर client फिर भी काम न करे, तो extension में configured route की पुष्टि करें: PortSwigger के अनुसार, client और extension configuration के आधार पर endpoint root path या `/sse` हो सकता है।<sup>[[9]](#references)[[7]](#references)</sup>

## अलग-अलग clients का उपयोग

### Codex CLI

- ऊपर बताए अनुसार `~/.codex/config.toml` configure करें।
- `codex` चलाएँ, फिर Burp tools की सूची verify करने के लिए `/mcp` चलाएँ।

### Gemini CLI

**burp-mcp-agents** repo launcher helpers प्रदान करता है:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (स्थानीय)

दिए गए launcher helper का उपयोग करें और कोई स्थानीय model चुनें:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

उदाहरण के लिए local models और अनुमानित VRAM आवश्यकताएँ:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## साक्ष्य-आधारित replay और validation

Agent को किसी संभावित लगने वाली व्याख्या या बीच में मिले response को प्रमाण न मानने दें। हर test को falsifiable बनाने के लिए Burp requests/responses और browser state का स्वतंत्र रूप से निरीक्षण करें।<sup>[[8]](#references)</sup>

1. एक baseline request/response pair सहेजें और attacker-controlled सटीक component की पहचान करें।
2. Authorization की तुलना के लिए, identifiers, cookies या tokens में बदलाव करने से पहले दोनों accounts के अंतर्गत उसी workflow को स्वतंत्र रूप से capture करें।
3. Mutation को replay करने से पहले hypothesis, evidence की location, अपेक्षित signal और उसे गलत साबित करने वाला result दर्ज करें।
4. एक बार में एक component में बदलाव करें, उससे बना pair सुरक्षित रखें और प्रत्यक्ष observations को inference से अलग label करें।
5. हर candidate को `open`, `blocked`, `rejected` या `confirmed` के रूप में track करें; उस पर तभी दोबारा विचार करें जब नया evidence mechanism या किसी prerequisite को बदलता हो।
6. Attacker control, reachability, repeatability, constraint bypass, impact और application की अंतिम state की पुष्टि करें। यदि दावा किया गया state change आगे की प्रक्रिया पर निर्भर है, तो redirect या सफल tool call प्रमाण नहीं है।

Exploitation के विवरण संबंधित technique page में रखें। उदाहरण के लिए, browser-message candidates [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md) में आते हैं, जबकि token key-selection behavior [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) में आता है।<sup>[[8]](#references)</sup>

एक संक्षिप्त hypothesis record से parallel agents को उसी आकर्षक branch को दोहराने से बचाया जा सकता है:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Burp MCP के साथ लक्षित out-of-band validation

Burp Suite Professional, आधिकारिक MCP extension के ज़रिए `generate_collaborator_payload` और `get_collaborator_interactions` उपलब्ध कराता है। पूरे target को scan किए बिना संदिग्ध server-side URL fetch का परीक्षण करने के लिए इन्हें `get_proxy_http_history_regex` और एक `send_http1_request` replay के साथ इस्तेमाल करें। History पढ़ने और request भेजने के लिए Burp अलग-अलग approval मांग सकता है।<sup>[[2]](#references)[[10]](#references)</sup>

1. History में ऐसा candidate URL-bearing request ढूँढें जिसमें `url=`, `webhook` या `callback` हो। मूल request और response सहेजें। History tool में `regex`, `count` और `offset` पैरामीटर होते हैं; model से हर entry जाँचने को कहने के बजाय पेजिनेशन करें।<sup>[[10]](#references)</sup>
2. नया Collaborator payload बनाएँ और उससे मिला **payload ID** सहेजें। कैप्चर की गई request को उसी host और port पर replay करें और केवल candidate URL को उस payload domain के अंतर्गत HTTPS URL से बदलें। `send_http1_request` के लिए पूरी HTTP/1.1 request को `content` के रूप में दें, साथ में `targetHostname`, `targetPort` और `usesHttps` भी दें; destination fields **application** की पहचान करते हैं, Collaborator host की नहीं।<sup>[[10]](#references)</sup>
3. उस payload ID के साथ `get_collaborator_interactions` को poll करें और interaction के समय का replay से मिलान करें। HTTP interaction fetch की पुष्टि करता है, जबकि केवल DNS से resolution का पता चलता है, पूरी हुई HTTP request का नहीं। Server egress और browser-side loading में अंतर करने के लिए interaction source और request headers जाँचें, फिर असंबंधित traffic को खारिज करने के लिए नए payload के साथ दोबारा परीक्षण करें।<sup>[[10]](#references)[[11]](#references)</sup>

MCP request tool सीधे response लौटाता है और ज़रूरी नहीं कि वह **Proxy > HTTP history** में दिखाई दे। History-backed artifact के लिए इसका request/response result सहेजें या proxied browser अथवा Repeater का इस्तेमाल करें। SSRF payload चुनने और आगे के परीक्षणों के लिए [SSRF chapter](../pentesting-web/ssrf-server-side-request-forgery/) देखें; out-of-band callback को internal-network impact का प्रमाण न मानें। MCP server का परीक्षण करने के लिए [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow) देखें।<sup>[[7]](#references)[[11]](#references)</sup>

## Passive review के लिए prompt pack

**burp-mcp-agents** repo में Burp traffic के evidence-driven analysis के लिए prompt templates शामिल हैं:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: व्यापक passive vulnerability surfacing।
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift और auth mismatches।
- `auth_flow_mapper.md`: authenticated और unauthenticated paths की तुलना।
- `ssrf_redirect_hunter.md`: URL fetch params/redirect chains से SSRF/open-redirect candidates।
- `logic_flaw_hunter.md`: multi-step logic flaws।
- `session_scope_hunter.md`: token audience/scope का गलत इस्तेमाल।
- `rate_limit_abuse_hunter.md`: throttling/abuse की कमियाँ।
- `report_writer.md`: evidence-केंद्रित reporting।

## वैकल्पिक attribution tagging

Logs में Burp/LLM traffic को tag करने के लिए header rewrite जोड़ें (proxy या Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## सुरक्षा संबंधी नोट्स

- जब ट्रैफ़िक में संवेदनशील डेटा हो, तो **local models** को प्राथमिकता दें।
- किसी finding के लिए केवल न्यूनतम आवश्यक साक्ष्य साझा करें।
- Burp को ही सत्य का स्रोत बनाए रखें; model का उपयोग **analysis और reporting** के लिए करें, scanning के लिए नहीं।

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** एक Burp extension है, जो local/cloud LLMs को passive/active analysis (62 vulnerability classes) के साथ जोड़ता है और 53+ MCP tools उपलब्ध कराता है, ताकि बाहरी MCP clients Burp को orchestrate कर सकें।<sup>[[5]](#references)</sup> मुख्य विशेषताएँ:

- **Context-menu triage**: Proxy के ज़रिए ट्रैफ़िक capture करें, **Proxy > HTTP History** खोलें, किसी request पर right-click करें → **Extensions > Burp AI Agent > Analyze this request** चुनें, ताकि उस request/response से जुड़ी AI chat शुरू हो।
- **Backends** (हर profile के लिए चुने जा सकते हैं):
  - Local HTTP: **Ollama**, **LM Studio**।
  - Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name)।
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` या `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login)।
- **Agent profiles**: prompt templates अपने-आप `~/.burp-ai-agent/AGENTS/` में install होते हैं; custom analysis/scanning behaviors जोड़ने के लिए वहाँ अतिरिक्त `*.md` files रखें।
- **MCP server**: किसी भी MCP client को Burp operations उपलब्ध कराने के लिए **Settings > MCP Server** के ज़रिए इसे enable करें (53+ tools)। Claude Desktop को server से जोड़ने के लिए `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) या `%APPDATA%\Claude\claude_desktop_config.json` (Windows) edit करें।
- **Privacy controls**: STRICT / BALANCED / OFF, remote models को भेजने से पहले संवेदनशील request data को redact करते हैं; secrets संभालते समय local backends को प्राथमिकता दें।
- **Audit logging**: AI/MCP actions की छेड़छाड़ का पता चल सके, ऐसी traceability के लिए हर entry पर SHA-256 integrity hashing वाले JSONL logs।
- **Build/load**: release JAR download करें या Java 21 से build करें:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

Operational सावधानियाँ: privacy mode लागू न होने पर cloud backends session cookies/PII exfiltrate कर सकते हैं; MCP का exposure Burp के remote orchestration की अनुमति देता है, इसलिए access को trusted agents तक सीमित रखें और integrity-hashed audit log की निगरानी करें।



## References

- [1] [Burp MCP + Codex CLI integration और Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server में strict Origin/header validation की समस्या](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty research के लिए Codex का उपयोग कैसे करें: व्यापक खोज करें, कठोरता से validate करें](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code और Codex के लिए Burp Suite orchestration](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server के tool implementations और parameters](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF vulnerabilities](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
