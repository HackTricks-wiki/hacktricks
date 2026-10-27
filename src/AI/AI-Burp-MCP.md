# Burp MCP: LLM-सहायता प्राप्त ट्रैफ़िक समीक्षा

{{#include ../banners/hacktricks-training.md}}

## अवलोकन

Burp का **MCP Server** extension, intercepted HTTP(S) traffic को MCP-सक्षम LLM clients के सामने उपलब्ध करा सकता है, ताकि वे vulnerability discovery और report drafting के लिए **वास्तविक requests/responses का विश्लेषण कर सकें**। Burp को ही विश्वसनीय स्रोत बनाए रखें: अंधाधुंध scanning करने के बजाय passive analysis या जानबूझकर किए गए, एक-चर वाले replays का उपयोग करें।<sup>[[8]](#references)</sup>

## आर्किटेक्चर

- **Burp MCP Server (BApp)** डिफ़ॉल्ट रूप से `127.0.0.1:9876` पर सुनता है और intercepted traffic को MCP के ज़रिए उपलब्ध कराता है।<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**, stdio (client side) को Burp के MCP SSE endpoint से जोड़ता है।
- **वैकल्पिक local reverse proxy** (Caddy), सख्त MCP handshake checks के लिए headers को सामान्य रूप में ढालता है।
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), या Ollama (local)।

## सेटअप

### 1) Burp MCP Server इंस्टॉल करें

Burp BApp Store से **MCP Server** इंस्टॉल करें और पुष्टि करें कि यह `127.0.0.1:9876` पर सुन रहा है।<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JAR निकालें

MCP Server tab में **Extract server proxy jar** पर क्लिक करें और `mcp-proxy-all.jar` सेव करें।<sup>[[7]](#references)</sup>

### 3) MCP client कॉन्फ़िगर करें (Codex उदाहरण)

Client को proxy JAR और Burp के direct SSE endpoint पर सेट करें। पैकेज किया गया proxy, stdio-to-SSE bridge है; यह Burp listener की जगह नहीं लेता।<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

समतुल्य Codex कमांड है:<sup>[[7]](#references)[[8]](#references)</sup>

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

प्रॉक्सी और क्लाइंट शुरू करें, और `--sse-url` को केवल इस Caddy listener का उपयोग करते समय `http://127.0.0.1:19876` पर सेट करें:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) ब्राउज़र स्थिति को proxy साक्ष्य के साथ जोड़ें (Playwright MCP)

Playwright MCP को इस तरह रजिस्टर करें कि उसका ब्राउज़र Burp के proxy का उपयोग करे। इससे agent rendered DOM/accessibility स्थिति को उस सटीक HTTP history से जोड़ सकता है जिसने उसे बनाया था।<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

Listener address को अनुकूलित करें, Codex को restart करें, और दोनों integrations को verify करने के लिए `/mcp` का उपयोग करें। इस उदाहरण में browser certificate errors को disable किया गया है, ताकि Burp के locally generated certificate के कारण HTTPS interception block न हो।<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-aware browser automation (OpenBurp)

Burp MCP connection और intercepted browser path अलग-अलग data flows हैं। MCP service, Burp tools को `127.0.0.1:9876` पर उपलब्ध कराती है, जबकि एक dedicated Chromium instance अपना HTTP(S) traffic Burp के proxy `127.0.0.1:8080` के ज़रिए भेजता है। इसलिए MCP tool से सीधे किए गए requests **Proxy > HTTP history** में दिखाई नहीं दे सकते; जब request/response को देखा, संपादित या evidence के रूप में सुरक्षित रखना हो, तो proxied browser का उपयोग करें।<sup>[[2]](#references)[[9]](#references)</sup>

SSE support वाला client सीधे Burp को register कर सकता है। केवल stdio support वाला client इसके बजाय PortSwigger का proxy JAR launch कर सकता है। दोनों ही स्थितियों में, दूसरा browser-control MCP register करें और उसे Burp के embedded Chromium पर point करें (`BURP_CHROMIUM` एक local executable path है):<sup>[[9]](#references)</sup>

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

TLS-bypass flag interception proxy द्वारा जनरेट किए गए certificates को स्वीकार करता है, जबकि `--isolated` assessment को operator की सामान्य browser profile का दोबारा उपयोग करने से रोकता है। Isolation profile state की सुरक्षा करता है, लेकिन यह **security sandbox नहीं है**: controller अब भी उस test browser में खोले गए authenticated sessions तक पहुंच सकता है, और Burp MCP संवेदनशील requests, responses और configuration को उजागर कर सकता है।<sup>[[9]](#references)</sup>

Client bridge को debug करने से पहले SSE listener का स्वतंत्र रूप से परीक्षण करें:<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

एक स्वस्थ listener `Content-Type: text/event-stream` लौटाता है। Headers के बाद timeout होना अपेक्षित है, क्योंकि SSE stream भविष्य के events के लिए खुली रहती है। यदि client फिर भी विफल हो, तो extension का configured route जाँचें: PortSwigger के अनुसार, client और extension configuration के आधार पर endpoint root path या `/sse` हो सकता है।<sup>[[9]](#references)[[7]](#references)</sup>

## अलग-अलग clients का उपयोग

### Codex CLI

- ऊपर बताए अनुसार `~/.codex/config.toml` configure करें।
- `codex` चलाएँ, फिर Burp tools की सूची सत्यापित करने के लिए `/mcp` चलाएँ।

### Gemini CLI

**burp-mcp-agents** repo launcher helpers प्रदान करता है:<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (स्थानीय)

दिए गए launcher helper का उपयोग करें और एक स्थानीय model चुनें:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

उदाहरण के लिए local models और उनकी अनुमानित VRAM आवश्यकताएँ:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## साक्ष्य-आधारित replay और validation

एजेंट को किसी विश्वसनीय लगने वाली व्याख्या या intermediate response को प्रमाण न मानने दें। हर test को falsifiable बनाने के लिए Burp requests/responses और browser की स्वतंत्र रूप से देखी गई स्थिति का उपयोग करें।<sup>[[8]](#references)</sup>

1. एक baseline request/response pair सहेजें और attacker-controlled सटीक component की पहचान करें।
2. Authorization की तुलना के लिए, identifiers, cookies या tokens में बदलाव करने से पहले दोनों accounts के तहत उसी workflow को स्वतंत्र रूप से capture करें।
3. किसी mutation को replay करने से पहले hypothesis, evidence location, expected signal और उसे गलत साबित करने वाले result को दर्ज करें।
4. एक बार में एक component में बदलाव करें, नतीजे वाला pair सहेजें, और प्रत्यक्ष observations को inference से अलग label करें।
5. हर candidate को `open`, `blocked`, `rejected` या `confirmed` के रूप में track करें; उस पर तभी दोबारा विचार करें जब नए evidence से mechanism या कोई prerequisite बदलता हो।
6. attacker control, reachability, repeatability, constraint bypass, impact और अंतिम application state की पुष्टि करें। यदि दावा किया गया state change downstream होता है, तो redirect या सफल tool call उसका प्रमाण नहीं है।

Exploitation की जानकारी संबंधित technique page में रखें। उदाहरण के लिए, browser-message candidates [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md) में आते हैं, जबकि token key-selection behavior [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) में आता है।<sup>[[8]](#references)</sup>

एक संक्षिप्त hypothesis record समानांतर agents को उसी आकर्षक branch पर दोबारा काम करने से रोकता है:<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Burp MCP के साथ WebSocket frame की छंटाई

आधिकारिक extension, Burp के WebSocket history में केवल-पढ़ने योग्य, पृष्ठांकित खोजों के लिए `get_proxy_websocket_history_regex` उपलब्ध कराता है। यह `regex`, `count` और `offset` लेता है; `send_http1_request` के विपरीत, यह WebSocket frame नहीं भेजता। Intercept बंद होने पर भी Burp संदेशों की दोनों दिशाओं को रिकॉर्ड करता है, इसलिए मॉडल को संबंधित frames का छोटा सेट देने से पहले history को फ़िल्टर करें।<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Burp-proxied browser के ज़रिए WebSocket-आधारित वही कार्रवाई दो अलग-अलग प्रमाणित test accounts से करें। हर upgrade handshake और उसके cookies, connection ID, frame direction और response frames को साथ रखें; पहले account के connection पर server-to-client event इस बात का सबूत नहीं है कि दूसरे account को भी वह मिला।
2. `get_proxy_websocket_history_regex` में `(?i)(subscribe|room|tenant|objectId)` जैसी सीमित expression, `count: 20` और `offset: 0` के साथ खोजें। बाद के matches देखने के लिए `offset` आगे बढ़ाएँ। outbound frame के object या topic identifier की तुलना उसी **connection** पर आए response से करें।
3. **Proxy > WebSockets history** में, संदिग्ध outbound frame को Repeater में भेजें। उसे उपयुक्त खुले connection से जोड़ें या दूसरे account के handshake के साथ फिर से connect करें। केवल object/topic identifier बदलें और मिले server messages तथा application state की तुलना दोनों baseline से करें। MCP history tool यह replay नहीं कर सकता; WebSocket Repeater frames को edit, resend और reconnect कर सकता है।

Cross-site WebSocket hijacking और broker topic authorization जैसे protocol-विशिष्ट tests के लिए, [WebSocket Attacks](../pentesting-web/websocket-attacks.md) देखें। सफल upgrade या client-side echo को इस बात का सबूत न मानें कि protected subscription सफल हुई।

## Burp MCP के साथ लक्षित out-of-band validation

Burp Suite Professional, आधिकारिक MCP extension के ज़रिए `generate_collaborator_payload` और `get_collaborator_interactions` उपलब्ध कराता है। पूरे target को scan किए बिना, संदिग्ध server-side URL fetch को जाँचने के लिए इन्हें `get_proxy_http_history_regex` और एक `send_http1_request` replay के साथ इस्तेमाल करें। History पढ़ने और request भेजने के लिए Burp अलग-अलग approval माँग सकता है।<sup>[[2]](#references)[[10]](#references)</sup>

1. ऐसे संभावित URL वाले request के लिए history फ़िल्टर करें जिसमें `url=`, `webhook` या `callback` हो। मूल request और response सहेजें। History tool `regex`, `count` और `offset` लेता है; मॉडल से हर entry की जाँच करवाने के बजाय पृष्ठांकन करें।<sup>[[10]](#references)</sup>
2. नया Collaborator payload बनाएँ और उससे मिला **payload ID** सुरक्षित रखें। पकड़े गए request को उसी host और port पर replay करें; केवल संदिग्ध URL को उस payload domain के अंतर्गत HTTPS URL से बदलें। `send_http1_request` के लिए, पूरा HTTP/1.1 request `content` के रूप में और `targetHostname`, `targetPort` तथा `usesHttps` दें; destination fields **application** की पहचान करते हैं, Collaborator host की नहीं।<sup>[[10]](#references)</sup>
3. उस payload ID के साथ `get_collaborator_interactions` को poll करें और interaction के समय का replay से मिलान करें। HTTP interaction fetch का समर्थन करता है, जबकि केवल DNS से resolution का पता चलता है, पूरा हुआ HTTP request नहीं। Browser-side loading से server egress को अलग पहचानने के लिए interaction source और request headers जाँचें, फिर असंबंधित traffic की संभावना हटाने के लिए नए payload के साथ दोहराएँ।<sup>[[10]](#references)[[11]](#references)</sup>

MCP request tool response सीधे लौटाता है और ज़रूरी नहीं कि वह **Proxy > HTTP history** में दर्ज हो। इसके request/response result को सुरक्षित रखें या history-आधारित प्रमाण के लिए proxied browser अथवा Repeater का इस्तेमाल करें। SSRF payload चुनने और आगे के tests के लिए, out-of-band callback को internal-network impact का सबूत मानने के बजाय [SSRF chapter](../pentesting-web/ssrf-server-side-request-forgery/) देखें। MCP server की जाँच के लिए, [MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow) देखें।<sup>[[7]](#references)[[11]](#references)</sup>

## Passive review के लिए prompt pack

**burp-mcp-agents** repo में Burp traffic के evidence-driven analysis के लिए prompt templates शामिल हैं:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: व्यापक passive vulnerability की पहचान।
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift और auth mismatches।
- `auth_flow_mapper.md`: authenticated और unauthenticated paths की तुलना।
- `ssrf_redirect_hunter.md`: URL fetch params/redirect chains से SSRF/open-redirect candidates की पहचान।
- `logic_flaw_hunter.md`: कई चरणों वाली logic flaws।
- `session_scope_hunter.md`: token audience/scope का दुरुपयोग।
- `rate_limit_abuse_hunter.md`: throttling/abuse की कमियाँ।
- `report_writer.md`: evidence-केंद्रित reporting।

## वैकल्पिक attribution tagging

Logs में Burp/LLM traffic को tag करने के लिए, header rewrite जोड़ें (proxy या Burp Match/Replace):<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## सुरक्षा संबंधी नोट्स

- जब ट्रैफ़िक में संवेदनशील डेटा हो, तो **local models** को प्राथमिकता दें।
- किसी finding के लिए केवल आवश्यक न्यूनतम evidence साझा करें।
- Burp को ही source of truth रखें; model का उपयोग **analysis और reporting** के लिए करें, scanning के लिए नहीं।

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** एक Burp extension है, जो local/cloud LLMs को passive/active analysis (62 vulnerability classes) के साथ जोड़ता है और 53+ MCP tools उपलब्ध कराता है, ताकि external MCP clients Burp को orchestrate कर सकें।<sup>[[5]](#references)</sup> मुख्य बातें:

- **Context-menu triage**: Proxy के ज़रिए ट्रैफ़िक capture करें, **Proxy > HTTP History** खोलें, किसी request पर right-click करें → **Extensions > Burp AI Agent > Analyze this request** चुनें। इससे उस request/response से जुड़ी AI chat शुरू होगी।
- **Backends** (हर profile के लिए चुने जा सकते हैं):
  - Local HTTP: **Ollama**, **LM Studio**।
  - Remote HTTP: **OpenAI-compatible** endpoint (base URL + model name)।
  - Cloud CLIs: **Gemini CLI** (`gemini auth login`), **Claude CLI** (`export ANTHROPIC_API_KEY=...` या `claude login`), **Codex CLI** (`export OPENAI_API_KEY=...`), **OpenCode CLI** (provider-specific login)।
- **Agent profiles**: prompt templates अपने-आप `~/.burp-ai-agent/AGENTS/` में install होते हैं; custom analysis/scanning behaviors जोड़ने के लिए वहाँ अतिरिक्त `*.md` files रखें।
- **MCP server**: Burp operations को किसी भी MCP client के लिए उपलब्ध कराने हेतु **Settings > MCP Server** में इसे enable करें (53+ tools)। Claude Desktop को server से जोड़ने के लिए `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) या `%APPDATA%\Claude\claude_desktop_config.json` (Windows) edit करें।
- **Privacy controls**: STRICT / BALANCED / OFF, remote models को भेजने से पहले संवेदनशील request data को redact करते हैं; secrets संभालते समय local backends को प्राथमिकता दें।
- **Audit logging**: AI/MCP actions की छेड़छाड़-स्पष्ट traceability के लिए हर entry पर SHA-256 integrity hashing वाले JSONL logs।
- **Build/load**: release JAR download करें या Java 21 से build करें:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

संचालन संबंधी सावधानियाँ: privacy mode लागू न होने पर cloud backends session cookies/PII को exfiltrate कर सकते हैं; MCP का exposure Burp का remote orchestration सक्षम करता है, इसलिए access को trusted agents तक सीमित रखें और integrity-hashed audit log की निगरानी करें।



## References

- [1] [Burp MCP + Codex CLI एकीकरण और Caddy handshake सुधार](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server में सख्त Origin/header validation की समस्या](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty research के लिए Codex का उपयोग कैसे करें: व्यापक रूप से खोजें, कठोरता से सत्यापित करें](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code और Codex के लिए Burp Suite orchestration](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server के tool implementations और parameters](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF vulnerabilities](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - WebSockets history](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Burp Repeater में WebSocket messages के साथ काम करना](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
