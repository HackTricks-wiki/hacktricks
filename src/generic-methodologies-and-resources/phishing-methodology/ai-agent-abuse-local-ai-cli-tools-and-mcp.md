# AI Agent Abuse: Local AI CLI Tools & MCP (Claude/Gemini/Warp)

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Local AI command-line interfaces (AI CLIs) जैसे Claude Code, Gemini CLI, Warp और समान टूल अक्सर शक्तिशाली बिल्ट‑इन के साथ आते हैं: filesystem read/write, shell execution और outbound network access. कई MCP क्लाइंट के रूप में कार्य करते हैं (Model Context Protocol), जिससे मॉडल STDIO या HTTP के माध्यम से बाहरी टूल्स को कॉल कर सकता है। चूँकि LLM टूल‑चेन की योजना गैर‑निर्धारित तरीके से बनाता है, एक जैसे prompts विभिन्न रन और होस्ट्स पर अलग प्रक्रिया, फ़ाइल और नेटवर्क व्यवहार का कारण बन सकते हैं।

सामान्य AI CLIs में देखे जाने वाले मुख्य यांत्रिकी:
- सामान्यतः Node/TypeScript में लागू, एक पतले wrapper के साथ जो मॉडल लॉन्च कर के टूल्स को एक्सपोज़ करता है।
- कई मोड: interactive chat, plan/execute, और single‑prompt run.
- MCP client support with STDIO and HTTP transports, जिससे लोकल और रिमोट क्षमता दोनों का विस्तार संभव होता है।

Abuse impact: एक ही प्रॉम्प्ट credentials का inventory और exfiltrate कर सकता है, स्थानीय फ़ाइलों में बदलाव कर सकता है, और चुपचाप capability बढ़ा सकता है रिमोट MCP सर्वरों से कनेक्ट करके (visibility gap यदि वे सर्वर थर्ड‑पार्टी हों)।

---

## Adversary Playbook – Prompt‑Driven Secrets Inventory

एजेंट को तेज़ी से credentials/secrets को triage और stage करने का निर्देश दें ताकि वे चुपके से exfiltration के लिए तैयार हो सकें:

- Scope: $HOME और application/wallet dirs के तहत recursive enumeration; noisy/pseudo paths से बचें (`/proc`, `/sys`, `/dev`)।
- Performance/stealth: recursion depth को cap करें; `sudo`/priv‑escalation से बचें; results को summarise करें।
- Targets: `~/.ssh`, `~/.aws`, cloud CLI creds, `.env`, `*.key`, `id_rsa`, `keystore.json`, browser storage (LocalStorage/IndexedDB profiles), crypto‑wallet data।
- Output: संक्षेप में सूची `/tmp/inventory.txt` में लिखें; यदि फाइल मौजूद है तो overwrite करने से पहले timestamped backup बनाएं।

Example operator prompt to an AI CLI:
```
You can read/write local files and run shell commands.
Recursively scan my $HOME and common app/wallet dirs to find potential secrets.
Skip /proc, /sys, /dev; do not use sudo; limit recursion depth to 3.
Match files/dirs like: id_rsa, *.key, keystore.json, .env, ~/.ssh, ~/.aws,
Chrome/Firefox/Brave profile storage (LocalStorage/IndexedDB) and any cloud creds.
Summarize full paths you find into /tmp/inventory.txt.
If /tmp/inventory.txt already exists, back it up to /tmp/inventory.txt.bak-<epoch> first.
Return a short summary only; no file contents.
```
---

## MCP के माध्यम से क्षमता विस्तार (STDIO और HTTP)

AI CLIs अक्सर अतिरिक्त टूल्स तक पहुँचने के लिए MCP क्लाइंट के रूप में कार्य करते हैं:

- STDIO transport (local tools): क्लाइंट एक सहायक चेन (helper chain) बनाता है ताकि टूल सर्वर चल सके। Typical lineage: `node → <ai-cli> → uv → python → file_write`. Example observed: `uv run --with fastmcp fastmcp run ./server.py` जो `python3.13` शुरू करता है और एजेंट की ओर से लोकल फाइल ऑपरेशन्स करता है।
- HTTP transport (remote tools): क्लाइंट outbound TCP खोलता है (e.g., port 8000) एक remote MCP server से, जो requested action execute करता है (e.g., write `/home/user/demo_http`)। एंडपॉइंट पर आपको केवल क्लाइंट की नेटवर्क एक्टिविटी दिखेगी; server‑side file touches होस्ट के बाहर होंगे।

Notes:
- MCP tools मॉडल को बताया जाते हैं और planning द्वारा स्वतः चयन किए जा सकते हैं। रन के बीच व्यवहार बदलता है।
- Remote MCP servers blast radius बढ़ाते हैं और host‑side visibility घटाते हैं।

---

## लोकल आर्टिफैक्ट्स और लॉग्स (Forensics)

- Gemini CLI सत्र लॉग्स: `~/.gemini/tmp/<uuid>/logs.json`
- आम तौर पर देखे जाने वाले फ़ील्ड: `sessionId`, `type`, `message`, `timestamp`.
- Example `message`: `"@.bashrc what is in this file?"` (user/agent का इरादा कैप्चर किया गया).
- Claude Code history: `~/.claude/history.jsonl`
- JSONL एंट्रीज़ जिनमें फ़ील्ड्स जैसे `display`, `timestamp`, `project` शामिल होते हैं।

इन लोकल लॉग्स को अपने LLM gateway/proxy (e.g., LiteLLM) पर देखी गई requests के साथ correlate करें ताकि tampering/model‑hijacking का पता चले: यदि जो मॉडल ने प्रोसेस किया वह लोकल prompt/output से भिन्न है, तो injected instructions या compromised tool descriptors की जाँच करें।

---

## Endpoint Telemetry Patterns

Amazon Linux 2023 पर Node v22.19.0 और Python 3.13 के साथ प्रतिनिधि चेन:

1) Built‑in tools (local file access)
- Parent: `node .../bin/claude --model <model>` (या CLI के लिए समतुल्य)
- Immediate child action: एक लोकल फ़ाइल बनाना/संशोधित करना (उदा., `demo-claude`)। फ़ाइल ईवेंट को parent→child lineage के माध्यम से जोड़ें।

2) MCP over STDIO (local tool server)
- Chain: `node → uv → python → file_write`
- Example spawn: `uv run --with fastmcp fastmcp run /home/ssm-user/tools/server.py`

3) MCP over HTTP (remote tool server)
- Client: `node/<ai-cli>` आउटबाउंड TCP खोलता है `remote_port: 8000` (या समान)
- Server: remote Python process request को हैंडल करता है और `/home/ssm-user/demo_http` लिखता है।

क्योंकि agent के निर्णय रन के हिसाब से भिन्न होते हैं, सटीक प्रक्रियाओं और प्रभावित पाथ्स में विविधता की उम्मीद करें।

---

## Detection Strategy

Telemetry sources
- Linux EDR — process, file और network events के लिए eBPF/auditd का उपयोग।
- Local AI‑CLI logs prompt/intent की visibility के लिए।
- LLM gateway logs (e.g., LiteLLM) cross‑validation और model‑tamper detection के लिए।

Hunting heuristics
- संवेदनशील file touches को AI‑CLI parent chain (उदा., `node → <ai-cli> → uv/python`) से जोड़ें।
- निम्नलिखित के तहत access/reads/writes पर अलर्ट करें: `~/.ssh`, `~/.aws`, browser profile storage, cloud CLI creds, `/etc/passwd`।
- AI‑CLI प्रोसेस से अनपेक्षित outbound connections को unapproved MCP endpoints (HTTP/SSE, 8000 जैसे ports) पर flag करें।
- लोकल `~/.gemini`/`~/.claude` आर्टिफैक्ट्स को LLM gateway prompts/outputs के साथ correlate करें; divergence संभावित hijacking का संकेत है।

उदाहरण pseudo‑rules (अपने EDR के अनुसार अनुकूलित करें):
```yaml
- when: file_write AND path IN ["$HOME/.ssh/*","$HOME/.aws/*","/etc/passwd"]
and ancestor_chain CONTAINS ["node", "claude|gemini|warp", "python|uv"]
then: alert("AI-CLI secrets touch via tool chain")

- when: outbound_tcp FROM process_name =~ "node|python" AND parent =~ "claude|gemini|warp"
and dest_port IN [8000, 3333, 8787]
then: tag("possible MCP over HTTP")
```
हार्डनिंग सुझाव
- फ़ाइल/सिस्टम टूल्स के लिए स्पष्ट उपयोगकर्ता अनुमोदन आवश्यक करें; टूल योजनाओं को लॉग करें और प्रदर्शित करें।
- AI‑CLI प्रक्रियाओं के नेटवर्क निकास को अनुमोदित MCP सर्वरों तक सीमित करें।
- निरंतर, छेड़छाड़-रोधी ऑडिटिंग के लिए स्थानीय AI‑CLI लॉग्स और LLM gateway लॉग्स को भेजें/इंजेस्ट करें।

---

## ब्लू‑टीम पुनरुत्पादन नोट्स

इन चेन को पुनरुत्पादित करने के लिए एक साफ़ VM पर EDR या eBPF tracer का उपयोग करें, उदाहरण के लिए:
- `node → claude --model claude-sonnet-4-20250514` फिर तुरंत स्थानीय फ़ाइल लिखना।
- `node → uv run --with fastmcp ... → python3.13` जो `$HOME` के अंतर्गत लिख रहा है।
- `node/<ai-cli>` जो एक बाहरी MCP सर्वर (port 8000) पर TCP स्थापित कर रहा है जबकि एक रिमोट Python प्रक्रिया एक फ़ाइल लिखती है।

सत्यापित करें कि आपकी डिटेक्शंस फ़ाइल/नेटवर्क इवेंट्स को आरंभ करने वाले AI‑CLI parent से जोड़ती हैं ताकि false positives से बचा जा सके।

---

## संदर्भ

- [Commanding attention: How adversaries are abusing AI CLI tools (Red Canary)](https://redcanary.com/blog/threat-detection/ai-cli-tools/)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
- [LiteLLM – LLM Gateway/Proxy](https://docs.litellm.ai)

{{#include ../../banners/hacktricks-training.md}}
