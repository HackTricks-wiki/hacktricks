# AI Agent Abuse: Local AI CLI Tools & MCP (Claude/Gemini/Warp)

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Local AI command-line interfaces (AI CLIs) जैसे Claude Code, Gemini CLI, Warp और समान टूल अक्सर शक्तिशाली बिल्ट‑इन के साथ आते हैं: filesystem read/write, shell execution और outbound network access. कई MCP क्लाइंट (Model Context Protocol) के रूप में काम करते हैं, जिससे मॉडल STDIO या HTTP के माध्यम से बाहरी टूल्स को कॉल कर सकता है। चूँकि LLM गैर-निर्धारणात्मक रूप से tool-chains की योजना बनाता है, समान prompts विभिन्न runs और hosts पर अलग process, file और network व्यवहारों का कारण बन सकते हैं।

Key mechanics seen in common AI CLIs:
- Typically implemented in Node/TypeScript with a thin wrapper launching the model and exposing tools.
- Multiple modes: interactive chat, plan/execute, and single‑prompt run.
- MCP client support with STDIO and HTTP transports, enabling both local and remote capability extension.

Abuse impact: A single prompt can inventory and exfiltrate credentials, modify local files, and silently extend capability by connecting to remote MCP servers (visibility gap if those servers are third‑party).

---

## Adversary Playbook – Prompt‑Driven Secrets Inventory

Task the agent to quickly triage and stage credentials/secrets for exfiltration while staying quiet:

- दायरा: $HOME और application/wallet dirs के तहत recursively enumerate करें; noisy/pseudo paths (`/proc`, `/sys`, `/dev`) से बचें।
- प्रदर्शन/स्टील्थ: recursion depth को सीमित रखें; `sudo`/priv‑escalation से बचें; परिणामों का सार दें।
- लक्ष्य: `~/.ssh`, `~/.aws`, cloud CLI creds, `.env`, `*.key`, `id_rsa`, `keystore.json`, browser storage (LocalStorage/IndexedDB profiles), crypto‑wallet data।
- आउटपुट: एक संक्षिप्त सूची `/tmp/inventory.txt` में लिखें; यदि फ़ाइल मौजूद है, तो overwrite करने से पहले एक timestamped बैकअप बनाएं।

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

## MCP के माध्यम से क्षमता विस्तार (STDIO and HTTP)

AI CLIs अक्सर अतिरिक्त टूल्स तक पहुँचने के लिए MCP क्लाइंट के रूप में काम करते हैं:

- STDIO transport (local tools): क्लाइंट एक सहायक चेन spawn करके tool server चलाता है. Typical lineage: `node → <ai-cli> → uv → python → file_write`. Example observed: `uv run --with fastmcp fastmcp run ./server.py` जो `python3.13` शुरू करता है और एजेंट की ओर से लोकल फाइल ऑपरेशंस करता है.
- HTTP transport (remote tools): क्लाइंट outbound TCP खोलता है (e.g., port 8000) एक remote MCP server के लिए, जो अनुरोधित कार्रवाई को execute करता है (e.g., write `/home/user/demo_http`). endpoint पर आप केवल क्लाइंट की नेटवर्क activity देखेंगे; server‑side file touches होस्ट के बाहर होते हैं।

Notes:
- MCP tools मॉडल को बताए जाते हैं और planning द्वारा auto‑selected हो सकते हैं। व्यवहार रन दर रन बदलता है।
- Remote MCP servers blast radius बढ़ाते हैं और host‑side visibility घटाते हैं।

---

## Local Artifacts and Logs (Forensics)

- Gemini CLI session logs: `~/.gemini/tmp/<uuid>/logs.json`
- Fields commonly seen: `sessionId`, `type`, `message`, `timestamp`.
- Example `message`: `"@.bashrc what is in this file?"` (user/agent intent captured).
- Claude Code history: `~/.claude/history.jsonl`
- JSONL entries with fields like `display`, `timestamp`, `project`.

इन लोकल लॉग्स को अपने LLM gateway/proxy (e.g., LiteLLM) पर देखे गए requests के साथ correlate करें ताकि tampering/model‑hijacking का पता चले: अगर मॉडल द्वारा process किया गया कंटेंट लोकल prompt/output से अलग है, तो injected instructions या compromised tool descriptors की जाँच करें।

---

## Endpoint Telemetry Patterns

Representative chains on Amazon Linux 2023 with Node v22.19.0 and Python 3.13:

1) Built‑in tools (local file access)
- Parent: `node .../bin/claude --model <model>` (or equivalent for the CLI)
- Immediate child action: create/modify a local file (e.g., `demo-claude`). फ़ाइल इवेंट को parent→child lineage के माध्यम से जोड़ें।

2) MCP over STDIO (local tool server)
- Chain: `node → uv → python → file_write`
- Example spawn: `uv run --with fastmcp fastmcp run /home/ssm-user/tools/server.py`

3) MCP over HTTP (remote tool server)
- Client: `node/<ai-cli>` opens outbound TCP to `remote_port: 8000` (or similar)
- Server: remote Python process handles the request and writes `/home/ssm-user/demo_http`.

एजेंट के निर्णय रन के अनुसार बदलते हैं, इसलिए exact processes और touched paths में variability की उम्मीद रखें।

---

## Detection Strategy

Telemetry sources
- Linux EDR using eBPF/auditd for process, file and network events.
- Local AI‑CLI logs for prompt/intent visibility.
- LLM gateway logs (e.g., LiteLLM) for cross‑validation and model‑tamper detection.

Hunting heuristics
- संवेदनशील फ़ाइल टच को AI‑CLI parent chain के साथ लिंक करें (e.g., `node → <ai-cli> → uv/python`)।
- अलर्ट करें जब access/reads/writes हों: `~/.ssh`, `~/.aws`, browser profile storage, cloud CLI creds, `/etc/passwd`.
- AI‑CLI प्रक्रिया से अनअपप्रूव्ड MCP endpoints (HTTP/SSE, ports like 8000) की ओर अनपेक्षित outbound connections पर फ्लैग लगाएं।
- लोकल `~/.gemini`/`~/.claude` artifacts को LLM gateway prompts/outputs के साथ correlate करें; divergence संभावित hijacking का संकेत है।

Example pseudo‑rules (adapt to your EDR):
```yaml
- when: file_write AND path IN ["$HOME/.ssh/*","$HOME/.aws/*","/etc/passwd"]
and ancestor_chain CONTAINS ["node", "claude|gemini|warp", "python|uv"]
then: alert("AI-CLI secrets touch via tool chain")

- when: outbound_tcp FROM process_name =~ "node|python" AND parent =~ "claude|gemini|warp"
and dest_port IN [8000, 3333, 8787]
then: tag("possible MCP over HTTP")
```
हार्डनिंग विचार
- फाइल/सिस्टम टूल्स के लिए स्पष्ट उपयोगकर्ता अनुमोदन आवश्यक करें; टूल योजनाओं को लॉग और प्रदर्शित करें।
- AI‑CLI प्रक्रियाओं के लिए नेटवर्क egress को अनुमोदित MCP सर्वरों तक सीमित करें।
- सुसंगत, छेड़छाड़-प्रतिरोधी ऑडिटिंग के लिए स्थानीय AI‑CLI लॉग्स और LLM gateway लॉग्स भेजें/इंजेस्ट करें।

---

## Blue‑Team पुनरुत्पादन नोट्स

इन तरह की चेन को पुनः उत्पन्न करने के लिए EDR या eBPF tracer के साथ एक साफ़ VM का उपयोग करें:
- `node → claude --model claude-sonnet-4-20250514` then immediate local file write.
- `node → uv run --with fastmcp ... → python3.13` writing under `$HOME`.
- `node/<ai-cli>` establishing TCP to an external MCP server (port 8000) while a remote Python process writes a file.

सत्यापित करें कि आपकी detections फाइल/नेटवर्क इवेंट्स को initiating AI‑CLI parent से जोड़ती हैं ताकि false positives से बचा जा सके।

---

## संदर्भ

- [Commanding attention: How adversaries are abusing AI CLI tools (Red Canary)](https://redcanary.com/blog/threat-detection/ai-cli-tools/)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
- [LiteLLM – LLM Gateway/Proxy](https://docs.litellm.ai)

{{#include ../../banners/hacktricks-training.md}}
