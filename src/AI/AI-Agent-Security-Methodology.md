# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

Agent assessment में **attacker-controlled input से externally observable effect तक** की कड़ी का अनुसरण करना चाहिए। Jailbreaking, character changes और system-prompt disclosure यह साबित करते हैं कि reasoning channel को प्रभावित किया जा सकता है, लेकिन high-impact finding वह chain है जो data access, unauthorized tool action, downstream injection sink, persistence या किसी दूसरे agent तक पहुँचती है।<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) coverage को label करने के लिए उपयोगी है (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust और rogue agents)। इन labels का उपयोग end-to-end attack path बनाने के बाद करें; model के unexpected text को test का अंत न मानें।<sup>[[1]](#references)[[2]](#references)</sup>

## Target map बनाएँ

Payloads लिखने से पहले हर agent workflow के लिए इन पाँच dimensions को दर्ज करें:<sup>[[2]](#references)</sup>

| Dimension | क्या-क्या सूचीबद्ध करें | Security question |
|---|---|---|
| **Untrusted input** | Chat/API parameters, URLs, documents, email, tickets, calendar entries, retrieved chunks, memory, tool results और peer-agent messages | Attacker कहाँ ऐसा content रख सकता है जो बाद में model context में जाए? |
| **Tools** | Tool names और schemas, side effects, auto-execution, confirmation behavior और dynamically loaded tools | कौन-सी calls secrets पढ़ती हैं, state लिखती हैं, messages भेजती हैं, data delete करती हैं, code execute करती हैं या value transfer करती हैं? |
| **Authority** | User delegation, service accounts, API tokens, credential lifetime, tenant/resource scope और network reach | हर call किस identity के रूप में चलती है, और क्या tool boundary पर authorization दोबारा जाँचा जाता है? |
| **Processing** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, file operations और deserializers | Model-generated data कहाँ किसी दूसरे interpreter के लिए syntax बन जाता है? |
| **Output** | Responses, rendered Markdown/HTML, links, image fetches, webhooks, email, files, logs, reports, metrics और peer-agent traffic | कौन-सा observable channel secret ले जा सकता है या secondary request trigger कर सकता है? |

इसे advertised integrations की सूची तक सीमित न करें। एक उपयोगी artifact में हर source को उस सटीक context position से map करें जहाँ वह पहुँचता है, उस बिंदु पर उपलब्ध tools, हर tool द्वारा उपयोग किए गए credentials, downstream interpreter और हर egress route को दर्ज करें। Per-user read token वाला वही tool कम impact वाला हो सकता है, जबकि shared administrator credential के साथ critical हो सकता है।<sup>[[2]](#references)</sup>

## Reconnaissance

### हर delivery और ingestion path को map करें

Delivery surface (web, mobile, API, email, chat platform, browser extension) से शुरुआत करें और client-to-backend traffic को proxy करें। UI में छिपे fields, search/autocomplete/filter parameters, conversation-state objects, upload और indexing jobs, tool responses तथा sub-agent traffic की जाँच करें। असली request schema देखने से पहले certificate pinning bypass करने के लिए केवल mobile clients के मामले में emulator और instrumentation की ज़रूरत पड़ सकती है।<sup>[[2]](#references)</sup>

इसके बाद model के नीचे का stack map करें: orchestration framework, prompt assembly, retrieval और memory stores, runtime (उदाहरण के लिए Python, container या WASM), mounted volumes, host services, internal APIs, cloud metadata तक पहुँच और पड़ोसी networks। Framework के defaults मायने रखते हैं, क्योंकि कुछ “tool calls” code generate या evaluate करके लागू किए जाते हैं; runtime/sandbox boundary तय करती है कि उसका परिणाम containment में रहता है या नहीं।<sup>[[2]](#references)</sup>

### Non-destructive probes से routing fingerprint करें

एक in-scope request की तुलना कई असंबंधित requests से करें और पूरा response, status code, latency तथा streaming behavior सुरक्षित रखें। किसी task-specific reasoning से पहले मिलने वाला स्थिर rejection अलग gateway/classifier का संकेत हो सकता है; संदर्भ के आधार पर refusal से लगता है कि request model तक पहुँची; खाली या पूरी तरह extractive answer keyword search या सीमित retrieval का संकेत हो सकता है। इन्हें hypotheses मानें और उसी probe को alternate API fields तथा ingestion paths से replay करके पुष्टि करें।<sup>[[2]](#references)</sup>

Recon तब पूरा होता है जब assessment उस सबसे शुरुआती attacker-controlled source की पहचान कर सके जो agent के behavior को बदलता है **और** उस source से पहुँच योग्य tools, identities, interpreters तथा outputs की भी।<sup>[[2]](#references)</sup>

## Exploitation: trust boundary पार करें

केवल prompt wording नहीं, channels को test करें। सामने से दिखने वाले entry point द्वारा क्या block होता है, यह जानने के लिए direct injection से शुरुआत करें; फिर नीचे दिए गए कम दिखाई देने वाले paths के ज़रिए उसी उद्देश्य को दोहराएँ:<sup>[[2]](#references)</sup>

- **Indirect content:** pages, files, email, tickets, metadata, alt text, HTML comments, off-screen text या zero-width characters। Payload delivery techniques के लिए [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) देखें।
- **Retrieval और memory:** ऐसा content poison करें जो बाद में retrieve होगा, या ऐसी state जो बाद के sessions में reload होगी। दर्ज करें कि original source delete करने पर behavior हटता है या नहीं।
- **Tool output और peer agents:** किसी tool response या agent-to-agent message में marker रखें, ताकि जाँचा जा सके कि internal traffic उन filters को bypass करता है या नहीं जो केवल user input और final output पर लागू होते हैं।
- **Supply chain:** tool descriptors, plugins, connected servers, skills, models और dependencies को trusted instruction sources के रूप में जाँचें। MCP-specific tests के लिए [MCP Servers](AI-MCP-Servers.md#mcp-vulns) देखें।
- **Human approval:** actual structured tool call की तुलना model-generated approval text से करें। जाँचें कि attacker का प्रभाव destination, scope, प्रभावित objects या irreversible side effects को छोड़ सकता है या नहीं।

पहले एक harmless, unique marker इस्तेमाल करें। Source artifact, observable होने पर assembled context, selected tool call, approval data, backend request/response और final state सुरक्षित रखें। इससे यह स्पष्ट होता है कि प्रभाव वास्तव में पड़ा या केवल action होने का hallucinated दावा किया गया।<sup>[[2]](#references)</sup>

## Execution: वास्तविक impact साबित करें

Influence से impact तक पहुँचने के दो अलग-अलग रास्ते हैं:<sup>[[2]](#references)</sup>

1. **Capability abuse:** authorized tool पहले से ही उद्देश्य पूरा करता है। उदाहरणों में एक tenant का record पढ़कर उसे attacker-visible report में लिखना, email भेजना, records बदलना, file delete करना या payment शुरू करना शामिल है। किसी secondary software bug की आवश्यकता नहीं है।
2. **Downstream sink exploitation:** attacker के नियंत्रण में आया model output किसी दूसरे component के लिए syntax बन जाता है। Database queries में [SQL injection](../pentesting-web/sql-injection/README.md) या [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers में [command injection](../pentesting-web/command-injection.md), चुने हुए URLs में [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), file operations में traversal, template/code evaluators में RCE और object parsers में [unsafe deserialization](../pentesting-web/deserialization/README.md) की जाँच करें।

हर candidate के लिए यह chain साबित करें:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

एक read-only integration भी तब exploit की जा सकती है, जब बाद का कोई component पढ़ी गई सामग्री को publish कर सके। सामान्य responses के साथ-साथ कम स्पष्ट egress का भी परीक्षण करें, जैसे attacker-controlled links, automatic image retrieval, webhooks, logs, reports, counters, notifications और दूसरे agents को भेजे गए messages।<sup>[[2]](#references)</sup>

## उद्देश्यों पर कार्रवाइयाँ

किसी एक कार्रवाई की पुष्टि करने के बाद, पहले दिखाई देने वाले प्रभाव पर रुकने के बजाय पूरे blast radius का मूल्यांकन करें:<sup>[[2]](#references)</sup>

- **Exfiltration:** secrets, user records, internal files, conversation data या prompt/context content किसी observable channel से बाहर जाते हैं।
- **Unauthorized action:** agent, attacker के उद्देश्य के लिए वैध write capabilities का उपयोग करता है।
- **Denial of service:** destructive tools या बार-बार किए गए महँगे operations, integrity या availability को प्रभावित करते हैं।
- **Persistence:** poisoned memory, indexed content, trusted state या runtime changes, मूल session या source हटाए जाने के बाद भी बने रहते हैं।
- **Propagation:** कोई trusted peer, compromised agent का message या shared state ग्रहण करता है और अपने tools व credentials से वही कार्रवाई दोहराता है।

Severity का निर्धारण reachable data, effective privilege, sink exploitability, egress, persistence और propagation के आधार पर होना चाहिए—न कि इस आधार पर कि model का text कितना चौंकाने वाला लगता है।<sup>[[2]](#references)</sup>

## आकलन के दौरान सत्यापित किए जाने वाले controls

Prompt filters और बेहतर system prompt, attacker की लागत बढ़ा सकते हैं, लेकिन उन्हें authorization boundaries नहीं मानना चाहिए। नीचे दिए गए controls को direct input, indirect content, memory, tools और peer agents के ज़रिए वही chain दोबारा चलाकर सत्यापित करें:<sup>[[2]](#references)</sup>

- एक deterministic policy layer, **हर tool invocation** पर authenticated user, tenant, object, action और destination की जाँच करती है; model, caller identity दे या बदल नहीं सकता।
- Read और write capabilities के लिए अलग-अलग, least-privilege, short-lived credentials इस्तेमाल होते हैं; high-impact tools सिर्फ़ ज़रूरत पड़ने पर उपलब्ध कराए जाते हैं और ingested content से कभी auto-execute नहीं होते।
- Network egress और internal destinations को model द्वारा चुने गए URLs से स्वतंत्र रूप से allowlist किया जाता है; metadata endpoints, mounted secrets और आस-पास की services तक runtime की पहुँच, ज़रूरत न होने पर blocked रहती है।
- Approval UI, canonical structured request से generate किया जाता है और उसमें free-form model summary के बजाय सटीक arguments, identity, destination, प्रभावित objects और side effects दिखाए जाते हैं।
- सफलता की पुष्टि destination system या system of record से की जाती है। Agent का narration, tool-call request या HTTP redirect, बताए गए state change का प्रमाण नहीं है।
- Memory और retrieval entries में provenance और trust labels बने रहते हैं; उन्हें invalidate किया जा सकता है और बाद की कार्रवाई में उपयोग किए जाने पर उनका फिर से authorization किया जाता है।
- Inter-agent messages को untrusted requests के रूप में authenticate और authorize किया जाता है; किसी peer की reputation या agent card, receiver के tools को अपने-आप delegate नहीं करती।

## References

- [1] [2026 के लिए OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agents पर हमले करने की Hacker's Guide](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
