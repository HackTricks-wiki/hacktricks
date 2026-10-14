# AI Agent सुरक्षा कार्यप्रणाली

{{#include ../banners/hacktricks-training.md}}

Agent assessment में **attacker-controlled input से बाहरी रूप से देखे जा सकने वाले प्रभाव तक** की कड़ी का अनुसरण करना चाहिए। Jailbreaking, character changes और system-prompt disclosure यह साबित करते हैं कि reasoning channel को प्रभावित किया जा सकता है, लेकिन high-impact finding वह कड़ी है जो data access, unauthorized tool action, downstream injection sink, persistence या किसी दूसरे agent तक पहुँचती है।<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) coverage को label करने में उपयोगी है (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust और rogue agents)। इन labels का उपयोग end-to-end attack path बनाने के बाद करें; model के अप्रत्याशित text को test का अंत न मानें।<sup>[[1]](#references)[[2]](#references)</sup>

## Target map बनाएँ

Payloads लिखने से पहले हर agent workflow के लिए इन पाँच dimensions को दर्ज करें:<sup>[[2]](#references)</sup>

| Dimension | क्या सूचीबद्ध करें | Security question |
|---|---|---|
| **Untrusted input** | Chat/API parameters, URLs, documents, email, tickets, calendar entries, retrieved chunks, memory, tool results और peer-agent messages | Attacker ऐसा content कहाँ रख सकता है जो बाद में model context में पहुँचे? |
| **Tools** | Tool names और schemas, side effects, auto-execution, confirmation behavior और dynamically loaded tools | कौन-सी calls secrets पढ़ती हैं, state लिखती हैं, messages भेजती हैं, data delete करती हैं, code execute करती हैं या value transfer करती हैं? |
| **Authority** | User delegation, service accounts, API tokens, credential lifetime, tenant/resource scope और network reach | हर call किस identity से चलती है, और क्या tool boundary पर authorization दोबारा जाँचा जाता है? |
| **Processing** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, file operations और deserializers | Model-generated data कहाँ किसी दूसरे interpreter के लिए syntax बन जाता है? |
| **Output** | Responses, rendered Markdown/HTML, links, image fetches, webhooks, email, files, logs, reports, metrics और peer-agent traffic | कौन-सा observable channel secret बाहर भेज सकता है या secondary request trigger कर सकता है? |

इसे advertised integrations की सूची तक सीमित न करें। एक उपयोगी artifact हर source को उस exact context position से map करता है जहाँ वह पहुँचता है, उस बिंदु पर उपलब्ध tools, हर tool द्वारा इस्तेमाल किया गया credential, downstream interpreter और हर egress route। Per-user read token वाला tool कम प्रभाव वाला हो सकता है, जबकि shared administrator credential के साथ वही tool critical हो सकता है।<sup>[[2]](#references)</sup>

## Reconnaissance

### हर delivery और ingestion path map करें

Delivery surface (web, mobile, API, email, chat platform, browser extension) से शुरू करें और client-to-backend traffic को proxy करें। UI द्वारा छिपाए गए fields, search/autocomplete/filter parameters, conversation-state objects, upload और indexing jobs, tool responses और sub-agent traffic की जाँच करें। Certificate pinning bypass करने और असली request schema देखने के लिए mobile-only clients में emulator और instrumentation की ज़रूरत हो सकती है।<sup>[[2]](#references)</sup>

फिर model के नीचे के stack को map करें: orchestration framework, prompt assembly, retrieval और memory stores, runtime (उदाहरण के लिए Python, container या WASM), mounted volumes, host services, internal APIs, cloud metadata तक पहुँचने की क्षमता और neighboring networks। Framework defaults महत्वपूर्ण हैं, क्योंकि कुछ “tool calls” code generate या evaluate करके लागू किए जाते हैं; runtime/sandbox boundary तय करती है कि नतीजा सीमित रहता है या नहीं।<sup>[[2]](#references)</sup>

### Non-destructive probes से routing पहचानें

पूरा response, status code, latency और streaming behavior जस का तस रखते हुए, in-scope request की तुलना कई असंबंधित requests से करें। Task-specific reasoning से पहले मिलने वाली स्थिर अस्वीकृति अलग gateway/classifier का संकेत हो सकती है; संदर्भ के अनुरूप refusal बताता है कि request model तक पहुँची; खाली या केवल extractive जवाब keyword search या सीमित retrieval का संकेत हो सकता है। इन्हें hypotheses मानें और उसी probe को alternate API fields और ingestion paths से दोहराकर पुष्टि करें।<sup>[[2]](#references)</sup>

Recon तब पूरा होता है जब assessment उस शुरुआती attacker-controlled source की पहचान कर सके जो agent के behavior को बदलता है **और** उस source से उपलब्ध tools, identities, interpreters और outputs की भी।<sup>[[2]](#references)</sup>

## Exploitation: trust boundary पार करें

सिर्फ prompt wording नहीं, channels भी test करें। पहले direct injection से पता करें कि visible front door क्या रोकता है, फिर नीचे दिए गए कम दिखाई देने वाले paths से उसी इरादे को दोहराएँ:<sup>[[2]](#references)</sup>

- **Indirect content:** pages, files, email, tickets, metadata, alt text, HTML comments, off-screen text या zero-width characters। Payload-delivery techniques के लिए [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) देखें।
- **Retrieval और memory:** ऐसा content poison करें जिसे बाद में retrieve किया जाएगा या ऐसा state जिसे बाद के sessions में फिर load किया जाएगा। दर्ज करें कि मूल source delete करने पर behavior हटता है या नहीं।
- **Tool output और peer agents:** किसी tool response या agent-to-agent message में marker डालें, ताकि पता चले कि internal traffic उन filters को bypass करता है या नहीं जो सिर्फ user input और final output पर लागू होते हैं।
- **Supply chain:** Tool descriptors, plugins, connected servers, skills, models और dependencies को trusted instruction sources के रूप में जाँचें। MCP-specific tests के लिए [MCP Servers](AI-MCP-Servers.md#mcp-vulns) देखें।
- **Human approval:** असली structured tool call की तुलना model-generated approval text से करें। जाँचें कि attacker का प्रभाव destination, scope, प्रभावित objects या irreversible side effects को हटवा सकता है या नहीं।

पहले benign, unique marker इस्तेमाल करें। Source artifact, दिखने पर assembled context, चुनी गई tool call, approval data, backend request/response और final state सुरक्षित रखें। इससे influence और किसी action के होने के hallucinated दावे में फर्क किया जा सकता है।<sup>[[2]](#references)</sup>

### Subagent context isolation

Non-fork Claude Agent SDK subagent को अपना `AgentDefinition.prompt`, delegation prompt और उपलब्ध tools मिलते हैं, लेकिन parent system prompt या conversation नहीं मिलते। अगर उसकी definition में `tools` छोड़ा गया है, तो उसे subagents के लिए उपलब्ध tools विरासत में मिलते हैं; project `CLAUDE.md` फिर भी load हो सकता है। इसलिए जब child वही filesystem या execution tools इस्तेमाल कर सकता हो, तो केवल parent तक सीमित prompt restriction भरोसेमंद boundary नहीं है।<sup>[[4]](#references)</sup>

Parent द्वारा अस्वीकार की गई direct request की तुलना उसी task को named subagent को सौंपने से करके boundary test करें। NCC Group की रिपोर्ट के अनुसार, operating-system file enumeration की एक अस्वीकृत request child के लिए एक harmless "layout map" के रूप में दोबारा पेश करने पर सफल हुई।<sup>[[3]](#references)</sup>

सिर्फ parent के final answer को नहीं, child की वास्तविक tool calls और प्रभावी tool allowlist को भी जाँचें; पुष्टि करें कि child ने उन files तक पहुँच बनाई या नहीं जिन तक parent नहीं पहुँचता।<sup>[[4]](#references)</sup> यह guardrail inheritance failure है, [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) या container escape का प्रमाण नहीं।<sup>[[3]](#references)[[4]](#references)</sup>

## Execution: असली प्रभाव साबित करें

Influence से impact तक पहुँचने के दो अलग रास्ते हैं:<sup>[[2]](#references)</sup>

1. **Capability abuse:** अधिकृत tool पहले से ही उद्देश्य पूरा करता है। उदाहरण के लिए, किसी tenant का record पढ़कर उसे attacker-visible report में लिखना, email भेजना, records बदलना, file delete करना या payment शुरू करना। किसी secondary software bug की ज़रूरत नहीं होती।
2. **Downstream sink exploitation:** Attacker द्वारा steered model output किसी दूसरे component के लिए syntax बन जाता है। Database queries में [SQL injection](../pentesting-web/sql-injection/README.md) या [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers में [command injection](../pentesting-web/command-injection.md), चुने गए URLs में [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), file operations में traversal, template/code evaluators में RCE और object parsers में [unsafe deserialization](../pentesting-web/deserialization/README.md) की जाँच करें।

हर संभावित मामले के लिए यह कड़ी साबित करें:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

एक read-only integration भी exploit की जा सकती है, यदि बाद का कोई भी component पढ़ी गई सामग्री को प्रकाशित कर सकता हो। सामान्य responses के साथ-साथ कम स्पष्ट egress की भी जाँच करें, जैसे attacker के नियंत्रण वाले links, automatic image retrieval, webhooks, logs, reports, counters, notifications और दूसरे agents को भेजे गए messages।<sup>[[2]](#references)</sup>

## उद्देश्यों पर कार्रवाइयाँ

किसी एक कार्रवाई की पुष्टि करने के बाद, पहले दिखाई देने वाले प्रभाव पर रुकने के बजाय पूरे blast radius का आकलन करें:<sup>[[2]](#references)</sup>

- **डेटा की चोरी:** secrets, user records, internal files, conversation data या prompt/context content किसी देखे जा सकने वाले channel से बाहर जाता है।
- **अनधिकृत कार्रवाई:** agent, attacker के उद्देश्य के लिए वैध write capabilities का उपयोग करता है।
- **सेवा से इनकार:** destructive tools या बार-बार किए गए महँगे operations से integrity या availability प्रभावित होती है।
- **स्थायित्व:** poisoned memory, indexed content, trusted state या runtime में किए गए बदलाव, मूल session या source हटाए जाने के बाद भी बने रहते हैं।
- **प्रसार:** कोई trusted peer compromised agent के message या shared state का उपयोग करता है और अपने tools तथा credentials से वही कार्रवाई दोहराता है।

Severity का निर्धारण पहुँच योग्य data, प्रभावी privilege, sink की exploitability, egress, persistence और propagation के आधार पर होना चाहिए—इस आधार पर नहीं कि model का text कितना चौंकाने वाला लगता है।<sup>[[2]](#references)</sup>

## आकलन के दौरान जाँचे जाने वाले controls

Prompt filters और बेहतर system prompt attacker की लागत बढ़ा सकते हैं, लेकिन इन्हें authorization boundaries नहीं मानना चाहिए। नीचे दिए गए controls को direct input, indirect content, memory, tools और peer agents के माध्यम से वही chain दोबारा चलाकर जाँचें:<sup>[[2]](#references)</sup>

- एक deterministic policy layer, **हर tool invocation** पर authenticated user, tenant, object, action और destination की जाँच करती है; model caller की identity दे या बदल नहीं सकता।
- Read और write capabilities के लिए अलग-अलग, least-privilege, short-lived credentials का उपयोग होता है; high-impact tools केवल आवश्यकता के समय उपलब्ध कराए जाते हैं और ingested content से कभी auto-execute नहीं होते।
- Network egress और internal destinations को model द्वारा चुने गए URLs से स्वतंत्र रूप से allowlist किया जाता है; metadata endpoints, mounted secrets और पड़ोसी services तक runtime की पहुँच को तब तक block रखा जाता है, जब तक उनकी आवश्यकता न हो।
- Approval UI, canonical structured request से तैयार होता है और उसमें सटीक arguments, identity, destination, प्रभावित objects और side effects दिखाए जाते हैं—सिर्फ model का free-form सारांश नहीं।
- सफलता की पुष्टि destination system या system of record से की जाती है। Agent का विवरण, tool-call request या HTTP redirect, दावे किए गए state change का प्रमाण नहीं है।
- Memory और retrieval entries में provenance और trust labels बने रहते हैं, उन्हें invalidate किया जा सकता है, और बाद की कार्रवाई में उपयोग किए जाने पर उनके लिए फिर से authorization लिया जाता है।
- Inter-agent messages को untrusted requests की तरह authenticate और authorize किया जाता है; किसी peer की प्रतिष्ठा या agent card से receiver के tools का उपयोग करने की अनुमति अपने-आप नहीं मिलती।

## References

- [1] [2026 के लिए OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agents पर हमले करने के लिए Hacker की Guide](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AI Agent को उसके Sandbox से बाहर निकालना वास्तव में कितना कठिन है?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK में Subagents](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
