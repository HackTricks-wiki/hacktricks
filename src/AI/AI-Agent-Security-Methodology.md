# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

Agent assessment में **attacker-controlled input से externally observable effect तक** की कड़ी का अनुसरण करना चाहिए। Jailbreaking, character changes और system-prompt disclosure यह साबित करते हैं कि reasoning channel को प्रभावित किया जा सकता है, लेकिन high-impact finding वह कड़ी है जो data access, unauthorized tool action, downstream injection sink, persistence या किसी दूसरे agent तक पहुँचती है।<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) coverage को label करने के लिए उपयोगी है (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust और rogue agents)। इन labels का उपयोग end-to-end attack path बनाने के बाद करें; model के अप्रत्याशित text को test का अंत न मानें।<sup>[[1]](#references)[[2]](#references)</sup>

## Build the target map

Payloads लिखने से पहले हर agent workflow के लिए इन पाँच dimensions को दर्ज करें:<sup>[[2]](#references)</sup>

| Dimension | क्या सूचीबद्ध करें | Security question |
|---|---|---|
| **Untrusted input** | Chat/API parameters, URLs, documents, email, tickets, calendar entries, retrieved chunks, memory, tool results और peer-agent messages | Attacker ऐसा content कहाँ रख सकता है जो बाद में model context में आए? |
| **Tools** | Tool names और schemas, side effects, auto-execution, confirmation behavior और dynamically loaded tools | कौन-सी calls secrets पढ़ती हैं, state लिखती हैं, messages भेजती हैं, data delete करती हैं, code execute करती हैं या value transfer करती हैं? |
| **Authority** | User delegation, service accounts, API tokens, credential lifetime, tenant/resource scope और network reach | हर call किस identity के तहत चलती है, और क्या tool boundary पर authorization दोबारा जाँचा जाता है? |
| **Processing** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, file operations और deserializers | Model-generated data कहाँ किसी दूसरे interpreter के लिए syntax बनता है? |
| **Output** | Responses, rendered Markdown/HTML, links, image fetches, webhooks, email, files, logs, reports, metrics और peer-agent traffic | कौन-सा observable channel secret ले जा सकता है या secondary request trigger कर सकता है? |

इसे advertised integrations की सूची तक सीमित न करें। उपयोगी artifact में हर source को उस exact context position से map करें जहाँ वह पहुँचता है, उस बिंदु पर उपलब्ध tools, हर tool द्वारा इस्तेमाल की जाने वाली credential, downstream interpreter और हर egress route दर्ज करें। Per-user read token वाला वही tool कम प्रभाव वाला हो सकता है, जबकि shared administrator credential के साथ critical हो सकता है।<sup>[[2]](#references)</sup>

## Reconnaissance

### Map every delivery and ingestion path

Delivery surface (web, mobile, API, email, chat platform, browser extension) से शुरुआत करें और client-to-backend traffic को proxy करें। UI में छिपे fields, search/autocomplete/filter parameters, conversation-state objects, upload और indexing jobs, tool responses तथा sub-agent traffic की जाँच करें। असली request schema दिखने से पहले certificate pinning bypass करने के लिए केवल mobile clients में emulator और instrumentation की आवश्यकता हो सकती है।<sup>[[2]](#references)</sup>

इसके बाद model के नीचे का stack map करें: orchestration framework, prompt assembly, retrieval और memory stores, runtime (उदाहरण के लिए Python, container या WASM), mounted volumes, host services, internal APIs, cloud metadata तक पहुँच और पड़ोसी networks। Framework के defaults मायने रखते हैं, क्योंकि कुछ “tool calls” code generate या evaluate करके लागू किए जाते हैं; runtime/sandbox boundary तय करती है कि परिणाम सीमित रहता है या नहीं।<sup>[[2]](#references)</sup>

### Fingerprint routing with non-destructive probes

Scope में आने वाले request की तुलना कई असंबंधित requests से करें और पूरा response, status code, latency तथा streaming behavior सुरक्षित रखें। किसी भी task-specific reasoning से पहले आने वाला स्थिर rejection अलग gateway/classifier का संकेत हो सकता है; संदर्भ-आधारित refusal बता सकता है कि request model तक पहुँचा; खाली या पूरी तरह extractive answer keyword search या सीमित retrieval का संकेत हो सकता है। इन्हें hypotheses मानें और वही probe दूसरे API fields तथा ingestion paths से दोबारा भेजकर पुष्टि करें।<sup>[[2]](#references)</sup>

Recon तभी पूरा है जब assessment उस शुरुआती attacker-controlled source की पहचान कर सके जो agent के behavior को बदलता है **और** उस source से उपलब्ध tools, identities, interpreters और outputs की भी।<sup>[[2]](#references)</sup>

## Exploitation: cross a trust boundary

सिर्फ prompt wording नहीं, channels भी test करें। Visible front door क्या रोकता है, यह जानने के लिए पहले direct injection करें; फिर नीचे दिए गए कम-दिखाई देने वाले paths से उसी आशय को दोहराएँ:<sup>[[2]](#references)</sup>

- **Indirect content:** pages, files, email, tickets, metadata, alt text, HTML comments, off-screen text या zero-width characters। Payload delivery techniques के लिए [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) देखें।
- **Retrieval and memory:** ऐसा content poison करें जिसे बाद में retrieve किया जाएगा, या ऐसी state जिसे अगले sessions में reload किया जाएगा। दर्ज करें कि original source delete करने पर behavior हटता है या नहीं।
- **Tool output and peer agents:** tool response या agent-to-agent message में marker रखें और जाँचें कि क्या internal traffic उन filters को bypass करता है जो केवल user input और final output पर लागू होते हैं।
- **Supply chain:** tool descriptors, plugins, connected servers, skills, models और dependencies को trusted instruction sources के रूप में जाँचें। MCP-specific tests के लिए [MCP Servers](AI-MCP-Servers.md#mcp-vulns) देखें।
- **Human approval:** वास्तविक structured tool call की तुलना model-generated approval text से करें। जाँचें कि attacker का प्रभाव destination, scope, affected objects या irreversible side effects को छोड़ सकता है या नहीं।

पहले एक benign, unique marker का उपयोग करें। Source artifact, observable होने पर assembled context, selected tool call, approval data, backend request/response और final state सुरक्षित रखें। इससे प्रभाव डालने की क्षमता और किसी कार्रवाई के हो जाने के hallucinated दावे में फर्क करना संभव होता है।<sup>[[2]](#references)</sup>

### Policy-shaped text in a tool-risk judge

Model-based tool gate को उपयोगी classification context के भीतर attacker-controlled text मिल सकता है। उदाहरण के लिए, LangChain का experimental `AutoModeMiddleware` प्रस्तावित tool call, उसके arguments, optional tool description और पिछले अधिकतम 30 messages को TypeSafe के `is_risky` judge के पास भेजता है। यह middleware configured tools को तब block करता है जब लौटाई गई Noul probability कम-से-कम `0.5` हो; unlisted tools को यह classify नहीं करता।<sup>[[5]](#references)</sup> TypeSafe यह भी चेतावनी देता है कि state का उद्देश्य data होना हो, तब भी उसमें adversarial text classification को प्रभावित कर सकता है।<sup>[[6]](#references)</sup>

**Counterfeit policy** केवल system message होने का दावा करने से अलग है। यह lower-trust state के भीतर वैकल्पिक labels या risk definitions रखती है और judge को developer-defined criteria के बजाय उन definitions का उपयोग करने के लिए प्रेरित करती है। Datadog के test में, user-editable `profile_description` को `can_edit:false` के साथ tool arguments में कॉपी किया गया था। उसके policy-जैसे text ने तर्क दिया कि write attempt low risk है, क्योंकि किसी भी mutation से पहले अलग permission check उसे अस्वीकार कर देना चाहिए। 40 runs में, औसत `is_risky` score `0.893` से घटकर `0.290` हो गया, जबकि direct role-spoofing तुलना का औसत `0.905` था। औसत का `0.5` से नीचे आना यह साबित नहीं करता कि हर individual call gate से पास हुई, और experiment ने **किसी unauthorized write के पूरा होने** का प्रदर्शन नहीं किया।<sup>[[7]](#references)</sup>

इस boundary को test करते समय classifier verdict और tool के वास्तविक authorization result में फर्क रखें। जाँचें कि कौन-से editable fields judge तक पहुँचते हैं, उसी proposed action की तुलना policy-जैसे text के साथ और उसके बिना करें, और final state को स्वतंत्र रूप से verify करें। अलग permission check में connector के service-account rights के बजाय authenticated requester की authority का उपयोग होना चाहिए।<sup>[[7]](#references)</sup> अन्य classifier failure modes के लिए [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) देखें; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) अलग routing और credential boundary से संबंधित हैं।

### Subagent context isolation

Non-fork Claude Agent SDK subagent को अपना `AgentDefinition.prompt`, delegation prompt और उपलब्ध tools मिलते हैं, लेकिन parent system prompt या conversation नहीं। यदि उसकी definition में `tools` नहीं दिया गया है, तो वह subagents के लिए उपलब्ध tools inherit करता है; project `CLAUDE.md` फिर भी load हो सकता है। इसलिए parent-only prompt restriction एक अविश्वसनीय boundary है, जब child वही filesystem या execution tools इस्तेमाल कर सकता हो।<sup>[[4]](#references)</sup>

Parent द्वारा refuse किए गए direct request की तुलना उसी task को named subagent को delegate करके करें। NCC Group की रिपोर्ट के अनुसार, operating-system file enumeration का एक refused request, child को “layout map” बनाने के harmless काम के रूप में देने पर सफल हुआ।<sup>[[3]](#references)</sup>

सिर्फ parent के final answer को नहीं, child के वास्तविक tool calls और प्रभावी tool allowlist को देखें; पुष्टि करें कि child ने उन files तक पहुँच बनाई जिन्हें parent access नहीं करता।<sup>[[4]](#references)</sup> यह guardrail inheritance failure है, [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) या container escape का प्रमाण नहीं।<sup>[[3]](#references)[[4]](#references)</sup>

## Execution: prove real impact

Influence से impact तक पहुँचने के दो अलग रास्ते हैं:<sup>[[2]](#references)</sup>

1. **Capability abuse:** अधिकृत tool पहले से ही उद्देश्य पूरा करता है। उदाहरण के लिए, किसी tenant का record पढ़कर उसे attacker-visible report में लिखना, email भेजना, records बदलना, file delete करना या payment शुरू करना। इसके लिए किसी secondary software bug की आवश्यकता नहीं होती।
2. **Downstream sink exploitation:** Attacker के निर्देशों से प्रभावित model output किसी दूसरे component के लिए syntax बन जाता है। Database queries में [SQL injection](../pentesting-web/sql-injection/README.md) या [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers में [command injection](../pentesting-web/command-injection.md), चुने गए URLs में [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), file operations में traversal, template/code evaluators में RCE और object parsers में [unsafe deserialization](../pentesting-web/deserialization/README.md) की जाँच करें।

हर संभावित मामले के लिए यह कड़ी साबित करें:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Read-only integration तब भी exploitable है, जब कोई बाद का component पढ़ी गई जानकारी को प्रकाशित कर सकता हो। सामान्य responses के साथ-साथ कम स्पष्ट egress चैनलों की भी जाँच करें, जैसे attacker-controlled links, automatic image retrieval, webhooks, logs, reports, counters, notifications और अन्य agents को भेजे गए messages।<sup>[[2]](#references)</sup>

## उद्देश्यों पर कार्रवाइयाँ

किसी एक कार्रवाई की पुष्टि करने के बाद, पहले दिखाई देने वाले प्रभाव पर रुकने के बजाय पूरे blast radius का आकलन करें:<sup>[[2]](#references)</sup>

- **Exfiltration:** secrets, user records, internal files, conversation data या prompt/context content किसी observable channel से बाहर जाते हैं।
- **Unauthorized action:** agent attacker के उद्देश्य के लिए वैध write capabilities का उपयोग करता है।
- **Denial of service:** destructive tools या बार-बार किए गए महँगे operations, integrity या availability को प्रभावित करते हैं।
- **Persistence:** poisoned memory, indexed content, trusted state या runtime में किए गए बदलाव, मूल session या source हटाए जाने के बाद भी बने रहते हैं।
- **Propagation:** कोई trusted peer compromised agent का message या shared state इस्तेमाल करता है और अपने tools व credentials से वही कार्रवाई दोहराता है।

Severity का निर्धारण उपलब्ध data, प्रभावी privilege, sink की exploitability, egress, persistence और propagation के आधार पर होना चाहिए—न कि इस आधार पर कि model का text कितना चौंकाने वाला लगता है।<sup>[[2]](#references)</sup>

## Assessment के दौरान जाँचे जाने वाले controls

Prompt filters और बेहतर system prompt attacker की लागत बढ़ा सकते हैं, लेकिन उन्हें authorization boundaries नहीं मानना चाहिए। नीचे दिए गए controls को उसी chain को direct input, indirect content, memory, tools और peer agents के ज़रिए दोबारा चलाकर validate करें:<sup>[[2]](#references)</sup>

- एक deterministic policy layer **हर tool invocation** पर authenticated user, tenant, object, action और destination की जाँच करे; model caller identity नहीं दे सकता और न ही उसे override कर सकता है।
- Read और write capabilities के लिए अलग-अलग, least-privilege, short-lived credentials का उपयोग हो; high-impact tools केवल ज़रूरत पड़ने पर उपलब्ध कराए जाएँ और ingested content से कभी auto-execute न हों।
- Network egress और internal destinations को model द्वारा चुने गए URLs से स्वतंत्र रूप से allowlist किया जाए; metadata endpoints, mounted secrets और आसपास की services तक runtime access को तब तक block रखा जाए, जब तक उनकी ज़रूरत न हो।
- Approval UI canonical structured request से बने और उसमें सटीक arguments, identity, destination, प्रभावित objects और side effects दिखें—सिर्फ़ model का free-form summary नहीं।
- Success की पुष्टि destination system या system of record से की जाए। Agent का वर्णन, tool-call request या HTTP redirect, दावा किए गए state change का प्रमाण नहीं है।
- Memory और retrieval entries में provenance और trust labels बने रहें, उन्हें invalidate किया जा सके, और बाद की कार्रवाई में उपयोग किए जाने पर उन्हें फिर से authorize किया जाए।
- Inter-agent messages को untrusted requests मानकर authenticate और authorize किया जाए; किसी peer की reputation या agent card से receiver के tools का implicit delegation नहीं होना चाहिए।

A2A agent cards, task flows और उनके attack surface के लिए [A2A Protocol Security](AI-A2A-Protocol.md) देखें।

## References

- [1] [2026 के लिए Agentic Applications के OWASP Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agents पर हमले करने के लिए Hacker की मार्गदर्शिका](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AI Agent को उसके Sandbox से बाहर निकालना वास्तव में कितना कठिन है?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK में Subagents](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode middleware का source](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev model jaggedness: adversarial content](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev as a judge: Counterfeit policy, Jev को कैसे प्रभावित करती है](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
