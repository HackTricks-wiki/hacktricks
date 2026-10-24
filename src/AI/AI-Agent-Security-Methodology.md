# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

एजेंट का आकलन **हमलावर के नियंत्रण वाले इनपुट से बाहरी रूप से देखे जा सकने वाले प्रभाव तक** की कड़ी का अनुसरण करना चाहिए। Jailbreaking, character changes और system-prompt disclosure यह साबित करते हैं कि reasoning channel को प्रभावित किया जा सकता है, लेकिन सबसे गंभीर निष्कर्ष वह कड़ी है जो data access, अनधिकृत tool action, downstream injection sink, persistence या किसी अन्य agent तक पहुँचती है।<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) कवरेज को वर्गीकृत करने के लिए उपयोगी है (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust और rogue agents)। इन लेबलों का उपयोग end-to-end attack path बनाने के बाद करें; model के अप्रत्याशित text को test का अंतिम परिणाम न मानें।<sup>[[1]](#references)[[2]](#references)</sup>

## लक्ष्य का मानचित्र बनाएँ

Payload लिखने से पहले हर agent workflow के लिए इन पाँच आयामों को दर्ज करें:<sup>[[2]](#references)</sup>

| आयाम | क्या सूचीबद्ध करें | सुरक्षा प्रश्न |
|---|---|---|
| **अविश्वसनीय इनपुट** | Chat/API parameters, URLs, documents, email, tickets, calendar entries, retrieved chunks, memory, tool results और peer-agent messages | हमलावर ऐसा content कहाँ रख सकता है जो बाद में model context में पहुँचे? |
| **Tools** | Tool names और schemas, side effects, auto-execution, confirmation behavior और dynamically loaded tools | कौन-सी calls secrets पढ़ती हैं, state लिखती हैं, messages भेजती हैं, data मिटाती हैं, code execute करती हैं या value transfer करती हैं? |
| **अधिकार** | User delegation, service accounts, API tokens, credential lifetime, tenant/resource scope और network reach | हर call किस identity के रूप में चलती है, और क्या tool boundary पर authorization दोबारा जाँचा जाता है? |
| **प्रोसेसिंग** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, file operations और deserializers | Model-generated data कहाँ किसी दूसरे interpreter के लिए syntax बन जाता है? |
| **आउटपुट** | Responses, rendered Markdown/HTML, links, image fetches, webhooks, email, files, logs, reports, metrics और peer-agent traffic | कौन-सा observable channel secret भेज सकता है या secondary request trigger कर सकता है? |

इसे advertised integrations की सूची तक सीमित न करें। एक उपयोगी artifact हर source को उस सटीक context position से जोड़ता है जहाँ वह पहुँचता है, वहाँ उपलब्ध tools से, हर tool द्वारा उपयोग किए गए credential से, downstream interpreter से और हर egress route से। Per-user read token वाला वही tool कम प्रभाव वाला हो सकता है, जबकि shared administrator credential के साथ वह critical हो सकता है।<sup>[[2]](#references)</sup>

## Reconnaissance

### हर delivery और ingestion path का मानचित्र बनाएँ

Delivery surface (web, mobile, API, email, chat platform, browser extension) से शुरुआत करें और client-to-backend traffic को proxy करें। UI में छिपे fields, search/autocomplete/filter parameters, conversation-state objects, upload और indexing jobs, tool responses तथा sub-agent traffic की जाँच करें। असली request schema दिखने से पहले certificate pinning को bypass करने के लिए mobile-only clients में emulator और instrumentation की ज़रूरत हो सकती है।<sup>[[2]](#references)</sup>

फिर model के नीचे के stack का मानचित्र बनाएँ: orchestration framework, prompt assembly, retrieval और memory stores, runtime (उदाहरण के लिए Python, container या WASM), mounted volumes, host services, internal APIs, cloud metadata तक पहुँच और पड़ोसी networks। Framework के defaults महत्वपूर्ण हैं, क्योंकि कुछ “tool calls” code generate या evaluate करके लागू किए जाते हैं; runtime/sandbox boundary तय करती है कि परिणाम सीमित रहता है या नहीं।<sup>[[2]](#references)</sup>

### गैर-विनाशकारी probes से routing की पहचान करें

दायरे में आने वाली request की तुलना कई असंबंधित requests से करें और पूरा response, status code, latency तथा streaming behavior सुरक्षित रखें। किसी task-specific reasoning से पहले स्थिर rejection, अलग gateway/classifier का संकेत हो सकता है; संदर्भ के अनुरूप refusal बताता है कि request model तक पहुँची; खाली या केवल extractive answer keyword search या सीमित retrieval का संकेत हो सकता है। इन्हें परिकल्पनाएँ मानें और उसी probe को वैकल्पिक API fields तथा ingestion paths से दोबारा भेजकर पुष्टि करें।<sup>[[2]](#references)</sup>

Recon तभी पूरा होता है जब आकलन में हमलावर के नियंत्रण वाले उस सबसे शुरुआती source की पहचान हो जो agent के behavior को बदलता है **और** उस source से उपलब्ध tools, identities, interpreters तथा outputs की भी।<sup>[[2]](#references)</sup>

## Exploitation: trust boundary पार करें

केवल prompt wording नहीं, channels की भी जाँच करें। पहले direct injection से पता करें कि दिखाई देने वाला front door क्या रोकता है, फिर नीचे दिए कम दिखाई देने वाले paths से उसी आशय की जाँच दोहराएँ:<sup>[[2]](#references)</sup>

- **Indirect content:** pages, files, email, tickets, metadata, alt text, HTML comments, off-screen text या zero-width characters। Payload-delivery techniques के लिए [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) देखें।
- **Retrieval और memory:** ऐसा content poison करें जिसे बाद में retrieve किया जाएगा, या ऐसी state जिसे अगले sessions में फिर load किया जाएगा। दर्ज करें कि मूल source हटाने से behavior बंद होता है या नहीं।
- **Tool output और peer agents:** tool response या agent-to-agent message में marker रखें और जाँचें कि क्या internal traffic, केवल user input और final output पर लागू filters को bypass करता है।
- **Supply chain:** tool descriptors, plugins, connected servers, skills, models और dependencies की trusted instruction sources के रूप में समीक्षा करें। MCP-विशिष्ट tests के लिए [MCP Servers](AI-MCP-Servers.md#mcp-vulns) देखें।
- **Human approval:** वास्तविक structured tool call की तुलना model-generated approval text से करें। जाँचें कि हमलावर का प्रभाव destination, scope, प्रभावित objects या irreversible side effects को हटवा सकता है या नहीं।

पहले एक अहानिकर, अद्वितीय marker इस्तेमाल करें। Source artifact, दिखाई देने पर assembled context, चुनी गई tool call, approval data, backend request/response और अंतिम state सुरक्षित रखें। इससे प्रभाव को कार्रवाई हो जाने के झूठे दावे से अलग किया जा सकता है।<sup>[[2]](#references)</sup>

### Tool-risk judge में policy-जैसा text

Model-आधारित tool gate को उपयोगी classification context के भीतर हमलावर के नियंत्रण वाला text मिल सकता है। उदाहरण के लिए, LangChain का experimental `AutoModeMiddleware`, प्रस्तावित tool call, उसके arguments, वैकल्पिक tool description और हाल के अधिकतम 30 messages को TypeSafe `is_risky` judge के पास भेजता है। यह configured tools को तब block करता है जब लौटाई गई Noul probability कम-से-कम `0.5` हो; इस middleware द्वारा unlisted tools का वर्गीकरण नहीं किया जाता।<sup>[[5]](#references)</sup> TypeSafe यह भी चेतावनी देता है कि state को data के रूप में इस्तेमाल करने का इरादा होने पर भी उसमें मौजूद adversarial text classification को प्रभावित कर सकता है।<sup>[[6]](#references)</sup>

**Counterfeit policy**, केवल system message होने का दावा करने से अलग है। इसमें lower-trust state के भीतर वैकल्पिक labels या risk definitions रखे जाते हैं और judge को developer द्वारा तय criteria के बजाय उन परिभाषाओं का उपयोग करने के लिए प्रेरित किया जाता है। Datadog के test में, user-editable `profile_description` को `can_edit:false` के साथ tool arguments में कॉपी किया गया था। उसमें मौजूद policy-जैसे text का तर्क था कि write का प्रयास low risk है, क्योंकि mutation से पहले एक अलग permission check उसे रोक देगा। 40 runs में औसत `is_risky` score `0.893` से गिरकर `0.290` हो गया, जबकि direct role-spoofing comparison का औसत `0.905` था। औसत का `0.5` से नीचे जाना यह साबित नहीं करता कि हर individual call gate से पास हुई, और प्रयोग ने **अनधिकृत write पूरी होने का प्रदर्शन नहीं किया**।<sup>[[7]](#references)</sup>

इस boundary की जाँच करते समय classifier के verdict को tool के वास्तविक authorization result से अलग रखें। देखें कि कौन-से editable fields judge तक पहुँचते हैं, policy-जैसे text के साथ और उसके बिना उसी प्रस्तावित action की तुलना करें, और अंतिम state की स्वतंत्र रूप से पुष्टि करें। अलग permission check में connector के service-account अधिकारों के बजाय authenticated requester के अधिकार इस्तेमाल होने चाहिए।<sup>[[7]](#references)</sup> अन्य classifier failure modes के लिए [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) देखें; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) एक अलग routing और credential boundary से संबंधित हैं।

### Subagent context isolation

Non-fork Claude Agent SDK subagent को अपना `AgentDefinition.prompt`, delegation prompt और उपलब्ध tools मिलते हैं, लेकिन parent system prompt या conversation नहीं। अगर उसकी definition में `tools` छोड़ा गया हो, तो उसे subagents के लिए उपलब्ध tools विरासत में मिलते हैं; project `CLAUDE.md` फिर भी load हो सकता है। इसलिए parent-only prompt restriction एक अविश्वसनीय boundary है, खासकर जब child वही filesystem या execution tools इस्तेमाल कर सकता हो।<sup>[[4]](#references)</sup>

Parent द्वारा मना किए गए direct request की तुलना उसी task को named subagent को सौंपने से करके boundary जाँचें। NCC Group की रिपोर्ट के अनुसार, operating-system file enumeration का एक मना किया गया अनुरोध child के लिए एक निरापद "layout map" के रूप में पेश करने पर सफल हुआ।<sup>[[3]](#references)</sup>

केवल parent के final answer को नहीं, child की वास्तविक tool calls और प्रभावी tool allowlist की जाँच करें; पुष्टि करें कि child ने ऐसी files access कीं या नहीं जिन्हें parent access नहीं करता।<sup>[[4]](#references)</sup> यह guardrail inheritance की विफलता है, [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) या container escape का प्रमाण नहीं।<sup>[[3]](#references)[[4]](#references)</sup>

## Execution: वास्तविक प्रभाव साबित करें

प्रभाव से impact तक पहुँचने के दो अलग रास्ते हैं:<sup>[[2]](#references)</sup>

1. **Capability abuse:** अधिकृत tool पहले से ही उद्देश्य पूरा करता है। उदाहरणों में एक tenant का record पढ़कर उसे हमलावर को दिखाई देने वाली report में लिखना, email भेजना, records बदलना, file मिटाना या payment शुरू करना शामिल है। किसी secondary software bug की ज़रूरत नहीं होती।
2. **Downstream sink exploitation:** हमलावर द्वारा निर्देशित model output किसी दूसरे component के लिए syntax बन जाता है। Database queries में [SQL injection](../pentesting-web/sql-injection/README.md) या [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers में [command injection](../pentesting-web/command-injection.md), चुने गए URLs में [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), file operations में traversal, template/code evaluators में RCE और object parsers में [unsafe deserialization](../pentesting-web/deserialization/README.md) की जाँच करें।

हर संभावित निष्कर्ष के लिए यह कड़ी साबित करें:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Read-only integration भी exploitable रहता है, अगर बाद का कोई component पढ़ी गई जानकारी को प्रकाशित कर सकता हो। सामान्य responses के साथ-साथ कम स्पष्ट egress की भी जाँच करें, जैसे attacker-controlled links, automatic image retrieval, webhooks, logs, reports, counters, notifications और अन्य agents को भेजे गए messages।<sup>[[2]](#references)</sup>

## उद्देश्यों पर कार्रवाइयाँ

किसी एक कार्रवाई की पुष्टि करने के बाद, पहले दिखाई देने वाले प्रभाव पर रुकने के बजाय पूरे blast radius का आकलन करें:<sup>[[2]](#references)</sup>

- **Exfiltration:** secrets, user records, internal files, conversation data या prompt/context content किसी observable channel से बाहर जाए।
- **अनधिकृत कार्रवाई:** agent, attacker के उद्देश्य के लिए वैध write capabilities का उपयोग करे।
- **Denial of service:** destructive tools या बार-बार किए गए महँगे operations, integrity या availability को प्रभावित करें।
- **Persistence:** poisoned memory, indexed content, trusted state या runtime changes, मूल session या source हटाए जाने के बाद भी बने रहें।
- **Propagation:** कोई trusted peer, compromised agent का message या shared state ग्रहण करे और अपने tools तथा credentials से कार्रवाई दोहराए।

Severity का निर्धारण उपलब्ध data, प्रभावी privilege, sink की exploitability, egress, persistence और propagation के आधार पर होना चाहिए—न कि इस आधार पर कि model का text कितना चौंकाने वाला दिखता है।<sup>[[2]](#references)</sup>

## Assessment के दौरान validate किए जाने वाले controls

Prompt filters और बेहतर system prompt, attacker की लागत बढ़ा सकते हैं, लेकिन उन्हें authorization boundaries नहीं मानना चाहिए। नीचे दिए गए controls को direct input, indirect content, memory, tools और peer agents के ज़रिए उसी chain को फिर से चलाकर validate करें:<sup>[[2]](#references)</sup>

- एक deterministic policy layer, **हर tool invocation** पर authenticated user, tenant, object, action और destination की जाँच करे; model caller identity नहीं दे सकता और न ही उसे override कर सकता है।
- Read और write capabilities के लिए अलग-अलग, least-privilege, short-lived credentials का उपयोग हो; high-impact tools केवल ज़रूरत के समय उपलब्ध कराए जाएँ और ingested content से कभी auto-execute न हों।
- Network egress और internal destinations को model द्वारा चुने गए URLs से स्वतंत्र रूप से allowlist किया जाए; जब तक आवश्यक न हो, metadata endpoints, mounted secrets और neighboring services तक runtime access को block किया जाए।
- Approval UI, canonical structured request से generate हो और उसमें सटीक arguments, identity, destination, प्रभावित objects और side effects दिखें—सिर्फ model का free-form summary नहीं।
- Success की पुष्टि destination system या system of record से की जाए। Agent का वर्णन, tool-call request या HTTP redirect, बताए गए state change का प्रमाण नहीं है।
- Memory और retrieval entries में provenance और trust labels सुरक्षित रहें, उन्हें invalidate किया जा सके और बाद की कार्रवाई में उपयोग होने पर उनका दोबारा authorization हो।
- Inter-agent messages को untrusted requests के रूप में authenticate और authorize किया जाए; किसी peer की reputation या agent card से receiver के tools का अधिकार अपने-आप हस्तांतरित नहीं होता।

## References

- [1] [2026 के लिए Agentic Applications के OWASP Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agents पर हमला करने के लिए Hacker की गाइड](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AI Agent को उसके Sandbox से बाहर निकालना वास्तव में कितना कठिन है?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK में Subagents](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode middleware का source](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev model jaggedness: adversarial content](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev को judge के रूप में उपयोग करना: counterfeit policy, Jev को कैसे प्रभावित करती है](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
