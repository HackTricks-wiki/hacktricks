# AI Agent सुरक्षा कार्यप्रणाली

{{#include ../banners/hacktricks-training.md}}

Agent assessment में **attacker-controlled input से externally observable effect तक** की कड़ी का अनुसरण करना चाहिए। Jailbreaking, character changes और system-prompt disclosure यह साबित करते हैं कि reasoning channel को प्रभावित किया जा सकता है, लेकिन high-impact finding वह कड़ी है जो data access, unauthorized tool action, downstream injection sink, persistence या किसी दूसरे agent तक पहुँचती है।<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) coverage को label करने में उपयोगी है (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust और rogue agents)। किसी model के अप्रत्याशित text को test का अंत मानने के बजाय, end-to-end attack path बनाने के बाद इन labels का उपयोग करें।<sup>[[1]](#references)[[2]](#references)</sup>

## Target map बनाएँ

Payloads लिखने से पहले हर agent workflow के लिए इन पाँच dimensions को दर्ज करें:<sup>[[2]](#references)</sup>

| Dimension | क्या सूचीबद्ध करें | Security question |
|---|---|---|
| **Untrusted input** | Chat/API parameters, URLs, documents, email, tickets, calendar entries, retrieved chunks, memory, tool results और peer-agent messages | Attacker ऐसा content कहाँ रख सकता है जो बाद में model context में आए? |
| **Tools** | Tool names और schemas, side effects, auto-execution, confirmation behavior और dynamically loaded tools | कौन-सी calls secrets पढ़ती हैं, state लिखती हैं, messages भेजती हैं, data delete करती हैं, code execute करती हैं या value transfer करती हैं? |
| **Authority** | User delegation, service accounts, API tokens, credential lifetime, tenant/resource scope और network reach | हर call किस identity से चलती है, और क्या tool boundary पर authorization दोबारा जाँचा जाता है? |
| **Processing** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, file operations और deserializers | Model-generated data कहाँ किसी दूसरे interpreter के लिए syntax बन जाता है? |
| **Output** | Responses, rendered Markdown/HTML, links, image fetches, webhooks, email, files, logs, reports, metrics और peer-agent traffic | कौन-सा observable channel secret पहुँचा सकता है या secondary request trigger कर सकता है? |

इसे advertised integrations की सूची तक सीमित न करें। उपयोगी artifact में हर source को उस सटीक context position से map किया जाता है जहाँ वह पहुँचता है, उस बिंदु पर उपलब्ध tools, हर tool द्वारा उपयोग किया गया credential, downstream interpreter और हर egress route दर्ज होते हैं। वही tool per-user read token के साथ low impact वाला हो सकता है, लेकिन shared administrator credential के साथ critical हो सकता है।<sup>[[2]](#references)</sup>

## Reconnaissance

### हर delivery और ingestion path map करें

Delivery surface (web, mobile, API, email, chat platform, browser extension) से शुरू करें और client-to-backend traffic को proxy करें। UI में छिपे fields, search/autocomplete/filter parameters, conversation-state objects, upload और indexing jobs, tool responses और sub-agent traffic की जाँच करें। असली request schema सामने आने से पहले certificate pinning bypass करने के लिए mobile-only clients को emulator और instrumentation की ज़रूरत हो सकती है।<sup>[[2]](#references)</sup>

इसके बाद model के नीचे का stack map करें: orchestration framework, prompt assembly, retrieval और memory stores, runtime (उदाहरण के लिए Python, container या WASM), mounted volumes, host services, internal APIs, cloud metadata तक पहुँच और पड़ोसी networks। Framework defaults मायने रखते हैं, क्योंकि कुछ “tool calls” code generate या evaluate करके लागू किए जाते हैं; runtime/sandbox boundary तय करती है कि वह परिणाम contained रहता है या नहीं।<sup>[[2]](#references)</sup>

### Non-destructive probes से routing की पहचान करें

एक in-scope request की तुलना कई असंबंधित requests से करें और पूरा response, status code, latency तथा streaming behavior सुरक्षित रखें। किसी task-specific reasoning से पहले मिलने वाला स्थिर rejection अलग gateway/classifier का संकेत हो सकता है; संदर्भ-आधारित refusal बताता है कि request model तक पहुँची; खाली या पूरी तरह extractive answer keyword search या सीमित retrieval का संकेत हो सकता है। इन्हें hypotheses मानें और वही probe वैकल्पिक API fields तथा ingestion paths से replay करके पुष्टि करें।<sup>[[2]](#references)</sup>

Recon तभी पूरा होता है जब assessment उस शुरुआती attacker-controlled source का नाम बता सके जो agent के behavior को बदलता है **और** उस source से पहुँच योग्य tools, identities, interpreters और outputs की पहचान कर सके।<sup>[[2]](#references)</sup>

## Exploitation: trust boundary पार करें

सिर्फ prompt wording नहीं, channels भी test करें। सामने के visible entry point पर क्या block होता है, यह जानने के लिए direct injection से शुरू करें; फिर नीचे दिए गए कम दिखाई देने वाले paths से उसी intent को दोहराएँ:<sup>[[2]](#references)</sup>

- **Indirect content:** pages, files, email, tickets, metadata, alt text, HTML comments, off-screen text या zero-width characters। Payload-delivery techniques के लिए [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) देखें।
- **Retrieval और memory:** ऐसा content poison करें जिसे बाद में retrieve किया जाएगा, या ऐसी state जिसे बाद के sessions में फिर load किया जाएगा। दर्ज करें कि original source delete करने से behavior हटता है या नहीं।
- **Tool output और peer agents:** किसी tool response या agent-to-agent message में marker रखें, ताकि जाँचा जा सके कि internal traffic उन filters को bypass करता है या नहीं जो सिर्फ user input और final output पर लागू होते हैं।
- **Supply chain:** tool descriptors, plugins, connected servers, skills, models और dependencies को trusted instruction sources मानकर review करें। MCP-specific tests के लिए [MCP Servers](AI-MCP-Servers.md#mcp-vulns) देखें।
- **Human approval:** असली structured tool call की तुलना model-generated approval text से करें। जाँचें कि attacker का influence destination, scope, प्रभावित objects या irreversible side effects को छोड़ सकता है या नहीं।

पहले एक benign, unique marker का उपयोग करें। Source artifact, observable होने पर assembled context, चुना गया tool call, approval data, backend request/response और final state सुरक्षित रखें। इससे influence को उस hallucinated दावे से अलग किया जा सकता है कि कोई action हुआ था।<sup>[[2]](#references)</sup>

### Tool-risk judge में policy-जैसा text

Model-based tool gate को उपयोगी classification context के भीतर attacker-controlled text मिल सकता है। उदाहरण के लिए, LangChain का experimental `AutoModeMiddleware` प्रस्तावित tool call, उसके arguments, वैकल्पिक tool description और हाल के अधिकतम 30 messages को TypeSafe `is_risky` judge के पास भेजता है। लौटाई गई Noul probability `0.5` या उससे अधिक होने पर यह configured tools को block करता है; इस middleware द्वारा unlisted tools classify नहीं किए जाते।<sup>[[5]](#references)</sup> TypeSafe यह चेतावनी भी देता है कि state में मौजूद adversarial text classification को प्रभावित कर सकता है, भले ही state का उद्देश्य data होना हो।<sup>[[6]](#references)</sup>

**Counterfeit policy**, सिर्फ system message होने का दावा करने से अलग है। यह lower-trust state में वैकल्पिक labels या risk definitions रखती है और judge को developer-defined criteria के बजाय उन्हीं definitions का उपयोग करने के लिए प्रेरित करती है। Datadog के test में, user-editable `profile_description` को `can_edit:false` के साथ tool arguments में copy किया गया था। उसके policy-जैसे text में तर्क था कि write attempt low risk है, क्योंकि किसी भी mutation से पहले अलग permission check उसे reject कर देगा। 40 runs में औसत `is_risky` score `0.893` से गिरकर `0.290` हो गया, जबकि direct role-spoofing comparison का औसत `0.905` था। औसत का `0.5` से नीचे जाना यह साबित नहीं करता कि हर individual call gate से गुज़र गई, और experiment ने **unauthorized write पूरा होने का प्रदर्शन नहीं किया**।<sup>[[7]](#references)</sup>

इस boundary को test करते समय classifier verdict और tool के वास्तविक authorization result में अंतर रखें। जाँचें कि कौन-से editable fields judge तक पहुँचते हैं, policy-जैसे text के साथ और उसके बिना उसी प्रस्तावित action की तुलना करें, और final state को स्वतंत्र रूप से verify करें। अलग permission check में connector के service-account rights के बजाय authenticated requester की authority का उपयोग होना चाहिए।<sup>[[7]](#references)</sup> अन्य classifier failure modes के लिए [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) देखें; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) एक अलग routing और credential boundary से संबंधित हैं।

### Subagent context isolation

Non-fork Claude Agent SDK subagent को अपना `AgentDefinition.prompt`, delegation prompt और उपलब्ध tools मिलते हैं, लेकिन parent system prompt या conversation नहीं मिलते। अगर उसकी definition में `tools` छोड़ दिया जाए, तो उसे subagents के लिए उपलब्ध tools विरासत में मिलते हैं; project `CLAUDE.md` फिर भी load हो सकता है। इसका अर्थ है कि parent-only prompt restriction एक अविश्वसनीय boundary है, जब child उन्हीं filesystem या execution tools का उपयोग कर सकता हो।<sup>[[4]](#references)</sup>

इस boundary को test करने के लिए, ऐसे direct request की तुलना करें जिसे parent refuse करता है और उसी task को किसी नामित subagent को delegate करें। NCC Group की report के अनुसार, operating-system file enumeration का एक refused request, child के लिए एक harmless “layout map” के रूप में पेश करने पर सफल हुआ।<sup>[[3]](#references)</sup>

सिर्फ parent के final answer पर नहीं, child के असली tool calls और effective tool allowlist पर भी नज़र डालें; पुष्टि करें कि child ने वे files access कीं या नहीं जिन्हें parent access नहीं करता।<sup>[[4]](#references)</sup> यह guardrail inheritance की विफलता है, [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) या container escape का प्रमाण नहीं।<sup>[[3]](#references)[[4]](#references)</sup>

### Mobile GUI agents: screen instructions और action rebinding

कोई phone GUI agent अगला cross-app action चुनने से पहले हर screenshot cloud model को भेज सकता है। **Indirect visual injection** test करने के लिए, किसी SMS, email या page में attacker-controlled text रखें जिसे agent किसी authorized task के दौरान देखेगा। Direct task prompt की तुलना उसी instruction से करें जो सिर्फ screenshot में दिखाई देती है, फिर अगले action और high-risk-operation के किसी भी निर्णय की जाँच करें। Assessed assistant में client-side `checkPrompt` ने direct task text को screen किया, लेकिन screenshot content पर समान filtering लागू नहीं की। यह [agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md) का mobile, cross-app रूप है; यह Android component authentication bypass करने का तरीका नहीं है।<sup>[[9]](#references)</sup>

Side-effect का एक उदाहरणात्मक test attacker-controlled form का उपयोग करता है, जो agent से sensitive fields भरने को कहता है और फिर human से “upload” पर click करने का अनुरोध करता है, जबकि page उन fields के बदलते ही उन्हें submit कर देता है। Human handoff उस data की सुरक्षा नहीं कर सकता जिसे page code पहले ही भेज चुका हो; agent की narration को प्रमाण मानने के बजाय वास्तविक submission verify करें। Source इसे एक संभावित pattern के रूप में प्रस्तुत करता है, हर assistant के demonstrated compromise के रूप में नहीं।<sup>[[9]](#references)</sup>

**GUI TOCTOU / action rebinding** एक अलग failure mode है: agent `t0` पर देखी गई screen के आधार पर input की योजना बनाता है, लेकिन `t1` पर input inject होने से पहले foreground UI बदल जाता है।<sup>[[8]](#references)</sup> `t2` पर लिया गया बाद का screenshot पहले से commit हो चुके action को undo नहीं कर सकता।<sup>[[9]](#references)</sup> Authorized Android test में यह workflow दोबारा उपयोग किया जा सकता है:<sup>[[8]](#references)</sup>

1. Target control के screen coordinates profile करें और controlled app में उसी जगह एक benign control render करें।
2. उस carrier को तब तक visible रखें जब तक agent उसे देख न ले, फिर उसके observation-to-action gap के दौरान एक सामान्य foreground transition trigger करें।
3. जाँचें कि planned tap नई app के control पर पड़ता है या नहीं, और agent की narration पर निर्भर रहने के बजाय target app में परिणामी state verify करें।

Original action-rebinding study इसे ऐसे app के साथ दिखाती है जिसके पास कोई dangerous permissions नहीं हैं; यह multistep flows के लिए agent के task-recovery loop के ज़रिए transition दोहराने का भी वर्णन करती है।<sup>[[8]](#references)</sup>

**यह न मानें** कि यह primitive हर assistant पर बिना बदलाव के काम करेगा। Doubao assessment में, `OpClickUI` ने top-level Activity बदलने पर clicks छोड़ दिए और उससे पहले के तीन steps में `OpOpenApp` आने पर screenshots की तुलना की। इसलिए single taps, long presses और double taps attacker के नियंत्रण वाले timing के लिए बहुत कम भरोसेमंद थे। `OpTypeText`, `OpSwipeUI` और `OpScrollWheelAction` में ऐसे समान guards नहीं थे, लेकिन report ने उनके practical impact को अधिक सीमित आंका।<sup>[[9]](#references)</sup>

## Execution: वास्तविक impact साबित करें

Influence से impact तक पहुँचने के दो अलग रास्ते हैं:<sup>[[2]](#references)</sup>

1. **Capability abuse:** Authorized tool पहले से ही उद्देश्य पूरा करता है। उदाहरणों में एक tenant का record पढ़कर उसे attacker-visible report में लिखना, email भेजना, records बदलना, file delete करना या payment शुरू करना शामिल है। किसी secondary software bug की आवश्यकता नहीं होती।
2. **Downstream sink exploitation:** Attacker के नियंत्रण में आया model output किसी दूसरे component के लिए syntax बन जाता है। Database queries में [SQL injection](../pentesting-web/sql-injection/README.md) या [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers में [command injection](../pentesting-web/command-injection.md), चुने गए URLs में [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), file operations में traversal, template/code evaluators में RCE, और object parsers में [unsafe deserialization](../pentesting-web/deserialization/README.md) की जाँच करें।

हर संभावित finding के लिए इस chain को साबित करें:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

केवल-पढ़ने वाला integration भी exploit किया जा सकता है, यदि बाद का कोई component पढ़ी गई जानकारी प्रकाशित कर सकता हो। सामान्य responses के साथ-साथ कम स्पष्ट egress की भी जाँच करें, जैसे attacker-controlled links, automatic image retrieval, webhooks, logs, reports, counters, notifications और अन्य agents को भेजे गए messages।<sup>[[2]](#references)</sup>

## उद्देश्यों पर कार्रवाइयाँ

किसी एक कार्रवाई की पुष्टि करने के बाद, पहले दिखाई देने वाले प्रभाव पर रुकने के बजाय उसके पूरे प्रभाव-क्षेत्र का आकलन करें:<sup>[[2]](#references)</sup>

- **डेटा की चोरी:** secrets, user records, internal files, conversation data या prompt/context की सामग्री किसी दिखाई देने वाले channel से बाहर जाती है।
- **अनधिकृत कार्रवाई:** agent attacker के उद्देश्य के लिए वैध write capabilities का उपयोग करता है।
- **सेवा से इनकार:** destructive tools या बार-बार किए गए महँगे operations, integrity या availability को प्रभावित करते हैं।
- **स्थायित्व:** poisoned memory, indexed content, trusted state या runtime में किए गए बदलाव, मूल session या source हटाए जाने के बाद भी बने रहते हैं।
- **प्रसार:** कोई trusted peer, compromised agent के message या shared state का उपयोग करता है और अपने tools तथा credentials से वही कार्रवाई दोहराता है।

गंभीरता का आकलन उपलब्ध data, प्रभावी privileges, sink की exploitability, egress, persistence और propagation के आधार पर होना चाहिए—न कि इस आधार पर कि model का text कितना चौंकाने वाला लगता है।<sup>[[2]](#references)</sup>

## आकलन के दौरान सत्यापित किए जाने वाले controls

Prompt filters और बेहतर system prompt attacker की लागत बढ़ा सकते हैं, लेकिन इन्हें authorization boundaries नहीं मानना चाहिए। नीचे दिए गए controls को उसी chain को direct input, indirect content, memory, tools और peer agents के माध्यम से फिर से चलाकर सत्यापित करें:<sup>[[2]](#references)</sup>

- एक deterministic policy layer, **हर tool invocation** पर authenticated user, tenant, object, action और destination की जाँच करता है; model caller की identity दे या बदल नहीं सकता।
- Read और write capabilities के लिए अलग-अलग, least-privilege, short-lived credentials का उपयोग होता है; high-impact tools केवल आवश्यकता के समय उपलब्ध कराए जाते हैं और ingested content से कभी auto-execute नहीं होते।
- Network egress और internal destinations को model द्वारा चुने गए URLs से स्वतंत्र रूप से allowlist किया जाता है; metadata endpoints, mounted secrets और आस-पास की services तक runtime की पहुँच तब तक अवरुद्ध रहती है, जब तक उनकी आवश्यकता न हो।
- Approval UI, canonical structured request से बनता है और उसमें सटीक arguments, identity, destination, प्रभावित objects और side effects दिखते हैं—सिर्फ model का free-form सारांश नहीं।
- सफलता की पुष्टि destination system या system of record से की जाती है। Agent का विवरण, tool-call request या HTTP redirect, बताए गए state change का प्रमाण नहीं है।
- Memory और retrieval entries में provenance तथा trust labels सुरक्षित रहते हैं, उन्हें invalidate किया जा सकता है, और बाद की कार्रवाई में उपयोग होने पर उनका दोबारा authorization किया जाता है।
- Inter-agent messages को untrusted requests के रूप में authenticate और authorize किया जाता है; किसी peer की प्रतिष्ठा या agent card से receiver के tools का अधिकार स्वतः नहीं मिलता।

A2A agent cards, task flows और उनसे जुड़े attack surface के लिए [A2A Protocol Security](AI-A2A-Protocol.md) देखें।

## References

- [1] [2026 के लिए OWASP Agentic Applications के शीर्ष 10 जोखिम](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agents पर हमला करने के लिए Hacker की मार्गदर्शिका](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [AI Agent को उसके Sandbox से बाहर निकालना वास्तव में कितना कठिन है?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK में Subagents](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode middleware का source](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev model jaggedness: adversarial content](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev को judge के रूप में इस्तेमाल करना: counterfeit policy, Jev को कैसे प्रभावित करती है](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Zero-Permission Manipulation: क्या हम Large Multimodal Model से संचालित GUI Agents पर भरोसा कर सकते हैं?](https://arxiv.org/html/2601.12349v1)
- [9] [जब AI Assistant Hacker की Attack Chain का हिस्सा बन जाता है | Doubao Phone का Security Analysis](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
