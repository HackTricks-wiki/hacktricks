# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## A2A क्या है

A2A (Agent2Agent) एक open protocol है, जो एक AI agent को दूसरे agent को खोजने और HTTP के ज़रिए उसे काम भेजने देता है। MCP किसी agent को **tools and data** से जोड़ता है; A2A किसी agent को **other agents** से जोड़ता है, जो आमतौर पर किसी दूसरी टीम या कंपनी के स्वामित्व वाली remote services होती हैं। A2A server एक web API है, जिसके पीछे LLM agent होता है। इसलिए protocol के अपने objects (agent cards, tasks, push-notification webhooks, extended cards) सामान्य API test में authentication, IDOR और SSRF की विशिष्ट जाँचें जोड़ते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

मुख्य हिस्से ये हैं:

- **Agent Card:** एक JSON document जो agent का वर्णन करता है: नाम, विवरण, skills, service URL(s), समर्थित transports, capabilities (streaming, push notifications, extended card) और वे `securitySchemes` जिनका client को उपयोग करना होगा। इसे `https://<host>/.well-known/agent-card.json` पर प्रकाशित किया जाता है। पुराने deployments, जो spec 0.2.x का पालन करते हैं, `/.well-known/agent.json` का उपयोग करते हैं।<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** काम की इकाई। एक message task बनाता है (जिसमें server द्वारा बनाया गया `id` और एक `contextId` होता है), और client बाद में उसे पढ़ता, रद्द करता या उसकी सदस्यता लेता है।<sup>[[1]](#references)</sup>
- **Transports:** HTTP पर JSON-RPC 2.0 (streaming के लिए SSE के साथ), gRPC और HTTP+JSON REST binding।<sup>[[1]](#references)</sup>
- **Authentication:** credentials HTTP headers में जाते हैं (उदाहरण के लिए `Authorization: Bearer ...`), JSON-RPC payload के अंदर कभी नहीं। Agent card बताता है कि कौन-सी scheme आवश्यक है।<sup>[[1]](#references)</sup>

Versions के बीच method names बदल गए हैं, इसलिए दोनों sets आज़माएँ:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operation | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Message भेजें | `message/send` | `SendMessage` | `POST /message:send` |
| Streaming message भेजें | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Task प्राप्त करें | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Tasks की सूची बनाएँ | - | `ListTasks` | `GET /tasks` |
| Task रद्द करें | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification config | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 spec version चुनने के लिए `A2A-Version` header (या request parameter) का उपयोग करता है, और इसके बिना आने वाली requests को 0.3 माना जाता है।<sup>[[1]](#references)</sup>

## Discovery

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

कार्ड से निम्नलिखित नोट करें:

- हर service `url`: 1.0 में ये `supportedInterfaces` के अंतर्गत होते हैं, जबकि पुराने कार्ड में top-level `url` हो सकता है। हर endpoint और transport रिकॉर्ड करें, जिसमें internal hostnames, staging URLs और alternate ports शामिल हैं।<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: ये दिखाते हैं कि agent क्या कर सकता है और उसके पीछे कौन-से tools या data हैं।
- `securitySchemes` / `security`: अगर ये खाली या अनुपस्थित हैं, तो संभवतः agent को credentials के बिना call करने के लिए बनाया गया है।
- `capabilities.pushNotifications` और `capabilities.extendedAgentCard` (0.3 में `supportsAuthenticatedExtendedCard`)।

Spec के अनुसार, public card में credentials या internal implementation details नहीं होने चाहिए, इसलिए किसी public card में internal URLs, keys या विस्तृत tool lists मिलना अपने-आप में एक finding है।<sup>[[1]](#references)</sup>

### Multi-agent host में Agent Card name collision

कार्ड का `name` एक ऐसा label है जिसे इंसान पढ़ सकते हैं, स्थिर routing identity नहीं।<sup>[[1]](#references)[[5]](#references)</sup> अगर कोई host दो अलग-अलग remote peers को एक ही local name के अंतर्गत register करता है, तो उसका agent tree, generated tool name, client map या broker route, trusted peer के लिए बना task दूसरे peer को भेज सकता है।<sup>[[5]](#references)</sup> इसके लिए attacker-controlled peer को **उसी routing namespace** में शामिल किया जाना ज़रूरी है; केवल Internet पर duplicate card प्रकाशित करना पर्याप्त नहीं है।<sup>[[5]](#references)</sup>

दो नियंत्रित peers, अलग-अलग URLs और एक harmless marker का इस्तेमाल करके host के **admission-to-dispatch** path का परीक्षण करें:<sup>[[5]](#references)</sup>

1. Trusted peer का card, origin और local selector रिकॉर्ड करें। एक दूसरा peer register करें, जिसके card का `name` वही हो, लेकिन जिसका URL आपके नियंत्रण वाले endpoint की ओर संकेत करे।
2. वह operation trigger करें जो trusted peer को name से चुनता है। Registration के दोनों क्रम आज़माएँ और, अगर names tool identifiers बन जाते हैं, तो host का सामान्य name normalization भी आज़माएँ। पता लगाएँ कि marker किस endpoint को मिलता है और response कौन-सा agent लौटाता है।
3. केवल दूसरे card का name बदलें और फिर से परीक्षण करें। अगर request केवल collision वाले मामले में दूसरे endpoint तक पहुँचती है, तो यह गलत peer को dispatch होने का प्रमाण है। अलग से जाँचें कि कोई sensitive context या credential वास्तव में attach किया गया था या नहीं; केवल name collision, credentials या tool-authority के transfer का **प्रमाण नहीं** है।

अगर caller किसी card name को resolve करने के बजाय किसी fixed, origin-bound endpoint को address करता है, तो यह परीक्षण लागू नहीं होता।<sup>[[5]](#references)</sup> इसके बाद के malicious peer responses और prompt-injection के प्रभाव के लिए [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary) देखें।

## A2A endpoints का परीक्षण

### बिना authentication के task submission

कार्ड में सूचीबद्ध हर `url` पर बिना किसी credentials के एक न्यूनतम message भेजें:

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

`PONG` वाला `Task` या `Message` परिणाम, जब card में security scheme घोषित हो, इसका मतलब है कि RPC endpoint पर authentication लागू नहीं है (यह केवल UI या card पर लागू हो सकता है)। अगर card में कोई scheme घोषित न हो, तो देखें कि agent की skills किन चीज़ों तक पहुँच सकती हैं: ऐसा unauthenticated agent जो internal data पढ़ सकता है या tools चला सकता है, उन tools के लिए unauthenticated API के बराबर है।

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

स्पेक के अनुसार, हर request पर server को जाँचना चाहिए कि caller को task access करने की अनुमति है या नहीं। साथ ही, कोई filter न दिए जाने पर भी `ListTasks` को caller के दायरे तक सीमित रखना चाहिए।<sup>[[1]](#references)</sup> इसे दो identities (A और B) से जाँचें:

1. A के रूप में, एक task बनाएँ और उसका `id` और `contextId` सहेजें।
2. B के रूप में (या बिना credentials के), A के `id` के साथ `tasks/get` / `GetTask` कॉल करें, फिर बिना parameters के `ListTasks` कॉल करें।
3. A के task पर cancel और subscribe भी आज़माएँ। साथ ही, B के रूप में एक नया message भेजें जिसमें A का `taskId` या `contextId` शामिल हो (इससे B का text A की conversation में जुड़ जाएगा)।

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

असुरक्षित: B को A का history, artifacts या status मिलता है, या वह A का task बदल सकता है। सुरक्षित: `TaskNotFoundError`, जिसमें "मौजूद है लेकिन आपका नहीं" और "मौजूद नहीं है" के बीच कोई अंतर न हो।<sup>[[1]](#references)</sup> Task IDs अक्सर UUIDs होते हैं, इसलिए उन्हें उन जगहों पर खोजें जहाँ वे leak हो सकते हैं (shared links, logs, push notification payloads, error messages)।

### Push notification webhook SSRF

जब `capabilities.pushNotifications` true हो, तो client agent को एक webhook URL देता है, और agent बाद में उस URL पर task updates के साथ `POST` requests भेजता है। Spec कहता है कि agents को private ranges, localhost और link-local addresses अस्वीकार करने चाहिए, और allowlists का इस्तेमाल करना चाहिए।<sup>[[1]](#references)</sup> एक task बनाएँ, ऐसा push notification config register करें जिसका `url` आपके OAST host पर पॉइंट करे, ताकि outbound requests की पुष्टि हो सके। फिर (केवल तभी, जब scope इसकी अनुमति देता हो) internal targets, जैसे `http://127.0.0.1:<port>/` या `http://169.254.169.254/`, आज़माएँ। Internal services का नक्शा बनाने के लिए errors और timing की तुलना करें। Agent इन requests में configured authentication header भी जोड़ता है, इसलिए जाँचें कि जब आप किसी दूसरे user के config का URL बदल सकते हों, तो यह header attacker-chosen host को न भेजा जाए। देखें [SSRF](../pentesting-web/ssrf-server-side-request-forgery/)।

### दूसरे SSRF entry point के रूप में File-URL Parts

A2A 1.0 में कोई message या artifact `url` वाले `Part` के रूप में file reference ले जा सकता है (0.3 में `kind: "file"` और `file.uri` इस्तेमाल होता है)।<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Protocol reference को लेकर चलता है; उसे fetch करना application का व्यवहार है, A2A SDK की आवश्यकता नहीं।<sup>[[6]](#references)</sup> यह ऊपर दिए गए push-notification callback URL से अलग है। दोनों दिशाओं में जाँचें: A2A server को भेजी गई client-supplied file, और किसी lower-trust peer द्वारा orchestrator को लौटाया गया file URL।<sup>[[1]](#references)[[6]](#references)</sup>

किसी अधिकृत 1.0 JSON-RPC endpoint के लिए, सामान्य text part को एक unique OAST path वाले URL से बदलें और जाँचें कि request **कौन-सा component** करता है:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

केवल तभी जब recipient इसे dereference करे, [SSRF workflow](../pentesting-web/ssrf-server-side-request-forgery/) का उपयोग करके scope के भीतर आने वाले internal destinations, redirects और DNS resolution में बदलावों का परीक्षण करें। केवल मान्य `Part` या सफल task response से SSRF साबित नहीं होता; destination पर fetch की पुष्टि करें और यह भी जाँचें कि fetched content agent तक पहुँचता है या नहीं।<sup>[[6]](#references)</sup>

### Extended agent card तक पहुँच

`GetExtendedAgentCard` के लिए authentication आवश्यक होना चाहिए और यह public card से अधिक skills और configuration लौटा सकता है।<sup>[[1]](#references)</sup> इसे बिना credentials और low-privilege identity के साथ call करें और नतीजे की public card से तुलना करें।

### Push notification config और task के दौरान credential leaks

Push notification configs में webhook URL और वे credentials संग्रहीत होते हैं जिन्हें agent उस पर भेजता है। Specification के अनुसार, हर push notification config operation (create, get, list, delete) में यह सत्यापित होना चाहिए कि caller को task तक पहुँचने की अनुमति है।<sup>[[1]](#references)</sup> इन routes पर [task IDOR section](#task-idor-tasksget-gettask-cancel-subscribe) वाला दो-identity test दोहराएँ। किसी दूसरे user का readable config webhook token leak करता है, जबकि writable config उस user के task updates को आपके host पर redirect करता है।

जब किसी task के दौरान agent को अतिरिक्त authorization की आवश्यकता होती है, तो वह task को `TASK_STATE_AUTH_REQUIRED` में ले जाता है। Client authorization की व्यवस्था out of band कर सकता है; specification कहती है कि agents को credentials out of band मिलने चाहिए, जब तक कि in-band mechanism पर सहमति न हुई हो। In-band exchange किसी credential को A2A agents की chain में भेज सकता है और उसे उस chain के हर agent के सामने उजागर कर सकता है।<sup>[[1]](#references)</sup> Orchestrator test में जाँचें कि क्या user द्वारा किसी downstream agent के लिए दिया गया credential messages, artifacts या task history में दिखाई देता है, जिसे दूसरे agents (या task IDOR के ज़रिए दूसरे users) पढ़ सकते हैं।

Agent card fields और task results भी calling agent के लिए untrusted input हैं। [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) में दी गई indirect prompt injection techniques और [AI Agent Security Methodology](AI-Agent-Security-Methodology.md) में दिए गए inter-agent trust checks से उनका परीक्षण करें।

## References

- [1] [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Agent2Agent Protocol (A2A) की घोषणा](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A specification v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A specification v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Multi-Agent Systems में Agent Name Collision Attacks](https://arxiv.org/abs/2609.27624)
- [6] [A2A .NET SDK Security Guide](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [A2A Python v1.0 Migration Guide](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
