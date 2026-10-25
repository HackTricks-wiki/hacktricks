# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## A2A क्या है

A2A (Agent2Agent) एक open protocol है, जो एक AI agent को दूसरे agent का पता लगाने और HTTP के ज़रिए उसे काम भेजने देता है। MCP किसी agent को **tools और data** से जोड़ता है; A2A किसी agent को **दूसरे agents** से जोड़ता है, जो आमतौर पर किसी दूसरी टीम या कंपनी के स्वामित्व वाली remote services होती हैं। A2A server, अपने पीछे LLM agent वाला एक web API होता है, इसलिए protocol के अपने objects (agent cards, tasks, push-notification webhooks, extended cards) सामान्य API test में authentication, IDOR और SSRF की खास जाँचें जोड़ते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

इसके मुख्य हिस्से हैं:

- **Agent Card:** एक JSON document जो agent का वर्णन करता है: नाम, विवरण, skills, service URL(s), supported transports, capabilities (streaming, push notifications, extended card) और वे `securitySchemes` जिनका client को उपयोग करना होता है। यह `https://<host>/.well-known/agent-card.json` पर प्रकाशित होता है। पुराने deployments, जो spec 0.2.x का पालन करते हैं, `/.well-known/agent.json` का उपयोग करते हैं।<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** काम की इकाई। एक message task बनाता है (जिसमें server द्वारा जनरेट किया गया `id` और `contextId` होता है), और client बाद में उसे पढ़ता है, cancel करता है या उसकी सदस्यता लेता है।<sup>[[1]](#references)</sup>
- **Transports:** HTTP पर JSON-RPC 2.0 (streaming के लिए SSE के साथ), gRPC, और HTTP+JSON REST binding।<sup>[[1]](#references)</sup>
- **Authentication:** credentials HTTP headers में जाते हैं (उदाहरण के लिए `Authorization: Bearer ...`), JSON-RPC payload के अंदर कभी नहीं। Agent card बताता है कि किस scheme की आवश्यकता है।<sup>[[1]](#references)</sup>

Versions के बीच method names बदल गए हैं, इसलिए दोनों sets आज़माएँ:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operation | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Message भेजें | `message/send` | `SendMessage` | `POST /message:send` |
| Streaming message भेजें | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Task प्राप्त करें | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Tasks की सूची | - | `ListTasks` | `GET /tasks` |
| Task cancel करें | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification config | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 spec version चुनने के लिए `A2A-Version` header (या request parameter) का उपयोग करता है, और इसके बिना आने वाले requests को 0.3 माना जाता है।<sup>[[1]](#references)</sup>

## खोज

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

कार्ड से ये जानकारी लिख लें:

- हर service `url` (अक्सर कोई internal hostname, staging URL या public site से अलग port)।
- `skills`: ये दिखाते हैं कि agent क्या कर सकता है और इसके पीछे कौन-से tools या data हैं।
- `securitySchemes` / `security`: अगर ये खाली हैं या मौजूद नहीं हैं, तो संभवतः agent को credentials के बिना call करने के लिए बनाया गया है।
- `capabilities.pushNotifications` और `capabilities.extendedAgentCard` (0.3 में `supportsAuthenticatedExtendedCard`)।

स्पेक के अनुसार, public card में credentials या internal implementation details नहीं होने चाहिए। इसलिए public card में internal URLs, keys या tools की विस्तृत सूची मिलना पहले से ही एक finding है।<sup>[[1]](#references)</sup>

## A2A endpoints की जाँच

### बिना authentication के task submission

कार्ड में सूचीबद्ध हर `url` पर बिना किसी credentials के एक minimal message भेजें:

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

A `Task` या `Message` का `PONG` परिणाम, जब card में security scheme घोषित हो, इसका अर्थ है कि RPC endpoint पर authentication लागू नहीं है (यह केवल UI या card पर लागू हो सकता है)। यदि card में कोई scheme घोषित नहीं है, तो जाँचें कि agent की skills किन चीज़ों तक पहुँच सकती हैं: ऐसा unauthenticated agent जो internal data पढ़ सकता है या tools कॉल कर सकता है, उन tools के लिए unauthenticated API के समान है।

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Spec के अनुसार, server को हर request पर जाँचना चाहिए कि caller को उस task तक पहुँचने की अनुमति है या नहीं, और filter न दिए जाने पर भी `ListTasks` का दायरा caller तक सीमित रखना चाहिए।<sup>[[1]](#references)</sup> दो identities (A और B) के साथ इसकी जाँच करें:

1. A के रूप में, एक task बनाएँ और उसका `id` तथा `contextId` सहेजें।
2. B के रूप में (या credentials के बिना), A के `id` के साथ `tasks/get` / `GetTask` कॉल करें, फिर बिना parameters के `ListTasks` कॉल करें।
3. A के task पर cancel और subscribe भी आज़माएँ, और B के रूप में एक नया message भेजें जिसमें A का `taskId` या `contextId` शामिल हो (इससे B का text A की conversation में जुड़ जाएगा)।

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

असुरक्षित: B को A का इतिहास, artifacts या status मिलता है, या वह A का task बदल सकता है। सुरक्षित: `TaskNotFoundError` मिलता है, और "मौजूद है लेकिन आपका नहीं" तथा "मौजूद नहीं है" के बीच कोई अंतर नहीं होता।<sup>[[1]](#references)</sup> Task IDs अक्सर UUIDs होते हैं, इसलिए उन्हें उन जगहों पर खोजें जहाँ वे leak हो सकते हैं (shared links, logs, push notification payloads, error messages)।

### Push notification webhook SSRF

जब `capabilities.pushNotifications` true होता है, तो client agent को एक webhook URL देता है, और agent बाद में उस URL पर task updates के साथ `POST` requests भेजता है। Spec कहता है कि agents को private ranges, localhost और link-local addresses अस्वीकार करने चाहिए और allowlists का उपयोग करना चाहिए।<sup>[[1]](#references)</sup> एक task बनाएँ, ऐसा push notification config register करें जिसका `url` आपके OAST host की ओर इंगित करता हो, ताकि outbound requests की पुष्टि हो सके। फिर (केवल तभी जब scope इसकी अनुमति देता हो) `http://127.0.0.1:<port>/` या `http://169.254.169.254/` जैसे internal targets आज़माएँ। Internal services का नक्शा बनाने के लिए errors और timing की तुलना करें। Agent इन requests में configured authentication header भी जोड़ता है, इसलिए जाँचें कि जब आप किसी दूसरे user के config का URL बदल सकते हों, तो यह header attacker द्वारा चुने गए host को न भेजा जाए। देखें [SSRF](../pentesting-web/ssrf-server-side-request-forgery/)।

### Extended agent card तक पहुंच

`GetExtendedAgentCard` के लिए authentication आवश्यक होना चाहिए और यह public card से अधिक skills और configuration लौटा सकता है।<sup>[[1]](#references)</sup> इसे credentials के बिना और low-privilege identity के साथ call करें, फिर परिणाम की public card से तुलना करें।

### Push notification config और task के दौरान credential leaks

Push notification configs में webhook URL और वे credentials संग्रहित होते हैं जिन्हें agent उस URL पर भेजता है। Spec के अनुसार, हर push notification config operation (create, get, list, delete) में यह सत्यापित होना चाहिए कि caller को task तक पहुंचने की अनुमति है।<sup>[[1]](#references)</sup> इन routes पर [task IDOR वाले section](#task-idor-tasksget-gettask-cancel-subscribe) का two-identity test दोहराएँ। किसी दूसरे user का readable config webhook token leak करता है, और writable config उस user के task updates को आपके host पर redirect करता है।

जब किसी task के दौरान agent को अतिरिक्त authorization की आवश्यकता होती है, तो वह task को `TASK_STATE_AUTH_REQUIRED` पर ले जाता है। Client authorization की व्यवस्था out of band कर सकता है; specification कहता है कि agents को credentials out of band मिलने चाहिए, जब तक कि in-band mechanism पर सहमति न हुई हो। In-band exchange किसी credential को A2A agents की chain के पार भेज सकता है और उसे उस chain के हर agent के सामने उजागर कर सकता है।<sup>[[1]](#references)</sup> Orchestrator test में जाँचें कि क्या user द्वारा किसी एक downstream agent के लिए दिया गया credential messages, artifacts या task history में दिखाई देता है, जिन्हें दूसरे agents (या task IDOR के ज़रिए दूसरे users) पढ़ सकते हैं।

Agent card fields और task results भी calling agent के लिए untrusted input हैं। उन्हें [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) में दी गई indirect prompt injection techniques और [AI Agent Security Methodology](AI-Agent-Security-Methodology.md) में दिए गए inter-agent trust checks से जाँचें।

## References

- [1] [A2A Protocol विनिर्देशन](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Agent2Agent Protocol (A2A) की घोषणा](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A विनिर्देशन v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A विनिर्देशन v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
