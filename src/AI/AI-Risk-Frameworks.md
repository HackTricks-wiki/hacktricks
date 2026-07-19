# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ने AI systems को प्रभावित करने वाली top 10 machine learning vulnerabilities की पहचान की है। इन vulnerabilities से data poisoning, model inversion और adversarial attacks सहित कई security issues हो सकते हैं। Secure AI systems बनाने के लिए इन vulnerabilities को समझना महत्वपूर्ण है।

Top 10 machine learning vulnerabilities की updated और detailed list के लिए [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project देखें।

- **Input Manipulation Attack**: Attacker **incoming data** में बहुत छोटे, अक्सर अदृश्य बदलाव करता है, ताकि model गलत decision ले।\
*Example*: Stop-sign पर paint के कुछ छोटे छींटे self-driving car को speed-limit sign "दिखने" पर मजबूर कर देते हैं।

- **Data Poisoning Attack**: **training set** को जानबूझकर खराब samples से दूषित किया जाता है, जिससे model हानिकारक rules सीखता है।\
*Example*: Antivirus training corpus में malware binaries को "benign" के रूप में mislabeled किया जाता है, जिससे बाद में उसी तरह का malware detection से बच निकलता है।

- **Model Inversion Attack**: Outputs को probe करके attacker एक **reverse model** बनाता है, जो original inputs की sensitive features को reconstruct करता है।\
*Example*: Cancer-detection model की predictions से किसी patient की MRI image को फिर से बनाना।

- **Membership Inference Attack**: Adversary confidence में अंतर देखकर यह जांचता है कि training के दौरान **specific record** का उपयोग किया गया था या नहीं।\
*Example*: यह confirm करना कि किसी व्यक्ति का bank transaction fraud-detection model के training data में मौजूद है।

- **Model Theft**: बार-बार querying करने से attacker decision boundaries सीख सकता है और **model's behavior** (और IP) को **clone** कर सकता है।\
*Example*: ML-as-a-Service API से पर्याप्त Q&A pairs इकट्ठे करके लगभग equivalent local model बनाना।

- **AI Supply-Chain Attack**: **ML pipeline** में किसी भी component (data, libraries, pre-trained weights, CI/CD) को compromise करके downstream models को दूषित करना।\
*Example*: Model-hub पर मौजूद poisoned dependency कई apps में backdoored sentiment-analysis model install कर देती है।

- **Transfer Learning Attack**: **pre-trained model** में malicious logic डाली जाती है, जो victim के task पर fine-tuning के बाद भी बनी रहती है।\
*Example*: Hidden trigger वाला vision backbone medical imaging के लिए adapt किए जाने के बाद भी labels को बदल देता है।

- **Model Skewing**: सूक्ष्म रूप से biased या mislabeled data **model's outputs** को attacker के agenda के पक्ष में बदल देता है।\
*Example*: "clean" spam emails को ham के रूप में label करके inject करना, ताकि spam filter भविष्य में उसी तरह के emails को पास कर दे।

- **Output Integrity Attack**: Attacker **model predictions in transit** को बदलता है, model को नहीं, और downstream systems को धोखा देता है।\
*Example*: File-quarantine stage तक पहुंचने से पहले malware classifier के "malicious" verdict को "benign" में बदल देना।

- **Model Poisoning** --- अक्सर write access प्राप्त करने के बाद **model parameters** में सीधे और targeted बदलाव करना, ताकि behavior बदल जाए।\
*Example*: Production में fraud-detection model के weights को बदलना, ताकि कुछ cards से होने वाले transactions हमेशा approve हो जाएं।


## Google SAIF Risks

Google का [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) AI systems से जुड़े विभिन्न risks का विवरण देता है:

- **Data Poisoning**: Malicious actors accuracy को कम करने, backdoors implant करने या results को skew करने के लिए training/tuning data को बदलते या उसमें data inject करते हैं, जिससे पूरे data-lifecycle में model integrity कमजोर होती है।

- **Unauthorized Training Data**: Copyrighted, sensitive या unpermitted datasets को ingest करने से legal, ethical और performance liabilities पैदा होती हैं, क्योंकि model ऐसे data से सीखता है जिसे उपयोग करने की अनुमति उसे कभी नहीं दी गई थी।

- **Model Source Tampering**: Training से पहले या उसके दौरान model code, dependencies या weights में supply-chain अथवा insider manipulation hidden logic embed कर सकती है, जो retraining के बाद भी बनी रह सकती है।

- **Excessive Data Handling**: कमजोर data-retention और governance controls के कारण systems आवश्यकता से अधिक personal data store या process करते हैं, जिससे exposure और compliance risk बढ़ता है।

- **Model Exfiltration**: Attackers model files/weights चुरा लेते हैं, जिससे intellectual property का नुकसान होता है और copy-cat services या follow-on attacks संभव हो जाते हैं।

- **Model Deployment Tampering**: Adversaries model artifacts या serving infrastructure को बदल देते हैं, जिससे running model vetted version से अलग हो जाता है और उसका behaviour बदल सकता है।

- **Denial of ML Service**: APIs को flood करने या “sponge” inputs भेजने से compute/energy समाप्त हो सकती है और model offline हो सकता है, जो classic DoS attacks जैसा है।

- **Model Reverse Engineering**: बड़ी संख्या में input-output pairs इकट्ठे करके attackers model को clone या distil कर सकते हैं, जिससे imitation products और customized adversarial attacks को बढ़ावा मिलता है।

- **Insecure Integrated Component**: Vulnerable plugins, agents या upstream services attackers को AI pipeline में code inject करने या privileges escalate करने की अनुमति देते हैं।

- **Prompt Injection**: ऐसे prompts बनाना (directly या indirectly) जिनमें system intent को override करने वाले instructions छिपे हों, जिससे model unintended commands perform करे।

- **Model Evasion**: Carefully designed inputs model को mis-classify करने, hallucinate करने या disallowed content output करने के लिए trigger करते हैं, जिससे safety और trust कमजोर होते हैं।

- **Sensitive Data Disclosure**: Model अपने training data या user context से private अथवा confidential information reveal करता है, जिससे privacy और regulations का उल्लंघन होता है।

- **Inferred Sensitive Data**: Model ऐसे personal attributes deduce करता है जो कभी provide नहीं किए गए थे, जिससे inference के माध्यम से नए privacy harms पैदा होते हैं।

- **Insecure Model Output**: Unsanitized responses harmful code, misinformation या inappropriate content को users अथवा downstream systems तक पहुंचा देते हैं।

- **Rogue Actions**: Autonomously-integrated agents पर्याप्त user oversight के बिना unintended real-world operations (file writes, API calls, purchases आदि) execute करते हैं।

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI systems से जुड़े risks को समझने और कम करने के लिए एक comprehensive framework प्रदान करता है। यह उन विभिन्न attack techniques और tactics को categorize करता है जिनका adversaries AI models के विरुद्ध उपयोग कर सकते हैं, और यह भी बताता है कि विभिन्न attacks perform करने के लिए AI systems का उपयोग कैसे किया जा सकता है।

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers active session tokens या cloud API credentials चुराकर paid, cloud-hosted LLMs को बिना authorization के invoke करते हैं। Access को अक्सर reverse proxies के माध्यम से resell किया जाता है, जो victim के account के सामने काम करते हैं, जैसे "oai-reverse-proxy" deployments। Consequences में financial loss, policy के बाहर model misuse और victim tenant पर attribution शामिल हैं।

TTPs:
- Infected developer machines या browsers से tokens harvest करें; CI/CD secrets चुराएं; leaked cookies खरीदें।
- ऐसा reverse proxy स्थापित करें जो requests को genuine provider तक forward करे, upstream key को छिपाए और कई customers को multiplex करे।
- Enterprise guardrails और rate limits को bypass करने के लिए direct base-model endpoints का दुरुपयोग करें।

Mitigations:
- Tokens को device fingerprint, IP ranges और client attestation से bind करें; short expirations लागू करें और MFA से refresh करें।
- Keys का scope न्यूनतम रखें (कोई tool access नहीं, जहां लागू हो read-only); anomaly होने पर rotate करें।
- सभी traffic को server-side policy gateway के पीछे terminate करें, जो safety filters, per-route quotas और tenant isolation लागू करता हो।
- Unusual usage patterns (अचानक spend spikes, atypical regions, UA strings) की निगरानी करें और suspicious sessions को automatically revoke करें।
- लंबे समय तक चलने वाली static API keys के बजाय अपने IdP द्वारा जारी mTLS या signed JWTs को प्राथमिकता दें।

## Self-hosted LLM inference hardening

Confidential data के लिए local LLM server चलाने से cloud-hosted APIs से अलग attack surface बनता है: inference/debug endpoints prompts को leak कर सकते हैं, serving stack आमतौर पर reverse proxy expose करता है, और GPU device nodes बड़े `ioctl()` surfaces तक access देते हैं। यदि आप on-prem inference service का assessment या deployment कर रहे हैं, तो कम से कम निम्नलिखित points की समीक्षा करें।

### Prompt leakage via debug and monitoring endpoints

Inference API को **multi-user sensitive service** मानें। Debug या monitoring routes prompt contents, slot state, model metadata अथवा internal queue information expose कर सकते हैं। `llama.cpp` में `/slots` endpoint विशेष रूप से sensitive है, क्योंकि यह per-slot state expose करता है और केवल slot inspection/management के लिए है।

- Inference server के सामने reverse proxy रखें और **deny by default** लागू करें।
- Client/UI के लिए आवश्यक exact HTTP method + path combinations को ही allowlist करें।
- जहां संभव हो, backend में introspection endpoints disable करें, उदाहरण के लिए `llama-server --no-slots`।
- Reverse proxy को `127.0.0.1` से bind करें और उसे LAN पर publish करने के बजाय SSH local port forwarding जैसे authenticated transport के माध्यम से expose करें।

nginx के साथ example allowlist:
```nginx
map "$request_method:$uri" $llm_whitelist {
default 0;

"GET:/health"              1;
"GET:/v1/models"           1;
"POST:/v1/completions"     1;
"POST:/v1/chat/completions" 1;
}

server {
listen 127.0.0.1:80;

location / {
if ($llm_whitelist = 0) { return 403; }
proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
}
}
```
### बिना network और UNIX sockets वाले Rootless containers

यदि inference daemon UNIX socket पर listening support करता है, तो TCP की तुलना में इसे प्राथमिकता दें और container को **no network stack** के साथ चलाएँ:
```bash
podman run --rm -d \
--network none \
--user 1000:1000 \
--userns=keep-id \
--umask=007 \
--volume /var/lib/models:/models:ro \
--volume /srv/llm/socks:/run/llama-cpp \
ghcr.io/ggml-org/llama.cpp:server-cuda13 \
--host /run/llama-cpp/llama-cpp.sock \
--model /models/model.gguf \
--parallel 4 \
--no-slots
```
लाभ:
- `--network none` inbound/outbound TCP/IP exposure को हटाता है और उन user-mode helpers की आवश्यकता से बचाता है, जिनकी rootless containers को अन्यथा जरूरत होती।
- एक UNIX socket आपको socket path पर POSIX permissions/ACLs को पहली access-control layer के रूप में उपयोग करने देता है।
- `--userns=keep-id` और rootless Podman container breakout के प्रभाव को कम करते हैं, क्योंकि container root, host root नहीं होता।
- Read-only model mounts container के अंदर से model tampering की संभावना को कम करते हैं।

### GPU device-node न्यूनतमकरण

GPU-backed inference के लिए, `/dev/nvidia*` files उच्च-मूल्य वाले local attack surfaces हैं, क्योंकि वे बड़े driver `ioctl()` handlers और संभावित रूप से shared GPU memory-management paths को expose करते हैं।

- `/dev/nvidia*` को world writable न छोड़ें।
- `nvidia`, `nvidiactl`, और `nvidia-uvm` को `NVreg_DeviceFileUID/GID/Mode`, udev rules, और ACLs के साथ restrict करें, ताकि केवल mapped container UID ही उन्हें open कर सके।
- Headless inference hosts पर `nvidia_drm`, `nvidia_modeset`, और `nvidia_peermem` जैसे अनावश्यक modules को blacklist करें।
- Runtime को inference startup के दौरान opportunistically `modprobe` करने देने के बजाय, boot पर केवल आवश्यक modules को preload करें।

उदाहरण:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
एक महत्वपूर्ण review point **`/dev/nvidia-uvm`** है। भले ही workload स्पष्ट रूप से `cudaMallocManaged()` का उपयोग न करता हो, हाल के CUDA runtimes को फिर भी `nvidia-uvm` की आवश्यकता हो सकती है। क्योंकि यह device shared है और GPU virtual memory management संभालता है, इसे cross-tenant data-exposure surface मानें। यदि inference backend इसे support करता है, तो Vulkan backend एक दिलचस्प trade-off हो सकता है, क्योंकि इससे container के सामने `nvidia-uvm` expose करने से पूरी तरह बचा जा सकता है।

### inference workers के लिए LSM confinement

Inference process के आसपास defense in depth के रूप में AppArmor/SELinux/seccomp का उपयोग किया जाना चाहिए:

- केवल उन shared libraries, model paths, socket directory और GPU device nodes को allow करें जिनकी वास्तव में आवश्यकता है।
- `sys_admin`, `sys_module`, `sys_rawio` और `sys_ptrace` जैसी high-risk capabilities को स्पष्ट रूप से deny करें।
- Model directory को read-only रखें और writable paths को केवल runtime socket/cache directories तक सीमित करें।
- Denial logs की निगरानी करें, क्योंकि जब model server या post-exploitation payload अपने अपेक्षित behaviour से बाहर निकलने का प्रयास करता है, तो ये उपयोगी detection telemetry प्रदान करते हैं।

GPU-backed worker के लिए Example AppArmor rules:
```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```
## Phantom Squatting: LLM द्वारा hallucinate किए गए domains को AI Supply-Chain Vector के रूप में

Phantom squatting, **slopsquatting** का **domain/URL equivalent** है। किसी गैर-मौजूद package name को hallucinate करने के बजाय, LLM किसी वास्तविक brand के लिए एक संभावित **portal, API, webhook, billing, SSO, download या support domain** hallucinate करता है, और कोई attacker उस namespace को किसी human या agent द्वारा उपयोग किए जाने से पहले register कर लेता है।

यह महत्वपूर्ण है क्योंकि कई AI-assisted workflows में model output को **trusted dependency** माना जाता है:
- Developers सुझाए गए endpoint को code या CI/CD integrations में paste कर देते हैं।
- AI agents documentation, schemas, APKs, ZIPs या webhook targets को automatically fetch करते हैं।
- Generated runbooks या docs fake URL को authoritative मानकर embed कर सकते हैं।

### Offensive workflow

1. **Hallucination surface को probe करें**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` या `mobile app` portals जैसे realistic workflows के बारे में brand-specific questions पूछें।
2. **Candidates को normalize करें**: generated URLs को resolve करें, NXDOMAIN responses को parent registerable domain में collapse करें और prompt families को deduplicate करें। Prompt corpora विविध रहने चाहिए, उदाहरण के लिए **Jaccard similarity** के आधार पर near-duplicates को हटाकर।
3. **Predictable hallucinations को prioritize करें**:
- **Thermal Hallucination Persistence (THP)**: वही fake domain अलग-अलग temperatures पर दिखाई दे, जिसमें `T=0.1` जैसा low temperature भी शामिल है।
- **Cross-model consensus**: कई LLM families एक ही fake domain generate करें।
4. Parent domain को **register और weaponize** करें, फिर phishing, fake APK/ZIP downloads, credential harvesters, malicious docs या ऐसे API endpoints host करें जो secrets/webhook payloads collect करते हों। **Pure domain-level hallucinations** को monetize करना सबसे आसान है क्योंकि attacker पूरे namespace को control करता है; subdomain/path hallucinations का भी दुरुपयोग किया जा सकता है, जब normalized parent unregistered हो।
5. **Zero-reputation window का exploit करें**: नए registered domains में अक्सर blocklist history, URL reputation और mature telemetry नहीं होती, इसलिए detections के catch up करने तक वे controls को bypass कर सकते हैं। Attackers crawler-only benign responses, redirect cloaking, CAPTCHA gates या delayed payload staging के जरिए इस window को बढ़ा सकते हैं।

### Agents के लिए यह खतरनाक क्यों है

Human victim के मामले में fake domain को आमतौर पर click और किसी अन्य action की आवश्यकता होती है। लेकिन **agentic workflow** में LLM **lure** और **executor**, दोनों हो सकता है: agent hallucinated URL प्राप्त करता है, उसे fetch करता है, response parse करता है और फिर tokens leak कर सकता है, instructions execute कर सकता है, dependency download कर सकता है या बिना किसी human review के poisoned data को CI/CD में push कर सकता है।

### Practical attacker prompts

High-yield prompts आमतौर पर explicit phishing lures के बजाय सामान्य enterprise tasks जैसे दिखते हैं:
- “`<brand>` integrations के लिए payment sandbox URL क्या है?”
- “`<brand>` build notifications के लिए मुझे कौन-सा webhook endpoint उपयोग करना चाहिए?”
- “`<brand>` का employee benefits / billing / SSO portal कहाँ है?”
- “`<brand>` के लिए direct Android APK या desktop client download दें।”

### Defensive inversion

इसे केवल prompt-injection problem के रूप में नहीं, बल्कि proactive domain-monitoring problem के रूप में देखें:
- एक **brand prompt corpus** बनाएं और समय-समय पर उन LLMs को probe करें जिन पर आपके users/agents निर्भर हैं।
- Hallucinated URLs store करें और track करें कि कौन-से URLs temperatures/models के बीच stable हैं।
- **Adversarial Exploitation Window (AEW)** को track करें: first hallucination और attacker registration के बीच का समय। Positive AEW का अर्थ है कि defenders weaponization से पहले pre-register, sinkhole या pre-block कर सकते हैं।
- Parent domains के **NXDOMAIN → registered** transitions को monitor करें।
- Registration पर registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status और brand-asset similarity की triage करें।
- Policy gates जोड़ें ताकि agents/developers default रूप से **LLM-generated domains पर trust न करें**: first use से पहले allowlists, ownership validation, CT/RDAP checks या human approval आवश्यक करें।

यह एक साथ कई AI risk buckets में आता है: **AI supply-chain attack**, **insecure model output**, और जब agents hallucinated URL को autonomously consume करते हैं तब **rogue actions**।

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
