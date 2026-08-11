# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ने AI systems को प्रभावित करने वाली top 10 machine learning vulnerabilities की पहचान की है। इन vulnerabilities से data poisoning, model inversion और adversarial attacks सहित कई security issues उत्पन्न हो सकते हैं। Secure AI systems बनाने के लिए इन vulnerabilities को समझना महत्वपूर्ण है।

Top 10 machine learning vulnerabilities की updated और detailed list के लिए [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project देखें।<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Attacker **incoming data** में बहुत छोटे, अक्सर अदृश्य बदलाव करता है, ताकि model गलत निर्णय ले।\
*उदाहरण*: Stop-sign पर paint के कुछ छोटे धब्बे self-driving car को उसे speed-limit sign के रूप में "देखने" के लिए भ्रमित कर देते हैं।

- **Data Poisoning Attack**: **Training set** को जानबूझकर खराब samples से दूषित किया जाता है, जिससे model हानिकारक नियम सीखता है।\
*उदाहरण*: Antivirus training corpus में malware binaries को "benign" के रूप में गलत label किया जाता है, जिससे बाद में उसी तरह का malware detection से बच निकलता है।

- **Model Inversion Attack**: Outputs की probing करके attacker एक **reverse model** बनाता है, जो original inputs की sensitive features को reconstruct करता है।\
*उदाहरण*: Cancer-detection model की predictions से patient की MRI image को दोबारा बनाना।

- **Membership Inference Attack**: Adversary confidence में अंतर देखकर यह जांचता है कि training के दौरान **specific record** का उपयोग किया गया था या नहीं।\
*उदाहरण*: यह पुष्टि करना कि किसी व्यक्ति का bank transaction fraud-detection model के training data में मौजूद है।

- **Model Theft**: बार-बार querying करने से attacker decision boundaries सीखकर **model's behavior** (और IP) को **clone** कर सकता है।\
*उदाहरण*: ML-as-a-Service API से पर्याप्त Q&A pairs इकट्ठा करके लगभग समान local model बनाना।

- **AI Supply-Chain Attack**: **ML pipeline** के किसी भी component (data, libraries, pre-trained weights, CI/CD) को compromise करके downstream models को दूषित करना।\
*उदाहरण*: Model-hub की poisoned dependency कई apps में backdoored sentiment-analysis model install कर देती है।

- **Transfer Learning Attack**: **Pre-trained model** में malicious logic डाला जाता है, जो victim के task पर fine-tuning के बाद भी बना रहता है।\
*उदाहरण*: Hidden trigger वाला vision backbone medical imaging के लिए adapt किए जाने के बाद भी labels को बदल देता है।

- **Model Skewing**: सूक्ष्म रूप से biased या mislabeled data **model's outputs** को attacker के agenda के पक्ष में बदल देता है।\
*उदाहरण*: "Clean" spam emails को ham के रूप में label करके inject करना, ताकि spam filter भविष्य के समान emails को allow कर दे।

- **Output Integrity Attack**: Attacker model को नहीं, बल्कि **model predictions in transit** को बदलता है और downstream systems को भ्रमित करता है।\
*उदाहरण*: File-quarantine stage तक पहुंचने से पहले malware classifier के "malicious" verdict को "benign" में बदल देना।

- **Model Poisoning** --- अक्सर write access प्राप्त करने के बाद **model parameters** में सीधे, targeted बदलाव करना, ताकि behavior बदल जाए।\
*उदाहरण*: Production में fraud-detection model के weights को बदलना, ताकि कुछ cards से होने वाले transactions हमेशा approve हो जाएं।


## Google SAIF Risks

Google का [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) AI systems से जुड़े विभिन्न risks को रेखांकित करता है:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Malicious actors training/tuning data को बदलते या उसमें data inject करते हैं, जिससे accuracy घटती है, backdoors डाले जाते हैं या results skew होते हैं और पूरे data-lifecycle में model integrity कमजोर होती है।

- **Unauthorized Training Data**: Copyrighted, sensitive या unpermitted datasets को ingest करने से legal, ethical और performance liabilities उत्पन्न होती हैं, क्योंकि model ऐसे data से सीखता है जिसका उपयोग करने की उसे अनुमति नहीं थी।

- **Model Source Tampering**: Training से पहले या उसके दौरान model code, dependencies या weights में supply-chain या insider manipulation hidden logic डाल सकती है, जो retraining के बाद भी बनी रहती है।

- **Excessive Data Handling**: कमजोर data-retention और governance controls systems को आवश्यकता से अधिक personal data store या process करने देते हैं, जिससे exposure और compliance risk बढ़ता है।

- **Model Exfiltration**: Attackers model files/weights चुरा लेते हैं, जिससे intellectual property का नुकसान होता है और copy-cat services या follow-on attacks संभव हो जाते हैं।

- **Model Deployment Tampering**: Adversaries model artifacts या serving infrastructure को बदल देते हैं, जिससे running model vetted version से अलग हो जाता है और उसका behaviour बदल सकता है।

- **Denial of ML Service**: APIs को flood करना या “sponge” inputs भेजना compute/energy समाप्त कर सकता है और model को offline कर सकता है, जो classic DoS attacks जैसा है।

- **Model Reverse Engineering**: बड़ी संख्या में input-output pairs इकट्ठा करके attackers model को clone या distil कर सकते हैं, जिससे imitation products और customized adversarial attacks को बढ़ावा मिलता है।

- **Insecure Integrated Component**: Vulnerable plugins, agents या upstream services attackers को AI pipeline में code inject करने या privileges escalate करने देते हैं।

- **Prompt Injection**: ऐसे prompts बनाना (directly या indirectly) जिनमें system intent को override करने वाले instructions छिपे हों, जिससे model unintended commands execute करे।

- **Model Evasion**: Carefully designed inputs model को mis-classify करने, hallucinate करने या disallowed content output करने के लिए trigger करते हैं, जिससे safety और trust कमजोर होते हैं।

- **Sensitive Data Disclosure**: Model अपने training data या user context से private या confidential information reveal करता है, जिससे privacy और regulations का उल्लंघन होता है।

- **Inferred Sensitive Data**: Model ऐसे personal attributes deduce करता है जो कभी provide नहीं किए गए थे, जिससे inference के माध्यम से नई privacy harms उत्पन्न होती हैं।

- **Insecure Model Output**: Unsanitized responses harmful code, misinformation या inappropriate content users या downstream systems तक पहुंचा देते हैं।

- **Rogue Actions**: Autonomously-integrated agents पर्याप्त user oversight के बिना unintended real-world operations (file writes, API calls, purchases, आदि) execute करते हैं।

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI systems से जुड़े risks को समझने और कम करने के लिए एक comprehensive framework प्रदान करता है। यह उन विभिन्न attack techniques और tactics को categorize करता है जिनका adversaries AI models के विरुद्ध उपयोग कर सकते हैं, और यह भी बताता है कि अलग-अलग attacks करने के लिए AI systems का उपयोग कैसे किया जाए।<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers active session tokens या cloud API credentials चुराकर paid, cloud-hosted LLMs को बिना authorization invoke करते हैं। Access को अक्सर reverse proxies के माध्यम से resell किया जाता है, जो victim के account के सामने काम करते हैं, जैसे "oai-reverse-proxy" deployments। इसके परिणामों में financial loss, policy के बाहर model misuse और victim tenant को attribution शामिल हैं।<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- Infected developer machines या browsers से tokens harvest करना; CI/CD secrets चुराना; leaked cookies खरीदना।<sup>[[5]](#references)</sup>
- ऐसा reverse proxy स्थापित करना जो requests को genuine provider तक forward करे, upstream key को छिपाए और कई customers को multiplex करे।<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Enterprise guardrails और rate limits को bypass करने के लिए direct base-model endpoints का दुरुपयोग करना।<sup>[[4]](#references)</sup>

Mitigations:
- Tokens को device fingerprint, IP ranges और client attestation से bind करें; short expirations लागू करें और MFA के साथ refresh करें।
- Keys का scope न्यूनतम रखें (कोई tool access नहीं, जहां लागू हो वहां read-only); anomaly होने पर rotate करें।
- सभी traffic को policy gateway के पीछे server-side terminate करें, जो safety filters, per-route quotas और tenant isolation लागू करता हो।
- Unusual usage patterns (अचानक spend spikes, atypical regions, UA strings) की निगरानी करें और suspicious sessions को automatically revoke करें।
- Long-lived static API keys के बजाय अपने IdP द्वारा जारी mTLS या signed JWTs को प्राथमिकता दें।

## Self-hosted LLM inference hardening

Confidential data के लिए local LLM server चलाने से cloud-hosted APIs की तुलना में एक अलग attack surface बनता है: inference/debug endpoints prompts leak कर सकते हैं, serving stack आमतौर पर reverse proxy expose करता है और GPU device nodes बड़े `ioctl()` surfaces तक access देते हैं। यदि आप on-prem inference service का assessment या deployment कर रहे हैं, तो कम से कम निम्नलिखित points की समीक्षा करें।<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

Inference API को **multi-user sensitive service** मानें। Debug या monitoring routes prompt contents, slot state, model metadata या internal queue information expose कर सकते हैं। `llama.cpp` में `/slots` endpoint विशेष रूप से sensitive है, क्योंकि यह per-slot state expose करता है और केवल slot inspection/management के लिए है।<sup>[[8]](#references)</sup>

- Inference server के सामने reverse proxy रखें और **deny by default** लागू करें।
- Client/UI के लिए आवश्यक exact HTTP method + path combinations को ही allowlist करें।
- जब संभव हो, backend में ही introspection endpoints disable करें, उदाहरण के लिए `llama-server --no-slots`।<sup>[[9]](#references)</sup>
- Reverse proxy को `127.0.0.1` से bind करें और उसे LAN पर publish करने के बजाय SSH local port forwarding जैसे authenticated transport के माध्यम से expose करें।

Example allowlist with nginx:
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

यदि inference daemon UNIX socket पर listen करने का समर्थन करता है, तो TCP की अपेक्षा इसे प्राथमिकता दें और container को **no network stack** के साथ चलाएँ:<sup>[[8]](#references)</sup>
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
- `--network none` inbound/outbound TCP/IP exposure को हटाता है और उन user-mode helpers से बचाता है जिनकी rootless containers को अन्यथा आवश्यकता होती।
- एक UNIX socket आपको socket path पर POSIX permissions/ACLs को पहली access-control layer के रूप में उपयोग करने देता है।
- `--userns=keep-id` और rootless Podman container breakout के प्रभाव को कम करते हैं, क्योंकि container root, host root नहीं होता।
- Read-only model mounts container के अंदर से model tampering की संभावना को कम करते हैं।

Persistent deployments के लिए, इन्हीं restrictions को Podman Quadlet units के रूप में व्यक्त किया जा सकता है। यदि GPU access को Container Device Interface के माध्यम से delegate किया गया है, तो हर accelerator node को expose करने के बजाय CDI device specification को यथासंभव narrow रखें।<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node minimization

GPU-backed inference के लिए, `/dev/nvidia*` files high-value local attack surfaces हैं, क्योंकि वे बड़े driver `ioctl()` handlers और संभावित shared GPU memory-management paths को expose करती हैं।<sup>[[8]](#references)</sup>

- `/dev/nvidia*` को world writable न छोड़ें।
- `nvidia`, `nvidiactl`, और `nvidia-uvm` को `NVreg_DeviceFileUID/GID/Mode`, udev rules, और ACLs के माध्यम से restrict करें, ताकि केवल mapped container UID ही उन्हें open कर सके।
- Headless inference hosts पर `nvidia_drm`, `nvidia_modeset`, और `nvidia_peermem` जैसे अनावश्यक modules को blacklist करें।
- Runtime को inference startup के दौरान opportunistically `modprobe` करने देने के बजाय boot पर केवल आवश्यक modules को preload करें।

उदाहरण:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
एक महत्वपूर्ण review बिंदु **`/dev/nvidia-uvm`** है। भले ही workload स्पष्ट रूप से `cudaMallocManaged()` का उपयोग न करता हो, हाल के CUDA runtimes को फिर भी `nvidia-uvm` की आवश्यकता हो सकती है। क्योंकि यह device shared है और GPU virtual memory management संभालता है, इसे cross-tenant data-exposure surface मानें। यदि inference backend इसका समर्थन करता है, तो Vulkan backend एक रोचक trade-off हो सकता है, क्योंकि इससे container में `nvidia-uvm` expose करने से पूरी तरह बचा जा सकता है।<sup>[[8]](#references)</sup>

### inference workers के लिए LSM confinement

inference process के चारों ओर defense in depth के रूप में AppArmor/SELinux/seccomp का उपयोग किया जाना चाहिए:<sup>[[8]](#references)</sup>

- केवल उन shared libraries, model paths, socket directory और GPU device nodes को अनुमति दें जिनकी वास्तव में आवश्यकता है।
- `sys_admin`, `sys_module`, `sys_rawio` और `sys_ptrace` जैसी high-risk capabilities को स्पष्ट रूप से deny करें।
- model directory को read-only रखें और writable paths को केवल runtime socket/cache directories तक सीमित रखें।
- denial logs की निगरानी करें, क्योंकि जब model server या कोई post-exploitation payload अपने अपेक्षित behaviour से बाहर निकलने का प्रयास करता है, तब वे उपयोगी detection telemetry प्रदान करते हैं।

GPU-backed worker के लिए उदाहरण AppArmor rules:
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
## Phantom Squatting: LLM-Hallucinated Domains एक AI Supply-Chain Vector के रूप में

Phantom squatting, **slopsquatting का domain/URL equivalent** है। किसी non-existent package name को hallucinate करने के बजाय, LLM किसी वास्तविक brand के लिए एक plausible **portal, API, webhook, billing, SSO, download या support domain** hallucinate करता है, और कोई attacker उस namespace को किसी human या agent द्वारा उपयोग किए जाने से पहले register कर लेता है।<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

यह महत्वपूर्ण है क्योंकि कई AI-assisted workflows में model output को एक **trusted dependency** माना जाता है:
- Developers सुझाए गए endpoint को code या CI/CD integrations में paste कर देते हैं।
- AI agents documentation, schemas, APKs, ZIPs या webhook targets को automatically fetch करते हैं।
- Generated runbooks या docs fake URL को authoritative URL की तरह embed कर सकते हैं।

### Offensive workflow

1. **Hallucination surface को probe करें**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` या `mobile app` portals जैसे realistic workflows के बारे में brand-specific questions पूछें।<sup>[[12]](#references)</sup>
2. **Candidates को normalize करें**: generated URLs को resolve करें, NXDOMAIN responses को parent registerable domain तक collapse करें, और prompt families को deduplicate करें। Prompt corpora diverse रहने चाहिए, उदाहरण के लिए **Jaccard similarity** वाले near-duplicates को हटाकर।
3. **Predictable hallucinations को prioritize करें**:
- **Thermal Hallucination Persistence (THP)**: वही fake domain अलग-अलग temperatures पर दिखाई देता है, जिसमें `T=0.1` जैसी low temperature भी शामिल है।
- **Cross-model consensus**: कई LLM families एक ही fake domain generate करती हैं।
4. Parent domain को **register और weaponize** करें, फिर phishing, fake APK/ZIP downloads, credential harvesters, malicious docs या ऐसे API endpoints host करें जो secrets/webhook payloads collect करते हों। **Pure domain-level hallucinations** monetize करने के लिए सबसे आसान होती हैं क्योंकि attacker पूरे namespace को control करता है; subdomain/path hallucinations का भी abuse किया जा सकता है, जब normalized parent unregistered हो।
5. **Zero-reputation window का exploit करें**: नए registered domains में अक्सर blocklist history, URL reputation और mature telemetry नहीं होती, इसलिए detections के catch up करने तक वे controls को bypass कर सकते हैं। Attackers crawler-only benign responses, redirect cloaking, CAPTCHA gates या delayed payload staging के माध्यम से इस window को बढ़ा सकते हैं।

### Agents के लिए यह खतरनाक क्यों है

Human victim के मामले में fake domain के लिए आमतौर पर click और एक अन्य action की आवश्यकता होती है। लेकिन **agentic workflow** में LLM **lure** और **executor**, दोनों हो सकता है: agent hallucinated URL प्राप्त करता है, उसे fetch करता है, response को parse करता है और फिर बिना किसी human review के tokens leak कर सकता है, instructions execute कर सकता है, dependency download कर सकता है या poisoned data को CI/CD में push कर सकता है।<sup>[[12]](#references)</sup>

### Practical attacker prompts

High-yield prompts आमतौर पर explicit phishing lures के बजाय normal enterprise tasks जैसे दिखाई देते हैं:<sup>[[12]](#references)</sup>
- “`<brand>` integrations के लिए payment sandbox URL क्या है?”
- “`<brand>` build notifications के लिए मुझे कौन-सा webhook endpoint उपयोग करना चाहिए?”
- “`<brand>` के लिए employee benefits / billing / SSO portal कहाँ है?”
- “`<brand>` के लिए direct Android APK या desktop client download दें।”

### Defensive inversion

इसे केवल prompt-injection problem न मानकर proactive domain-monitoring problem की तरह treat करें:<sup>[[12]](#references)</sup>
- एक **brand prompt corpus** बनाएं और उन LLMs को समय-समय पर probe करें जिन पर आपके users/agents निर्भर करते हैं।
- Hallucinated URLs store करें और track करें कि कौन-से URLs temperatures/models के बीच stable रहते हैं।
- **Adversarial Exploitation Window (AEW)** को track करें: first hallucination और attacker registration के बीच का समय। Positive AEW का अर्थ है कि defenders weaponization से पहले pre-register, sinkhole या pre-block कर सकते हैं।
- Parent domains के लिए **NXDOMAIN → registered** transitions monitor करें।
- Registration पर registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status और brand-asset similarity की triage करें।
- ऐसी policy gates जोड़ें ताकि agents/developers **default रूप से LLM-generated domains पर trust न करें**: first use से पहले allowlists, ownership validation, CT/RDAP checks या human approval आवश्यक करें।

यह एक साथ कई AI risk buckets में आता है: **AI supply-chain attack**, **insecure model output**, और **rogue actions**, जब agents autonomously hallucinated URL का उपयोग करते हैं।

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Code Assistant LLMs के जोखिम: Harmful Content, Misuse और Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: नए AI Attack में उपयोग किए गए Stolen Cloud Credentials](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (stolen LLM access की reselling)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - on-premise low-privileged LLM server की deployment का Deep-dive](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: Software Supply Chain Vector के रूप में AI-Hallucinated Domains](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI Hallucinations एक नई Supply Chain Attacks class को कैसे बढ़ावा दे रही हैं](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
