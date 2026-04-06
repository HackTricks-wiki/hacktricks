# AI जोखिम

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ने उन शीर्ष 10 machine learning कमजोरियों की पहचान की है जो AI सिस्टम को प्रभावित कर सकती हैं। ये कमजोरियां data poisoning, model inversion, और adversarial attacks जैसे कई सुरक्षा मुद्दों का कारण बन सकती हैं। सुरक्षित AI सिस्टम बनाने के लिए इन कमजोरियों को समझना आवश्यक है।

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: एक attacker छोटे, अक्सर अदृश्य बदलाव **incoming data** में जोड़ता है ताकि मॉडल गलत निर्णय ले।\
*उदाहरण*: स्टॉप‑साइन पर कुछ रंग के धब्बे एक self‑driving कार को "speed‑limit sign" देखने के लिए धोखा दे सकते हैं।

- **Data Poisoning Attack**: **training set** जानबूझकर खराब नमूनों से प्रदूषित किया जाता है, जिससे मॉडल हानिकारक नियम सीख लेता है।\
*उदाहरण*: एक antivirus training corpus में malware बाइनरीज़ को गलत तरीके से "benign" के रूप में लेबल करना ताकि बाद में समान malware बच निकल सके।

- **Model Inversion Attack**: outputs की पैठ करके, attacker एक **reverse model** बनाता है जो मूल inputs की संवेदनशील विशेषताओं को reconstruct कर सकता है।\
*उदाहरण*: cancer‑detection मॉडल की predictions से किसी मरीज की MRI इमेज को फिर से बनाना।

- **Membership Inference Attack**: adversary यह जाँचता है कि क्या कोई **specific record** training में इस्तेमाल हुई थी, confidence के अंतर देखकर।\
*उदाहरण*: यह पुष्टि करना कि किसी व्यक्ति का बैंक ट्रांजैक्शन fraud‑detection मॉडल के training data में मौजूद है।

- **Model Theft**: बार‑बार प्रश्न करके attacker decision boundaries सीखकर **clone the model's behavior** कर लेता है (और IP चुरा लेता है)।\
*उदाहरण*: ML‑as‑a‑Service API से पर्याप्त Q&A जोड़े निकाल कर लगभग समान local मॉडल बनाना।

- **AI Supply‑Chain Attack**: ML pipeline के किसी भी component (data, libraries, pre‑trained weights, CI/CD) को compromise करके downstream models को भ्रष्ट किया जा सकता है।\
*उदाहरण*: model‑hub में एक poisoned dependency एक backdoored sentiment‑analysis मॉडल इंस्टॉल कर देती है जो कई ऐप्स में फैल जाता है।

- **Transfer Learning Attack**: एक **pre‑trained model** में malicious logic घोंप दी जाती है और victim के task पर fine‑tuning के बाद भी जीवित रहती है।\
*उदाहरण*: एक vision backbone जिसमें hidden trigger हो, medical imaging के लिए adapt करने पर भी labels flip कर देता है।

- **Model Skewing**: धीरे‑धीरे biased या mislabeled data मॉडल के आउटपुट को attacker के एजेंडा के पक्ष में **shifts the model's outputs** कर देता है।\
*उदाहरण*: "clean" spam emails को ham के रूप में लेबल कराकर spam filter को आगे समान ईमेल्स पास करने देना।

- **Output Integrity Attack**: attacker मॉडल को नहीं बल्कि **alters model predictions in transit** करता है, जिससे downstream सिस्टम धोखा खा जाते हैं।\
*उदाहरण*: एक malware classifier के "malicious" फैसले को "benign" में बदल दिया जाता है इससे पहले कि file‑quarantine चरण उसे देखे।

- **Model Poisoning** --- सीधे, लक्षित परिवर्तन **model parameters** में किए जाते हैं, अक्सर write access हासिल करने के बाद, ताकि व्यवहार बदल सके।\
*उदाहरण*: production में fraud‑detection मॉडल के weights को tweak कर देना ताकि कुछ कार्डों की ट्रांज़ैक्शन हमेशा approve हो जाएँ।


## Google SAIF Risks

Google का [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) AI सिस्टम से जुड़े विभिन्न जोखिमों का विवरण देता है:

- **Data Poisoning**: malicious actors training/tuning data को बदलते या inject करते हैं ताकि accuracy घटे, backdoors implant हों, या परिणाम skew हो जाएँ, जिससे पूरे data‑lifecycle में model की सत्यनिष्ठा प्रभावित होती है।

- **Unauthorized Training Data**: copyrighted, sensitive, या unpermitted datasets ingest करने से कानूनी, नैतिक और प्रदर्शन संबंधी जिम्मेदारियाँ बनती हैं क्योंकि मॉडल ऐसे डेटा से सीखता है जिसे उपयोग करने की अनुमति नहीं थी।

- **Model Source Tampering**: supply‑chain या insider manipulation से model code, dependencies, या weights को training से पहले या दौरान बदल कर छिपा logic embed किया जा सकता है जो retraining के बाद भी बना रहता है।

- **Excessive Data Handling**: कमजोर data‑retention और governance controls सिस्टम को आवश्यक से अधिक personal data संग्रहीत या process करने देते हैं, जिससे exposure और compliance जोखिम बढ़ता है।

- **Model Exfiltration**: attackers model files/weights चुरा लेते हैं, जिससे intellectual property का नुकसान होता है और copy‑cat सेवाएँ या follow‑on attacks संभव हो जाते हैं।

- **Model Deployment Tampering**: adversaries model artifacts या serving infrastructure को modify करते हैं ताकि running model vetted version से भिन्न हो, संभावित रूप से व्यवहार बदल जाए।

- **Denial of ML Service**: APIs पर flood करना या “sponge” inputs भेजना compute/energy को खत्म कर सकता है और मॉडल को offline कर सकता है, क्लासिक DoS attacks की तरह।

- **Model Reverse Engineering**: बहुत सारे input‑output जोड़ों को harvest कर attackers मॉडल को clone या distil कर सकते हैं, जिससे imitation products और customized adversarial attacks को पोषण मिलता है।

- **Insecure Integrated Component**: कमजोर plugins, agents, या upstream services attackers को code inject करने या AI pipeline में privileges escalate करने की अनुमति दे सकते हैं।

- **Prompt Injection**: prompts (सीधे या परोक्ष रूप से) ऐसी instructions smuggle करने के लिए तैयार की जाती हैं जो system intent को override कर देती हैं, और मॉडल को unintended commands करवा देती हैं।

- **Model Evasion**: सावधानीपूर्वक डिज़ाइन किए हुए inputs मॉडल को mis‑classify, hallucinate, या disallowed content आउटपुट करने पर मजबूर करते हैं, जिससे safety और trust कमजोर होते हैं।

- **Sensitive Data Disclosure**: मॉडल अपने training data या user context से निजी या confidential जानकारी उजागर कर देता है, जिससे privacy और नियमों का उल्लंघन होता है।

- **Inferred Sensitive Data**: मॉडल उन व्यक्तिगत गुणों का अनुमान लगा लेता है जो कभी प्रदान नहीं किए गए थे, जिससे inference के माध्यम से नई privacy हानियाँ बनती हैं।

- **Insecure Model Output**: बिना sanitize किए गए responses उपयोगकर्ताओं या downstream systems को हानिकारक कोड, misinformation, या अनुचित सामग्री पास कर देते हैं।

- **Rogue Actions**: autonomously‑integrated agents बिना पर्याप्त user oversight के unintended real‑world operations (file writes, API calls, purchases, आदि) execute कर लेते हैं।

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI सिस्टम से जुड़े जोखिमों को समझने और कम करने के लिए एक व्यापक फ्रेमवर्क प्रदान करती है। यह उन attack techniques और tactics को वर्गीकृत करती है जो adversaries AI models के खिलाफ उपयोग कर सकते हैं और साथ ही यह बताती है कि AI सिस्टम का उपयोग विभिन्न attacks को अंजाम देने के लिए कैसे किया जा सकता है।


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers active session tokens या cloud API credentials चुरा लेते हैं और बिना authorization के paid, cloud‑hosted LLMs invoke करते हैं। Access अक्सर reverse proxies के माध्यम से resale किया जाता है जो victim के account को front करते हैं, जैसे "oai-reverse-proxy" deployments। परिणामों में वित्तीय नुकसान, नीति के बाहर model misuse, और victim tenant के खिलाफ attribution शामिल हैं।

TTPs:
- संक्रमित developer machines या browsers से tokens harvest करना; CI/CD secrets चुराना; leaked cookies खरीदना।
- एक reverse proxy खड़ा करना जो requests को genuine provider पर forward करे, upstream key को छुपाते हुए और कई ग्राहकों को multiplex करते हुए।
- enterprise guardrails और rate limits bypass करने के लिए direct base‑model endpoints का दुरुपयोग।

Mitigations:
- tokens को device fingerprint, IP ranges, और client attestation से bind करें; short expirations लागू करें और MFA के साथ refresh करवाएँ।
- keys को न्यूनतम scope दें (कोई tool access न दें, जहां लागू हो वहां read‑only रखें); anomaly पर rotate करें।
- policy gateway के पीछे server‑side सभी ट्रैफ़िक terminate करें जो safety filters, per‑route quotas, और tenant isolation लागू करे।
- unusual usage patterns (अचानक खर्च में spike, atypical regions, UA strings) के लिए monitor करें और suspicious sessions को auto‑revoke करें।
- long‑lived static API keys की बजाय अपने IdP द्वारा जारी mTLS या signed JWTs को प्राथमिकता दें।

## Self-hosted LLM inference hardening

Confidential data के लिए local LLM server चलाना cloud‑hosted APIs से अलग attack surface बनाता है: inference/debug endpoints prompts को leak कर सकते हैं, serving stack आम तौर पर एक reverse proxy expose करता है, और GPU device nodes बड़े `ioctl()` surfaces तक पहुँच देते हैं। यदि आप on‑prem inference service का आकलन या तैनाती कर रहे हैं, तो कम से कम निम्न बिंदुओं की समीक्षा करें।

### Prompt leakage via debug and monitoring endpoints

Inference API को एक **multi-user sensitive service** की तरह मानें। Debug या monitoring routes prompt contents, slot state, model metadata, या internal queue जानकारी expose कर सकते हैं। `llama.cpp` में, `/slots` endpoint विशेष रूप से संवेदनशील है क्योंकि यह per‑slot state दिखाता है और केवल slot inspection/management के लिए ही होना चाहिए।

- inference server के सामने एक reverse proxy रखें और **deny by default** लागू करें।
- केवल उन्हीं HTTP method + path combinations को allowlist करें जिनकी client/UI को वास्तव में आवश्यकता है।
- backend में जितना संभव हो introspection endpoints को disable करें, उदाहरण के लिए `llama-server --no-slots`।
- reverse proxy को `127.0.0.1` से bind करें और LAN पर publish करने के बजाय इसे SSH local port forwarding जैसे authenticated transport के माध्यम से expose करें।

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
### Rootless containers जिनमें no network और UNIX sockets हों

यदि inference daemon UNIX socket पर listen करना सपोर्ट करता है, तो TCP की बजाय इसे प्राथमिकता दें और container को **no network stack** के साथ चलाएँ:
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
Benefits:
- `--network none` इनबाउंड/आउटबाउंड TCP/IP एक्सपोज़र को हटाता है और उन user-mode helpers की आवश्यकता से बचाता है जिनकी rootless containers को अन्यथा जरूरत होती।
- A UNIX socket आपको socket path पर POSIX permissions/ACLs इस्तेमाल करने देता है, जो पहले access-control layer के रूप में काम करता है।
- `--userns=keep-id` और rootless Podman container breakout के प्रभाव को कम करते हैं क्योंकि container root, host root नहीं होता।
- Read-only model mounts कंटेनर के अंदर से model tampering की संभावना को कम करते हैं।

### GPU device-node minimization

For GPU-backed inference, `/dev/nvidia*` files उच्च-मूल्य वाली स्थानीय attack surfaces होती हैं क्योंकि वे बड़े driver `ioctl()` handlers और संभावित रूप से साझा GPU memory-management paths को एक्सपोज़ करती हैं।

- Do not leave `/dev/nvidia*` world writable.
- Restrict `nvidia`, `nvidiactl`, and `nvidia-uvm` with `NVreg_DeviceFileUID/GID/Mode`, udev rules, and ACLs so only the mapped container UID can open them.
- Blacklist unnecessary modules such as `nvidia_drm`, `nvidia_modeset`, and `nvidia_peermem` on headless inference hosts.
- Preload only required modules at boot instead of letting the runtime opportunistically `modprobe` them during inference startup.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**। Even if the workload does not explicitly use `cudaMallocManaged()`, recent CUDA runtimes may still require `nvidia-uvm`. Because this device is shared and handles GPU virtual memory management, treat it as a cross-tenant data-exposure surface. If the inference backend supports it, a Vulkan backend can be an interesting trade-off because it may avoid exposing `nvidia-uvm` to the container at all.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp should be used as defense in depth around the inference process:

- केवल उन्हीं shared libraries, model paths, socket directory, और GPU device nodes को allow करें जिनकी वाकई ज़रूरत है।
- स्पष्ट रूप से उच्च-जोखिम capabilities जैसे `sys_admin`, `sys_module`, `sys_rawio`, और `sys_ptrace` को deny करें।
- model directory को read-only रखें और writable paths को केवल runtime socket/cache directories तक सीमित रखें।
- denial logs की निगरानी करें क्योंकि जब model server या कोई post-exploitation payload अपनी अपेक्षित व्यवहार से बाहर निकलने की कोशिश करता है तो ये उपयोगी detection telemetry प्रदान करते हैं।

Example AppArmor rules for a GPU-backed worker:
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
## संदर्भ
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
