# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ने उन शीर्ष 10 मशीन लर्निंग कमजोरियों की पहचान की है जो AI प्रणालियों को प्रभावित कर सकती हैं। ये कमजोरियाँ डेटा poisoning, model inversion, और adversarial attacks सहित विभिन्न सुरक्षा समस्याओं का कारण बन सकती हैं। सुरक्षित AI सिस्टम बनाने के लिए इन कमजोरियों को समझना आवश्यक है।

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: एक आक्रमणकारी छोटे, अक्सर अदृश्य बदलाव **incoming data** में जोड़ता है ताकि मॉडल गलत निर्णय ले।\
*Example*: स्टॉप‑साइन पर कुछ रंग के धब्बे एक self‑driving कार को यह "देखने" के लिए बेवकूफ़ बना देते हैं कि वह speed‑limit sign है।

- **Data Poisoning Attack**: **training set** जानबूझकर खराब सैंपलों से दूषित किया जाता है, जिससे मॉडल हानिकारक नियम सीख लेता है।\
*Example*: Malware binaries को एक antivirus training corpus में "benign" के रूप में गलत लेबल कर देना, जिससे बाद में समान malware बच निकलता है।

- **Model Inversion Attack**: आउटपुट्स को probe करके, एक आक्रमणकारी एक उल्टा मॉडल बनाता है जो मूल इनपुट्स की संवेदनशील विशेषताओं का पुनर्निर्माण करता है।\
*Example*: कैंसर‑डिटेक्शन मॉडल की predictions से किसी रोगी की MRI इमेज को फिर से बनाना।

- **Membership Inference Attack**: विरोधी यह परीक्षण करता है कि क्या कोई **specific record** training के दौरान उपयोग किया गया था, confidence में अंतर देखकर।\
*Example*: यह पुष्टि करना कि किसी व्यक्ति का बैंक ट्रांज़ैक्शन fraud‑detection मॉडल के training data में मौजूद है।

- **Model Theft**: बार‑बार querying करके एक आक्रमणकारी decision boundaries सीख लेता है और **clone the model's behavior** (और IP) कर लेता है।\
*Example*: ML‑as‑a‑Service API से पर्याप्त Q&A जोड़े इकट्ठा करके एक निकट‑बराबर local मॉडल बनाना।

- **AI Supply‑Chain Attack**: ML pipeline के किसी भी घटक (data, libraries, pre‑trained weights, CI/CD) को compromise करके downstream मॉडल्स को corrupt किया जा सकता है।\
*Example*: model‑hub पर एक poisoned dependency एक backdoored sentiment‑analysis model इंस्टॉल कर देती है जो कई ऐप्स में फैल जाता है।

- **Transfer Learning Attack**: एक malicious logic को **pre‑trained model** में पनपाया जाता है जो victim के टास्क पर fine‑tuning के बाद भी जीवित रहता है।\
*Example*: एक vision backbone जिसमें छुपा हुआ trigger है, वह medical imaging के लिए अनुकूलित करने के बाद भी labels उलट देता है।

- **Model Skewing**: सूक्ष्म रूप से biased या mislabeled data मॉडल के आउटपुट्स को इस तरह बदल देती है कि वह आक्रमणकारी के एजेंडा को फायदा पहुँचाए।\
*Example*: "clean" spam ईमेल्स को ham के रूप में लेबल करके एक spam filter को इस तरह प्रशिक्षित करना कि भविष्य के समान ईमेल पास कर दिए जाएँ।

- **Output Integrity Attack**: आक्रमणकारी transit में मॉडल की predictions को बदल देता है, मॉडल को नहीं, जिससे downstream सिस्टम्स गुमराह होते हैं।\
*Example*: एक malware classifier का "malicious" verdict quarantine चरण तक पहुँचने से पहले "benign" में बदल देना।

- **Model Poisoning** --- सीधे, लक्षित बदलाव सीधे **model parameters** में करना, अक्सर write access हासिल करने के बाद, व्यवहार बदलने के लिए।\
*Example*: production में fraud‑detection मॉडल के weights को tweak कर देना ताकि कुछ कार्ड्स की ट्रांज़ैक्शंस हमेशा approve हो जाएँ।


## Google SAIF Risks

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) में AI प्रणालियों से जुचे विभिन्न जोखिमों का वर्णन है:

- **Data Poisoning**: malicious actors training/tuning data में बदलाव या injection करते हैं ताकि accuracy घटे, backdoors implant हों, या परिणाम skew हों, जिससे पूरे data‑lifecycle में model की अखंडता क्षतिग्रस्त होती है।

- **Unauthorized Training Data**: copyrighted, sensitive, या अनधिकृत datasets का ingest करना कानूनी, नैतिक और प्रदर्शन संबंधी liabilities उत्पन्न करता है क्योंकि मॉडल ऐसे डेटा से सीखता है जिसका उपयोग करने की अनुमति नहीं थी।

- **Model Source Tampering**: supply‑chain या insider द्वारा मॉडल कोड, dependencies, या weights को training से पहले या दौरान manipulate किया जा सकता है, जिससे hidden logic embed हो सकती है जो retraining के बाद भी बनी रहती है।

- **Excessive Data Handling**: कमजोर data‑retention और governance controls सिस्टम को आवश्यक से अधिक personal data संग्रहित या process करने के लिए प्रेरित करते हैं, जिससे exposure और compliance जोखिम बढ़ता है।

- **Model Exfiltration**: आक्रमणकारी मॉडल फाइल्स/weights चुरा लेते हैं, जिससे intellectual property का नुकसान होता है और copy‑cat सेवाएँ या आगे के आक्रमण संभव होते हैं।

- **Model Deployment Tampering**: विरोधी model artifacts या serving infrastructure में बदलाव करते हैं ताकि running model वैधित संस्करण से अलग हो, संभवतः व्यवहार बदल जाए।

- **Denial of ML Service**: APIs पर भीड़ कर देना या “sponge” inputs भेजना compute/energy को खपत कर सकता है और मॉडल को offline कर सकता है, जो क्लासिक DoS attacks जैसा है।

- **Model Reverse Engineering**: बड़े पैमाने पर input‑output pairs harvest करके आक्रमणकारी मॉडल को clone या distil कर सकते हैं, जिससे imitation products और customized adversarial attacks को बढ़ावा मिलता है।

- **Insecure Integrated Component**: vulnerable plugins, agents, या upstream services आक्रमणकारियों को कोड inject करने या AI pipeline के भीतर privileges escalate करने की अनुमति देते हैं।

- **Prompt Injection**: prompts (directly या indirectly) तैयार करके ऐसी instructions छिपाने की कोशिश करना जो सिस्टम intent को override कर दें और मॉडल से unintended commands करवा दें।

- **Model Evasion**: सावधानीपूर्वक डिज़ाइन किए गए इनपुट्स मॉडल को mis‑classify, hallucinate, या disallowed content आउटपुट करने पर मजबूर करते हैं, जिससे safety और trust कमज़ोर होता है।

- **Sensitive Data Disclosure**: मॉडल अपने training data या user context से private या confidential जानकारी उजागर कर देता है, जो privacy और regulations का उल्लंघन है।

- **Inferred Sensitive Data**: मॉडल उन personal attributes का अनुमान लगा लेता है जो कभी प्रदान नहीं किए गए थे, जिससे inference के माध्यम से नए privacy नुकसान उत्पन्न होते हैं।

- **Insecure Model Output**: unsanitized responses users या downstream systems को हानिकारक कोड, misinformation, या अनुचित कंटेंट भेजते हैं।

- **Rogue Actions**: autonomously‑integrated agents बिना उपयुक्त user oversight के unintended real‑world operations (file writes, API calls, purchases, आदि) निष्पादित कर देते हैं।

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI प्रणालियों से जुड़े जोखिमों को समझने और कम करने के लिए एक व्यापक ढाँचा प्रदान करती है। यह उन विभिन्न attack techniques और tactics को वर्गीकृत करती है जो adversaries AI मॉडल्स के खिलाफ उपयोग कर सकते हैं और साथ ही यह बताती है कि AI सिस्टम्स का उपयोग विभिन्न आक्रमणों के प्रदर्शन के लिए कैसे किया जा सकता है।

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers active session tokens या cloud API credentials चुरा लेते हैं और बिना प्राधिकरण के paid, cloud-hosted LLMs invoke करते हैं। Access अक्सर reverse proxies के माध्यम से पुनर्विक्रय किया जाता है जो victim’s account को front करते हैं, उदा. "oai-reverse-proxy" deployments। परिणामों में वित्तीय नुकसान, नीति के बाहर model misuse, और victim tenant के प्रति attribution शामिल हो सकते हैं।

TTPs:
- संक्रमित developer machines या browsers से tokens harvest करना; CI/CD secrets चुराना; leaked cookies खरीदना।
- एक reverse proxy खड़ा करना जो requests को genuine provider की ओर forward करे, upstream key छिपाए और कई ग्राहकों को multiplex करे।
- enterprise guardrails और rate limits को बायपास करने के लिए direct base‑model endpoints का दुरुपयोग करना।

Mitigations:
- tokens को device fingerprint, IP ranges, और client attestation के साथ bind करें; short expirations लागू करें और MFA के साथ refresh करें।
- keys को न्यूनतम scope दें (जहाँ लागू हो वहां no tool access, read‑only); anomaly पर rotate करें।
- policy gateway के पीछे server‑side पर सभी ट्रैफ़िक terminate करें जो safety filters, per‑route quotas, और tenant isolation लागू करता है।
- असामान्य usage patterns (अचानक खर्च में spike, atypical regions, UA strings) के लिए मॉनिटर करें और suspicious sessions को auto‑revoke करें।
- लंबे‑जीवित static API keys के बजाय mTLS या signed JWTs जो आपके IdP द्वारा जारी हों, को प्राथमिकता दें।

## Self-hosted LLM inference hardening

Confidential data के लिए local LLM server चलाने से cloud-hosted APIs से अलग attack surface बनता है: inference/debug endpoints prompts को leak कर सकते हैं, serving stack आम तौर पर एक reverse proxy expose करता है, और GPU device nodes बड़े `ioctl()` surfaces तक पहुँच प्रदान करते हैं। यदि आप किसी on‑prem inference service का आकलन या परिनियोजन कर रहे हैं, तो कम से कम निम्न बिंदुओं की समीक्षा करें।

### Prompt leakage via debug and monitoring endpoints

Treat the inference API as a **multi-user sensitive service**. Debug या monitoring routes prompt contents, slot state, model metadata, या internal queue जानकारी को expose कर सकते हैं। `llama.cpp` में, `/slots` endpoint विशेष रूप से संवेदनशील है क्योंकि यह per‑slot state को expose करता है और केवल slot inspection/management के लिए ही माना गया है।

- Put a reverse proxy in front of the inference server and **deny by default**.
- Only allowlist the exact HTTP method + path combinations that are needed by the client/UI.
- Disable introspection endpoints in the backend itself whenever possible, for example `llama-server --no-slots`.
- Bind the reverse proxy to `127.0.0.1` and expose it through an authenticated transport such as SSH local port forwarding instead of publishing it on the LAN.

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
### Rootless containers with no network and UNIX sockets

यदि inference daemon UNIX socket पर listening का समर्थन करता है, तो TCP के बजाय उसे प्राथमिकता दें और container को **no network stack** के साथ चलाएँ:
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
- `--network none` इनबाउंड/आउटबाउंड TCP/IP एक्सपोज़र को हटाता है और उन user-mode helpers से बचाता है जिनकी rootless containers को अन्यथा आवश्यकता होती है।
- एक UNIX socket आपको socket path पर POSIX permissions/ACLs का उपयोग करने की अनुमति देता है, जो पहला access-control स्तर बनता है।
- `--userns=keep-id` और rootless Podman container breakout के प्रभाव को कम करते हैं क्योंकि container root host root नहीं होता।
- Read-only model mounts container के अंदर से model छेड़छाड़ की संभावना को कम करते हैं।

### GPU device-node न्यूनतमकरण

GPU-backed inference के लिए, `/dev/nvidia*` फाइलें उच्च-मूल्य local attack surfaces होती हैं क्योंकि वे बड़े driver `ioctl()` handlers और संभावित रूप से shared GPU memory-management paths को एक्सपोज़ करती हैं।

- `/dev/nvidia*` को world writable न छोड़ें।
- `nvidia`, `nvidiactl`, और `nvidia-uvm` को `NVreg_DeviceFileUID/GID/Mode`, udev rules, और ACLs के साथ सीमित करें ताकि केवल mapped container UID ही इन्हें खोल सके।
- headless inference hosts पर अनावश्यक modules जैसे `nvidia_drm`, `nvidia_modeset`, और `nvidia_peermem` को blacklist करें।
- रनटाइम को inference startup के दौरान अवसरवादी रूप से `modprobe` करने देने के बजाय केवल आवश्यक modules को boot पर preload करें।

उदाहरण:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
एक महत्वपूर्ण समीक्षा बिंदु है **`/dev/nvidia-uvm`**। भले ही workload स्पष्ट रूप से `cudaMallocManaged()` का उपयोग न करे, हाल के CUDA runtimes फिर भी `nvidia-uvm` की आवश्यकता कर सकते हैं। क्योंकि यह device shared है और GPU virtual memory management को हैंडल करता है, इसे cross-tenant data-exposure surface के रूप में मानें। यदि inference backend इसे सपोर्ट करता है, तो एक Vulkan backend एक रोचक trade-off हो सकता है क्योंकि इससे `nvidia-uvm` को container को पूरी तरह एक्सपोज़ करने से बचाया जा सकता है।

### inference workers के लिए LSM confinement

AppArmor/SELinux/seccomp का उपयोग inference process के चारों ओर defense-in-depth के रूप में किया जाना चाहिए:

- केवल उन shared libraries, model paths, socket directory, और GPU device nodes की अनुमति दें जो वास्तव में आवश्यक हैं।
- स्पष्ट रूप से उच्च-जोखिम क्षमताओं जैसे `sys_admin`, `sys_module`, `sys_rawio`, और `sys_ptrace` को deny करें।
- model directory को read-only रखें और writable paths को केवल runtime socket/cache directories तक सीमित रखें।
- denial logs की निगरानी करें क्योंकि जब model server या कोई post-exploitation payload अपनी अपेक्षित व्यवहार से बाहर निकलने की कोशिश करता है तो वे उपयोगी detection telemetry प्रदान करते हैं।

GPU-backed worker के लिए AppArmor नियमों का उदाहरण:
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
