# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP ने machine learning की उन शीर्ष 10 vulnerabilities की पहचान की है जो AI systems को प्रभावित कर सकती हैं। इन vulnerabilities से data poisoning, model inversion और adversarial attacks सहित कई तरह की security समस्याएँ पैदा हो सकती हैं। सुरक्षित AI systems बनाने के लिए इन vulnerabilities को समझना बेहद ज़रूरी है।

Machine learning की शीर्ष 10 vulnerabilities की अद्यतन और विस्तृत सूची के लिए [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project देखें।<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: हमलावर **आने वाले data** में छोटे, अक्सर अदृश्य बदलाव करता है, ताकि model गलत निर्णय ले।\
    *उदाहरण*: Stop sign पर paint के कुछ छींटे self-driving car को उसे speed-limit sign "देखने" के लिए धोखा दे सकते हैं।

- **Data Poisoning Attack**: **Training set** को जान-बूझकर दूषित samples से भर दिया जाता है, जिससे model हानिकारक नियम सीखता है।\
*उदाहरण*: Antivirus training corpus में malware binaries को गलत तरीके से "benign" लेबल किया जाता है, जिससे बाद में उनसे मिलते-जुलते malware बच निकलते हैं।

- **Model Inversion Attack**: Outputs की जाँच करके हमलावर एक **reverse model** बनाता है, जो मूल inputs की संवेदनशील विशेषताओं को फिर से तैयार करता है।\
*उदाहरण*: Cancer-detection model की predictions से किसी मरीज़ की MRI image फिर से बनाना।

- **Membership Inference Attack**: Adversary confidence में अंतर देखकर जाँचता है कि training के दौरान **किसी खास record** का इस्तेमाल हुआ था या नहीं।\
*उदाहरण*: पुष्टि करना कि किसी व्यक्ति का bank transaction fraud-detection model के training data में मौजूद है।

- **Model Theft**: बार-बार query करके हमलावर decision boundaries सीखता है और **model के व्यवहार (और IP) की नकल** करता है।\
*उदाहरण*: ML-as-a-Service API से पर्याप्त Q&A pairs इकट्ठा करके लगभग समान local model बनाना।

- **AI Supply‑Chain Attack**: **ML pipeline** के किसी भी component (data, libraries, pre-trained weights, CI/CD) से छेड़छाड़ करके downstream models को दूषित करना।\
*उदाहरण*: Model-hub पर मौजूद poisoned dependency कई apps में backdoored sentiment-analysis model install कर देती है।

- **Transfer Learning Attack**: **Pre-trained model** में malicious logic डाल दी जाती है, जो victim के task पर fine-tuning के बाद भी बनी रहती है।\
*उदाहरण*: Hidden trigger वाला vision backbone, medical imaging के लिए adapt किए जाने के बाद भी labels बदल देता है।

- **Model Skewing**: सूक्ष्म रूप से biased या गलत लेबल वाला data **model के outputs को बदल देता है**, ताकि वे हमलावर के उद्देश्य के पक्ष में हों।\
*उदाहरण*: "Clean" spam emails को ham लेबल करके inject करना, ताकि spam filter भविष्य में उनसे मिलते-जुलते emails को जाने दे।

- **Output Integrity Attack**: हमलावर model को नहीं, बल्कि **रास्ते में model की predictions को बदलता है**, जिससे downstream systems धोखा खा जाते हैं।\
*उदाहरण*: File-quarantine stage तक verdict पहुँचने से पहले malware classifier के "malicious" नतीजे को "benign" में बदल देना।

- **Model Poisoning** --- अक्सर write access हासिल करने के बाद, व्यवहार बदलने के लिए सीधे **model parameters** में लक्षित बदलाव करना।\
*उदाहरण*: Production में fraud-detection model के weights बदलना, ताकि कुछ खास cards के transactions हमेशा approve हों।


## Google SAIF Risks

Google का [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) AI systems से जुड़े कई risks का विवरण देता है:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Malicious actors training/tuning data को बदलते या उसमें data जोड़ते हैं, जिससे accuracy घटती है, backdoors डाले जाते हैं या नतीजों को पक्षपाती बनाया जाता है। इससे पूरे data lifecycle में model integrity कमज़ोर होती है। 

- **Unauthorized Training Data**: Copyright-सुरक्षित, संवेदनशील या बिना अनुमति वाले datasets को शामिल करने से कानूनी, नैतिक और performance संबंधी जोखिम पैदा होते हैं, क्योंकि model ऐसे data से सीखता है जिसका इस्तेमाल करने की उसे अनुमति नहीं थी। 

- **Model Source Tampering**: Training से पहले या उसके दौरान model code, dependencies या weights से supply-chain या insider के ज़रिए छेड़छाड़ करने पर hidden logic शामिल हो सकती है, जो retraining के बाद भी बनी रहती है। 

- **Excessive Data Handling**: Data-retention और governance controls कमज़ोर होने से systems ज़रूरत से ज़्यादा personal data store या process करते हैं, जिससे exposure और compliance risk बढ़ता है। 

- **Model Exfiltration**: हमलावर model files/weights चुरा लेते हैं, जिससे intellectual property का नुकसान होता है और नकल करने वाली services या आगे के attacks संभव होते हैं। 

- **Model Deployment Tampering**: Adversaries model artifacts या serving infrastructure में बदलाव करते हैं, जिससे चल रहा model जाँचे-परखे version से अलग हो जाता है और उसका व्यवहार बदल सकता है। 

- **Denial of ML Service**: APIs पर बाढ़ की तरह requests भेजने या “sponge” inputs देने से compute/energy खत्म हो सकती है और model offline हो सकता है—यह पारंपरिक DoS attacks जैसा है। 

- **Model Reverse Engineering**: बड़ी संख्या में input-output pairs इकट्ठा करके हमलावर model की नकल या distillation कर सकते हैं, जिससे नकल वाले products और विशेष रूप से बनाए गए adversarial attacks को बढ़ावा मिलता है। 

- **Insecure Integrated Component**: Vulnerable plugins, agents या upstream services हमलावरों को AI pipeline में code inject करने या privileges बढ़ाने का मौका देते हैं। 

- **Prompt Injection**: सीधे या परोक्ष रूप से ऐसे prompts बनाना जो system के इरादे को नज़रअंदाज़ कराने वाले निर्देश छिपाकर भेजें, जिससे model अनचाहे commands चलाए। 

- **Model Evasion**: सावधानी से बनाए गए inputs model से गलत classification, hallucination या प्रतिबंधित content output करवा सकते हैं, जिससे सुरक्षा और भरोसा कमज़ोर होता है। 

- **Sensitive Data Disclosure**: Model अपने training data या user context से निजी या गोपनीय जानकारी उजागर करता है, जिससे privacy और नियमों का उल्लंघन होता है। 

- **Inferred Sensitive Data**: Model उन personal attributes का अनुमान लगाता है जो कभी दिए ही नहीं गए थे, जिससे अनुमान के ज़रिए privacy को नया नुकसान पहुँचता है। 

- **Insecure Model Output**: बिना sanitize किए गए responses से harmful code, गलत जानकारी या अनुचित content users या downstream systems तक पहुँच सकता है। 

- **Rogue Actions**: अपने-आप काम करने वाले agents पर्याप्त user oversight के बिना अनचाहे वास्तविक operations (file writes, API calls, purchases आदि) कर देते हैं।

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI systems से जुड़े risks को समझने और कम करने के लिए एक व्यापक framework देता है। यह उन अलग-अलग attack techniques और tactics को वर्गीकृत करता है जिनका इस्तेमाल adversaries AI models के विरुद्ध कर सकते हैं, और यह भी बताता है कि अलग-अलग attacks करने के लिए AI systems का इस्तेमाल कैसे किया जा सकता है।<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

हमलावर active session tokens या cloud API credentials चुराकर बिना अनुमति के paid, cloud-hosted LLMs का इस्तेमाल करते हैं। अक्सर access को ऐसे reverse proxies के ज़रिए दोबारा बेचा जाता है जो victim के account के आगे काम करते हैं, जैसे "oai-reverse-proxy" deployments। इसके नतीजों में वित्तीय नुकसान, policy के विरुद्ध model का इस्तेमाल और victim tenant पर दोष आना शामिल है।<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- संक्रमित developer machines या browsers से tokens इकट्ठा करना; CI/CD secrets चुराना; leak हुई cookies खरीदना।<sup>[[5]](#references)</sup>
- ऐसा reverse proxy स्थापित करना जो requests को असली provider तक भेजे, upstream key को छिपाए और कई customers को एक साथ सेवा दे।<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Enterprise guardrails और rate limits को bypass करने के लिए direct base-model endpoints का दुरुपयोग करना।<sup>[[4]](#references)</sup>

Mitigations:
- Tokens को device fingerprint, IP ranges और client attestation से बाँधें; उनकी कम expiration अवधि तय करें और MFA से refresh करें।
- Keys को न्यूनतम scope दें (कोई tool access नहीं; जहाँ लागू हो, केवल read-only); anomaly मिलने पर rotate करें।
- सभी traffic को policy gateway के पीछे server-side पर terminate करें, जहाँ safety filters, हर route के quotas और tenant isolation लागू हों।
- असामान्य usage patterns (खर्च में अचानक बढ़ोतरी, असामान्य regions, UA strings) पर नज़र रखें और संदिग्ध sessions को अपने-आप revoke करें।
- लंबे समय तक चलने वाली static API keys के बजाय mTLS या आपके IdP द्वारा जारी signed JWTs को प्राथमिकता दें।

## Self-hosted LLM inference hardening

गोपनीय data के लिए local LLM server चलाने से cloud-hosted APIs से अलग attack surface बनता है: inference/debug endpoints prompts को leak कर सकते हैं, serving stack आम तौर पर reverse proxy दिखाता है और GPU device nodes से बड़े `ioctl()` surfaces तक पहुँच मिलती है। यदि आप on-prem inference service का आकलन या deployment कर रहे हैं, तो कम-से-कम इन बिंदुओं की समीक्षा करें।<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

Inference API को **कई users वाली संवेदनशील service** मानें। Debug या monitoring routes prompt contents, slot state, model metadata या आंतरिक queue की जानकारी उजागर कर सकते हैं। `llama.cpp` में `/slots` endpoint विशेष रूप से संवेदनशील है, क्योंकि यह हर slot की state दिखाता है और इसका इस्तेमाल केवल slot की जाँच/management के लिए होना चाहिए।<sup>[[8]](#references)</sup>

- Inference server के आगे reverse proxy रखें और **डिफ़ॉल्ट रूप से access अस्वीकार करें**।
- केवल उन सटीक HTTP method + path combinations को allowlist करें जिनकी client/UI को ज़रूरत है।
- जब भी संभव हो, backend में introspection endpoints बंद करें; उदाहरण के लिए `llama-server --no-slots`।<sup>[[9]](#references)</sup>
- Reverse proxy को `127.0.0.1` से bind करें और LAN पर प्रकाशित करने के बजाय SSH local port forwarding जैसे authenticated transport के ज़रिए उपलब्ध कराएँ।

nginx के साथ allowlist का उदाहरण:

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

यदि inference daemon UNIX socket पर सुनने का समर्थन करता है, तो TCP के बजाय उसे प्राथमिकता दें और container को **बिना network stack** के चलाएँ:<sup>[[8]](#references)</sup>

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
- `--network none` inbound/outbound TCP/IP exposure हटाता है और उन user-mode helpers की ज़रूरत से बचाता है जिनकी rootless containers को अन्यथा आवश्यकता होती।
- UNIX socket से आप socket path पर POSIX permissions/ACLs को पहली access-control layer के रूप में इस्तेमाल कर सकते हैं।
- `--userns=keep-id` और rootless Podman container breakout के प्रभाव को कम करते हैं, क्योंकि container root, host root नहीं होता।
- Read-only model mounts से container के भीतर से model tampering की संभावना कम होती है।

स्थायी deployments के लिए, इन्हीं restrictions को Podman Quadlet units के रूप में व्यक्त किया जा सकता है। यदि GPU access को Container Device Interface के ज़रिए delegate किया जाता है, तो हर accelerator node expose करने के बजाय CDI device specification को यथासंभव सीमित रखें।<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node को न्यूनतम करना

GPU-backed inference के लिए, `/dev/nvidia*` files उच्च-मूल्य वाले local attack surfaces हैं, क्योंकि वे बड़े driver `ioctl()` handlers और संभावित रूप से shared GPU memory-management paths को expose करते हैं।<sup>[[8]](#references)</sup>

- `/dev/nvidia*` को world writable न छोड़ें।
- `nvidia`, `nvidiactl`, और `nvidia-uvm` को `NVreg_DeviceFileUID/GID/Mode`, udev rules, और ACLs के ज़रिए सीमित करें, ताकि केवल mapped container UID ही उन्हें खोल सके।
- Headless inference hosts पर `nvidia_drm`, `nvidia_modeset`, और `nvidia_peermem` जैसे अनावश्यक modules को blacklist करें।
- Inference startup के दौरान runtime को opportunistically `modprobe` करने देने के बजाय, boot के समय केवल आवश्यक modules preload करें।

उदाहरण:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

एक महत्वपूर्ण समीक्षा बिंदु **`/dev/nvidia-uvm`** है। भले ही workload स्पष्ट रूप से `cudaMallocManaged()` का उपयोग न करता हो, हाल के CUDA runtimes को फिर भी `nvidia-uvm` की आवश्यकता हो सकती है। चूँकि यह device साझा होता है और GPU virtual memory management संभालता है, इसे tenants के बीच data exposure का एक संभावित माध्यम मानें। यदि inference backend इसका समर्थन करता है, तो Vulkan backend एक दिलचस्प विकल्प हो सकता है, क्योंकि इससे container को `nvidia-uvm` दिखाने की आवश्यकता पूरी तरह टल सकती है।<sup>[[8]](#references)</sup>

### Inference workers के लिए LSM confinement

Inference process के चारों ओर defense in depth के रूप में AppArmor/SELinux/seccomp का उपयोग किया जाना चाहिए:<sup>[[8]](#references)</sup>

- केवल उन्हीं shared libraries, model paths, socket directory और GPU device nodes को अनुमति दें जिनकी वास्तव में आवश्यकता है।
- `sys_admin`, `sys_module`, `sys_rawio` और `sys_ptrace` जैसी उच्च-जोखिम वाली capabilities को स्पष्ट रूप से अस्वीकार करें।
- Model directory को read-only रखें और writable paths को केवल runtime socket/cache directories तक सीमित रखें।
- Denial logs की निगरानी करें, क्योंकि जब model server या post-exploitation payload अपने अपेक्षित व्यवहार से बाहर निकलने की कोशिश करता है, तो ये उपयोगी detection telemetry देते हैं।

GPU-backed worker के लिए AppArmor rules का उदाहरण:

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

## Phantom Squatting: LLM द्वारा भ्रमित होकर बनाए गए डोमेन, AI सप्लाई-चेन के एक वेक्टर के रूप में

Phantom squatting, **slopsquatting के domain/URL समकक्ष** है। किसी ऐसे package name की कल्पना करने के बजाय जो मौजूद ही नहीं है, LLM किसी वास्तविक brand के लिए एक विश्वसनीय लगने वाले **portal, API, webhook, billing, SSO, download या support domain** की कल्पना करता है, और कोई attacker उस namespace को किसी व्यक्ति या agent द्वारा उपयोग किए जाने से पहले register कर लेता है।<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

यह महत्वपूर्ण है क्योंकि AI-सहायता वाले कई workflows में model के output को **विश्वसनीय dependency** माना जाता है:
- Developers सुझाए गए endpoint को code या CI/CD integrations में paste कर देते हैं।
- AI agents documentation, schemas, APKs, ZIPs या webhook targets को अपने आप fetch करते हैं।
- बनाए गए runbooks या docs में fake URL को आधिकारिक URL की तरह शामिल किया जा सकता है।

### Offensive workflow

1. **भ्रम की संभावना वाले हिस्सों की जाँच करें**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` या `mobile app` portals जैसे वास्तविक workflows के बारे में brand-विशिष्ट सवाल पूछें।<sup>[[12]](#references)</sup>
2. **उम्मीदवारों को सामान्यीकृत करें**: बनाए गए URLs को resolve करें, NXDOMAIN responses को parent registerable domain तक सीमित करें, और prompt families में duplicate हटाएँ। Prompt corpora विविध रहने चाहिए; उदाहरण के लिए, **Jaccard similarity** का उपयोग करके लगभग समान prompts हटाएँ।
3. **पूर्वानुमानित भ्रमों को प्राथमिकता दें**:
   - **Thermal Hallucination Persistence (THP)**: वही fake domain अलग-अलग temperatures पर दिखाई दे, जिनमें `T=0.1` जैसी कम temperature भी शामिल हो।
   - **Cross-model consensus**: कई LLM families एक ही fake domain बनाएँ।
4. Parent domain को **register करके हथियारबंद करें**, फिर उस पर phishing, fake APK/ZIP downloads, credential harvesters, malicious docs या secrets/webhook payloads इकट्ठा करने वाले API endpoints host करें। **केवल domain-स्तर के भ्रमों** से कमाई करना सबसे आसान है, क्योंकि attacker के पास पूरा namespace होता है; subdomain/path के भ्रमों का भी दुरुपयोग किया जा सकता है, यदि normalized parent अभी register न हुआ हो।
5. **शून्य-प्रतिष्ठा वाली अवधि का फायदा उठाएँ**: नए registered domains में अक्सर blocklist history, URL reputation और पर्याप्त telemetry नहीं होती, इसलिए detections के सक्रिय होने तक वे controls को bypass कर सकते हैं। Attackers crawler-only benign responses, redirect cloaking, CAPTCHA gates या देर से payload staging के जरिए इस अवधि को बढ़ा सकते हैं।

### Agents के लिए यह खतरनाक क्यों है

किसी इंसानी शिकार के मामले में fake domain को आम तौर पर अब भी click और एक अन्य कार्रवाई की ज़रूरत होती है। **Agentic workflow** में LLM, **lure** और **executor**, दोनों हो सकता है: agent को hallucinated URL मिलता है, वह उसे fetch करता है, response को parse करता है, और फिर बिना किसी इंसानी समीक्षा के tokens leak कर सकता है, instructions execute कर सकता है, dependency download कर सकता है या CI/CD में poisoned data push कर सकता है।<sup>[[12]](#references)</sup>

### हमलावरों के लिए व्यावहारिक prompts

ज़्यादा प्रभावी prompts अक्सर स्पष्ट phishing lures के बजाय सामान्य enterprise tasks जैसे लगते हैं:<sup>[[12]](#references)</sup>
- “`<brand>` integrations के लिए payment sandbox URL क्या है?”
- “`<brand>` build notifications के लिए मुझे कौन-सा webhook endpoint इस्तेमाल करना चाहिए?”
- “`<brand>` के employee benefits / billing / SSO portal कहाँ हैं?”
- “`<brand>` के लिए direct Android APK या desktop client download दें।”

### Defensive inversion

इसे केवल prompt-injection की समस्या न मानकर proactive domain-monitoring की समस्या मानें:<sup>[[12]](#references)</sup>
- **Brand prompt corpus** बनाएँ और समय-समय पर उन LLMs की जाँच करें जिन पर आपके users/agents निर्भर हैं।
- Hallucinated URLs को store करें और track करें कि कौन-से URLs अलग-अलग temperatures/models पर स्थिर रहते हैं।
- **Adversarial Exploitation Window (AEW)** को track करें: पहली hallucination और attacker द्वारा registration के बीच का समय। Positive AEW का अर्थ है कि defenders, weaponization से पहले pre-register, sinkhole या pre-block कर सकते हैं।
- Parent domains के **NXDOMAIN → registered** transitions को monitor करें।
- Registration होने पर registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status और brand-asset similarity की जाँच करें।
- ऐसी policy gates जोड़ें जिनसे agents/developers **LLM द्वारा बनाए गए domains पर default रूप से भरोसा न करें**: पहली बार उपयोग करने से पहले allowlists, ownership validation, CT/RDAP checks या human approval अनिवार्य करें।

यह एक साथ कई AI risk categories में आता है: **AI supply-chain attack**, **insecure model output**, और जब agents hallucinated URL का स्वायत्त रूप से उपयोग करते हैं, तब **rogue actions**।

## References

- [1] [OWASP Machine Learning की शीर्ष 10 कमजोरियाँ](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – जोखिम](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Code Assistant LLMs के जोखिम: हानिकारक सामग्री, दुरुपयोग और धोखा](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: नए AI हमले में इस्तेमाल किए गए चुराए गए Cloud Credentials](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking योजना का परिचय – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (चुराई गई LLM access को दोबारा बेचना)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - ऑन-प्रिमाइज़ कम-विशेषाधिकार वाले LLM server की deployment का गहन विश्लेषण](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI द्वारा भ्रमित होकर बनाए गए domains, software supply chain के एक vector के रूप में](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI की hallucinations कैसे supply chain attacks के एक नए वर्ग को बढ़ावा दे रही हैं](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
