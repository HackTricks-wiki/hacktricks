# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ने machine learning की ऐसी शीर्ष 10 vulnerabilities की पहचान की है जो AI systems को प्रभावित कर सकती हैं। इन vulnerabilities से data poisoning, model inversion और adversarial attacks समेत कई सुरक्षा समस्याएँ हो सकती हैं। सुरक्षित AI systems बनाने के लिए इन vulnerabilities को समझना बेहद ज़रूरी है।

Machine learning की शीर्ष 10 vulnerabilities की अद्यतन और विस्तृत सूची के लिए [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project देखें।<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: हमलावर **आने वाले data** में छोटे, अक्सर न दिखने वाले बदलाव करता है, ताकि model गलत निर्णय ले।\
    *उदाहरण*: Stop-sign पर paint के कुछ छींटे self-driving car को उसे speed-limit sign के रूप में "देखने" के लिए धोखा देते हैं।

- **Data Poisoning Attack**: **training set** को जानबूझकर खराब samples से दूषित किया जाता है, जिससे model हानिकारक नियम सीखता है।\
*उदाहरण*: Antivirus training corpus में malware binaries को गलत तरीके से "benign" के रूप में label किया जाता है, जिससे बाद में उसी तरह का malware बच निकलता है।

- **Model Inversion Attack**: Outputs को probe करके, हमलावर एक **reverse model** बनाता है जो मूल inputs की संवेदनशील विशेषताओं को फिर से तैयार करता है।\
*उदाहरण*: Cancer-detection model की predictions से किसी मरीज़ की MRI image को फिर से बनाना।

- **Membership Inference Attack**: हमलावर confidence में अंतर देखकर जाँचता है कि training के दौरान **कोई खास record** इस्तेमाल किया गया था या नहीं।\
*उदाहरण*: पुष्टि करना कि किसी व्यक्ति का bank transaction fraud-detection model के training data में मौजूद है।

- **Model Theft**: बार-बार queries करने से हमलावर decision boundaries सीखता है और **model के व्यवहार (और IP) की नकल** करता है।\
*उदाहरण*: ML-as-a-Service API से पर्याप्त Q&A pairs इकट्ठा करके लगभग समान local model बनाना।

- **AI Supply‑Chain Attack**: **ML pipeline** के किसी भी component (data, libraries, pre-trained weights, CI/CD) से समझौता करके downstream models को दूषित करना।\
*उदाहरण*: Model-hub पर मौजूद poisoned dependency कई apps में backdoored sentiment-analysis model install कर देती है।

- **Transfer Learning Attack**: **pre-trained model** में malicious logic डाल दी जाती है, जो victim के task पर fine-tuning करने के बाद भी बनी रहती है।\
*उदाहरण*: छिपे हुए trigger वाला vision backbone, medical imaging के लिए adapt किए जाने के बाद भी labels बदल देता है।

- **Model Skewing**: बायस वाला या गलत label किया गया data चुपचाप **model के outputs को बदलता है**, ताकि वे हमलावर के मकसद के पक्ष में हों।\
*उदाहरण*: "clean" spam emails को ham के रूप में label करके डालना, ताकि spam filter भविष्य में उसी तरह के emails को जाने दे।

- **Output Integrity Attack**: हमलावर **model predictions को transit के दौरान बदलता है**, model को नहीं, जिससे downstream systems धोखे में आ जाते हैं।\
*उदाहरण*: File-quarantine stage तक पहुँचने से पहले malware classifier के "malicious" verdict को "benign" में बदलना।

- **Model Poisoning** --- अक्सर write access हासिल करने के बाद, व्यवहार बदलने के लिए सीधे **model parameters** में लक्षित बदलाव करना।\
*उदाहरण*: Production में fraud-detection model के weights बदलना, ताकि कुछ खास cards से किए गए transactions हमेशा approve हों।

## Google SAIF Risks

Google का [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) AI systems से जुड़े कई जोखिमों की रूपरेखा देता है:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Malicious actors training/tuning data को बदलते हैं या उसमें data डालते हैं, जिससे accuracy घटती है, backdoors जुड़ते हैं या results में पक्षपात आता है। इससे पूरे data-lifecycle में model integrity कमज़ोर होती है।

- **Unauthorized Training Data**: Copyrighted, sensitive या बिना अनुमति वाले datasets को शामिल करने से कानूनी, नैतिक और performance से जुड़े जोखिम पैदा होते हैं, क्योंकि model ऐसे data से सीखता है जिसे इस्तेमाल करने की उसे अनुमति नहीं थी।

- **Model Source Tampering**: Training से पहले या उसके दौरान model code, dependencies या weights में supply-chain या insider के ज़रिए छेड़छाड़ से ऐसा छिपा हुआ logic जुड़ सकता है जो retraining के बाद भी बना रहता है।

- **Excessive Data Handling**: Data retention और governance के कमज़ोर controls से systems ज़रूरत से ज़्यादा personal data store या process कर सकते हैं, जिससे जोखिम और compliance संबंधी खतरे बढ़ते हैं।

- **Model Exfiltration**: हमलावर model files/weights चुरा लेते हैं, जिससे intellectual property का नुकसान होता है और copy-cat services या आगे के attacks संभव हो जाते हैं।

- **Model Deployment Tampering**: हमलावर model artifacts या serving infrastructure में बदलाव करते हैं, जिससे चल रहा model जाँचे गए version से अलग हो जाता है और उसका व्यवहार बदल सकता है।

- **Denial of ML Service**: APIs पर requests की बाढ़ लाने या “sponge” inputs भेजने से compute/energy खत्म हो सकती है और model offline हो सकता है। यह पारंपरिक DoS attacks जैसा है।

- **Model Reverse Engineering**: बड़ी संख्या में input-output pairs इकट्ठा करके हमलावर model को clone या distil कर सकते हैं, जिससे नकल करने वाले products और अनुकूलित adversarial attacks को बढ़ावा मिलता है।

- **Insecure Integrated Component**: Vulnerable plugins, agents या upstream services से हमलावर AI pipeline में code डाल सकते हैं या अपने privileges बढ़ा सकते हैं।

- **Prompt Injection**: सीधे या परोक्ष रूप से ऐसे prompts बनाना जो instructions को छिपाकर system के इरादे को override करें और model से अनचाहे commands करवाएँ।

- **Model Evasion**: सावधानी से बनाए गए inputs model से गलत classification, hallucination या प्रतिबंधित content का output करवा सकते हैं, जिससे सुरक्षा और भरोसा कमज़ोर होता है।

- **Sensitive Data Disclosure**: Model अपने training data या user context से निजी या गोपनीय जानकारी उजागर करता है, जिससे privacy और regulations का उल्लंघन होता है।

- **Inferred Sensitive Data**: Model ऐसे personal attributes का अनुमान लगाता है जो कभी दिए ही नहीं गए थे, और इस inference से privacy को नया नुकसान पहुँचता है।

- **Insecure Model Output**: बिना sanitize किए गए responses से harmful code, misinformation या अनुचित content users या downstream systems तक पहुँच सकता है।

- **Rogue Actions**: Autonomously-integrated agents पर्याप्त user oversight के बिना अनचाहे वास्तविक कार्य (file writes, API calls, purchases आदि) करते हैं।

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI systems से जुड़े जोखिमों को समझने और कम करने के लिए एक व्यापक framework देता है। यह उन विभिन्न attack techniques और tactics को वर्गीकृत करता है जिनका adversaries AI models के विरुद्ध इस्तेमाल कर सकते हैं, और यह भी बताता है कि अलग-अलग attacks करने के लिए AI systems का इस्तेमाल कैसे किया जा सकता है।<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

हमलावर active session tokens या cloud API credentials चुराकर बिना अनुमति के paid, cloud-hosted LLMs का इस्तेमाल करते हैं। अक्सर victim के account के माध्यम से requests भेजने वाले reverse proxies के ज़रिए access को फिर से बेचा जाता है, जैसे "oai-reverse-proxy" deployments। इसके परिणामों में वित्तीय नुकसान, policy के विरुद्ध model का इस्तेमाल और victim tenant पर आरोप लगना शामिल हैं।<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- संक्रमित developer machines या browsers से tokens हासिल करना; CI/CD secrets चुराना; leak हुई cookies खरीदना।<sup>[[5]](#references)</sup>
- ऐसा reverse proxy स्थापित करना जो requests को असली provider तक भेजे, upstream key को छिपाए और कई customers के requests को एक साथ संभाले।<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Enterprise guardrails और rate limits को bypass करने के लिए direct base-model endpoints का दुरुपयोग करना।<sup>[[4]](#references)</sup>

**In-host API-key reuse:** Host से समझौता होने के बाद, implant victim host से सीधे model API requests भेज सकता है और replies को C2 के ज़रिए relay कर सकता है—इसके लिए cloud API key export करने या local AI CLI चलाने की ज़रूरत नहीं होती। देखे गए handler में, C2 से मिली key को प्राथमिकता दी जाती है; वह मौजूद न होने पर ही implant अपने process environment से `OPENAI_API_KEY` पढ़ता है। इसलिए victim के account का इस्तेमाल करने के लिए उस process को दिखने वाली एक valid key और model API तक access ज़रूरी है। Operator का prompt Chat Completions API तक जाता है, जबकि model output और token usage C2 के ज़रिए वापस आते हैं। इससे developer के AI tools चलाए बिना victim के paid model access का इस्तेमाल हो सकता है। यह [local AI CLI or MCP configuration abuse](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md) से अलग है।<sup>[[14]](#references)</sup>

Mitigations:
- Tokens को device fingerprint, IP ranges और client attestation से बाँधें; कम समय की expirations लागू करें और MFA के साथ refresh करें।
- Keys को न्यूनतम scope दें (tool access न दें, जहाँ लागू हो वहाँ केवल read-only access दें); असामान्य गतिविधि पर keys rotate करें।
- सभी traffic को server-side पर ऐसे policy gateway के पीछे रखें जो safety filters, per-route quotas और tenant isolation लागू करता हो।
- असामान्य usage patterns (खर्च में अचानक बढ़ोतरी, असामान्य regions, UA strings) पर नज़र रखें और संदिग्ध sessions को अपने-आप revoke करें।
- लंबे समय तक चलने वाली static API keys के बजाय अपने IdP से जारी mTLS या signed JWTs को प्राथमिकता दें।

## Self-hosted LLM inference hardening

गोपनीय data के लिए local LLM server चलाने से cloud-hosted APIs से अलग attack surface बनता है: inference/debug endpoints prompts leak कर सकते हैं, serving stack में आम तौर पर reverse proxy होता है, और GPU device nodes से बड़े `ioctl()` surfaces तक access मिलता है। यदि आप on-prem inference service का आकलन या deployment कर रहे हैं, तो कम-से-कम निम्नलिखित बिंदुओं की समीक्षा करें।<sup>[[8]](#references)</sup>

### Prompt leakage via debug and monitoring endpoints

Inference API को **कई users वाली संवेदनशील service** मानें। Debug या monitoring routes से prompt contents, slot state, model metadata या internal queue की जानकारी उजागर हो सकती है। `llama.cpp` में `/slots` endpoint विशेष रूप से संवेदनशील है, क्योंकि यह हर slot की state उजागर करता है और केवल slot inspection/management के लिए बनाया गया है।<sup>[[8]](#references)</sup>

Exposed model runners और संबंधित AI services की black-box fingerprinting और testing के लिए [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md) देखें।

- Inference server के सामने reverse proxy रखें और **डिफ़ॉल्ट रूप से access deny करें**।
- केवल client/UI के लिए ज़रूरी HTTP method + path combinations को allowlist करें।
- जहाँ संभव हो, backend में ही introspection endpoints बंद करें, उदाहरण के लिए `llama-server --no-slots`।<sup>[[9]](#references)</sup>
- Reverse proxy को `127.0.0.1` से bind करें और उसे LAN पर प्रकाशित करने के बजाय SSH local port forwarding जैसे authenticated transport के ज़रिए expose करें।

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

### बिना नेटवर्क और UNIX sockets वाले Rootless containers

अगर inference daemon UNIX socket पर सुनने का समर्थन करता है, तो TCP के बजाय इसे प्राथमिकता दें और container को **बिना network stack** के चलाएँ:<sup>[[8]](#references)</sup>

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
- `--network none` इनबाउंड/आउटबाउंड TCP/IP एक्सपोज़र हटाता है और उन user-mode helpers की आवश्यकता से बचाता है जिनकी rootless containers को अन्यथा ज़रूरत होती।
- UNIX socket आपको socket path पर POSIX permissions/ACLs को पहली access-control layer के रूप में इस्तेमाल करने देता है।
- `--userns=keep-id` और rootless Podman container breakout के प्रभाव को कम करते हैं, क्योंकि container root, host root नहीं होता।
- Read-only model mounts container के अंदर से model tampering की संभावना कम करते हैं।

स्थायी deployments के लिए, इन्हीं प्रतिबंधों को Podman Quadlet units के रूप में व्यक्त किया जा सकता है। अगर GPU access को Container Device Interface के ज़रिए दिया जाता है, तो हर accelerator node को expose करने के बजाय CDI device specification को यथासंभव सीमित रखें।<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node न्यूनतमकरण

GPU-backed inference के लिए, `/dev/nvidia*` files उच्च-मूल्य वाले स्थानीय attack surfaces हैं, क्योंकि वे बड़े driver `ioctl()` handlers और संभावित रूप से साझा GPU memory-management paths को एक्सपोज़ करते हैं।<sup>[[8]](#references)</sup>

- `/dev/nvidia*` को world writable न छोड़ें।
- `nvidia`, `nvidiactl`, और `nvidia-uvm` को `NVreg_DeviceFileUID/GID/Mode`, udev rules, और ACLs के ज़रिए सीमित करें, ताकि केवल mapped container UID ही उन्हें खोल सके।
- Headless inference hosts पर `nvidia_drm`, `nvidia_modeset`, और `nvidia_peermem` जैसे अनावश्यक modules को blacklist करें।
- Inference startup के दौरान runtime को opportunistically `modprobe` करने देने के बजाय, boot पर केवल आवश्यक modules preload करें।

उदाहरण:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

एक महत्वपूर्ण समीक्षा बिंदु **`/dev/nvidia-uvm`** है। भले ही workload स्पष्ट रूप से `cudaMallocManaged()` का उपयोग न करे, हाल के CUDA runtimes को फिर भी `nvidia-uvm` की आवश्यकता हो सकती है। चूँकि यह device साझा होता है और GPU virtual memory management संभालता है, इसे tenants के बीच data exposure का संभावित माध्यम मानें। यदि inference backend इसका समर्थन करता है, तो Vulkan backend एक दिलचस्प विकल्प हो सकता है, क्योंकि इससे container में `nvidia-uvm` को उजागर करने से पूरी तरह बचा जा सकता है।<sup>[[8]](#references)</sup>

### inference workers के लिए LSM confinement

inference process के आसपास defense in depth के तौर पर AppArmor/SELinux/seccomp का उपयोग किया जाना चाहिए:<sup>[[8]](#references)</sup>

- केवल उन shared libraries, model paths, socket directory और GPU device nodes को अनुमति दें जिनकी वास्तव में आवश्यकता है।
- `sys_admin`, `sys_module`, `sys_rawio` और `sys_ptrace` जैसी उच्च-जोखिम वाली capabilities को स्पष्ट रूप से अस्वीकार करें।
- model directory को read-only रखें और writable paths को केवल runtime socket/cache directories तक सीमित रखें।
- denial logs की निगरानी करें, क्योंकि model server या post-exploitation payload द्वारा अपने अपेक्षित व्यवहार से बाहर निकलने की कोशिश करने पर वे उपयोगी detection telemetry देते हैं।

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

## Phantom Squatting: LLM द्वारा hallucinate किए गए domains, AI supply-chain vector के रूप में

Phantom squatting, **slopsquatting का domain/URL समकक्ष** है। किसी ऐसे package name को hallucinate करने के बजाय जो मौजूद ही नहीं है, LLM किसी असली brand के लिए एक विश्वसनीय-सा **portal, API, webhook, billing, SSO, download या support domain** hallucinate करता है, और कोई attacker उस namespace को किसी इंसान या agent के इस्तेमाल करने से पहले register कर लेता है।<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

यह इसलिए मायने रखता है क्योंकि AI-सहायता वाले कई workflows में model के output को **trusted dependency** माना जाता है:
- Developers सुझाए गए endpoint को code या CI/CD integrations में paste कर देते हैं।
- AI agents documentation, schemas, APKs, ZIPs या webhook targets को अपने-आप fetch करते हैं।
- Generated runbooks या docs में fake URL ऐसे शामिल हो सकता है, मानो वह authoritative हो।

### Offensive workflow

1. **Hallucination surface की जाँच करें**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` या `mobile app` portals जैसे वास्तविक workflows के बारे में brand-विशिष्ट सवाल पूछें।<sup>[[12]](#references)</sup>
2. **Candidates को normalize करें**: generated URLs को resolve करें, NXDOMAIN responses को parent registerable domain तक सीमित करें और prompt families से duplicates हटाएँ। Prompt corpora में विविधता बनाए रखें, उदाहरण के लिए **Jaccard similarity** के आधार पर लगभग समान prompts हटाकर।
3. **अनुमानित hallucinations को प्राथमिकता दें**:
   - **Thermal Hallucination Persistence (THP)**: वही fake domain अलग-अलग temperatures पर दिखाई देता है, जिनमें `T=0.1` जैसा low temperature भी शामिल है।
   - **Cross-model consensus**: कई LLM families वही fake domain generate करती हैं।
4. Parent domain को **register और weaponize** करें, फिर वहाँ phishing, fake APK/ZIP downloads, credential harvesters, malicious docs या secrets/webhook payloads इकट्ठा करने वाले API endpoints host करें। **सिर्फ domain-स्तर की hallucinations** से कमाई करना सबसे आसान है, क्योंकि attacker पूरे namespace को control करता है; subdomain/path hallucinations का भी दुरुपयोग किया जा सकता है, अगर normalized parent register न हुआ हो।
5. **Zero-reputation window का फायदा उठाएँ**: नए registered domains में अक्सर blocklist history, URL reputation और पर्याप्त telemetry नहीं होती, इसलिए detections के प्रभावी होने तक वे controls को bypass कर सकते हैं। Attackers इस window को crawler-only benign responses, redirect cloaking, CAPTCHA gates या delayed payload staging से बढ़ा सकते हैं।

### Agents के लिए यह खतरनाक क्यों है

किसी इंसानी victim के मामले में fake domain पर आमतौर पर click करना और एक और action लेना ज़रूरी होता है। **Agentic workflow** में LLM ही **lure** और **executor**, दोनों हो सकता है: agent hallucinated URL प्राप्त करता है, उसे fetch करता है, response parse करता है और फिर tokens leak कर सकता है, instructions execute कर सकता है, dependency download कर सकता है या बिना किसी मानवीय समीक्षा के poisoned data को CI/CD में push कर सकता है।<sup>[[12]](#references)</sup>

### Attacker के लिए उपयोगी prompts

ज़्यादा असरदार prompts अक्सर सीधे phishing lures के बजाय सामान्य enterprise tasks जैसे दिखते हैं:<sup>[[12]](#references)</sup>
- “`<brand>` integrations के लिए payment sandbox URL क्या है?”
- “`<brand>` build notifications के लिए कौन-सा webhook endpoint इस्तेमाल करना चाहिए?”
- “`<brand>` का employee benefits / billing / SSO portal कहाँ है?”
- “`<brand>` के लिए direct Android APK या desktop client download दें।”

### Defensive inversion

इसे सिर्फ prompt-injection की समस्या नहीं, बल्कि proactive domain-monitoring की समस्या मानें:<sup>[[12]](#references)</sup>
- **Brand prompt corpus** बनाएँ और समय-समय पर उन LLMs की जाँच करें जिन पर आपके users/agents निर्भर हैं।
- Hallucinated URLs को store करें और track करें कि कौन-से URLs अलग-अलग temperatures/models पर स्थिर रहते हैं।
- **Adversarial Exploitation Window (AEW)** track करें: पहली hallucination और attacker द्वारा registration के बीच का समय। Positive AEW का मतलब है कि defenders weaponization से पहले pre-register या sinkhole कर सकते हैं, या पहले से block कर सकते हैं।
- Parent domains में **NXDOMAIN → registered** transitions monitor करें।
- Registration होने पर registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status और brand-asset similarity की जाँच करें।
- ऐसे policy gates जोड़ें ताकि agents/developers **LLM-generated domains पर default रूप से भरोसा न करें**: पहली बार इस्तेमाल से पहले allowlists, ownership validation, CT/RDAP checks या human approval ज़रूरी करें।

यह एक साथ AI risk की कई श्रेणियों में आता है: **AI supply-chain attack**, **insecure model output**, और जब agents hallucinated URL को अपने-आप इस्तेमाल करते हैं, तब **rogue actions**।

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Code Assistant LLMs के जोखिम: हानिकारक सामग्री, दुरुपयोग और धोखा](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: नए AI attack में इस्तेमाल किए गए चुराए हुए Cloud Credentials](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking योजना का विवरण – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (चुराई हुई LLM access को फिर से बेचना)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - On-premise, low-privileged LLM server की deployment का गहन विश्लेषण](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI द्वारा hallucinate किए गए domains, software supply chain vector के रूप में](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI hallucinations किस तरह supply-chain attacks की नई श्रेणी को बढ़ावा दे रहे हैं](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: नया AI-enabled command-and-control framework](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
