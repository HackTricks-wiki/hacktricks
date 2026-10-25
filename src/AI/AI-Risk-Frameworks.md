# AI जोखिम

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp ने machine learning की शीर्ष 10 vulnerabilities की पहचान की है, जो AI systems को प्रभावित कर सकती हैं। इन vulnerabilities से data poisoning, model inversion और adversarial attacks समेत कई सुरक्षा समस्याएँ हो सकती हैं। सुरक्षित AI systems बनाने के लिए इन vulnerabilities को समझना ज़रूरी है।

Machine learning की शीर्ष 10 vulnerabilities की अद्यतन और विस्तृत सूची के लिए [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project देखें।<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Attacker **आने वाले डेटा** में छोटे, अक्सर अदृश्य बदलाव करता है, ताकि model गलत निर्णय ले।\
    *उदाहरण*: Stop sign पर paint के कुछ छींटे self-driving car को उसे speed-limit sign के रूप में "देखने" पर मजबूर कर देते हैं।

- **Data Poisoning Attack**: **Training set** को जानबूझकर खराब samples से दूषित किया जाता है, जिससे model हानिकारक नियम सीखता है।\
*उदाहरण*: Antivirus training corpus में malware binaries को "benign" के रूप में गलत label किया जाता है, जिससे बाद में ऐसे ही malware बच निकलते हैं।

- **Model Inversion Attack**: Outputs की जाँच करके attacker एक **reverse model** बनाता है, जो मूल inputs की संवेदनशील विशेषताओं को फिर से निर्मित करता है।\
*उदाहरण*: Cancer-detection model की predictions से मरीज की MRI image फिर से बनाना।

- **Membership Inference Attack**: Adversary confidence में अंतर देखकर जाँचता है कि training के दौरान **कोई खास record** इस्तेमाल हुआ था या नहीं।\
*उदाहरण*: यह पुष्टि करना कि किसी व्यक्ति का bank transaction fraud-detection model के training data में मौजूद है।

- **Model Theft**: बार-बार query करने से attacker decision boundaries सीखकर **model के व्यवहार (और IP) की नकल** कर सकता है।\
*उदाहरण*: ML-as-a-Service API से पर्याप्त Q&A pairs इकट्ठा करके लगभग समकक्ष local model बनाना।

- **AI Supply‑Chain Attack**: **ML pipeline** में किसी भी component (data, libraries, pre-trained weights, CI/CD) से छेड़छाड़ करके आगे बनने वाले models को दूषित करना।\
*उदाहरण*: Model-hub पर मौजूद poisoned dependency कई apps में backdoored sentiment-analysis model install कर देती है।

- **Transfer Learning Attack**: **Pre-trained model** में malicious logic डाल दी जाती है, जो victim के task पर fine-tuning के बाद भी बनी रहती है।\
*उदाहरण*: Hidden trigger वाला vision backbone, medical imaging के लिए adapt किए जाने के बाद भी labels बदल देता है।

- **Model Skewing**: सूक्ष्म रूप से biased या गलत label किया गया data **model के outputs को बदल देता है**, ताकि वे attacker के मकसद के अनुकूल हों।\
*उदाहरण*: "Clean" spam emails को ham label करके डालना, ताकि spam filter भविष्य में ऐसे ही emails को आने दे।

- **Output Integrity Attack**: Attacker model को नहीं, बल्कि **रास्ते में model predictions को बदलता है**, जिससे downstream systems को धोखा दिया जा सके।\
*उदाहरण*: File-quarantine stage तक पहुँचने से पहले malware classifier के "malicious" verdict को "benign" में बदल देना।

- **Model Poisoning** --- अक्सर write access मिलने के बाद, व्यवहार बदलने के लिए सीधे **model parameters** में लक्षित बदलाव करना।\
*उदाहरण*: Production में fraud-detection model के weights को इस तरह बदलना कि कुछ खास cards से किए गए transactions हमेशा approve हों।


## Google SAIF जोखिम

Google का [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) AI systems से जुड़े विभिन्न जोखिमों की रूपरेखा देता है:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Malicious actors accuracy घटाने, backdoors डालने या नतीजों को पक्षपाती बनाने के लिए training/tuning data में बदलाव करते हैं या data जोड़ते हैं। इससे पूरे data-lifecycle में model integrity कमज़ोर होती है।

- **Unauthorized Training Data**: Copyrighted, sensitive या बिना अनुमति वाले datasets को शामिल करने से कानूनी, नैतिक और performance संबंधी जोखिम पैदा होते हैं, क्योंकि model ऐसे data से सीखता है जिसके इस्तेमाल की अनुमति उसे नहीं थी।

- **Model Source Tampering**: Training से पहले या उसके दौरान model code, dependencies या weights के साथ supply-chain या insider द्वारा छेड़छाड़ करने से hidden logic शामिल हो सकती है, जो retraining के बाद भी बनी रहती है।

- **Excessive Data Handling**: Data-retention और governance के कमज़ोर controls के कारण systems ज़रूरत से ज़्यादा personal data store या process कर सकते हैं, जिससे data exposure और compliance के जोखिम बढ़ते हैं।

- **Model Exfiltration**: Attackers model files/weights चुरा लेते हैं, जिससे intellectual property का नुकसान होता है और नकल करने वाली services या बाद के attacks संभव होते हैं।

- **Model Deployment Tampering**: Adversaries model artifacts या serving infrastructure में बदलाव करते हैं, ताकि चल रहा model जाँचे गए version से अलग हो और उसका व्यवहार बदल सके।

- **Denial of ML Service**: APIs पर बहुत अधिक requests भेजकर या “sponge” inputs देकर compute/energy खत्म की जा सकती है और model को offline किया जा सकता है। यह पारंपरिक DoS attacks जैसा है।

- **Model Reverse Engineering**: बहुत सारे input-output pairs इकट्ठा करके attackers model की नकल या distillation कर सकते हैं, जिससे imitation products और अनुकूलित adversarial attacks को बढ़ावा मिलता है।

- **Insecure Integrated Component**: Vulnerable plugins, agents या upstream services attackers को AI pipeline में code डालने या privileges बढ़ाने का रास्ता दे सकते हैं।

- **Prompt Injection**: सीधे या परोक्ष रूप से ऐसे prompts बनाना जो system के इरादे को बदलने वाले instructions छिपाकर भेजें और model से अनचाहे commands करवाएँ।

- **Model Evasion**: सावधानी से बनाए गए inputs model से गलत classification, hallucination या निषिद्ध content का output करवा सकते हैं, जिससे सुरक्षा और भरोसा कमज़ोर होता है।

- **Sensitive Data Disclosure**: Model अपने training data या user context से निजी या गोपनीय जानकारी उजागर कर सकता है, जिससे privacy और regulations का उल्लंघन होता है।

- **Inferred Sensitive Data**: Model ऐसे personal attributes का अनुमान लगा सकता है जो कभी दिए ही नहीं गए थे, जिससे अनुमान के ज़रिए privacy को नया नुकसान पहुँचता है।

- **Insecure Model Output**: बिना sanitize किए गए responses के ज़रिए हानिकारक code, गलत जानकारी या अनुचित content users या downstream systems तक पहुँच सकता है।

- **Rogue Actions**: Autonomously-integrated agents पर्याप्त user oversight के बिना अनचाहे वास्तविक कार्य (file writes, API calls, purchases आदि) कर सकते हैं।

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI systems से जुड़े जोखिमों को समझने और कम करने के लिए एक व्यापक framework प्रदान करता है। इसमें विभिन्न attack techniques और tactics को वर्गीकृत किया गया है, जिनका adversaries AI models के विरुद्ध उपयोग कर सकते हैं; साथ ही यह भी बताया गया है कि अलग-अलग attacks करने के लिए AI systems का कैसे उपयोग किया जा सकता है।<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers active session tokens या cloud API credentials चुराकर बिना अनुमति paid, cloud-hosted LLMs का उपयोग करते हैं। इस access को अक्सर ऐसे reverse proxies के ज़रिए दोबारा बेचा जाता है, जो victim के account के माध्यम से requests भेजते हैं, जैसे "oai-reverse-proxy" deployments। इसके परिणामों में वित्तीय नुकसान, policy के बाहर model का दुरुपयोग और victim tenant पर आरोप आना शामिल हैं।<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs:
- संक्रमित developer machines या browsers से tokens इकट्ठा करना; CI/CD secrets चुराना; leaked cookies खरीदना।<sup>[[5]](#references)</sup>
- ऐसा reverse proxy चलाना जो requests को असली provider तक पहुँचाए, upstream key छिपाए और कई customers की requests को एक साथ संभाले।<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Enterprise guardrails और rate limits को bypass करने के लिए सीधे base-model endpoints का दुरुपयोग करना।<sup>[[4]](#references)</sup>

Mitigations:
- Tokens को device fingerprint, IP ranges और client attestation से बाँधें; कम expiry लागू करें और MFA के साथ refresh करें।
- Keys को न्यूनतम scope दें (tool access न दें, जहाँ लागू हो वहाँ read-only रखें); असामान्य गतिविधि दिखने पर rotate करें।
- सभी traffic को policy gateway के पीछे server-side terminate करें, जो safety filters, हर route के लिए quotas और tenant isolation लागू करे।
- उपयोग के असामान्य पैटर्न (अचानक spend में बढ़ोतरी, असामान्य regions, UA strings) पर नज़र रखें और संदिग्ध sessions को अपने-आप revoke करें।
- लंबे समय तक चलने वाली static API keys के बजाय अपने IdP द्वारा जारी mTLS या signed JWTs को प्राथमिकता दें।

## Self-hosted LLM inference को सुरक्षित करना

गोपनीय data के लिए local LLM server चलाने से cloud-hosted APIs से अलग attack surface बनता है: inference/debug endpoints prompts leak कर सकते हैं, serving stack में आमतौर पर reverse proxy मौजूद होता है और GPU device nodes बड़े `ioctl()` surfaces तक पहुँच देते हैं। यदि आप on-prem inference service का आकलन या deployment कर रहे हैं, तो कम-से-कम इन बिंदुओं की समीक्षा करें।<sup>[[8]](#references)</sup>

### Debug और monitoring endpoints से prompt leakage

Inference API को **कई users वाली संवेदनशील service** मानें। Debug या monitoring routes prompt contents, slot state, model metadata या internal queue की जानकारी उजागर कर सकते हैं। `llama.cpp` में `/slots` endpoint विशेष रूप से संवेदनशील है, क्योंकि यह हर slot का state उजागर करता है और इसका उद्देश्य केवल slot का निरीक्षण/प्रबंधन करना है।<sup>[[8]](#references)</sup>

Exposed model runners और संबंधित AI services की black-box fingerprinting और testing के लिए [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md) देखें।

- Inference server के सामने reverse proxy रखें और **डिफ़ॉल्ट रूप से access रोकें**।
- केवल उन सटीक HTTP method + path combinations को allowlist करें जिनकी client/UI को ज़रूरत है।
- जब भी संभव हो, backend में ही introspection endpoints बंद करें, उदाहरण के लिए `llama-server --no-slots`।<sup>[[9]](#references)</sup>
- Reverse proxy को `127.0.0.1` पर bind करें और उसे LAN पर publish करने के बजाय SSH local port forwarding जैसे authenticated transport के ज़रिए उपलब्ध कराएँ।

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
- UNIX socket से आप socket path पर POSIX permissions/ACLs को access-control की पहली परत के रूप में इस्तेमाल कर सकते हैं।
- `--userns=keep-id` और rootless Podman, container breakout के प्रभाव को कम करते हैं, क्योंकि container root, host root नहीं होता।
- Read-only model mounts, container के भीतर से model के साथ छेड़छाड़ की संभावना कम करते हैं।

स्थायी deployments के लिए, इन्हीं प्रतिबंधों को Podman Quadlet units के ज़रिए व्यक्त किया जा सकता है। यदि GPU access को Container Device Interface के ज़रिए सौंपा गया है, तो हर accelerator node को expose करने के बजाय CDI device specification को यथासंभव सीमित रखें।<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node को न्यूनतम करना

GPU-backed inference के लिए, `/dev/nvidia*` files उच्च-मूल्य वाले local attack surfaces हैं, क्योंकि वे बड़े driver `ioctl()` handlers और संभावित रूप से साझा GPU memory-management paths को expose करती हैं।<sup>[[8]](#references)</sup>

- `/dev/nvidia*` को world writable न छोड़ें।
- `nvidia`, `nvidiactl`, और `nvidia-uvm` को `NVreg_DeviceFileUID/GID/Mode`, udev rules, और ACLs के ज़रिए प्रतिबंधित करें, ताकि केवल mapped container UID ही उन्हें खोल सके।
- Headless inference hosts पर `nvidia_drm`, `nvidia_modeset`, और `nvidia_peermem` जैसे अनावश्यक modules को blacklist करें।
- Inference startup के दौरान runtime को opportunistically `modprobe` करने देने के बजाय, boot पर केवल आवश्यक modules preload करें।

उदाहरण:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

एक महत्वपूर्ण समीक्षा बिंदु **`/dev/nvidia-uvm`** है। भले ही workload स्पष्ट रूप से `cudaMallocManaged()` का उपयोग न करे, हाल के CUDA runtimes को फिर भी `nvidia-uvm` की आवश्यकता हो सकती है। चूँकि यह device साझा होता है और GPU virtual memory management संभालता है, इसे tenants के बीच data exposure का एक संभावित माध्यम मानें। यदि inference backend इसका समर्थन करता है, तो Vulkan backend एक दिलचस्प trade-off हो सकता है, क्योंकि इससे container को `nvidia-uvm` बिल्कुल भी उपलब्ध कराने की आवश्यकता नहीं पड़ सकती।<sup>[[8]](#references)</sup>

### Inference workers के लिए LSM confinement

Inference process के चारों ओर defense in depth के रूप में AppArmor/SELinux/seccomp का उपयोग किया जाना चाहिए:<sup>[[8]](#references)</sup>

- केवल उन्हीं shared libraries, model paths, socket directory और GPU device nodes को अनुमति दें जिनकी वास्तव में आवश्यकता है।
- `sys_admin`, `sys_module`, `sys_rawio` और `sys_ptrace` जैसी high-risk capabilities को स्पष्ट रूप से अस्वीकार करें।
- Model directory को read-only रखें और writable paths को केवल runtime socket/cache directories तक सीमित रखें।
- Denial logs की निगरानी करें, क्योंकि model server या post-exploitation payload द्वारा अपने अपेक्षित व्यवहार से बाहर निकलने की कोशिश करने पर वे उपयोगी detection telemetry प्रदान करते हैं।

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

## Phantom Squatting: LLM द्वारा गढ़े गए डोमेन, AI सप्लाई-चेन का एक जोखिम

Phantom squatting, **slopsquatting का डोमेन/URL समकक्ष** है। किसी ऐसे पैकेज नाम को गढ़ने के बजाय जिसका अस्तित्व नहीं है, LLM किसी वास्तविक ब्रांड के लिए एक संभावित **portal, API, webhook, billing, SSO, download या support domain** गढ़ता है, और कोई हमलावर उस namespace को किसी इंसान या agent के इस्तेमाल करने से पहले register कर लेता है।<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

यह इसलिए मायने रखता है क्योंकि कई AI-सहायता वाले workflows में model के output को **विश्वसनीय dependency** माना जाता है:
- Developers सुझाए गए endpoint को code या CI/CD integrations में paste कर देते हैं।
- AI agents documentation, schemas, APKs, ZIPs या webhook targets को अपने-आप fetch करते हैं।
- बनाए गए runbooks या docs में नकली URL को आधिकारिक बताकर शामिल किया जा सकता है।

### हमलावर का workflow

1. **Hallucination के संभावित ठिकानों को जाँचें**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` या `mobile app` portals जैसे वास्तविक workflows के बारे में ब्रांड-विशिष्ट सवाल पूछें।<sup>[[12]](#references)</sup>
2. **उम्मीदवारों को सामान्यीकृत करें**: बनाए गए URLs को resolve करें, NXDOMAIN responses को parent registerable domain तक सीमित करें और prompt families से duplicate हटाएँ। Prompt corpora में विविधता बनाए रखें, उदाहरण के लिए **Jaccard similarity** का इस्तेमाल करके लगभग समान prompts हटाएँ।
3. **अनुमानित hallucinations को प्राथमिकता दें**:
   - **Thermal Hallucination Persistence (THP)**: एक ही नकली domain अलग-अलग temperatures पर दिखाई दे, जिसमें `T=0.1` जैसे कम temperature भी शामिल हों।
   - **कई models की सहमति**: LLM की कई families एक ही नकली domain बनाएँ।
4. Parent domain **register करके उसे हमले के लिए इस्तेमाल करें**, फिर वहाँ phishing, नकली APK/ZIP downloads, credential harvesters, दुर्भावनापूर्ण docs या ऐसे API endpoints होस्ट करें जो secrets/webhook payloads इकट्ठा करें। **सिर्फ domain-स्तर की hallucinations** से कमाई करना सबसे आसान है, क्योंकि हमलावर पूरे namespace को नियंत्रित करता है; subdomain/path hallucinations का भी दुरुपयोग किया जा सकता है, अगर सामान्यीकृत parent unregistered हो।
5. **शुरुआती शून्य-प्रतिष्ठा अवधि का फायदा उठाएँ**: नए register किए गए domains में अक्सर blocklist history, URL reputation और पर्याप्त telemetry नहीं होती, इसलिए detections के पकड़ने तक वे controls को बायपास कर सकते हैं। हमलावर crawler-only benign responses, redirect cloaking, CAPTCHA gates या payload को देर से stage करके इस अवधि को बढ़ा सकते हैं।

### Agents के लिए यह ख़तरनाक क्यों है

किसी इंसानी पीड़ित को नकली domain पर जाने के लिए आम तौर पर क्लिक और एक अन्य कार्रवाई करनी पड़ती है। **Agentic workflow** में LLM ही **झाँसा देने वाला** और **कार्रवाई करने वाला**—दोनों हो सकता है: agent को hallucinated URL मिलता है, वह उसे fetch करता है, response को parse करता है और फिर किसी human review के बिना tokens leak कर सकता है, instructions execute कर सकता है, dependency download कर सकता है या दूषित data को CI/CD में push कर सकता है।<sup>[[12]](#references)</sup>

### हमलावरों के लिए व्यावहारिक prompts

ज़्यादा असरदार prompts आम तौर पर स्पष्ट phishing के बजाय सामान्य enterprise tasks जैसे दिखते हैं:<sup>[[12]](#references)</sup>
- “`<brand>` integrations के लिए payment sandbox URL क्या है?”
- “`<brand>` की build notifications के लिए मुझे कौन-सा webhook endpoint इस्तेमाल करना चाहिए?”
- “`<brand>` का employee benefits / billing / SSO portal कहाँ है?”
- “`<brand>` के लिए सीधा Android APK या desktop client download दें।”

### रक्षात्मक उपाय

इसे केवल prompt-injection की समस्या नहीं, बल्कि सक्रिय domain-monitoring की समस्या मानें:<sup>[[12]](#references)</sup>
- **Brand prompt corpus** बनाएँ और समय-समय पर उन LLMs की जाँच करें जिन पर आपके users/agents निर्भर करते हैं।
- Hallucinated URLs संग्रहीत करें और देखें कि कौन-से URLs अलग-अलग temperatures/models पर स्थिर रहते हैं।
- **Adversarial Exploitation Window (AEW)** पर नज़र रखें: पहली hallucination से लेकर हमलावर द्वारा domain register करने तक का समय। Positive AEW का मतलब है कि defenders हथियार बनाए जाने से पहले domain pre-register, sinkhole या pre-block कर सकते हैं।
- Parent domains के **NXDOMAIN → registered** transitions पर नज़र रखें।
- Registration होने पर registrar, creation date, nameservers, privacy shielding, page content, screenshots, parked-page status और brand-asset similarity की जाँच करें।
- ऐसी policy gates जोड़ें ताकि agents/developers **LLM-जनरेट किए गए domains पर डिफ़ॉल्ट रूप से भरोसा न करें**: पहली बार इस्तेमाल से पहले allowlists, ownership validation, CT/RDAP checks या human approval ज़रूरी करें।

यह एक साथ AI जोखिम की कई श्रेणियों में आता है: **AI supply-chain attack**, **असुरक्षित model output** और जब agents hallucinated URL का अपने-आप इस्तेमाल करते हैं, तब **rogue actions**।

## References

- [1] [OWASP के शीर्ष 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – जोखिम](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 – Code Assistant LLMs के जोखिम: हानिकारक सामग्री, दुरुपयोग और धोखा](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: नए AI हमले में चोरी किए गए Cloud Credentials का इस्तेमाल](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking योजना का अवलोकन – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (चुराए गए LLM access को फिर से बेचना)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - ऑन-प्रिमाइज़ कम-अधिकार वाले LLM server की तैनाती का गहन विश्लेषण](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI द्वारा गढ़े गए डोमेन, Software Supply Chain का एक जोखिम](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI hallucinations कैसे supply chain attacks की एक नई श्रेणी को बढ़ावा दे रही हैं](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
