# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp, AI sistemlerini etkileyebilecek en önemli 10 machine learning vulnerability'yi belirlemiştir. Bu vulnerabilities; data poisoning, model inversion ve adversarial attacks dahil olmak üzere çeşitli security issue'lara yol açabilir. Bu vulnerabilities'leri anlamak, güvenli AI sistemleri oluşturmak için kritik öneme sahiptir.

En güncel ve ayrıntılı top 10 machine learning vulnerabilities listesi için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine başvurun.<sup>[[10]](#references)</sup>

- **Input Manipulation Attack**: Bir attacker, modelin yanlış karar vermesini sağlamak için **incoming data** üzerinde küçük ve çoğunlukla görünmez değişiklikler yapar.\
*Örnek*: Birkaç boya lekesi, self-driving car'ın bir stop işaretini hız sınırı işareti olarak "görmesine" neden olur.

- **Data Poisoning Attack**: **Training set**, modele zararlı kurallar öğretecek kötü örneklerle kasıtlı olarak kirletilir.\
*Örnek*: Bir antivirus training corpus içindeki malware binary'leri "benign" olarak etiketlenir ve benzer malware'lerin daha sonra tespit edilmeden geçmesine izin verilir.

- **Model Inversion Attack**: Bir attacker, çıktıları inceleyerek orijinal input'ların hassas özelliklerini yeniden oluşturan bir **reverse model** oluşturur.\
*Örnek*: Bir cancer-detection model'inin tahminlerinden bir hastanın MRI görüntüsünü yeniden oluşturmak.

- **Membership Inference Attack**: Adversary, confidence farklarını tespit ederek **specific record**'un training sırasında kullanılıp kullanılmadığını test eder.\
*Örnek*: Bir kişinin bank transaction'ının fraud-detection model'inin training data'sında bulunduğunu doğrulamak.

- **Model Theft**: Tekrarlanan sorgular, bir attacker's decision boundary'leri öğrenmesini ve **model's behavior**'ı (ve IP'sini) clone etmesini sağlar.\
*Örnek*: Bir ML-as-a-Service API'den near-equivalent bir local model oluşturmak için yeterli sayıda Q&A pair toplamak.

- **AI Supply-Chain Attack**: **ML pipeline** içindeki herhangi bir component'in (data, library'ler, pre-trained weight'ler, CI/CD) ele geçirilerek downstream model'lerin bozulması.\
*Örnek*: Bir model-hub üzerindeki poisoned dependency, birçok app'e backdoored sentiment-analysis model'i yükler.

- **Transfer Learning Attack**: Kötü amaçlı logic bir **pre-trained model** içine yerleştirilir ve victim'ın task'ı üzerinde fine-tuning yapılmasından sonra da varlığını sürdürür.\
*Örnek*: Gizli bir trigger içeren vision backbone, medical imaging için adapte edildikten sonra da label'ları değiştirmeye devam eder.

- **Model Skewing**: İnce şekilde biased veya yanlış etiketlenmiş data, **model's outputs**'u attacker's agenda'sını destekleyecek şekilde değiştirir.\
*Örnek*: "Clean" spam email'lerini ham olarak etiketleyip enjekte etmek; böylece bir spam filter'ın gelecekteki benzer email'lere izin vermesini sağlamak.

- **Output Integrity Attack**: Attacker, modelin kendisini değil, **model predictions**'ı transit sırasında değiştirerek downstream system'leri kandırır.\
*Örnek*: File-quarantine stage görmeden önce bir malware classifier'ın "malicious" kararını "benign" olarak değiştirmek.

- **Model Poisoning** --- Genellikle write access elde edildikten sonra **model parameters** üzerinde doğrudan ve hedefli değişiklikler yaparak davranışı değiştirmek.\
*Örnek*: Production'daki bir fraud-detection model'inin weight'lerini değiştirerek belirli card'lardan yapılan transaction'ların her zaman onaylanmasını sağlamak.


## Google SAIF Riskleri

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) framework'ü, AI sistemleriyle ilişkili çeşitli riskleri açıklamaktadır:<sup>[[11]](#references)</sup>

- **Data Poisoning**: Kötü amaçlı kişiler, accuracy'yi düşürmek, backdoor yerleştirmek veya sonuçları çarpıtmak için training/tuning data'sını değiştirir ya da data enjekte eder. Bu durum, tüm data-lifecycle boyunca model integrity'sini zayıflatır.

- **Unauthorized Training Data**: Copyright'lı, hassas veya izin alınmamış dataset'lerin alınması; modelin kullanmasına izin verilmeyen data'dan öğrenmesi nedeniyle legal, ethical ve performance riskleri oluşturur.

- **Model Source Tampering**: Training'den önce veya training sırasında model code'unun, dependency'lerin veya weight'lerin supply-chain ya da insider manipulation yoluyla değiştirilmesi, retraining'den sonra bile kalıcı olan gizli logic yerleştirebilir.

- **Excessive Data Handling**: Zayıf data-retention ve governance kontrolleri, sistemlerin gerekenden daha fazla personal data saklamasına veya işlemesine yol açarak exposure ve compliance riskini artırır.

- **Model Exfiltration**: Attacker'lar model file'larını veya weight'lerini çalar; bu durum intellectual property kaybına ve copy-cat service'lerin ya da follow-on attack'ların etkinleştirilmesine neden olur.

- **Model Deployment Tampering**: Adversary'ler model artifact'larını veya serving infrastructure'ı değiştirerek çalışan modelin incelenmiş version'dan farklı olmasını sağlar ve behaviour'ı değiştirebilir.

- **Denial of ML Service**: API'leri flood'lamak veya “sponge” input'lar göndermek compute/energy kaynaklarını tüketerek modeli offline bırakabilir; bu durum klasik DoS attack'larına benzer.

- **Model Reverse Engineering**: Çok sayıda input-output pair toplayan attacker'lar modeli clone edebilir veya distil edebilir; bu da imitation product'ları ve özelleştirilmiş adversarial attack'ları destekler.

- **Insecure Integrated Component**: Vulnerable plugin'ler, agent'lar veya upstream service'ler, attacker'ların AI pipeline içine code enjekte etmesine ya da privilege escalation yapmasına olanak tanır.

- **Prompt Injection**: System intent'i geçersiz kılan instruction'ları gizlice iletmek ve modelin amaçlanmayan command'leri çalıştırmasını sağlamak için doğrudan veya dolaylı prompt'lar oluşturmak.

- **Model Evasion**: Özenle tasarlanmış input'lar, modelin yanlış classification yapmasına, hallucinate etmesine veya izin verilmeyen content output etmesine neden olarak safety ve trust'ı zayıflatır.

- **Sensitive Data Disclosure**: Model, training data'sından veya user context'inden private ya da confidential information açığa çıkararak privacy ve regulation'ları ihlal eder.

- **Inferred Sensitive Data**: Model, hiç sağlanmamış personal attribute'ları çıkarabilir ve inference yoluyla yeni privacy zararları oluşturabilir.

- **Insecure Model Output**: Sanitize edilmemiş response'lar, harmful code'u, misinformation'ı veya inappropriate content'i user'lara ya da downstream system'lere aktarır.

- **Rogue Actions**: Autonomously-integrated agent'lar, yeterli user oversight olmadan amaçlanmayan real-world operation'ları (file write, API call, purchase vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve azaltmak için kapsamlı bir framework sunar. Adversary'lerin AI model'lerine karşı kullanabileceği çeşitli attack technique ve tactic'lerini; ayrıca AI sistemlerinin farklı attack'ları gerçekleştirmek için nasıl kullanılacağını kategorilere ayırır.<sup>[[12]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attacker'lar active session token'larını veya cloud API credential'larını çalarak ücretli, cloud-hosted LLM'leri yetkisiz şekilde çağırır. Access çoğunlukla victim'ın account'unu öne çıkaran reverse proxy'ler üzerinden yeniden satılır; örneğin "oai-reverse-proxy" deployment'ları. Sonuçlar arasında financial loss, policy dışı model misuse ve victim tenant'a atfedilme bulunur.<sup>[[2]](#references)[[3]](#references)</sup>

TTP'ler:
- Infected developer machine'lardan veya browser'lardan token toplamak; CI/CD secret'larını çalmak; leak edilmiş cookie'ler satın almak.
- Genuine provider'a request'leri forward eden, upstream key'i gizleyen ve birçok customer'ı multiplex eden bir reverse proxy kurmak.
- Enterprise guardrail'lerini ve rate limit'lerini aşmak için direct base-model endpoint'lerini kötüye kullanmak.

Mitigations:
- Token'ları device fingerprint, IP range'leri ve client attestation'a bağlamak; kısa expiration süreleri uygulamak ve MFA ile refresh etmek.
- Key'leri minimum scope'la sınırlandırmak (tool access olmadan, uygun durumlarda read-only); anomaly durumunda rotate etmek.
- Tüm traffic'i safety filter'ları, route başına quota'ları ve tenant isolation'ı uygulayan bir policy gateway arkasında server-side sonlandırmak.
- Olağandışı usage pattern'lerini (ani spend spike'ları, alışılmadık region'lar, UA string'leri) izlemek ve şüpheli session'ları otomatik olarak revoke etmek.
- Uzun ömürlü static API key'ler yerine IdP'niz tarafından verilen mTLS veya signed JWT'leri tercih etmek.

## Self-hosted LLM inference hardening

Confidential data için local LLM server çalıştırmak, cloud-hosted API'lerden farklı bir attack surface oluşturur: inference/debug endpoint'leri prompt'ları leak edebilir, serving stack genellikle bir reverse proxy açığa çıkarır ve GPU device node'ları geniş `ioctl()` surface'lerine access sağlar. Bir on-prem inference service'i değerlendiriyor veya deployment ediyorsanız en azından aşağıdaki noktaları inceleyin.<sup>[[4]](#references)</sup>

### Debug ve monitoring endpoint'leri üzerinden prompt leakage

Inference API'yi **multi-user sensitive service** olarak değerlendirin. Debug veya monitoring route'ları prompt content'ini, slot state'i, model metadata'sını veya internal queue information'ı açığa çıkarabilir. `llama.cpp` içinde `/slots` endpoint'i özellikle hassastır; çünkü her slot'a ait state'i açığa çıkarır ve yalnızca slot inspection/management amacıyla kullanılması gerekir.<sup>[[4]](#references)[[5]](#references)</sup>

- Inference server'ın önüne bir reverse proxy koyun ve **deny by default** uygulayın.
- Yalnızca client/UI tarafından ihtiyaç duyulan kesin HTTP method + path combination'larını allowlist'e alın.
- Backend'in kendisindeki introspection endpoint'lerini mümkün olduğunda devre dışı bırakın; örneğin `llama-server --no-slots`.
- Reverse proxy'yi `127.0.0.1` adresine bind edin ve LAN üzerinde publish etmek yerine SSH local port forwarding gibi authenticated bir transport üzerinden expose edin.

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
### Ağ olmadan ve UNIX sockets kullanan rootless konteynerler

Inference daemon bir UNIX socket üzerinden dinlemeyi destekliyorsa, bunu TCP yerine tercih edin ve konteyneri **ağ yığını olmadan** çalıştırın:
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
Faydalar:
- `--network none`, gelen/giden TCP/IP maruziyetini ortadan kaldırır ve rootless container'ların aksi durumda ihtiyaç duyacağı kullanıcı alanı yardımcılarını önler.
- Bir UNIX socket, ilk erişim denetimi katmanı olarak socket path üzerinde POSIX izinlerini/ACL'lerini kullanmanıza olanak tanır.
- `--userns=keep-id` ve rootless Podman, container breakout etkisini azaltır; çünkü container root'u host root'u değildir.
- Salt okunur model mount'ları, container içinden model üzerinde değişiklik yapılması olasılığını azaltır.

### GPU device-node minimizasyonu

GPU destekli inference için `/dev/nvidia*` dosyaları, büyük driver `ioctl()` işleyicilerini ve potansiyel olarak paylaşılan GPU memory-management yollarını açığa çıkardıkları için yüksek değerli yerel saldırı yüzeyleridir.<sup>[[4]](#references)</sup>

- `/dev/nvidia*` dosyalarını world writable bırakmayın.
- `nvidia`, `nvidiactl` ve `nvidia-uvm` öğelerini `NVreg_DeviceFileUID/GID/Mode`, udev kuralları ve ACL'ler ile kısıtlayarak yalnızca eşlenen container UID'sinin bunları açabilmesini sağlayın.
- Headless inference host'larında `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz modülleri blacklist'e alın.
- Runtime'ın inference startup sırasında fırsatçı biçimde `modprobe` çalıştırmasına izin vermek yerine yalnızca gerekli modülleri boot sırasında preload edin.

Örnek:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Önemli bir inceleme noktası **`/dev/nvidia-uvm`**'dir. İş yükü açıkça `cudaMallocManaged()` kullanmasa bile, güncel CUDA runtime'ları yine de `nvidia-uvm` gerektirebilir. Bu aygıt paylaşıldığı ve GPU sanal bellek yönetimini gerçekleştirdiği için, onu tenant'lar arası veri ifşası yüzeyi olarak değerlendirin. Inference backend destekliyorsa Vulkan backend ilginç bir ödünleşim sunabilir; çünkü container'a `nvidia-uvm` erişimi sağlanmasını tamamen önleyebilir.

### Inference worker'ları için LSM confinement

AppArmor/SELinux/seccomp, inference process'i çevresinde defense in depth olarak kullanılmalıdır:<sup>[[4]](#references)</sup>

- Yalnızca gerçekten gerekli olan shared library'lere, model path'lerine, socket directory'sine ve GPU device node'larına izin verin.
- `sys_admin`, `sys_module`, `sys_rawio` ve `sys_ptrace` gibi yüksek riskli capability'leri açıkça reddedin.
- Model directory'sini read-only tutun ve yazılabilir path'leri yalnızca runtime socket/cache directory'leriyle sınırlandırın.
- Denial log'larını izleyin; model server veya post-exploitation payload beklenen davranış alanından çıkmaya çalıştığında bu log'lar yararlı detection telemetry sağlar.

GPU-backed bir worker için örnek AppArmor kuralları:
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
## Phantom Squatting: LLM-Hallucinated Domains as Bir AI Tedarik-Zinciri Vektörü

Phantom squatting, **slopsquatting'in domain/URL karşılığıdır**. LLM, var olmayan bir paket adını hallucinate etmek yerine gerçek bir marka için makul görünen bir **portal, API, webhook, billing, SSO, download veya support domain'ini** hallucinate eder ve saldırgan, bir insan veya agent bunu kullanmadan önce bu namespace'i kaydeder.<sup>[[8]](#references)[[9]](#references)</sup>

Bu önemlidir; çünkü birçok AI destekli workflow'da model çıktısı **güvenilir bir dependency** olarak kabul edilir:
- Developer'lar önerilen endpoint'i code veya CI/CD entegrasyonlarına yapıştırır.
- AI agent'ları documentation, schema, APK, ZIP veya webhook target'larını otomatik olarak fetch eder.
- Oluşturulan runbook'lar veya doc'lar sahte URL'yi yetkiliymiş gibi embed edebilir.

### Offensive workflow

1. **Hallucination surface'i probe edin**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` veya `mobile app` portalları gibi gerçekçi workflow'lar hakkında marka-özel sorular sorun.
2. **Adayları normalize edin**: oluşturulan URL'leri resolve edin, NXDOMAIN response'larını parent registerable domain'e indirgeyin ve prompt family'lerini deduplicate edin. Prompt corpus'ları çeşitli kalmalıdır; örneğin **Jaccard similarity** kullanarak birbirine çok yakın tekrarları çıkarın.
3. **Öngörülebilir hallucination'lara öncelik verin**:
- **Thermal Hallucination Persistence (THP)**: aynı fake domain, `T=0.1` gibi düşük temperature değerleri dahil olmak üzere farklı temperature değerlerinde de görünür.
- **Cross-model consensus**: birden fazla LLM family aynı fake domain'i üretir.
4. **Parent domain'i register edip weaponize edin**; ardından phishing, fake APK/ZIP download'ları, credential harvester'lar, malicious doc'lar veya secret/webhook payload'larını toplayan API endpoint'leri host edin. **Pure domain-level hallucination'lar** monetize edilmesi en kolay olanlardır; çünkü saldırgan tüm namespace'i kontrol eder. Subdomain/path hallucination'ları da normalize edilmiş parent register edilmemiş olduğunda abuse edilebilir.
5. **Zero-reputation window'ı exploit edin**: yeni register edilmiş domain'lerde genellikle blocklist history, URL reputation ve olgun telemetry bulunmadığından, detection'lar yetişene kadar kontrolleri bypass edebilirler. Saldırganlar bu window'ı crawler-only benign response'lar, redirect cloaking, CAPTCHA gate'leri veya gecikmeli payload staging ile uzatabilir.

### Agent'lar için neden tehlikelidir?

İnsan victim için fake domain genellikle bir click ve ek bir action gerektirir. **Agentic workflow**'ta ise LLM hem **lure** hem de **executor** olabilir: agent hallucinate edilmiş URL'yi alır, URL'yi fetch eder, response'u parse eder ve ardından herhangi bir human review olmadan token'ları leak edebilir, instruction'ları execute edebilir, bir dependency download edebilir veya CI/CD'ye poisoned data push edebilir.<sup>[[8]](#references)</sup>

### Pratik attacker prompt'ları

High-yield prompt'lar genellikle açık phishing lure'ları yerine normal enterprise task'larına benzer:
- “`<brand>` entegrasyonları için payment sandbox URL'si nedir?”
- “`<brand>` build notification'ları için hangi webhook endpoint'ini kullanmalıyım?”
- “`<brand>` için employee benefits / billing / SSO portalı nerede?”
- “`<brand>` için doğrudan Android APK veya desktop client download'ını ver.”

### Defensive inversion

Bunu yalnızca bir prompt-injection problemi olarak değil, proaktif bir domain-monitoring problemi olarak ele alın:
- Bir **brand prompt corpus** oluşturun ve kullanıcılarınızın/agent'larınızın güvendiği LLM'leri periyodik olarak probe edin.
- Hallucinate edilmiş URL'leri saklayın ve hangilerinin temperature/model'lar arasında stabil olduğunu takip edin.
- **Adversarial Exploitation Window (AEW)** değerini takip edin: ilk hallucination ile saldırganın registration'ı arasındaki süre. Pozitif AEW, defender'ların weaponization'dan önce pre-register, sinkhole veya pre-block yapabileceği anlamına gelir.
- Parent domain'lerdeki **NXDOMAIN → registered** geçişlerini izleyin.
- Registration sonrasında registrar'ı, creation date'i, nameserver'ları, privacy shielding'i, page content'i, screenshot'ları, parked-page status'ını ve brand-asset similarity'yi triage edin.
- Agent'ların/developer'ların **LLM tarafından üretilen domain'lere varsayılan olarak trust etmemesi** için policy gate'leri ekleyin: ilk kullanımdan önce allowlist, ownership validation, CT/RDAP check veya human approval gerektirin.

Bu durum aynı anda birkaç AI risk bucket'ına uyar: **AI supply-chain attack**, **insecure model output** ve agent'ların hallucinate edilmiş URL'yi otonom olarak tüketmesi durumunda **rogue actions**.

## References
- [1] [Unit 42 – Code Assistant LLM'lerinin riskleri: Zararlı içerik, kötüye kullanım ve aldatma](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [2] [LLMJacking scheme'e genel bakış – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [3] [oai-reverse-proxy (çalınmış LLM erişiminin yeniden satılması)](https://gitgud.io/khanon/oai-reverse-proxy)
- [4] [Synacktiv - On-premise düşük yetkili bir LLM server'ının deployment'ına derinlemesine bakış](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [5] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [6] [Podman quadlet'leri: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [7] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [8] [Unit 42 – Phantom Squatting: AI-Hallucinated Domain'ler bir Software Supply Chain Vector olarak](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [9] [Socket – Slopsquatting: AI Hallucination'ları yeni bir Supply Chain Attack sınıfını nasıl besliyor](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [10] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [11] [Google SAIF (Security AI Framework) Risk'leri](https://saif.google/secure-ai-framework/risks)
- [12] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)

{{#include ../banners/hacktricks-training.md}}
