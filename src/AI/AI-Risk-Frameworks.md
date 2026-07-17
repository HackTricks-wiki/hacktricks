# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp, AI sistemlerini etkileyebilecek en önemli 10 machine learning vulnerability'yi belirlemiştir. Bu vulnerability'ler data poisoning, model inversion ve adversarial attack'ler dahil olmak üzere çeşitli security issue'lara yol açabilir. Bu vulnerability'leri anlamak, güvenli AI sistemleri oluşturmak için kritik öneme sahiptir.

En güncel ve ayrıntılı top 10 machine learning vulnerability listesi için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine başvurun.

- **Input Manipulation Attack**: Bir attacker, modelin yanlış karar vermesini sağlamak için **gelen data** üzerinde küçük ve çoğu zaman görünmez değişiklikler yapar.\
*Örnek*: Bir stop sign üzerindeki birkaç boya lekesi, self-driving car'ın bunu speed-limit sign olarak "görmesine" neden olur.

- **Data Poisoning Attack**: **Training set**, modele zararlı kuralları öğretmek amacıyla kasıtlı olarak kötü örneklerle kirletilir.\
*Örnek*: Malware binary'leri bir antivirus training corpus'unda "benign" olarak etiketlenir ve benzer malware'lerin daha sonra fark edilmeden geçmesine izin verilir.

- **Model Inversion Attack**: Bir attacker, output'ları sorgulayarak orijinal input'ların hassas özelliklerini yeniden oluşturan bir **reverse model** oluşturur.\
*Örnek*: Bir cancer-detection modelinin tahminlerinden hastanın MRI görüntüsünü yeniden oluşturmak.

- **Membership Inference Attack**: Adversary, confidence farklılıklarını gözlemleyerek **belirli bir record'un** training sırasında kullanılıp kullanılmadığını test eder.\
*Örnek*: Bir kişinin bank transaction'ının fraud-detection modelinin training data'sında bulunduğunu doğrulamak.

- **Model Theft**: Tekrarlanan query'ler, bir attacker's decision boundary'leri öğrenmesini ve **modelin davranışını** (ve IP'sini) klonlamasını sağlar.\
*Örnek*: Bir ML-as-a-Service API'sinden near-equivalent bir local model oluşturmak için yeterli sayıda Q&A pair toplamak.

- **AI Supply-Chain Attack**: **ML pipeline** içindeki herhangi bir component'in (data, library'ler, pre-trained weight'ler, CI/CD) ele geçirilerek downstream model'lerin bozulması.\
*Örnek*: Bir model-hub üzerindeki poisoned dependency, birçok app'e backdoored sentiment-analysis model kurar.

- **Transfer Learning Attack**: **Pre-trained model** içine malicious logic yerleştirilir ve victim'ın task'ı üzerinde yapılan fine-tuning sonrasında da varlığını sürdürür.\
*Örnek*: Gizli bir trigger içeren vision backbone, medical imaging için adapte edildikten sonra da label'ları değiştirmeye devam eder.

- **Model Skewing**: İnce biçimde biased veya yanlış etiketlenmiş data, attacker's agenda'sını destekleyecek şekilde **model output'larını kaydırır**.\
*Örnek*: "Clean" spam email'lerini ham olarak etiketleyip eklemek; böylece spam filter'ın gelecekteki benzer email'lerine izin vermesini sağlamak.

- **Output Integrity Attack**: Attacker, modelin kendisini değil, **model prediction'larını aktarım sırasında değiştirerek** downstream sistemleri kandırır.\
*Örnek*: File-quarantine aşaması görmeden önce bir malware classifier'ın "malicious" verdict'ini "benign" olarak değiştirmek.

- **Model Poisoning** --- Genellikle write access elde edildikten sonra **model parameter'larının** kendisinde doğrudan ve hedefli değişiklikler yaparak davranışı değiştirmek.\
*Örnek*: Production'daki bir fraud-detection modelinin weight'lerini değiştirerek belirli card'lardan gelen transaction'ların her zaman onaylanmasını sağlamak.


## Google SAIF Riskleri

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) framework'ü, AI sistemleriyle ilişkili çeşitli riskleri açıklar:

- **Data Poisoning**: Malicious actor'ler accuracy'yi düşürmek, backdoor yerleştirmek veya sonuçları skew etmek amacıyla training/tuning data'sını değiştirir ya da data ekler; bu durum tüm data-lifecycle boyunca model integrity'sini zayıflatır.

- **Unauthorized Training Data**: Copyright'lı, hassas veya izinsiz dataset'lerin alınması, modelin kullanmasına hiçbir zaman izin verilmeyen data'dan öğrenmesi nedeniyle legal, ethical ve performance liability'ler oluşturur.

- **Model Source Tampering**: Training'den önce veya training sırasında model code'unun, dependency'lerin veya weight'lerin supply-chain ya da insider manipulation ile değiştirilmesi, retraining sonrasında bile kalıcı olan gizli logic'ler yerleştirebilir.

- **Excessive Data Handling**: Zayıf data-retention ve governance control'leri, sistemlerin gerekenden daha fazla personal data saklamasına veya işlemesine yol açarak exposure ve compliance risk'ini artırır.

- **Model Exfiltration**: Attacker'lar model file'larını/weight'lerini çalar; bu durum intellectual property kaybına yol açar ve copy-cat service'leri veya follow-on attack'leri mümkün kılar.

- **Model Deployment Tampering**: Adversary'ler model artifact'larını veya serving infrastructure'ını değiştirerek çalışan modelin doğrulanmış sürümden farklı olmasını sağlar ve potansiyel olarak behaviour'ı değiştirir.

- **Denial of ML Service**: API'leri flood etmek veya “sponge” input'ları göndermek compute/energy kaynaklarını tüketerek modeli offline bırakabilir; bu, klasik DoS attack'lerini andırır.

- **Model Reverse Engineering**: Çok sayıda input-output pair toplayarak attacker'lar modeli klonlayabilir veya distil edebilir; bu durum imitation product'larına ve özelleştirilmiş adversarial attack'lere olanak sağlar.

- **Insecure Integrated Component**: Vulnerable plugin'ler, agent'lar veya upstream service'ler attacker'ların code inject etmesine ya da AI pipeline içinde privilege escalation yapmasına izin verir.

- **Prompt Injection**: System intent'i geçersiz kılan instruction'ları gizlice iletmek ve modelin istenmeyen command'ler çalıştırmasını sağlamak için doğrudan veya dolaylı olarak prompt'lar oluşturmak.

- **Model Evasion**: Dikkatle tasarlanmış input'lar modeli mis-classify yapmaya, hallucinate etmeye veya disallowed content output etmeye zorlayarak safety ve trust'ı zayıflatır.

- **Sensitive Data Disclosure**: Model, training data'sından veya user context'inden private ya da confidential information açıklayarak privacy ve regulation'ları ihlal eder.

- **Inferred Sensitive Data**: Model, hiç sağlanmamış personal attribute'ları çıkarabilir ve inference yoluyla yeni privacy ihlalleri oluşturabilir.

- **Insecure Model Output**: Sanitize edilmemiş response'lar harmful code, misinformation veya inappropriate content'i user'lara ya da downstream sistemlere aktarır.

- **Rogue Actions**: Autonomous olarak entegre edilmiş agent'lar, yeterli user oversight olmadan istenmeyen real-world operation'ları (file write'ları, API call'ları, purchase'lar vb.) çalıştırır.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve azaltmak için kapsamlı bir framework sunar. Adversary'lerin AI model'lerine karşı kullanabileceği çeşitli attack technique ve tactic'lerini, ayrıca farklı attack'leri gerçekleştirmek için AI sistemlerinin nasıl kullanılabileceğini kategorize eder.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attacker'lar active session token'larını veya cloud API credential'larını çalarak ücretli, cloud-hosted LLM'leri authorization olmadan çağırır. Access çoğu zaman victim'ın account'unu öne çıkaran reverse proxy'ler üzerinden yeniden satılır; örneğin "oai-reverse-proxy" deployment'ları. Sonuçlar arasında financial loss, modelin policy dışında kötüye kullanılması ve victim tenant'a attribution bulunur.

TTP'ler:
- Infected developer machine'lerinden veya browser'lardan token'ları harvest edin; CI/CD secret'larını çalın; leaked cookie'ler satın alın.
- Genuine provider'a request'leri forward eden, upstream key'i gizleyen ve çok sayıda customer'ı multiplex eden bir reverse proxy kurun.
- Enterprise guardrail'lerini ve rate limit'lerini bypass etmek için direct base-model endpoint'lerini abuse edin.

Mitigations:
- Token'ları device fingerprint, IP range'leri ve client attestation'a bind edin; kısa expiration'lar uygulayın ve MFA ile refresh edin.
- Key'leri minimum scope ile sınırlandırın (tool access yok; uygulanabildiğinde read-only); anomaly durumunda rotate edin.
- Tüm traffic'i safety filter'ları, route başına quota'ları ve tenant isolation'ı uygulayan bir policy gateway arkasında server-side sonlandırın.
- Olağandışı usage pattern'lerini (ani spend spike'ları, atypical region'lar, UA string'leri) izleyin ve şüpheli session'ları otomatik olarak revoke edin.
- Uzun ömürlü static API key'ler yerine IdP'niz tarafından verilen mTLS veya signed JWT'leri tercih edin.

## Self-hosted LLM inference hardening

Confidential data için local bir LLM server çalıştırmak, cloud-hosted API'lerden farklı bir attack surface oluşturur: inference/debug endpoint'leri prompt'ları leak edebilir, serving stack genellikle bir reverse proxy açığa çıkarır ve GPU device node'ları geniş `ioctl()` surface'lerine erişim sağlar. Bir on-prem inference service'i değerlendiriyor veya deployment ediyorsanız en azından aşağıdaki noktaları inceleyin.

### Debug ve monitoring endpoint'leri üzerinden prompt leakage

Inference API'yi **multi-user hassas bir service** olarak değerlendirin. Debug veya monitoring route'ları prompt içeriklerini, slot state'ini, model metadata'sını veya internal queue information'ı açığa çıkarabilir. `llama.cpp` içinde `/slots` endpoint'i özellikle hassastır; çünkü per-slot state'i açığa çıkarır ve yalnızca slot inspection/management amacıyla kullanılır.

- Inference server'ın önüne bir reverse proxy koyun ve **default olarak deny uygulayın**.
- Client/UI tarafından ihtiyaç duyulan tam HTTP method + path combination'larını yalnızca allowlist'e alın.
- Backend'in kendisindeki introspection endpoint'lerini mümkün olduğunda disable edin; örneğin `llama-server --no-slots`.
- Reverse proxy'yi `127.0.0.1` adresine bind edin ve LAN üzerinde publish etmek yerine SSH local port forwarding gibi authenticated bir transport üzerinden expose edin.

nginx ile örnek allowlist:
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
### Ağsız rootless container'lar ve UNIX socket'leri

Inference daemon bir UNIX socket üzerinden dinlemeyi destekliyorsa, bunu TCP'ye tercih edin ve container'ı **network stack olmadan** çalıştırın:
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
Faydaları:
- `--network none`, gelen/giden TCP/IP maruziyetini ortadan kaldırır ve rootless container'ların aksi hâlde ihtiyaç duyacağı user-mode yardımcılarını engeller.
- Bir UNIX socket, ilk access-control katmanı olarak socket path'i üzerinde POSIX izinlerini/ACL'lerini kullanmanızı sağlar.
- `--userns=keep-id` ve rootless Podman, container breakout etkisini azaltır; çünkü container root'u host root'u değildir.
- Salt-okunur model mount'ları, container içinden model kurcalanması olasılığını azaltır.

### GPU device-node minimizasyonu

GPU destekli inference için `/dev/nvidia*` dosyaları, büyük driver `ioctl()` işleyicilerini ve potansiyel olarak paylaşılan GPU memory-management yollarını açığa çıkardıkları için yüksek değerli yerel saldırı yüzeyleridir.

- `/dev/nvidia*` dosyalarını world-writable bırakmayın.
- `nvidia`, `nvidiactl` ve `nvidia-uvm` erişimini `NVreg_DeviceFileUID/GID/Mode`, udev kuralları ve ACL'ler ile kısıtlayın; böylece yalnızca eşlenen container UID'si bunları açabilsin.
- Headless inference host'larında `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz modülleri blacklist'e alın.
- Runtime'ın inference startup sırasında fırsatçı biçimde `modprobe` çalıştırmasına izin vermek yerine, yalnızca gerekli modülleri boot sırasında preload edin.

Örnek:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Önemli bir inceleme noktası **`/dev/nvidia-uvm`**'dir. İş yükü açıkça `cudaMallocManaged()` kullanmasa bile, güncel CUDA runtime'ları yine de `nvidia-uvm` gerektirebilir. Bu device paylaşıldığı ve GPU virtual memory management işlemlerini gerçekleştirdiği için, bunu tenant'lar arası data-exposure surface olarak değerlendirin. Inference backend bunu destekliyorsa, Vulkan backend ilgi çekici bir trade-off olabilir; çünkü `nvidia-uvm`'yi container'a hiç expose etmeyebilir.

### Inference worker'ları için LSM confinement

AppArmor/SELinux/seccomp, inference process'i çevresinde defense in depth olarak kullanılmalıdır:

- Yalnızca gerçekten gerekli olan shared library'lere, model path'lerine, socket directory'sine ve GPU device node'larına izin verin.
- `sys_admin`, `sys_module`, `sys_rawio` ve `sys_ptrace` gibi high-risk capability'leri açıkça deny edin.
- Model directory'sini read-only tutun ve writable path'leri yalnızca runtime socket/cache directory'leriyle sınırlandırın.
- Denial log'larını monitor edin; model server veya post-exploitation payload beklenen davranışından kaçmaya çalıştığında bunlar faydalı detection telemetry sağlar.

GPU-backed worker için örnek AppArmor kuralları:
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
## Phantom Squatting: LLM Tarafından Halü sine Edilen Alan Adları Bir AI Supply-Chain Vektörü Olarak

Phantom squatting, **slopsquatting'in domain/URL eşdeğeridir**. LLM, mevcut olmayan bir paket adını halü sine etmek yerine, gerçek bir marka için makul görünen bir **portal, API, webhook, billing, SSO, download veya support domain'i** halü sine eder ve saldırgan, bir insan veya agent bu namespace'i kullanmadan önce onu kaydeder.

Bu önemlidir; çünkü birçok AI destekli iş akışında model çıktısı **güvenilir bir bağımlılık** olarak değerlendirilir:
- Geliştiriciler önerilen endpoint'i kodlarına veya CI/CD entegrasyonlarına yapıştırır.
- AI agent'ları documentation, schema, APK, ZIP veya webhook hedeflerini otomatik olarak fetch eder.
- Oluşturulan runbook veya dokümanlar, sahte URL'yi yetkiliymiş gibi içerebilir.

### Offensive workflow

1. **Halü sinasyon yüzeyini probe edin**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` veya `mobile app` portalları gibi gerçekçi workflow'lar hakkında markaya özgü sorular sorun.
2. **Adayları normalize edin**: oluşturulan URL'leri resolve edin, NXDOMAIN yanıtlarını parent registerable domain'e indirgeyin ve prompt ailelerinin duplicate kayıtlarını kaldırın. Prompt corpus'ları çeşitli kalmalıdır; örneğin **Jaccard similarity** kullanarak birbirine çok benzeyen kayıtları çıkarın.
3. **Öngörülebilir halü sinasyonlara öncelik verin**:
- **Thermal Hallucination Persistence (THP)**: aynı sahte domain, `T=0.1` gibi düşük temperature değerleri dahil olmak üzere farklı temperature değerlerinde görünür.
- **Cross-model consensus**: birden fazla LLM ailesi aynı sahte domain'i üretir.
4. Parent domain'i **register edin ve weaponize edin**; ardından phishing, sahte APK/ZIP download'ları, credential harvester'lar, malicious document'lar veya secret/webhook payload'larını toplayan API endpoint'leri host edin. **Pure domain-level hallucination'lar**, saldırgan tüm namespace'i kontrol ettiği için monetize edilmesi en kolay olanlardır; normalize edilen parent kayıtlı değilse subdomain/path hallucination'ları da abuse edilebilir.
5. **Zero-reputation window'dan yararlanın**: yeni kaydedilen domain'lerde genellikle blocklist geçmişi, URL reputation ve olgun telemetry bulunmaz; bu nedenle detection mekanizmaları yetişene kadar kontrolleri aşabilirler. Saldırganlar bu pencereyi yalnızca crawler'lara benign response döndürerek, redirect cloaking, CAPTCHA gate'leri veya gecikmeli payload staging kullanarak uzatabilir.

### Agent'lar için neden tehlikelidir

İnsan bir victim için sahte domain genellikle bir click ve başka bir action gerektirir. **Agentic workflow**'ta ise LLM hem **lure** hem de **executor** olabilir: agent halü sine edilmiş URL'yi alır, fetch eder, response'u parse eder ve ardından herhangi bir human review olmadan token'ları leak edebilir, instruction'ları execute edebilir, bir dependency download edebilir veya CI/CD'ye poisoned data gönderebilir.

### Practical attacker prompts

Yüksek verimli prompt'lar genellikle açık phishing lure'ları yerine normal enterprise task'ları andırır:
- “`<brand>` entegrasyonları için payment sandbox URL'si nedir?”
- “`<brand>` build notification'ları için hangi webhook endpoint'ini kullanmalıyım?”
- “`<brand>` için employee benefits / billing / SSO portalı nerede?”
- “`<brand>` için doğrudan Android APK veya desktop client download'ını ver.”

### Defensive inversion

Bunu yalnızca bir prompt-injection problemi olarak değil, proaktif bir domain-monitoring problemi olarak ele alın:
- Bir **brand prompt corpus** oluşturun ve kullanıcılarınızın/agent'larınızın dayandığı LLM'leri periyodik olarak probe edin.
- Halü sine edilmiş URL'leri saklayın ve hangilerinin temperature/model'lar arasında stabil kaldığını takip edin.
- **Adversarial Exploitation Window (AEW)** değerini takip edin: ilk halü sinasyon ile saldırganın registration işlemi arasındaki süre. Pozitif AEW, defender'ların weaponization'dan önce pre-register, sinkhole veya pre-block yapabileceği anlamına gelir.
- Parent domain'ler için **NXDOMAIN → registered** geçişlerini izleyin.
- Registration sonrasında registrar, creation date, nameserver, privacy shielding, page content, screenshot, parked-page status ve brand-asset similarity bilgilerini triage edin.
- Agent'ların/geliştiricilerin **LLM tarafından oluşturulan domain'lere varsayılan olarak güvenmemesi** için policy gate'leri ekleyin: ilk kullanımdan önce allowlist, ownership validation, CT/RDAP check veya human approval zorunlu kılın.

Bu durum aynı anda birkaç AI risk kategorisine uyar: **AI supply-chain attack**, **insecure model output** ve agent'ların halü sine edilmiş URL'yi otonom olarak tüketmesi durumunda **rogue actions**.

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
