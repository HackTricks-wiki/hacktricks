# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp, AI sistemlerini etkileyebilecek en önemli 10 machine learning vulnerability'sini belirlemiştir. Bu vulnerability'ler data poisoning, model inversion ve adversarial attacks dahil olmak üzere çeşitli security sorunlarına yol açabilir. Bu vulnerability'leri anlamak, güvenli AI sistemleri oluşturmak için kritik öneme sahiptir.

En güncel ve ayrıntılı en önemli 10 machine learning vulnerability listesi için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine başvurun.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Bir saldırgan, modelin yanlış karar vermesini sağlamak için **gelen veriye** küçük ve çoğu zaman görünmez değişiklikler ekler.\
*Örnek*: Birkaç boya lekesi, self-driving car'ın bir stop işaretini hız sınırı işareti olarak "görmesine" neden olur.

- **Data Poisoning Attack**: **Training set**, modele zararlı kuralları öğretecek kötü örneklerle kasıtlı olarak kirletilir.\
*Örnek*: Bir antivirus training corpus'unda malware binary'leri "benign" olarak etiketlenir ve benzer malware'lerin daha sonra gözden kaçmasına izin verilir.

- **Model Inversion Attack**: Bir saldırgan, çıktıları sorgulayarak orijinal girdilerin hassas özelliklerini yeniden oluşturan bir **reverse model** oluşturur.\
*Örnek*: Bir cancer-detection model'inin tahminlerinden bir hastanın MRI görüntüsünü yeniden oluşturmak.

- **Membership Inference Attack**: Saldırgan, güven düzeylerindeki farklılıkları tespit ederek **belirli bir kaydın** training sırasında kullanılıp kullanılmadığını test eder.\
*Örnek*: Bir kişinin banka işleminin fraud-detection model'inin training data'sında bulunduğunu doğrulamak.

- **Model Theft**: Tekrarlanan sorgular, saldırganın karar sınırlarını öğrenmesine ve **modelin davranışını clone etmesine** (ve IP'sini ele geçirmesine) olanak tanır.\
*Örnek*: Bir ML-as-a-Service API'sinden near-equivalent bir local model oluşturmak için yeterli sayıda Q&A çifti toplamak.

- **AI Supply-Chain Attack**: **ML pipeline** içindeki herhangi bir component'in (data, libraries, pre-trained weights, CI/CD) ele geçirilmesi, downstream modellerin bozulmasına neden olur.\
*Örnek*: Bir model-hub üzerindeki poisoned dependency, birçok app'e backdoored bir sentiment-analysis model'i yükler.

- **Transfer Learning Attack**: Malicious logic, **pre-trained model** içine yerleştirilir ve victim'ın task'ı üzerinde fine-tuning işleminden sonra da varlığını sürdürür.\
*Örnek*: Gizli bir trigger içeren vision backbone, medical imaging için uyarlandıktan sonra da label'ları değiştirmeye devam eder.

- **Model Skewing**: Subtly biased veya yanlış etiketlenmiş data, saldırganın amacını destekleyecek şekilde **modelin output'larını kaydırır**.\
*Örnek*: "Clean" spam email'lerini ham olarak etiketleyerek bir spam filter'ın gelecekteki benzer email'lerine izin vermesini sağlamak.

- **Output Integrity Attack**: Saldırgan, modelin kendisini değil, **model predictions'larını transit sırasında değiştirerek** downstream sistemleri kandırır.\
*Örnek*: File-quarantine aşaması görmeden önce bir malware classifier'ın "malicious" kararını "benign" olarak değiştirmek.

- **Model Poisoning** --- Genellikle write access elde edildikten sonra **model parameters** üzerinde doğrudan ve hedefli değişiklikler yapılarak davranışın değiştirilmesi.\
*Örnek*: Belirli kartlardan yapılan işlemlerin her zaman onaylanması için production'daki bir fraud-detection model'inin weights'lerini değiştirmek.


## Google SAIF Risks

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) framework'ü AI sistemleriyle ilişkili çeşitli riskleri açıklar:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Malicious actors, accuracy'yi düşürmek, backdoor yerleştirmek veya sonuçları çarpıtmak için training/tuning data'yı değiştirir ya da data ekler; bu durum tüm data-lifecycle boyunca model integrity'sini zayıflatır.

- **Unauthorized Training Data**: Copyright'li, hassas veya izin alınmamış dataset'lerin alınması, modelin kullanmasına izin verilmeyen datadan öğrenmesi nedeniyle yasal, etik ve performance sorumlulukları oluşturur.

- **Model Source Tampering**: Training öncesinde veya sırasında model code'unun, dependencies'lerin veya weights'lerin supply-chain ya da insider manipulation yoluyla değiştirilmesi, retraining sonrasında bile kalıcı olan gizli logic yerleştirebilir.

- **Excessive Data Handling**: Zayıf data-retention ve governance kontrolleri, sistemlerin gereğinden fazla personal data saklamasına veya işlemesine yol açarak exposure ve compliance risk'ini artırır.

- **Model Exfiltration**: Saldırganlar model files/weights'leri çalar; bu durum intellectual property kaybına neden olur ve copy-cat service'leri veya follow-on attacks'i mümkün kılar.

- **Model Deployment Tampering**: Adversaries, model artifacts'lerini veya serving infrastructure'ını değiştirerek çalışan modelin vetted version'dan farklı olmasını ve bunun sonucunda behaviour'ın değişmesini sağlayabilir.

- **Denial of ML Service**: API'leri flood'lamak veya "sponge" inputs göndermek compute/energy kaynaklarını tüketebilir ve modeli offline duruma getirebilir; bu, klasik DoS attacks'e benzer.

- **Model Reverse Engineering**: Saldırganlar çok sayıda input-output pair toplayarak modeli clone edebilir veya distil edebilir; bu da imitation products ve özelleştirilmiş adversarial attacks için kaynak oluşturur.

- **Insecure Integrated Component**: Vulnerable plugin'ler, agent'ler veya upstream service'ler, saldırganların AI pipeline içine code inject etmesine veya privilege escalation gerçekleştirmesine izin verir.

- **Prompt Injection**: System intent'i geçersiz kılan instruction'ları gizlice iletmek ve modelin istenmeyen command'ler çalıştırmasını sağlamak için doğrudan veya dolaylı prompt'lar oluşturmak.

- **Model Evasion**: Dikkatle tasarlanmış input'lar, modelin yanlış classification yapmasına, hallucination üretmesine veya izin verilmeyen content output etmesine neden olarak safety ve trust'ı zedeler.

- **Sensitive Data Disclosure**: Model, training data'sından veya user context'inden private ya da confidential information açığa çıkararak privacy ve regulations'ı ihlal eder.

- **Inferred Sensitive Data**: Model, hiç sağlanmamış personal attribute'ları çıkarabilir ve inference yoluyla yeni privacy zararları oluşturabilir.

- **Insecure Model Output**: Sanitize edilmemiş responses, harmful code'u, misinformation'ı veya inappropriate content'i user'lara ya da downstream sistemlere aktarır.

- **Rogue Actions**: Autonomously-integrated agent'ler, yeterli user oversight olmadan istenmeyen gerçek dünya operations'larını (file writes, API calls, purchases vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve azaltmak için kapsamlı bir framework sunar. Adversaries'lerin AI modellerine karşı kullanabileceği çeşitli attack technique'leri ve tactic'leri, ayrıca farklı attacks gerçekleştirmek için AI sistemlerinin nasıl kullanılacağını kategorilere ayırır.<sup>[[3]](#references)</sup>

## LLMJacking (Cloud-hosted LLM Access Token Theft & Resale)

Saldırganlar active session token'larını veya cloud API credential'larını çalarak ücretli, cloud-hosted LLM'leri izinsiz şekilde çağırır. Access çoğunlukla victim'ın account'unu öne çıkaran reverse proxy'ler aracılığıyla yeniden satılır; örneğin "oai-reverse-proxy" deployment'ları. Sonuçlar arasında financial loss, policy dışı model misuse ve victim tenant'a atfedilme bulunur.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP'ler:
- Infected developer machine'lerden veya browser'lardan token'ları toplayın; CI/CD secret'larını çalın; leaked cookie'ler satın alın.<sup>[[5]](#references)</sup>
- Genuine provider'a request'leri forward eden, upstream key'i gizleyen ve çok sayıda customer'ı multiplex eden bir reverse proxy kurun.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Enterprise guardrail'larını ve rate limit'lerini bypass etmek için direct base-model endpoint'lerini abuse edin.<sup>[[4]](#references)</sup>

Mitigations:
- Token'ları device fingerprint, IP range'leri ve client attestation'a bağlayın; kısa expiration sürelerini zorunlu kılın ve MFA ile refresh edin.
- Key'leri minimum scope ile sınırlandırın (tool access olmasın, uygun durumlarda read-only); anomaly durumunda rotate edin.
- Tüm traffic'i, safety filter'larını, route başına quota'ları ve tenant isolation'ı uygulayan bir policy gateway arkasında server-side terminate edin.
- Olağandışı usage pattern'lerini (ani spend spike'ları, alışılmadık region'lar, UA string'leri) izleyin ve şüpheli session'ları otomatik olarak revoke edin.
- Uzun ömürlü static API key'ler yerine IdP'niz tarafından verilen mTLS veya signed JWT'leri tercih edin.

## Self-hosted LLM inference hardening

Confidential data için local bir LLM server çalıştırmak, cloud-hosted API'lerden farklı bir attack surface oluşturur: inference/debug endpoint'leri prompt'ları leak edebilir, serving stack genellikle bir reverse proxy açığa çıkarır ve GPU device node'ları geniş `ioctl()` surface'lerine erişim sağlar. Bir on-prem inference service'i değerlendiriyor veya deploy ediyorsanız en azından aşağıdaki noktaları inceleyin.<sup>[[8]](#references)</sup>

### Debug ve monitoring endpoint'leri üzerinden prompt leakage

Inference API'yi **multi-user sensitive service** olarak değerlendirin. Debug veya monitoring route'ları prompt content'lerini, slot state'i, model metadata'sını veya internal queue information'ı açığa çıkarabilir. `llama.cpp` içinde `/slots` endpoint'i özellikle hassastır; çünkü per-slot state'i açığa çıkarır ve yalnızca slot inspection/management için tasarlanmıştır.<sup>[[8]](#references)</sup>

- Inference server'ın önüne bir reverse proxy koyun ve **default olarak deny uygulayın**.
- Client/UI tarafından gereken tam HTTP method + path kombinasyonlarını yalnızca allowlist'e alın.
- Backend'in kendisindeki introspection endpoint'lerini mümkün olduğunda devre dışı bırakın; örneğin `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Reverse proxy'yi `127.0.0.1` adresine bind edin ve LAN'da yayınlamak yerine SSH local port forwarding gibi authenticated bir transport üzerinden expose edin.

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
### Ağ olmadan ve UNIX sockets ile rootless containers

Inference daemon bir UNIX socket üzerinde dinlemeyi destekliyorsa, TCP yerine bunu tercih edin ve container'ı **ağ yığını olmadan** çalıştırın:<sup>[[8]](#references)</sup>
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
- `--network none`, gelen/giden TCP/IP maruziyetini ortadan kaldırır ve rootless container'ların aksi takdirde ihtiyaç duyacağı user-mode yardımcılarını önler.
- UNIX socket, ilk access-control katmanı olarak socket path üzerinde POSIX permissions/ACLs kullanmanıza olanak tanır.
- `--userns=keep-id` ve rootless Podman, container breakout etkisini azaltır; çünkü container root'u host root'u değildir.
- Read-only model mount'ları, container içinden model tampering olasılığını azaltır.

Kalıcı deployment'lar için aynı kısıtlamalar Podman Quadlet unit'leri olarak ifade edilebilir. GPU erişimi Container Device Interface üzerinden devrediliyorsa, her accelerator node'u açığa çıkarmak yerine CDI device specification'ı mümkün olduğunca dar tutun.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU device-node minimizasyonu

GPU destekli inference için `/dev/nvidia*` dosyaları, büyük driver `ioctl()` handler'larını ve potansiyel olarak paylaşılan GPU memory-management path'lerini açığa çıkardıkları için yüksek değerli yerel attack surface'lerdir.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` dosyalarını world writable bırakmayın.
- `nvidia`, `nvidiactl` ve `nvidia-uvm` erişimini `NVreg_DeviceFileUID/GID/Mode`, udev rules ve ACLs kullanarak yalnızca mapped container UID bunları açabilecek şekilde kısıtlayın.
- Headless inference host'larında `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz module'leri blacklist'e alın.
- Runtime'ın inference startup sırasında bunları fırsatçı biçimde `modprobe` etmesine izin vermek yerine yalnızca gerekli module'leri boot sırasında preload edin.

Örnek:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Önemli bir inceleme noktası **`/dev/nvidia-uvm`**'dir. Workload açıkça `cudaMallocManaged()` kullanmasa bile, güncel CUDA runtime'ları yine de `nvidia-uvm` gerektirebilir. Bu cihaz paylaşıldığından ve GPU sanal bellek yönetimini gerçekleştirdiğinden, bunu tenant'lar arası veri ifşası yüzeyi olarak değerlendirin. Inference backend destekliyorsa, Vulkan backend ilginç bir trade-off olabilir; çünkü `nvidia-uvm`'nin container'a hiç açılmasını önleyebilir.<sup>[[8]](#references)</sup>

### Inference worker'ları için LSM confinement

Inference process'i çevresinde defense in depth olarak AppArmor/SELinux/seccomp kullanılmalıdır:<sup>[[8]](#references)</sup>

- Yalnızca gerçekten gerekli olan shared library'lere, model path'lerine, socket directory'sine ve GPU device node'larına izin verin.
- `sys_admin`, `sys_module`, `sys_rawio` ve `sys_ptrace` gibi yüksek riskli capability'leri açıkça reddedin.
- Model directory'sini read-only tutun ve writable path'leri yalnızca runtime socket/cache directory'leriyle sınırlandırın.
- Denial log'larını izleyin; bunlar model server veya post-exploitation payload'ı beklenen davranışından kaçmaya çalıştığında faydalı detection telemetry sağlar.

GPU destekli bir worker için örnek AppArmor kuralları:
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
## Phantom Squatting: LLM-Hallucinated Domains as an AI Tedarik Zinciri Vektörü

Phantom squatting, **slopsquatting'in domain/URL karşılığıdır**. Var olmayan bir paket adını hallucinate etmek yerine LLM, gerçek bir marka için makul görünen bir **portal, API, webhook, billing, SSO, download veya support domain'ini** hallucinate eder ve saldırgan, bir insan veya agent bunu kullanmadan önce bu namespace'i kaydeder.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Bu önemlidir; çünkü birçok AI destekli workflow'da model çıktısı **güvenilir bir dependency** olarak kabul edilir:
- Developer'lar önerilen endpoint'i code'a veya CI/CD integration'larına yapıştırır.
- AI agent'lar documentation, schema, APK, ZIP veya webhook hedeflerini otomatik olarak fetch eder.
- Oluşturulan runbook'lar veya dokümanlar sahte URL'yi yetkiliymiş gibi içerebilir.

### Offensive workflow

1. **Hallucination yüzeyini probe edin**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` veya `mobile app` portalları gibi gerçekçi workflow'lar hakkında markaya özgü sorular sorun.<sup>[[12]](#references)</sup>
2. **Adayları normalize edin**: oluşturulan URL'leri resolve edin, NXDOMAIN yanıtlarını parent registerable domain'e indirgeyin ve prompt ailelerindeki tekrarları kaldırın. Prompt corpus çeşitli tutulmalıdır; örneğin **Jaccard similarity** kullanarak birbirine çok benzeyen tekrarları çıkarın.
3. **Öngörülebilir hallucination'lara öncelik verin**:
- **Thermal Hallucination Persistence (THP)**: aynı sahte domain, `T=0.1` gibi düşük sıcaklıklar dahil olmak üzere farklı sıcaklıklarda görünür.
- **Cross-model consensus**: birden fazla LLM ailesi aynı sahte domain'i üretir.
4. Parent domain'i **register edin ve weaponize edin**; ardından phishing, sahte APK/ZIP download'ları, credential harvester'lar, malicious document'lar veya secret/webhook payload'larını toplayan API endpoint'leri host edin. **Salt domain-level hallucination'lar**, saldırgan tüm namespace'i kontrol ettiği için monetize edilmesi en kolay olanlardır; normalize edilmiş parent kayıtlı değilse subdomain/path hallucination'ları da abuse edilebilir.
5. **Zero-reputation window'ı exploit edin**: yeni kaydedilen domain'lerde genellikle blocklist geçmişi, URL reputation'ı ve olgun telemetry bulunmaz; bu nedenle detection'lar yetişene kadar kontrolleri aşabilirler. Saldırganlar bu pencereyi yalnızca crawler'lara benign yanıtlar vererek, redirect cloaking, CAPTCHA gate'leri veya payload staging'i geciktirerek uzatabilir.

### Agent'lar için neden tehlikelidir

İnsan mağdur açısından sahte domain genellikle bir click ve başka bir action gerektirir. **Agentic workflow** açısından ise LLM hem **lure** hem de **executor** olabilir: agent hallucinate edilmiş URL'yi alır, URL'yi fetch eder, yanıtı parse eder ve ardından herhangi bir human review olmadan token'ları leak edebilir, instruction'ları execute edebilir, bir dependency download edebilir veya poisoned data'yı CI/CD'ye gönderebilir.<sup>[[12]](#references)</sup>

### Pratik attacker prompt'ları

Yüksek verimli prompt'lar genellikle açık phishing lure'ları yerine normal enterprise görevleri gibi görünür:<sup>[[12]](#references)</sup>
- “`<brand>` integration'ları için payment sandbox URL'si nedir?”
- “`<brand>` build notification'ları için hangi webhook endpoint'ini kullanmalıyım?”
- “`<brand>` için employee benefits / billing / SSO portalı nerede?”
- “`<brand>` için doğrudan Android APK veya desktop client download'ını ver.”

### Defensive inversion

Bunu yalnızca bir prompt-injection problemi olarak değil, proaktif bir domain-monitoring problemi olarak ele alın:<sup>[[12]](#references)</sup>
- Bir **brand prompt corpus** oluşturun ve kullanıcılarınızın/agent'larınızın güvendiği LLM'leri düzenli olarak probe edin.
- Hallucinate edilmiş URL'leri saklayın ve hangilerinin temperature/model'lar arasında stabil olduğunu takip edin.
- **Adversarial Exploitation Window (AEW)** değerini takip edin: ilk hallucination ile saldırganın registration'ı arasındaki süre. Pozitif AEW, defender'ların weaponization'dan önce domain'i pre-register etmesine, sinkhole etmesine veya pre-block etmesine olanak tanır.
- Parent domain'lerdeki **NXDOMAIN → registered** geçişlerini izleyin.
- Registration sonrasında registrar'ı, creation date'i, nameserver'ları, privacy shielding'i, page content'i, screenshot'ları, parked-page status'ını ve brand-asset similarity'yi triage edin.
- Agent'ların/developer'ların **LLM-generated domain'lere varsayılan olarak güvenmemesi** için policy gate'leri ekleyin: ilk kullanım öncesinde allowlist, ownership validation, CT/RDAP check'leri veya human approval zorunlu kılın.

Bu durum aynı anda birkaç AI risk kategorisine uyar: **AI supply-chain attack**, **insecure model output** ve agent'ların hallucinate edilmiş URL'yi otonom olarak tüketmesi durumunda **rogue actions**.

## References

- [1] [OWASP Makine Öğrenimi Güvenlik Açıkları Top 10'u](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) - Riskler](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Threat Matrix](https://atlas.mitre.org/)
- [4] [Unit 42 - Code Assistant LLM'lerinin Riskleri: Zararlı İçerik, Kötüye Kullanım ve Aldatma](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig - LLMjacking: Yeni AI Saldırısında Kullanılan Çalınmış Cloud Credential'ları](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme overview - The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (çalınmış LLM erişiminin yeniden satışı)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - On-premise, düşük ayrıcalıklı bir LLM server'ının deployment'ına deep dive](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlet'leri: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 - Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket - Slopsquatting: AI Hallucination'ları Yeni Bir Supply Chain Attack Sınıfını Nasıl Besliyor?](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
