# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp, AI sistemlerini etkileyebilecek en önemli 10 machine learning vulnerability'sini belirlemiştir. Bu vulnerability'ler data poisoning, model inversion ve adversarial attacks dahil olmak üzere çeşitli security issues'a yol açabilir. Bu vulnerability'leri anlamak, güvenli AI sistemleri oluşturmak için kritik öneme sahiptir.

En güncel ve ayrıntılı en önemli 10 machine learning vulnerability listesi için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine bakın.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Bir attacker, modelin yanlış karar vermesini sağlamak için **incoming data** üzerine küçük ve çoğu zaman görünmez değişiklikler ekler.\
*Örnek*: Birkaç boya lekesi, self-driving car'ın bir stop işaretini speed-limit işareti olarak "görmesine" neden olur.

- **Data Poisoning Attack**: **Training set**, kötü örneklerle kasıtlı olarak kirletilir ve modele zararlı kurallar öğretilir.\
*Örnek*: Malware binary'leri bir antivirus training corpus'unda yanlışlıkla "benign" olarak etiketlenir ve benzer malware'lerin daha sonra gözden kaçmasına izin verilir.

- **Model Inversion Attack**: Bir attacker, çıktıları sorgulayarak orijinal input'ların hassas özelliklerini yeniden oluşturan bir **reverse model** oluşturur.\
*Örnek*: Bir cancer-detection modelinin tahminlerinden bir hastanın MRI görüntüsünü yeniden oluşturmak.

- **Membership Inference Attack**: Adversary, confidence farklılıklarını tespit ederek **specific record**'un training sırasında kullanılıp kullanılmadığını test eder.\
*Örnek*: Bir kişinin bank transaction'ının fraud-detection modelinin training data'sında bulunduğunu doğrulamak.

- **Model Theft**: Tekrarlanan sorgulama, attacker's decision boundary'leri öğrenmesini ve **model's behavior**'ını (ve IP'sini) **clone** etmesini sağlar.\
*Örnek*: Bir ML-as-a-Service API'den yeterli sayıda Q&A çifti toplayarak neredeyse eşdeğer bir local model oluşturmak.

- **AI Supply-Chain Attack**: Downstream modelleri bozmak için **ML pipeline** içindeki herhangi bir component'i (data, libraries, pre-trained weights, CI/CD) compromise etmek.\
*Örnek*: Bir model-hub üzerindeki poisoned dependency, birçok app'e backdoored sentiment-analysis model yükler.

- **Transfer Learning Attack**: Malicious logic, **pre-trained model** içine yerleştirilir ve victim'ın task'ı üzerinde fine-tuning yapılmasından sonra da varlığını sürdürür.\
*Örnek*: Gizli bir trigger içeren vision backbone, medical imaging için uyarlandıktan sonra da label'ları değiştirmeye devam eder.

- **Model Skewing**: İnce şekilde biased veya yanlış etiketlenmiş data, attacker's agenda'sını desteklemek üzere **model's outputs**'unu değiştirir.\
*Örnek*: "Temiz" spam email'lerini ham olarak etiketleyip eklemek ve böylece spam filter'ın gelecekteki benzer email'lerine izin vermesini sağlamak.

- **Output Integrity Attack**: Attacker, modelin kendisini değil, **model predictions**'ını transit sırasında değiştirerek downstream sistemleri kandırır.\
*Örnek*: File-quarantine aşaması görmeden önce bir malware classifier'ın "malicious" kararını "benign" olarak değiştirmek.

- **Model Poisoning** --- Genellikle write access elde edildikten sonra **model parameters** üzerinde doğrudan ve hedefli değişiklikler yaparak davranışı değiştirmek.\
*Örnek*: Production ortamındaki bir fraud-detection modelinin weights'lerini, belirli card'lardan yapılan transaction'ların her zaman onaylanacağı şekilde değiştirmek.


## Google SAIF Riskleri

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) framework'ü, AI sistemleriyle ilişkili çeşitli riskleri açıklar:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Malicious actors, accuracy'yi düşürmek, backdoor yerleştirmek veya sonuçları saptırmak için training/tuning data'sını değiştirir ya da data ekler; bu durum tüm data-lifecycle boyunca model integrity'sini zayıflatır.

- **Unauthorized Training Data**: Copyright'li, hassas veya izin alınmamış dataset'leri içeri almak, modelin kullanmasına izin verilmeyen data'dan öğrenmesi nedeniyle hukuki, etik ve performance riskleri oluşturur.

- **Model Source Tampering**: Training öncesinde veya sırasında model code'u, dependencies'leri veya weights'leri üzerinde yapılan supply-chain ya da insider manipulation, retraining sonrasında bile varlığını sürdüren gizli logic yerleştirebilir.

- **Excessive Data Handling**: Zayıf data-retention ve governance kontrolleri, sistemlerin gereğinden fazla personal data depolamasına veya işlemesine yol açarak exposure ve compliance riskini artırır.

- **Model Exfiltration**: Attackers, model files/weights'lerini çalarak intellectual property kaybına neden olur ve copy-cat services veya follow-on attacks gerçekleştirilmesini mümkün kılar.

- **Model Deployment Tampering**: Adversaries, model artifacts'larını veya serving infrastructure'ını değiştirerek çalışan modelin doğrulanmış sürümden farklı olmasını sağlayabilir ve böylece behaviour'ı değiştirebilir.

- **Denial of ML Service**: API'leri flood etmek veya “sponge” inputs göndermek, compute/energy kaynaklarını tüketerek modeli offline bırakabilir; bu, klasik DoS attacks'e benzer.

- **Model Reverse Engineering**: Büyük miktarda input-output pair toplayan attackers, modeli clone veya distil edebilir; bu da imitation products ve özelleştirilmiş adversarial attacks için kaynak sağlar.

- **Insecure Integrated Component**: Vulnerable plugins, agents veya upstream services, attacker'ların AI pipeline içine code inject etmesine veya privilege escalation yapmasına olanak tanır.

- **Prompt Injection**: System intent'i geçersiz kılan instructions'ları doğrudan veya dolaylı olarak gizlice iletmek için prompt'lar hazırlamak ve modelin istenmeyen commands gerçekleştirmesini sağlamak.

- **Model Evasion**: Dikkatle tasarlanmış inputs, modelin yanlış classification yapmasını, hallucinate etmesini veya izin verilmeyen content üretmesini tetikleyerek safety ve trust'ı zayıflatır.

- **Sensitive Data Disclosure**: Model, training data'sından veya user context'inden private ya da confidential information açığa çıkararak privacy ve regulations'ı ihlal eder.

- **Inferred Sensitive Data**: Model, hiç sağlanmamış personal attributes'ları çıkarır ve inference yoluyla yeni privacy zararları oluşturur.

- **Insecure Model Output**: Sanitize edilmemiş responses, harmful code, misinformation veya inappropriate content'i users'a ya da downstream systems'a aktarır.

- **Rogue Actions**: Autonomously-integrated agents, yeterli user oversight olmadan istenmeyen real-world operations (file writes, API calls, purchases vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve azaltmak için kapsamlı bir framework sağlar. Çeşitli attack techniques ve tactics'lerini kategorilere ayırır; adversaries'in AI models'a karşı kullanabileceği tekniklerin yanı sıra AI systems'ın farklı attacks gerçekleştirmek için nasıl kullanılabileceğini de ele alır.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Attackers, active session tokens veya cloud API credentials'ları çalar ve ücretli, cloud-hosted LLM'leri yetkisiz şekilde çağırır. Access çoğunlukla victim'ın account'unu öne çıkaran reverse proxy'ler aracılığıyla yeniden satılır; örneğin "oai-reverse-proxy" deployments. Sonuçlar arasında financial loss, policy dışı model misuse ve victim tenant'a atfedilme bulunur.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

TTPs:
- Infected developer machines veya browsers'dan tokens toplamak; CI/CD secrets çalmak; leaked cookies satın almak.<sup>[[5]](#references)</sup>
- Genuine provider'a requests forward eden, upstream key'i gizleyen ve birçok customer'ı multiplex eden bir reverse proxy kurmak.<sup>[[5]](#references)[[7]](#references)</sup>
- Enterprise guardrails ve rate limits'i bypass etmek için direct base-model endpoints'lerini kötüye kullanmak.<sup>[[4]](#references)</sup>

Mitigations:
- Tokens'ları device fingerprint, IP ranges ve client attestation'a bağlamak; kısa expiration süreleri uygulamak ve MFA ile refresh etmek.
- Keys'leri minimum kapsamla sınırlandırmak (tool access olmadan, uygun durumlarda read-only); anomaly durumunda rotate etmek.
- Tüm traffic'i safety filters, route başına quotas ve tenant isolation uygulayan bir policy gateway arkasında server-side sonlandırmak.
- Unusual usage patterns'ı (ani spend spikes, atypical regions, UA strings) izlemek ve suspicious sessions'ları otomatik olarak revoke etmek.
- Uzun ömürlü static API keys yerine IdP'niz tarafından verilen mTLS veya signed JWTs kullanmayı tercih etmek.

## Self-hosted LLM inference hardening

Confidential data için local LLM server çalıştırmak, cloud-hosted APIs'den farklı bir attack surface oluşturur: inference/debug endpoints prompt'ları leak edebilir, serving stack genellikle bir reverse proxy açığa çıkarır ve GPU device nodes geniş `ioctl()` surfaces'larına erişim sağlar. Bir on-prem inference service'i değerlendiriyor veya deploy ediyorsanız en azından aşağıdaki noktaları inceleyin.<sup>[[8]](#references)</sup>

### Debug ve monitoring endpoints üzerinden prompt leakage

Inference API'yi **multi-user sensitive service** olarak ele alın. Debug veya monitoring routes, prompt contents, slot state, model metadata ya da internal queue information açığa çıkarabilir. `llama.cpp` içinde `/slots` endpoint'i özellikle hassastır; slot başına state'i açığa çıkarır ve yalnızca slot inspection/management için tasarlanmıştır.<sup>[[8]](#references)</sup>

- Inference server'ın önüne bir reverse proxy koyun ve **deny by default** uygulayın.
- Client/UI tarafından ihtiyaç duyulan tam HTTP method + path kombinasyonlarını yalnızca allowlist'e ekleyin.
- Backend'in kendisindeki introspection endpoints'lerini mümkün olduğunda devre dışı bırakın; örneğin `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Reverse proxy'yi `127.0.0.1` adresine bind edin ve LAN üzerinde yayınlamak yerine SSH local port forwarding gibi authenticated bir transport üzerinden expose edin.

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
### Ağ olmadan rootless container'lar ve UNIX socket'leri

Inference daemon bir UNIX socket üzerinden dinlemeyi destekliyorsa, TCP yerine bunu tercih edin ve container'ı **ağ yığını olmadan** çalıştırın:<sup>[[8]](#references)</sup>
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
- `--network none`, gelen/giden TCP/IP maruziyetini kaldırır ve rootless container'ların aksi durumda ihtiyaç duyacağı user-mode yardımcılarını önler.
- Bir UNIX socket, ilk erişim kontrol katmanı olarak socket path üzerinde POSIX permissions/ACLs kullanmanıza olanak tanır.
- `--userns=keep-id` ve rootless Podman, container breakout etkisini azaltır; çünkü container root'u host root'u değildir.
- Read-only model mount'ları, container içinden model tampering olasılığını azaltır.

### GPU device-node minimization

GPU-backed inference için `/dev/nvidia*` dosyaları, geniş driver `ioctl()` handler'larını ve potansiyel olarak paylaşılan GPU memory-management yollarını açığa çıkardıkları için yüksek değerli yerel attack surface'lerdir.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` dosyalarını world writable bırakmayın.
- `nvidia`, `nvidiactl` ve `nvidia-uvm` erişimini `NVreg_DeviceFileUID/GID/Mode`, udev rules ve ACLs kullanarak yalnızca mapped container UID bunları açabilecek şekilde kısıtlayın.
- Headless inference host'larında `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz modülleri blacklist'e alın.
- Runtime'ın inference startup sırasında bunları fırsatçı biçimde `modprobe` etmesine izin vermek yerine yalnızca gerekli modülleri boot sırasında preload edin.

Örnek:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Önemli bir inceleme noktası **`/dev/nvidia-uvm`**'dir. Workload açıkça `cudaMallocManaged()` kullanmasa bile, güncel CUDA runtime'ları yine de `nvidia-uvm` gerektirebilir. Bu device paylaşımlı olduğundan ve GPU virtual memory management işlemlerini gerçekleştirdiğinden, cross-tenant data-exposure surface olarak değerlendirin. Inference backend destekliyorsa, Vulkan backend ilginç bir trade-off olabilir; çünkü `nvidia-uvm`'yi container'a hiç expose etmeyi gerektirmeyebilir.<sup>[[8]](#references)</sup>

### Inference worker'ları için LSM izolasyonu

Inference process'i etrafında defense in depth olarak AppArmor/SELinux/seccomp kullanılmalıdır:<sup>[[8]](#references)</sup>

- Yalnızca gerçekten gerekli olan shared library'lere, model path'lerine, socket directory'sine ve GPU device node'larına izin verin.
- `sys_admin`, `sys_module`, `sys_rawio` ve `sys_ptrace` gibi yüksek riskli capability'leri açıkça deny edin.
- Model directory'sini read-only tutun ve writable path'leri yalnızca runtime socket/cache directory'leriyle sınırlandırın.
- Denial log'larını izleyin; bunlar model server veya bir post-exploitation payload beklenen davranışından kaçmaya çalıştığında yararlı detection telemetry sağlar.

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
## Phantom Squatting: AI Tarafından Halüsinasyon Görülen Alan Adları ile AI Tedarik Zinciri Vektörü

Phantom squatting, **slopsquatting'in alan adı/URL eşdeğeridir**. LLM, var olmayan bir paket adını halüsinasyon yoluyla üretmek yerine gerçek bir marka için makul görünen bir **portal, API, webhook, billing, SSO, download veya support alan adı** üretir ve saldırgan, bir insan veya agent bu alan adını kullanmadan önce ilgili namespace'i kaydeder.<sup>[[12]](#references)[[13]](#references)</sup>

Bu önemlidir çünkü birçok AI destekli workflow'da model çıktısı **güvenilir bir dependency** olarak kabul edilir:
- Developer'lar önerilen endpoint'i koda veya CI/CD entegrasyonlarına yapıştırır.
- AI agent'ları documentation, schema, APK, ZIP veya webhook hedeflerini otomatik olarak fetch eder.
- Oluşturulan runbook'lar veya dokümanlar sahte URL'yi authoritative bir URL gibi içerebilir.

### Offensive workflow

1. **Hallüsinasyon yüzeyini probe edin**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` veya `mobile app` portalları gibi gerçekçi workflow'lar hakkında marka odaklı sorular sorun.<sup>[[12]](#references)</sup>
2. **Adayları normalize edin**: oluşturulan URL'leri resolve edin, NXDOMAIN yanıtlarını kaydedilebilir parent domain'e indirgeyin ve prompt ailelerinin duplicate'lerini kaldırın. Prompt corpus'ları çeşitli kalmalıdır; örneğin **Jaccard similarity** kullanarak birbirine çok yakın duplicate'leri çıkarın.
3. **Öngörülebilir halüsinasyonlara öncelik verin**:
- **Thermal Hallucination Persistence (THP)**: aynı sahte domain, `T=0.1` gibi düşük temperature değerleri dahil olmak üzere farklı temperature değerlerinde görünür.
- **Cross-model consensus**: birden fazla LLM ailesi aynı sahte domain'i üretir.
4. Parent domain'i **register edin ve weaponize edin**; ardından phishing, sahte APK/ZIP download'ları, credential harvester'lar, malicious document'lar veya secret/webhook payload toplayan API endpoint'leri host edin. **Pure domain-level hallucination'lar**, saldırganın tüm namespace'i kontrol etmesi nedeniyle monetize edilmesi en kolay olanlardır; subdomain/path hallucination'ları da normalize edilmiş parent domain register edilmemişse kötüye kullanılabilir.
5. **Zero-reputation window'ı exploit edin**: yeni register edilmiş domain'lerde genellikle blocklist geçmişi, URL reputation ve olgun telemetry bulunmaz; bu nedenle detection mekanizmaları yetişene kadar kontrolleri bypass edebilirler. Saldırganlar bu pencereyi yalnızca crawler'lara benign response'lar göndererek, redirect cloaking, CAPTCHA gate'leri veya gecikmeli payload staging kullanarak uzatabilir.

### Agent'lar için neden tehlikelidir?

İnsan kurban için sahte domain genellikle bir click ve başka bir action gerektirir. **Agentic workflow** için ise LLM hem **lure** hem de **executor** olabilir: agent, halüsinasyonla oluşturulmuş URL'yi alır, fetch eder, response'u parse eder ve ardından herhangi bir human review olmadan token'ları leak edebilir, instruction'ları execute edebilir, bir dependency download edebilir veya poisoned data'yı CI/CD'ye push edebilir.<sup>[[12]](#references)</sup>

### Practical attacker prompts

Yüksek verimli prompt'lar genellikle açık phishing lure'ları yerine normal enterprise task'ları gibi görünür:<sup>[[12]](#references)</sup>
- “`<brand>` integrations için payment sandbox URL'si nedir?”
- “`<brand>` build notification'ları için hangi webhook endpoint'ini kullanmalıyım?”
- “`<brand>` için employee benefits / billing / SSO portalı nerede?”
- “`<brand>` için doğrudan Android APK veya desktop client download'ını ver.”

### Defensive inversion

Bunu yalnızca prompt-injection problemi olarak değil, proaktif bir domain-monitoring problemi olarak ele alın:<sup>[[12]](#references)</sup>
- Bir **brand prompt corpus** oluşturun ve kullanıcılarınızın/agent'larınızın güvendiği LLM'leri periyodik olarak probe edin.
- Halüsinasyonla oluşturulmuş URL'leri saklayın ve hangilerinin temperature/model'lar arasında stabil olduğunu takip edin.
- **Adversarial Exploitation Window (AEW)** değerini takip edin: ilk halüsinasyon ile attacker registration arasındaki süre. Pozitif AEW, defender'ların weaponization'dan önce domain'i pre-register edebileceği, sinkhole'a yönlendirebileceği veya pre-block edebileceği anlamına gelir.
- Parent domain'ler için **NXDOMAIN → registered** geçişlerini izleyin.
- Registration sonrasında registrar'ı, creation date'i, nameserver'ları, privacy shielding'i, page content'i, screenshot'ları, parked-page status'unu ve brand-asset similarity'yi triage edin.
- Agent'ların/developer'ların **LLM tarafından oluşturulan domain'lere varsayılan olarak güvenmemesi** için policy gate'leri ekleyin: ilk kullanımdan önce allowlist, ownership validation, CT/RDAP check'leri veya human approval zorunlu kılın.

Bu durum aynı anda çeşitli AI risk kategorilerine girer: **AI supply-chain attack**, **insecure model output** ve agent'ların halüsinasyonla oluşturulmuş URL'yi otonom olarak tüketmesi halinde **rogue actions**.

## References

- [1] [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risks](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS)
- [4] [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Stolen Cloud Credentials Used in New AI Attack](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI-Hallucinated Domains as a Software Supply Chain Vector](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
