# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP, AI sistemlerini etkileyebilecek en önemli 10 machine learning açığını belirlemiştir. Bu açıklar data poisoning, model inversion ve adversarial attacks dahil olmak üzere çeşitli güvenlik sorunlarına yol açabilir. Bu açıkları anlamak, güvenli AI sistemleri oluşturmak için kritik öneme sahiptir.

En güncel ve ayrıntılı top 10 machine learning vulnerabilities listesi için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine başvurun.

- **Input Manipulation Attack**: Bir saldırgan, modelin yanlış karar vermesini sağlamak için **gelen veriye** küçük ve çoğu zaman görünmez değişiklikler ekler.\
*Örnek*: Bir stop işaretinin üzerine birkaç boya lekesi konulması, self-driving car'ın işareti hız sınırı işareti olarak "görmesine" neden olur.

- **Data Poisoning Attack**: **Training set**, kötü örneklerle kasıtlı olarak kirletilerek modele zararlı kurallar öğretilir.\
*Örnek*: Bir antivirus training corpus içindeki malware binary'leri "benign" olarak yanlış etiketlenir ve benzer malware'lerin daha sonra gözden kaçmasına izin verilir.

- **Model Inversion Attack**: Bir saldırgan, çıktıları sorgulayarak orijinal girdilerin hassas özelliklerini yeniden oluşturan bir **reverse model** oluşturur.\
*Örnek*: Bir cancer-detection modelinin tahminlerinden bir hastanın MRI görüntüsünü yeniden oluşturmak.

- **Membership Inference Attack**: Saldırgan, güven düzeylerindeki farklılıkları tespit ederek **belirli bir kaydın** training sırasında kullanılıp kullanılmadığını test eder.\
*Örnek*: Bir kişinin banka işleminin fraud-detection modelinin training data'sında bulunduğunu doğrulamak.

- **Model Theft**: Tekrarlanan sorgulama, saldırganın karar sınırlarını öğrenmesine ve modelin davranışını (ve IP'sini) **klonlamasına** olanak tanır.\
*Örnek*: Bir ML-as-a-Service API'den yeterli sayıda Q&A çifti toplayarak neredeyse eşdeğer bir local model oluşturmak.

- **AI Supply-Chain Attack**: **ML pipeline** içindeki herhangi bir bileşenin (data, libraries, pre-trained weights, CI/CD) ele geçirilmesi, sonraki modellerin bozulmasına yol açabilir.\
*Örnek*: Bir model-hub üzerindeki poisoned dependency, birçok uygulamaya backdoored bir sentiment-analysis model kurar.

- **Transfer Learning Attack**: **Pre-trained model** içine kötü amaçlı logic yerleştirilir ve kurbanın görevi üzerinde fine-tuning yapılmasından sonra da varlığını sürdürür.\
*Örnek*: Gizli bir trigger içeren bir vision backbone, medical imaging için uyarlandıktan sonra da label'ları değiştirmeye devam eder.

- **Model Skewing**: İnce biçimde biased veya yanlış etiketlenmiş data, saldırganın amacını destekleyecek şekilde **modelin çıktılarını değiştirir**.\
*Örnek*: "Clean" spam e-postalarını ham olarak etiketleyerek enjekte etmek; böylece bir spam filter'ın benzer gelecekteki e-postalara izin vermesini sağlamak.

- **Output Integrity Attack**: Saldırgan modelin kendisini değil, **model predictions'larını aktarım sırasında değiştirerek** sonraki sistemleri kandırır.\
*Örnek*: Bir malware classifier'ın "malicious" kararını file-quarantine aşaması görmeden önce "benign" olarak değiştirmek.

- **Model Poisoning** --- Genellikle write access elde edildikten sonra **model parameters** üzerinde doğrudan ve hedefli değişiklikler yaparak davranışı değiştirmek.\
*Örnek*: Production'daki bir fraud-detection modelinin weights değerlerini değiştirerek belirli kartlardan yapılan işlemlerin her zaman onaylanmasını sağlamak.


## Google SAIF Risks

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) çerçevesi, AI sistemleriyle ilişkili çeşitli riskleri açıklar:

- **Data Poisoning**: Kötü amaçlı kişiler, accuracy'yi düşürmek, backdoor yerleştirmek veya sonuçları saptırmak için training/tuning data'sını değiştirir ya da data ekler; bu durum tüm data-lifecycle boyunca model integrity'sini zayıflatır.

- **Unauthorized Training Data**: Copyright kapsamındaki, hassas veya izinsiz dataset'lerin alınması; modelin kullanmasına hiçbir zaman izin verilmeyen data'dan öğrenmesi nedeniyle hukuki, etik ve performance riskleri oluşturur.

- **Model Source Tampering**: Training öncesinde veya sırasında model code'unun, dependencies'lerin ya da weights'lerin supply-chain veya insider manipulation yoluyla değiştirilmesi, retraining sonrasında bile varlığını sürdüren gizli logic yerleştirebilir.

- **Excessive Data Handling**: Zayıf data-retention ve governance kontrolleri, sistemlerin gereğinden fazla personal data saklamasına veya işlemesine yol açarak exposure ve compliance riskini artırır.

- **Model Exfiltration**: Saldırganlar model files/weights'leri çalar; bu, intellectual property kaybına ve copy-cat services veya follow-on attacks oluşturulmasına olanak tanır.

- **Model Deployment Tampering**: Adversaries, model artifacts'lerini veya serving infrastructure'ı değiştirerek çalışan modelin doğrulanmış sürümden farklı olmasını sağlayabilir ve potansiyel olarak davranışını değiştirebilir.

- **Denial of ML Service**: API'leri flood'lamak veya “sponge” inputs göndermek compute/energy kaynaklarını tüketerek modeli offline duruma getirebilir; bu, klasik DoS attacks'leri andırır.

- **Model Reverse Engineering**: Saldırganlar, çok sayıda input-output pair toplayarak modeli klonlayabilir veya distil edebilir; bu da imitation products ve özelleştirilmiş adversarial attacks için kaynak oluşturur.

- **Insecure Integrated Component**: Vulnerable plugins, agents veya upstream services, saldırganların AI pipeline içine code inject etmesine veya privilege escalation gerçekleştirmesine olanak tanır.

- **Prompt Injection**: System intent'i geçersiz kılan talimatları gizlice içeri sokmak ve modelin istenmeyen commands gerçekleştirmesini sağlamak için doğrudan veya dolaylı biçimde prompts oluşturmak.

- **Model Evasion**: Özenle tasarlanmış inputs, modelin yanlış sınıflandırma yapmasına, hallucinate etmesine veya izin verilmeyen content üretmesine neden olarak safety ve trust'ı zayıflatır.

- **Sensitive Data Disclosure**: Model, training data'sından veya user context'ten private ya da confidential information açığa çıkararak privacy ve regulations'ı ihlal eder.

- **Inferred Sensitive Data**: Model, hiç sağlanmamış personal attributes'ları çıkarabilir ve inference yoluyla yeni privacy ihlalleri oluşturabilir.

- **Insecure Model Output**: Sanitize edilmemiş responses, harmful code, misinformation veya inappropriate content'i kullanıcılara ya da downstream systems'e aktarır.

- **Rogue Actions**: Autonomously-integrated agents, yeterli user oversight olmadan istenmeyen gerçek dünya işlemlerini (file writes, API calls, purchases vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve azaltmak için kapsamlı bir framework sağlar. Adversaries'lerin AI models'e karşı kullanabileceği çeşitli attack techniques ve tactics'leri, ayrıca AI systems'in farklı attacks gerçekleştirmek için nasıl kullanılabileceğini kategorilere ayırır.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Saldırganlar active session tokens veya cloud API credentials'ları çalar ve ücretli, cloud-hosted LLM'leri izinsiz şekilde çalıştırır. Access, çoğu zaman kurbanın account'unun önünde konumlanan reverse proxies aracılığıyla yeniden satılır; örneğin "oai-reverse-proxy" deployments. Sonuçlar arasında financial loss, policy dışında model misuse ve victim tenant'a atfedilme bulunur.

TTPs:
- Infected developer machines veya browsers'tan tokens toplayın; CI/CD secrets'ları çalın; leaked cookies satın alın.
- Genuine provider'a requests ileten, upstream key'i gizleyen ve birçok customer'ı multiplex eden bir reverse proxy kurun.
- Enterprise guardrails ve rate limits'i aşmak için direct base-model endpoints'leri kötüye kullanın.

Mitigations:
- Tokens'ları device fingerprint, IP ranges ve client attestation'a bağlayın; kısa expirations uygulayın ve MFA ile refresh edin.
- Keys'leri minimum kapsamda tutun (tool access olmasın, uygun olduğunda read-only kullanın); anomaly durumunda rotate edin.
- Safety filters, route başına quotas ve tenant isolation uygulayan bir policy gateway arkasında tüm traffic'i server-side sonlandırın.
- Unusual usage patterns'ı (ani spend spikes, atypical regions, UA strings) izleyin ve şüpheli sessions'ları otomatik olarak revoke edin.
- Uzun ömürlü static API keys yerine IdP'niz tarafından verilen mTLS veya signed JWTs kullanmayı tercih edin.

## Self-hosted LLM inference hardening

Confidential data için local LLM server çalıştırmak, cloud-hosted APIs'lerden farklı bir attack surface oluşturur: inference/debug endpoints prompts leak edebilir, serving stack genellikle bir reverse proxy açığa çıkarır ve GPU device nodes büyük `ioctl()` surfaces'larına erişim sağlar. Bir on-prem inference service'i değerlendiriyor veya deploy ediyorsanız en azından aşağıdaki noktaları inceleyin.

### Debug ve monitoring endpoints üzerinden prompt leakage

Inference API'yi **multi-user sensitive service** olarak ele alın. Debug veya monitoring routes; prompt contents, slot state, model metadata veya internal queue information açığa çıkarabilir. `llama.cpp` içinde `/slots` endpoint'i özellikle hassastır; per-slot state'i açığa çıkarır ve yalnızca slot inspection/management için tasarlanmıştır.

- Inference server'ın önüne bir reverse proxy koyun ve **deny by default** uygulayın.
- Client/UI tarafından ihtiyaç duyulan tam HTTP method + path combinations'ı yalnızca allowlist'e alın.
- Mümkün olduğunda backend'in içindeki introspection endpoints'leri devre dışı bırakın; örneğin `llama-server --no-slots`.
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
### Ağ olmadan rootless container'lar ve UNIX socket'leri

Inference daemon bir UNIX socket üzerinde dinlemeyi destekliyorsa, TCP yerine bunu tercih edin ve container'ı **network stack olmadan** çalıştırın:
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
- `--network none`, gelen/giden TCP/IP maruziyetini ortadan kaldırır ve rootless container'ların aksi takdirde ihtiyaç duyacağı user-mode yardımcılarından kaçınır.
- Bir UNIX socket, ilk access-control katmanı olarak socket path üzerinde POSIX permissions/ACLs kullanmanıza olanak tanır.
- `--userns=keep-id` ve rootless Podman, container breakout etkisini azaltır; çünkü container root kullanıcısı host root kullanıcısı değildir.
- Read-only model mount'ları, container içinden model tampering olasılığını azaltır.

### GPU device-node minimizasyonu

GPU-backed inference için `/dev/nvidia*` dosyaları, büyük driver `ioctl()` işleyicilerini ve potansiyel olarak paylaşılan GPU memory-management yollarını açığa çıkardıkları için yüksek değerli local attack surface'lerdir.

- `/dev/nvidia*` dosyalarını herkes tarafından yazılabilir durumda bırakmayın.
- `nvidia`, `nvidiactl` ve `nvidia-uvm` için `NVreg_DeviceFileUID/GID/Mode`, udev rules ve ACLs kullanarak yalnızca mapped container UID'nin bunları açabilmesini sağlayın.
- Headless inference host'larında `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz modülleri blacklist edin.
- Runtime'ın inference startup sırasında bunları fırsatçı biçimde `modprobe` etmesine izin vermek yerine yalnızca gerekli modülleri boot sırasında preload edin.

Örnek:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Önemli bir inceleme noktası **`/dev/nvidia-uvm`**'dir. İş yükü açıkça `cudaMallocManaged()` kullanmasa bile, güncel CUDA runtime'ları yine de `nvidia-uvm` gerektirebilir. Bu device paylaşıldığından ve GPU virtual memory management işlemlerini yürüttüğünden, bunu tenant'lar arası veri ifşası yüzeyi olarak değerlendirin. Inference backend destekliyorsa, Vulkan backend ilginç bir trade-off olabilir; çünkü `nvidia-uvm`'yi container'a hiç expose etmeyi gerektirmeyebilir.

### Inference worker'ları için LSM izolasyonu

Inference process'i çevresinde defense in depth olarak AppArmor/SELinux/seccomp kullanılmalıdır:

- Yalnızca gerçekten gerekli olan shared library'lere, model path'lerine, socket directory'ye ve GPU device node'larına izin verin.
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
## Phantom Squatting: LLM-Hallucinated Domains as an AI Supply-Chain Vector

Phantom squatting, **slopsquatting'in domain/URL eşdeğeridir**. LLM, mevcut olmayan bir package adını hallucinate etmek yerine, gerçek bir brand için makul görünen bir **portal, API, webhook, billing, SSO, download veya support domain'i** hallucinate eder ve saldırgan, bir insan veya agent onu kullanmadan önce bu namespace'i register eder.

Bu önemlidir; çünkü birçok AI-assisted workflow'da model çıktısı **güvenilir bir dependency** olarak kabul edilir:
- Developer'lar önerilen endpoint'i code veya CI/CD integration'larına yapıştırır.
- AI agent'lar documentation, schema, APK, ZIP veya webhook target'larını otomatik olarak fetch eder.
- Oluşturulan runbook veya doc'lar fake URL'yi authoritative bir kaynakmış gibi içerebilir.

### Offensive workflow

1. **Hallucination surface'i probe edin**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` veya `mobile app` portal'ları gibi gerçekçi workflow'lar hakkında brand-specific sorular sorun.
2. **Adayları normalize edin**: generated URL'leri resolve edin, NXDOMAIN response'larını parent registerable domain'e indirgeyin ve prompt family'lerini deduplicate edin. Prompt corpus'ları çeşitli kalmalıdır; örneğin **Jaccard similarity** kullanarak near-duplicate'leri eleyin.
3. **Öngörülebilir hallucination'lara öncelik verin**:
- **Thermal Hallucination Persistence (THP)**: aynı fake domain, `T=0.1` gibi düşük temperature değerleri dahil olmak üzere farklı temperature'larda görünür.
- **Cross-model consensus**: birden fazla LLM family aynı fake domain'i üretir.
4. Parent domain'i **register edin ve weaponize edin**, ardından phishing, fake APK/ZIP download'ları, credential harvester'lar, malicious doc'lar veya secret/webhook payload'larını toplayan API endpoint'leri host edin. **Pure domain-level hallucination'lar** monetize edilmesi en kolay olanlardır; çünkü saldırgan tüm namespace'i kontrol eder. Subdomain/path hallucination'ları da normalize edilen parent register edilmemişse abuse edilebilir.
5. **Zero-reputation window'u exploit edin**: yeni register edilmiş domain'ler genellikle blocklist geçmişinden, URL reputation'dan ve olgun telemetry'den yoksundur; bu nedenle detection'lar yetişene kadar kontrolleri bypass edebilirler. Saldırganlar bu window'u crawler-only benign response'lar, redirect cloaking, CAPTCHA gate'leri veya delayed payload staging ile uzatabilir.

### Agent'lar için neden tehlikelidir?

Human victim için fake domain genellikle bir click ve başka bir action gerektirir. **Agentic workflow** için LLM hem **lure** hem de **executor** olabilir: agent hallucinate edilmiş URL'yi alır, URL'yi fetch eder, response'u parse eder ve ardından herhangi bir human review olmadan token'ları leak edebilir, instruction'ları execute edebilir, bir dependency download edebilir veya poisoned data'yı CI/CD'ye push edebilir.

### Practical attacker prompts

High-yield prompt'lar genellikle explicit phishing lure'ları yerine normal enterprise task'ları andırır:
- “`<brand>` integration'ları için payment sandbox URL nedir?”
- “`<brand>` build notification'ları için hangi webhook endpoint'i kullanmalıyım?”
- “`<brand>` için employee benefits / billing / SSO portal'ı nerede?”
- “`<brand>` için doğrudan Android APK veya desktop client download'ını ver.”

### Defensive inversion

Bunu yalnızca bir prompt-injection problemi olarak değil, proactive domain-monitoring problemi olarak ele alın:
- Bir **brand prompt corpus** oluşturun ve kullanıcılarınızın/agent'larınızın güvendiği LLM'leri periyodik olarak probe edin.
- Hallucinate edilmiş URL'leri saklayın ve hangilerinin temperature/model'lar arasında stable olduğunu track edin.
- **Adversarial Exploitation Window (AEW)** değerini track edin: ilk hallucination ile attacker registration arasındaki süre. Pozitif AEW, defender'ların weaponization'dan önce pre-register, sinkhole veya pre-block yapabileceği anlamına gelir.
- Parent domain'ler için **NXDOMAIN → registered** transition'larını monitor edin.
- Registration sonrasında registrar'ı, creation date'i, nameserver'ları, privacy shielding'i, page content'i, screenshot'ları, parked-page status'ını ve brand-asset similarity'yi triage edin.
- Agent ve developer'ların **LLM-generated domain'lere varsayılan olarak güvenmemesi** için policy gate'leri ekleyin: ilk kullanım öncesinde allowlist, ownership validation, CT/RDAP check veya human approval gerektirin.

Bu konu aynı anda birkaç AI risk bucket'ına uyar: **AI supply-chain attack**, **insecure model output** ve agent'ların hallucinate edilmiş URL'yi otonom olarak tükettiği durumlarda **rogue actions**.

## References
- [Unit 42 – Code Assistant LLM'lerinin Riskleri: Zararlı İçerik, Kötüye Kullanım ve Aldatma](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (çalınmış LLM erişiminin yeniden satılması)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - On-premise düşük yetkili bir LLM server deployment'ının deep-dive incelemesi](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlet'leri: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting: Software Supply Chain Vector olarak AI-Hallucinated Domain'ler](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting: AI Hallucination'ları Yeni Bir Supply Chain Attack Sınıfını Nasıl Besliyor](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
