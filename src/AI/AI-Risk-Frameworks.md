# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp, yapay zeka sistemlerini etkileyebilecek en önemli 10 makine öğrenmesi açığını belirledi. Bu açıklıklar veri poisoning, model inversion ve adversarial saldırılar dahil olmak üzere çeşitli güvenlik sorunlarına yol açabilir. Bu açıklıkları anlamak, güvenli AI sistemleri inşa etmek için kritiktir.

Güncel ve ayrıntılı Top 10 makine öğrenmesi açıklıkları listesi için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine bakın.

- **Input Manipulation Attack**: Bir saldırgan modele yanlış karar aldırmak için **gelen veriye** çok küçük, çoğunlukla görünmez değişiklikler ekler.\
Örnek: Bir stop‑tabela üzerindeki birkaç boya lekesi, otonom aracın tabelayı hız‑limit tabelası olarak "görmesine" yol açar.

- **Data Poisoning Attack**: **training set** kasıtlı olarak kötü örneklerle kirletilir ve model zararlı kuralları öğrenir.\
Örnek: Bir antivirüs eğitim korpusunda kötü amaçlı ikili dosyalar "benign" olarak yanlış etiketlenirse benzer malware'ler sonradan atlatılabilir.

- **Model Inversion Attack**: Çıktıları sorgulayarak bir saldırgan, orijinal girdilerin hassas özelliklerini yeniden inşa eden bir **reverse model** oluşturur.\
Örnek: Bir kanser tespit modelinin tahminlerinden bir hastanın MRI görüntüsünü yeniden oluşturmak.

- **Membership Inference Attack**: Saldırgan, **belirli bir kayıt**ın eğitim sırasında kullanılıp kullanılmadığını güven farklarını gözlemleyerek test eder.\
Örnek: Bir kişinin banka işleminin bir fraud‑detection modelinin eğitim verisinde yer aldığını doğrulamak.

- **Model Theft**: Tekrarlı sorgulamalar, bir saldırganın karar sınırlarını öğrenmesine ve **modelin davranışını klonlamasına** (ve fikri mülkiyeti çalmasına) olanak sağlar.\
Örnek: ML‑as‑a‑Service API'sinden yeterli sayıda soru‑cevap çifti toplayarak neredeyse eşdeğer bir yerel model oluşturmak.

- **AI Supply‑Chain Attack**: ML pipeline içindeki herhangi bir bileşenin (veri, kütüphaneler, pre‑trained weights, CI/CD) ele geçirilmesi, downstream modelleri bozmak için kullanılabilir.\
Örnek: Bir model‑hub'daki zehirlenmiş bir bağımlılık, aralarında çok sayıda uygulama bulunan bir backdoored sentiment‑analysis modelini kurar.

- **Transfer Learning Attack**: Kötü amaçlı mantık **pre‑trained model** içine eklenir ve kurbanın görevi için fine‑tuning yapıldıktan sonra bile hayatta kalır.\
Örnek: Gizli bir trigger içeren bir vision backbone, medical imaging için adapte edildikten sonra bile etiketleri tersine çevirir.

- **Model Skewing**: İnce yanlı veya yanlış etiketlenmiş veri, **modelin çıktılarında** saldırganın ajandasını destekleyecek şekilde kayma yaratır.\
Örnek: Benzer gelecekteki e‑postaların geçmesine izin vermek için "temiz" spam e‑postalarının ham olarak etiketlenmesi.

- **Output Integrity Attack**: Saldırgan, modeli değiştirmeden, **model tahminlerini transit esnasında** değiştirir ve downstream sistemleri yanıltır.\
Örnek: Bir malware classifier'ın "malicious" hükmünü dosya‑karantina aşamasına ulaşmadan önce "benign" olarak çevirmek.

- **Model Poisoning** --- Yazma erişimi elde edildikten sonra genellikle doğrudan **model parametrelerinde** hedefli değişiklikler yapılarak davranışın değiştirilmesi.\
Örnek: Prodüksiyondaki bir fraud‑detection modelinin ağırlıklarını değiştirerek belirli kartlardan gelen işlemlerin her zaman onaylanmasını sağlamak.


## Google SAIF Risks

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) AI sistemleriyle ilişkili çeşitli riskleri sıralar:

- **Data Poisoning**: Kötü niyetli aktörler, doğruluğu bozmak, backdoor yerleştirmek veya sonuçları kaydırmak amacıyla eğitim/ayarlama verilerini değiştirir veya enjekte eder; bu, veri yaşam döngüsü boyunca model bütünlüğünü zedeler.

- **Unauthorized Training Data**: Telif hakkıyla korunan, hassas veya izin verilmemiş veri setlerinin alınması, modelin kullanmasına izin verilmeyen verilerden öğrenmesi nedeniyle yasal, etik ve performans riskleri yaratır.

- **Model Source Tampering**: Supply‑chain veya içeriden müdahale yoluyla model kodu, bağımlılıklar veya weights eğitim öncesinde ya da sırasında manipüle edilerek yeniden eğitme sonrası bile devam eden gizli mantık gömülebilir.

- **Excessive Data Handling**: Zayıf veri‑saklama ve yönetişim kontrolleri, sistemlerin gerekenden fazla kişisel veri depolamasına veya işlemeye neden olarak maruziyeti ve uyumluluk riskini artırır.

- **Model Exfiltration**: Saldırganlar model dosyalarını/weights çalar; bu, fikri mülkiyet kaybına ve taklit servislerin veya takip saldırılarının ortaya çıkmasına neden olur.

- **Model Deployment Tampering**: Saldırganlar model artifact'larını veya serving altyapısını değiştirir, böylece çalışan model doğrulanmış versiyondan farklı olur ve davranışı değişebilir.

- **Denial of ML Service**: API'leri aşırı yükleme veya “sponge” girdiler gönderme, compute/enerji kaynaklarını tüketebilir ve modeli çevrimdışı bırakabilir; klasik DoS saldırılarına benzer.

- **Model Reverse Engineering**: Çok sayıda input‑output çifti toplayarak saldırganlar modeli klonlayabilir veya distill edebilir, bu da taklit ürünleri ve özelleştirilmiş adversarial saldırıları besler.

- **Insecure Integrated Component**: Zayıf plugin'ler, agent'lar veya upstream servisler, saldırganların AI pipeline içine kod enjekte etmesine veya ayrıcalıkları yükseltmesine izin verir.

- **Prompt Injection**: Doğrudan veya dolaylı olarak hazırlanmış prompt'lar, sistem niyetini geçersiz kılacak talimatları kaçırmak için kullanılır ve modelin istenmeyen komutları yerine getirmesine yol açar.

- **Model Evasion**: Özenle tasarlanmış girdiler modelin yanlış sınıflandırma, hallucination veya yasaklanmış içerik üretmesine neden olur; bu güven ve emniyeti aşındırır.

- **Sensitive Data Disclosure**: Model, eğitim verilerinden veya kullanıcı bağlamından özel ya da gizli bilgileri ifşa eder ve gizlilik ile mevzuata aykırılık oluşturur.

- **Inferred Sensitive Data**: Model, hiç sağlanmamış kişisel özellikleri çıkarım yoluyla tahmin eder ve bu yeni gizlilik zararlarına neden olur.

- **Insecure Model Output**: Temizlenmemiş yanıtlar, zararlı kod, yanlış bilgi veya uygun olmayan içerikler kullanıcıya ya da downstream sistemlere geçebilir.

- **Rogue Actions**: Otonom olarak entegre edilmiş agent'lar, kullanıcı gözetimi olmadan gerçek dünya işlemleri (dosya yazma, API çağrıları, satın almalar vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI sistemleriyle ilişkili riskleri anlamak ve hafifletmek için kapsamlı bir çerçeve sağlar. AI modellere karşı kullanılabilecek çeşitli saldırı tekniklerini ve taktiklerini kategorize eder ve ayrıca AI sistemlerini farklı saldırılar için nasıl kullanabileceğinizi gösterir.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Saldırganlar aktif oturum token'larını veya cloud API kimlik bilgilerini çalar ve yetkisiz olarak ücretli, bulut barındırılan LLM'leri çağırır. Erişim genellikle kurbanın hesabını öne alan reverse proxy'ler aracılığıyla yeniden satılır; örn. "oai-reverse-proxy" dağıtımları. Sonuçlar arasında mali kayıp, politikalara aykırı model kötüye kullanımı ve suçu yüklenebilecek tenant attribution'ı yer alır.

TTPs:
- Enfekte olmuş geliştirici makinelerinden veya tarayıcılardan token toplamak; CI/CD sırlarını çalmak; sızdırılmış cookie'leri satın almak.
- İsteği gerçek sağlayıcıya ileten, upstream anahtarı gizleyen ve birçok müşteriyi multiplex eden bir reverse proxy kurmak.
- Kurumsal guardrail'ları ve rate limit'leri atlamak için doğrudan base‑model endpoint'lerini kötüye kullanmak.

Mitigations:
- Token'ları cihaz fingerprint'ine, IP aralıklarına ve client attestation'a bağlayın; kısa süreli geçerlilikler zorunlu kılın ve MFA ile yenileyin.
- Anahtarları minimal scope ile verin (gerekirse no tool access, read‑only); anormallikte rotate edin.
- Safety filtrelerini, per‑route kota'larını ve tenant izolasyonunu uygulayan bir policy gateway arkasında tüm trafiği server‑side sonlandırın.
- Olağandışı kullanım desenlerini (ani harcama sıçramaları, alışılmadık bölgeler, UA string'leri) izleyin ve şüpheli oturumları otomatik iptal edin.
- Uzun ömürlü statik API anahtarları yerine IdP tarafından verilen mTLS veya signed JWTs tercih edin.

## Self-hosted LLM inference hardening

Kıymetli veriler için yerel bir LLM sunucusu çalıştırmak, cloud‑hosted API'lerden farklı bir saldırı yüzeyi oluşturur: inference/debug endpoint'leri prompt içeriklerini leak edebilir, serving stack genellikle bir reverse proxy açığa çıkarır ve GPU device node'ları geniş bir `ioctl()` yüzeyi sağlar. Eğer bir on‑prem inference servisini değerlendiriyor veya dağıtıyorsanız en azından aşağıdaki noktaları inceleyin.

### Prompt leakage via debug and monitoring endpoints

Inference API'sini bir **çok‑kullanıcılı hassas servis** olarak ele alın. Debug veya monitoring rotaları prompt içeriklerini, slot durumunu, model metadata'sını veya iç kuyruk bilgilerini ifşa edebilir. `llama.cpp` içinde `/slots` endpoint'i özellikle hassastır çünkü her slot için durum açığa çıkarır ve sadece slot inceleme/yonetimi için tasarlanmıştır.

- Inference server'ın önüne bir reverse proxy koyun ve **varsayılan olarak reddet**.
- Sadece client/UI tarafından gereken tam HTTP method + path kombinasyonlarını allowlist'leyin.
- Mümkün olduğunca backend içinde introspection endpoint'lerini devre dışı bırakın, örn. `llama-server --no-slots`.
- Reverse proxy'yi `127.0.0.1` ile sınırlayın ve LAN'da yayımlamak yerine SSH local port forwarding gibi kimlikli bir taşıma üzerinden sunun.

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
### Rootless containers: ağsız ve UNIX sockets

Eğer inference daemon UNIX socket üzerinde dinlemeyi destekliyorsa, TCP yerine onu tercih edin ve container'ı **no network stack** ile çalıştırın:
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
- `--network none` gelen/giden TCP/IP maruziyetini kaldırır ve aksi takdirde rootless containers'ın ihtiyaç duyacağı user-mode helpers kullanımını önler.
- A UNIX socket, socket yolunda POSIX permissions/ACLs kullanmanıza izin vererek ilk erişim-kontrol katmanı olarak görev yapar.
- `--userns=keep-id` ve rootless Podman, container breakout etkisini azaltır çünkü container root host root değildir.
- Read-only model mounts, container içinden model tampering olasılığını azaltır.

### GPU device-node minimizasyonu

GPU destekli inference için, `/dev/nvidia*` dosyaları yüksek değerli yerel saldırı yüzeyleridir; çünkü büyük sürücü `ioctl()` işleyicilerini ve potansiyel olarak paylaşılan GPU bellek-yönetimi yollarını açığa çıkarırlar.

- `/dev/nvidia*` dosyalarını world-writable bırakmayın.
- `nvidia`, `nvidiactl` ve `nvidia-uvm`'yi `NVreg_DeviceFileUID/GID/Mode`, udev kuralları ve ACLs ile kısıtlayın; böylece yalnızca haritalanmış container UID bunları açabilir.
- Headless inference host'larda `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz modülleri kara listeye alın.
- Runtime'ın inference başlatılırken bunları fırsatçı şekilde `modprobe` etmesine izin vermek yerine, önyüklemede sadece gerekli modülleri önceden yükleyin.

Örnek:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**. Even if the workload does not explicitly use `cudaMallocManaged()`, recent CUDA runtimes may still require `nvidia-uvm`. Because this device is shared and handles GPU virtual memory management, treat it as a cross-tenant data-exposure surface. If the inference backend supports it, a Vulkan backend can be an interesting trade-off because it may avoid exposing `nvidia-uvm` to the container at all.

### LSM confinement for inference workers

AppArmor/SELinux/seccomp should be used as defense in depth around the inference process:

- Allow only the shared libraries, model paths, socket directory, and GPU device nodes that are actually required.
- Explicitly deny high-risk capabilities such as `sys_admin`, `sys_module`, `sys_rawio`, and `sys_ptrace`.
- Keep the model directory read-only and scope writable paths to the runtime socket/cache directories only.
- Monitor denial logs because they provide useful detection telemetry when the model server or a post-exploitation payload tries to escape its expected behaviour.

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
## Kaynaklar
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
