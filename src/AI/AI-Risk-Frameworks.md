# Yapay Zeka Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp, AI sistemlerini etkileyebilecek en önemli 10 makine öğrenimi zafiyetini tanımladı. Bu zafiyetler veri poisoning, model inversion ve adversarial saldırılar dahil çeşitli güvenlik sorunlarına yol açabilir. Bu zafiyetleri anlamak, güvenli AI sistemleri inşa etmek için kritiktir.

Güncel ve ayrıntılı Top 10 listesi için bkz. [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Bir saldırgan, modelin yanlış karar vermesi için **gelen veriye** küçük, genellikle görünmez değişiklikler ekler.\
*Örnek*: Bir dur‑işaretine birkaç boya lekesi sürülmesi, otonom aracı bir hız‑sınırı işareti gördüğüne kandırabilir.

- **Data Poisoning Attack**: **eğitim seti** kasıtlı olarak kötü örneklerle kirletilir ve modele zararlı kurallar öğretilir.\
*Örnek*: Bir antivirüs eğitim korpusunda kötü amaçlı binary'lerin "benign" olarak etiketlenmesi, benzer malware'lerin sonraki tespitlerden kaçmasını sağlar.

- **Model Inversion Attack**: Çıktıları sorgulayarak, bir saldırgan orijinal girdinin hassas özelliklerini yeniden oluşturabilen bir **ters model** inşa eder.\
*Örnek*: Bir kanser tespit modelinin tahminlerinden bir hastanın MRI görüntüsünü yeniden yaratmak.

- **Membership Inference Attack**: Saldırgan, **belirli bir kaydın** eğitim sırasında kullanılıp kullanılmadığını güven farklarını tespit ederek test eder.\
*Örnek*: Bir kişinin banka işlemlerinin dolandırıcılık tespit modelinin eğitim verisinde yer aldığını doğrulamak.

- **Model Theft**: Tekrarlı sorgulamalar, bir saldırganın karar sınırlarını öğrenmesini ve **modelin davranışını klonlamasını** sağlar (ve IP'yi çalar).\
*Örnek*: ML‑as‑a‑Service API'sinden yeterli Q&A çifti hasat edilerek eşdeğer bir lokal model oluşturmak.

- **AI Supply‑Chain Attack**: ML pipeline'ındaki herhangi bir bileşen (veri, kütüphaneler, ön‑eğitilmiş ağırlıklar, CI/CD) ele geçirilerek downstream modelleri bozmak.\
*Örnek*: Bir model‑hub üzerindeki zehirlenmiş bağımlılık, birçok uygulamaya backdoor'lu bir sentiment‑analiz modeli kurar.

- **Transfer Learning Attack**: Zararlı mantık, bir **pre‑trained model**'e yerleştirilir ve kurbanın görevi için fine‑tuning yapıldığında bile hayatta kalır.\
*Örnek*: Gizli bir tetik içeren bir vision backbone, tıbbi görüntüleme için uyarlanırken etiketleri tersine çevirmeye devam eder.

- **Model Skewing**: İnce şekilde önyargılı veya yanlış etiketlenmiş veri, modelin çıktılarında **saldırganın gündemini** destekleyecek kaymalar oluşturur.\
*Örnek*: "Temiz" spam e‑postaların ham (ham) olarak etiketlenmesi, bir spam filtresinin benzer gelecekteki e‑postaları geçirmesini sağlar.

- **Output Integrity Attack**: Saldırgan, modeli değil ama model tahminlerini **iletim sırasında değiştirir**, böylece downstream sistemleri kandırır.\
*Örnek*: Bir malware sınıflandırıcısının "malicious" kararını, dosya‑karantina aşamasına ulaşmadan önce "benign" olarak çevirmek.

- **Model Poisoning** --- Yazma erişimi elde edildikten sonra **model parametrelerine** doğrudan, hedefe yönelik değişiklikler yapılarak davranışın değiştirilmesi.\
*Örnek*: Prod'daki bir fraud‑detection modelinin ağırlıklarını değiştirerek belirli kartlardan gelen işlemlerin her zaman onaylanmasını sağlamak.


## Google SAIF Risks

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) AI sistemleriyle ilişkili çeşitli riskleri özetler:

- **Data Poisoning**: Kötü niyetli aktörler, doğruluğu bozmak, backdoor yerleştirmek veya sonuçları çarpıtmak için eğitim/ayarlama verisini değiştirir veya enjekte eder; bu, veri yaşam döngüsü boyunca model bütünlüğünü baltalar.

- **Unauthorized Training Data**: Telif hakkı korumalı, hassas veya izinsiz veri setlerinin alınması, modelin asla kullanmasına izin verilmeyen verilerden öğrenmesi nedeniyle hukuki, etik ve performans riskleri yaratır.

- **Model Source Tampering**: Tedarik zinciri veya içeriden gelen müdahalelerle model kodu, bağımlılıklar veya ağırlıklar eğitim öncesi veya sırasında manipüle edilerek gizli mantık gömülebilir ve yeniden eğitmeden sonra bile kalıcı olur.

- **Excessive Data Handling**: Zayıf veri‑saklama ve yönetişim kontrolleri, sistemlerin gerekenden fazla kişisel veri saklamasına veya işlemesine yol açarak maruziyeti ve uyumluluk riskini artırır.

- **Model Exfiltration**: Saldırganlar model dosyalarını/ağırlıklarını çalar; bu, fikri mülkiyet kaybına ve taklit hizmetler veya takip saldırıları için imkan sağlar.

- **Model Deployment Tampering**: Saldırganlar model artefaktlarını veya serving altyapısını değiştirerek çalışmakta olan modelin doğrulanmış sürümden farklı davranmasına neden olabilir.

- **Denial of ML Service**: API'ların taşması veya “sponge” girdiler gönderilmesi, compute/enerji tüketimini artırarak modeli çevrimdışı hale getirebilir; klasik DoS saldırılarına benzer.

- **Model Reverse Engineering**: Yüksek sayıda input‑output çifti toplayarak, saldırganlar modeli klonlayabilir veya distil edebilir; bu taklit ürünlere ve özelleştirilmiş adversarial saldırılara zemin hazırlar.

- **Insecure Integrated Component**: Zayıf plugin'ler, agent'lar veya upstream servisler, saldırganların pipeline içinde kod enjekte etmesine veya ayrıcalıkları yükseltmesine izin verir.

- **Prompt Injection**: Doğrudan veya dolaylı olarak, sistem niyetini geçersiz kılacak şekilde talimat kaçıracak prompt'lar hazırlanması; modelin istenmeyen komutları yerine getirmesi.

- **Model Evasion**: Dikkatle tasarlanmış girdiler modelin yanlış sınıflandırma, hallucination veya yasaklı içerik üretmesine neden olarak güveni zedeler.

- **Sensitive Data Disclosure**: Model, eğitim verisinden veya kullanıcı bağlamından özel ya da gizli bilgileri ifşa ederek gizliliği ve düzenlemeleri ihlal eder.

- **Inferred Sensitive Data**: Model, hiç verilmemiş kişisel özellikleri çıkarsayarak yeni gizlilik zararları (inference) yaratır.

- **Insecure Model Output**: Temizlenmemiş yanıtlar kullanıcılara veya downstream sistemlere zararlı kod, yanlış bilgi veya uygunsuz içerik geçirebilir.

- **Rogue Actions**: Otonom entegre agent'lar, yetersiz kullanıcı gözetimiyle istem dışı gerçek dünya işlemleri (dosya yazma, API çağrıları, satın almalar vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve hafifletmek için kapsamlı bir çerçeve sağlar. AI modellere karşı kullanılabilecek çeşitli saldırı tekniklerini ve taktikleri kategorize eder; ayrıca AI sistemlerini kullanarak farklı saldırılar nasıl yapılır gösterir.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Saldırganlar aktif oturum token'larını veya cloud API kimlik bilgilerini çalar ve yetkisiz olarak ücretli, cloud‑hosted LLM'leri çağırır. Erişim genellikle kurbanın hesabını öne çıkaran reverse proxy'ler üzerinden yeniden satılır; örn. "oai-reverse-proxy" dağıtımları. Sonuçlar arasında finansal kayıp, politikalara aykırı model suistimali ve mağdur tenant'a atfedilme yer alır.

TTPs:
- Enfekte olmuş geliştirici makinelerinden veya tarayıcılardan token'ları hasat etmek; CI/CD secret'larını çalmak; leaked cookies satın almak.
- Gerçek sağlayıcıya istekleri ileten, upstream anahtarı gizleyen ve birden çok müşteriyi çoklayabilen bir reverse proxy kurmak.
- Kurumsal guardrail'ları ve rate limit'leri atlatmak için doğrudan base‑model endpoint'lerini kötüye kullanmak.

Mitigations:
- Token'ları cihaz fingerprint'ine, IP aralıklarına ve client attestation'a bağlayın; kısa süreli geçerlilikler zorunlu kılın ve MFA ile yenileyin.
- Anahtarları minimum kapsama ile sınırlayın (kullanılmayan araç erişimi yok, mümkünse sadece read‑only); anormallikte rotate edin.
- Sunucu tarafında, güvenlik filtreleri, rota bazlı kotalar ve tenant izolasyonu uygulayan bir policy gateway arkasında tüm trafiği sonlandırın.
- Olağandışı kullanım kalıpları (ani harcama sıçramaları, alışılmadık bölgeler, UA stringleri) için izleme yapın ve şüpheli oturumları otomatik reddedin.
- Uzun ömürlü statik API anahtarları yerine mTLS veya IdP'niz tarafından verilen signed JWT'leri tercih edin.

## Self-hosted LLM inference hardening

Kabul edilen veya gizli veriler için lokal bir LLM sunucusu çalıştırmak, cloud‑hosted API'lardan farklı bir attack surface yaratır: inference/debug endpoint'ları prompt'ları leak edebilir, serving stack genellikle bir reverse proxy açar ve GPU device node'ları büyük `ioctl()` yüzeylerine erişim verir. Eğer bir on‑prem inference servisini değerlendiriyor veya dağıtıyorsanız, en azından aşağıdaki noktaları gözden geçirin.

### Prompt leak'i via debug and monitoring endpoints

Inference API'sini bir **çok‑kullanıcılı hassas servis** olarak ele alın. Debug veya monitoring rotaları prompt içeriklerini, slot durumunu, model metadata'sını veya iç kuyruk bilgilerini ifşa edebilir. `llama.cpp`'de `/slots` endpoint'i özellikle hassastır çünkü her‑slot durumunu ortaya koyar ve yalnızca slot inceleme/yonetimi için tasarlanmıştır.

- Inference sunucusunun önüne bir reverse proxy koyun ve **varsayılan olarak reddet**.
- Sadece client/UI tarafından gereken tam HTTP method + path kombinasyonlarını allowlist'leyin.
- Mümkün olduğunda backend'de introspection endpoint'lerini devre dışı bırakın; örn. `llama-server --no-slots`.
- Reverse proxy'yi `127.0.0.1`'e bağlayın ve LAN'da yayınlamak yerine SSH local port forwarding gibi kimlikli bir taşıma üzerinden açın.

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
### Ağsız ve UNIX soketleriyle rootless container'lar

Eğer inference daemon'u bir UNIX soketi üzerinde dinlemeyi destekliyorsa, TCP yerine bunu tercih edin ve container'ı **ağ yığını olmadan** çalıştırın:
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
Avantajlar:
- `--network none` inbound/outbound TCP/IP maruziyetini kaldırır ve rootless container'ların aksi takdirde ihtiyaç duyacağı user-mode helper'ları engeller.
- Bir UNIX socket, soket yolunda POSIX permissions/ACLs'i ilk erişim-denetim katmanı olarak kullanmanıza izin verir.
- `--userns=keep-id` ve rootless Podman, container breakout etkisini azaltır çünkü container root host root değildir.
- Salt okunur model mount'ları, konteyner içinden modelin değiştirilme olasılığını azaltır.

### GPU device-node minimizasyonu

GPU-backed inference için, `/dev/nvidia*` dosyaları büyük sürücü `ioctl()` handler'larını ve potansiyel olarak paylaşılan GPU bellek-yönetim yollarını açığa çıkardıkları için yüksek değerli yerel saldırı yüzeyleridir.

- Do not leave `/dev/nvidia*` world writable.
- `nvidia`, `nvidiactl` ve `nvidia-uvm`'i `NVreg_DeviceFileUID/GID/Mode`, udev kuralları ve ACLs ile kısıtlayın, böylece yalnızca eşlenen container UID bunları açabilir/erişebilir.
- Headless inference host'larda `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz modülleri kara listeye alın.
- Runtime'ın inference başlangıcında bunları fırsatçı şekilde `modprobe` etmesine izin vermek yerine, yalnızca gereken modülleri önyüklemede preload edin.

Example:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
One important review point is **`/dev/nvidia-uvm`**. Even if the workload does not explicitly use `cudaMallocManaged()`, recent CUDA runtimes may still require `nvidia-uvm`. Because this device is shared and handles GPU virtual memory management, treat it as a cross-tenant data-exposure surface. If the inference backend supports it, a Vulkan backend can be an interesting trade-off because it may avoid exposing `nvidia-uvm` to the container at all.

### Inference çalışanları için LSM kısıtlaması

AppArmor/SELinux/seccomp, inference süreci etrafında derinlikli savunma olarak kullanılmalıdır:

- Yalnızca gerçekten gerekli olan paylaşılan kütüphanelere, model yollarına, socket dizinine ve GPU aygıt düğümlerine izin verin.
- `sys_admin`, `sys_module`, `sys_rawio` ve `sys_ptrace` gibi yüksek riskli capability'leri açıkça reddedin.
- Model dizinini salt okunur tutun ve yazılabilir yolları yalnızca runtime socket/cache dizinleriyle sınırlayın.
- Reddetme loglarını izleyin; çünkü model sunucusu veya bir post-exploitation payload beklenen davranışından kaçmaya çalıştığında faydalı tespit telemetrisi sağlar.

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
## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
