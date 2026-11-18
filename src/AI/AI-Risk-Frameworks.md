# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp, AI sistemlerini etkileyebilecek en önemli 10 machine learning güvenlik açığını belirlemiştir. Bu güvenlik açıkları; data poisoning, model inversion ve adversarial attacks dahil olmak üzere çeşitli güvenlik sorunlarına yol açabilir. Güvenli AI sistemleri oluşturmak için bu güvenlik açıklarını anlamak kritik öneme sahiptir.

En güncel ve ayrıntılı machine learning güvenlik açıkları listesi için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine bakın.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Saldırgan, modelin yanlış karar vermesini sağlamak için **gelen verilerde** küçük, çoğu zaman görünmez değişiklikler yapar.\
    *Örnek*: Birkaç boya lekesi, otonom bir aracın dur işaretini hız sınırı işareti olarak "görmesine" yol açar.

- **Data Poisoning Attack**: **Training set**, modele zararlı kurallar öğretecek şekilde kasıtlı olarak kirletilir.\
*Örnek*: Bir antivirüs eğitim derlemindeki malware binary'leri yanlışlıkla "zararsız" olarak etiketlenir ve benzer malware örneklerinin daha sonra tespit edilmeden geçmesine izin verir.

- **Model Inversion Attack**: Saldırgan, modelin çıktılarından yararlanarak orijinal girdilerin hassas özelliklerini yeniden oluşturan bir **ters model** oluşturur.\
*Örnek*: Bir kanser tespit modelinin tahminlerinden hastanın MRI görüntüsünü yeniden oluşturmak.

- **Membership Inference Attack**: Saldırgan, güven düzeylerindeki farklılıkları tespit ederek eğitim sırasında **belirli bir kaydın** kullanılıp kullanılmadığını sınar.\
*Örnek*: Bir kişinin banka işleminin fraud detection modelinin eğitim verilerinde bulunduğunu doğrulamak.

- **Model Theft**: Tekrarlanan sorgular, saldırganın karar sınırlarını öğrenmesini ve modelin davranışını (ve IP'sini) **kopyalamasını** sağlar.\
*Örnek*: ML-as-a-Service API'sinden yeterince Soru-Cevap çifti toplayarak neredeyse eşdeğer bir yerel model oluşturmak.

- **AI Supply‑Chain Attack**: Aşağı akış modellerini bozmak için **ML pipeline** içindeki herhangi bir bileşen (veri, kütüphaneler, önceden eğitilmiş ağırlıklar, CI/CD) ele geçirilir.\
*Örnek*: Model hub'ındaki zehirlenmiş bir bağımlılık, birçok uygulamaya arka kapılı bir sentiment analysis modeli yükler.

- **Transfer Learning Attack**: Kötü amaçlı mantık **önceden eğitilmiş bir modele** yerleştirilir ve kurbanın görevi üzerinde fine-tuning yapıldıktan sonra da varlığını sürdürür.\
*Örnek*: Gizli bir tetikleyici içeren vision backbone, medical imaging için uyarlandıktan sonra da etiketleri değiştirmeye devam eder.

- **Model Skewing**: İnce biçimde yanlı veya yanlış etiketlenmiş veriler, saldırganın amacını destekleyecek şekilde **modelin çıktılarını değiştirir**.\
*Örnek*: Spam filtresinin gelecekteki benzer e-postaları geçirmesini sağlamak için "temiz" spam e-postalarını ham olarak etiketleyip eklemek.

- **Output Integrity Attack**: Saldırgan modelin kendisini değil, **model tahminlerini aktarım sırasında değiştirerek** aşağı akış sistemlerini kandırır.\
*Örnek*: Dosya karantinaya alınmadan önce bir malware classifier'ın "kötü amaçlı" kararını "zararsız" olarak değiştirmek.

- **Model Poisoning** --- Genellikle yazma erişimi elde ettikten sonra, davranışını değiştirmek için doğrudan ve hedefli biçimde **model parametrelerini** değiştirmek.\
*Örnek*: Belirli kartlardan yapılan işlemlerin her zaman onaylanması için üretimdeki bir fraud detection modelinin ağırlıklarını değiştirmek.


## Google SAIF Riskleri

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) çerçevesi, AI sistemleriyle ilişkili çeşitli riskleri açıklar:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Kötü amaçlı kişiler; doğruluğu düşürmek, arka kapılar yerleştirmek veya sonuçları çarpıtmak için eğitim/tuning verilerini değiştirir ya da bunlara veri ekler. Bu durum, tüm data lifecycle boyunca model bütünlüğünü zedeler.

- **Unauthorized Training Data**: Telif hakkıyla korunan, hassas veya kullanım izni alınmamış veri kümelerinin alınması, modelin kullanmasına izin verilmeyen verilerden öğrenmesi nedeniyle yasal, etik ve performans açısından sorumluluklar doğurur.

- **Model Source Tampering**: Model kodunun, bağımlılıklarının veya ağırlıklarının eğitimden önce ya da eğitim sırasında supply-chain veya içeriden biri tarafından değiştirilmesi, yeniden eğitimden sonra da kalıcı olabilen gizli mantık ekleyebilir.

- **Excessive Data Handling**: Zayıf veri saklama ve yönetişim kontrolleri, sistemlerin gerekenden fazla kişisel veri saklamasına veya işlemesine yol açarak veri açığa çıkma ve uyumluluk riskini artırır.

- **Model Exfiltration**: Saldırganlar model dosyalarını/ağırlıklarını çalar; bu da fikri mülkiyet kaybına ve taklit hizmetlerin veya devam niteliğindeki saldırıların önünün açılmasına neden olur.

- **Model Deployment Tampering**: Saldırganlar model artifact'lerini veya serving altyapısını değiştirerek çalışan modelin denetlenmiş sürümden farklı olmasını sağlar ve olası davranış değişikliklerine yol açar.

- **Denial of ML Service**: API'lere yoğun istek göndermek veya “sponge” girdiler kullanmak, işlem gücünü/enerjiyi tüketip modeli devre dışı bırakarak klasik DoS attacks yöntemlerini taklit edebilir.

- **Model Reverse Engineering**: Çok sayıda girdi-çıktı çifti toplayan saldırganlar modeli klonlayabilir veya distil edebilir; bu da taklit ürünlerin ve özelleştirilmiş adversarial attacks yöntemlerinin önünü açar.

- **Insecure Integrated Component**: Savunmasız plugin'ler, agent'lar veya üst akış hizmetleri, saldırganların AI pipeline'a kod eklemesine ya da ayrıcalıklarını yükseltmesine olanak tanır.

- **Prompt Injection**: Sistem amacını geçersiz kılan talimatları doğrudan veya dolaylı olarak prompt'lara gizlice eklemek, modelin istenmeyen komutları yerine getirmesine neden olur.

- **Model Evasion**: Özenle tasarlanmış girdiler, modelin yanlış sınıflandırma yapmasına, hallucinate etmesine veya izin verilmeyen içerik üretmesine yol açarak güvenliği ve güveni zedeler.

- **Sensitive Data Disclosure**: Model, eğitim verilerindeki veya kullanıcı bağlamındaki özel ya da gizli bilgileri açığa çıkararak gizlilik ve düzenlemeleri ihlal eder.

- **Inferred Sensitive Data**: Model, hiç paylaşılmamış kişisel özellikleri çıkarımlayarak yeni gizlilik zararlarına yol açar.

- **Insecure Model Output**: Arındırılmamış yanıtlar, zararlı kodları, yanlış bilgileri veya uygunsuz içerikleri kullanıcılara ya da aşağı akış sistemlerine aktarır.

- **Rogue Actions**: Otonom biçimde entegre edilmiş agent'lar, yeterli kullanıcı gözetimi olmadan istenmeyen gerçek dünya işlemlerini (dosya yazma, API çağrıları, satın alma vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve azaltmak için kapsamlı bir çerçeve sunar. Saldırganların AI modellerine karşı kullanabileceği çeşitli saldırı tekniklerini ve taktiklerini, ayrıca AI sistemlerinin farklı saldırıları gerçekleştirmek için nasıl kullanılabileceğini sınıflandırır.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Saldırganlar etkin oturum token'larını veya cloud API kimlik bilgilerini çalar ve ücretli, cloud-hosted LLM'leri yetkisiz şekilde kullanır. Erişim genellikle kurbanın hesabına bağlanan reverse proxy'ler üzerinden yeniden satılır; örneğin "oai-reverse-proxy" kurulumları. Sonuçları arasında maddi kayıp, modelin politikalar dışında kötüye kullanılması ve işlemlerin kurbanın tenant'ına atfedilmesi yer alır.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP'ler:
- Ele geçirilmiş geliştirici makinelerinden veya tarayıcılardan token toplamak; CI/CD secret'larını çalmak; leak edilmiş cookie'leri satın almak.<sup>[[5]](#references)</sup>
- İstekleri gerçek sağlayıcıya ileten, üst akış anahtarını gizleyen ve birçok müşteriyi aynı anda destekleyen bir reverse proxy kurmak.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Kurumsal güvenlik önlemlerini ve hız sınırlarını aşmak için doğrudan base-model endpoint'lerini kötüye kullanmak.<sup>[[4]](#references)</sup>

**In-host API-key reuse:** Bir makine ele geçirildikten sonra implant, cloud API key'ini dışarı aktarmadan veya yerel bir AI CLI başlatmadan, doğrudan kurbanın makinesinden model API istekleri gönderebilir ve yanıtları C2 üzerinden iletebilir. Gözlemlenen handler'da, C2 tarafından sağlanan bir key önceliklidir; key yoksa implant kendi proses ortamındaki `OPENAI_API_KEY` değerini okur. Bu nedenle kurbanın hesabını kullanmak, prosesin görebildiği geçerli bir key ve model API'sine erişim gerektirir. Operatörün prompt'u Chat Completions API'ye gider; model çıktısı ve token kullanımı ise C2 üzerinden geri döner. Bu yöntem, geliştiricinin AI araçlarını çalıştırmadan kurbanın ücretli model erişimini tüketebilir; [local AI CLI or MCP configuration abuse](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md) yönteminden farklı olarak.<sup>[[14]](#references)</sup>

Azaltma yöntemleri:
- Token'ları cihaz parmak izine, IP aralıklarına ve istemci attestation'ına bağlayın; kısa süreli geçerlilik uygulayın ve MFA ile yenileyin.
- Key'lere asgari kapsam tanımlayın (tool erişimi vermeyin, uygun olduğunda salt okunur yapın); anormallik durumunda döndürün.
- Tüm trafiği, güvenlik filtreleri, rota başına kotalar ve tenant izolasyonu uygulayan bir policy gateway arkasında sunucu tarafında sonlandırın.
- Olağan dışı kullanım örüntülerini (ani harcama artışları, alışılmadık bölgeler, UA string'leri) izleyin ve şüpheli oturumları otomatik olarak iptal edin.
- Uzun ömürlü statik API key'leri yerine IdP'niz tarafından verilen mTLS veya imzalı JWT'leri tercih edin.

## Kendi barındırılan LLM inference sistemlerini güçlendirme

Gizli veriler için yerel bir LLM server çalıştırmak, cloud-hosted API'lerden farklı bir saldırı yüzeyi oluşturur: inference/debug endpoint'leri prompt'ları leak edebilir, serving stack genellikle bir reverse proxy'yi açığa çıkarır ve GPU device node'ları geniş `ioctl()` saldırı yüzeylerine erişim sağlar. Şirket içinde barındırılan bir inference hizmetini değerlendiriyor veya dağıtıyorsanız en azından aşağıdaki noktaları gözden geçirin.<sup>[[8]](#references)</sup>

### Debug ve monitoring endpoint'leri üzerinden prompt sızıntısı

Inference API'yi **birden fazla kullanıcıya hizmet veren hassas bir hizmet** olarak değerlendirin. Debug veya monitoring rotaları prompt içeriklerini, slot durumunu, model metadata'sını veya dahili kuyruk bilgilerini açığa çıkarabilir. `llama.cpp` içinde `/slots` endpoint'i özellikle hassastır; çünkü slot başına durumu açığa çıkarır ve yalnızca slot inceleme/yönetimi için tasarlanmıştır.<sup>[[8]](#references)</sup>

Açığa çıkmış model runner'larını ve ilgili AI hizmetlerini black-box fingerprinting ve test işlemine tabi tutmak için [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md) sayfasına bakın.

- Inference server'ın önüne bir reverse proxy koyun ve varsayılan olarak **erişimi reddedin**.
- Yalnızca istemci/UI için gereken HTTP method + path eşleşmelerine izin verin.
- Mümkün olduğunda backend'deki introspection endpoint'lerini devre dışı bırakın; örneğin `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Reverse proxy'yi `127.0.0.1` adresine bağlayın ve LAN'da yayımlamak yerine SSH yerel port yönlendirmesi gibi kimlik doğrulamalı bir aktarım üzerinden erişime açın.

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
- `--network none`, gelen/giden TCP/IP maruziyetini ortadan kaldırır ve rootless container'ların aksi hâlde ihtiyaç duyacağı user-mode yardımcılarını önler.
- UNIX socket, ilk erişim denetimi katmanı olarak socket yolunda POSIX izinlerini/ACL'leri kullanmanıza olanak tanır.
- `--userns=keep-id` ve rootless Podman, container root kullanıcısı host root kullanıcısı olmadığından container breakout etkisini azaltır.
- Salt okunur model bağlamaları, container içinden modele müdahale edilmesi olasılığını azaltır.

Kalıcı dağıtımlarda aynı kısıtlamalar Podman Quadlet birimleriyle ifade edilebilir. GPU erişimi Container Device Interface üzerinden devrediliyorsa, her accelerator düğümünü açığa çıkarmak yerine CDI aygıt belirtimini olabildiğince dar kapsamlı tutun.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU aygıt düğümlerini en aza indirme

GPU destekli inference için `/dev/nvidia*` dosyaları, büyük driver `ioctl()` işleyicilerini ve potansiyel olarak paylaşılan GPU bellek yönetimi yollarını açığa çıkardığından yüksek değerli yerel saldırı yüzeyleridir.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` dosyalarını herkes tarafından yazılabilir durumda bırakmayın.
- `nvidia`, `nvidiactl` ve `nvidia-uvm` aygıtlarını `NVreg_DeviceFileUID/GID/Mode`, udev kuralları ve ACL'lerle kısıtlayarak yalnızca eşlenen container UID'sinin bunları açabilmesini sağlayın.
- Headless inference host'larında `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz modülleri kara listeye alın.
- Runtime'ın inference başlangıcında fırsat buldukça `modprobe` çalıştırmasına izin vermek yerine, önyükleme sırasında yalnızca gereken modülleri önceden yükleyin.

Örnek:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Önemli bir inceleme noktası **`/dev/nvidia-uvm`**’dir. İş yükü açıkça `cudaMallocManaged()` kullanmasa bile, güncel CUDA runtime’ları yine de `nvidia-uvm` gerektirebilir. Bu aygıt paylaşıldığından ve GPU sanal bellek yönetimini gerçekleştirdiğinden, kiracılar arası veri ifşasına yol açabilecek bir yüzey olarak ele alınmalıdır. Inference backend bunu destekliyorsa Vulkan backend ilginç bir seçenek olabilir; çünkü `nvidia-uvm`’yi kapsayıcıya hiç açmayı gerektirmeyebilir.<sup>[[8]](#references)</sup>

### Inference çalışanları için LSM kısıtlaması

Inference sürecinin çevresinde, ek bir savunma katmanı olarak AppArmor/SELinux/seccomp kullanılmalıdır:<sup>[[8]](#references)</sup>

- Yalnızca gerçekten gereken paylaşılan kütüphanelere, model yollarına, soket dizinine ve GPU aygıt düğümlerine izin verin.
- `sys_admin`, `sys_module`, `sys_rawio` ve `sys_ptrace` gibi yüksek riskli yetenekleri açıkça reddedin.
- Model dizinini salt okunur tutun ve yazılabilir yolları yalnızca runtime soket/önbellek dizinleriyle sınırlayın.
- Model sunucusu veya post-exploitation payload’ı beklenen davranışının dışına çıkmaya çalıştığında, yararlı tespit telemetrisi sağladıkları için ret günlüklerini izleyin.

GPU destekli bir çalışan için örnek AppArmor kuralları:

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

Phantom squatting, **slopsquatting'in domain/URL eşdeğeridir**. LLM, var olmayan bir paket adını halüsinasyonla üretmek yerine gerçek bir marka için makul görünen bir **portal, API, webhook, faturalandırma, SSO, indirme veya destek domain'i** halüsinasyonla üretir ve bir saldırgan, bir insan ya da agent bunu kullanmadan önce söz konusu namespace'i kaydeder.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Bu önemlidir; çünkü AI destekli birçok iş akışında model çıktısı **güvenilir bir bağımlılık** olarak kabul edilir:
- Geliştiriciler önerilen endpoint'i koda veya CI/CD entegrasyonlarına yapıştırır.
- AI agent'ları dokümantasyonu, şemaları, APK'ları, ZIP dosyalarını veya webhook hedeflerini otomatik olarak getirir.
- Oluşturulan runbook'lar veya dokümanlar, sahte URL'yi yetkili bir kaynakmış gibi içerebilir.

### Saldırı iş akışı

1. **Halüsinasyon yüzeyini araştırın**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` veya `mobile app` portalları gibi gerçekçi iş akışları hakkında markaya özel sorular sorun.<sup>[[12]](#references)</sup>
2. **Adayları normalize edin**: oluşturulan URL'leri çözümleyin, NXDOMAIN yanıtlarını kaydedilebilir üst domain'e indirgeyin ve prompt ailelerindeki tekrarları giderin. Prompt külliyatı çeşitli kalmalı; örneğin **Jaccard benzerliği** kullanarak neredeyse aynı olanları eleyin.
3. **Tahmin edilebilir halüsinasyonlara öncelik verin**:
   - **Thermal Hallucination Persistence (THP)**: aynı sahte domain, `T=0.1` gibi düşük sıcaklıklar da dahil olmak üzere farklı sıcaklıklarda tekrar görünür.
   - **Modeller arası uzlaşma**: birden fazla LLM ailesi aynı sahte domain'i üretir.
4. Üst domain'i **kaydedip silahlandırın**; ardından kimlik avı sayfaları, sahte APK/ZIP indirmeleri, kimlik bilgisi toplayıcıları, kötü amaçlı dokümanlar veya sırları/webhook payload'larını toplayan API endpoint'leri barındırın. **Yalnızca domain düzeyindeki halüsinasyonlardan** para kazanmak en kolaydır; çünkü saldırgan tüm namespace'i kontrol eder. Normalize edilen üst domain kaydedilmemişse subdomain/path halüsinasyonları da kötüye kullanılabilir.
5. **Sıfır itibar penceresinden yararlanın**: yeni kaydedilen domain'lerin genellikle blocklist geçmişi, URL itibarı ve olgun telemetrisi yoktur; bu nedenle tespitler yetişene kadar denetimleri atlatabilirler. Saldırganlar bu pencereyi crawler'lara özel zararsız yanıtlar, yönlendirme gizleme, CAPTCHA kontrolleri veya gecikmeli payload hazırlama yoluyla uzatabilir.

### Agent'lar için neden tehlikeli?

İnsan kurban için sahte domain genellikle tıklama ve ardından başka bir eylem gerektirir. **Agent tabanlı bir iş akışında** ise LLM hem **yem** hem de **uygulayıcı** olabilir: agent halüsinasyonla üretilen URL'yi alır, getirir, yanıtı ayrıştırır ve ardından token'ları sızdırabilir, talimatları çalıştırabilir, bir bağımlılık indirebilir veya insan incelemesi olmadan CI/CD'ye zehirlenmiş veri gönderebilir.<sup>[[12]](#references)</sup>

### Uygulamada kullanılabilecek saldırgan prompt'ları

Verimi yüksek prompt'lar genellikle açık kimlik avı tuzakları yerine sıradan kurumsal görevler gibi görünür:<sup>[[12]](#references)</sup>
- “`<brand>` entegrasyonları için ödeme sandbox URL'si nedir?”
- “`<brand>` build bildirimleri için hangi webhook endpoint'ini kullanmalıyım?”
- “`<brand>` için çalışan yan hakları / faturalandırma / SSO portalı nerede?”
- “`<brand>` için doğrudan Android APK'sını veya masaüstü istemci indirme bağlantısını ver.”

### Savunma amaçlı tersine çevirme

Bunu yalnızca prompt injection sorunu olarak değil, proaktif bir domain izleme sorunu olarak ele alın:<sup>[[12]](#references)</sup>
- Kullanıcılarınızın/agent'larınızın yararlandığı LLM'leri düzenli olarak araştırmak için bir **marka prompt külliyatı** oluşturun.
- Halüsinasyonla üretilen URL'leri saklayın ve sıcaklıklar/modeller arasında hangilerinin tutarlı olduğunu izleyin.
- **Adversarial Exploitation Window (AEW)** değerini izleyin: ilk halüsinasyon ile saldırganın domain'i kaydetmesi arasındaki süre. Pozitif AEW, savunucuların domain'i önceden kaydetmesine, sinkhole etmesine veya silahlandırılmadan önce engellemesine olanak tanır.
- Üst domain'lerin **NXDOMAIN → kayıtlı** geçişlerini izleyin.
- Kayıt tespit edildiğinde registrar'ı, oluşturulma tarihini, nameserver'ları, gizlilik korumasını, sayfa içeriğini, ekran görüntülerini, park edilmiş sayfa durumunu ve marka varlıklarına benzerliğini inceleyin.
- Agent'ların/geliştiricilerin **LLM tarafından oluşturulan domain'lere varsayılan olarak güvenmemesi** için politika kontrolleri ekleyin: ilk kullanımdan önce allowlist, sahiplik doğrulaması, CT/RDAP kontrolleri veya insan onayı isteyin.

Bu durum aynı anda birkaç AI risk kategorisine girer: **AI tedarik zinciri saldırısı**, **güvenli olmayan model çıktısı** ve agent'ların halüsinasyonla üretilen URL'yi otonom biçimde tükettiği **rogue actions**.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [OWASP Makine Öğreniminin En Önemli 10 Güvenlik Açığı](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Riskler](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Tehdit Matrisi](https://atlas.mitre.org/)
- [4] [Unit 42 – Code Assistant LLM'lerin Riskleri: Zararlı İçerik, Kötüye Kullanım ve Aldatma](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Yeni Bir AI Saldırısında Kullanılan Çalınmış Cloud Kimlik Bilgileri](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking düzenine genel bakış – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (çalınmış LLM erişimini yeniden satma)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Yerel ortamda dağıtılan, düşük ayrıcalıklı bir LLM sunucusunun derinlemesine incelenmesi](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp sunucusu README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlet'leri: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) spesifikasyonu](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI Halüsinasyonuyla Oluşturulan Domain'ler, Yazılım Tedarik Zinciri Vektörü Olarak](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI Halüsinasyonları Yeni Bir Tedarik Zinciri Saldırısı Sınıfını Nasıl Besliyor?](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2: AI özellikli yeni command-and-control framework'ü](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
