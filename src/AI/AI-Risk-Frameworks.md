# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP, AI sistemlerini etkileyebilecek en önemli 10 machine learning güvenlik açığını belirlemiştir. Bu güvenlik açıkları; data poisoning, model inversion ve adversarial attacks gibi çeşitli güvenlik sorunlarına yol açabilir. Güvenli AI sistemleri oluşturmak için bu güvenlik açıklarını anlamak çok önemlidir.

En önemli 10 machine learning güvenlik açığının güncel ve ayrıntılı listesi için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine bakın.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Saldırgan, modelin yanlış karar vermesini sağlamak için **gelen verilerde** küçük ve çoğu zaman görünmez değişiklikler yapar.\
    *Örnek*: Birkaç boya lekesi, otonom aracın dur levhasını hız sınırı levhası olarak "görmesine" neden olur.

- **Data Poisoning Attack**: Modeli zararlı kuralları öğrenmeye yönlendirmek için **training set** kasıtlı olarak bozulur.\
*Örnek*: Bir antivirus eğitim derlemindeki malware dosyaları "zararsız" olarak etiketlenir ve benzer malware dosyalarının daha sonra tespit edilmeden geçmesi sağlanır.

- **Model Inversion Attack**: Saldırgan, modelin çıktılarından yararlanarak orijinal girdilerin hassas özelliklerini yeniden oluşturan bir **ters model** kurar.\
*Örnek*: Bir kanser tespit modelinin tahminlerinden hastaya ait MRI görüntüsünü yeniden oluşturmak.

- **Membership Inference Attack**: Saldırgan, güven düzeyindeki farklılıklara bakarak **belirli bir kaydın** eğitim sırasında kullanılıp kullanılmadığını test eder.\
*Örnek*: Bir kişinin banka işleminin fraud-detection modelinin training data'sında bulunduğunu doğrulamak.

- **Model Theft**: Tekrarlanan sorgular, saldırganın karar sınırlarını öğrenmesini ve **modelin davranışını (ve fikri mülkiyetini) kopyalamasını** sağlar.\
*Örnek*: ML-as-a-Service API'sinden yeterli sayıda soru-cevap çiftini toplayarak neredeyse eşdeğer bir yerel model oluşturmak.

- **AI Supply-Chain Attack**: **ML pipeline** içindeki herhangi bir bileşenin (data, libraries, pre-trained weights, CI/CD) ele geçirilmesi, sonraki aşamalardaki modelleri bozabilir.\
*Örnek*: Bir model-hub'daki zehirlenmiş bir dependency, birçok uygulamaya arka kapılı bir sentiment-analysis modelinin yüklenmesine neden olur.

- **Transfer Learning Attack**: **Pre-trained model** içine kötü amaçlı mantık yerleştirilir ve bu mantık, kurbanın görevi için yapılan fine-tuning sonrasında da varlığını sürdürür.\
*Örnek*: Gizli bir tetikleyici içeren bir vision backbone, medical imaging için uyarlandıktan sonra da etiketleri değiştirmeye devam eder.

- **Model Skewing**: İnce biçimde yanlı veya yanlış etiketlenmiş veriler, saldırganın amacını destekleyecek şekilde **model çıktılarını kaydırır**.\
*Örnek*: Spam filtresinin benzer gelecek e-postaları geçirmesini sağlamak için "temiz" spam e-postalarını ham olarak etiketleyip eklemek.

- **Output Integrity Attack**: Saldırgan modelin kendisini değil, **model tahminlerini aktarım sırasında değiştirerek** sonraki sistemleri yanıltır.\
*Örnek*: Dosya karantinası aşamasına ulaşmadan önce bir malware classifier'ın "kötü amaçlı" kararını "zararsız" olarak değiştirmek.

- **Model Poisoning** --- Genellikle yazma erişimi elde ettikten sonra, davranışı değiştirmek için doğrudan ve hedefli biçimde **model parametrelerini** değiştirmek.\
*Örnek*: Üretimdeki bir fraud-detection modelinin ağırlıklarını değiştirerek belirli kartlarla yapılan işlemlerin her zaman onaylanmasını sağlamak.


## Google SAIF Riskleri

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) çerçevesi, AI sistemleriyle ilişkili çeşitli riskleri açıklar:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Kötü amaçlı kişiler, doğruluğu düşürmek, arka kapılar yerleştirmek veya sonuçları saptırmak için training/tuning verilerini değiştirir ya da veri ekler. Bu, tüm data lifecycle boyunca model bütünlüğünü zedeler.

- **Unauthorized Training Data**: Telif hakkıyla korunan, hassas veya kullanılması için izin alınmamış veri kümelerinin alınması; modelin kullanma izni olmayan verilerden öğrenmesi nedeniyle hukuki, etik ve performans açısından riskler doğurur.

- **Model Source Tampering**: Eğitimden önce veya eğitim sırasında model kodunun, dependency'lerin ya da ağırlıkların supply-chain veya içeriden biri tarafından değiştirilmesi, yeniden eğitimden sonra bile varlığını sürdüren gizli mantıklar ekleyebilir.

- **Excessive Data Handling**: Zayıf data-retention ve governance kontrolleri, sistemlerin gereğinden fazla kişisel veri saklamasına veya işlemesine yol açarak veri ihlali ve mevzuata uyum risklerini artırır.

- **Model Exfiltration**: Saldırganlar model dosyalarını/ağırlıklarını çalar; bu da fikri mülkiyet kaybına ve taklit hizmetlerin ya da sonraki saldırıların önünü açar.

- **Model Deployment Tampering**: Saldırganlar model artefact'larını veya serving altyapısını değiştirerek çalışan modelin doğrulanmış sürümden farklı olmasına ve olası davranış değişikliklerine yol açar.

- **Denial of ML Service**: API'lere istek yağdırmak veya “sponge” girdiler göndermek, işlem gücünü/enerjiyi tüketerek modeli devre dışı bırakabilir; bu, klasik DoS attacks yöntemlerine benzer.

- **Model Reverse Engineering**: Çok sayıda girdi-çıktı çiftini toplayan saldırganlar modeli kopyalayabilir veya distil edebilir; bu da taklit ürünlerin ve özelleştirilmiş adversarial attacks yöntemlerinin önünü açar.

- **Insecure Integrated Component**: Güvenlik açığı bulunan plugin'ler, agent'lar veya upstream hizmetler, saldırganların AI pipeline içinde kod eklemesine ya da yetkilerini yükseltmesine olanak tanır.

- **Prompt Injection**: Sistem amacını geçersiz kılan talimatları gizlice eklemek ve modelin istenmeyen komutları yerine getirmesini sağlamak için doğrudan veya dolaylı prompt'lar oluşturmak.

- **Model Evasion**: Özenle tasarlanmış girdiler, modelin yanlış sınıflandırma yapmasına, hallucinate etmesine veya izin verilmeyen içerikler üretmesine neden olarak güvenliği ve güveni zedeler.

- **Sensitive Data Disclosure**: Model, training data'sından veya kullanıcı bağlamından özel ya da gizli bilgileri açığa çıkararak gizlilik ve mevzuat gerekliliklerini ihlal eder.

- **Inferred Sensitive Data**: Model, hiç paylaşılmamış kişisel özellikleri çıkarım yoluyla belirleyerek yeni gizlilik zararlarına neden olur.

- **Insecure Model Output**: Temizlenmemiş yanıtlar, zararlı kodları, yanlış bilgileri veya uygunsuz içerikleri kullanıcılara ya da sonraki sistemlere iletir.

- **Rogue Actions**: Otonom olarak entegre edilmiş agent'lar, yeterli kullanıcı denetimi olmadan istenmeyen gerçek dünya işlemlerini (dosya yazma, API çağrıları, satın alma vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve azaltmak için kapsamlı bir çerçeve sunar. Saldırganların AI modellerine karşı kullanabileceği çeşitli saldırı tekniklerini ve taktiklerini, ayrıca farklı saldırıları gerçekleştirmek için AI sistemlerinin nasıl kullanılabileceğini sınıflandırır.<sup>[[3]](#references)</sup>

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Saldırganlar etkin session token'larını veya cloud API kimlik bilgilerini çalarak ücretli, cloud-hosted LLM'leri yetkisiz şekilde kullanır. Erişim genellikle kurbanın hesabını arka planda kullanan reverse proxy'ler üzerinden, örneğin "oai-reverse-proxy" kurulumları aracılığıyla yeniden satılır. Sonuçlar arasında maddi kayıp, modelin politikalar dışında kötüye kullanılması ve işlemlerin kurban tenant'a atfedilmesi bulunur.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP'ler:
- Bulaşmış geliştirici makinelerinden veya tarayıcılardan token toplamak; CI/CD secrets'ları çalmak; sızdırılmış cookies satın almak.<sup>[[5]](#references)</sup>
- İstekleri gerçek sağlayıcıya ileten, upstream key'i gizleyen ve birçok müşterinin isteklerini bir araya getiren bir reverse proxy kurmak.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Kurumsal guardrail'leri ve rate limit'leri aşmak için doğrudan base-model endpoint'lerini kötüye kullanmak.<sup>[[4]](#references)</sup>

Azaltma yöntemleri:
- Token'ları cihaz parmak izine, IP aralıklarına ve client attestation'a bağlayın; kısa süreli geçerlilik uygulayın ve MFA ile yenileyin.
- Key'lere yalnızca gereken en düşük kapsamı verin (tool erişimi vermeyin; uygunsa salt okunur kullanın); anomali tespit edildiğinde key'leri döndürün.
- Tüm trafiği, safety filter'ları, route başına kotaları ve tenant izolasyonunu uygulayan bir policy gateway arkasında, sunucu tarafında sonlandırın.
- Olağandışı kullanım modellerini (harcamada ani artışlar, alışılmadık bölgeler, UA string'leri) izleyin ve şüpheli session'ları otomatik olarak iptal edin.
- Uzun süre geçerli statik API key'leri yerine, IdP'niz tarafından verilen mTLS veya imzalı JWT'leri tercih edin.

## Self-hosted LLM inference güvenliğinin güçlendirilmesi

Gizli veriler için yerel bir LLM server çalıştırmak, cloud-hosted API'lerden farklı bir saldırı yüzeyi oluşturur: inference/debug endpoint'leri prompt'ları sızdırabilir, serving stack genellikle bir reverse proxy'yi açığa çıkarır ve GPU device node'ları geniş `ioctl()` yüzeylerine erişim sağlar. On-prem bir inference service'i değerlendiriyor veya dağıtıyorsanız en azından aşağıdaki noktaları gözden geçirin.<sup>[[8]](#references)</sup>

### Debug ve monitoring endpoint'leri üzerinden prompt sızıntısı

Inference API'sini **birden çok kullanıcının eriştiği hassas bir hizmet** olarak değerlendirin. Debug veya monitoring route'ları prompt içeriklerini, slot durumunu, model metadata'sını ya da dahili kuyruk bilgilerini açığa çıkarabilir. `llama.cpp` içinde `/slots` endpoint'i, slota özgü durumu açığa çıkardığı ve yalnızca slot inceleme/yönetimi için tasarlandığı için özellikle hassastır.<sup>[[8]](#references)</sup>

Açık durumdaki model runner'larını ve ilişkili AI hizmetlerini black-box fingerprinting ve test işlemine tabi tutmak için [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md) sayfasına bakın.

- Inference server'ın önüne bir reverse proxy koyun ve **varsayılan olarak tüm erişimi reddedin**.
- Yalnızca client/UI için gereken tam HTTP method + path kombinasyonlarına allowlist üzerinden izin verin.
- Mümkün olduğunda backend'deki introspection endpoint'lerini devre dışı bırakın; örneğin `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Reverse proxy'yi `127.0.0.1` adresine bağlayın ve LAN'de yayımlamak yerine SSH local port forwarding gibi kimlik doğrulamalı bir aktarım yöntemiyle erişime açın.

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

### Ağsız ve UNIX socket kullanan rootless container'lar

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

Faydaları:
- `--network none`, gelen/giden TCP/IP maruziyetini ortadan kaldırır ve rootless container'ların aksi hâlde ihtiyaç duyacağı user-mode yardımcılarını devre dışı bırakır.
- UNIX socket, ilk erişim denetimi katmanı olarak socket yolunda POSIX izinlerini/ACL'leri kullanmanızı sağlar.
- `--userns=keep-id` ve rootless Podman, container içindeki root kullanıcısı host root olmadığı için container breakout etkisini azaltır.
- Salt okunur model mount'ları, container içinden modelin kurcalanması olasılığını azaltır.

Kalıcı dağıtımlar için aynı kısıtlamalar Podman Quadlet birimleriyle ifade edilebilir. GPU erişimi Container Device Interface üzerinden devrediliyorsa, her hızlandırıcı düğümünü açığa çıkarmak yerine CDI aygıt belirtimini olabildiğince dar tutun.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU aygıt düğümü minimizasyonu

GPU destekli çıkarım için `/dev/nvidia*` dosyaları, büyük sürücü `ioctl()` işleyicilerini ve potansiyel olarak paylaşılan GPU bellek yönetimi yollarını açığa çıkardığından yüksek değerli yerel saldırı yüzeyleridir.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` dosyalarını tüm kullanıcılara yazılabilir bırakmayın.
- Yalnızca eşlenmiş container UID'sinin bu dosyaları açabilmesi için `nvidia`, `nvidiactl` ve `nvidia-uvm` erişimini `NVreg_DeviceFileUID/GID/Mode`, udev kuralları ve ACL'lerle kısıtlayın.
- Başsız çıkarım sunucularında `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz modülleri kara listeye alın.
- Çalışma zamanının çıkarım başlangıcı sırasında fırsatçı biçimde `modprobe` çalıştırmasına izin vermek yerine, yalnızca gerekli modülleri önyükleme sırasında önceden yükleyin.

Örnek:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Önemli bir inceleme noktası **`/dev/nvidia-uvm`**'dir. İş yükü açıkça `cudaMallocManaged()` kullanmasa bile güncel CUDA runtime'ları `nvidia-uvm` gerektirebilir. Bu aygıt paylaşıldığından ve GPU sanal bellek yönetimini gerçekleştirdiğinden, tenant'lar arası veri ifşası yüzeyi olarak değerlendirin. Inference backend bunu destekliyorsa Vulkan backend ilginç bir ödünleşim sunabilir; çünkü `nvidia-uvm`'yi container'a hiç açığa çıkarmayabilir.<sup>[[8]](#references)</sup>

### Inference worker'ları için LSM kısıtlaması

Inference sürecinde ek bir güvenlik katmanı olarak AppArmor/SELinux/seccomp kullanılmalıdır:<sup>[[8]](#references)</sup>

- Yalnızca gerçekten gereken paylaşılan kütüphanelere, model yollarına, socket dizinine ve GPU aygıt düğümlerine izin verin.
- `sys_admin`, `sys_module`, `sys_rawio` ve `sys_ptrace` gibi yüksek riskli yetenekleri açıkça engelleyin.
- Model dizinini salt okunur tutun ve yazılabilir yolları yalnızca runtime socket/cache dizinleriyle sınırlandırın.
- Reddetme günlüklerini izleyin; bunlar, model sunucusu veya post-exploitation payload beklenen davranışın dışına çıkmaya çalıştığında yararlı tespit telemetrisi sağlar.

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

## Phantom Squatting: AI Tarafından Halüsinasyonla Üretilen Alan Adları, AI Tedarik Zinciri Vektörü Olarak

Phantom squatting, **slopsquatting'in alan adı/URL karşılığıdır**. LLM, var olmayan bir paket adını halüsinasyonla üretmek yerine gerçek bir marka için makul görünen bir **portal, API, webhook, faturalandırma, SSO, indirme veya destek alan adı** uydurur ve saldırgan, bir insan ya da agent bu alan adını kullanmadan önce ilgili ad alanını kaydeder.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Bu önemlidir; çünkü AI destekli birçok iş akışında model çıktısı **güvenilir bir bağımlılık** olarak değerlendirilir:
- Geliştiriciler önerilen endpoint'i koda veya CI/CD entegrasyonlarına yapıştırır.
- AI agent'ları belgeleri, şemaları, APK'ları, ZIP'leri veya webhook hedeflerini otomatik olarak getirir.
- Oluşturulan runbook'lar veya belgeler, sahte URL'yi yetkili bir kaynakmış gibi içerebilir.

### Saldırı iş akışı

1. **Halüsinasyon yüzeyini araştırın**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` veya `mobile app` portalları gibi gerçekçi iş akışları hakkında markaya özgü sorular sorun.<sup>[[12]](#references)</sup>
2. **Adayları normalleştirin**: oluşturulan URL'leri çözümleyin, NXDOMAIN yanıtlarını kaydedilebilir ana alan adına indirgeyin ve prompt ailelerindeki tekrarları kaldırın. Örneğin, **Jaccard benzerliği** kullanarak neredeyse aynı olanları çıkarıp prompt derlemlerini çeşitli tutun.
3. **Tahmin edilebilir halüsinasyonlara öncelik verin**:
   - **Thermal Hallucination Persistence (THP)**: aynı sahte alan adı, `T=0.1` gibi düşük sıcaklıklar da dahil olmak üzere farklı sıcaklıklarda görünür.
   - **Modeller arası uzlaşma**: birden fazla LLM ailesi aynı sahte alan adını üretir.
4. Ana alan adını **kaydedip silahlandırın**; ardından kimlik avı, sahte APK/ZIP indirmeleri, kimlik bilgisi toplayıcıları, kötü amaçlı belgeler veya sırları/webhook payload'larını toplayan API endpoint'leri barındırın. **Yalnızca alan adı düzeyindeki halüsinasyonların** paraya dönüştürülmesi en kolaydır; çünkü saldırgan tüm ad alanını kontrol eder. Normalleştirilmiş ana alan adı kaydedilmemişse alt alan adı/yol halüsinasyonları da kötüye kullanılabilir.
5. **Sıfır itibar penceresinden yararlanın**: yeni kaydedilen alan adlarında genellikle engelleme listesi geçmişi, URL itibarı ve olgun telemetri bulunmaz; bu nedenle tespitler yetişene kadar kontrolleri aşabilirler. Saldırganlar bu pencereyi yalnızca crawler'lara zararsız yanıtlar vererek, yönlendirme gizleme kullanarak, CAPTCHA kapıları ekleyerek veya payload'ları gecikmeli olarak devreye alarak uzatabilir.

### Agent'lar için neden tehlikeli?

İnsan kurban için sahte alan adı genellikle yine de bir tıklama ve başka bir eylem gerektirir. **Agentic bir iş akışında** ise LLM hem **yem** hem de **uygulayıcı** olabilir: agent halüsinasyonla üretilen URL'yi alır, getirir, yanıtı ayrıştırır ve ardından insan denetimi olmadan token'ları leak edebilir, talimatları çalıştırabilir, bir bağımlılık indirebilir veya zehirlenmiş verileri CI/CD'ye gönderebilir.<sup>[[12]](#references)</sup>

### Saldırganlar için pratik prompt'lar

Yüksek verim sağlayan prompt'lar genellikle açık kimlik avı tuzakları yerine normal kurumsal görevler gibi görünür:<sup>[[12]](#references)</sup>
- “`<brand>` entegrasyonları için ödeme sandbox URL'si nedir?”
- “`<brand>` derleme bildirimleri için hangi webhook endpoint'ini kullanmalıyım?”
- “`<brand>` için çalışan yan hakları / faturalandırma / SSO portalı nerede?”
- “`<brand>` için doğrudan Android APK'sını veya masaüstü istemci indirmesini ver.”

### Savunma amaçlı tersine çevirme

Bunu yalnızca bir prompt injection sorunu olarak değil, proaktif bir alan adı izleme sorunu olarak ele alın:<sup>[[12]](#references)</sup>
- Kullanıcılarınızın/agent'larınızın yararlandığı LLM'leri düzenli olarak araştırmak için bir **marka prompt derlemi** oluşturun.
- Halüsinasyonla üretilen URL'leri saklayın ve hangilerinin farklı sıcaklıklar/modeller arasında kararlı kaldığını izleyin.
- **Adversarial Exploitation Window (AEW)** değerini izleyin: ilk halüsinasyon ile saldırganın alan adını kaydetmesi arasındaki süre. Pozitif AEW, savunucuların silahlandırılmadan önce alan adını önceden kaydetmesine, sinkhole etmesine veya önceden engellemesine olanak tanır.
- Ana alan adlarındaki **NXDOMAIN → kayıtlı** geçişlerini izleyin.
- Alan adı kaydedildiğinde kayıt operatörünü, oluşturulma tarihini, ad sunucularını, gizlilik korumasını, sayfa içeriğini, ekran görüntülerini, park edilmiş sayfa durumunu ve marka varlıklarına benzerliği inceleyin.
- Agent'ların/geliştiricilerin **LLM tarafından oluşturulan alan adlarına varsayılan olarak güvenmemesini** sağlayacak politika kapıları ekleyin: ilk kullanımdan önce izin listeleri, sahiplik doğrulaması, CT/RDAP kontrolleri veya insan onayı zorunlu olsun.

Bu saldırı aynı anda birkaç AI risk kategorisine girer: **AI tedarik zinciri saldırısı**, **güvenli olmayan model çıktısı** ve agent'ların halüsinasyonla üretilen URL'yi otonom olarak tükettiği durumlarda **yetkisiz eylemler**.

## References

- [1] [OWASP Makine Öğrenimi Güvenlik Açıkları İlk 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Güvenli AI Çerçevesi) – Riskler](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Tehdit Matrisi](https://atlas.mitre.org/)
- [4] [Unit 42 – Kod Asistanı LLM'lerinin Riskleri: Zararlı İçerik, Kötüye Kullanım ve Aldatma](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Yeni Bir AI Saldırısında Kullanılan Çalınmış Cloud Kimlik Bilgileri](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking planına genel bakış – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (çalınmış LLM erişiminin yeniden satılması)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Ayrıcalıkları düşük, şirket içi bir LLM sunucusunun dağıtımına derinlemesine bakış](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) spesifikasyonu](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI Halüsinasyonuyla Üretilen Alan Adları, Yazılım Tedarik Zinciri Vektörü Olarak](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI Halüsinasyonları Yeni Bir Tedarik Zinciri Saldırısı Sınıfını Nasıl Besliyor?](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
