# Yapay Zeka Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp, AI sistemlerini etkileyebilecek en önemli 10 machine learning güvenlik açığını belirlemiştir. Bu güvenlik açıkları; data poisoning, model inversion ve adversarial attacks dahil olmak üzere çeşitli güvenlik sorunlarına yol açabilir. Güvenli AI sistemleri oluşturmak için bu güvenlik açıklarını anlamak çok önemlidir.

En güncel ve ayrıntılı ilk 10 machine learning güvenlik açığı listesi için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine bakın.<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Saldırgan, modelin yanlış karar vermesine neden olmak için **gelen verilerde** küçük ve çoğu zaman görünmez değişiklikler yapar.\
    *Örnek*: Dur işaretine sürülen birkaç boya lekesi, sürücüsüz bir otomobilin işareti hız sınırı tabelası olarak "görmesine" neden olur.

- **Data Poisoning Attack**: **Training set**, modele zararlı kurallar öğreten kötü örneklerle kasıtlı olarak kirletilir.\
*Örnek*: Antivirus training corpus içindeki malware binary dosyaları yanlışlıkla "zararsız" olarak etiketlenir ve benzer malware örneklerinin daha sonra tespit edilmeden geçmesine olanak tanır.

- **Model Inversion Attack**: Saldırgan, çıktıları sorgulayarak **ters bir model** oluşturur ve bu modelle özgün girdilerin hassas özelliklerini yeniden oluşturur.\
*Örnek*: Bir cancer-detection modelinin tahminlerinden hastanın MRI görüntüsünü yeniden oluşturmak.

- **Membership Inference Attack**: Saldırgan, güven skorlarındaki farklılıklara bakarak **belirli bir kaydın** training sırasında kullanılıp kullanılmadığını test eder.\
*Örnek*: Bir kişinin banka işleminin fraud-detection modelinin training verilerinde bulunduğunu doğrulamak.

- **Model Theft**: Tekrarlanan sorgular, saldırganın karar sınırlarını öğrenmesine ve modelin davranışını (ve IP'sini) **kopyalamasına** olanak tanır.\
*Örnek*: ML-as-a-Service API'sinden yeterli sayıda soru-cevap çifti toplayarak neredeyse eşdeğer bir yerel model oluşturmak.

- **AI Supply-Chain Attack**: **ML pipeline** içindeki herhangi bir bileşenin (veri, libraries, önceden eğitilmiş weights, CI/CD) ele geçirilmesi, sonraki modellerin bozulmasına yol açar.\
*Örnek*: Model-hub üzerindeki zehirli bir dependency, birçok uygulamaya arka kapı içeren bir sentiment-analysis modelini yükler.

- **Transfer Learning Attack**: Kötü amaçlı mantık **önceden eğitilmiş bir modele** yerleştirilir ve kurbanın görevine göre fine-tuning yapıldıktan sonra da varlığını sürdürür.\
*Örnek*: Gizli bir tetikleyici içeren vision backbone, medical imaging için uyarlandıktan sonra da etiketleri değiştirmeye devam eder.

- **Model Skewing**: İnce biçimde yanlı veya yanlış etiketlenmiş veriler, saldırganın amacını desteklemek için **model çıktılarının yönünü değiştirir**.\
*Örnek*: Spam filtresinin gelecekteki benzer e-postaları geçirmesini sağlamak için "temiz" spam e-postalarını ham olarak etiketleyip sisteme eklemek.

- **Output Integrity Attack**: Saldırgan modelin kendisini değil, **model tahminlerini aktarım sırasında değiştirerek** sonraki sistemleri kandırır.\
*Örnek*: Dosya karantina aşaması sonucu görmeden önce malware classifier'ın "kötü amaçlı" kararını "zararsız" olarak değiştirmek.

- **Model Poisoning** --- Genellikle yazma erişimi elde edildikten sonra, davranışı değiştirmek için doğrudan **model parameters** üzerinde hedefli değişiklikler yapmak.\
*Örnek*: Belirli kartlardan yapılan işlemlerin her zaman onaylanması için üretimdeki fraud-detection modelinin weights değerlerini değiştirmek.


## Google SAIF Riskleri

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) çerçevesi, AI sistemleriyle ilişkili çeşitli riskleri açıklar:<sup>[[2]](#references)</sup>

- **Data Poisoning**: Kötü niyetli kişiler, doğruluğu düşürmek, arka kapılar yerleştirmek veya sonuçları saptırmak için training/tuning verilerini değiştirir ya da sisteme veri ekler; böylece tüm data-lifecycle boyunca model bütünlüğünü tehlikeye atar. 

- **Unauthorized Training Data**: Telifli, hassas veya kullanım izni olmayan veri kümelerinin alınması; modelin kullanmasına izin verilmeyen verilerden öğrenmesi nedeniyle hukuki, etik ve performansla ilgili sorumluluklar doğurur. 

- **Model Source Tampering**: Training öncesinde veya sırasında model kodunun, dependencies ya da weights değerlerinin supply-chain saldırısıyla veya içeriden biri tarafından değiştirilmesi, yeniden training sonrasında bile varlığını sürdüren gizli mantıklar ekleyebilir. 

- **Excessive Data Handling**: Veri saklama ve yönetişim kontrollerinin zayıf olması, sistemlerin gerekenden fazla kişisel veriyi depolamasına veya işlemesine yol açarak maruziyet ve uyumluluk riskini artırır. 

- **Model Exfiltration**: Saldırganlar model dosyalarını/weights değerlerini çalar; bu da fikri mülkiyet kaybına yol açar ve kopya hizmetlerin ya da sonraki saldırıların önünü açar. 

- **Model Deployment Tampering**: Saldırganlar model artifact'lerini veya serving altyapısını değiştirerek çalışan modelin onaylanmış sürümden farklı olmasına ve davranışının değişmesine yol açabilir. 

- **Denial of ML Service**: API'lere aşırı istek göndermek veya "sponge" girdileri kullanmak, compute/energy kaynaklarını tüketerek modeli devre dışı bırakabilir; bu, klasik DoS saldırılarına benzer. 

- **Model Reverse Engineering**: Çok sayıda girdi-çıktı çifti toplayan saldırganlar modeli kopyalayabilir veya distil edebilir; bu da taklit ürünlerin ve özelleştirilmiş adversarial attacks'ların önünü açar. 

- **Insecure Integrated Component**: Güvenlik açığı bulunan plugins, agents veya upstream services, saldırganların AI pipeline'a kod eklemesine ya da ayrıcalıklarını yükseltmesine olanak tanır. 

- **Prompt Injection**: Sistem amacını geçersiz kılacak talimatları gizlice yerleştirmek ve modelin istenmeyen komutları yerine getirmesini sağlamak için doğrudan veya dolaylı prompt'lar oluşturmak. 

- **Model Evasion**: Özenle hazırlanmış girdiler, modelin yanlış sınıflandırma yapmasına, hallucination üretmesine veya izin verilmeyen içerikler sunmasına neden olarak güvenliği ve güveni zedeler. 

- **Sensitive Data Disclosure**: Model, training verilerinden veya kullanıcı bağlamından özel ya da gizli bilgileri açığa çıkararak gizliliği ve mevzuatı ihlal eder. 

- **Inferred Sensitive Data**: Model, hiç paylaşılmamış kişisel özellikleri çıkarımla belirleyerek yeni gizlilik zararlarına yol açar. 

- **Insecure Model Output**: Temizlenmemiş yanıtlar; zararlı kodu, yanlış bilgileri veya uygunsuz içeriği kullanıcılara ya da sonraki sistemlere aktarır. 

- **Rogue Actions**: Otonom olarak entegre edilmiş agents, yeterli kullanıcı denetimi olmadan istenmeyen gerçek dünya işlemlerini (dosya yazma, API çağrıları, satın alma vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve azaltmak için kapsamlı bir çerçeve sunar. Bu çerçeve, saldırganların AI modellerine karşı kullanabileceği çeşitli saldırı tekniklerini ve taktiklerini, ayrıca farklı saldırıları gerçekleştirmek için AI sistemlerinin nasıl kullanılabileceğini sınıflandırır.<sup>[[3]](#references)</sup>

## LLMJacking (Token Hırsızlığı ve Bulutta Barındırılan LLM Erişiminin Yeniden Satışı)

Saldırganlar, etkin session token'larını veya cloud API credentials'larını çalarak ücretli, bulutta barındırılan LLM'leri yetkisiz şekilde kullanır. Erişim genellikle kurbanın hesabını kullanan reverse proxy'ler aracılığıyla yeniden satılır; örneğin "oai-reverse-proxy" kurulumları. Sonuçları arasında maddi kayıp, modelin politikalara aykırı kullanılması ve faaliyetlerin kurban tenant'ına atfedilmesi bulunur.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP'ler:
- Bulaşmış geliştirici makinelerinden veya browser'lardan token'ları toplamak; CI/CD secrets'larını çalmak; leak edilmiş cookies satın almak.<sup>[[5]](#references)</sup>
- İstekleri gerçek provider'a ileten, upstream key'i gizleyen ve birçok müşteriyi aynı anda destekleyen bir reverse proxy kurmak.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Kurumsal guardrails ve rate limits'i aşmak için doğrudan base-model endpoints'lerini kötüye kullanmak.<sup>[[4]](#references)</sup>

Azaltma yöntemleri:
- Token'ları device fingerprint'e, IP aralıklarına ve client attestation'a bağlayın; kısa süreli geçerlilik uygulayın ve MFA ile yenileyin.
- Keys kapsamını olabildiğince dar tutun (tool erişimi vermeyin, mümkün olan yerlerde salt okunur yapın); anormallik durumunda rotate edin.
- Tüm trafiği, safety filters, route başına kotalar ve tenant izolasyonu uygulayan bir policy gateway arkasından sunucu tarafında sonlandırın.
- Olağandışı kullanım örüntülerini (ani harcama artışları, alışılmadık bölgeler, UA strings) izleyin ve şüpheli oturumları otomatik olarak iptal edin.
- Uzun süre geçerli statik API keys yerine mTLS veya IdP'niz tarafından verilen imzalı JWT'leri tercih edin.

## Kendi barındırdığınız LLM inference'ını güçlendirme

Gizli veriler için yerel bir LLM server çalıştırmak, cloud-hosted APIs'lerden farklı bir saldırı yüzeyi oluşturur: inference/debug endpoints prompt'ları sızdırabilir, serving stack genellikle bir reverse proxy'yi dışarı açar ve GPU device nodes geniş `ioctl()` saldırı yüzeylerine erişim sağlar. Şirket içi bir inference service'i değerlendiriyor veya devreye alıyorsanız en azından aşağıdaki noktaları gözden geçirin.<sup>[[8]](#references)</sup>

### Debug ve monitoring endpoints üzerinden prompt sızıntısı

Inference API'yi **çok kullanıcılı, hassas bir hizmet** olarak ele alın. Debug veya monitoring routes; prompt içeriklerini, slot durumunu, model metadata'sını ya da dahili queue bilgilerini açığa çıkarabilir. `llama.cpp` içinde `/slots` endpoint'i özellikle hassastır; her slotun durumunu açığa çıkarır ve yalnızca slot inceleme/yönetimi için tasarlanmıştır.<sup>[[8]](#references)</sup>

- Inference server'ın önüne bir reverse proxy koyun ve **varsayılan olarak tüm erişimi reddedin**.
- Yalnızca istemci/UI için gereken belirli HTTP method + path kombinasyonlarını allowlist'e ekleyin.
- Mümkün olduğunda backend'deki introspection endpoints'lerini devre dışı bırakın; örneğin `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Reverse proxy'yi `127.0.0.1` adresine bind edin ve LAN'de yayımlamak yerine SSH local port forwarding gibi kimlik doğrulamalı bir aktarım üzerinden erişime açın.

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

### Ağ erişimi olmayan ve UNIX socket kullanan rootless container'lar

Inference daemon UNIX socket üzerinden dinlemeyi destekliyorsa, bunu TCP'ye tercih edin ve container'ı **ağ yığını olmadan** çalıştırın:<sup>[[8]](#references)</sup>

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
- `--network none`, gelen/giden TCP/IP maruziyetini ortadan kaldırır ve rootless container'ların aksi takdirde ihtiyaç duyacağı user-mode yardımcılarını devre dışı bırakır.
- UNIX socket, ilk erişim denetimi katmanı olarak socket yolu üzerinde POSIX izinlerini/ACL'leri kullanmanızı sağlar.
- `--userns=keep-id` ve rootless Podman, container breakout'unun etkisini azaltır; çünkü container içindeki root, host üzerindeki root değildir.
- Salt okunur model mount'ları, container içinden modele müdahale edilmesi olasılığını azaltır.

Kalıcı dağıtımlarda aynı kısıtlamalar Podman Quadlet birimleriyle ifade edilebilir. GPU erişimi Container Device Interface üzerinden devrediliyorsa, tüm hızlandırıcı düğümlerini açığa çıkarmak yerine CDI aygıt belirtimini olabildiğince dar kapsamlı tutun.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### GPU aygıt düğümlerini en aza indirme

GPU destekli inference için `/dev/nvidia*` dosyaları, büyük sürücü `ioctl()` işleyicilerini ve muhtemelen paylaşılan GPU bellek yönetimi yollarını açığa çıkardığından yüksek değerli yerel saldırı yüzeyleridir.<sup>[[8]](#references)</sup>

- `/dev/nvidia*` dosyalarını herkes tarafından yazılabilir durumda bırakmayın.
- Yalnızca eşlenmiş container UID'sinin bu dosyaları açabilmesi için `nvidia`, `nvidiactl` ve `nvidia-uvm` aygıtlarını `NVreg_DeviceFileUID/GID/Mode`, udev kuralları ve ACL'lerle kısıtlayın.
- Headless inference sunucularında `nvidia_drm`, `nvidia_modeset` ve `nvidia_peermem` gibi gereksiz modülleri kara listeye alın.
- Runtime'ın inference başlangıcında fırsatçı biçimde `modprobe` etmesine izin vermek yerine, önyükleme sırasında yalnızca gerekli modülleri önceden yükleyin.

Örnek:

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Önemli bir inceleme noktası **`/dev/nvidia-uvm`**'dir. İş yükü açıkça `cudaMallocManaged()` kullanmasa bile, güncel CUDA runtime'ları `nvidia-uvm`'yi yine de gerektirebilir. Bu aygıt paylaşıldığı ve GPU sanal bellek yönetimini gerçekleştirdiği için, bunu kiracılar arası veri ifşasına yol açabilecek bir saldırı yüzeyi olarak değerlendirin. Inference backend bunu destekliyorsa, Vulkan backend ilginç bir seçenek olabilir; çünkü `nvidia-uvm`'nin container'a hiç açılmasını önleyebilir.<sup>[[8]](#references)</sup>

### Inference worker'ları için LSM kısıtlaması

Inference sürecini çok katmanlı savunma kapsamında korumak için AppArmor/SELinux/seccomp kullanılmalıdır:<sup>[[8]](#references)</sup>

- Yalnızca gerçekten gereken paylaşılan kütüphanelere, model yollarına, socket dizinine ve GPU aygıt düğümlerine izin verin.
- `sys_admin`, `sys_module`, `sys_rawio` ve `sys_ptrace` gibi yüksek riskli yetenekleri açıkça engelleyin.
- Model dizinini salt okunur tutun ve yazılabilir yolları yalnızca runtime socket/cache dizinleriyle sınırlandırın.
- Reddetme günlüklerini izleyin; model sunucusu veya bir post-exploitation payload beklenen davranış sınırlarının dışına çıkmaya çalıştığında bu günlükler faydalı tespit telemetrisi sağlar.

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

## Phantom Squatting: LLM Halüsinasyonuyla Üretilen Alan Adları Bir AI Tedarik Zinciri Vektörü Olarak

Phantom squatting, **slopsquatting'in alan adı/URL eşdeğeridir**. LLM, var olmayan bir paket adını halüsinasyonla üretmek yerine gerçek bir markaya ait makul görünen bir **portal, API, webhook, faturalandırma, SSO, indirme veya destek alan adı** uydurur; saldırgan da bir insan ya da agent bunu kullanmadan önce ilgili namespace'i kaydeder.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Bu önemlidir; çünkü AI destekli pek çok iş akışında model çıktısı **güvenilir bir bağımlılık** olarak kabul edilir:
- Geliştiriciler önerilen endpoint'i koda veya CI/CD entegrasyonlarına yapıştırır.
- AI agent'ları dokümantasyonu, şemaları, APK'ları, ZIP dosyalarını veya webhook hedeflerini otomatik olarak getirir.
- Oluşturulan runbook'lar veya dokümanlar, sahte URL'yi yetkili bir kaynaktan geliyormuş gibi içerebilir.

### Offensive workflow

1. **Halüsinasyon yüzeyini araştırın**: `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` veya `mobile app` portalları gibi gerçekçi iş akışları hakkında markaya özel sorular sorun.<sup>[[12]](#references)</sup>
2. **Adayları normalleştirin**: oluşturulan URL'leri çözümleyin, NXDOMAIN yanıtlarını kaydedilebilir üst alan adına indirgeme yoluyla ele alın ve prompt ailelerindeki yinelenenleri kaldırın. Prompt derlemleri çeşitli tutulmalıdır; örneğin **Jaccard benzerliği** kullanarak birbirine çok benzeyenleri çıkarın.
3. **Öngörülebilir halüsinasyonlara öncelik verin**:
   - **Thermal Hallucination Persistence (THP)**: aynı sahte alan adı farklı sıcaklıklarda, `T=0.1` gibi düşük sıcaklıklarda bile görünür.
   - **Modeller arası uzlaşı**: birden fazla LLM ailesi aynı sahte alan adını üretir.
4. Üst alan adını **kaydedip silahlandırın**; ardından kimlik avı, sahte APK/ZIP indirmeleri, kimlik bilgisi toplayıcılar, kötü amaçlı dokümanlar veya sırları/webhook payload'larını toplayan API endpoint'leri barındırın. **Salt alan adı düzeyindeki halüsinasyonlardan** para kazanmak en kolaydır; çünkü saldırgan tüm namespace'i kontrol eder. Normalleştirilmiş üst alan adı kaydedilmemişse alt alan adı/yol halüsinasyonları da kötüye kullanılabilir.
5. **Sıfır itibar penceresinden yararlanın**: yeni kaydedilmiş alan adlarının genellikle blocklist geçmişi, URL itibarı ve olgun telemetrisi olmaz; bu nedenle tespitler yetişene kadar denetimleri atlatabilirler. Saldırganlar tarayıcılara özel zararsız yanıtlar, yönlendirme gizleme, CAPTCHA kapıları veya gecikmeli payload yerleştirme kullanarak bu pencereyi uzatabilir.

### Agent'lar için neden tehlikeli?

İnsan kurban için sahte alan adı genellikle bir tıklama ve ek bir eylem gerektirir. **Agent tabanlı bir iş akışında** LLM hem **yem** hem de **uygulayıcı** olabilir: agent halüsinasyonla üretilmiş URL'yi alır, URL'ye erişir, yanıtı ayrıştırır ve ardından token'ları leak edebilir, talimatları çalıştırabilir, bir bağımlılık indirebilir veya zehirlenmiş verileri insan incelemesi olmadan CI/CD'ye gönderebilir.<sup>[[12]](#references)</sup>

### Saldırganlar için pratik prompt'lar

Yüksek verimli prompt'lar genellikle açık kimlik avı tuzaklarından ziyade normal kurumsal görevlere benzer:<sup>[[12]](#references)</sup>
- “`<brand>` entegrasyonları için ödeme sandbox URL'si nedir?”
- “`<brand>` derleme bildirimleri için hangi webhook endpoint'ini kullanmalıyım?”
- “`<brand>` için çalışan yan hakları / faturalandırma / SSO portalı nerede?”
- “`<brand>` için doğrudan Android APK'sını veya masaüstü istemcisi indirme bağlantısını ver.”

### Savunma amaçlı tersine çevirme

Bunu yalnızca bir prompt injection sorunu olarak değil, proaktif bir alan adı izleme problemi olarak ele alın:<sup>[[12]](#references)</sup>
- Bir **marka prompt derlemi** oluşturun ve kullanıcılarınızın/agent'larınızın güvendiği LLM'leri düzenli olarak sorgulayın.
- Halüsinasyonla üretilen URL'leri saklayın ve sıcaklıklar/modeller arasında hangilerinin kararlı olduğunu izleyin.
- **Adversarial Exploitation Window (AEW)** değerini izleyin: ilk halüsinasyon ile saldırganın alan adını kaydetmesi arasındaki süre. Pozitif AEW, savunucuların silahlandırılmadan önce alan adını önceden kaydetmesine, sinkhole etmesine veya engellemesine olanak tanır.
- Üst alan adlarının **NXDOMAIN → kayıtlı** geçişlerini izleyin.
- Alan adı kaydedildiğinde kayıt kuruluşunu, oluşturulma tarihini, nameserver'ları, gizlilik kalkanlamasını, sayfa içeriğini, ekran görüntülerini, park edilmiş sayfa durumunu ve marka varlıklarına benzerliğini inceleyin.
- Agent'ların/geliştiricilerin **LLM tarafından oluşturulan alan adlarına varsayılan olarak güvenmemesi** için politika kontrolleri ekleyin: ilk kullanımdan önce allowlist, sahiplik doğrulaması, CT/RDAP kontrolleri veya insan onayı isteyin.

Bu durum aynı anda birkaç AI risk kategorisine girer: **AI tedarik zinciri saldırısı**, **güvenli olmayan model çıktısı** ve agent'ların halüsinasyonla oluşturulmuş URL'yi otonom olarak tükettiği **rogue actions**.

## References

- [1] [OWASP Machine Learning Güvenlik Açıkları İlk 10 Listesi](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Riskler](https://saif.google/secure-ai-framework/risks)
- [3] [MITRE ATLAS Tehdit Matrisi](https://atlas.mitre.org/)
- [4] [Unit 42 – Code Assistant LLM'lerinin Riskleri: Zararlı İçerik, Kötüye Kullanım ve Aldatma](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking: Yeni Bir AI Saldırısında Kullanılan Çalıntı Cloud Kimlik Bilgileri](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [LLMJacking planına genel bakış – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (çalıntı LLM erişimini yeniden satma)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - On-premise, düşük ayrıcalıklı bir LLM sunucusunun dağıtımına derinlemesine bakış](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [llama.cpp sunucusu README dosyası](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [CNCF Container Device Interface (CDI) belirtimi](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting: AI Halüsinasyonuyla Üretilen Alan Adları Bir Yazılım Tedarik Zinciri Vektörü Olarak](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting: AI Halüsinasyonları Yeni Bir Tedarik Zinciri Saldırısı Sınıfını Nasıl Besliyor?](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
