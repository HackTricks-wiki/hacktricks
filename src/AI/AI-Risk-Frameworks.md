# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp, AI sistemlerini etkileyebilecek en yaygın 10 makine öğrenimi açığını belirledi. Bu zayıflıklar veri zehirlenmesi, model tersine çevirme ve adversarial saldırılar dahil olmak üzere çeşitli güvenlik sorunlarına yol açabilir. Bu zayıflıkları anlamak, güvenli AI sistemleri inşa etmek için kritiktir.

Güncel ve detaylı liste için [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) projesine bakın.

- **Input Manipulation Attack**: Bir saldırgan, modelin yanlış karar vermesine neden olmak için **gelen veriye** çok küçük, genellikle görünmez değişiklikler ekler.\
*Örnek*: Bir dur işaretine birkaç boya lekesi eklenmesi, otonom bir aracı bunu hız limiti işareti olarak "görmeye" kandırır.

- **Data Poisoning Attack**: **eğitim seti** kötü örneklerle kasıtlı olarak kirletilir ve modele zararlı kurallar öğretilir.\
*Örnek*: Bir antivirüs eğitim korpusunda kötü amaçlı ikili dosyalar "zararsız" olarak yanlış etiketlenirse, benzer malware sonra tespit edilmeden kaçabilir.

- **Model Inversion Attack**: Çıktılar sorgulanarak, saldırgan orijinal girdilerin hassas özelliklerini yeniden oluşturan bir **ters model** inşa eder.\
*Örnek*: Bir kanser tespit modelinin tahminlerinden bir hastanın MRI görüntüsünün yeniden oluşturulması.

- **Membership Inference Attack**: Rakip, eğitim sırasında belirli bir kaydın kullanılıp kullanılmadığını güven farklarını tespit ederek test eder.\
*Örnek*: Bir kişinin banka işleminin dolandırıcılık tespit modelinin eğitim verisinde yer aldığını doğrulamak.

- **Model Theft**: Tekrarlanan sorgulamalar sayesinde saldırgan karar sınırlarını öğrenir ve **modelin davranışını klonlar** (ve fikri mülkiyeti çalar).\
*Örnek*: Bir ML‑as‑a‑Service API'sinden yeterli sayıda Soru‑Cevap çifti toplayarak neredeyse eşdeğer bir lokal model oluşturmak.

- **AI Supply‑Chain Attack**: **ML pipeline** içindeki herhangi bir bileşenin (veri, kütüphaneler, pre‑trained weights, CI/CD) ele geçirilmesi, türev modellerin bozulmasına yol açar.\
*Örnek*: Bir model‑hub üzerindeki zehirlenmiş bir bağımlılık, birçok uygulamaya arka kapılı bir sentiment‑analiz modeli kurar.

- **Transfer Learning Attack**: Kötü amaçlı mantık, bir **pre‑trained model** içine yerleştirilir ve kurbanın görevi için fine‑tune edildikten sonra bile hayatta kalır.\
*Örnek*: Gizli bir tetik içeren bir vision backbone, tıbbi görüntüleme için uyarlandıktan sonra bile etiketleri tersine çevirir.

- **Model Skewing**: İnce bir şekilde önyargılı veya yanlış etiketlenmiş veri, modelin çıktılarında saldırganın gündemini **tercih eden kaymaları** yaratır.\
*Örnek*: "Temiz" spam e‑postaları ham olarak etiketleyip bir spam filtresinin gelecekte benzer mailleri kaçırmasını sağlamak.

- **Output Integrity Attack**: Saldırgan, modeli değil, **model tahminlerini iletim sırasında değiştirir**, böylece downstream sistemleri kandırır.\
*Örnek*: Bir malware sınıflandırıcısının "malicious" kararını dosya‑karantinaya alınmadan önce "benign" olarak değiştirmek.

- **Model Poisoning** --- Yazma erişimi elde edildikten sonra sıklıkla doğrudan, hedefli şekilde **model parametrelerinde** değişiklik yapılarak davranışın değiştirilmesi.\
*Örnek*: Prodüksiyondaki bir dolandırıcılık tespit modelinin ağırlıklarını kırpıp belirli kartlardan gelen işlemlerin her zaman onaylanmasını sağlamak.


## Google SAIF Risks

Google'ın [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) AI sistemleriyle ilişkili çeşitli riskleri özetler:

- **Data Poisoning**: Kötü niyetli aktörler eğitim/ayarlama verisini değiştirir veya enjekte eder; doğruluğu bozar, backdoor yerleştirir veya sonuçları kaydırır, böylece model bütün veri‑yaşam döngüsü boyunca bütünlüğünü yitirir.

- **Unauthorized Training Data**: Telif hakkı korumalı, hassas veya izin verilmemiş veri kümelerinin alınması; modelin asla kullanmasına izin verilmeyen verilerden öğrenmesi nedeniyle yasal, etik ve performans sorumlulukları yaratır.

- **Model Source Tampering**: Tedarik zinciri veya içeriden müdahale ile model kodu, bağımlılıklar veya weights eğitim öncesi veya sırasında manipüle edilerek gizli mantık yerleştirilebilir ve yeniden eğitimden sonra bile devam edebilir.

- **Excessive Data Handling**: Zayıf veri‑saklama ve yönetişim kontrolleri sistemlerin gereğinden fazla kişisel veri saklamasına veya işlemesine izin verir; maruziyeti ve uyumluluk riskini arttırır.

- **Model Exfiltration**: Saldırganlar model dosyalarını/weights çalar; fikri mülkiyet kaybına, taklit hizmetlere veya takip saldırılarına olanak sağlar.

- **Model Deployment Tampering**: Saldırganlar model artefaktlarını veya servis altyapısını değiştirir, böylece çalışan model onaylanan sürümden farklı olur ve davranışı değiştirir.

- **Denial of ML Service**: API'leri doldurmak veya “sponge” girdiler göndermek hesaplama/enerji tüketimini tükenebilir ve modeli çevrimdışı bırakabilir; klasik DoS saldırılarına benzer.

- **Model Reverse Engineering**: Büyük sayıda input‑output çifti toplayarak saldırganlar modeli klonlayabilir veya distill edebilir; taklit ürünleri ve özelleştirilmiş adversarial saldırıları besler.

- **Insecure Integrated Component**: Güvenliği zayıf eklentiler, ajanlar veya upstream servisler saldırganların kod enjekte etmesine veya AI pipeline içinde ayrıcalık yükseltmesine izin verir.

- **Prompt Injection**: Sistemin niyetini geçersiz kılacak komutları kaçırmak için (doğrudan veya dolaylı) crafted promptlar oluşturmak; modelin istenmeyen komutları yerine getirmesine sebep olur.

- **Model Evasion**: Özenle tasarlanmış girdiler modelin yanlış sınıflandırmasına, halüsinasyona veya yasaklı içeriği üretmesine neden olur; güvenilirlik ve güveni aşındırır.

- **Sensitive Data Disclosure**: Model, eğitim verisinden veya kullanıcı bağlamından özel ya da gizli bilgileri açığa çıkarır; mahremiyeti ve düzenlemeleri ihlal eder.

- **Inferred Sensitive Data**: Model, hiç sağlanmamış kişisel özellikleri tahmin eder; çıkarım yoluyla yeni mahremiyet zararları oluşturur.

- **Insecure Model Output**: Temizlenmemiş yanıtlar zararlı kod, yanlış bilgi veya uygunsuz içerik olarak kullanıcılara veya downstream sistemlere iletilir.

- **Rogue Actions**: Otonom entegre ajanlar, uygun kullanıcı gözetimi olmadan istenmeyen gerçek dünya işlemleri (dosya yazma, API çağrıları, satın almalar vb.) gerçekleştirir.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) AI sistemleriyle ilişkili riskleri anlamak ve hafifletmek için kapsamlı bir çerçeve sağlar. Matrix, saldırganların AI modellere karşı kullanabileceği çeşitli saldırı tekniklerini ve taktikleri ile AI sistemlerini kullanarak farklı saldırılar gerçekleştirme yollarını kategorize eder.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Saldırganlar aktif oturum tokenlarını veya cloud API kimlik bilgilerini çalar ve yetkisiz olarak ücretli, cloud‑hosted LLM'leri çağırır. Erişim genellikle kurbanın hesabını öne çıkaran reverse proxy'ler aracılığıyla yeniden satılır; örn. "oai-reverse-proxy" dağıtımları. Sonuçlar arasında finansal kayıp, modelin politikanın dışına çıkarak kötüye kullanımı ve kurban tenant'a atfedilme yer alır.

TTPs:
- Enfekte olmuş geliştirici makinelerinden veya tarayıcılardan token toplamak; CI/CD gizli anahtarlarını çalmak; sızdırılmış cookies satın almak.
- Gerçek sağlayıcıya istekleri ileten, upstream anahtarı gizleyen ve birden fazla müşteriyi multiplex eden bir reverse proxy kurmak.
- Kurumsal guardrails ve rate limitleri atlatmak için doğrudan base‑model endpoint'lerini suistimal etmek.

Mitigations:
- Tokenları cihaz parmak izi, IP aralıkları ve client attestation ile bağlamak; kısa sürelere zorlamak ve MFA ile yenilemek.
- Anahtarları minimal scope'la sınırlandırmak (araç erişimi yok, gerekiyorsa yalnızca read‑only); anomalide döndürmek.
- Güvenlik filtreleri, rota bazlı kotalar ve tenant izolasyonu uygulayan bir policy gateway arkasında tüm trafiği server‑side sonlandırmak.
- Olağan dışı kullanım desenlerini (ani harcama sıçramaları, alışılmadık bölgeler, UA stringleri) izlemek ve şüpheli oturumları otomatik iptal etmek.
- Uzun ömürlü statik API anahtarları yerine mTLS veya IdP'niz tarafından verilen imzalı JWT'leri tercih edin.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
