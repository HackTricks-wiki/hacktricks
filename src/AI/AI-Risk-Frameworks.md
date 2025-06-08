# AI Riskleri

{{#include ../banners/hacktricks-training.md}}

## OWASP En İyi 10 Makine Öğrenimi Açığı

Owasp, AI sistemlerini etkileyebilecek en iyi 10 makine öğrenimi açığını belirlemiştir. Bu açıklar, veri zehirlenmesi, model tersine çevirme ve düşmanca saldırılar gibi çeşitli güvenlik sorunlarına yol açabilir. Bu açıkları anlamak, güvenli AI sistemleri inşa etmek için kritik öneme sahiptir.

En güncel ve detaylı en iyi 10 makine öğrenimi açığı listesi için [OWASP En İyi 10 Makine Öğrenimi Açığı](https://owasp.org/www-project-machine-learning-security-top-10/) projesine başvurun.

- **Girdi Manipülasyonu Saldırısı**: Bir saldırgan, modelin yanlış karar vermesi için **gelen verilerde** küçük, genellikle görünmez değişiklikler ekler.\
*Örnek*: Bir dur işaretinin üzerine birkaç boya lekesi eklemek, otonom bir arabanın hız sınırı işaretini "görmesini" yanıltır.

- **Veri Zehirlenmesi Saldırısı**: **Eğitim seti**, kötü örneklerle kasıtlı olarak kirletilir ve modele zararlı kurallar öğretilir.\
*Örnek*: Kötü amaçlı yazılım ikilileri, bir antivirüs eğitim kümesinde "zararsız" olarak yanlış etiketlenir, böylece benzer kötü amaçlı yazılımlar daha sonra geçer.

- **Model Tersine Çevirme Saldırısı**: Çıktıları sorgulayarak, bir saldırgan orijinal girdilerin hassas özelliklerini yeniden oluşturan bir **ters model** inşa eder.\
*Örnek*: Bir kanser tespit modelinin tahminlerinden bir hastanın MRI görüntüsünü yeniden oluşturmak.

- **Üyelik Çıkarım Saldırısı**: Düşman, bir **belirli kaydın** eğitim sırasında kullanılıp kullanılmadığını güven farklarını tespit ederek test eder.\
*Örnek*: Bir kişinin banka işleminin bir dolandırıcılık tespit modelinin eğitim verilerinde göründüğünü doğrulamak.

- **Model Hırsızlığı**: Tekrar eden sorgulamalar, bir saldırganın karar sınırlarını öğrenmesine ve **modelin davranışını** (ve IP'yi) kopyalamasına olanak tanır.\
*Örnek*: Bir ML-as-a-Service API'sinden yeterince Soru-Cevap çifti toplayarak neredeyse eşdeğer bir yerel model oluşturmak.

- **AI Tedarik Zinciri Saldırısı**: **ML boru hattındaki** herhangi bir bileşeni (veri, kütüphaneler, önceden eğitilmiş ağırlıklar, CI/CD) tehlikeye atarak aşağı akış modellerini bozmak.\
*Örnek*: Bir model merkezi üzerindeki zehirli bir bağımlılık, birçok uygulama arasında arka kapılı bir duygu analizi modelini kurar.

- **Transfer Öğrenme Saldırısı**: Kötü niyetli bir mantık, bir **önceden eğitilmiş modelde** yerleştirilir ve kurbanın görevinde ince ayar yapıldığında hayatta kalır.\
*Örnek*: Gizli bir tetikleyiciye sahip bir görsel omurga, tıbbi görüntüleme için uyarlanmış olsa bile etiketleri değiştirmeye devam eder.

- **Model Çarpıtma**: İnce bir şekilde önyargılı veya yanlış etiketlenmiş veriler, **modelin çıktısını** saldırganın gündemini destekleyecek şekilde kaydırır.\
*Örnek*: "Temiz" spam e-postalarını ham olarak etiketleyerek, bir spam filtresinin benzer gelecekteki e-postaları geçmesine izin vermek.

- **Çıktı Bütünlüğü Saldırısı**: Saldırgan, **model tahminlerini iletim sırasında** değiştirir, modeli değil, aşağı akış sistemlerini yanıltır.\
*Örnek*: Bir kötü amaçlı yazılım sınıflandırıcısının "kötü" kararını "zararsız" olarak değiştirmek, dosya karantina aşamasında görünmeden önce.

- **Model Zehirlenmesi** --- **Model parametrelerine** doğrudan, hedeflenmiş değişiklikler, genellikle yazma erişimi kazandıktan sonra, davranışı değiştirmek için.\
*Örnek*: Üretimdeki bir dolandırıcılık tespit modelinin ağırlıklarını ayarlamak, belirli kartlardan gelen işlemlerin her zaman onaylanmasını sağlamak.

## Google SAIF Riskleri

Google'ın [SAIF (Güvenlik AI Çerçevesi)](https://saif.google/secure-ai-framework/risks), AI sistemleriyle ilişkili çeşitli riskleri özetlemektedir:

- **Veri Zehirlenmesi**: Kötü niyetli aktörler, doğruluğu azaltmak, arka kapılar yerleştirmek veya sonuçları çarpıtmak için eğitim/ayar verilerini değiştirir veya ekler, bu da model bütünlüğünü tüm veri yaşam döngüsü boyunca zayıflatır.

- **Yetkisiz Eğitim Verisi**: Telif hakkı olan, hassas veya izin verilmeyen veri setlerinin alınması, modelin asla kullanmasına izin verilmediği verilerden öğrenmesi nedeniyle yasal, etik ve performans sorumlulukları yaratır.

- **Model Kaynağı Manipülasyonu**: Eğitim öncesi veya sırasında model kodu, bağımlılıkları veya ağırlıkları tedarik zinciri veya iç kaynaklar tarafından manipüle edilmesi, yeniden eğitimden sonra bile devam eden gizli mantık yerleştirebilir.

- **Aşırı Veri Yönetimi**: Zayıf veri saklama ve yönetim kontrolleri, sistemlerin gerekli olandan daha fazla kişisel veri saklamasına veya işlemesine neden olur, bu da maruz kalma ve uyum riskini artırır.

- **Model Sızdırılması**: Saldırganlar model dosyalarını/ağırlıklarını çalar, bu da fikri mülkiyet kaybına ve taklit hizmetlerin veya takip eden saldırıların mümkün olmasına neden olur.

- **Model Dağıtım Manipülasyonu**: Düşmanlar, çalışan modelin onaylanmış versiyondan farklı olmasını sağlamak için model nesnelerini veya sunum altyapısını değiştirir, bu da davranışı değiştirebilir.

- **ML Hizmetine Red**: API'leri doldurmak veya "sünger" girdileri göndermek, hesaplama/enerjiyi tüketebilir ve modeli çevrimdışı bırakabilir, klasik DoS saldırılarını yansıtır.

- **Model Tersine Mühendislik**: Büyük sayıda girdi-çıktı çifti toplayarak, saldırganlar modeli kopyalayabilir veya damıtabilir, bu da taklit ürünleri ve özelleştirilmiş düşmanca saldırıları besler.

- **Güvensiz Entegre Bileşen**: Zayıf eklentiler, ajanlar veya yukarı akış hizmetleri, saldırganların AI boru hattında kod enjekte etmesine veya ayrıcalıkları artırmasına izin verir.

- **İstemci Enjeksiyonu**: Sistem niyetini geçersiz kılacak talimatları gizlice taşımak için istemcileri (doğrudan veya dolaylı olarak) oluşturmak, modelin istenmeyen komutlar gerçekleştirmesine neden olur.

- **Model Kaçışı**: Özenle tasarlanmış girdiler, modelin yanlış sınıflandırmasına, hayal etmesine veya yasaklı içerik çıkarmasına neden olur, bu da güvenliği ve güveni zayıflatır.

- **Hassas Veri Açığa Çıkması**: Model, eğitim verilerinden veya kullanıcı bağlamından özel veya gizli bilgileri açığa çıkarır, bu da gizliliği ve düzenlemeleri ihlal eder.

- **Çıkarılan Hassas Veri**: Model, asla sağlanmamış kişisel özellikleri çıkarır, bu da çıkarım yoluyla yeni gizlilik zararları yaratır.

- **Güvensiz Model Çıktısı**: Sanitasyondan geçmemiş yanıtlar, kullanıcılara veya aşağı akış sistemlerine zararlı kod, yanlış bilgi veya uygunsuz içerik iletebilir.

- **Serseri Eylemler**: Otonom olarak entegre edilmiş ajanlar, yeterli kullanıcı denetimi olmadan istenmeyen gerçek dünya işlemleri (dosya yazma, API çağrıları, satın almalar vb.) gerçekleştirir.

## Mitre AI ATLAS Matrisi

[MITRE AI ATLAS Matrisi](https://atlas.mitre.org/matrices/ATLAS), AI sistemleriyle ilişkili riskleri anlamak ve azaltmak için kapsamlı bir çerçeve sunar. Düşmanların AI modellerine karşı kullanabileceği çeşitli saldırı tekniklerini ve taktiklerini kategorize eder ve ayrıca AI sistemlerini farklı saldırılar gerçekleştirmek için nasıl kullanabileceğinizi gösterir.

{{#include ../banners/hacktricks-training.md}}
