# Tehdit Modelleme

{{#include ../banners/hacktricks-training.md}}

## Tehdit Modelleme

HackTricks'in Tehdit Modelleme üzerine kapsamlı kılavuzuna hoş geldiniz! Bu kritik siber güvenlik alanını keşfetmeye başlayın; burada bir sistemdeki potansiyel zayıflıkları tanımlıyor, anlıyor ve bunlara karşı stratejiler geliştiriyoruz. Bu konu, gerçek dünya örnekleri, yararlı yazılımlar ve anlaşılması kolay açıklamalarla dolu adım adım bir kılavuz olarak hizmet vermektedir. Hem yeni başlayanlar hem de siber güvenlik savunmalarını güçlendirmek isteyen deneyimli uygulayıcılar için idealdir.

### Yaygın Olarak Kullanılan Senaryolar

1. **Yazılım Geliştirme**: Güvenli Yazılım Geliştirme Yaşam Döngüsü (SSDLC) kapsamında, tehdit modelleme, geliştirme sürecinin erken aşamalarında **potansiyel zayıflık kaynaklarını tanımlamaya** yardımcı olur.
2. **Sızma Testi**: Sızma Testi Uygulama Standardı (PTES) çerçevesi, testi gerçekleştirmeden önce **sistemin zayıflıklarını anlamak için tehdit modellemesi** gerektirir.

### Tehdit Modeli Kısaca

Bir Tehdit Modeli genellikle bir diyagram, resim veya bir uygulamanın planlanan mimarisini veya mevcut yapısını gösteren başka bir görsel illüstrasyon olarak temsil edilir. Bu, bir **veri akış diyagramı** ile benzerlik gösterir, ancak ana fark güvenlik odaklı tasarımında yatmaktadır.

Tehdit modelleri genellikle kırmızı ile işaretlenmiş unsurlar içerir; bu, potansiyel zayıflıkları, riskleri veya engelleri simgeler. Risk tanımlama sürecini kolaylaştırmak için CIA (Gizlilik, Bütünlük, Erişilebilirlik) üçlüsü kullanılır ve bu, birçok tehdit modelleme metodolojisinin temelini oluşturur; STRIDE en yaygın olanlardan biridir. Ancak, seçilen metodoloji belirli bağlama ve gereksinimlere bağlı olarak değişebilir.

### CIA Üçlüsü

CIA Üçlüsü, bilgi güvenliği alanında yaygın olarak tanınan bir modeldir ve Gizlilik, Bütünlük ve Erişilebilirlik anlamına gelir. Bu üç sütun, birçok güvenlik önlemi ve politikasının temelini oluşturur; bunlar arasında tehdit modelleme metodolojileri de bulunmaktadır.

1. **Gizlilik**: Verilerin veya sistemin yetkisiz kişiler tarafından erişilmemesini sağlamak. Bu, veri ihlallerini önlemek için uygun erişim kontrolleri, şifreleme ve diğer önlemleri gerektiren güvenliğin merkezi bir yönüdür.
2. **Bütünlük**: Verilerin yaşam döngüsü boyunca doğruluğu, tutarlılığı ve güvenilirliği. Bu ilke, verilerin yetkisiz taraflarca değiştirilmemesini veya bozulmamasını sağlar. Genellikle kontrol toplamları, hashleme ve diğer veri doğrulama yöntemlerini içerir.
3. **Erişilebilirlik**: Bu, verilerin ve hizmetlerin ihtiyaç duyulduğunda yetkili kullanıcılara erişilebilir olmasını sağlar. Bu genellikle sistemlerin kesintilere rağmen çalışmaya devam etmesi için yedeklilik, hata toleransı ve yüksek erişilebilirlik yapılandırmalarını içerir.

### Tehdit Modelleme Metodolojileri

1. **STRIDE**: Microsoft tarafından geliştirilen STRIDE, **Sahtecilik, Manipülasyon, Reddetme, Bilgi Açıklaması, Hizmet Reddi ve Yetki Yükseltme** için bir kısaltmadır. Her kategori bir tehdit türünü temsil eder ve bu metodoloji, potansiyel tehditleri tanımlamak için bir program veya sistemin tasarım aşamasında yaygın olarak kullanılır.
2. **DREAD**: Bu, tanımlanan tehditlerin risk değerlendirmesi için kullanılan başka bir Microsoft metodolojisidir. DREAD, **Zarar potansiyeli, Yeniden üretilebilirlik, Sömürülebilirlik, Etkilenen kullanıcılar ve Keşfedilebilirlik** anlamına gelir. Bu faktörlerin her biri puanlanır ve sonuç, tanımlanan tehditlerin önceliklendirilmesinde kullanılır.
3. **PASTA** (Saldırı Simülasyonu ve Tehdit Analizi Süreci): Bu, yedi adımlı, **risk merkezli** bir metodolojidir. Güvenlik hedeflerini tanımlama ve belirleme, teknik kapsam oluşturma, uygulama ayrıştırma, tehdit analizi, zayıflık analizi ve risk/triage değerlendirmesini içerir.
4. **Trike**: Bu, varlıkları savunmaya odaklanan risk temelli bir metodolojidir. **Risk yönetimi** perspektifinden başlar ve tehditler ile zayıflıkları bu bağlamda inceler.
5. **VAST** (Görsel, Çevik ve Basit Tehdit Modelleme): Bu yaklaşım, daha erişilebilir olmayı hedefler ve Çevik geliştirme ortamlarına entegre olur. Diğer metodolojilerden unsurlar birleştirir ve **tehditlerin görsel temsillerine** odaklanır.
6. **OCTAVE** (Operasyonel Olarak Kritik Tehdit, Varlık ve Zayıflık Değerlendirmesi): CERT Koordinasyon Merkezi tarafından geliştirilen bu çerçeve, **belirli sistemler veya yazılımlar yerine kurumsal risk değerlendirmesine** yöneliktir.

## Araçlar

Tehdit modellerinin oluşturulması ve yönetilmesi konusunda **yardımcı** olabilecek çeşitli araçlar ve yazılım çözümleri mevcuttur. İşte göz önünde bulundurabileceğiniz birkaç tane.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Siber güvenlik profesyonelleri için gelişmiş, çok özellikli, çok platformlu bir GUI web örümceği/gezgini. Spider Suite, saldırı yüzeyi haritalama ve analiz için kullanılabilir.

**Kullanım**

1. Bir URL Seçin ve Tarayın

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Grafiği Görüntüleyin

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP'tan açık kaynak bir proje olan Threat Dragon, sistem diyagramları ile tehditleri/azaltmaları otomatik olarak oluşturmak için bir kural motoru içeren hem web hem de masaüstü uygulamasıdır.

**Kullanım**

1. Yeni Proje Oluşturun

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Bazen şöyle görünebilir:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Yeni Projeyi Başlatın

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Yeni Projeyi Kaydedin

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Modelinizi Oluşturun

İlham almak için SpiderSuite Crawler gibi araçlar kullanabilirsiniz, temel bir model şöyle görünebilir:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Varlıklar hakkında biraz açıklama:

- Süreç (Web sunucusu veya web işlevi gibi varlık)
- Aktör (Bir Kişi, örneğin bir Web Sitesi Ziyaretçisi, Kullanıcı veya Yöneticisi)
- Veri Akış Hattı (Etkileşim Göstergesi)
- Güven Sınırı (Farklı ağ segmentleri veya kapsamları.)
- Depolama (Verilerin depolandığı yerler, örneğin Veritabanları)

5. Bir Tehdit Oluşturun (Adım 1)

Öncelikle bir tehdidi eklemek istediğiniz katmanı seçmelisiniz.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Şimdi tehdidi oluşturabilirsiniz.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Aktör Tehditleri ile Süreç Tehditleri arasında bir fark olduğunu unutmayın. Eğer bir Aktöre tehdit eklerseniz, yalnızca "Sahtecilik" ve "Reddetme" seçeneklerini seçebilirsiniz. Ancak örneğimizde bir Süreç varlığına tehdit eklediğimiz için tehdit oluşturma kutusunda bunu göreceğiz:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Tamam

Artık bitmiş modeliniz şöyle görünmelidir. Ve OWASP Threat Dragon ile basit bir tehdit modeli nasıl oluşturduğunuz budur.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Bu, yazılım projelerinin tasarım aşamasında tehditleri bulmaya yardımcı olan Microsoft'tan ücretsiz bir araçtır. STRIDE metodolojisini kullanır ve özellikle Microsoft'un yığını üzerinde geliştirme yapanlar için uygundur.

{{#include ../banners/hacktricks-training.md}}
