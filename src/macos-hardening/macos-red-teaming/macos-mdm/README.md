# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM'ler hakkında bilgi edinmek için:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Temel Bilgiler

### **MDM (Mobile Device Management) Genel Bakış**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM), akıllı telefonlar, dizüstü bilgisayarlar ve tabletler gibi çeşitli son kullanıcı cihazlarını yönetmek için kullanılır. Özellikle Apple platformları (iOS, macOS, tvOS) için özel özellikler, API'ler ve uygulamalardan oluşur. MDM'nin çalışması, ticari olarak sunulan veya açık kaynaklı olan ve [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)'ü desteklemesi gereken uyumlu bir MDM sunucusuna bağlıdır. Önemli noktalar şunlardır:

- Cihazlar üzerinde merkezi kontrol sağlar.
- MDM protokolüne uyan bir MDM sunucusuna bağlıdır.
- MDM sunucusu cihazlara uzaktan veri silme veya yapılandırma yükleme gibi çeşitli komutlar gönderebilir.

### **DEP (Device Enrollment Program) Temel Bilgileri**

Apple'ın sunduğu [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), iOS, macOS ve tvOS cihazları için sıfır dokunuşlu yapılandırma sağlayarak Mobile Device Management (MDM) entegrasyonunu kolaylaştırır. DEP, kayıt işlemini otomatikleştirir ve cihazların kutudan çıkar çıkmaz, kullanıcı veya yönetici müdahalesini en aza indirerek çalışır durumda olmasını sağlar. Temel özellikleri şunlardır:

- Cihazların ilk etkinleştirme sırasında önceden tanımlanmış bir MDM sunucusuna otomatik olarak kaydolmasını sağlar.
- Öncelikle yeni cihazlar için faydalıdır, ancak yeniden yapılandırılan cihazlarda da kullanılabilir.
- Basit bir kurulum sağlayarak cihazları kuruluşta kullanılmaya hızla hazırlar.

### **Güvenlik Hususu**

DEP'in sağladığı kayıt kolaylığının yararlı olmakla birlikte güvenlik riskleri de oluşturabileceğini unutmamak önemlidir. MDM kaydı için koruyucu önlemler yeterince uygulanmazsa saldırganlar, bu kolaylaştırılmış süreçten yararlanarak kurumsal bir cihazmış gibi davranan kendi cihazlarını kuruluşun MDM sunucusuna kaydettirebilir.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Güvenlik Uyarısı**: Gerekli önlemler alınmadığında, basitleştirilmiş DEP kaydı yetkisiz cihazların kuruluşun MDM sunucusuna kaydedilmesine olanak sağlayabilir.

### SCEP (Simple Certificate Enrolment Protocol) nedir?

- TLS ve HTTPS yaygınlaşmadan önce oluşturulmuş, görece eski bir protokoldür.
- İstemcilere, sertifika almak amacıyla **Certificate Signing Request** (CSR) gönderme konusunda standart bir yöntem sunar. İstemci, sunucudan kendisine imzalı bir sertifika vermesini ister.

### Configuration Profile'lar (diğer adıyla mobileconfig'ler) nedir?

- Apple'ın **sistem yapılandırmasını ayarlamak/zorunlu kılmak** için kullandığı resmî yöntemdir.
- Birden fazla payload içerebilen dosya biçimidir.
- Property list'lere (XML türündeki) dayanır.
- “Kaynağını doğrulamak, bütünlüğünü sağlamak ve içeriğini korumak için imzalanabilir ve şifrelenebilir.” Basics — Page 70, iOS Security Guide, January 2018.

## Protokoller

### MDM

- APNs (**Apple sunucuları**) + RESTful API (**MDM** **satıcısı** sunucuları) birleşimidir.
- **İletişim**, bir **cihaz** ile **cihaz** **yönetimi** **ürünüyle** ilişkili bir sunucu arasında gerçekleşir.
- MDM'den cihaza gönderilen **komutlar**, **plist ile kodlanmış sözlükler** biçimindedir.
- Tüm iletişim **HTTPS** üzerinden gerçekleşir. MDM sunucuları pinning kullanabilir (ve genellikle kullanır).
- Apple, kimlik doğrulama için MDM satıcısına bir **APNs sertifikası** verir.

### DEP

- **3 API** vardır: satıcılar için 1, MDM satıcıları için 1 ve cihaz kimliği için 1 (belgelenmemiş):
  - [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) olarak adlandırılan API. MDM sunucuları bunu DEP profillerini belirli cihazlarla ilişkilendirmek için kullanır.
  - [Apple Authorized Resellers tarafından kullanılan DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html). Cihazları kaydetmek, kayıt durumunu ve işlem durumunu kontrol etmek için kullanılır.
  - Belgelenmemiş özel DEP API'si. Apple cihazları bunu DEP profillerini almak için kullanır. macOS'ta bu API üzerinden iletişimden `cloudconfigurationd` ikilisi sorumludur.
- Daha moderndir ve plist yerine **JSON** tabanlıdır.
- Apple, MDM satıcısına bir **OAuth token** verir.

**DEP "cloud service" API**

- RESTful'dur.
- Cihaz kayıtlarını Apple'dan MDM sunucusuna senkronize eder.
- “DEP profillerini” MDM sunucusundan Apple'a senkronize eder (Apple bunları daha sonra cihaza iletir).
- Bir DEP “profili” şunları içerir:
  - MDM satıcısının sunucu URL'si
  - Sunucu URL'si için ek güvenilir sertifikalar (isteğe bağlı pinning)
  - Ek ayarlar (ör. Setup Assistant'ta hangi ekranların atlanacağı)

## Seri Numarası

2010'dan sonra üretilen Apple cihazlarının genellikle **12 karakterli alfasayısal** seri numaraları vardır. İlk **üç rakam** üretim yerini, sonraki **iki rakam** üretim **yılını** ve **haftasını**, sonraki **üç rakam** **benzersiz** bir **tanımlayıcıyı**, son **dört rakam** ise **model numarasını** belirtir.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Kayıt ve yönetim adımları

1. Cihaz kaydının oluşturulması (Satıcı, Apple): Yeni cihazın kaydı oluşturulur.
2. Cihaz kaydının atanması (Müşteri): Cihaz bir MDM sunucusuna atanır.
3. Cihaz kaydının senkronizasyonu (MDM satıcısı): MDM, cihaz kayıtlarını senkronize eder ve DEP profillerini Apple'a gönderir.
4. DEP check-in (Cihaz): Cihaz DEP profilini alır.
5. Profilin alınması (Cihaz)
6. Profilin yüklenmesi (Cihaz) a. MDM, SCEP ve kök CA payload'ları dâhil
7. MDM komutlarının gönderilmesi (Cihaz)

![Seri Numarası - Kayıt ve yönetim adımları: 7. MDM komutlarının gönderilmesi (Cihaz)](<../../../images/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` dosyası, kayıt sürecinin üst düzey “adımları” olarak değerlendirilebilecek işlevleri dışa aktarır.

### Adım 4: DEP check-in - Activation Record'un alınması

Sürecin bu bölümü, **bir kullanıcı Mac'i ilk kez başlattığında** (veya cihaz tamamen silindikten sonra) gerçekleşir.

![Kayıt ve yönetim adımları - Adım 4: DEP check-in - Activation Record'un alınması: Sürecin bu bölümü, bir kullanıcı Mac'i ilk kez başlattığında (veya cihaz tamamen silindikten sonra) gerçekleşir](<../../../images/image (1044).png>)

veya `sudo profiles show -type enrollment` komutu çalıştırıldığında

- **Cihazın DEP etkin olup olmadığını** belirler.
- Activation Record, **DEP “profilinin”** dahili adıdır.
- Cihaz internete bağlanır bağlanmaz başlar.
- **`CPFetchActivationRecord`** tarafından yürütülür.
- XPC üzerinden **`cloudconfigurationd`** tarafından uygulanır. **“Setup Assistant”** (cihaz ilk kez başlatıldığında) veya **`profiles`** komutu, Activation Record'u almak için **bu daemon'la iletişim kurar**.
  - LaunchDaemon (her zaman root olarak çalışır)

Activation Record'u almak için **`MCTeslaConfigurationFetcher`** tarafından yürütülen birkaç adım uygulanır. Bu süreçte **Absinthe** adlı bir şifreleme kullanılır<sup>[[1]](#references)</sup>

1. **Sertifikayı** alır.
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Sertifikadan durumu **başlatır** (**`NACInit`**).
   1. Cihaza özgü çeşitli verileri kullanır (ör. **`IOKit` üzerinden Seri Numarası**).
3. **Oturum anahtarını** alır.
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Oturumu kurar (**`NACKeyEstablishment`**).
5. İsteği gönderir.
   1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) adresine POST isteği göndererek `{ "action": "RequestProfileConfiguration", "sn": "" }` verisini iletir.
   2. JSON payload'u Absinthe kullanılarak şifrelenir (**`NACSign`**).
   3. Tüm istekler HTTPS üzerinden yapılır; yerleşik kök sertifikalar kullanılır.

![Kayıt ve yönetim adımları - Adım 4: DEP check-in - Activation Record'un alınması: 3. Tüm istekler HTTPS üzerinden yapılır; yerleşik kök sertifikalar kullanılır](<../../../images/image (566) (1).png>)

Yanıt, aşağıdakiler gibi önemli verileri içeren bir JSON sözlüğüdür:

- **url**: Activation Profile için MDM satıcısının sunucu ana bilgisayarının URL'si
- **anchor-certs**: Güvenilir anchor olarak kullanılan DER sertifikalarının dizisi

### **Adım 5: Profilin alınması**

![Adım 4: DEP check-in - Activation Record'un alınması - Adım 5: Profilin alınması: Adım 5: Profilin alınması](<../../../images/image (444).png>)

- İstek, **DEP profilinde sağlanan URL'ye** gönderilir.
- Sağlanmışsa **güveni değerlendirmek** için **Anchor sertifikaları** kullanılır.
  - Hatırlatma: DEP profilinin **anchor_certs** özelliği
- **İstek, cihaz kimlik bilgilerini içeren basit bir .plist** dosyasıdır.
  - Örnekler: **UDID, işletim sistemi sürümü**.
- CMS imzalı, DER kodlamalıdır.
- **Cihaz kimlik sertifikası (APNS'den)** kullanılarak imzalanır.
- **Sertifika zincirinde** süresi dolmuş **Apple iPhone Device CA** bulunur.

![Adım 4: DEP check-in - Activation Record'un alınması - Adım 5: Profilin alınması: Cihaz kimlik sertifikası (APNS'den) kullanılarak imzalanır](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Adım 6: Profilin yüklenmesi

- Alındıktan sonra **profil sisteme kaydedilir**.
- Bu adım otomatik olarak başlar (**Setup Assistant** içindeyse).
- **`CPInstallActivationProfile`** tarafından yürütülür.
- XPC üzerinden mdmclient tarafından uygulanır.
  - Bağlama bağlı olarak LaunchDaemon (root olarak) veya LaunchAgent (kullanıcı olarak)
- Configuration Profile'lar yüklenecek birden fazla payload içerir.
- Framework, profilleri yüklemek için eklenti tabanlı bir mimariye sahiptir.
- Her payload türü bir eklentiyle ilişkilidir.
  - XPC (framework içinde) veya klasik Cocoa (ManagedClient.app içinde) olabilir.
- Örnek:
  - Certificate Payload'ları CertificateService.xpc kullanır.

Genellikle bir MDM satıcısı tarafından sağlanan **Activation Profile** şu payload'ları **içerir**:

- `com.apple.mdm`: Cihazı MDM'ye **kaydetmek** için
- `com.apple.security.scep`: Cihaza güvenli biçimde bir **istemci sertifikası** sağlamak için
- `com.apple.security.pem`: **Güvenilir CA sertifikalarını** cihazın System Keychain'ine **yüklemek** için
- MDM payload'unun yüklenmesi, belgelerdeki **MDM check-in** adımına karşılık gelir.
- Payload **önemli özellikler içerir**:
- - MDM Check-In URL'si (**`CheckInURL`**)
  - MDM Command Polling URL'si (**`ServerURL`**) + bunu tetikleyecek APNs konusu
- MDM payload'unu yüklemek için **`CheckInURL`** adresine istek gönderilir.
- **`mdmclient`** tarafından uygulanır.
- MDM payload'u diğer payload'lara bağlı olabilir.
- **İsteklerin belirli sertifikalara pinning uygulanmasını** sağlar:
  - Özellik: **`CheckInURLPinningCertificateUUIDs`**
  - Özellik: **`ServerURLPinningCertificateUUIDs`**
  - PEM payload'u üzerinden iletilir.
- Cihaza bir kimlik sertifikası atanmasını sağlar:
  - Özellik: IdentityCertificateUUID
  - SCEP payload'u üzerinden iletilir.

### **Adım 7: MDM komutlarını dinleme**

- MDM check-in tamamlandıktan sonra satıcı **APNs kullanarak push bildirimleri gönderebilir**.
- Bildirim alındığında **`mdmclient`** tarafından işlenir.
- MDM komutlarını sorgulamak için ServerURL'ye istek gönderilir.
- Daha önce yüklenmiş MDM payload'u kullanılır:
  - İstek pinning'i için **`ServerURLPinningCertificateUUIDs`**
  - TLS istemci sertifikası için **`IdentityCertificateUUID`**

## Saldırılar

### Cihazları Başka Kuruluşlara Kaydetme

Atanmış bir seri numarası kuruluşun kayıt yolunu belirleyebilir, ancak MDM kaydını **garanti etmez**. Sunucu, kayıt profilini döndürmeden önce `configuration_web_url` üzerinden kullanıcı kimlik doğrulaması isteyebilir. Atanmış her seri numarasının kurumsal cihaza kaydolabileceğini varsaymak yerine, alternatif bir kayıt yolunun bu kontrolü atlayıp atlamadığını değerlendirin.<sup>[[3]](#references)</sup>

Rogue-enrollment iş akışı için aşağıdaki bağlantıdaki sayfayı kullanın. Ele geçirilmenin ardından MDM kontrolü ve paket teslimi için [macOS Red Teaming](../) sayfasına bakın.


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [macOS MDM'ye Derinlemesine Bir Bakış (ve Nasıl Ele Geçirilebileceği)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM kayıt güvenliği araştırması)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Web görünümleri üzerinden kimlik doğrulama](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
