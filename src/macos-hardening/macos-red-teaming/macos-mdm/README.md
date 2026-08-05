# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM'leri hakkında bilgi edinmek için:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Temel Bilgiler

### **MDM (Mobile Device Management) Genel Bakış**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM), akıllı telefonlar, laptop'lar ve tabletler gibi çeşitli son kullanıcı cihazlarını yönetmek için kullanılır. Özellikle Apple platformları (iOS, macOS, tvOS) için özel bir dizi özellik, API ve uygulamayı içerir. MDM'nin çalışması, ticari olarak sunulan veya open-source olan ve [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)'ü desteklemesi gereken uyumlu bir MDM sunucusuna dayanır. Önemli noktalar:

- Cihazlar üzerinde merkezi kontrol.
- MDM protokolüne uyan bir MDM sunucusuna bağımlılık.
- MDM sunucusunun cihazlara uzaktan veri silme veya yapılandırma yükleme gibi çeşitli komutlar gönderebilmesi.

### **DEP (Device Enrollment Program) Temelleri**

Apple tarafından sunulan [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), iOS, macOS ve tvOS cihazları için zero-touch yapılandırma sağlayarak Mobile Device Management (MDM) entegrasyonunu kolaylaştırır. DEP, enrollment sürecini otomatikleştirerek cihazların kullanıcı veya yönetici müdahalesini en aza indirerek kutudan çıkar çıkmaz çalışır durumda olmasını sağlar. Temel özellikler:

- Cihazların ilk etkinleştirme sırasında önceden tanımlanmış bir MDM sunucusuna otomatik olarak kayıt olmasını sağlar.
- Öncelikle yeni cihazlar için faydalıdır; ancak yeniden yapılandırılan cihazlar için de kullanılabilir.
- Basit bir kurulum sağlayarak cihazları kuruluşta kullanılmaya hızlıca hazır hale getirir.

### **Güvenlik Hususları**

DEP tarafından sağlanan enrollment kolaylığının faydalı olmakla birlikte güvenlik riskleri de oluşturabileceğini belirtmek önemlidir. MDM enrollment için koruyucu önlemler yeterince uygulanmazsa saldırganlar, kurumsal bir cihaz gibi görünerek kendi cihazlarını kuruluşun MDM sunucusuna kaydetmek için bu kolaylaştırılmış süreci kötüye kullanabilir.<sup>[2]</sup>

> [!CAUTION]
> **Güvenlik Uyarısı**: Basitleştirilmiş DEP enrollment, uygun güvenlik önlemleri mevcut değilse yetkisiz cihazların kuruluşun MDM sunucusuna kaydedilmesine olanak sağlayabilir.

### SCEP (Simple Certificate Enrolment Protocol) Nedir?

- TLS ve HTTPS'in yaygınlaşmasından önce oluşturulmuş, nispeten eski bir protokoldür.
- İstemcilere, sertifika verilmesi amacıyla standartlaştırılmış bir **Certificate Signing Request** (CSR) gönderme yöntemi sunar. İstemci, sunucudan kendisine imzalı bir sertifika vermesini ister.

### Configuration Profiles (diğer adıyla mobileconfigs) Nedir?

- **Sistem yapılandırmasını ayarlamak/zorunlu kılmak için** Apple'ın resmi yöntemidir.
- Birden fazla payload içerebilen dosya formatıdır.
- Property list'lere (XML türündeki) dayanır.
- “Kökenlerini doğrulamak, bütünlüklerini güvence altına almak ve içeriklerini korumak için imzalanabilir ve şifrelenebilir.” Basics — Page 70, iOS Security Guide, January 2018.

## Protokoller

### MDM

- APNs (**Apple sunucuları**) + RESTful API (**MDM vendor** sunucuları) birleşimidir.
- **İletişim**, bir **cihaz** ile bir **cihaz** **yönetimi** **ürünü** ile ilişkili sunucu arasında gerçekleşir.
- **Komutlar**, MDM'den cihaza **plist-encoded dictionary** biçiminde iletilir.
- Her şey **HTTPS** üzerinden gerçekleşir. MDM sunucuları certificate pinning kullanabilir (ve genellikle kullanır).
- Apple, kimlik doğrulama için MDM vendor'a bir **APNs certificate** verir.

### DEP

- **3 API** bulunur: 1 tanesi reseller'lar, 1 tanesi MDM vendor'ları ve 1 tanesi device identity için (belgelenmemiş):
- Sözde [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM sunucuları bunu DEP profillerini belirli cihazlarla ilişkilendirmek için kullanır.
- Cihazları enroll etmek, enrollment durumunu kontrol etmek ve transaction durumunu kontrol etmek için [Apple Authorized Resellers tarafından kullanılan DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html).
- Belgelenmemiş private DEP API. Apple Devices bunu DEP profillerini istemek için kullanır. macOS'ta `cloudconfigurationd` binary'si bu API üzerinden iletişim kurmaktan sorumludur.
- Daha modern ve **JSON** tabanlıdır (plist'in aksine).
- Apple, MDM vendor'a bir **OAuth token** verir.

**DEP "cloud service" API**

- RESTful'dur.
- Cihaz kayıtlarını Apple'dan MDM sunucusuna sync eder.
- “DEP profiles”'ı MDM sunucusundan Apple'a sync eder (daha sonra Apple tarafından cihaza iletilir).
- Bir DEP “profile” şunları içerir:
- MDM vendor sunucusunun URL'si.
- Sunucu URL'si için ek trusted certificates (isteğe bağlı pinning).
- Ek ayarlar (ör. Setup Assistant'ta hangi ekranların atlanacağı).

## Serial Number

2010'dan sonra üretilen Apple cihazları genellikle **12 karakterli alfanümerik** serial number'lara sahiptir. İlk üç karakter üretim yerini, sonraki **iki** karakter üretim yılını ve haftasını, sonraki **üç** karakter benzersiz bir **identifier**'ı ve **son dört** karakter model numarasını belirtir.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Enrollment ve yönetim adımları

1. Device record creation (Reseller, Apple): Yeni cihazın kaydı oluşturulur.
2. Device record assignment (Customer): Cihaz bir MDM sunucusuna atanır.
3. Device record sync (MDM vendor): MDM, cihaz kayıtlarını sync eder ve DEP profillerini Apple'a push eder.
4. DEP check-in (Device): Cihaz DEP profilini alır.
5. Profile retrieval (Device)
6. Profile installation (Device) a. MDM, SCEP ve root CA payload'ları dahil.
7. MDM command issuance (Device)

![Serial Number - Enrollment ve yönetim adımları: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` dosyası, enrollment sürecinin **yüksek seviyeli "adımları"** olarak değerlendirilebilecek fonksiyonları dışa aktarır.

### Step 4: DEP check-in - Activation Record'ı Alma

Sürecin bu bölümü, bir **kullanıcının Mac'i ilk kez başlatması** (veya tamamen wipe işleminden sonra) sırasında gerçekleşir.

![Enrollment ve yönetim adımları - Step 4: DEP check-in - Activation Record'ı Alma: Sürecin bu bölümü, kullanıcının Mac'i ilk kez başlatması veya tamamen...](<../../../images/image (1044).png>)

veya `sudo profiles show -type enrollment` komutu çalıştırıldığında gerçekleşir.

- **Cihazın DEP enabled olup olmadığını** belirler.
- Activation Record, **DEP “profile”** için kullanılan dahili addır.
- Cihaz Internet'e bağlanır bağlanmaz başlar.
- **`CPFetchActivationRecord`** tarafından yürütülür.
- XPC üzerinden **`cloudconfigurationd`** tarafından uygulanır. **"Setup Assistant**" (cihaz ilk kez başlatıldığında) veya **`profiles`** komutu, activation record'ı almak için **bu daemon ile iletişim kurar**.
- LaunchDaemon (her zaman root olarak çalışır).

Activation Record'ı almak için gereken birkaç adım **`MCTeslaConfigurationFetcher`** tarafından gerçekleştirilir. Bu süreç **Absinthe** adlı bir encryption kullanır.<sup>[1]</sup>

1. **Certificate** alınır.
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Certificate'tan state başlatılır (**`NACInit`**).
1. Çeşitli cihaza özgü verileri kullanır (ör. **`IOKit` üzerinden Serial Number**).
3. **Session key** alınır.
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Session oluşturulur (**`NACKeyEstablishment`**).
5. Request yapılır.
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) adresine POST yapılarak `{ "action": "RequestProfileConfiguration", "sn": "" }` verisi gönderilir.
2. JSON payload, Absinthe kullanılarak encryption uygulanır (**`NACSign`**).
3. Tüm request'ler HTTPs üzerinden yapılır; built-in root certificates kullanılır.

![Enrollment ve yönetim adımları - Step 4: DEP check-in - Activation Record'ı Alma: 3. Tüm request'ler HTTPs üzerinden yapılır; built-in root certificates kullanılır](<../../../images/image (566) (1).png>)

Response, aşağıdakiler gibi bazı önemli verileri içeren bir JSON dictionary'dir:

- **url**: Activation profile için MDM vendor host'unun URL'si.
- **anchor-certs**: Trusted anchor olarak kullanılan DER certificates dizisi.

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Activation Record'ı Alma - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- Request, **DEP profile'da sağlanan url** adresine gönderilir.
- Sağlanmışsa **anchor certificates**, **trust değerlendirmesi** için kullanılır.
- Hatırlatma: DEP profile'ın **anchor_certs** property'si.
- **Request, cihaz tanımlama bilgilerini içeren basit bir .plist'tir**.
- Örnekler: **UDID, OS version**.
- CMS-signed, DER-encoded.
- **APNS'ten alınan device identity certificate** kullanılarak imzalanır.
- **Certificate chain**, süresi dolmuş **Apple iPhone Device CA** içerir.

![Step 4: DEP check-in - Activation Record'ı Alma - Step 5: Profile Retrieval: APNS'ten alınan device identity certificate kullanılarak imzalanır](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- Alındıktan sonra **profile sistemde saklanır**.
- Bu adım otomatik olarak başlar (**setup assistant** içindeyse).
- **`CPInstallActivationProfile`** tarafından yürütülür.
- XPC üzerinden mdmclient tarafından uygulanır.
- Bağlama bağlı olarak LaunchDaemon (root olarak) veya LaunchAgent (user olarak).
- Configuration profiles, yüklenecek birden fazla payload içerir.
- Framework, profilleri yüklemek için plugin tabanlı bir mimariye sahiptir.
- Her payload türü bir plugin ile ilişkilidir.
- Bu plugin, XPC (framework içinde) veya classic Cocoa (ManagedClient.app içinde) olabilir.
- Örnek:
- Certificate Payloads, CertificateService.xpc'yi kullanır.

Genellikle bir MDM vendor tarafından sağlanan **activation profile** aşağıdaki payload'ları içerir:

- `com.apple.mdm`: cihazı MDM'e **enroll etmek** için.
- `com.apple.security.scep`: cihaza güvenli şekilde bir **client certificate** sağlamak için.
- `com.apple.security.pem`: trusted CA certificates'ı cihazın System Keychain'ine **yüklemek** için.
- MDM payload'ını yüklemek, dokümantasyondaki **MDM check-in** işlemine eşdeğerdir.
- Payload, **önemli key property'ler** içerir:
- - MDM Check-In URL (**`CheckInURL`**).
- MDM Command Polling URL (**`ServerURL`**) + bunu tetiklemek için APNs topic.
- MDM payload'ını yüklemek için request **`CheckInURL`** adresine gönderilir.
- **`mdmclient`** tarafından uygulanır.
- MDM payload'ı diğer payload'lara bağlı olabilir.
- **Request'lerin belirli certificates'a pinlenmesine** olanak sağlar:
- Property: **`CheckInURLPinningCertificateUUIDs`**.
- Property: **`ServerURLPinningCertificateUUIDs`**.
- PEM payload üzerinden iletilir.
- Cihaza bir identity certificate atanmasına olanak sağlar:
- Property: IdentityCertificateUUID.
- SCEP payload üzerinden iletilir.

### **Step 7: MDM command'larını Dinleme**

- MDM check-in tamamlandıktan sonra vendor, **APNs kullanarak push notifications gönderebilir**.
- Alındığında **`mdmclient`** tarafından işlenir.
- MDM command'larını poll etmek için request ServerURL'a gönderilir.
- Daha önce yüklenen MDM payload'ından yararlanır:
- Pinning request için **`ServerURLPinningCertificateUUIDs`**.
- TLS client certificate için **`IdentityCertificateUUID`**.

## Saldırılar

### Diğer Organizasyonlarda Cihaz Enroll Etme

Daha önce belirtildiği gibi, bir cihazı bir organizasyona enroll etmeye çalışmak için **sadece o organizasyona ait bir Serial Number gereklidir**. Cihaz enroll edildikten sonra birçok organizasyon yeni cihaza hassas veriler yükler: certificates, applications, WiFi passwords, VPN configurations [ve benzeri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle enrollment süreci doğru şekilde korunmuyorsa saldırganlar için tehlikeli bir giriş noktası olabilir:<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Referanslar

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
