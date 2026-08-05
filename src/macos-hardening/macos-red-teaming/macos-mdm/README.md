# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM'leri hakkında bilgi edinmek için:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Temel Bilgiler

### **MDM (Mobile Device Management) Genel Bakış**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM), akıllı telefonlar, laptop'lar ve tabletler gibi çeşitli son kullanıcı cihazlarını yönetmek için kullanılır. Özellikle Apple platformları (iOS, macOS, tvOS) için bu süreç, bir dizi özel özellik, API ve uygulamayı kapsar. MDM'nin çalışması, ticari olarak sunulan veya open-source olan ve [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) desteğine sahip uyumlu bir MDM sunucusuna bağlıdır. Önemli noktalar:

- Cihazlar üzerinde merkezi kontrol.
- MDM protokolüne uygun bir MDM sunucusuna bağımlılık.
- MDM sunucusunun cihazlara uzaktan veri silme veya yapılandırma yükleme gibi çeşitli komutlar gönderebilmesi.

### **DEP (Device Enrollment Program) Temelleri**

Apple tarafından sunulan [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), iOS, macOS ve tvOS cihazları için zero-touch yapılandırma sağlayarak Mobile Device Management (MDM) entegrasyonunu kolaylaştırır. DEP, enrollment sürecini otomatikleştirerek cihazların minimum kullanıcı veya yönetici müdahalesiyle kutudan çıkar çıkmaz kullanılabilir durumda olmasını sağlar. Temel özellikler:

- Cihazların ilk etkinleştirme sırasında önceden tanımlanmış bir MDM sunucusuna otomatik olarak kaydolmasını sağlar.
- Öncelikli olarak yeni cihazlar için faydalıdır; ancak yeniden yapılandırılan cihazlar için de kullanılabilir.
- Basit bir kurulum sağlayarak cihazları kuruluş içinde kullanılmaya hızla hazır hâle getirir.

### **Güvenlik Hususları**

DEP tarafından sağlanan enrollment kolaylığının faydalı olmakla birlikte güvenlik riskleri de oluşturabileceğini belirtmek önemlidir. MDM enrollment için koruyucu önlemler yeterince uygulanmazsa saldırganlar, kurumsal bir cihaz gibi davranarak cihazlarını kuruluşun MDM sunucusuna kaydetmek için bu kolaylaştırılmış süreci kötüye kullanabilir.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Güvenlik Uyarısı**: Basitleştirilmiş DEP enrollment, uygun güvenlik önlemleri mevcut değilse yetkisiz cihazların kuruluşun MDM sunucusuna kaydedilmesine olanak tanıyabilir.

### Temel Bilgiler SCEP (Simple Certificate Enrolment Protocol) nedir?

- TLS ve HTTPS yaygınlaşmadan önce oluşturulmuş, görece eski bir protokoldür.
- Client'lara, sertifika alma amacıyla standartlaştırılmış bir **Certificate Signing Request** (CSR) gönderme yöntemi sağlar. Client, server'dan kendisine imzalı bir sertifika vermesini ister.

### Configuration Profiles (diğer adıyla mobileconfigs) nedir?

- Apple'ın **system configuration ayarlamak/zorlamak** için sunduğu resmi yöntemdir.
- Birden fazla payload içerebilen dosya formatıdır.
- Property list'lere (XML türündeki) dayanır.
- “kökenlerini doğrulamak, bütünlüklerini güvence altına almak ve içeriklerini korumak için imzalanabilir ve şifrelenebilir.” Basics — Page 70, iOS Security Guide, January 2018.

## Protokoller

### MDM

- APNs (**Apple server**ları) + RESTful API (**MDM** **vendor** server'ları) bileşimidir.
- **İletişim**, bir **device** ile bir **device** **management** **product**'ı ile ilişkili server arasında gerçekleşir.
- **Komutlar**, MDM'den cihaza **plist-encoded dictionary**'ler olarak gönderilir.
- Tamamı **HTTPS** üzerinden gerçekleşir. MDM server'ları pinlenebilir (ve genellikle pinlenir).
- Apple, authentication için MDM vendor'una bir **APNs certificate** verir.

### DEP

- **3 API** vardır: 1'i reseller'lar, 1'i MDM vendor'ları ve 1'i device identity için (belgelendirilmemiş):
- Sözde [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM server'ları tarafından DEP profile'larını belirli cihazlarla ilişkilendirmek için kullanılır.
- Cihazları enroll etmek, enrollment durumunu kontrol etmek ve transaction durumunu kontrol etmek için [Apple Authorized Reseller'lar tarafından kullanılan DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html).
- Belgelendirilmemiş private DEP API. Apple Devices tarafından DEP profile'larını istemek için kullanılır. macOS'ta `cloudconfigurationd` binary'si bu API üzerinden iletişim kurmaktan sorumludur.
- Daha modern ve **JSON** tabanlıdır (plist'in aksine).
- Apple, MDM vendor'una bir **OAuth token** verir.

**DEP "cloud service" API**

- RESTful'dur.
- Device record'larını Apple'dan MDM server'a sync eder.
- “DEP profile”larını MDM server'dan Apple'a sync eder (daha sonra Apple tarafından cihaza gönderilir).
- Bir DEP “profile” şunları içerir:
- MDM vendor server URL'si.
- Server URL için ek trusted certificate'lar (isteğe bağlı pinning).
- Ek ayarlar (örneğin Setup Assistant'ta hangi ekranların atlanacağı).

## Serial Number

2010'dan sonra üretilen Apple cihazları genellikle **12 karakterli alfanümerik** serial number'lara sahiptir. İlk üç karakter üretim konumunu, sonraki **iki** karakter üretim yılını ve haftasını, sonraki **üç** karakter **benzersiz** bir **identifier**'ı ve son **dört** karakter model numarasını belirtir.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Enrollment ve management adımları

1. Device record oluşturma (Reseller, Apple): Yeni cihazın record'u oluşturulur.
2. Device record atama (Customer): Cihaz bir MDM server'a atanır.
3. Device record sync (MDM vendor): MDM, device record'larını sync eder ve DEP profile'larını Apple'a push eder.
4. DEP check-in (Device): Device, DEP profile'ını alır.
5. Profile retrieval (Device)
6. Profile installation (Device), a. MDM, SCEP ve root CA payload'ları dahil
7. MDM command issuance (Device)

![Serial Number - Enrollment ve management adımları: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` dosyası, enrollment sürecinin **high-level "steps"** olarak değerlendirilebilecek fonksiyonlarını export eder.

### Step 4: DEP check-in - Activation Record'ı alma

Sürecin bu bölümü, **kullanıcı bir Mac'i ilk kez boot ettiğinde** (veya tamamen wipe işleminden sonra) gerçekleşir.

![Enrollment ve management adımları - Step 4: DEP check-in - Activation Record'ı alma: Bu bölüm, kullanıcının bir Mac'i ilk kez boot etmesiyle veya tamamen...](<../../../images/image (1044).png>)

veya `sudo profiles show -type enrollment` çalıştırıldığında.

- **Cihazın DEP enabled olup olmadığını** belirler.
- Activation Record, DEP “profile”ının dahili adıdır.
- Cihaz Internet'e bağlanır bağlanmaz başlar.
- **`CPFetchActivationRecord`** tarafından yürütülür.
- XPC üzerinden **`cloudconfigurationd`** tarafından uygulanır. **"Setup Assistant**" (cihaz ilk kez boot edildiğinde) veya **`profiles`** komutu, activation record'ı almak için **bu daemon ile iletişim kurar**.
- LaunchDaemon (her zaman root olarak çalışır).

Activation Record'ı almak için **`MCTeslaConfigurationFetcher`** tarafından gerçekleştirilen birkaç adım izlenir. Bu süreç **Absinthe** adlı bir encryption kullanır.<sup>[[1]](#references)</sup>

1. **Certificate**'ı al
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Certificate'tan state'i (**`NACInit`**) **initialize et**
1. Cihaza özgü çeşitli verileri kullanır (ör. **`IOKit`** üzerinden **Serial Number**).
3. **Session key**'i al
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Session'ı (**`NACKeyEstablishment`**) oluştur.
5. Request'i yap.
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) adresine POST gönderilir ve `{ "action": "RequestProfileConfiguration", "sn": "" }` verileri gönderilir.
2. JSON payload'ı Absinthe kullanılarak encrypt edilir (**`NACSign`**).
3. Tüm request'ler HTTPs üzerinden yapılır; yerleşik root certificate'lar kullanılır.

![Enrollment ve management adımları - Step 4: DEP check-in - Activation Record'ı alma: 3. Tüm request'ler HTTPs üzerinden yapılır; yerleşik root certificate'lar kullanılır](<../../../images/image (566) (1).png>)

Response, aşağıdakiler gibi bazı önemli veriler içeren bir JSON dictionary'dir:

- **url**: Activation profile için MDM vendor host'unun URL'si.
- **anchor-certs**: Trusted anchor olarak kullanılan DER certificate'larının array'i.

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Activation Record'ı alma - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- Request, **DEP profile'ında sağlanan url**'ye gönderilir.
- Sağlanmışsa **trust'i değerlendirmek** için **anchor certificate'lar** kullanılır.
- Hatırlatma: DEP profile'ının **anchor_certs** property’si.
- **Request, device identification içeren basit bir .plist**'tir.
- Örnekler: **UDID, OS version**.
- CMS-signed, DER-encoded'dır.
- **APNS'ten gelen device identity certificate** kullanılarak imzalanır.
- **Certificate chain**, süresi dolmuş **Apple iPhone Device CA** içerir.

![Step 4: DEP check-in - Activation Record'ı alma - Step 5: Profile Retrieval: APNS'ten gelen device identity certificate kullanılarak imzalanır](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- Alındıktan sonra **profile sistemde saklanır**.
- Bu adım otomatik olarak başlar (**setup assistant** içindeyse).
- **`CPInstallActivationProfile`** tarafından yürütülür.
- XPC üzerinden mdmclient tarafından uygulanır.
- Bağlama bağlı olarak LaunchDaemon (root olarak) veya LaunchAgent (user olarak).
- Configuration profile'larının yüklenecek birden fazla payload'ı vardır.
- Framework, profile'ları yüklemek için plugin tabanlı bir architecture kullanır.
- Her payload türü bir plugin ile ilişkilidir.
- XPC (framework içinde) veya classic Cocoa (ManagedClient.app içinde) olabilir.
- Örnek:
- Certificate Payload'ları CertificateService.xpc'yi kullanır.

Genellikle bir MDM vendor tarafından sağlanan **activation profile** aşağıdaki payload'ları **içerir**:

- `com.apple.mdm`: cihazı MDM'e **enroll etmek** için.
- `com.apple.security.scep`: cihaza güvenli biçimde bir **client certificate** sağlamak için.
- `com.apple.security.pem`: trusted CA certificate'larını cihazın System Keychain'ine **yüklemek** için.
- MDM payload'ını yüklemek, documentation'daki **MDM check-in** işlemine eşdeğerdir.
- Payload **temel property'ler içerir**:
- - MDM Check-In URL'si (**`CheckInURL`**).
- MDM Command Polling URL'si (**`ServerURL`**) + tetiklemek için APNs topic'i.
- MDM payload'ını yüklemek için request **`CheckInURL`**'ye gönderilir.
- **`mdmclient`** tarafından uygulanır.
- MDM payload'ı diğer payload'lara bağlı olabilir.
- **Request'lerin belirli certificate'lara pinlenmesine** olanak tanır:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- PEM payload üzerinden gönderilir.
- Cihaza bir identity certificate atanmasına olanak tanır:
- Property: IdentityCertificateUUID
- SCEP payload üzerinden gönderilir.

### **Step 7: MDM command'larını dinleme**

- MDM check-in tamamlandıktan sonra vendor, **APNs kullanarak push notification** gönderebilir.
- Alındığında **`mdmclient`** tarafından işlenir.
- MDM command'larını poll etmek için ServerURL'ye request gönderilir.
- Daha önce yüklenen MDM payload'ı kullanılır:
- Pinning request'i için **`ServerURLPinningCertificateUUIDs`**.
- TLS client certificate için **`IdentityCertificateUUID`**.

## Saldırılar

### Diğer Organizasyonlarda Cihaz Enroll Etme

Daha önce belirtildiği gibi, bir cihazı bir organizasyona enroll etmeyi denemek için **tek gereken o Organizasyona ait bir Serial Number'dır**. Cihaz enroll edildikten sonra birçok organizasyon yeni cihaza sensitive data yükler: certificate'lar, application'lar, WiFi password'leri, VPN configuration'ları [ve benzerleri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle enrollment süreci doğru şekilde korunmuyorsa saldırganlar için tehlikeli bir entrypoint olabilir:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Referanslar

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
