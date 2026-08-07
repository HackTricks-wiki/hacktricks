# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM'leri hakkında bilgi edinmek için:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Temel Bilgiler

### **MDM (Mobile Device Management) Genel Bakış**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM), akıllı telefonlar, laptoplar ve tabletler gibi çeşitli son kullanıcı cihazlarını yönetmek için kullanılır. Özellikle Apple platformları (iOS, macOS, tvOS) için bu işlem, bir dizi özel özellik, API ve uygulamayı kapsar. MDM'nin çalışması, ticari olarak sunulan veya open-source olan ve [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)'ü desteklemesi gereken uyumlu bir MDM sunucusuna bağlıdır. Önemli noktalar şunlardır:

- Cihazlar üzerinde merkezi kontrol.
- MDM protocol'üne uyan bir MDM sunucusuna bağımlılık.
- MDM sunucusunun cihazlara uzaktan veri silme veya yapılandırma yükleme gibi çeşitli komutlar gönderebilmesi.

### **DEP (Device Enrollment Program) Temelleri**

Apple tarafından sunulan [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), iOS, macOS ve tvOS cihazları için zero-touch yapılandırmayı kolaylaştırarak Mobile Device Management (MDM) entegrasyonunu basitleştirir. DEP, enrollment sürecini otomatikleştirerek cihazların minimum kullanıcı veya yönetici müdahalesiyle kutudan çıkar çıkmaz çalışır durumda olmasını sağlar. Temel özellikleri şunlardır:

- Cihazların ilk etkinleştirme sırasında önceden tanımlanmış bir MDM sunucusuna otomatik olarak kayıt olmasını sağlar.
- Öncelikli olarak yeni cihazlar için faydalıdır, ancak yeniden yapılandırılan cihazlarda da kullanılabilir.
- Basit bir kurulum sağlayarak cihazları kuruluş kullanımı için hızlıca hazır hale getirir.

### **Güvenlik Hususu**

DEP tarafından sağlanan enrollment kolaylığının faydalı olmakla birlikte güvenlik riskleri de oluşturabileceğini belirtmek önemlidir. MDM enrollment için koruyucu önlemler yeterince uygulanmazsa saldırganlar, kurumsal bir cihaz gibi görünerek kendi cihazlarını kuruluşun MDM sunucusuna kaydetmek için bu basitleştirilmiş süreci kötüye kullanabilir.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Güvenlik Uyarısı**: Basitleştirilmiş DEP enrollment süreci, uygun güvenlik önlemleri mevcut değilse yetkisiz cihazların kuruluşun MDM sunucusuna kaydedilmesine olanak sağlayabilir.

### Temel Bilgiler: SCEP (Simple Certificate Enrolment Protocol) nedir?

- TLS ve HTTPS yaygınlaşmadan önce oluşturulmuş, nispeten eski bir protocol.
- Client'lara, certificate verilmesi amacıyla standartlaştırılmış bir **Certificate Signing Request** (CSR) gönderme yöntemi sağlar. Client, server'dan kendisine imzalı bir certificate vermesini ister.

### Configuration Profiles (diğer adıyla mobileconfigs) nedir?

- **System configuration ayarlamak/zorlamak** için Apple'ın resmi yöntemidir.
- Birden fazla payload içerebilen file format'ıdır.
- Property list'lere (XML türü) dayanır.
- “Kökenlerini doğrulamak, bütünlüklerini güvence altına almak ve içeriklerini korumak için imzalanabilir ve şifrelenebilir.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocol'ler

### MDM

- APNs (**Apple server**'ları) + RESTful API (**MDM** **vendor** server'ları) birleşimi
- **Communication**, bir **device** ile bir **device** **management** **product**'ı ile ilişkili bir server arasında gerçekleşir
- **Commands**, MDM'den device'a **plist-encoded dictionaries** olarak iletilir
- Tamamı **HTTPS** üzerinden gerçekleşir. MDM server'ları pin'lenebilir (ve genellikle pin'lenir).
- Apple, authentication için MDM vendor'ına bir **APNs certificate** verir

### DEP

- **3 API**: 1'i reseller'lar, 1'i MDM vendor'ları, 1'i device identity için (belgelenmemiş):
- Sözde [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Bu, MDM server'larının DEP profile'larını belirli device'larla ilişkilendirmesi için kullanılır.
- Device'ları enroll etmek, enrollment durumunu kontrol etmek ve transaction durumunu kontrol etmek için [Apple Authorized Reseller'lar tarafından kullanılan DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html).
- Belgelenmemiş private DEP API. Bu, Apple Device'larının DEP profile'larını istemesi için kullanılır. macOS'ta `cloudconfigurationd` binary'si bu API üzerinden communication'dan sorumludur.
- Daha modern ve **JSON** tabanlıdır (plist'e kıyasla)
- Apple, MDM vendor'ına bir **OAuth token** verir

**DEP "cloud service" API**

- RESTful
- device record'larını Apple'dan MDM server'ına sync eder
- “DEP profile”larını MDM server'ından Apple'a sync eder (daha sonra Apple tarafından device'a iletilir)
- Bir DEP “profile” şunları içerir:
- MDM vendor server URL'si
- Server URL için ek trusted certificate'lar (optional pinning)
- Ek ayarlar (örneğin Setup Assistant'ta hangi ekranların atlanacağı)

## Serial Number

2010'dan sonra üretilen Apple device'ları genellikle **12 karakterli alfanümerik** serial number'lara sahiptir. İlk **üç basamak üretim konumunu**, sonraki **iki basamak üretim yılını** ve **haftasını**, sonraki **üç basamak benzersiz** bir **identifier**'ı ve **son dört basamak model number'ını** belirtir.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Enrollment ve management adımları

1. Device record oluşturma (Reseller, Apple): Yeni device için record oluşturulur
2. Device record ataması (Customer): Device bir MDM server'ına atanır
3. Device record sync'i (MDM vendor): MDM, device record'larını sync eder ve DEP profile'larını Apple'a push eder
4. DEP check-in (Device): Device kendi DEP profile'ını alır
5. Profile retrieval (Device)
6. Profile installation (Device) a. MDM, SCEP ve root CA payload'ları dahil
7. MDM command issuance (Device)

![Serial Number - Enrollment ve management adımları: 7. MDM command issuance (Device)](<../../../images/image (694).png>)

`/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` file'ı, enrollment sürecinin **yüksek seviyeli "adımları"** olarak değerlendirilebilecek function'ları export eder.

### Step 4: DEP check-in - Activation Record'ı alma

Bu süreç, **bir user Mac'i ilk kez boot ettiğinde** (veya tamamen wipe edildikten sonra) gerçekleşir.

![Enrollment ve management adımları - Step 4: DEP check-in - Activation Record'ı alma: Bu süreç, bir user Mac'i ilk kez boot ettiğinde veya tamamen wipe edildikten sonra gerçekleşir](<../../../images/image (1044).png>)

veya `sudo profiles show -type enrollment` çalıştırıldığında

- **Device'ın DEP enabled olup olmadığını** belirler
- Activation Record, **DEP “profile”** için kullanılan internal name'dir
- Device Internet'e bağlanır bağlanmaz başlar
- **`CPFetchActivationRecord`** tarafından yönlendirilir
- XPC aracılığıyla **`cloudconfigurationd`** tarafından uygulanır. **"Setup Assistant**" (device ilk kez boot edildiğinde) veya **`profiles`** command'ı, activation record'ı almak için **bu daemon ile iletişim kurar**.
- LaunchDaemon (her zaman root olarak çalışır)

Activation Record'ı almak için gereken birkaç adım **`MCTeslaConfigurationFetcher`** tarafından gerçekleştirilir. Bu process, **Absinthe** adlı bir encryption kullanır<sup>[[1]](#references)</sup>

1. **Certificate**'ı al
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. State'i certificate'tan **initialize** et (**`NACInit`**)
1. Çeşitli device-specific data kullanır (ör. **`IOKit`** üzerinden **Serial Number**)
3. **Session key**'i al
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Session'ı oluştur (**`NACKeyEstablishment`**)
5. Request'i gönder
1. [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) adresine POST göndererek `{ "action": "RequestProfileConfiguration", "sn": "" }` data'sını iletir
2. JSON payload'ı Absinthe kullanılarak encrypted edilir (**`NACSign`**)
3. Tüm request'ler HTTPs üzerinden gönderilir, built-in root certificate'lar kullanılır

![Enrollment ve management adımları - Step 4: DEP check-in - Activation Record'ı alma: 3. Tüm request'ler HTTPs üzerinden gönderilir, built-in root certificate'lar kullanılır](<../../../images/image (566) (1).png>)

Response, aşağıdakiler gibi bazı önemli data'ları içeren bir JSON dictionary'dir:

- **url**: Activation profile için MDM vendor host'unun URL'si
- **anchor-certs**: Trusted anchor olarak kullanılan DER certificate'larından oluşan array

### **Step 5: Profile Retrieval**

![Step 4: DEP check-in - Activation Record'ı alma - Step 5: Profile Retrieval: Step 5: Profile Retrieval](<../../../images/image (444).png>)

- Request, **DEP profile'ında sağlanan url**'ye gönderilir.
- Sağlanmışsa **trust'i değerlendirmek** için **anchor certificate'lar** kullanılır.
- Hatırlatma: DEP profile'ının **anchor_certs** property'si
- **Request, device identification** içeren basit bir `.plist`'tir
- Örnekler: **UDID, OS version**.
- CMS-signed, DER-encoded
- **APNS'ten alınan device identity certificate** kullanılarak imzalanır
- **Certificate chain**, süresi dolmuş **Apple iPhone Device CA**'yı içerir

![Step 4: DEP check-in - Activation Record'ı alma - Step 5: Profile Retrieval: APNS'ten alınan device identity certificate kullanılarak imzalanır](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Step 6: Profile Installation

- Alındıktan sonra **profile system üzerinde saklanır**
- Bu step otomatik olarak başlar (**setup assistant** içindeyse)
- **`CPInstallActivationProfile`** tarafından yönlendirilir
- XPC üzerinden mdmclient tarafından uygulanır
- Context'e bağlı olarak LaunchDaemon (root olarak) veya LaunchAgent (user olarak)
- Configuration profile'ları yüklenecek birden fazla payload içerir
- Framework, profile'ları yüklemek için plugin-based bir architecture'a sahiptir
- Her payload type bir plugin ile ilişkilidir
- XPC (framework içinde) veya classic Cocoa (ManagedClient.app içinde) olabilir
- Örnek:
- Certificate Payloads, CertificateService.xpc'i kullanır

Genellikle bir MDM vendor tarafından sağlanan **activation profile** aşağıdaki payload'ları **içerir**:

- `com.apple.mdm`: device'ı MDM'e **enroll etmek** için
- `com.apple.security.scep`: device'a güvenli biçimde bir **client certificate** sağlamak için
- `com.apple.security.pem`: trusted CA certificate'larını device'ın System Keychain'ine **yüklemek** için
- MDM payload'ını yüklemek, documentation'daki **MDM check-in'e** denktir
- Payload **temel property'leri içerir**:
- - MDM Check-In URL'si (**`CheckInURL`**)
- MDM Command Polling URL'si (**`ServerURL`**) + bunu trigger etmek için APNs topic'i
- MDM payload'ını yüklemek için request **`CheckInURL`**'ye gönderilir
- **`mdmclient`** tarafından uygulanır
- MDM payload'ı diğer payload'lara bağlı olabilir
- Request'lerin belirli certificate'lara pin'lenmesine olanak sağlar:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- PEM payload üzerinden iletilir
- Device'ın bir identity certificate ile ilişkilendirilmesini sağlar:
- Property: IdentityCertificateUUID
- SCEP payload üzerinden iletilir

### **Step 7: MDM command'larını dinleme**

- MDM check-in tamamlandıktan sonra vendor, **APNs kullanarak push notification'lar gönderebilir**
- Alındığında **`mdmclient`** tarafından işlenir
- MDM command'larını poll etmek için request ServerURL'ye gönderilir
- Daha önce yüklenen MDM payload'ından yararlanır:
- Request pinning için **`ServerURLPinningCertificateUUIDs`**
- TLS client certificate için **`IdentityCertificateUUID`**

## Saldırılar

### Device'ları Diğer Organisation'lara Enroll Etme

Daha önce belirtildiği gibi, bir device'ı bir organization'a enroll etmeyi denemek için **yalnızca o Organization'a ait bir Serial Number gereklidir**. Device enroll edildikten sonra birçok organization yeni device'a sensitive data yükler: certificate'lar, application'lar, WiFi password'leri, VPN configuration'ları [ve benzerleri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle enrollment process doğru şekilde korunmuyorsa saldırganlar için tehlikeli bir entrypoint olabilir:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## References

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
