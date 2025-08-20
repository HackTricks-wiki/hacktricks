# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**macOS MDM'leri hakkında bilgi almak için kontrol edin:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Temel Bilgiler

### **MDM (Mobil Cihaz Yönetimi) Genel Bakış**

[Mobil Cihaz Yönetimi](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM), akıllı telefonlar, dizüstü bilgisayarlar ve tabletler gibi çeşitli son kullanıcı cihazlarını yönetmek için kullanılır. Özellikle Apple'ın platformları (iOS, macOS, tvOS) için, özel özellikler, API'ler ve uygulamalar setini içerir. MDM'nin çalışması, ya ticari olarak mevcut ya da açık kaynak olan uyumlu bir MDM sunucusuna dayanır ve [MDM Protokolü](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)'nu desteklemelidir. Ana noktalar şunlardır:

- Cihazlar üzerinde merkezi kontrol.
- MDM protokolüne uyan bir MDM sunucusuna bağımlılık.
- MDM sunucusunun cihazlara çeşitli komutlar gönderebilme yeteneği, örneğin, uzaktan veri silme veya yapılandırma yükleme.

### **DEP (Cihaz Kaydı Programı) Temelleri**

Apple tarafından sunulan [Cihaz Kaydı Programı](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP), iOS, macOS ve tvOS cihazları için sıfırdan yapılandırmayı kolaylaştırarak Mobil Cihaz Yönetimi (MDM) entegrasyonunu basitleştirir. DEP, cihazların kutudan çıkar çıkmaz çalışır hale gelmesini sağlayarak, kullanıcı veya yönetici müdahalesini en aza indirir. Temel yönler şunlardır:

- Cihazların ilk etkinleştirme sırasında önceden tanımlanmış bir MDM sunucusuna otomatik olarak kaydolmasını sağlar.
- Öncelikle yeni cihazlar için faydalıdır, ancak yeniden yapılandırma sürecindeki cihazlar için de geçerlidir.
- Cihazların kurumsal kullanım için hızlı bir şekilde hazır hale gelmesini sağlayan basit bir kurulum sunar.

### **Güvenlik Dikkati**

DEP tarafından sağlanan kayıt kolaylığının faydalı olmasına rağmen, güvenlik riskleri de oluşturabileceğini belirtmek önemlidir. MDM kaydı için koruyucu önlemler yeterince uygulanmazsa, saldırganlar bu basitleştirilmiş süreci kullanarak kendi cihazlarını organizasyonun MDM sunucusuna kaydedebilir ve kurumsal bir cihaz gibi davranabilirler.

> [!CAUTION]
> **Güvenlik Uyarısı**: Basitleştirilmiş DEP kaydı, uygun koruma önlemleri alınmadığı takdirde, organizasyonun MDM sunucusunda yetkisiz cihaz kaydına izin verebilir.

### SCEP (Basit Sertifika Kaydı Protokolü) Nedir?

- TLS ve HTTPS yaygınlaşmadan önce oluşturulmuş, nispeten eski bir protokoldür.
- Müşterilere bir **Sertifika İmzalama Talebi** (CSR) gönderme konusunda standart bir yol sunar. Müşteri, sunucudan imzalı bir sertifika talep eder.

### Yapılandırma Profilleri (aka mobileconfigs) Nedir?

- Apple’ın **sistem yapılandırmasını ayarlama/uygulama** için resmi yolu.
- Birden fazla yük içerebilen dosya formatı.
- Özellik listelerine (XML türü) dayanır.
- “Kökenlerini doğrulamak, bütünlüklerini sağlamak ve içeriklerini korumak için imzalanabilir ve şifrelenebilir.” Temeller — Sayfa 70, iOS Güvenlik Kılavuzu, Ocak 2018.

## Protokoller

### MDM

- APNs (**Apple sunucuları**) + RESTful API (**MDM** **satıcı** sunucuları) kombinasyonu
- **İletişim**, bir **cihaz** ile bir **cihaz yönetim** **ürünü** ile ilişkili bir sunucu arasında gerçekleşir
- **Komutlar**, MDM'den cihaza **plist kodlu sözlükler** şeklinde iletilir
- Tüm iletişim **HTTPS** üzerinden gerçekleşir. MDM sunucuları genellikle pinlenmiştir.
- Apple, MDM satıcısına kimlik doğrulama için bir **APNs sertifikası** verir.

### DEP

- **3 API**: 1 satıcılar için, 1 MDM satıcıları için, 1 cihaz kimliği için (belgelendirilmemiş):
- Sözde [DEP "bulut hizmeti" API'si](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Bu, MDM sunucularının DEP profillerini belirli cihazlarla ilişkilendirmek için kullandığı bir API'dir.
- [Apple Yetkili Satıcıları tarafından kullanılan DEP API'si](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) cihazları kaydetmek, kayıt durumunu kontrol etmek ve işlem durumunu kontrol etmek için kullanılır.
- Belgelendirilmemiş özel DEP API'si. Bu, Apple Cihazlarının DEP profillerini talep etmek için kullandığı bir API'dir. macOS'ta, `cloudconfigurationd` ikili dosyası bu API üzerinden iletişim kurmaktan sorumludur.
- Daha modern ve **JSON** tabanlıdır (plist'e karşı)
- Apple, MDM satıcısına bir **OAuth token** verir.

**DEP "bulut hizmeti" API'si**

- RESTful
- Apple'dan MDM sunucusuna cihaz kayıtlarını senkronize eder
- MDM sunucusundan Apple'a "DEP profilleri" senkronize eder (daha sonra cihazlara Apple tarafından iletilir)
- Bir DEP “profili” şunları içerir:
- MDM satıcı sunucu URL'si
- Sunucu URL'si için ek güvenilir sertifikalar (isteğe bağlı pinleme)
- Ek ayarlar (örneğin, Kurulum Asistanı'nda hangi ekranların atlanacağı)

## Seri Numarası

2010'dan sonra üretilen Apple cihazları genellikle **12 karakterli alfanümerik** seri numaralarına sahiptir; **ilk üç rakam üretim yerini**, sonraki **iki** rakam **yıl** ve **hafta** numarasını, sonraki **üç** rakam **benzersiz** **tanımlayıcıyı** ve **son dört** rakam **model numarasını** temsil eder.

{{#ref}}
macos-serial-number.md
{{#endref}}

## Kayıt ve Yönetim Adımları

1. Cihaz kaydı oluşturma (Satıcı, Apple): Yeni cihaz için kayıt oluşturulur
2. Cihaz kaydı atama (Müşteri): Cihaz bir MDM sunucusuna atanır
3. Cihaz kaydı senkronizasyonu (MDM satıcısı): MDM, cihaz kayıtlarını senkronize eder ve DEP profillerini Apple'a iletir
4. DEP kontrolü (Cihaz): Cihaz DEP profilini alır
5. Profil alma (Cihaz)
6. Profil yükleme (Cihaz) a. MDM, SCEP ve kök CA yüklerini içerir
7. MDM komutunun verilmesi (Cihaz)

![](<../../../images/image (694).png>)

Dosya `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd`, kayıt sürecinin **yüksek seviyeli "adımları"** olarak kabul edilebilecek işlevleri dışa aktarır.

### Adım 4: DEP kontrolü - Aktivasyon Kaydını Alma

Bu süreç, bir **kullanıcının bir Mac'i ilk kez başlattığında** (veya tamamen silindikten sonra) gerçekleşir.

![](<../../../images/image (1044).png>)

veya `sudo profiles show -type enrollment` komutu çalıştırıldığında

- **Cihazın DEP etkin olup olmadığını belirleme**
- Aktivasyon Kaydı, **DEP “profili”** için içsel bir isimdir
- Cihaz internete bağlandığı anda başlar
- **`CPFetchActivationRecord`** tarafından yönlendirilir
- **`cloudconfigurationd`** tarafından XPC aracılığıyla uygulanır. **"Kurulum Asistanı"** (cihaz ilk kez başlatıldığında) veya **`profiles`** komutu, aktivasyon kaydını almak için bu daemon ile **iletişim kurar**.
- LaunchDaemon (her zaman root olarak çalışır)

Aktivasyon Kaydını almak için **`MCTeslaConfigurationFetcher`** tarafından gerçekleştirilen birkaç adım izlenir. Bu süreç, **Absinthe** adı verilen bir şifreleme kullanır.

1. **sertifika al**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. Sertifikadan durumu **başlat** (**`NACInit`**)
1. Çeşitli cihaz spesifik verileri kullanır (yani **Seri Numarası `IOKit` aracılığıyla**)
3. **oturum anahtarını al**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Oturumu kur (**`NACKeyEstablishment`**)
5. Talebi yap
1. POST [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) verileri göndererek `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. JSON yükü Absinthe ile şifrelenir (**`NACSign`**)
3. Tüm talepler HTTPS üzerinden, yerleşik kök sertifikalar kullanılarak yapılır

![](<../../../images/image (566) (1).png>)

Yanıt, aşağıdaki gibi bazı önemli verileri içeren bir JSON sözlüğüdür:

- **url**: aktivasyon profili için MDM satıcı ana bilgisayarının URL'si
- **anchor-certs**: güvenilir kökler olarak kullanılan DER sertifikalarının dizisi

### **Adım 5: Profil Alma**

![](<../../../images/image (444).png>)

- **DEP profilinde sağlanan URL'ye** talep gönderilir.
- **Köprü sertifikaları**, sağlanmışsa **güveni değerlendirmek** için kullanılır.
- Hatırlatma: **anchor_certs** özelliği DEP profilinin
- **Talep, cihaz tanımlaması ile basit bir .plist**'tir
- Örnekler: **UDID, OS versiyonu**.
- CMS imzalı, DER kodlu
- **Cihaz kimliği sertifikası (APNS'den)** kullanılarak imzalanmıştır.
- **Sertifika zinciri**, süresi dolmuş **Apple iPhone Cihaz CA**'sını içerir.

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Adım 6: Profil Yükleme

- Alındıktan sonra, **profil sistemde saklanır**
- Bu adım otomatik olarak başlar (eğer **kurulum asistanındaysa**)
- **`CPInstallActivationProfile`** tarafından yönlendirilir
- XPC üzerinden mdmclient tarafından uygulanır
- Bağlama Daemon (root olarak) veya Bağlama Ajanı (kullanıcı olarak), bağlama bağlamına bağlı olarak
- Yapılandırma profilleri, yüklemek için birden fazla yük içerir
- Çerçeve, profilleri yüklemek için eklenti tabanlı bir mimariye sahiptir
- Her yük türü bir eklenti ile ilişkilendirilmiştir
- XPC (çerçevede) veya klasik Cocoa (ManagedClient.app içinde) olabilir
- Örnek:
- Sertifika Yükleri, CertificateService.xpc kullanır

Genellikle, bir MDM satıcısı tarafından sağlanan **aktivasyon profili** aşağıdaki yükleri **içerecektir**:

- `com.apple.mdm`: cihazı MDM'ye **kaydetmek** için
- `com.apple.security.scep`: cihaza güvenli bir **istemci sertifikası** sağlamak için.
- `com.apple.security.pem`: cihaza güvenilir CA sertifikalarını **yüklemek** için.
- MDM yüklemesi, belgelerdeki **MDM kontrolü** ile eşdeğerdir
- Yük **anahtar özellikleri** içerir:
- - MDM Kontrol URL'si (**`CheckInURL`**)
- MDM Komut Polling URL'si (**`ServerURL`**) + tetiklemek için APNs konusu
- MDM yüklemesi için, **`CheckInURL`**'ye bir talep gönderilir
- **`mdmclient`** içinde uygulanır
- MDM yüklemesi diğer yüklerden bağımsız olabilir
- **Belirli sertifikalara pinlenmiş taleplere** izin verir:
- Özellik: **`CheckInURLPinningCertificateUUIDs`**
- Özellik: **`ServerURLPinningCertificateUUIDs`**
- PEM yükü aracılığıyla iletilir
- Cihazın bir kimlik sertifikası ile tanımlanmasına izin verir:
- Özellik: IdentityCertificateUUID
- SCEP yükü aracılığıyla iletilir

### **Adım 7: MDM komutlarını dinleme**

- MDM kontrolü tamamlandıktan sonra, satıcı **APNs kullanarak push bildirimleri gönderebilir**
- Alındığında, **`mdmclient`** tarafından işlenir
- MDM komutlarını sorgulamak için, ServerURL'ye bir talep gönderilir
- Daha önce yüklenmiş MDM yüklemesini kullanır:
- **`ServerURLPinningCertificateUUIDs`** pinleme talebi için
- **`IdentityCertificateUUID`** TLS istemci sertifikası için

## Saldırılar

### Diğer Organizasyonlarda Cihaz Kaydı

Daha önce belirtildiği gibi, bir cihazı bir organizasyona kaydetmek için **sadece o Organizasyona ait bir Seri Numarası gereklidir**. Cihaz kaydedildikten sonra, birçok organizasyon yeni cihaza hassas veriler yükleyecektir: sertifikalar, uygulamalar, WiFi şifreleri, VPN yapılandırmaları [ve benzeri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle, kayıt süreci doğru bir şekilde korunmazsa, bu saldırganlar için tehlikeli bir giriş noktası olabilir:

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
