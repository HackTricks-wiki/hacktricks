# Diğer Organizasyonlardaki Cihazları Enrol Etme

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

[**Daha önce belirtildiği gibi**](#what-is-mdm-mobile-device-management)**,** bir cihazı bir organizasyona enrol etmeye çalışmak için **yalnızca o Organizasyona ait bir Serial Number gereklidir**. Cihaz enrol edildikten sonra birçok organizasyon yeni cihaza hassas veriler yükler: sertifikalar, uygulamalar, WiFi parolaları, VPN yapılandırmaları [ve benzerleri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle enrolment süreci doğru şekilde korunmuyorsa saldırganlar için tehlikeli bir giriş noktası oluşturabilir.

**Aşağıda araştırmanın bir özeti verilmiştir: [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Daha fazla teknik ayrıntı için inceleyin!**<sup>[[1]](#references)</sup>

## DEP ve MDM Binary Analysis Genel Bakışı

Bu araştırma, macOS üzerindeki Device Enrollment Program (DEP) ve Mobile Device Management (MDM) ile ilişkili binary'leri inceler. Temel bileşenler şunlardır:

- **`mdmclient`**: MDM sunucularıyla iletişim kurar ve 10.13.4 öncesi macOS sürümlerinde DEP check-in işlemlerini tetikler.
- **`profiles`**: Configuration Profiles'ı yönetir ve macOS 10.13.4 ve sonraki sürümlerde DEP check-in işlemlerini tetikler.
- **`cloudconfigurationd`**: DEP API iletişimlerini yönetir ve Device Enrollment profillerini alır.

DEP check-in işlemleri, Activation Record'u almak için private Configuration Profiles framework'ündeki `CPFetchActivationRecord` ve `CPGetActivationRecord` fonksiyonlarını kullanır. `CPFetchActivationRecord`, XPC üzerinden `cloudconfigurationd` ile koordinasyon sağlar.<sup>[[1]](#references)</sup>

## Tesla Protocol ve Absinthe Scheme Reverse Engineering

DEP check-in sürecinde `cloudconfigurationd`, _iprofiles.apple.com/macProfile_ adresine şifrelenmiş ve imzalanmış bir JSON payload gönderir. Payload, cihazın serial number'ını ve "RequestProfileConfiguration" action'ını içerir. Kullanılan encryption scheme dahili olarak "Absinthe" olarak adlandırılır. Bu scheme'i çözmek karmaşıktır ve çok sayıda adım içerir; bu durum, Activation Record isteğine arbitrary serial number'lar eklemek için alternatif yöntemlerin araştırılmasına yol açmıştır.<sup>[[1]](#references)</sup>

## DEP İsteklerini Proxy'leme

Charles Proxy gibi araçları kullanarak _iprofiles.apple.com_ adresine yönelik DEP isteklerini intercept etme ve değiştirme girişimleri, payload encryption'ı ve SSL/TLS security önlemleri nedeniyle engellenmiştir. Bununla birlikte, `MCCloudConfigAcceptAnyHTTPSCertificate` configuration'ını etkinleştirmek server certificate validation'ı bypass etmeyi sağlar; ancak payload'ın encrypted olması, decryption key olmadan serial number'ın değiştirilmesini yine de engeller.<sup>[[1]](#references)</sup>

## DEP ile Etkileşime Giren System Binary'lerini Instrument Etme

`cloudconfigurationd` gibi system binary'lerini instrument etmek, macOS'ta System Integrity Protection (SIP)'ın devre dışı bırakılmasını gerektirir. SIP devre dışı bırakıldığında LLDB gibi araçlar system process'lerine attach olmak ve DEP API etkileşimlerinde kullanılan serial number'ı potansiyel olarak değiştirmek için kullanılabilir. Bu yöntem, entitlements ve code signing karmaşıklıklarını ortadan kaldırdığı için tercih edilir.<sup>[[1]](#references)</sup>

**Binary Instrumentation'ı Exploit Etme:**
`cloudconfigurationd` içindeki JSON serialization işleminden önce DEP request payload'ını değiştirmek etkili olmuştur. Süreç şu adımlardan oluşmuştur:

1. LLDB'yi `cloudconfigurationd`'ye attach etmek.
2. System serial number'ın alındığı noktayı bulmak.
3. Payload encrypted edilip gönderilmeden önce memory'ye arbitrary bir serial number inject etmek.

Bu yöntem, arbitrary serial number'lar için eksiksiz DEP profillerinin alınmasını sağlayarak potansiyel bir vulnerability göstermiştir.<sup>[[1]](#references)</sup>

### Python ile Instrumentation'ı Otomatikleştirme

Exploitation süreci, LLDB API ile Python kullanılarak otomatikleştirilmiştir. Böylece arbitrary serial number'ların programatik olarak inject edilmesi ve bunlara karşılık gelen DEP profillerinin alınması mümkün hale gelmiştir.<sup>[[1]](#references)</sup>

### DEP ve MDM Vulnerability'lerinin Olası Etkileri

Araştırma, önemli security endişelerini ortaya koymuştur:

1. **Information Disclosure**: DEP-registered bir serial number sağlanarak DEP profilinde bulunan hassas organizasyon bilgileri alınabilir.<sup>[[1]](#references)</sup>

## Referanslar

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
