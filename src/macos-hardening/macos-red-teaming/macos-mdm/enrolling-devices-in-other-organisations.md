# Diğer Organizasyonlara Cihaz Kaydetme

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

[**Daha önce belirtildiği gibi**](#what-is-mdm-mobile-device-management)**,** bir cihazı bir organizasyona kaydetmeyi denemek için **yalnızca o Organizasyona ait bir Serial Number gereklidir**. Cihaz kaydedildikten sonra birçok organizasyon yeni cihaza hassas veriler yükler: sertifikalar, uygulamalar, WiFi şifreleri, VPN yapılandırmaları [ve benzeri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle, kayıt işlemi doğru şekilde korunmuyorsa saldırganlar için tehlikeli bir giriş noktası olabilir.

**Aşağıdaki içerik araştırmanın özetidir: [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Daha fazla teknik ayrıntı için inceleyin!**<sup>[[1]](#references)</sup>

## DEP ve MDM Binary Analysis Genel Bakışı

Bu araştırma, macOS üzerindeki Device Enrollment Program (DEP) ve Mobile Device Management (MDM) ile ilişkili binary'leri inceler. Temel bileşenler şunlardır:

- **`mdmclient`**: MDM sunucularıyla iletişim kurar ve 10.13.4 öncesi macOS sürümlerinde DEP check-in işlemlerini tetikler.
- **`profiles`**: Configuration Profiles'ı yönetir ve 10.13.4 ve sonraki macOS sürümlerinde DEP check-in işlemlerini tetikler.
- **`cloudconfigurationd`**: DEP API iletişimini yönetir ve Device Enrollment profillerini alır.

DEP check-in işlemleri, Activation Record'ı almak için private Configuration Profiles framework'ündeki `CPFetchActivationRecord` ve `CPGetActivationRecord` işlevlerini kullanır; `CPFetchActivationRecord`, XPC üzerinden `cloudconfigurationd` ile iletişimi koordine eder.<sup>[[1]](#references)</sup>

## Tesla Protocol ve Absinthe Scheme Reverse Engineering

DEP check-in işlemi, `cloudconfigurationd`'nin _iprofiles.apple.com/macProfile_ adresine şifrelenmiş ve imzalanmış bir JSON payload göndermesini içerir. Payload, cihazın serial number'ını ve "RequestProfileConfiguration" action'ını içerir. Kullanılan encryption scheme dahili olarak "Absinthe" olarak adlandırılır. Bu scheme'i çözmek karmaşıktır ve çok sayıda adım içerir; bu durum, Activation Record isteğine arbitrary serial number eklemek için alternatif yöntemlerin araştırılmasına yol açmıştır.<sup>[[1]](#references)</sup>

## DEP İsteklerini Proxy'leme

Charles Proxy gibi araçlar kullanılarak _iprofiles.apple.com_ adresine gönderilen DEP isteklerini intercept etme ve değiştirme girişimleri, payload encryption ve SSL/TLS security measures nedeniyle engellenmiştir. Ancak `MCCloudConfigAcceptAnyHTTPSCertificate` configuration'ının etkinleştirilmesi, server certificate validation işleminin bypass edilmesini sağlar; yine de payload'ın encrypted yapısı, decryption key olmadan serial number'ın değiştirilmesini engeller.<sup>[[1]](#references)</sup>

## DEP ile Etkileşime Giren System Binary'lerini Instrument Etme

`cloudconfigurationd` gibi system binary'lerini instrument etmek, macOS'te System Integrity Protection (SIP) özelliğinin devre dışı bırakılmasını gerektirir. SIP devre dışıyken LLDB gibi araçlar system process'lerine attach olmak ve DEP API etkileşimlerinde kullanılan serial number'ı potansiyel olarak değiştirmek için kullanılabilir. Bu yöntem, entitlements ve code signing karmaşıklıklarını ortadan kaldırdığı için tercih edilir.

**Binary Instrumentation'ı Exploit Etme:**
`cloudconfigurationd` içindeki JSON serialization işleminden önce DEP request payload'ını değiştirmek etkili olmuştur. Süreç şu adımlardan oluşur:

1. LLDB'yi `cloudconfigurationd`'ye attach etmek.
2. System serial number'ın alındığı noktayı bulmak.
3. Payload encryption edilip gönderilmeden önce memory'ye arbitrary bir serial number inject etmek.

Bu yöntem, arbitrary serial number'lar için tam DEP profillerinin alınmasını sağlamış ve olası bir vulnerability ortaya koymuştur.<sup>[[1]](#references)</sup>

### Instrumentation'ı Python ile Automate Etme

Exploitation süreci, LLDB API kullanılarak Python ile automate edilmiştir; böylece arbitrary serial number'ları programatik olarak inject etmek ve bunlara karşılık gelen DEP profillerini almak mümkün hâle gelmiştir.<sup>[[1]](#references)</sup>

### DEP ve MDM Vulnerability'lerinin Olası Etkileri

Araştırma, önemli security concerns'ları ortaya koymuştur:

1. **Information Disclosure**: DEP-registered bir serial number sağlanarak, DEP profile içinde yer alan hassas organizasyon bilgileri alınabilir.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
