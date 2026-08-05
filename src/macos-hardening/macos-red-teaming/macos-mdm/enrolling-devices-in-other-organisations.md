# Other Organisations İçinde Cihaz Kaydetme

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

[**Daha önce belirtildiği gibi**](#what-is-mdm-mobile-device-management)**,** bir cihazı bir organization içine kaydetmeyi denemek için **yalnızca o Organization'a ait bir Serial Number gereklidir**. Cihaz kaydedildikten sonra birçok organization yeni cihaza hassas veriler yükler: sertifikalar, uygulamalar, WiFi şifreleri, VPN yapılandırmaları [ve benzerleri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle, kayıt işlemi doğru şekilde korunmuyorsa saldırganlar için tehlikeli bir giriş noktası oluşturabilir.

**Aşağıda araştırmanın bir özeti verilmiştir: [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Daha fazla teknik ayrıntı için inceleyin!**<sup>[1]</sup>

## DEP ve MDM Binary Analysis Genel Bakışı

Bu araştırma, macOS üzerindeki Device Enrollment Program (DEP) ve Mobile Device Management (MDM) ile ilişkili binary'leri inceler. Temel bileşenler şunlardır:

- **`mdmclient`**: MDM sunucularıyla iletişim kurar ve 10.13.4 öncesi macOS sürümlerinde DEP check-in işlemlerini tetikler.
- **`profiles`**: Configuration Profiles'ı yönetir ve macOS 10.13.4 ve sonraki sürümlerde DEP check-in işlemlerini tetikler.
- **`cloudconfigurationd`**: DEP API iletişimlerini yönetir ve Device Enrollment profillerini alır.

DEP check-in işlemleri, Activation Record'u almak için private Configuration Profiles framework'ündeki `CPFetchActivationRecord` ve `CPGetActivationRecord` işlevlerini kullanır. `CPFetchActivationRecord`, XPC aracılığıyla `cloudconfigurationd` ile iletişimi koordine eder.<sup>[1]</sup>

## Tesla Protocol ve Absinthe Scheme Reverse Engineering

DEP check-in işlemi, `cloudconfigurationd`'nin şifrelenmiş ve imzalanmış bir JSON payload'ını _iprofiles.apple.com/macProfile_'a göndermesini içerir. Payload, cihazın serial number'ını ve "RequestProfileConfiguration" action'ını içerir. Kullanılan encryption scheme dahili olarak "Absinthe" olarak adlandırılır. Bu scheme'i çözümlemek karmaşıktır ve çok sayıda adım gerektirir; bu durum, Activation Record isteğine rastgele serial number'lar eklemek için alternatif yöntemlerin araştırılmasına yol açmıştır.<sup>[1]</sup>

## DEP İsteklerini Proxy Üzerinden Yönlendirme

Charles Proxy gibi araçları kullanarak _iprofiles.apple.com_'a gönderilen DEP isteklerini yakalama ve değiştirme girişimleri, payload encryption'ı ve SSL/TLS security measures nedeniyle engellenmiştir. Bununla birlikte, `MCCloudConfigAcceptAnyHTTPSCertificate` configuration'ının etkinleştirilmesi server certificate validation işleminin atlanmasını sağlar; ancak payload'ın encrypted olması, decryption key olmadan serial number'ın değiştirilmesini hâlâ engeller.<sup>[1]</sup>

## DEP ile Etkileşime Giren System Binary'lerini Instrumentation ile İnceleme

`cloudconfigurationd` gibi system binary'lerini instrument etmek, macOS'ta System Integrity Protection (SIP) özelliğinin devre dışı bırakılmasını gerektirir. SIP devre dışıyken LLDB gibi araçlar system process'lerine attach olmak ve DEP API etkileşimlerinde kullanılan serial number'ı değiştirmek için kullanılabilir. Bu yöntem, entitlements ve code signing karmaşıklıklarını ortadan kaldırdığı için tercih edilir.

**Binary Instrumentation'ı Exploit Etme:**
`cloudconfigurationd` içindeki DEP request payload'ının JSON serialization öncesinde değiştirilmesi etkili olmuştur. İşlem şu adımlardan oluşur:

1. LLDB'yi `cloudconfigurationd`'ye attach etmek.
2. System serial number'ın alındığı noktayı bulmak.
3. Payload encrypted edilip gönderilmeden önce memory içine rastgele bir serial number inject etmek.

Bu yöntem, rastgele serial number'lar için eksiksiz DEP profillerinin alınmasını sağlayarak potansiyel bir vulnerability olduğunu göstermiştir.<sup>[1]</sup>

### Python ile Instrumentation'ı Otomatikleştirme

Exploitation işlemi, LLDB API kullanılarak Python ile otomatikleştirilmiştir. Böylece rastgele serial number'ların programatik olarak inject edilmesi ve bunlara karşılık gelen DEP profillerinin alınması mümkün hâle gelmiştir.<sup>[1]</sup>

### DEP ve MDM Vulnerability'lerinin Olası Etkileri

Araştırma, önemli security concerns'ları ortaya koymuştur:

1. **Information Disclosure**: DEP'e kayıtlı bir serial number sağlanarak DEP profile içinde bulunan hassas organizational information alınabilir.<sup>[1]</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
