# Other Organisations'a Cihaz Kaydetme

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

Apple Automated Device Enrollment (eski adıyla DEP), bir kuruluşa atanmış cihazı tanımlayarak başlar. Burada özetlenen 2018 araştırması, atanmış bir seri numarasının bilinmesinin, bazı kuruluşların yeterli ek authentication gerektirmemesi nedeniyle bu kuruluşların enrollment profillerini almak için yeterli olduğunu gösterdi. Bu tarihsel bir bulgudur; günümüzdeki her MDM'e yalnızca seri numarasıyla katılınabileceği anlamına gelmez. Profiller sertifikalar, uygulamalar, Wi-Fi secrets, VPN ayarları ve diğer hassas yapılandırmaları içerebilir.<sup>[[1]](#references)[[2]](#references)</sup>

**Aşağıda araştırmanın özeti yer almaktadır: [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Daha fazla teknik ayrıntı için inceleyin!**<sup>[[1]](#references)</sup>

## DEP ve MDM Binary Analysis Genel Bakışı

Araştırma, o dönemde güncel olan macOS sürümlerinde DEP ve MDM ile ilişkili binary'leri analiz etti. Bileşen adları ve sorumlulukları sürümler arasında değişebilir:

- **`mdmclient`**: MDM sunucularıyla iletişim kurar ve 10.13.4 öncesindeki macOS sürümlerinde DEP check-in işlemlerini tetikler.
- **`profiles`**: Configuration Profiles'ı yönetir ve macOS 10.13.4 ve sonraki sürümlerde DEP check-in işlemlerini tetikler.
- **`cloudconfigurationd`**: DEP API iletişimlerini yönetir ve Device Enrollment profillerini alır.

DEP check-in işlemleri, Activation Record'u almak için private Configuration Profiles framework'ündeki `CPFetchActivationRecord` ve `CPGetActivationRecord` fonksiyonlarını kullanır; `CPFetchActivationRecord`, XPC üzerinden `cloudconfigurationd` ile iletişimi koordine eder.<sup>[[1]](#references)</sup>

## Tesla Protocol ve Absinthe Scheme Reverse Engineering

DEP check-in işlemi, `cloudconfigurationd`'nin _iprofiles.apple.com/macProfile_ adresine şifrelenmiş ve imzalanmış bir JSON payload göndermesini içerir. Payload, cihazın seri numarasını ve "RequestProfileConfiguration" action'ını içerir. Kullanılan encryption scheme dahili olarak "Absinthe" olarak adlandırılır. Bu scheme'in çözülmesi karmaşıktır ve çok sayıda adım içerir; bu durum, Activation Record request'ine arbitrary serial number eklemek için alternatif yöntemlerin araştırılmasına yol açmıştır.<sup>[[1]](#references)</sup>

## DEP Requests Proxy'leme

Charles Proxy gibi araçları kullanarak _iprofiles.apple.com_ adresine gönderilen DEP requests'leri intercept etme ve değiştirme girişimleri, payload encryption ve SSL/TLS security measures nedeniyle engellendi. Ancak `MCCloudConfigAcceptAnyHTTPSCertificate` configuration'ının etkinleştirilmesi server certificate validation işlemini bypass etmeyi sağlar; payload'ın encrypted olması, decryption key olmadan seri numarasının değiştirilmesini yine de engeller.<sup>[[1]](#references)</sup>

## DEP ile Etkileşime Giren System Binaries'leri Instrument Etme

`cloudconfigurationd` gibi system binaries'lerini instrument etmek, macOS'te System Integrity Protection (SIP)'ın devre dışı bırakılmasını gerektirir. SIP devre dışıyken LLDB gibi araçlar system process'lerine attach olmak ve DEP API interactions sırasında kullanılan seri numarasını potansiyel olarak değiştirmek için kullanılabilir. Bu yöntem, entitlements ve code signing karmaşıklıklarını ortadan kaldırdığı için tercih edilir.<sup>[[1]](#references)</sup>

**Binary Instrumentation'ı Exploit Etme:**
`cloudconfigurationd` içindeki JSON serialization işleminden önce DEP request payload'ının değiştirilmesi etkili oldu. Süreç şu adımlardan oluşuyordu:

1. LLDB'yi `cloudconfigurationd`'ye attach etmek.
2. System serial number'ın alındığı noktayı bulmak.
3. Payload encrypt edilip gönderilmeden önce memory'ye arbitrary serial number inject etmek.

Bu yöntem, araştırmacıların sağlanan ve atanmış serial number'lar için DEP profillerini almasını sağladı. Atanmamış arbitrary bir serial number'ı geçerli hale getirmedi.<sup>[[1]](#references)</sup>

### Python ile Instrumentation'ı Otomatikleştirme

Exploitation süreci, LLDB API'si kullanılarak Python ile otomatikleştirildi; böylece arbitrary serial number'ları programatik olarak inject etmek ve karşılık gelen DEP profillerini almak mümkün hale geldi.<sup>[[1]](#references)</sup>

### DEP ve MDM Vulnerabilities'lerinin Olası Etkileri

Araştırma, önemli security concerns'leri ortaya koydu:

1. **Information Disclosure**: DEP'e kayıtlı bir serial number sağlanarak DEP profile içinde bulunan hassas kurumsal bilgiler alınabilir.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
