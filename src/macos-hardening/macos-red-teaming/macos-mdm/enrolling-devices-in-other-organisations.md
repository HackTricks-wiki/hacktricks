# Other Organisations'a Device Enrollment

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Apple Automated Device Enrollment (eski adıyla DEP), bir kuruluşa atanmış bir device'ı tanımlayarak başlar. Burada özetlenen 2018 araştırması, atanmış bir serial number bilgisinin bazı kuruluşların enrollment profillerini almak için yeterli olduğunu gösterdi; çünkü bu kuruluşlar yeterli ek authentication gerektirmiyordu. Bu, güncel her MDM'e yalnızca bir serial number ile katılınabileceği anlamına gelen bir iddia değil, tarihsel bir bulgudur. Profiller certificates, applications, Wi-Fi secrets, VPN settings ve diğer hassas configuration bilgilerini içerebilir.<sup>[[1]](#references)[[2]](#references)</sup>

**Aşağıda araştırmanın bir özeti verilmiştir: [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Daha fazla teknik ayrıntı için inceleyin!**<sup>[[1]](#references)</sup>

## DEP ve MDM Binary Analysis Genel Bakışı

Araştırma, o dönemde güncel olan macOS sürümlerinde DEP ve MDM ile ilişkili binary'leri analiz etti. Component adları ve sorumlulukları sürümler arasında değişebilir:

- **`mdmclient`**: MDM server'larıyla iletişim kurar ve 10.13.4 öncesi macOS sürümlerinde DEP check-in işlemlerini tetikler.
- **`profiles`**: Configuration Profiles'ı yönetir ve macOS 10.13.4 ve sonraki sürümlerde DEP check-in işlemlerini tetikler.
- **`cloudconfigurationd`**: DEP API iletişimlerini yönetir ve Device Enrollment profillerini alır.

DEP check-in işlemleri, Activation Record'u almak için private Configuration Profiles framework'ündeki `CPFetchActivationRecord` ve `CPGetActivationRecord` function'larını kullanır; `CPFetchActivationRecord`, XPC üzerinden `cloudconfigurationd` ile iletişimi koordine eder.<sup>[[1]](#references)</sup>

## Tesla Protocol ve Absinthe Scheme Reverse Engineering

DEP check-in işlemi, `cloudconfigurationd`'nin _iprofiles.apple.com/macProfile_'a encrypted ve signed bir JSON payload göndermesini içerir. Payload, device'ın serial number bilgisini ve "RequestProfileConfiguration" action'ını içerir. Kullanılan encryption scheme dahili olarak "Absinthe" olarak adlandırılır. Bu scheme'i çözmek karmaşıktır ve çok sayıda adım içerir; bu durum, Activation Record request'ine arbitrary serial number'lar eklemek için alternatif yöntemlerin araştırılmasına yol açmıştır.<sup>[[1]](#references)</sup>

## DEP Requests Proxying

Charles Proxy gibi tools kullanılarak _iprofiles.apple.com_'a yapılan DEP request'lerini intercept etme ve değiştirme girişimleri, payload encryption'ı ve SSL/TLS security measures nedeniyle engellendi. Ancak `MCCloudConfigAcceptAnyHTTPSCertificate` configuration'ının etkinleştirilmesi server certificate validation'ını bypass etmeye olanak tanır; yine de payload'ın encrypted olması, decryption key olmadan serial number'ın değiştirilmesini engeller.<sup>[[1]](#references)</sup>

## DEP ile Etkileşime Giren System Binaries'lerin Instrumentation'ı

`cloudconfigurationd` gibi system binaries'leri instrument etmek, macOS'ta System Integrity Protection (SIP)'ın devre dışı bırakılmasını gerektirir. SIP devre dışıyken LLDB gibi tools, system process'lerine attach olmak ve DEP API interactions sırasında kullanılan serial number'ı değiştirmek için kullanılabilir. Bu yöntem, entitlements ve code signing karmaşıklıklarını ortadan kaldırdığı için tercih edilir.<sup>[[1]](#references)</sup>

**Binary Instrumentation'ı Exploit Etme:**
`cloudconfigurationd` içindeki DEP request payload'ının JSON serialization'dan önce değiştirilmesinin etkili olduğu görüldü. Süreç şu adımlardan oluşuyordu:

1. LLDB'yi `cloudconfigurationd`'ye attach etmek.
2. System serial number'ın alındığı noktayı bulmak.
3. Payload encrypted edilip gönderilmeden önce memory'ye arbitrary bir serial number inject etmek.

Bu yöntem, araştırmacıların sağlanan ve atanmış serial number'lar için DEP profillerini almasını sağladı. Atanmamış arbitrary bir serial number'ı geçerli hale getirmedi.<sup>[[1]](#references)</sup>

### Python ile Instrumentation'ı Automate Etme

Exploitation süreci, LLDB API ile Python kullanılarak automate edildi; böylece arbitrary serial number'ların programmatically inject edilmesi ve karşılık gelen DEP profillerinin alınması mümkün hale geldi.<sup>[[1]](#references)</sup>

## 2025 Revisit: VM'den Rogue Enrollment

Black Hat Asia 2025 araştırması, orijinal trust-boundary probleminin **MDM layer**'ında hâlâ önem taşıyabildiğini gösterdi: araştırmacılar `cloudconfigurationd`'yi LLDB ile patch etmek yerine, macOS'u OpenCore ile QEMU/KVM altında çalıştırdı ve candidate identity bilgisini VM'in SMBIOS'u üzerinden sağladı. Değiştirilmemiş macOS enrollment stack'i daha sonra encrypted Apple exchange işlemini gerçekleştirdi. Bu nedenle publicly leaked serial'lar ve geçerli görünen candidates, karşılık gelen physical Mac'e sahip olunmadan test edilebilir; ancak başarılı sonuç için serial'ın bir kuruluşa atanmış olması ve kuruluşun enrollment path'inin yetersiz authentication uygulaması gerekir.<sup>[[3]](#references)</sup>

Yetkili bir lab device'ı için ilgili OpenCore `PlatformInfo` değerleri bir product model ve serial içerir (gerçek deployments ayrıca ROM ve UUID değerlerini kendi içinde tutarlı halde bulundurur):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
Aynı araştırma, özel `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck` dosyasında `CheckProfilesFetchRateLimit` durumunu da tespit etti. Denetim istemci üzerinde tutulduğundan, depolanan zaman değerlerini değiştirmek bu denetimi etkisiz hâle getirdi. Bu yollar belgelenmemiş ve sürüme bağlıdır, ancak güncel bir macOS derlemesini değerlendirirken yararlı reversing pivotlarıdır:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
İkinci artifact, flow'un doğrudan `ConfigurationURL` mı yoksa kimlik doğrulamalı `ConfigurationWebURL` mı kullandığını da içerecek şekilde, cached activation record'u açığa çıkarabilir. Hem duyurulan flow'u hem de MDM'e özgü legacy enrollment endpoint'lerini test edin: SSO'yu yalnızca ana web flow'unda etkinleştirmek, paralel doğrudan endpoint'i korumaz. Protokol sequence'inin tamamı için [macOS MDM overview](README.md) bölümüne bakın.<sup>[[3]](#references)</sup>

### Enrollment Sonrası Secret Hunting

Rogue enrollment yalnızca başlangıç noktasıdır. Enrollment sonrasında teslim edilen her profile'ı, bootstrap policy'yi, package-repository configuration'ını, agent installation script'ini ve self-service item'ını inceleyin. 2025 araştırması; Wi-Fi credentials, paylaşılan local-administrator passwords, imzalı cloud-storage URLs, webhook URLs, security-agent activation data ve MDM/API credentials örneklerini ortaya çıkardı. Teslim edilen bir script'teki tenant API credential, tek bir rogue endpoint'i diğer managed devices üzerinde kontrole dönüştürebilir; bu nedenle hem live filesystem'ı hem de indirilen/cached policy content'i tarayın.<sup>[[3]](#references)</sup>

Faydalı inceleme hedefleri şunlardır:<sup>[[3]](#references)</sup>

- Yüklü `.mobileconfig` payload'ları ve Configuration Profiles database.
- Account oluşturan veya EDR/VPN agent'ları yükleyen PreStage/bootstrap scripts ve packages.
- Özellikle bearer/SAS-style signatures içeren query strings barındıran Munki veya diğer package repository URLs.
- Enrollment SSO policy'sini zorunlu kılmayan legacy routes dahil olmak üzere self-service catalogs ve bunların arkasındaki policy APIs.
- `password`, `token`, `secret`, `Authorization`, webhook hostnames ve vendor API endpoints için shell history ve cached policy output.

### Trust Boundary'yi Hardening Etme

Bir serial number'ı **possession kanıtı olarak değil**, inventory/routing attribute olarak değerlendirin. Enrollment ve self service için user authentication zorunlu tutun, her device için benzersiz local administrator passwords oluşturun ve tenant API credentials veya yeniden kullanılabilir infrastructure secrets'ları profiles ya da scripts içine hiçbir zaman gömmeyin. Kaçınılmaz bootstrap token'ını kısa ömürlü tutun ve yalnızca provision edilmekte olan tek action ve device ile sınırlandırın.<sup>[[3]](#references)</sup>

macOS 14 veya sonraki sürümleri çalıştıran Apple-silicon Mac'lerde Managed Device Attestation, identity'yi Secure Enclave'e cryptographically bind edebilir. Apple-rooted attestation; fresh nonce ile birlikte serial number, UDID, OS version, SIP state ve secure-boot state taşıyabilir; ACME de bunun ardından hardware-bound client identity düzenleyebilir. MDM channel'ını korumak ve high-value certificates, VPN access ile diğer resources'lara erişimi denetlemek için bu identity'yi kullanın; ancak device attestation operator'ı değil device'ı kanıtladığından, ayrı user authentication mekanizmasını koruyun.<sup>[[4]](#references)</sup>

## DEP ve MDM Vulnerabilities'ın Potential Impacts

Araştırma, önemli security concerns'ları öne çıkardı:

1. **Information Disclosure**: DEP-registered bir serial number sağlanarak DEP profile'ında bulunan hassas organizational information alınabilir.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Rogue Device Enrolments Kullanılarak Apple MDM'lerinin Hacking Edilmesi](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
