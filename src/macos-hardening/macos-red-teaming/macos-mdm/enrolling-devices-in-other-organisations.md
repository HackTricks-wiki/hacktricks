# Diğer Kuruluşlarda Cihaz Kaydı

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

[**Daha önce belirtildiği gibi**](#what-is-mdm-mobile-device-management)**,** bir cihazı bir kuruluşa kaydetmek için **sadece o Kuruluşa ait bir Seri Numarası gereklidir**. Cihaz kaydedildikten sonra, birkaç kuruluş yeni cihaza hassas veriler yükleyecektir: sertifikalar, uygulamalar, WiFi şifreleri, VPN yapılandırmaları [ve benzeri](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Bu nedenle, kayıt süreci doğru bir şekilde korunmazsa, bu saldırganlar için tehlikeli bir giriş noktası olabilir.

**Aşağıda, araştırmanın bir özeti bulunmaktadır [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Daha fazla teknik detay için kontrol edin!**

## DEP ve MDM İkili Analizi Genel Görünümü

Bu araştırma, macOS'taki Cihaz Kaydı Programı (DEP) ve Mobil Cihaz Yönetimi (MDM) ile ilişkili ikililere dalmaktadır. Ana bileşenler şunlardır:

- **`mdmclient`**: MDM sunucularıyla iletişim kurar ve macOS sürümleri 10.13.4 öncesinde DEP kontrol noktalarını tetikler.
- **`profiles`**: Yapılandırma Profillerini yönetir ve macOS sürümleri 10.13.4 ve sonrasında DEP kontrol noktalarını tetikler.
- **`cloudconfigurationd`**: DEP API iletişimlerini yönetir ve Cihaz Kaydı profillerini alır.

DEP kontrol noktaları, Aktivasyon Kaydını almak için özel Yapılandırma Profilleri çerçevesinden `CPFetchActivationRecord` ve `CPGetActivationRecord` işlevlerini kullanır; `CPFetchActivationRecord`, `cloudconfigurationd` ile XPC üzerinden koordine olur.

## Tesla Protokolü ve Absinthe Şeması Tersine Mühendislik

DEP kontrol noktası, `cloudconfigurationd`'nin _iprofiles.apple.com/macProfile_ adresine şifrelenmiş, imzalı bir JSON yükü göndermesini içerir. Yük, cihazın seri numarasını ve "RequestProfileConfiguration" eylemini içerir. Kullanılan şifreleme şeması dahili olarak "Absinthe" olarak adlandırılmaktadır. Bu şemanın çözülmesi karmaşıktır ve birçok adım içerir; bu da Aktivasyon Kaydı isteğine keyfi seri numaraları eklemek için alternatif yöntemlerin araştırılmasına yol açmıştır.

## DEP İsteklerini Proxyleme

_iprofiles.apple.com_ adresine giden DEP isteklerini kesmek ve değiştirmek için Charles Proxy gibi araçlar kullanma girişimleri, yük şifrelemesi ve SSL/TLS güvenlik önlemleri nedeniyle engellenmiştir. Ancak, `MCCloudConfigAcceptAnyHTTPSCertificate` yapılandırmasını etkinleştirmek, sunucu sertifikası doğrulamasını atlamayı sağlar; ancak yükün şifreli doğası, şifre çözme anahtarı olmadan seri numarasının değiştirilmesini engeller.

## DEP ile Etkileşimde Bulunan Sistem İkili Dosyalarını Enstrümante Etme

`cloudconfigurationd` gibi sistem ikili dosyalarını enstrümante etmek, macOS'ta Sistem Bütünlüğü Koruması (SIP) devre dışı bırakılmasını gerektirir. SIP devre dışı bırakıldığında, LLDB gibi araçlar sistem süreçlerine bağlanmak ve DEP API etkileşimlerinde kullanılan seri numarasını potansiyel olarak değiştirmek için kullanılabilir. Bu yöntem, yetkilendirmeler ve kod imzalama karmaşıklıklarından kaçındığı için tercih edilmektedir.

**İkili Enstrümantasyonun Sömürülmesi:**
`cloudconfigurationd`'de JSON serileştirmeden önce DEP istek yükünü değiştirmek etkili olmuştur. Süreç şunları içeriyordu:

1. LLDB'yi `cloudconfigurationd`'ye bağlamak.
2. Sistem seri numarasının alındığı noktayı bulmak.
3. Yük şifrelenmeden ve gönderilmeden önce belleğe keyfi bir seri numarası enjekte etmek.

Bu yöntem, keyfi seri numaraları için tam DEP profilleri almayı sağladı ve potansiyel bir zafiyeti gösterdi.

### Python ile Enstrümantasyonu Otomatikleştirme

Sömürü süreci, keyfi seri numaralarını programatik olarak enjekte etmek ve karşılık gelen DEP profillerini almak için LLDB API'si ile Python kullanılarak otomatikleştirildi.

### DEP ve MDM Zafiyetlerinin Potansiyel Etkileri

Araştırma, önemli güvenlik endişelerini vurgulamıştır:

1. **Bilgi Sızdırma**: DEP'e kayıtlı bir seri numarası sağlayarak, DEP profilinde bulunan hassas kurumsal bilgilere erişim sağlanabilir.

{{#include ../../../banners/hacktricks-training.md}}
