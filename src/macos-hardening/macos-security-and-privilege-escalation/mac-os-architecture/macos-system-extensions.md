# macOS Sistem Uzantıları

{{#include ../../../banners/hacktricks-training.md}}

## Sistem Uzantıları / Uç Nokta Güvenliği Çerçevesi

Kernel Uzantılarının aksine, **Sistem Uzantıları kullanıcı alanında çalışır** ve bu da uzantı arızası nedeniyle sistem çökmesi riskini azaltır.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Üç tür sistem uzantısı vardır: **DriverKit** Uzantıları, **Ağ** Uzantıları ve **Uç Nokta Güvenliği** Uzantıları.

### **DriverKit Uzantıları**

DriverKit, **donanım desteği sağlayan** kernel uzantılarının yerini alır. Cihaz sürücülerinin (USB, Seri, NIC ve HID sürücüleri gibi) kernel alanında değil, kullanıcı alanında çalışmasına olanak tanır. DriverKit çerçevesi, **belirli I/O Kit sınıflarının kullanıcı alanı sürümlerini** içerir ve kernel, normal I/O Kit olaylarını kullanıcı alanına ileterek bu sürücülerin çalışması için daha güvenli bir ortam sunar.

### **Ağ Uzantıları**

Ağ Uzantıları, ağ davranışlarını özelleştirme yeteneği sağlar. Birkaç tür Ağ Uzantısı vardır:

- **Uygulama Proxy**: Akış odaklı, özel bir VPN protokolü uygulayan bir VPN istemcisi oluşturmak için kullanılır. Bu, ağ trafiğini bağlantılara (veya akışlara) göre yönetmesi anlamına gelir.
- **Paket Tüneli**: Bireysel paketlere dayalı, özel bir VPN protokolü uygulayan bir VPN istemcisi oluşturmak için kullanılır. Bu, ağ trafiğini bireysel paketlere göre yönetmesi anlamına gelir.
- **Veri Filtreleme**: Ağ "akışlarını" filtrelemek için kullanılır. Akış düzeyinde ağ verilerini izleyebilir veya değiştirebilir.
- **Paket Filtreleme**: Bireysel ağ paketlerini filtrelemek için kullanılır. Paket düzeyinde ağ verilerini izleyebilir veya değiştirebilir.
- **DNS Proxy**: Özel bir DNS sağlayıcısı oluşturmak için kullanılır. DNS isteklerini ve yanıtlarını izlemek veya değiştirmek için kullanılabilir.

## Uç Nokta Güvenliği Çerçevesi

Uç Nokta Güvenliği, Apple tarafından macOS'ta sağlanan bir çerçevedir ve sistem güvenliği için bir dizi API sunar. **Güvenlik satıcıları ve geliştiricilerin kötü niyetli etkinlikleri tanımlamak ve korumak için sistem etkinliğini izleyip kontrol edebilecekleri ürünler geliştirmeleri amacıyla kullanılması amaçlanmıştır.**

Bu çerçeve, **sistem etkinliğini izlemek ve kontrol etmek için bir dizi API** sağlar; bu, işlem yürütmeleri, dosya sistemi olayları, ağ ve kernel olayları gibi etkinlikleri içerir.

Bu çerçevenin temeli, **`/System/Library/Extensions/EndpointSecurity.kext`** konumunda bulunan bir Kernel Uzantısı (KEXT) olarak kernel'de uygulanmıştır. Bu KEXT, birkaç ana bileşenden oluşur:

- **EndpointSecurityDriver**: Bu, kernel uzantısı için "giriş noktası" olarak işlev görür. OS ile Uç Nokta Güvenliği çerçevesi arasındaki ana etkileşim noktasıdır.
- **EndpointSecurityEventManager**: Bu bileşen, kernel kancalarını uygulamaktan sorumludur. Kernel kancaları, çerçevenin sistem çağrılarını keserek sistem olaylarını izlemesine olanak tanır.
- **EndpointSecurityClientManager**: Bu, kullanıcı alanı istemcileriyle iletişimi yönetir, hangi istemcilerin bağlı olduğunu ve olay bildirimlerini alması gerektiğini takip eder.
- **EndpointSecurityMessageManager**: Bu, kullanıcı alanı istemcilerine mesajlar ve olay bildirimleri gönderir.

Uç Nokta Güvenliği çerçevesinin izleyebileceği olaylar şunlara ayrılır:

- Dosya olayları
- İşlem olayları
- Soket olayları
- Kernel olayları (örneğin, bir kernel uzantısının yüklenmesi/boşaltılması veya bir I/O Kit cihazının açılması)

### Uç Nokta Güvenliği Çerçevesi Mimarisi

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Kullanıcı alanı iletişimi**, Uç Nokta Güvenliği çerçevesi ile IOUserClient sınıfı aracılığıyla gerçekleşir. İki farklı alt sınıf, çağıran türüne bağlı olarak kullanılır:

- **EndpointSecurityDriverClient**: Bu, yalnızca sistem süreci `endpointsecurityd` tarafından tutulan `com.apple.private.endpoint-security.manager` yetkisini gerektirir.
- **EndpointSecurityExternalClient**: Bu, `com.apple.developer.endpoint-security.client` yetkisini gerektirir. Bu genellikle Uç Nokta Güvenliği çerçevesiyle etkileşimde bulunması gereken üçüncü taraf güvenlik yazılımları tarafından kullanılır.

Uç Nokta Güvenliği Uzantıları:**`libEndpointSecurity.dylib`** sistem uzantılarının kernel ile iletişim kurmak için kullandığı C kütüphanesidir. Bu kütüphane, Uç Nokta Güvenliği KEXT ile iletişim kurmak için I/O Kit (`IOKit`) kullanır.

**`endpointsecurityd`** uç nokta güvenliği sistem uzantılarını yönetmek ve başlatmakla ilgili önemli bir sistem daemon'udur, özellikle erken önyükleme sürecinde. **Sadece sistem uzantıları**, `Info.plist` dosyalarında **`NSEndpointSecurityEarlyBoot`** ile işaretlenmiş olanlar bu erken önyükleme muamelesini alır.

Başka bir sistem daemon'u, **`sysextd`**, **sistem uzantılarını doğrular** ve bunları uygun sistem konumlarına taşır. Ardından ilgili daemon'dan uzantıyı yüklemesini ister. **`SystemExtensions.framework`** sistem uzantılarını etkinleştirmek ve devre dışı bırakmakla sorumludur.

## ESF'yi Aşmak

ESF, bir kırmızı takım üyesini tespit etmeye çalışan güvenlik araçları tarafından kullanılır, bu nedenle bunun nasıl önlenebileceğine dair herhangi bir bilgi ilginçtir.

### CVE-2021-30965

Sorun, güvenlik uygulamasının **Tam Disk Erişimi izinlerine** sahip olması gerektiğidir. Yani, bir saldırgan bunu kaldırabilirse, yazılımın çalışmasını engelleyebilir:
```bash
tccutil reset All
```
Daha fazla bilgi için bu bypass ve ilgili olanlar hakkında [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI) konuşmasına bakın.

Sonunda, bu, **`tccd`** tarafından yönetilen güvenlik uygulamasına yeni izin **`kTCCServiceEndpointSecurityClient`** verilerek düzeltildi, böylece `tccutil` izinlerini temizlemeyecek ve çalışmasını engellemeyecek.

## Referanslar

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
