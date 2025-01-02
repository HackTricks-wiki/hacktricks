# macOS Güvenliği ve Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Temel MacOS

Eğer macOS ile tanışık değilseniz, macOS'un temellerini öğrenmeye başlamalısınız:

- Özel macOS **dosyaları ve izinleri:**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Yaygın macOS **kullanıcıları**

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- **kernel**'in **mimari**si

{{#ref}}
mac-os-architecture/
{{#endref}}

- Yaygın macOS **ağ hizmetleri ve protokolleri**

{{#ref}}
macos-protocols.md
{{#endref}}

- **Açık kaynak** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Bir `tar.gz` indirmek için, [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) gibi bir URL'yi [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) olarak değiştirin.

### MacOS MDM

Şirketlerde **macOS** sistemlerinin büyük olasılıkla **bir MDM ile yönetileceği** düşünülmektedir. Bu nedenle, bir saldırgan açısından **bu durumun nasıl çalıştığını** bilmek ilginçtir:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - İnceleme, Hata Ayıklama ve Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Güvenlik Koruma Önlemleri

{{#ref}}
macos-security-protections/
{{#endref}}

## Saldırı Yüzeyi

### Dosya İzinleri

Eğer bir **root olarak çalışan bir işlem** bir dosya yazıyorsa ve bu dosya bir kullanıcı tarafından kontrol edilebiliyorsa, kullanıcı bunu **yetkileri yükseltmek için** kötüye kullanabilir.\
Bu aşağıdaki durumlarda gerçekleşebilir:

- Kullanılan dosya zaten bir kullanıcı tarafından oluşturulmuş (kullanıcıya ait)
- Kullanılan dosya, bir grup nedeniyle kullanıcı tarafından yazılabilir
- Kullanılan dosya, kullanıcıya ait bir dizin içinde (kullanıcı dosyayı oluşturabilir)
- Kullanılan dosya, root'a ait bir dizin içinde ancak kullanıcı bir grup nedeniyle üzerinde yazma erişimine sahip (kullanıcı dosyayı oluşturabilir)

**root** tarafından **kullanılacak bir dosya** oluşturabilmek, bir kullanıcının **içeriğinden faydalanmasına** veya hatta başka bir yere işaret etmek için **sembolik/sert bağlantılar** oluşturmasına olanak tanır.

Bu tür güvenlik açıkları için **savunmasız `.pkg` yükleyicilerini kontrol etmeyi** unutmayın:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Dosya Uzantısı ve URL şeması uygulama işleyicileri

Dosya uzantılarıyla kaydedilen garip uygulamalar kötüye kullanılabilir ve farklı uygulamalar belirli protokolleri açmak için kaydedilebilir.

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Yetki Yükseltme

macOS'ta **uygulamalar ve ikili dosyalar**, diğerlerinden daha ayrıcalıklı olmalarını sağlayan klasörlere veya ayarlara erişim iznine sahip olabilir.

Bu nedenle, bir macOS makinesini başarılı bir şekilde ele geçirmek isteyen bir saldırgan, **TCC ayrıcalıklarını yükseltmek** (veya ihtiyaçlarına bağlı olarak **SIP'yi atlamak**) zorundadır.

Bu ayrıcalıklar genellikle uygulamanın imzalandığı **haklar** şeklinde verilir veya uygulama bazı erişimler talep edebilir ve **kullanıcı onayladıktan** sonra **TCC veritabanlarında** bulunabilir. Bir işlemin bu ayrıcalıkları elde etmenin bir diğer yolu, bu **ayrıcalıklara** sahip bir işlemin **çocuğu** olmaktır, çünkü genellikle **devralınır**.

Farklı yollar bulmak için bu bağlantılara göz atın [**TCC'de yetki yükseltme**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**TCC'yi atlamak**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) ve geçmişte [**SIP'nin nasıl atlandığı**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Geleneksel Yetki Yükseltme

Elbette, bir kırmızı takım perspektifinden root'a yükselmekle de ilgilenmelisiniz. Bazı ipuçları için aşağıdaki gönderiyi kontrol edin:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Uyum

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Referanslar

- [**OS X Olay Yanıtı: Betik ve Analiz**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
