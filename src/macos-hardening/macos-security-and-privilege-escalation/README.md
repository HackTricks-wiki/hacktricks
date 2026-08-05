# macOS Güvenliği ve Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Temel MacOS

macOS hakkında bilgi sahibi değilseniz macOS'un temellerini öğrenerek başlamalısınız:

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

- k**ernel** mimarisi


{{#ref}}
mac-os-architecture/
{{#endref}}

- Yaygın macOS **network servisleri ve protokolleri**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Bir `tar.gz` indirmek için [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) gibi bir URL'yi [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) şeklinde değiştirin.

### MacOS MDM

Şirketlerde **macOS** sistemlerinin bir **MDM ile yönetilmesi** oldukça muhtemeldir. Bu nedenle, saldırganın bakış açısından **bunun nasıl çalıştığını** bilmek ilgi çekicidir:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - İnceleme, Debugging ve Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Güvenlik Korumaları


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### Dosya İzinleri

**root olarak çalışan bir process**, bir kullanıcı tarafından kontrol edilebilen bir dosyaya **yazarsa**, kullanıcı bunu **privilege escalation** için kötüye kullanabilir.\
Bu, aşağıdaki durumlarda gerçekleşebilir:

- Kullanılan dosya daha önce bir kullanıcı tarafından oluşturulmuştur (dosyanın sahibi kullanıcıdır)
- Kullanılan dosya bir grup nedeniyle kullanıcı tarafından yazılabilirdir
- Kullanılan dosya kullanıcının sahip olduğu bir dizinin içindedir (kullanıcı dosyayı oluşturabilir)
- Kullanılan dosya root'un sahip olduğu bir dizinin içindedir ancak kullanıcı bir grup nedeniyle bu dizine yazma erişimine sahiptir (kullanıcı dosyayı oluşturabilir)

**root tarafından kullanılacak bir dosya oluşturabilmek**, kullanıcının **içeriğinden yararlanmasına** veya dosyayı başka bir konuma gösterecek **symlink/hardlink**'ler oluşturmasına olanak tanır.

Bu tür zafiyetler için **zafiyetli `.pkg` installer'larını** kontrol etmeyi unutmayın:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Dosya Uzantısı ve URL scheme app handler'ları

Dosya uzantıları tarafından kaydedilmiş şüpheli uygulamalar kötüye kullanılabilir ve farklı uygulamalar belirli protokolleri açmak üzere kaydedilebilir.


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

macOS'ta **uygulamalar ve binary'ler, klasörlere veya ayarlara erişim izinlerine sahip olabilir**; bu da onları diğerlerinden daha ayrıcalıklı hale getirir.

Bu nedenle, bir macOS makinesini başarıyla ele geçirmek isteyen bir saldırganın **TCC ayrıcalıklarını yükseltmesi** (veya ihtiyaçlarına bağlı olarak **SIP'i bypass etmesi**) gerekir.

Bu ayrıcalıklar genellikle uygulamanın imzalandığı **entitlement**'lar aracılığıyla verilir veya uygulama bazı erişimler talep edebilir; **kullanıcı bunları onayladıktan** sonra bu erişimler **TCC database**'lerinde bulunabilir. Bir process'in bu ayrıcalıkları elde etmesinin başka bir yolu da bu **ayrıcalıklara** sahip bir process'in **child process'i** olmasıdır; çünkü bu ayrıcalıklar genellikle **inherit** edilir.

Farklı yöntemlerle [**TCC'de privilege escalation**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses) yapmayı, [**TCC'yi bypass etmeyi**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) ve geçmişte [**SIP'in nasıl bypass edildiğini**](macos-security-protections/macos-sip.md#sip-bypasses) öğrenmek için bu bağlantıları takip edin.

## macOS Geleneksel Privilege Escalation

Elbette bir red team perspektifinden root'a yükselmeyle de ilgilenmelisiniz. Bazı ipuçları için aşağıdaki gönderiye göz atın:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Referanslar

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
