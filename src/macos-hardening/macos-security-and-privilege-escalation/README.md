# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic MacOS

macOS'a aşina değilseniz macOS'un temellerini öğrenerek başlamalısınız:

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

- **kernel**'ın **mimarisi**


{{#ref}}
mac-os-architecture/
{{#endref}}

- Yaygın macOS **ağ hizmetleri ve protokolleri**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Bir `tar.gz` indirmek için [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) gibi bir URL'yi [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) şeklinde değiştirin.

### MacOS MDM

Şirketlerde **macOS** sistemleri büyük olasılıkla bir MDM ile **yönetilecektir**. Bu nedenle, saldırgan açısından **bunun nasıl çalıştığını** bilmek ilgi çekicidir:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - İnceleme, Debugging ve Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Security Protections


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

**root olarak çalışan bir process**, bir kullanıcının kontrol edebildiği bir dosyaya **yazarsa**, kullanıcı bunu **privilege escalation** için kötüye kullanabilir.\
Bu, aşağıdaki durumlarda gerçekleşebilir:

- Kullanılan dosya daha önce bir kullanıcı tarafından oluşturulmuştur (dosyanın sahibi kullanıcıdır)
- Kullanılan dosya, bir grup nedeniyle kullanıcı tarafından yazılabilirdir
- Kullanılan dosya, kullanıcıya ait bir dizinin içindedir (kullanıcı dosyayı oluşturabilir)
- Kullanılan dosya root'a ait bir dizinin içindedir, ancak kullanıcı bir grup nedeniyle üzerinde yazma erişimine sahiptir (kullanıcı dosyayı oluşturabilir)

**root tarafından kullanılacak** bir **dosya oluşturabilmek**, kullanıcının dosyanın **içeriğinden yararlanmasına** veya dosyayı başka bir konuma yönlendirmek için **symlink/hardlink** oluşturmasına olanak tanır.

Bu tür zafiyetler için **zafiyetli `.pkg` installer'larını** kontrol etmeyi unutmayın:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

Dosya uzantıları tarafından kaydedilen garip uygulamalar kötüye kullanılabilir ve belirli protokolleri açmak için farklı uygulamalar kaydedilebilir.


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

macOS'ta **uygulamalar ve binary'ler**, kendilerini diğerlerinden daha ayrıcalıklı hâle getiren klasörlere veya ayarlara erişim izinlerine sahip olabilir.

Bu nedenle, bir macOS makinesini başarıyla compromise etmek isteyen bir saldırganın **TCC ayrıcalıklarını yükseltmesi** (veya ihtiyaçlarına bağlı olarak **SIP'i bypass etmesi**) gerekir.

Bu ayrıcalıklar genellikle uygulamanın imzalandığı **entitlement'lar** biçiminde verilir veya uygulama bazı erişimler talep etmiş olabilir; **kullanıcı bunları onayladıktan** sonra bu izinler **TCC veritabanlarında** bulunabilir. Bir process'in bu ayrıcalıkları elde etmesinin başka bir yolu da bu **ayrıcalıklara** sahip bir process'in **child process'i** olmasıdır; çünkü bu ayrıcalıklar genellikle **miras alınır**.<sup>[[5]](#references)</sup>

Farklı **TCC'de privilege escalation** yöntemlerini, [**TCC'yi bypass etme**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) yöntemlerini ve geçmişte [**SIP'in nasıl bypass edildiğini**](macos-security-protections/macos-sip.md#sip-bypasses) öğrenmek için bu bağlantıları takip edin.

## macOS Traditional Privilege Escalation

Elbette bir red team perspektifinden root'a yükselmekle de ilgilenmelisiniz. Bazı ipuçları için aşağıdaki gönderiyi inceleyin:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
