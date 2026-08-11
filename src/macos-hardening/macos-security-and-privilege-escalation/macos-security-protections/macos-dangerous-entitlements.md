# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlement'lar, işletim sisteminin imzalı koda verdiği yetenekleri ve güvenlik istisnalarını tanımlar. Aşağıdaki girdiler, offensive review sırasında özellikle faydalı olanlara odaklanır.<sup>[[13]](#references)</sup>

> [!WARNING]
> **`com.apple`** ile başlayan entitlement'ların üçüncü taraflar için mevcut olmadığını, yalnızca Apple'ın bunları verebileceğini unutmayın... Ancak bir enterprise certificate kullanıyorsanız aslında **`com.apple`** ile başlayan kendi entitlement'larınızı oluşturabilir ve buna dayanan korumaları bypass edebilirsiniz.

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement'ı bir process'in **SIP'i bypass etmesine** olanak tanır. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement'ı bir process'in **SIP'i bypass etmesine** olanak tanır. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Bu entitlement, bir process'in kernel dışındaki **herhangi bir** process için **task port** almasına olanak tanır. Daha fazla bilgi için [**buraya bakın**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Bu entitlement, **`com.apple.security.cs.debugger`** entitlement'ına sahip diğer process'lerin, bu entitlement'a sahip binary tarafından çalıştırılan process'in task port'unu almasına ve **ona code inject etmesine** olanak tanır. Daha fazla bilgi için [**buraya bakın**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement'a sahip uygulamalar, `Get Task Allow` entitlement'ı `true` olarak ayarlanmış unsigned ve third-party uygulamalar için geçerli bir task port almak üzere `task_for_pid()` çağırabilir. Ancak debugging tool entitlement'ı olsa bile bir debugger, **`Get Task Allow entitlement'ı olmayan** ve bu nedenle System Integrity Protection tarafından korunan process'lerin **task port'larını alamaz**. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Bu entitlement, bir uygulamanın **framework'leri, plug-in'leri veya library'leri**, Apple tarafından ya da ana executable ile aynı Team ID kullanılarak imzalanmış olmalarını gerektirmeden **load etmesine** olanak tanır; bu nedenle bir attacker arbitrary library load'u code inject etmek için abuse edebilir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Bu entitlement, **`com.apple.security.cs.disable-library-validation`** ile oldukça benzerdir; ancak library validation'ı **doğrudan disable etmek** yerine process'in runtime sırasında bunu disable etmek için bir **`csops` system call** çağırmasına olanak tanır.

Entitlement adı, onu kullanan `csops` operation'ının yanında XNU içinde hardcoded olarak bulunur:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV` için kernel handler (`bsd/kern/kern_proc.c`), primitive'in ne kadar sınırlı olduğunu tam olarak gösterir:<sup>[[2]](#references)</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
Dolayısıyla işlem:

- **Yalnızca macOS'ta** çalışır (diğer tüm platformlarda `ENOTSUP`).
- Yalnızca **kendisinde** çalışır (`forself == 1`) — bununla başka bir process'ten library validation özelliğini kaldıramazsınız.
- Process'in ilgili **entitlement'ı gerçekten taşımasını** gerektirir ve process `CS_INSTALLER` olarak işaretlenmişse veya bir subsystem root path altında çalışıyorsa işlemi reddeder.
- Process'in code-signing flag'lerinden **`CS_REQUIRE_LV | CS_FORCED_LV`** bitlerini temizler.

XNU yorumu, amaçlanan kullanım alanını ve bunun bir attacker için neden ilgi çekici olduğunu açıklar:

> Bu seçenek, çalışan bir process'ten library validation'ı kaldırmak için kullanılır. Bu, bir programın güvenilmeyen library'leri yüklemesi gereken plugin architecture'larında kullanılır. [...] Bir process güvenilmeyen library'yi yükledikten sonra, gelecekte library validation'a güvenmek etkili olmayacaktır.

Başka bir deyişle, **bu entitlement'ı taşıyan herhangi bir binary bir dylib-injection hedefidir**: `CS_REQUIRE_LV` özelliğini kaldırdıktan sonra bu binary içinde code çalıştırın (veya onu plug-in'inizi yüklemeye ikna edin); ardından host process'in yapmasına izin verilen her şeyi devralırsınız.

### `com.apple.security.cs.allow-dyld-environment-variables`

Bu entitlement, library ve code inject etmek için kullanılabilecek **DYLD environment variable'larını kullanmaya** izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` veya `com.apple.rootless.storage`.`TCC`

[**Bu bloga göre**](https://objective-see.org/blog/blog_0x4C.html) **ve** [**bu bloga göre**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), bu entitlement'lar bir process'in **TCC** database'ini **değiştirmesine** izin verir.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** ve **`system.install.apple-software.standar-user`**

Bu entitlement'lar bir process'in **kullanıcıdan izin istemeden software yüklemesine** izin verir; bu, **privilege escalation** için yararlı olabilir.

### `com.apple.private.security.kext-management`

Bir **kernel extension'ı yüklemesini kernel'den istemek** için gereken entitlement.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement'ı, **iCloud token'ları sağlayan** **`com.apple.iCloudHelper`** XPC service'iyle iletişim kurulmasını mümkün kılar.

**iMovie** ve **Garageband** bu entitlement'a sahipti.

Bu entitlement üzerinden **iCloud token'larını elde etmeye** yönelik exploit hakkında daha fazla **bilgi** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Bunun ne yapılmasına izin verdiğini bilmiyorum

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Bu rapor**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), bu entitlement'ın reboot sonrasında SSV-korumalı içeriklerin güncellenmesi için kullanılabileceğinden bahsediyor. Nasıl yapılacağını biliyorsanız lütfen bir PR gönderin!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Aynı rapor**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), sealed snapshot oluşturmanın reboot sonrasında SSV-korumalı içeriklerin güncellenmesi için kullanılabileceğinden bahsediyor. Nasıl yapılacağını biliyorsanız lütfen bir PR gönderin!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Bu entitlement, uygulamanın erişebildiği **keychain** gruplarını listeler:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Sahip olabileceğiniz en yüksek TCC izinlerinden biri olan **Tam Disk Erişimi** izinlerini verir.

### **`kTCCServiceAppleEvents`**

Uygulamanın, genellikle **görevleri otomatikleştirmek** için kullanılan diğer uygulamalara events göndermesine izin verir. Diğer uygulamaları kontrol ederek, bu uygulamalara verilmiş izinleri kötüye kullanabilir.

Örneğin, kullanıcıdan parolasını istemelerini sağlayabilir:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Veya **keyfi eylemler** gerçekleştirmelerini sağlamak.

### **`kTCCServiceEndpointSecurityClient`**

Diğer izinlerin yanı sıra, **kullanıcının TCC veritabanına yazılmasına** izin verir.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Kullanıcının **`NFSHomeDirectory`** özniteliğinin **değiştirilmesine** izin verir. Bu işlem, kullanıcının home folder path'ini değiştirir ve dolayısıyla **TCC'nin bypass edilmesini** sağlar.

### **`kTCCServiceSystemPolicyAppBundles`**

App bundle içindeki (app.app içinde) dosyaların değiştirilmesine izin verir; bu işlem varsayılan olarak **yasaktır**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Bu erişime kimlerin sahip olduğunu _System Settings_ > _Privacy & Security_ > _App Management_ bölümünden kontrol etmek mümkündür.

### `kTCCServiceAccessibility`

Process, **macOS accessibility özelliklerini abuse edebilir**. Bu, örneğin keystroke'lara basabileceği anlamına gelir. Böylece Finder gibi bir app'i kontrol etmek için erişim isteğinde bulunabilir ve bu izinle iletişim kutusunu onaylayabilir.

## Trustcache/CDhash ile ilgili entitlements

Downgrade edilmiş Apple binary'lerinin çalıştırılmasını engelleyen Trustcache/CDhash korumalarını bypass etmek için kullanılabilecek bazı entitlements vardır.

## Orta

### `com.apple.security.cs.allow-jit`

Bu entitlement, `mmap()` system function'ına `MAP_JIT` flag'ini geçirerek bir process'in **writable ve executable memory oluşturmasına** izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Bu entitlement, **C code'u override etmeye veya patch'lemeye**, uzun süredir kullanımdan kaldırılmış olan (temelde insecure) **`NSCreateObjectFileImageFromMemory`** işlevini kullanmaya veya **DVDPlayback** framework'ünü kullanmaya izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Bu entitlement'ın eklenmesi, app'inizi memory-unsafe code language'larındaki yaygın vulnerabilities'lara maruz bırakır. App'inizin bu exception'a gerçekten ihtiyaç duyup duymadığını dikkatlice değerlendirin.

### `com.apple.security.cs.disable-executable-page-protection`

Bu entitlement, zorla çıkış yapmasını sağlamak için kendi executable file'larının disk üzerindeki **section'larını değiştirmesine** izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement, app'inizden temel bir security protection'ı kaldıran ve bir attacker'ın app'inizin executable code'unu tespit edilmeden yeniden yazabilmesini mümkün kılan aşırı kapsamlı bir entitlement'tır. Mümkünse daha dar kapsamlı entitlements'ları tercih edin.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Bu entitlement, bir nullfs file system'inin mount edilmesine izin verir (varsayılan olarak yasaktır). Araç: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Bu blog yazısına göre, bu TCC izni genellikle şu biçimde bulunur:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
İşlemin **tüm TCC izinlerini istemesine** izin verir.

### **`kTCCServicePostEvent`**

`CGEventPost()` aracılığıyla sistem genelinde **sentetik klavye ve fare olaylarının enjekte edilmesine** izin verir. Bu izne sahip bir işlem, herhangi bir uygulamada tuş vuruşlarını, fare tıklamalarını ve kaydırma olaylarını simüle edebilir; bu da masaüstünün etkili bir şekilde **uzaktan kontrol edilmesini** sağlar.

Bu, `kTCCServiceAccessibility` veya `kTCCServiceListenEvent` ile birleştirildiğinde özellikle tehlikelidir; çünkü hem girdilerin okunmasına hem de enjekte edilmesine olanak tanır.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Sistem genelindeki **tüm klavye ve mouse olaylarının intercept edilmesine** (input monitoring / keylogging) olanak tanır. Bir process, herhangi bir uygulamada yazılan her tuş vuruşunu yakalamak için bir `CGEventTap` kaydedebilir; buna parolalar, kredi kartı numaraları ve özel mesajlar da dahildir.

Ayrıntılı exploitation teknikleri için bkz.:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**Display buffer'ın okunmasına** — güvenli metin alanları da dahil olmak üzere herhangi bir uygulamanın ekran görüntülerinin alınmasına ve ekran videosunun kaydedilmesine — olanak tanır. OCR ile birleştirildiğinde bu, parolaları ve hassas verileri ekrandan otomatik olarak çıkarabilir.

> [!WARNING]
> macOS Sonoma ile birlikte screen capture, menü çubuğunda kalıcı bir gösterge gösterir. Daha eski sürümlerde screen recording tamamen sessiz şekilde gerçekleştirilebilir.

### **`kTCCServiceCamera`**

Dahili kameradan veya bağlı USB kameralardan **fotoğraf ve video yakalanmasına** olanak tanır. Camera entitlement'ına sahip bir binary'ye code injection uygulanması, sessiz görsel gözetimi mümkün kılar.

### **`kTCCServiceMicrophone`**

Tüm input cihazlarından **ses kaydedilmesine** olanak tanır. Microphone erişimine sahip background daemon'lar, görünür bir uygulama penceresi olmadan kalıcı ortam sesi gözetimi sağlar.

### **`kTCCServiceLocation`**

Wi-Fi triangulation veya Bluetooth beacon'ları aracılığıyla cihazın **fiziksel konumunun sorgulanmasına** olanak tanır. Sürekli izleme; ev/iş adreslerini, seyahat düzenlerini ve günlük rutinleri ortaya çıkarır.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**'a (isimler, e-postalar, telefonlar — spear-phishing için kullanışlı), **Calendar**'a (toplantı programları, katılımcı listeleri) ve **Photos**'a (kişisel fotoğraflar, kimlik bilgileri içerebilecek ekran görüntüleri, konum metadata'sı) erişim sağlar.

TCC izinleri üzerinden gerçekleştirilen complete credential theft exploitation teknikleri için bkz.:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**, normalde sandbox tarafından engellenen sistem genelindeki Mach/XPC servisleriyle iletişime izin vererek App Sandbox'ı zayıflatır. Bu, **primary sandbox escape primitive**'idir — ele geçirilmiş bir sandboxed app, privileged daemon'lara ulaşmak ve bunların XPC interface'lerini exploit etmek için mach-lookup exceptions kullanabilir.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Ayrıntılı exploitation chain için: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, bkz.:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements**, user-space driver binary'lerinin IOKit arayüzleri üzerinden kernel ile doğrudan iletişim kurmasına izin verir. DriverKit binary'leri donanımı yönetir: USB, Thunderbolt, PCIe, HID cihazları, ses ve networking.

Bir DriverKit binary'sini compromise etmek şunları mümkün kılar:
- Hatalı biçimlendirilmiş `IOConnectCallMethod` çağrıları üzerinden **kernel attack surface**
- **USB device spoofing** (HID injection için klavyeyi taklit etme)
- PCIe/Thunderbolt arayüzleri üzerinden **DMA attacks**
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Ayrıntılı IOKit/DriverKit exploitation için bkz.:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` işlemleri ve `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` işleyicisi)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: TCC'yi Bypass Etme](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Müziği çal ve TCC'yi Bypass Et, diğer adıyla CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "Mac'inizde Olan Apple'ın iCloud'unda mı Kalır?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple'ın OTA Update'inin Kâbusu: Signature Verification'ı Bypass Etme ve Kernel'i Ele Geçirme](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — JIT-compiled Code Çalıştırmaya İzin Verme Entitlement'ı (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Unsigned Executable Memory'ye İzin Verme Entitlement'ı](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Executable Memory Protection'ı Devre Dışı Bırakma Entitlement'ı](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
