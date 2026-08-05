# macOS Dangerous Entitlements ve TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> **`com.apple`** ile başlayan entitlements üçüncü taraflar için kullanılamaz; bunları yalnızca Apple verebilir... Ya da bir enterprise certificate kullanıyorsanız, aslında **`com.apple`** ile başlayan kendi entitlements'larınızı oluşturabilir ve buna dayalı protections'ı bypass edebilirsiniz.

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement'ı **SIP'yi bypass etmeye** olanak tanır. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement'ı **SIP'yi bypass etmeye** olanak tanır. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (önceden `task_for_pid-allow` olarak adlandırılıyordu)**

Bu entitlement, kernel dışındaki **herhangi bir** process için **task port'u almaya** olanak tanır. Daha fazla bilgi için [**buraya bakın**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Bu entitlement, **`com.apple.security.cs.debugger`** entitlement'ına sahip diğer process'lerin, bu entitlement'a sahip binary tarafından çalıştırılan process'in task port'unu almasına ve **ona code inject etmesine** olanak tanır. Daha fazla bilgi için [**buraya bakın**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement'a sahip Apps, `Get Task Allow` entitlement'ı `true` olarak ayarlanmış unsigned ve third-party Apps için geçerli bir task port almak üzere `task_for_pid()` çağrısı yapabilir. Ancak debugging tool entitlement'ına sahip olsa bile bir debugger, **`Get Task Allow entitlement'ına sahip olmayan** ve bu nedenle System Integrity Protection tarafından korunan process'lerin **task port'larını alamaz**. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Bu entitlement, ana executable ile **Apple tarafından imzalanmış veya aynı Team ID ile imzalanmış olması gerekmeksizin frameworks, plug-ins veya libraries yüklemeye** olanak tanır; bu nedenle bir attacker, code inject etmek için herhangi bir library load işlemini abuse edebilir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Bu entitlement, **`com.apple.security.cs.disable-library-validation`** ile oldukça benzerdir; ancak library validation'ı **doğrudan devre dışı bırakmak** yerine process'in runtime sırasında bunu devre dışı bırakmak için bir `csops` system call çağırmasına olanak tanır.

Entitlement adı, onu kullanan `csops` operation'ının yanında XNU içinde hardcoded olarak bulunur:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV` için kernel handler (`bsd/kern/kern_proc.c`), primitive'in ne kadar dar kapsamlı olduğunu tam olarak gösterir:<sup>[3]</sup>
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
Yani işlem:

- **Yalnızca macOS'ta** çalışır (diğer tüm platformlarda `ENOTSUP`).
- Yalnızca **kendisinde** çalışır (`forself == 1`) — bununla başka bir process'ten library validation'ı kaldıramazsınız.
- Process'in gerçekten **entitlement'a sahip olmasını** gerektirir ve process `CS_INSTALLER` olarak işaretlenmişse veya bir subsystem root path altında çalışıyorsa işlemi reddeder.
- Process'in code-signing flag'lerinden **`CS_REQUIRE_LV | CS_FORCED_LV`** değerlerini temizler.

XNU yorumu, amaçlanan kullanım senaryosunu ve bunun bir attacker için neden ilgi çekici olduğunu açıklar:

> Bu seçenek, çalışan bir process'ten library validation'ı kaldırmak için kullanılır. Bu, bir programın güvenilmeyen library'leri yüklemesi gereken plugin architecture'larında kullanılır. [...] Bir process güvenilmeyen library'yi yükledikten sonra, gelecekte library validation'a güvenmek etkili olmayacaktır.

Başka bir deyişle, **bu entitlement'ı taşıyan herhangi bir binary bir dylib-injection target'ıdır**: `CS_REQUIRE_LV` değerini kaldırdıktan sonra onun içinde code çalıştırın (veya onu plug-in'inizi yüklemeye ikna edin); ardından host process'in yapmasına izin verilen her şeyi yapabilirsiniz.

### `com.apple.security.cs.allow-dyld-environment-variables`

Bu entitlement, library'leri ve code'u inject etmek için kullanılabilecek **DYLD environment variables'ı kullanmaya** izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` veya `com.apple.rootless.storage`.`TCC`

[**Bu bloga göre**](https://objective-see.org/blog/blog_0x4C.html) **ve** [**bu bloga göre**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), bu entitlement'lar **TCC** database'ini **modify etmeye** izin verir.

### **`system.install.apple-software`** ve **`system.install.apple-software.standar-user`**

Bu entitlement'lar, kullanıcıdan **izin istemeden software install etmeye** izin verir; bu da bir **privilege escalation** için yararlı olabilir.

### `com.apple.private.security.kext-management`

**Kernel'den bir kernel extension load etmesini istemek** için gereken entitlement.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement'ı ile **iCloud token'ları sağlayacak** olan **`com.apple.iCloudHelper`** XPC service'i ile iletişim kurulabilir.

**iMovie** ve **Garageband** bu entitlement'a sahipti.

Bu entitlement'ı kullanarak **iCloud token'ları elde etmeye** yönelik exploit hakkında daha fazla **bilgi** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Bunun ne yapmaya izin verdiğini bilmiyorum

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), bunun reboot sonrasında SSV-protected içerikleri update etmek için kullanılabileceğinden **bahsediliyor**. Nasıl çalıştığını biliyorsanız lütfen bir PR gönderin!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), bunun reboot sonrasında SSV-protected içerikleri update etmek için kullanılabileceğinden **bahsediliyor**. Nasıl çalıştığını biliyorsanız lütfen bir PR gönderin!

### `keychain-access-groups`

Bu entitlement listesi, application'ın erişebildiği **keychain** gruplarını gösterir:
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

Sahip olabileceğiniz en yüksek TCC izinlerinden biri olan **Full Disk Access** izinlerini verir.

### **`kTCCServiceAppleEvents`**

Uygulamanın, genellikle **automating tasks** için kullanılan diğer uygulamalara event göndermesine izin verir. Diğer uygulamaları kontrol ederek, bu uygulamalara verilmiş izinleri kötüye kullanabilir.

Örneğin, kullanıcıdan parolasını istemelerini sağlayarak:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Veya onların **keyfi eylemler gerçekleştirmesini** sağlamak.

### **`kTCCServiceEndpointSecurityClient`**

Diğer izinlerin yanı sıra, **kullanıcının TCC veritabanına yazmaya** izin verir.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Bir kullanıcının **`NFSHomeDirectory`** özniteliğini **değiştirmeye** izin verir. Bu, kullanıcının home folder path'ini değiştirir ve dolayısıyla **TCC'yi bypass etmeye** izin verir.

### **`kTCCServiceSystemPolicyAppBundles`**

App bundle'ları içindeki (app.app içinde) dosyaları değiştirmeye izin verir; bu işlem varsayılan olarak **yasaktır**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Bu erişime kimlerin sahip olduğunu _Sistem Ayarları_ > _Gizlilik ve Güvenlik_ > _App Management_ bölümünden kontrol etmek mümkündür.

### `kTCCServiceAccessibility`

Process, **macOS accessibility özelliklerini abuse edebilir**. Bu, örneğin keystroke'lara basabileceği anlamına gelir. Böylece Finder gibi bir app'i kontrol etmek için erişim isteyebilir ve bu izinle dialog'u onaylayabilir.

## Trustcache/CDhash ile ilgili entitlements

Apple binary'lerinin downgrade edilmiş versiyonlarının çalıştırılmasını engelleyen Trustcache/CDhash protections'ı bypass etmek için kullanılabilecek bazı entitlements vardır.

## Orta

### `com.apple.security.cs.allow-jit`

Bu entitlement, `mmap()` system function'ına `MAP_JIT` flag'ini geçirerek **writable ve executable memory oluşturulmasına** izin verir. Daha fazla bilgi için [**buna bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Bu entitlement, **C code'u override veya patch etmeye**, uzun süredir deprecated olan **`NSCreateObjectFileImageFromMemory`**'yi (temelde insecure'dur) kullanmaya veya **DVDPlayback** framework'ünü kullanmaya izin verir. Daha fazla bilgi için [**buna bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Bu entitlement'ın dahil edilmesi, app'inizi memory-unsafe code dillerindeki yaygın vulnerabilities'lara maruz bırakır. App'inizin bu exception'a ihtiyaç duyup duymadığını dikkatlice değerlendirin.

### `com.apple.security.cs.disable-executable-page-protection`

Bu entitlement, forcefully exit etmek için kendi executable file'larının disk üzerindeki **section'larını değiştirmeye** izin verir. Daha fazla bilgi için [**buna bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Disable Executable Memory Protection Entitlement, app'inizden temel bir security protection'ı kaldıran ve bir attacker's app'inizin executable code'unu detection olmadan yeniden yazabilmesini mümkün kılan extreme bir entitlement'tır. Mümkünse daha dar kapsamlı entitlements'ları tercih edin.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Bu entitlement, bir nullfs file system'ı mount etmeye izin verir (varsayılan olarak yasaktır). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Bu blogpost'a göre, bu TCC permission genellikle şu biçimde bulunur:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Process'in **tüm TCC izinlerini istemesine** izin verir.

### **`kTCCServicePostEvent`**

`CGEventPost()` aracılığıyla sistem genelinde **sentetik klavye ve fare olaylarının enjekte edilmesine** izin verir. Bu izne sahip bir process, herhangi bir uygulamada klavye tuş vuruşlarını, fare tıklamalarını ve kaydırma olaylarını simüle edebilir; bu da masaüstü üzerinde etkin bir şekilde **uzaktan kontrol** sağlar.

Bu, hem girdinin okunmasına hem de enjekte edilmesine izin verdiğinden, `kTCCServiceAccessibility` veya `kTCCServiceListenEvent` ile birlikte kullanıldığında özellikle tehlikelidir.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Sistem genelindeki **tüm klavye ve fare olaylarının interception edilmesine** (input monitoring / keylogging) olanak tanır. Bir process, herhangi bir application'da yazılan her tuş vuruşunu yakalamak için bir `CGEventTap` kaydedebilir; buna parolalar, kredi kartı numaraları ve özel mesajlar da dahildir.

Ayrıntılı exploitation teknikleri için bkz.:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**Ekran buffer'ının okunmasına** olanak tanır — güvenli metin alanları da dahil olmak üzere herhangi bir application'ın ekran görüntülerinin alınmasını ve ekran videosunun kaydedilmesini sağlar. OCR ile birleştirildiğinde, parolalar ve hassas veriler ekrandan otomatik olarak çıkarılabilir.

> [!WARNING]
> macOS Sonoma'dan itibaren screen capture, menü çubuğunda kalıcı bir gösterge gösterir. Daha eski sürümlerde screen recording tamamen sessiz gerçekleştirilebilir.

### **`kTCCServiceCamera`**

Yerleşik kameradan veya bağlı USB kameralardan **fotoğraf ve video yakalanmasına** olanak tanır. Camera entitlement'ına sahip bir binary'ye code injection uygulanması, sessiz görsel gözetimi mümkün kılar.

### **`kTCCServiceMicrophone`**

Tüm input cihazlarından **ses kaydedilmesine** olanak tanır. Microphone erişimine sahip background daemon'lar, görünür bir application penceresi olmadan kalıcı ortam sesi gözetimi sağlar.

### **`kTCCServiceLocation`**

Wi-Fi triangulation veya Bluetooth beacon'ları üzerinden cihazın **fiziksel konumunun** sorgulanmasına olanak tanır. Sürekli monitoring; ev/iş adreslerini, seyahat modellerini ve günlük rutinleri ortaya çıkarır.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**'a (isimler, e-postalar, telefonlar — spear-phishing için kullanışlı), **Calendar**'a (toplantı programları, katılımcı listeleri) ve **Photos**'a (kimlik bilgileri içerebilecek kişisel fotoğraflar ve ekran görüntüleri, konum metadata'sı) erişim sağlar.

TCC izinleri üzerinden gerçekleştirilen eksiksiz credential theft exploitation teknikleri için bkz.:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox ve Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exception'ları**, normalde sandbox'ın engellediği system-wide Mach/XPC service'leriyle iletişime izin vererek App Sandbox'ı zayıflatır. Bu, **primary sandbox escape primitive'idir** — ele geçirilmiş bir sandboxed app, privileged daemon'lara ulaşmak ve bunların XPC interface'lerini exploit etmek için mach-lookup exception'larını kullanabilir.
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

**DriverKit entitlements**, user-space driver binary'lerinin IOKit arayüzleri üzerinden kernel ile doğrudan iletişim kurmasına olanak tanır. DriverKit binary'leri donanımı yönetir: USB, Thunderbolt, PCIe, HID cihazları, ses ve ağ.

Bir DriverKit binary'sinin ele geçirilmesi şunları mümkün kılar:
- Hatalı biçimlendirilmiş `IOConnectCallMethod` çağrıları üzerinden **kernel attack surface**
- **USB device spoofing** (HID injection için klavye taklidi)
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

## Referanslar

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` işlemleri ve `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` işleyicisi)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
