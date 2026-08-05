# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> **`com.apple`** ile başlayan entitlements üçüncü taraflar için kullanılamaz; bunları yalnızca Apple verebilir... Ya da bir enterprise certificate kullanıyorsanız, aslında **`com.apple`** ile başlayan kendi entitlements'larınızı oluşturabilir ve buna dayalı protections'ları bypass edebilirsiniz.

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement'ı **SIP'i bypass etmeye** olanak tanır. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement'ı **SIP'i bypass etmeye** olanak tanır. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Bu entitlement, kernel hariç **herhangi bir** process için **task port'u almaya** olanak tanır. Daha fazla bilgi için [**buraya bakın**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Bu entitlement, **`com.apple.security.cs.debugger`** entitlement'ına sahip diğer process'lerin, bu entitlement'a sahip binary tarafından çalıştırılan process'in task port'unu almasına ve **ona code inject etmesine** olanak tanır. Daha fazla bilgi için [**buraya bakın**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement'a sahip Apps, `Get Task Allow` entitlement'ı `true` olarak ayarlanmış unsigned ve third-party Apps için geçerli bir task port almak üzere `task_for_pid()` çağırabilir. Ancak debugging tool entitlement'ı olsa bile bir debugger, **`Get Task Allow entitlement`'ına sahip olmayan** ve bu nedenle System Integrity Protection tarafından korunan process'lerin **task port'larını alamaz**. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Bu entitlement, ana executable ile **Apple tarafından imzalanmış veya aynı Team ID ile imzalanmış olmadan** frameworks, plug-ins veya libraries **yüklemeye** olanak tanır; dolayısıyla bir attacker, code inject etmek için rastgele bir library load'u abuse edebilir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Bu entitlement, **`com.apple.security.cs.disable-library-validation`** ile çok benzerdir; ancak library validation'ı **doğrudan devre dışı bırakmak** yerine process'in runtime sırasında bunu devre dışı bırakmak için bir **`csops` system call** çağırmasına olanak tanır.

Entitlement adı, onu kullanan `csops` operation'ının yanında XNU içinde hardcoded olarak bulunur:<sup>[[2]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV` için kernel handler (`bsd/kern/kern_proc.c`), primitive'in ne kadar dar kapsamlı olduğunu tam olarak gösterir:<sup>[[3]](#references)</sup>
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
- Process'in entitlement'ı gerçekten **taşımasını** gerektirir ve process `CS_INSTALLER` olarak işaretlenmişse veya bir subsystem root path altında çalışıyorsa işlemi reddeder.
- Process'in code-signing flag'lerinden **`CS_REQUIRE_LV | CS_FORCED_LV`** değerlerini temizler.

XNU yorumu, amaçlanan kullanım alanını ve bunun bir attacker için neden ilginç olduğunu açıklıyor:

> Bu seçenek, çalışan bir process'ten library validation'ı kaldırmak için kullanılır. Bu, bir programın güvenilmeyen library'leri yüklemesi gerektiği plugin architecture'larında kullanılır. [...] Bir process güvenilmeyen library'yi yükledikten sonra, gelecekte library validation'a güvenmek etkili olmayacaktır.

Başka bir deyişle, **bu entitlement'ı taşıyan her binary bir dylib-injection target'ıdır**: `CS_REQUIRE_LV` değerini kaldırdıktan sonra bu binary içinde code çalıştırın (veya onu plug-in'inizi yüklemeye ikna edin); böylece host process'in yapmasına izin verilen her şeyi devralırsınız.

### `com.apple.security.cs.allow-dyld-environment-variables`

Bu entitlement, library ve code inject etmek için kullanılabilecek **DYLD environment variables'ı kullanmaya** izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` veya `com.apple.rootless.storage`.`TCC`

[**Bu bloga göre**](https://objective-see.org/blog/blog_0x4C.html) **ve** [**bu bloga göre**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), bu entitlement'lar **TCC** database'ini **değiştirmeye** izin verir.

### **`system.install.apple-software`** ve **`system.install.apple-software.standar-user`**

Bu entitlement'lar, kullanıcıdan **izin istemeden software yüklemeye** izin verir; bu da bir **privilege escalation** için faydalı olabilir.

### `com.apple.private.security.kext-management`

Bir **kernel extension'ı yüklemesi için kernel'den istek göndermek** amacıyla gereken entitlement.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement'ı ile **iCloud token'ları sağlayacak** **`com.apple.iCloudHelper`** XPC service'i ile iletişim kurulabilir.

**iMovie** ve **Garageband** bu entitlement'a sahipti.

Bu entitlement üzerinden **iCloud token'ları elde etmeye** yönelik exploit hakkında daha fazla **bilgi** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Bunun ne yapılmasına izin verdiğini bilmiyorum

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), bunun reboot sonrasında SSV-protected içerikleri **update etmek için kullanılabileceğinden** bahsediliyor. Nasıl çalıştığını biliyorsanız lütfen bir PR gönderin!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), bunun reboot sonrasında SSV-protected içerikleri **update etmek için kullanılabileceğinden** bahsediliyor. Nasıl çalıştığını biliyorsanız lütfen bir PR gönderin!

### `keychain-access-groups`

Bu entitlement listesi, application'ın erişebildiği **keychain** gruplarını belirtir:
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

Genellikle **automating tasks** için kullanılan diğer uygulamalara event göndermesine izin verir. Diğer uygulamaları kontrol ederek bu uygulamalara verilen izinleri kötüye kullanabilir.

Örneğin, bu uygulamaların kullanıcıdan parolasını istemesini sağlayabilir:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Veya **arbitrary actions** gerçekleştirmelerini sağlamak.

### **`kTCCServiceEndpointSecurityClient`**

Diğer izinlerin yanı sıra, **kullanıcının TCC database'ine yazılmasına** izin verir.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Bir kullanıcının **`NFSHomeDirectory`** attribute'unu **değiştirmeye** izin verir; bu, kullanıcının home folder path'ini değiştirir ve dolayısıyla **TCC'yi bypass etmeye** olanak tanır.

### **`kTCCServiceSystemPolicyAppBundles`**

App bundle'larının (app.app içindeki) dosyalarını değiştirmeye izin verir; bu işlem varsayılan olarak **disallowed** durumdadır.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Bu erişime kimin sahip olduğunu _System Settings_ > _Privacy & Security_ > _App Management_ bölümünden kontrol etmek mümkündür.

### `kTCCServiceAccessibility`

Process, **macOS accessibility features'larını abuse edebilir**. Bu, örneğin keystroke'lara basabileceği anlamına gelir. Böylece Finder gibi bir app'i kontrol etmek için access isteyebilir ve bu permission ile dialog'u approve edebilir.

## Trustcache/CDhash ile ilgili entitlements

Downgrade edilmiş Apple binary'lerinin çalıştırılmasını engelleyen Trustcache/CDhash protections'larını bypass etmek için kullanılabilecek bazı entitlements vardır.

## Orta

### `com.apple.security.cs.allow-jit`

Bu entitlement, `mmap()` system function'ına `MAP_JIT` flag'ini geçirerek **writable ve executable memory oluşturulmasına** izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Bu entitlement, **C code'unu override veya patch etmeye**, uzun süredir deprecated olan **`NSCreateObjectFileImageFromMemory`** API'sini kullanmaya (bu API temelde insecure'dur) veya **DVDPlayback** framework'ünü kullanmaya izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Bu entitlement'ın dahil edilmesi, app'inizi memory-unsafe code languages'larındaki yaygın vulnerabilities'lara maruz bırakır. App'inizin bu exception'a ihtiyaç duyup duymadığını dikkatlice değerlendirin.

### `com.apple.security.cs.disable-executable-page-protection`

Bu entitlement, forcefully exit etmek için disk üzerindeki **kendi executable files'larının bölümlerini değiştirmeye** izin verir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Disable Executable Memory Protection Entitlement, app'inizden temel bir security protection'ı kaldıran ve bir attacker'ın app'inizin executable code'unu detection olmadan yeniden yazabilmesini mümkün kılan extreme bir entitlement'tır. Mümkünse daha dar kapsamlı entitlements'ları tercih edin.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Bu entitlement, bir nullfs file system'i mount etmeye izin verir (varsayılan olarak forbidden'dır). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Bu blog yazısına göre, bu TCC permission genellikle şu biçimde bulunur:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
İşlemin **tüm TCC izinlerini istemesine** olanak tanır.

### **`kTCCServicePostEvent`**

`CGEventPost()` aracılığıyla sistem genelinde **sentetik klavye ve fare olaylarının enjekte edilmesine** olanak tanır. Bu izne sahip bir işlem, herhangi bir uygulamada tuş vuruşlarını, fare tıklamalarını ve kaydırma olaylarını simüle edebilir; bu da masaüstü üzerinde etkili bir şekilde **uzaktan kontrol** sağlar.

Bu, `kTCCServiceAccessibility` veya `kTCCServiceListenEvent` ile birleştirildiğinde özellikle tehlikelidir; çünkü hem girişlerin okunmasına hem de enjekte edilmesine olanak tanır.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Sistem genelinde **tüm klavye ve fare olaylarının intercept edilmesine** (input monitoring / keylogging) izin verir. Bir process, parolalar, kredi kartı numaraları ve özel mesajlar dahil olmak üzere herhangi bir uygulamada yazılan her tuş vuruşunu yakalamak için bir `CGEventTap` kaydedebilir.

Ayrıntılı exploitation teknikleri için bkz.:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Ekran buffer'ının **okunmasına** — güvenli metin alanları dahil olmak üzere herhangi bir uygulamanın ekran görüntülerinin alınmasına ve ekran videosunun kaydedilmesine — izin verir. OCR ile birleştirildiğinde bu, parolaları ve ekrandaki hassas verileri otomatik olarak çıkarabilir.

> [!WARNING]
> macOS Sonoma ile birlikte screen capture, menü çubuğunda kalıcı bir gösterge gösterir. Daha eski sürümlerde screen recording tamamen sessiz olabilir.

### **`kTCCServiceCamera`**

Dahili kamera veya bağlı USB kameralar üzerinden **fotoğraf ve video yakalanmasına** izin verir. Camera entitlement'ına sahip bir binary'ye code injection uygulanması, sessiz görsel gözetim sağlar.

### **`kTCCServiceMicrophone`**

Tüm input cihazlarından **ses kaydedilmesine** izin verir. Mic access'e sahip background daemon'lar, görünür bir uygulama penceresi olmadan kalıcı ortam sesi gözetimi sağlar.

### **`kTCCServiceLocation`**

Wi-Fi triangulation veya Bluetooth beacon'ları üzerinden cihazın **fiziksel konumunun** sorgulanmasına izin verir. Sürekli monitoring; ev/iş adreslerini, seyahat modellerini ve günlük rutinleri ortaya çıkarır.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**'a (isimler, e-postalar, telefonlar — spear-phishing için kullanışlı), **Calendar**'a (toplantı programları, katılımcı listeleri) ve **Photos**'a (kişisel fotoğraflar, credential içerebilecek ekran görüntüleri, konum metadata'sı) erişim sağlar.

TCC izinleri üzerinden complete credential theft exploitation teknikleri için bkz.:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**, normalde sandbox'ın engellediği system-wide Mach/XPC service'larıyla iletişime izin vererek App Sandbox'ı zayıflatır. Bu, **primary sandbox escape primitive**'dir — ele geçirilmiş bir sandboxed app, privileged daemon'lara ulaşmak ve onların XPC interface'lerini exploit etmek için mach-lookup exceptions kullanabilir.
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

**DriverKit entitlements**, user-space driver binary'lerinin IOKit arayüzleri üzerinden kernel ile doğrudan iletişim kurmasına olanak tanır. DriverKit binary'leri donanımı yönetir: USB, Thunderbolt, PCIe, HID cihazları, ses ve networking.

Bir DriverKit binary'sinin ele geçirilmesi şunları sağlar:
- Hatalı `IOConnectCallMethod` çağrıları üzerinden **kernel attack surface**
- **USB device spoofing** (HID injection için klavye taklidi)
- PCIe/Thunderbolt arayüzleri üzerinden **DMA attacks**
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Ayrıntılı IOKit/DriverKit exploitation bilgileri için bkz.:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Referanslar

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` işlemleri ve `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` işleyicisi)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
