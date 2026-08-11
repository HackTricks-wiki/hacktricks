# macOS Tehlikeli Entitlements ve TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements, işletim sisteminin imzalı koda verdiği yetenekleri ve güvenlik istisnalarını belirtir. Aşağıdaki girdiler, offensive review sırasında özellikle kullanışlı olanlara odaklanır.<sup>[[13]](#references)</sup>

> [!WARNING]
> **`com.apple`** ile başlayan entitlements'ların üçüncü taraflar tarafından kullanılamayacağını, bunları yalnızca Apple'ın verebileceğini unutmayın... Ancak bir enterprise certificate kullanıyorsanız, aslında **`com.apple`** ile başlayan kendi entitlements'larınızı oluşturabilir ve buna dayanan korumaları bypass edebilirsiniz.

## Yüksek

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement'ı bir process'in **SIP'i bypass etmesine** olanak tanır. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement'ı bir process'in **SIP'i bypass etmesine** olanak tanır. Daha fazla bilgi için [buraya bakın](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (daha önce `task_for_pid-allow` olarak adlandırılıyordu)**

Bu entitlement, bir process'in kernel dışındaki **herhangi bir** process için **task port** almasına olanak tanır. Daha fazla bilgi için [**buraya bakın**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Bu entitlement, **`com.apple.security.cs.debugger`** entitlement'ına sahip diğer process'lerin, bu entitlement'a sahip binary tarafından çalıştırılan process'in task port'unu almasına ve **ona code inject etmesine** olanak tanır. Daha fazla bilgi için [**buraya bakın**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement'a sahip uygulamalar, `Get Task Allow` entitlement'ı `true` olarak ayarlanmış unsigned ve third-party uygulamalar için geçerli bir task port almak üzere `task_for_pid()` çağırabilir. Ancak debugging tool entitlement'ına sahip olsa bile bir debugger, **`Get Task Allow entitlement'ına sahip olmayan** ve bu nedenle System Integrity Protection tarafından korunan process'lerin **task port'larını alamaz**. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Bu entitlement, bir uygulamanın framework'leri, plug-in'leri veya library'leri, bunların Apple tarafından ya da ana executable ile aynı Team ID kullanılarak imzalanmış olmasını gerektirmeden **yüklemesine** olanak tanır; dolayısıyla bir attacker, code inject etmek için arbitrary library load'u abuse edebilir. Daha fazla bilgi için [**buraya bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Bu entitlement, **`com.apple.security.cs.disable-library-validation`** ile oldukça benzerdir; ancak library validation'ı **doğrudan disable etmek** yerine process'in runtime sırasında bunu disable etmek için bir `csops` system call çağırmasına olanak tanır.

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
Yani işlem:

- **Yalnızca macOS'ta** çalışır (diğer tüm platformlarda `ENOTSUP`).
- Yalnızca **kendisinde** çalışır (`forself == 1`) — bununla başka bir process'ten library validation'ı kaldıramazsınız.
- Process'in ilgili **entitlement'ı gerçekten taşımasını** gerektirir ve process `CS_INSTALLER` olarak işaretlenmişse veya bir subsystem root path altında çalışıyorsa işlemi reddeder.
- Process'in code-signing flags değerinden **`CS_REQUIRE_LV | CS_FORCED_LV`** bitlerini temizler.

XNU yorumu, amaçlanan kullanım senaryosunu ve bunun bir attacker için neden ilgi çekici olduğunu açıklar:

> Bu seçenek, çalışan bir process'ten library validation'ı kaldırmak için kullanılır. Bu, bir programın güvenilmeyen library'leri yüklemesi gerektiğinde plugin architecture'larında kullanılır. [...] Bir process güvenilmeyen library'yi yükledikten sonra, gelecekte library validation'a güvenmek etkili olmayacaktır.

Başka bir deyişle, **bu entitlement'ı taşıyan her binary bir dylib-injection target'ıdır**: `CS_REQUIRE_LV` değerini kaldırdıktan sonra bu binary'nin içinde code çalıştırın (veya onu plug-in'inizi yüklemeye ikna edin); ardından host process'in yapmasına izin verilen her şeyden yararlanabilirsiniz.

### `com.apple.security.cs.allow-dyld-environment-variables`

Bu entitlement, library ve code inject etmek için kullanılabilecek **DYLD environment variable'larının kullanılmasına** izin verir. Daha fazla bilgi için [**buna bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` veya `com.apple.rootless.storage`.`TCC`

[**Bu bloga göre**](https://objective-see.org/blog/blog_0x4C.html) **ve** [**bu bloga göre**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), bu entitlement'lar bir process'in **TCC** database'ini **değiştirmesine** izin verir.<sup>[[6]](#references)[[7]](#references)</sup>

### Authorization rights **`system.install.apple-software`** ve **`system.install.apple-software.standard-user`**

Bu Authorization Services hakları, Apple tarafından sağlanan software'in kurulumunu yönetir. Bunları elde etme yetkisine sahip bir process, normal authorization flow'unu atlayabilir; bu da **privilege escalation** için yararlı olabilir.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

**Kernel'den bir kernel extension yüklemesini** istemek için gereken entitlement.

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement'ı, **iCloud token'ları sağlayacak** olan **`com.apple.iCloudHelper`** XPC service'i ile iletişim kurulmasını mümkün kılar.

**iMovie** ve **Garageband** bu entitlement'a sahipti.

Bu entitlement'tan **iCloud token'larını elde etmeye** yönelik exploit hakkında daha fazla **bilgi** için şu konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Bunun neye izin verdiğini bilmiyorum

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Bu rapor**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), bu entitlement'ın reboot sonrasında SSV-korumalı içeriklerin güncellenmesi için kullanılabileceğinden bahsediyor. Nasıl olduğunu biliyorsanız lütfen bir PR gönderin!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Aynı rapor**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), sealed snapshot oluşturmanın reboot sonrasında SSV-korumalı içeriklerin güncellenmesi için kullanılabileceğinden bahsediyor. Nasıl olduğunu biliyorsanız lütfen bir PR gönderin!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Bu entitlement, application'ın erişebildiği **keychain** gruplarını listeler:
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

Uygulamanın, genellikle **automating tasks** için kullanılan diğer uygulamalara event göndermesine izin verir. Diğer uygulamaları kontrol ederek bu uygulamalara verilen izinleri kötüye kullanabilir.

Örneğin, kullanıcıdan parolasını istemelerini sağlamak:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Veya onları **keyfi eylemler** gerçekleştirmeye zorlamak.

### **`kTCCServiceEndpointSecurityClient`**

Diğer izinlerin yanı sıra, **kullanıcının TCC veritabanına yazmaya** izin verir.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Bir kullanıcının **`NFSHomeDirectory`** özniteliğini **değiştirmeye** izin verir; bu, kullanıcının home klasörü yolunu değiştirir ve dolayısıyla **TCC'yi bypass etmeye** olanak tanır.

### **`kTCCServiceSystemPolicyAppBundles`**

App bundle'larının (app.app içindeki) dosyalarını değiştirmeye izin verir; bu işlem varsayılan olarak **yasaktır**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Bu erişime kimin sahip olduğunu _Sistem Ayarları_ > _Gizlilik ve Güvenlik_ > _App Yönetimi_ bölümünden kontrol etmek mümkündür.

### `kTCCServiceAccessibility`

Process, **macOS accessibility özelliklerini abuse edebilir**. Bu, örneğin keystroke'lara basabileceği anlamına gelir. Böylece Finder gibi bir app'i kontrol etmek için erişim isteğinde bulunabilir ve bu izinle iletişim kutusunu onaylayabilir.

## Trustcache/CDhash ile ilgili entitlements

Downgrade edilmiş Apple binary'lerinin çalıştırılmasını engelleyen Trustcache/CDhash korumalarını bypass etmek için kullanılabilecek bazı entitlements vardır.

## Medium

### `com.apple.security.cs.allow-jit`

Bu entitlement, `mmap()` system function'ına `MAP_JIT` flag'ini geçirerek bir process'in **writable ve executable bellek oluşturmasına** izin verir. Daha fazla bilgi için [**buna bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Bu entitlement, **C kodunu override veya patch etmeye**, uzun süredir deprecated olan **`NSCreateObjectFileImageFromMemory`** API'sini kullanmaya (bu API temelde insecure'dur) veya **DVDPlayback** framework'ünü kullanmaya izin verir. Daha fazla bilgi için [**buna bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Bu entitlement'ın dahil edilmesi, app'inizi memory-unsafe code dillerindeki yaygın güvenlik açıklarına maruz bırakır. App'inizin bu exception'a ihtiyaç duyup duymadığını dikkatlice değerlendirin.

### `com.apple.security.cs.disable-executable-page-protection`

Bu entitlement, bir process'in kendi executable dosyalarının disk üzerindeki **bölümlerini değiştirmesine** ve zorla çıkış yapmasına izin verir. Daha fazla bilgi için [**buna bakın**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement, app'inizden temel bir güvenlik korumasını kaldıran aşırı bir entitlement'tır ve bir attacker'ın app'inizin executable kodunu tespit edilmeden yeniden yazmasını mümkün kılar. Mümkünse daha dar kapsamlı entitlements kullanın.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Bu entitlement, bir nullfs file system mount etmeye izin verir (varsayılan olarak yasaktır). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Bu blogpost'a göre, bu TCC izni genellikle şu biçimde bulunur:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
İşlemin **tüm TCC izinlerini istemesine** olanak tanır.

### **`kTCCServicePostEvent`**

`CGEventPost()` aracılığıyla sistem genelinde **sentetik klavye ve fare olaylarının enjekte edilmesine** olanak tanır. Bu izne sahip bir işlem, herhangi bir uygulamada tuş vuruşlarını, fare tıklamalarını ve kaydırma olaylarını simüle edebilir; bu da masaüstünün **uzaktan kontrolünü** etkili bir şekilde sağlar.

Bu, `kTCCServiceAccessibility` veya `kTCCServiceListenEvent` ile birlikte kullanıldığında özellikle tehlikelidir; çünkü hem girdilerin okunmasına hem de enjekte edilmesine olanak tanır.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Sistem genelinde **tüm klavye ve fare olaylarının yakalanmasına** (input monitoring / keylogging) olanak tanır. Bir process, herhangi bir uygulamada yazılan her tuş vuruşunu yakalamak için bir `CGEventTap` kaydedebilir; buna parolalar, kredi kartı numaraları ve özel mesajlar da dahildir.

Ayrıntılı exploitation teknikleri için bkz.:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**Ekran arabelleğinin okunmasına** — güvenli metin alanları da dahil olmak üzere herhangi bir uygulamanın ekran görüntülerinin alınmasına ve ekran videosunun kaydedilmesine — olanak tanır. OCR ile birleştirildiğinde bu, parolaları ve hassas verileri ekrandan otomatik olarak çıkarabilir.

> [!WARNING]
> macOS Sonoma ile birlikte ekran capture işlemi, menü çubuğunda kalıcı bir gösterge görüntüler. Daha eski sürümlerde ekran kaydı tamamen sessiz şekilde gerçekleştirilebilir.

### **`kTCCServiceCamera`**

Yerleşik kameradan veya bağlı USB kameralardan **fotoğraf ve video capture edilmesine** olanak tanır. Camera yetkisine sahip bir binary'ye code injection uygulanması, sessiz görsel gözetlemeyi mümkün kılar.

### **`kTCCServiceMicrophone`**

Tüm input cihazlarından **ses kaydedilmesine** olanak tanır. Microphone erişimine sahip background daemon'lar, görünür bir uygulama penceresi olmadan kalıcı ortam sesi gözetlemesi sağlar.

### **`kTCCServiceLocation`**

Wi-Fi triangulation veya Bluetooth beacon'ları üzerinden cihazın **fiziksel konumunun** sorgulanmasına olanak tanır. Sürekli monitoring; ev/iş adreslerini, seyahat modellerini ve günlük rutinleri ortaya çıkarır.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**'a (isimler, e-postalar, telefonlar — spear-phishing için kullanışlı), **Calendar**'a (toplantı programları, katılımcı listeleri) ve **Photos**'a (kişisel fotoğraflar, credential içerebilecek ekran görüntüleri, konum metadata'sı) erişim sağlar.

TCC permissions üzerinden gerçekleştirilen eksiksiz credential theft exploitation teknikleri için bkz.:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exception'ları**, normalde sandbox'ın engellediği sistem genelindeki Mach/XPC service'leriyle iletişime izin vererek App Sandbox'ı zayıflatır. Bu, **primary sandbox escape primitive'idir** — ele geçirilmiş bir sandbox'lı uygulama, privileged daemon'lara ulaşmak ve bunların XPC interface'lerini exploit etmek için mach-lookup exception'larını kullanabilir.
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

**DriverKit entitlements**, user-space driver binary'lerinin IOKit interfaces üzerinden kernel ile doğrudan iletişim kurmasına olanak tanır. DriverKit binary'leri donanımı yönetir: USB, Thunderbolt, PCIe, HID cihazları, ses ve networking.

Bir DriverKit binary'sinin ele geçirilmesi şunları mümkün kılar:
- Hatalı `IOConnectCallMethod` çağrıları üzerinden **kernel attack surface**
- **USB device spoofing** (HID injection için klavye taklidi)
- PCIe/Thunderbolt interfaces üzerinden **DMA attacks**
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
- [9] [Apple'ın OTA Update Kabusu: Signature Verification'ı Bypass Etme ve Kernel'i Ele Geçirme](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — JIT-compiled Code Çalıştırmaya İzin Veren Entitlement (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Unsigned Executable Memory Kullanımına İzin Veren Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Executable Memory Protection'ı Devre Dışı Bırakan Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Authorization Services Programming Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
