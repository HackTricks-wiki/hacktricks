# macOS Tehlikeli Entitlements ve TCC izinleri

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Dikkat: **`com.apple`** ile başlayan entitlements üçüncü taraflara açık değildir, yalnızca Apple bunları verebilir... Ya da bir enterprise sertifikası kullanıyorsanız gerçekte **`com.apple`** ile başlayan kendi entitlements'ınızı oluşturup buna dayalı korumaları atlayabilirsiniz.

## Yüksek

### `com.apple.rootless.install.heritable`

Bu entitlement **`com.apple.rootless.install.heritable`** ile **SIP'i atlatmak** mümkündür. Daha fazla bilgi için bkz. [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Bu entitlement **`com.apple.rootless.install`** ile **SIP'i atlatmak** mümkündür. Daha fazla bilgi için bkz.[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Bu entitlement kernel hariç herhangi bir süreç için **task port** almayı sağlar. Daha fazla bilgi için bkz. [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Bu entitlement, **`com.apple.security.cs.debugger`** entitlement'ına sahip diğer süreçlerin, bu entitlement'a sahip binary tarafından çalıştırılan sürecin task port'unu almasına ve **üzerine kod enjekte etmesine** izin verir. Daha fazla bilgi için bkz. [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement'a sahip uygulamalar, `task_for_pid()` çağrısını yaparak `Get Task Allow` entitlement'ı `true` olarak ayarlanmış unsigned ve üçüncü taraf uygulamalar için geçerli bir task port alabilirler. Ancak, debugging tool entitlement'a rağmen bir debugger, `Get Task Allow` entitlement'ına sahip olmayan ve dolayısıyla System Integrity Protection ile korunan süreçlerin **task port'larını alamaz**. Daha fazla bilgi için bkz. [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Bu entitlement, ana yürütülebilir ile aynı Team ID ile imzalanmamış veya Apple tarafından imzalanmamış framework, plug-in veya kütüphanelerin **yüklenmesine izin verir**, böylece bir saldırgan rastgele bir kütüphane yüklemesini kötüye kullanarak kod enjekte edebilir. Daha fazla bilgi için bkz. [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Bu entitlement, **`com.apple.security.cs.disable-library-validation`**'a oldukça benzerdir fakat **doğrudan kütüphane doğrulamayı devre dışı bırakmak** yerine, sürecin bunu devre dışı bırakmak için bir `csops` sistem çağrısı yapmasına **izin verir**.\
Daha fazla bilgi için bkz. [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Bu entitlement, kütüphane ve kod enjekte etmek için kullanılabilecek **DYLD environment variable'larının** kullanılmasına izin verir. Daha fazla bilgi için bkz. [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), bu entitlements **TCC** veritabanını **değiştirmeye** izin verir.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Bu entitlements, kullanıcıdan izin istemeden **yazılım yüklemeye** izin verir; bu, bir **privilege escalation** için yardımcı olabilir.

### `com.apple.private.security.kext-management`

Kernel'e bir kernel extension yüklemesini **sormak** için gereken entitlement.

### **`com.apple.private.icloud-account-access`**

Bu entitlement ile **`com.apple.iCloudHelper`** XPC servisi ile iletişim kurmak mümkündür; bu servis **iCloud tokenları** sağlar.

**iMovie** ve **Garageband**'in bu entitlemente sahip olduğu bilinmektedir.

Bu entitlemment'tan **icloud tokenları** elde etmek için yapılan exploit hakkında daha fazla bilgi için konuşmaya bakın: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Bunun ne yaptığı hakkında bilgim yok

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) içinde bunun yeniden başlatmadan sonra SSV-korumalı içeriği güncellemek için kullanılabileceği **bahsedilmiş**. Eğer nasıl yapıldığını biliyorsanız PR gönderin lütfen!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) içinde bunun yeniden başlatmadan sonra SSV-korumalı içeriği güncellemek için kullanılabileceği **bahsedilmiş**. Eğer nasıl yapıldığını biliyorsanız PR gönderin lütfen!

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

Size **Tam Disk Erişimi** izni verir; bu, sahip olabileceğiniz en yüksek TCC izinlerinden biridir.

### **`kTCCServiceAppleEvents`**

Uygulamanın, genellikle **görevleri otomatikleştirmek** için kullanılan diğer uygulamalara olay göndermesine izin verir. Diğer uygulamaları kontrol ederek, bu uygulamalara verilen izinleri kötüye kullanabilir.

Örneğin, onların kullanıcıdan şifre istemesini sağlayabilir:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Veya onların **arbitrary actions** gerçekleştirmesini sağlamak.

### **`kTCCServiceEndpointSecurityClient`**

Diğer izinlerin yanı sıra, kullanıcının TCC veritabanını **write** etmeye izin verir.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Bir kullanıcının home klasör yolunu değiştiren **`NFSHomeDirectory`** özniteliğini **change** etmeye izin verir ve bu nedenle **bypass TCC**'ye olanak tanır.

### **`kTCCServiceSystemPolicyAppBundles`**

App bundle (inside app.app) içindeki dosyaları modify etmeye izin verir; bu varsayılan olarak **disallowed by default**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Bu erişime kimin sahip olduğunu _System Settings_ > _Privacy & Security_ > _App Management._ altında kontrol etmek mümkündür.

### `kTCCServiceAccessibility`

Process, macOS erişilebilirlik özelliklerini **abuse** edebilecektir; bu, örneğin tuş vuruşlarını basabilmesi anlamına gelir. Bu yüzden Finder gibi bir uygulamayı kontrol etmek için erişim isteyebilir ve bu izinle onay diyalogunu kabul edebilir.

## Trustcache/CDhash related entitlements

Trustcache/CDhash korumalarını, Apple ikili dosyalarının downgraded sürümlerinin çalıştırılmasını engelleyen korumaları bypass etmek için kullanılabilecek bazı entitlements vardır.

## Medium

### `com.apple.security.cs.allow-jit`

Bu entitlement, `mmap()` sistem fonksiyonuna `MAP_JIT` bayrağı geçirerek **yazılabilir ve çalıştırılabilir bellek oluşturma** izni verir. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Bu entitlement, C kodunu **override veya patch** etmeye, uzun süredir kullanımdan kaldırılmış **`NSCreateObjectFileImageFromMemory`** (ki bu temelde güvensizdir) fonksiyonunu kullanmaya veya **DVDPlayback** framework'ünü kullanmaya izin verir. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Including this entitlement exposes your app to common vulnerabilities in memory-unsafe code languages. Carefully consider whether your app needs this exception.

### `com.apple.security.cs.disable-executable-page-protection`

Bu entitlement, diskteki kendi executable dosyalarının bölümlerini **modify** etmesine izin verir. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> The Disable Executable Memory Protection Entitlement is an extreme entitlement that removes a fundamental security protection from your app, making it possible for an attacker to rewrite your app’s executable code without detection. Prefer narrower entitlements if possible.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Bu entitlement, nullfs dosya sistemi mount etmeye (varsayılan olarak forbidden) izin verir. Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

According to this blogpost, this TCC permission usually found in the form:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
İşlemin **tüm TCC izinlerini** talep etmesine izin ver.

### **`kTCCServicePostEvent`**

Sistem genelinde `CGEventPost()` aracılığıyla **sentetik klavye ve fare olayları enjekte etmeyi** sağlar. Bu izne sahip bir süreç herhangi bir uygulamada tuş vuruşlarını, fare tıklamalarını ve kaydırma olaylarını simüle edebilir — bu da masaüstünün **uzaktan kontrolünü** etkili bir şekilde sağlar.

Bu, hem girdi okumayı hem de enjekte etmeyi mümkün kıldığı için `kTCCServiceAccessibility` veya `kTCCServiceListenEvent` ile birleştirildiğinde özellikle tehlikelidir.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

İzin verir **tüm sistem çapındaki klavye ve fare olaylarını yakalamaya** (input monitoring / keylogging). Bir süreç, herhangi bir uygulamada yazılan her tuş vuruşunu yakalamak için bir `CGEventTap` kaydı yapabilir; bunların içinde parolalar, kredi kartı numaraları ve özel mesajlar bulunur.

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

İzin verir **ekran tamponunu okumaya** — herhangi bir uygulamanın ekran görüntülerini almak ve ekran videosu kaydetmek, güvenli metin alanları dahil. OCR ile birleştiğinde, bu ekran görüntülerinden otomatik olarak parolalar ve hassas veriler çıkarılabilir.

> [!WARNING]
> macOS Sonoma ile başlayarak, ekran kaydı sürekli bir menü çubuğu göstergesi gösterir. Daha eski sürümlerde, ekran kaydı tamamen sessiz olabilir.

### **`kTCCServiceCamera`**

İzin verir **yerleşik kameradan veya bağlı USB kameralardan fotoğraf ve video çekmeye**. Bir camera-entitled binary'ye yapılan Code injection, görünmez görsel gözetlemeyi mümkün kılar.

### **`kTCCServiceMicrophone`**

İzin verir **tüm giriş cihazlarından ses kaydetmeye**. Mikrofon erişimi olan arka plan daemon'ları görünür bir uygulama penceresi olmadan sürekli ortam ses gözetlemesi sağlar.

### **`kTCCServiceLocation`**

İzin verir cihazın **fiziksel konumunu** Wi-Fi triangulation veya Bluetooth beacons aracılığıyla sorgulamaya. Sürekli izleme ev/iş adreslerini, seyahat kalıplarını ve günlük rutinleri ortaya çıkarır.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Erişim sağlar **Contacts** (isimler, e-postalar, telefonlar — spear-phishing için kullanışlı), **Calendar** (toplantı takvimleri, katılımcı listeleri) ve **Photos** (kişisel fotoğraflar, kimlik bilgileri içerebilecek ekran görüntüleri, konum metadata'sı).

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing İzinleri

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**, App Sandbox'u zayıflatır; sandbox'ın normalde engellediği system-wide Mach/XPC servisleriyle iletişim kurulmasına izin verir. Bu, **primary sandbox escape primitive**'dir — ele geçirilmiş bir sandboxed app, mach-lookup exceptions kullanarak ayrıcalıklı daemon'lara ulaşabilir ve onların XPC arayüzlerini istismar edebilir.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Detaylı exploitation chain için: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, bkz:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** kullanıcı alanı sürücü ikili dosyalarının IOKit arayüzleri aracılığıyla kernel ile doğrudan iletişim kurmasına izin verir. DriverKit ikili dosyaları donanımı yönetir: USB, Thunderbolt, PCIe, HID cihazları, ses ve ağ.

Bir DriverKit ikili dosyasının ele geçirilmesi şunları sağlar:
- **Kernel attack surface** yanlış biçimlendirilmiş `IOConnectCallMethod` çağrıları aracılığıyla
- **USB device spoofing** (HID enjeksiyonu için klavye taklidi yapmak)
- **DMA attacks** PCIe/Thunderbolt arayüzleri aracılığıyla
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Detaylı IOKit/DriverKit exploitation için bakınız:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
