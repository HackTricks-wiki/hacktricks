# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Let daarop dat entitlements wat met **`com.apple`** begin, nie vir derde partye beskikbaar is nie; slegs Apple kan dit toestaan... Of as jy 'n enterprise certificate gebruik, kan jy eintlik jou eie entitlements skep wat met **`com.apple`** begin en beskermings wat hierop gebaseer is, omseil.

## Hoog

### `com.apple.rootless.install.heritable`

Die entitlement **`com.apple.rootless.install.heritable`** laat jou toe om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die entitlement **`com.apple.rootless.install`** laat jou toe om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (voorheen `task_for_pid-allow` genoem)**

Hierdie entitlement laat jou toe om die **task port vir enige** process te verkry, behalwe die kernel. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Hierdie entitlement laat ander processes met die **`com.apple.security.cs.debugger`** entitlement toe om die task port te verkry van die process wat deur die binary met hierdie entitlement uitgevoer word en **code daarin te inject**. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps met die Debugging Tool Entitlement kan `task_for_pid()` aanroep om 'n geldige task port te verkry vir unsigned en derdeparty-apps met die `Get Task Allow` entitlement ingestel op `true`. Selfs met die debugging tool entitlement kan 'n debugger egter **nie die task ports verkry** van processes wat **nie die `Get Task Allow` entitlement het nie** en wat daarom deur System Integrity Protection beskerm word. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Hierdie entitlement laat jou toe om frameworks, plug-ins of libraries te **laai sonder dat dit óf deur Apple onderteken is óf met dieselfde Team ID** as die hoof-executable onderteken is; 'n aanvaller kan dus 'n arbitrêre library load misbruik om code te inject. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Hierdie entitlement is baie soortgelyk aan **`com.apple.security.cs.disable-library-validation`**, maar **in plaas daarvan om** library validation **direk te disable**, laat dit die process toe om 'n `csops` system call aan te roep om dit tydens runtime te disable.

Die entitlement-naam is hardcoded in XNU langs die `csops`-operasie wat dit gebruik:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Die kernel handler vir `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) toon presies hoe eng die primitive is:<sup>[[2]](#references)</sup>
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
Die operasie:

- Is **slegs macOS** (`ENOTSUP` op elke ander platform).
- Werk slegs op **homself** (`forself == 1`) — jy kan nie library validation hiermee van ’n ander process verwyder nie.
- Vereis dat die process werklik **die entitlement besit**, en weier indien die process as `CS_INSTALLER` gemerk is of onder ’n subsystem root path loop.
- Verwyder **`CS_REQUIRE_LV | CS_FORCED_LV`** van die process se code-signing flags.

Die XNU-kommentaar verduidelik die beoogde gebruiksgeval, asook waarom dit vir ’n aanvaller interessant is:

> This option is used to remove library validation from a running process. This is used in plugin architectures when a program needs to load untrusted libraries. [...] Once a process has loaded the untrusted library, relying on library validation in the future will not be effective.

Met ander woorde, **enige binary wat hierdie entitlement dra, is ’n dylib-injection target**: kry code binne-in dit aan die gang (of oortuig dit om jou plug-in te laai) nadat dit `CS_REQUIRE_LV` laat vaar het, en jy erf alles wat die host process vertrou word om te doen.

### `com.apple.security.cs.allow-dyld-environment-variables`

Hierdie entitlement laat jou toe om **DYLD environment variables te gebruik** wat gebruik kan word om libraries en code te inject. Kyk [**hierdie vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` of `com.apple.rootless.storage`.`TCC`

[**Volgens hierdie blog**](https://objective-see.org/blog/blog_0x4C.html) **en** [**hierdie blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), laat hierdie entitlements jou toe om die **TCC**-databasis te **wysig**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** en **`system.install.apple-software.standar-user`**

Hierdie entitlements laat jou toe om sagteware **te installeer sonder om die gebruiker se toestemming te vra**, wat nuttig kan wees vir **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement wat nodig is om die **kernel te vra om ’n kernel extension te laai**.

### **`com.apple.private.icloud-account-access`**

Met die entitlement **`com.apple.private.icloud-account-access`** is dit moontlik om met die **`com.apple.iCloudHelper`** XPC service te kommunikeer, wat **iCloud tokens sal verskaf**.

**iMovie** en **Garageband** het hierdie entitlement gehad.

Vir meer **inligting** oor die exploit om **iCloud tokens** uit hierdie entitlement te **verkry**, kyk na die praatjie: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ek weet nie wat dit toelaat om te doen nie

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die SSV-beskermde inhoud ná ’n reboot op te dateer. As jy weet hoe dit werk, stuur asseblief ’n PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die SSV-beskermde inhoud ná ’n reboot op te dateer. As jy weet hoe dit werk, stuur asseblief ’n PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Hierdie entitlement lys die **keychain**-groepe waartoe die toepassing toegang het:
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

Gee **Full Disk Access**-toestemmings, een van die hoogste TCC-toestemmings wat jy kan hê.

### **`kTCCServiceAppleEvents`**

Laat die app toe om gebeurtenisse na ander toepassings te stuur wat algemeen gebruik word om take te **automateer**. Deur ander apps te beheer, kan dit die toestemmings wat aan hierdie ander apps toegestaan is, misbruik.

Soos om hulle die gebruiker vir sy wagwoord te laat vra:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Of om hulle **arbitrêre aksies** te laat uitvoer.

### **`kTCCServiceEndpointSecurityClient`**

Laat onder andere toe om die gebruiker se TCC-databasis te **skryf**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Laat toe om die **`NFSHomeDirectory`**-kenmerk van ’n gebruiker te **verander**, wat sy tuisgids se pad verander en daarom toelaat om **TCC te omseil**.

### **`kTCCServiceSystemPolicyAppBundles`**

Laat toe om lêers binne app-bundels (binne app.app) te wysig, wat **by verstek nie toegelaat word nie**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om in _System Settings_ > _Privacy & Security_ > _App Management_ te kyk wie hierdie toegang het.

### `kTCCServiceAccessibility`

Die proses sal macOS se **toeganklikheidskenmerke kan misbruik**, wat byvoorbeeld beteken dat dit toetsaanslae sal kan druk. Dit kan dus toegang versoek om ’n app soos Finder te beheer en die dialoog met hierdie toestemming goedkeur.

## Trustcache/CDhash-verwante entitlements

Daar is sommige entitlements wat gebruik kan word om Trustcache/CDhash-beskermings te omseil, wat die uitvoering van afgegradeerde weergawes van Apple-binaries voorkom.

## Medium

### `com.apple.security.cs.allow-jit`

Hierdie entitlement laat toe om **geheue te skep wat skryfbaar en uitvoerbaar is** deur die `MAP_JIT`-vlag aan die `mmap()`-stelsel-funksie deur te gee. Sien [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Hierdie entitlement laat toe om **C-kode te oorskryf of te patch**, die lank-verouderde **`NSCreateObjectFileImageFromMemory`** te gebruik (wat fundamenteel onveilig is), of die **DVDPlayback**-framework te gebruik. Sien [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Die insluiting van hierdie entitlement stel jou app bloot aan algemene kwesbaarhede in geheue-onveilige kodetale. Oorweeg sorgvuldig of jou app hierdie uitsondering benodig.

### `com.apple.security.cs.disable-executable-page-protection`

Hierdie entitlement laat toe om **afdelings van sy eie uitvoerbare lêers** op skyf te wysig om dit kragtig te laat afsluit. Sien [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Die Disable Executable Memory Protection Entitlement is ’n uiterste entitlement wat ’n fundamentele sekuriteitsbeskerming uit jou app verwyder, wat dit vir ’n aanvaller moontlik maak om jou app se uitvoerbare kode sonder opsporing te herskryf. Gebruik indien moontlik nouer entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Hierdie entitlement laat toe om ’n nullfs-lêerstelsel te mount (by verstek verbode). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Volgens hierdie blogplasing word hierdie TCC-toestemming gewoonlik in die volgende vorm gevind:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Laat die process toe om **al die TCC permissions aan te vra**.

### **`kTCCServicePostEvent`**

Laat **synthetic keyboard- en mouse events** stelselwyd via `CGEventPost()` **inject**. 'n Process met hierdie permission kan keystrokes, mouse clicks en scroll events in enige application simuleer — wat effektief **remote control** van die desktop verskaf.

Dit is veral gevaarlik wanneer dit met `kTCCServiceAccessibility` of `kTCCServiceListenEvent` gekombineer word, aangesien dit beide die lees EN die **inject** van input toelaat.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Laat **alle sleutelbord- en muisgebeure** stelselwyd onderskep word (invoermonitering / keylogging). ’n Proses kan ’n `CGEventTap` registreer om elke toetsaanslag wat in enige toepassing getik word, vas te vang, insluitend wagwoorde, kredietkaartnommers en private boodskappe.

Vir gedetailleerde exploitation-tegnieke, sien:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Laat die **vertoonbuffer lees** — om skermskote te neem en skermvideo van enige toepassing op te neem, insluitend veilige teksvelde. In kombinasie met OCR kan dit wagwoorde en sensitiewe data outomaties uit die skerm onttrek.

> [!WARNING]
> Vanaf macOS Sonoma wys screen capture ’n aanhoudende kieslysbalk-aanwyser. Op ouer weergawes kan skermopname heeltemal stil wees.

### **`kTCCServiceCamera`**

Laat foto’s en video vanaf die ingeboude kamera of gekoppelde USB-kameras vasgelê word. Code injection in ’n kamera-entitled binary maak stille visuele toesig moontlik.

### **`kTCCServiceMicrophone`**

Laat oudio vanaf alle invoertoestelle opgeneem word. Agtergrond-daemons met mikrofoontoegang bied aanhoudende omgewingsoudio-toesig sonder ’n sigbare toepassingsvenster.

### **`kTCCServiceLocation`**

Laat die toestel se **fisiese ligging** deur middel van Wi-Fi-triangulasie of Bluetooth-bakens navraag doen. Deurlopende monitering onthul huis-/werkadresse, reispatrone en daaglikse roetines.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Toegang tot **Contacts** (name, e-posadresse, telefoonnommers — nuttig vir spear-phishing), **Calendar** (vergaderskedules, deelnemerslyste) en **Photos** (persoonlike foto’s, skermskote wat geloofsbriewe kan bevat, liggingmetadata).

Vir volledige exploitation-tegnieke vir credential theft deur middel van TCC-permissies, sien:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox- en Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Tydelike Sandbox-uitsonderings** verswak die App Sandbox deur kommunikasie met stelselwye Mach/XPC-dienste toe te laat wat die sandbox normaalweg blokkeer. Dit is die **primêre sandbox escape primitive** — ’n gekompromitteerde sandboxed toepassing kan mach-lookup-uitsonderings gebruik om bevoorregte daemons te bereik en hul XPC-koppelvlakke te exploiteer.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Vir die gedetailleerde exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, sien:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit-entitlements** laat user-space driver binaries toe om direk met die kernel deur IOKit-interfaces te kommunikeer. DriverKit-binaries bestuur hardeware: USB, Thunderbolt, PCIe, HID-toestelle, oudio en networking.

Die kompromittering van ’n DriverKit-binary maak die volgende moontlik:
- **Kernel attack surface** deur misvormde `IOConnectCallMethod`-calls
- **USB-device spoofing** (emuleer ’n sleutelbord vir HID-injection)
- **DMA-attacks** deur PCIe/Thunderbolt-interfaces
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Vir gedetailleerde IOKit/DriverKit exploitation, sien:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Verwysings

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [The Nightmare of Apple's OTA Update: Bypassing the Signature Verification and Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
