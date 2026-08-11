# macOS Dangerous Entitlements & TCC-perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements verklaar vermoëns en sekuriteitsuitsonderings wat die bedryfstelsel aan ondertekende kode toestaan. Die inskrywings hieronder fokus op dié wat besonder nuttig is tydens offensive review.<sup>[[13]](#references)</sup>

> [!WARNING]
> Let daarop dat entitlements wat met **`com.apple`** begin, nie vir derdepartye beskikbaar is nie; slegs Apple kan dit toestaan... Of, indien jy ’n enterprise certificate gebruik, kan jy eintlik jou eie entitlements skep wat met **`com.apple`** begin en beskermings wat hierop gebaseer is, omseil.

## High

### `com.apple.rootless.install.heritable`

Die entitlement **`com.apple.rootless.install.heritable`** laat ’n proses toe om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die entitlement **`com.apple.rootless.install`** laat ’n proses toe om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Hierdie entitlement laat ’n proses toe om die **task port vir enige** proses behalwe die kernel te verkry. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Hierdie entitlement laat ander prosesse met die **`com.apple.security.cs.debugger`**-entitlement toe om die task port te verkry van die proses wat deur die binary met hierdie entitlement uitgevoer word, en om **kode daarin te inject**. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps met die Debugging Tool Entitlement kan `task_for_pid()` aanroep om ’n geldige task port te verkry vir unsigned en third-party apps met die `Get Task Allow`-entitlement op `true` gestel. Selfs met die debugging tool-entitlement kan ’n debugger egter **nie die task ports verkry** van prosesse wat **nie die `Get Task Allow`-entitlement het nie**, en wat dus deur System Integrity Protection beskerm word. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Hierdie entitlement laat ’n toepassing toe om **frameworks, plug-ins of libraries te laai sonder dat daar vereis word dat hulle deur Apple of met dieselfde Team ID** as die hoof-executable onderteken is; ’n aanvaller kan dus ’n arbitrary library load misbruik om kode te inject. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Hierdie entitlement is baie soortgelyk aan **`com.apple.security.cs.disable-library-validation`**, maar **in plaas daarvan om** library validation **direk te deaktiveer**, laat dit die proses toe om ’n `csops` system call aan te roep om dit tydens runtime te deaktiveer.

Die entitlement-naam is hardcoded in XNU langs die `csops`-operasie wat dit gebruik:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Die kernel handler vir `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) wys presies hoe beperk die primitive is:<sup>[[2]](#references)</sup>
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
- Werk net op **homself** (`forself == 1`) — jy kan nie hiermee library validation van ’n ander proses verwyder nie.
- Vereis dat die proses werklik die entitlement **besit**, en weier as die proses as `CS_INSTALLER` gemerk is of onder ’n subsystem root path loop.
- Verwyder **`CS_REQUIRE_LV | CS_FORCED_LV`** uit die proses se code-signing flags.

Die XNU-opmerking verduidelik die beoogde gebruiksgeval, en ook waarom dit vir ’n aanvaller interessant is:

> Hierdie opsie word gebruik om library validation van ’n lopende proses te verwyder. Dit word in plugin-architectures gebruik wanneer ’n program onbetroubare libraries moet laai. [...] Sodra ’n proses die onbetroubare library gelaai het, sal dit nie effektief wees om in die toekoms op library validation staat te maak nie.

Met ander woorde, **enige binary met hierdie entitlement is ’n dylib-injection target**: kry code binne-in dit aan die loop (of oortuig dit om jou plug-in te laai) nadat dit `CS_REQUIRE_LV` laat val het, en jy erf wat die host-proses ook al vertrou word om te doen.

### `com.apple.security.cs.allow-dyld-environment-variables`

Hierdie entitlement laat jou toe om **DYLD environment variables te gebruik** wat aangewend kan word om libraries en code te injecteer. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` of `com.apple.rootless.storage`.`TCC`

[**Volgens hierdie blog**](https://objective-see.org/blog/blog_0x4C.html) **en** [**hierdie blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), laat hierdie entitlements ’n proses toe om die **TCC**-databasis te **wysig**.<sup>[[6]](#references)[[7]](#references)</sup>

### Authorization rights **`system.install.apple-software`** en **`system.install.apple-software.standard-user`**

Hierdie Authorization Services-regte beheer die installering van Apple-verskafte software. ’n Proses wat daarop geregtig is om dit te verkry, kan die gewone authorization flow omseil, wat nuttig kan wees vir **privilege escalation**.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

Entitlement wat nodig is om die **kernel te vra om ’n kernel extension te laai**.

### **`com.apple.private.icloud-account-access`**

Die entitlement **`com.apple.private.icloud-account-access`** maak dit moontlik om met die **`com.apple.iCloudHelper`** XPC service te kommunikeer, wat **iCloud tokens sal verskaf**.

**iMovie** en **Garageband** het hierdie entitlement gehad.

Vir meer **inligting** oor die exploit om **icloud tokens te verkry** deur hierdie entitlement, kyk na die talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ek weet nie wat dit moontlik maak om te doen nie

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) noem dat hierdie entitlement gebruik kon word om SSV-beskermde inhoud ná ’n reboot by te werk. As jy weet hoe, stuur asseblief ’n PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Dieselfde verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) noem dat die skep van ’n sealed snapshot gebruik kon word om SSV-beskermde inhoud ná ’n reboot by te werk. As jy weet hoe, stuur asseblief ’n PR!<sup>[[9]](#references)</sup>

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

Laat die toepassing toe om events na ander toepassings te stuur wat algemeen gebruik word vir **die outomatisering van take**. Deur ander toepassings te beheer, kan dit die toestemmings misbruik wat aan hierdie ander toepassings toegeken is.

Soos om hulle die gebruiker se wagwoord te laat vra:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Of om hulle **arbitrêre aksies** te laat uitvoer.

### **`kTCCServiceEndpointSecurityClient`**

Laat onder andere toe om die gebruiker se **TCC-databasis te skryf**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Laat toe om die **`NFSHomeDirectory`**-kenmerk van ’n gebruiker te **verander**, wat sy tuisvouerpad verander en daarom toelaat om **TCC te omseil**.

### **`kTCCServiceSystemPolicyAppBundles`**

Laat toe om lêers binne app-bundles (binne app.app) te wysig, wat **by verstek nie toegelaat word nie**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om te kontroleer wie hierdie toegang het in _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Die proses sal **die macOS-toeganklikheidsfunksies kan misbruik**, wat byvoorbeeld beteken dat dit sleuteldrukke sal kan uitvoer. Dit kan dus toegang versoek om ’n app soos Finder te beheer en die dialoog met hierdie toestemming goedkeur.

## Trustcache/CDhash-verwante entitlements

Daar is sommige entitlements wat gebruik kan word om Trustcache/CDhash-beskermings te omseil, wat die uitvoering van afgegradeerde weergawes van Apple-binaries voorkom.

## Medium

### `com.apple.security.cs.allow-jit`

Hierdie entitlement laat ’n proses toe om **geheue te skep wat skryfbaar en uitvoerbaar is** deur die `MAP_JIT`-vlag aan die `mmap()`-stelsel-funksie deur te gee. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Hierdie entitlement laat toe om **C-kode te oorheers of te patch**, die lank-verouderde **`NSCreateObjectFileImageFromMemory`** te gebruik (wat fundamenteel onveilig is), of die **DVDPlayback**-framework te gebruik. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Deur hierdie entitlement in te sluit, stel jy jou app bloot aan algemene kwesbaarhede in geheue-onveilige kodetale. Oorweeg noukeurig of jou app hierdie uitsondering benodig.

### `com.apple.security.cs.disable-executable-page-protection`

Hierdie entitlement laat toe om **dele van sy eie uitvoerbare lêers** op skyf te wysig om dit kragtig te laat afsluit. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Die Disable Executable Memory Protection Entitlement is ’n uiterste entitlement wat ’n fundamentele sekuriteitsbeskerming uit jou app verwyder, wat dit vir ’n aanvaller moontlik maak om jou app se uitvoerbare kode sonder opsporing te herskryf. Verkies nouer entitlements indien moontlik.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Hierdie entitlement laat toe om ’n nullfs-lêerstelsel te mount (by verstek verbied). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Volgens hierdie blogpost word hierdie TCC-toestemming gewoonlik in die vorm gevind:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Laat die proses toe om **al die TCC permissions te vra**.

### **`kTCCServicePostEvent`**

Laat **die inspuiting van sintetiese sleutelbord- en muisgebeure** stelselwyd via `CGEventPost()` toe. ’n Proses met hierdie permission kan sleuteldrukke, muisklikke en scroll-gebeure in enige toepassing simuleer — wat effektief **remote control** van die desktop verskaf.

Dit is veral gevaarlik wanneer dit met `kTCCServiceAccessibility` of `kTCCServiceListenEvent` gekombineer word, aangesien dit beide die lees EN inspuiting van input moontlik maak.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Laat **die onderskepping van alle sleutelbord- en muisgebeurtenisse** stelselwyd toe (insetmonitering / keylogging). ’n Proses kan ’n `CGEventTap` registreer om elke sleuteldruk wat in enige toepassing ingetik word, vas te lê, insluitend wagwoorde, kredietkaartnommers en private boodskappe.

Vir gedetailleerde exploitation techniques, sien:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Laat **die lees van die skermbuffer** toe — die neem van screenshots en die opneem van skermvideo van enige toepassing, insluitend veilige teksvelde. In kombinasie met OCR kan dit wagwoorde en sensitiewe data outomaties uit die skerm onttrek.

> [!WARNING]
> Vanaf macOS Sonoma wys screen capture ’n permanente menubalk-aanwyser. Op ouer weergawes kan screen recording heeltemal stil plaasvind.

### **`kTCCServiceCamera`**

Laat **die vaslegging van foto's en video** vanaf die ingeboude kamera of gekoppelde USB-kameras toe. Code injection in ’n camera-entitled binary maak stille visuele toesig moontlik.

### **`kTCCServiceMicrophone`**

Laat **die opneem van oudio** vanaf alle invoertoestelle toe. Agtergronddaemons met mic access verskaf volgehoue omgewingsoudiotoesig sonder ’n sigbare toepassingsvenster.

### **`kTCCServiceLocation`**

Laat die navraag van die toestel se **fisiese ligging** via Wi-Fi-triangulasie of Bluetooth-beacons toe. Deurlopende monitering onthul huis-/werkadresse, reispatrone en daaglikse roetines.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Toegang tot **Contacts** (name, e-posadresse, telefoonnommers — nuttig vir spear-phishing), **Calendar** (vergaderingskedules, deelnemerlyste) en **Photos** (persoonlike foto's, screenshots wat credentials kan bevat, liggingsmetadata).

Vir volledige credential theft exploitation techniques via TCC-permissions, sien:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Tydelike Sandbox-uitsonderings** verswak die App Sandbox deur kommunikasie met stelselwye Mach/XPC-dienste toe te laat wat die sandbox normaalweg blokkeer. Dit is die **primêre sandbox escape primitive** — ’n gekompromitteerde sandboxed app kan mach-lookup-uitsonderings gebruik om bevoorregte daemons te bereik en hul XPC-interfaces te exploit.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Vir ’n gedetailleerde exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, sien:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** laat user-space driver binaries toe om direk met die kernel deur IOKit interfaces te kommunikeer. DriverKit binaries bestuur hardeware: USB, Thunderbolt, PCIe, HID devices, audio en networking.

Die kompromittering van ’n DriverKit binary aktiveer:
- **Kernel attack surface** deur misvormde `IOConnectCallMethod` calls
- **USB device spoofing** (emuleer ’n keyboard vir HID injection)
- **DMA attacks** deur PCIe/Thunderbolt interfaces
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Vir gedetailleerde IOKit/DriverKit exploitation, sien:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*`-bewerkings en `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV`-hanteerder)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement om Library Validation te deaktiveer](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement om DYLD-omgewingsveranderlikes toe te laat](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Speel die musiek en bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Die nagmerrie van Apple se OTA Update: Bypassing the Signature Verification and Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement om uitvoering van JIT-gekompileerde kode toe te laat (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement om ongetekende uitvoerbare geheue toe te laat](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement om beskerming van uitvoerbare geheue te deaktiveer](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Programmeringsgids vir magtigingsdienste](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
