# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements verklaar vermoëns en sekuriteitsuitsonderings wat die bedryfstelsel aan ondertekende code toestaan. Die inskrywings hieronder fokus op dié wat besonder nuttig is tydens offensive review.<sup>[[13]](#references)</sup>

> [!WARNING]
> Let daarop dat entitlements wat met **`com.apple`** begin, nie vir derde partye beskikbaar is nie; slegs Apple kan dit toestaan... Of, indien jy 'n enterprise certificate gebruik, kan jy eintlik jou eie entitlements skep wat met **`com.apple`** begin en beskermings wat hierop gebaseer is, omseil.

## High

### `com.apple.rootless.install.heritable`

Die entitlement **`com.apple.rootless.install.heritable`** laat 'n proses toe om **SIP te bypass**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die entitlement **`com.apple.rootless.install`** laat 'n proses toe om **SIP te bypass**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Hierdie entitlement laat 'n proses toe om die **task port van enige** proses behalwe die kernel te verkry. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Hierdie entitlement laat ander prosesse met die **`com.apple.security.cs.debugger`**-entitlement toe om die task port te verkry van die proses wat deur die binary met hierdie entitlement uitgevoer word en **code daarin te inject**. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps met die Debugging Tool Entitlement kan `task_for_pid()` aanroep om 'n geldige task port te verkry vir unsigned en derdeparty-apps met die `Get Task Allow`-entitlement wat op `true` gestel is. Selfs met die debugging tool entitlement kan 'n debugger egter **nie die task ports verkry** van prosesse wat **nie die `Get Task Allow`-entitlement het nie**, en wat dus deur System Integrity Protection beskerm word. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Hierdie entitlement laat 'n toepassing toe om **frameworks, plug-ins of libraries te laai sonder dat daar vereis word dat hulle deur Apple of met dieselfde Team ID as die hoof-executable onderteken is**, sodat 'n aanvaller 'n arbitrary library load kan misbruik om code te inject. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Hierdie entitlement is baie soortgelyk aan **`com.apple.security.cs.disable-library-validation`**, maar **in plaas daarvan om** library validation **direk te disable**, laat dit die proses toe om 'n `csops` system call aan te roep om dit tydens runtime te disable.

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
Dus die bewerking:

- Is **slegs macOS** (`ENOTSUP` op elke ander platform).
- Werk slegs op **homself** (`forself == 1`) — jy kan nie library validation met hierdie bewerking van ’n ander process verwyder nie.
- Vereis dat die process werklik die entitlement **besit**, en weier indien die process as `CS_INSTALLER` gemerk is of onder ’n subsystem root path loop.
- Verwyder **`CS_REQUIRE_LV | CS_FORCED_LV`** uit die process se code-signing flags.

Die XNU-kommentaar verduidelik die beoogde gebruiksgeval, asook waarom dit vir ’n aanvaller interessant is:

> Hierdie opsie word gebruik om library validation van ’n lopende process te verwyder. Dit word in plugin-argitekture gebruik wanneer ’n program onbetroubare libraries moet laai. [...] Nadat ’n process die onbetroubare library gelaai het, sal dit nie effektief wees om in die toekoms op library validation staat te maak nie.

Met ander woorde, **enige binary wat hierdie entitlement bevat, is ’n dylib-injection-teiken**: kry code binne-in hom aan die loop (of oorreed hom om jou plug-in te laai) nadat dit `CS_REQUIRE_LV` laat val het, en jy erf wat ook al die host process vertrou word om te doen.

### `com.apple.security.cs.allow-dyld-environment-variables`

Hierdie entitlement laat jou toe om **DYLD environment variables te gebruik**, wat gebruik kan word om libraries en code te inject. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` of `com.apple.rootless.storage`.`TCC`

[**Volgens hierdie blog**](https://objective-see.org/blog/blog_0x4C.html) **en** [**hierdie blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), laat hierdie entitlements ’n process toe om die **TCC**-databasis te **wysig**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** en **`system.install.apple-software.standar-user`**

Hierdie entitlements laat ’n process toe om **software te installeer sonder om die gebruiker se toestemming te vra**, wat nuttig kan wees vir **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement wat nodig is om die **kernel te versoek om ’n kernel extension te laai**.

### **`com.apple.private.icloud-account-access`**

Die entitlement **`com.apple.private.icloud-account-access`** maak dit moontlik om met die **`com.apple.iCloudHelper`** XPC service te kommunikeer, wat **iCloud tokens verskaf**.

**iMovie** en **Garageband** het hierdie entitlement gehad.

Vir meer **inligting** oor die exploit om **iCloud tokens** uit daardie entitlement te **verkry**, kyk na die talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ek weet nie wat dit toelaat nie

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) noem dat hierdie entitlement gebruik kon word om SSV-protected contents ná ’n reboot op te dateer. As jy weet hoe, stuur asseblief ’n PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Dieselfde verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) noem dat die skep van ’n sealed snapshot gebruik kon word om SSV-protected contents ná ’n reboot op te dateer. As jy weet hoe, stuur asseblief ’n PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Hierdie entitlement lys die **keychain**-groepe waartoe die application toegang het:
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

Laat die app toe om events na ander toepassings te stuur wat algemeen gebruik word om **take te outomatiseer**. Deur ander apps te beheer, kan dit die toestemmings wat aan hierdie ander apps toegeken is, misbruik.

Soos om hulle die gebruiker vir sy wagwoord te laat vra:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Of om hulle **arbitrary actions** te laat uitvoer.

### **`kTCCServiceEndpointSecurityClient`**

Laat onder andere toe om die gebruiker se **TCC database te skryf**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Laat toe om die **`NFSHomeDirectory`**-attribuut van ’n gebruiker te **verander**, wat sy home folder path verander en daarom toelaat om **TCC te omseil**.

### **`kTCCServiceSystemPolicyAppBundles`**

Laat toe om lêers binne app bundles (binne app.app) te wysig, wat **by verstek verbied word**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om in _System Settings_ > _Privacy & Security_ > _App Management_ te kyk wie hierdie toegang het.

### `kTCCServiceAccessibility`

Die process sal **macOS se accessibility features kan misbruik**, wat byvoorbeeld beteken dat dit keystrokes sal kan druk. Dit kan dus toegang versoek om ’n app soos Finder te beheer en die dialoog met hierdie permission goedkeur.

## Trustcache/CDhash-related entitlements

Daar is sommige entitlements wat gebruik kan word om Trustcache/CDhash-protections te omseil, wat die execution van downgraded versions van Apple binaries voorkom.

## Medium

### `com.apple.security.cs.allow-jit`

Hierdie entitlement laat ’n process toe om **geheue te skep wat writable en executable is** deur die `MAP_JIT`-flag aan die `mmap()`-system function deur te gee. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Hierdie entitlement laat toe om **C code te override of te patch**, die lank-verouderde **`NSCreateObjectFileImageFromMemory`** te gebruik (wat fundamenteel insecure is), of die **DVDPlayback**-framework te gebruik. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Die insluiting van hierdie entitlement stel jou app bloot aan algemene vulnerabilities in memory-unsafe code languages. Oorweeg noukeurig of jou app hierdie uitsondering nodig het.

### `com.apple.security.cs.disable-executable-page-protection`

Hierdie entitlement laat toe om **seksies van sy eie executable files** op disk te wysig om dit te dwing om uit te tree. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Die Disable Executable Memory Protection Entitlement is ’n ekstreme entitlement wat ’n fundamentele security protection uit jou app verwyder, wat dit vir ’n attacker moontlik maak om jou app se executable code sonder detection te herskryf. Gebruik, indien moontlik, narrower entitlements.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Hierdie entitlement laat toe om ’n nullfs file system te mount (by verstek verbied). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Volgens hierdie blogpost word hierdie TCC-permission gewoonlik in die volgende vorm gevind:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Laat die proses toe om **al die TCC-permissies aan te vra**.

### **`kTCCServicePostEvent`**

Laat **sintetiese sleutelbord- en muisgebeure** stelselwyd via `CGEventPost()` **inspuit**. ’n Proses met hierdie toestemming kan sleuteldrukke, muisklikke en rolgebeure in enige toepassing simuleer — wat effektief **afstandbeheer** oor die lessenaar bied.

Dit is veral gevaarlik in kombinasie met `kTCCServiceAccessibility` of `kTCCServiceListenEvent`, aangesien dit beide die **lees EN inspuiting van invoer** moontlik maak.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Laat **intercepting all keyboard and mouse events** stelselwyd toe (input monitoring / keylogging). ’n Proses kan ’n `CGEventTap` registreer om elke toetsaanslag wat in enige toepassing getik word, vas te lê, insluitend wagwoorde, kredietkaartnommers en private boodskappe.

Vir gedetailleerde exploitation techniques, sien:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Laat **reading the display buffer** toe — om screenshots te neem en skermvideo van enige toepassing op te neem, insluitend veilige teksvelde. Gekombineer met OCR kan dit wagwoorde en sensitiewe data outomaties van die skerm onttrek.

> [!WARNING]
> Vanaf macOS Sonoma wys screen capture ’n permanente menu bar-indikator. Op ouer weergawes kan screen recording heeltemal stil wees.

### **`kTCCServiceCamera`**

Laat **capturing photos and video** vanaf die ingeboude kamera of gekoppelde USB-kameras toe. Code injection in ’n binary met kamera-entitlements maak stille visuele toesig moontlik.

### **`kTCCServiceMicrophone`**

Laat **recording audio** vanaf alle invoertoestelle toe. Background daemons met mikrofoontoegang bied permanente omgewingsklank-toesig sonder enige sigbare toepassingsvenster.

### **`kTCCServiceLocation`**

Laat die toestel se **physical location** via Wi-Fi-triangulasie of Bluetooth-beacons navraag doen. Deurlopende monitoring onthul huis-/werkadresse, reispatrone en daaglikse roetines.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Toegang tot **Contacts** (name, e-posse, telefoonnommers — nuttig vir spear-phishing), **Calendar** (vergaderskedules, deelnemerslyste) en **Photos** (persoonlike foto’s, screenshots wat credentials kan bevat, liggingmetadata).

Vir volledige credential theft exploitation techniques via TCC-permissies, sien:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** verswak die App Sandbox deur kommunikasie met stelselwye Mach/XPC-dienste toe te laat wat die sandbox normaalweg blokkeer. Dit is die **primary sandbox escape primitive** — ’n gekompromitteerde sandboxed app kan mach-lookup exceptions gebruik om bevoorregte daemons te bereik en hul XPC-interfaces te exploit.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Vir 'n gedetailleerde exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, sien:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** laat user-space driver binaries toe om direk met die kernel deur IOKit-interfaces te kommunikeer. DriverKit binaries bestuur hardeware: USB, Thunderbolt, PCIe, HID-devices, audio en networking.

As 'n DriverKit binary gekompromitteer word, maak dit die volgende moontlik:
- **Kernel attack surface** deur misvormde `IOConnectCallMethod`-calls
- **USB device spoofing** (emuleer 'n keyboard vir HID injection)
- **DMA attacks** deur PCIe/Thunderbolt-interfaces
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

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*`-operasies en `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV`-hanteerder)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement om Library Validation te deaktiveer](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement om DYLD Environment Variables toe te laat](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Speel die musiek en bypass TCC, oftewel CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "Wat op jou Mac gebeur, bly op Apple se iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Die nagmerrie van Apple se OTA Update: Bypassing van die Signature Verification en Pwning van die Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement om JIT-compiled Code uit te voer (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement om Unsigned Executable Memory toe te laat](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement om Executable Memory Protection te deaktiveer](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
