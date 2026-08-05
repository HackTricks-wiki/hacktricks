# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Let daarop dat entitlements wat met **`com.apple`** begin, nie vir derde partye beskikbaar is nie; slegs Apple kan dit toeken... Of as jy 'n enterprise certificate gebruik, kan jy eintlik jou eie entitlements skep wat met **`com.apple`** begin en beskermings wat hierop gebaseer is, omseil.

## Hoog

### `com.apple.rootless.install.heritable`

Die entitlement **`com.apple.rootless.install.heritable`** laat jou toe om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Die entitlement **`com.apple.rootless.install`** laat jou toe om **SIP te omseil**. Kyk [hier vir meer inligting](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Hierdie entitlement laat jou toe om die **task port vir enige** proses, behalwe die kernel, te verkry. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Hierdie entitlement laat ander prosesse met die **`com.apple.security.cs.debugger`**-entitlement toe om die task port van die proses wat deur die binary met hierdie entitlement uitgevoer word, te verkry en **kode daarin te inject**. Kyk [**hier vir meer inligting**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps met die Debugging Tool Entitlement kan `task_for_pid()` aanroep om 'n geldige task port vir unsigned en derdeparty-apps te verkry met die `Get Task Allow`-entitlement op `true` gestel. Selfs met die debugging tool entitlement kan 'n debugger egter nie die **task ports** van prosesse kry wat **nie die `Get Task Allow`-entitlement het nie**, en wat dus deur System Integrity Protection beskerm word. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Hierdie entitlement laat jou toe om frameworks, plug-ins of libraries te **laai sonder dat hulle óf deur Apple onderteken is óf met dieselfde Team ID as die hoof-executable onderteken is**, sodat 'n aanvaller 'n arbitrêre library load kan misbruik om kode te inject. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Hierdie entitlement is baie soortgelyk aan **`com.apple.security.cs.disable-library-validation`**, maar **in plaas daarvan om** library validation **direk te deaktiveer**, laat dit die proses toe om 'n `csops` system call aan te roep om dit tydens runtime te deaktiveer.

Die entitlement-naam is hardcoded in XNU langs die `csops`-operasie wat dit gebruik:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Die kernel handler vir `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) toon presies hoe beperk die primitive is:<sup>[3]</sup>
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
Dus die operasie:

- Is **slegs macOS** (`ENOTSUP` op elke ander platform).
- Werk slegs op **homself** (`forself == 1`) — jy kan nie hiermee library validation van ’n ander proses verwyder nie.
- Vereis dat die proses werklik **die entitlement besit**, en weier as die proses as `CS_INSTALLER` gemerk is of onder ’n subsystem root path loop.
- Verwyder **`CS_REQUIRE_LV | CS_FORCED_LV`** uit die proses se code-signing flags.

Die XNU-kommentaar verduidelik die beoogde gebruiksgeval, en ook waarom dit vir ’n aanvaller interessant is:

> This option is used to remove library validation from a running process. This is used in plugin architectures when a program needs to load untrusted libraries. [...] Once a process has loaded the untrusted library, relying on library validation in the future will not be effective.

Met ander woorde, **enige binary wat hierdie entitlement bevat, is ’n dylib-injection target**: kry code binne-in dit aan die gang (of oortuig dit om jou plug-in te laai) nadat dit `CS_REQUIRE_LV` laat vaar het, en jy erf waarvoor die host process ook al vertrou word om te doen.

### `com.apple.security.cs.allow-dyld-environment-variables`

Hierdie entitlement laat jou toe om **DYLD environment variables te gebruik** wat gebruik kan word om libraries en code te inject. Sien [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**Volgens hierdie blog**](https://objective-see.org/blog/blog_0x4C.html) **en** [**hierdie blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), laat hierdie entitlements jou toe om die **TCC**-databasis te **wysig**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Hierdie entitlements laat jou toe om **software te installeer sonder om die gebruiker vir toestemming te vra**, wat nuttig kan wees vir ’n **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement wat nodig is om die **kernel te vra om ’n kernel extension te laai**.

### **`com.apple.private.icloud-account-access`**

Met die entitlement **`com.apple.private.icloud-account-access`** is dit moontlik om met die **`com.apple.iCloudHelper`** XPC service te kommunikeer, wat **iCloud tokens sal verskaf**.

**iMovie** en **Garageband** het hierdie entitlement gehad.

Vir meer **inligting** oor die exploit om **iCloud tokens** uit daardie entitlement te **verkry**, sien die praatjie: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Ek weet nie wat dit toelaat om te doen nie

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die SSV-beskermde inhoud ná ’n reboot op te dateer. As jy weet hoe, stuur asseblief ’n PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **word genoem dat dit gebruik kan word om** die SSV-beskermde inhoud ná ’n reboot op te dateer. As jy weet hoe, stuur asseblief ’n PR!

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

Laat die app toe om events na ander toepassings te stuur wat algemeen gebruik word om **take te outomatiseer**. Deur ander apps te beheer, kan dit die toestemmings wat aan hierdie ander apps toegeken is, misbruik.

Byvoorbeeld, deur hulle die gebruiker vir sy wagwoord te laat vra:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Of om hulle **arbitrêre aksies** te laat uitvoer.

### **`kTCCServiceEndpointSecurityClient`**

Laat onder andere toe om **die gebruiker se TCC-databasis te skryf**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Laat toe om die **`NFSHomeDirectory`**-kenmerk van ’n gebruiker te **verander**, wat sy tuisvouerpad verander en daarom toelaat om **TCC te omseil**.

### **`kTCCServiceSystemPolicyAppBundles`**

Laat toe om lêers binne app-bundels (binne app.app) te wysig, wat **by verstek verbied** word.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Dit is moontlik om in _System Settings_ > _Privacy & Security_ > _App Management_ te kyk wie hierdie toegang het.

### `kTCCServiceAccessibility`

Die proses sal die **macOS-toeganklikheidskenmerke kan misbruik**, wat byvoorbeeld beteken dat dit sleuteldrukke kan simuleer. Dit kan dus toegang versoek om ’n app soos Finder te beheer en die dialoog met hierdie toestemming goedkeur.

## Trustcache/CDhash-verwante entitlements

Daar is sommige entitlements wat gebruik kan word om Trustcache/CDhash-beskermings te omseil, wat die uitvoering van afgegradeerde weergawes van Apple-binaries voorkom.

## Medium

### `com.apple.security.cs.allow-jit`

Hierdie entitlement laat toe om **geheue te skep wat skryfbaar en uitvoerbaar is** deur die `MAP_JIT`-vlag aan die `mmap()`-stelsel-funksie deur te gee. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Hierdie entitlement laat toe om **C-kode te oorskryf of te patch**, die lankal verouderde **`NSCreateObjectFileImageFromMemory`** te gebruik (wat fundamenteel onveilig is), of die **DVDPlayback**-framework te gebruik. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Die insluiting van hierdie entitlement stel jou app bloot aan algemene kwesbaarhede in geheue-onveilige kodetale. Oorweeg noukeurig of jou app hierdie uitsondering benodig.

### `com.apple.security.cs.disable-executable-page-protection`

Hierdie entitlement laat toe om **afdelings van sy eie uitvoerbare lêers** op skyf te wysig om gedwonge beëindiging te veroorsaak. Kyk [**hier vir meer inligting**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Die Disable Executable Memory Protection Entitlement is ’n uiterste entitlement wat ’n fundamentele sekuriteitsbeskerming uit jou app verwyder, wat dit vir ’n aanvaller moontlik maak om jou app se uitvoerbare kode sonder opsporing te herskryf. Gebruik eerder nouer entitlements indien moontlik.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Hierdie entitlement laat toe om ’n nullfs-lêerstelsel te mount (by verstek verbied). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Volgens hierdie blogpost word hierdie TCC-toestemming gewoonlik in die volgende vorm gevind:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Laat die proses toe om **vir alle TCC-toestemmings te vra**.

### **`kTCCServicePostEvent`**

Laat **die inspuiting van sintetiese sleutelbord- en muisgebeure** stelselwyd via `CGEventPost()` toe. ’n Proses met hierdie toestemming kan sleuteldrukke, muisklikke en blaai-gebeure in enige toepassing simuleer — wat dit effektief **remote control** oor die lessenaar gee.

Dit is veral gevaarlik in kombinasie met `kTCCServiceAccessibility` of `kTCCServiceListenEvent`, aangesien dit beide die lees EN inspuiting van invoer toelaat.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Laat **die onderskep van alle sleutelbord- en muisgebeure** stelselwyd toe (input monitoring / keylogging). ’n Proses kan ’n `CGEventTap` registreer om elke toetsaanslag wat in enige toepassing getik word, vas te lê, insluitend wagwoorde, kredietkaartnommers en private boodskappe.

Vir gedetailleerde exploitation techniques, sien:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Laat **die lees van die display buffer** toe — die neem van screenshots en opname van skermvideo van enige toepassing, insluitend veilige teksvelde. In kombinasie met OCR kan dit wagwoorde en sensitiewe data outomaties van die skerm onttrek.

> [!WARNING]
> Vanaf macOS Sonoma wys screen capture ’n permanente menu bar-indikator. Op ouer weergawes kan screen recording heeltemal stil plaasvind.

### **`kTCCServiceCamera`**

Laat **die vaslegging van foto’s en video** vanaf die ingeboude kamera of gekoppelde USB-kameras toe. Code injection in ’n camera-entitled binary maak silent visual surveillance moontlik.

### **`kTCCServiceMicrophone`**

Laat **die opname van oudio** vanaf alle invoertoestelle toe. Background daemons met mic access maak aanhoudende ambient audio surveillance moontlik sonder ’n sigbare toepassingsvenster.

### **`kTCCServiceLocation`**

Laat die navraag van die toestel se **fisiese ligging** via Wi-Fi-triangulasie of Bluetooth-beacons toe. Deurlopende monitering onthul huis-/werkadresse, reispatrone en daaglikse roetines.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Toegang tot **Contacts** (name, e-posadresse, telefoonnommers — nuttig vir spear-phishing), **Calendar** (vergaderskedules, deelnemerslyste) en **Photos** (persoonlike foto’s, screenshots wat credentials kan bevat, liggingmetadata).

Vir volledige credential theft exploitation techniques via TCC-permissions, sien:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** verswak die App Sandbox deur kommunikasie met stelselwye Mach/XPC-services toe te laat wat die sandbox normaalweg blokkeer. Dit is die **primêre sandbox escape primitive** — ’n gekompromitteerde sandboxed app kan mach-lookup exceptions gebruik om bevoorregte daemons te bereik en hul XPC-interfaces te exploiteer.
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

Die kompromittering van ’n DriverKit binary maak die volgende moontlik:
- **Kernel attack surface** deur misvormde `IOConnectCallMethod`-calls
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

## Verwysings

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*`-bewerkings en `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV`-handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
