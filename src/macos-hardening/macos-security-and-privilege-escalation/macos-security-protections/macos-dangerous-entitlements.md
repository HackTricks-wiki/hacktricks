# Entitlements Hatari za macOS na ruhusa za TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Kumbuka kwamba entitlements zinazoanza na **`com.apple`** hazipatikani kwa third-parties; Apple pekee inaweza kuzigawa... Au ikiwa unatumia enterprise certificate, unaweza kuunda entitlements zako zinazoanza na **`com.apple`** na kwa hakika bypass protections zinazotegemea hili.

## High

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** inaruhusu **bypass SIP**. Angalia [hapa kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** inaruhusu **bypass SIP**. Angalia [hapa kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Entitlement hii inaruhusu kupata **task port ya process yoyote**, isipokuwa kernel. Angalia [**hapa kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Entitlement hii inaruhusu processes nyingine zilizo na entitlement **`com.apple.security.cs.debugger`** kupata task port ya process inayoendeshwa na binary yenye entitlement hii na **ku-inject code ndani yake**. Angalia [**hapa kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps zilizo na Debugging Tool Entitlement zinaweza kuita `task_for_pid()` ili kupata task port halali ya unsigned na third-party apps zilizo na entitlement ya `Get Task Allow` iliyowekwa kuwa `true`. Hata hivyo, hata ikiwa na debugging tool entitlement, debugger **haiwezi kupata task ports** za processes ambazo **hazina entitlement ya `Get Task Allow`**, na hivyo zinalindwa na System Integrity Protection. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Entitlement hii inaruhusu **kupakia frameworks, plug-ins, au libraries bila kusainiwa na Apple au kusainiwa kwa Team ID sawa** na executable kuu, kwa hiyo attacker anaweza kutumia vibaya library load yoyote ili ku-inject code. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Entitlement hii inafanana sana na **`com.apple.security.cs.disable-library-validation`**, lakini **badala yake** ya **kuzima moja kwa moja** library validation, inaruhusu process **kuita system call ya `csops` ili kuizima** wakati wa runtime.

Jina la entitlement limewekwa moja kwa moja kwenye XNU karibu na `csops` operation inayoitumia:<sup>[[2]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Msimamizi wa kernel wa `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) anaonyesha kwa usahihi jinsi primitive hii ilivyo finyu:<sup>[[3]](#references)</sup>
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
Kwa hivyo operesheni hii:

- Ni ya **macOS pekee** (`ENOTSUP` kwenye platform nyingine zote).
- Inafanya kazi kwenye **mchakato wenyewe tu** (`forself == 1`) — huwezi kuondoa library validation kwenye mchakato mwingine kwa kutumia hii.
- Inahitaji mchakato uwe na **entitlement** hiyo, na hukataa ikiwa mchakato umewekewa alama `CS_INSTALLER` au unaendeshwa chini ya subsystem root path.
- Huondoa **`CS_REQUIRE_LV | CS_FORCED_LV`** kutoka kwenye code-signing flags za mchakato.

Maoni ya XNU yanaeleza matumizi yaliyokusudiwa, na pia kwa nini yanavutia kwa attacker:

> Chaguo hili hutumiwa kuondoa library validation kutoka kwenye mchakato unaoendelea. Hii hutumiwa katika plugin architectures wakati programu inahitaji kupakia libraries zisizoaminika. [...] Baada ya mchakato kupakia library isiyoaminika, kutegemea library validation baadaye hakutakuwa na ufanisi.

Kwa maneno mengine, **binary yoyote iliyo na entitlement hii ni dylib-injection target**: fanya code ianze kutekelezwa ndani yake (au ishawishi ipakie plug-in yako) baada ya kuondoa `CS_REQUIRE_LV`, kisha unarithi uwezo wowote ambao host process inaaminika kuwa nao.

### `com.apple.security.cs.allow-dyld-environment-variables`

Entitlement hii inaruhusu **kutumia DYLD environment variables** ambazo zinaweza kutumiwa ku-inject libraries na code. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` au `com.apple.rootless.storage`.`TCC`

[**Kulingana na blog hii**](https://objective-see.org/blog/blog_0x4C.html) **na** [**blog hii**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), entitlements hizi zinaruhusu **kurekebisha** database ya **TCC**.

### **`system.install.apple-software`** na **`system.install.apple-software.standar-user`**

Entitlements hizi zinaruhusu **ku-install software bila kumuuliza mtumiaji ruhusa**, jambo ambalo linaweza kusaidia katika **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement inayohitajika ili kuiomba **kernel ipakie kernel extension**.

### **`com.apple.private.icloud-account-access`**

Kwa kutumia entitlement **`com.apple.private.icloud-account-access`**, inawezekana kuwasiliana na **`com.apple.iCloudHelper`** XPC service ambayo **hutoa iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii.

Kwa **maelezo zaidi** kuhusu exploit ya **kupata iCloud tokens** kupitia entitlement hiyo, angalia talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui hii inaruhusu kufanya nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imetajwa kwamba hii inaweza kutumiwa** kusasisha contents zinazolindwa na SSV baada ya reboot. Ikiwa unajua inavyotumwa, tafadhali tuma PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imetajwa kwamba hii inaweza kutumiwa** kusasisha contents zinazolindwa na SSV baada ya reboot. Ikiwa unajua inavyotumwa, tafadhali tuma PR!

### `keychain-access-groups`

Entitlement hii huorodhesha **keychain** groups ambazo application inaweza kufikia:
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

Hutoa ruhusa za **Full Disk Access**, ambazo ni miongoni mwa ruhusa za juu zaidi za TCC unazoweza kuwa nazo.

### **`kTCCServiceAppleEvents`**

Huruhusu app kutuma events kwa apps nyingine ambazo hutumiwa kwa kawaida **kuendesha tasks kiotomatiki**. Kwa kudhibiti apps nyingine, inaweza kutumia vibaya ruhusa zilizopewa apps hizo.

Kama vile kuzifanya zimwombe mtumiaji password yake:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Au kuwafanya wafanye **arbitrary actions**.

### **`kTCCServiceEndpointSecurityClient`**

Inaruhusu, miongoni mwa permissions nyingine, **kuandika TCC database ya mtumiaji**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Inaruhusu **kubadilisha** attribute ya **`NFSHomeDirectory`** ya mtumiaji, jambo linalobadilisha path ya home folder yake na hivyo kuruhusu **kubypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Inaruhusu kurekebisha files zilizo ndani ya app bundles (ndani ya app.app), jambo ambalo **limezuiwa kwa default**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia ni nani aliye na access hii katika _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Process itaweza **kutumia vibaya macOS accessibility features**, ambayo ina maana kwamba, kwa mfano, itaweza kubonyeza keystrokes. Kwa hiyo inaweza kuomba access ya ku-control app kama Finder na ku-approve dialog kwa kutumia permission hii.

## Trustcache/CDhash related entitlements

Kuna entitlements kadhaa ambazo zinaweza kutumiwa kubypass Trustcache/CDhash protections, ambazo huzuia execution ya downgraded versions za Apple binaries.

## Medium

### `com.apple.security.cs.allow-jit`

Entitlement hii inaruhusu **kuunda memory ambayo inaweza kuandikwa na kutekelezwa** kwa kupitisha flag ya `MAP_JIT` kwenye system function ya `mmap()`. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Entitlement hii inaruhusu **ku-override au ku-patch C code**, kutumia **`NSCreateObjectFileImageFromMemory`** ambayo imepitwa na wakati kwa muda mrefu (na kimsingi si salama), au kutumia framework ya **DVDPlayback**. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Kujumuisha entitlement hii kunaweka app yako kwenye vulnerabilities za kawaida katika memory-unsafe code languages. Fikiria kwa makini ikiwa app yako inahitaji exception hii.

### `com.apple.security.cs.disable-executable-page-protection`

Entitlement hii inaruhusu **kurekebisha sections za executable files zake yenyewe** kwenye disk ili kulazimisha kutoka. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Disable Executable Memory Protection Entitlement ni entitlement ya extreme ambayo huondoa security protection ya msingi kutoka kwenye app yako, na kufanya iwezekane kwa attacker kuandika upya executable code ya app yako bila kugunduliwa. Tumia entitlements nyembamba zaidi inapowezekana.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Entitlement hii inaruhusu ku-mount nullfs file system (ambayo imekatazwa kwa default). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na blogpost hii, TCC permission hii kwa kawaida hupatikana katika mfumo wa:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ruhusu **process kuomba ruhusa zote za TCC**.

### **`kTCCServicePostEvent`**

Ruhusu **kuingiza matukio ghushi ya keyboard na mouse** katika mfumo mzima kupitia `CGEventPost()`. Process yenye ruhusa hii inaweza kuiga keystrokes, mibofyo ya mouse, na matukio ya kusogeza katika application yoyote — hivyo kutoa **remote control** ya desktop.

Hii ni hatari hasa inapounganishwa na `kTCCServiceAccessibility` au `kTCCServiceListenEvent`, kwa kuwa inaruhusu kusoma NA kuingiza input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Inaruhusu **kunasa matukio yote ya keyboard na mouse** katika mfumo mzima (input monitoring / keylogging). Process inaweza kusajili `CGEventTap` ili kunasa kila keystroke inayoandikwa katika application yoyote, ikijumuisha passwords, namba za credit card, na private messages.

Kwa mbinu za kina za exploitation, tazama:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Inaruhusu **kusoma display buffer** — kuchukua screenshots na kurekodi screen video ya application yoyote, ikijumuisha secure text fields. Ikiunganishwa na OCR, hii inaweza kutoa passwords na data nyeti kutoka kwenye screen automatically.

> [!WARNING]
> Kuanzia macOS Sonoma, screen capture huonyesha indicator inayoendelea kwenye menu bar. Kwenye matoleo ya zamani, screen recording inaweza kufanyika kimya kabisa.

### **`kTCCServiceCamera`**

Inaruhusu **kunasa picha na video** kutoka kwenye camera iliyojengwa ndani au cameras za USB zilizounganishwa. Code injection kwenye binary yenye camera entitlement huwezesha visual surveillance ya siri.

### **`kTCCServiceMicrophone`**

Inaruhusu **kurekodi audio** kutoka kwenye vifaa vyote vya input. Background daemons zenye mic access hutoa ambient audio surveillance inayoendelea bila application window inayoonekana.

### **`kTCCServiceLocation`**

Inaruhusu kuuliza **physical location** ya kifaa kupitia Wi-Fi triangulation au Bluetooth beacons. Ufuatiliaji unaoendelea hufichua anwani za nyumbani/kazini, mifumo ya safari, na shughuli za kila siku.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Access kwa **Contacts** (majina, emails, simu — muhimu kwa spear-phishing), **Calendar** (ratiba za mikutano, orodha za washiriki), na **Photos** (picha binafsi, screenshots ambazo zinaweza kuwa na credentials, metadata ya location).

Kwa mbinu kamili za credential theft exploitation kupitia TCC permissions, tazama:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** hudhoofisha App Sandbox kwa kuruhusu mawasiliano na system-wide Mach/XPC services ambazo sandbox kwa kawaida huzuia. Hii ndiyo **primary sandbox escape primitive** — app iliyoathiriwa ndani ya sandbox inaweza kutumia mach-lookup exceptions kufikia privileged daemons na ku-exploit XPC interfaces zao.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Kwa exploitation chain ya kina: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, tazama:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** huruhusu user-space driver binaries kuwasiliana moja kwa moja na kernel kupitia IOKit interfaces. DriverKit binaries hudhibiti hardware: USB, Thunderbolt, PCIe, HID devices, audio, na networking.

Kompromaisi ya DriverKit binary huwezesha:
- **Kernel attack surface** kupitia calls za `IOConnectCallMethod` zenye data iliyoundwa vibaya
- **USB device spoofing** (kuiga keyboard kwa HID injection)
- **DMA attacks** kupitia PCIe/Thunderbolt interfaces
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Kwa maelezo ya kina kuhusu exploitation ya IOKit/DriverKit, tazama:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Marejeo

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (operations za `CS_OPS_*` na `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (handler ya `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
