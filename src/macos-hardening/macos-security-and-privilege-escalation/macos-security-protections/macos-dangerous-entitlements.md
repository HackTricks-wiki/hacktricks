# Entitlements Hatari za macOS na ruhusa za TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Kumbuka kwamba entitlements zinazoanza na **`com.apple`** hazipatikani kwa third-parties, ni Apple pekee inayoweza kuzigawa... Au ikiwa unatumia enterprise certificate, unaweza kuunda entitlements zako zinazoanza na **`com.apple`** na kwa kweli ukakwepa protections zinazotegemea hili.

## Juu

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** inaruhusu **kukwepa SIP**. Angalia [hapa kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** inaruhusu **kukwepa SIP**. Angalia [hapa kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (hapo awali iliitwa `task_for_pid-allow`)**

Entitlement hii inaruhusu kupata **task port ya process yoyote**, isipokuwa kernel. Angalia [**hapa kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Entitlement hii inaruhusu processes nyingine zilizo na entitlement **`com.apple.security.cs.debugger`** kupata task port ya process inayoendeshwa na binary yenye entitlement hii na **kuingiza code ndani yake**. Angalia [**hapa kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps zilizo na Debugging Tool Entitlement zinaweza kuita `task_for_pid()` ili kupata task port halali ya unsigned na third-party apps zilizo na `Get Task Allow` entitlement iliyowekwa kuwa `true`. Hata hivyo, hata ikiwa na debugging tool entitlement, debugger **haiwezi kupata task ports** za processes ambazo **hazina `Get Task Allow entitlement`**, na kwa hiyo zinalindwa na System Integrity Protection. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Entitlement hii inaruhusu **kupakia frameworks, plug-ins, au libraries bila kusainiwa na Apple au kusainiwa kwa Team ID ileile** ya executable kuu, kwa hiyo attacker anaweza kutumia vibaya arbitrary library load ili kuingiza code. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Entitlement hii inafanana sana na **`com.apple.security.cs.disable-library-validation`**, lakini **badala ya kuzima** library validation **moja kwa moja**, inaruhusu process **kuita `csops` system call ili kuizima** wakati wa runtime.

Jina la entitlement limewekwa moja kwa moja ndani ya XNU karibu na `csops` operation inayotumia entitlement hii:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Kidhibiti cha kernel cha `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) kinaonyesha kwa usahihi jinsi primitive hii ilivyo finyu:<sup>[[2]](#references)</sup>
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
Kwa hiyo operesheni:

- Ni ya **macOS pekee** (`ENOTSUP` kwenye platform nyingine zote).
- Hufanya kazi kwenye **mchakato wenyewe tu** (`forself == 1`) — huwezi kuondoa library validation kwenye mchakato mwingine kwa kutumia operesheni hii.
- Inahitaji mchakato huo **uwe na entitlement** husika, na hukataa ikiwa mchakato umewekewa alama `CS_INSTALLER` au unaendeshwa chini ya subsystem root path.
- Huondoa **`CS_REQUIRE_LV | CS_FORCED_LV`** kwenye code-signing flags za mchakato.

Maoni ya XNU yanaeleza matumizi yaliyokusudiwa, na pia kwa nini ni ya kuvutia kwa attacker:

> Chaguo hili hutumika kuondoa library validation kwenye mchakato unaoendelea kufanya kazi. Hutumika katika plugin architectures wakati programu inahitaji kupakia libraries zisizoaminika. [...] Baada ya mchakato kupakia library isiyoaminika, kutegemea library validation baadaye hakutakuwa na ufanisi.

Kwa maneno mengine, **binary yoyote yenye entitlement hii ni dylib-injection target**: fanya code iendeshe ndani yake (au ishawishi ipakie plug-in yako) baada ya kuondoa `CS_REQUIRE_LV`, kisha unarithi kile ambacho host process inaaminika kufanya.

### `com.apple.security.cs.allow-dyld-environment-variables`

Entitlement hii inaruhusu **kutumia DYLD environment variables**, ambazo zinaweza kutumika kuingiza libraries na code. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` au `com.apple.rootless.storage`.`TCC`

[**Kulingana na blogu hii**](https://objective-see.org/blog/blog_0x4C.html) **na** [**blogu hii**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), entitlements hizi zinaruhusu **kubadilisha** database ya **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** na **`system.install.apple-software.standar-user`**

Entitlements hizi zinaruhusu **kusakinisha software bila kumuuliza mtumiaji ruhusa**, jambo ambalo linaweza kusaidia katika **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement inayohitajika kuomba **kernel ipakie kernel extension**.

### **`com.apple.private.icloud-account-access`**

Kwa entitlement **`com.apple.private.icloud-account-access`**, inawezekana kuwasiliana na **`com.apple.iCloudHelper`** XPC service ambayo **hutoa iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii.

Kwa **maelezo** zaidi kuhusu exploit ya **kupata iCloud tokens** kupitia entitlement hiyo, angalia talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui hii inaruhusu kufanya nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imetajwa kwamba hii inaweza kutumika** kusasisha maudhui yanayolindwa na SSV baada ya reboot. Ikiwa unajua jinsi inavyofanya kazi, tafadhali tuma PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imetajwa kwamba hii inaweza kutumika** kusasisha maudhui yanayolindwa na SSV baada ya reboot. Ikiwa unajua jinsi inavyofanya kazi, tafadhali tuma PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Entitlement hii huorodhesha makundi ya **keychain** ambayo application ina ruhusa ya kuyafikia:
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

Hutoa ruhusa za **Full Disk Access**, mojawapo ya ruhusa za juu zaidi za TCC unazoweza kuwa nazo.

### **`kTCCServiceAppleEvents`**

Hur允许 app kutuma events kwa apps nyingine ambazo hutumiwa kwa kawaida **kuendesha kazi kiotomatiki**. Kwa kudhibiti apps nyingine, inaweza kutumia vibaya ruhusa zilizopewa apps hizo nyingine.

Kama vile kuzifanya zimwombe mtumiaji neno lake la siri:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Au kuzifanya zitekeleze **arbitrary actions**.

### **`kTCCServiceEndpointSecurityClient`**

Huruhusu, miongoni mwa permissions nyingine, **kuandika database ya TCC ya mtumiaji**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Huruhusu **kubadilisha** attribute ya **`NFSHomeDirectory`** ya mtumiaji, jambo linalobadilisha njia ya folder yake ya nyumbani na hivyo kuruhusu **kubypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Huruhusu kurekebisha files zilizo ndani ya app bundles (ndani ya app.app), jambo ambalo **limezuiwa kwa default**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia ni nani aliye na access hii katika _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Process itaweza **kutumia vibaya vipengele vya macOS accessibility**, Hii inamaanisha kwamba, kwa mfano, itaweza kubonyeza keystrokes. Kwa hiyo inaweza kuomba access ya ku-control app kama Finder na ku-approve dialog kwa kutumia permission hii.

## Entitlements zinazohusiana na Trustcache/CDhash

Kuna entitlements ambazo zinaweza kutumiwa kubypass protections za Trustcache/CDhash, ambazo huzuia execution ya downgraded versions za Apple binaries.

## Wastani

### `com.apple.security.cs.allow-jit`

Entitlement hii huruhusu **kuunda memory inayoweza kuandikwa na kutekelezwa** kwa kupitisha flag ya `MAP_JIT` kwa system function ya `mmap()`. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Entitlement hii huruhusu **ku-override au ku-patch C code**, kutumia **`NSCreateObjectFileImageFromMemory`** ambayo imepitwa na wakati kwa muda mrefu (na kimsingi si salama), au kutumia framework ya **DVDPlayback**. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Kujumuisha entitlement hii huweka app yako katika hatari ya common vulnerabilities kwenye lugha za code zisizo salama kwa matumizi ya memory. Fikiria kwa makini ikiwa app yako inahitaji exception hii.

### `com.apple.security.cs.disable-executable-page-protection`

Entitlement hii huruhusu **kurekebisha sections za executable files zake yenyewe** kwenye disk ili kulazimisha kutoka. Angalia [**hii kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement ni entitlement kali sana ambayo huondoa security protection ya msingi kutoka kwenye app yako, na kumwezesha attacker kuandika upya executable code ya app yako bila kugunduliwa. Tumia entitlements nyembamba zaidi inapowezekana.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Entitlement hii huruhusu ku-mount nullfs file system (ambayo imekatazwa kwa default). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na blogpost hii, TCC permission hii kwa kawaida hupatikana katika mfumo wa:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ruhusu mchakato **kuomba ruhusa zote za TCC**.

### **`kTCCServicePostEvent`**

Ruhusu **kuingiza matukio bandia ya keyboard na mouse** katika mfumo mzima kupitia `CGEventPost()`. Mchakato wenye ruhusa hii unaweza kuiga mibofyo ya keyboard, mibofyo ya mouse, na matukio ya kusogeza ukurasa katika application yoyote — hivyo kutoa **remote control** ya desktop.

Hii ni hatari hasa inapounganishwa na `kTCCServiceAccessibility` au `kTCCServiceListenEvent`, kwa kuwa inaruhusu kusoma NA kuingiza input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Inaruhusu **intercepting all keyboard and mouse events** system-wide (input monitoring / keylogging). Process inaweza kusajili `CGEventTap` ili kunasa kila keystroke inayochapishwa katika application yoyote, ikijumuisha passwords, credit card numbers, na private messages.

Kwa exploitation techniques za kina tazama:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Inaruhusu **kusoma display buffer** — kuchukua screenshots na kurekodi screen video ya application yoyote, ikijumuisha secure text fields. Ikiunganishwa na OCR, hii inaweza kutoa passwords na sensitive data kutoka kwenye screen automatically.

> [!WARNING]
> Kuanzia macOS Sonoma, screen capture huonyesha persistent menu bar indicator. Kwenye versions za zamani, screen recording inaweza kufanyika kimya kabisa.

### **`kTCCServiceCamera`**

Inaruhusu **capturing photos and video** kutoka kwenye built-in camera au USB cameras zilizounganishwa. Code injection kwenye binary yenye camera entitlement huwezesha silent visual surveillance.

### **`kTCCServiceMicrophone`**

Inaruhusu **recording audio** kutoka kwenye input devices zote. Background daemons zenye mic access hutoa persistent ambient audio surveillance bila application window inayoonekana.

### **`kTCCServiceLocation`**

Inaruhusu kuuliza **physical location** ya device kupitia Wi-Fi triangulation au Bluetooth beacons. Continuous monitoring hufichua anwani za nyumbani/kazini, travel patterns, na daily routines.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Access ya **Contacts** (majina, emails, phones — muhimu kwa spear-phishing), **Calendar** (ratiba za meetings, attendee lists), na **Photos** (personal photos, screenshots ambazo zinaweza kuwa na credentials, location metadata).

Kwa credential theft exploitation techniques kamili kupitia TCC permissions, tazama:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** hudhoofisha App Sandbox kwa kuruhusu communication na system-wide Mach/XPC services ambazo sandbox kwa kawaida huzuia. Hii ndiyo **primary sandbox escape primitive** — application iliyo-compromise ndani ya sandbox inaweza kutumia mach-lookup exceptions kufikia privileged daemons na ku-exploit XPC interfaces zao.
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

**DriverKit entitlements** huruhusu binary za user-space driver kuwasiliana moja kwa moja na kernel kupitia interfaces za IOKit. Binary za DriverKit hudhibiti hardware: USB, Thunderbolt, PCIe, HID devices, audio, na networking.

Kompromasi ya binary ya DriverKit huwezesha:
- **Kernel attack surface** kupitia calls za `IOConnectCallMethod` zilizoundwa vibaya
- **USB device spoofing** (kuiga keyboard kwa HID injection)
- **DMA attacks** kupitia interfaces za PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Kwa maelezo ya kina kuhusu exploitation ya IOKit/DriverKit, angalia:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Marejeo

- [1] [XNU — `bsd/sys/codesign.h` (operesheni za `CS_OPS_*` na `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (handler ya `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement ya Debugging Tool (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement ya Kuzima Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement ya Kuruhusu Vigezo vya Mazingira vya DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Kubypass TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Cheza muziki na ubypass TCC, yaani CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [The Nightmare of Apple's OTA Update: Kubypass Uthibitishaji wa Signature na Kupwn Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement ya Kuruhusu Utekelezaji wa Code Iliyotengenezwa kwa JIT (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement ya Kuruhusu Kumbukumbu ya Executable Isiyotiwa Saini](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement ya Kuzima Ulinzi wa Kumbukumbu ya Executable](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
