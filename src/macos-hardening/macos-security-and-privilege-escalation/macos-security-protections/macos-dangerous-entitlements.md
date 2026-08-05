# Entitlements Hatari za macOS na ruhusa za TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Kumbuka kuwa entitlements zinazoanza na **`com.apple`** hazipatikani kwa third-parties, ni Apple pekee inayoweza kuzigawa... Au ikiwa unatumia enterprise certificate, unaweza kuunda entitlements zako zinazoanza na **`com.apple`** na kwa kweli bypass protections zinazotegemea hili.

## Juu

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** inaruhusu **bypass SIP**. Angalia [hapa kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** inaruhusu **bypass SIP**. Angalia[ hapa kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (hapo awali iliitwa `task_for_pid-allow`)**

Entitlement hii inaruhusu kupata **task port ya process yoyote**, isipokuwa kernel. Angalia [**hapa kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Entitlement hii inaruhusu processes nyingine zilizo na entitlement **`com.apple.security.cs.debugger`** kupata task port ya process inayoendeshwa na binary iliyo na entitlement hii na **ku-inject code ndani yake**. Angalia [**hapa kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps zilizo na Debugging Tool Entitlement zinaweza kuita `task_for_pid()` ili kupata task port halali ya unsigned na third-party apps zilizo na entitlement ya `Get Task Allow` iliyowekwa kuwa `true`. Hata hivyo, hata ikiwa na debugging tool entitlement, debugger **haiwezi kupata task ports** za processes ambazo **hazina entitlement ya `Get Task Allow`**, na kwa hiyo zinalindwa na System Integrity Protection. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Entitlement hii inaruhusu **kupakia frameworks, plug-ins, au libraries bila kusainiwa na Apple au kusainiwa kwa Team ID sawa** na executable kuu, hivyo attacker anaweza kutumia vibaya library load yoyote ili ku-inject code. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Entitlement hii inafanana sana na **`com.apple.security.cs.disable-library-validation`**, lakini **badala ya ku-disable library validation moja kwa moja**, inaruhusu process **kuita system call ya `csops` ili ku-disable wakati wa runtime**.

Jina la entitlement limewekwa moja kwa moja kwenye XNU karibu na operesheni ya `csops` inayotumia entitlement hiyo:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Handler ya kernel ya `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) inaonyesha hasa jinsi primitive ilivyo na upeo mdogo:<sup>[3]</sup>
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

- Ni ya **macOS-only** (`ENOTSUP` kwenye platform nyingine zote).
- Hufanya kazi kwenye **yenyewe tu** (`forself == 1`) — huwezi kuondoa library validation kutoka kwa process nyingine kwa kutumia hii.
- Inahitaji process hiyo **iwe na entitlement** hiyo, na hukataa ikiwa process imewekewa alama `CS_INSTALLER` au inaendeshwa chini ya subsystem root path.
- Huondoa **`CS_REQUIRE_LV | CS_FORCED_LV`** kutoka kwenye code-signing flags za process.

Maelezo ya XNU yanafafanua matumizi yaliyokusudiwa, na pia kwa nini ni ya kuvutia kwa attacker:

> Chaguo hili hutumika kuondoa library validation kutoka kwenye process inayoendelea kufanya kazi. Hutumika katika plugin architectures ambapo program inahitaji kupakia libraries zisizoaminika. [...] Mara process inapokuwa imepakia library isiyoaminika, kutegemea library validation baadaye hakutakuwa na ufanisi.

Kwa maneno mengine, **binary yoyote yenye entitlement hii ni dylib-injection target**: endesha code ndani yake (au ishawishi ipakie plug-in yako) baada ya kuondoa `CS_REQUIRE_LV`, kisha unapata uwezo wa kufanya chochote ambacho host process imeaminiwa kufanya.

### `com.apple.security.cs.allow-dyld-environment-variables`

Entitlement hii inaruhusu **kutumia DYLD environment variables** ambazo zinaweza kutumiwa ku-inject libraries na code. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` au `com.apple.rootless.storage`.`TCC`

[**Kulingana na blog hii**](https://objective-see.org/blog/blog_0x4C.html) **na** [**blog hii**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), entitlements hizi zinaruhusu **kurekebisha** database ya **TCC**.

### **`system.install.apple-software`** na **`system.install.apple-software.standar-user`**

Entitlements hizi zinaruhusu **ku-install software bila kumuuliza user ruhusa**, jambo ambalo linaweza kusaidia katika **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement inayohitajika ili kuomba **kernel ipakie kernel extension**.

### **`com.apple.private.icloud-account-access`**

Kwa entitlement **`com.apple.private.icloud-account-access`**, inawezekana kuwasiliana na **`com.apple.iCloudHelper`** XPC service ambayo **itatoa iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii.

Kwa **maelezo zaidi** kuhusu exploit ya **kupata iCloud tokens** kupitia entitlement hiyo, angalia talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui hii inaruhusu kufanya nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imetajwa kwamba hii inaweza kutumiwa** ku-update contents zinazolindwa na SSV baada ya reboot. Ikiwa unajua jinsi ya kuituma, tafadhali tuma PR!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **imetajwa kwamba hii inaweza kutumiwa** ku-update contents zinazolindwa na SSV baada ya reboot. Ikiwa unajua jinsi ya kuituma, tafadhali tuma PR!

### `keychain-access-groups`

Entitlement hii inaorodhesha **keychain** groups ambazo application ina access nazo:
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

Huruhusu app kutuma events kwa applications nyingine ambazo hutumiwa kwa kawaida **automating tasks**. Kwa kudhibiti apps nyingine, inaweza kutumia vibaya ruhusa zilizopewa apps hizo nyingine.

Kwa mfano, kuzifanya zimwombe mtumiaji nenosiri lake:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Au kuwafanya watekeleze **arbitrary actions**.

### **`kTCCServiceEndpointSecurityClient`**

Hutoa, miongoni mwa ruhusa nyingine, uwezo wa **kuandika users TCC database**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Hutoa uwezo wa **kubadilisha** sifa ya **`NFSHomeDirectory`** ya user, jambo linalobadilisha njia ya home folder yake na hivyo kuruhusu **kubypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Huruhusu kurekebisha files ndani ya app bundles (ndani ya app.app), jambo ambalo **limezuiwa kwa default**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia ni nani aliye na access hii katika _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Process itaweza **kutumia vibaya vipengele vya macOS accessibility**, kumaanisha kwamba, kwa mfano, itaweza kubonyeza keystrokes. Kwa hiyo inaweza kuomba access ya kudhibiti app kama Finder na kuidhinisha dialog kwa kutumia permission hii.

## Entitlements zinazohusiana na Trustcache/CDhash

Kuna entitlements ambazo zinaweza kutumiwa kubypass ulinzi wa Trustcache/CDhash, unaozuia utekelezaji wa matoleo yaliyodowngrade ya Apple binaries.

## Wastani

### `com.apple.security.cs.allow-jit`

Entitlement hii huruhusu **kuunda memory ambayo inaweza kuandikwa na kutekelezwa** kwa kupitisha flag ya `MAP_JIT` kwenye system function ya `mmap()`. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Entitlement hii huruhusu **ku-override au kupatch C code**, kutumia **`NSCreateObjectFileImageFromMemory`** iliyopitwa na wakati kwa muda mrefu (ambayo kimsingi si salama), au kutumia framework ya **DVDPlayback**. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Kujumuisha entitlement hii huweka app yako kwenye hatari ya vulnerabilities za kawaida katika lugha za code zisizo salama kwa memory. Fikiria kwa makini ikiwa app yako inahitaji exception hii.

### `com.apple.security.cs.disable-executable-page-protection`

Entitlement hii huruhusu **kurekebisha sections za executable files zake yenyewe** kwenye disk ili kulazimisha exit. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Disable Executable Memory Protection Entitlement ni entitlement ya kiwango cha juu sana inayoondoa ulinzi wa msingi wa security kutoka kwenye app yako, na hivyo kumwezesha attacker kuandika upya executable code ya app yako bila kugunduliwa. Tumia entitlements nyembamba zaidi ikiwezekana.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Entitlement hii huruhusu ku-mount nullfs file system (imezuiwa kwa default). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na chapisho hili la blogu, TCC permission hii kwa kawaida hupatikana katika mfumo wa:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ruhusu process **kuomba ruhusa zote za TCC**.

### **`kTCCServicePostEvent`**

Inaruhusu **kuingiza matukio bandia ya keyboard na mouse** katika mfumo mzima kupitia `CGEventPost()`. Process yenye ruhusa hii inaweza kuiga mibofyo ya keyboard, mibofyo ya mouse na matukio ya kusogeza katika application yoyote — hivyo kutoa **udhibiti wa mbali** wa desktop.

Hii ni hatari hasa inapounganishwa na `kTCCServiceAccessibility` au `kTCCServiceListenEvent`, kwa kuwa inaruhusu kusoma NA kuingiza input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Inaruhusu **intercepting all keyboard and mouse events** system-wide (input monitoring / keylogging). Process inaweza kusajili `CGEventTap` ili kunasa kila keystroke inayoandikwa katika application yoyote, ikijumuisha passwords, credit card numbers, na private messages.

Kwa mbinu za kina za exploitation tazama:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Inaruhusu **reading the display buffer** — kuchukua screenshots na kurekodi screen video ya application yoyote, ikijumuisha secure text fields. Ikiunganishwa na OCR, hii inaweza kutoa passwords na sensitive data kutoka kwenye screen automatically.

> [!WARNING]
> Kuanzia macOS Sonoma, screen capture huonyesha persistent menu bar indicator. Kwenye versions za zamani, screen recording inaweza kuwa completely silent.

### **`kTCCServiceCamera`**

Inaruhusu **capturing photos and video** kutoka kwenye built-in camera au USB cameras zilizounganishwa. Code injection kwenye binary yenye camera entitlement huwezesha silent visual surveillance.

### **`kTCCServiceMicrophone`**

Inaruhusu **recording audio** kutoka kwenye input devices zote. Background daemons zenye mic access hutoa persistent ambient audio surveillance bila application window inayoonekana.

### **`kTCCServiceLocation`**

Inaruhusu kuuliza **physical location** ya device kupitia Wi-Fi triangulation au Bluetooth beacons. Continuous monitoring hufichua anwani za nyumbani/kazini, travel patterns, na daily routines.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Access kwenye **Contacts** (majina, emails, simu — muhimu kwa spear-phishing), **Calendar** (ratiba za mikutano, attendee lists), na **Photos** (personal photos, screenshots ambazo zinaweza kuwa na credentials, location metadata).

Kwa mbinu kamili za credential theft exploitation kupitia TCC permissions, tazama:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** hudhoofisha App Sandbox kwa kuruhusu mawasiliano na system-wide Mach/XPC services ambazo sandbox kwa kawaida huzuia. Hii ndiyo **primary sandbox escape primitive** — app ya sandbox iliyo-compromise inaweza kutumia mach-lookup exceptions kufikia privileged daemons na ku-exploit XPC interfaces zao.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Kwa maelezo ya kina ya exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, tazama:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** huruhusu user-space driver binaries kuwasiliana moja kwa moja na kernel kupitia interfaces za IOKit. DriverKit binaries hudhibiti hardware: USB, Thunderbolt, PCIe, vifaa vya HID, audio, na networking.

Kuhatarisha DriverKit binary huwezesha:
- **Kernel attack surface** kupitia calls za `IOConnectCallMethod` zenye muundo hatari
- **USB device spoofing** (kuiga keyboard kwa ajili ya HID injection)
- **DMA attacks** kupitia interfaces za PCIe/Thunderbolt
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
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
