# Entitlements Hatari za macOS na ruhusa za TCC

{{#include ../../../banners/hacktricks-training.md}}

Entitlements hutangaza uwezo na vighairi vya usalama ambavyo mfumo wa uendeshaji huwapa code iliyotiwa saini. Maingizo yaliyo hapa chini yanaangazia yale yenye manufaa hasa wakati wa ukaguzi wa offensive.<sup>[[13]](#references)</sup>

> [!WARNING]
> Kumbuka kuwa entitlements zinazoanza na **`com.apple`** hazipatikani kwa third-parties; Apple pekee inaweza kuzipa... Au ikiwa unatumia enterprise certificate, unaweza kuunda entitlements zako zinazoanza na **`com.apple`** na kwa kweli ukakwepa protections zinazotegemea hili.

## High

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** inaruhusu process **kuepuka SIP**. Angalia [hapa kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** inaruhusu process **kuepuka SIP**. Angalia [hapa kwa maelezo zaidi](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (hapo awali iliitwa `task_for_pid-allow`)**

Entitlement hii inaruhusu process kupata **task port ya process yoyote** isipokuwa kernel. Angalia [**hapa kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Entitlement hii inaruhusu processes nyingine zilizo na entitlement **`com.apple.security.cs.debugger`** kupata task port ya process inayoendeshwa na binary yenye entitlement hii na **kuingiza code ndani yake**. Angalia [**hapa kwa maelezo zaidi**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps zilizo na Debugging Tool Entitlement zinaweza kuita `task_for_pid()` ili kupata task port halali ya apps ambazo hazijasainiwa na third-party apps zilizo na entitlement ya `Get Task Allow` iliyowekwa kuwa `true`. Hata hivyo, hata ikiwa na debugging tool entitlement, debugger **haiwezi kupata task ports** za processes ambazo **hazina entitlement ya `Get Task Allow`**, na hivyo zinalindwa na System Integrity Protection. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Entitlement hii inaruhusu application **kupakia frameworks, plug-ins au libraries bila kuhitaji zisainiwe na Apple au ziwe na Team ID sawa** na executable kuu, hivyo attacker anaweza kutumia vibaya library load ya kiholela ili kuingiza code. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Entitlement hii inafanana sana na **`com.apple.security.cs.disable-library-validation`**, lakini **badala ya kuzima** library validation **moja kwa moja**, inaruhusu process **kuita system call ya `csops` ili kuizima** wakati wa runtime.

Jina la entitlement limewekwa moja kwa moja kwenye XNU karibu na operation ya `csops` inayotumia entitlement hiyo:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
Handler wa kernel wa `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) unaonyesha kwa usahihi jinsi primitive ilivyo finyu:<sup>[[2]](#references)</sup>
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
- Hufanya kazi kwenye **mchakato wenyewe tu** (`forself == 1`) — huwezi kuondoa library validation kutoka kwenye mchakato mwingine kwa kutumia hii.
- Inahitaji mchakato **uwe na entitlement hiyo**, na hukataa ikiwa mchakato umewekewa alama `CS_INSTALLER` au unaendeshwa chini ya subsystem root path.
- Huondoa **`CS_REQUIRE_LV | CS_FORCED_LV`** kwenye code-signing flags za mchakato.

Maelezo ya XNU yanafafanua matumizi yaliyokusudiwa, na pia kwa nini ni ya kuvutia kwa attacker:

> Chaguo hili hutumika kuondoa library validation kutoka kwenye mchakato unaoendelea kufanya kazi. Hutumika katika plugin architectures wakati programu inahitaji kupakia libraries zisizoaminika. [...] Baada ya mchakato kupakia library isiyoaminika, kutegemea library validation baadaye hakutakuwa na ufanisi.

Kwa maneno mengine, **binary yoyote iliyo na entitlement hii ni dylib-injection target**: fanya code iendeshe ndani yake (au ishawishi ipakie plug-in yako) baada ya kuondoa `CS_REQUIRE_LV`, kisha unarithi kila kitu ambacho host process inaaminiwa kufanya.

### `com.apple.security.cs.allow-dyld-environment-variables`

Entitlement hii inaruhusu **kutumia DYLD environment variables** ambazo zinaweza kutumiwa ku-inject libraries na code. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` au `com.apple.rootless.storage`.`TCC`

[**Kulingana na blogu hii**](https://objective-see.org/blog/blog_0x4C.html) **na** [**blogu hii**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), entitlements hizi huruhusu mchakato **kurekebisha** database ya **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### Authorization rights **`system.install.apple-software`** na **`system.install.apple-software.standard-user`**

Haki hizi za Authorization Services hudhibiti usakinishaji wa software iliyotolewa na Apple. Mchakato uliopewa entitlement ya kuzipata unaweza kupita authorization flow ya kawaida, jambo ambalo linaweza kusaidia katika **privilege escalation**.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

Entitlement inayohitajika kuomba **kernel ipakie kernel extension**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** huwezesha kuwasiliana na **`com.apple.iCloudHelper`** XPC service, ambayo **hutoa iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii.

Kwa **maelezo** zaidi kuhusu exploit ya **kupata icloud tokens** kupitia entitlement hiyo, angalia talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui hii inaruhusu kufanya nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Report hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) inataja kwamba entitlement hii inaweza kutumiwa kusasisha contents zinazolindwa na SSV baada ya reboot. Ikiwa unajua jinsi, tafadhali tuma PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Report hiyo hiyo**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) inataja kwamba kuunda sealed snapshot kunaweza kutumiwa kusasisha contents zinazolindwa na SSV baada ya reboot. Ikiwa unajua jinsi, tafadhali tuma PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Entitlement hii huorodhesha groups za **keychain** ambazo application ina access nazo:
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

Huruhusu app kutuma events kwa applications nyingine ambazo hutumiwa kwa kawaida **automating tasks**. Kwa kudhibiti apps nyingine, inaweza kutumia vibaya ruhusa walizopewa apps hizo nyingine.

Kwa mfano, kuzifanya zimwombe mtumiaji nenosiri lake:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Au kuwafanya kutekeleza **vitendo holela**.

### **`kTCCServiceEndpointSecurityClient`**

Huruhusu, miongoni mwa ruhusa nyingine, **kuandika database ya TCC ya mtumiaji**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Huruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji, jambo linalobadilisha njia ya folda yake ya nyumbani na hivyo kuruhusu **kuepuka TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Huruhusu kurekebisha faili zilizo ndani ya app bundles (ndani ya app.app), jambo ambalo **limezuiwa kwa chaguo-msingi**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia ni nani aliye na access hii katika _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Mchakato utaweza **kutumia vibaya vipengele vya accessibility vya macOS**, ambayo ina maana kwamba, kwa mfano, utaweza kubonyeza vitufe. Kwa hiyo unaweza kuomba access ya kudhibiti app kama Finder na kuidhinisha dialog kwa kutumia ruhusa hii.

## Entitlements zinazohusiana na Trustcache/CDhash

Kuna entitlements kadhaa ambazo zinaweza kutumiwa kuepuka ulinzi wa Trustcache/CDhash, unaozuia utekelezaji wa matoleo yaliyopunguzwa hadhi ya Apple binaries.

## Wastani

### `com.apple.security.cs.allow-jit`

Entitlement hii huruhusu mchakato **kuunda memory inayoweza kuandikwa na kutekelezwa** kwa kupitisha flag ya `MAP_JIT` kwenye system function ya `mmap()`. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Entitlement hii huruhusu **kubadilisha au kupachika patch kwenye C code**, kutumia **`NSCreateObjectFileImageFromMemory`** ambayo imepitwa na wakati kwa muda mrefu (na kimsingi si salama), au kutumia framework ya **DVDPlayback**. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Kujumuisha entitlement hii huweka app yako katika hatari ya vulnerabilities za kawaida katika lugha za kuandika code zisizo salama kwa memory. Fikiria kwa makini ikiwa app yako inahitaji exception hii.

### `com.apple.security.cs.disable-executable-page-protection`

Entitlement hii huruhusu **kubadilisha sections za executable files zake yenyewe** kwenye disk ili kulazimisha kutoka. Angalia [**hapa kwa maelezo zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Entitlement ya Disable Executable Memory Protection ni entitlement kali sana inayoondoa ulinzi wa msingi wa security kutoka kwenye app yako, na hivyo kumwezesha attacker kuandika upya executable code ya app yako bila kugunduliwa. Tumia entitlements nyembamba zaidi inapowezekana.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Entitlement hii huruhusu kuweka nullfs file system (imezuiwa kwa chaguo-msingi). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na blogpost hii, ruhusa hii ya TCC kwa kawaida hupatikana katika mfumo wa:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ruhusu mchakato **kuomba ruhusa zote za TCC**.

### **`kTCCServicePostEvent`**

Huruhusu **kuingiza matukio bandia ya kibodi na kipanya** kote kwenye mfumo kupitia `CGEventPost()`. Mchakato wenye ruhusa hii unaweza kuiga mibofyo ya vitufe, mibofyo ya kipanya na matukio ya kusogeza katika programu yoyote — hivyo kutoa **udhibiti wa mbali** wa desktop.

Hii ni hatari hasa inapounganishwa na `kTCCServiceAccessibility` au `kTCCServiceListenEvent`, kwa kuwa huruhusu kusoma NA kuingiza input.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Inaruhusu **kunasa matukio yote ya kibodi na kipanya** kwenye mfumo mzima (ufuatiliaji wa ingizo / keylogging). Mchakato unaweza kusajili `CGEventTap` ili kunasa kila kibonyezo kinachoandikwa katika programu yoyote, ikiwemo nywila, nambari za kadi za mkopo, na ujumbe wa faragha.

Kwa mbinu za kina za exploitation tazama:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Inaruhusu **kusoma display buffer** — kupiga screenshots na kurekodi video ya skrini ya programu yoyote, ikiwemo sehemu salama za kuingiza maandishi. Ikiunganishwa na OCR, hii inaweza kutoa kiotomatiki nywila na data nyeti kutoka kwenye skrini.

> [!WARNING]
> Kuanzia macOS Sonoma, screen capture huonyesha kiashiria kinachoendelea kuwepo kwenye menu bar. Kwenye matoleo ya zamani, screen recording inaweza kufanyika kimya kabisa.

### **`kTCCServiceCamera`**

Inaruhusu **kunasa picha na video** kutoka kwa kamera iliyojengwa ndani au kamera za USB zilizounganishwa. Code injection kwenye binary iliyopewa ruhusa ya kutumia kamera huwezesha ufuatiliaji wa kimya wa picha.

### **`kTCCServiceMicrophone`**

Inaruhusu **kurekodi sauti** kutoka kwa vifaa vyote vya kuingiza sauti. Background daemons zilizo na ufikiaji wa mic hutoa ufuatiliaji endelevu wa sauti za mazingira bila dirisha lolote la programu linaloonekana.

### **`kTCCServiceLocation`**

Inaruhusu kuulizia **mahali halisi** pa kifaa kupitia triangulation ya Wi-Fi au Bluetooth beacons. Ufuatiliaji endelevu hufichua anwani za nyumbani/kazini, mifumo ya usafiri, na ratiba za kila siku.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Ufikiaji wa **Contacts** (majina, barua pepe, simu — muhimu kwa spear-phishing), **Calendar** (ratiba za mikutano, orodha za washiriki), na **Photos** (picha za kibinafsi, screenshots ambazo zinaweza kuwa na credentials, metadata ya eneo).

Kwa mbinu kamili za credential theft exploitation kupitia ruhusa za TCC, tazama:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements za Sandbox & Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** hudhoofisha App Sandbox kwa kuruhusu mawasiliano na huduma za Mach/XPC za mfumo mzima ambazo sandbox kwa kawaida huzuia. Hii ndiyo **primitive kuu ya sandbox escape** — programu iliyoathiriwa iliyo ndani ya sandbox inaweza kutumia mach-lookup exceptions kufikia privileged daemons na kutumia vibaya interfaces zao za XPC.
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

**DriverKit entitlements** huruhusu user-space driver binaries kuwasiliana moja kwa moja na kernel kupitia interfaces za IOKit. DriverKit binaries husimamia hardware: USB, Thunderbolt, PCIe, HID devices, audio, na networking.

Kompromi ya DriverKit binary huwezesha:
- **Kernel attack surface** kupitia `IOConnectCallMethod` calls zilizoundwa vibaya
- **USB device spoofing** (kuiga keyboard kwa HID injection)
- **DMA attacks** kupitia PCIe/Thunderbolt interfaces
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Kwa maelezo ya kina kuhusu exploitation ya IOKit/DriverKit, angalia:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (operesheni za `CS_OPS_*` na `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (handler ya `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement ya Debugging Tool (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement ya Kuzima Library Validation](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement ya Kuruhusu DYLD Environment Variables](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Jinamizi la Apple's OTA Update: Bypassing the Signature Verification and Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement ya Kuruhusu Utekelezaji wa JIT-compiled Code (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement ya Kuruhusu Unsigned Executable Memory](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement ya Kuzima Executable Memory Protection](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Mwongozo wa Kuprogramu Authorization Services](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
