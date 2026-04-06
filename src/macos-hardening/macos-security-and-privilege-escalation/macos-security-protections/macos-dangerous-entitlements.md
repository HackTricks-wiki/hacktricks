# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Kumbuka kuwa entitlements zinazotangazwa na **`com.apple`** hazipatikani kwa third-parties, ni Apple tu wanaoweza kuzitoa... Au ikiwa unatumia enterprise certificate unaweza kuunda entitlements zako mwenyewe zinazotangazwa kwa **`com.apple`** na kwa kweli kupitisha ulinzi unaotegemea hili.

## High

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** inaruhusu **bypass SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** inaruhusu **bypass SIP**. Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Entitlement hii inaruhusu kupata **task port ya mchakato wowote**, isipokuwa kernel. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Entitlement hii inaruhusu mchakato mwingine mwenye entitlement `com.apple.security.cs.debugger` kupata task port ya mchakato unaoendeshwa na binary iliyo na entitlement hii na **ku-inject code** ndani yake. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps zenye Debugging Tool Entitlement zinaweza kuita `task_for_pid()` ili kupata task port halali kwa apps zisizotiwa saini na za third-party ambazo `Get Task Allow` imewekwa kuwa `true`. Hata hivyo, hata kwa debugging tool entitlement, debugger **hawezi kupata task ports** za michakato ambayo **haina `Get Task Allow` entitlement**, na ambayo kwa hivyo zina lindwa na System Integrity Protection. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Entitlement hii inaruhusu **ku-load frameworks, plug-ins, au libraries bila kuhitaji kuwa zimetia saini na Apple au kuwa zimeitwa kwa Team ID sawa** na executable kuu, hivyo mshambuliaji anaweza kutumia mzigo wowote wa library ili ku-inject code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Entitlement hii ni sawa sana na **`com.apple.security.cs.disable-library-validation`** lakini **badala ya kuizima validation ya library moja kwa moja**, inaruhusu mchakato **kuitisha system call ya `csops` ili kuizima**.\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Entitlement hii inaruhusu kutumia **DYLD environment variables** ambazo zinaweza kutumika ku-inject libraries na code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), entitlements hizi zinaruhusu **kurekebisha** database ya **TCC**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Entitlements hizi zinaruhusu **kusakinisha software bila kuuliza ruhusa kwa mtumiaji**, jambo ambalo linaweza kusaidia katika **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement inahitajika kuomba **kernel i-load kernel extension**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** inawezesha kuwasiliana na XPC service `com.apple.iCloudHelper` ambayo itatoa **iCloud tokens**.

**iMovie** na **Garageband** zilikuwa na entitlement hii.

Kwa **maelezo zaidi** kuhusu exploit ya **kupata iCloud tokens** kutoka entitlement hiyo angalia hotuba: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Sijui hili linaruhusu kufanya nini

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Katika [**hii report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) imetajwa kuwa hii inaweza kutumika kusasisha vitu vilivyolindwa na SSV baada ya reboot. Ikiwa unajua jinsi, tuma PR tafadhali!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Katika [**hii report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) imetajwa kuwa hii inaweza kutumika kusasisha vitu vilivyolindwa na SSV baada ya reboot. Ikiwa unajua jinsi, tuma PR tafadhali!

### `keychain-access-groups`

Entitlement hii inaorodhesha vikundi vya **keychain** ambavyo application ina ufikiaji kwa:
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

Hutoa ruhusa za **Full Disk Access**, moja ya ruhusa za juu zaidi za TCC unazoweza kuwa nazo.

### **`kTCCServiceAppleEvents`**

Inaruhusu app kutuma matukio kwa programu nyingine ambazo kawaida zinatumika kuendesha kazi kiotomatiki. Ikiwa itadhibiti programu nyingine, inaweza kutumia vibaya ruhusa zilizotolewa kwa programu hizo.

Kwa mfano, kuwalazimisha waulize mtumiaji nywila yake:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Au kuwafanya wafanye **vitendo vya hiari**.

### **`kTCCServiceEndpointSecurityClient`**

Inaruhusu, miongoni mwa ruhusa nyingine, **kuandika databasi ya TCC ya watumiaji**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji ambayo hubadilisha njia ya folda yake ya nyumbani na kwa hivyo inaruhusu **kuvuka TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Inaruhusu kubadilisha faili ndani ya apps bundle (ndani ya app.app), ambayo ni **hairuhusiwi kwa chaguo-msingi**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Inawezekana kuangalia nani ana upatikanaji huu katika _System Settings_ > _Privacy & Security_ > _App Management_.

### `kTCCServiceAccessibility`

Mchakato utakuwa na uwezo wa **kutumia vibaya vipengele vya accessibility vya macOS**, ambayo inamaanisha, kwa mfano, atakuwa na uwezo wa kubonyeza vibonye vya kibodi. Hivyo anaweza kuomba ruhusa za kudhibiti app kama Finder na kuidhinisha dialog kwa ruhusa hii.

## Ruhusa zinazohusiana na Trustcache/CDhash

Kuna ruhusa ambazo zinaweza kutumika kuvuka ulinzi wa Trustcache/CDhash, ambao unazuia utekelezaji wa toleo lililopunguzwa la binary za Apple.

## Wastani

### `com.apple.security.cs.allow-jit`

Ruhusa hii inaruhusu **kuunda kumbukumbu inayoweza kuandikwa na kutekelezwa** kwa kupitisha bendera ya `MAP_JIT` kwa mfumo wa `mmap()`. Angalia [**hii kwa habari zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Ruhusa hii inaruhusu **kubadilisha au ku-patch msimbo wa C**, kutumia `NSCreateObjectFileImageFromMemory` iliyokataliwa kwa muda mrefu (ambayo kwa msingi si salama), au kutumia framework ya **DVDPlayback**. Angalia [**hii kwa habari zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Kuingiza ruhusa hii kunaonyesha app yako kwa udhaifu wa kawaida katika lugha zisizo salama kwa kumbukumbu. Fikiria kwa umakini ikiwa app yako inahitaji msamaha huu.

### `com.apple.security.cs.disable-executable-page-protection`

Ruhusa hii inaruhusu **kubadilisha sehemu za faili zake za executable** kwenye diski ili kulazimisha kutolewa. Angalia [**hii kwa habari zaidi**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Disable Executable Memory Protection Entitlement ni ruhusa kali inayotoa ulinzi wa msingi kutoka kwa app yako, ikifanya iwezekane kwa mshukiwa kuandika upya msimbo wa executable wa app yako bila kugunduliwa. Pendelea ruhusa ndogo zaidi inapowezekana.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Ruhusa hii inaruhusu ku-mount mfumo wa faili wa nullfs (almazuiwa kwa chaguo-msingi). Chombo: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Kulingana na chapisho hili la blogi, ruhusa hii ya TCC kwa kawaida hupatikana kwa fomu:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Ruhusu mchakato **kuomba ruhusa zote za TCC**.

### **`kTCCServicePostEvent`**

Inaruhusu **kuingiza matukio bandia ya kibodi na panya** kwa mfumo mzima kupitia `CGEventPost()`. Mchakato uliyo na ruhusa hii unaweza kuiga mabofyo ya kibodi, bonyezo za panya, na matukio ya kusogeza katika programu yoyote — kwa ufanisi ukitoa **udhibiti wa mbali** wa desktop.

Hii ni hatari hasa ikishirikishwa na `kTCCServiceAccessibility` au `kTCCServiceListenEvent`, kwani inaruhusu kusoma NA kuingiza pembejeo.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Inaruhusu **kuingilia/kunasa matukio yote ya kibodi na panya kwenye mfumo mzima** (input monitoring / keylogging). Mchakato unaweza kusajili `CGEventTap` ili kunasa kila bonyezo la kibodi linaloandikwa katika programu yoyote, ikiwa ni pamoja na nywila, namba za kadi za mkopo, na ujumbe wa faragha.

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Inaruhusu **kusoma display buffer** — kuchukua picha za skrini na kurekodi video za skrini za programu yoyote, ikijumuisha sehemu za maandishi zilizo salama. Ikiunganishwa na OCR, hii inaweza kutoa kwa moja nywila na data nyeti kutoka kwenye skrini.

> [!WARNING]
> Kuanzia macOS Sonoma, screen capture inaonyesha kiashirio cha kudumu kwenye menu bar. Kwa matoleo ya zamani, kurekodi skrini kunaweza kukaa kimya kabisa.

### **`kTCCServiceCamera`**

Inaruhusu **kunasa picha na video** kutoka kwa kamera ya ndani au kamera za USB zilizounganishwa. Code injection katika binary yenye haki za kamera inaweza kuwezesha ufuatiliaji wa kuona bila sauti.

### **`kTCCServiceMicrophone`**

Inaruhusu **kurekodi sauti** kutoka kwa vifaa vyote vya kuingiza. Background daemons zenye upatikanaji wa mic hutoa ufuatiliaji wa sauti wa mazingira unaodumu bila dirisha la programu linaloonekana.

### **`kTCCServiceLocation`**

Inaruhusu kuuliza eneo la kifaa **kimwili** kwa kutumia triangulation ya Wi‑Fi au beacons za Bluetooth. Ufuatiliaji wa kudumu unafunua anwani za nyumbani/kazi, mifumo ya kusafiri, na ratiba za kila siku.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Ufikiaji wa **Contacts** (majina, barua pepe, nambari za simu — muhimu kwa spear-phishing), **Calendar** (ratiba za mikutano, orodha ya washiriki), na **Photos** (picha za kibinafsi, screenshots ambazo zinaweza kuwa na nywila, metadata ya eneo).

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** zinaudhoofisha App Sandbox kwa kuruhusu mawasiliano na huduma za mfumo mzima za Mach/XPC ambazo sandbox kawaida hupiga. Hii ni the **primary sandbox escape primitive** — app iliyoharibiwa ndani ya sandbox inaweza kutumia mach-lookup exceptions kufikia daemons zenye vipaumbele na ku-exploit interfaces zao za XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Kwa mfululizo wa kina wa exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, angalia:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** zinawezesha user-space driver binaries kuwasiliana moja kwa moja na kernel kupitia interfaces za IOKit. Binaries za DriverKit husimamia hardware: USB, Thunderbolt, PCIe, HID devices, audio, na networking.

Kuharibu binary ya DriverKit kunaweza kuruhusu:
- **Kernel attack surface** kupitia miito isiyo sahihi ya `IOConnectCallMethod`
- **USB device spoofing** (kuiga keyboard kwa ajili ya HID injection)
- **DMA attacks** kupitia interfaces za PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Kwa maelezo ya kina kuhusu IOKit/DriverKit exploitation, angalia:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
