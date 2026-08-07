# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> ध्यान दें कि **`com.apple`** से शुरू होने वाले entitlements third-parties के लिए उपलब्ध नहीं हैं, इन्हें केवल Apple grant कर सकता है... या यदि आप enterprise certificate का उपयोग कर रहे हैं, तो आप वास्तव में **`com.apple`** से शुरू होने वाले अपने entitlements बना सकते हैं और इसके आधार पर protections को bypass कर सकते हैं।

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement **SIP को bypass** करने की अनुमति देता है। अधिक जानकारी के लिए [यह देखें](macos-sip.md#com.apple.rootless.install.heritable)।

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement **SIP को bypass** करने की अनुमति देता है। अधिक जानकारी के लिए [यह देखें](macos-sip.md#com.apple.rootless.install)।

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

यह entitlement kernel को छोड़कर **किसी भी** process के लिए **task port प्राप्त** करने की अनुमति देता है। [अधिक जानकारी के लिए **यह देखें**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)।

### `com.apple.security.get-task-allow`

यह entitlement, **`com.apple.security.cs.debugger`** entitlement वाले अन्य processes को इस entitlement वाले binary द्वारा चलाए गए process का task port प्राप्त करने और **उसमें code inject करने** की अनुमति देता है। [अधिक जानकारी के लिए **यह देखें**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)।

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement वाले apps unsigned और third-party apps के लिए `task_for_pid()` call करके एक valid task port प्राप्त कर सकते हैं, जिनमें `Get Task Allow` entitlement `true` पर set हो। हालांकि, debugging tool entitlement होने पर भी debugger उन processes के **task ports प्राप्त नहीं कर सकता** जिनमें **`Get Task Allow` entitlement नहीं है**, और जो इसलिए System Integrity Protection द्वारा protected हैं। [**अधिक जानकारी के लिए यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

यह entitlement frameworks, plug-ins या libraries को **Apple द्वारा signed या main executable के समान Team ID से signed हुए बिना load करने** की अनुमति देता है, इसलिए attacker code inject करने के लिए किसी arbitrary library load का abuse कर सकता है। [**अधिक जानकारी के लिए यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

यह entitlement **`com.apple.security.cs.disable-library-validation`** के समान है, लेकिन library validation को **सीधे disable करने** के बजाय, यह process को runtime पर इसे disable करने के लिए **एक `csops` system call call करने** की अनुमति देता है।

Entitlement name XNU में उस `csops` operation के पास hardcoded है जो इसका उपयोग करता है:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) के लिए kernel handler स्पष्ट रूप से दिखाता है कि यह primitive कितना सीमित है:<sup>[[2]](#references)</sup>
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
तो operation:

- केवल **macOS-only** है (हर दूसरे platform पर `ENOTSUP`)।
- केवल **itself** (`forself == 1`) पर काम करता है — इसके द्वारा किसी अन्य process से library validation हटाना संभव नहीं है।
- Process के पास वास्तव में **entitlement** होना आवश्यक है, और यदि process पर `CS_INSTALLER` flag लगा हो या वह subsystem root path के अंतर्गत चल रहा हो, तो यह मना कर देता है।
- Process के code-signing flags से **`CS_REQUIRE_LV | CS_FORCED_LV`** हटा देता है।

XNU comment इसके intended use case को समझाता है और यह भी बताता है कि attacker के लिए यह interesting क्यों है:

> इस option का उपयोग किसी running process से library validation हटाने के लिए किया जाता है। इसका उपयोग plugin architectures में किया जाता है, जब किसी program को untrusted libraries load करने की आवश्यकता होती है। [...] एक बार जब process untrusted library load कर लेता है, तो भविष्य में library validation पर निर्भर रहना प्रभावी नहीं होगा।

दूसरे शब्दों में, **इस entitlement वाली कोई भी binary dylib-injection target है**: इसके अंदर code चलाएं (या इसे अपना plug-in load करने के लिए तैयार करें), इसके `CS_REQUIRE_LV` हटाने के बाद, और आपको host process को प्राप्त सभी trusted actions विरासत में मिल जाते हैं।

### `com.apple.security.cs.allow-dyld-environment-variables`

यह entitlement **DYLD environment variables का उपयोग करने** की अनुमति देता है, जिनका उपयोग libraries और code inject करने के लिए किया जा सकता है। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)।<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**इस blog के अनुसार**](https://objective-see.org/blog/blog_0x4C.html) **और** [**इस blog के अनुसार**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ये entitlements **TCC** database को **modify** करने की अनुमति देते हैं।<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

ये entitlements user से **permissions पूछे बिना software install** करने की अनुमति देते हैं, जो **privilege escalation** में उपयोगी हो सकता है।

### `com.apple.private.security.kext-management`

**kernel extension load करने** के लिए **kernel से request करने** हेतु आवश्यक entitlement।

### **`com.apple.private.icloud-account-access`**

इस entitlement **`com.apple.private.icloud-account-access`** के साथ **`com.apple.iCloudHelper`** XPC service से communicate करना संभव है, जो **iCloud tokens provide** करेगा।

**iMovie** और **Garageband** के पास यह entitlement था।

इस entitlement से **iCloud tokens प्राप्त करने** वाले exploit के बारे में अधिक **information** के लिए यह talk देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: मुझे नहीं पता कि इससे क्या किया जा सकता है

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**इस report में**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **उल्लेख किया गया है कि इसका उपयोग** reboot के बाद SSV-protected contents को update करने के लिए किया जा सकता है। यदि आपको पता है कि यह कैसे काम करता है, तो कृपया PR भेजें!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**इस report में**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **उल्लेख किया गया है कि इसका उपयोग** reboot के बाद SSV-protected contents को update करने के लिए किया जा सकता है। यदि आपको पता है कि यह कैसे काम करता है, तो कृपया PR भेजें!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

यह entitlement उन **keychain** groups की list देता है, जिन तक application की access है:
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

**Full Disk Access** permissions देता है, जो TCC में मिलने वाली सबसे उच्च permissions में से एक है।

### **`kTCCServiceAppleEvents`**

App को आमतौर पर **automating tasks** के लिए उपयोग किए जाने वाले अन्य applications को events भेजने की अनुमति देता है। अन्य apps को नियंत्रित करके, यह उन apps को दी गई permissions का दुरुपयोग कर सकता है।

उदाहरण के लिए, उनसे user से उसका password पूछने के लिए कहना:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
या उन्हें **arbitrary actions** करने के लिए बाध्य करना।

### **`kTCCServiceEndpointSecurityClient`**

अन्य permissions के अलावा, यह **users के TCC database में write** करने की अनुमति देता है।

### **`kTCCServiceSystemPolicySysAdminFiles`**

यह किसी user के **`NFSHomeDirectory`** attribute को **change** करने की अनुमति देता है, जिससे उसका home folder path बदल जाता है और इसलिए **TCC को bypass** किया जा सकता है।

### **`kTCCServiceSystemPolicyAppBundles`**

यह app bundles (app.app के अंदर) की files को modify करने की अनुमति देता है, जो default रूप से **disallowed** है।

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

यह _System Settings_ > _Privacy & Security_ > _App Management_ में check करना संभव है कि किसके पास यह access है।

### `kTCCServiceAccessibility`

Process **macOS accessibility features का abuse** कर सकेगा, जिसका अर्थ है कि उदाहरण के लिए वह keystrokes press कर सकेगा। इसलिए वह Finder जैसे app को control करने के लिए access request कर सकता है और इस permission से dialog को approve कर सकता है।

## Trustcache/CDhash related entitlements

कुछ entitlements हैं जिनका उपयोग Trustcache/CDhash protections को bypass करने के लिए किया जा सकता है, जो Apple binaries के downgraded versions के execution को रोकते हैं।

## मध्यम

### `com.apple.security.cs.allow-jit`

यह entitlement `mmap()` system function में `MAP_JIT` flag pass करके **writable और executable memory create** करने की अनुमति देता है। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)।<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

यह entitlement **C code को override या patch** करने, लंबे समय से deprecated **`NSCreateObjectFileImageFromMemory`** (जो मूल रूप से insecure है) का उपयोग करने, या **DVDPlayback** framework का उपयोग करने की अनुमति देता है। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)।<sup>[[11]](#references)</sup>

> [!CAUTION]
> इस entitlement को शामिल करने से आपका app memory-unsafe code languages की common vulnerabilities के प्रति exposed हो जाता है। ध्यानपूर्वक विचार करें कि क्या आपके app को इस exception की आवश्यकता है।

### `com.apple.security.cs.disable-executable-page-protection`

यह entitlement forcefully exit करने के लिए disk पर अपनी executable files के **sections को modify** करने की अनुमति देता है। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)।<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement एक extreme entitlement है, जो आपके app से एक fundamental security protection हटा देता है और attacker के लिए बिना detection के आपके app के executable code को rewrite करना संभव बनाता है। यदि संभव हो तो narrower entitlements को प्राथमिकता दें।

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

यह entitlement nullfs file system को mount करने की अनुमति देता है (default रूप से forbidden)। Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

इस blogpost के अनुसार, यह TCC permission आमतौर पर इस रूप में पाई जाती है:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Process को **सभी TCC permissions के लिए पूछने** की अनुमति देता है।

### **`kTCCServicePostEvent`**

`CGEventPost()` के माध्यम से system-wide **synthetic keyboard और mouse events inject** करने की अनुमति देता है। इस permission वाला process किसी भी application में keystrokes, mouse clicks और scroll events simulate कर सकता है — प्रभावी रूप से desktop का **remote control** प्रदान करता है।

यह `kTCCServiceAccessibility` या `kTCCServiceListenEvent` के साथ combined होने पर विशेष रूप से dangerous है, क्योंकि इससे input को पढ़ना AND inject करना दोनों संभव हो जाता है।
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

System-wide **सभी keyboard और mouse events को intercept करने** की अनुमति देता है (input monitoring / keylogging)। कोई process हर application में टाइप की गई प्रत्येक keystroke को capture करने के लिए `CGEventTap` register कर सकता है, जिसमें passwords, credit card numbers और private messages भी शामिल हैं।

विस्तृत exploitation techniques के लिए देखें:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**Display buffer पढ़ने** की अनुमति देता है — किसी भी application के screenshots लेने और screen video record करने की, जिसमें secure text fields भी शामिल हैं। OCR के साथ combined होने पर, यह screen से passwords और sensitive data को automatically extract कर सकता है।

> [!WARNING]
> macOS Sonoma से शुरू होकर, screen capture एक persistent menu bar indicator दिखाता है। पुराने versions में, screen recording पूरी तरह silent हो सकती है।

### **`kTCCServiceCamera`**

Built-in camera या connected USB cameras से photos और video **capture करने** की अनुमति देता है। Camera-entitled binary में code injection silent visual surveillance enable करता है।

### **`kTCCServiceMicrophone`**

सभी input devices से audio **record करने** की अनुमति देता है। Mic access वाले background daemons बिना किसी visible application window के persistent ambient audio surveillance उपलब्ध कराते हैं।

### **`kTCCServiceLocation`**

Wi-Fi triangulation या Bluetooth beacons के माध्यम से device की **physical location** query करने की अनुमति देता है। Continuous monitoring से home/work addresses, travel patterns और daily routines का पता चलता है।

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts** (names, emails, phones — spear-phishing के लिए उपयोगी), **Calendar** (meeting schedules, attendee lists) और **Photos** (personal photos, credentials वाली screenshots, location metadata) तक access।

TCC permissions के माध्यम से complete credential theft exploitation techniques के लिए देखें:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** App Sandbox को weaken करते हैं, क्योंकि वे system-wide Mach/XPC services के साथ communication की अनुमति देते हैं, जिन्हें sandbox normally block करता है। यह **primary sandbox escape primitive** है — compromised sandboxed app privileged daemons तक पहुँचने और उनके XPC interfaces को exploit करने के लिए mach-lookup exceptions का उपयोग कर सकता है।
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
विस्तृत exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape के लिए देखें:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** user-space driver binaries को IOKit interfaces के माध्यम से सीधे kernel से communicate करने की अनुमति देते हैं। DriverKit binaries hardware को manage करती हैं: USB, Thunderbolt, PCIe, HID devices, audio और networking।

किसी DriverKit binary को compromise करने से सक्षम होता है:
- malformed `IOConnectCallMethod` calls के माध्यम से **Kernel attack surface**
- **USB device spoofing** (HID injection के लिए keyboard emulate करना)
- PCIe/Thunderbolt interfaces के माध्यम से **DMA attacks**
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
विस्तृत IOKit/DriverKit exploitation के लिए, देखें:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## संदर्भ

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations और `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: TCC Bypass](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — संगीत चलाएं और TCC Bypass करें, उर्फ CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "आपके Mac पर होने वाली बातें, क्या Apple's iCloud पर रहती हैं?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple के OTA Update का Nightmare: Signature Verification को Bypass करना और Kernel को Pwn करना](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
