# macOS Dangerous Entitlements और TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements उन capabilities और security exceptions की घोषणा करते हैं जिन्हें operating system signed code को प्रदान करता है। नीचे दी गई entries उन entitlements पर केंद्रित हैं जो offensive review के दौरान विशेष रूप से उपयोगी हैं।<sup>[[13]](#references)</sup>

> [!WARNING]
> ध्यान दें कि **`com.apple`** से शुरू होने वाले entitlements third-parties के लिए उपलब्ध नहीं हैं, इन्हें केवल Apple grant कर सकता है... या यदि आप enterprise certificate का उपयोग कर रहे हैं, तो वास्तव में अपने स्वयं के **`com.apple`** से शुरू होने वाले entitlements बना सकते हैं और इस आधार पर protections को bypass कर सकते हैं।

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement किसी process को **SIP bypass** करने की अनुमति देता है। अधिक जानकारी के लिए [यह देखें](macos-sip.md#com.apple.rootless.install.heritable)।

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement किसी process को **SIP bypass** करने की अनुमति देता है। अधिक जानकारी के लिए [यह देखें](macos-sip.md#com.apple.rootless.install)।

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

यह entitlement किसी process को kernel को छोड़कर **किसी भी** process का **task port** प्राप्त करने की अनुमति देता है। [**अधिक जानकारी के लिए यह देखें**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)।

### `com.apple.security.get-task-allow`

यह entitlement ऐसे अन्य processes को, जिनके पास **`com.apple.security.cs.debugger`** entitlement है, इस entitlement वाले binary द्वारा चलाए गए process का task port प्राप्त करने और **उसमें code inject करने** की अनुमति देता है। [**अधिक जानकारी के लिए यह देखें**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)।

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement वाले apps, `task_for_pid()` को call करके उन unsigned और third-party apps के लिए valid task port प्राप्त कर सकते हैं जिनमें `Get Task Allow` entitlement `true` पर set है। हालांकि, debugging tool entitlement के साथ भी debugger उन processes के **task ports प्राप्त नहीं कर सकता** जिनमें **`Get Task Allow` entitlement नहीं है**, और इसलिए वे System Integrity Protection द्वारा protected हैं। [**अधिक जानकारी के लिए यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)।<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

यह entitlement किसी application को **frameworks, plug-ins या libraries load करने** की अनुमति देता है, बिना यह आवश्यक किए कि वे Apple द्वारा या main executable के समान Team ID के साथ signed हों। इसलिए attacker code inject करने के लिए arbitrary library load का abuse कर सकता है। [**अधिक जानकारी के लिए यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)।<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

यह entitlement **`com.apple.security.cs.disable-library-validation`** के समान है, लेकिन library validation को **सीधे disable करने** के बजाय यह process को runtime पर इसे disable करने के लिए **`csops` system call call करने** की अनुमति देता है।

Entitlement का नाम XNU में उस `csops` operation के पास hardcoded है जो इसका उपयोग करता है:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) के लिए kernel handler दिखाता है कि यह primitive वास्तव में कितना सीमित है:<sup>[[2]](#references)</sup>
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
इसलिए यह operation:

- केवल **macOS-only** है (हर दूसरे platform पर `ENOTSUP`)।
- केवल **खुद पर** काम करता है (`forself == 1`) — इसके जरिए किसी अन्य process से library validation हटाना संभव नहीं है।
- Process के पास वास्तव में **entitlement होना** आवश्यक है, और यदि process पर `CS_INSTALLER` flag लगा हो या वह subsystem root path के अंतर्गत चल रहा हो, तो यह मना कर देता है।
- Process के code-signing flags से **`CS_REQUIRE_LV | CS_FORCED_LV`** हटाता है।

XNU comment इसके intended use case को समझाता है और यह भी बताता है कि attacker के लिए यह क्यों interesting है:

> इस option का उपयोग किसी running process से library validation हटाने के लिए किया जाता है। इसका उपयोग plugin architectures में किया जाता है, जब किसी program को untrusted libraries load करनी हों। [...] एक बार process untrusted library load कर ले, तो भविष्य में library validation पर निर्भर रहना effective नहीं होगा।

दूसरे शब्दों में, **इस entitlement वाला कोई भी binary dylib-injection target है**: इसके `CS_REQUIRE_LV` हटाने के बाद इसमें code चलाएँ (या इसे अपना plug-in load करने के लिए convince करें), और host process को जो भी करने की अनुमति है, वह आपको भी प्राप्त हो जाती है।

### `com.apple.security.cs.allow-dyld-environment-variables`

यह entitlement **DYLD environment variables का उपयोग** करने की अनुमति देता है, जिनका उपयोग libraries और code inject करने के लिए किया जा सकता है। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)।<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` या `com.apple.rootless.storage`.`TCC`

[**इस blog के अनुसार**](https://objective-see.org/blog/blog_0x4C.html) **और** [**इस blog के अनुसार**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ये entitlements किसी process को **TCC database को modify** करने की अनुमति देते हैं।<sup>[[6]](#references)[[7]](#references)</sup>

### Authorization rights **`system.install.apple-software`** और **`system.install.apple-software.standard-user`**

ये Authorization Services rights Apple द्वारा प्रदान किए गए software के installation को नियंत्रित करते हैं। इन्हें प्राप्त करने के entitlement वाले process के लिए सामान्य authorization flow को bypass करना संभव हो सकता है, जो **privilege escalation** में सहायक हो सकता है।<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

**kernel से kernel extension load करने** का अनुरोध करने के लिए आवश्यक entitlement।

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** के कारण **`com.apple.iCloudHelper`** XPC service के साथ communicate करना संभव होता है, जो **iCloud tokens प्रदान** करेगा।

**iMovie** और **Garageband** के पास यह entitlement था।

उस entitlement से **icloud tokens प्राप्त** करने वाले exploit के बारे में अधिक **जानकारी** के लिए यह talk देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: मुझे नहीं पता कि इससे क्या किया जा सकता है

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**यह report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) में बताया गया है कि इस entitlement का उपयोग reboot के बाद SSV-protected contents को update करने के लिए किया जा सकता है। यदि आपको पता है कि कैसे, तो कृपया PR भेजें!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**इसी report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) में बताया गया है कि sealed snapshot बनाने का उपयोग reboot के बाद SSV-protected contents को update करने के लिए किया जा सकता है। यदि आपको पता है कि कैसे, तो कृपया PR भेजें!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

यह entitlement उन **keychain** groups की सूची देता है, जिन तक application की access है:
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

**Full Disk Access** permissions देता है, जो TCC की सबसे उच्च permissions में से एक है।

### **`kTCCServiceAppleEvents`**

ऐप को आमतौर पर **automating tasks** के लिए उपयोग किए जाने वाले अन्य applications को events भेजने की अनुमति देता है। अन्य apps को control करके, यह उन apps को दी गई permissions का दुरुपयोग कर सकता है।

उदाहरण के लिए, उनसे user से उसका password पूछने के लिए कहना:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
या उन्हें **मनमानी कार्रवाइयाँ** करने के लिए मजबूर करना।

### **`kTCCServiceEndpointSecurityClient`**

अन्य अनुमतियों के साथ-साथ, **users की TCC database में लिखने** की अनुमति देता है।

### **`kTCCServiceSystemPolicySysAdminFiles`**

किसी user की **`NFSHomeDirectory`** attribute को **बदलने** की अनुमति देता है, जिससे उसका home folder path बदल जाता है और इसलिए **TCC को bypass** किया जा सकता है।

### **`kTCCServiceSystemPolicyAppBundles`**

apps bundle (app.app के अंदर) की files को modify करने की अनुमति देता है, जिसे default रूप से **अस्वीकृत** किया जाता है।

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

यह _System Settings_ > _Privacy & Security_ > _App Management_ में check करना संभव है कि किसे यह access प्राप्त है।

### `kTCCServiceAccessibility`

यह process **macOS accessibility features का दुरुपयोग** कर सकेगा, जिसका अर्थ है कि, उदाहरण के लिए, वह keystrokes दबा सकेगा। इसलिए वह Finder जैसे app को control करने के लिए access request कर सकता है और इस permission के साथ dialog को approve कर सकता है।

## Trustcache/CDhash से संबंधित entitlements

कुछ ऐसे entitlements हैं जिनका उपयोग Trustcache/CDhash protections को bypass करने के लिए किया जा सकता है, जो Apple binaries के downgraded versions के execution को रोकते हैं।

## Medium

### `com.apple.security.cs.allow-jit`

यह entitlement किसी process को `mmap()` system function में `MAP_JIT` flag पास करके **ऐसी memory create करने** की अनुमति देता है जो writable और executable हो। अधिक जानकारी के लिए [**इसे देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)।<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

यह entitlement **C code को override या patch** करने, लंबे समय से deprecated **`NSCreateObjectFileImageFromMemory`** (जो मूल रूप से insecure है) का उपयोग करने, या **DVDPlayback** framework का उपयोग करने की अनुमति देता है। अधिक जानकारी के लिए [**इसे देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)।<sup>[[11]](#references)</sup>

> [!CAUTION]
> इस entitlement को शामिल करने से आपका app memory-unsafe code languages की सामान्य vulnerabilities के संपर्क में आ जाता है। सावधानीपूर्वक विचार करें कि क्या आपके app को वास्तव में इस exception की आवश्यकता है।

### `com.apple.security.cs.disable-executable-page-protection`

यह entitlement disk पर अपनी executable files के **sections को modify** करने की अनुमति देता है, ताकि जबरन exit किया जा सके। अधिक जानकारी के लिए [**इसे देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)।<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement एक अत्यंत शक्तिशाली entitlement है, जो आपके app से एक मूलभूत security protection हटा देता है और attacker के लिए आपके app के executable code को बिना detection के rewrite करना संभव बनाता है। यदि संभव हो, तो अधिक सीमित entitlements का उपयोग करें।

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

यह entitlement nullfs file system को mount करने की अनुमति देता है (जो default रूप से forbidden है)। Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)।

### `kTCCServiceAll`

इस blogpost के अनुसार, यह TCC permission आमतौर पर इस रूप में पाई जाती है:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Process को **सभी TCC permissions के लिए अनुरोध करने की अनुमति देता है**।

### **`kTCCServicePostEvent`**

`CGEventPost()` के माध्यम से system-wide **synthetic keyboard और mouse events inject करने की अनुमति देता है**। इस permission वाले process से किसी भी application में keystrokes, mouse clicks और scroll events simulate किए जा सकते हैं — यानी desktop का प्रभावी रूप से **remote control** मिल जाता है।

यह `kTCCServiceAccessibility` या `kTCCServiceListenEvent` के साथ विशेष रूप से खतरनाक है, क्योंकि इससे input को पढ़ने और inject करने, दोनों की अनुमति मिल जाती है।
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

पूरे system में **सभी keyboard और mouse events को intercept करने** (input monitoring / keylogging) की अनुमति देता है। कोई process हर application में टाइप किए गए प्रत्येक keystroke को capture करने के लिए `CGEventTap` register कर सकता है, जिसमें passwords, credit card numbers और private messages भी शामिल हैं।

विस्तृत exploitation techniques के लिए देखें:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**display buffer को पढ़ने** — screenshots लेने और किसी भी application की screen video record करने — की अनुमति देता है, जिसमें secure text fields भी शामिल हैं। OCR के साथ मिलकर, यह screen से passwords और sensitive data को automatically extract कर सकता है।

> [!WARNING]
> macOS Sonoma से शुरू होकर, screen capture एक persistent menu bar indicator दिखाता है। पुराने versions में screen recording पूरी तरह silent हो सकती है।

### **`kTCCServiceCamera`**

Built-in camera या connected USB cameras से **photos और video capture करने** की अनुमति देता है। Camera-entitled binary में code injection silent visual surveillance सक्षम करता है।

### **`kTCCServiceMicrophone`**

सभी input devices से **audio record करने** की अनुमति देता है। Mic access वाले background daemons बिना किसी visible application window के persistent ambient audio surveillance प्रदान करते हैं।

### **`kTCCServiceLocation`**

Wi-Fi triangulation या Bluetooth beacons के माध्यम से device की **physical location query करने** की अनुमति देता है। Continuous monitoring से home/work addresses, travel patterns और daily routines का पता चलता है।

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts** (names, emails, phones — spear-phishing के लिए उपयोगी), **Calendar** (meeting schedules, attendee lists) और **Photos** (personal photos, credentials वाली screenshots, location metadata) तक access।

TCC permissions के माध्यम से complete credential theft exploitation techniques के लिए देखें:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** App Sandbox को कमजोर करते हैं, क्योंकि वे system-wide Mach/XPC services के साथ communication की अनुमति देते हैं, जिन्हें sandbox सामान्यतः block करता है। यह **primary sandbox escape primitive** है — compromised sandboxed app privileged daemons तक पहुंचने और उनके XPC interfaces का exploitation करने के लिए mach-lookup exceptions का उपयोग कर सकता है।
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
For detailed exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, देखें:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** user-space driver binaries को IOKit interfaces के माध्यम से सीधे kernel के साथ communicate करने की अनुमति देते हैं। DriverKit binaries hardware को manage करते हैं: USB, Thunderbolt, PCIe, HID devices, audio और networking।

DriverKit binary को compromise करने से ये संभव हो जाते हैं:
- malformed `IOConnectCallMethod` calls के माध्यम से **Kernel attack surface**
- **USB device spoofing** (HID injection के लिए keyboard emulate करना)
- PCIe/Thunderbolt interfaces के माध्यम से **DMA attacks**
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
विस्तृत IOKit/DriverKit exploitation के लिए देखें:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations और `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: TCC को bypass करना](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — music चलाएं और TCC को bypass करें, यानी CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "आपके Mac पर होने वाली चीज़ें Apple के iCloud पर रहती हैं?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple के OTA Update का Nightmare: Signature Verification को bypass करना और Kernel को Pwn करना](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Authorization Services Programming Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
