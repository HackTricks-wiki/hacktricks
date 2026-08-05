# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> ध्यान दें कि **`com.apple`** से शुरू होने वाले entitlements third-parties के लिए उपलब्ध नहीं होते, इन्हें केवल Apple grant कर सकता है... या यदि आप enterprise certificate का उपयोग कर रहे हैं, तो आप वास्तव में **`com.apple`** से शुरू होने वाले अपने entitlements बना सकते हैं और इस पर आधारित protections को bypass कर सकते हैं।

## उच्च

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement **SIP को bypass** करने की अनुमति देता है। अधिक जानकारी के लिए [यहाँ देखें](macos-sip.md#com.apple.rootless.install.heritable)।

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement **SIP को bypass** करने की अनुमति देता है। अधिक जानकारी के लिए [यहाँ देखें](macos-sip.md#com.apple.rootless.install)।

### **`com.apple.system-task-ports` (पहले `task_for_pid-allow` कहा जाता था)**

यह entitlement kernel को छोड़कर **किसी भी** process का **task port प्राप्त** करने की अनुमति देता है। अधिक जानकारी के लिए [**यहाँ देखें**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)।

### `com.apple.security.get-task-allow`

यह entitlement, **`com.apple.security.cs.debugger`** entitlement वाले अन्य processes को इस entitlement वाले binary द्वारा चलाए जा रहे process का task port प्राप्त करने और **उसमें code inject करने** की अनुमति देता है। अधिक जानकारी के लिए [**यहाँ देखें**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)।

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement वाले apps, `task_for_pid()` को call करके उन unsigned और third-party apps के लिए valid task port प्राप्त कर सकते हैं जिनमें `Get Task Allow` entitlement `true` पर set है। हालांकि, debugging tool entitlement होने पर भी, debugger उन processes के **task ports प्राप्त नहीं कर सकता** जिनमें **`Get Task Allow` entitlement नहीं है**, और जो इसलिए System Integrity Protection द्वारा protected हैं। अधिक जानकारी के लिए [**यहाँ देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)।

### `com.apple.security.cs.disable-library-validation`

यह entitlement **ऐसे frameworks, plug-ins या libraries load करने** की अनुमति देता है जो न तो Apple द्वारा signed हों और न ही main executable के समान Team ID से signed हों, इसलिए attacker code inject करने के लिए किसी arbitrary library load का abuse कर सकता है। अधिक जानकारी के लिए [**यहाँ देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

यह entitlement **`com.apple.security.cs.disable-library-validation`** के समान है, लेकिन **सीधे** library validation को disable करने के **बजाय**, यह process को runtime पर इसे disable करने के लिए **`csops` system call call करने** की अनुमति देता है।

Entitlement name को XNU में उस `csops` operation के पास hardcode किया गया है जो इसका उपयोग करता है:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) के लिए kernel handler दिखाता है कि primitive वास्तव में कितना सीमित है:<sup>[3]</sup>
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
- केवल **itself** (`forself == 1`) पर काम करता है — इसके द्वारा किसी अन्य process से library validation हटाई नहीं जा सकती।
- Process के पास वास्तव में **entitlement** होना आवश्यक है, और यदि process पर `CS_INSTALLER` flag लगा हो या वह subsystem root path के अंतर्गत चल रहा हो, तो यह operation अस्वीकार कर दिया जाता है।
- Process के code-signing flags से **`CS_REQUIRE_LV | CS_FORCED_LV`** clear करता है।

XNU comment intended use case समझाती है और यह भी बताती है कि attacker के लिए यह क्यों interesting है:

> इस option का उपयोग किसी running process से library validation हटाने के लिए किया जाता है। इसका उपयोग plugin architectures में किया जाता है, जब किसी program को untrusted libraries load करने की आवश्यकता होती है। [...] एक बार process ने untrusted library load कर ली, तो भविष्य में library validation पर निर्भर रहना प्रभावी नहीं होगा।

दूसरे शब्दों में, **इस entitlement वाला कोई भी binary dylib-injection target है**: इसके द्वारा `CS_REQUIRE_LV` हटाए जाने के बाद इसमें code चलाएं (या इसे अपना plug-in load करने के लिए convince करें), और host process को जो भी कार्य करने की अनुमति है, वह आपको भी मिल जाती है।

### `com.apple.security.cs.allow-dyld-environment-variables`

यह entitlement **DYLD environment variables का उपयोग** करने की अनुमति देता है, जिनका उपयोग libraries और code inject करने के लिए किया जा सकता है। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)।

### `com.apple.private.tcc.manager` या `com.apple.rootless.storage`.`TCC`

[**इस blog के अनुसार**](https://objective-see.org/blog/blog_0x4C.html) **और** [**इस blog के अनुसार**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ये entitlements **TCC** database को **modify** करने की अनुमति देते हैं।

### **`system.install.apple-software`** और **`system.install.apple-software.standar-user`**

ये entitlements user से **permissions मांगे बिना software install** करने की अनुमति देते हैं, जो **privilege escalation** में सहायक हो सकता है।

### `com.apple.private.security.kext-management`

**Kernel extension load करने के लिए kernel से request करने हेतु आवश्यक entitlement**।

### **`com.apple.private.icloud-account-access`**

इस entitlement **`com.apple.private.icloud-account-access`** के साथ **`com.apple.iCloudHelper`** XPC service के साथ communicate करना संभव है, जो **iCloud tokens प्रदान** करेगी।

**iMovie** और **Garageband** के पास यह entitlement था।

इस entitlement से **iCloud tokens प्राप्त करने** वाले exploit के बारे में अधिक **जानकारी** के लिए यह talk देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: मुझे नहीं पता कि इससे क्या किया जा सकता है।

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**इस report में**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **उल्लेख किया गया है कि इसका उपयोग** reboot के बाद SSV-protected contents को update करने के लिए किया जा सकता है। यदि आपको पता है कि इसे कैसे किया जाता है, तो कृपया PR भेजें!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**इस report में**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **उल्लेख किया गया है कि इसका उपयोग** reboot के बाद SSV-protected contents को update करने के लिए किया जा सकता है। यदि आपको पता है कि इसे कैसे किया जाता है, तो कृपया PR भेजें!

### `keychain-access-groups`

यह entitlement उन **keychain** groups की सूची देता है, जिन तक application की पहुंच है:
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

ऐप को अन्य applications को events भेजने की अनुमति देता है, जिनका उपयोग आमतौर पर **tasks को automate करने** के लिए किया जाता है। अन्य apps को नियंत्रित करके, यह उन apps को दी गई permissions का दुरुपयोग कर सकता है।

उदाहरण के लिए, उन्हें user से उसका password पूछने के लिए मजबूर करना:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
या उन्हें **arbitrary actions** करने के लिए मजबूर करना।

### **`kTCCServiceEndpointSecurityClient`**

अन्य permissions के अलावा, यह **user की TCC database में write** करने की अनुमति देता है।

### **`kTCCServiceSystemPolicySysAdminFiles`**

यह किसी user के **`NFSHomeDirectory`** attribute को **change** करने की अनुमति देता है, जिससे उसका home folder path बदल जाता है और इसलिए **TCC को bypass** किया जा सकता है।

### **`kTCCServiceSystemPolicyAppBundles`**

यह apps bundle (app.app के अंदर) की files को modify करने की अनुमति देता है, जिसे default रूप से **disallowed** किया गया है।

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

यह _System Settings_ > _Privacy & Security_ > _App Management_ में check करना possible है कि किसके पास यह access है।

### `kTCCServiceAccessibility`

Process **macOS accessibility features का abuse** कर सकेगा, जिसका अर्थ है कि, उदाहरण के लिए, वह keystrokes press कर सकेगा। इसलिए वह Finder जैसे app को control करने के लिए access request कर सकता है और इस permission के साथ dialog को approve कर सकता है।

## Trustcache/CDhash से संबंधित entitlements

कुछ ऐसे entitlements हैं जिनका उपयोग Trustcache/CDhash protections को bypass करने के लिए किया जा सकता है। ये protections Apple binaries के downgraded versions के execution को रोकती हैं।

## Medium

### `com.apple.security.cs.allow-jit`

यह entitlement `mmap()` system function में `MAP_JIT` flag pass करके ऐसी **memory create** करने की अनुमति देता है जो writable और executable हो। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)।

### `com.apple.security.cs.allow-unsigned-executable-memory`

यह entitlement **C code को override या patch** करने, लंबे समय से deprecated **`NSCreateObjectFileImageFromMemory`** (जो मूल रूप से insecure है) का उपयोग करने, या **DVDPlayback** framework का उपयोग करने की अनुमति देता है। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)।

> [!CAUTION]
> इस entitlement को शामिल करने से आपका app memory-unsafe code languages में मौजूद common vulnerabilities के प्रति exposed हो जाता है। ध्यानपूर्वक विचार करें कि क्या आपके app को इस exception की आवश्यकता है।

### `com.apple.security.cs.disable-executable-page-protection`

यह entitlement अपने executable files के sections को disk पर **modify** करने की अनुमति देता है, ताकि forcefully exit किया जा सके। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)।

> [!CAUTION]
> Disable Executable Memory Protection Entitlement एक extreme entitlement है, जो आपके app से एक fundamental security protection हटा देता है। इससे attacker के लिए आपके app के executable code को detection के बिना rewrite करना possible हो जाता है। यदि possible हो, तो narrower entitlements को प्राथमिकता दें।

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

यह entitlement nullfs file system को mount करने की अनुमति देता है (जो default रूप से forbidden है)। Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)।

### `kTCCServiceAll`

इस blogpost के अनुसार, यह TCC permission आमतौर पर इस रूप में मिलती है:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Process को **सभी TCC permissions के लिए अनुरोध करने** की अनुमति देता है।

### **`kTCCServicePostEvent`**

`CGEventPost()` के माध्यम से system-wide **synthetic keyboard और mouse events inject करने** की अनुमति देता है। इस permission वाला process किसी भी application में keystrokes, mouse clicks और scroll events simulate कर सकता है — जो प्रभावी रूप से desktop का **remote control** प्रदान करता है।

यह `kTCCServiceAccessibility` या `kTCCServiceListenEvent` के साथ विशेष रूप से खतरनाक है, क्योंकि इससे input को पढ़ना AND inject करना, दोनों संभव हो जाते हैं।
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

पूरे system में **सभी keyboard और mouse events को intercept करने** (input monitoring / keylogging) की अनुमति देता है। कोई process हर application में टाइप की गई प्रत्येक keystroke को capture करने के लिए `CGEventTap` register कर सकता है, जिसमें passwords, credit card numbers और private messages भी शामिल हैं।

विस्तृत exploitation techniques के लिए देखें:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**display buffer को पढ़ने** — screenshots लेने और किसी भी application की screen video record करने — की अनुमति देता है, जिसमें secure text fields भी शामिल हैं। OCR के साथ मिलकर, यह screen से passwords और sensitive data को automatically extract कर सकता है।

> [!WARNING]
> macOS Sonoma से शुरू होकर, screen capture persistent menu bar indicator दिखाता है। पुराने versions में screen recording पूरी तरह silent हो सकती है।

### **`kTCCServiceCamera`**

Built-in camera या connected USB cameras से **photos और video capture करने** की अनुमति देता है। Camera-entitled binary में code injection silent visual surveillance को सक्षम करता है।

### **`kTCCServiceMicrophone`**

सभी input devices से **audio record करने** की अनुमति देता है। Mic access वाले background daemons बिना किसी visible application window के persistent ambient audio surveillance उपलब्ध कराते हैं।

### **`kTCCServiceLocation`**

Wi-Fi triangulation या Bluetooth beacons के माध्यम से device की **physical location query करने** की अनुमति देता है। Continuous monitoring से home/work addresses, travel patterns और daily routines का पता चलता है।

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts** (names, emails, phones — spear-phishing के लिए उपयोगी), **Calendar** (meeting schedules, attendee lists) और **Photos** (personal photos, ऐसे screenshots जिनमें credentials हो सकते हैं, location metadata) तक access।

TCC permissions के माध्यम से complete credential theft exploitation techniques के लिए देखें:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox और Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** App Sandbox को कमजोर करते हैं, क्योंकि वे system-wide Mach/XPC services के साथ communication की अनुमति देते हैं, जिन्हें sandbox सामान्य रूप से block करता है। यह **primary sandbox escape primitive** है — compromised sandboxed app privileged daemons तक पहुंचने और उनके XPC interfaces का exploitation करने के लिए mach-lookup exceptions का उपयोग कर सकता है।
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
विस्तृत exploitation chain के लिए: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, देखें:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** user-space driver binaries को IOKit interfaces के माध्यम से kernel के साथ सीधे communicate करने की अनुमति देते हैं। DriverKit binaries hardware को manage करती हैं: USB, Thunderbolt, PCIe, HID devices, audio और networking।

DriverKit binary को compromise करने से सक्षम होता है:
- malformed `IOConnectCallMethod` calls के माध्यम से **Kernel attack surface**
- **USB device spoofing** (HID injection के लिए keyboard को emulate करना)
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

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations और `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
