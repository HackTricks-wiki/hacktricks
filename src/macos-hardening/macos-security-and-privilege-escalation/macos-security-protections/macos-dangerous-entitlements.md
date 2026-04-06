# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> ध्यान दें कि उन entitlements जो **`com.apple`** से शुरू होते हैं third-parties के लिए उपलब्ध नहीं हैं, केवल Apple इन्हें प्रदान कर सकता है... या यदि आप एक enterprise certificate का उपयोग कर रहे हैं तो आप असल में अपनी ही entitlements **`com.apple`** से शुरू करके इन सुरक्षा उपायों को बायपास कर सकते हैं।

## High

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** को **SIP बायपास** करने की अनुमति देता है। Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** को **SIP बायपास** करने की अनुमति देता है। Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

यह entitlement किसी भी प्रक्रिया (kernel को छोड़कर) के लिए **task port** प्राप्त करने की अनुमति देता है। Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

यह entitlement उन अन्य प्रक्रियाओं को, जिनके पास **`com.apple.security.cs.debugger`** entitlement है, उस प्रक्रिया के task port को प्राप्त करने और उस पर **कोड इंजेक्ट** करने की अनुमति देता है जो इस entitlement वाले बाइनरी द्वारा चल रही है। Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement वाले ऐप्स `task_for_pid()` कॉल कर के unsigned और third-party ऐप्स के लिए, जिनका `Get Task Allow` entitlement `true` सेट है, मान्य task port प्राप्त कर सकते हैं। हालांकि, debugging tool entitlement होने के बावजूद, एक debugger उन प्रक्रियाओं के task ports प्राप्त नहीं कर सकता जिनके पास `Get Task Allow` entitlement नहीं है, और इसलिए वे System Integrity Protection द्वारा संरक्षित होते हैं। Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

यह entitlement Apple द्वारा साइन किए बिना या main executable के समान Team ID से साइन किए बिना frameworks, plug-ins, या libraries को लोड करने की अनुमति देता है, जिससे कोई attacker arbitrary library लोड का दुरुपयोग कर के कोड इंजेक्ट कर सकता है। Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

यह entitlement **`com.apple.security.cs.disable-library-validation`** के बहुत समान है परन्तु सीधे library validation को डिसेबल करने के बजाय, यह प्रक्रिया को इसे डिसेबल करने के लिए `csops` system call कॉल करने की अनुमति देता है।\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

यह entitlement DYLD environment variables के उपयोग की अनुमति देता है, जिन्हें libraries और कोड इंजेक्ट करने के लिए इस्तेमाल किया जा सकता है। Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ये entitlements TCC डेटाबेस को **modify** करने की अनुमति देते हैं।

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

ये entitlements उपयोगकर्ता से अनुमति पूछे बिना सॉफ़्टवेयर install करने की अनुमति देते हैं, जो एक **privilege escalation** के लिए उपयोगी हो सकता है।

### `com.apple.private.security.kext-management`

यह entitlement kernel से kernel extension लोड करने के लिए आवश्यक है।

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** के साथ यह संभव है कि आप **`com.apple.iCloudHelper`** XPC service से संवाद कर सकें जो **iCloud tokens** प्रदान करेगा।

**iMovie** और **Garageband** में यह entitlement था।

iCloud tokens प्राप्त करने के लिए इस entitlement का उपयोग करने वाले exploit के बारे में अधिक जानकारी के लिए उस टॉक को देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: मुझे पता नहीं है कि यह क्या करने की अनुमति देता है

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **is mentioned that this could be used to** update the SSV-protected contents after a reboot. If you know how it send a PR please!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **is mentioned that this could be used to** update the SSV-protected contents after a reboot. If you know how it send a PR please!

### `keychain-access-groups`

यह entitlement उस keychain समूहों की सूची देता है जिन तक एप्लिकेशन की पहुँच है:
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

यह **Full Disk Access** अनुमतियाँ देता है, जो TCC की सबसे उच्च अनुमतियों में से एक है जो आपके पास हो सकती है।

### **`kTCCServiceAppleEvents`**

ऐप को अन्य एप्लिकेशन को इवेंट्स भेजने की अनुमति देता है, जो सामान्यतः **ऑटोमेट किए जाने वाले कार्यों** के लिए उपयोग होते हैं। अन्य ऐप्स को नियंत्रित करके, यह उन अन्य ऐप्स को दी गई अनुमतियों का दुरुपयोग कर सकता है।

जैसे उन्हें उपयोगकर्ता से उसका पासवर्ड माँगवाना:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
या उन्हें **मनमानी क्रियाएँ** करने के लिए मजबूर करना।

### **`kTCCServiceEndpointSecurityClient`**

अन्य अनुमति के अलावा, उपयोगकर्ता के TCC डेटाबेस को **लिखने** की अनुमति देता है।

### **`kTCCServiceSystemPolicySysAdminFiles`**

एक उपयोगकर्ता के **`NFSHomeDirectory`** attribute को **बदलने** की अनुमति देता है, जो उसके होम फ़ोल्डर का पथ बदल देता है और इसलिए TCC को **बायपास** करने की अनुमति देता है।

### **`kTCCServiceSystemPolicyAppBundles`**

apps bundle (inside app.app) के अंदर फाइलें संशोधित करने की अनुमति देता है, जो डिफ़ॉल्ट रूप से **अनुमत नहीं** है।

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

यह जांचना संभव है कि किसके पास यह एक्सेस है: _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

प्रोसेस macOS की accessibility विशेषताओं का **दुरुपयोग** कर पाएगा, जिसका मतलब है कि उदाहरण के लिए वह कीस्ट्रोक दबा सकेगा। इसलिए वह Finder जैसे ऐप को नियंत्रित करने के लिए एक्सेस का अनुरोध कर सकता है और इस अनुमति के साथ डायलॉग को स्वीकृत कर सकता है।

## Trustcache/CDhash related entitlements

कुछ entitlements ऐसे हैं जिनका उपयोग Trustcache/CDhash सुरक्षा को बायपास करने के लिए किया जा सकता है, जो Apple बाइनरी के downgraded संस्करणों के निष्पादन को रोकती हैं।

## Medium

### `com.apple.security.cs.allow-jit`

यह entitlement `MAP_JIT` फ़्लैग को `mmap()` सिस्टम फ़ंक्शन में पास करके **ऐसा मेमोरी बनाना संभव बनाता है जो लिखने योग्य और निष्पादन योग्य हो**। अधिक जानकारी के लिए [**इसे देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

यह entitlement C कोड को **ओवरराइड या पैच** करने, लंबे समय से अप्रचलित **`NSCreateObjectFileImageFromMemory`** (जो मूल रूप से असुरक्षित है) का उपयोग करने, या **DVDPlayback** फ़्रेमवर्क का उपयोग करने की अनुमति देता है। अधिक जानकारी के लिए [**इसे देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> इस entitlement को शामिल करने से आपका ऐप मेमोरी-संबंधी असुरक्षित कोड भाषाओं में मौजूद सामान्य कमजोरियों के प्रति खुला हो जाता है। सावधानीपूर्वक विचार करें कि क्या आपके ऐप को यह अपवाद वास्तव में चाहिए।

### `com.apple.security.cs.disable-executable-page-protection`

यह entitlement डिस्क पर अपने ही executable फ़ाइलों के सेक्शनों को **संशोधित करने** की अनुमति देता है ताकि वे ज़बरदस्ती exit कर सकें। अधिक जानकारी के लिए [**इसे देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> The Disable Executable Memory Protection Entitlement एक अत्यंत entitlement है जो आपके ऐप से एक मौलिक सुरक्षा संरक्षण हटाता है, जिससे एक हमलावर के लिए आपके ऐप के executable कोड को बिना पता चले पुनःलिखित करना संभव हो जाता है। यदि संभव हो तो संकुचित entitlements को प्राथमिकता दें।

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

यह entitlement nullfs फ़ाइल सिस्टम mount करने की अनुमति देता है (डिफ़ॉल्ट रूप से निषेध)। टूल: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

इस ब्लॉगपोस्ट के अनुसार, यह TCC अनुमति आमतौर पर निम्न रूप में मिलती है:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
प्रोसेस को **सभी TCC permissions के लिए पूछने की अनुमति दें**।

### **`kTCCServicePostEvent`**

यह `CGEventPost()` के माध्यम से सिस्टम-व्यापी **कृत्रिम कीबोर्ड और माउस इवेंट इंजेक्ट करने** की अनुमति देता है। इस अनुमति वाला प्रोसेस किसी भी एप्लिकेशन में कीस्ट्रोक्स, माउस क्लिक और स्क्रॉल इवेंट्स का अनुकरण कर सकता है — प्रभावी रूप से डेस्कटॉप का **दूरस्थ नियंत्रण** प्रदान करता है।

यह विशेष रूप से खतरनाक है जब इसे `kTCCServiceAccessibility` या `kTCCServiceListenEvent` के साथ मिलाया जाए, क्योंकि यह इनपुट को पढ़ने और इंजेक्ट करने दोनों की अनुमति देता है।
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

सिस्टम-व्यापी स्तर पर **सभी कीबोर्ड और माउस इवेंट्स को इंटरसेप्ट करने** की अनुमति देता है (input monitoring / keylogging)। कोई प्रोसेस `CGEventTap` रजिस्टर कर सकता है ताकि किसी भी एप्लिकेशन में टाइप किया गया हर कीस्ट्रोक कैप्चर हो सके, जिनमें पासवर्ड, क्रेडिट कार्ड नंबर, और निजी संदेश शामिल हैं।

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Allows **reading the display buffer** — किसी भी एप्लिकेशन के स्क्रीनशॉट लेने और स्क्रीन वीडियो रिकॉर्ड करने की क्षमता, जिनमें secure text fields भी शामिल हैं। OCR के साथ मिलकर, यह स्क्रीन से ऑटोमेटिक रूप से पासवर्ड और संवेदनशील डेटा निकाल सकता है।

> [!WARNING]
> macOS Sonoma से शुरू होकर, screen capture एक स्थायी मेनू बार संकेतक दिखाती है। पुराने वर्ज़नों में, स्क्रीन रिकॉर्डिंग पूरी तरह से बिना किसी संकेत के हो सकती है।

### **`kTCCServiceCamera`**

बिल्ट-इन कैमरा या कनेक्टेड USB कैमरों से **फोटो और वीडियो कैप्चर करने** की अनुमति देता है। किसी camera-entitled बाइनरी में Code injection से बिना किसी संकेत वाली विज़ुअल निगरानी संभव हो सकती है।

### **`kTCCServiceMicrophone`**

सभी इनपुट डिवाइसेज़ से **ऑडियो रिकॉर्ड करने** की अनुमति देता है। mic एक्सेस वाले background daemons लगातार परिवेशीय ऑडियो निगरानी प्रदान कर सकते हैं, बिना किसी दिखाई देने वाले एप्लिकेशन विंडो के।

### **`kTCCServiceLocation`**

Wi‑Fi triangulation या Bluetooth beacons के माध्यम से डिवाइस के **भौतिक स्थान** को क्वेरी करने की अनुमति देता है। लगातार मॉनिटरिंग घर/कार्यालय के पते, यात्रा पैटर्न, और दैनिक दिनचर्या प्रकट कर सकती है।

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts** (नाम, ईमेल, फोन — spear-phishing के लिए उपयोगी), **Calendar** (मीटिंग शेड्यूल, उपस्थित लोगों की सूची), और **Photos** (निजी फ़ोटो, ऐसे स्क्रीनशॉट जो credentials या लोकेशन मेटाडेटा रख सकते हैं) तक पहुँच।

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** App Sandbox को कमजोर करते हैं, क्योंकि ये sandbox सामान्यतः ब्लॉक करने वाली सिस्टम-व्यापी Mach/XPC सेवाओं के साथ संचार की अनुमति देते हैं। यह **primary sandbox escape primitive** है — एक compromised sandboxed app mach-lookup exceptions का उपयोग करके privileged daemons तक पहुँच सकता है और उनके XPC interfaces का exploit कर सकता है।
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

DriverKit entitlements user-space driver binaries को IOKit interfaces के माध्यम से सीधे kernel के साथ संवाद करने की अनुमति देते हैं। DriverKit बाइनरीज़ हार्डवेयर का प्रबंधन करती हैं: USB, Thunderbolt, PCIe, HID devices, audio, and networking.

किसी DriverKit बाइनरी के समझौते पर सक्षम होते हैं:
- **Kernel attack surface** खराब स्वरूप के `IOConnectCallMethod` कॉल्स के ज़रिए
- **USB device spoofing** (HID injection के लिए keyboard का अनुकरण)
- **DMA attacks** PCIe/Thunderbolt इंटरफेस के जरिए
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
विस्तृत IOKit/DriverKit exploitation के लिए देखें:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
