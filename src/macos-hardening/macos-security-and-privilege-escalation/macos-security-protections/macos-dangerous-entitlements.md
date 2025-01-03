# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> ध्यान दें कि **`com.apple`** से शुरू होने वाले अधिकार तीसरे पक्ष के लिए उपलब्ध नहीं हैं, केवल Apple उन्हें प्रदान कर सकता है।

## High

### `com.apple.rootless.install.heritable`

अधिकार **`com.apple.rootless.install.heritable`** **SIP** को **बायपास** करने की अनुमति देता है। अधिक जानकारी के लिए [यहाँ देखें](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

अधिकार **`com.apple.rootless.install`** **SIP** को **बायपास** करने की अनुमति देता है। अधिक जानकारी के लिए [यहाँ देखें](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (पहले `task_for_pid-allow` कहा जाता था)**

यह अधिकार किसी भी प्रक्रिया के लिए **टास्क पोर्ट प्राप्त करने** की अनुमति देता है, सिवाय कर्नेल के। अधिक जानकारी के लिए [**यहाँ देखें**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

यह अधिकार अन्य प्रक्रियाओं को **`com.apple.security.cs.debugger`** अधिकार के साथ उस प्रक्रिया के टास्क पोर्ट को प्राप्त करने की अनुमति देता है जो इस अधिकार वाले बाइनरी द्वारा चलायी जाती है और **इस पर कोड इंजेक्ट** करने की अनुमति देता है। अधिक जानकारी के लिए [**यहाँ देखें**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

डिबगिंग टूल अधिकार वाले ऐप्स `task_for_pid()` को कॉल कर सकते हैं ताकि बिना साइन किए गए और तीसरे पक्ष के ऐप्स के लिए वैध टास्क पोर्ट प्राप्त किया जा सके जिनका `Get Task Allow` अधिकार `true` पर सेट है। हालाँकि, डिबगिंग टूल अधिकार के साथ भी, एक डिबगर **उन प्रक्रियाओं के टास्क पोर्ट प्राप्त नहीं कर सकता** जिनके पास `Get Task Allow` अधिकार नहीं है, और जो इसलिए सिस्टम इंटीग्रिटी प्रोटेक्शन द्वारा सुरक्षित हैं। अधिक जानकारी के लिए [**यहाँ देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

यह अधिकार **Apple द्वारा साइन किए गए या मुख्य निष्पादन योग्य के समान टीम आईडी के साथ साइन किए गए** बिना फ्रेमवर्क, प्लग-इन या लाइब्रेरी को **लोड** करने की अनुमति देता है, इसलिए एक हमलावर कुछ मनमाने लाइब्रेरी लोड का दुरुपयोग करके कोड इंजेक्ट कर सकता है। अधिक जानकारी के लिए [**यहाँ देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

यह अधिकार **`com.apple.security.cs.disable-library-validation`** के समान है लेकिन **सीधे लाइब्रेरी मान्यता को अक्षम करने** के बजाय, यह प्रक्रिया को **इसे अक्षम करने के लिए `csops` सिस्टम कॉल करने** की अनुमति देता है।\
अधिक जानकारी के लिए [**यहाँ देखें**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

यह अधिकार **DYLD पर्यावरण चर** का उपयोग करने की अनुमति देता है जो लाइब्रेरी और कोड इंजेक्ट करने के लिए उपयोग किए जा सकते हैं। अधिक जानकारी के लिए [**यहाँ देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` या `com.apple.rootless.storage`.`TCC`

[**इस ब्लॉग के अनुसार**](https://objective-see.org/blog/blog_0x4C.html) **और** [**इस ब्लॉग के अनुसार**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), ये अधिकार **TCC** डेटाबेस को **संशोधित** करने की अनुमति देते हैं।

### **`system.install.apple-software`** और **`system.install.apple-software.standar-user`**

ये अधिकार **उपयोगकर्ता से अनुमति पूछे बिना सॉफ़्टवेयर स्थापित** करने की अनुमति देते हैं, जो **अधिकार वृद्धि** के लिए सहायक हो सकता है।

### `com.apple.private.security.kext-management`

अधिकार जो **कर्नेल से कर्नेल एक्सटेंशन लोड करने** के लिए पूछने की आवश्यकता है।

### **`com.apple.private.icloud-account-access`**

अधिकार **`com.apple.private.icloud-account-access`** के माध्यम से **`com.apple.iCloudHelper`** XPC सेवा के साथ संवाद करना संभव है जो **iCloud टोकन** प्रदान करेगा।

**iMovie** और **Garageband** के पास यह अधिकार था।

इस अधिकार से **icloud टोकन** प्राप्त करने के लिए **जानकारी** के लिए बात देखें: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: मुझे नहीं पता कि यह क्या करने की अनुमति देता है

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**इस रिपोर्ट में**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **उल्लेख किया गया है कि इसका उपयोग** रिबूट के बाद SSV-सुरक्षित सामग्री को अपडेट करने के लिए किया जा सकता है। यदि आप जानते हैं कि यह कैसे किया जाता है तो कृपया एक PR भेजें!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**इस रिपोर्ट में**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **उल्लेख किया गया है कि इसका उपयोग** रिबूट के बाद SSV-सुरक्षित सामग्री को अपडेट करने के लिए किया जा सकता है। यदि आप जानते हैं कि यह कैसे किया जाता है तो कृपया एक PR भेजें!

### `keychain-access-groups`

यह अधिकार **keychain** समूहों की सूची है जिन तक एप्लिकेशन की पहुँच है:
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

पूर्ण डिस्क एक्सेस अनुमति देता है, जो TCC की सबसे उच्च अनुमति में से एक है जो आपके पास हो सकती है।

### **`kTCCServiceAppleEvents`**

ऐप को अन्य अनुप्रयोगों को घटनाएँ भेजने की अनुमति देता है जो सामान्यतः **कार्य स्वचालित करने** के लिए उपयोग किए जाते हैं। अन्य ऐप्स को नियंत्रित करते हुए, यह इन अन्य ऐप्स को दी गई अनुमतियों का दुरुपयोग कर सकता है।

जैसे कि उन्हें उपयोगकर्ता से उसका पासवर्ड पूछने के लिए कहना:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
या **मनमाने क्रियाएँ** करने के लिए।

### **`kTCCServiceEndpointSecurityClient`**

अन्य अनुमतियों के बीच, **उपयोगकर्ताओं के TCC डेटाबेस** को **लिखने** की अनुमति देता है।

### **`kTCCServiceSystemPolicySysAdminFiles`**

एक उपयोगकर्ता के **`NFSHomeDirectory`** विशेषता को **बदलने** की अनुमति देता है, जो उसके होम फ़ोल्डर पथ को बदलता है और इसलिए **TCC** को **बायपास** करने की अनुमति देता है।

### **`kTCCServiceSystemPolicyAppBundles`**

ऐप्स बंडल (app.app के अंदर) के अंदर फ़ाइलों को संशोधित करने की अनुमति देता है, जो **डिफ़ॉल्ट रूप से अस्वीकृत** है।

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

यह _System Settings_ > _Privacy & Security_ > _App Management_ में यह जांचना संभव है कि किसके पास यह पहुंच है।

### `kTCCServiceAccessibility`

प्रक्रिया **macOS पहुंच विशेषताओं** का **दुरुपयोग** करने में सक्षम होगी, जिसका अर्थ है कि उदाहरण के लिए वह कीस्ट्रोक दबा सकेगा। इसलिए वह Finder जैसे ऐप को नियंत्रित करने के लिए पहुंच का अनुरोध कर सकता है और इस अनुमति के साथ संवाद को मंजूरी दे सकता है।

## मध्यम

### `com.apple.security.cs.allow-jit`

यह अधिकार **लिखने योग्य और निष्पादन योग्य मेमोरी** बनाने की अनुमति देता है, `mmap()` सिस्टम फ़ंक्शन को `MAP_JIT` ध्वज पास करके। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)।

### `com.apple.security.cs.allow-unsigned-executable-memory`

यह अधिकार **C कोड को ओवरराइड या पैच** करने की अनुमति देता है, लंबे समय से अप्रचलित **`NSCreateObjectFileImageFromMemory`** (जो मौलिक रूप से असुरक्षित है) का उपयोग करने की अनुमति देता है, या **DVDPlayback** फ्रेमवर्क का उपयोग करता है। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)।

> [!CAUTION]
> इस अधिकार को शामिल करने से आपका ऐप मेमोरी-खतरनाक कोड भाषाओं में सामान्य कमजोरियों के लिए उजागर होता है। सावधानी से विचार करें कि क्या आपके ऐप को इस अपवाद की आवश्यकता है।

### `com.apple.security.cs.disable-executable-page-protection`

यह अधिकार **अपने स्वयं के निष्पादन योग्य फ़ाइलों** के खंडों को संशोधित करने की अनुमति देता है ताकि बलात्कारी निकासी की जा सके। अधिक जानकारी के लिए [**यह देखें**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)।

> [!CAUTION]
> निष्पादन योग्य मेमोरी सुरक्षा अधिकार एक चरम अधिकार है जो आपके ऐप से एक मौलिक सुरक्षा सुरक्षा को हटा देता है, जिससे एक हमलावर के लिए आपके ऐप के निष्पादन योग्य कोड को बिना पहचान के फिर से लिखना संभव हो जाता है। यदि संभव हो तो संकीर्ण अधिकारों को प्राथमिकता दें।

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

यह अधिकार एक nullfs फ़ाइल प्रणाली को माउंट करने की अनुमति देता है (डिफ़ॉल्ट रूप से निषिद्ध)। उपकरण: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)।

### `kTCCServiceAll`

इस ब्लॉगपोस्ट के अनुसार, यह TCC अनुमति आमतौर पर इस रूप में पाई जाती है:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
प्रक्रिया को **सभी TCC अनुमतियों के लिए पूछने की अनुमति दें**।

### **`kTCCServicePostEvent`**

{{#include ../../../banners/hacktricks-training.md}}
