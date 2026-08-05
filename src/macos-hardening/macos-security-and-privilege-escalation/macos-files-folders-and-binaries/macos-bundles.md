# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

macOS में Bundles विभिन्न resources के containers के रूप में काम करते हैं, जिनमें applications, libraries और अन्य आवश्यक files शामिल होती हैं। इससे Finder में वे single objects के रूप में दिखाई देते हैं, जैसे सामान्य `*.app` files। सबसे सामान्य रूप से मिलने वाला bundle `.app` bundle है, हालांकि `.framework`, `.systemextension` और `.kext` जैसे अन्य प्रकार भी आम हैं।

### Essential Components of a Bundle

किसी bundle के अंदर, विशेष रूप से `<application>.app/Contents/` directory में, कई महत्वपूर्ण resources रखे जाते हैं:

- **\_CodeSignature**: यह directory code-signing details को store करती है, जो application की integrity verify करने के लिए आवश्यक होती हैं। आप निम्न जैसे commands का उपयोग करके code-signing information inspect कर सकते हैं:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: इसमें user interaction पर चलने वाला application का executable binary होता है।
- **Resources**: Application के user interface components, जिनमें images, documents और interface descriptions (nib/xib files) शामिल हैं, का repository।
- **Info.plist**: Application की मुख्य configuration file के रूप में कार्य करती है और system द्वारा application को उचित रूप से पहचानने तथा उसके साथ interact करने के लिए महत्वपूर्ण है।

#### Info.plist में महत्वपूर्ण Keys

`Info.plist` file application configuration का आधार है और इसमें निम्नलिखित keys शामिल होती हैं:

- **CFBundleExecutable**: `Contents/MacOS` directory में स्थित मुख्य executable file का नाम निर्दिष्ट करता है।
- **CFBundleIdentifier**: Application के लिए global identifier प्रदान करता है, जिसका macOS द्वारा application management के लिए व्यापक रूप से उपयोग किया जाता है।
- **LSMinimumSystemVersion**: Application को चलाने के लिए आवश्यक macOS का minimum version बताता है।

### Bundles की खोज

`Safari.app` जैसे bundle के contents की खोज के लिए निम्नलिखित command का उपयोग किया जा सकता है: `bash ls -lR /Applications/Safari.app/Contents`

यह exploration `_CodeSignature`, `MacOS`, `Resources` जैसी directories और `Info.plist` जैसी files दिखाता है। इनमें से प्रत्येक application को secure करने से लेकर उसके user interface और operational parameters को परिभाषित करने तक एक विशिष्ट उद्देश्य पूरा करता है।

#### Additional Bundle Directories

Common directories के अतिरिक्त, bundles में निम्नलिखित भी शामिल हो सकते हैं:

- **Frameworks**: Application द्वारा उपयोग किए जाने वाले bundled frameworks रखता है। Frameworks अतिरिक्त resources वाले dylibs की तरह होते हैं।
- **PlugIns**: Application की capabilities को बढ़ाने वाले plug-ins और extensions के लिए directory।
- **XPCServices**: Application द्वारा out-of-process communication के लिए उपयोग की जाने वाली XPC services रखता है।

यह structure सुनिश्चित करता है कि सभी आवश्यक components bundle के भीतर encapsulated रहें, जिससे modular और secure application environment बनाया जा सके।

`Info.plist` keys और उनके meanings की अधिक विस्तृत जानकारी के लिए Apple developer documentation में extensive resources उपलब्ध हैं: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: जब quarantined bundle को पहली बार execute किया जाता है, तो macOS deep signature verification करता है और उसे randomized translocated path से चला सकता है। स्वीकार किए जाने के बाद, बाद के launches में केवल shallow checks किए जाते हैं; `Resources/`, `PlugIns/`, nibs आदि में मौजूद resource files को ऐतिहासिक रूप से check नहीं किया जाता था। macOS 13 Ventura के बाद first run पर deep check लागू किया जाता है और नया *App Management* TCC permission third-party processes को user consent के बिना अन्य bundles को modify करने से रोकता है, लेकिन पुराने systems अभी भी vulnerable हैं।
- **Bundle Identifier collisions**: एक ही `CFBundleIdentifier` का पुनः उपयोग करने वाले कई embedded targets (PlugIns, helper tools) signature validation को बाधित कर सकते हैं और कभी-कभी URL-scheme hijacking/confusion को सक्षम कर सकते हैं। हमेशा sub-bundles को enumerate करें और unique IDs verify करें।

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura से पहले, signed app में UI resources को बदलने से shallow code signing bypass किया जा सकता था और app के entitlements के साथ code execution प्राप्त किया जा सकता था। Current research (2024) के अनुसार यह pre-Ventura और un-quarantined builds पर अभी भी काम करता है:<sup>[1][2]</sup>

1. Target app को writable location (जैसे `/tmp/Victim.app`) पर copy करें।
2. `Contents/Resources/MainMenu.nib` (या `NSMainNibFile` में declared किसी भी nib) को ऐसे malicious nib से replace करें जो `NSAppleScript`, `NSTask` आदि को instantiate करे।
3. App launch करें। Malicious nib victim के bundle ID और entitlements (TCC grants, microphone/camera आदि) के अंतर्गत execute होता है।
4. Ventura+ first launch पर bundle को deep-verify करके और बाद के modifications के लिए *App Management* permission आवश्यक बनाकर mitigation करता है। इससे persistence कठिन हो जाती है, लेकिन पुराने macOS पर initial-launch attacks अभी भी लागू होते हैं।<sup>[1]</sup>

Minimal malicious nib payload example (`ibtool` से xib को nib में compile करें):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundles के अंदर Framework / PlugIn / dylib Hijacking

क्योंकि `@rpath` lookups bundled Frameworks/PlugIns को प्राथमिकता देते हैं, इसलिए `Contents/Frameworks/` या `Contents/PlugIns/` के अंदर malicious library रखने से load order को redirect किया जा सकता है, जब main binary को library validation के बिना sign किया गया हो या कमजोर `LC_RPATH` ordering के साथ sign किया गया हो।

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
- `com.apple.security.cs.disable-library-validation` के absent होने पर Hardened runtime third-party dylibs को block करता है; पहले entitlements चेक करें।
- `Contents/XPCServices/` के अंतर्गत XPC services अक्सर sibling frameworks लोड करती हैं—persistence या privilege escalation paths के लिए उनके binaries को भी इसी तरह patch करें।

## Quick Inspection Cheatsheet
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
- [2] [Dirty NIB और bundle resource tampering write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
