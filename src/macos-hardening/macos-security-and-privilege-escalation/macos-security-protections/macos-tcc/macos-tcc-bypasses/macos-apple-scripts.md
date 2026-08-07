# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

यह task automation के लिए उपयोग की जाने वाली scripting language है, जो **remote processes के साथ interact करती है**। यह **अन्य processes से कुछ actions करने के लिए कहना** काफी आसान बनाती है। **Malware** इन सुविधाओं का दुरुपयोग करके अन्य processes द्वारा exported functions का दुरुपयोग कर सकता है।\
उदाहरण के लिए, कोई malware **browser में खुले pages में arbitrary JS code inject** कर सकता है। या user से अनुरोधित कुछ allow permissions पर **auto click** कर सकता है;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
यहाँ कुछ examples हैं: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScripts का उपयोग करने वाले malware के बारे में अधिक जानकारी [**यहाँ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) प्राप्त करें।<sup>[[3]](#references)</sup>

### Automation / TCC की विशेषताएँ

Apple Events approvals **directional** होते हैं: prompt एक **source process -> target process** pair के लिए होता है। जब user **Allow** पर click करता है, तो उसी source से उसी target को भेजे जाने वाले future requests तब तक allowed रहते हैं, जब तक entry reset न की जाए। Testing के दौरान, `Terminal -> Finder` या `Terminal -> System Events` को एक बार grant करना बाद में permission को बिना किसी अन्य popup के reuse करने के लिए पर्याप्त है।<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
यह विशेष रूप से तब प्रासंगिक है जब **target** **Finder** हो, क्योंकि Finder को हमेशा **Full Disk Access** प्राप्त होता है, भले ही वह FDA UI में दिखाई न दे। इसलिए, कोई भी host जिसके पास पहले से Finder पर **Automation** है, TCC-protected files तक पहुंचने के लिए AppleScript/JXA proxy के रूप में उपयोग किया जा सकता है।<sup>[[1]](#references)</sup> सामान्य Finder और System Events payloads पहले से [the main TCC page](../README.md) और [the Apple Events page](../macos-apple-events.md) में documented हैं।

### Modern offensive tradecraft

`/usr/bin/osascript` केवल सबसे स्पष्ट entry point है। AppleScript और JXA **Mach-O binaries** से भी **`NSAppleScript`** / **`OSAScript`** के माध्यम से execute किए जा सकते हैं, जो evasion और ऐसे host के अंदर काम करने, जिसे पहले से उपयोगी TCC grants प्राप्त हैं, दोनों के लिए उपयोगी है।<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
यदि आप एक custom helper बनाते हैं जो सीधे Apple Events भेजता है, तो उसे एक **real app identity** देने से testing और operations काफी अधिक reliable हो जाते हैं। व्यवहार में इसका अर्थ है `CFBundleIdentifier` और `NSAppleEventsUsageDescription` के साथ `Info.plist` embed करना, binary को sign करना और `com.apple.security.automation.apple-events` entitlement देना। अन्यथा Apple Events prompt का attribution अक्सर **parent host** (उदाहरण के लिए `Terminal`) को किया जाता है या `NSAppleScript` execution भ्रमित करने वाली `-1750` / `errOSASystemError` errors के साथ fail हो जाता है।<sup>[[2]](#references)</sup>

Apple scripts को आसानी से "**compiled**" किया जा सकता है। इन versions को `osadecompile` से आसानी से "**decompiled**" किया जा सकता है।

हालांकि, इन scripts को **"Read only"** के रूप में भी **export** किया जा सकता है ("Export..." option के माध्यम से):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
और इस मामले में `osadecompile` का उपयोग करने पर भी content को decompile नहीं किया जा सकता।

हालांकि, इस तरह के executables को समझने के लिए अभी भी कुछ tools का उपयोग किया जा सकता है, [**read this research for more info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) tool, [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) के साथ, यह समझने में बहुत उपयोगी होगा कि script कैसे काम करती है।

## References

- [1] [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [How Offensive Actors Use AppleScript For Attacking macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Adventures in Reversing Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
