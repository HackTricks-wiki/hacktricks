# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

यह एक scripting language है जिसका उपयोग task automation के लिए किया जाता है, जो **remote processes** के साथ **interacting** करती है। यह **other processes** से कुछ actions perform करने के लिए पूछना बहुत आसान बनाती है। **Malware** इन features का abuse करके अन्य processes द्वारा exported functions का abuse कर सकती है।\
उदाहरण के लिए, कोई malware ब्राउज़र में खुली pages पर **arbitrary JS code inject** कर सकती है। या user से मांगी गई कुछ allow permissions पर **auto click** कर सकती है;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Here you have some examples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScripts का उपयोग करके malware के बारे में अधिक जानकारी [**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) पर पाएं।

### Automation / TCC quirks

Apple Events approvals **directional** हैं: prompt एक **source process -> target process** pair के लिए होता है। एक बार user **Allow** पर क्लिक कर दे, तो same source से same target के future requests तब तक allowed रहते हैं जब तक entry reset न हो जाए। Testing के दौरान, `Terminal -> Finder` या `Terminal -> System Events` को एक बार grant करना बाद में बिना किसी और popup के permission reuse करने के लिए पर्याप्त है।
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
यह खास तौर पर तब प्रासंगिक है जब **target** **Finder** हो, क्योंकि Finder के पास हमेशा **Full Disk Access** होता है, भले ही वह FDA UI में दिखाई न दे। इसलिए, कोई भी host जिसके पास पहले से Finder पर Automation है, उसे TCC-protected files तक access करने के लिए AppleScript/JXA proxy के रूप में इस्तेमाल किया जा सकता है। Generic Finder और System Events payloads पहले से ही [the main TCC page](../README.md) और [the Apple Events page](../macos-apple-events.md) में documented हैं।

### Modern offensive tradecraft

`/usr/bin/osascript` केवल सबसे visible entry point है। AppleScript और JXA **Mach-O binaries** के जरिए भी **`NSAppleScript`** / **`OSAScript`** से execute कर सकते हैं, जो evasion और ऐसे host के अंदर रहने दोनों के लिए useful है जिसमें पहले से interesting TCC grants हों।
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
यदि आप एक custom helper बनाते हैं जो सीधे Apple Events भेजता है, तो उसे एक **real app identity** देने से testing और operations कहीं ज़्यादा reliable हो जाते हैं। व्यवहार में इसका मतलब है `Info.plist` में `CFBundleIdentifier` और `NSAppleEventsUsageDescription` embed करना, binary को sign करना, और `com.apple.security.automation.apple-events` entitlement देना। वरना Apple Events prompt अक्सर **parent host** (उदाहरण के लिए `Terminal`) को attributed हो जाता है, या `NSAppleScript` execution बस confusing `-1750` / `errOSASystemError` errors के साथ fail हो जाती है।

Apple scripts को आसानी से "**compiled**" किया जा सकता है। इन versions को `osadecompile` के साथ आसानी से "**decompiled**" किया जा सकता है

हालाँकि, इन scripts को "**Read only**" के रूप में भी **exported** किया जा सकता है ( "Export..." option के जरिए):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
और इस case में content को `osadecompile` के साथ भी decompile नहीं किया जा सकता

हालांकि, अभी भी कुछ tools हैं जिनका उपयोग इस तरह के executables को समझने के लिए किया जा सकता है, [**read this research for more info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) tool, [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) के साथ, यह समझने में बहुत useful होगा कि script कैसे work करती है।

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
