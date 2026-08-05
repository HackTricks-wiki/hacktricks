# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

यह task automation के लिए उपयोग की जाने वाली scripting language है, जो **remote processes के साथ interact** करती है। यह **अन्य processes से कुछ actions करने के लिए कहना** काफी आसान बनाती है। **Malware** इन features का दुरुपयोग करके अन्य processes द्वारा exported functions का दुरुपयोग कर सकता है।\
उदाहरण के लिए, कोई malware **browser में खुले pages में arbitrary JS code inject** कर सकता है। या user से मांगी गई कुछ allow permissions पर **auto click** कर सकता है;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
यहां कुछ examples हैं: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScripts का उपयोग करने वाले malware के बारे में अधिक जानकारी [**यहां**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) प्राप्त करें।

### Automation / TCC की विशेषताएं

Apple Events approvals **directional** होते हैं: prompt एक **source process -> target process** pair के लिए होता है। जब user **Allow** पर click करता है, तो उसी source से उसी target को future requests की अनुमति तब तक रहती है, जब तक entry reset न की जाए। Testing के दौरान, `Terminal -> Finder` या `Terminal -> System Events` की अनुमति एक बार देना बाद में permission को बिना किसी अन्य popup के reuse करने के लिए पर्याप्त है।<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
यह विशेष रूप से तब relevant है जब **target**, **Finder** हो, क्योंकि Finder के पास हमेशा **Full Disk Access** होता है, भले ही वह FDA UI में दिखाई न दे। इसलिए, कोई भी host जिसके पास पहले से Finder पर **Automation** है, उसे TCC-protected files तक पहुंचने के लिए AppleScript/JXA proxy के रूप में इस्तेमाल किया जा सकता है।<sup>[[1]](#references)</sup> Generic Finder और System Events payloads पहले से ही [मुख्य TCC page](../README.md) और [Apple Events page](../macos-apple-events.md) में documented हैं।

### Modern offensive tradecraft

`/usr/bin/osascript` केवल सबसे visible entry point है। AppleScript और JXA **Mach-O binaries** से भी **`NSAppleScript`** / **`OSAScript`** के माध्यम से execute किए जा सकते हैं, जो evasion के लिए और ऐसे host के भीतर रहने के लिए उपयोगी है जिसके पास पहले से ही महत्वपूर्ण TCC grants हैं।<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
यदि आप एक custom helper बनाते हैं जो Apple Events को सीधे भेजता है, तो उसे **real app identity** देने से testing और operations काफी अधिक विश्वसनीय हो जाते हैं। व्यवहार में इसका अर्थ है `CFBundleIdentifier` और `NSAppleEventsUsageDescription` के साथ `Info.plist` embed करना, binary को sign करना और `com.apple.security.automation.apple-events` entitlement देना। अन्यथा Apple Events prompt अक्सर **parent host** (उदाहरण के लिए `Terminal`) को श्रेय दिया जाता है या `NSAppleScript` execution अस्पष्ट `-1750` / `errOSASystemError` errors के साथ विफल हो जाता है।<sup>[[2]](#references)</sup>

Apple scripts को आसानी से "**compiled**" किया जा सकता है। इन versions को `osadecompile` से आसानी से "**decompiled**" किया जा सकता है।

हालांकि, इन scripts को **"Read only"** के रूप में भी **export** किया जा सकता है ("Export..." option के माध्यम से):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
और इस मामले में content को `osadecompile` के साथ भी decompile नहीं किया जा सकता।

हालांकि, इस तरह के executables को समझने के लिए अभी भी कुछ tools का उपयोग किया जा सकता है, [**अधिक जानकारी के लिए यह research पढ़ें**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) tool, [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) के साथ, यह समझने में बहुत उपयोगी होगा कि script कैसे काम करती है।

## References

- [1] [macOS TCC User Privacy Protections को Accident और Design के माध्यम से Bypass करना](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [macOS CLI Tools में AppleScript को काम कराना: Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Offensive Actors macOS पर हमला करने के लिए AppleScript का उपयोग कैसे करते हैं](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Malicious Run-Only AppleScripts को Reverse करने के Adventures](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
