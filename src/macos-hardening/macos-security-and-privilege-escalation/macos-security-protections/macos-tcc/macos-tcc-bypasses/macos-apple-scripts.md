# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript एक automation language है, जो scriptable applications को Apple Events भेज सकती है। संबंधित grants के साथ, malware किसी scriptable browser tab में JavaScript inject कर सकता है या permission dialog पर click करने के लिए System Events/Accessibility का उपयोग कर सकता है। Apple Events और Accessibility अलग-अलग TCC services हैं और सामान्यतः इनके लिए संबंधित user approvals आवश्यक होते हैं।<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
`abbeycode/AppleScripts` repository में automation के उदाहरण शामिल हैं।<sup>[[7]](#references)</sup>\
AppleScripts का उपयोग करने वाले malware के बारे में अधिक जानकारी [**यहाँ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) प्राप्त करें।<sup>[[3]](#references)</sup>

### Automation / TCC quirks

Apple Events approvals **directional** होते हैं: prompt एक **source process -> target process** pair के लिए होता है। उपयोगकर्ता द्वारा **Allow** पर क्लिक करने के बाद, उसी source से उसी target को भेजे गए भविष्य के requests तब तक allowed रहते हैं, जब तक entry को reset नहीं किया जाता। Testing के दौरान, `Terminal -> Finder` या `Terminal -> System Events` को एक बार अनुमति देना बाद में permission को बिना किसी अन्य popup के reuse करने के लिए पर्याप्त है।<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
यह विशेष रूप से तब प्रासंगिक है जब **target** **Finder** हो, क्योंकि Finder के पास हमेशा **Full Disk Access** होता है, भले ही वह FDA UI में दिखाई न दे। इसलिए, कोई भी host जिसके पास पहले से Finder पर Automation है, TCC-protected files तक पहुंचने के लिए AppleScript/JXA proxy के रूप में उपयोग किया जा सकता है।<sup>[[1]](#references)</sup> Generic Finder और System Events payloads पहले से ही [the main TCC page](../README.md) और [the Apple Events page](../macos-apple-events.md) में documented हैं।

### Modern offensive tradecraft

`/usr/bin/osascript` केवल सबसे स्पष्ट entry point है। AppleScript और JXA **Mach-O binaries** से भी **`NSAppleScript`** / **`OSAScript`** के माध्यम से execute हो सकते हैं, जो evasion के लिए और ऐसे host के अंदर रहने के लिए उपयोगी है जिसे पहले से ही उपयोगी TCC grants प्राप्त हैं।<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
यदि आप एक custom helper बनाते हैं जो सीधे Apple Events भेजता है, तो उसे **real app identity** देने से testing और operations कहीं अधिक reliable हो जाते हैं। व्यवहार में इसका अर्थ है `CFBundleIdentifier` और `NSAppleEventsUsageDescription` के साथ `Info.plist` embed करना, binary को sign करना और `com.apple.security.automation.apple-events` entitlement देना। अन्यथा Apple Events prompt अक्सर **parent host** (उदाहरण के लिए `Terminal`) को attributed होता है या `NSAppleScript` execution confusing `-1750` / `errOSASystemError` errors के साथ fail हो जाता है।<sup>[[2]](#references)</sup>

AppleScripts को compiled form में save किया जा सकता है और सामान्यतः `osadecompile` से decompile किया जा सकता है।

हालांकि, इन scripts को **"Read only"** के रूप में भी **"Export..."** option के माध्यम से export किया जा सकता है:

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
उस स्थिति में `osadecompile` सामान्य source को recover करने से इनकार करता है, लेकिन bytecode और Apple Event terminology का फिर भी analysis किया जा सकता है।

SentinelOne का run-only research बताता है कि इस restriction के बावजूद structure को कैसे recover किया जा सकता है। `applescript-disassembler` और `aevt_decompile` compiled script और Apple Event data का inspection करने में मदद करते हैं।<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [macOS TCC User Privacy Protections को Accident और Design द्वारा Bypass करना](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [macOS CLI Tools में AppleScript को Work कराना: Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Offensive Actors macOS पर Attacking के लिए AppleScript का कैसे उपयोग करते हैं](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Malicious Run-Only AppleScripts को Reverse करने के Adventures](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/AppleScripts examples](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
