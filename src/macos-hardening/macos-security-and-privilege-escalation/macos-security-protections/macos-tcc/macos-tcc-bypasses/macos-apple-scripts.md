# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

작업 자동화를 위해 **remote processes와 상호작용하는** scripting language입니다. 다른 processes에 **특정 작업을 수행하도록 요청하는** 것이 매우 쉽습니다. **Malware**는 이러한 기능을 악용하여 다른 processes가 export한 functions를 악용할 수 있습니다.\
예를 들어, malware는 **browser에서 열린 페이지에 arbitrary JS code를 inject**할 수 있습니다. 또는 사용자에게 요청된 일부 allow permissions를 **auto click**할 수 있습니다;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
다음은 몇 가지 예시입니다: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScripts를 사용하는 malware에 대한 자세한 정보는 [**여기**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automation / TCC 특이 사항

Apple Events 승인은 **방향성**이 있습니다. 즉, 프롬프트는 **소스 프로세스 -> 대상 프로세스** 쌍에 대해 표시됩니다. 사용자가 **허용**을 클릭하면 항목이 reset될 때까지 동일한 소스에서 동일한 대상으로 보내는 이후 요청이 허용됩니다. 테스트 중 `Terminal -> Finder` 또는 `Terminal -> System Events`를 한 번 허용하면, 나중에 다른 팝업 없이 해당 권한을 재사용할 수 있습니다.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
이는 **target**이 **Finder**인 경우 특히 중요합니다. Finder는 FDA UI에 표시되지 않더라도 항상 **Full Disk Access**를 보유하기 때문입니다. 따라서 이미 Finder에 대한 **Automation** 권한이 있는 모든 host는 TCC-protected files에 접근하기 위한 AppleScript/JXA proxy로 사용될 수 있습니다.<sup>[[1]](#references)</sup> 일반적인 Finder 및 System Events payloads는 이미 [the main TCC page](../README.md)와 [the Apple Events page](../macos-apple-events.md)에 문서화되어 있습니다.

### Modern offensive tradecraft

`/usr/bin/osascript`는 가장 눈에 잘 띄는 진입점일 뿐입니다. AppleScript와 JXA는 **`NSAppleScript`** / **`OSAScript`**를 통해 **Mach-O binaries**에서도 실행할 수 있으며, 이는 evasion뿐만 아니라 이미 유용한 TCC grants를 보유한 host 내부에서 실행하는 데에도 유용합니다.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
커스텀 helper를 직접 Apple Events를 전송하도록 빌드하는 경우, **real app identity**를 부여하면 testing과 operations의 reliability가 크게 향상됩니다. 실제로 이는 `CFBundleIdentifier`와 `NSAppleEventsUsageDescription`이 포함된 `Info.plist`를 임베드하고, binary에 signing을 적용하며, `com.apple.security.automation.apple-events` entitlement를 부여하는 것을 의미합니다. 그렇지 않으면 Apple Events prompt가 자주 **parent host**(예: `Terminal`)에 귀속되거나, `NSAppleScript` 실행이 혼란스러운 `-1750` / `errOSASystemError` errors와 함께 실패합니다.<sup>[[2]](#references)</sup>

Apple scripts는 쉽게 "**compiled**"할 수 있습니다. 이러한 버전은 `osadecompile`을 사용하여 쉽게 "**decompiled**"할 수 있습니다.

그러나 이러한 scripts는 "**Read only**"로도 **exported**할 수 있습니다("Export..." option 사용):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
그리고 이 경우에는 `osadecompile`을 사용해도 콘텐츠를 decompile할 수 없습니다.

하지만 이러한 유형의 실행 파일을 이해하는 데 사용할 수 있는 도구가 여전히 있습니다. [**자세한 내용은 이 research를 참고하세요**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) 도구와 [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile)을 사용하면 script가 어떻게 작동하는지 이해하는 데 매우 유용합니다.

## References

- [1] [우연과 설계로 macOS TCC User Privacy Protections 우회하기](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [macOS CLI Tools에서 AppleScript 작동시키기: 문서화되지 않은 부분](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Offensive Actors가 macOS 공격에 AppleScript를 사용하는 방법](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | 악성 Run-Only AppleScripts를 Reverse Engineering한 경험](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
