# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript는 scriptable application으로 Apple Events를 전송할 수 있는 자동화 언어입니다. 관련 grant가 있으면 malware가 scriptable browser tab에 JavaScript를 주입하거나 System Events/Accessibility를 사용해 permission dialog를 클릭할 수 있습니다. Apple Events와 Accessibility는 서로 다른 TCC service이며 일반적으로 각각에 해당하는 사용자의 승인이 필요합니다.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
`abbeycode/AppleScripts` repository에는 automation examples가 포함되어 있습니다.<sup>[[7]](#references)</sup>\
AppleScript를 사용하는 malware에 대한 자세한 정보는 [**여기**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)에서 확인할 수 있습니다.<sup>[[3]](#references)</sup>

### Automation / TCC 특이점

Apple Events 승인은 **directional**합니다. 즉, 프롬프트는 **source process -> target process** 쌍에 적용됩니다. 사용자가 **Allow**를 클릭하면 항목이 reset될 때까지 동일한 source에서 동일한 target으로 전송되는 이후 요청이 허용됩니다. 테스트 중 `Terminal -> Finder` 또는 `Terminal -> System Events`를 한 번 승인하면, 이후에는 다른 팝업 없이 해당 permission을 재사용할 수 있습니다.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
이는 특히 **target**이 **Finder**인 경우와 관련이 깊습니다. Finder는 FDA UI에 표시되지 않더라도 항상 **Full Disk Access**를 보유하기 때문입니다. 따라서 이미 Finder에 대한 Automation 권한이 있는 모든 host는 TCC-protected 파일에 접근하기 위한 AppleScript/JXA proxy로 사용될 수 있습니다.<sup>[[1]](#references)</sup> 일반적인 Finder 및 System Events payloads는 이미 [main TCC 페이지](../README.md)와 [Apple Events 페이지](../macos-apple-events.md)에 문서화되어 있습니다.

### 최신 offensive tradecraft

`/usr/bin/osascript`는 가장 눈에 잘 띄는 entry point일 뿐입니다. AppleScript와 JXA는 **`NSAppleScript`** / **`OSAScript`**를 통해 **Mach-O binaries**에서도 실행할 수 있으며, 이는 evasion뿐만 아니라 이미 유용한 TCC grants를 보유한 host 내부에서 실행하는 데도 유용합니다.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
커스텀 helper를 빌드하여 Apple Events를 직접 전송하는 경우, **실제 app identity**를 부여하면 테스트와 운영을 훨씬 안정적으로 수행할 수 있습니다. 실제로는 `CFBundleIdentifier`와 `NSAppleEventsUsageDescription`이 포함된 `Info.plist`를 내장하고, binary에 서명하며, `com.apple.security.automation.apple-events` entitlement를 부여해야 합니다. 그렇지 않으면 Apple Events prompt가 **부모 host**(예: `Terminal`)에 귀속되는 경우가 많거나, `NSAppleScript` 실행이 혼란스러운 `-1750` / `errOSASystemError` 오류와 함께 실패합니다.<sup>[[2]](#references)</sup>

AppleScripts는 compiled form으로 저장할 수 있으며 일반적으로 `osadecompile`로 decompile할 수 있습니다.

그러나 이러한 scripts는 **"Read only"**로 export할 수도 있습니다("Export..." 옵션 사용):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
그 경우 `osadecompile`은 일반 소스 복구를 거부하지만, bytecode와 Apple Event 용어는 여전히 분석할 수 있습니다.

SentinelOne의 run-only 연구에서는 이러한 제한에도 불구하고 구조를 복구하는 방법을 설명합니다. `applescript-disassembler`와 `aevt_decompile`은 compiled script와 Apple Event 데이터를 검사하는 데 도움이 됩니다.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [우연과 설계에 의한 macOS TCC 사용자 개인정보 보호 우회](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [macOS CLI 도구에서 AppleScript 작동시키기: 문서화되지 않은 부분](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [공격 주체가 macOS 공격에 AppleScript를 사용하는 방법](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | 악성 Run-Only AppleScript를 Reverse Engineering한 경험](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/AppleScripts 예제](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
