# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

원격 프로세스와 **상호작용**하며 작업 자동화를 위해 사용되는 스크립팅 언어입니다. 다른 프로세스에게 특정 동작을 수행하도록 **요청**하는 것을 매우 쉽게 만듭니다. **Malware**는 이러한 기능을 악용해 다른 프로세스가 내보내는 함수들을 악용할 수 있습니다.\
예를 들어, malware가 브라우저에서 열린 페이지에 **임의의 JS 코드**를 주입할 수 있습니다. 또는 사용자에게 요청된 일부 권한을 **자동으로 클릭**할 수 있습니다.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
여기 몇 가지 예시가 있습니다: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
applescripts를 사용하는 malware에 대한 더 많은 정보는 [**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)에서 찾을 수 있습니다.

### Automation / TCC quirks

Apple Events 승인에는 **방향성**이 있습니다: 프롬프트는 **source process -> target process** 쌍에 대해 표시됩니다. 사용자가 **Allow**를 클릭하면, 같은 source에서 같은 target으로 향하는 이후 요청은 항목이 재설정될 때까지 허용됩니다. 테스트 중에 `Terminal -> Finder` 또는 `Terminal -> System Events`를 한 번 허용하면, 나중에 다른 팝업 없이 그 권한을 재사용할 수 있습니다.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
이것은 특히 **target**이 **Finder**인 경우에 중요합니다. Finder는 FDA UI에 나타나지 않더라도 항상 **Full Disk Access**를 가지고 있기 때문입니다. 따라서 이미 Finder에 대한 Automation을 가진 모든 host는 TCC로 보호된 파일에 접근하기 위한 AppleScript/JXA proxy로 사용할 수 있습니다. 일반적인 Finder 및 System Events payload는 이미 [the main TCC page](../README.md)와 [the Apple Events page](../macos-apple-events.md)에 문서화되어 있습니다.

### Modern offensive tradecraft

`/usr/bin/osascript`는 가장 눈에 띄는 entry point일 뿐입니다. AppleScript와 JXA는 **Mach-O binaries**를 통해서도 **`NSAppleScript`** / **`OSAScript`**로 실행될 수 있으며, 이는 evasion에도 유용하고 이미 흥미로운 TCC grants가 있는 host 안에서 살아가는 데에도 유용합니다.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
If you build a custom helper that sends Apple Events directly, giving it a **real app identity** makes testing and operations much more reliable. In practice this means embedding an `Info.plist` with `CFBundleIdentifier` and `NSAppleEventsUsageDescription`, signing the binary, and granting the `com.apple.security.automation.apple-events` entitlement. Otherwise the Apple Events prompt is frequently attributed to the **parent host** (for example `Terminal`) or the `NSAppleScript` execution just fails with confusing `-1750` / `errOSASystemError` errors.

Apple scripts may be easily "**compiled**". These versions can be easily "**decompiled**" with `osadecompile`

However, these scripts can also be **exported as "Read only"** (via the "Export..." option):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
and in this case the content cannot be decompiled even with `osadecompile`

하지만 여전히 이 ধরনের executables를 이해하는 데 사용할 수 있는 도구들이 있다, [**자세한 내용은 이 research를 읽어라**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler)와 [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile)을 함께 쓰면 script가 어떻게 동작하는지 이해하는 데 매우 유용하다.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
