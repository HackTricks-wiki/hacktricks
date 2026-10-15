# macOS 파일 확장자 및 URL scheme 앱 핸들러

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices 데이터베이스

macOS에 설치된 모든 애플리케이션의 데이터베이스로, 각 설치된 애플리케이션이 지원하는 **URL schemes**, **document types**, **UTIs**, 기본 핸들러 등의 정보를 조회할 수 있습니다.

다음 명령으로 이 데이터베이스를 덤프할 수 있습니다:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 도구를 사용할 수 있습니다.

**`/usr/libexec/lsd`**는 데이터베이스의 핵심입니다. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` 등 **여러 XPC 서비스**를 제공합니다. 하지만 MIME 유형이나 URL scheme의 기본 앱을 변경하는 `.launchservices.changedefaulthandler` 또는 `.launchservices.changeurlschemehandler` 등 노출된 XPC 기능을 애플리케이션이 사용하려면 **일부 entitlement**도 필요합니다.

**`/System/Library/CoreServices/launchservicesd`**는 `com.apple.coreservices.launchservicesd` 서비스를 제공하며, 실행 중인 애플리케이션에 대한 정보를 조회하는 데 사용할 수 있습니다. 시스템 도구 **`/usr/bin/lsappinfo`** 또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)을 사용해 조회할 수 있습니다.

운영자 관점에서 다음과 같이 **유용한 뷰가 보통 두 가지**라는 점을 기억하세요.

- LaunchServices / `lsd`에서 관리하는 **등록 데이터베이스**(`.csstore` 파일에 저장됨).
- `LSHandlers` 배열 안에 저장된 **사용자별 유효 기본값**: `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`.

이 구분은 중요합니다. 애플리케이션이 어떤 유형이나 scheme을 처리할 수 있는 것으로 **등록**되어 있어도, **현재 기본 앱**은 여전히 다른 bundle ID일 수 있습니다.

최근 macOS 버전에서는 등록 대상을 찾을 때 `/Applications`만 검색하지 않습니다. Spotlight에서 표시되고 접근 가능한 다른 폴더 및 마운트된 공유 볼륨의 앱도 레지스트리에 들어갈 수 있습니다. 따라서 분류 과정에서 `lsregister -dump`의 `path`와 볼륨 정보를 보존하고, 앱 번들이 계속 검색 가능한 상태라면 앱 등록 해제가 오래 유지될 것이라고 가정하지 마세요.<sup>[[4]](#references)</sup>

## 파일 확장자 및 URL scheme 앱 핸들러

다음 명령줄은 확장자에 따라 파일을 열 수 있는 애플리케이션을 찾는 데 유용합니다:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

또는 [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) 같은 것을 사용하세요:

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

애플리케이션에서 지원하는 확장자도 다음과 같이 확인할 수 있습니다:

```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
				<string>css</string>
				<string>pdf</string>
				<string>webarchive</string>
				<string>webbookmark</string>
				<string>webhistory</string>
				<string>webloc</string>
				<string>download</string>
				<string>safariextz</string>
				<string>gif</string>
				<string>html</string>
				<string>htm</string>
				<string>js</string>
				<string>jpg</string>
				<string>jpeg</string>
				<string>jp2</string>
				<string>txt</string>
				<string>text</string>
				<string>png</string>
				<string>tiff</string>
				<string>tif</string>
				<string>url</string>
				<string>ico</string>
				<string>xhtml</string>
				<string>xht</string>
				<string>xml</string>
				<string>xbl</string>
				<string>svg</string>
```

## 유효한 핸들러 열거

**현재 사용자의 기본 앱**을 확인할 때 가장 유용한 파일은 보통 다음과 같습니다:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

해당 앱에서 **URL scheme** 핸들러를 덤프하려면:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

**content-type / UTI** 핸들러를 덤프하려면:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

샘플 파일의 UTI 트리를 확인하려면:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

기본값을 조회하거나 변경할 때 더 편리한 CLI를 원한다면:

```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```

### 파일별 `Open With` 재정의

핸들러 확인에는 **파일별** 계층도 있습니다. 파일의 UTI와 사용자의 전역 기본값으로 대체하기 전에 LaunchServices는 `com.apple.LaunchServices.OpenWith` 확장 속성을 확인합니다. Finder는 파일 하나에 **항상 다음으로 열기**를 선택하면 이 속성을 생성합니다. 속성 값은 애플리케이션 경로, 번들 식별자, 버전 선택자가 포함된 바이너리 property list입니다.<sup>[[3]](#references)</sup>

파일 이름 확장자를 신뢰하지 말고 이를 검사하고 디코딩합니다:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

단일 lure가 열릴 때 `duti`, `dutix` 또는 `LSHandlers`에는 안전한 전역 기본값이 표시되는데도 예상치 못한 애플리케이션이 실행되는 경우 유용합니다. 통제된 실험실 환경에서는 Finder를 통해 설정한 파일에서 정확한 불투명 값을 복사할 수 있습니다. 해당 값을 삭제하면 일반적인 유형 기반 확인 방식이 복원됩니다:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Interesting Info.plist 키

애플리케이션 번들을 분류할 때 다음 키가 가장 중요합니다.

- **`CFBundleDocumentTypes`**: 번들이 열 수 있다고 표시하는 문서 그룹입니다.
- **`LSItemContentTypes`**: 문서 유형을 UTI에 연결하는 **최신 / 권장** 방식입니다.
- **`LSHandlerRank`**: LaunchServices에서 사용하는 우선순위입니다 (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: 앱에서 구현하는 사용자 지정 URI scheme입니다.
- **`UTExportedTypeDeclarations`**: 앱이 **소유하는** UTI입니다.
- **`UTImportedTypeDeclarations`**: 앱이 소유하지는 않지만 시스템이 인식하도록 하려는 UTI입니다.

빠르게 분류할 때 유용한 명령은 다음과 같습니다:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

미묘하지만 중요한 점: **`LSItemContentTypes`**가 있으면 **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, **`CFBundleTypeOSTypes`** 같은 이전 키는 사실상 레거시 호환성 데이터입니다. 실제 handler 확인에서는 먼저 UTI 경로에 주목하세요.

## Offensive notes

handler가 등록되기 전에 앱이 실행될 필요는 없지만, **`.app` bundle을 작성하는 것만으로 즉시 등록이 보장되지는 않습니다**. Finder는 앱을 발견할 때, 예를 들어 사용자가 앱의 폴더를 탐색할 때 앱을 등록할 수 있습니다. 부팅 또는 로그인 시점이나 명시적인 등록 호출을 통해 등록될 수도 있습니다. claim을 테스트하기 전에 `lsregister -dump`를 확인하세요. 등록만으로 앱이 실행되거나 유효한 기본 앱이 되는 것은 아닙니다.<sup>[[5]](#references)</sup> persistence의 전제 조건은 [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices)를 참조하세요.

이는 **persistence / hijacking 연구**와 **initial-access 체인** 모두에 유용합니다.

- 악성 앱은 **잘 쓰이지 않는 확장자** 또는 **custom UTI**를 claim한 뒤, 피해자가 유인 파일을 열 때까지 기다릴 수 있습니다.
- 악성 앱은 브라우저, Electron 앱, office 문서, chat client 또는 다른 helper 앱에서 접근할 수 있는 **custom URL scheme**을 등록할 수 있습니다.<sup>[[1]](#references)</sup>
- 일반적인 기본 앱 확인과 특정 후보 handler 테스트를 분리하려면, LaunchServices를 통해 `open 'targetscheme://host/path?value=test'`로 scheme을 호출한 다음 `open -b com.vendor.Target 'targetscheme://host/path?value=test'`로 특정 등록 bundle을 대상으로 지정합니다. 이는 수신 앱이 공격자가 제어하는 URL 구성 요소를 어떻게 검증하고 디코딩하는지 감사할 때 유용합니다.<sup>[[1]](#references)</sup>
- 앱 bundle을 빌드한 뒤 수정했다면, 다음 명령으로 LaunchServices가 다시 파싱하도록 할 수 있습니다.

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

의심스러운 번들을 테스트할 때는 다음 사항에 특히 주의하세요.

- 흔하지 않은 유형에 **`LSHandlerRank=Owner`**가 설정되어 있는지.
- 여러 확장자를 처리한다고 선언하는 광범위한 **`CFBundleDocumentTypes`** 배열.
- 문서 또는 URI handler 뒤에만 흥미로운 동작이 숨겨져 있는 **helper / wrapper apps**.
- LaunchServices로 디스패치되는 **shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc` 방식의 트릭과 관련 Gatekeeper 우회 방법은 [이 페이지](macos-security-protections/macos-fs-tricks/README.md)를 확인하세요.<sup>[[2]](#references)</sup>

### 하위 구성 요소 옵션으로 전달되는 URL 매개변수

브라우저의 external-protocol 확인은 handler를 여는 것만 승인할 뿐, URL 매개변수를 신뢰할 수 있게 만들지는 않습니다. 수신 앱의 URL parser에서 library, media engine, helper process 또는 파일 쓰기 옵션까지 추적하세요. URL 필드를 하위 구성 요소 옵션 이름으로 바꾸는 query-key prefix가 있는지 확인하세요. 임시 계정에서 무해한 marker를 사용해 일반 구분자와 percent-encoded 구분자 모두 테스트하세요.<sup>[[6]](#references)</sup>

앱의 초기 parsing뿐만 아니라 **하위 구성 요소가 최종적으로 허용하는 옵션**을 검증하세요. 한 handler에서는 prefix가 붙은 query key가 mpv input command까지 전달될 수 있었습니다. 해당 옵션을 차단해도 파일 쓰기 경로는 남아 있었습니다. 이미 알려진 위험한 키 하나만이 아니라, 도달 가능한 옵션 유형을 테스트하세요.<sup>[[7]](#references)</sup>

### 내장 `applescript://` handler

`applescript://com.apple.scripteditor` URL handler는 `action=new`와 URL-encoded `script` 매개변수를 허용합니다. 따라서 브라우저 링크를 통해 공격자가 제어하는 AppleScript가 편집기에 이미 입력된 상태로 Script Editor를 열 수 있어, Terminal에 붙여넣는 단계가 필요하지 않습니다. **자동으로 실행되는 것은 아닙니다**. 브라우저에서 Script Editor를 열지 묻는 메시지가 표시될 수 있으며, 사용자가 스크립트를 실행해야 합니다.<sup>[[8]](#references)</sup>

최신 macOS 버전에서는 스크립트 문서 경고가 표시될 수 있으며, XProtect는 실행 시 AppleScript를 검사합니다.<sup>[[8]](#references)[[9]](#references)</sup>

평가 대상 macOS 버전에서 handler와 확인 메시지를 점검하려면 무해한 로컬 probe를 사용하세요. **Run**을 클릭할 때까지 편집기에 스크립트를 입력하기만 해야 합니다.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

폴더를 둘러보거나 파일을 선택하는 것만으로 passive code-execution을 유도하려는 경우, 별개이지만 밀접하게 관련된 파일 핸들러 공격 표면인 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 전용 페이지도 확인하세요.



## References

- [1] [Objective-See - 사용자 지정 URL Scheme을 통한 원격 Mac 악용](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate를 우회하기: macOS Gatekeeper 결함 자세히 살펴보기](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS가 올바른 앱에서 파일을 여는 방식](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia에서 LaunchServices 제어하기](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Launch Services 개념](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - IINA URL scheme 명령 실행 연구](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - URL scheme에서 mpv 옵션을 안전하지 않게 처리하는 문제](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - ClickFix 기법은 Terminal 대신 Script Editor를 사용](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Terminal 및 스크립트 보호](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
