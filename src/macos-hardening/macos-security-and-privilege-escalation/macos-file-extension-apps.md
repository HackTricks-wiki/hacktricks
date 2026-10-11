# macOS 파일 확장자 및 URL scheme 앱 핸들러

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices 데이터베이스

macOS에 설치된 모든 애플리케이션의 데이터베이스입니다. 이를 쿼리하면 각 설치된 애플리케이션이 지원하는 **URL schemes**, **document types**, **UTIs**, 기본 핸들러 등의 정보를 얻을 수 있습니다.

다음 명령으로 이 데이터베이스를 덤프할 수 있습니다:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 도구를 사용할 수 있습니다.

**`/usr/libexec/lsd`**는 데이터베이스의 핵심입니다. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` 등 **여러 XPC 서비스**를 제공합니다. 하지만 노출된 XPC 기능을 사용하려면 애플리케이션에 **일부 entitlement**도 필요합니다. 예를 들어 MIME 타입이나 URL scheme의 기본 앱을 변경하는 `.launchservices.changedefaulthandler`, `.launchservices.changeurlschemehandler` 등이 있습니다.

**`/System/Library/CoreServices/launchservicesd`**는 `com.apple.coreservices.launchservicesd` 서비스를 제공하며, 실행 중인 애플리케이션에 관한 정보를 조회하는 데 사용할 수 있습니다. 시스템 도구 **`/usr/bin/lsappinfo`** 또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)을 사용해 조회할 수 있습니다.

운영자 관점에서 다음과 같은 **두 가지 유용한 관점**이 있다는 점을 기억하세요.

- LaunchServices / `lsd`가 관리하는 **등록 데이터베이스** (`.csstore` 파일에 저장됨).
- `LSHandlers` 배열 내 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`에 저장된 **사용자별 유효 기본값**.

이 구분이 중요한 이유는 애플리케이션이 특정 타입이나 scheme을 처리할 수 있도록 **등록**되어 있어도, **현재 기본 앱**은 여전히 다른 bundle ID일 수 있기 때문입니다.

최신 macOS 릴리스에서는 등록 대상 탐색이 `/Applications`에만 국한되지 않습니다. Spotlight에서 검색 가능하고 접근 가능한 다른 폴더와 마운트된/공유 볼륨에 있는 앱도 레지스트리에 포함될 수 있습니다. 따라서 분류 과정에서 `lsregister -dump`의 `path` 및 볼륨 정보를 보존하고, 앱 bundle이 계속 검색 가능한 상태라면 등록 해제가 지속될 것이라고 가정하지 마세요.<sup>[[4]](#references)</sup>

## 파일 확장자 및 URL scheme 앱 핸들러

다음 명령은 확장자에 따라 파일을 열 수 있는 애플리케이션을 찾는 데 유용합니다.

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

또는 [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps)와 같은 것을 사용할 수도 있습니다:

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

애플리케이션이 지원하는 확장자는 다음을 실행해 확인할 수도 있습니다:

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

## 유효 핸들러 열거

**현재 사용자의 기본 앱 설정**을 확인할 때 가장 유용한 파일은 보통 다음과 같습니다:

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

기본값을 조회하거나 변경할 때 더 사용하기 쉬운 CLI를 원한다면:

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

Handler resolution에는 **파일별** 계층도 있습니다. 파일의 UTI와 사용자의 전역 기본값으로 넘어가기 전에 LaunchServices는 `com.apple.LaunchServices.OpenWith` 확장 속성을 확인합니다. Finder는 파일 하나에 **Always Open With**를 선택하면 이 속성을 생성합니다. 속성 값은 애플리케이션 경로, bundle identifier, 버전 선택자가 포함된 바이너리 property list입니다.<sup>[[3]](#references)</sup>

파일 이름 확장자를 신뢰하지 말고 이를 검사하고 디코딩합니다:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

단일 유인 파일이 열릴 때 `duti`, `dutix` 또는 `LSHandlers`에 안전한 전역 기본값이 표시되는데도 예상치 못한 앱이 실행되는 경우 유용합니다. 통제된 실험 환경에서는 Finder를 통해 설정한 파일에서 정확한 불투명 값을 복사할 수 있으며, 이 값을 삭제하면 일반적인 타입 기반 처리가 복원됩니다:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## 흥미로운 Info.plist 키

애플리케이션 번들을 분류할 때 가장 중요한 키는 다음과 같습니다.

- **`CFBundleDocumentTypes`**: 번들이 열 수 있다고 주장하는 문서 그룹입니다.
- **`LSItemContentTypes`**: 문서 유형을 UTI에 연결하는 **최신 / 권장** 방식입니다.
- **`LSHandlerRank`**: LaunchServices에서 사용하는 우선순위입니다 (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: 앱이 구현하는 사용자 지정 URI scheme입니다.
- **`UTExportedTypeDeclarations`**: 앱이 **소유하는** UTI입니다.
- **`UTImportedTypeDeclarations`**: 앱이 소유하지는 않지만 시스템이 인식하기를 원하는 UTI입니다.

빠르게 분류할 때 유용한 명령은 다음과 같습니다.

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

미묘하지만 중요한 세부 사항: **`LSItemContentTypes`**가 있으면 **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, **`CFBundleTypeOSTypes`** 같은 이전 키는 사실상 레거시 호환성 데이터입니다. 실제 handler 확인에서는 먼저 UTI 경로에 집중하세요.

## Offensive notes

흥미로운 대상이 되기 위해 애플리케이션을 실행할 필요는 없습니다. 드롭되거나 복제된 `.app` bundle은 디스크에 기록되는 즉시 **`lsd`에 의해 자동으로 파싱될 수 있으며**, 사용자가 bundle을 한 번도 실행하지 않아도 선언된 document type / URL scheme이 등록될 수 있습니다.

이는 **persistence / hijacking research**와 **initial-access chains** 모두에 유용합니다.

- 악성 앱은 **드문 확장자**나 **custom UTI**를 주장하고, 피해자가 유인 파일을 열 때까지 기다릴 수 있습니다.
- 악성 앱은 browser, Electron app, office document, chat client 또는 다른 helper app에서 접근할 수 있는 **custom URL scheme**을 등록할 수 있습니다.<sup>[[1]](#references)</sup>
- 일반적인 기본 resolution과 특정 후보 handler 테스트를 구분하려면, LaunchServices를 통해 `open 'targetscheme://host/path?value=test'`로 scheme을 호출한 다음 `open -b com.vendor.Target 'targetscheme://host/path?value=test'`로 특정 등록 bundle을 대상으로 지정합니다. 이를 통해 수신 앱이 공격자 제어 URL 구성 요소를 검증하고 디코딩하는 방식을 감사할 수 있습니다.<sup>[[1]](#references)</sup>
- 앱 bundle을 빌드한 후 수정했다면, 다음 명령으로 LaunchServices가 다시 파싱하도록 할 수 있습니다:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

의심스러운 bundle을 테스트할 때는 다음 사항에 특히 주의하세요.

- 흔하지 않은 유형에 설정된 **`LSHandlerRank=Owner`**.
- 여러 확장자를 처리한다고 주장하는 광범위한 **`CFBundleDocumentTypes`** 배열.
- 문서 또는 URI handler 뒤에만 흥미로운 동작이 숨겨져 있는 **helper / wrapper 앱**.
- LaunchServices로 dispatch되는 **바로가기와 유사한 파일**(`.webloc`, `.inetloc`, `.fileloc`). `.fileloc` 유형의 트릭과 관련 Gatekeeper 관점은 [이 다른 페이지](macos-security-protections/macos-fs-tricks/README.md)를 확인하세요.<sup>[[2]](#references)</sup>

폴더를 둘러보거나 파일을 선택하는 것만으로 발생하는 passive code-execution이 목표라면, [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 전용 페이지도 확인하세요. 이는 관련성은 높지만 별개의 파일 handler 공격 표면입니다.



## References

- [1] [Objective-See - 사용자 지정 URL scheme을 통한 원격 Mac 공격](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate 우회: macOS Gatekeeper 결함 자세히 살펴보기](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS에서 파일을 올바른 앱으로 여는 방법](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia에서 LaunchServices 제어하기](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
