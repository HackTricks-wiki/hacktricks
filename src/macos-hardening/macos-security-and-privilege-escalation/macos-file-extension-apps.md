# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

macOS에 설치된 모든 애플리케이션의 데이터베이스로, 각 설치된 애플리케이션이 지원하는 **URL schemes**, **document types**, **UTIs**, 기본 handlers 등의 정보를 조회하는 데 사용할 수 있습니다.

다음 명령어로 이 데이터베이스를 dump할 수 있습니다:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 도구를 사용할 수 있습니다.

**`/usr/libexec/lsd`**는 데이터베이스의 핵심입니다. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` 등과 같은 **여러 XPC services**를 제공합니다. 하지만 노출된 XPC 기능을 사용할 수 있도록 애플리케이션에 특정 **entitlements**도 요구합니다. 예를 들어 `.launchservices.changedefaulthandler` 또는 `.launchservices.changeurlschemehandler`는 MIME types 또는 URL schemes의 기본 앱을 변경하는 데 사용되며, 이 외에도 여러 기능이 있습니다.

**`/System/Library/CoreServices/launchservicesd`**는 `com.apple.coreservices.launchservicesd` service를 등록하며, 실행 중인 애플리케이션에 대한 정보를 가져오기 위해 조회할 수 있습니다. 시스템 도구 **`/usr/bin/lsappinfo`** 또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 를 사용해 조회할 수 있습니다.

Operator 관점에서는 일반적으로 다음 **두 가지 유용한 뷰**가 있다는 점을 기억해야 합니다.

- LaunchServices / `lsd`가 관리하는 **registration database** (`.csstore` files를 기반으로 함).
- `LSHandlers` array 내부의 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`에 저장된 **per-user effective defaults**.

이 구분은 중요합니다. 애플리케이션이 특정 type 또는 scheme을 처리할 수 있도록 **registered**되어 있어도, **current default**는 여전히 다른 bundle ID일 수 있습니다.

## File Extension & URL scheme app handlers

다음 line은 extension에 따라 파일을 열 수 있는 애플리케이션을 찾는 데 유용합니다:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
또는 [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps)와 같은 것을 사용하세요:
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
다음과 같이 애플리케이션이 지원하는 확장자도 확인할 수 있습니다:
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

**현재 사용자의 기본값**을 확인하는 데 가장 유용한 파일은 일반적으로 다음과 같습니다:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
이를 이용해 **URL scheme** 핸들러를 덤프하려면:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
**content-type / UTI** handler를 덤프하려면:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
샘플 파일의 UTI 트리를 해석하려면:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
더 사용자 친화적인 CLI로 기본값을 조회하거나 변경하려면:
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
## 흥미로운 Info.plist 키

애플리케이션 bundle을 triage할 때는 다음 키가 가장 중요합니다:

- **`CFBundleDocumentTypes`**: bundle이 열 수 있다고 선언하는 문서 그룹입니다.
- **`LSItemContentTypes`**: 문서 유형을 UTI에 바인딩하는 **modern / preferred** 방식입니다.
- **`LSHandlerRank`**: LaunchServices에서 사용하는 순위입니다 (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: 앱이 구현하는 custom URI schemes입니다.
- **`UTExportedTypeDeclarations`**: 앱이 **소유하는** UTI입니다.
- **`UTImportedTypeDeclarations`**: 앱이 소유하지는 않지만 시스템이 인식하도록 하려는 UTI입니다.

유용한 빠른 triage 명령은 다음과 같습니다:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
미묘하지만 중요한 세부 사항: **`LSItemContentTypes`**가 존재하는 경우 **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, **`CFBundleTypeOSTypes`**와 같은 이전 키는 사실상 legacy 호환성 데이터입니다. 실제 handler resolution에서는 먼저 UTI 경로에 집중하세요.

## Offensive notes

흥미로운 대상이 되기 위해 애플리케이션을 실행할 필요는 없습니다. 드롭되거나 복제된 `.app` bundle은 **디스크에 기록되는 즉시 `lsd`에 의해 자동으로 파싱될 수 있으며**, 사용자가 bundle을 실행하지 않아도 선언된 document types / URL schemes가 등록될 수 있습니다.

이는 **persistence / hijacking research**와 **initial-access chains** 모두에 유용합니다.

- 악성 앱은 **rare extension** 또는 **custom UTI**를 주장하고, 피해자가 lure file을 열 때까지 기다릴 수 있습니다.
- 악성 앱은 browser, Electron app, office document, chat client 또는 다른 helper app에서 접근 가능한 **custom URL scheme**을 등록할 수 있습니다.<sup>[[1]](#references)</sup>
- 빌드한 후 app bundle을 편집했다면 다음 명령으로 LaunchServices가 이를 다시 파싱하도록 강제할 수 있습니다:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
의심스러운 bundle을 테스트할 때는 다음 항목에 특히 주의하세요:

- 일반적이지 않은 type에 설정된 **`LSHandlerRank=Owner`**.
- 많은 extension을 주장하는 광범위한 **`CFBundleDocumentTypes`** 배열.
- 유일하게 흥미로운 동작이 document 또는 URI handler 뒤에 숨겨진 **helper / wrapper apps**.
- 결국 LaunchServices로 dispatch되는 **shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc` 스타일의 tricks 및 관련 Gatekeeper 관점에 대해서는 [이 다른 페이지](macos-security-protections/macos-fs-tricks/README.md)를 확인하세요.<sup>[[2]](#references)</sup>

단순히 folder를 탐색하거나 file을 선택하는 것만으로 passive code-execution이 발생하는지 확인하려는 경우에는 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 전용 페이지도 확인하세요. 이는 서로 밀접하게 관련되어 있지만 별개의 file-handler surface입니다.

## References


- [1] [Objective-See - Custom URL Schemes를 통한 Remote Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: macOS의 Gatekeeper flaws 자세히 살펴보기](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
