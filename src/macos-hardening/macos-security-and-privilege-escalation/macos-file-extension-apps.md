# macOS 파일 확장자 및 URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

macOS에 설치된 모든 애플리케이션의 데이터베이스로, 각 설치된 애플리케이션이 지원하는 **URL schemes**, **document types**, **UTIs** 및 기본 handlers와 같은 정보를 조회할 수 있습니다.

다음 명령으로 이 데이터베이스를 dump할 수 있습니다:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 도구를 사용할 수 있습니다.

**`/usr/libexec/lsd`** 는 데이터베이스의 핵심입니다. 이 프로세스는 `.lsd.installation`, `.lsd.open`, `.lsd.openurl` 등 **여러 XPC 서비스**를 제공합니다. 하지만 노출된 XPC 기능을 사용하려면 애플리케이션에 특정 **entitlements**도 필요합니다. 예를 들어 MIME type 또는 URL scheme의 기본 앱을 변경하려면 `.launchservices.changedefaulthandler` 또는 `.launchservices.changeurlschemehandler`와 같은 entitlement가 필요합니다.

**`/System/Library/CoreServices/launchservicesd`** 는 `com.apple.coreservices.launchservicesd` 서비스를 등록하며, 실행 중인 애플리케이션에 대한 정보를 조회하는 데 사용할 수 있습니다. 시스템 도구인 **`/usr/bin/lsappinfo`** 또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 을 사용해 조회할 수 있습니다.

operator 관점에서는 일반적으로 **두 가지 유용한 관점**이 있다는 점을 기억해야 합니다.

- LaunchServices / `lsd` 가 관리하는 **registration database** (`.csstore` 파일을 기반으로 함).
- `LSHandlers` 배열 내부의 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` 에 저장되는 **per-user effective defaults**.

이 구분은 중요합니다. 애플리케이션이 특정 type 또는 scheme을 처리할 수 있는 것으로 **등록**되어 있어도, **현재 기본 앱**은 여전히 다른 bundle ID일 수 있습니다.

최근 macOS 릴리스에서는 registration discovery가 `/Applications`로 제한되지 않습니다. Spotlight에서 검색 가능하고 접근할 수 있는 다른 폴더 및 마운트된 공유 볼륨의 앱도 registry에 등록될 수 있습니다. 따라서 triage 중에는 `lsregister -dump`의 `path` 및 volume 정보를 보존해야 하며, bundle이 계속 검색 가능한 상태라면 앱을 unregister해도 해당 상태가 지속된다고 가정해서는 안 됩니다.<sup>[[4]](#references)</sup>

## File Extension & URL scheme app handlers

다음 명령은 확장자에 따라 파일을 열 수 있는 애플리케이션을 찾는 데 유용합니다.
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
다음을 수행하여 애플리케이션이 지원하는 확장자도 확인할 수 있습니다:
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
## 유효한 handlers 열거

**현재 사용자의 기본값**에 가장 유용한 파일은 일반적으로:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
**URL scheme** 핸들러를 dump하려면:
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
샘플 파일의 UTI 트리를 확인하려면:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
더 편리한 CLI로 기본값을 조회하거나 변경하려면:
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

Handler resolution에는 **파일별** 계층도 있습니다. 파일의 UTI와 사용자의 global default로 fallback하기 전에 LaunchServices는 `com.apple.LaunchServices.OpenWith` extended attribute를 확인합니다. Finder는 한 파일에 대해 **Always Open With**를 선택하면 이 attribute를 생성하며, 그 값은 application path, bundle identifier, version selector를 포함하는 binary property list입니다.<sup>[[3]](#references)</sup>

파일 이름 확장자를 신뢰하지 말고 이를 검사하고 decode합니다:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
이는 `duti`, `dutix` 또는 `LSHandlers`에서 무해한 전역 기본값을 보고하더라도 단일 lure가 예기치 않은 application으로 열릴 때 유용합니다. 통제된 lab에서는 Finder를 통해 구성된 파일에서 정확한 opaque 값을 복사할 수 있으며, 이를 삭제하면 일반적인 type 기반 resolution이 복원됩니다:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## 흥미로운 Info.plist 키

애플리케이션 bundle을 triage할 때 다음 키가 가장 중요합니다:

- **`CFBundleDocumentTypes`**: bundle이 열 수 있다고 주장하는 문서 그룹입니다.
- **`LSItemContentTypes`**: 문서 유형을 UTI에 연결하는 **modern / preferred** 방식입니다.
- **`LSHandlerRank`**: LaunchServices에서 사용하는 순위입니다 (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: 앱이 구현하는 custom URI schemes입니다.
- **`UTExportedTypeDeclarations`**: 앱이 **소유하는** UTI입니다.
- **`UTImportedTypeDeclarations`**: 앱이 소유하지는 않지만 system이 인식하도록 하려는 UTI입니다.

유용한 quick triage command는 다음과 같습니다:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
미묘하지만 중요한 세부 사항: **`LSItemContentTypes`**가 존재하는 경우 **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, **`CFBundleTypeOSTypes`**와 같은 이전 키는 사실상 legacy compatibility data입니다. 실제 handler resolution에서는 먼저 UTI 경로에 집중해야 합니다.

## Offensive notes

애플리케이션은 interesting해지기 위해 실행될 필요가 없습니다. 삭제되었거나 clone된 `.app` bundle은 **디스크에 기록되는 즉시 `lsd`에 의해 자동으로 parse될 수 있으며**, 사용자가 bundle을 한 번도 실행하지 않아도 선언된 document types / URL schemes가 등록될 수 있습니다.

이는 **persistence / hijacking research**와 **initial-access chains** 모두에 유용합니다:

- 악성 앱은 **희귀한 extension** 또는 **custom UTI**를 claim하고 victim이 lure file을 열 때까지 기다릴 수 있습니다.
- 악성 앱은 browser, Electron app, office document, chat client 또는 다른 helper app에서 접근할 수 있는 **custom URL scheme**을 등록할 수 있습니다.<sup>[[1]](#references)</sup>
- 일반적인 default resolution과 특정 candidate handler 테스트를 구분하려면, `open 'targetscheme://host/path?value=test'`를 사용해 LaunchServices를 통해 scheme을 invoke한 다음, `open -b com.vendor.Target 'targetscheme://host/path?value=test'`를 사용해 특정 registered bundle을 대상으로 지정합니다. 이는 receiving app이 attacker-controlled URL components를 어떻게 validate하고 decode하는지 audit할 때 유용합니다.<sup>[[1]](#references)</sup>
- app bundle을 build한 후 편집했다면 다음 명령으로 LaunchServices가 이를 다시 parse하도록 강제할 수 있습니다:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
의심스러운 bundle을 테스트할 때는 다음 항목에 특히 주의하세요:

- 흔하지 않은 type에 설정된 **`LSHandlerRank=Owner`**.
- 여러 extension을 지원한다고 주장하는 광범위한 **`CFBundleDocumentTypes`** 배열.
- 유일하게 흥미로운 동작이 document 또는 URI handler 뒤에 숨겨진 **Helper / wrapper apps**.
- 결국 LaunchServices로 dispatch되는 **Shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc` 스타일의 tricks 및 관련 Gatekeeper 측면은 [이 다른 페이지](macos-security-protections/macos-fs-tricks/README.md)를 확인하세요.<sup>[[2]](#references)</sup>

폴더를 탐색하거나 파일을 선택하는 것만으로 passive code-execution을 달성하는 것이 목표라면, 전용 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 페이지도 확인하세요. 이는 서로 다르지만 밀접하게 관련된 file-handler surface입니다.



## References

- [1] [Objective-See - Custom URL Schemes를 통한 Remote Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate 우회: macOS의 Gatekeeper flaws 자세히 살펴보기](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS가 올바른 app에서 file을 여는 방법](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia에서 LaunchServices 제어하기](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
