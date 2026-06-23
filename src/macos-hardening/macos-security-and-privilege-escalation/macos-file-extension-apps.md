# macOS 파일 확장자 및 URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

이것은 macOS에 설치된 모든 applications의 database로, 각 installed application에 대해 지원하는 **URL schemes**, **document types**, **UTIs**, 그리고 default handlers 같은 정보를 조회할 수 있습니다.

이 database는 다음으로 dump할 수 있습니다:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 도구를 사용합니다.

**`/usr/libexec/lsd`**는 데이터베이스의 핵심입니다. 이 도구는 `.lsd.installation`, `.lsd.open`, `.lsd.openurl` 같은 **여러 XPC 서비스**를 제공합니다. 하지만 노출된 XPC 기능을 사용하려면 애플리케이션에 **일부 entitlements**도 필요합니다. 예를 들어 MIME type 또는 URL scheme에 대한 기본 앱을 변경하는 `.launchservices.changedefaulthandler`나 `.launchservices.changeurlschemehandler` 같은 것들입니다.

**`/System/Library/CoreServices/launchservicesd`**는 `com.apple.coreservices.launchservicesd` 서비스를 소유하며, 실행 중인 애플리케이션에 대한 정보를 얻기 위해 질의할 수 있습니다. 시스템 도구 **`/usr/bin/lsappinfo`** 또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)으로 질의할 수 있습니다.

운영자 관점에서 보면, 보통 **두 가지 유용한 view**가 있다는 점을 기억하세요:

- LaunchServices / `lsd`가 관리하는 **registration database** (`.csstore` 파일 기반).
- `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`의 `LSHandlers` 배열 안에 저장된 **per-user effective defaults**.

이 구분은 중요합니다. 애플리케이션은 어떤 type이나 scheme를 처리할 수 있도록 **registered**될 수 있지만, **현재 default**는 여전히 다른 bundle ID일 수 있습니다.

## File Extension & URL scheme app handlers

다음 줄은 확장자에 따라 파일을 열 수 있는 애플리케이션을 찾는 데 유용할 수 있습니다:
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
애플리케이션이 지원하는 extension도 다음과 같이 확인할 수 있습니다:
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
## 유효한 handlers 열거하기

**현재 사용자 defaults**에 가장 유용한 파일은 보통 다음과 같습니다:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
그것에서 **URL scheme** handler를 dump하려면:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
**content-type / UTI** handler를 dump하려면:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
샘플 파일의 UTI tree를 확인하려면:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
더 친숙한 CLI로 defaults를 query하거나 change하고 싶다면:
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
## Interesting Info.plist keys

애플리케이션 번들을 triage할 때, 다음 키들이 가장 중요합니다:

- **`CFBundleDocumentTypes`**: 번들이 열 수 있다고 주장하는 document groups.
- **`LSItemContentTypes`**: document types를 UTIs에 바인딩하는 **modern / preferred** 방법.
- **`LSHandlerRank`**: LaunchServices에서 사용하는 ranking (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: 앱이 구현한 custom URI schemes.
- **`UTExportedTypeDeclarations`**: 앱이 **owns** 하는 UTIs.
- **`UTImportedTypeDeclarations`**: 앱이 소유하지 않지만 시스템이 인식하길 원하는 UTIs.

유용한 빠른 triage command는:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
미묘하지만 중요한 세부사항: **`LSItemContentTypes`**가 존재하면, **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, **`CFBundleTypeOSTypes`** 같은 이전 키들은 사실상 legacy 호환성 데이터입니다. 실제 handler resolution에서는 먼저 UTI 경로에 집중하세요.

## Offensive notes

Applications는 실행될 필요 없이도 흥미로워질 수 있습니다. 드롭되거나 복제된 `.app` bundle은 디스크에 기록되는 즉시 **`lsd`가 자동으로 parse**할 수 있으며, 사용자가 bundle을 한 번도 실행하지 않아도 선언된 document types / URL schemes가 등록될 수 있습니다.

이는 **persistence / hijacking research**와 **initial-access chains** 둘 다에 유용합니다:

- 악성 app은 **드문 extension** 또는 **custom UTI**를 claim하고, victim이 lure file을 열 때까지 기다릴 수 있습니다.
- 악성 app은 browser, Electron app, office document, chat client, 또는 다른 helper app에서 접근 가능한 **custom URL scheme**을 등록할 수 있습니다.
- app bundle을 빌드한 뒤 수정하면, 다음 명령으로 LaunchServices가 다시 parse하게 강제할 수 있습니다:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
의심스러운 bundle을 테스트할 때는 다음 사항에 특히 주의하세요:

- 흔하지 않은 타입에 대한 **`LSHandlerRank=Owner`**.
- 많은 extension을 주장하는 광범위한 **`CFBundleDocumentTypes`** 배열.
- 유일하게 흥미로운 동작이 document 또는 URI handler 뒤에 숨어 있는 **Helper / wrapper apps**.
- `LaunchServices`로 디스패치되는 **Shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc` 스타일 트릭과 관련된 Gatekeeper 관점은 [이 다른 페이지](macos-security-protections/macos-fs-tricks/README.md)를 확인하세요.

목표가 폴더를 그냥 열어보거나 파일을 선택하는 것만으로 passive code-execution을 얻는 것이라면, 별도로 제공된 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 페이지도 확인하세요. 이는 다르지만 밀접하게 관련된 file-handler 표면입니다.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
