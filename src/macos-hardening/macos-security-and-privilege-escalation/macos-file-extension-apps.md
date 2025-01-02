# macOS 파일 확장자 및 URL 스킴 앱 핸들러

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices 데이터베이스

이것은 macOS에 설치된 모든 애플리케이션의 데이터베이스로, 지원하는 URL 스킴 및 MIME 타입과 같은 각 설치된 애플리케이션에 대한 정보를 얻기 위해 쿼리할 수 있습니다.

이 데이터베이스를 덤프하는 것은 가능합니다:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Or using the tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`**는 데이터베이스의 두뇌입니다. **여러 XPC 서비스**를 제공합니다. 예를 들어 `.lsd.installation`, `.lsd.open`, `.lsd.openurl` 등이 있습니다. 그러나 노출된 XPC 기능을 사용하기 위해서는 애플리케이션에 **일부 권한**이 필요합니다. 예를 들어 mime 유형이나 URL 스킴에 대한 기본 앱을 변경하기 위한 `.launchservices.changedefaulthandler` 또는 `.launchservices.changeurlschemehandler`와 같은 권한이 필요합니다.

**`/System/Library/CoreServices/launchservicesd`**는 서비스 `com.apple.coreservices.launchservicesd`를 주장하며 실행 중인 애플리케이션에 대한 정보를 얻기 위해 쿼리할 수 있습니다. 시스템 도구 /**`usr/bin/lsappinfo`** 또는 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)로 쿼리할 수 있습니다.

## 파일 확장자 및 URL 스킴 앱 핸들러

다음 줄은 확장자에 따라 파일을 열 수 있는 애플리케이션을 찾는 데 유용할 수 있습니다:
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
응용 프로그램이 지원하는 확장자를 확인하려면 다음을 수행할 수 있습니다:
```
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
{{#include ../../banners/hacktricks-training.md}}
