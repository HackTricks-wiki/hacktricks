# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

To jest baza danych wszystkich zainstalowanych aplikacji w macOS, która może być zapytana o informacje na temat każdej zainstalowanej aplikacji, takie jak obsługiwane schematy URL i typy MIME.

Możliwe jest zrzucenie tej bazy danych za pomocą:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Lub używając narzędzia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** jest mózgiem bazy danych. Zapewnia **kilka usług XPC** takich jak `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i inne. Ale również **wymaga pewnych uprawnień** dla aplikacji, aby mogły korzystać z udostępnionych funkcji XPC, takich jak `.launchservices.changedefaulthandler` lub `.launchservices.changeurlschemehandler`, aby zmienić domyślne aplikacje dla typów mime lub schematów url i inne.

**`/System/Library/CoreServices/launchservicesd`** rości sobie prawo do usługi `com.apple.coreservices.launchservicesd` i można go zapytać, aby uzyskać informacje o uruchomionych aplikacjach. Można go zapytać za pomocą narzędzia systemowego /**`usr/bin/lsappinfo`** lub za pomocą [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Obsługa aplikacji dla rozszerzeń plików i schematów URL

Poniższa linia może być przydatna do znalezienia aplikacji, które mogą otwierać pliki w zależności od rozszerzenia:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Lub użyj czegoś takiego jak [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Możesz również sprawdzić rozszerzenia obsługiwane przez aplikację, wykonując:
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
