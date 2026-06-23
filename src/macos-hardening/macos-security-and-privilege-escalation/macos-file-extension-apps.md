# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

To jest baza danych wszystkich zainstalowanych aplikacji w macOS, którą można odpytać, aby uzyskać informacje o każdej zainstalowanej aplikacji, takie jak obsługiwane **URL schemes**, **document types**, **UTIs** oraz domyślne handlery.

Możliwe jest zrzucenie tej bazy danych za pomocą:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Lub używając narzędzia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** jest mózgiem bazy danych. Zapewnia **kilka usług XPC** takich jak `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i inne. Ale **wymaga też pewnych entitlements** dla aplikacji, aby mogły korzystać z udostępnionych funkcji XPC, takich jak `.launchservices.changedefaulthandler` lub `.launchservices.changeurlschemehandler` do zmiany domyślnych aplikacji dla typów MIME lub schematów URL i innych.

**`/System/Library/CoreServices/launchservicesd`** obsługuje usługę `com.apple.coreservices.launchservicesd` i można ją odpytać, aby uzyskać informacje o uruchomionych aplikacjach. Można ją odpytać za pomocą systemowego narzędzia **`/usr/bin/lsappinfo`** albo przy użyciu [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Z perspektywy operatora pamiętaj, że zwykle istnieją **dwa przydatne widoki**:

- **Baza rejestracyjna** zarządzana przez LaunchServices / `lsd` (oparta na plikach `.csstore`).
- **Domyślne ustawienia efektywne dla konkretnego użytkownika** przechowywane w `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` w tablicy `LSHandlers`.

To rozróżnienie ma znaczenie: aplikacja może być **zarejestrowana** jako zdolna do obsługi typu lub schematu, ale **aktualnym domyślnym** nadal może być inny bundle ID.

## File Extension & URL scheme app handlers

Następująca linia może być przydatna do znalezienia aplikacji, które mogą otwierać pliki w zależności od rozszerzenia:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Albo użyj czegoś takiego jak [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Możesz też sprawdzić rozszerzenia obsługiwane przez aplikację, wykonując:
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
## Wyliczanie effective handlers

Najbardziej przydatnym plikiem dla **current user's defaults** jest zazwyczaj:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Aby z niego zrzucić obsługę **URL scheme**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Aby zrzucić handler'y **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Aby rozwiązać drzewo UTI przykładowego pliku:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Jeśli chcesz bardziej przyjazny CLI do odpytywania lub zmieniania defaults:
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
## Interesujące klucze Info.plist

Podczas analizy pakietu aplikacji te klucze mają największe znaczenie:

- **`CFBundleDocumentTypes`**: grupy dokumentów, które pakiet deklaruje jako możliwe do otwarcia.
- **`LSItemContentTypes`**: **nowoczesny / preferowany** sposób powiązania typów dokumentów z UTI.
- **`LSHandlerRank`**: ranking używany przez LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: niestandardowe schematy URI zaimplementowane przez aplikację.
- **`UTExportedTypeDeclarations`**: UTI, które aplikacja **posiada**.
- **`UTImportedTypeDeclarations`**: UTI, których aplikacja nie posiada, ale chce, aby system je rozpoznawał.

Przydatnym szybkim poleceniem do triage jest:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Subtelny, ale ważny szczegół: jeśli **`LSItemContentTypes`** jest obecny, starsze klucze, takie jak **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`**, są w praktyce danymi zgodności wstecznej. Dla rzeczywistego rozstrzygania handlera najpierw skup się na ścieżce UTI.

## Offensive notes

Aplikacji nie trzeba uruchamiać, aby stały się interesujące. Upuszczony lub sklonowany bundle `.app` może zostać **automatycznie sparsowany przez `lsd` zaraz po zapisaniu na dysku**, a jego zadeklarowane typy dokumentów / schematy URL mogą zostać zarejestrowane, zanim użytkownik w ogóle uruchomi bundle.

Jest to przydatne zarówno w badaniach nad **persistence / hijacking**, jak i w łańcuchach **initial-access**:

- Złośliwa aplikacja może przejąć **rzadkie rozszerzenie** lub **własny UTI** i czekać, aż ofiara otworzy zwabiający plik.
- Złośliwa aplikacja może zarejestrować **własny schemat URL** dostępny z przeglądarki, aplikacji Electron, dokumentu office, klienta czatu albo innej aplikacji pomocniczej.
- Jeśli po zbudowaniu zmodyfikujesz bundle aplikacji, możesz wymusić na LaunchServices ponowne jego sparsowanie za pomocą:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Podczas testowania podejrzanych bundle, zwróć szczególną uwagę na:

- **`LSHandlerRank=Owner`** dla nietypowych typów.
- **Szerokie tablice `CFBundleDocumentTypes`** deklarujące wiele rozszerzeń.
- **Helper / wrapper apps**, których jedyne interesujące zachowanie jest ukryte za handlerem dokumentu lub URI.
- **Pliki podobne do shortcutów** (`.webloc`, `.inetloc`, `.fileloc`), które finalnie przekazują obsługę do LaunchServices. W przypadku trików w stylu `.fileloc` i powiązanych wektorów Gatekeeper, sprawdź [tę inną stronę](macos-security-protections/macos-fs-tricks/README.md).

Jeśli Twoim celem jest pasywne code-execution wynikające jedynie z przeglądania folderu lub zaznaczenia pliku, sprawdź też dedykowaną stronę o [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), ponieważ jest to inny, ale bardzo blisko powiązany surface obsługi plików.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
