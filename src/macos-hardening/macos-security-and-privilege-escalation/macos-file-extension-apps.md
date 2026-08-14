# Obsługa rozszerzeń plików i schematów URL przez aplikacje w macOS

{{#include ../../banners/hacktricks-training.md}}

## Baza danych LaunchServices

Jest to baza danych wszystkich zainstalowanych aplikacji w macOS, którą można odpytywać w celu uzyskania informacji o każdej zainstalowanej aplikacji, takich jak obsługiwane **schematy URL**, **typy dokumentów**, **UTI** oraz domyślne handlery.

Możliwe jest zrzucenie tej bazy danych za pomocą:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Lub za pomocą narzędzia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** jest mózgiem tej bazy danych. Udostępnia **kilka usług XPC**, takich jak `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i inne. Wymaga jednak również **określonych entitlements** przyznanych aplikacjom, aby mogły korzystać z udostępnianych funkcjonalności XPC, takich jak `.launchservices.changedefaulthandler` lub `.launchservices.changeurlschemehandler`, służących do zmiany domyślnych aplikacji dla typów MIME lub schematów URL, a także innych funkcji.

**`/System/Library/CoreServices/launchservicesd`** rejestruje usługę `com.apple.coreservices.launchservicesd` i można wysyłać do niej zapytania w celu uzyskania informacji o uruchomionych aplikacjach. Można ją odpytywać za pomocą narzędzia systemowego **`/usr/bin/lsappinfo`** lub narzędzia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Z perspektywy operatora należy pamiętać, że zwykle dostępne są **dwa przydatne widoki**:

- **Baza danych rejestracji** zarządzana przez LaunchServices / `lsd` (wspierana przez pliki `.csstore`).
- **Efektywne ustawienia domyślne dla użytkownika** przechowywane w `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, w tablicy `LSHandlers`.

To rozróżnienie ma znaczenie: aplikacja może być **zarejestrowana** jako zdolna do obsługi danego typu lub schematu, ale **bieżącą aplikacją domyślną** może nadal być inny bundle ID.

W nowszych wydaniach macOS wykrywanie rejestracji nie ogranicza się do `/Applications`: aplikacje znajdujące się w innych folderach widocznych dla Spotlight i dostępnych dla systemu, a także na zamontowanych lub współdzielonych woluminach, mogą trafić do rejestru. Dlatego podczas triage należy zachować informacje o `path` i woluminie z danych `lsregister -dump` oraz nie zakładać, że wyrejestrowanie aplikacji będzie trwałe, dopóki bundle pozostaje możliwy do wykrycia.<sup>[[4]](#references)</sup>

## Obsługa aplikacji dla rozszerzeń plików i schematów URL

Poniższy wiersz może być przydatny do znalezienia aplikacji, które mogą otwierać pliki w zależności od rozszerzenia:
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
## Enumerowanie efektywnych programów obsługi

Najbardziej przydatnym plikiem dotyczącym **ustawień domyślnych bieżącego użytkownika** jest zazwyczaj:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Aby zrzucić handlery **URL scheme** z niego:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Aby zrzucić handlery **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Aby określić drzewo UTI przykładowego pliku:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Jeśli chcesz korzystać z bardziej przyjaznego CLI do sprawdzania lub zmieniania wartości domyślnych:
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
### Nadpisania `Open With` dla poszczególnych plików

Rozstrzyganie handlera obejmuje również warstwę **specyficzną dla pliku**. Zanim LaunchServices użyje UTI pliku i globalnego ustawienia domyślnego użytkownika, sprawdza extended attribute `com.apple.LaunchServices.OpenWith`. Finder tworzy go po wybraniu opcji **Always Open With** dla jednego pliku; jego wartość to binarna property list zawierająca ścieżkę aplikacji, bundle identifier oraz selektor wersji.<sup>[[3]](#references)</sup>

Inspect and decode it without trusting the filename extension:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Jest to przydatne, gdy pojedynczy lure otwiera się za pomocą nieoczekiwanej aplikacji, mimo że `duti`, `dutix` lub `LSHandlers` wskazuje łagodną wartość domyślną globalnie. W kontrolowanym laboratorium dokładną nieprzejrzystą wartość można skopiować z pliku skonfigurowanego za pomocą Findera; jej usunięcie przywraca normalne rozpoznawanie na podstawie typu:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Interesujące klucze Info.plist

Podczas analizowania pakietu aplikacji najważniejsze są następujące klucze:

- **`CFBundleDocumentTypes`**: grupy dokumentów, które według deklaracji pakietu może on otwierać.
- **`LSItemContentTypes`**: **nowoczesny / preferowany** sposób wiązania typów dokumentów z UTI.
- **`LSHandlerRank`**: ranking używany przez LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: niestandardowe schematy URI implementowane przez aplikację.
- **`UTExportedTypeDeclarations`**: UTI, których aplikacja jest **właścicielem**.
- **`UTImportedTypeDeclarations`**: UTI, których aplikacja nie jest właścicielem, ale chce, aby system je rozpoznawał.

Przydatne szybkie polecenie do analizy wstępnej to:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Subtelny, ale istotny szczegół: jeśli obecny jest **`LSItemContentTypes`**, starsze klucze, takie jak **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`**, są w praktyce danymi zapewniającymi kompatybilność ze starszymi wersjami. Przy rozwiązywaniu handlera w pierwszej kolejności skup się na ścieżce UTI.

## Offensive notes

Aplikacje nie muszą być uruchamiane, aby stały się interesujące. Upuszczony lub sklonowany pakiet `.app` może zostać **automatycznie przeanalizowany przez `lsd` natychmiast po zapisaniu na dysku**, a zadeklarowane typy dokumentów / schematy URL mogą zostać zarejestrowane, nawet jeśli użytkownik nigdy nie uruchomi pakietu.

Jest to przydatne zarówno w **badaniach nad persistence / hijacking**, jak i w **łańcuchach initial access**:

- Złośliwa aplikacja może przejąć **rzadkie rozszerzenie** lub **custom UTI** i czekać, aż ofiara otworzy plik-przynętę.
- Złośliwa aplikacja może zarejestrować **custom URL scheme** dostępny z poziomu przeglądarki, aplikacji Electron, dokumentu biurowego, klienta czatu lub innej aplikacji pomocniczej.<sup>[[1]](#references)</sup>
- Aby oddzielić normalne rozwiązywanie domyślne od testowania konkretnego kandydata na handler, wywołaj schemat przez LaunchServices za pomocą `open 'targetscheme://host/path?value=test'`, a następnie wskaż konkretny zarejestrowany bundle poleceniem `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Jest to przydatne podczas audytowania sposobu, w jaki aplikacja odbierająca waliduje i dekoduje kontrolowane przez atakującego komponenty URL.<sup>[[1]](#references)</sup>
- Jeśli edytujesz pakiet aplikacji po jego zbudowaniu, możesz wymusić ponowną analizę przez LaunchServices za pomocą:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Podczas testowania podejrzanych bundles zwróć szczególną uwagę na:

- **`LSHandlerRank=Owner`** w przypadku nietypowych typów.
- **Szerokie tablice `CFBundleDocumentTypes`** deklarujące wiele rozszerzeń.
- **Aplikacje Helper / wrapper**, których jedyne interesujące zachowanie jest ukryte za handlerem dokumentów lub URI.
- **Pliki przypominające skróty** (`.webloc`, `.inetloc`, `.fileloc`), które ostatecznie przekazują obsługę do LaunchServices. W przypadku sztuczek w stylu `.fileloc` i powiązanych aspektów Gatekeeper sprawdź [tę inną stronę](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Jeśli Twoim celem jest pasywne wykonanie kodu wynikające wyłącznie z przeglądania folderu lub wybrania pliku, sprawdź również dedykowaną stronę dotyczącą [generatorów Quick Look](macos-proces-abuse/macos-quicklook-generators.md), ponieważ jest to inna, choć blisko powiązana, powierzchnia obsługi plików.



## References

- [1] [Objective-See - Zdalne wykorzystanie Maca za pomocą niestandardowych schematów URL](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Omijanie bramy: bliższe spojrzenie na luki Gatekeeper w macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Jak macOS otwiera plik we właściwej aplikacji](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Kontrolowanie LaunchServices w macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
