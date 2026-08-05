# macOS - obsługa rozszerzeń plików i schematów URL przez aplikacje

{{#include ../../banners/hacktricks-training.md}}

## Baza danych LaunchServices

Jest to baza danych wszystkich zainstalowanych aplikacji w macOS, którą można odpytywać w celu uzyskania informacji o każdej zainstalowanej aplikacji, takich jak obsługiwane **schematy URL**, **typy dokumentów**, **UTI** oraz domyślne mechanizmy obsługi.

Możliwe jest zrzucenie tej bazy danych za pomocą:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Lub za pomocą narzędzia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** jest mózgiem bazy danych. Udostępnia **kilka usług XPC**, takich jak `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i inne. Wymaga jednak również **określonych entitlements** od aplikacji, aby mogły korzystać z udostępnionych funkcji XPC, takich jak `.launchservices.changedefaulthandler` lub `.launchservices.changeurlschemehandler`, służących do zmiany domyślnych aplikacji dla typów MIME lub schematów URL, a także innych funkcji.

**`/System/Library/CoreServices/launchservicesd`** rejestruje usługę `com.apple.coreservices.launchservicesd` i można odpytywać ją w celu uzyskania informacji o uruchomionych aplikacjach. Można to zrobić za pomocą narzędzia systemowego **`/usr/bin/lsappinfo`** lub narzędzia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Z perspektywy operatora należy pamiętać, że zazwyczaj dostępne są **dwa przydatne widoki**:

- **Baza danych rejestracji** zarządzana przez LaunchServices / `lsd` (oparta na plikach `.csstore`).
- **Efektywne wartości domyślne dla użytkownika** przechowywane w `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, w tablicy `LSHandlers`.

To rozróżnienie ma znaczenie: aplikacja może być **zarejestrowana** jako obsługująca dany typ lub schemat, ale **bieżącą aplikacją domyślną** może nadal być inny bundle ID.

## Handlery aplikacji dla rozszerzeń plików i schematów URL

Poniższa linia może być przydatna do znalezienia aplikacji, które mogą otwierać pliki w zależności od ich rozszerzenia:
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
## Enumerowanie aktywnych handlerów

Najbardziej przydatnym plikiem zawierającym informacje o **domyślnych ustawieniach bieżącego użytkownika** jest zazwyczaj:
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
## Interesujące klucze Info.plist

Podczas triage bundle aplikacji najważniejsze są następujące klucze:

- **`CFBundleDocumentTypes`**: grupy dokumentów, które bundle deklaruje jako obsługiwane.
- **`LSItemContentTypes`**: **nowoczesny / preferowany** sposób wiązania typów dokumentów z UTI.
- **`LSHandlerRank`**: ranking używany przez LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: niestandardowe schematy URI zaimplementowane przez aplikację.
- **`UTExportedTypeDeclarations`**: UTI, których aplikacja jest **właścicielem**.
- **`UTImportedTypeDeclarations`**: UTI, których aplikacja nie posiada, ale chce, aby system je rozpoznawał.

Przydatne szybkie polecenie triage to:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Subtelny, ale ważny szczegół: jeśli **`LSItemContentTypes`** jest obecny, starsze klucze, takie jak **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`**, są w praktyce danymi służącymi zapewnieniu zgodności ze starszymi wersjami. Przy faktycznym rozwiązywaniu handlera w pierwszej kolejności należy skupić się na ścieżce UTI.

## Uwagi ofensywne

Aplikacje nie muszą być uruchamiane, aby stać się interesujące. Upuszczony lub sklonowany bundle `.app` może zostać **automatycznie przeanalizowany przez `lsd` natychmiast po zapisaniu go na dysku**, a zadeklarowane przez niego typy dokumentów / schematy URL mogą zostać zarejestrowane bez uruchamiania bundla przez użytkownika.

Jest to przydatne zarówno w badaniach nad **persistence / hijacking**, jak i w **łańcuchach initial access**:

- Złośliwa aplikacja może przejąć **rzadkie rozszerzenie** lub **custom UTI** i czekać, aż ofiara otworzy plik-przynętę.
- Złośliwa aplikacja może zarejestrować **custom URL scheme** dostępny z poziomu przeglądarki, aplikacji Electron, dokumentu biurowego, klienta czatu lub innej aplikacji pomocniczej.<sup>[[1]](#references)</sup>
- Jeśli po zbudowaniu edytujesz bundle aplikacji, możesz wymusić ponowne przeanalizowanie go przez LaunchServices za pomocą:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Podczas testowania podejrzanych bundle'ów zwróć szczególną uwagę na:

- **`LSHandlerRank=Owner`** w przypadku nietypowych typów.
- Szerokie tablice **`CFBundleDocumentTypes`**, które deklarują obsługę wielu rozszerzeń.
- Aplikacje pomocnicze / wrappery, których jedyne interesujące zachowanie jest dostępne za pośrednictwem handlera dokumentów lub URI.
- Pliki przypominające skróty (`.webloc`, `.inetloc`, `.fileloc`), które ostatecznie przekazują obsługę do LaunchServices. W przypadku sztuczek w stylu `.fileloc` i powiązanych zagadnień dotyczących Gatekeeper sprawdź [tę inną stronę](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Jeśli Twoim celem jest pasywne wykonanie kodu wynikające wyłącznie z przeglądania folderu lub wybrania pliku, sprawdź także dedykowaną stronę dotyczącą [generatorów Quick Look](macos-proces-abuse/macos-quicklook-generators.md), ponieważ jest to inna, choć blisko powiązana, powierzchnia handlerów plików.

## Referencje

- [1] [Objective-See - Zdalne wykorzystanie Maca za pośrednictwem niestandardowych schematów URL](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Omijanie bramy: bliższe spojrzenie na luki Gatekeeper w systemie macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
