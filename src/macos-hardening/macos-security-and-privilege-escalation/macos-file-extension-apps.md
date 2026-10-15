# Programy obsługujące rozszerzenia plików i schematy URL w macOS

{{#include ../../banners/hacktricks-training.md}}

## Baza danych LaunchServices

Jest to baza danych wszystkich aplikacji zainstalowanych w macOS, którą można odpytywać, aby uzyskać informacje o każdej z nich, takie jak obsługiwane **schematy URL**, **typy dokumentów**, **UTI** i domyślne programy obsługujące.

Bazę tę można zrzucić za pomocą:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Lub używając narzędzia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** jest mózgiem bazy danych. Udostępnia **kilka usług XPC**, takich jak `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i inne. Wymaga jednak również **pewnych entitlements** od aplikacji, aby mogły korzystać z udostępnionych funkcji XPC, takich jak `.launchservices.changedefaulthandler` lub `.launchservices.changeurlschemehandler`, które umożliwiają zmianę domyślnych aplikacji dla typów MIME lub schematów URL.

**`/System/Library/CoreServices/launchservicesd`** udostępnia usługę `com.apple.coreservices.launchservicesd`, za pomocą której można uzyskać informacje o uruchomionych aplikacjach. Można z niej korzystać przy użyciu narzędzia systemowego **`/usr/bin/lsappinfo`** lub [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Z perspektywy operatora warto pamiętać, że zazwyczaj przydatne są **dwa widoki**:

- **Baza rejestracji** zarządzana przez LaunchServices / `lsd` (oparta na plikach `.csstore`).
- **Efektywne ustawienia domyślne dla użytkownika** przechowywane w tablicy `LSHandlers` w pliku `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`.

To rozróżnienie ma znaczenie: aplikacja może być **zarejestrowana** jako obsługująca dany typ lub schemat, ale **aktualną aplikacją domyślną** nadal może być inny bundle ID.

W nowszych wydaniach macOS wyszukiwanie aplikacji do rejestracji nie ogranicza się do `/Applications`: aplikacje w innych folderach widocznych w Spotlight i dostępnych dla systemu oraz na zamontowanych lub udostępnionych woluminach mogą zostać dodane do rejestru. Dlatego podczas analizy zachowuj informacje o `path` i woluminie z `lsregister -dump` i nie zakładaj, że wyrejestrowanie aplikacji będzie trwałe, dopóki pakiet aplikacji pozostaje wykrywalny.<sup>[[4]](#references)</sup>

## Obsługa aplikacji dla rozszerzeń plików i schematów URL

Poniższe polecenie może pomóc znaleźć aplikacje, które mogą otwierać pliki w zależności od ich rozszerzenia:

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

## Enumerowanie aktywnych programów obsługi

Najbardziej przydatnym plikiem zawierającym **domyślne ustawienia bieżącego użytkownika** jest zazwyczaj:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Aby zrzucić obsługiwane przez nią **schematy URL**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Aby wykonać dump handlerów **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Aby ustalić drzewo UTI przykładowego pliku:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Jeśli chcesz korzystać z bardziej przyjaznego CLI do sprawdzania lub zmieniania ustawień domyślnych:

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

Rozpoznawanie programu obsługującego plik ma również warstwę **specyficzną dla danego pliku**. Zanim LaunchServices użyje UTI pliku i globalnego ustawienia domyślnego użytkownika, sprawdza atrybut rozszerzony `com.apple.LaunchServices.OpenWith`. Finder tworzy go po wybraniu opcji **Zawsze otwieraj za pomocą** dla jednego pliku; jego wartość to binarna lista właściwości zawierająca ścieżkę do aplikacji, identyfikator pakietu i selektor wersji.<sup>[[3]](#references)</sup>

Sprawdź i zdekoduj go, nie ufając rozszerzeniu nazwy pliku:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Jest to przydatne, gdy pojedyncza przynęta otwiera się w nieoczekiwanej aplikacji, mimo że `duti`, `dutix` lub `LSHandlers` wskazuje bezpieślną globalną aplikację domyślną. W kontrolowanym laboratorium dokładną nieprzejrzystą wartość można skopiować z pliku skonfigurowanego w Finderze; jej usunięcie przywraca normalne rozpoznawanie na podstawie typu:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Interesujące klucze Info.plist

Podczas wstępnej analizy pakietu aplikacji najważniejsze są te klucze:

- **`CFBundleDocumentTypes`**: grupy dokumentów, które pakiet deklaruje jako obsługiwane.
- **`LSItemContentTypes`**: **nowoczesny / preferowany** sposób przypisywania typów dokumentów do UTI.
- **`LSHandlerRank`**: priorytet używany przez LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: niestandardowe schematy URI obsługiwane przez aplikację.
- **`UTExportedTypeDeclarations`**: UTI, których aplikacja jest **właścicielem**.
- **`UTImportedTypeDeclarations`**: UTI, których aplikacja nie jest właścicielem, ale które chce udostępnić systemowi.

Przydatnym poleceniem do szybkiej analizy jest:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Subtelny, ale ważny szczegół: jeśli obecny jest klucz **`LSItemContentTypes`**, starsze klucze, takie jak **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`**, są w praktyce danymi zapewniającymi zgodność ze starszymi wersjami. Przy rzeczywistym rozwiązywaniu obsługi najpierw skup się na ścieżce UTI.

## Uwagi ofensywne

Aplikacje nie muszą być uruchomione, aby ich deklaracje obsługi były interesujące, ale **samo zapisanie pakietu `.app` nie gwarantuje natychmiastowej rejestracji**. Finder może zarejestrować aplikację po jej wykryciu, również gdy użytkownik przegląda jej folder; rejestracja może też nastąpić podczas uruchamiania lub logowania albo przez jawne wywołanie rejestracji. Przed testowaniem deklaracji sprawdź `lsregister -dump`. Sama rejestracja ani nie uruchamia aplikacji, ani nie ustawia jej jako efektywnego domyślnego programu.<sup>[[5]](#references)</sup> Informacje o wymaganiach dotyczących persistence znajdziesz w sekcji [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Jest to przydatne zarówno w badaniach nad **persistence / hijackingiem**, jak i w **łańcuchach initial access**:

- Złośliwa aplikacja może zadeklarować obsługę **rzadkiego rozszerzenia** lub **niestandardowego UTI** i czekać, aż ofiara otworzy plik-przynętę.
- Złośliwa aplikacja może zarejestrować **niestandardowy schemat URL**, do którego można uzyskać dostęp z przeglądarki, aplikacji Electron, dokumentu biurowego, klienta czatu lub innej aplikacji pomocniczej.<sup>[[1]](#references)</sup>
- Aby oddzielić normalne rozstrzyganie domyślnego programu od testowania konkretnego kandydata na obsługę, wywołaj schemat przez LaunchServices za pomocą `open 'targetscheme://host/path?value=test'`, a następnie wskaż konkretny zarejestrowany bundle poleceniem `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Przydaje się to do audytu sposobu, w jaki aplikacja odbierająca weryfikuje i dekoduje kontrolowane przez atakującego elementy URL.<sup>[[1]](#references)</sup>
- Jeśli zmodyfikujesz pakiet aplikacji po jego zbudowaniu, możesz wymusić ponowne przeanalizowanie go przez LaunchServices za pomocą:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Podczas testowania podejrzanych pakietów zwróć szczególną uwagę na:

- **`LSHandlerRank=Owner`** dla nietypowych typów.
- **Szerokie** tablice `CFBundleDocumentTypes` deklarujące obsługę wielu rozszerzeń.
- **Aplikacje pomocnicze / opakowujące**, których jedyne interesujące zachowanie uruchamia się za pośrednictwem obsługi dokumentów lub URI.
- **Pliki przypominające skróty** (`.webloc`, `.inetloc`, `.fileloc`), które ostatecznie przekazują obsługę do LaunchServices. Informacje o sztuczkach w stylu `.fileloc` i powiązanych aspektach Gatekeeper znajdziesz na [tej stronie](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### Parametry URL przekazywane do dalszych opcji

Potwierdzenie otwarcia zewnętrznego protokołu w przeglądarce zatwierdza jedynie otwarcie programu obsługującego ten protokół; nie oznacza, że parametry URL są godne zaufania. Prześledź parser URL odbierającej aplikacji aż do używanej biblioteki, silnika multimedialnego, procesu pomocniczego lub opcji zapisu plików. Poszukaj prefiksu klucza zapytania, który zamienia pola URL na nazwy dalszych opcji. Przetestuj zarówno separatory dosłowne, jak i zakodowane procentowo, używając nieszkodliwego znacznika na koncie testowym.<sup>[[6]](#references)</sup>

Zweryfikuj **końcową opcję akceptowaną przez dalszy komponent**, a nie tylko początkowe parsowanie w aplikacji. Jeden z programów obsługujących pozwalał przekazywać klucze zapytania z prefiksem do poleceń wejściowych mpv; zablokowanie tej opcji nadal pozostawiało możliwość zapisu pliku. Testuj dostępną klasę opcji, a nie tylko jeden znany niebezpieczny klucz.<sup>[[7]](#references)</sup>

### Wbudowana obsługa `applescript://`

Obsługa URL `applescript://com.apple.scripteditor` akceptuje `action=new` oraz parametr `script` zakodowany w URL. Dzięki temu odnośnik w przeglądarce może otworzyć Script Editor z umieszczonym w edytorze kodem AppleScript kontrolowanym przez atakującego, bez konieczności wklejania go w Terminalu. **Nie powoduje to automatycznego wykonania**: przeglądarka może zapytać o zgodę na otwarcie Script Editor, a użytkownik musi uruchomić skrypt.<sup>[[8]](#references)</sup>

Nowsze wersje macOS mogą wyświetlać ostrzeżenie dotyczące dokumentu skryptu, a XProtect skanuje AppleScript podczas wykonywania.<sup>[[8]](#references)[[9]](#references)</sup>

Użyj nieszkodliwej lokalnej sondy, aby sprawdzić obsługę i monity w ocenianej wersji macOS; sonda powinna jedynie wypełnić edytor, dopóki użytkownik nie kliknie **Run**.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Jeśli Twoim celem jest pasywne wykonanie kodu przez samo przeglądanie folderu lub wybranie pliku, sprawdź też dedykowaną stronę dotyczącą [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), ponieważ opisuje ona inną, ale ściśle powiązaną powierzchnię obsługi plików.



## References

- [1] [Objective-See - Zdalne przejęcie Maca za pomocą niestandardowych schematów URL](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Ominięcie Gate: bliższe spojrzenie na luki w Gatekeeperze w macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Jak macOS otwiera plik we właściwej aplikacji](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Kontrolowanie LaunchServices w macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Koncepcje Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Badanie wykonania poleceń przez schemat URL IINA](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Niebezpieczna obsługa opcji mpv w schemacie URL](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - Technika ClickFix wykorzystuje Script Editor zamiast Terminala](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Zabezpieczenia Terminala i skryptów](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
