# Obsługa rozszerzeń plików i schematów URL przez aplikacje w macOS

{{#include ../../banners/hacktricks-training.md}}

## Baza danych LaunchServices

Jest to baza danych wszystkich aplikacji zainstalowanych w macOS, którą można przeszukiwać, aby uzyskać informacje o każdej z nich, takie jak obsługiwane **schematy URL**, **typy dokumentów**, **UTI** i domyślne aplikacje obsługujące te typy.

Bazę danych można zrzucić za pomocą:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Lub używając narzędzia [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** to mózg bazy danych. Udostępnia **kilka usług XPC**, takich jak `.lsd.installation`, `.lsd.open`, `.lsd.openurl` i inne. Aby aplikacje mogły korzystać z udostępnionych funkcji XPC, wymagane są jednak **określone entitlements**, na przykład `.launchservices.changedefaulthandler` lub `.launchservices.changeurlschemehandler`, które pozwalają zmieniać domyślne aplikacje dla typów MIME lub schematów URL, a także inne.

**`/System/Library/CoreServices/launchservicesd`** rejestruje usługę `com.apple.coreservices.launchservicesd` i można wysyłać do niej zapytania, aby uzyskać informacje o uruchomionych aplikacjach. Można wysyłać do niej zapytania za pomocą systemowego narzędzia **`/usr/bin/lsappinfo`** lub [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Z perspektywy operatora warto pamiętać, że zazwyczaj przydatne są **dwa widoki**:

- **Baza danych rejestracji** zarządzana przez LaunchServices / `lsd` (oparta na plikach `.csstore`).
- **Efektywne ustawienia domyślne dla użytkownika** przechowywane w `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, w tablicy `LSHandlers`.

To rozróżnienie ma znaczenie: aplikacja może być **zarejestrowana** jako obsługująca dany typ lub schemat, ale **aktualnie domyślną** aplikacją może nadal być inny identyfikator bundle.

W nowszych wersjach macOS wykrywanie zarejestrowanych aplikacji nie ogranicza się do `/Applications`: do rejestru mogą trafić aplikacje z innych dostępnych folderów widocznych dla Spotlight oraz z zamontowanych lub współdzielonych woluminów. Dlatego podczas triage zachowaj informacje o `path` i woluminie z wyniku `lsregister -dump` i nie zakładaj, że wyrejestrowanie aplikacji będzie trwałe, dopóki jej bundle pozostaje wykrywalny.<sup>[[4]](#references)</sup>

## Obsługa plików według rozszerzenia i schematów URL

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

Możesz także sprawdzić rozszerzenia obsługiwane przez aplikację, wykonując:

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

## Ustalanie aktywnych programów obsługi

Najbardziej przydatnym plikiem zawierającym **domyślne aplikacje bieżącego użytkownika** jest zazwyczaj:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Aby zrzucić handlery **URL scheme** z tej aplikacji:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Aby wykonać dump obsługiwaczy **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Aby rozwiązać drzewo UTI przykładowego pliku:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Jeśli chcesz używać bardziej przyjaznego CLI do sprawdzania lub zmieniania ustawień domyślnych:

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

Rozwiązywanie skojarzeń obejmuje również warstwę **specyficzną dla pliku**. Zanim LaunchServices użyje UTI pliku i globalnego domyślnego ustawienia użytkownika, sprawdza atrybut rozszerzony `com.apple.LaunchServices.OpenWith`. Finder tworzy go po wybraniu opcji **Zawsze otwieraj za pomocą** dla jednego pliku; jego wartość to binarna lista właściwości zawierająca ścieżkę aplikacji, identyfikator pakietu i selektor wersji.<sup>[[3]](#references)</sup>

Sprawdź i zdekoduj ten atrybut, nie ufając rozszerzeniu nazwy pliku:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Jest to przydatne, gdy pojedynczy wabik otwiera się w nieoczekiwanej aplikacji, mimo że `duti`, `dutix` lub `LSHandlers` wskazuje bezpieczną wartość domyślną dla całego systemu. W kontrolowanym laboratorium dokładną nieprzejrzystą wartość można skopiować z pliku skonfigurowanego za pomocą Findera; jej usunięcie przywraca normalne rozpoznawanie na podstawie typu:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Interesujące klucze Info.plist

Podczas wstępnej analizy pakietu aplikacji najważniejsze są te klucze:

- **`CFBundleDocumentTypes`**: grupy dokumentów, które pakiet deklaruje, że może otwierać.
- **`LSItemContentTypes`**: **nowoczesny / preferowany** sposób powiązania typów dokumentów z UTI.
- **`LSHandlerRank`**: ranking używany przez LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: niestandardowe schematy URI obsługiwane przez aplikację.
- **`UTExportedTypeDeclarations`**: UTI, których aplikacja jest **właścicielem**.
- **`UTImportedTypeDeclarations`**: UTI, których aplikacja nie jest właścicielem, ale które chce udostępnić systemowi do rozpoznawania.

Przydatne polecenie do szybkiej analizy to:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Subtelny, ale ważny szczegół: jeśli występuje **`LSItemContentTypes`**, starsze klucze, takie jak **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** i **`CFBundleTypeOSTypes`**, są w praktyce danymi zapewniającymi zgodność ze starszymi wersjami. Przy ustalaniu rzeczywistego handlera najpierw skup się na ścieżce UTI.

## Notatki ofensywne

Aplikacje nie muszą być uruchamiane, aby stały się interesujące. Porzucony lub sklonowany pakiet `.app` może zostać **automatycznie przeanalizowany przez `lsd`, gdy tylko zostanie zapisany na dysku**, a zadeklarowane przez niego typy dokumentów i schematy URL mogą zostać zarejestrowane, zanim użytkownik uruchomi pakiet.

Jest to przydatne zarówno w **badaniach nad persistence / hijacking**, jak i w **łańcuchach initial access**:

- Złośliwa aplikacja może zgłosić obsługę **rzadkiego rozszerzenia** lub **niestandardowego UTI** i czekać, aż ofiara otworzy plik-przynętę.
- Złośliwa aplikacja może zarejestrować **niestandardowy schemat URL**, dostępny z poziomu przeglądarki, aplikacji Electron, dokumentu biurowego, klienta czatu lub innej aplikacji pomocniczej.<sup>[[1]](#references)</sup>
- Aby odróżnić normalne rozstrzyganie domyślne od testowania konkretnego kandydata na handler, wywołaj schemat przez LaunchServices poleceniem `open 'targetscheme://host/path?value=test'`, a następnie wskaż konkretny zarejestrowany pakiet poleceniem `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Przydaje się to podczas audytu sposobu, w jaki aplikacja odbierająca sprawdza i dekoduje kontrolowane przez atakującego komponenty URL.<sup>[[1]](#references)</sup>
- Jeśli edytujesz pakiet aplikacji po jego zbudowaniu, możesz wymusić ponowną analizę przez LaunchServices za pomocą:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Podczas testowania podejrzanych pakietów zwróć szczególną uwagę na:

- **`LSHandlerRank=Owner`** dla nietypowych typów.
- **Rozbudowane** tablice `CFBundleDocumentTypes`, deklarujące obsługę wielu rozszerzeń.
- **Aplikacje pomocnicze / opakowujące**, których jedyne interesujące zachowanie uruchamia się za pośrednictwem procedury obsługi dokumentów lub URI.
- **Pliki przypominające skróty** (`.webloc`, `.inetloc`, `.fileloc`), które ostatecznie wywołują LaunchServices. W przypadku sztuczek związanych z plikami `.fileloc` i powiązanych zagadnień dotyczących Gatekeepera sprawdź [tę inną stronę](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Jeśli celem jest pasywne wykonanie kodu przez samo przejście do folderu lub wybranie pliku, sprawdź również dedykowaną stronę dotyczącą [generatorów Quick Look](macos-proces-abuse/macos-quicklook-generators.md), ponieważ jest to inna, choć blisko powiązana powierzchnia obsługi plików.



## References

- [1] [Objective-See - Zdalne przejęcie Maca za pomocą niestandardowych schematów URL](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Omijanie bramki: bliższe spojrzenie na luki w Gatekeeperze w macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Jak macOS otwiera plik we właściwej aplikacji](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Kontrolowanie LaunchServices w macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
