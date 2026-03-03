# Ucieczka z kiosków

{{#include ../banners/hacktricks-training.md}}

---

## Sprawdź urządzenie fizyczne

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Wyłączenie i ponowne włączenie urządzenia może ujawnić ekran startowy    |
| Power cable  | Sprawdź, czy urządzenie uruchomi się ponownie po krótkotrwałym odcięciu zasilania |
| USB ports    | Podłącz fizyczną klawiaturę, aby uzyskać więcej skrótów                      |
| Ethernet     | Skanowanie sieci lub sniffing może umożliwić dalszą eksploatację           |

## Sprawdź możliwe akcje wewnątrz aplikacji GUI

**Common Dialogs** to opcje takie jak **saving a file**, **opening a file**, wybór czcionki, koloru... Większość z nich będzie **offer a full Explorer functionality**. Oznacza to, że będziesz mieć dostęp do funkcji Explorer, jeśli możesz dostać się do tych opcji:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Powinieneś sprawdzić, czy możesz:

- Modyfikować lub tworzyć nowe pliki
- Tworzyć symbolic links
- Uzyskać dostęp do restricted areas
- Uruchomić inne aplikacje

### Wykonywanie poleceń

Może **używając opcji `Open with`** opcji\*\* możesz otworzyć/wykonać jakiś rodzaj shell.

#### Windows

Na przykład _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ Znajdź więcej binariów, które można wykorzystać do wykonywania poleceń (i wykonywania nieoczekiwanych działań) tutaj: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Więcej tutaj: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Omijanie ograniczeń ścieżek

- **Environment variables**: Istnieje wiele zmiennych środowiskowych wskazujących na pewne ścieżki
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Ścieżki do łączenia się z udziałami sieciowymi. Powinieneś spróbować połączyć się z C$ lokalnej maszyny ("\\\127.0.0.1\c$\Windows\System32")
- **More UNC paths:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Użyj *Open/Save/Print-to-file* dialogs jako Explorer-lite. Spróbuj `*.*` / `*.exe` w polu nazwy pliku, kliknij prawym przyciskiem na foldery dla **Open in new window**, i użyj **Properties → Open file location** aby rozszerzyć nawigację.
- **Create execution paths from dialogs**: Utwórz nowy plik i zmień jego nazwę na `.CMD` lub `.BAT`, albo stwórz skrót wskazujący na `%WINDIR%\System32` (lub konkretny binarny jak `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Jeśli możesz przeglądać do `cmd.exe`, spróbuj **drag-and-drop** dowolnego pliku na niego, aby uruchomić prompt. Jeśli Task Manager jest osiągalny (`CTRL+SHIFT+ESC`), użyj **Run new task**.
- **Task Scheduler bypass**: Jeśli interaktywne shelle są zablokowane, ale harmonogramowanie jest dozwolone, utwórz zadanie uruchamiające `cmd.exe` (GUI `taskschd.msc` lub `schtasks.exe`).
- **Weak allowlists**: Jeśli wykonanie jest dozwolone na podstawie **filename/extension**, zmień nazwę swojego payloadu na dozwoloną nazwę. Jeśli dozwolone według **directory**, skopiuj payload do dozwolonego folderu programu i uruchom go stamtąd.
- **Find writable staging paths**: Zacznij od `%TEMP%` i wypisz zapisywalne foldery przy pomocy Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Następny krok**: Jeśli zdobędziesz shell, przejdź do Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Pobierz binaria

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Edytor rejestru: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Dostęp do systemu plików z poziomu przeglądarki

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Skróty klawiszowe

- Sticky Keys – Naciśnij SHIFT 5 razy
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Przytrzymaj NUMLOCK przez 5 sekund
- Filter Keys – Przytrzymaj prawy SHIFT przez 12 sekund
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Pokaż pulpit
- WINDOWS+E – Uruchom Windows Explorer
- WINDOWS+R – Uruchom
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Szukaj
- SHIFT+F10 – Menu kontekstowe
- CTRL+SHIFT+ESC – Menedżer zadań
- CTRL+ALT+DEL – Ekran startowy w nowszych wersjach Windows
- F1 – Pomoc F3 – Szukaj
- F6 – Pasek adresu
- F11 – Przełącz pełny ekran w Internet Explorer
- CTRL+H – Historia w Internet Explorer
- CTRL+T – Internet Explorer – Nowa karta
- CTRL+N – Internet Explorer – Nowa strona
- CTRL+O – Otwórz plik
- CTRL+S – Zapisz CTRL+N – Nowe RDP / Citrix

### Gesty przesunięcia

- Przeciągnij od lewej do prawej, aby zobaczyć wszystkie otwarte okna, zminimalizować aplikację KIOSK i uzyskać bezpośredni dostęp do całego systemu;
- Przeciągnij od prawej do lewej, aby otworzyć Action Center, zminimalizować aplikację KIOSK i uzyskać bezpośredni dostęp do całego systemu;
- Przeciągnij od górnej krawędzi, aby zobaczyć pasek tytułu dla aplikacji otwartej w trybie pełnoekranowym;
- Przeciągnij w górę od dołu, aby pokazać pasek zadań w aplikacji pełnoekranowej.

### Triki Internet Explorera

#### 'Image Toolbar'

To pasek narzędzi, który pojawia się w lewym górnym rogu obrazu po jego kliknięciu. Będziesz mógł zapisać, wydrukować, wysłać maila, otworzyć "My Pictures" w Explorer. Kiosk musi używać Internet Explorer.

#### Protokół Shell

Wpisz te adresy URL, aby uzyskać widok Explorer:

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Pokaż rozszerzenia plików

Sprawdź tę stronę, aby uzyskać więcej informacji: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Triki przeglądarek

Kopia zapasowa wersji iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Utwórz wspólne okno dialogowe za pomocą JavaScript i uzyskaj dostęp do Eksploratora plików: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesty i przyciski

- Przeciągnij w górę czterema (lub pięcioma) palcami / Podwójne dotknięcie przycisku Home: Wyświetla widok wielozadaniowości i umożliwia zmianę aplikacji
- Przeciągnij w lewo lub prawo czterema lub pięcioma palcami: Aby przejść do następnej/poprzedniej aplikacji
- Ściśnij ekran pięcioma palcami / Naciśnij przycisk Home / Przeciągnij szybko jednym palcem od dołu ekranu w górę: Aby przejść do ekranu głównego
- Przeciągnij jednym palcem od dołu ekranu około 1–2 cale (wolno): Pojawi się dock
- Przeciągnij w dół od górnej części ekranu jednym palcem: Aby zobaczyć powiadomienia
- Przeciągnij w dół prawy górny róg ekranu jednym palcem: Aby zobaczyć centrum sterowania iPad Pro
- Przeciągnij jednym palcem od lewej krawędzi ekranu na 1–2 cale: Aby zobaczyć widok Today
- Szybko przesuń jednym palcem z centrum ekranu w prawo lub w lewo: Aby przejść do następnej/poprzedniej aplikacji
- Naciśnij i przytrzymaj przycisk On/Off/Sleep w prawym górnym rogu iPada + Przesuń suwak Slide to power off w prawo: Aby wyłączyć urządzenie
- Naciśnij przycisk On/Off/Sleep w prawym górnym rogu iPada oraz przycisk Home przez kilka sekund: Aby wymusić twarde wyłączenie
- Naciśnij szybko przycisk On/Off/Sleep w prawym górnym rogu iPada oraz przycisk Home: Aby wykonać zrzut ekranu, który pojawi się w lewym dolnym rogu ekranu. Jeśli przytrzymasz oba przyciski przez kilka sekund, wykona się twarde wyłączenie.

### Skróty

Powinieneś mieć klawiaturę iPada lub adapter USB do klawiatury. Poniżej pokazano tylko skróty, które mogą pomóc w opuszczeniu aplikacji.

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### Skróty systemowe

Te skróty dotyczą ustawień wizualnych i dźwięku, w zależności od użycia iPada.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Przyciemnij ekran                                                               |
| F2       | Rozjaśnij ekran                                                                 |
| F7       | Cofnij jedną piosenkę                                                           |
| F8       | Odtwórz/pauza                                                                   |
| F9       | Następna piosenka                                                               |
| F10      | Wycisz                                                                          |
| F11      | Zmniejsz głośność                                                               |
| F12      | Zwiększ głośność                                                                |
| ⌘ Space  | Wyświetla listę dostępnych języków; aby wybrać, naciśnij ponownie spację.      |

#### Nawigacja iPada

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Przejdź do ekranu głównego                              |
| ⌘⇧H (Command-Shift-H)                              | Przejdź do ekranu głównego                              |
| ⌘ (Space)                                          | Otwórz Spotlight                                        |
| ⌘⇥ (Command-Tab)                                   | Wyświetl ostatnie dziesięć używanych aplikacji          |
| ⌘\~                                                | Przejdź do ostatniej aplikacji                          |
| ⌘⇧3 (Command-Shift-3)                              | Zrzut ekranu (pojawia się w lewym dolnym rogu do zapisania lub akcji) |
| ⌘⇧4                                                | Zrzut ekranu i otwórz go w edytorze                     |
| Press and hold ⌘                                   | Lista dostępnych skrótów dla aplikacji                  |
| ⌘⌥D (Command-Option/Alt-D)                         | Pokaż dock                                              |
| ^⌥H (Control-Option-H)                             | Przycisk Home                                           |
| ^⌥H H (Control-Option-H-H)                         | Pokaż pasek wielozadaniowości                           |
| ^⌥I (Control-Option-i)                             | Wybór elementu                                          |
| Escape                                             | Przywróć / Wstecz                                       |
| → (Right arrow)                                    | Następny element                                        |
| ← (Left arrow)                                     | Poprzedni element                                       |
| ↑↓ (Up arrow, Down arrow)                          | Jednoczesne stuknięcie zaznaczonego elementu           |
| ⌥ ↓ (Option-Down arrow)                            | Przewiń w dół                                           |
| ⌥↑ (Option-Up arrow)                               | Przewiń w górę                                          |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Przewiń w lewo lub prawo                                |
| ^⌥S (Control-Option-S)                             | Włącz/wyłącz mowę VoiceOver                             |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Przełącz na poprzednią aplikację                        |
| ⌘⇥ (Command-Tab)                                   | Przełącz z powrotem na oryginalną aplikację             |
| ←+→, then Option + ← or Option+→                   | Nawiguj po Docku                                        |

#### Skróty Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Otwórz lokalizację                               |
| ⌘T                      | Otwórz nową kartę                                |
| ⌘W                      | Zamknij bieżącą kartę                            |
| ⌘R                      | Odśwież bieżącą kartę                            |
| ⌘.                      | Zatrzymaj ładowanie bieżącej karty               |
| ^⇥                      | Przejdź do następnej karty                       |
| ^⇧⇥ (Control-Shift-Tab) | Przejdź do poprzedniej karty                     |
| ⌘L                      | Zaznacz pole tekstowe/URL, aby je edytować       |
| ⌘⇧T (Command-Shift-T)   | Otwórz ostatnio zamkniętą kartę (można użyć wielokrotnie) |
| ⌘\[                     | Cofnij jedną stronę w historii przeglądania      |
| ⌘]                      | Przejdź do przodu o jedną stronę w historii       |
| ⌘⇧R                     | Aktywuj tryb czytnika (Reader Mode)              |

#### Skróty Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Otwórz lokalizację           |
| ⌘T                         | Otwórz nową kartę            |
| ⌘W                         | Zamknij bieżącą kartę        |
| ⌘R                         | Odśwież bieżącą kartę        |
| ⌘.                         | Zatrzymaj ładowanie karty    |
| ⌘⌥F (Command-Option/Alt-F) | Wyszukaj w skrzynce pocztowej|

## Źródła

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
