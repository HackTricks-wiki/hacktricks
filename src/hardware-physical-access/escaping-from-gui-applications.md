# Ucieczka z KIOSK-ów

{{#include ../banners/hacktricks-training.md}}

---

## Sprawdź urządzenie fizyczne

| Komponent     | Akcja                                                              |
| ------------- | ------------------------------------------------------------------ |
| Przycisk zasilania | Wyłączenie i ponowne włączenie urządzenia może ujawnić ekran startowy |
| Kabel zasilający  | Sprawdź, czy urządzenie uruchamia się ponownie po krótkim odcięciu zasilania |
| Porty USB    | Podłącz fizyczną klawiaturę z dodatkowymi skrótami                |
| Ethernet     | Skanowanie sieci lub sniffing może umożliwić dalszą eksploatację   |

## Sprawdź możliwe działania w aplikacji GUI

**Typowe okna dialogowe** to opcje **zapisywania pliku**, **otwierania pliku**, wybierania czcionki, koloru... Większość z nich **oferuje pełną funkcjonalność Eksploratora**. Oznacza to, że będziesz mógł uzyskać dostęp do funkcji Eksploratora, jeśli możesz uzyskać dostęp do tych opcji:

- Zamknij/Zamknij jako
- Otwórz/Otwórz za pomocą
- Drukuj
- Eksportuj/Importuj
- Szukaj
- Skanuj

Powinieneś sprawdzić, czy możesz:

- Modyfikować lub tworzyć nowe pliki
- Tworzyć linki symboliczne
- Uzyskać dostęp do zastrzeżonych obszarów
- Uruchamiać inne aplikacje

### Wykonywanie poleceń

Może **używając opcji `Otwórz za pomocą`** możesz otworzyć/wykonać jakiś rodzaj powłoki.

#### Windows

Na przykład _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ znajdź więcej binarnych plików, które mogą być używane do wykonywania poleceń (i wykonywania nieoczekiwanych działań) tutaj: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Więcej tutaj: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Obejście ograniczeń ścieżek

- **Zmienne środowiskowe**: Istnieje wiele zmiennych środowiskowych, które wskazują na jakąś ścieżkę
- **Inne protokoły**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Linki symboliczne**
- **Skróty**: CTRL+N (otwórz nową sesję), CTRL+R (wykonaj polecenia), CTRL+SHIFT+ESC (Menadżer zadań), Windows+E (otwórz eksplorator), CTRL-B, CTRL-I (Ulubione), CTRL-H (Historia), CTRL-L, CTRL-O (Plik/Otwórz), CTRL-P (Okno drukowania), CTRL-S (Zapisz jako)
- Ukryte menu administracyjne: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **Ścieżki UNC**: Ścieżki do połączenia z udostępnionymi folderami. Powinieneś spróbować połączyć się z C$ lokalnej maszyny ("\\\127.0.0.1\c$\Windows\System32")
- **Więcej ścieżek UNC:**

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

### Pobierz swoje binaria

Konsola: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Eksplorator: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Edytor rejestru: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Uzyskiwanie dostępu do systemu plików z przeglądarki

| ŚCIEŻKA                | ŚCIEŻKA              | ŚCIEŻKA               | ŚCIEŻKA                |
| --------------------- | ------------------- | --------------------- | --------------------- |
| File:/C:/windows      | File:/C:/windows/   | File:/C:/windows\\    | File:/C:\windows      |
| File:/C:\windows\\    | File:/C:\windows/   | File://C:/windows     | File://C:/windows/    |
| File://C:/windows\\   | File://C:\windows   | File://C:\windows/    | File://C:\windows\\   |
| C:/windows            | C:/windows/         | C:/windows\\         | C:\windows            |
| C:\windows\\          | C:\windows/         | %WINDIR%             | %TMP%                 |
| %TEMP%                | %SYSTEMDRIVE%       | %SYSTEMROOT%         | %APPDATA%             |
| %HOMEDRIVE%           | %HOMESHARE          |                      | <p><br></p>           |

### Skróty

- Sticky Keys – Naciśnij SHIFT 5 razy
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Przytrzymaj NUMLOCK przez 5 sekund
- Filter Keys – Przytrzymaj prawy SHIFT przez 12 sekund
- WINDOWS+F1 – Wyszukiwanie w systemie Windows
- WINDOWS+D – Pokaż pulpit
- WINDOWS+E – Uruchom Eksplorator Windows
- WINDOWS+R – Uruchom
- WINDOWS+U – Centrum ułatwień dostępu
- WINDOWS+F – Szukaj
- SHIFT+F10 – Menu kontekstowe
- CTRL+SHIFT+ESC – Menedżer zadań
- CTRL+ALT+DEL – Ekran powitalny w nowszych wersjach Windows
- F1 – Pomoc F3 – Szukaj
- F6 – Pasek adresu
- F11 – Przełącz pełny ekran w Internet Explorer
- CTRL+H – Historia Internet Explorer
- CTRL+T – Internet Explorer – Nowa karta
- CTRL+N – Internet Explorer – Nowa strona
- CTRL+O – Otwórz plik
- CTRL+S – Zapisz CTRL+N – Nowy RDP / Citrix

### Przesunięcia

- Przesuń od lewej do prawej, aby zobaczyć wszystkie otwarte okna, minimalizując aplikację KIOSK i uzyskując dostęp do całego systemu operacyjnego bezpośrednio;
- Przesuń od prawej do lewej, aby otworzyć Centrum akcji, minimalizując aplikację KIOSK i uzyskując dostęp do całego systemu operacyjnego bezpośrednio;
- Przesuń w dół z górnej krawędzi, aby uczynić pasek tytułu widocznym dla aplikacji otwartej w trybie pełnoekranowym;
- Przesuń w górę od dołu, aby pokazać pasek zadań w aplikacji pełnoekranowej.

### Sztuczki Internet Explorer

#### 'Pasek narzędzi obrazów'

To pasek narzędzi, który pojawia się w lewym górnym rogu obrazu po jego kliknięciu. Będziesz mógł Zapisz, Drukuj, Mailto, Otwórz "Moje obrazy" w Eksploratorze. Kiosk musi używać Internet Explorer.

#### Protokół Shell

Wpisz te adresy URL, aby uzyskać widok Eksploratora:

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Panel sterowania
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mój komputer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Moje miejsca w sieci
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Pokaż rozszerzenia plików

Sprawdź tę stronę, aby uzyskać więcej informacji: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Sztuczki przeglądarek

Kopia zapasowa wersji iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

Utwórz wspólne okno dialogowe za pomocą JavaScript i uzyskaj dostęp do eksploratora plików: `document.write('<input/type=file>')`\
Źródło: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesty i przyciski

- Przesuń w górę czterema (lub pięcioma) palcami / Podwójne naciśnięcie przycisku Home: Aby wyświetlić widok multitaskingu i zmienić aplikację
- Przesuń w jedną lub drugą stronę czterema lub pięcioma palcami: Aby przejść do następnej/ostatniej aplikacji
- Złap ekran pięcioma palcami / Naciśnij przycisk Home / Przesuń w górę jednym palcem od dołu ekranu w szybkim ruchu do góry: Aby uzyskać dostęp do ekranu głównego
- Przesuń jednym palcem od dołu ekranu tylko 1-2 cale (wolno): Pojawi się dock
- Przesuń w dół z górnej części wyświetlacza jednym palcem: Aby wyświetlić powiadomienia
- Przesuń w dół jednym palcem w prawym górnym rogu ekranu: Aby zobaczyć centrum sterowania iPada Pro
- Przesuń jednym palcem z lewej strony ekranu 1-2 cale: Aby zobaczyć widok Dzisiaj
- Szybko przesuń jednym palcem z centrum ekranu w prawo lub w lewo: Aby przejść do następnej/ostatniej aplikacji
- Naciśnij i przytrzymaj przycisk Włącz/**Wyłącz**/Uśpij w prawym górnym rogu **iPada +** Przesuń suwak **wyłączania** całkowicie w prawo: Aby wyłączyć
- Naciśnij przycisk Włącz/**Wyłącz**/Uśpij w prawym górnym rogu **iPada i przycisk Home przez kilka sekund**: Aby wymusić twarde wyłączenie
- Naciśnij przycisk Włącz/**Wyłącz**/Uśpij w prawym górnym rogu **iPada i przycisk Home szybko**: Aby zrobić zrzut ekranu, który pojawi się w lewym dolnym rogu wyświetlacza. Naciśnij oba przyciski jednocześnie bardzo krótko, ponieważ jeśli przytrzymasz je przez kilka sekund, zostanie wykonane twarde wyłączenie.

### Skróty

Powinieneś mieć klawiaturę iPada lub adapter klawiatury USB. Tylko skróty, które mogą pomóc w ucieczce z aplikacji, będą tutaj pokazane.

| Klawisz | Nazwa         |
| ------- | ------------ |
| ⌘       | Komenda      |
| ⌥       | Opcja (Alt)  |
| ⇧       | Shift        |
| ↩       | Powrót       |
| ⇥       | Tab          |
| ^       | Kontrola     |
| ←       | Strzałka w lewo   |
| →       | Strzałka w prawo  |
| ↑       | Strzałka w górę     |
| ↓       | Strzałka w dół     |

#### Skróty systemowe

Te skróty dotyczą ustawień wizualnych i dźwiękowych, w zależności od użycia iPada.

| Skrót   | Akcja                                                                         |
| ------- | ------------------------------------------------------------------------------ |
| F1      | Przyciemnij ekran                                                              |
| F2      | Rozjaśnij ekran                                                                |
| F7      | Wróć do poprzedniej piosenki                                                  |
| F8      | Odtwarzaj/pauzuj                                                               |
| F9      | Przewiń do następnej piosenki                                                |
| F10     | Wycisz                                                                          |
| F11     | Zmniejsz głośność                                                              |
| F12     | Zwiększ głośność                                                              |
| ⌘ Spacja | Wyświetl listę dostępnych języków; aby wybrać jeden, naciśnij spację ponownie. |

#### Nawigacja po iPadzie

| Skrót                                           | Akcja                                                  |
| ------------------------------------------------ | ------------------------------------------------------- |
| ⌘H                                                 | Przejdź do ekranu głównego                              |
| ⌘⇧H (Command-Shift-H)                              | Przejdź do ekranu głównego                              |
| ⌘ (Spacja)                                          | Otwórz Spotlight                                        |
| ⌘⇥ (Command-Tab)                                   | Lista ostatnich dziesięciu używanych aplikacji         |
| ⌘\~                                                | Przejdź do ostatniej aplikacji                          |
| ⌘⇧3 (Command-Shift-3)                              | Zrzut ekranu (pojawia się w lewym dolnym rogu, aby zapisać lub działać na nim) |
| ⌘⇧4                                                | Zrzut ekranu i otwórz go w edytorze                    |
| Naciśnij i przytrzymaj ⌘                           | Lista skrótów dostępnych dla aplikacji                  |
| ⌘⌥D (Command-Option/Alt-D)                         | Otwiera dock                                            |
| ^⌥H (Control-Option-H)                             | Przycisk Home                                           |
| ^⌥H H (Control-Option-H-H)                         | Pokaż pasek multitaskingu                                |
| ^⌥I (Control-Option-i)                             | Wybór elementu                                          |
| Escape                                             | Przycisk wstecz                                        |
| → (Strzałka w prawo)                               | Następny element                                        |
| ← (Strzałka w lewo)                                | Poprzedni element                                       |
| ↑↓ (Strzałka w górę, Strzałka w dół)              | Jednoczesne naciśnięcie wybranego elementu             |
| ⌥ ↓ (Opcja-Strzałka w dół)                        | Przewiń w dół                                         |
| ⌥↑ (Opcja-Strzałka w górę)                        | Przewiń w górę                                        |
| ⌥← lub ⌥→ (Opcja-Strzałka w lewo lub Opcja-Strzałka w prawo) | Przewiń w lewo lub w prawo                            |
| ^⌥S (Control-Option-S)                             | Włącz lub wyłącz mowę VoiceOver                        |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Przełącz do poprzedniej aplikacji                      |
| ⌘⇥ (Command-Tab)                                   | Przełącz z powrotem do oryginalnej aplikacji          |
| ←+→, następnie Opcja + ← lub Opcja+→               | Nawiguj przez Dock                                     |

#### Skróty Safari

| Skrót                | Akcja                                           |
| -------------------- | ----------------------------------------------- |
| ⌘L (Command-L)       | Otwórz lokalizację                              |
| ⌘T                   | Otwórz nową kartę                              |
| ⌘W                   | Zamknij bieżącą kartę                          |
| ⌘R                   | Odśwież bieżącą kartę                          |
| ⌘.                   | Zatrzymaj ładowanie bieżącej karty             |
| ^⇥                   | Przełącz do następnej karty                    |
| ^⇧⇥ (Control-Shift-Tab) | Przejdź do poprzedniej karty                   |
| ⌘L                   | Wybierz pole tekstowe/URL, aby je zmodyfikować  |
| ⌘⇧T (Command-Shift-T) | Otwórz ostatnio zamkniętą kartę (można używać wielokrotnie) |
| ⌘\[                  | Wróć o jedną stronę w historii przeglądania    |
| ⌘]                   | Przejdź do przodu o jedną stronę w historii przeglądania |
| ⌘⇧R                  | Aktywuj tryb czytania                           |

#### Skróty Mail

| Skrót                   | Akcja                       |
| ----------------------- | ---------------------------- |
| ⌘L                      | Otwórz lokalizację          |
| ⌘T                      | Otwórz nową kartę           |
| ⌘W                      | Zamknij bieżącą kartę      |
| ⌘R                      | Odśwież bieżącą kartę      |
| ⌘.                      | Zatrzymaj ładowanie bieżącej karty |
| ⌘⌥F (Command-Option/Alt-F) | Szukaj w swojej skrzynce pocztowej |

## Odnośniki

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
