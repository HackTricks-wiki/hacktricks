# Ucieczka z KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Sprawdź fizyczne urządzenie

| Komponent    | Działanie                                                         |
| ------------ | ----------------------------------------------------------------- |
| Przycisk zasilania | Wyłączenie i ponowne włączenie urządzenia może ujawnić ekran startowy |
| Kabel zasilający  | Sprawdź, czy urządzenie uruchomi się ponownie po krótkim odłączeniu zasilania |
| Porty USB    | Podłącz fizyczną klawiaturę z większą liczbą skrótów              |
| Ethernet     | Skanowanie sieci lub sniffing może umożliwić dalszą eksploatację  |

## Sprawdź możliwe działania wewnątrz aplikacji GUI

**Common Dialogs** to opcje **zapisywania pliku**, **otwierania pliku**, wybierania czcionki, koloru... Większość z nich **oferuje pełną funkcjonalność Explorera**. Oznacza to, że będziesz mieć dostęp do funkcji Explorera, jeśli uzyskasz dostęp do tych opcji:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Sprawdź, czy możesz:

- Modyfikować lub tworzyć nowe pliki
- Tworzyć symbolic links
- Uzyskać dostęp do ograniczonych obszarów
- Uruchamiać inne aplikacje

### Wykonywanie poleceń

Być może **używając opcji `Open with`**\*\* możesz otworzyć/uruchomić jakiś rodzaj shell.

#### Windows

Na przykład _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ więcej binary, których można użyć do wykonywania poleceń (i przeprowadzania nieoczekiwanych działań), znajdziesz tutaj: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Więcej tutaj: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Omijanie ograniczeń ścieżek

- **Zmienne środowiskowe**: Istnieje wiele zmiennych środowiskowych wskazujących na określoną ścieżkę
- **Inne protokoły**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Skróty**: CTRL+N (otwarcie nowej sesji), CTRL+R (wykonywanie poleceń), CTRL+SHIFT+ESC (Task Manager), Windows+E (otwarcie Explorera), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Ukryte menu administracyjne: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **Ścieżki UNC**: Ścieżki służące do łączenia się z folderami współdzielonymi. Spróbuj połączyć się z C$ lokalnej maszyny ("\\\127.0.0.1\c$\Windows\System32")
- **Więcej ścieżek UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%              | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Używaj okien dialogowych *Open/Save/Print-to-file* jako uproszczonego Explorera. Spróbuj użyć `*.*` / `*.exe` w polu nazwy pliku, kliknij prawym przyciskiem foldery, aby wybrać **Open in new window**, i użyj **Properties → Open file location**, aby rozszerzyć nawigację.<sup>[[1]](#references)</sup>
- **Create execution paths from dialogs**: Utwórz nowy plik i zmień jego nazwę na `.CMD` lub `.BAT`, albo utwórz skrót wskazujący na `%WINDIR%\System32` (lub konkretny binary, taki jak `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Jeśli możesz przejść do `cmd.exe`, spróbuj użyć **drag-and-drop**, przeciągając dowolny plik na `cmd.exe`, aby uruchomić prompt. Jeśli Task Manager jest dostępny (`CTRL+SHIFT+ESC`), użyj opcji **Run new task**.
- **Task Scheduler bypass**: Jeśli interaktywne shelle są zablokowane, ale planowanie zadań jest dozwolone, utwórz zadanie uruchamiające `cmd.exe` (GUI `taskschd.msc` lub `schtasks.exe`).
- **Weak allowlists**: Jeśli wykonywanie jest dozwolone na podstawie **nazwy/rozszerzenia pliku**, zmień nazwę payloadu na dozwoloną. Jeśli dozwolony jest **katalog**, skopiuj payload do dozwolonego folderu programów i uruchom go stamtąd.
- **Find writable staging paths**: Zacznij od `%TEMP%` i wylicz zapisywalne foldery za pomocą Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Następny krok**: Jeśli uzyskasz shell, przejdź do checklisty Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Pobierz swoje pliki binarne

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

### Skróty

- Sticky Keys – naciśnij SHIFT 5 razy
- Mouse Keys – SHIFT+ALT+NUMLOCK
- Wysoki kontrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – przytrzymaj NUMLOCK przez 5 sekund
- Filter Keys – przytrzymaj prawy SHIFT przez 12 sekund
- WINDOWS+F1 – wyszukiwanie w Windows
- WINDOWS+D – pokaż pulpit
- WINDOWS+E – uruchom Eksplorator Windows
- WINDOWS+R – Uruchom
- WINDOWS+U – Centrum ułatwień dostępu
- WINDOWS+F – wyszukiwanie
- SHIFT+F10 – menu kontekstowe
- CTRL+SHIFT+ESC – Menedżer zadań
- CTRL+ALT+DEL – ekran powitalny w nowszych wersjach Windows
- F1 – pomoc F3 – wyszukiwanie
- F6 – pasek adresu
- F11 – przełącz tryb pełnoekranowy w Internet Explorerze
- CTRL+H – historia Internet Explorera
- CTRL+T – Internet Explorer – nowa karta
- CTRL+N – Internet Explorer – nowa strona
- CTRL+O – otwórz plik
- CTRL+S – zapisz CTRL+N – nowy RDP / Citrix

### Gesty przesuwania

- Przesuń palcem od lewej strony do prawej, aby zobaczyć wszystkie otwarte okna, zminimalizować aplikację KIOSK i uzyskać bezpośredni dostęp do całego systemu operacyjnego;
- Przesuń palcem od prawej strony do lewej, aby otworzyć Centrum akcji, zminimalizować aplikację KIOSK i uzyskać bezpośredni dostęp do całego systemu operacyjnego;
- Przesuń palcem od górnej krawędzi, aby wyświetlić pasek tytułu aplikacji otwartej w trybie pełnoekranowym;
- Przesuń palcem w górę od dolnej krawędzi, aby wyświetlić pasek zadań w aplikacji pełnoekranowej.

### Sztuczki dotyczące Internet Explorera

#### „Image Toolbar”

To pasek narzędzi pojawiający się w lewym górnym rogu obrazu po jego kliknięciu. Umożliwia zapisanie, wydrukowanie i wysłanie obrazu pocztą, a także otwarcie folderu „Moje obrazy” w Eksploratorze. Kiosk musi korzystać z Internet Explorera.

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
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Moje miejsca sieciowe
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Pokaż rozszerzenia plików

Sprawdź tę stronę, aby uzyskać więcej informacji: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Sztuczki dotyczące przeglądarek

Kopie zapasowe wersji iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Utwórz wspólne okno dialogowe za pomocą JavaScript i uzyskaj dostęp do eksploratora plików: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Źródło: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesty i przyciski

- Przesuń w górę czterema (lub pięcioma) palcami / kliknij dwukrotnie przycisk Home: aby wyświetlić widok wielozadaniowy i zmienić aplikację
- Przesuń w jedną lub drugą stronę czterema albo pięcioma palcami: aby przejść do następnej/poprzedniej aplikacji
- Ściągnij ekran pięcioma palcami / dotknij przycisku Home / szybko przesuń jednym palcem od dołu ekranu w górę: aby przejść do ekranu Home
- Przesuń jednym palcem od dołu ekranu na odległość 1–2 cali (powoli): pojawi się dock
- Przesuń jednym palcem w dół od górnej krawędzi ekranu: aby wyświetlić powiadomienia
- Przesuń jednym palcem w dół od prawego górnego rogu ekranu: aby wyświetlić Centrum sterowania iPada Pro
- Przesuń jednym palcem od lewej krawędzi ekranu na odległość 1–2 cali: aby wyświetlić widok Dzisiaj
- Szybko przesuń jednym palcem od środka ekranu w prawo lub w lewo: aby przejść do następnej/poprzedniej aplikacji
- Naciśnij i przytrzymaj przycisk Wł./**Wył.**/uśpienia w prawym górnym rogu **iPada +** przesuń suwak **wyłączania** maksymalnie w prawo: aby wyłączyć urządzenie
- Naciśnij przycisk Wł./**Wył.**/uśpienia w prawym górnym rogu **iPada oraz przycisk Home przez kilka sekund**: aby wymusić całkowite wyłączenie
- Naciśnij szybko przycisk Wł./**Wył.**/uśpienia w prawym górnym rogu **iPada oraz przycisk Home**: aby wykonać zrzut ekranu, który pojawi się w lewym dolnym rogu ekranu. Naciśnij oba przyciski jednocześnie, ale bardzo krótko, ponieważ przytrzymanie ich przez kilka sekund spowoduje całkowite wyłączenie urządzenia.<sup>[[3]](#references)</sup>

### Skróty

Potrzebujesz klawiatury iPada lub adaptera klawiatury USB. Poniżej pokazano tylko skróty, które mogą pomóc w opuszczeniu aplikacji.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Te skróty dotyczą ustawień obrazu i dźwięku, zależnie od sposobu korzystania z iPada.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Przyciemnij ekran                                                             |
| F2       | Rozjaśnij ekran                                                               |
| F7       | Poprzedni utwór                                                                |
| F8       | Odtwórz/wstrzymaj                                                              |
| F9       | Pomiń utwór                                                                    |
| F10      | Wycisz                                                                         |
| F11      | Zmniejsz głośność                                                              |
| F12      | Zwiększ głośność                                                               |
| ⌘ Space  | Wyświetl listę dostępnych języków; aby wybrać język, ponownie naciśnij spację. |

#### Nawigacja po iPadzie

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Przejdź do ekranu Home                                  |
| ⌘⇧H (Command-Shift-H)                              | Przejdź do ekranu Home                                  |
| ⌘ (Space)                                          | Otwórz Spotlight                                        |
| ⌘⇥ (Command-Tab)                                   | Wyświetl listę dziesięciu ostatnio używanych aplikacji  |
| ⌘\~                                                | Przejdź do ostatniej aplikacji                           |
| ⌘⇧3 (Command-Shift-3)                              | Zrzut ekranu (pojawia się w lewym dolnym rogu, aby go zapisać lub wykonać na nim działanie) |
| ⌘⇧4                                                | Wykonaj zrzut ekranu i otwórz go w edytorze              |
| Naciśnij i przytrzymaj ⌘                            | Lista skrótów dostępnych dla aplikacji                  |
| ⌘⌥D (Command-Option/Alt-D)                         | Wyświetl dock                                            |
| ^⌥H (Control-Option-H)                             | Przycisk Home                                            |
| ^⌥H H (Control-Option-H-H)                         | Pokaż pasek wielozadaniowości                            |
| ^⌥I (Control-Option-i)                             | Wybór elementu                                           |
| Escape                                             | Przycisk Wstecz                                          |
| → (Right arrow)                                    | Następny element                                         |
| ← (Left arrow)                                     | Poprzedni element                                        |
| ↑↓ (Up arrow, Down arrow)                          | Dotknij wybranego elementu jednocześnie                 |
| ⌥ ↓ (Option-Down arrow)                            | Przewiń w dół                                           |
| ⌥↑ (Option-Up arrow)                               | Przewiń w górę                                          |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Przewiń w lewo lub w prawo                              |
| ^⌥S (Control-Option-S)                             | Włącz lub wyłącz mowę VoiceOver                          |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Przełącz na poprzednią aplikację                         |
| ⌘⇥ (Command-Tab)                                   | Przełącz z powrotem na pierwotną aplikację               |
| ←+→, then Option + ← or Option+→                   | Nawiguj po docku                                         |

#### Skróty Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Otwórz lokalizację                                |
| ⌘T                      | Otwórz nową kartę                                 |
| ⌘W                      | Zamknij bieżącą kartę                             |
| ⌘R                      | Odśwież bieżącą kartę                             |
| ⌘.                      | Zatrzymaj ładowanie bieżącej karty                |
| ^⇥                      | Przełącz na następną kartę                         |
| ^⇧⇥ (Control-Shift-Tab) | Przejdź do poprzedniej karty                       |
| ⌘L                      | Zaznacz pole tekstowe/adresu URL, aby je zmodyfikować |
| ⌘⇧T (Command-Shift-T)   | Otwórz ostatnio zamkniętą kartę (można użyć wielokrotnie) |
| ⌘\[                     | Przejdź o jedną stronę wstecz w historii przeglądania |
| ⌘]                      | Przejdź o jedną stronę do przodu w historii przeglądania |
| ⌘⇧R                     | Włącz tryb Reader                              |

#### Skróty Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Otwórz lokalizację            |
| ⌘T                         | Otwórz nową kartę             |
| ⌘W                         | Zamknij bieżącą kartę         |
| ⌘R                         | Odśwież bieżącą kartę         |
| ⌘.                         | Zatrzymaj ładowanie bieżącej karty |
| ⌘⌥F (Command-Option/Alt-F) | Wyszukaj w skrzynce pocztowej  |

## References

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
