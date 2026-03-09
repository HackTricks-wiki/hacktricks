# Ucieczka z KIOSK-ów

{{#include ../banners/hacktricks-training.md}}

---

## Sprawdź urządzenie fizyczne

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Wyłączenie i ponowne włączenie urządzenia może odsłonić ekran startowy |
| Power cable  | Sprawdź, czy urządzenie uruchamia się ponownie po krótkim odcięciu zasilania |
| USB ports    | Podłącz fizyczną klawiaturę — więcej skrótów                       |
| Ethernet     | Skanowanie sieci lub sniffing może umożliwić dalszą eksploatację    |

## Sprawdź możliwe działania w aplikacji GUI

**Common Dialogs** to opcje takie jak **saving a file**, **opening a file**, wybór czcionki, koloru... Większość z nich zaoferuje **pełną funkcjonalność Explorer**. To oznacza, że będziesz mógł uzyskać dostęp do funkcji Explorer, jeśli możesz otworzyć te opcje:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Sprawdź, czy możesz:

- Modyfikować lub tworzyć nowe pliki
- Tworzyć symbolic links
- Uzyskać dostęp do obszarów z ograniczeniami
- Uruchamiać inne aplikacje

### Wykonywanie poleceń

Możliwe, że **using a `Open with`** option\*\* możesz otworzyć/uruchomić jakiś rodzaj shell.

#### Windows

Na przykład _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ znajdź więcej binarek, które mogą być użyte do wykonywania poleceń (i wykonywania nieoczekiwanych działań) tutaj: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Więcej tutaj: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypassing path restrictions

- **Environment variables**: Istnieje wiele zmiennych środowiskowych wskazujących na ścieżki
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (otwórz nową sesję), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (otwórz explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Ukryte menu administracyjne: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Ścieżki do łączenia się z udziałami sieciowymi. Spróbuj połączyć się z C$ lokalnej maszyny ("\\\127.0.0.1\c$\Windows\System32")
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

- **Dialog-box pivoting**: Użyj *Open/Save/Print-to-file* dialogs jako uproszczonego Explorer. Spróbuj `*.*` / `*.exe` w polu nazwy pliku, kliknij prawym przyciskiem na foldery dla **Open in new window**, i użyj **Properties → Open file location** aby rozszerzyć nawigację.
- **Create execution paths from dialogs**: Utwórz nowy plik i zmień jego nazwę na `.CMD` lub `.BAT`, lub stwórz skrót wskazujący na `%WINDIR%\System32` (lub konkretny binarny jak `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Jeśli możesz przejść do `cmd.exe`, spróbuj **drag-and-drop** dowolnego pliku na niego, aby uruchomić prompt. Jeśli Task Manager jest osiągalny (`CTRL+SHIFT+ESC`), użyj **Run new task**.
- **Task Scheduler bypass**: Jeśli interaktywne shelle są zablokowane, ale dozwolone jest planowanie, stwórz zadanie uruchamiające `cmd.exe` (GUI `taskschd.msc` lub `schtasks.exe`).
- **Weak allowlists**: Jeśli wykonywanie jest dozwolone według **filename/extension**, zmień nazwę payloadu na dozwoloną. Jeśli dozwolone według **directory**, skopiuj payload do dozwolonego folderu programów i uruchom go stamtąd.
- **Find writable staging paths**: Zacznij od `%TEMP%` i wypisz foldery zapisywalne za pomocą Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Next step**: If you gain a shell, pivot to the Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Download Your Binaries

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Accessing filesystem from the browser

| ŚCIEŻKA             | ŚCIEŻKA          | ŚCIEŻKA           | ŚCIEŻKA             |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### ShortCuts

- Sticky Keys – Press SHIFT 5 times
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Hold NUMLOCK for 5 seconds
- Filter Keys – Hold right SHIFT for 12 seconds
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Show Desktop
- WINDOWS+E – Launch Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen on newer Windows versions
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Toggle full screen within Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Swipes

- Przesuń palcem od lewej do prawej, aby zobaczyć wszystkie otwarte okna, minimalizując aplikację KIOSK i uzyskać bezpośredni dostęp do całego systemu;
- Przesuń palcem od prawej do lewej, aby otworzyć Action Center, minimalizując aplikację KIOSK i uzyskać bezpośredni dostęp do całego systemu;
- Przesuń palcem od górnej krawędzi, aby wyświetlić pasek tytułu aplikacji otwartej w trybie pełnoekranowym;
- Przesuń palcem w górę od dołu, aby pokazać pasek zadań w aplikacji pełnoekranowej.

### Internet Explorer Tricks

#### 'Image Toolbar'

To pasek narzędzi, który pojawia się w lewym górnym rogu obrazu po jego kliknięciu. Będziesz mógł Save, Print, Mailto, Open "My Pictures" w Explorer. Kiosk musi używać Internet Explorer.

#### Shell Protocol

Wpisz te URL-e, aby uzyskać widok Explorer:

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

### Show File Extensions

Sprawdź tę stronę po więcej informacji: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Browsers tricks

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Utwórz standardowy dialog przy użyciu JavaScript i uzyskaj dostęp do file explorer: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures and bottoms

- Swipe up with four (or five) fingers / Double-tap Home button: Aby wyświetlić widok multitask i zmienić aplikację
- Swipe one way or another with four or five fingers: Aby przejść do następnej/poprzedniej aplikacji
- Pinch the screen with five fingers / Touch Home button / Swipe up with 1 finger from the bottom of the screen in a quick motion to the up: Aby przejść do ekranu głównego
- Swipe one finger from the bottom of the screen just 1-2 inches (slow): Pojawi się dock
- Swipe down from the top of the display with 1 finger: Aby zobaczyć powiadomienia
- Swipe down with 1 finger the top-right corner of the screen: Aby zobaczyć centrum sterowania iPad Pro
- Swipe 1 finger from the left of the screen 1-2 inches: Aby zobaczyć widok Today
- Swipe fast 1 finger from the centre of the screen to the right or left: Aby przełączyć się do następnej/poprzedniej aplikacji
- Press and hold the On/**Off**/Sleep button at the upper-right corner of the **iPad +** Move the Slide to **power off** slider all the way to the right: Aby wyłączyć urządzenie
- Press the On/**Off**/Sleep button at the upper-right corner of the **iPad and the Home button for a few second**: Aby wymusić twarde wyłączenie
- Press the On/**Off**/Sleep button at the upper-right corner of the **iPad and the Home button quickly**: Aby zrobić zrzut ekranu, który pojawi się w lewym dolnym rogu ekranu. Naciśnij oba przyciski bardzo krótko jednocześnie; jeśli przytrzymasz je kilka sekund, zostanie wykonane twarde wyłączenie.

### Shortcuts

Powinieneś mieć klawiaturę do iPada lub adapter USB. Poniżej pokazane są tylko skróty, które mogą pomóc w ucieczce z aplikacji.

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

#### System shortcuts

Te skróty dotyczą ustawień wizualnych i dźwiękowych, w zależności od użycia iPada.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Przyciemnij ekran                                                               |
| F2       | Rozjaśnij ekran                                                                 |
| F7       | Wróć do poprzedniego utworu                                                     |
| F8       | Odtwórz/pauza                                                                   |
| F9       | Następny utwór                                                                  |
| F10      | Wycisz                                                                          |
| F11      | Zmniejsz głośność                                                               |
| F12      | Zwiększ głośność                                                                |
| ⌘ Space  | Wyświetla listę dostępnych języków; aby wybrać, stuknij ponownie spację.       |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Przejdź do ekranu głównego                              |
| ⌘⇧H (Command-Shift-H)                              | Przejdź do ekranu głównego                              |
| ⌘ (Space)                                          | Otwórz Spotlight                                        |
| ⌘⇥ (Command-Tab)                                   | Wyświetl ostatnie dziesięć używanych aplikacji          |
| ⌘\~                                                | Przejdź do ostatniej aplikacji                          |
| ⌘⇧3 (Command-Shift-3)                              | Zrzut ekranu (pojawia się w lewym dolnym rogu do zapisu)|
| ⌘⇧4                                                | Zrzut ekranu i otwarcie w edytorze                      |
| Press and hold ⌘                                   | Lista skrótów dostępnych dla aplikacji                  |
| ⌘⌥D (Command-Option/Alt-D)                         | Wyświetl dock                                           |
| ^⌥H (Control-Option-H)                             | Przycisk Home                                           |
| ^⌥H H (Control-Option-H-H)                         | Pokaż pasek multitask                                   |
| ^⌥I (Control-Option-i)                             | Wybór elementu                                          |
| Escape                                             | Przycisk Wstecz                                         |
| → (Right arrow)                                    | Następny element                                        |
| ← (Left arrow)                                     | Poprzedni element                                       |
| ↑↓ (Up arrow, Down arrow)                          | Jednoczesne stuknięcie zaznaczonego elementu            |
| ⌥ ↓ (Option-Down arrow)                            | Scroll w dół                                           |
| ⌥↑ (Option-Up arrow)                               | Scroll w górę                                          |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Scroll w lewo lub w prawo                               |
| ^⌥S (Control-Option-S)                             | Włącz/wyłącz mowę VoiceOver                             |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Przełącz na poprzednią aplikację                        |
| ⌘⇥ (Command-Tab)                                   | Powrót do oryginalnej aplikacji                         |
| ←+→, then Option + ← or Option+→                   | Nawiguj po Dock                                         |

#### Safari shortcuts

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Otwórz lokalizację                               |
| ⌘T                      | Otwórz nową kartę                                 |
| ⌘W                      | Zamknij bieżącą kartę                             |
| ⌘R                      | Odśwież bieżącą kartę                             |
| ⌘.                      | Zatrzymaj ładowanie bieżącej karty                |
| ^⇥                      | Przejdź do następnej karty                        |
| ^⇧⇥ (Control-Shift-Tab) | Przejdź do poprzedniej karty                      |
| ⌘L                      | Zaznacz pole tekstowe/URL, aby je modyfikować     |
| ⌘⇧T (Command-Shift-T)   | Otwórz ostatnio zamkniętą kartę (można użyć wielokrotnie) |
| ⌘\[                     | Wróć o jedną stronę w historii przeglądania       |
| ⌘]                      | Przejdź do przodu o jedną stronę w historii       |
| ⌘⇧R                     | Aktywuj Reader Mode                               |

#### Mail shortcuts

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Otwórz lokalizację           |
| ⌘T                         | Otwórz nową kartę            |
| ⌘W                         | Zamknij bieżącą kartę        |
| ⌘R                         | Odśwież bieżącą kartę        |
| ⌘.                         | Zatrzymaj ładowanie          |
| ⌘⌥F (Command-Option/Alt-F) | Wyszukaj w skrzynce pocztowej|

## References

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
