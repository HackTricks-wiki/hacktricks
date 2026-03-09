# Escaping from KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Physisches Gerät überprüfen

| Komponente   | Aktion                                                              |
| ------------ | ------------------------------------------------------------------- |
| Ein-/Ausschalter | Das Gerät aus- und wieder einschalten kann den Startbildschirm sichtbar machen |
| Netzkabel    | Prüfe, ob das Gerät neu startet, wenn kurz die Stromversorgung getrennt wird |
| USB-Ports    | Schließe eine physische Tastatur an, um mehr Tastenkombinationen zu nutzen |
| Ethernet     | Netzwerkscan oder Sniffing kann weitere Ausnutzungen ermöglichen     |

## Prüfe mögliche Aktionen innerhalb der GUI-Anwendung

**Common Dialogs** sind jene Optionen wie **Speichern einer Datei**, **Öffnen einer Datei**, Schriftart auswählen, Farbe... Die meisten bieten eine **volle Explorer-Funktionalität**. Das bedeutet, dass du auf Explorer-Funktionen zugreifen kannst, wenn du diese Optionen erreichst:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Du solltest prüfen, ob du:

- Neue Dateien ändern oder erstellen kannst
- Symbolische Links erstellen kannst
- Zugriff auf eingeschränkte Bereiche erhältst
- Andere Apps ausführen kannst

### Befehlsausführung

Vielleicht **using a `Open with`** option\*\* kannst du eine Art Shell öffnen/ausführen.

#### Windows

Zum Beispiel _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ Weitere Binaries, die zum Ausführen von Befehlen (und zum Ausführen unerwarteter Aktionen) verwendet werden können, findest du hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Mehr hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Umgehung von Pfadbeschränkungen

- **Umgebungsvariablen**: Es gibt viele Umgebungsvariablen, die auf einen Pfad zeigen
- **Andere Protokolle**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolische Links**
- **Tastenkombinationen**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Verstecktes Administrationsmenü: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Pfade, um sich mit freigegebenen Ordnern zu verbinden. Du solltest versuchen, dich mit dem C$ der lokalen Maschine zu verbinden ("\\\127.0.0.1\c$\Windows\System32")
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

- **Dialog-box pivoting**: Nutze *Open/Save/Print-to-file* Dialoge als abgespeckten Explorer. Versuche `*.*` / `*.exe` im Dateinamenfeld, Rechtsklick auf Ordner für **Open in new window**, und benutze **Properties → Open file location**, um die Navigation zu erweitern.
- **Create execution paths from dialogs**: Erstelle eine neue Datei und benenne sie in `.CMD` oder `.BAT` um, oder erstelle eine Verknüpfung, die auf `%WINDIR%\System32` zeigt (oder auf ein spezifisches Binary wie `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Wenn du zu `cmd.exe` navigieren kannst, versuche, jede Datei per **drag-and-drop** darauf zu ziehen, um eine Eingabeaufforderung zu starten. Wenn der Task Manager erreichbar ist (`CTRL+SHIFT+ESC`), benutze **Run new task**.
- **Task Scheduler bypass**: Wenn interaktive Shells blockiert sind, Scheduling aber erlaubt ist, erstelle eine Aufgabe, die `cmd.exe` ausführt (GUI `taskschd.msc` oder `schtasks.exe`).
- **Weak allowlists**: Wenn Ausführung durch **filename/extension** erlaubt ist, benenne dein Payload in einen erlaubten Namen um. Wenn es nach **directory** erlaubt ist, kopiere das Payload in einen erlaubten Programmordner und führe es dort aus.
- **Find writable staging paths**: Beginne mit `%TEMP%` und enumeriere beschreibbare Ordner mit Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Nächster Schritt**: Wenn du eine shell erhältst, wechsle zur Windows LPE-Checkliste:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Binaries herunterladen

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Zugriff aufs Dateisystem vom Browser

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Tastenkombinationen

- Sticky Keys – Drücke SHIFT 5-mal
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Halte NUMLOCK für 5 Sekunden
- Filter Keys – Halte die rechte SHIFT-Taste für 12 Sekunden
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Desktop anzeigen
- WINDOWS+E – Windows Explorer starten
- WINDOWS+R – Ausführen
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Suchen
- SHIFT+F10 – Kontextmenü
- CTRL+SHIFT+ESC – Task-Manager
- CTRL+ALT+DEL – Splash-Screen bei neueren Windows-Versionen
- F1 – Hilfe F3 – Suchen
- F6 – Adressleiste
- F11 – Vollbild umschalten in Internet Explorer
- CTRL+H – Internet Explorer Verlauf
- CTRL+T – Internet Explorer – Neuer Tab
- CTRL+N – Internet Explorer – Neue Seite
- CTRL+O – Datei öffnen
- CTRL+S – Speichern CTRL+N – Neuer RDP / Citrix

### Wischgesten

- Wische von der linken Seite nach rechts, um alle offenen Windows zu sehen, wodurch die KIOSK-App minimiert wird und direkter Zugriff auf das gesamte OS möglich ist;
- Wische von der rechten Seite nach links, um das Action Center zu öffnen, wodurch die KIOSK-App minimiert wird und direkter Zugriff auf das gesamte OS möglich ist;
- Wische vom oberen Rand nach innen, um die Titelleiste für eine App im Vollbildmodus sichtbar zu machen;
- Wische vom unteren Rand nach oben, um in einer Vollbild-App die Taskleiste anzuzeigen.

### Internet Explorer Tricks

#### 'Image Toolbar'

Das ist eine Toolbar, die oben links über einem Bild erscheint, wenn es angeklickt wird. Du kannst Save, Print, Mailto, "My Pictures" in Explorer öffnen. Der Kiosk muss Internet Explorer verwenden.

#### Shell Protocol

Gib diese URLs ein, um eine Explorer-Ansicht zu erhalten:

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

### Dateiendungen anzeigen

Weitere Informationen: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Browser-Tricks

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Erstelle einen common dialog mit JavaScript und greife auf den Datei-Explorer zu: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesten und Tasten

- Wische mit vier (oder fünf) Fingern nach oben / Doppeltippe auf die Home-Taste: Öffnet die Multitasking-Ansicht und wechselt die App
- Wische mit vier oder fünf Fingern in eine Richtung: Wechselt zur nächsten/vorherigen App
- Kneife den Bildschirm mit fünf Fingern / Drücke die Home-Taste / Wische schnell mit 1 Finger von unten nach oben: Geht zum Home-Bildschirm
- Wische mit einem Finger von unten nur 1–2 Zoll (langsam): Das Dock erscheint
- Wische mit 1 Finger von der oberen Anzeige nach unten: Zeigt Benachrichtigungen an
- Wische mit 1 Finger in die obere rechte Ecke des Bildschirms nach unten: Zeigt das Kontrollzentrum des iPad Pro
- Wische mit 1 Finger von links des Bildschirms 1–2 Zoll: Zeigt die Today-Ansicht
- Wische schnell mit 1 Finger von der Mitte des Bildschirms nach rechts oder links: Wechsel zur nächsten/vorherigen App
- Drücke und halte die On/**Off**/Sleep-Taste oben rechts am **iPad +** und bewege den Slider Slide to **power off** ganz nach rechts: Ausschalten
- Drücke die On/**Off**/Sleep-Taste oben rechts am **iPad und die Home-Taste für ein paar Sekunden**: Erzwingt einen Hard Power Off
- Drücke die On/**Off**/Sleep-Taste oben rechts am **iPad und die Home-Taste kurz**: Macht einen Screenshot, der unten links im Display erscheint. Drückst du beide Tasten sehr kurz gleichzeitig, wird ein Hard Power Off ausgeführt, wenn du sie länger hältst.

### Tastenkürzel

Du solltest eine iPad-Tastatur oder einen USB-Tastatur-Adapter haben. Nur Kürzel, die beim Verlassen der Anwendung helfen, werden hier angezeigt.

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

#### Systemkürzel

Diese Kürzel betreffen die Anzeige- und Toneinstellungen, je nach Verwendung des iPad.

| Shortcut | Aktion                                                                          |
| -------- | ------------------------------------------------------------------------------- |
| F1       | Bildschirm dimmen                                                               |
| F2       | Bildschirm aufhellen                                                            |
| F7       | Einen Song zurück                                                               |
| F8       | Play/Pause                                                                      |
| F9       | Song überspringen                                                               |
| F10      | Stummschalten                                                                   |
| F11      | Lautstärke verringern                                                           |
| F12      | Lautstärke erhöhen                                                              |
| ⌘ Space  | Zeigt eine Liste verfügbarer Sprachen; zum Auswählen erneut die Leertaste drücken. |

#### iPad-Navigation

| Shortcut                                           | Aktion                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gehe zum Home                                           |
| ⌘⇧H (Command-Shift-H)                              | Gehe zum Home                                           |
| ⌘ (Space)                                          | Spotlight öffnen                                        |
| ⌘⇥ (Command-Tab)                                   | Liste der letzten zehn verwendeten Apps                 |
| ⌘\~                                                | Zur letzten App wechseln                                |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (erscheint unten links zum Speichern oder Aktionen) |
| ⌘⇧4                                                | Screenshot und öffne ihn im Editor                      |
| Press and hold ⌘                                   | Liste der verfügbaren Kürzel für die App                |
| ⌘⌥D (Command-Option/Alt-D)                         | Dock einblenden                                         |
| ^⌥H (Control-Option-H)                             | Home-Button                                             |
| ^⌥H H (Control-Option-H-H)                         | Multitasking-Leiste anzeigen                            |
| ^⌥I (Control-Option-i)                             | Item-Auswahl                                            |
| Escape                                             | Zurück                                                  |
| → (Right arrow)                                    | Nächstes Element                                        |
| ← (Left arrow)                                     | Vorheriges Element                                      |
| ↑↓ (Up arrow, Down arrow)                          | Ausgewähltes Element gleichzeitig antippen              |
| ⌥ ↓ (Option-Down arrow)                            | Nach unten scrollen                                     |
| ⌥↑ (Option-Up arrow)                               | Nach oben scrollen                                      |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Nach links oder rechts scrollen                         |
| ^⌥S (Control-Option-S)                             | VoiceOver-Sprachausgabe an/aus                          |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Zur vorherigen App wechseln                             |
| ⌘⇥ (Command-Tab)                                   | Zur ursprünglichen App zurückwechseln                   |
| ←+→, then Option + ← or Option+→                   | Durch das Dock navigieren                               |

#### Safari-Tastenkürzel

| Shortcut                | Aktion                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Location öffnen                                  |
| ⌘T                      | Neuen Tab öffnen                                 |
| ⌘W                      | Aktuellen Tab schließen                          |
| ⌘R                      | Aktuellen Tab neu laden                          |
| ⌘.                      | Laden des aktuellen Tabs stoppen                 |
| ^⇥                      | Zum nächsten Tab wechseln                        |
| ^⇧⇥ (Control-Shift-Tab) | Zum vorherigen Tab wechseln                      |
| ⌘L                      | Textfeld/URL-Feld auswählen, um es zu bearbeiten |
| ⌘⇧T (Command-Shift-T)   | Zuletzt geschlossenen Tab öffnen (mehrfach möglich) |
| ⌘\[                     | Geht eine Seite in der Historie zurück           |
| ⌘]                      | Geht eine Seite in der Historie vorwärts         |
| ⌘⇧R                     | Reader Mode aktivieren                           |

#### Mail-Tastenkürzel

| Shortcut                   | Aktion                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Location öffnen              |
| ⌘T                         | Neuen Tab öffnen             |
| ⌘W                         | Aktuellen Tab schließen      |
| ⌘R                         | Aktuellen Tab neu laden      |
| ⌘.                         | Laden des aktuellen Tabs stoppen |
| ⌘⌥F (Command-Option/Alt-F) | In deinem Postfach suchen     |

## Quellen

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
