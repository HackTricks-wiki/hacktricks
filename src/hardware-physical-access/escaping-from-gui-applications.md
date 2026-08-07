# Aus KIOSKs ausbrechen

{{#include ../banners/hacktricks-training.md}}

---

## Physisches Gerät überprüfen

| Komponente    | Aktion                                                               |
| ------------- | -------------------------------------------------------------------- |
| Power button  | Das Aus- und Einschalten des Geräts kann den Startbildschirm anzeigen |
| Power cable   | Prüfen, ob das Gerät neu startet, wenn die Stromversorgung kurz unterbrochen wird |
| USB ports     | Physische Tastatur mit weiteren Shortcuts anschließen                |
| Ethernet      | Ein Network scan oder Sniffing kann weitere Exploitation ermöglichen  |

## Auf mögliche Aktionen innerhalb der GUI-Anwendung prüfen

**Common Dialogs** sind Optionen zum **Speichern einer Datei**, **Öffnen einer Datei**, Auswählen einer Schriftart, einer Farbe usw. Die meisten davon **bieten eine vollständige Explorer-Funktionalität**. Das bedeutet, dass du auf Explorer-Funktionen zugreifen kannst, wenn du diese Optionen erreichen kannst:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Du solltest prüfen, ob du Folgendes kannst:

- Dateien ändern oder neue Dateien erstellen
- Symbolic links erstellen
- Zugriff auf eingeschränkte Bereiche erhalten
- Andere Apps ausführen

### Command Execution

Vielleicht kannst du über die Option **`Open with`**\*\* eine Shell öffnen/ausführen.

#### Windows

Zum Beispiel _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ weitere Binaries, die zum Ausführen von Commands (und für unerwartete Aktionen) verwendet werden können, findest du hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Mehr hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Pfadbeschränkungen umgehen

- **Environment variables**: Es gibt zahlreiche Environment variables, die auf bestimmte Pfade verweisen
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (neue Sitzung öffnen), CTRL+R (Commands ausführen), CTRL+SHIFT+ESC (Task Manager), Windows+E (Explorer öffnen), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Verstecktes Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Pfade zum Verbinden mit freigegebenen Ordnern. Du solltest versuchen, eine Verbindung mit C$ des lokalen Rechners herzustellen ("\\\127.0.0.1\c$\Windows\System32")
- **More UNC paths:**

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

- **Dialog-box pivoting**: Verwende *Open/Save/Print-to-file*-Dialoge als Explorer-lite. Versuche `*.*` / `*.exe` im Dateinamenfeld, klicke mit der rechten Maustaste auf Ordner, um **Open in new window** auszuwählen, und verwende **Properties → Open file location**, um die Navigation zu erweitern.<sup>[[1]](#references)</sup>
- **Create execution paths from dialogs**: Erstelle eine neue Datei und benenne sie in `.CMD` oder `.BAT` um, oder erstelle einen Shortcut, der auf `%WINDIR%\System32` (oder ein bestimmtes Binary wie `%WINDIR%\System32\cmd.exe`) zeigt.
- **Shell launch pivots**: Wenn du zu `cmd.exe` navigieren kannst, versuche, eine beliebige Datei per **drag-and-drop** darauf zu ziehen, um eine Eingabeaufforderung zu starten. Wenn der Task Manager erreichbar ist (`CTRL+SHIFT+ESC`), verwende **Run new task**.
- **Task Scheduler bypass**: Wenn interaktive Shells blockiert sind, Scheduling aber erlaubt ist, erstelle eine Task, die `cmd.exe` ausführt (GUI `taskschd.msc` oder `schtasks.exe`).
- **Weak allowlists**: Wenn die Ausführung anhand von **filename/extension** erlaubt ist, benenne deinen Payload in einen zulässigen Namen um. Wenn sie anhand eines **directory** erlaubt ist, kopiere den Payload in einen zulässigen Programmordner und führe ihn dort aus.
- **Find writable staging paths**: Beginne mit `%TEMP%` und ermittle mit Sysinternals AccessChk beschreibbare Ordner.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Nächster Schritt**: Wenn du eine Shell erhältst, fahre mit der Windows-LPE-Checkliste fort:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Deine Binaries herunterladen

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry-Editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Zugriff auf das Dateisystem über den Browser

| PATH                | PATH              | PATH               | PATH               |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Tastenkombinationen

- Sticky Keys – SHIFT 5-mal drücken
- Mouse Keys – SHIFT+ALT+NUMLOCK
- Hoher Kontrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCK 5 Sekunden gedrückt halten
- Filter Keys – rechte SHIFT-Taste 12 Sekunden gedrückt halten
- WINDOWS+F1 – Windows-Suche
- WINDOWS+D – Desktop anzeigen
- WINDOWS+E – Windows Explorer starten
- WINDOWS+R – Ausführen
- WINDOWS+U – Center für erleichterte Bedienung
- WINDOWS+F – Suchen
- SHIFT+F10 – Kontextmenü
- CTRL+SHIFT+ESC – Task-Manager
- CTRL+ALT+DEL – Startbildschirm bei neueren Windows-Versionen
- F1 – Hilfe F3 – Suchen
- F6 – Adressleiste
- F11 – Vollbild im Internet Explorer ein-/ausschalten
- CTRL+H – Internet Explorer-Verlauf
- CTRL+T – Internet Explorer – Neuer Tab
- CTRL+N – Internet Explorer – Neue Seite
- CTRL+O – Datei öffnen
- CTRL+S – Speichern CTRL+N – Neues RDP / Citrix

### Wischgesten

- Von der linken Seite nach rechts wischen, um alle geöffneten Windows anzuzeigen, die KIOSK-App zu minimieren und direkt auf das gesamte OS zuzugreifen;
- Von der rechten Seite nach links wischen, um das Action Center zu öffnen, die KIOSK-App zu minimieren und direkt auf das gesamte OS zuzugreifen;
- Vom oberen Rand nach innen wischen, um die Titelleiste einer im Vollbildmodus geöffneten App sichtbar zu machen;
- Vom unteren Rand nach oben wischen, um die Taskleiste in einer Vollbild-App anzuzeigen.

### Internet-Explorer-Tricks

#### „Image Toolbar“

Dies ist eine Toolbar, die oben links am Bild erscheint, wenn darauf geklickt wird. Du kannst damit in Explorer speichern, drucken, per Mail versenden und „Meine Bilder“ öffnen. Der Kiosk muss Internet Explorer verwenden.

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

### Dateierweiterungen anzeigen

Auf dieser Seite findest du weitere Informationen: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Browser-Tricks

Backup-Versionen von iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Erstelle mit JavaScript einen allgemeinen Dialog und greife auf den File Explorer zu: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Quelle: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesten und Schaltflächen

- Mit vier (oder fünf) Fingern nach oben wischen / zweimal die Home-Taste drücken: Multitasking-Ansicht anzeigen und App wechseln
- Mit vier oder fünf Fingern in eine beliebige Richtung wischen: Zur nächsten/vorherigen App wechseln
- Mit fünf Fingern auf dem Bildschirm zusammenziehen / die Home-Taste berühren / mit einem Finger in einer schnellen Bewegung vom unteren Bildschirmrand nach oben wischen: Home aufrufen
- Mit einem Finger 1–2 Zoll vom unteren Bildschirmrand nach oben wischen (langsam): Das Dock wird angezeigt
- Mit einem Finger vom oberen Rand des Displays nach unten wischen: Benachrichtigungen anzeigen
- Mit einem Finger von der oberen rechten Ecke des Bildschirms nach unten wischen: Kontrollzentrum des iPad Pro anzeigen
- Mit einem Finger 1–2 Zoll vom linken Bildschirmrand nach rechts wischen: Heute-Ansicht anzeigen
- Mit einem Finger schnell von der Mitte des Bildschirms nach rechts oder links wischen: Zur nächsten/vorherigen App wechseln
- Die Ein-/**Aus**-/Sleep-Taste oben rechts am **iPad gedrückt halten +** den Schieberegler **Ausschalten** ganz nach rechts bewegen: Ausschalten
- Die Ein-/**Aus**-/Sleep-Taste oben rechts am **iPad und die Home-Taste einige Sekunden gedrückt halten**: Ein erzwungenes vollständiges Ausschalten durchführen
- Die Ein-/**Aus**-/Sleep-Taste oben rechts am **iPad und die Home-Taste kurz drücken**: Einen Screenshot aufnehmen, der unten links im Display eingeblendet wird. Drücke beide Tasten gleichzeitig nur sehr kurz, da ein mehrere Sekunden langes Gedrückthalten ein vollständiges Ausschalten erzwingt.<sup>[[3]](#references)</sup>

### Tastenkombinationen

Du benötigst eine iPad-Tastatur oder einen USB-Tastaturadapter. Hier werden nur Tastenkombinationen angezeigt, die beim Verlassen der App helfen können.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

#### System-Tastenkombinationen

Diese Tastenkombinationen gelten je nach Verwendung des iPad für Anzeige- und Soundeinstellungen.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Bildschirm abdunkeln                                                           |
| F2       | Bildschirm aufhellen                                                           |
| F7       | Einen Song zurück                                                              |
| F8       | Wiedergabe/Pause                                                               |
| F9       | Song überspringen                                                              |
| F10      | Stummschalten                                                                  |
| F11      | Lautstärke verringern                                                          |
| F12      | Lautstärke erhöhen                                                             |
| ⌘ Space  | Eine Liste der verfügbaren Sprachen anzeigen; zur Auswahl erneut die Leertaste drücken. |

#### iPad-Navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Zu Home wechseln                                        |
| ⌘⇧H (Command-Shift-H)                              | Zu Home wechseln                                        |
| ⌘ (Space)                                          | Spotlight öffnen                                        |
| ⌘⇥ (Command-Tab)                                   | Die zehn zuletzt verwendeten Apps auflisten             |
| ⌘\~                                                | Zur letzten App wechseln                                |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (wird unten links eingeblendet, um ihn zu speichern oder zu bearbeiten) |
| ⌘⇧4                                                | Screenshot aufnehmen und im Editor öffnen               |
| ⌘ gedrückt halten                                  | Liste der für die App verfügbaren Tastenkombinationen anzeigen |
| ⌘⌥D (Command-Option/Alt-D)                         | Dock anzeigen                                           |
| ^⌥H (Control-Option-H)                             | Home-Taste                                              |
| ^⌥H H (Control-Option-H-H)                         | Multitasking-Leiste anzeigen                            |
| ^⌥I (Control-Option-i)                             | Elementauswahl                                          |
| Escape                                             | Zurück-Taste                                            |
| → (Right arrow)                                    | Nächstes Element                                        |
| ← (Left arrow)                                     | Vorheriges Element                                      |
| ↑↓ (Up arrow, Down arrow)                          | Ausgewähltes Element gleichzeitig antippen              |
| ⌥ ↓ (Option-Down arrow)                            | Nach unten scrollen                                     |
| ⌥↑ (Option-Up arrow)                               | Nach oben scrollen                                      |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Nach links oder rechts scrollen                         |
| ^⌥S (Control-Option-S)                             | VoiceOver-Sprachausgabe ein- oder ausschalten           |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Zur vorherigen App wechseln                             |
| ⌘⇥ (Command-Tab)                                   | Zur ursprünglichen App zurückwechseln                  |
| ←+→, then Option + ← or Option+→                   | Durch das Dock navigieren                               |

#### Safari-Tastenkombinationen

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Ort öffnen                                       |
| ⌘T                      | Einen neuen Tab öffnen                            |
| ⌘W                      | Aktuellen Tab schließen                           |
| ⌘R                      | Aktuellen Tab aktualisieren                       |
| ⌘.                      | Laden des aktuellen Tabs stoppen                  |
| ^⇥                      | Zum nächsten Tab wechseln                         |
| ^⇧⇥ (Control-Shift-Tab) | Zum vorherigen Tab wechseln                       |
| ⌘L                      | Texteingabe-/URL-Feld zur Bearbeitung auswählen  |
| ⌘⇧T (Command-Shift-T)   | Zuletzt geschlossenen Tab öffnen (mehrfach möglich) |
| ⌘\[                     | Eine Seite im Browserverlauf zurückgehen          |
| ⌘]                      | Eine Seite im Browserverlauf vorgehen             |
| ⌘⇧R                     | Reader-Modus aktivieren                           |

#### Mail-Tastenkombinationen

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Ort öffnen                   |
| ⌘T                         | Einen neuen Tab öffnen       |
| ⌘W                         | Aktuellen Tab schließen      |
| ⌘R                         | Aktuellen Tab aktualisieren  |
| ⌘.                         | Laden des aktuellen Tabs stoppen |
| ⌘⌥F (Command-Option/Alt-F) | Im Postfach suchen           |

## Referenzen

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
