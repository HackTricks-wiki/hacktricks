# Ausbruch aus KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Physisches Gerät überprüfen

| Komponente   | Aktion                                                              |
| ------------ | ------------------------------------------------------------------- |
| Power button | Das Gerät aus- und wieder einschalten kann den Startbildschirm anzeigen |
| Power cable  | Prüfen, ob das Gerät neu startet, wenn die Stromversorgung kurz unterbrochen wird |
| USB ports    | Physische Tastatur anschließen, die mehr Tastenkombinationen bietet |
| Ethernet     | Netzwerk-Scan oder Sniffing kann weitere Ausnutzungen ermöglichen    |

## Prüfen möglicher Aktionen innerhalb der GUI-Anwendung

**Common Dialogs** sind Optionen wie **Speichern einer Datei**, **Öffnen einer Datei**, Auswahl einer Schriftart, einer Farbe... Die meisten davon werden **eine vollständige Explorer-Funktionalität bieten**. Das bedeutet, dass Sie auf Explorer-Funktionen zugreifen können, wenn Sie diese Optionen erreichen:

- Schließen/Schließen als
- Öffnen/Öffnen mit
- Drucken
- Exportieren/Importieren
- Suchen
- Scannen

Sie sollten prüfen, ob Sie:

- Dateien ändern oder neue Dateien erstellen können
- Symbolische Links erstellen können
- Zugriff auf eingeschränkte Bereiche erhalten können
- Andere Apps ausführen können

### Befehlsausführung

Vielleicht können Sie mit der `Open with`-Option eine Art Shell öffnen/ausführen.

#### Windows

Zum Beispiel _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ — weitere Binaries, die verwendet werden können, um Befehle auszuführen (und unerwartete Aktionen durchzuführen), finden Sie hier: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_z.B. bash, sh, zsh..._ Weitere Informationen hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Umgehen von Pfadbeschränkungen

- **Environment variables**: Es gibt viele Umgebungsvariablen, die auf einen Pfad verweisen
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (Neue Sitzung öffnen), CTRL+R (Befehle ausführen), CTRL+SHIFT+ESC (Task-Manager), Windows+E (Explorer öffnen), CTRL-B, CTRL-I (Favoriten), CTRL-H (Verlauf), CTRL-L, CTRL-O (Datei/Öffnen-Dialog), CTRL-P (Druck-Dialog), CTRL-S (Speichern unter)
- Verstecktes Administrationsmenü: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Pfade, um sich mit freigegebenen Ordnern zu verbinden. Versuchen Sie, eine Verbindung zum C$ des lokalen Rechners herzustellen ("\\\127.0.0.1\c$\Windows\System32")
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

### Eingeschränkte Desktop-Ausbrüche (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Verwenden Sie *Open/Save/Print-to-file*-Dialoge als Explorer-Light. Versuchen Sie `*.*` / `*.exe` im Dateinamenfeld, Rechtsklick auf Ordner für **In neuem Fenster öffnen**, und verwenden Sie **Eigenschaften → Dateispeicherort öffnen**, um die Navigation zu erweitern.
- **Create execution paths from dialogs**: Erstellen Sie eine neue Datei und benennen Sie sie in `.CMD` oder `.BAT` um, oder erstellen Sie eine Verknüpfung, die auf `%WINDIR%\System32` zeigt (oder auf ein bestimmtes Binary wie `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Wenn Sie zu `cmd.exe` navigieren können, versuchen Sie, eine beliebige Datei per **Drag-and-drop** darauf zu ziehen, um eine Eingabeaufforderung zu starten. Wenn der Task-Manager erreichbar ist (`CTRL+SHIFT+ESC`), verwenden Sie **Neuen Task ausführen**.
- **Task Scheduler bypass**: Wenn interaktive Shells blockiert sind, Planung aber erlaubt ist, erstellen Sie eine Aufgabe, die `cmd.exe` ausführt (GUI `taskschd.msc` oder `schtasks.exe`).
- **Weak allowlists**: Wenn Ausführung über **Dateiname/Erweiterung** erlaubt ist, benennen Sie Ihren Payload in einen erlaubten Namen um. Wenn über **Verzeichnis** erlaubt, kopieren Sie den Payload in einen erlaubten Programmordner und führen ihn dort aus.
- **Find writable staging paths**: Beginnen Sie mit `%TEMP%` und listen Sie beschreibbare Ordner mit Sysinternals AccessChk auf.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Nächster Schritt**: Wenn du eine Shell erhältst, wechsle zur Windows LPE-Checkliste:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Binaries herunterladen

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Zugriff auf das Dateisystem im Browser

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

- Sticky Keys – Drücke SHIFT 5 Mal
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Halte NUMLOCK für 5 Sekunden
- Filter Keys – Halte die rechte SHIFT-Taste für 12 Sekunden
- WINDOWS+F1 – Windows-Suche
- WINDOWS+D – Desktop anzeigen
- WINDOWS+E – Windows Explorer starten
- WINDOWS+R – Ausführen
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Suchen
- SHIFT+F10 – Kontextmenü
- CTRL+SHIFT+ESC – Task-Manager
- CTRL+ALT+DEL – Splash-Bildschirm bei neueren Windows-Versionen
- F1 – Hilfe F3 – Suchen
- F6 – Adressleiste
- F11 – Vollbild umschalten innerhalb von Internet Explorer
- CTRL+H – Internet Explorer Verlauf
- CTRL+T – Internet Explorer – Neuer Tab
- CTRL+N – Internet Explorer – Neue Seite
- CTRL+O – Datei öffnen
- CTRL+S – Speichern CTRL+N – Neuer RDP / Citrix

### Wischgesten

- Wische von links nach rechts, um alle offenen Windows zu sehen, die KIOSK-App zu minimieren und direkt auf das gesamte OS zuzugreifen;
- Wische von rechts nach links, um das Action Center zu öffnen, die KIOSK-App zu minimieren und direkt auf das gesamte OS zuzugreifen;
- Wische vom oberen Bildschirmrand nach innen, um die Titelleiste für eine App im Vollbildmodus sichtbar zu machen;
- Wische vom unteren Bildschirmrand nach oben, um die Taskleiste in einer Vollbild-App anzuzeigen.

### Internet Explorer-Tricks

#### 'Image Toolbar'

Das ist eine Symbolleiste, die oben links am Bild erscheint, wenn es angeklickt wird. Du kannst damit Save, Print, Mailto und "My Pictures" im Explorer öffnen. Der Kiosk muss Internet Explorer verwenden.

#### Shell-Protokoll

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

Siehe diese Seite für mehr Informationen: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Browser-Tricks

Backup iKat-Versionen:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Erzeuge einen Common Dialog mit JavaScript und greife auf den Datei-Explorer zu: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gesten und Tasten

- Wische mit vier (oder fünf) Fingern nach oben / Doppeltippe auf den Home-Button: Zum Anzeigen der Multitasking-Ansicht und Wechseln der App
- Wische mit vier oder fünf Fingern in die eine oder andere Richtung: Um zur nächsten/vorherigen App zu wechseln
- Zusammenziehen mit fünf Fingern / Home-Button berühren / Mit 1 Finger schnell vom unteren Bildschirmrand nach oben wischen: Zum Aufrufen des Home-Bildschirms
- Wische mit einem Finger vom unteren Bildschirmrand nur 1–2 Zoll (langsam): Das Dock erscheint
- Wische mit 1 Finger von oben nach unten: Um deine Benachrichtigungen zu sehen
- Wische mit 1 Finger von der oberen rechten Ecke nach unten: Um das Kontrollzentrum des iPad Pro zu sehen
- Wische mit 1 Finger von links 1–2 Zoll: Um die Heute-Ansicht zu sehen
- Wische schnell mit 1 Finger vom Bildschirmzentrum nach rechts oder links: Um zur nächsten/vorherigen App zu wechseln
- Drücke und halte den On/**Off**/Sleep-Button oben rechts am **iPad +** und bewege den Slide to **power off**-Schieber ganz nach rechts: Zum Ausschalten
- Drücke den On/**Off**/Sleep-Button oben rechts am **iPad** und den Home-Button für ein paar Sekunden: Zum Erzwingen eines harten Ausschaltens
- Drücke den On/**Off**/Sleep-Button oben rechts am **iPad** und den Home-Button schnell: Zum Erstellen eines Screenshots, der unten links im Display auftaucht. Drückst du beide Tasten sehr kurz gleichzeitig, passiert ein Screenshot; hältst du sie ein paar Sekunden, wird ein hartes Ausschalten ausgeführt.

### Tastenkürzel

Du solltest eine iPad-Tastatur oder einen USB-Tastatur-Adapter haben. Hier werden nur Kürzel gezeigt, die beim Entkommen aus der Anwendung helfen können.

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

Diese Kürzel betreffen Anzeige- und Toneinstellungen, abhängig von der Nutzung des iPad.

| Shortcut | Aktion                                                                        |
| -------- | ----------------------------------------------------------------------------- |
| F1       | Bildschirm dimmen                                                             |
| F2       | Bildschirm aufhellen                                                          |
| F7       | Ein Lied zurück                                                               |
| F8       | Play/Pause                                                                    |
| F9       | Lied überspringen                                                             |
| F10      | Stummschalten                                                                 |
| F11      | Lautstärke verringern                                                         |
| F12      | Lautstärke erhöhen                                                            |
| ⌘ Space  | Zeigt eine Liste verfügbarer Sprachen; zum Auswählen erneut die Leertaste tippen. |

#### iPad-Navigation

| Shortcut                                           | Aktion                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gehe zum Home                                           |
| ⌘⇧H (Command-Shift-H)                              | Gehe zum Home                                           |
| ⌘ (Space)                                          | Spotlight öffnen                                        |
| ⌘⇥ (Command-Tab)                                   | Listet die letzten zehn verwendeten Apps auf            |
| ⌘\~                                                | Gehe zur letzten App                                    |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (erscheint unten links zum Speichern oder Bearbeiten) |
| ⌘⇧4                                                | Screenshot und öffnet diesen im Editor                  |
| Press and hold ⌘                                   | Liste der verfügbaren Kürzel für die App                |
| ⌘⌥D (Command-Option/Alt-D)                         | Öffnet das Dock                                         |
| ^⌥H (Control-Option-H)                             | Home-Button                                             |
| ^⌥H H (Control-Option-H-H)                         | Zeigt die Multitasking-Leiste                           |
| ^⌥I (Control-Option-i)                             | Item-Auswahl                                            |
| Escape                                             | Zurück                                                  |
| → (Right arrow)                                    | Nächstes Element                                        |
| ← (Left arrow)                                     | Vorheriges Element                                      |
| ↑↓ (Up arrow, Down arrow)                          | Markiertes Element gleichzeitig antippen                |
| ⌥ ↓ (Option-Down arrow)                            | Nach unten scrollen                                     |
| ⌥↑ (Option-Up arrow)                               | Nach oben scrollen                                      |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Nach links oder rechts scrollen                         |
| ^⌥S (Control-Option-S)                             | VoiceOver-Sprachausgabe ein-/ausschalten                |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Zur vorherigen App wechseln                             |
| ⌘⇥ (Command-Tab)                                   | Zur ursprünglichen App zurückwechseln                   |
| ←+→, dann Option + ← oder Option+→                 | Durch das Dock navigieren                               |

#### Safari-Kürzel

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
| ⌘⇧T (Command-Shift-T)   | Zuletzt geschlossenen Tab öffnen (mehrfach nutzbar) |
| ⌘\[                     | Eine Seite zurück in der Browserverlauf          |
| ⌘]                      | Eine Seite vorwärts in der Browserverlauf        |
| ⌘⇧R                     | Reader Mode aktivieren                           |

#### Mail-Kürzel

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
