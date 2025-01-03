{{#include ../../banners/hacktricks-training.md}}

# Überprüfen Sie mögliche Aktionen innerhalb der GUI-Anwendung

**Gemeinsame Dialoge** sind Optionen wie **eine Datei speichern**, **eine Datei öffnen**, eine Schriftart oder eine Farbe auswählen... Die meisten von ihnen bieten **eine vollständige Explorer-Funktionalität**. Das bedeutet, dass Sie auf Explorer-Funktionen zugreifen können, wenn Sie auf diese Optionen zugreifen können:

- Schließen/Als schließen
- Öffnen/Öffnen mit
- Drucken
- Exportieren/Importieren
- Suchen
- Scannen

Sie sollten überprüfen, ob Sie:

- Dateien ändern oder neue Dateien erstellen können
- Symbolische Links erstellen können
- Zugriff auf eingeschränkte Bereiche erhalten können
- Andere Apps ausführen können

## Befehlsausführung

Vielleicht können Sie **mit einer `Öffnen mit`** Option\*\* eine Art Shell öffnen/ausführen.

### Windows

Zum Beispiel _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ finden Sie hier weitere Binärdateien, die verwendet werden können, um Befehle auszuführen (und unerwartete Aktionen durchzuführen): [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX \_\_

_bash, sh, zsh..._ Mehr hier: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Umgehung von Pfadbeschränkungen

- **Umgebungsvariablen**: Es gibt viele Umgebungsvariablen, die auf einen bestimmten Pfad zeigen
- **Andere Protokolle**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolische Links**
- **Verknüpfungen**: CTRL+N (neue Sitzung öffnen), CTRL+R (Befehle ausführen), CTRL+SHIFT+ESC (Task-Manager), Windows+E (Explorer öffnen), CTRL-B, CTRL-I (Favoriten), CTRL-H (Verlauf), CTRL-L, CTRL-O (Datei/Öffnen-Dialog), CTRL-P (Drucken-Dialog), CTRL-S (Speichern unter)
- Verstecktes Administrationsmenü: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell-URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC-Pfade**: Pfade zum Verbinden mit freigegebenen Ordnern. Sie sollten versuchen, sich mit dem C$ des lokalen Computers zu verbinden ("\\\127.0.0.1\c$\Windows\System32")
- **Weitere UNC-Pfade:**

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

## Laden Sie Ihre Binärdateien herunter

Konsole: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registrierungseditor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Zugriff auf das Dateisystem über den Browser

| PFAD                | PFAD              | PFAD               | PFAD                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Verknüpfungen

- Sticky Keys – Drücken Sie SHIFT 5 Mal
- Mouse Keys – SHIFT+ALT+NUMLOCK
- Hoher Kontrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Halten Sie NUMLOCK 5 Sekunden lang gedrückt
- Filter Keys – Halten Sie die rechte SHIFT-Taste 12 Sekunden lang gedrückt
- WINDOWS+F1 – Windows-Suche
- WINDOWS+D – Desktop anzeigen
- WINDOWS+E – Windows Explorer starten
- WINDOWS+R – Ausführen
- WINDOWS+U – Eingabehilfen-Center
- WINDOWS+F – Suchen
- SHIFT+F10 – Kontextmenü
- CTRL+SHIFT+ESC – Task-Manager
- CTRL+ALT+DEL – Startbildschirm in neueren Windows-Versionen
- F1 – Hilfe F3 – Suchen
- F6 – Adressleiste
- F11 – Vollbildmodus in Internet Explorer umschalten
- CTRL+H – Internet Explorer Verlauf
- CTRL+T – Internet Explorer – Neuer Tab
- CTRL+N – Internet Explorer – Neue Seite
- CTRL+O – Datei öffnen
- CTRL+S – Speichern CTRL+N – Neues RDP / Citrix

## Wischen

- Wischen Sie von der linken Seite nach rechts, um alle offenen Fenster zu sehen, minimieren Sie die KIOSK-App und greifen Sie direkt auf das gesamte Betriebssystem zu;
- Wischen Sie von der rechten Seite nach links, um das Aktionscenter zu öffnen, minimieren Sie die KIOSK-App und greifen Sie direkt auf das gesamte Betriebssystem zu;
- Wischen Sie von der oberen Kante nach unten, um die Titelleiste für eine im Vollbildmodus geöffnete App sichtbar zu machen;
- Wischen Sie von unten nach oben, um die Taskleiste in einer Vollbild-App anzuzeigen.

## Internet Explorer Tricks

### 'Bildtoolbar'

Es ist eine Toolbar, die oben links im Bild erscheint, wenn darauf geklickt wird. Sie können Speichern, Drucken, Mailto, "Meine Bilder" im Explorer öffnen. Der Kiosk muss Internet Explorer verwenden.

### Shell-Protokoll

Geben Sie diese URLs ein, um eine Explorer-Ansicht zu erhalten:

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Systemsteuerung
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mein Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Meine Netzwerkstandorte
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Dateierweiterungen anzeigen

Überprüfen Sie diese Seite für weitere Informationen: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Browser-Tricks

Backup iKat-Versionen:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Erstellen Sie einen gemeinsamen Dialog mit JavaScript und greifen Sie auf den Datei-Explorer zu: `document.write('<input/type=file>')`
Quelle: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gesten und Tasten

- Wischen Sie mit vier (oder fünf) Fingern nach oben / Doppeltippen auf die Home-Taste: Um die Multitasking-Ansicht anzuzeigen und die App zu wechseln

- Wischen Sie in eine oder andere Richtung mit vier oder fünf Fingern: Um zur nächsten/vorherigen App zu wechseln

- Kneifen Sie den Bildschirm mit fünf Fingern / Berühren Sie die Home-Taste / Wischen Sie mit 1 Finger schnell von unten nach oben: Um auf die Startseite zuzugreifen

- Wischen Sie mit einem Finger von unten auf dem Bildschirm nur 1-2 Zoll (langsam): Das Dock wird angezeigt

- Wischen Sie mit 1 Finger von oben auf dem Display: Um Ihre Benachrichtigungen anzuzeigen

- Wischen Sie mit 1 Finger in die obere rechte Ecke des Bildschirms: Um das Kontrollzentrum des iPad Pro zu sehen

- Wischen Sie mit 1 Finger von der linken Seite des Bildschirms 1-2 Zoll: Um die Heute-Ansicht zu sehen

- Wischen Sie schnell mit 1 Finger von der Mitte des Bildschirms nach rechts oder links: Um zur nächsten/vorherigen App zu wechseln

- Drücken und halten Sie die Ein-/**Ausschalt**-/Ruhe-Taste in der oberen rechten Ecke des **iPad +** Bewegen Sie den Schieberegler **zum Ausschalten** ganz nach rechts: Um auszuschalten

- Drücken Sie die Ein-/**Ausschalt**-/Ruhe-Taste in der oberen rechten Ecke des **iPad und die Home-Taste für einige Sekunden**: Um einen harten Ausschaltvorgang zu erzwingen

- Drücken Sie die Ein-/**Ausschalt**-/Ruhe-Taste in der oberen rechten Ecke des **iPad und die Home-Taste schnell**: Um einen Screenshot zu machen, der in der unteren linken Ecke des Displays angezeigt wird. Drücken Sie beide Tasten gleichzeitig sehr kurz, da bei längerem Halten ein harter Ausschaltvorgang durchgeführt wird.

## Verknüpfungen

Sie sollten eine iPad-Tastatur oder einen USB-Tastaturadapter haben. Nur Verknüpfungen, die beim Entkommen aus der Anwendung helfen könnten, werden hier angezeigt.

| Taste | Name         |
| --- | ------------ |
| ⌘   | Befehl      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Eingabe       |
| ⇥   | Tab          |
| ^   | Steuerung      |
| ←   | Linker Pfeil   |
| →   | Rechter Pfeil  |
| ↑   | Aufwärtspfeil     |
| ↓   | Abwärtspfeil     |

### Systemverknüpfungen

Diese Verknüpfungen sind für die visuellen Einstellungen und Toneinstellungen, abhängig von der Verwendung des iPads.

| Verknüpfung | Aktion                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Bildschirm dimmen                                                                    |
| F2       | Bildschirm aufhellen                                                                |
| F7       | Einen Song zurück                                                                  |
| F8       | Abspielen/Pause                                                                     |
| F9       | Song überspringen                                                                      |
| F10      | Stummschalten                                                                           |
| F11      | Lautstärke verringern                                                                |
| F12      | Lautstärke erhöhen                                                                |
| ⌘ Space  | Eine Liste verfügbarer Sprachen anzeigen; um eine auszuwählen, drücken Sie die Leertaste erneut. |

### iPad-Navigation

| Verknüpfung                                           | Aktion                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Gehe zu Home                                              |
| ⌘⇧H (Befehl-Shift-H)                              | Gehe zu Home                                              |
| ⌘ (Leertaste)                                      | Spotlight öffnen                                          |
| ⌘⇥ (Befehl-Tab)                                   | Liste der letzten zehn verwendeten Apps                                 |
| ⌘\~                                                | Gehe zur letzten App                                       |
| ⌘⇧3 (Befehl-Shift-3)                              | Screenshot (schwebt unten links, um zu speichern oder zu handeln) |
| ⌘⇧4                                                | Screenshot und im Editor öffnen                    |
| Drücken und Halten von ⌘                                   | Liste der verfügbaren Verknüpfungen für die App                 |
| ⌘⌥D (Befehl-Option/Alt-D)                         | Dock anzeigen                                      |
| ^⌥H (Steuerung-Option-H)                             | Home-Taste                                             |
| ^⌥H H (Steuerung-Option-H-H)                         | Multitasking-Leiste anzeigen                                      |
| ^⌥I (Steuerung-Option-i)                             | Elementauswahl                                            |
| Escape                                             | Zurück-Taste                                             |
| → (Rechter Pfeil)                                    | Nächstes Element                                               |
| ← (Linker Pfeil)                                     | Vorheriges Element                                           |
| ↑↓ (Aufwärtspfeil, Abwärtspfeil)                          | Ausgewähltes Element gleichzeitig antippen                        |
| ⌥ ↓ (Option-Abwärtspfeil)                            | Nach unten scrollen                                             |
| ⌥↑ (Option-Aufwärtspfeil)                               | Nach oben scrollen                                               |
| ⌥← oder ⌥→ (Option-Linker Pfeil oder Option-Rechter Pfeil) | Nach links oder rechts scrollen                                    |
| ^⌥S (Steuerung-Option-S)                             | VoiceOver-Sprachausgabe ein- oder ausschalten                         |
| ⌘⇧⇥ (Befehl-Shift-Tab)                            | Zur vorherigen App wechseln                              |
| ⌘⇥ (Befehl-Tab)                                   | Zur ursprünglichen App zurückwechseln                         |
| ←+→, dann Option + ← oder Option+→                   | Durch das Dock navigieren                                   |

### Safari-Verknüpfungen

| Verknüpfung                | Aktion                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Befehl-L)          | Standort öffnen                                    |
| ⌘T                      | Neuen Tab öffnen                                   |
| ⌘W                      | Den aktuellen Tab schließen                            |
| ⌘R                      | Den aktuellen Tab aktualisieren                          |
| ⌘.                      | Das Laden des aktuellen Tabs stoppen                     |
| ^⇥                      | Zum nächsten Tab wechseln                           |
| ^⇧⇥ (Steuerung-Shift-Tab) | Zum vorherigen Tab wechseln                         |
| ⌘L                      | Das Texteingabefeld/URL-Feld auswählen, um es zu ändern     |
| ⌘⇧T (Befehl-Shift-T)   | Letzten geschlossenen Tab öffnen (kann mehrmals verwendet werden) |
| ⌘\[                     | Gehe eine Seite in deinem Browserverlauf zurück      |
| ⌘]                      | Gehe eine Seite in deinem Browserverlauf vorwärts   |
| ⌘⇧R                     | Reader-Modus aktivieren                             |

### Mail-Verknüpfungen

| Verknüpfung                   | Aktion                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Standort öffnen                |
| ⌘T                         | Neuen Tab öffnen               |
| ⌘W                         | Den aktuellen Tab schließen        |
| ⌘R                         | Den aktuellen Tab aktualisieren      |
| ⌘.                         | Das Laden des aktuellen Tabs stoppen |
| ⌘⌥F (Befehl-Option/Alt-F) | In deinem Postfach suchen       |

# Referenzen

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../../banners/hacktricks-training.md}}
