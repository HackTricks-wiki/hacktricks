# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

**Für weitere Details zur Technik siehe den Originalbeitrag von:** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) und den folgenden Beitrag von [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**.** Hier ist eine Zusammenfassung:

### Was sind Nib-Dateien

Nib (kurz für NeXT Interface Builder) Dateien, Teil von Apples Entwicklungsökosystem, sind dazu gedacht, **UI-Elemente** und deren Interaktionen in Anwendungen zu definieren. Sie umfassen serialisierte Objekte wie Fenster und Schaltflächen und werden zur Laufzeit geladen. Trotz ihrer fortwährenden Nutzung empfiehlt Apple jetzt Storyboards für eine umfassendere Visualisierung des UI-Flusses.

Die Haupt-Nib-Datei wird im Wert **`NSMainNibFile`** innerhalb der `Info.plist`-Datei der Anwendung referenziert und wird durch die Funktion **`NSApplicationMain`** geladen, die in der `main`-Funktion der Anwendung ausgeführt wird.

### Dirty Nib Injection Prozess

#### Erstellen und Einrichten einer NIB-Datei

1. **Erste Einrichtung**:
- Erstellen Sie eine neue NIB-Datei mit XCode.
- Fügen Sie ein Objekt zur Benutzeroberfläche hinzu und setzen Sie dessen Klasse auf `NSAppleScript`.
- Konfigurieren Sie die anfängliche `source`-Eigenschaft über Benutzerdefinierte Laufzeitattribute.
2. **Codeausführungs-Gadget**:
- Die Einrichtung ermöglicht das Ausführen von AppleScript auf Abruf.
- Integrieren Sie eine Schaltfläche, um das `Apple Script`-Objekt zu aktivieren, das speziell den Selektor `executeAndReturnError:` auslöst.
3. **Testen**:

- Ein einfaches Apple Script zu Testzwecken:

```bash
set theDialogText to "PWND"
display dialog theDialogText
```

- Testen Sie, indem Sie im XCode-Debugger ausführen und auf die Schaltfläche klicken.

#### Zielanwendung anvisieren (Beispiel: Pages)

1. **Vorbereitung**:
- Kopieren Sie die Zielanwendung (z. B. Pages) in ein separates Verzeichnis (z. B. `/tmp/`).
- Starten Sie die Anwendung, um Gatekeeper-Probleme zu umgehen und sie zu cachen.
2. **Überschreiben der NIB-Datei**:
- Ersetzen Sie eine vorhandene NIB-Datei (z. B. About Panel NIB) durch die erstellte DirtyNIB-Datei.
3. **Ausführung**:
- Lösen Sie die Ausführung aus, indem Sie mit der Anwendung interagieren (z. B. das Menüelement `Über` auswählen).

#### Proof of Concept: Zugriff auf Benutzerdaten

- Ändern Sie das AppleScript, um auf Benutzerdaten zuzugreifen und diese zu extrahieren, z. B. Fotos, ohne die Zustimmung des Benutzers.

### Codebeispiel: Bösartige .xib-Datei

- Greifen Sie auf eine [**Beispiel einer bösartigen .xib-Datei**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4) zu, die das Ausführen beliebigen Codes demonstriert.

### Anderes Beispiel

Im Beitrag [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) finden Sie ein Tutorial, wie man einen Dirty Nib erstellt.&#x20;

### Umgang mit Startbeschränkungen

- Startbeschränkungen behindern die Ausführung von Apps aus unerwarteten Orten (z. B. `/tmp`).
- Es ist möglich, Apps zu identifizieren, die nicht durch Startbeschränkungen geschützt sind, und sie für die NIB-Datei-Injektion anzuvisieren.

### Zusätzliche macOS-Schutzmaßnahmen

Seit macOS Sonoma sind Änderungen innerhalb von App-Bundles eingeschränkt. Frühere Methoden umfassten:

1. Kopieren der App an einen anderen Ort (z. B. `/tmp/`).
2. Umbenennen von Verzeichnissen innerhalb des App-Bundles, um anfängliche Schutzmaßnahmen zu umgehen.
3. Nach dem Ausführen der App, um sich bei Gatekeeper zu registrieren, das App-Bundle ändern (z. B. MainMenu.nib durch Dirty.nib ersetzen).
4. Verzeichnisse zurückbenennen und die App erneut ausführen, um die injizierte NIB-Datei auszuführen.

**Hinweis**: Neuere macOS-Updates haben diesen Exploit gemildert, indem sie Dateiänderungen innerhalb von App-Bundles nach dem Caching durch Gatekeeper verhindern, wodurch der Exploit unwirksam wird.

{{#include ../../../banners/hacktricks-training.md}}
