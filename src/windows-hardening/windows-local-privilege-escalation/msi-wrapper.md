# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper kann eine ausführbare Datei oder ein Skript als Windows Installer-Datei (`.msi`) verpacken. Lade die kostenlose Edition herunter und starte sie. Wähle anschließend die ausführbare Datei aus, die verpackt werden soll.<sup>[[3]](#references)</sup> Um eine Befehlsfolge auszuführen, wähle eine `.bat`-Datei als Eingabe, anstatt `cmd.exe` zu verpacken.<sup>[[1]](#references)</sup>

![Auswählen der Quelldatei oder des Batch-Skripts in MSI Wrapper](<../../images/image (417).png>)

Konfiguriere den Ausführungskontext und andere Eigenschaften des Installers sorgfältig:

![Konfigurieren der Anwendungs-ID und des Sicherheitskontexts in MSI Wrapper](<../../images/image (312).png>)

![Konfigurieren der Installer-Eigenschaften in MSI Wrapper](<../../images/image (346).png>)

![Überprüfen der Build-Einstellungen von MSI Wrapper](<../../images/image (1072).png>)

Diese Werte können beim Verpacken einer benutzerdefinierten Binärdatei geändert werden.

Gehe durch die verbleibenden Seiten des Assistenten und wähle **Build**, um den Installer zu erstellen.<sup>[[1]](#references)</sup>

## Ausführungskontext des umschlossenen Befehls überprüfen

Verpacke für ein Testpaket eine `.bat`-Datei, die ihren Token aufzeichnet, anstatt anzunehmen, dass die Einstellung zur Rechteerhöhung des MSI auch für dessen untergeordneten Prozess gilt.<sup>[[4]](#references)</sup> Wähle im Assistenten den Sicherheitskontext **System** statt **User** und eine computerweite Installation mit erhöhten Rechten, wenn dies der vorgesehene Weg ist.<sup>[[5]](#references)</sup> Die Option **System** umgeht keine Autorisierung: Ein Benutzer ohne Administratorrechte benötigt weiterhin einen Weg für eine Installation mit erhöhten Rechten, etwa die [Fehlkonfiguration mit den zwei Richtlinien `AlwaysInstallElevated`](index.html#alwaysinstallelevated) oder einen privilegierten Installer-Workflow.<sup>[[2]](#references)</sup> Bei Auswahl von **User** wird der umschlossene Befehl stattdessen im Kontext des installierenden Benutzers ausgeführt. Das kann für benutzerspezifische oder Netzwerkressourcen erforderlich sein.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Erstellen Sie das MSI mit dieser Batch-Datei als Eingabe, führen Sie es anschließend auf dem Testhost aus und überprüfen Sie die aufgezeichnete Identität und die Berechtigungen.<sup>[[4]](#references)</sup> MSI Wrapper ordnet einem Batch-Exitcode ungleich null den Installationsfehler 1603 zu. Der explizite Exitcode null verhindert daher nach einem erfolgreichen Test einen falschen Fehler.<sup>[[4]](#references)</sup> Die Ausgabedatei ist ein Testartefakt; schließen Sie nicht allein aus einem erfolgreichen `msiexec`-Exit oder einer Installation im Quiet-Modus auf eine Ausführung als SYSTEM.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` unterdrückt die MSI-Benutzeroberfläche, nicht unbedingt die eigene Benutzeroberfläche der eingebundenen ausführbaren Datei.<sup>[[6]](#references)[[7]](#references)</sup> Legen Sie bei einem eingebundenen Installer dessen unterstützte Silent-Argumente im Wizard fest; die dynamische Eigenschaft `WRAPPED_ARGUMENTS` von MSI Wrapper ist eine PRO-Funktion.<sup>[[1]](#references)[[7]](#references)</sup> Siehe [den WiX-Ansatz mit Custom Actions](create-msi-with-wix.md), wenn Sie die Reihenfolge und Impersonation von Custom Actions direkt steuern müssen.

> [!WARNING]
> Das Erstellen eines MSI gewährt nicht automatisch erhöhte Berechtigungen. Ob eine Installation mit erhöhten Berechtigungen ausgeführt wird, hängt von der Windows-Installer-Richtlinie, dem Paketkontext und der Benutzerautorisierung ab. Microsoft warnt, dass die Aktivierung von `AlwaysInstallElevated` für Benutzer und Computer Nichtadministratoren das Installieren von Paketen mit Systemberechtigungen ermöglicht.<sup>[[2]](#references)</sup>



## References

- [1] [MSI Wrapper-Dokumentation - Erste Schritte](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installieren eines Pakets mit erhöhten Berechtigungen für einen Nichtadministrator](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - MSI aus einer Batchdatei erstellen](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Wizard-Seiten](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Befehlszeilenoptionen](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Befehlszeilenargumente](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
