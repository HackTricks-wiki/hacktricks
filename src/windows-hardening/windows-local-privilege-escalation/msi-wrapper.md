# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper kann eine ausführbare Datei oder ein Skript als Windows-Installer-Datei (`.msi`) paketieren. Lade die kostenlose Edition herunter und starte sie. Wähle anschließend die ausführbare Datei aus, die paketiert werden soll.<sup>[[3]](#references)</sup> Um eine Befehlsfolge auszuführen, wähle eine `.bat`-Datei als Eingabe aus, anstatt `cmd.exe` zu paketieren.<sup>[[1]](#references)</sup>

![Auswählen der Quelldatei oder des Batch-Skripts in MSI Wrapper](<../../images/image (417).png>)

Konfiguriere den Ausführungskontext und die anderen Eigenschaften des Installers sorgfältig:

![Konfigurieren der Anwendungs-ID und des Sicherheitskontexts in MSI Wrapper](<../../images/image (312).png>)

![Konfigurieren der Eigenschaften des Installers in MSI Wrapper](<../../images/image (346).png>)

![Überprüfen der Build-Einstellungen von MSI Wrapper](<../../images/image (1072).png>)

Diese Werte können beim Paketieren einer benutzerdefinierten Binärdatei geändert werden.

Fahre durch die verbleibenden Seiten des Assistenten fort und wähle **Build**, um den Installer zu erzeugen.<sup>[[1]](#references)</sup>

> [!WARNING]
> Das Erstellen einer MSI-Datei gewährt nicht automatisch erhöhte Berechtigungen. Ob die Installation mit erhöhten Berechtigungen erfolgt, hängt von der Windows-Installer-Richtlinie, dem Paketkontext und der Benutzerautorisierung ab. Microsoft warnt davor, dass die Aktivierung von `AlwaysInstallElevated` sowohl für den Benutzer als auch für den Computer Nichtadministratoren ermöglicht, Pakete mit Systemberechtigungen zu installieren.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper-Dokumentation - Erste Schritte](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installieren eines Pakets mit erhöhten Berechtigungen für einen Nichtadministrator](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
