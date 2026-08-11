# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper kann eine ausführbare Datei oder ein Skript als Windows-Installer-Datei (`.msi`) verpacken. Laden Sie die kostenlose Edition herunter und starten Sie sie. Wählen Sie anschließend die ausführbare Datei aus, die verpackt werden soll. Um eine Befehlssequenz auszuführen, wählen Sie eine `.bat`-Datei als Eingabe aus, anstatt `cmd.exe` zu verpacken.<sup>[[1]](#references)</sup>

![Auswählen der Quelldatei oder des Batchskripts in MSI Wrapper](<../../images/image (417).png>)

Konfigurieren Sie den Ausführungskontext und andere Eigenschaften des Installers sorgfältig:

![Konfigurieren der Anwendungs-ID und des Sicherheitskontexts in MSI Wrapper](<../../images/image (312).png>)

![Konfigurieren der Eigenschaften des Installers in MSI Wrapper](<../../images/image (346).png>)

![Überprüfen der Build-Einstellungen von MSI Wrapper](<../../images/image (1072).png>)

Diese Werte können beim Verpacken einer benutzerdefinierten Binärdatei geändert werden.

Fahren Sie mit den verbleibenden Seiten des Assistenten fort und wählen Sie **Build**, um den Installer zu erstellen.<sup>[[1]](#references)</sup>

> [!WARNING]
> Das Erstellen einer MSI-Datei gewährt allein keine erhöhten Rechte. Ob die Installation mit erhöhten Rechten erfolgt, hängt von der Windows-Installer-Richtlinie, dem Paketkontext und der Benutzerautorisierung ab. Microsoft weist darauf hin, dass die Aktivierung von `AlwaysInstallElevated` sowohl für den Benutzer als auch für den Computer Nichtadministratoren ermöglicht, Pakete mit Systemrechten zu installieren.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper-Dokumentation - Erste Schritte](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installieren eines Pakets mit erhöhten Rechten für einen Nichtadministrator](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
