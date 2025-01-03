# Anti-Forensische Techniken

{{#include ../../banners/hacktricks-training.md}}

## Zeitstempel

Ein Angreifer könnte daran interessiert sein, **die Zeitstempel von Dateien zu ändern**, um nicht entdeckt zu werden.\
Es ist möglich, die Zeitstempel im MFT in den Attributen `$STANDARD_INFORMATION` \_\_ und \_\_ `$FILE_NAME` zu finden.

Beide Attribute haben 4 Zeitstempel: **Änderung**, **Zugriff**, **Erstellung** und **MFT-Registrierungsänderung** (MACE oder MACB).

**Windows Explorer** und andere Tools zeigen die Informationen aus **`$STANDARD_INFORMATION`** an.

### TimeStomp - Anti-forensisches Tool

Dieses Tool **modifiziert** die Zeitstempelinformationen innerhalb von **`$STANDARD_INFORMATION`**, **aber** **nicht** die Informationen innerhalb von **`$FILE_NAME`**. Daher ist es möglich, **verdächtige** **Aktivitäten** zu **identifizieren**.

### Usnjrnl

Das **USN Journal** (Update Sequence Number Journal) ist eine Funktion des NTFS (Windows NT-Dateisystem), die Änderungen am Volume verfolgt. Das [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) Tool ermöglicht die Untersuchung dieser Änderungen.

![](<../../images/image (801).png>)

Das vorherige Bild ist die **Ausgabe**, die von dem **Tool** angezeigt wird, wo zu beobachten ist, dass einige **Änderungen vorgenommen wurden**.

### $LogFile

**Alle Metadatenänderungen an einem Dateisystem werden** in einem Prozess protokolliert, der als [Write-Ahead Logging](https://en.wikipedia.org/wiki/Write-ahead_logging) bekannt ist. Die protokollierten Metadaten werden in einer Datei namens `**$LogFile**` gespeichert, die sich im Stammverzeichnis eines NTFS-Dateisystems befindet. Tools wie [LogFileParser](https://github.com/jschicht/LogFileParser) können verwendet werden, um diese Datei zu analysieren und Änderungen zu identifizieren.

![](<../../images/image (137).png>)

Wiederum ist in der Ausgabe des Tools zu sehen, dass **einige Änderungen vorgenommen wurden**.

Mit demselben Tool ist es möglich zu identifizieren, **zu welcher Zeit die Zeitstempel geändert wurden**:

![](<../../images/image (1089).png>)

- CTIME: Erstellungszeit der Datei
- ATIME: Änderungszeit der Datei
- MTIME: MFT-Registrierungsänderung der Datei
- RTIME: Zugriffszeit der Datei

### Vergleich von `$STANDARD_INFORMATION` und `$FILE_NAME`

Eine weitere Möglichkeit, verdächtig modifizierte Dateien zu identifizieren, wäre der Vergleich der Zeit in beiden Attributen auf **Unstimmigkeiten** zu überprüfen.

### Nanosekunden

**NTFS**-Zeitstempel haben eine **Präzision** von **100 Nanosekunden**. Daher ist es sehr **verdächtig**, Dateien mit Zeitstempeln wie 2010-10-10 10:10:**00.000:0000 zu finden.

### SetMace - Anti-forensisches Tool

Dieses Tool kann beide Attribute `$STANDARD_INFORMATION` und `$FILE_NAME` ändern. Allerdings ist es seit Windows Vista notwendig, dass ein aktives Betriebssystem diese Informationen ändert.

## Datenversteckung

NFTS verwendet einen Cluster und die minimale Informationsgröße. Das bedeutet, dass, wenn eine Datei einen Cluster und einen halben Cluster belegt, die **verbleibende Hälfte niemals verwendet wird**, bis die Datei gelöscht wird. Daher ist es möglich, **Daten in diesem Slack-Space zu verstecken**.

Es gibt Tools wie Slacker, die es ermöglichen, Daten in diesem "versteckten" Raum zu verbergen. Eine Analyse des `$logfile` und `$usnjrnl` kann jedoch zeigen, dass einige Daten hinzugefügt wurden:

![](<../../images/image (1060).png>)

Dann ist es möglich, den Slack-Space mit Tools wie FTK Imager wiederherzustellen. Beachten Sie, dass diese Art von Tool den Inhalt obfuskiert oder sogar verschlüsselt speichern kann.

## UsbKill

Dies ist ein Tool, das den Computer **ausschaltet, wenn eine Änderung an den USB**-Ports erkannt wird.\
Eine Möglichkeit, dies zu entdecken, wäre, die laufenden Prozesse zu inspizieren und **jedes laufende Python-Skript zu überprüfen**.

## Live-Linux-Distributionen

Diese Distributionen werden **im RAM** ausgeführt. Die einzige Möglichkeit, sie zu erkennen, besteht darin, **wenn das NTFS-Dateisystem mit Schreibberechtigungen gemountet ist**. Wenn es nur mit Lesezugriff gemountet ist, wird es nicht möglich sein, die Eindringung zu erkennen.

## Sichere Löschung

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows-Konfiguration

Es ist möglich, mehrere Windows-Protokollierungsmethoden zu deaktivieren, um die forensische Untersuchung erheblich zu erschweren.

### Zeitstempel deaktivieren - UserAssist

Dies ist ein Registrierungsschlüssel, der Daten und Uhrzeiten speichert, wann jede ausführbare Datei vom Benutzer ausgeführt wurde.

Das Deaktivieren von UserAssist erfordert zwei Schritte:

1. Setzen Sie zwei Registrierungsschlüssel, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` und `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, beide auf null, um anzuzeigen, dass wir UserAssist deaktivieren möchten.
2. Löschen Sie Ihre Registrierungssubbäume, die wie `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` aussehen.

### Zeitstempel deaktivieren - Prefetch

Dies speichert Informationen über die ausgeführten Anwendungen mit dem Ziel, die Leistung des Windows-Systems zu verbessern. Dies kann jedoch auch für forensische Praktiken nützlich sein.

- Führen Sie `regedit` aus
- Wählen Sie den Dateipfad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Klicken Sie mit der rechten Maustaste auf `EnablePrefetcher` und `EnableSuperfetch`
- Wählen Sie Ändern bei jedem dieser, um den Wert von 1 (oder 3) auf 0 zu ändern
- Neustart

### Zeitstempel deaktivieren - Letzte Zugriffszeit

Immer wenn ein Ordner von einem NTFS-Volume auf einem Windows NT-Server geöffnet wird, nimmt das System sich die Zeit, um **ein Zeitstempelfeld für jeden aufgelisteten Ordner zu aktualisieren**, das als letzte Zugriffszeit bezeichnet wird. Bei einem stark genutzten NTFS-Volume kann dies die Leistung beeinträchtigen.

1. Öffnen Sie den Registrierungs-Editor (Regedit.exe).
2. Navigieren Sie zu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Suchen Sie nach `NtfsDisableLastAccessUpdate`. Wenn es nicht existiert, fügen Sie dieses DWORD hinzu und setzen Sie seinen Wert auf 1, um den Prozess zu deaktivieren.
4. Schließen Sie den Registrierungs-Editor und starten Sie den Server neu.

### USB-Historie löschen

Alle **USB-Geräteeinträge** werden in der Windows-Registrierung unter dem **USBSTOR**-Registrierungsschlüssel gespeichert, der Unterschlüssel enthält, die erstellt werden, wenn Sie ein USB-Gerät an Ihren PC oder Laptop anschließen. Sie finden diesen Schlüssel hier `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Durch das Löschen dieses** Schlüssels löschen Sie die USB-Historie.\
Sie können auch das Tool [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) verwenden, um sicherzustellen, dass Sie sie gelöscht haben (und um sie zu löschen).

Eine weitere Datei, die Informationen über die USBs speichert, ist die Datei `setupapi.dev.log` im Verzeichnis `C:\Windows\INF`. Diese sollte ebenfalls gelöscht werden.

### Schattenkopien deaktivieren

**Liste** der Schattenkopien mit `vssadmin list shadowstorage`\
**Löschen** Sie sie, indem Sie `vssadmin delete shadow` ausführen.

Sie können sie auch über die GUI löschen, indem Sie die Schritte in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) befolgen.

Um Schattenkopien zu deaktivieren, [Schritte von hier](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Öffnen Sie das Dienstprogramm Dienste, indem Sie "Dienste" in das Textsuchfeld eingeben, nachdem Sie auf die Windows-Starttaste geklickt haben.
2. Suchen Sie in der Liste nach "Volume Shadow Copy", wählen Sie es aus und greifen Sie dann mit einem Rechtsklick auf die Eigenschaften zu.
3. Wählen Sie Deaktiviert aus dem Dropdown-Menü "Starttyp" und bestätigen Sie die Änderung, indem Sie auf Übernehmen und OK klicken.

Es ist auch möglich, die Konfiguration zu ändern, welche Dateien in der Schattenkopie kopiert werden sollen, in der Registrierung `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`.

### Gelöschte Dateien überschreiben

- Sie können ein **Windows-Tool** verwenden: `cipher /w:C`. Dies weist Cipher an, alle Daten aus dem verfügbaren ungenutzten Speicherplatz auf dem C-Laufwerk zu entfernen.
- Sie können auch Tools wie [**Eraser**](https://eraser.heidi.ie) verwenden.

### Windows-Ereignisprotokolle löschen

- Windows + R --> eventvwr.msc --> Erweitern Sie "Windows-Protokolle" --> Klicken Sie mit der rechten Maustaste auf jede Kategorie und wählen Sie "Protokoll löschen"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows-Ereignisprotokolle deaktivieren

- `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Deaktivieren Sie im Abschnitt Dienste den Dienst "Windows-Ereignisprotokoll"
- `WEvtUtil.exec clear-log` oder `WEvtUtil.exe cl`

### Deaktivieren von $UsnJrnl

- `fsutil usn deletejournal /d c:`

{{#include ../../banners/hacktricks-training.md}}
