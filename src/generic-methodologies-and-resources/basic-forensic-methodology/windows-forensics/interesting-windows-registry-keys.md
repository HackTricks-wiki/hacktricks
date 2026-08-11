# Interessante Windows-Registry-Schlüssel

{{#include ../../../banners/hacktricks-training.md}}

Windows-Registry-Hives gehören zu den schnellsten Möglichkeiten, von _was ist passiert?_ zu _welcher Benutzer, wann und von wo?_ zu gelangen. Für Live-Analysen sollte `CurrentControlSet` bevorzugt werden. Bei der Offline-Analyse von Hives muss zunächst ermittelt werden, welches `ControlSet00x` aktiv war, anstatt `ControlSet001` fest zu codieren.

### Windows-Version und Besitzerinformationen

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows-Edition/-Build, Installationszeit, registrierter Besitzer, Produktname und weitere Build-Metadaten.
- `SYSTEM\Select`: ordnet `Current`, `Default` und `LastKnownGood` den tatsächlichen, vom System verwendeten `ControlSet00x`-Werten zu.

### Computername

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: aktueller Hostname.

### Zeitzoneneinstellung

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: konfigurierte Zeitzone und Werte im Zusammenhang mit der Sommerzeit.

### Nachverfolgung von Zugriffszeiten

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` gibt an, ob die Zeitstempel des letzten NTFS-Zugriffs aktualisiert werden.
- Zum Aktivieren: `fsutil behavior set disablelastaccess 0`

### Details zum Herunterfahren

- `SYSTEM\CurrentControlSet\Control\Windows`: Zeitpunkt des letzten Herunterfahrens.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: Ältere Systeme können zusätzlich Zähler für das Herunterfahren bereitstellen.

### Netzwerkkonfiguration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs der Schnittstelle, DHCP-Leases sowie Gateway- und DNS-Daten.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: Name/SSID des Netzwerkprofils sowie Zeitpunkte der ersten und letzten Verbindung.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` und `...\Unmanaged\{GUID}`: Korrelationsdaten des Profils, etwa die MAC-Adresse des Gateways und das DNS-Suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: vom Host veröffentlichte lokale Netzwerkfreigaben.

### Remotezugriff und Verlauf von Netzwerkfreigaben

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: ausgehende RDP-MRU-Liste (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: Verlauf ausgehender RDP-Verbindungen pro Host. Unterschlüssel enthalten häufig `UsernameHint`; der `LastWrite`-Zeitpunkt des Schlüssels ist ein nützlicher Ansatzpunkt.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: zugeordneten Netzlaufwerke, UNC-Freigaben und Einhängepunkte von Wechselmedien, die einem bestimmten Benutzer zugeordnet sind.

### Automatisch startende Programme und geplante Persistenz

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` und `...\Tasks\{GUID}`: Metadaten geplanter Tasks. Wenn hier ein Task vorhanden ist, aber der Wert `SD` in `Tree\<TaskName>` fehlt, sollte eine versteckte Task-Manipulation im Stil von Tarrask vermutet und mit `C:\Windows\System32\Tasks\<TaskName>` korreliert werden.

### Suchvorgänge, eingegebene Pfade und MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: Suchbegriffe des Datei-Explorers.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: manuell eingegebene Explorer-Pfade.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: die letzten 26 `Win + R`-Befehle. `MRUList` bewahrt ihre Reihenfolge.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: zuletzt geöffnete Dokumente und Ordner.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: zuletzt verwendete Office-Dateien.

### Nachverfolgung der Benutzeraktivität

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: Ausführungsverlauf GUI-gesteuerter Aktionen. Wertnamen sind ROT13-codiert, und die Binärdaten enthalten Ausführungszähler sowie den Zeitpunkt der letzten Ausführung.<sup>[[1]](#references)</sup>
- `UserAssist` sollte als starker unterstützender Beleg und nicht als alleinige Entscheidungsgrundlage betrachtet werden: Die Funktion verfolgt hauptsächlich über den Explorer gestartete Apps oder `.lnk`-Dateien und kann Befehlszeilen- oder Dienstausführungen übersehen. Unter Windows 10+ bedeuten einige Einträge nicht zwingend, dass der Prozess vollständig ausgeführt wurde.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` und `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: moderne Ausführungsspuren unter Windows 10/11 mit SID-Zuordnung und Zeitpunkt der letzten Ausführung. Diese sind besonders für lokal ausgeführte Binärdateien nützlich, ältere Einträge können jedoch schnell entfernt werden, und Ausführungen von Netzwerkfreigaben oder Wechselmedien sind weniger zuverlässig.
- Für umfassendere Ausführungsartefakte wie Prefetch, Amcache, ShimCache und SRUM siehe die zentrale [Übersicht zur Windows-Forensik](README.md#programs-executed).

### Shellbags

- Shellbags werden sowohl in `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` als auch in `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` gespeichert.<sup>[[1]](#references)</sup>
- `NTUSER.DAT`-Einträge sind besonders für das Durchsuchen von UNC-Pfaden/Netzwerken nützlich, während `UsrClass.dat` unter Windows Vista+ üblicherweise lokale Shellbags und Shellbags von Wechseldatenträger-Ordnern speichert.
- Sie können die Existenz und das Durchsuchen von Ordnern sowie Einstellungen der Ordneransicht anzeigen, selbst nachdem der Ordner gelöscht wurde. Ein Explorer-ähnlicher Zugriff auf Archivdateien kann ebenfalls Shellbag-Spuren hinterlassen.<sup>[[1]](#references)</sup>
- Nicht jeder Shellbag belegt einen erfolgreichen Zugriff auf einen Ordner. Daher sollte er mit LNKs, Jump Lists, Zeitstempeln oder Volume-Zuordnungen corroboriert werden.
- Verwende **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** oder **SBECmd**, um sie zu analysieren.

### USB-Informationen

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primäres Inventar von USB-Massenspeichergeräten (Hersteller, Produkt, Revision, Seriennummer/Geräteinstanz).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: umfassenderes USB-Geräteinventar, einschließlich Nicht-Speichergeräten.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: Bei aktuellen Windows-10/11-Builds ist dies eine wichtige Stelle für gerätespezifische Lebenszyklus-Zeitstempel wie Installation, Erstinstallation, letztes Anschließen und letztes Entfernen.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: ordnet Volumes und Gerätekennungen Laufwerksbuchstaben/Volume-GUIDs zu. Es kann sein, dass nur die letzte Zuordnung für einen bestimmten Laufwerksbuchstaben erhalten bleibt.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: nützlicher Ansatzpunkt für Volume-Seriennummern und Metadaten früherer Medien.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: benutzerspezifischer Verlauf von Interaktionen mit Laufwerksbuchstaben und Freigaben.<sup>[[2]](#references)</sup>
- Moderne Telefone und Tablets, die über MTP/PTP verbunden sind, erscheinen möglicherweise **nicht** unter `USBSTOR`. Prüfe zusätzlich `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` und `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Um ein Gerät einem Benutzer zuzuordnen, sollte von Geräte- oder Volume-Kennungen zu benutzerspezifischen Artefakten wie Shellbags, LNKs, Jump Lists, `RecentDocs` und `MountPoints2` pivotiert werden.<sup>[[2]](#references)</sup>

## References

- [1] [Windows-Registry-Forensik-Spickzettel 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB-Geräteforensik unter Windows 10 und 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
