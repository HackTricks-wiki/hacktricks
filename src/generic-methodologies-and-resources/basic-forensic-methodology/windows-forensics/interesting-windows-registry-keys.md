# Interessante Windows-Registrierungsschlüssel

Windows-Registrierungs-Hives gehören zu den schnellsten Möglichkeiten, von _was ist passiert?_ zu _welcher Benutzer, wann und von wo?_ zu gelangen. Bei der Live-Analyse sollte `CurrentControlSet` bevorzugt werden. Bei der Offline-Hive-Analyse muss zuerst ermittelt werden, welches `ControlSet00x` aktiv war, anstatt `ControlSet001` fest zu codieren.

### Windows-Version und Besitzerinformationen

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows-Edition/-Build, Installationszeit, registrierter Besitzer, Produktname und weitere Build-Metadaten.
- `SYSTEM\Select`: ordnet `Current`, `Default` und `LastKnownGood` den tatsächlichen, vom System verwendeten `ControlSet00x`-Werten zu.

### Computername

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: aktueller Hostname.

### Zeitzoneneinstellung

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: konfigurierte Zeitzone und DST-bezogene Werte.

### Nachverfolgung von Zugriffszeiten

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` gibt an, ob die NTFS-Zeitstempel des letzten Zugriffs aktualisiert werden.
- Verwende zum Aktivieren: `fsutil behavior set disablelastaccess 0`

### Details zum Herunterfahren

- `SYSTEM\CurrentControlSet\Control\Windows`: Zeitpunkt des letzten Herunterfahrens.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: Ältere Systeme können zusätzlich Zähler für das Herunterfahren bereitstellen.

### Netzwerkkonfiguration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: Interface-IP-Adressen, DHCP-Leases, Gateway- und DNS-Daten.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: Name/SSID des Netzwerkprofils sowie Zeitpunkte der ersten und letzten Verbindung.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` und `...\Unmanaged\{GUID}`: Daten zur Profilzuordnung, etwa die MAC-Adresse des Gateways und das DNS-Suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: vom Host veröffentlichte lokale Freigabeordner.

### Remotezugriff und Verlauf von Netzwerkfreigaben

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: ausgehende RDP-MRU-Liste (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: Verlauf ausgehender RDP-Verbindungen pro Host. Unterschlüssel speichern häufig `UsernameHint`; der `LastWrite`-Zeitpunkt des Schlüssels ist ein nützlicher Ansatzpunkt.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: gemappte Netzlaufwerke, UNC-Freigaben und Einbindungspunkte für Wechselmedien, die einem bestimmten Benutzer zugeordnet sind.

### Automatisch startende Programme und geplante Persistenz

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` und `...\Tasks\{GUID}`: Metadaten geplanter Tasks. Wenn hier ein Task vorhanden ist, aber der Wert `SD` in `Tree\<TaskName>` fehlt, sollte eine versteckte, Tarrask-ähnliche Manipulation des Tasks vermutet und mit `C:\Windows\System32\Tasks\<TaskName>` abgeglichen werden.

### Suchen, eingegebene Pfade und MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: Suchbegriffe des File Explorers.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: manuell eingegebene Explorer-Pfade.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: die letzten 26 `Win + R`-Befehle. `MRUList` bewahrt deren Reihenfolge.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: kürzlich geöffnete Dokumente und Ordner.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: zuletzt verwendete Office-Dateien.

### Nachverfolgung von Benutzeraktivitäten

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: Ausführungshistorie, die über die GUI ausgelöst wurde. Wertnamen sind ROT13-kodiert, und die Binärdaten enthalten Ausführungszähler sowie den Zeitpunkt der letzten Ausführung.<sup>[[1]](#references)</sup>
- `UserAssist` sollte als starke unterstützende Evidenz und nicht als alleinige Grundlage für ein Urteil betrachtet werden: Es erfasst hauptsächlich über den Explorer gestartete Anwendungen oder `.lnk`-Dateien und kann Befehlszeilen- oder Service-Ausführungen übersehen. Unter Windows 10+ bedeuten einige Einträge nicht zwangsläufig, dass der Prozess vollständig ausgeführt wurde.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` und `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: moderne Ausführungsspuren unter Windows 10/11 mit SID-Zuordnung und Zeitpunkt der letzten Ausführung. Diese sind besonders für lokal ausgeführte Binärdateien nützlich, ältere Einträge können jedoch schnell entfernt werden, und Ausführungen von Netzwerkfreigaben oder Wechselmedien sind weniger zuverlässig.
- Für umfassendere Ausführungsartefakte wie Prefetch, Amcache, ShimCache und SRUM siehe die zentrale [Übersicht zur Windows-Forensik](README.md#programs-executed).

### Shellbags

- Shellbags werden sowohl in `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` als auch in `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` gespeichert.<sup>[[1]](#references)</sup>
- `NTUSER.DAT`-Einträge sind besonders für das Durchsuchen von UNC-/Netzwerkpfaden nützlich, während Windows Vista+ lokale Ordner und Ordner auf Wechselmedien üblicherweise in `UsrClass.dat` speichert.
- Sie können die Existenz und das Durchsuchen von Ordnern sowie Einstellungen der Ordneransicht anzeigen, selbst nachdem der Ordner gelöscht wurde. Ein Explorer-ähnlicher Zugriff auf Archivdateien kann ebenfalls Shellbag-Spuren hinterlassen.<sup>[[1]](#references)</sup>
- Nicht jedes Shellbag belegt einen erfolgreichen Ordnerzugriff. Daher sollte eine Bestätigung durch LNKs, Jump Lists, Zeitstempel oder Volume-Zuordnungen erfolgen.
- Verwende **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** oder **SBECmd**, um sie zu analysieren.

### USB-Informationen

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primäres Inventar von USB-Massenspeichergeräten (Hersteller, Produkt, Revision, Seriennummer/Geräteinstanz).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: umfassenderes USB-Geräteinventar, einschließlich Nicht-Speichergeräten.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: Bei aktuellen Windows-10/11-Builds ist dies eine wichtige Fundstelle für gerätespezifische Lebenszyklus-Zeitstempel wie Installation, Erstinstallation, letzte Verbindung und letzte Entfernung.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: ordnet Volumes und Gerätekennungen Laufwerksbuchstaben bzw. Volume-GUIDs zu. Nur die letzte Zuordnung für einen bestimmten Laufwerksbuchstaben kann erhalten bleiben.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: nützlicher Ansatzpunkt für Volume-Seriennummern und Metadaten früherer Medien.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: benutzerspezifischer Verlauf von Interaktionen mit Laufwerksbuchstaben und Freigaben.<sup>[[2]](#references)</sup>
- Moderne Telefone und Tablets, die über MTP/PTP verbunden werden, erscheinen möglicherweise **nicht** unter `USBSTOR`. Prüfe daher auch `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` und `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Um ein Gerät einem Benutzer zuzuordnen, sollte von Geräte- oder Volume-Kennungen zu benutzerspezifischen Artefakten wie Shellbags, LNKs, Jump Lists, `RecentDocs` und `MountPoints2` pivotiert werden.<sup>[[2]](#references)</sup>

## References

- [1] [Windows-Registry-Forensik-Spickzettel 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB-Geräteforensik unter Windows 10 und 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
