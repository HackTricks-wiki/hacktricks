# Interessante Windows-Registry-Schlüssel

{{#include ../../../banners/hacktricks-training.md}}

Windows-Registry-Hives gehören zu den schnellsten Möglichkeiten, von _was ist passiert?_ zu _welcher Benutzer, wann und von wo?_ zu gelangen. Für die Live-Analyse sollte `CurrentControlSet` bevorzugt werden. Bei der Offline-Hive-Analyse muss zuerst ermittelt werden, welches `ControlSet00x` aktiv war, anstatt `ControlSet001` fest zu codieren.

### Windows-Version und Besitzerinformationen

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows-Edition/-Build, Installationszeit, registrierter Besitzer, Produktname und weitere Build-Metadaten.
- `SYSTEM\Select`: ordnet `Current`, `Default` und `LastKnownGood` den tatsächlichen, vom System verwendeten `ControlSet00x`-Werten zu.

### Computername

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: aktueller Hostname.

### Zeitzoneneinstellung

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: konfigurierte Zeitzone und Werte im Zusammenhang mit der Sommerzeit.

### Erfassung von Zugriffszeiten

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` gibt an, ob die NTFS-Zeitstempel für den letzten Zugriff aktualisiert werden.
- Zum Aktivieren: `fsutil behavior set disablelastaccess 0`

### Details zum Herunterfahren

- `SYSTEM\CurrentControlSet\Control\Windows`: Zeitpunkt des letzten Herunterfahrens.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: Ältere Systeme können zusätzlich Zähler für das Herunterfahren enthalten.

### Netzwerkkonfiguration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IPs der Schnittstelle, DHCP-Leases sowie Gateway- und DNS-Daten.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: Name/SSID des Netzwerkprofils sowie Zeitpunkte der ersten und letzten Verbindung.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` und `...\Unmanaged\{GUID}`: Korrelationsdaten des Profils, etwa die MAC-Adresse des Gateways und das DNS-Suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: vom Host veröffentlichte lokale Freigabeordner.

### Remotezugriff und Verlauf von Netzwerkfreigaben

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: ausgehende RDP-MRU-Liste (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: Verlauf ausgehender RDP-Verbindungen pro Host. Unterschlüssel enthalten häufig `UsernameHint`; der Zeitpunkt von `LastWrite` ist ein nützlicher Anhaltspunkt.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: zu einem bestimmten Benutzer gehörende gemappte Netzlaufwerke, UNC-Freigaben und Einbindungspunkte für Wechselmedien.

### Automatisch gestartete Programme und geplante Persistenz

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` und `...\Tasks\{GUID}`: Metadaten geplanter Tasks. Wenn hier ein Task vorhanden ist, aber der Wert `SD` unter `Tree\<TaskName>` fehlt, sollte eine versteckte, Tarrask-ähnliche Manipulation des Tasks vermutet und mit `C:\Windows\System32\Tasks\<TaskName>` korreliert werden.

### Suchen, eingegebene Pfade und MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: Suchbegriffe des File Explorers.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: manuell eingegebene Explorer-Pfade.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: die letzten 26 `Win + R`-Befehle. `MRUList` bewahrt ihre Reihenfolge.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: kürzlich geöffnete Dokumente und Ordner.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: zuletzt verwendete Office-Dateien.

### Erfassung von Benutzeraktivitäten

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: durch die GUI ausgelöster Ausführungsverlauf. Wertnamen sind ROT13-codiert, und die Binärdaten enthalten Ausführungszähler sowie den Zeitpunkt der letzten Ausführung.<sup>[[1]](#references)</sup>
- `UserAssist` sollte als starker unterstützender Beleg und nicht als alleinige Bewertung betrachtet werden: Es erfasst hauptsächlich über den Explorer gestartete Apps oder `.lnk`-Dateien und kann Befehlszeilen- oder Dienstausführungen übersehen. Unter Windows 10+ bedeuten manche Einträge nicht zwangsläufig, dass der Prozess vollständig ausgeführt wurde.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` und `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: moderne Ausführungsspuren von Windows 10/11 mit SID-Zuordnung und Zeitpunkt der letzten Ausführung. Diese sind besonders für lokal ausgeführte Binärdateien nützlich, ältere Einträge können jedoch schnell entfernt werden, und Ausführungen von Netzwerkfreigaben/Wechselmedien sind weniger zuverlässig.
- Für umfassendere Ausführungsartefakte wie Prefetch, Amcache, ShimCache und SRUM siehe die zentrale [Übersicht zur Windows-Forensik](README.md#programs-executed).

### Shellbags

- Shellbags werden sowohl in `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` als auch in `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` gespeichert.<sup>[[1]](#references)</sup>
- `NTUSER.DAT`-Einträge sind besonders für das Durchsuchen von UNC-/Netzwerkpfaden nützlich, während Windows Vista+ lokale Ordner und Ordner auf Wechselmedien üblicherweise in `UsrClass.dat` speichert.
- Sie können die Existenz und Navigation in Ordnern sowie Einstellungen der Ordneransicht anzeigen, selbst nachdem der Ordner gelöscht wurde. Ein Explorer-ähnlicher Zugriff auf Archivdateien kann ebenfalls Shellbag-Spuren hinterlassen.<sup>[[1]](#references)</sup>
- Nicht jeder Shellbag belegt einen erfolgreichen Ordnerzugriff. Daher sollte er mit LNKs, Jump Lists, Zeitstempeln oder Volume-Zuordnungen corroboriert werden.
- Verwende **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** oder **SBECmd**, um sie zu analysieren.

### USB-Informationen

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primäres Inventar von USB-Massenspeichergeräten (Hersteller, Produkt, Revision, Seriennummer/Geräteinstanz).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: umfassenderes USB-Geräteinventar, einschließlich Geräten ohne Speicherfunktion.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: In aktuellen Windows-10/11-Builds ist dies eine wichtige Stelle für Lebenszyklus-Zeitstempel pro Gerät, etwa Installation, Erstinstallation, letztes Anschließen und letztes Entfernen.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: ordnet Volumes und Gerätekennungen Laufwerksbuchstaben/Volume-GUIDs zu. Möglicherweise bleibt nur die letzte Zuordnung für einen bestimmten Laufwerksbuchstaben erhalten.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: nützlicher Anhaltspunkt für Volume-Seriennummern und Metadaten früherer Medien.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: benutzerspezifischer Verlauf der Interaktion mit Laufwerksbuchstaben und Freigaben.<sup>[[2]](#references)</sup>
- Moderne, über MTP/PTP verbundene Smartphones und Tablets erscheinen möglicherweise **nicht** unter `USBSTOR`. Prüfe auch `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` und `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Um ein Gerät einem Benutzer zuzuordnen, sollte von Geräte- oder Volume-Kennungen zu benutzerspezifischen Artefakten wie Shellbags, LNKs, Jump Lists, `RecentDocs` und `MountPoints2` pivotiert werden.<sup>[[2]](#references)</sup>

## Referenzen

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
