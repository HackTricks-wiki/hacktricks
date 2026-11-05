# Interessante Windows-Registry-Schlüssel

{{#include ../../../banners/hacktricks-training.md}}

Windows-Registry-Hives sind eine der schnellsten Möglichkeiten, von _Was ist passiert?_ zu _welcher Benutzer, wann und von wo?_ zu gelangen. Bevorzuge bei Live-Analysen `CurrentControlSet`; bei der Offline-Analyse von Hives ermittle zuerst, welches `ControlSet00x` aktiv war, anstatt `ControlSet001` fest zu verwenden.

### Windows-Version und Besitzerinformationen

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows-Edition/-Build, Installationszeitpunkt, registrierter Besitzer, Produktname und weitere Build-Metadaten.
- `SYSTEM\Select`: Ordnet `Current`, `Default` und `LastKnownGood` den tatsächlichen `ControlSet00x`-Werten zu, die vom System verwendet werden.

### Computername

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: aktueller Hostname.

### Zeitzoneneinstellung

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: konfigurierte Zeitzone und Werte im Zusammenhang mit der Sommerzeit.

### Nachverfolgung von Zugriffszeiten

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` gibt an, ob die NTFS-Zeitstempel des letzten Zugriffs aktualisiert werden.
- Zum Aktivieren folgenden Befehl verwenden: `fsutil behavior set disablelastaccess 0`

### Details zum Herunterfahren

- `SYSTEM\CurrentControlSet\Control\Windows`: Zeitpunkt des letzten Herunterfahrens.
- Ältere Systeme können außerdem unter `SYSTEM\CurrentControlSet\Control\Watchdog\Display` Zähler für das Herunterfahren enthalten.

### Netzwerkkonfiguration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: Schnittstellen-IPs, DHCP-Leases sowie Gateway- und DNS-Daten.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: Name des Netzwerkprofils/SSID sowie erste und letzte Verbindungszeit.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` und `...\Unmanaged\{GUID}`: Daten zur Profilzuordnung, etwa die MAC-Adresse des Gateways und das DNS-Suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: lokale freigegebene Ordner, die vom Host bereitgestellt werden.

### Remotezugriff und Verlauf von Netzwerkfreigaben

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: ausgehende RDP-MRU-Liste (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: Verlauf ausgehender RDP-Verbindungen pro Host. Unterschlüssel enthalten häufig `UsernameHint`; der `LastWrite`-Zeitpunkt des Schlüssels ist ein nützlicher Anhaltspunkt.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: zu einem bestimmten Benutzer gehörende Netzlaufwerke, UNC-Freigaben und Einbindungspunkte für Wechseldatenträger.

### Automatisch startende Programme und geplante Persistenz

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` und `...\Tasks\{GUID}`: Metadaten geplanter Tasks. Falls hier ein Task vorhanden ist, aber der Wert `SD` unter `Tree\<TaskName>` fehlt, ist eine Task-Manipulation im Stil von Tarrask zu vermuten. Gleiche den Befund mit `C:\Windows\System32\Tasks\<TaskName>` ab.

### Suchbegriffe, eingegebene Pfade und MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: Suchbegriffe im Datei-Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: manuell im Explorer eingegebene Pfade.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: die letzten 26 `Win + R`-Befehle. `MRUList` bewahrt ihre Reihenfolge.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: kürzlich geöffnete Dokumente und Ordner.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: zuletzt verwendete Office-Dateien.

### Nachverfolgung von Benutzeraktivitäten

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: Ausführungsverlauf über die GUI. Wertnamen sind ROT13-kodiert; die Binärdaten enthalten Ausführungszähler und den Zeitpunkt der letzten Ausführung.<sup>[[1]](#references)</sup>
- Betrachte `UserAssist` als starkes unterstützendes Indiz, nicht als alleinigen Beweis: Es erfasst hauptsächlich Apps oder `.lnk`-Dateien, die über den Explorer gestartet wurden, und kann Befehlszeilen- oder Dienstausführungen übersehen. Unter Windows 10 und neuer bedeuten manche Einträge nicht zwangsläufig, dass der Prozess vollständig ausgeführt wurde.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` und `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: Ausführungsspuren unter modernen Windows-10/11-Versionen mit SID-Zuordnung und Zeitpunkt der letzten Ausführung. Diese sind besonders hilfreich bei lokal ausgeführten Binärdateien; ältere Einträge können jedoch schnell verfallen, und Ausführungen von Netzwerkfreigaben/Wechseldatenträgern sind weniger zuverlässig.
- Weitere Ausführungsartefakte wie Prefetch, Amcache, ShimCache und SRUM findest du in der [Übersicht zur Windows-Forensik](./#programs-executed).

### Shellbags

- Shellbags werden sowohl in `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` als auch in `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` gespeichert.<sup>[[1]](#references)</sup>
- Einträge in `NTUSER.DAT` sind besonders hilfreich bei der Navigation in UNC-/Netzwerkpfaden, während Windows Vista und neuere Versionen lokale Shellbags und Shellbags für Wechseldatenträger üblicherweise in `UsrClass.dat` speichern.
- Sie können die Existenz und Navigation in Ordnern sowie Ordneransichtseinstellungen belegen, auch nachdem der Ordner gelöscht wurde. Der Zugriff über den Explorer auf Archivdateien kann ebenfalls Shellbag-Spuren hinterlassen.<sup>[[1]](#references)</sup>
- Nicht jede Shellbag belegt einen erfolgreichen Ordnerzugriff. Gleiche sie daher mit LNKs, Jump Lists, Zeitstempeln oder Volume-Zuordnungen ab.
- Verwende **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** oder **SBECmd**, um sie auszuwerten.

### USB-Informationen

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primäres Inventar von USB-Massenspeichergeräten (Hersteller, Produkt, Revision, Seriennummer/Geräteinstanz).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: umfangreicheres USB-Geräteinventar, auch mit Geräten ohne Speicherfunktion.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: Bei neueren Windows-10/11-Builds ist dies eine wichtige Fundstelle für Lebenszyklus-Zeitstempel einzelner Geräte, etwa Installation, Erstinstallation, letztes Anschließen und letztes Entfernen.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: Ordnet Volumes und Gerätekennungen Laufwerksbuchstaben/Volume-GUIDs zu. Für einen bestimmten Laufwerksbuchstaben bleibt möglicherweise nur die letzte Zuordnung erhalten.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: nützlicher Anhaltspunkt für Volume-Seriennummern und Metadaten früherer Datenträger.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: benutzerspezifischer Verlauf zu Laufwerksbuchstaben und Netzwerkfreigaben.<sup>[[2]](#references)</sup>
- Moderne Smartphones und Tablets, die über MTP/PTP verbunden werden, erscheinen möglicherweise **nicht** unter `USBSTOR`. Prüfe auch `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` und `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Um ein Gerät einem Benutzer zuzuordnen, verfolge Geräte- oder Volume-Kennungen bis zu benutzerspezifischen Artefakten wie Shellbags, LNKs, Jump Lists, `RecentDocs` und `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Cheat Sheet zur Windows-Registry-Forensik 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB-Geräteforensik unter Windows 10 und 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
