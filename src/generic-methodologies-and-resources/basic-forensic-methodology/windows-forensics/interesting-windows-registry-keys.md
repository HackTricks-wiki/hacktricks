# Interessante Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives sind eine der schnellsten Möglichkeiten, von _was ist passiert?_ zu _welcher User, wann und von wo?_ zu wechseln. Für Live-Analyse verwende `CurrentControlSet`; für Offline-Hive-Analyse löse zuerst auf, welches `ControlSet00x` aktiv war, statt `ControlSet001` hart zu codieren.

### Windows-Version und Owner-Info

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows-Edition/Build, Installationszeit, registrierter Owner, Product Name und andere Build-Metadaten.
- `SYSTEM\Select`: mappt `Current`, `Default` und `LastKnownGood` auf die echten `ControlSet00x`-Werte, die vom System verwendet werden.

### Computername

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: aktueller Hostname.

### Zeitzoneneinstellung

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: konfigurierte Zeitzone und DST-bezogene Werte.

### Access-Time-Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` zeigt an, ob NTFS Last-Access-Timestamps aktualisiert.
- Um es zu aktivieren, verwende: `fsutil behavior set disablelastaccess 0`

### Shutdown-Details

- `SYSTEM\CurrentControlSet\Control\Windows`: letzte Shutdown-Zeit.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: ältere Systeme können auch Shutdown-Counters offenlegen.

### Netzwerkkonfiguration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: Interface-IPs, DHCP-Leases, Gateway- und DNS-Daten.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: Netzwerkprofilname/SSID plus erste und letzte Verbindungszeit.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` und `...\Unmanaged\{GUID}`: Profil-Korrelationsdaten wie Gateway-MAC-Adresse und DNS-Suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: vom Host veröffentlichte lokale Freigaben.

### Remote Access und Netzwerkfreigaben-Historie

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: ausgehende RDP-MRU-Liste (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: ausgehende RDP-Historie pro Host. Subkeys speichern häufig `UsernameHint`, und die `LastWrite`-Zeit des Keys ist ein nützlicher Pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: gemappte Netzlaufwerke, UNC-Freigaben und Einhängepunkte für Wechseldatenträger, die an einen bestimmten User gebunden sind.

### Programme, die automatisch starten, und geplante Persistenz

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` und `...\Tasks\{GUID}`: Metadaten geplanter Tasks. Wenn ein Task hier existiert, aber der `SD`-Wert in `Tree\<TaskName>` fehlt, ist das ein Hinweis auf verstecktes Tarrask-artiges Task-Tampering; korreliere es mit `C:\Windows\System32\Tasks\<TaskName>`.

### Suchen, Typed Paths und MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: Suchbegriffe im File Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: manuell eingegebene Explorer-Pfade.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: die letzten 26 `Win + R`-Befehle. `MRUList` bewahrt ihre Reihenfolge.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: zuletzt geöffnete Dokumente und Ordner.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: zuletzt verwendete Office-Dateien.

### User-Aktivitäts-Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-basierte Ausführungshistorie. Wertnamen sind ROT13-codiert, und die Binärdaten enthalten Ausführungszähler und letzte Ausführungszeit.
- Betrachte `UserAssist` als starkes unterstützendes Indiz, nicht als alleinige Beweisgrundlage: Es verfolgt hauptsächlich Apps oder `.lnk`-Dateien, die über Explorer gestartet wurden, und kann Ausführungen per Kommandozeile oder Dienst übersehen. Unter Windows 10+ bedeuten einige Einträge nicht zwingend, dass der Prozess vollständig ausgeführt wurde.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` und `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: moderne Windows 10/11-Ausführungs-Trails mit SID-Zuordnung und letzter Ausführungszeit. Das ist besonders nützlich für lokal ausgeführte Binaries, aber ältere Einträge können schnell verschwinden, und Ausführungen von Netzwerkfreigaben/Wechseldatenträgern sind weniger zuverlässig.
- Für umfassendere Ausführungs-Artefakte wie Prefetch, Amcache, ShimCache und SRUM siehe die Haupt-[Windows forensics overview](README.md#programs-executed).

### Shellbags

- Shellbags werden sowohl in `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` als auch in `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` gespeichert.
- `NTUSER.DAT`-Einträge sind besonders nützlich für UNC-/Netzwerk-Browsing, während `UsrClass.dat` der Ort ist, an dem Windows Vista+ typischerweise lokale/Wechseldatenträger-Shellbags speichert.
- Sie können Ordnerexistenz, Traversal und Folder-View-Preferences selbst nach dem Löschen des Ordners zeigen. Explorer-ähnlicher Zugriff auf Archivdateien kann ebenfalls Shellbag-Spuren hinterlassen.
- Nicht jeder Shellbag beweist erfolgreichen Ordnerzugriff, also mit LNKs, Jump Lists, Timestamps oder Volume-Mappings korrelieren.
- Verwende **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** oder **SBECmd**, um sie zu parsen.

### USB-Informationen

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primäres Inventar von USB-Massenspeichergeräten (Vendor, Product, Revision, Serial/Device Instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: breiteres USB-Geräteinventar, einschließlich Nicht-Speichergeräten.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: auf aktuellen Windows 10/11-Builds ein hochrelevanter Ort für Lifecycle-Timestamps pro Gerät wie Install, First Install, Last Arrival und Last Removal.
- `HKLM\SYSTEM\MountedDevices`: mappt Volumes und Gerätekennungen auf Laufwerksbuchstaben / Volume-GUIDs. Nur die letzte Zuordnung für einen bestimmten Laufwerksbuchstaben kann erhalten bleiben.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: nützlicher Pivot für Volume-Seriennummern und frühere Medien-Metadaten.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: benutzerspezifische Historie von Laufwerksbuchstaben- und Share-Interaktionen.
- Moderne Telefone und Tablets, die über MTP/PTP verbunden sind, erscheinen möglicherweise **nicht** unter `USBSTOR`. Prüfe außerdem `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` und `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
- Um ein Gerät einem User zuzuordnen, pivotiere von Geräte- oder Volume-Kennungen zu benutzerspezifischen Artefakten wie shellbags, LNKs, Jump Lists, `RecentDocs` und `MountPoints2`.



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
