# Interessante Windows Registry-sleutels

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry-hives is een van die vinnigste maniere om van _wat het gebeur?_ na _watter gebruiker, wanneer en van waar?_ te beweeg. Verkies `CurrentControlSet` vir lewendige ontleding; los eers vir offline hive-ontleding op watter `ControlSet00x` aktief was, eerder as om `ControlSet001` hard te kodeer.

### Windows-weergawe en eienaarinligting

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows-uitgawe/-build, installasietyd, geregistreerde eienaar, produknaam en ander build-metadata.
- `SYSTEM\Select`: koppel `Current`, `Default` en `LastKnownGood` aan die werklike `ControlSet00x`-waardes wat deur die stelsel gebruik word.

### Rekenaarnaam

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: huidige hostname.

### Tydsone-instelling

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: gekonfigureerde tydsone en DST-verwante waardes.

### Nasporing van toegangstye

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` dui aan of NTFS se laaste-toegang-tydstempels opgedateer word.
- Om dit te aktiveer, gebruik: `fsutil behavior set disablelastaccess 0`

### Afsluitingsbesonderhede

- `SYSTEM\CurrentControlSet\Control\Windows`: tyd van die laaste afsluiting.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: ouer stelsels kan ook afsluitingstellers blootstel.

### Netwerkkonfigurasie

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: koppelvlak-IP's, DHCP-leases, gateway- en DNS-data.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: netwerkprofielnaam/SSID plus eerste en laaste verbindingstye.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` en `...\Unmanaged\{GUID}`: profielkorrelasiedata soos gateway-MAC-adres en DNS-agtervoegsel.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: plaaslike gedeelde vouers wat deur die host gepubliseer word.

### Afstandtoegang en geskiedenis van netwerkdelings

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: uitgaande RDP MRU-lys (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: uitgaande RDP-geskiedenis per host. Subsleutels stoor gewoonlik `UsernameHint`, en die sleutel se `LastWrite`-tyd is 'n nuttige pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: gekarteerde netwerkaandrywers, UNC-delings en monteringspunte vir verwyderbare media wat aan 'n spesifieke gebruiker gekoppel is.

### Programme wat outomaties begin en geskeduleerde persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` en `...\Tasks\{GUID}`: metadata van geskeduleerde take. As 'n taak hier bestaan, maar die `SD`-waarde in `Tree\<TaskName>` ontbreek, vermoed versteekte Tarrask-styl taammanipulasie en korreleer dit met `C:\Windows\System32\Tasks\<TaskName>`.

### Soektogte, getikte paaie en MRU's

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer-soekterme.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer-paaie wat handmatig getik is.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: die laaste 26 `Win + R`-opdragte. `MRUList` behou hul volgorde.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: dokumente en vouers wat onlangs oopgemaak is.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: onlangse Office-lêers.

### Nasporing van gebruikersaktiwiteit

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-gedrewe uitvoergeskiedenis. Waardename is ROT13-geënkodeer, en die binêre data bevat uitvoertellers en die laaste uitvoeringstyd.<sup>[[1]](#references)</sup>
- Behandel `UserAssist` as sterk ondersteunende bewyse, nie as 'n selfstandige uitspraak nie: dit volg hoofsaaklik toepassings of `.lnk`-lêers wat deur Explorer geloods is en kan command-line- of diensuitvoering mis. Op Windows 10+ beteken sommige inskrywings nie noodwendig dat die proses volledig uitgevoer is nie.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` en `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: moderne Windows 10/11-uitvoerspore met SID-toeskrywing en laaste uitvoeringstyd. Dit is veral nuttig vir binaries wat plaaslik uitgevoer is, maar ouer inskrywings kan vinnig verouder en uitvoerings vanaf netwerkdelings/verwyderbare media is minder betroubaar.
- Vir breër uitvoerartefakte soos Prefetch, Amcache, ShimCache en SRUM, sien die hoof-[Windows forensics overview](README.md#programs-executed).

### Shellbags

- Shellbags word in beide `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` en `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` gestoor.<sup>[[1]](#references)</sup>
- `NTUSER.DAT`-inskrywings is veral nuttig vir UNC-/netwerkblaai, terwyl `UsrClass.dat` is waar Windows Vista+ gewoonlik plaaslike/verwyderbare-vouer-shellbags stoor.
- Hulle kan die bestaan, deurkruising en voueraansigvoorkeure van vouers wys, selfs nadat die vouer uitgevee is. Explorer-agtige toegang tot argieflêers kan ook shellbag-spore laat.<sup>[[1]](#references)</sup>
- Nie elke shellbag bewys suksesvolle vouertoegang nie, dus moet dit met LNK's, Jump Lists, tydstempels of volume-karterings gestaaf word.
- Gebruik **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** of **SBECmd** om hulle te ontleed.

### USB-inligting

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primêre inventaris van USB-massastoor-toestelle (vervaardiger, produk, hersiening, reeks-/toestelinstansie).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: breër USB-toestelinventaris, insluitend nie-stoortoestelle.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: op onlangse Windows 10/11-builds is dit 'n waardevolle plek vir toestelspesifieke lewensiklustydstempels soos installering, eerste installering, laaste aankoms en laaste verwydering.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: koppel volumes en toestelidentifiseerders aan aandrywerletters / volume-GUID's. Slegs die laaste kartering vir 'n gegewe aandrywerletter kan behoue bly.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: nuttige pivot vir volumenommers en metadata van vorige media.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: gebruikerspesifieke geskiedenis van aandrywerletter- en deelinteraksie.<sup>[[2]](#references)</sup>
- Moderne fone en tablette wat via MTP/PTP gekoppel is, verskyn moontlik **nie** onder `USBSTOR` nie. Kontroleer ook `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` en `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Om 'n toestel aan 'n gebruiker te koppel, pivot vanaf toestel- of volume-identifiseerders na per-gebruiker-artefakte soos shellbags, LNK's, Jump Lists, `RecentDocs` en `MountPoints2`.<sup>[[2]](#references)</sup>

## Verwysings

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
