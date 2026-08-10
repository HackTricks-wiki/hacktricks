# Interessante Windows Registry-sleutels

Windows Registry-hives is een van die vinnigste maniere om van _wat het gebeur?_ na _watter gebruiker, wanneer, en van waar af?_ te beweeg. Vir lewendige ontleding, verkies `CurrentControlSet`; vir vanlyn hive-ontleding, bepaal eers watter `ControlSet00x` aktief was, eerder as om `ControlSet001` hard te kodeer.

### Windows-weergawe en eienaarinligting

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows-uitgawe/bou, installasietyd, geregistreerde eienaar, produknaam en ander boumetadata.
- `SYSTEM\Select`: koppel `Current`, `Default` en `LastKnownGood` aan die werklike `ControlSet00x`-waardes wat deur die stelsel gebruik word.

### Rekenaarnaam

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: huidige gasheernaam.

### Tydsone-instelling

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: gekonfigureerde tydsone en DST-verwante waardes.

### Nasporing van toegangstye

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` dui aan of NTFS-laaste-toegangtydstempels opgedateer word.
- Om dit te aktiveer, gebruik: `fsutil behavior set disablelastaccess 0`

### Afsluitbesonderhede

- `SYSTEM\CurrentControlSet\Control\Windows`: laaste afsluitingstyd.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: ouer stelsels kan ook afsluitingstellers blootstel.

### Netwerkkonfigurasie

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: koppelvlak-IP’s, DHCP-leases, gateway- en DNS-data.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: netwerkprofielnaam/SSID plus eerste en laaste verbindingstye.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` en `...\Unmanaged\{GUID}`: profielkorrelasie-data soos gateway-MAC-adres en DNS-agtervoegsel.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: plaaslike gedeelde vouers wat deur die gasheer gepubliseer word.

### Afstandtoegang en geskiedenis van netwerkdelings

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: uitgaande RDP-MRU-lys (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: uitgaande RDP-geskiedenis per gasheer. Subsleutels stoor gewoonlik `UsernameHint`, en die sleutel se `LastWrite`-tyd is ’n nuttige pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: gekarteerde netwerkdrywe, UNC-delings en verwyderbare-media-koppelpunte wat aan ’n spesifieke gebruiker gekoppel is.

### Programme wat outomaties begin en geskeduleerde persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` en `...\Tasks\{GUID}`: metadata van geskeduleerde take. Indien ’n taak hier bestaan maar die `SD`-waarde uit `Tree\<TaskName>` ontbreek, vermoed versteekte Tarrask-styl-taakmanipulasie en korreleer dit met `C:\Windows\System32\Tasks\<TaskName>`.

### Soektogte, ingetikte paaie en MRU’s

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer-soekterme.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: paaie wat handmatig in Explorer ingetik is.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: die laaste 26 `Win + R`-opdragte. `MRUList` behou hul volgorde.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: dokumente en vouers wat onlangs oopgemaak is.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: onlangse Office-lêers.

### Nasporing van gebruikersaktiwiteit

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-gedrewe uitvoeringsgeskiedenis. Waardename is ROT13-geënkodeer, en die binêre data bevat lopertellers en laaste looptyd.<sup>[[1]](#references)</sup>
- Behandel `UserAssist` as sterk ondersteunende bewys, nie as ’n selfstandige uitspraak nie: dit volg hoofsaaklik toepassings of `.lnk`-lêers wat deur Explorer geloods is en kan opdragreël- of diensuitvoering mis. Op Windows 10+ beteken sommige inskrywings nie noodwendig dat die proses volledig geloop het nie.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` en `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: moderne Windows 10/11-uitvoeringspore met SID-toeskrywing en laaste uitvoeringstyd. Dit is veral nuttig vir plaaslik uitgevoerde binaries, maar ouer inskrywings kan vinnig verouder, en uitvoerings vanaf netwerkdelings/verwyderbare media is minder betroubaar.
- Vir breër uitvoeringsartefakte soos Prefetch, Amcache, ShimCache en SRUM, sien die hoof-[Windows forensics-oorsig](README.md#programs-executed).

### Shellbags

- Shellbags word in beide `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` en `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` gestoor.<sup>[[1]](#references)</sup>
- `NTUSER.DAT`-inskrywings is veral nuttig vir UNC-/netwerkblaai, terwyl `UsrClass.dat` is waar Windows Vista+ gewoonlik plaaslike/verwyderbare-vouer-shellbags stoor.
- Hulle kan vouerbestaan, navigasie en voueraansig-voorkeure toon, selfs nadat die vouer uitgevee is. Explorer-agtige toegang tot argieflêers kan ook shellbag-spore laat.<sup>[[1]](#references)</sup>
- Nie elke shellbag bewys suksesvolle vouertoegang nie, dus bevestig dit met LNK’s, Jump Lists, tydstempels of volumekarterings.
- Gebruik **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** of **SBECmd** om hulle te ontleed.

### USB-inligting

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primêre inventaris van USB-massastoor-toestelle (verskaffer, produk, hersiening, reeksnommer/toestelinstansie).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: breër USB-toestelinventaris, insluitend nie-bergingstoestelle.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: op onlangse Windows 10/11-bouweergawes is dit ’n waardevolle plek vir lewensiklustydstempels per toestel, soos installering, eerste installering, laaste aankoms en laaste verwydering.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: koppel volumes en toestelidentifiseerders aan dryfletters / volume-GUID’s. Slegs die laaste kartering vir ’n gegewe dryfletter kan behoue bly.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: ’n nuttige pivot vir volumereeksnommers en vorige mediadata.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: gebruikerspesifieke geskiedenis van dryfletter- en deelinteraksies.<sup>[[2]](#references)</sup>
- Moderne fone en tablette wat via MTP/PTP gekoppel is, verskyn moontlik **nie** onder `USBSTOR` nie. Kontroleer ook `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` en `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Om ’n toestel aan ’n gebruiker te koppel, pivot vanaf toestel- of volume-identifiseerders na per-gebruiker-artefakte soos shellbags, LNK’s, Jump Lists, `RecentDocs` en `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
