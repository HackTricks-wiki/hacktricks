# Interessante Windows-registersleutels

{{#include ../../../banners/hacktricks-training.md}}

Windows-registerkorwe is een van die vinnigste maniere om van _wat het gebeur?_ oor te skakel na _watter gebruiker, wanneer en van waar?_. Gebruik `CurrentControlSet` vir lewendige ontleding; bepaal eers watter `ControlSet00x` aktief was vir ontleding van vanlyn registerkorwe, eerder as om `ControlSet001` hard te kodeer.

### Windows-weergawe en eienaarsinligting

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows-uitgawe/bouweergawe, installasietyd, geregistreerde eienaar, produknaam en ander boumetadata.
- `SYSTEM\Select`: koppel `Current`, `Default` en `LastKnownGood` aan die werklike `ControlSet00x`-waardes wat deur die stelsel gebruik word.

### Rekenaarnaam

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: huidige gasheernaam.

### Tydsone-instelling

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: gekonfigureerde tydsone en waardes wat met DST verband hou.

### Nasporing van toegangstye

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` dui aan of NTFS se laaste-toegang-tydstempels bygewerk word.
- Gebruik die volgende om dit te aktiveer: `fsutil behavior set disablelastaccess 0`

### Afsluitbesonderhede

- `SYSTEM\CurrentControlSet\Control\Windows`: laaste afsluittyd.
- Ouer stelsels kan ook afsluit-tellers blootstel by `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Netwerkkonfigurasie

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: koppelvlak-IP's, DHCP-huurtydperke, poort- en DNS-data.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: netwerkprofielnaam/SSID plus eerste en laaste verbindingstye.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` en `...\Unmanaged\{GUID}`: profielkorrelasiedata, soos die poort se MAC-adres en DNS-agtervoegsel.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: plaaslike gedeelde vouers wat deur die gasheer gepubliseer word.

### Geskiedenis van afstandtoegang en netwerkaandele

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: uitgaande RDP-MRU-lys (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: uitgaande RDP-geskiedenis per gasheer. Subsleutels stoor gewoonlik `UsernameHint`, en die sleutel se `LastWrite`-tyd is 'n nuttige pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: gekarteerde netwerkaandrywers, UNC-aandele en monteerpunte vir verwyderbare media wat aan 'n spesifieke gebruiker gekoppel is.

### Programme wat outomaties begin en geskeduleerde volharding

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` en `...\Tasks\{GUID}`: metadata van geskeduleerde take. As 'n taak hier bestaan maar die `SD`-waarde by `Tree\<TaskName>` ontbreek, vermoed verberging van take soortgelyk aan Tarrask en korreleer dit met `C:\Windows\System32\Tasks\<TaskName>`.

### Soektogte, ingetikte paaie en MRU's

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer-soekterme.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer-paaie wat met die hand ingetik is.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: die laaste 26 `Win + R`-opdragte. `MRUList` behou hul volgorde.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: dokumente en vouers wat onlangs oopgemaak is.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office-lêers wat onlangs oopgemaak is.

### Nasporing van gebruikersaktiwiteit

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: uitvoeringsgeskiedenis van aktiwiteit deur die GUI. Waardename is met ROT13 geënkodeer, en die binêre data bevat uitvoertellers en die laaste uitvoeringstyd.<sup>[[1]](#references)</sup>
- Beskou `UserAssist` as sterk ondersteunende bewyse, nie as 'n alleenstaande gevolgtrekking nie: dit spoor hoofsaaklik programme of `.lnk`-lêers na wat deur Explorer geloods word en kan uitvoering via die opdragreël of dienste miskyk. Op Windows 10 en nuwer beteken sommige inskrywings nie noodwendig dat die proses ten volle uitgevoer is nie.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` en `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: uitvoeringsporing in moderne Windows 10/11 met SID-toeskrywing en die laaste uitvoeringstyd. Dit is veral nuttig vir binêre lêers wat plaaslik uitgevoer is, maar ouer inskrywings kan vinnig verval en uitvoerings vanaf netwerkaandele/verwyderbare media is minder betroubaar.
- Sien die hoof-[Windows-forensiese oorsig](./#programs-executed) vir breër uitvoeringsartefakte soos Prefetch, Amcache, ShimCache en SRUM.

### Shellbags

- Shellbags word in beide `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` en `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` gestoor.<sup>[[1]](#references)</sup>
- `NTUSER.DAT`-inskrywings is veral nuttig vir UNC-/netwerkblaai, terwyl Windows Vista en nuwer gewoonlik plaaslike/verwyderbare vouer-shellbags in `UsrClass.dat` stoor.
- Hulle kan wys dat 'n vouer bestaan het, dat daardeur geblaai is en wat die voueraansigvoorkeure was, selfs nadat die vouer uitgevee is. Toegang tot argieflêers via Explorer-agtige programme kan ook shellbag-spore laat.<sup>[[1]](#references)</sup>
- Nie elke shellbag bewys dat 'n vouer suksesvol besoek is nie; bevestig dit dus met LNK's, Jump Lists, tydstempels of volumekarterings.
- Gebruik **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** of **SBECmd** om hulle te ontleed.

### USB-inligting

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primêre inventaris van USB-massabergingstoestelle (vervaardiger, produk, hersiening, reeksnommer/toestelinstansie).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: breër inventaris van USB-toestelle, insluitend toestelle wat nie bergingstoestelle is nie.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: op onlangse Windows 10/11-bouweergawes is dit 'n waardevolle plek vir lewensiklustydstempels per toestel, soos installasie, eerste installasie, laaste aansluiting en laaste verwydering.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: koppel volumes en toestelidentifiseerders aan skyfletters/volume-GUID's. Slegs die laaste kartering vir 'n gegewe skyfletter sal dalk behoue bly.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: 'n nuttige pivot vir volumesereeksnommers en vorige mediadata.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: gebruikerspesifieke geskiedenis van interaksie met skyfletters en aandele.<sup>[[2]](#references)</sup>
- Moderne fone en tablette wat via MTP/PTP gekoppel is, verskyn **dalk nie** onder `USBSTOR` nie. Gaan ook `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` en `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` na.<sup>[[2]](#references)</sup>
- Om 'n toestel aan 'n gebruiker te koppel, volg toestel- of volume-identifiseerders na artefakte per gebruiker, soos shellbags, LNK's, Jump Lists, `RecentDocs` en `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Bedrogblad vir Windows-registerforensika 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB-toestelforensika op Windows 10 en 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
