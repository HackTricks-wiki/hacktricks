# Interesting Windows Registry Keys

Windows Registry hives ni mojawapo ya njia za haraka zaidi za kutoka _nini kilitokea?_ hadi _ni mtumiaji gani, lini, na kutoka wapi?_. Kwa uchanganuzi wa live, pendelea `CurrentControlSet`; kwa uchanganuzi wa hive iliyo nje ya mfumo, kwanza tambua ni `ControlSet00x` ipi iliyokuwa active badala ya kuweka `ControlSet001` moja kwa moja.

### Taarifa za Toleo la Windows na Mmiliki

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edition/build ya Windows, muda wa usakinishaji, mmiliki aliyesajiliwa, jina la product, na metadata nyingine za build.
- `SYSTEM\Select`: huunganisha `Current`, `Default`, na `LastKnownGood` na thamani halisi za `ControlSet00x` zilizotumiwa na mfumo.

### Jina la Computer

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname ya sasa.

### Mpangilio wa Time Zone

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: time zone iliyosanidiwa na thamani zinazohusiana na DST.

### Ufuatiliaji wa Access Time

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` huonyesha ikiwa timestamps za last-access za NTFS zinasasishwa.
- Kuiwezesha, tumia: `fsutil behavior set disablelastaccess 0`

### Maelezo ya Shutdown

- `SYSTEM\CurrentControlSet\Control\Windows`: muda wa shutdown wa mwisho.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: mifumo ya zamani inaweza pia kuonyesha counters za shutdown.

### Usanidi wa Network

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP za interface, DHCP leases, gateway na data ya DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: jina la network profile/SSID pamoja na nyakati za muunganisho wa kwanza na wa mwisho.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` na `...\Unmanaged\{GUID}`: data ya kuhusisha profile, kama vile gateway MAC address na DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: folders za local zilizoshirikiwa na kuchapishwa na host.

### Remote Access na Historia ya Network Share

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: orodha ya outbound RDP MRU (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historia ya outbound RDP kwa kila host. Subkeys kwa kawaida huhifadhi `UsernameHint`, na muda wa `LastWrite` wa key ni pivot muhimu.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapped network drives, UNC shares, na mount points za removable media zinazohusishwa na user maalum.

### Programs Zinazoanza Automatically na Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` na `...\Tasks\{GUID}`: metadata ya scheduled task. Ikiwa task ipo hapa lakini value ya `SD` haipo kwenye `Tree\<TaskName>`, shuku task tampering ya aina ya Tarrask na ihusishe na `C:\Windows\System32\Tasks\<TaskName>`.

### Searches, Typed Paths, na MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: search terms za File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: paths za Explorer zilizoandikwa manually.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: commands 26 za mwisho za `Win + R`. `MRUList` huhifadhi mpangilio wake.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documents na folders zilizofunguliwa hivi karibuni.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: files za hivi karibuni za Office.

### Ufuatiliaji wa Shughuli za User

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historia ya execution iliyoanzishwa kupitia GUI. Majina ya values yame-encode kwa ROT13, na binary data ina run counters pamoja na muda wa mwisho wa run.<sup>[[1]](#references)</sup>
- Chukulia `UserAssist` kama ushahidi thabiti wa kusaidia, si hitimisho la pekee: hasa hufuatilia apps au files za `.lnk` zilizoanzishwa kupitia Explorer na inaweza kukosa execution ya command-line au service. Kwenye Windows 10+, baadhi ya entries si lazima zimaanishe kuwa process ili-run kikamilifu.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` na `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: execution traces za kisasa za Windows 10/11 zenye SID attribution na muda wa mwisho wa execution. Hizi ni muhimu hasa kwa binaries zilizotekelezwa locally, lakini entries za zamani zinaweza kuondolewa haraka na executions kutoka network shares/removable media si za kuaminika sana.
- Kwa execution artifacts pana zaidi kama Prefetch, Amcache, ShimCache, na SRUM, angalia [muhtasari mkuu wa Windows forensics](README.md#programs-executed).

### Shellbags

- Shellbags huhifadhiwa katika `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` na `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Entries za `NTUSER.DAT` ni muhimu hasa kwa ku-browse UNC/network, huku `UsrClass.dat` ikiwa mahali ambapo Windows Vista+ kwa kawaida huhifadhi shellbags za folders za local/removable.
- Zinaweza kuonyesha uwepo wa folder, traversal, na mapendeleo ya folder-view hata baada ya folder kufutwa. Access inayofanana na Explorer kwa archive files pia inaweza kuacha shellbag traces.<sup>[[1]](#references)</sup>
- Si kila shellbag inathibitisha access iliyofanikiwa ya folder, kwa hiyo ithibitishe kwa LNKs, Jump Lists, timestamps, au volume mappings.
- Tumia **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** au **SBECmd** kuziparse.

### Taarifa za USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventory kuu ya USB mass-storage devices (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventory pana ya USB devices, ikijumuisha devices zisizo za storage.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: kwenye builds za hivi karibuni za Windows 10/11, hapa kuna taarifa muhimu za lifecycle timestamps kwa kila device, kama install, first install, last arrival, na last removal.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: huunganisha volumes na device identifiers na drive letters / volume GUIDs. Mapping ya mwisho pekee ya drive letter fulani inaweza kubaki.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivot muhimu kwa volume serial numbers na metadata ya awali ya media.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historia ya interaction ya drive-letter na share kwa user maalum.<sup>[[2]](#references)</sup>
- Simu na tablets za kisasa zilizounganishwa kupitia MTP/PTP huenda **zisionekane** chini ya `USBSTOR`. Pia angalia `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` na `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Ili kuhusisha device na user, fanya pivot kutoka device au volume identifiers kwenda kwenye per-user artifacts kama shellbags, LNKs, Jump Lists, `RecentDocs`, na `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
