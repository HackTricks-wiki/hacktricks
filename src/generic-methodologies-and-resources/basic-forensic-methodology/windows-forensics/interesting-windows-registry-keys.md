# Interesting Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives ni mojawapo ya njia za haraka zaidi za kubadilika kutoka _nini kilitokea?_ hadi _ni mtumiaji gani, lini, na kutoka wapi?_. Kwa uchanganuzi wa moja kwa moja tumia `CurrentControlSet`; kwa uchanganuzi wa hive iliyo nje ya mfumo, kwanza tambua ni `ControlSet00x` ipi iliyokuwa active badala ya kuweka `ControlSet001` moja kwa moja.

### Windows Version and Owner Info

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: toleo/build ya Windows, muda wa usakinishaji, mmiliki aliyesajiliwa, jina la bidhaa, na metadata nyingine za build.
- `SYSTEM\Select`: huunganisha `Current`, `Default`, na `LastKnownGood` na thamani halisi za `ControlSet00x` zilizotumiwa na mfumo.

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname ya sasa.

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: time zone iliyosanidiwa na thamani zinazohusiana na DST.

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` huonyesha ikiwa timestamps za mwisho za ufikiaji za NTFS zinasasishwa.
- Ili kuiwezesha, tumia: `fsutil behavior set disablelastaccess 0`

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: muda wa mwisho wa shutdown.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: mifumo ya zamani inaweza pia kuonyesha counters za shutdown.

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP za interface, DHCP leases, gateway na data ya DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: jina la network profile/SSID pamoja na nyakati za kwanza na za mwisho za connection.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` na `...\Unmanaged\{GUID}`: data ya kuhusianisha profile kama vile gateway MAC address na DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: folders za local zilizoshirikiwa na kuchapishwa na host.

### Remote Access and Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historia ya outbound RDP kwa kila host. Subkeys kwa kawaida huhifadhi `UsernameHint`, na muda wa `LastWrite` wa key ni pivot muhimu.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: network drives zilizomapishwa, UNC shares, na mount points za removable media zinazohusishwa na mtumiaji maalum.

### Programs that Start Automatically and Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` na `...\Tasks\{GUID}`: metadata ya scheduled task. Ikiwa task ipo hapa lakini value ya `SD` haipo kwenye `Tree\<TaskName>`, shuku task tampering ya mtindo wa Tarrask iliyofichwa na ihusianishe na `C:\Windows\System32\Tasks\<TaskName>`.

### Searches, Typed Paths, and MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: maneno yaliyotafutwa kwenye File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: paths za Explorer zilizoandikwa manually.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: commands 26 za mwisho za `Win + R`. `MRUList` huhifadhi mpangilio wake.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documents na folders zilizofunguliwa hivi karibuni.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: files za Office zilizotumiwa hivi karibuni.

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historia ya execution iliyoanzishwa kupitia GUI. Majina ya values yame-encode kwa ROT13, na binary data inajumuisha run counters na muda wa mwisho wa run.<sup>[[1]](#references)</sup>
- Ichukulie `UserAssist` kama ushahidi thabiti wa kusaidia, si hitimisho la pekee: hufuatilia hasa apps au files za `.lnk` zilizoanzishwa kupitia Explorer na inaweza kukosa execution ya command-line au service. Kwenye Windows 10+, baadhi ya entries si lazima zimaanishe kuwa process iliendeshwa kikamilifu.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` na `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: execution traces za kisasa za Windows 10/11 zenye SID attribution na muda wa mwisho wa execution. Hizi ni muhimu hasa kwa binaries zilizoendeshwa locally, lakini entries za zamani zinaweza kuondolewa haraka na executions kutoka network shares/removable media si za kuaminika kwa kiwango sawa.
- Kwa execution artifacts pana zaidi kama Prefetch, Amcache, ShimCache, na SRUM, tazama [Windows forensics overview](README.md#programs-executed) kuu.

### Shellbags

- Shellbags huhifadhiwa katika `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` na `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Entries za `NTUSER.DAT` ni muhimu hasa kwa kuvinjari UNC/network, wakati `UsrClass.dat` ndiyo mahali ambapo Windows Vista+ kwa kawaida huhifadhi shellbags za folders za local/removable.
- Zinaweza kuonyesha uwepo wa folder, traversal, na mapendeleo ya folder-view hata baada ya folder kufutwa. Ufikiaji wa archive files kupitia Explorer-like interfaces unaweza pia kuacha shellbag traces.<sup>[[1]](#references)</sup>
- Si kila shellbag inathibitisha ufikiaji uliofanikiwa wa folder, kwa hiyo linganisha na LNKs, Jump Lists, timestamps, au volume mappings.
- Tumia **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** au **SBECmd** kuziparse.

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventory kuu ya USB mass-storage devices (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventory pana zaidi ya USB devices, ikijumuisha devices zisizo za storage.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: kwenye builds za hivi karibuni za Windows 10/11 hapa ni sehemu yenye thamani kubwa kwa lifecycle timestamps za kila device, kama vile install, first install, last arrival, na last removal.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: huunganisha volumes na device identifiers na drive letters / volume GUIDs. Mapping ya mwisho pekee ya drive letter fulani inaweza kubaki.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivot muhimu kwa volume serial numbers na metadata ya media iliyotumika awali.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historia ya user-specific ya mwingiliano na drive letters na shares.<sup>[[2]](#references)</sup>
- Simu na tablets za kisasa zilizounganishwa kupitia MTP/PTP zinaweza **kutoonekana** chini ya `USBSTOR`. Kagua pia `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` na `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Ili kuhusianisha device na mtumiaji, fanya pivot kutoka device au volume identifiers kwenda kwenye per-user artifacts kama shellbags, LNKs, Jump Lists, `RecentDocs`, na `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
