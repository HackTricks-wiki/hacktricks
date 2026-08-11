# Interesting Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives ni mojawapo ya njia za haraka zaidi za kugeuka kutoka _nini kilitokea?_ hadi _ni mtumiaji gani, lini, na kutoka wapi?_. Kwa uchambuzi wa moja kwa moja tumia `CurrentControlSet`; kwa uchambuzi wa hive iliyo nje ya mfumo, kwanza bainisha ni `ControlSet00x` ipi ilikuwa active badala ya kuweka `ControlSet001` moja kwa moja.

### Taarifa za Toleo la Windows na Mmiliki

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: edition/build ya Windows, muda wa usakinishaji, mmiliki aliyesajiliwa, jina la bidhaa, na metadata nyingine za build.
- `SYSTEM\Select`: huunganisha `Current`, `Default`, na `LastKnownGood` na thamani halisi za `ControlSet00x` zilizotumiwa na mfumo.

### Jina la Kompyuta

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname ya sasa.

### Mpangilio wa Time Zone

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: time zone iliyosanidiwa na thamani zinazohusiana na DST.

### Ufuatiliaji wa Muda wa Ufikiaji

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` huonyesha ikiwa timestamps za mwisho za ufikiaji za NTFS zinasasishwa.
- Ili kuiwezesha, tumia: `fsutil behavior set disablelastaccess 0`

### Maelezo ya Kuzima Mfumo

- `SYSTEM\CurrentControlSet\Control\Windows`: muda wa mwisho wa kuzima mfumo.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: mifumo ya zamani inaweza pia kuwa na vihesabu vya kuzima mfumo.

### Usanidi wa Network

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP za interface, DHCP leases, gateway na data za DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: jina la network profile/SSID pamoja na nyakati za kwanza na za mwisho za kuunganishwa.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` na `...\Unmanaged\{GUID}`: data za kuhusisha profile, kama vile anwani ya MAC ya gateway na DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: folda za ndani zilizoshirikiwa na host.

### Historia ya Remote Access na Network Share

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historia ya outbound RDP kwa kila host. Subkeys kwa kawaida huhifadhi `UsernameHint`, na muda wa `LastWrite` wa key ni pivot muhimu.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: network drives zilizomapishwa, UNC shares, na mount points za removable media zinazohusishwa na mtumiaji mahususi.

### Programu Zinazoanza Kiotomatiki na Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` na `...\Tasks\{GUID}`: metadata ya scheduled task. Ikiwa task ipo hapa lakini thamani ya `SD` haipo kwenye `Tree\<TaskName>`, shuku task tampering ya aina ya Tarrask iliyofichwa na ilinganishe na `C:\Windows\System32\Tasks\<TaskName>`.

### Utafutaji, Njia Zilizoandikwa na MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: maneno ya utafutaji ya File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: njia za Explorer zilizoandikwa manually.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: amri 26 za mwisho za `Win + R`. `MRUList` huhifadhi mpangilio wake.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documents na folda zilizofunguliwa hivi karibuni.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: files za hivi karibuni za Office.

### Ufuatiliaji wa Shughuli za Mtumiaji

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historia ya execution iliyoanzishwa kupitia GUI. Majina ya values yame-encode kwa ROT13, na binary data ina run counters pamoja na muda wa mwisho wa ku-run.<sup>[[1]](#references)</sup>
- Chukulia `UserAssist` kama ushahidi thabiti wa kuunga mkono, si hukumu ya pekee: hufuatilia hasa apps au files za `.lnk` zilizoanzishwa kupitia Explorer na inaweza kukosa execution ya command-line au service. Kwenye Windows 10+, baadhi ya entries si lazima zimaanishe kuwa process ili-run kikamilifu.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` na `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: execution traces za kisasa za Windows 10/11 zenye attribution ya SID na muda wa mwisho wa execution. Hizi zinafaa hasa kwa binaries zilizo-execute locally, lakini entries za zamani zinaweza kuondolewa haraka na executions kutoka network shares/removable media haziaminiki sana.
- Kwa execution artifacts pana zaidi kama Prefetch, Amcache, ShimCache, na SRUM, tazama [muhtasari mkuu wa Windows forensics](README.md#programs-executed).

### Shellbags

- Shellbags huhifadhiwa katika `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` na `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Entries za `NTUSER.DAT` zinafaa hasa kwa kuvinjari UNC/network, huku `UsrClass.dat` ikiwa mahali ambapo Windows Vista+ kwa kawaida huhifadhi shellbags za folda za local/removable.
- Zinaweza kuonyesha uwepo wa folda, kuipitia, na mapendeleo ya mwonekano wa folda hata baada ya folda kufutwa. Ufikiaji wa archive files kwa kutumia Explorer-like tools unaweza pia kuacha shellbag traces.<sup>[[1]](#references)</sup>
- Si kila shellbag inathibitisha ufikiaji uliofanikiwa wa folda, hivyo linganisha na LNKs, Jump Lists, timestamps, au volume mappings.
- Tumia **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** au **SBECmd** kuzichanganua.

### Taarifa za USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventory kuu ya USB mass-storage devices (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventory pana ya USB devices, ikijumuisha devices zisizo za storage.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: kwenye builds za hivi karibuni za Windows 10/11, hapa kuna taarifa muhimu za lifecycle timestamps kwa kila device, kama install, first install, last arrival, na last removal.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: huunganisha volumes na device identifiers na drive letters / volume GUIDs. Mapping ya mwisho pekee ya drive letter inaweza kubaki.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivot muhimu kwa volume serial numbers na metadata ya media iliyotumika awali.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historia ya mtumiaji mahususi ya mwingiliano na drive letters na shares.<sup>[[2]](#references)</sup>
- Simu na tablets za kisasa zilizounganishwa kupitia MTP/PTP huenda **zisionekane** kwenye `USBSTOR`. Pia kagua `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` na `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Ili kuhusisha device na mtumiaji, tumia device au volume identifiers kama pivot kuelekea per-user artifacts kama shellbags, LNKs, Jump Lists, `RecentDocs`, na `MountPoints2`.<sup>[[2]](#references)</sup>

## References

- [1] [Cheat Sheet ya Windows Registry Forensics 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Forensics ya USB Devices kwenye Windows 10 na 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
