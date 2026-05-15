# Funguo Muhimu za Windows Registry

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives ni mojawapo ya njia za haraka zaidi za kuhamia kutoka _nini kilitokea?_ hadi _mtumiaji gani, lini, na kutoka wapi?_. Kwa uchambuzi wa moja kwa moja prefer `CurrentControlSet`; kwa uchambuzi wa offline hive kwanza tambua ni `ControlSet00x` gani ilikuwa active badala ya kuhardcode `ControlSet001`.

### Toleo la Windows na Taarifa za Mmiliki

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, wakati wa install, registered owner, product name, na metadata nyingine za build.
- `SYSTEM\Select`: huweka `Current`, `Default`, na `LastKnownGood` kuwa values halisi za `ControlSet00x` zinazotumiwa na mfumo.

### Jina la Kompyuta

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: hostname ya sasa.

### Mipangilio ya Time Zone

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: time zone iliyosanidiwa na values zinazohusiana na DST.

### Ufuatiliaji wa Muda wa Ufikiaji

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` inaonyesha kama timestamps za last-access za NTFS zinasasishwa.
- Kuiwasha, tumia: `fsutil behavior set disablelastaccess 0`

### Maelezo ya Shutdown

- `SYSTEM\CurrentControlSet\Control\Windows`: wakati wa mwisho wa shutdown.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: mifumo ya zamani inaweza pia kuonyesha shutdown counters.

### Usanidi wa Mtandao

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP za interface, DHCP leases, gateway na data za DNS.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: jina la network profile/SSID pamoja na nyakati za kwanza na mwisho za connection.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` na `...\Unmanaged\{GUID}`: data za correlation za profile kama gateway MAC address na DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: folda za local shared zilizochapishwa na host.

### Ufikiaji wa Mbali na Historia ya Network Share

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historia ya outbound RDP kwa kila host. Subkeys mara nyingi huhifadhi `UsernameHint`, na wakati wa `LastWrite` wa key ni pivot muhimu.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapped network drives, UNC shares, na mount points za removable media zinazohusishwa na user fulani.

### Programu Zinazoanza Kiotomatiki na Persistence Iliyoratibiwa

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` na `...\Tasks\{GUID}`: metadata za scheduled task. Ikiwa task ipo hapa lakini value ya `SD` haipo kwenye `Tree\<TaskName>`, shuku hidden Tarrask-style task tampering na ihusishe na `C:\Windows\System32\Tasks\<TaskName>`.

### Utafutaji, Typed Paths, na MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: maneno ya utafutaji ya File Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: paths za Explorer zilizoandikwa manually.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: amri 26 za mwisho za `Win + R`. `MRUList` huhifadhi mpangilio wao.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documents na folders zilizofunguliwa karibuni.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: files za hivi karibuni za Office.

### Ufuatiliaji wa Shughuli za User

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historia ya execution inayoendeshwa kupitia GUI. Jina la value limefichwa kwa ROT13, na data ya binary inajumuisha counters za kuendeshwa na wakati wa mwisho wa kuendeshwa.
- Chukulia `UserAssist` kama ushahidi wa kuunga mkono wenye nguvu, si verdict pekee: hasa hufuata apps au `.lnk` files zilizozinduliwa kupitia Explorer na inaweza kukosa command-line au service execution. Kwenye Windows 10+, baadhi ya entries si lazima ziashirie kwamba process ilikimbia kikamilifu.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` na `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: execution traces za kisasa za Windows 10/11 zenye SID attribution na wakati wa mwisho wa execution. Hizi ni muhimu sana kwa binaries zilizotekelezwa locally, lakini entries za zamani zinaweza kuisha haraka na executions kutoka network shares/removable media si za kuaminika sana.
- Kwa broader execution artifacts kama Prefetch, Amcache, ShimCache, na SRUM, angalia [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Shellbags huhifadhiwa katika `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` na `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- Entries za `NTUSER.DAT` ni muhimu sana kwa UNC/network browsing, huku `UsrClass.dat` ikiwa mahali ambapo Windows Vista+ mara nyingi huhifadhi local/removable-folder shellbags.
- Zinaweza kuonyesha uwepo wa folda, traversal, na folder-view preferences hata baada ya folda kufutwa. Access ya aina ya Explorer kwa archive files pia inaweza kuacha shellbag traces.
- Si kila shellbag inathibitisha folder access iliyofanikiwa, kwa hiyo thibitisha kwa LNKs, Jump Lists, timestamps, au volume mappings.
- Tumia **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** au **SBECmd** kuzichambua.

### Taarifa za USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: orodha kuu ya USB mass-storage devices (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: orodha pana zaidi ya USB devices, ikijumuisha devices zisizo za storage.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: kwenye builds za hivi karibuni za Windows 10/11 hili ni eneo lenye thamani kubwa kwa lifecycle timestamps za kila device kama install, first install, last arrival, na last removal.
- `HKLM\SYSTEM\MountedDevices`: huweka ramani ya volumes na device identifiers kwa drive letters / volume GUIDs. Huenda ikabaki tu mapping ya mwisho kwa drive letter fulani.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivot muhimu kwa volume serial numbers na metadata za media za awali.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historia ya mwingiliano ya drive-letter na share kwa user husika.
- Simu na tablets za kisasa zilizounganishwa kupitia MTP/PTP huenda **zisionekane** chini ya `USBSTOR`. Kagua pia `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` na `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
- Kuunganisha device na user, anza kutoka kwa device au volume identifiers kwenda kwenye per-user artifacts kama shellbags, LNKs, Jump Lists, `RecentDocs`, na `MountPoints2`.



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
