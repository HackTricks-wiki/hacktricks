# Vifunguo Muhimu vya Windows Registry

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives ni mojawapo ya njia za haraka zaidi za kubadilisha swali kutoka _nini kilitokea?_ hadi _ni mtumiaji gani, lini, na kutoka wapi?_. Kwa uchanganuzi wa mfumo unaoendelea, tumia `CurrentControlSet`; kwa uchanganuzi wa hive nje ya mfumo, kwanza tambua ni `ControlSet00x` gani iliyokuwa inatumika badala ya kudhani `ControlSet001`.

### Taarifa za Toleo la Windows na Mmiliki

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: toleo/build ya Windows, muda wa usakinishaji, mmiliki aliyesajiliwa, jina la bidhaa na metadata nyingine za build.
- `SYSTEM\Select`: huunganisha `Current`, `Default` na `LastKnownGood` na thamani halisi za `ControlSet00x` zilizotumiwa na mfumo.

### Jina la Kompyuta

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: jina la sasa la kompyuta.

### Mipangilio ya Eneo la Saa

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: eneo la saa lililowekwa na thamani zinazohusiana na DST.

### Ufuatiliaji wa Muda wa Ufikiaji

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` huonyesha ikiwa mihuri ya muda ya ufikiaji wa mwisho wa NTFS inasasishwa.
- Ili kuiwasha, tumia: `fsutil behavior set disablelastaccess 0`

### Maelezo ya Kuzima

- `SYSTEM\CurrentControlSet\Control\Windows`: muda wa kuzima wa mwisho.
- Mifumo ya zamani inaweza pia kuonyesha kaunta za kuzima katika `SYSTEM\CurrentControlSet\Control\Watchdog\Display`.

### Mipangilio ya Mtandao

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: IP za interface, leases za DHCP, taarifa za gateway na DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: jina la wasifu wa mtandao/SSID pamoja na nyakati za muunganisho wa kwanza na wa mwisho.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` na `...\Unmanaged\{GUID}`: data za kulinganisha wasifu kama vile anwani ya MAC ya gateway na DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: folda za ndani zilizoshirikiwa na kompyuta.

### Ufikiaji wa Mbali na Historia ya Network Share

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: orodha ya MRU ya miunganisho ya RDP inayotoka (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historia ya RDP inayotoka kwa kila host. Subkeys kwa kawaida huhifadhi `UsernameHint`, na muda wa `LastWrite` wa key ni sehemu muhimu ya kufuatilia.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: drive za mtandao zilizowekwa ramani, UNC shares, na mount points za media zinazoweza kuondolewa zinazohusishwa na mtumiaji mahususi.

### Programu Zinazojiendesha Zenyewe na Persistence Iliyopangwa

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` na `...\Tasks\{GUID}`: metadata ya scheduled task. Ikiwa task ipo hapa lakini thamani ya `SD` haipo kwenye `Tree\<TaskName>`, shuku uchezaji uliofichwa wa task wa aina ya Tarrask na ulinganishe na `C:\Windows\System32\Tasks\<TaskName>`.

### Utafutaji, Njia Zilizoandikwa na MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: maneno yaliyotafutwa kwenye File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: njia za Explorer zilizoandikwa kwa mkono.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: amri 26 za mwisho za `Win + R`. `MRUList` huhifadhi mpangilio wake.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: nyaraka na folda zilizofunguliwa hivi karibuni.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: faili za Office zilizotumiwa hivi karibuni.

### Ufuatiliaji wa Shughuli za Mtumiaji

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historia ya utekelezaji iliyoanzishwa kupitia GUI. Majina ya thamani yamesimbwa kwa ROT13, na data ya binary inajumuisha kaunta za uendeshaji na muda wa uendeshaji wa mwisho.<sup>[[1]](#references)</sup>
- Ichukulie `UserAssist` kama ushahidi thabiti wa kuunga mkono, si hukumu ya mwisho: hufuatilia hasa programu au faili za `.lnk` zilizozinduliwa kupitia Explorer na inaweza kukosa utekelezaji wa command-line au service. Kwenye Windows 10 na matoleo mapya zaidi, baadhi ya maingizo hayamaanishi lazima kwamba mchakato uliendeshwa kikamilifu.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` na `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: athari za utekelezaji kwenye Windows 10/11 za sasa zenye uhusishaji wa SID na muda wa utekelezaji wa mwisho. Hizi ni muhimu hasa kwa binaries zilizotekelezwa ndani ya kompyuta, lakini maingizo ya zamani yanaweza kufutika haraka na rekodi za utekelezaji kutoka network shares/media zinazoweza kuondolewa si za kutegemewa sana.
- Kwa ushahidi mpana zaidi wa utekelezaji kama Prefetch, Amcache, ShimCache na SRUM, tazama [muhtasari wa uchunguzi wa Windows](./#programs-executed).

### Shellbags

- Shellbags huhifadhiwa katika `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` na `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Maingizo ya `NTUSER.DAT` ni muhimu hasa kwa kuvinjari UNC/network, ilhali `UsrClass.dat` ndiyo sehemu ambayo Windows Vista na matoleo mapya zaidi huhifadhi kwa kawaida shellbags za folda za ndani/zinazoweza kuondolewa.
- Yanaweza kuonyesha kuwepo kwa folda, kuvinjari kwake na mapendeleo ya mwonekano wa folda hata baada ya folda kufutwa. Ufikiaji wa faili za archive kwa njia inayofanana na Explorer unaweza pia kuacha athari za shellbag.<sup>[[1]](#references)</sup>
- Si kila shellbag inathibitisha kwamba folda ilifikiwa kwa mafanikio, kwa hiyo linganisha na LNKs, Jump Lists, mihuri ya muda au ramani za volume.
- Tumia **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** au **SBECmd** kuzichanganua.

### Taarifa za USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: orodha kuu ya vifaa vya hifadhi ya USB (mtengenezaji, bidhaa, toleo, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: orodha pana zaidi ya vifaa vya USB, ikijumuisha vifaa visivyohifadhi data.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: kwenye builds za hivi karibuni za Windows 10/11, hapa kunaweza kuwa na mihuri ya muda muhimu ya mzunguko wa maisha wa kila kifaa, kama vile kusakinishwa, kusakinishwa kwa mara ya kwanza, kuunganishwa mara ya mwisho na kuondolewa mara ya mwisho.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: huunganisha volumes na vitambulisho vya vifaa na herufi za drive / volume GUIDs. Ramani ya mwisho tu ya herufi fulani ya drive ndiyo inayoweza kubaki.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: sehemu muhimu ya kufuatilia namba za serial za volume na metadata ya media iliyotumika awali.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historia ya mtumiaji mahususi ya mwingiliano na herufi za drive na shares.<sup>[[2]](#references)</sup>
- Simu na tablets za kisasa zilizounganishwa kupitia MTP/PTP huenda **zisionekane** chini ya `USBSTOR`. Angalia pia `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` na `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Ili kuhusisha kifaa na mtumiaji, fuatilia vitambulisho vya kifaa au volume hadi kwenye ushahidi wa kila mtumiaji, kama vile shellbags, LNKs, Jump Lists, `RecentDocs` na `MountPoints2`.<sup>[[2]](#references)</sup>



## References

- [1] [Karatasi ya Marejeo ya Uchunguzi wa Windows Registry 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Uchunguzi wa Vifaa vya USB kwenye Windows 10 na 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
