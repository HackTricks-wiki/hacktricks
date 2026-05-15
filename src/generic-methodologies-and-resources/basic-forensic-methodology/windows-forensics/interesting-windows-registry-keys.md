# दिलचस्प Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives _what happened?_ से _कौन-सा user, कब, और कहाँ से?_ तक जाने का सबसे तेज़ तरीका हैं। live analysis के लिए `CurrentControlSet` prefer करें; offline hive analysis के लिए पहले resolve करें कि कौन-सा `ControlSet00x` active था, बजाय `ControlSet001` को hardcode करने के।

### Windows Version and Owner Info

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, install time, registered owner, product name, और अन्य build metadata।
- `SYSTEM\Select`: `Current`, `Default`, और `LastKnownGood` को system द्वारा इस्तेमाल किए गए real `ControlSet00x` values से map करता है।

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: current hostname।

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: configured time zone और DST-related values।

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` बताता है कि NTFS last-access timestamps update हो रहे हैं या नहीं।
- इसे enable करने के लिए, use करें: `fsutil behavior set disablelastaccess 0`

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: last shutdown time।
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: पुराने systems में shutdown counters भी दिख सकते हैं।

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface IPs, DHCP leases, gateway और DNS data।
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile name/SSID plus first और last connection times।
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` और `...\Unmanaged\{GUID}`: profile correlation data जैसे gateway MAC address और DNS suffix।
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host द्वारा publish किए गए local shared folders।

### Remote Access and Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`)।
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: per-host outbound RDP history। Subkeys आमतौर पर `UsernameHint` store करते हैं, और key का `LastWrite` time एक useful pivot है।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapped network drives, UNC shares, और removable-media mount points जो किसी specific user से जुड़े हों।

### Programs that Start Automatically and Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` और `...\Tasks\{GUID}`: scheduled task metadata। अगर यहाँ task मौजूद है लेकिन `Tree\<TaskName>` से `SD` value missing है, तो hidden Tarrask-style task tampering suspect करें और इसे `C:\Windows\System32\Tasks\<TaskName>` के साथ correlate करें।

### Searches, Typed Paths, and MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer search terms।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: manually typed Explorer paths।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: last 26 `Win + R` commands। `MRUList` उनका order preserve करता है।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: recently opened documents और folders।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office recent files।

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-driven execution history। Value names ROT13-encoded होते हैं, और binary data में run counters और last run time शामिल होता है।
- `UserAssist` को strong supporting evidence की तरह देखें, standalone verdict की तरह नहीं: यह मुख्यतः Explorer के through लॉन्च हुए apps या `.lnk` files track करता है और command-line या service execution miss कर सकता है। Windows 10+ पर, कुछ entries का मतलब यह जरूरी नहीं कि process पूरी तरह run हुआ।
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` और `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: modern Windows 10/11 execution traces with SID attribution और last execution time। ये locally executed binaries के लिए विशेष रूप से useful हैं, लेकिन पुराने entries जल्दी age out हो सकते हैं और network shares/removable media से executions कम reliable होते हैं।
- Prefetch, Amcache, ShimCache, और SRUM जैसे broader execution artifacts के लिए main [Windows forensics overview](README.md#programs-executed) देखें।

### Shellbags

- Shellbags दोनों `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` और `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` में store होते हैं।
- `NTUSER.DAT` entries खास तौर पर UNC/network browsing के लिए useful हैं, जबकि `UsrClass.dat` वह जगह है जहाँ Windows Vista+ आमतौर पर local/removable-folder shellbags store करता है।
- ये folder के existence, traversal, और folder-view preferences दिखा सकते हैं, भले ही folder बाद में delete हो गया हो। archive files तक Explorer-like access भी shellbag traces छोड़ सकता है।
- हर shellbag successful folder access prove नहीं करता, इसलिए LNKs, Jump Lists, timestamps, या volume mappings से corroborate करें।
- इन्हें parse करने के लिए **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** या **SBECmd** use करें।

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage devices की primary inventory (vendor, product, revision, serial/device instance)।
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: broader USB device inventory, जिसमें non-storage devices भी शामिल हैं।
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: recent Windows 10/11 builds पर यह per-device lifecycle timestamps जैसे install, first install, last arrival, और last removal के लिए high-value spot है।
- `HKLM\SYSTEM\MountedDevices`: volumes और device identifiers को drive letters / volume GUIDs से map करता है। किसी given drive letter के लिए सिर्फ last mapping survive कर सकती है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial numbers और previous media metadata के लिए useful pivot।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific drive-letter और share interaction history।
- MTP/PTP के through connected modern phones और tablets `USBSTOR` के तहत **नहीं** दिख सकते हैं। `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` और `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` भी check करें।
- किसी device को user से tie करने के लिए, device या volume identifiers से per-user artifacts जैसे shellbags, LNKs, Jump Lists, `RecentDocs`, और `MountPoints2` में pivot करें।



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
