# रोचक Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives _क्या हुआ?_ से _कौन-सा user, कब और कहाँ से?_ तक pivot करने के सबसे तेज़ तरीकों में से एक हैं। Live analysis के लिए `CurrentControlSet` को प्राथमिकता दें; offline hive analysis के लिए पहले यह निर्धारित करें कि कौन-सा `ControlSet00x` active था, बजाय इसके कि `ControlSet001` को hardcode करें।

### Windows Version और Owner Info

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, install time, registered owner, product name और अन्य build metadata।
- `SYSTEM\Select`: `Current`, `Default` और `LastKnownGood` को system द्वारा उपयोग किए गए वास्तविक `ControlSet00x` values से map करता है।

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: current hostname।

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: configured time zone और DST-related values।

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` बताता है कि NTFS last-access timestamps update किए जा रहे हैं या नहीं।
- इसे enable करने के लिए उपयोग करें: `fsutil behavior set disablelastaccess 0`

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: last shutdown time।
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: पुराने systems shutdown counters भी expose कर सकते हैं।

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface IPs, DHCP leases, gateway और DNS data।<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile name/SSID तथा first और last connection times।
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` और `...\Unmanaged\{GUID}`: profile correlation data, जैसे gateway MAC address और DNS suffix।
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host द्वारा publish किए गए local shared folders।

### Remote Access और Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`)।<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: प्रत्येक host की outbound RDP history। Subkeys में सामान्यतः `UsernameHint` store होता है और key का `LastWrite` time एक उपयोगी pivot है।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: किसी specific user से जुड़े mapped network drives, UNC shares और removable-media mount points।

### Automatically Start होने वाले Programs और Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` और `...\Tasks\{GUID}`: scheduled task metadata। यदि यहाँ कोई task मौजूद है, लेकिन `SD` value `Tree\<TaskName>` से missing है, तो hidden Tarrask-style task tampering का संदेह करें और इसे `C:\Windows\System32\Tasks\<TaskName>` के साथ correlate करें।

### Searches, Typed Paths और MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer search terms।<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: manually typed Explorer paths।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: अंतिम 26 `Win + R` commands। `MRUList` उनका order preserve करता है।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: हाल ही में खोले गए documents और folders।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office recent files।

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-driven execution history। Value names ROT13-encoded होते हैं और binary data में run counters तथा last run time शामिल होते हैं।<sup>[[1]](#references)</sup>
- `UserAssist` को strong supporting evidence मानें, standalone verdict नहीं: यह मुख्यतः Explorer के माध्यम से launch किए गए apps या `.lnk` files को track करता है और command-line या service execution को miss कर सकता है। Windows 10+ पर कुछ entries का अर्थ यह आवश्यक नहीं है कि process पूरी तरह run हुआ था।
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` और `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID attribution और last execution time वाले modern Windows 10/11 execution traces। ये locally executed binaries के लिए विशेष रूप से उपयोगी हैं, लेकिन पुराने entries जल्दी age out हो सकते हैं और network shares/removable media से किए गए executions कम reliable होते हैं।
- Prefetch, Amcache, ShimCache और SRUM जैसे broader execution artifacts के लिए मुख्य [Windows forensics overview](README.md#programs-executed) देखें।

### Shellbags

- Shellbags `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` और `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` दोनों में store होते हैं।<sup>[[1]](#references)</sup>
- `NTUSER.DAT` entries UNC/network browsing के लिए विशेष रूप से उपयोगी हैं, जबकि `UsrClass.dat` वह स्थान है जहाँ Windows Vista+ सामान्यतः local/removable-folder shellbags store करता है।
- ये folder के अस्तित्व, traversal और folder-view preferences को दिखा सकते हैं, भले ही folder delete किया जा चुका हो। Archive files तक Explorer-जैसी access भी shellbag traces छोड़ सकती है।<sup>[[1]](#references)</sup>
- प्रत्येक shellbag successful folder access को prove नहीं करता, इसलिए LNKs, Jump Lists, timestamps या volume mappings से corroborate करें।
- इन्हें parse करने के लिए **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** या **SBECmd** का उपयोग करें।

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage devices की primary inventory (vendor, product, revision, serial/device instance)।
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: broader USB device inventory, जिसमें non-storage devices भी शामिल हैं।
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: recent Windows 10/11 builds पर यह per-device lifecycle timestamps, जैसे install, first install, last arrival और last removal, के लिए high-value location है।<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: volumes और device identifiers को drive letters / volume GUIDs से map करता है। किसी दिए गए drive letter के लिए केवल last mapping survive कर सकती है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial numbers और previous media metadata के लिए उपयोगी pivot।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific drive-letter और share interaction history।<sup>[[2]](#references)</sup>
- MTP/PTP के माध्यम से connected modern phones और tablets **`USBSTOR` के अंतर्गत दिखाई नहीं दे सकते**। `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` और `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` को भी check करें।<sup>[[2]](#references)</sup>
- किसी device को user से tie करने के लिए device या volume identifiers से per-user artifacts, जैसे shellbags, LNKs, Jump Lists, `RecentDocs` और `MountPoints2`, की ओर pivot करें।<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
