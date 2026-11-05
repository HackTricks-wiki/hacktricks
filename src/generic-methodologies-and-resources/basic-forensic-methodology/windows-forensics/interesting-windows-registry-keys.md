# रोचक Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives, _क्या हुआ?_ से _कौन-सा user, कब और कहाँ से?_ तक पहुँचने के सबसे तेज़ तरीकों में से एक हैं। Live analysis के लिए `CurrentControlSet` को प्राथमिकता दें; offline hive analysis के लिए, `ControlSet001` को hardcode करने के बजाय पहले पता करें कि कौन-सा `ControlSet00x` सक्रिय था।

### Windows Version और Owner की जानकारी

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, install time, registered owner, product name और build से जुड़ा अन्य metadata।
- `SYSTEM\Select`: `Current`, `Default` और `LastKnownGood` को system द्वारा उपयोग किए गए वास्तविक `ControlSet00x` values से map करता है।

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: वर्तमान hostname।

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: configured time zone और DST से जुड़े values।

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` बताता है कि NTFS के last-access timestamps update हो रहे हैं या नहीं।
- इसे enable करने के लिए, यह उपयोग करें: `fsutil behavior set disablelastaccess 0`

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: पिछली shutdown time।
- पुराने systems में shutdown counters `SYSTEM\CurrentControlSet\Control\Watchdog\Display` में भी मिल सकते हैं।

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface IPs, DHCP leases, gateway और DNS data।<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile name/SSID के साथ पहली और आखिरी connection times।
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` और `...\Unmanaged\{GUID}`: profile correlation data, जैसे gateway MAC address और DNS suffix।
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host द्वारा प्रकाशित local shared folders।

### Remote Access और Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outgoing RDP MRU list (`MRU0`..`MRU9`)।<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: हर host के लिए outgoing RDP history। Subkeys में आम तौर पर `UsernameHint` होता है, और key का `LastWrite` time एक उपयोगी pivot है।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: किसी specific user से जुड़े mapped network drives, UNC shares और removable-media mount points।

### Automatically Start होने वाले Programs और Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` और `...\Tasks\{GUID}`: scheduled task metadata। यदि यहाँ task मौजूद है, लेकिन `Tree\<TaskName>` से `SD` value गायब है, तो hidden Tarrask-style task tampering का संदेह करें और इसे `C:\Windows\System32\Tasks\<TaskName>` से correlate करें।

### Searches, Typed Paths और MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer search terms।<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer में manually typed paths।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: पिछली 26 `Win + R` commands। `MRUList` उनका क्रम सुरक्षित रखता है।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: हाल ही में खोले गए documents और folders।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office की हाल की files।

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI के ज़रिए हुई execution history। Value names ROT13-encoded होते हैं, और binary data में run counters तथा last run time शामिल होते हैं।<sup>[[1]](#references)</sup>
- `UserAssist` को मज़बूत supporting evidence मानें, अकेले निर्णायक प्रमाण नहीं: यह मुख्य रूप से Explorer के ज़रिए launch किए गए apps या `.lnk` files को track करता है और command-line या service execution छूट सकती है। Windows 10+ पर, कुछ entries का यह अर्थ ज़रूरी नहीं कि process पूरी तरह चला हो।
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` और `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID attribution और last execution time वाले आधुनिक Windows 10/11 execution traces। ये locally executed binaries के लिए खास तौर पर उपयोगी हैं, लेकिन पुराने entries जल्दी हट सकते हैं और network shares/removable media से executions के traces कम भरोसेमंद होते हैं।
- Prefetch, Amcache, ShimCache और SRUM जैसे व्यापक execution artifacts के लिए मुख्य [Windows forensics overview](./#programs-executed) देखें।

### Shellbags

- Shellbags, `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` और `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`—दोनों में store होते हैं।<sup>[[1]](#references)</sup>
- `NTUSER.DAT` entries, UNC/network browsing के लिए खास तौर पर उपयोगी हैं, जबकि Windows Vista+ में local/removable-folder shellbags आम तौर पर `UsrClass.dat` में store होते हैं।
- Folder delete होने के बाद भी ये folder का अस्तित्व, उसमें जाने और folder-view preferences दिखा सकते हैं। Archive files तक Explorer-जैसी पहुँच के traces भी shellbags में रह सकते हैं।<sup>[[1]](#references)</sup>
- हर shellbag सफल folder access का प्रमाण नहीं होता, इसलिए LNKs, Jump Lists, timestamps या volume mappings से इसकी पुष्टि करें।
- इन्हें parse करने के लिए **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** या **SBECmd** का उपयोग करें।

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage devices की मुख्य inventory (vendor, product, revision, serial/device instance)।
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: व्यापक USB device inventory, जिसमें non-storage devices भी शामिल हैं।
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: हाल के Windows 10/11 builds में, यह per-device lifecycle timestamps—जैसे install, first install, last arrival और last removal—के लिए एक महत्वपूर्ण स्थान है।<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: volumes और device identifiers को drive letters / volume GUIDs से map करता है। किसी drive letter के लिए केवल आखिरी mapping बची रह सकती है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial numbers और पिछले media metadata के लिए उपयोगी pivot।
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific drive-letter और share interaction history।<sup>[[2]](#references)</sup>
- MTP/PTP के ज़रिए connect किए गए आधुनिक phones और tablets, `USBSTOR` में **नहीं** दिख सकते। `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` और `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` भी देखें।<sup>[[2]](#references)</sup>
- किसी device को user से जोड़ने के लिए, device या volume identifiers से per-user artifacts जैसे shellbags, LNKs, Jump Lists, `RecentDocs` और `MountPoints2` तक pivot करें।<sup>[[2]](#references)</sup>



## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Windows 10 और 11 पर USB Device Forensics - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
