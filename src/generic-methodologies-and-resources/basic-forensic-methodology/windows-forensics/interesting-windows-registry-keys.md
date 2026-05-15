# İlginç Windows Registry Anahtarları

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive’ları, _ne oldu?_ sorusundan _hangi kullanıcı, ne zaman ve nereden?_ sorusuna geçmenin en hızlı yollarından biridir. Canlı analiz için `CurrentControlSet` tercih edin; offline hive analizinde önce hangi `ControlSet00x`’in aktif olduğunu çözün, `ControlSet001`’i sabitleyip bırakmayın.

### Windows Version and Owner Info

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, install time, registered owner, product name ve diğer build metadata.
- `SYSTEM\Select`: sistem tarafından kullanılan gerçek `ControlSet00x` değerlerine `Current`, `Default` ve `LastKnownGood` eşler.

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: mevcut hostname.

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: yapılandırılmış time zone ve DST ile ilgili değerler.

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate`, NTFS last-access timestamp’lerinin güncellenip güncellenmediğini gösterir.
- Bunu etkinleştirmek için: `fsutil behavior set disablelastaccess 0`

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: son shutdown zamanı.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: eski sistemler shutdown sayaçlarını da açığa çıkarabilir.

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface IP’leri, DHCP lease’leri, gateway ve DNS verileri.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile adı/SSID ile ilk ve son bağlantı zamanları.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` ve `...\Unmanaged\{GUID}`: gateway MAC address ve DNS suffix gibi profil korelasyon verileri.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host tarafından yayınlanan yerel shared folders.

### Remote Access and Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU listesi (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: host başına outbound RDP geçmişi. Alt anahtarlar genelde `UsernameHint` saklar ve anahtarın `LastWrite` zamanı faydalı bir pivot’tur.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: belirli bir kullanıcıya bağlı mapped network drives, UNC shares ve removable-media mount points.

### Programs that Start Automatically and Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` ve `...\Tasks\{GUID}`: scheduled task metadata. Eğer burada bir task varsa ama `Tree\<TaskName>` içinde `SD` değeri yoksa, gizli Tarrask tarzı task tampering şüphesi oluşur ve bunu `C:\Windows\System32\Tasks\<TaskName>` ile korele edin.

### Searches, Typed Paths, and MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer arama terimleri.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: elle yazılmış Explorer path’leri.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: son 26 `Win + R` komutu. `MRUList` sıralarını korur.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: yakın zamanda açılan belgeler ve klasörler.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office recent files.

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-driven execution geçmişi. Değer adları ROT13 ile kodludur ve binary data run sayaçlarını ve son run zamanını içerir.
- `UserAssist`’i tek başına karar değil, güçlü destekleyici kanıt olarak değerlendirin: esas olarak Explorer üzerinden başlatılan app’leri veya `.lnk` dosyalarını izler ve command-line ya da service execution’ı kaçırabilir. Windows 10+ üzerinde bazı girdiler, process’in tam olarak çalıştığı anlamına gelmeyebilir.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` ve `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID ataması ve son execution time içeren modern Windows 10/11 execution trace’leri. Özellikle local olarak çalıştırılan binary’ler için faydalıdır; ancak eski girdiler hızlıca silinebilir ve network share/removable media üzerinden yapılan executions daha az güvenilirdir.
- Prefetch, Amcache, ShimCache ve SRUM gibi daha geniş execution artefact’leri için ana [Windows forensics overview](README.md#programs-executed) bölümüne bakın.

### Shellbags

- Shellbags, hem `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` hem de `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` içinde saklanır.
- `NTUSER.DAT` girdileri özellikle UNC/network browsing için kullanışlıdır; `UsrClass.dat` ise Windows Vista+’ın genellikle local/removable-folder shellbags sakladığı yerdir.
- Klasör silinmiş olsa bile klasörün varlığını, traversal’ı ve folder-view tercihlerini gösterebilir. Arşiv dosyalarına Explorer benzeri erişim de shellbag izleri bırakabilir.
- Her shellbag başarılı klasör erişimini kanıtlamaz; bu yüzden LNK’ler, Jump Lists, zaman damgaları veya volume mappings ile doğrulayın.
- Bunları ayrıştırmak için **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** veya **SBECmd** kullanın.

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage device’larının ana envanteri (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: non-storage device’lar dahil daha geniş USB device envanteri.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: recent Windows 10/11 builds üzerinde, install, first install, last arrival ve last removal gibi device lifecycle timestamp’leri için yüksek değerli bir noktadır.
- `HKLM\SYSTEM\MountedDevices`: volume’ları ve device identifier’ları drive letter’lara / volume GUID’lerine eşler. Bir drive letter için yalnızca son mapping kalabilir.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial number’ları ve önceki media metadata için faydalı bir pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: kullanıcıya özgü drive-letter ve share etkileşim geçmişi.
- MTP/PTP ile bağlanan modern telefonlar ve tabletler `USBSTOR` altında görünmeyebilir. Ayrıca `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` ve `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` anahtarlarını da kontrol edin.
- Bir device’ı bir kullanıcıya bağlamak için device veya volume identifier’larından shellbags, LNK’ler, Jump Lists, `RecentDocs` ve `MountPoints2` gibi per-user artefact’lere pivot edin.



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
