# İlginç Windows Registry Anahtarları

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive'ları, _ne oldu?_ sorusundan _hangi kullanıcı, ne zaman ve nereden?_ sorularına geçiş yapmanın en hızlı yollarından biridir. Canlı analiz için `CurrentControlSet` kullanın; çevrimdışı hive analizinde `ControlSet001` değerini sabit olarak kullanmak yerine öncelikle hangi `ControlSet00x` değerinin etkin olduğunu belirleyin.

### Windows Sürümü ve Sahip Bilgileri

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows sürümü/build bilgileri, kurulum zamanı, kayıtlı sahip, ürün adı ve diğer build meta verileri.
- `SYSTEM\Select`: `Current`, `Default` ve `LastKnownGood` değerlerini sistem tarafından kullanılan gerçek `ControlSet00x` değerleriyle eşler.

### Bilgisayar Adı

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: mevcut hostname.

### Saat Dilimi Ayarı

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: yapılandırılmış saat dilimi ve DST ile ilgili değerler.

### Erişim Zamanı Takibi

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate`, NTFS son erişim zaman damgalarının güncellenip güncellenmediğini belirtir.
- Etkinleştirmek için şunu kullanın: `fsutil behavior set disablelastaccess 0`

### Kapatma Ayrıntıları

- `SYSTEM\CurrentControlSet\Control\Windows`: son kapatma zamanı.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: eski sistemler ayrıca kapatma sayaçlarını da gösterebilir.

### Network Yapılandırması

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface IP'leri, DHCP lease'leri, gateway ve DNS verileri.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profil adı/SSID ile ilk ve son bağlantı zamanları.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` ve `...\Unmanaged\{GUID}`: gateway MAC adresi ve DNS suffix gibi profil korelasyon verileri.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host tarafından yayınlanan yerel paylaşımlı klasörler.

### Remote Access ve Network Share Geçmişi

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: giden RDP MRU listesi (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: host bazında giden RDP geçmişi. Alt anahtarlar genellikle `UsernameHint` değerini saklar; anahtarın `LastWrite` zamanı yararlı bir pivot noktasıdır.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: belirli bir kullanıcıya bağlı map edilmiş network drive'lar, UNC share'ler ve çıkarılabilir medya mount noktaları.

### Otomatik Başlayan Programlar ve Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` ve `...\Tasks\{GUID}`: scheduled task meta verileri. Burada bir task mevcutsa ancak `SD` değeri `Tree\<TaskName>` içinde eksikse, gizli Tarrask tarzı task manipülasyonundan şüphelenin ve bunu `C:\Windows\System32\Tasks\<TaskName>` ile korele edin.

### Aramalar, Yazılan Path'ler ve MRU'lar

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer arama terimleri.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer'a manuel olarak yazılan path'ler.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: son 26 `Win + R` komutu. `MRUList` bunların sırasını korur.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: yakın zamanda açılan dokümanlar ve klasörler.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office son kullanılan dosyaları.

### Kullanıcı Aktivitesi Takibi

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI üzerinden gerçekleştirilen çalıştırma geçmişi. Değer adları ROT13 ile encode edilmiştir ve binary veriler çalıştırma sayaçları ile son çalıştırma zamanını içerir.<sup>[[1]](#references)</sup>
- `UserAssist` verisini tek başına kesin kanıt olarak değil, güçlü bir destekleyici kanıt olarak değerlendirin: Bu veri temel olarak Explorer üzerinden başlatılan uygulamaları veya `.lnk` dosyalarını takip eder; command-line ya da service çalıştırmalarını kaçırabilir. Windows 10+ sürümlerinde bazı girdiler process'in tamamen çalıştığı anlamına gelmeyebilir.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` ve `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID attribution ve son çalıştırma zamanı içeren modern Windows 10/11 çalıştırma izleri. Bunlar özellikle yerel olarak çalıştırılan binary'ler için yararlıdır; ancak eski girdiler hızlı şekilde silinebilir ve network share'lerden/çıkarılabilir medyadan gerçekleştirilen çalıştırmalar daha az güvenilirdir.
- Prefetch, Amcache, ShimCache ve SRUM gibi daha kapsamlı çalıştırma artifact'leri için ana [Windows forensics overview](README.md#programs-executed) sayfasına bakın.

### Shellbags

- Shellbag'ler hem `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` hem de `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` içinde saklanır.<sup>[[1]](#references)</sup>
- `NTUSER.DAT` girdileri UNC/network browsing için özellikle yararlıdır; `UsrClass.dat` ise Windows Vista+ sürümlerinde yerel/çıkarılabilir klasör shellbag'lerinin yaygın olarak saklandığı yerdir.
- Klasör silinmiş olsa bile klasörün varlığını, klasörde gezinildiğini ve klasör görünümü tercihlerini gösterebilirler. Archive dosyalarına Explorer benzeri erişim de shellbag izleri bırakabilir.<sup>[[1]](#references)</sup>
- Her shellbag başarılı klasör erişimini kanıtlamaz; bu nedenle LNK'ler, Jump List'ler, zaman damgaları veya volume mapping'leri ile doğrulayın.
- Bunları parse etmek için **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** veya **SBECmd** kullanın.

### USB Bilgileri

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage cihazlarının birincil envanteri (vendor, ürün, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: storage olmayan cihazlar da dahil olmak üzere daha geniş USB cihaz envanteri.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: güncel Windows 10/11 build'lerinde bu alan, install, first install, last arrival ve last removal gibi cihaz bazlı lifecycle zaman damgaları için yüksek değerli bir noktadır.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: volume'leri ve cihaz identifier'larını drive letter'lar / volume GUID'leri ile eşler. Belirli bir drive letter için yalnızca son mapping korunmuş olabilir.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial number'ları ve önceki medya meta verilerini incelemek için yararlı bir pivot noktasıdır.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: kullanıcıya özel drive-letter ve share etkileşim geçmişi.<sup>[[2]](#references)</sup>
- MTP/PTP üzerinden bağlanan modern telefonlar ve tabletler `USBSTOR` altında görünmeyebilir. Ayrıca `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` ve `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` konumlarını da kontrol edin.<sup>[[2]](#references)</sup>
- Bir cihazı kullanıcıyla ilişkilendirmek için cihaz veya volume identifier'larından shellbag'ler, LNK'ler, Jump List'ler, `RecentDocs` ve `MountPoints2` gibi kullanıcı bazlı artifact'lere pivot yapın.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
