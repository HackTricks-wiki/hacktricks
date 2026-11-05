# İlginç Windows Registry Anahtarları

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive’ları, _ne oldu?_ sorusundan _hangi kullanıcı, ne zaman ve nereden?_ sorularına geçmenin en hızlı yollarından biridir. Canlı analizde `CurrentControlSet` kullanın; çevrimdışı hive analizinde `ControlSet001` değerini sabit kodlamak yerine önce hangi `ControlSet00x` değerinin etkin olduğunu belirleyin.

### Windows Sürümü ve Sahip Bilgileri

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows sürümü/build’i, kurulum zamanı, kayıtlı sahip, ürün adı ve diğer build meta verileri.
- `SYSTEM\Select`: `Current`, `Default` ve `LastKnownGood` değerlerini sistemin kullandığı gerçek `ControlSet00x` değerlerine eşler.

### Bilgisayar Adı

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: geçerli hostname.

### Saat Dilimi Ayarı

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: yapılandırılmış saat dilimi ve DST ile ilgili değerler.

### Erişim Zamanı Takibi

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate`, NTFS’in son erişim zaman damgalarını güncelleyip güncellemediğini belirtir.
- Etkinleştirmek için şunu kullanın: `fsutil behavior set disablelastaccess 0`

### Kapatma Ayrıntıları

- `SYSTEM\CurrentControlSet\Control\Windows`: son kapatma zamanı.
- Eski sistemlerde kapatma sayaçları `SYSTEM\CurrentControlSet\Control\Watchdog\Display` altında da bulunabilir.

### Ağ Yapılandırması

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: arabirim IP’leri, DHCP kiraları, ağ geçidi ve DNS verileri.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: ağ profili adı/SSID ile ilk ve son bağlantı zamanları.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` ve `...\Unmanaged\{GUID}`: ağ geçidinin MAC adresi ve DNS suffix’i gibi profil ilişkilendirme verileri.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: ana bilgisayarın yayımladığı yerel paylaşılan klasörler.

### Uzaktan Erişim ve Ağ Paylaşımı Geçmişi

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: giden RDP MRU listesi (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: ana bilgisayara göre giden RDP geçmişi. Alt anahtarlarda genellikle `UsernameHint` bulunur; anahtarın `LastWrite` zamanı da yararlı bir inceleme noktasıdır.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: belirli bir kullanıcıya bağlı eşlenmiş ağ sürücüleri, UNC paylaşımları ve çıkarılabilir medya bağlama noktaları.

### Otomatik Başlayan Programlar ve Zamanlanmış Kalıcılık

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` ve `...\Tasks\{GUID}`: zamanlanmış görev meta verileri. Burada bir görev varsa ancak `Tree\<TaskName>` altında `SD` değeri yoksa, gizli Tarrask tarzı görev kurcalamasından şüphelenin ve bunu `C:\Windows\System32\Tasks\<TaskName>` ile ilişkilendirin.

### Aramalar, Yazılan Yollar ve MRU’lar

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer arama terimleri.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer’a elle yazılan yollar.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: son 26 `Win + R` komutu. `MRUList` bunların sırasını korur.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: yakın zamanda açılan belgeler ve klasörler.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office’te son kullanılan dosyalar.

### Kullanıcı Etkinliği Takibi

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI üzerinden başlatılan işlemlerin geçmişi. Değer adları ROT13 ile kodlanmıştır; ikili veriler çalıştırma sayaçlarını ve son çalıştırma zamanını içerir.<sup>[[1]](#references)</sup>
- `UserAssist` kayıtlarını tek başına kesin kanıt olarak değil, güçlü destekleyici kanıt olarak değerlendirin: bu kayıtlar çoğunlukla Explorer üzerinden başlatılan uygulamaları veya `.lnk` dosyalarını izler; komut satırı ya da hizmet üzerinden çalıştırmaları gözden kaçırabilir. Windows 10 ve sonraki sürümlerde bazı kayıtlar işlemin gerçekten çalıştığı anlamına gelmeyebilir.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` ve `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID ataması ve son çalıştırma zamanı bilgisi içeren modern Windows 10/11 çalıştırma izleri. Bunlar özellikle yerel olarak çalıştırılan ikili dosyalar için yararlıdır; ancak eski kayıtlar kısa sürede silinebilir ve ağ paylaşımlarından/çıkarılabilir medyadan yapılan çalıştırmalar daha az güvenilirdir.
- Prefetch, Amcache, ShimCache ve SRUM gibi daha kapsamlı çalıştırma izleri için ana [Windows forensics overview](./#programs-executed) sayfasına bakın.

### Shellbag’ler

- Shellbag’ler hem `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` hem de `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` konumlarında saklanır.<sup>[[1]](#references)</sup>
- `NTUSER.DAT` kayıtları UNC/ağ gezinmesi için özellikle yararlıyken, Windows Vista ve sonraki sürümlerde yerel/çıkarılabilir klasörlere ait shellbag’ler genellikle `UsrClass.dat` içinde saklanır.
- Klasör silinmiş olsa bile klasörün varlığını, klasörlerde gezinildiğini ve klasör görünümü tercihlerini gösterebilirler. Arşiv dosyalarına Explorer benzeri erişim de shellbag izleri bırakabilir.<sup>[[1]](#references)</sup>
- Her shellbag klasöre başarıyla erişildiğini kanıtlamaz; bu nedenle bulguları LNK’ler, Jump List’ler, zaman damgaları veya birim eşlemeleriyle doğrulayın.
- Bunları ayrıştırmak için **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** veya **SBECmd** kullanın.

### USB Bilgileri

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB yığın depolama aygıtlarının temel envanteri (üretici, ürün, revizyon, seri numarası/aygıt örneği).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: depolama aygıtları dışındakiler de dahil olmak üzere daha kapsamlı USB aygıt envanteri.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: güncel Windows 10/11 build’lerinde aygıta özel kurulum, ilk kurulum, son bağlanma ve son çıkarılma gibi yaşam döngüsü zaman damgaları için değerli bir konumdur.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: birimleri ve aygıt tanımlayıcılarını sürücü harflerine / birim GUID’lerine eşler. Belirli bir sürücü harfi için yalnızca son eşleme kalmış olabilir.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: birim seri numaraları ve önceki medya meta verileri için yararlı bir inceleme noktasıdır.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: kullanıcıya özel sürücü harfi ve paylaşım etkileşimi geçmişi.<sup>[[2]](#references)</sup>
- MTP/PTP üzerinden bağlanan modern telefonlar ve tabletler `USBSTOR` altında görünmeyebilir. `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` ve `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` konumlarını da kontrol edin.<sup>[[2]](#references)</sup>
- Bir aygıtı kullanıcıyla ilişkilendirmek için aygıt veya birim tanımlayıcılarından shellbag, LNK, Jump List, `RecentDocs` ve `MountPoints2` gibi kullanıcıya özel izlere geçin.<sup>[[2]](#references)</sup>



## References

- [1] [Windows Registry Forensics Hızlı Başvuru Sayfası 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Windows 10 ve 11’de USB Aygıtı Forensics’i - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
