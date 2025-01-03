{{#include ../../banners/hacktricks-training.md}}

# Zaman Damgaları

Bir saldırgan, **dosyaların zaman damgalarını değiştirmekle** ilgilenebilir.\
Zaman damgalarını, MFT içinde `$STANDARD_INFORMATION` **ve** `$FILE_NAME` özniteliklerinde bulmak mümkündür.

Her iki öznitelik de 4 zaman damgasına sahiptir: **Değiştirme**, **erişim**, **oluşturma** ve **MFT kayıt değişikliği** (MACE veya MACB).

**Windows Gezgini** ve diğer araçlar, **`$STANDARD_INFORMATION`** içindeki bilgileri gösterir.

## TimeStomp - Anti-forensic Aracı

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgilerini **değiştirir** **ancak** **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle, **şüpheli** **etkinlikleri** **belirlemek** mümkündür.

## Usnjrnl

**USN Journal** (Güncelleme Sırası Numarası Günlüğü), NTFS (Windows NT dosya sistemi) özelliğidir ve hacim değişikliklerini takip eder. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı, bu değişikliklerin incelenmesini sağlar.

![](<../../images/image (449).png>)

Önceki görüntü, dosya üzerinde bazı **değişikliklerin yapıldığını** gözlemleyebileceğimiz **aracın** gösterdiği **çıktıdır**.

## $LogFile

**Bir dosya sistemine yapılan tüm meta veri değişiklikleri**, [ön yazma günlüğü](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir süreçte kaydedilir. Kaydedilen meta veriler, NTFS dosya sisteminin kök dizininde bulunan `**$LogFile**` adlı bir dosyada tutulur. [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar, bu dosyayı ayrıştırmak ve değişiklikleri belirlemek için kullanılabilir.

![](<../../images/image (450).png>)

Yine, aracın çıktısında **bazı değişikliklerin yapıldığını** görmek mümkündür.

Aynı aracı kullanarak, **zaman damgalarının hangi zamana kadar değiştirildiğini** belirlemek mümkündür:

![](<../../images/image (451).png>)

- CTIME: Dosyanın oluşturulma zamanı
- ATIME: Dosyanın değiştirilme zamanı
- MTIME: Dosyanın MFT kayıt değişikliği
- RTIME: Dosyanın erişim zamanı

## `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli değiştirilmiş dosyaları belirlemenin bir diğer yolu, her iki öznitelikteki zamanı karşılaştırarak **uyumsuzluklar** aramaktır.

## Nanosecond

**NTFS** zaman damgalarının **kesinliği** **100 nanosecond**'dir. Bu nedenle, 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyaları bulmak **çok şüphelidir**.

## SetMace - Anti-forensic Aracı

Bu araç, hem `$STARNDAR_INFORMATION` hem de `$FILE_NAME` özniteliklerini değiştirebilir. Ancak, Windows Vista'dan itibaren, bu bilgileri değiştirmek için canlı bir işletim sistemine ihtiyaç vardır.

# Veri Gizleme

NFTS, bir küme ve minimum bilgi boyutu kullanır. Bu, bir dosya bir buçuk küme kaplıyorsa, **kalan yarının asla kullanılmayacağı** anlamına gelir. Bu nedenle, bu boşlukta **veri gizlemek mümkündür**.

Slacker gibi, bu "gizli" alanda veri gizlemeye olanak tanıyan araçlar vardır. Ancak, `$logfile` ve `$usnjrnl` analizi, bazı verilerin eklendiğini gösterebilir:

![](<../../images/image (452).png>)

Bu nedenle, FTK Imager gibi araçlar kullanarak boş alanı geri almak mümkündür. Bu tür araçların içeriği obfuscate veya hatta şifreli olarak kaydedebileceğini unutmayın.

# UsbKill

Bu, **USB** portlarında herhangi bir değişiklik tespit edildiğinde bilgisayarı **kapatan** bir araçtır.\
Bunu keşfetmenin bir yolu, çalışan süreçleri incelemek ve **her bir python betiğini gözden geçirmektir**.

# Canlı Linux Dağıtımları

Bu dağıtımlar, **RAM** belleği içinde **çalıştırılır**. Onları tespit etmenin tek yolu, **NTFS dosya sisteminin yazma izinleriyle monte edilmesidir**. Sadece okuma izinleriyle monte edilirse, ihlali tespit etmek mümkün olmayacaktır.

# Güvenli Silme

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows Yapılandırması

Adli soruşturmayı çok daha zor hale getirmek için birçok Windows günlüğü yöntemini devre dışı bırakmak mümkündür.

## Zaman Damgalarını Devre Dışı Bırak - UserAssist

Bu, her çalıştırılan yürütülebilir dosyanın tarihlerini ve saatlerini koruyan bir kayıt anahtarıdır.

UserAssist'i devre dışı bırakmak iki adım gerektirir:

1. UserAssist'i devre dışı bırakmak istediğimizi belirtmek için `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` adlı iki kayıt anahtarını sıfıra ayarlayın.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` gibi görünen kayıt alt ağaçlarınızı temizleyin.

## Zaman Damgalarını Devre Dışı Bırak - Prefetch

Bu, Windows sisteminin performansını artırmak amacıyla çalıştırılan uygulamalar hakkında bilgi kaydedecektir. Ancak, bu adli uygulamalar için de faydalı olabilir.

- `regedit` çalıştırın
- Dosya yolunu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` seçin
- `EnablePrefetcher` ve `EnableSuperfetch` üzerinde sağ tıklayın
- Her birinin değerini 1 (veya 3) yerine 0 olarak değiştirmek için Değiştir'i seçin
- Yeniden başlatın

## Zaman Damgalarını Devre Dışı Bırak - Son Erişim Zamanı

Bir NTFS hacminden bir klasör açıldığında, sistem, listedeki her klasör için **bir zaman damgası alanını güncellemek için zamanı alır**, buna son erişim zamanı denir. Yoğun kullanılan bir NTFS hacminde, bu performansı etkileyebilir.

1. Kayıt Defteri Düzenleyicisini (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` yoluna gidin.
3. `NtfsDisableLastAccessUpdate` anahtarını arayın. Eğer yoksa, bu DWORD'u ekleyin ve değerini 1 olarak ayarlayın, bu işlem devre dışı bırakılacaktır.
4. Kayıt Defteri Düzenleyicisini kapatın ve sunucuyu yeniden başlatın.

## USB Geçmişini Sil

Tüm **USB Aygıt Girişleri**, bir USB Aygıtını PC veya dizüstü bilgisayarınıza taktığınızda oluşturulan alt anahtarları içeren **USBSTOR** kayıt anahtarı altında Windows Kayıt Defteri'nde saklanır. Bu anahtarı burada bulabilirsiniz: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bunu silerek**, USB geçmişini sileceksiniz.\
Ayrıca, silindiğinizden emin olmak için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) aracını kullanabilirsiniz (ve silmek için).

USB'ler hakkında bilgi kaydeden bir diğer dosya, `C:\Windows\INF` içindeki `setupapi.dev.log` dosyasıdır. Bu dosya da silinmelidir.

## Gölge Kopyalarını Devre Dışı Bırak

**Gölge kopyaları listeleyin**: `vssadmin list shadowstorage`\
**Silin**: `vssadmin delete shadow`

Ayrıca, [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresinde önerilen adımları izleyerek GUI üzerinden de silebilirsiniz.

Gölge kopyalarını devre dışı bırakmak için [buradaki adımları](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) izleyebilirsiniz:

1. Windows başlat düğmesine tıkladıktan sonra metin arama kutusuna "services" yazarak Hizmetler programını açın.
2. Listeden "Volume Shadow Copy"yi bulun, seçin ve sağ tıklayarak Özellikler'e erişin.
3. "Başlangıç türü" açılır menüsünden Devre Dışı seçeneğini seçin ve ardından değişikliği onaylamak için Uygula ve Tamam'a tıklayın.

Hangi dosyaların gölge kopyasında kopyalanacağını yapılandırmayı da kayıt defterinde `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` ile değiştirmek mümkündür.

## Silinmiş Dosyaları Üzerine Yaz

- **Windows aracı** kullanabilirsiniz: `cipher /w:C` Bu, şifreleme aracına C sürücüsündeki kullanılmayan disk alanından herhangi bir veriyi kaldırmasını belirtir.
- Ayrıca, [**Eraser**](https://eraser.heidi.ie) gibi araçlar da kullanabilirsiniz.

## Windows Olay Günlüklerini Sil

- Windows + R --> eventvwr.msc --> "Windows Günlükleri"ni genişletin --> Her kategoriye sağ tıklayın ve "Günlüğü Temizle"yi seçin
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Windows Olay Günlüklerini Devre Dışı Bırak

- `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Hizmetler bölümünde "Windows Olay Günlüğü" hizmetini devre dışı bırakın
- `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl`

## $UsnJrnl'yi Devre Dışı Bırak

- `fsutil usn deletejournal /d c:`

{{#include ../../banners/hacktricks-training.md}}
