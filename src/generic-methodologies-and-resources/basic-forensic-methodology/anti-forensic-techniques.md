# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Bir saldırgan, **dosyaların zaman damgalarını değiştirmekle** ilgilenebilir.\
Zaman damgalarını, `$STANDARD_INFORMATION` \_\_ ve \_\_ `$FILE_NAME` öznitelikleri içinde bulmak mümkündür.

Her iki öznitelik de 4 zaman damgasına sahiptir: **Değiştirme**, **erişim**, **oluşturma** ve **MFT kayıt değişikliği** (MACE veya MACB).

**Windows gezgini** ve diğer araçlar, **`$STANDARD_INFORMATION`** içindeki bilgileri gösterir.

### TimeStomp - Anti-forensic Tool

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgilerini **değiştirir** **ama** **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle, **şüpheli** **faaliyetleri** **belirlemek** mümkündür.

### Usnjrnl

**USN Journal** (Güncelleme Sırası Numarası Günlüğü), NTFS (Windows NT dosya sistemi) özelliğidir ve hacim değişikliklerini takip eder. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı, bu değişikliklerin incelenmesini sağlar.

![](<../../images/image (801).png>)

Önceki resim, **dosyaya bazı değişiklikler yapıldığını** gözlemleyebileceğiniz **araç** tarafından gösterilen **çıktıdır**.

### $LogFile

**Bir dosya sistemine yapılan tüm meta veri değişiklikleri**, [ön yazma günlüğü](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir süreçte kaydedilir. Kaydedilen meta veriler, NTFS dosya sisteminin kök dizininde bulunan `**$LogFile**` adlı bir dosyada tutulur. [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar, bu dosyayı ayrıştırmak ve değişiklikleri belirlemek için kullanılabilir.

![](<../../images/image (137).png>)

Yine, aracın çıktısında **bazı değişikliklerin yapıldığını** görmek mümkündür.

Aynı aracı kullanarak, **zaman damgalarının hangi zamana kadar değiştirildiğini** belirlemek mümkündür:

![](<../../images/image (1089).png>)

- CTIME: Dosyanın oluşturulma zamanı
- ATIME: Dosyanın değiştirilme zamanı
- MTIME: Dosyanın MFT kayıt değişikliği
- RTIME: Dosyanın erişim zamanı

### `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli değiştirilmiş dosyaları belirlemenin bir diğer yolu, her iki öznitelikteki zamanı karşılaştırarak **uyumsuzluklar** aramaktır.

### Nanoseconds

**NTFS** zaman damgalarının **kesinliği** **100 nanosecond**'dir. Bu nedenle, 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyaları bulmak **çok şüphelidir**.

### SetMace - Anti-forensic Tool

Bu araç, hem `$STARNDAR_INFORMATION` hem de `$FILE_NAME` özniteliklerini değiştirebilir. Ancak, Windows Vista'dan itibaren, bu bilgileri değiştirmek için canlı bir işletim sistemine ihtiyaç vardır.

## Data Hiding

NFTS, bir küme ve minimum bilgi boyutu kullanır. Bu, bir dosya bir buçuk küme kapladığında, **kalan yarının asla kullanılmayacağı** anlamına gelir. Bu nedenle, bu boşlukta **veri gizlemek** mümkündür.

Slacker gibi, bu "gizli" alanda veri gizlemeye olanak tanıyan araçlar vardır. Ancak, `$logfile` ve `$usnjrnl` analizi, bazı verilerin eklendiğini gösterebilir:

![](<../../images/image (1060).png>)

Daha sonra, FTK Imager gibi araçlar kullanarak boş alanı geri almak mümkündür. Bu tür araçların içeriği obfuscate veya hatta şifreli olarak kaydedebileceğini unutmayın.

## UsbKill

Bu, **USB** portlarında herhangi bir değişiklik tespit edildiğinde bilgisayarı **kapatan** bir araçtır.\
Bunu keşfetmenin bir yolu, çalışan süreçleri incelemek ve **her bir python betiğini gözden geçirmektir**.

## Live Linux Distributions

Bu dağıtımlar **RAM** belleği içinde **çalıştırılır**. Onları tespit etmenin tek yolu, **NTFS dosya sisteminin yazma izinleriyle monte edilmesidir**. Sadece okuma izinleriyle monte edilirse, ihlali tespit etmek mümkün olmayacaktır.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Forensik araştırmayı çok daha zor hale getirmek için birçok Windows günlüğü yöntemini devre dışı bırakmak mümkündür.

### Disable Timestamps - UserAssist

Bu, her çalıştırılan yürütülebilir dosyanın tarihlerini ve saatlerini koruyan bir kayıt anahtarıdır.

UserAssist'i devre dışı bırakmak iki adım gerektirir:

1. UserAssist'i devre dışı bırakmak istediğimizi belirtmek için `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` adlı iki kayıt anahtarını sıfıra ayarlayın.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` gibi görünen kayıt alt ağaçlarınızı temizleyin.

### Disable Timestamps - Prefetch

Bu, Windows sisteminin performansını artırmak amacıyla çalıştırılan uygulamalar hakkında bilgi kaydedecektir. Ancak, bu forensik uygulamalar için de yararlı olabilir.

- `regedit` çalıştırın
- Dosya yolunu seçin `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Hem `EnablePrefetcher` hem de `EnableSuperfetch` üzerinde sağ tıklayın
- Her birinin değerini 1 (veya 3) yerine 0 olarak değiştirmek için Değiştir'i seçin
- Yeniden başlatın

### Disable Timestamps - Last Access Time

Bir NTFS hacminden bir klasör açıldığında, sistem, listedeki her klasör için **bir zaman damgası alanını güncellemek için zamanı alır**, bu alana son erişim zamanı denir. Yoğun kullanılan bir NTFS hacminde, bu performansı etkileyebilir.

1. Kayıt Defteri Düzenleyicisini (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` yoluna gidin.
3. `NtfsDisableLastAccessUpdate` anahtarını arayın. Eğer yoksa, bu DWORD'u ekleyin ve değerini 1 olarak ayarlayın, bu işlem devre dışı bırakılacaktır.
4. Kayıt Defteri Düzenleyicisini kapatın ve sunucuyu yeniden başlatın.

### Delete USB History

Tüm **USB Aygıt Girişleri**, bir USB Aygıtını PC veya Dizüstü Bilgisayarınıza taktığınızda oluşturulan alt anahtarları içeren **USBSTOR** kayıt anahtarı altında Windows Kayıt Defteri'nde saklanır. Bu anahtarı burada bulabilirsiniz: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bunu silerek** USB geçmişini sileceksiniz.\
Ayrıca, bunları sildiğinizden emin olmak için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) aracını kullanabilirsiniz (ve silmek için).

USB'ler hakkında bilgi kaydeden bir diğer dosya, `C:\Windows\INF` içindeki `setupapi.dev.log` dosyasıdır. Bu dosya da silinmelidir.

### Disable Shadow Copies

**Gölge kopyaları listeleyin** `vssadmin list shadowstorage`\
**Silin** `vssadmin delete shadow` komutunu çalıştırarak

Ayrıca, [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresinde önerilen adımları izleyerek GUI üzerinden de silebilirsiniz.

Gölge kopyalarını devre dışı bırakmak için [buradaki adımları](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) izleyin:

1. Windows başlat düğmesine tıkladıktan sonra metin arama kutusuna "services" yazarak Hizmetler programını açın.
2. Listeden "Volume Shadow Copy"yi bulun, seçin ve sağ tıklayarak Özellikler'e erişin.
3. "Başlangıç türü" açılır menüsünden Devre Dışı seçeneğini seçin ve ardından değişikliği onaylamak için Uygula ve Tamam'a tıklayın.

Hangi dosyaların gölge kopyasında kopyalanacağını yapılandırmayı da kayıt defterinde `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` değiştirerek yapabilirsiniz.

### Overwrite deleted files

- **Windows aracı** kullanabilirsiniz: `cipher /w:C` Bu, şifreleme aracına C sürücüsündeki kullanılmayan disk alanından herhangi bir veriyi kaldırmasını belirtir.
- Ayrıca [**Eraser**](https://eraser.heidi.ie) gibi araçlar da kullanabilirsiniz.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Günlükleri"ni genişletin --> Her kategoriye sağ tıklayın ve "Günlüğü Temizle"yi seçin
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Hizmetler bölümünde "Windows Olay Günlüğü" hizmetini devre dışı bırakın
- `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Son Windows 10/11 ve Windows Server sürümleri, `Microsoft-Windows-PowerShell/Operational` altında **zengin PowerShell forensik kalıntıları** tutar (olaylar 4104/4105/4106). Saldırganlar bunları anlık olarak devre dışı bırakabilir veya silebilir:
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
Tespit: bellek içindeki `ntdll`'yi disk ile karşılaştırın veya kullanıcı modundan önce hook yapın.

### Alternatif Veri Akışları (ADS) Yeniden Canlanması

2023'teki kötü amaçlı yazılım kampanyalarında (örneğin **FIN12** yükleyicileri) geleneksel tarayıcılardan kaçınmak için ADS içinde ikinci aşama ikili dosyaları sahneleme yaparken görüldü:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Akışları `dir /R`, `Get-Item -Stream *` veya Sysinternals `streams64.exe` ile listeleyin. Ana makine dosyasını FAT/exFAT'a veya SMB üzerinden kopyalamak gizli akışı kaldırır ve bu, araştırmacılar tarafından yükü geri almak için kullanılabilir.

### BYOVD & “AuKill” (2023)

Kendi Zayıf Sürücünüzü Getirin, fidye yazılımı saldırılarında **anti-forensics** için artık rutin olarak kullanılmaktadır. Açık kaynaklı araç **AuKill**, şifreleme ve günlük yok etmeden **önce** EDR ve adli sensörleri askıya almak veya sonlandırmak için imzalı ancak zayıf bir sürücü (`procexp152.sys`) yükler:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Sürücü daha sonra kaldırılır, minimum artefakt bırakır.  
Önlemler: Microsoft'un savunmasız sürücü kara listesini (HVCI/SAC) etkinleştirin ve kullanıcı yazılabilir yollarından kernel hizmeti oluşturulması hakkında uyarı verin.

---

## Linux Anti-Forensics: Kendinden Yamanma ve Bulut C2 (2023–2025)

### Kendinden yamanma ile tehlikeye atılmış hizmetleri tespit oranını azaltma (Linux)  
Düşmanlar, yeniden istismar edilmesini önlemek ve zafiyet tabanlı tespitleri bastırmak için bir hizmeti istismar ettikten hemen sonra giderek daha fazla "kendinden yamanma" yapmaktadır. Amaç, savunmasız bileşenleri en son meşru yukarı akış ikili/jar'ları ile değiştirmektir, böylece tarayıcılar ana bilgisayarı yamanmış olarak rapor ederken kalıcılık ve C2 devam eder.

Örnek: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- İstismar sonrası, saldırganlar Maven Central'dan (repo1.maven.org) meşru jar'ları aldı, ActiveMQ kurulumundaki savunmasız jar'ları sildi ve aracıyı yeniden başlattı.  
- Bu, diğer ayak başlarını (cron, SSH yapılandırma değişiklikleri, ayrı C2 implantları) korurken başlangıçtaki RCE'yi kapattı.

Operasyonel örnek (gösterim amaçlı)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Forensic/hunting tips
- Zamanlanmamış ikili/JAR değişiklikleri için hizmet dizinlerini gözden geçirin:
- Debian/Ubuntu: `dpkg -V activemq` ve dosya hash'lerini/yollarını repo aynalarıyla karşılaştırın.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Paket yöneticisi tarafından sahiplenilmeyen veya dışarıdan güncellenmiş sembolik bağlantılar için disk üzerinde mevcut JAR sürümlerini arayın.
- Zaman çizelgesi: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` ile ctime/mtime'yi uzlaşma penceresiyle ilişkilendirin.
- Shell geçmişi/proses telemetresi: ilk istismar sonrası `curl`/`wget` ile `repo1.maven.org` veya diğer artefakt CDN'lerine dair kanıt.
- Değişiklik yönetimi: “yamanın” kim tarafından ve neden uygulandığını doğrulayın, sadece yamanmış bir sürümün mevcut olduğunu değil.

### Cloud‑service C2 with bearer tokens and anti‑analysis stagers
Gözlemlenen ticaret, birden fazla uzun mesafe C2 yolu ve anti-analiz paketlemesini birleştirdi:
- Sandbox'lamayı ve statik analizi engellemek için şifre korumalı PyInstaller ELF yükleyicileri (örneğin, şifreli PYZ, `/_MEI*` altında geçici çıkarım).
- Göstergeler: `strings` ile `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` gibi hitler.
- Çalışma zamanı artefaktları: `/tmp/_MEI*` veya özel `--runtime-tmpdir` yollarına çıkarım.
- Hardcoded OAuth Bearer token'ları kullanan Dropbox destekli C2
- Ağ işaretleri: `api.dropboxapi.com` / `content.dropboxapi.com` ile `Authorization: Bearer <token>`.
- Normalde dosya senkronize etmeyen sunucu iş yüklerinden Dropbox alanlarına outbound HTTPS için proxy/NetFlow/Zeek/Suricata'da avlanın.
- Bir kanal engellendiğinde kontrolü koruyarak tünelleme (örneğin, Cloudflare Tunnel `cloudflared`) ile paralel/yedek C2.
- Host IOCs: `cloudflared` süreçleri/birimleri, `~/.cloudflared/*.json` konfigürasyonu, Cloudflare kenarlarına outbound 443.

### Persistence and “hardening rollback” to maintain access (Linux examples)
Saldırganlar genellikle kendini yamanayı dayanıklı erişim yollarıyla birleştirir:
- Cron/Anacron: her `/etc/cron.*/` dizinindeki `0anacron` stub'unda düzenlemeler yaparak periyodik yürütme.
- Avlanma:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH konfigürasyonu sertleştirme geri alma: root girişlerini etkinleştirme ve düşük ayrıcalıklı hesaplar için varsayılan shell'leri değiştirme.
- Root girişini etkinleştirme için avlanma:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# "yes" gibi bayrak değerleri veya aşırı izinli ayarlar
```
- Sistem hesaplarında şüpheli etkileşimli shell'ler için avlanma (örneğin, `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Disk'e bırakılan ve bulut C2 ile de iletişim kuran rastgele, kısa isimli beacon artefaktları (8 alfabetik karakter):
- Avlanma:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Savunucular, bu artefaktları dışa açılma ve hizmet yamanma olaylarıyla ilişkilendirerek, ilk istismarı gizlemek için kullanılan anti-forensic kendini düzeltme yöntemlerini ortaya çıkarmalıdır.

## References

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (Mart 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (Haziran 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
