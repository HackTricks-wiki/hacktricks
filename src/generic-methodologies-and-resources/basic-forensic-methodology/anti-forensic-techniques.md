# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Bir saldırgan, tespit edilmekten kaçınmak için **dosyaların zaman damgalarını değiştirmekle** ilgilenebilir.\
Zaman damgalarını MFT içindeki `$STANDARD_INFORMATION` \_\_ ve \_\_ `$FILE_NAME` özniteliklerinde bulmak mümkündür.

Her iki öznitelikte de 4 zaman damgası bulunur: **Modification**, **access**, **creation** ve **MFT registry modification** (MACE veya MACB).

**Windows Explorer** ve diğer araçlar, **`$STANDARD_INFORMATION`** içindeki bilgileri gösterir.

### TimeStomp - Anti-forensic Tool

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgilerini **değiştirir**, **ancak** **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle, **şüpheli etkinlikleri** **tespit etmek** mümkündür.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), birim değişikliklerini takip eden NTFS (Windows NT file system) özelliğidir. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı bu değişikliklerin incelenmesini sağlar.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal), birim değişikliklerini takip eden NTFS (Windows NT file system) özelliğidir. ...](<../../images/image (801).png>)

Önceki görsel, **dosyada bazı değişiklikler yapıldığını** gösteren aracın **çıktısıdır**.

### $LogFile

Bir file system üzerindeki **tüm metadata değişiklikleri**, [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) adı verilen bir süreçle kaydedilir. Kaydedilen metadata, NTFS file system'in kök dizininde bulunan `**$LogFile**` adlı dosyada tutulur. Bu dosyayı ayrıştırıp değişiklikleri tespit etmek için [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar kullanılabilir.

![Usnjrnl - $LogFile: Bir file system üzerindeki tüm metadata değişiklikleri, write-ahead logging adı verilen bir süreçle kaydedilir. Kaydedilen metadata, NTFS file system'in kök dizininde bulunan $LogFile adlı dosyada tutulur...](<../../images/image (137).png>)

Yine, aracın çıktısında **bazı değişikliklerin yapıldığını** görmek mümkündür.

Aynı aracı kullanarak zaman damgalarının **hangi zamanda değiştirildiğini** tespit etmek mümkündür:

![Usnjrnl - $LogFile: Aynı aracı kullanarak zaman damgalarının hangi zamanda değiştirildiğini tespit etmek mümkündür](<../../images/image (1089).png>)

- CTIME: Dosyanın oluşturulma zamanı
- ATIME: Dosyanın değiştirilme zamanı
- MTIME: Dosyanın MFT registry modification zamanı
- RTIME: Dosyaya erişim zamanı

### `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli biçimde değiştirilmiş dosyaları tespit etmenin bir başka yolu, **uyuşmazlıkları** bulmak için her iki öznitelikteki zamanları karşılaştırmaktır.

### Nanoseconds

**NTFS** zaman damgalarının **hassasiyeti** **100 nanoseconds** düzeyindedir. Bu nedenle, 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyalar bulmak çok şüphelidir**.

### SetMace - Anti-forensic Tool

Bu araç, hem `$STARNDAR_INFORMATION` hem de `$FILE_NAME` özniteliklerini değiştirebilir. Ancak Windows Vista'dan itibaren bu bilgileri değiştirmek için çalışan bir OS gerekir.

## Data Hiding

NFTS bir cluster ve minimum bilgi boyutu kullanır. Bunun anlamı, bir dosya bir buçuk cluster kaplıyorsa, dosya silinene kadar **kalan yarım cluster'ın hiçbir zaman kullanılmayacağıdır**. Bu durumda **slack space içinde veri gizlemek** mümkündür.

slacker gibi araçlar verileri bu "gizli" alanda saklamaya olanak tanır. Ancak `$logfile` ve `$usnjrnl` üzerinde yapılacak bir analiz, bazı verilerin eklendiğini gösterebilir:

![SetMace - Anti-forensic Tool - Data Hiding: slacker gibi araçlar verileri bu "gizli" alanda saklamaya olanak tanır. Ancak $logfile ve $usnjrnl üzerinde yapılacak bir analiz...](<../../images/image (1060).png>)

Ardından, FTK Imager gibi araçlar kullanarak slack space'i kurtarmak mümkündür. Bu tür araçların içeriği gizlenmiş, hatta şifrelenmiş biçimde kaydedebileceğini unutmayın.

## UsbKill

Bu araç, USB portlarında herhangi bir değişiklik algılandığında **bilgisayarı kapatır**.\
Bunu tespit etmenin bir yolu, çalışan süreçleri incelemek ve **çalışan her Python scriptini gözden geçirmektir**.

## Live Linux Distributions

Bu dağıtımlar **RAM belleği içinde çalıştırılır**. Bunları tespit etmenin tek yolu, NTFS file system'in yazma izinleriyle bağlanmış olmasıdır. Yalnızca okuma izinleriyle bağlanmışsa izinsiz girişi tespit etmek mümkün olmaz.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Delayed Windows self-deletion

Çalışan bir Windows image, süreci etkin olduğu sırada kilitli olabilir. Bir süreç, silme işlemini bir alt `cmd.exe` sürecine devredebilir, zamanlayıcı olarak `choice` kullanabilir ve shell `del` komutuna ulaşmadan önce sonlanabilir. Bu gecikme, özgün sürecin image handle'ını serbest bırakmasını sağlar; yol boşluk içeriyorsa tam yolu tırnak içine almak gerekir.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Bu dizge başka bir etkileşimli `cmd` isteminden yazılmak yerine doğrudan `cmd.exe`'ye bağımsız değişken olarak verildiğinde, `^&` yerine `&`, `^>nul` yerine `>nul` kullanın. Bu, dizin girdisini kaldırır; **güvenli silme değildir** ve çalıştırma, görev, dosya sistemi günlüğü veya diğer adli izleri kaldırmaz. Komut satırı `choice /T`, `Del` ve üst sürecin imaj yolunu bir arada içeren kısa ömürlü `cmd.exe` alt süreçlerini araştırın.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows Yapılandırması

Adli incelemeyi çok daha zor hâle getirmek için çeşitli Windows günlükleme yöntemlerini devre dışı bırakmak mümkündür.

### Zaman Damgalarını Devre Dışı Bırakma - UserAssist

Bu, kullanıcının her yürütülebilir dosyayı çalıştırdığı tarih ve saatleri tutan bir kayıt defteri anahtarıdır.

UserAssist'i devre dışı bırakmak için iki adım gerekir:

1. UserAssist'in devre dışı bırakılmasını istediğimizi belirtmek için `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` kayıt defteri anahtarlarının ikisini de sıfıra ayarlayın.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` benzeri kayıt defteri alt ağaçlarınızı temizleyin.

### Zaman Damgalarını Devre Dışı Bırakma - Prefetch

Bu, Windows sisteminin performansını artırmak amacıyla yürütülen uygulamalar hakkındaki bilgileri kaydeder. Ancak bu bilgiler adli incelemelerde de işe yarayabilir.

- `regedit` komutunu çalıştırın
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` dosya yolunu seçin
- Hem `EnablePrefetcher` hem de `EnableSuperfetch` öğesine sağ tıklayın
- Her birinin değerini 1'den (veya 3'ten) 0'a değiştirmek için Değiştir'i seçin
- Yeniden başlatın

### Zaman Damgalarını Devre Dışı Bırakma - Son Erişim Zamanı

Windows NT sunucusunda bir NTFS birimindeki klasör her açıldığında sistem, son erişim zamanı adı verilen **listelenen her klasördeki zaman damgası alanını günceller**. Yoğun kullanılan bir NTFS biriminde bu, performansı etkileyebilir.

1. Kayıt Defteri Düzenleyicisi'ni (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` konumuna gidin.
3. `NtfsDisableLastAccessUpdate` öğesini bulun. Yoksa bu DWORD'u ekleyin ve değerini 1 olarak ayarlayarak işlemi devre dışı bırakın.
4. Kayıt Defteri Düzenleyicisi'ni kapatın ve sunucuyu yeniden başlatın.

### USB Geçmişini Silme

Tüm **USB aygıtı girdileri**, bilgisayarınıza veya dizüstü bilgisayarınıza bir USB aygıtı taktığınızda oluşturulan alt anahtarları içeren **USBSTOR** kayıt defteri anahtarında saklanır. Bu anahtarı burada bulabilirsiniz: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bu anahtarı silmek** USB geçmişini siler.\
Bunları sildiğinizden emin olmak (ve silmek) için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) aracını da kullanabilirsiniz.

USB'ler hakkındaki bilgileri kaydeden başka bir dosya da `C:\Windows\INF` içindeki `setupapi.dev.log` dosyasıdır. Bu da silinmelidir.

### Shadow Copy'leri Devre Dışı Bırakma

Shadow copy'leri `vssadmin list shadowstorage` ile **listeleyin**\
`vssadmin delete shadow` komutunu çalıştırarak **silin**

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) sayfasında önerilen adımları izleyerek GUI üzerinden de silebilirsiniz.

Shadow copy'leri devre dışı bırakmak için [buradaki adımlar](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Windows başlat düğmesine tıkladıktan sonra metin arama kutusuna "services" yazarak Hizmetler programını açın.
2. Listeden "Volume Shadow Copy" öğesini bulun ve seçin; ardından sağ tıklayıp Özellikler'e gidin.
3. "Başlangıç türü" açılır menüsünden Devre Dışı'nı seçin ve Uygula ile Tamam'a tıklayarak değişikliği onaylayın.

Kayıt defterindeki `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` ayarını değiştirerek shadow copy'de hangi dosyaların kopyalanacağını da değiştirebilirsiniz.

### Silinen dosyaların üzerine yazma

- Bir **Windows aracı** kullanabilirsiniz: `cipher /w:C`. Bu komut, C sürücüsündeki kullanılabilir boş disk alanındaki verileri kaldırması için cipher'a talimat verir.
- [**Eraser**](https://eraser.heidi.ie) gibi araçları da kullanabilirsiniz.

### Windows olay günlüklerini silme

- Windows + R --> eventvwr.msc --> "Windows Günlükleri"ni genişletin --> Her kategoriye sağ tıklayıp "Günlüğü Temizle"yi seçin
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows olay günlüklerini devre dışı bırakma

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Hizmetler bölümünde "Windows Event Log" hizmetini devre dışı bırakın
- `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl`

### $UsnJrnl'yi devre dışı bırakma

- `fsutil usn deletejournal /d c:`

---

## Gelişmiş Günlükleme ve İz Kurcalama (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11'in ve Windows Server'ın güncel sürümleri, `Microsoft-Windows-PowerShell/Operational` altında **kapsamlı PowerShell adli inceleme artefaktları** (4104/4105/4106 olayları) tutar.  
Saldırganlar bunları anında devre dışı bırakabilir veya silebilir:

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

Savunmacılar, bu kayıt defteri anahtarlarındaki değişiklikleri ve çok sayıda PowerShell olayının silinmesini izlemelidir.

### ETW (Event Tracing for Windows) Patch

Uç nokta güvenlik ürünleri büyük ölçüde ETW'ye dayanır. 2024'te yaygınlaşan bir kaçınma yöntemi, bellekteki `ntdll!EtwEventWrite`/`EtwEventWriteFull` işlevlerini yamalayarak her ETW çağrısının olay üretmeden `STATUS_SUCCESS` döndürmesini sağlamaktır:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoC'ler (örn. `EtwTiSwallow`) aynı primitive'i PowerShell veya C++ ile uygular.  
Patch **process-local** olduğundan, başka process'lerin içinde çalışan EDR'ler bunu gözden kaçırabilir.<sup>[[5]](#references)</sup>
Tespit: bellekteki `ntdll` ile disktekini karşılaştırın veya user-mode'dan önce hook edin.

### Alternate Data Streams (ADS) Yeniden Canlanması

2023'teki malware kampanyalarında (örn. **FIN12** loader'ları), geleneksel tarayıcılardan gizlenmek için ikinci aşama binary'lerinin ADS içinde saklandığı görülmüştür:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumerate stream'leri `dir /R`, `Get-Item -Stream *` veya Sysinternals `streams64.exe` ile listeleyin.
Ana dosyayı FAT/exFAT'e veya SMB üzerinden kopyalamak gizli stream'i kaldırır ve araştırmacıların payload'ı kurtarmasını sağlayabilir.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver, ransomware saldırılarında **anti-forensics** amacıyla artık rutin olarak kullanılıyor.  
Açık kaynaklı **AuKill** aracı, imzalı ancak savunmasız bir sürücüyü (`procexp152.sys`) yükleyerek **şifreleme ve logların yok edilmesinden önce** EDR ve adli bilişim sensörlerini askıya alır veya sonlandırır:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Sürücü daha sonra kaldırılır ve geride çok az iz bırakır.<sup>[[1]](#references)</sup>  
Azaltma önlemleri: Microsoft’un savunmasız sürücü engelleme listesini (HVCI/SAC) etkinleştirin
ve kullanıcı tarafından yazılabilir yollardan kernel-service oluşturulması durumunda uyarı verin.

---

## Linux Anti-Forensics: Kendi kendine yama uygulama ve Cloud C2 (2023–2025)

### Tespiti azaltmak için ele geçirilmiş servislerin kendilerine yama uygulaması (Linux)
Saldırganlar, yeniden istismar edilmesini önlemek ve güvenlik açığı tabanlı tespitleri bastırmak için bir servisi istismar ettikten hemen sonra giderek daha sık “kendilerine yama uyguluyor”. Amaç, savunmasız bileşenleri en son resmi upstream ikili dosyaları/JAR’larıyla değiştirmek; böylece kalıcılık ve C2 sürerken tarayıcıların ana bilgisayarın yamalı olduğunu bildirmesini sağlamaktır.<sup>[[3]](#references)</sup>

Örnek: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- İstismar sonrası saldırganlar Maven Central’dan (repo1.maven.org) resmi JAR’ları indirdi, ActiveMQ kurulumundaki savunmasız JAR’ları sildi ve broker’ı yeniden başlattı.
- Bu işlem ilk RCE açığını kapatırken diğer erişim noktalarını (cron, SSH yapılandırma değişiklikleri, ayrı C2 implantları) korudu.

Operasyonel örnek (açıklayıcı)
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

Adli bilişim/avcılık ipuçları
- Zamanlanmamış binary/JAR değişiklikleri için servis dizinlerini inceleyin:
  - Debian/Ubuntu: `dpkg -V activemq` komutunu çalıştırın ve dosya hash'lerini/yollarını depo yansılarıyla karşılaştırın.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Diskte bulunan ancak paket yöneticisine ait olmayan JAR sürümlerini veya harici olarak güncellenmiş sembolik bağlantıları arayın.
- Zaman çizelgesi: İhlal aralığıyla ctime/mtime değerlerini ilişkilendirmek için `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` komutunu çalıştırın.
- Shell geçmişi/süreç telemetrisi: İlk istismardan hemen sonra `repo1.maven.org` veya diğer artifact CDN'lerine `curl`/`wget` kullanıldığına dair kanıt.
- Değişiklik yönetimi: Yalnızca yamalı bir sürümün bulunduğunu değil, “yamayı” kimin ve neden uyguladığını doğrulayın.

### Bearer token'lar ve analiz karşıtı stager'lar kullanan cloud-service C2
Gözlemlenen saldırı teknikleri, birden fazla uzun süreli C2 yolu ile analiz karşıtı paketlemeyi bir arada kullanıyordu:<sup>[[3]](#references)</sup>
- Sandbox kullanımını ve statik analizi zorlaştırmak için parola korumalı PyInstaller ELF yükleyicileri (ör. şifrelenmiş PYZ, `/_MEI*` altında geçici çıkarma).
  - Göstergeler: `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` gibi `strings` eşleşmeleri.
  - Çalışma zamanı izleri: `/tmp/_MEI*` dizinine veya özel `--runtime-tmpdir` yollarına çıkarma.
- Sabit kodlanmış OAuth Bearer token'ları kullanan Dropbox tabanlı C2
  - Ağ göstergeleri: `Authorization: Bearer <token>` içeren `api.dropboxapi.com` / `content.dropboxapi.com` istekleri.
  - Normalde dosya eşitlemesi yapmayan sunucu iş yüklerinden Dropbox alan adlarına giden HTTPS trafiğini proxy/NetFlow/Zeek/Suricata kayıtlarında arayın.
- Kanallardan biri engellenirse denetimi sürdürmek için tünelleme üzerinden paralel/yedek C2 (ör. Cloudflare Tunnel `cloudflared`).
  - Ana makine IOC'leri: `cloudflared` süreçleri/birimleri, `~/.cloudflared/*.json` konumundaki yapılandırma, Cloudflare uçlarına giden 443 numaralı port trafiği.

### Erişimi sürdürmek için kalıcılık ve “hardening geri alma” (Linux örnekleri)
Saldırganlar, kendini yamalamayı sıklıkla kalıcı erişim yollarıyla birleştirir:<sup>[[3]](#references)</sup>
- Cron/Anacron: Periyodik çalıştırma için her `/etc/cron.*/` dizinindeki `0anacron` taslağında yapılan değişiklikler.
  - Araştırın:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- SSH yapılandırması sağlamlaştırmasını geri alma: root login'leri etkinleştirme ve düşük ayrıcalıklı hesapların varsayılan shell'lerini değiştirme.
  - root login'lerin etkinleştirilmesini araştırın:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Sistem hesaplarında (örn. `games`) şüpheli etkileşimli shell'leri araştırın:
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Diske bırakılan ve cloud C2 ile de iletişim kuran rastgele, kısa adlı beacon artifact'leri (8 alfabetik karakter):
  - Ara:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Savunmacılar, ilk istismarı gizlemek için kullanılan anti-forensic kendi kendini düzeltme işlemlerini ortaya çıkarmak amacıyla bu artefaktları dışa açık olma ve servis yamalama olaylarıyla ilişkilendirmelidir.

## Statik gömülü kabuk yürütmesi

Gömülü bir yorumlayıcı ve komut uygulamaları içeren bir betik sarmalayıcı, desteklenen kabuk işlemlerini `/bin/sh` ve ayrı yardımcı program süreçlerini başlatmak yerine tek bir yürütülebilir dosyanın içinde çalıştırabilir. HimitsuShell, bu tür statik bir musl ikilisi oluşturur. [SHc sarmalayıcılarının](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md) aksine, yerleşik komutlarının ana kabuğu veya ayrı bir yardımcı program sürecini başlatması gerekmez. Desteklenmeyen komutlar sistem kabuğuna devredilebilir.<sup>[[9]](#references)</sup>

Bu, kabuk süreçlerinin ve alt `execve` çağrılarının görünürlüğünü azaltır.<sup>[[9]](#references)</sup> Sarmalayıcı süreci ve sistem çağrıları çekirdek izleme noktaları üzerinden gözlemlenebilir; bu nedenle projenin çekirdek izleme araçları tarafından bile görülemez olduğu iddiası kelimesi kelimesine alınmamalıdır.<sup>[[9]](#references)[[11]](#references)</sup>

Belgelenen x86_64 derlemesi için girdi dosyasını `launcher.sh` adıyla tutun ve derlemeden önce kapsayıcıya kopyalayın. Çıktı `safeLauncher` olur:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

Herkese açık `compile.sh`, betiği AES-256-CTR ile şifreler, sona erme değerini ve ara anahtarları/IV’leri AES-256-CBC ile şifreler, şifrelenmiş dosyaları `xxd -i` ile C dizilerine dönüştürür ve bunları `-static -s` kullanarak `lib.bc` ile bağlar. Son şifreleme anahtarı ve IV de dosyaya gömülüdür; dolayısıyla bu, gelişigüzel statik çıkarımlara karşı koruma sağlar, asla kurtarılamayacak bir sır değildir.<sup>[[10]](#references)</sup>

Varsayılan LLVM geçişleri `-sobf` ve `-sub` şeklindedir. Belgelenmiş alternatifleri (control-flow flattening (`fla`) veya bogus control flow (`bcf`) gibi) etkinleştirmek için derlemeden önce `/var/work/compile.sh` dosyasını düzenleyin.<sup>[[9]](#references)[[10]](#references)</sup>

Bu wrapper’a güvenmeden önce betik uyumluluğunu test edin: proje POSIX shell sözdizimini hedefler, Bash/Zsh betiklerinin çalışmayabileceği konusunda uyarır ve yerleşik komut kümesinin dışındaki komutların sistem shell’ini çağırdığını belirtir.<sup>[[9]](#references)</sup>

Düzleştirilmiş control flow analizi için bkz. [dar bir yürütme dilimiyle düzleştirilmiş control flow’u atlatma](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: EDR’yi devre dışı bırakmak için silahlandırılmış savunmasız bir sürücü (Mart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Gizlilik için EtwEventWrite’ı yamalama: Tespit ve tehdit avcılığı (Haziran 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Kalıcılık için yama uygulama: DripDropper Linux malware’i bulutta nasıl ilerliyor](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [.NET’inizi gizleme - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Meşru yazılımlara gömülü bir SectopRAT varyantını ortaya çıkarma](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [HimitsuShell README](https://github.com/HimitsuShell/HimitsuShell)
- [10] [HimitsuShell derleme betiği](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Linux kernel olay histogramları ve syscall izleme](https://docs.kernel.org/trace/histogram.html)
