# Anti-Forensic Teknikler

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

Bir attacker, tespit edilmekten kaçınmak için **dosyaların timestamps bilgilerini değiştirmekle** ilgilenebilir.\
Timestamps bilgilerini MFT içinde `$STANDARD_INFORMATION` \_\_ ve \_\_ `$FILE_NAME` attribute'larında bulmak mümkündür.

Her iki attribute da 4 timestamps bilgisine sahiptir: **Modification**, **access**, **creation** ve **MFT registry modification** (MACE veya MACB).

**Windows explorer** ve diğer araçlar bilgileri **`$STANDARD_INFORMATION`** üzerinden gösterir.

### TimeStomp - Anti-forensic Tool

Bu tool, **`$STANDARD_INFORMATION`** içindeki timestamp bilgilerini **değiştirir**, ancak **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle **şüpheli** **activity**'yi **tespit etmek** mümkündür.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), volume değişikliklerini takip eden NTFS'nin (Windows NT file system) bir özelliğidir. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) tool'u bu değişikliklerin incelenmesine olanak tanır.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal), volume değişikliklerini takip eden NTFS'nin (Windows NT file system) bir özelliğidir. ...](<../../images/image (801).png>)

Önceki image, **tool** tarafından gösterilen **output**'tur ve dosya üzerinde bazı **değişikliklerin gerçekleştirildiği** görülebilir.

### $LogFile

Bir file system üzerindeki **tüm metadata değişiklikleri**, [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir process ile loglanır. Loglanan metadata, bir NTFS file system'inin root directory'sinde bulunan `**$LogFile**` adlı bir file'da tutulur. Bu file'ı parse etmek ve değişiklikleri tespit etmek için [LogFileParser](https://github.com/jschicht/LogFileParser) gibi tool'lar kullanılabilir.

![Usnjrnl - $LogFile: Bir file system üzerindeki tüm metadata değişiklikleri write-ahead logging olarak bilinen bir process ile loglanır. Loglanan metadata, root... içinde bulunan $LogFile adlı bir file'da tutulur.](<../../images/image (137).png>)

Yine tool'un output'unda **bazı değişikliklerin gerçekleştirildiği** görülebilir.

Aynı tool kullanılarak **timestamps bilgilerinin hangi zamana değiştirildiği** tespit edilebilir:

![Usnjrnl - $LogFile: Aynı tool kullanılarak timestamps bilgilerinin hangi zamana değiştirildiğinin tespit edilmesi mümkündür](<../../images/image (1089).png>)

- CTIME: File'ın oluşturulma zamanı
- ATIME: File'ın değiştirilme zamanı
- MTIME: File'ın MFT registry modification zamanı
- RTIME: File'ın erişim zamanı

### `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli şekilde değiştirilmiş file'ları tespit etmenin başka bir yolu, **uyuşmazlıkları** aramak amacıyla her iki attribute'taki zamanı karşılaştırmaktır.

### Nanoseconds

**NTFS** timestamps bilgileri **100 nanoseconds** hassasiyetine sahiptir. Bu nedenle 2010-10-10 10:10:**00.000:0000 gibi timestamps bilgilerine sahip file'ları bulmak çok şüphelidir**.

### SetMace - Anti-forensic Tool

Bu tool, `$STARNDAR_INFORMATION` ve `$FILE_NAME` attribute'larının her ikisini de değiştirebilir. Ancak Windows Vista'dan itibaren bu bilgiyi değiştirmek için çalışan bir OS gerekir.

## Data Hiding

NFTS bir cluster ve minimum information size kullanır. Bu, bir file bir cluster'ın bir buçuk katını kaplıyorsa, **kalan yarının file silinene kadar hiçbir zaman kullanılmayacağı** anlamına gelir. Böylece **slack space içinde data gizlemek** mümkündür.

slacker gibi tool'lar data'yı bu "gizli" alanda saklamaya olanak tanır. Ancak `$logfile` ve `$usnjrnl` analizi, bazı data'ların eklendiğini gösterebilir:

![SetMace - Anti-forensic Tool - Data Hiding: slacker gibi tool'lar data'yı bu "gizli" alanda saklamaya olanak tanır. Ancak $logfile ve $usnjrnl analizi, bazı data'ların eklendiğini gösterebilir:](<../../images/image (1060).png>)

Daha sonra FTK Imager gibi tool'lar kullanılarak slack space alınabilir. Bu tür tool'ların içeriği obfuscated veya hatta encrypted şekilde kaydedebileceğini unutmayın.

## UsbKill

Bu, USB portlarında herhangi bir değişiklik tespit edilirse **computer'ı kapatan** bir tool'dur.\
Bunu keşfetmenin bir yolu, çalışan process'leri incelemek ve **çalışan her Python script'ini gözden geçirmektir**.

## Live Linux Distributions

Bu distro'lar **RAM** memory içinde **çalıştırılır**. Bunları tespit etmenin tek yolu, NTFS file-system'inin write permissions ile mount edilmiş olmasıdır. Sadece read permissions ile mount edilmişse intrusion'ı tespit etmek mümkün olmaz.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Forensics investigation'ı çok daha zorlaştırmak için çeşitli Windows logging method'larını devre dışı bırakmak mümkündür.

### Disable Timestamps - UserAssist

Bu, her executable'ın user tarafından çalıştırıldığı tarih ve saatleri tutan bir registry key'dir.

UserAssist'i devre dışı bırakmak iki adım gerektirir:

1. UserAssist'in devre dışı bırakılmasını istediğimizi belirtmek için `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` registry key'lerinin ikisini de sıfıra ayarlayın.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` gibi görünen registry subtree'lerinizi temizleyin.

### Disable Timestamps - Prefetch

Bu, Windows system'inin performansını iyileştirmek amacıyla çalıştırılan application'lar hakkında bilgi kaydeder. Ancak bu bilgiler forensics işlemleri için de yararlı olabilir.

- `regedit` çalıştırın
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` file path'ini seçin
- `EnablePrefetcher` ve `EnableSuperfetch` üzerinde sağ tıklayın
- Bu değerlerin her birinde Modify'ı seçerek değeri 1'den (veya 3'ten) 0'a değiştirin
- Restart edin

### Disable Timestamps - Last Access Time

Bir folder Windows NT server üzerindeki bir NTFS volume'ünden her açıldığında system, last access time olarak adlandırılan **her listelenen folder üzerindeki bir timestamp field'ını günceller**. Yoğun kullanılan bir NTFS volume'ünde bu durum performance'ı etkileyebilir.

1. Registry Editor'ı (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` konumuna gidin.
3. `NtfsDisableLastAccessUpdate` değerini arayın. Mevcut değilse bu DWORD'u ekleyin ve değerini 1 olarak ayarlayın; bu process'i devre dışı bırakır.
4. Registry Editor'ı kapatın ve server'ı reboot edin.

### Delete USB History

Tüm **USB Device Entries**, PC'nize veya Laptop'unuza bir USB Device taktığınızda oluşturulan sub key'leri içeren **USBSTOR** registry key'i altında Windows Registry'de saklanır. Bu key'i burada bulabilirsiniz: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bunu silmek**, USB history'yi siler.\
Bunları sildiğinizden emin olmak (ve silmek) için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) tool'unu da kullanabilirsiniz.

USB'ler hakkında bilgi kaydeden başka bir file, `C:\Windows\INF` içindeki `setupapi.dev.log` file'ıdır. Bu da silinmelidir.

### Disable Shadow Copies

`vssadmin list shadowstorage` ile shadow copy'leri **listeleyin**\
`vssadmin delete shadow` çalıştırarak bunları **silin**

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresindeki adımları izleyerek GUI üzerinden de silebilirsiniz.

Shadow copy'leri devre dışı bırakmak için [buradaki adımları](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) uygulayın:

1. Windows start button'a tıkladıktan sonra text search box'a "services" yazarak Services programını açın.
2. Listeden "Volume Shadow Copy"yi bulun, seçin ve sağ tıklayarak Properties'e erişin.
3. "Startup type" drop-down menu'sünden Disabled'ı seçin ve ardından Apply ve OK'e tıklayarak değişikliği onaylayın.

Shadow copy içinde hangi file'ların kopyalanacağını registry'deki `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` konumundan değiştirmek de mümkündür.

### Overwrite deleted files

- Bir **Windows tool'u** kullanabilirsiniz: `cipher /w:C`. Bu, cipher'a C drive içindeki kullanılabilir boş disk alanından tüm data'yı kaldırmasını söyler.
- [**Eraser**](https://eraser.heidi.ie) gibi tool'lar da kullanabilirsiniz.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Logs"u genişletin --> Her category'ye sağ tıklayın ve "Clear Log"u seçin
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Services section içinde "Windows Event Log" service'ini devre dışı bırakın
- `WEvtUtil.exec clear-log` veya `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11 ve Windows Server'ın güncel version'ları,
`Microsoft-Windows-PowerShell/Operational` altında (4104/4105/4106 event'leri) **zengin PowerShell forensic artifact'ları** tutar.
Attackers bunları anlık olarak devre dışı bırakabilir veya silebilir:
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
Savunucular, bu registry key'lerinde yapılan değişiklikleri ve PowerShell event'lerinin yüksek hacimli olarak kaldırılmasını izlemelidir.

### ETW (Event Tracing for Windows) Patch

Endpoint security products, ETW'ye büyük ölçüde güvenir. Popüler bir 2024 evasion yöntemi, bellekteki
`ntdll!EtwEventWrite`/`EtwEventWriteFull` işlevlerine patch uygulayarak her ETW çağrısının event oluşturmadan
`STATUS_SUCCESS` döndürmesini sağlamaktır:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoC'ler (ör. `EtwTiSwallow`) aynı primitive'i PowerShell veya C++ ile uygular.
Patch **process-local** olduğundan, diğer process'lerin içinde çalışan EDR'ler bunu gözden kaçırabilir.<sup>[[5]](#references)</sup>
Detection: bellekteki `ntdll` ile disktekini karşılaştırın veya user-mode öncesinde hook kullanın.

### Alternate Data Streams (ADS) Revival

2023'teki malware kampanyalarında (ör. **FIN12** loader'ları), geleneksel scanner'ların görüş alanından uzak kalmak için second-stage binary'leri ADS içinde stage ettikleri görüldü:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
`dir /R`, `Get-Item -Stream *` veya Sysinternals `streams64.exe` ile stream'leri listeleyin.
Host dosyasının FAT/exFAT'e veya SMB üzerinden kopyalanması gizli stream'i kaldırır ve payload'ın
araştırmacılar tarafından kurtarılmasını sağlar.

### BYOVD ve “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver artık ransomware
saldırılarında **anti-forensics** amacıyla rutin olarak kullanılmaktadır.
Açık kaynaklı **AuKill** aracı, imzalı ancak güvenlik açığı bulunan bir driver'ı (`procexp152.sys`)
yükleyerek **şifreleme ve log destruction** işlemlerinden önce EDR ve forensic sensörlerini
askıya alır veya sonlandırır:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Sürücü daha sonra kaldırılır ve geride minimum düzeyde artifact bırakır.<sup>[[1]](#references)</sup>
Mitigations: Microsoft vulnerable-driver blocklist'i (HVCI/SAC) etkinleştirin
ve user-writable path'lerden kernel-service oluşturulması konusunda alert oluşturun.

---

## Linux Anti-Forensics: Self-Patching ve Cloud C2 (2023–2025)

### Detection'ı azaltmak için compromised service'leri self-patch etme (Linux)
Adversaries, hem yeniden exploitation'ı önlemek hem de vulnerability-based detection'ları bastırmak için bir service'i exploit ettikten hemen sonra giderek daha fazla “self-patch” ediyor. Fikir, vulnerable component'leri en güncel legitimate upstream binary/JAR'larla değiştirmektir; böylece scanner'lar host'un patched olduğunu bildirirken persistence ve C2 devam eder.<sup>[[3]](#references)</sup>

Örnek: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Post-exploitation sonrasında attackers, Maven Central'dan (repo1.maven.org) legitimate JAR'lar indirdi, ActiveMQ install'ındaki vulnerable JAR'ları sildi ve broker'ı yeniden başlattı.
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
- Planlanmamış binary/JAR değişiklikleri için service directory'lerini inceleyin:
- Debian/Ubuntu: `dpkg -V activemq` çalıştırın ve dosya hash'lerini/path'lerini repo mirror'larıyla karşılaştırın.
- Diskte package manager tarafından sahiplenilmeyen JAR version'larını veya out-of-band güncellenmiş symbolic link'leri arayın.
- Timeline: compromise window ile ctime/mtime değerlerini ilişkilendirmek için `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` komutunu kullanın.
- Shell history/process telemetry: initial exploitation'ın hemen ardından `repo1.maven.org` veya diğer artifact CDN'lerine `curl`/`wget` yapıldığına dair kanıt arayın.
- Change management: yalnızca patched version'ın mevcut olduğunu doğrulamakla kalmayın; “patch”i kimin ve neden uyguladığını doğrulayın.

### Bearer token'lar ve anti-analysis stager'lar ile Cloud-service C2
Gözlemlenen tradecraft, birden fazla long-haul C2 path'ini ve anti-analysis packaging yöntemini birleştiriyordu:<sup>[[3]](#references)</sup>
- Sandboxing ve static analysis'i zorlaştırmak için password-protected PyInstaller ELF loader'ları (ör. encrypted PYZ, `/_MEI*` altında temporary extraction).
- Indicators: `strings` çıktısında `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` eşleşmeleri.
- Runtime artifacts: `/tmp/_MEI*` veya özel `--runtime-tmpdir` path'lerine extraction.
- Hardcoded OAuth Bearer token'ları kullanan Dropbox-backed C2
- Network markers: `Authorization: Bearer <token>` ile birlikte `api.dropboxapi.com` / `content.dropboxapi.com`.
- Normalde dosya sync etmeyen server workload'larından Dropbox domain'lerine giden outbound HTTPS trafiği için proxy/NetFlow/Zeek/Suricata üzerinde hunt yapın.
- Tunneling üzerinden parallel/backup C2 (ör. Cloudflare Tunnel `cloudflared`); kanallardan biri engellense bile control'ü korur.
- Host IOCs: `cloudflared` process/unit'leri, `~/.cloudflared/*.json` config'i ve Cloudflare edge'lerine outbound 443 bağlantıları.

### Access'i sürdürmek için persistence ve “hardening rollback” (Linux örnekleri)
Attackers sıklıkla self-patching işlemini durable access path'leriyle birlikte kullanır:<sup>[[3]](#references)</sup>
- Cron/Anacron: periyodik execution için her `/etc/cron.*/` directory'sindeki `0anacron` stub'ına yapılan değişiklikler.
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
- System account'lar (ör. `games`) üzerindeki şüpheli interactive shell'ler için hunt:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Diskte bırakılan ve aynı zamanda cloud C2 ile iletişim kuran random, kısa isimli beacon artifact'leri (8 alphabetical karakter):
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders, initial exploitation'ı gizlemek için kullanılan anti-forensic self-remediation'ı ortaya çıkarmak amacıyla bu artifact'leri external exposure ve service patching event'leriyle ilişkilendirmelidir.

## References

- [1] [Sophos X-Ops – AuKill: EDR'yi devre dışı bırakmak için weaponized vulnerable driver (Mart 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Stealth için EtwEventWrite patch'leme: Detection & Hunting (Haziran 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Persistence için patch'leme: DripDropper Linux malware cloud içinde nasıl ilerliyor](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Your .NET'i gizlemek - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)

{{#include ../../banners/hacktricks-training.md}}
