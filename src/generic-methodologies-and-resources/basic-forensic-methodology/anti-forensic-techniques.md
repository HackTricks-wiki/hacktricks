# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

एक attacker का उद्देश्य detection से बचने के लिए **files के timestamps बदलना** हो सकता है।\
MFT में timestamps को `$STANDARD_INFORMATION` \_\_ और \_\_ `$FILE_NAME` attributes के अंदर पाया जा सकता है।

दोनों attributes में 4 timestamps होते हैं: **Modification**, **access**, **creation**, और **MFT registry modification** (MACE या MACB)।

**Windows explorer** और अन्य tools **`$STANDARD_INFORMATION`** से information दिखाते हैं।

### TimeStomp - Anti-forensic Tool

यह tool **`$STANDARD_INFORMATION`** के अंदर timestamp information को **modify करता है**, लेकिन **`$FILE_NAME`** के अंदर मौजूद information को **modify नहीं करता**। इसलिए **suspicious** **activity** की **पहचान** करना संभव है।

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), NTFS (Windows NT file system) का एक feature है, जो volume में होने वाले changes का record रखता है। [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) tool इन changes की examination की अनुमति देता है।

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal), NTFS (Windows NT file system) का एक feature है, जो volume में होने वाले changes का record रखता है।...](<../../images/image (801).png>)

पिछली image **tool** द्वारा दिखाया गया **output** है, जिसमें देखा जा सकता है कि file में **कुछ changes किए गए** थे।

### $LogFile

**File system में होने वाले सभी metadata changes को log किया जाता है**। इस process को [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) कहा जाता है। Logged metadata को `**$LogFile**` नाम की file में रखा जाता है, जो NTFS file system की root directory में स्थित होती है। [LogFileParser](https://github.com/jschicht/LogFileParser) जैसे tools का उपयोग इस file को parse करने और changes की पहचान करने के लिए किया जा सकता है।

![Usnjrnl - $LogFile: File system में होने वाले सभी metadata changes को write-ahead logging नामक process में log किया जाता है। Logged metadata को $LogFile नाम की file में रखा जाता है, जो root...](<../../images/image (137).png>)

फिर से, tool के output में देखा जा सकता है कि **कुछ changes किए गए** थे।

उसी tool का उपयोग करके यह पहचानना संभव है कि **timestamps को किस समय modify किया गया**:

![Usnjrnl - $LogFile: उसी tool का उपयोग करके यह पहचानना संभव है कि timestamps को किस समय modify किया गया](<../../images/image (1089).png>)

- CTIME: File का creation time
- ATIME: File का modification time
- MTIME: File का MFT registry modification
- RTIME: File का access time

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

Suspicious रूप से modified files की पहचान करने का एक अन्य तरीका दोनों attributes के time की तुलना करके **mismatches** ढूँढना है।

### Nanoseconds

**NTFS** timestamps की **precision** **100 nanoseconds** होती है। इसलिए 2010-10-10 10:10:**00.000:0000 जैसे timestamps वाली files का मिलना **बहुत suspicious है**।

### SetMace - Anti-forensic Tool

यह tool दोनों attributes `$STARNDAR_INFORMATION` और `$FILE_NAME` को modify कर सकता है। हालांकि, Windows Vista से इस information को modify करने के लिए live OS आवश्यक है।

## Data Hiding

NFTS cluster और minimum information size का उपयोग करता है। इसका अर्थ है कि यदि कोई file डेढ़ cluster का उपयोग करती है, तो उसका **बाकी आधा हिस्सा कभी उपयोग नहीं किया जाएगा** जब तक file delete न हो जाए। इसलिए, **इस slack space में data छिपाना** संभव है।

slacker जैसे tools इस "hidden" space में data छिपाने की अनुमति देते हैं। हालांकि, `$logfile` और `$usnjrnl` के analysis से पता चल सकता है कि कुछ data जोड़ा गया था:

![SetMace - Anti-forensic Tool - Data Hiding: slacker जैसे tools इस "hidden" space में data छिपाने की अनुमति देते हैं। हालांकि, $logfile और $usnjrnl के analysis से पता चल सकता है कि...](<../../images/image (1060).png>)

इसके बाद, FTK Imager जैसे tools का उपयोग करके slack space को retrieve करना संभव है। ध्यान दें कि इस प्रकार का tool content को obfuscated या encrypted रूप में save कर सकता है।

## UsbKill

यह एक ऐसा tool है जो **USB ports में कोई भी change detect होने पर computer को बंद कर देता है**।\
इसे discover करने का एक तरीका running processes का निरीक्षण करना और **चल रही प्रत्येक python script की समीक्षा करना** है।

## Live Linux Distributions

ये distros **RAM** memory के अंदर **execute** होते हैं। इन्हें detect करने का एकमात्र तरीका **तभी है जब NTFS file-system को write permissions के साथ mount किया गया हो**। यदि इसे केवल read permissions के साथ mount किया गया है, तो intrusion को detect करना संभव नहीं होगा।

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Forensics investigation को बहुत कठिन बनाने के लिए Windows की कई logging methods को disable करना संभव है।

### Disable Timestamps - UserAssist

यह एक registry key है, जो user द्वारा प्रत्येक executable को run किए जाने की dates और hours maintain करती है।

UserAssist को disable करने के लिए दो steps आवश्यक हैं:

1. दो registry keys, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` और `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, दोनों को zero पर set करें, ताकि यह signal मिले कि हम UserAssist को disable करना चाहते हैं।
2. अपने उन registry subtrees को clear करें जो `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` जैसे दिखाई देते हैं।

### Disable Timestamps - Prefetch

यह Windows system की performance बेहतर बनाने के उद्देश्य से executed applications के बारे में information save करता है। हालांकि, यह forensics practices के लिए भी उपयोगी हो सकता है।

- `regedit` execute करें
- File path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` select करें
- `EnablePrefetcher` और `EnableSuperfetch` दोनों पर right-click करें
- इनमें से प्रत्येक पर Modify select करके value को 1 (या 3) से 0 में बदलें
- Restart करें

### Disable Timestamps - Last Access Time

जब भी Windows NT server पर किसी NTFS volume से कोई folder खोला जाता है, तो system प्रत्येक listed folder पर एक timestamp field update करने के लिए time record करता है, जिसे last access time कहा जाता है। अत्यधिक उपयोग किए गए NTFS volume पर यह performance को प्रभावित कर सकता है।

1. Registry Editor (Regedit.exe) खोलें।
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` पर जाएँ।
3. `NtfsDisableLastAccessUpdate` खोजें। यदि यह मौजूद नहीं है, तो यह DWORD add करें और इसका value 1 set करें, जिससे process disable हो जाएगा।
4. Registry Editor बंद करें और server को reboot करें।

### Delete USB History

सभी **USB Device Entries** Windows Registry में **USBSTOR** registry key के अंतर्गत stored होती हैं। इसमें ऐसी sub keys होती हैं जो आपके PC या Laptop में USB Device plug करने पर create होती हैं। यह key यहाँ मिल सकती है: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`। **इसे delete करने पर** USB history delete हो जाएगी।\
आप [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) tool का भी उपयोग कर सकते हैं, ताकि यह सुनिश्चित हो सके कि entries delete कर दी गई हैं (और उन्हें delete करने के लिए)।

USBs के बारे में information save करने वाली एक अन्य file `setupapi.dev.log` है, जो `C:\Windows\INF` के अंदर होती है। इसे भी delete किया जाना चाहिए।

### Disable Shadow Copies

`vssadmin list shadowstorage` चलाकर shadow copies की **list** बनाएँ।\
`vssadmin delete shadow` चलाकर उन्हें **delete** करें।

आप [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) में दिए गए steps का पालन करके GUI के माध्यम से भी उन्हें delete कर सकते हैं।

Shadow copies को disable करने के लिए [steps from here](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Windows start button पर click करने के बाद text search box में "services" type करके Services program खोलें।
2. List में "Volume Shadow Copy" खोजें, उसे select करें और right-click करके Properties खोलें।
3. "Startup type" drop-down menu से Disabled चुनें, फिर Apply और OK पर click करके change confirm करें।

Registry में shadow copy के अंदर copy की जाने वाली files की configuration को `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` पर modify करना भी संभव है।

### Overwrite deleted files

- आप एक **Windows tool** का उपयोग कर सकते हैं: `cipher /w:C`। यह C drive के उपलब्ध unused disk space से data remove करने के लिए cipher को निर्देश देगा।
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

Windows 10/11 और Windows Server के recent versions `Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106) के अंतर्गत **rich PowerShell forensic artifacts** रखते हैं।
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
Defenders को उन registry keys में होने वाले बदलावों और PowerShell events को बड़े पैमाने पर हटाने की निगरानी करनी चाहिए।

### ETW (Event Tracing for Windows) Patch

Endpoint security products ETW पर बहुत अधिक निर्भर करते हैं। 2024 की एक लोकप्रिय evasion method है कि memory में `ntdll!EtwEventWrite`/`EtwEventWriteFull` को patch किया जाए, ताकि हर ETW call event emit किए बिना `STATUS_SUCCESS` return करे:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (जैसे `EtwTiSwallow`) इसी primitive को PowerShell या C++ में implement करते हैं।  
क्योंकि patch **process-local** होता है, इसलिए अन्य processes के अंदर चलने वाले EDRs इसे miss कर सकते हैं।<sup>[[5]](#references)</sup>  
Detection: memory में मौजूद `ntdll` की disk पर मौजूद प्रति से तुलना करें, या user-mode से पहले hook करें।

### Alternate Data Streams (ADS) Revival

2023 में malware campaigns (जैसे **FIN12** loaders) में traditional scanners की नजर से बाहर रहने के लिए second-stage binaries को  
ADS के अंदर stage करते हुए देखा गया है:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
`dir /R`, `Get-Item -Stream *`, या Sysinternals `streams64.exe` से streams की enumeration करें।  
host file को FAT/exFAT पर या SMB के माध्यम से कॉपी करने पर hidden stream हट जाएगा और investigators इसका उपयोग payload recover करने के लिए कर सकते हैं।

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver का उपयोग अब ransomware intrusions में **anti-forensics** के लिए नियमित रूप से किया जाता है।  
open-source tool **AuKill**, signed लेकिन vulnerable driver (`procexp152.sys`) को load करके **encryption & log destruction** से पहले EDR और forensic sensors को suspend या terminate करता है:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
ड्राइवर को बाद में हटा दिया जाता है, जिससे बहुत कम artifacts बचते हैं।<sup>[[1]](#references)</sup>
Mitigations: Microsoft vulnerable-driver blocklist (HVCI/SAC) सक्षम करें,
और user-writable paths से kernel-service creation पर alert करें।

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Detection कम करने के लिए compromised services को self-patch करना (Linux)
Adversaries किसी service का exploitation करने के तुरंत बाद उसे तेजी से “self-patch” कर रहे हैं, ताकि re-exploitation को रोका जा सके और vulnerability-based detections को दबाया जा सके। इसका उद्देश्य vulnerable components को नवीनतम legitimate upstream binaries/JARs से बदलना है, ताकि scanners host को patched रिपोर्ट करें, जबकि persistence और C2 बने रहें।<sup>[[3]](#references)</sup>

Example: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)।<sup>[[3]](#references)[[4]](#references)</sup>
- Post‑exploitation के बाद, attackers ने Maven Central (repo1.maven.org) से legitimate JARs fetch किए, ActiveMQ install में vulnerable JARs को delete किया और broker को restart किया।
- इससे initial RCE बंद हो गया, जबकि अन्य footholds (cron, SSH config changes, अलग C2 implants) बने रहे।

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
फोरेंसिक/हंटिंग टिप्स
- अनिर्धारित binary/JAR replacements के लिए service directories की समीक्षा करें:
- Debian/Ubuntu: `dpkg -V activemq` चलाएँ और file hashes/paths की तुलना repo mirrors से करें।
- ऐसे JAR versions खोजें जो disk पर मौजूद हों लेकिन package manager के स्वामित्व में न हों, या ऐसे symbolic links जिन्हें out of band अपडेट किया गया हो।
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` का उपयोग करके ctime/mtime को compromise window के साथ correlate करें।
- Shell history/process telemetry: initial exploitation के तुरंत बाद `repo1.maven.org` या अन्य artifact CDNs से `curl`/`wget` के उपयोग के प्रमाण खोजें।
- Change management: केवल patched version मौजूद होने की पुष्टि न करें, बल्कि यह भी validate करें कि “patch” किसने और क्यों लागू किया।

### Bearer tokens और anti-analysis stagers के साथ Cloud-service C2
देखे गए tradecraft में कई long-haul C2 paths और anti-analysis packaging का संयोजन था:<sup>[[3]](#references)</sup>
- Sandboxing और static analysis में बाधा डालने के लिए password-protected PyInstaller ELF loaders (जैसे encrypted PYZ, `/_MEI*` के अंतर्गत temporary extraction)।
- Indicators: `strings` में `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` जैसे hits।
- Runtime artifacts: `/tmp/_MEI*` या custom `--runtime-tmpdir` paths में extraction।
- Hardcoded OAuth Bearer tokens का उपयोग करने वाला Dropbox-backed C2
- Network markers: `Authorization: Bearer <token>` के साथ `api.dropboxapi.com` / `content.dropboxapi.com`।
- ऐसे server workloads से Dropbox domains पर outbound HTTPS के लिए proxy/NetFlow/Zeek/Suricata में hunt करें, जो सामान्यतः files sync नहीं करते।
- Tunneling के माध्यम से parallel/backup C2 (जैसे Cloudflare Tunnel `cloudflared`), ताकि कोई एक channel block होने पर भी control बना रहे।
- Host IOCs: `cloudflared` processes/units, `~/.cloudflared/*.json` में config, और Cloudflare edges तक outbound 443।

### Access बनाए रखने के लिए Persistence और “hardening rollback” (Linux examples)
Attackers अक्सर self-patching को durable access paths के साथ जोड़ते हैं:<sup>[[3]](#references)</sup>
- Cron/Anacron: periodic execution के लिए प्रत्येक `/etc/cron.*/` directory में `0anacron` stub में edits।
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: root logins सक्षम करना और low-privileged accounts के लिए default shells बदलना।
- Root login enablement के लिए hunt करें:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# "yes" जैसे values या अत्यधिक permissive settings को flag करें
```
- System accounts (जैसे `games`) पर suspicious interactive shells के लिए hunt करें:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Random, short-named beacon artifacts (8 alphabetical chars), जिन्हें disk पर drop किया गया हो और जो cloud C2 से भी contact करते हों:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders को इन artifacts को external exposure और service patching events के साथ correlate करना चाहिए, ताकि initial exploitation को छिपाने के लिए उपयोग किए गए anti-forensic self-remediation का पता लगाया जा सके।

## References

- [1] [Sophos X-Ops – AuKill: EDR को disable करने वाला weaponized vulnerable driver (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Stealth के लिए EtwEventWrite को patch करना: Detection और Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Persistence के लिए patching: DripDropper Linux malware cloud में कैसे move करता है](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
