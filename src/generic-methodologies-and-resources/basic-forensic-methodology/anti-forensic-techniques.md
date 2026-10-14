# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## टाइमस्टैम्प

हमलावर का पता लगने से बचने के लिए **फ़ाइलों के टाइमस्टैम्प बदलने** में रुचि हो सकती है।\
MFT में attributes `$STANDARD_INFORMATION` \_\_ और \_\_ `$FILE_NAME` के अंदर टाइमस्टैम्प देखे जा सकते हैं।

दोनों attributes में 4 टाइमस्टैम्प होते हैं: **Modification**, **access**, **creation**, और **MFT registry modification** (MACE या MACB)।

**Windows explorer** और अन्य टूल **`$STANDARD_INFORMATION`** से जानकारी दिखाते हैं।

### TimeStomp - Anti-forensic Tool

यह टूल **`$STANDARD_INFORMATION`** के अंदर मौजूद टाइमस्टैम्प की जानकारी को **बदलता है**, **लेकिन** **`$FILE_NAME`** के अंदर की जानकारी को **नहीं**। इसलिए, **संदिग्ध गतिविधि** की **पहचान** करना संभव है।

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), NTFS (Windows NT file system) का एक फीचर है जो वॉल्यूम में हुए बदलावों का रिकॉर्ड रखता है। [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) टूल इन बदलावों की जाँच करने देता है।

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal), NTFS (Windows NT file system) का एक फीचर है जो वॉल्यूम में हुए बदलावों का रिकॉर्ड रखता है। यह...](<../../images/image (801).png>)

पिछली छवि में टूल का **आउटपुट** दिखाया गया है, जिसमें देखा जा सकता है कि फ़ाइल में कुछ **बदलाव किए गए थे**।

### $LogFile

[write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) नामक प्रक्रिया में **फ़ाइल सिस्टम के सभी metadata बदलावों का रिकॉर्ड रखा जाता है**। रिकॉर्ड किया गया metadata, NTFS फ़ाइल सिस्टम की root directory में मौजूद `**$LogFile**` नाम की फ़ाइल में रखा जाता है। इस फ़ाइल को parse करने और बदलावों की पहचान करने के लिए [LogFileParser](https://github.com/jschicht/LogFileParser) जैसे टूल इस्तेमाल किए जा सकते हैं।

![Usnjrnl - $LogFile: write-ahead logging नामक प्रक्रिया में फ़ाइल सिस्टम के सभी metadata बदलावों का रिकॉर्ड रखा जाता है। रिकॉर्ड किया गया metadata, NTFS फ़ाइल सिस्टम की root...](<../../images/image (137).png>)

फिर से, टूल के आउटपुट में देखा जा सकता है कि **कुछ बदलाव किए गए थे**।

इसी टूल का इस्तेमाल करके यह पता लगाना संभव है कि टाइमस्टैम्प **किस समय पर बदले गए थे**:

![Usnjrnl - $LogFile: इसी टूल का इस्तेमाल करके यह पता लगाना संभव है कि टाइमस्टैम्प किस समय पर बदले गए थे](<../../images/image (1089).png>)

- CTIME: फ़ाइल का creation time
- ATIME: फ़ाइल का modification time
- MTIME: फ़ाइल का MFT registry modification
- RTIME: फ़ाइल का access time

### `$STANDARD_INFORMATION` और `$FILE_NAME` की तुलना

संदिग्ध रूप से बदली गई फ़ाइलों की पहचान करने का एक और तरीका है, दोनों attributes के समय की तुलना करके **बेमेल** ढूँढना।

### Nanoseconds

**NTFS** टाइमस्टैम्प की **precision** **100 nanoseconds** होती है। इसलिए, 2010-10-10 10:10:**00.000:0000 जैसे टाइमस्टैम्प वाली फ़ाइलें मिलना बहुत संदिग्ध है**।

### SetMace - Anti-forensic Tool

यह टूल `$STARNDAR_INFORMATION` और `$FILE_NAME` दोनों attributes को बदल सकता है। हालाँकि, Windows Vista के बाद, इस जानकारी को बदलने के लिए live OS का होना आवश्यक है।

## Data Hiding

NFTS में cluster और जानकारी का न्यूनतम आकार इस्तेमाल होता है। इसका मतलब है कि अगर कोई फ़ाइल डेढ़ cluster का उपयोग करती है, तो **बाकी आधे हिस्से का उपयोग फ़ाइल delete होने तक कभी नहीं होगा**। इसलिए, **इस slack space में data छिपाना** संभव है।

slacker जैसे टूल इस "छिपी हुई" जगह में data छिपाने देते हैं। हालाँकि, `$logfile` और `$usnjrnl` का विश्लेषण दिखा सकता है कि कुछ data जोड़ा गया था:

![SetMace - Anti-forensic Tool - Data Hiding: slacker जैसे टूल इस "छिपी हुई" जगह में data छिपाने देते हैं। हालाँकि, $logfile और $usnjrnl का विश्लेषण दिखा सकता है कि...](<../../images/image (1060).png>)

इसके बाद, FTK Imager जैसे टूल से slack space को वापस प्राप्त करना संभव है। ध्यान दें कि इस तरह के टूल content को obfuscated या यहाँ तक कि encrypted रूप में भी सहेज सकते हैं।

## UsbKill

यह टूल **USB ports में कोई भी बदलाव होने पर कंप्यूटर बंद कर देता है**।\
इसका पता लगाने का एक तरीका running processes की जाँच करना और **चल रही हर Python script की समीक्षा करना** है।

## Live Linux Distributions

ये distros **RAM memory में चलाए जाते हैं**। इनका पता लगाने का एकमात्र तरीका यह है कि NTFS file-system को write permissions के साथ mount किया गया हो। अगर इसे केवल read permissions के साथ mount किया गया है, तो intrusion का पता लगाना संभव नहीं होगा।

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Windows में देरी से self-deletion

चल रही Windows image का process सक्रिय होने पर वह locked हो सकता है। कोई process deletion का काम child `cmd.exe` को सौंप सकता है, timer के रूप में `choice` इस्तेमाल कर सकता है, और shell के `del` तक पहुँचने से पहले exit हो सकता है। इस देरी से मूल process अपना image handle release कर पाता है; अगर path में spaces हों, तो पूरा path quotes में देना आवश्यक है।<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

जब यह string किसी अन्य interactive `cmd` prompt से टाइप करने के बजाय सीधे `cmd.exe` को argument के रूप में दी जाती है, तो `^&` की जगह `&` और `^>nul` की जगह `>nul` इस्तेमाल करें। इससे directory entry हट जाती है; यह **सुरक्षित रूप से मिटाना नहीं है** और इससे execution, task, filesystem-journal या अन्य forensic traces नहीं हटते। ऐसे कम समय तक चलने वाले `cmd.exe` child processes की तलाश करें जिनकी command line में `choice /T`, `Del` और parent का image path, तीनों शामिल हों।<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows कॉन्फ़िगरेशन

कई Windows logging methods को disable करना संभव है, जिससे forensic investigation काफी कठिन हो जाती है।

### Timestamps अक्षम करें - UserAssist

यह registry key उन तारीखों और समय को रिकॉर्ड करती है जब उपयोगकर्ता ने हर executable चलाया था।

UserAssist को disable करने के लिए दो चरण आवश्यक हैं:

1. दो registry keys, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` और `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, दोनों को zero पर सेट करें, ताकि UserAssist को disable करने का संकेत मिले।
2. ऐसे registry subtrees साफ़ करें जो `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` जैसे दिखते हों।

### Timestamps अक्षम करें - Prefetch

इसमें Windows system की performance बेहतर करने के उद्देश्य से चलाए गए applications की जानकारी सहेजी जाती है। हालांकि, यह forensic practices के लिए भी उपयोगी हो सकती है।

- `regedit` चलाएँ
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` file path चुनें
- `EnablePrefetcher` और `EnableSuperfetch`, दोनों पर right-click करें
- प्रत्येक पर Modify चुनें और value को 1 (या 3) से बदलकर 0 करें
- Restart करें

### Timestamps अक्षम करें - Last Access Time

जब भी Windows NT server पर किसी NTFS volume से folder खोला जाता है, तो system हर सूचीबद्ध folder में मौजूद timestamp field को **update करता है**। इसे last access time कहा जाता है। अधिक उपयोग वाले NTFS volume पर इससे performance प्रभावित हो सकती है।

1. Registry Editor (Regedit.exe) खोलें।
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` पर जाएँ।
3. `NtfsDisableLastAccessUpdate` ढूँढें। यदि यह मौजूद न हो, तो यह DWORD जोड़ें और इसकी value 1 पर सेट करें, जिससे यह प्रक्रिया disable हो जाएगी।
4. Registry Editor बंद करें और server reboot करें।

### USB History हटाएँ

सभी **USB Device Entries** Windows Registry में **USBSTOR** registry key के अंतर्गत सहेजी जाती हैं। इसमें ऐसी sub keys होती हैं जो आपके PC या Laptop में USB Device plug in करने पर बनती हैं। यह key यहाँ मिलेगी H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`। इसे **हटाने से** USB history मिट जाएगी।\
आप यह सुनिश्चित करने के लिए [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) tool भी इस्तेमाल कर सकते हैं कि आपने इन्हें हटा दिया है (और इन्हें हटाने के लिए भी)।

USBs की जानकारी सहेजने वाली एक अन्य file `C:\Windows\INF` के अंदर मौजूद `setupapi.dev.log` है। इसे भी हटाना चाहिए।

### Shadow Copies अक्षम करें

`vssadmin list shadowstorage` से shadow copies **सूचीबद्ध** करें।\
`vssadmin delete shadow` चलाकर उन्हें **हटाएँ**।

आप [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) में दिए गए चरणों का पालन करके GUI के ज़रिए भी उन्हें हटा सकते हैं।

Shadow copies अक्षम करने के लिए [यहाँ दिए गए चरण](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) अपनाएँ:

1. Windows start button पर click करने के बाद text search box में "services" टाइप करके Services program खोलें।
2. सूची में "Volume Shadow Copy" ढूँढें, उसे चुनें, फिर right-click करके Properties खोलें।
3. "Startup type" drop-down menu से Disabled चुनें, फिर Apply और OK पर click करके बदलाव की पुष्टि करें।

Registry में `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` के ज़रिए यह configuration भी बदली जा सकती है कि shadow copy में किन files को copy किया जाएगा।

### हटाई गई files को overwrite करें

- आप **Windows tool** इस्तेमाल कर सकते हैं: `cipher /w:C`। इससे cipher को C drive के उपलब्ध unused disk space से कोई भी data हटाने का निर्देश मिलेगा।
- आप [**Eraser**](https://eraser.heidi.ie) जैसे tools भी इस्तेमाल कर सकते हैं।

### Windows event logs हटाएँ

- Windows + R --> eventvwr.msc --> "Windows Logs" को Expand करें --> प्रत्येक category पर right-click करके "Clear Log" चुनें
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows event logs अक्षम करें

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Services section में "Windows Event Log" service को disable करें
- `WEvtUtil.exec clear-log` या `WEvtUtil.exe cl`

### $UsnJrnl अक्षम करें

- `fsutil usn deletejournal /d c:`

---

## उन्नत Logging और Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11 और Windows Server के हाल के versions, `Microsoft-Windows-PowerShell/Operational` के अंतर्गत **PowerShell के विस्तृत forensic artifacts** (events 4104/4105/4106) रखते हैं।  
Attackers इन्हें तुरंत disable या wipe कर सकते हैं:

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

Defenders को उन registry keys में बदलावों और PowerShell events को बड़ी मात्रा में हटाए जाने पर नज़र रखनी चाहिए।

### ETW (Event Tracing for Windows) Patch

Endpoint security products ETW पर बहुत अधिक निर्भर करते हैं। 2024 की एक लोकप्रिय evasion method यह है कि memory में `ntdll!EtwEventWrite`/`EtwEventWriteFull` को patch किया जाए, ताकि हर ETW call event emit किए बिना `STATUS_SUCCESS` लौटाए:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoCs (जैसे `EtwTiSwallow`) PowerShell या C++ में यही primitive लागू करते हैं।  
क्योंकि patch **process-local** होता है, इसलिए दूसरे processes के अंदर चलने वाले EDRs इसे पकड़ नहीं पाते।<sup>[[5]](#references)</sup>
Detection: memory में मौजूद `ntdll` की तुलना disk पर मौजूद `ntdll` से करें, या user-mode से पहले hook करें।

### Alternate Data Streams (ADS) का पुनरुत्थान

2023 में malware campaigns (जैसे **FIN12** loaders) में second-stage binaries को ADS के अंदर रखा गया है, ताकि वे traditional scanners की नज़र से बचे रहें:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

`dir /R`, `Get-Item -Stream *` या Sysinternals `streams64.exe` से streams की सूची बनाएँ।
होस्ट फ़ाइल को FAT/exFAT पर या SMB के ज़रिए कॉपी करने से छिपी हुई stream हट जाएगी; जाँचकर्ता इसका उपयोग payload को पुनर्प्राप्त करने के लिए कर सकते हैं।

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver का उपयोग अब ransomware intrusions में **anti-forensics** के लिए नियमित रूप से किया जाता है।  
ओपन-सोर्स टूल **AuKill**, EDR और forensic sensors को **encryption और log destruction से पहले** suspend या terminate करने के लिए एक signed लेकिन vulnerable driver (`procexp152.sys`) लोड करता है:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

ड्राइवर को बाद में हटा दिया जाता है, जिससे बहुत कम artifacts बचते हैं।<sup>[[1]](#references)</sup>  
Mitigations: Microsoft vulnerable-driver blocklist (HVCI/SAC) सक्षम करें,
और user-writable paths से kernel-service creation पर alert करें।

---

## Linux Anti-Forensics: Self-Patching और Cloud C2 (2023–2025)

### Detection कम करने के लिए compromised services को self-patch करना (Linux)
हमलावर increasingly किसी service का exploit करने के तुरंत बाद उसे “self-patch” करते हैं, ताकि दोबारा exploit होने से रोका जा सके और vulnerability-based detections को दबाया जा सके। इसका उद्देश्य vulnerable components को नवीनतम legitimate upstream binaries/JARs से बदलना है, ताकि scanners host को patched दिखाएँ, जबकि persistence और C2 बने रहें।<sup>[[3]](#references)</sup>

उदाहरण: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)।<sup>[[3]](#references)[[4]](#references)</sup>
- Post-exploitation में, हमलावरों ने Maven Central (repo1.maven.org) से legitimate JARs प्राप्त किए, ActiveMQ install में vulnerable JARs हटाए और broker को restart किया।
- इससे initial RCE बंद हो गया, जबकि अन्य footholds (cron, SSH config में बदलाव, अलग C2 implants) बने रहे।

Operational example (उदाहरण के लिए)
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
- अनिर्धारित binary/JAR प्रतिस्थापनों के लिए service directories की समीक्षा करें:
  - Debian/Ubuntu: `dpkg -V activemq` चलाएँ और file hashes/paths की repo mirrors से तुलना करें।
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - ऐसे JAR versions देखें जो disk पर मौजूद हों, लेकिन package manager के स्वामित्व में न हों; या ऐसे symbolic links जो बिना रिकॉर्ड के अपडेट किए गए हों।
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` चलाकर ctime/mtime को compromise window से मिलाएँ।
- Shell history/process telemetry: initial exploitation के तुरंत बाद `repo1.maven.org` या अन्य artifact CDNs से `curl`/`wget` के उपयोग के प्रमाण देखें।
- Change management: सिर्फ यह नहीं कि patched version मौजूद है, बल्कि यह भी सत्यापित करें कि “patch” किसने और क्यों लागू किया।

### Bearer tokens और anti-analysis stagers के साथ Cloud-service C2
देखे गए tradecraft में कई long-haul C2 paths और anti-analysis packaging का संयोजन था:<sup>[[3]](#references)</sup>
- Sandbox और static analysis में बाधा डालने के लिए password-protected PyInstaller ELF loaders (जैसे, encrypted PYZ, `/_MEI*` के अंतर्गत temporary extraction)।
  - Indicators: `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` जैसे `strings` hits।
  - Runtime artifacts: `/tmp/_MEI*` या custom `--runtime-tmpdir` paths में extraction।
- Hardcoded OAuth Bearer tokens का उपयोग करने वाला Dropbox-backed C2
  - Network markers: `Authorization: Bearer <token>` के साथ `api.dropboxapi.com` / `content.dropboxapi.com`।
  - Proxy/NetFlow/Zeek/Suricata में उन server workloads से Dropbox domains पर outbound HTTPS खोजें जो सामान्यतः files sync नहीं करते।
- Tunneling (जैसे, Cloudflare Tunnel `cloudflared`) के ज़रिए समानांतर/backup C2, ताकि एक channel block होने पर भी control बना रहे।
  - Host IOCs: `cloudflared` processes/units, `~/.cloudflared/*.json` पर config, Cloudflare edges पर outbound 443।

### Access बनाए रखने के लिए Persistence और “hardening rollback” (Linux उदाहरण)
हमलावर अक्सर self-patching के साथ durable access paths भी जोड़ते हैं:<sup>[[3]](#references)</sup>
- Cron/Anacron: periodic execution के लिए हर `/etc/cron.*/` directory में `0anacron` stub में बदलाव।
  - खोजें:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- SSH configuration hardening को rollback करना: root login सक्षम करना और कम विशेषाधिकार वाले accounts के लिए default shells बदलना।
  - root login सक्षम किए जाने के संकेत खोजें:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - सिस्टम खातों (जैसे, `games`) पर संदिग्ध interactive shells की तलाश करें:
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- डिस्क पर छोड़े गए random, 8 अक्षरों वाले छोटे नाम के beacon artifacts, जो cloud C2 से भी संपर्क करते हैं:
  - Hunt:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

डिफेंडर्स को initial exploitation छिपाने के लिए इस्तेमाल किए गए anti-forensic self-remediation का पता लगाने हेतु इन artifacts को external exposure और service patching events के साथ correlate करना चाहिए।

## Static embedded-shell execution

Embedded interpreter और command implementations वाला script wrapper, `/bin/sh` और अलग-अलग utility processes लॉन्च करने के बजाय, supported shell operations को एक executable के अंदर चला सकता है। HimitsuShell ऐसा static musl binary बनाता है। [SHc wrappers](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md) के विपरीत, इसके built-in commands को host shell या अलग utility process शुरू करने की ज़रूरत नहीं होती। Unsupported commands system shell पर fallback कर सकते हैं।<sup>[[9]](#references)</sup>

इससे shell-process और child-`execve` की visibility कम हो जाती है।<sup>[[9]](#references)</sup> Wrapper process और उसके system calls kernel tracepoints के ज़रिए अब भी observable रहते हैं, इसलिए kernel tracing से भी अदृश्य होने के project के दावे को शाब्दिक रूप से नहीं लेना चाहिए।<sup>[[9]](#references)[[11]](#references)</sup>

Documented x86_64 build के लिए, input का नाम `launcher.sh` ही रखें और compile करने से पहले उसे container में copy करें। Output `safeLauncher` है:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

सार्वजनिक `compile.sh` स्क्रिप्ट को AES-256-CTR से एन्क्रिप्ट करता है, expiration value और intermediate keys/IVs को AES-256-CBC से एन्क्रिप्ट करता है, एन्क्रिप्ट की गई फ़ाइलों को `xxd -i` की मदद से C arrays में बदलता है, और उन्हें `-static -s` का उपयोग करके `lib.bc` के साथ link करता है। अंतिम encryption key और IV भी embed किए जाते हैं, इसलिए यह सामान्य static extraction से बचाव है, ऐसा रहस्य नहीं जिसे कभी recover न किया जा सके।<sup>[[10]](#references)</sup>

डिफ़ॉल्ट LLVM passes `-sobf` और `-sub` हैं। दस्तावेज़ीकृत विकल्पों, जैसे control-flow flattening (`fla`) या bogus control flow (`bcf`), को सक्षम करने के लिए build करने से पहले `/var/work/compile.sh` संपादित करें।<sup>[[9]](#references)[[10]](#references)</sup>

इस wrapper पर भरोसा करने से पहले script compatibility जाँच लें: यह project POSIX shell syntax को target करता है, चेतावनी देता है कि Bash/Zsh scripts विफल हो सकती हैं, और कहता है कि इसके built-in set से बाहर के commands system shell चलाते हैं।<sup>[[9]](#references)</sup>

Flattened control flow के विश्लेषण के लिए, [bypassing flattened control flow with a narrow execution slice](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice) देखें।

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: EDR को निष्क्रिय करने वाला हथियारबंद vulnerable driver (मार्च 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Stealth के लिए EtwEventWrite को patch करना: Detection और Hunting (जून 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Persistence के लिए patching: DripDropper Linux malware cloud में कैसे फैलता है](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – वैध software में embedded SectopRAT variant का पता लगाना](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [HimitsuShell README](https://github.com/HimitsuShell/HimitsuShell)
- [10] [HimitsuShell build script](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Linux kernel event histograms और syscall tracing](https://docs.kernel.org/trace/histogram.html)
