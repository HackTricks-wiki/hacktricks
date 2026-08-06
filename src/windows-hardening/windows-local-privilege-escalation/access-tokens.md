# Tokeny dostępu

{{#include ../../banners/hacktricks-training.md}}

## Tokeny dostępu

Każdy **użytkownik zalogowany** do systemu **posiada token dostępu zawierający informacje dotyczące bezpieczeństwa** dla danej sesji logowania. System tworzy token dostępu, gdy użytkownik się loguje. **Każdy proces uruchomiony** w imieniu użytkownika **posiada kopię tokenu dostępu**. Token identyfikuje użytkownika, grupy użytkownika oraz uprawnienia użytkownika. Token zawiera również identyfikator SID logowania (Security Identifier), który identyfikuje bieżącą sesję logowania.

Możesz wyświetlić te informacje, wykonując `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
lub za pomocą _Process Explorer_ z Sysinternals (wybierz proces i przejdź do zakładki „Security”):

![Access Tokens - Access Tokens: lub za pomocą Process Explorer z Sysinternals (wybierz proces i przejdź do zakładki „Security”)](<../../images/image (772).png>)

### Lokalny administrator

Gdy lokalny administrator loguje się, **tworzone są dwa access tokens**: jeden z prawami administratora i drugi ze zwykłymi prawami. **Domyślnie**, gdy ten użytkownik wykonuje proces, używany jest token ze **zwykłymi** (nieadministracyjnymi) **prawami**. Gdy użytkownik ten próbuje **uruchomić** cokolwiek **jako administrator** (na przykład za pomocą opcji „Run as Administrator”), używany jest **UAC**, aby poprosić o zgodę.\
Jeśli chcesz [**dowiedzieć się więcej o UAC, przeczytaj tę stronę**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

W praktyce oznacza to, że **niepodniesiona powłoka administratora zwykle działa z filtrowanym tokenem**. Dlatego `whoami /groups` często wyświetla **`BUILTIN\Administrators` jako `Deny only`**, dopóki proces nie zostanie podniesiony. Wewnętrznie Windows przechowuje **powiązany podniesiony token** (`TokenLinkedToken`) i śledzi jego stan za pomocą pól takich jak `TokenElevationType`.

### Impersonacja użytkownika przy użyciu poświadczeń

Jeśli posiadasz **prawidłowe poświadczenia dowolnego innego użytkownika**, możesz **utworzyć** **nową sesję logowania** przy użyciu tych poświadczeń:
```
runas /user:domain\username cmd.exe
```
**access token** zawiera również **referencję** do sesji logowania wewnątrz **LSASS**, co jest przydatne, jeśli proces musi uzyskać dostęp do obiektów w sieci.\
Możesz uruchomić proces, który **używa innych poświadczeń do uzyskiwania dostępu do usług sieciowych**, za pomocą:
```
runas /user:domain\username /netonly cmd.exe
```
Jest to przydatne, jeśli masz użyteczne dane uwierzytelniające do uzyskiwania dostępu do obiektów w sieci, ale te dane nie są prawidłowe na bieżącym hoście, ponieważ będą używane wyłącznie w sieci (na bieżącym hoście zostaną użyte uprawnienia bieżącego użytkownika).

#### Szczegóły `runas /netonly`

`runas /netonly` (oraz helpers C2, takie jak `make_token`) tworzy token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Jest to bardzo przydatne do zrozumienia podczas lateral movement, ponieważ:<sup>[[3]](#references)</sup>

- **Lokalnie** nowy proces zachowuje **tę samą lokalną tożsamość**, grupy, poziom integralności oraz większość tych samych decyzji dotyczących dostępu co bieżący token.
- **Zdalnie** uwierzytelnianie wychodzące może używać **podanych danych uwierzytelniających** dla SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Dlatego `whoami` może nadal wyświetlać **oryginalnego lokalnego użytkownika**, podczas gdy dostęp sieciowy będzie realizowany jako **inne konto**.

Jest to świetna opcja, gdy dane uwierzytelniające są prawidłowe w domenie lub na innym hoście, ale użytkownik **nie może lub nie powinien logować się lokalnie** na bieżącej maszynie.

### Typy tokenów

Dostępne są dwa typy tokenów:

- **Primary Token**: Służy jako reprezentacja poświadczeń bezpieczeństwa procesu. Tworzenie tokenów podstawowych i kojarzenie ich z procesami wymaga podwyższonych uprawnień, co podkreśla zasadę separacji uprawnień. Zwykle za tworzenie tokenów odpowiada usługa uwierzytelniania, a za ich powiązanie z powłoką systemu operacyjnego użytkownika odpowiada usługa logowania. Warto zauważyć, że w momencie tworzenia procesy dziedziczą token podstawowy procesu nadrzędnego.
- **Impersonation Token**: Umożliwia aplikacji serwerowej tymczasowe przyjęcie tożsamości klienta w celu uzyskania dostępu do zabezpieczonych obiektów. Mechanizm ten obejmuje cztery poziomy działania:
- **Anonymous**: Zapewnia serwerowi dostęp podobny do dostępu niezidentyfikowanego użytkownika.
- **Identification**: Umożliwia serwerowi zweryfikowanie tożsamości klienta bez używania jej do uzyskiwania dostępu do obiektów.
- **Impersonation**: Umożliwia serwerowi działanie z wykorzystaniem tożsamości klienta.
- **Delegation**: Działa podobnie do Impersonation, ale dodatkowo umożliwia przekazanie tej tożsamości systemom zdalnym, z którymi komunikuje się serwer, zapewniając zachowanie poświadczeń.

#### Impersonate Tokens

Korzystając z modułu _**incognito**_ w metasploit, jeśli masz wystarczające uprawnienia, możesz łatwo **listować** i **podszywać się pod** inne **tokeny**. Może to być przydatne do wykonywania **działań tak, jakbyś był innym użytkownikiem**. Za pomocą tej techniki możesz również **eskalować uprawnienia**.

Kilka praktycznych uwag, o których łatwo zapomnieć podczas pracy:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** wymaga **`SeImpersonatePrivilege`** u wywołującego, a nowy proces zostanie uruchomiony w **sesji wywołującego**.
- **`CreateProcessAsUserW`** jest zwykle rozwiązaniem awaryjnym, gdy **`CreateProcessWithTokenW`** kończy się błędem `1314` lub gdy trzeba uruchomić proces w **sesji wskazanej przez token**.
- Jeśli token pochodzi z **`LogonUser(LOGON32_LOGON_NETWORK)`**, zwykle jest to **token podszywania się**, dlatego przed próbą uruchomienia procesu należy użyć **`DuplicateTokenEx(..., TokenPrimary, ...)`**.
- Nie każdy token podszywania się jest równie użyteczny: **`SecurityIdentification`** pozwala sprawdzić użytkownika, ale **nie pozwala działać w jego imieniu**. Jeśli primitive coercion lub klient pipe/RPC zapewnia token tylko na poziomie identification, sprawdź **`TokenImpersonationLevel`** i użyj primitive, który zapewnia **`SecurityImpersonation`** lub wyższy poziom.

#### Kradzież tokenów bez dotykania LSASS

Jeśli masz już kontekst **service** lub **SYSTEM**, a **uprzywilejowany użytkownik jest zalogowany**, kradzież lub duplikowanie tokenu tego użytkownika jest często cichsze niż zrzucanie **LSASS**. W wielu rzeczywistych intruzjach wystarcza to do:<sup>[[2]](#references)</sup>

- wykonywania lokalnych działań jako ten użytkownik
- uzyskiwania dostępu do zdalnych zasobów jako ten użytkownik
- wykonywania operacji AD bez wcześniejszego wyodrębniania danych uwierzytelniających możliwych do ponownego użycia

Przykłady **przejmowania tokenów sesji/użytkownika** z uprzywilejowanego kontekstu znajdziesz na stronie [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Pamiętaj, że interfejsy API, takie jak **`WTSQueryUserToken`**, są przeznaczone dla **wysoce zaufanych usług** i zwykle wymagają **`LocalSystem` + `SeTcbPrivilege`**, dlatego są przede wszystkim przydatne, gdy masz już kontrolę nad kontekstem na poziomie usługi. Sposoby uzyskania **SYSTEM** wymagające określonych uprawnień znajdziesz na poniższych stronach.

### Uprawnienia tokenów

Dowiedz się, które **uprawnienia tokenów można wykorzystać do eskalacji uprawnień:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Zobacz [**wszystkie możliwe uprawnienia tokenów oraz niektóre definicje na tej zewnętrznej stronie**](https://github.com/gtworek/Priv2Admin).

## Odnośniki

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
