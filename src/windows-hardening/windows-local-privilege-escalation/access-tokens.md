# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Każdy **użytkownik zalogowany** do systemu **posiada access token z informacjami o bezpieczeństwie** dla tej sesji logowania. System tworzy access token, gdy użytkownik się loguje. **Każdy uruchomiony proces** w imieniu użytkownika **ma kopię access token**. Token identyfikuje użytkownika, grupy użytkownika oraz uprawnienia użytkownika. Token zawiera także logon SID (Security Identifier), który identyfikuje bieżącą sesję logowania.

Możesz zobaczyć te informacje, wykonując `whoami /all`
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
lub używając _Process Explorer_ z Sysinternals (wybierz proces i otwórz kartę "Security"):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

Gdy lokalny administrator loguje się, **tworzone są dwa access tokens**: jeden z uprawnieniami administratora i drugi z normalnymi uprawnieniami. **Domyślnie**, gdy ten użytkownik uruchamia proces, używany jest token z **zwykłymi** (nieadministratorskimi) **uprawnieniami**. Gdy ten użytkownik próbuje **uruchomić** cokolwiek **jako administrator** (na przykład "Run as Administrator"), **UAC** zostanie użyte, aby poprosić o zgodę.\
Jeśli chcesz [**dowiedzieć się więcej o UAC, przeczytaj tę stronę**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

W praktyce oznacza to, że **niewywindowana powłoka admina zwykle działa z filtrowanym tokenem**. Dlatego `whoami /groups` często pokazuje **`BUILTIN\Administrators` jako `Deny only`**, dopóki proces nie zostanie wywindowany. Wewnątrz Windows utrzymuje **powiązany podwyższony token** (`TokenLinkedToken`) i śledzi stan za pomocą pól takich jak `TokenElevationType`.

### Credentials user impersonation

Jeśli masz **prawidłowe poświadczenia dowolnego innego użytkownika**, możesz **utworzyć** **nową sesję logowania** z tymi poświadczeniami :
```
runas /user:domain\username cmd.exe
```
**access token** ma również **reference** do sesji logowania w **LSASS**, co jest przydatne, jeśli proces musi uzyskać dostęp do niektórych obiektów sieci.\
Możesz uruchomić proces, który **uses different credentials for accessing network services** używając:
```
runas /user:domain\username /netonly cmd.exe
```
Jest to przydatne, jeśli masz użyteczne credentials do dostępu do obiektów w sieci, ale te credentials nie są ważne na obecnym hoście, ponieważ będą używane tylko w sieci (na obecnym hoście zostaną użyte uprawnienia bieżącego użytkownika).

#### Szczegóły `runas /netonly`

`runas /netonly` (oraz helpery C2, takie jak `make_token`) tworza **`LOGON32_LOGON_NEW_CREDENTIALS`** token. Jest to bardzo przydatne do zrozumienia podczas lateral movement, ponieważ:

- **Lokalnie**, nowy proces zachowuje **tę samą lokalną tożsamość**, grupy, poziom integralności i większość tych samych decyzji dostępu co bieżący token.
- **Zdalnie**, uwierzytelnianie wychodzące może używać **podanych credentials** dla SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Dlatego `whoami` może nadal pokazywać **oryginalnego lokalnego użytkownika**, podczas gdy dostęp sieciowy odbywa się jako **alternatywne konto**.

To świetna opcja, gdy credentials są ważne w domenie lub na innym hoście, ale użytkownik **nie może lub nie powinien logować się lokalnie** na bieżącej maszynie.

### Typy tokenów

Dostępne są dwa typy tokenów:

- **Primary Token**: Reprezentuje bezpieczeństwo credentials procesu. Tworzenie i powiązanie primary tokens z procesami to działania wymagające podwyższonych uprawnień, co podkreśla zasadę separacji uprawnień. Zwykle usługa uwierzytelniania odpowiada za tworzenie tokenów, a usługa logowania za ich powiązanie z powłoką systemową użytkownika. Warto zauważyć, że procesy dziedziczą primary token swojego procesu nadrzędnego podczas tworzenia.
- **Impersonation Token**: Umożliwia aplikacji serwera tymczasowe przyjęcie tożsamości klienta w celu dostępu do bezpiecznych obiektów. Mechanizm ten jest podzielony na cztery poziomy działania:
- **Anonymous**: Przyznaje dostęp serwera podobny do dostępu niezidentyfikowanego użytkownika.
- **Identification**: Pozwala serwerowi zweryfikować tożsamość klienta bez wykorzystywania jej do dostępu do obiektów.
- **Impersonation**: Umożliwia serwerowi działanie pod tożsamością klienta.
- **Delegation**: Podobne do Impersonation, ale obejmuje możliwość rozszerzenia tego przyjęcia tożsamości na zdalne systemy, z którymi serwer wchodzi w interakcję, zapewniając zachowanie credentials.

#### Impersonate Tokens

Używając modułu _**incognito**_ w metasploit, jeśli masz wystarczające uprawnienia, możesz łatwo **wypisać** i **impersonate** inne **tokens**. Może to być przydatne do wykonywania **działań tak, jakbyś był innym użytkownikiem**. Możesz też **eskalować privileges** tą techniką.

Kilka praktycznych uwag, o których łatwo zapomnieć podczas działania:

- **`CreateProcessWithTokenW`** wymaga **`SeImpersonatePrivilege`** po stronie wywołującego, a nowy proces uruchomi się w **sesji wywołującego**.
- **`CreateProcessAsUserW`** jest zwykle alternatywą, gdy `CreateProcessWithTokenW` zwraca błąd `1314`, albo gdy trzeba uruchomić proces w **sesji wskazanej przez token**.
- Jeśli token pochodzi z **`LogonUser(LOGON32_LOGON_NETWORK)`**, to zwykle jest to **impersonation token**, więc przed próbą uruchomienia procesu trzeba użyć **`DuplicateTokenEx(..., TokenPrimary, ...)`**.
- Nie każdy impersonation token jest równie użyteczny: **`SecurityIdentification`** pozwala sprawdzić użytkownika, ale **nie działać jako on**. Jeśli coercion primitive lub klient pipe/RPC daje tylko token na poziomie identification, sprawdź **`TokenImpersonationLevel`** i przełącz się na primitive, który daje **`SecurityImpersonation`** lub lepszy.

#### Token theft bez dotykania LSASS

Jeśli masz już kontekst **usługi** lub **SYSTEM** i **uprzywilejowany użytkownik jest zalogowany**, kradzież lub duplikacja tokena tego użytkownika jest często cichsza niż zrzucanie **LSASS**. W wielu rzeczywistych intruzjach wystarcza to do:

- wykonywania lokalnych działań jako ten użytkownik
- dostępu do zasobów zdalnych jako ten użytkownik
- wykonywania operacji AD bez wcześniejszego wyciągania wielokrotnego użytku credentials

Przykłady **session/user token hijacking** z uprzywilejowanego kontekstu znajdziesz w [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Pamiętaj, że API takie jak **`WTSQueryUserToken`** są przeznaczone dla **bardzo zaufanych usług** i zwykle wymagają **`LocalSystem` + `SeTcbPrivilege`**, więc są przede wszystkim użyteczne dopiero wtedy, gdy masz już kontrolę nad kontekstem poziomu usługi. Dla metod specyficznych dla privileges, które pozwalają najpierw uzyskać **SYSTEM**, sprawdź poniższe strony.

### Token Privileges

Dowiedz się, które **token privileges można nadużyć do eskalacji privileges:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Spójrz na [**wszystkie możliwe token privileges i niektóre definicje na tej zewnętrznej stronie**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
