# Tokeny dostępu

{{#include ../../banners/hacktricks-training.md}}

## Tokeny dostępu

Każdy proces ma **główny token dostępu**, który definiuje jego kontekst zabezpieczeń. Wątek zwykle używa tego tokenu, ale może też tymczasowo mieć **token impersonacji**. Tokeny zawierają SID użytkownika, SID-y grup, uprawnienia, informacje o poziomie integralności oraz SID logowania dla sesji logowania. Procesy zazwyczaj dziedziczą odwołanie do głównego tokenu procesu nadrzędnego; nie otrzymują niezależnej kopii jego zawartości.<sup>[[4]](#references)</sup>

Te informacje można wyświetlić, wykonując `whoami /all`

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

lub za pomocą _Process Explorer_ firmy Sysinternals (wybierz proces i otwórz kartę „Security”):

![Tokeny dostępu - Tokeny dostępu: lub za pomocą Process Explorer firmy Sysinternals (wybierz proces i otwórz kartę „Security”)](<../../images/image (772).png>)

### Administrator lokalny

Gdy wobec administratora obowiązuje **UAC Admin Approval Mode**, interaktywne logowanie tworzy pełny token administratora oraz token z ograniczeniami. Explorer i zwykłe procesy potomne domyślnie używają tokenu z ograniczeniami. Żądanie podniesienia uprawnień, takie jak **Uruchom jako administrator**, prosi UAC o uruchomienie programu z pełnym tokenem. Dokładne zachowanie różni się w przypadku wbudowanego konta Administrator oraz gdy Admin Approval Mode jest wyłączony.<sup>[[5]](#references)</sup>

Przeczytaj dedykowaną [**stronę UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md), aby poznać techniki obejścia i szczegóły dotyczące zasad.

W praktyce oznacza to, że **niepodniesiona powłoka administratora zwykle działa z tokenem z ograniczeniami**. Dlatego `whoami /groups` często pokazuje **`BUILTIN\Administrators` jako `Deny only`**, dopóki proces nie zostanie podniesiony. Wewnętrznie Windows przechowuje **powiązany token z podniesionymi uprawnieniami** (`TokenLinkedToken`) i śledzi ten stan za pomocą pól takich jak `TokenElevationType`.

### Impersonacja użytkownika za pomocą poświadczeń

Jeśli masz **prawidłowe poświadczenia dowolnego innego użytkownika**, możesz **utworzyć** **nową sesję logowania** przy ich użyciu:

```
runas /user:domain\username cmd.exe
```

**Token dostępu** zawiera również **odwołanie** do sesji logowania w **LSASS**; jest to przydatne, jeśli proces musi uzyskiwać dostęp do niektórych obiektów sieciowych.\
Możesz uruchomić proces, który **używa innych poświadczeń do uzyskiwania dostępu do usług sieciowych**, używając:

```
runas /user:domain\username /netonly cmd.exe
```

Jest to przydatne, jeśli masz przydatne poświadczenia umożliwiające dostęp do obiektów w sieci, ale te poświadczenia nie są poprawne na bieżącym hoście, ponieważ będą używane wyłącznie w sieci (na bieżącym hoście zostaną użyte uprawnienia bieżącego użytkownika).

#### Szczegóły `runas /netonly`

`runas /netonly` (oraz helpery C2, takie jak `make_token`) tworzy token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Warto to zrozumieć podczas lateral movement, ponieważ:<sup>[[3]](#references)</sup>

- **Lokalnie** nowy proces zachowuje **tę samą lokalną tożsamość**, grupy, poziom integralności i większość tych samych decyzji dotyczących dostępu co bieżący token.
- **Zdalnie** uwierzytelnianie ruchu wychodzącego może używać **podanych poświadczeń** dla SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Dlatego `whoami` może nadal wyświetlać **pierwotnego lokalnego użytkownika**, podczas gdy dostęp do sieci odbywa się jako **inne konto**.

To świetne rozwiązanie, gdy poświadczenia są poprawne w domenie lub na innym hoście, ale użytkownik **nie może lub nie powinien logować się lokalnie** na bieżącej maszynie.

### Typy tokenów

Dostępne są dwa typy tokenów:<sup>[[4]](#references)[[6]](#references)</sup>

- **Token podstawowy**: Reprezentuje kontekst zabezpieczeń procesu. Proces potomny zwykle dziedziczy token podstawowy procesu nadrzędnego, natomiast API tworzące proces z jawnym tokenem nakładają własne wymagania dotyczące dostępu do tokenu i uprawnień wywołującego.
- **Token personifikacji**: Pozwala wątkowi serwera tymczasowo używać kontekstu zabezpieczeń klienta podczas sprawdzania dostępu. Ma cztery poziomy:
  - **Anonimowy**: Zapewnia serwerowi dostęp zbliżony do dostępu niezidentyfikowanego użytkownika.
  - **Identyfikacja**: Pozwala serwerowi zweryfikować tożsamość klienta bez używania jej do uzyskiwania dostępu do obiektów.
  - **Personifikacja**: Umożliwia serwerowi działanie w ramach tożsamości klienta.
  - **Delegowanie**: Pozwala serwerowi personifikować klienta w systemach zdalnych, jeśli mechanizm uwierzytelniania i konfiguracja konta obsługują delegowanie.

#### Wstępnie oceń przechwycony token przed użyciem

Nie wybieraj tokenu wyłącznie na podstawie nazwy użytkownika. To samo konto może mieć kilka tokenów z różnymi sesjami logowania, identyfikatorami SID usług, uprawnieniami, poziomami integralności, ograniczeniami i poświadczeniami sieciowymi.<sup>[[9]](#references)</sup> Odczytaj co najmniej pola **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** oraz **`TokenStatistics.AuthenticationId`** za pomocą `GetTokenInformation`.<sup>[[7]](#references)</sup>

Ograniczony token może zawierać identyfikatory SID typu deny-only, usunięte uprawnienia i ograniczające identyfikatory SID. Gdy występują ograniczające identyfikatory SID, Windows wykonuje jedną kontrolę dostępu przy użyciu włączonych identyfikatorów SID, a drugą przy użyciu ograniczających identyfikatorów SID; **obie kontrole muszą zezwolić na dostęp**. Dlatego atrakcyjny identyfikator SID użytkownika lub włączona grupa widoczna w wynikach nie dowodzą same w sobie, że token umożliwia dostęp do obiektu docelowego.<sup>[[8]](#references)</sup>

Skorzystaj z poniższego schematu decyzyjnego, uwzględniającego udokumentowane wymagania dotyczące tokenów i tworzenia procesów:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Token podstawowy** wymaga uchwytu z prawami `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`, zanim będzie można przekazać go do `CreateProcessWithTokenW` lub `CreateProcessAsUserW`.
2. Przekształć **token personifikacji** za pomocą `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokeny na poziomie identyfikacji mogą udostępniać dane tożsamości, ale nie mogą wykonywać kontroli dostępu w imieniu tego klienta.
3. `CreateProcessWithTokenW` wymaga uprawnienia `SeImpersonatePrivilege` i uruchamia proces potomny w sesji wywołującego. `CreateProcessAsUserW` używa natomiast sesji tokenu, ale zwykle wymaga uprawnienia `SeIncreaseQuotaPrivilege` i może wymagać `SeAssignPrimaryTokenPrivilege`. Jeśli poświadczenia są dostępne, a tych uprawnień brakuje, udokumentowaną alternatywą jest `CreateProcessWithLogonW`.

#### Wyszukuj uchwyty tokenów, a nie tylko właścicieli procesów

Otwieranie tokenu podstawowego każdego procesu może pominąć **tokeny personifikacji zachowane jako zwykłe uchwyty** w usługach i procesach brokerów. Można ponownie wykorzystać następujący schemat pracy z tabelą uchwytów: wylicz uchwyty systemowe, filtruj obiekty tokenów, otwórz każdy proces będący ich właścicielem z prawem `PROCESS_DUP_HANDLE`, zduplikuj kandydujący uchwyt do bieżącego procesu, a następnie odczytaj powyższe pola. Potwierdź, że zduplikowany uchwyt zawiera prawa `TOKEN_QUERY` i `TOKEN_DUPLICATE`; samo znalezienie uchwytu tokenu nie oznacza, że można go zduplikować do użytecznego tokenu podstawowego. Procesy chronione i listy DACL procesów nadal mogą blokować dostęp do uchwytu procesu będącego właścicielem.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatyzuje wyliczanie zarówno tokenów podstawowych procesów, jak i zachowanych uchwytów tokenów. `list_token` zachowuje jednego preferowanego kandydata na nazwę użytkownika, a `list_all_token` wyświetla wszystkich kandydatów. PID ogranicza wyliczanie do jednego procesu będącego właścicielem.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Do ręcznej inspekcji i sprawdzania dostępu **TokenUniverse** może otwierać tokeny procesów/wątków, wyszukiwać istniejące uchwyty tokenów, sprawdzać ograniczenia i sesje logowania, duplikować tokeny oraz testować kilka metod tworzenia procesów.<sup>[[13]](#references)</sup> Informacje o podstawowym mechanizmie uchwytów między procesami znajdziesz tutaj:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Podszywanie się przy użyciu tokenów

Korzystając z modułu _**incognito**_ w metasploit, jeśli masz wystarczające uprawnienia, możesz łatwo **wyświetlić** i **podszyć się pod** inne **tokeny**. Może to być przydatne do wykonywania **działań tak, jakbyś był innym użytkownikiem**. Tą techniką możesz również **eskalować uprawnienia**.

Oto kilka praktycznych uwag, o których łatwo zapomnieć podczas działania:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** wymaga uprawnienia **`SeImpersonatePrivilege`** u wywołującego, a nowy proces zostanie uruchomiony w **sesji wywołującego**.
- **`CreateProcessAsUserW`** może być rozwiązaniem awaryjnym, gdy `CreateProcessWithTokenW` zwraca błąd `1314`, ale tylko wtedy, gdy wywołujący spełnia wymagania dotyczące uprawnień. To również właściwy wybór, gdy proces potomny ma działać w **sesji wskazanej przez token**.<sup>[[9]](#references)[[10]](#references)</sup>
- Jeśli token pochodzi z **`LogonUser(LOGON32_LOGON_NETWORK)`**, zwykle jest to **token impersonacji**, więc przed próbą uruchomienia z jego użyciem procesu należy wywołać **`DuplicateTokenEx(..., TokenPrimary, ...)`**.
- Nie każdy token impersonacji jest równie użyteczny: **`SecurityIdentification`** pozwala sprawdzić użytkownika, ale **nie pozwala działać w jego imieniu**. Jeśli mechanizm wymuszający uwierzytelnienie lub klient potoku/RPC udostępnia tylko token na poziomie identyfikacji, sprawdź **`TokenImpersonationLevel`** i użyj mechanizmu, który zwraca poziom **`SecurityImpersonation`** lub wyższy.

#### Kradzież tokenów bez ingerencji w LSASS

Jeśli masz już kontekst **usługi** lub **SYSTEM**, a **zalogowany jest użytkownik z wysokimi uprawnieniami**, kradzież lub duplikowanie tokenu tego użytkownika jest często mniej widoczne niż zrzucanie **LSASS**. W wielu rzeczywistych włamaniach wystarczy to, aby:<sup>[[2]](#references)</sup>

- wykonywać lokalne działania jako ten użytkownik
- uzyskiwać dostęp do zdalnych zasobów jako ten użytkownik
- wykonywać operacje w AD bez wcześniejszego wyodrębniania danych uwierzytelniających nadających się do ponownego użycia

Przykłady **przejmowania tokenów sesji/użytkownika** z kontekstu o wysokich uprawnieniach znajdziesz w [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Pamiętaj, że interfejsy API takie jak **`WTSQueryUserToken`** są przeznaczone dla **usług o wysokim poziomie zaufania** i zazwyczaj wymagają **`LocalSystem` + `SeTcbPrivilege`**, dlatego są przydatne przede wszystkim wtedy, gdy masz już kontrolę nad kontekstem usługi. Informacje o metodach uzyskania **SYSTEM** z wykorzystaniem konkretnych uprawnień znajdziesz na poniższych stronach.

### Uprawnienia tokenów

Dowiedz się, **które uprawnienia tokenów można wykorzystać do eskalacji uprawnień:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Zobacz [**pełną listę możliwych uprawnień tokenów i definicje na tej zewnętrznej stronie**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Zrozumienie i nadużywanie tokenów dostępu — część II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Nadużywanie tokenów Windows w celu przejęcia Active Directory bez ingerencji w LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Wyjaśnienie polecenia „make_token” w Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Tokeny dostępu — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Jak działa Kontrola konta użytkownika — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Poziomy impersonacji — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Wyliczenie TOKEN_INFORMATION_CLASS — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Tokeny z ograniczeniami — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Funkcja CreateProcessWithTokenW — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Funkcja CreateProcessAsUserW — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Funkcja DuplicateHandle — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
