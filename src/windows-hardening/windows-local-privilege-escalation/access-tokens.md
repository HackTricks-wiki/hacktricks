# Tokeny dostępu

{{#include ../../banners/hacktricks-training.md}}

## Tokeny dostępu

Każdy proces ma **podstawowy token dostępu**, który określa jego kontekst bezpieczeństwa. Wątek zwykle korzysta z tego tokenu, ale może też tymczasowo mieć **token impersonacji**. Tokeny zawierają SID użytkownika, SID grup, uprawnienia, informacje o poziomie integralności oraz SID logowania dla sesji logowania. Procesy zazwyczaj dziedziczą odwołanie do podstawowego tokenu procesu nadrzędnego; nie otrzymują niezależnej kopii jego zawartości.<sup>[[4]](#references)</sup>

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

lub używając _Process Explorer_ z pakietu Sysinternals (wybierz proces i otwórz kartę „Security”):

![Access Tokens - Access Tokens: lub używając Process Explorer z pakietu Sysinternals (wybierz proces i otwórz kartę „Security”)](<../../images/image (772).png>)

### Administrator lokalny

Gdy do administratora ma zastosowanie **UAC Admin Approval Mode**, logowanie interaktywne tworzy pełny token administratora oraz token z ograniczeniami. Explorer i zwykłe procesy podrzędne domyślnie używają tokenu z ograniczeniami. Żądanie podniesienia uprawnień, takie jak **Run as administrator**, prosi UAC o uruchomienie programu z pełnym tokenem. Dokładne zachowanie zależy od tego, czy używane jest wbudowane konto Administrator, oraz od tego, czy Admin Approval Mode jest wyłączony.<sup>[[5]](#references)</sup>

Przeczytaj dedykowaną [**stronę UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md), aby poznać techniki obejścia i szczegóły zasad.

W praktyce oznacza to, że **niepodniesiona powłoka administratora zwykle działa z tokenem z ograniczeniami**. Dlatego polecenie `whoami /groups` często pokazuje **`BUILTIN\Administrators` jako `Deny only`**, dopóki proces nie zostanie uruchomiony z podniesionymi uprawnieniami. Wewnętrznie Windows przechowuje **powiązany token z podniesionymi uprawnieniami** (`TokenLinkedToken`) i śledzi ten stan za pomocą pól takich jak `TokenElevationType`.

### Impersonacja użytkownika za pomocą poświadczeń

Jeśli masz **prawidłowe poświadczenia innego użytkownika**, możesz **utworzyć** **nową sesję logowania** przy użyciu tych poświadczeń:

```
runas /user:domain\username cmd.exe
```

**Token dostępu** zawiera również **referencję** do sesji logowania w **LSASS**. Jest to przydatne, gdy proces musi uzyskać dostęp do niektórych obiektów sieciowych.\
Możesz uruchomić proces, który **używa innych poświadczeń do uzyskiwania dostępu do usług sieciowych**, za pomocą:

```
runas /user:domain\username /netonly cmd.exe
```

Jest to przydatne, jeśli masz poświadczenia umożliwiające dostęp do obiektów w sieci, ale nie są one prawidłowe na bieżącym hoście, ponieważ będą używane wyłącznie w sieci (na bieżącym hoście zostaną użyte uprawnienia bieżącego użytkownika).

#### Szczegóły `runas /netonly`

`runas /netonly` (oraz narzędzia pomocnicze C2, takie jak `make_token`) tworzy token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Warto to zrozumieć podczas lateral movement, ponieważ:<sup>[[3]](#references)</sup>

- **Lokalnie** nowy proces zachowuje **tę samą lokalną tożsamość**, grupy, poziom integralności i większość tych samych decyzji dotyczących dostępu co bieżący token.
- **Zdalnie** uwierzytelnianie wychodzące może używać **podanych poświadczeń** w przypadku SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Dlatego `whoami` może nadal wyświetlać **pierwotnego lokalnego użytkownika**, podczas gdy dostęp do sieci odbywa się jako **inne konto**.

To świetna opcja, gdy poświadczenia są prawidłowe w domenie lub na innym hoście, ale użytkownik **nie może lub nie powinien logować się lokalnie** na bieżącej maszynie.

### Typy tokenów

Dostępne są dwa typy tokenów:<sup>[[4]](#references)[[6]](#references)</sup>

- **Token podstawowy**: Reprezentuje kontekst zabezpieczeń procesu. Proces potomny zwykle dziedziczy token podstawowy procesu nadrzędnego, natomiast interfejsy API tworzące proces z jawnym tokenem nakładają własne wymagania dotyczące dostępu do tokenu i uprawnień wywołującego.
- **Token personifikacji**: Umożliwia wątkowi serwera tymczasowe użycie kontekstu zabezpieczeń klienta podczas kontroli dostępu. Ma cztery poziomy:
  - **Anonimowy**: Zapewnia serwerowi dostęp podobny do dostępu niezidentyfikowanego użytkownika.
  - **Identyfikacja**: Umożliwia serwerowi weryfikację tożsamości klienta bez wykorzystywania jej do uzyskiwania dostępu do obiektów.
  - **Personifikacja**: Umożliwia serwerowi działanie w ramach tożsamości klienta.
  - **Delegowanie**: Pozwala serwerowi personifikować klienta w systemach zdalnych, jeśli mechanizm uwierzytelniania i konfiguracja konta obsługują delegowanie.

#### Wstępna analiza przechwyconego tokenu przed użyciem

Nie wybieraj tokenu wyłącznie na podstawie nazwy użytkownika. To samo konto może mieć kilka tokenów z różnymi sesjami logowania, identyfikatorami SID usług, uprawnieniami, poziomami integralności, ograniczeniami i poświadczeniami sieciowymi.<sup>[[9]](#references)</sup> Odczytaj co najmniej wartości **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** oraz **`TokenStatistics.AuthenticationId`** za pomocą `GetTokenInformation`.<sup>[[7]](#references)</sup>

Ograniczony token może zawierać identyfikatory SID używane wyłącznie do odmowy dostępu, usunięte uprawnienia i identyfikatory SID ograniczające. Gdy występują identyfikatory SID ograniczające, Windows przeprowadza jedną kontrolę dostępu z włączonymi identyfikatorami SID, a drugą z identyfikatorami SID ograniczającymi; **obie kontrole muszą zezwolić na dostęp**. Dlatego atrakcyjny identyfikator SID użytkownika lub włączona grupa widoczna w wynikach nie dowodzą same w sobie, że token umożliwia dostęp do obiektu docelowego.<sup>[[8]](#references)</sup>

Zastosuj poniższy schemat decyzyjny, uwzględniający udokumentowane wymagania dotyczące tokenów i tworzenia procesów:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Token podstawowy** wymaga uchwytu z uprawnieniami `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`, zanim będzie można przekazać go do `CreateProcessWithTokenW` lub `CreateProcessAsUserW`.
2. Przekształć **token personifikacji** za pomocą `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Tokeny na poziomie identyfikacji mogą ujawniać dane o tożsamości, ale nie mogą przeprowadzać kontroli dostępu jako dany klient.
3. `CreateProcessWithTokenW` wymaga `SeImpersonatePrivilege` i uruchamia proces potomny w sesji wywołującego. Natomiast `CreateProcessAsUserW` używa sesji tokenu, ale zwykle wymaga `SeIncreaseQuotaPrivilege`, a czasami także `SeAssignPrimaryTokenPrivilege`. Jeśli dostępne są poświadczenia, a tych uprawnień brakuje, udokumentowaną alternatywą jest `CreateProcessWithLogonW`.

#### Wyszukuj uchwyty tokenów, a nie tylko właścicieli procesów

Otwarcie tokenu podstawowego każdego procesu może nie wykryć **tokenów personifikacji przechowywanych jako zwykłe uchwyty** w usługach i procesach brokera. Można użyć wielokrotnego użytku procedury pracy z tabelą uchwytów: wyliczyć uchwyty systemowe, odfiltrować obiekty tokenów, otworzyć każdy proces właściciela z `PROCESS_DUP_HANDLE`, zduplikować kandydujący uchwyt do bieżącego procesu, a następnie odczytać powyższe pola. Sprawdź, czy zduplikowany uchwyt zawiera `TOKEN_QUERY` i `TOKEN_DUPLICATE`; samo znalezienie uchwytu tokenu nie oznacza, że można go zduplikować do użytecznego tokenu podstawowego. Procesy chronione i DACL procesów nadal mogą blokować dostęp do uchwytu procesu właściciela.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` automatyzuje wyliczanie tokenów podstawowych procesów oraz przechowywanych uchwytów tokenów. `list_token` zachowuje jednego preferowanego kandydata dla każdej nazwy użytkownika, natomiast `list_all_token` wyświetla wszystkich kandydatów. PID ogranicza wyliczanie do jednego procesu właściciela.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

W celu ręcznej inspekcji i sprawdzania dostępu **TokenUniverse** może otwierać tokeny procesów/wątków, wyszukiwać istniejące uchwyty tokenów, sprawdzać ograniczenia i sesje logowania, duplikować tokeny oraz testować kilka metod tworzenia procesów.<sup>[[13]](#references)</sup> Informacje o podstawowym mechanizmie uchwytów między procesami znajdziesz tutaj:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Wyszukiwanie aktywnych tokenów personifikacji wątków

Wątek usługi może tymczasowo personifikować klienta, nawet jeśli **główny token procesu** należy do konta usługi, dlatego skanowanie procesów według ich właściciela może nie wykryć kontekstu klienta.<sup>[[4]](#references)</sup> TokenUniverse może wyświetlać dostępne tokeny procesów/wątków; w System Informer sprawdź kartę **Threads** procesu i kolumnę **Impersonation**, aby znaleźć potencjalne wątki.<sup>[[13]](#references)[[14]](#references)</sup>

Aby sprawdzić to za pomocą ukierunkowanego wywołania API, utwórz migawkę `TH32CS_SNAPTHREAD`, przefiltruj `THREADENTRY32.th32OwnerProcessID` według PID usługi, a następnie dla każdego dostępnego wątku wywołaj `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` oraz `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)`.<sup>[[15]](#references)[[16]](#references)</sup> Wartość `TRUE` sprawia, że kontrola dostępu przy otwieraniu tokenu korzysta z kontekstu **procesu** wywołującego, co ma znaczenie, jeśli sam skaner personifikuje użytkownika na poziomie identyfikacji.<sup>[[17]](#references)</sup> Przed próbą duplikowania tokenu lub tworzenia procesu opisaną powyżej sprawdź użytkownika tokenu, jego typ, poziom personifikacji i identyfikator logowania.<sup>[[7]](#references)</sup> Wątek może przestać personifikować użytkownika między enumeracją a próbą otwarcia; brak tokenu, tokeny anonimowe, wątki chronione, listy DACL wątków i listy DACL tokenów mogą uniemożliwić pobranie tokenu.<sup>[[16]](#references)[[17]](#references)</sup> W przeciwieństwie do skanowania zachowanych uchwytów tokenów usługi ta metoda sprawdza **aktualnie przypisany token wątku**.

Informacje o ścieżce ataku, która pozyskuje token wątku przez nakłonienie uprzywilejowanego klienta do połączenia się z Twoim potokiem, zamiast skanowania istniejących wątków, znajdziesz w sekcji [personifikacja klienta named pipe](named-pipe-client-impersonation.md).

#### Personifikowanie tokenów

Jeśli masz wystarczające uprawnienia, za pomocą modułu _**incognito**_ w metasploit możesz łatwo **wyświetlać** i **personifikować** inne **tokeny**. Może to być przydatne do wykonywania **działań tak, jakbyś był innym użytkownikiem**. Ta technika może również posłużyć do **eskalacji uprawnień**.

Kilka praktycznych uwag, o których łatwo zapomnieć podczas działania:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** wymaga uprawnienia **`SeImpersonatePrivilege`** od wywołującego, a nowy proces zostanie uruchomiony w **sesji wywołującego**.
- **`CreateProcessAsUserW`** może być użyte jako rozwiązanie awaryjne, gdy `CreateProcessWithTokenW` zwraca błąd `1314`, ale tylko jeśli wywołujący spełnia wymagania dotyczące uprawnień. Jest to również właściwy wybór, gdy proces potomny ma działać w **sesji wskazanej przez token**.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** zwraca **token personifikacji**. Przed utworzeniem procesu przekształć go za pomocą **`DuplicateTokenEx(..., TokenPrimary, ...)`**. Nawet po przekształceniu wynikowy proces nie może użyć tego logowania sieciowego do uzyskania dostępu do uwierzytelnionych udziałów zdalnych ani drukarek: ten typ logowania nie buforuje poświadczeń. Jeśli masz poświadczenia i potrzebujesz dalszego dostępu do sieci, użyj logowania interaktywnego lub logowania z hasłem w postaci jawnej; nie myl tego z `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), które zachowuje lokalną tożsamość, a jednocześnie dostarcza poświadczenia do połączeń wychodzących.<sup>[[18]](#references)</sup>
- Nie każdy token personifikacji jest równie przydatny: **`SecurityIdentification`** pozwala sprawdzić użytkownika, ale **nie pozwala działać jako on**. Jeśli prymityw coercion lub klient potoku/RPC udostępnia tylko token na poziomie identyfikacji, sprawdź **`TokenImpersonationLevel`** i użyj prymitywu, który zapewnia **`SecurityImpersonation`** lub wyższy poziom.

#### Kradzież tokenów bez dotykania LSASS

Jeśli masz już kontekst **usługi** lub **SYSTEM**, a **uprzywilejowany użytkownik jest zalogowany**, kradzież lub duplikowanie tokenu tego użytkownika jest często trudniejsze do wykrycia niż zrzucanie **LSASS**. W wielu rzeczywistych włamaniach wystarczy to, aby:<sup>[[2]](#references)</sup>

- wykonywać lokalne działania jako ten użytkownik
- uzyskiwać dostęp do zdalnych zasobów jako ten użytkownik
- wykonywać operacje w AD bez wcześniejszego wyodrębniania poświadczeń wielokrotnego użytku

Przykłady **przejęcia tokenu sesji/użytkownika** z uprzywilejowanego kontekstu znajdziesz w [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Pamiętaj, że interfejsy API takie jak **`WTSQueryUserToken`** są przeznaczone dla **wysoce zaufanych usług** i zwykle wymagają **`LocalSystem` + `SeTcbPrivilege`**, dlatego są przydatne głównie wtedy, gdy masz już kontrolę nad kontekstem na poziomie usługi. Sposoby uzyskania **SYSTEM** z użyciem konkretnych uprawnień znajdziesz na poniższych stronach.

### Uprawnienia tokenu

Dowiedz się, które **uprawnienia tokenu można wykorzystać do eskalacji uprawnień:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Zobacz [**wszystkie możliwe uprawnienia tokenu i kilka definicji na tej zewnętrznej stronie**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Zrozumienie i nadużywanie tokenów dostępu — część II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Nadużywanie tokenów Windows w celu przejęcia Active Directory bez dotykania LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Objaśnienie polecenia „make_token” w Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Tokeny dostępu — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Jak działa Kontrola konta użytkownika — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Poziomy personifikacji — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Wyliczenie TOKEN_INFORMATION_CLASS — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Tokeny z ograniczeniami — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Funkcja CreateProcessWithTokenW — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Funkcja CreateProcessAsUserW — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Funkcja DuplicateHandle — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [Prośba o dodanie funkcji obsługi tokenów wątków do System Informer](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Przechodzenie przez listę wątków — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken — Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
