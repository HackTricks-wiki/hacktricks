# BloodHound & Ander Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Hierdie bladsy groepeer sommige van die nuttigste utilities om Active Directory-verhoudings te **enumerate** en te **visualise**.  Vir collection oor die stealthy **Active Directory Web Services (ADWS)**-kanaal, kyk na die verwysing hierbo.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) is 'n gevorderde **AD viewer & editor** wat die volgende moontlik maak:

* GUI-blaai deur die directory tree
* Redigering van object attributes & security descriptors
* Skep / vergelyk van snapshots vir offline analysis

### Vinnige gebruik

1. Begin die tool en verbind aan `dc01.corp.local` met enige domain credentials.
2. Skep 'n offline snapshot via `File ➜ Create Snapshot`.
3. Vergelyk twee snapshots met `File ➜ Compare` om permission drifts raak te sien.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) onttrek 'n groot stel artefacts uit 'n domain (ACLs, GPOs, trusts, CA templates …) en genereer 'n **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (grafiekvisualisering)

[BloodHound](https://github.com/SpecterOps/BloodHound) gebruik grafiekteorie om verborge voorregverhoudings binne on-prem AD, Entra ID en enige bykomende aanvalsvlakdata wat jy deur OpenGraph inneem, bloot te lê.<sup>[[1]](#references)</sup>

### Ontplooiing (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Versamelaars

* `SharpHound.exe` / `Invoke-BloodHound` – native of PowerShell-variant
* `RustHound-CE` – kruisplatform CE-versamelaar vir Linux, macOS en Windows
* `NetExec --bloodhound` – vinnige LDAP-gedrewe versameling vanaf Linux
* `AzureHound` – Entra ID-enumerasie
* **SoaPy + BOFHound** – ADWS-versameling (sien skakel bo-aan)

> BloodHound CE `v8+` het die versamelaar-uitvoerformaat verander toe OpenGraph bekendgestel is. Nadat jy vanaf legacy BloodHound of ouer CE-installasies opgegradeer het, voer discovery weer met huidige versamelaars uit voordat jy die data invoer.<sup>[[1]](#references)</sup>

#### Algemene SharpHound-modusse
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Die collectors genereer JSON wat via die BloodHound GUI ingeneem word.

#### SharpHound vanaf ’n Windows-host wat nie aan die domain gekoppel is nie

As jou operator-VM nie aan die target domain gekoppel is nie, wys DNS na ’n DC, begin ’n **network-only** shell, verifieer dat jy `SYSVOL`/`NETLOGON` op ’n DC kan sien, en versamel dan data teen die remote domain:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Dit is nuttig vir weggooibare jump boxes of operateurwerkstasies wat nie aan die domein gekoppel moet wees nie.

#### Kruisplatform-insameling vanaf Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` is ’n goeie verstekopsie wanneer jy CE-versoenbare uitvoer vanaf ’n nie-Windows-gasheer wil hê.<sup>[[2]](#references)</sup> `NetExec` is gerieflik wanneer jy dit reeds vir LDAP-validering of spraying gebruik en vinnig ’n graaf wil invoer. Vir nie-AD-datastelle kan BloodHound OpenGraph uitgebrei word met collectors soos [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (OpenGraph-padprioritisering)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) werk bo-op BloodHound CE/OpenGraph wanneer die graaf te groot is om handmatig deur te blaai. In plaas daarvan om slegs te vra of een principal een teiken kan bereik, bereken dit die kortste paaie vanaf baie gebruikers en rekenaars met lae voorregte na hoëwaarde-objekte, groepeer dit paaie wat dieselfde kante hergebruik, en wys dit die gedeelde knelpunt uit wat eerste reggestel behoort te word.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Met `MSSQLHound`- en `ConfigManBearPig`-data ingevoer, kan een bevinding oor [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) en [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md) heen strek, eerder as om dit as afsonderlike leidrade te laat.<sup>[[4]](#references)</sup> Voorbeeld van ’n gedeelde pad:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Volg die **effektiewe sekuriteitskonteks** by elke rand. ’n Pad word domeinkritiek sodra enige oorgang as ’n bevoorregte domeinidentiteit uitgevoer word, selfs al het dit van ’n normale gebruiker begin.
- Gegroepeerde bevindings is ideaal vir **choke-point-remediëring**: die verwydering van een SQL-impersonation-permission, linked-server-trust, certificate-template-abuse path of SCCM-assignment kan baie kortste paaie tegelyk laat verdwyn.
- Herprioritiseer “medium”-bevindings met **graph context**. SMB signing wat gedeaktiveer is, WebClient-blootstelling, delegation-foute of NTLM-relayable SQL servers verdien hoër prioriteit wanneer die compromised node onward paths na Domain Admins, Domain Controllers, CAs of SCCM site servers het.
- As jy ook `NTDS.dit`-uitset en ’n hashcat-potfile het, korreleer `--pwd` gekraakte wagwoorde met BloodHound-eienskappe sodat jy vinnig gewone wagwoordhergebruik kan onderskei van gekraakte creds op privileged, Kerberoastable, AS-REP roastable of path-relevant accounts.

### Privilege & logon-right-versameling

Windows **token privileges** (bv. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) kan DACL-checks omseil, dus stel die kartering daarvan oor die hele domein plaaslike LPE-edges bloot wat ACL-only graphs miskyk. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` en hul `SeDeny*`-teenhangers) word deur LSA afgedwing voordat ’n token selfs bestaan, en denies geniet voorkeur; daarom beperk hulle laterale beweging wesenlik (RDP/SMB/scheduled task/service logon).<sup>[[3]](#references)</sup>

**Run collectors elevated** waar moontlik: UAC skep ’n gefiltreerde token vir interactive admins (via `NtFilterToken`), verwyder sensitiewe privileges en merk admin-SIDs as deny-only. As jy privileges vanuit ’n non-elevated shell enumerateer, sal waardevolle privileges onsigbaar wees en BloodHound sal nie die edges inneem nie.<sup>[[3]](#references)</sup>

Twee aanvullende SharpHound-versamelingstrategieë bestaan nou:<sup>[[3]](#references)</sup>

- **GPO/SYSVOL-parsing (stealthy, low-privilege):**
1. Enumerate GPOs oor LDAP (`(objectCategory=groupPolicyContainer)`) en lees elke `gPCFileSysPath`.
2. Fetch `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` vanaf SYSVOL en parse die `[Privilege Rights]`-afdeling wat privilege/logon-right-name aan SIDs map.
3. Resolve GPO-links via `gPLink` op OUs/sites/domains, lys computers in die linked containers en attributeer die rights aan daardie machines.
4. Voordeel: werk met ’n normale gebruiker en is stil; nadeel: sien slegs rights wat via GPO gepush word (local tweaks word gemis).

- **LSA RPC-enumeration (noisy, accurate):**
- Vanuit ’n context met local admin op die target, open die Local Security Policy en call `LsaEnumerateAccountsWithUserRight` vir elke privilege/logon right om assigned principals oor RPC te enumerateer.
- Voordeel: capture rights wat plaaslik of buite GPO gestel is; nadeel: noisy network traffic en admin requirement op elke host.

**Example abuse path wat deur hierdie edges blootgelê word:** `CanRDP` ➜ host waar jou user ook `SeBackupPrivilege` het ➜ start ’n elevated shell om filtered tokens te vermy ➜ gebruik backup semantics om `SAM`- en `SYSTEM`-hives te lees ondanks restrictive DACLs ➜ exfiltreer en run `secretsdump.py` offline om die plaaslike Administrator NT hash vir laterale beweging/privilege escalation te recover.<sup>[[3]](#references)</sup>

### Prioritisering van Kerberoasting met BloodHound

Gebruik graph context om roasting targeted te hou:

1. Collect eenmalig met ’n ADWS-compatible collector en werk offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Import die ZIP, merk die compromised principal as owned en run ingeboude queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) om SPN accounts met admin/infra rights bloot te lê.
3. Prioritiseer SPNs volgens blast radius; review `pwdLastSet`, `lastLogon` en toegelate encryption types voordat jy crack.
4. Request slegs geselekteerde tickets, crack offline en query daarna weer BloodHound met die nuwe access:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumerateer **Group Policy Objects** en beklemtoon misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) voer ’n **gesondheidskontrole** van Active Directory uit en genereer ’n HTML-verslag met risikotelling.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Verwysings

- [1] [BloodHound Community Edition v8 Launches with OpenGraph: Identiteitsaanvalspaaie buite Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Verder as ACL's: Kartering van Windows-voorregte-eskalasiepaaie met BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder: OpenGraph-aanvalspadkartering in BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
