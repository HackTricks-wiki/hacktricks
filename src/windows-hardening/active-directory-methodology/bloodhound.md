# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Hierdie bladsy groepeer sommige van die nuttigste nutsprogramme om Active Directory-verhoudings te **enumereer** en te **visualiseer**.  Vir insameling oor die stealthy **Active Directory Web Services (ADWS)**-kanaal, kyk die verwysing hierbo.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) is 'n gevorderde **AD viewer & editor** wat toelaat:

* GUI-blaai deur die directory tree
* Wysig van object attributes & security descriptors
* Snapshot skepping / vergelyking vir offline analise

### Quick usage

1. Start die tool en connect to `dc01.corp.local` met enige domain credentials.
2. Skep 'n offline snapshot via `File ➜ Create Snapshot`.
3. Vergelyk twee snapshots met `File ➜ Compare` om permission drifts raak te sien.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) onttrek 'n groot stel artefacts uit 'n domain (ACLs, GPOs, trusts, CA templates …) en produseer 'n **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/SpecterOps/BloodHound) gebruik grafteorie om versteekte voorregverhoudings binne on-prem AD, Entra ID, en enige ekstra aanval-oppervlak-data wat jy deur OpenGraph inlees, bloot te lê.

### Ontplooiing (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – native or PowerShell variant
* `RustHound-CE` – kruisplatform CE collector vir Linux, macOS, en Windows
* `NetExec --bloodhound` – vinnige LDAP-gedrewe versameling vanaf Linux
* `AzureHound` – Entra ID enumerasie
* **SoaPy + BOFHound** – ADWS-versameling (sien skakel bo-aan)

> BloodHound CE `v8+` het die collector-uitvoerformaat verander toe OpenGraph ingestel is. Ná opgradering vanaf legacy BloodHound of ouer CE-installasies, voer discovery weer uit met huidige collectors voordat jy die data importeer.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Die collectors genereer JSON wat via die BloodHound GUI ingeneem word.

#### SharpHound vanaf 'n Windows-host wat nie by die domain aangesluit is nie

As jou operator VM nie by die teikendomain aangesluit is nie, wys DNS na 'n DC, begin 'n **network-only** shell, verifieer dat jy `SYSVOL`/`NETLOGON` op 'n DC kan sien, en versamel dan teen die remote domain:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Dit is nuttig vir weggooibare jump boxes of operator-werkstasies wat nie by die domain-joined moet wees nie.

#### Cross-platform collection from Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` is `n` goeie verstek wanneer jy CE-compatible output vanaf `n non-Windows host wil hê. `NetExec` is gerieflik wanneer jy dit reeds gebruik vir LDAP validation of spraying en `n vinnige graph import wil hê. Vir non-AD datasets kan BloodHound OpenGraph uitgebrei word met collectors soos [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Privilege & logon-right collection

Windows **token privileges** (bv. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) kan DACL checks omseil, so om hulle domain-wide te map, stel local LPE edges bloot wat ACL-only graphs mis. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` en hul `SeDeny*` eweknieë) word deur LSA afgedwing voordat `n token selfs bestaan, en denies het voorrang, so hulle beheer lateral movement (RDP/SMB/scheduled task/service logon) wesenlik.

**Run collectors elevated** wanneer moontlik: UAC skep `n filtered token vir interactive admins (via `NtFilterToken`), en stroop sensitiewe privileges uit en merk admin SIDs as deny-only. As jy privileges vanuit `n non-elevated shell enumereer, sal high-value privileges onsigbaar wees en BloodHound sal nie die edges ingesteel kry nie.

Twee aanvullende SharpHound collection strategies bestaan nou:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumereer GPOs oor LDAP (`(objectCategory=groupPolicyContainer)`) en lees elke `gPCFileSysPath`.
2. Haal `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` van SYSVOL af en parse die `[Privilege Rights]` section wat privilege/logon-right names na SIDs map.
3. Resolve GPO links via `gPLink` op OUs/sites/domains, lys computers in die linked containers, en attribute die rights aan daardie machines.
4. Pluspunt: werk met `n normale user en is stil; nadeel: sien slegs rights wat via GPO gepush word (local tweaks word gemis).

- **LSA RPC enumeration (noisy, accurate):**
- Vanuit `n context met local admin op die target, open die Local Security Policy en roep `LsaEnumerateAccountsWithUserRight` vir elke privilege/logon right aan om assigned principals oor RPC te enumereer.
- Pluspunt: vang rights wat plaaslik of buite GPO ingestel is; nadeel: lawaaierige network traffic en admin requirement op elke host.

**Example abuse path surfaced by these edges:** `CanRDP` ➜ host where your user also has `SeBackupPrivilege` ➜ start `n elevated shell om filtered tokens te vermy ➜ use backup semantics to read `SAM` and `SYSTEM` hives despite restrictive DACLs ➜ exfiltrate and run `secretsdump.py` offline to recover the local Administrator NT hash for lateral movement/privilege escalation.

### Prioritising Kerberoasting with BloodHound

Gebruik graph context om roasting targeted te hou:

1. Collect once with an ADWS-compatible collector and work offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Import the ZIP, merk die compromised principal as owned, en run built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) om SPN accounts met admin/infra rights bloot te stel.
3. Prioritise SPNs by blast radius; review `pwdLastSet`, `lastLogon`, and allowed encryption types before cracking.
4. Request only selected tickets, crack offline, then re-query BloodHound met die new access:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumereer **Group Policy Objects** en lig misconfigurations uit.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) voer 'n **gesondheidskontrole** van Active Directory uit en genereer 'n HTML-verslag met risikotelling.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Verwysings

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
