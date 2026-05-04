# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Bu sayfa, **enumerate** etmek ve Active Directory ilişkilerini **visualise** etmek için en kullanışlı araçlardan bazılarını gruplar. Gizli **Active Directory Web Services (ADWS)** kanalı üzerinden toplama için yukarıdaki referansa bakın.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals), şunlara izin veren gelişmiş bir **AD viewer & editor**'dür:

* Dizin ağacını GUI ile gezme
* Nesne özniteliklerini & security descriptors düzenleme
* Offline analiz için snapshot oluşturma / karşılaştırma

### Quick usage

1. Aracı başlatın ve herhangi bir domain kimlik bilgisiyle `dc01.corp.local` adresine bağlanın.
2. `File ➜ Create Snapshot` ile bir offline snapshot oluşturun.
3. İzin kaymalarını tespit etmek için iki snapshot'ı `File ➜ Compare` ile karşılaştırın.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon), bir domain'den büyük bir artefact kümesi (ACLs, GPOs, trusts, CA templates …) çıkarır ve bir **Excel report** üretir.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph görselleştirme)

[BloodHound](https://github.com/SpecterOps/BloodHound) graph teorisini kullanarak on-prem AD, Entra ID ve OpenGraph üzerinden içe aktardığınız ek attack-surface verileri içindeki gizli privilege ilişkilerini ortaya çıkarır.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – native or PowerShell varyantı
* `RustHound-CE` – Linux, macOS ve Windows için cross-platform CE collector
* `NetExec --bloodhound` – Linux'tan hızlı LDAP-tabanlı collection
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection (üstteki linke bakın)

> BloodHound CE `v8+`, OpenGraph geldiğinde collector output formatını değiştirdi. Legacy BloodHound veya daha eski CE kurulumlarından yükselttikten sonra, veriyi import etmeden önce current collectors ile discovery’yi yeniden çalıştırın.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Collector'lar, BloodHound GUI üzerinden içe aktarılan JSON üretir.

#### Domain'e katılmamış bir Windows host'tan SharpHound

Operatör VM'niz hedef domain'e katılı değilse, DNS'i bir DC'ye yönlendirin, **network-only** bir shell başlatın, bir DC üzerinde `SYSVOL`/`NETLOGON` görebildiğinizi doğrulayın ve ardından uzak domain'e karşı toplama yapın:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Bu, domain-joined olmaması gereken disposable jump box'lar veya operator workstation'lar için kullanışlıdır.

#### Linux/macOS'tan cross-platform collection
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` is a good default when you want CE-compatible output from a non-Windows host. `NetExec` is convenient when you are already using it for LDAP validation or spraying and want a quick graph import. For non-AD datasets, BloodHound OpenGraph can be extended with collectors such as [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Privilege & logon-right collection

Windows **token privileges** (e.g., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) can bypass DACL checks, so mapping them domain-wide exposes local LPE edges that ACL-only graphs miss. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` and their `SeDeny*` counterparts) are enforced by LSA before a token even exists, and denies take precedence, so they materially gate lateral movement (RDP/SMB/scheduled task/service logon).

**Run collectors elevated** when possible: UAC creates a filtered token for interactive admins (via `NtFilterToken`), stripping sensitive privileges and marking admin SIDs as deny-only. If you enumerate privileges from a non-elevated shell, high-value privileges will be invisible and BloodHound won’t ingest the edges.

Two complementary SharpHound collection strategies now exist:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. Enumerate GPOs over LDAP (`(objectCategory=groupPolicyContainer)`) and read each `gPCFileSysPath`.
2. Fetch `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` from SYSVOL and parse the `[Privilege Rights]` section that maps privilege/logon-right names to SIDs.
3. Resolve GPO links via `gPLink` on OUs/sites/domains, list computers in the linked containers, and attribute the rights to those machines.
4. Upside: works with a normal user and is quiet; downside: only sees rights pushed via GPO (local tweaks are missed).

- **LSA RPC enumeration (noisy, accurate):**
- From a context with local admin on the target, open the Local Security Policy and call `LsaEnumerateAccountsWithUserRight` for each privilege/logon right to enumerate assigned principals over RPC.
- Upside: captures rights set locally or outside GPO; downside: noisy network traffic and admin requirement on every host.

**Example abuse path surfaced by these edges:** `CanRDP` ➜ host where your user also has `SeBackupPrivilege` ➜ start an elevated shell to avoid filtered tokens ➜ use backup semantics to read `SAM` and `SYSTEM` hives despite restrictive DACLs ➜ exfiltrate and run `secretsdump.py` offline to recover the local Administrator NT hash for lateral movement/privilege escalation.

### Prioritising Kerberoasting with BloodHound

Use graph context to keep roasting targeted:

1. Collect once with an ADWS-compatible collector and work offline:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Import the ZIP, mark the compromised principal as owned, and run built-in queries (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) to surface SPN accounts with admin/infra rights.
3. Prioritise SPNs by blast radius; review `pwdLastSet`, `lastLogon`, and allowed encryption types before cracking.
4. Request only selected tickets, crack offline, then re-query BloodHound with the new access:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumerates **Group Policy Objects** and highlights misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) Active Directory üzerinde bir **health-check** yapar ve risk skoru içeren bir HTML raporu oluşturur.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referanslar

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
