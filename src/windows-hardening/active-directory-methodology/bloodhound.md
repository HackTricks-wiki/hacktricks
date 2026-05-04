# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Ця сторінка об’єднує деякі з найкорисніших утиліт для **enumerate** та **visualise** Active Directory relationships.  Для collection через прихований канал **Active Directory Web Services (ADWS)** див. посилання вище.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) — це просунутий **AD viewer & editor**, який дозволяє:

* GUI browsing дерева каталогу
* Editing атрибутів об’єктів і security descriptors
* Створення/порівняння snapshot для offline analysis

### Quick usage

1. Запустіть tool і підключіться до `dc01.corp.local` з будь-якими domain credentials.
2. Створіть offline snapshot через `File ➜ Create Snapshot`.
3. Порівняйте два snapshots через `File ➜ Compare`, щоб виявити permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extracts a large set of artefacts from a domain (ACLs, GPOs, trusts, CA templates …) and produces an **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/SpecterOps/BloodHound) використовує теорію графів, щоб виявляти приховані взаємини привілеїв всередині on-prem AD, Entra ID і будь-яких додаткових даних про attack-surface, які ви імпортуєте через OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – нативний або PowerShell-варіант
* `RustHound-CE` – кросплатформений CE-collector для Linux, macOS і Windows
* `NetExec --bloodhound` – швидкий LDAP-based collection з Linux
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection (див. посилання зверху)

> BloodHound CE `v8+` змінив формат output collector, коли з’явився OpenGraph. Після upgrade з legacy BloodHound або старіших CE installs, запустіть discovery з current collectors ще раз перед importing the data.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Колектори генерують JSON, який інжектиться через BloodHound GUI.

#### SharpHound з Windows-хоста, не приєднаного до домену

Якщо ваша operator VM не приєднана до цільового домену, вкажіть DNS на DC, запустіть shell **network-only**, переконайтеся, що ви бачите `SYSVOL`/`NETLOGON` на DC, і тоді збирайте дані для віддаленого домену:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Це корисно для одноразових jump boxes або operator workstations, які не мають бути domain-joined.

#### Cross-platform collection from Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` is a good default when you want CE-compatible output from a non-Windows host. `NetExec` is convenient when you are already using it for LDAP validation or spraying and want a quick graph import. For non-AD datasets, BloodHound OpenGraph can be extended with collectors such as [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Збір privilege & logon-right

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

### Пріоритизація Kerberoasting з BloodHound

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

[PingCastle](https://www.pingcastle.com/documentation/) виконує **health-check** Active Directory і генерує HTML-звіт із risk scoring.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## References

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
