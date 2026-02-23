# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: This page groups some of the most useful utilities to **enumerate** and **visualise** Active Directory relationships.  For collection over the stealthy **Active Directory Web Services (ADWS)** channel check the reference above.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) is an advanced **AD viewer & editor** which allows:

* GUI browsing of the directory tree
* Editing of object attributes & security descriptors
* Snapshot creation / comparison for offline analysis

### Quick usage

1. Start the tool and connect to `dc01.corp.local` with any domain credentials.
2. Create an offline snapshot via `File ➜ Create Snapshot`.
3. Compare two snapshots with `File ➜ Compare` to spot permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extracts a large set of artefacts from a domain (ACLs, GPOs, trusts, CA templates …) and produces an **Excel report**.

```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```

---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) uses graph theory + Neo4j to reveal hidden privilege relationships inside on-prem AD & Azure AD.

### Deployment (Docker CE)

```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```

### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – native or PowerShell variant
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – ADWS collection (see link at top)

#### Common SharpHound modes

```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```

The collectors generate JSON which is ingested via the BloodHound GUI.

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

[PingCastle](https://www.pingcastle.com/documentation/) performs a **health-check** of Active Directory and generates an HTML report with risk scoring.

```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```

## References

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
