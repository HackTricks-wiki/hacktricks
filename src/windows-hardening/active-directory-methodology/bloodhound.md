# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> ΣΗΜΕΙΩΣΗ: Αυτή η σελίδα συγκεντρώνει μερικά από τα πιο χρήσιμα βοηθητικά εργαλεία για να **enumerate** και να **visualise** Active Directory σχέσεις. Για συλλογή μέσω του stealthy **Active Directory Web Services (ADWS)** channel, δες την αναφορά παραπάνω.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) is an advanced **AD viewer & editor** που επιτρέπει:

* GUI browsing του directory tree
* Editing object attributes & security descriptors
* Snapshot creation / comparison για offline analysis

### Quick usage

1. Start the tool and connect to `dc01.corp.local` with any domain credentials.
2. Create an offline snapshot via `File ➜ Create Snapshot`.
3. Compare two snapshots with `File ➜ Compare` to spot permission drifts.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extracts a large set of artefacts από ένα domain (ACLs, GPOs, trusts, CA templates …) και produces an **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/SpecterOps/BloodHound) χρησιμοποιεί θεωρία γραφημάτων για να αποκαλύψει κρυφές σχέσεις προνομίων μέσα σε on-prem AD, Entra ID, και οποιαδήποτε επιπλέον δεδομένα attack-surface εισάγετε μέσω OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Συλλέκτες

* `SharpHound.exe` / `Invoke-BloodHound` – native or PowerShell variant
* `RustHound-CE` – cross-platform CE collector για Linux, macOS, και Windows
* `NetExec --bloodhound` – γρήγορη συλλογή μέσω LDAP από Linux
* `AzureHound` – απαρίθμηση Entra ID
* **SoaPy + BOFHound** – συλλογή ADWS (βλ. link στην κορυφή)

> BloodHound CE `v8+` άλλαξε το output format του collector όταν προστέθηκε το OpenGraph. Μετά από αναβάθμιση από legacy BloodHound ή παλαιότερες CE εγκαταστάσεις, εκτέλεσε ξανά discovery με τους τρέχοντες collectors πριν κάνεις import τα data.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Οι collectors δημιουργούν JSON το οποίο εισάγεται μέσω του BloodHound GUI.

#### SharpHound από Windows host που δεν είναι domain-joined

Αν το operator VM σου δεν είναι joined στο target domain, όρισε το DNS να δείχνει σε ένα DC, ξεκίνα ένα **network-only** shell, επιβεβαίωσε ότι μπορείς να δεις `SYSVOL`/`NETLOGON` σε ένα DC, και μετά κάνε συλλογή against το remote domain:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Αυτό είναι χρήσιμο για disposable jump boxes ή operator workstations που δεν θα πρέπει να είναι domain-joined.

#### Cross-platform collection from Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` is a good default when you want CE-compatible output from a non-Windows host. `NetExec` is convenient when you are already using it for LDAP validation or spraying and want a quick graph import. For non-AD datasets, BloodHound OpenGraph can be extended with collectors such as [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Συλλογή Privilege & logon-right

Windows **token privileges** (π.χ., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) can bypass DACL checks, so mapping them domain-wide exposes local LPE edges that ACL-only graphs miss. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` and their `SeDeny*` counterparts) are enforced by LSA before a token even exists, and denies take precedence, so they materially gate lateral movement (RDP/SMB/scheduled task/service logon).

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

### Προτεραιοποίηση Kerberoasting με BloodHound

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

Το [PingCastle](https://www.pingcastle.com/documentation/) πραγματοποιεί έναν **health-check** του Active Directory και δημιουργεί μια HTML αναφορά με risk scoring.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Αναφορές

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
