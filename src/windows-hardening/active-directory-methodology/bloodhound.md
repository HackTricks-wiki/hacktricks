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

---

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

{{#include ../../banners/hacktricks-training.md}}
