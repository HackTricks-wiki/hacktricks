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

---

## ShareHound

ShareHound collects SMB/DFS shares across AD, parses ACLs/NTFS rights, and exports OpenGraph nodes/edges for BloodHound.

* Nodes: Principal, NetworkShareHost, NetworkShareSMB/NetworkShareDFS, Directory, File
* Edges: HasNetworkShare, Contains, and permission edges from Principal→share (e.g., CanWriteDacl, CanWriteOwner, CanReadControl, CanDelete, CanDsWriteProperty, CanDsWriteExtendedProperties, CanDsControlAccess). NTFS-specific edges (e.g., CanNTFSGenericWrite) when applicable.
* Discovery: Multithreaded BFS over targets or AD subnets; export to `opengraph.json` for BloodHound (Upload Data ➜ OpenGraph JSON).
* Rule engine: Optional ShareQL rules to allow/deny exploration and tag risky shares/paths/principals.

### Install and run

```bash
pip install sharehound

# Enumerate domain-joined hosts via AD and export OpenGraph
sharehound \
  -ad DOMAIN.LOCAL -ai <dc_ip> -au <user> -ap '<pass>' \
  --subnets --depth 3 --threads 64

# Or target specific ranges/hosts
sharehound -tt 10.10.10.0/24 -tt filesrv01.domain.local \
  -ad DOMAIN.LOCAL -ai <dc_ip> -au <user> -ap '<pass>'

# Use rules to drive exploration/tagging
sharehound -ad DOMAIN.LOCAL -ai <dc_ip> -au <user> -ap '<pass>' \
  -rf rules/high_risk.sq
```

Import the generated `opengraph.json` into BloodHound (Upload Data ➜ OpenGraph JSON). Optional: set custom icons via `set-custom-icons.py` from the repository.

### Quick-start Cypher queries

- Full Control holders on a specific share (conjunctive rights):

```cypher
MATCH (p:Principal)-[r]->(s:NetworkShareSMB)
WHERE (p)-[:CanDelete]->(s)
  AND (p)-[:CanDsControlAccess]->(s)
  AND (p)-[:CanDsCreateChild]->(s)
  AND (p)-[:CanDsDeleteChild]->(s)
  AND (p)-[:CanDsDeleteTree]->(s)
  AND (p)-[:CanDsListContents]->(s)
  AND (p)-[:CanDsListObject]->(s)
  AND (p)-[:CanDsReadProperty]->(s)
  AND (p)-[:CanDsWriteExtendedProperties]->(s)
  AND (p)-[:CanDsWriteProperty]->(s)
  AND (p)-[:CanReadControl]->(s)
  AND (p)-[:CanWriteDacl]->(s)
  AND (p)-[:CanWriteOwner]->(s)
RETURN p,r,s
```

- Write-like capability on shares (any):

```cypher
MATCH x=(p:Principal)-[r:CanWriteDacl|CanWriteOwner|CanDsWriteProperty|CanDsWriteExtendedProperties]->(s:NetworkShareSMB)
RETURN x
```

- Find files named case-insensitively under shares/dirs:

```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.name) = toLower("flag.txt")
RETURN p
```

- Find files by extension (case-insensitive):

```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.extension) = toLower(".vmdk")
RETURN p
```

Tip: All node/edge kinds are defined in sharehound/kinds.py to help author precise Cypher queries.

## References

- [ShareHound (GitHub)](https://github.com/p0dalirius/sharehound)
- [ShareQL language (GitHub)](https://github.com/p0dalirius/shareql)
- [kinds.py schema (ShareHound)](https://github.com/p0dalirius/sharehound/blob/main/sharehound/kinds.py)

{{#include ../../banners/hacktricks-training.md}}