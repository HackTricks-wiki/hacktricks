# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTA: Esta página agrupa algunas de las utilidades más útiles para **enumerar** y **visualizar** relaciones de Active Directory. Para la recopilación a través del canal sigiloso **Active Directory Web Services (ADWS)** consulta la referencia anterior.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) es un **AD viewer & editor** avanzado que permite:

* Navegación GUI del árbol del directorio
* Edición de atributos de objetos & security descriptors
* Creación/comparación de snapshots para análisis offline

### Quick usage

1. Inicia la herramienta y conéctate a `dc01.corp.local` con cualquier credencial de dominio.
2. Crea un snapshot offline mediante `File ➜ Create Snapshot`.
3. Compara dos snapshots con `File ➜ Compare` para detectar cambios de permisos.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrae un gran conjunto de artefacts de un dominio (ACLs, GPOs, trusts, CA templates …) y genera un **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualización de grafos)

[BloodHound](https://github.com/SpecterOps/BloodHound) usa teoría de grafos para revelar relaciones ocultas de privilegios dentro de on-prem AD, Entra ID y cualquier dato adicional de superficie de ataque que ingieras a través de OpenGraph.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – variante nativa o PowerShell
* `RustHound-CE` – colector CE multiplataforma para Linux, macOS y Windows
* `NetExec --bloodhound` – recopilación rápida basada en LDAP desde Linux
* `AzureHound` – enumeración de Entra ID
* **SoaPy + BOFHound** – recopilación ADWS (ver enlace al principio)

> BloodHound CE `v8+` cambió el formato de salida del collector cuando llegó OpenGraph. Después de actualizar desde BloodHound legacy o instalaciones CE antiguas, vuelve a ejecutar discovery con los collectors actuales antes de importar los datos.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Los collectors generan JSON que se ingiere a través de la GUI de BloodHound.

#### SharpHound desde un host Windows no unido al dominio

Si tu VM de operador no está unida al dominio objetivo, apunta DNS a un DC, inicia un shell **network-only**, verifica que puedes ver `SYSVOL`/`NETLOGON` en un DC, y luego recopila contra el dominio remoto:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Esto es útil para jump boxes desechables o estaciones de trabajo de operador que no deben estar unidas al dominio.

#### Recolección multiplataforma desde Linux/macOS
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

[PingCastle](https://www.pingcastle.com/documentation/) realiza una **health-check** de Active Directory y genera un informe HTML con puntuación de riesgo.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referencias

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
