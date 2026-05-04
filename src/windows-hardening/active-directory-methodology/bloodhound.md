# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: Cette page regroupe certaines des utilitaires les plus utiles pour **énumérer** et **visualiser** les relations Active Directory. Pour la collecte via le canal furtif **Active Directory Web Services (ADWS)**, consultez la référence ci-dessus.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) est un **AD viewer & editor** avancé qui permet :

* Navigation GUI dans l'arborescence du répertoire
* Modification des attributs d'objet et des descripteurs de sécurité
* Création/comparaison de snapshots pour l'analyse offline

### Quick usage

1. Démarrez l'outil et connectez-vous à `dc01.corp.local` avec n'importe quelles credentials de domaine.
2. Créez un snapshot offline via `File ➜ Create Snapshot`.
3. Comparez deux snapshots avec `File ➜ Compare` pour repérer les dérives de permissions.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrait un large ensemble d'artefacts d'un domaine (ACLs, GPOs, trusts, CA templates …) et produit un **Excel report**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualisation de graphe)

[BloodHound](https://github.com/SpecterOps/BloodHound) utilise la théorie des graphes pour révéler les relations de privilèges cachées au sein de on-prem AD, Entra ID, et toutes données supplémentaires de surface d'attaque que vous ingérez via OpenGraph.

### Déploiement (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – variante native ou PowerShell
* `RustHound-CE` – collecteur CE multiplateforme pour Linux, macOS et Windows
* `NetExec --bloodhound` – collecte rapide pilotée par LDAP depuis Linux
* `AzureHound` – énumération Entra ID
* **SoaPy + BOFHound** – collecte ADWS (voir le lien en haut)

> BloodHound CE `v8+` a modifié le format de sortie du collecteur lors de l’arrivée d’OpenGraph. Après une mise à niveau depuis l’ancien BloodHound ou des installations CE plus anciennes, relancez la découverte avec les collecteurs actuels avant d’importer les données.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Les collecteurs génèrent du JSON qui est ingéré via l'interface graphique BloodHound.

#### SharpHound depuis un hôte Windows non joint au domaine

Si votre VM d’opérateur n’est pas jointe au domaine cible, pointez le DNS vers un DC, démarrez un shell **network-only**, vérifiez que vous pouvez voir `SYSVOL`/`NETLOGON` sur un DC, puis collectez contre le domaine distant :
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Ceci est utile pour les jump boxes jetables ou les postes de travail d’opérateur qui ne devraient pas être joints au domaine.

#### Collecte multiplateforme depuis Linux/macOS
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
1. Énumérer les GPO via LDAP (`(objectCategory=groupPolicyContainer)`) et lire chaque `gPCFileSysPath`.
2. Récupérer `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` depuis SYSVOL et analyser la section `[Privilege Rights]` qui mappe les noms de privilèges/logon-right aux SIDs.
3. Résoudre les liens GPO via `gPLink` sur les OUs/sites/domaines, lister les machines dans les conteneurs liés, et attribuer les droits à ces machines.
4. Avantage : fonctionne avec un utilisateur normal et reste discret ; inconvénient : ne voit que les droits poussés via GPO (les modifications locales sont ignorées).

- **LSA RPC enumeration (noisy, accurate):**
- Depuis un contexte avec local admin sur la cible, ouvrir la Local Security Policy et appeler `LsaEnumerateAccountsWithUserRight` pour chaque privilege/logon right afin d'énumérer les principaux assignés via RPC.
- Avantage : capture les droits définis localement ou en dehors de GPO ; inconvénient : trafic réseau bruyant et besoin des droits admin sur chaque hôte.

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

[Group3r](https://github.com/Group3r/Group3r) énumère les **Group Policy Objects** et met en évidence les mauvaises configurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) effectue un **health-check** d'Active Directory et génère un rapport HTML avec un score de risque.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Références

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
