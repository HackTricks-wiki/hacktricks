# BloodHound & autres outils d'énumération Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE : Cette page regroupe certaines des utilités les plus utiles pour **enumerate** et **visualise** les relations Active Directory. Pour la collecte via le discret canal **Active Directory Web Services (ADWS)**, consultez la référence ci‑dessus.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) est un **AD viewer & editor** avancé qui permet :

* Navigation GUI de l'arborescence de l'annuaire
* Modification des attributs d'objet et des descripteurs de sécurité
* Création de snapshots / comparaison pour analyse hors ligne

### Utilisation rapide

1. Démarrez l'outil et connectez-vous à `dc01.corp.local` avec des identifiants de domaine quelconques.
2. Créez un snapshot hors ligne via `File ➜ Create Snapshot`.
3. Comparez deux snapshots avec `File ➜ Compare` pour repérer les dérives de permissions.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrait un grand ensemble d'artefacts d'un domaine (ACLs, GPOs, trusts, CA templates …) et produit un **rapport Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualisation de graphes)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) utilise la théorie des graphes + Neo4j pour révéler les relations de privilèges cachées dans l'AD on-prem et Azure AD.

### Déploiement (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collecteurs

* `SharpHound.exe` / `Invoke-BloodHound` – natif ou variante PowerShell
* `AzureHound` – énumération Azure AD
* **SoaPy + BOFHound** – collecte ADWS (voir le lien en haut)

#### Modes courants de SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Les collectors génèrent du JSON qui est ingéré via le BloodHound GUI.

### Collecte des privilèges et des droits de connexion

Windows **token privileges** (e.g., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) peuvent contourner les vérifications DACL, donc les cartographier à l'échelle du domaine expose des edges LPE locaux que les graphes basés uniquement sur les ACL manquent. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` and their `SeDeny*` counterparts) sont appliqués par LSA avant même l'existence d'un token, et les deny ont la priorité, donc ils conditionnent matériellement le mouvement latéral (RDP/SMB/scheduled task/service logon).

**Run collectors elevated** quand c'est possible : UAC crée un filtered token pour les admins interactifs (via `NtFilterToken`), supprimant les privilèges sensibles et marquant les SIDs admin comme deny-only. Si vous énumérez les privileges depuis un shell non élevé, les privilèges de grande valeur seront invisibles et BloodHound n'ingérera pas les edges.

Deux stratégies complémentaires de collecte SharpHound existent maintenant :

- **GPO/SYSVOL parsing (furtif, faible privilège) :**
1. Enumérer les GPOs over LDAP (`(objectCategory=groupPolicyContainer)`) et lire chaque `gPCFileSysPath`.
2. Récupérer `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` depuis SYSVOL et parser la section `[Privilege Rights]` qui mappe les noms de privilege/logon-rights aux SIDs.
3. Résoudre les liens GPO via `gPLink` sur les OUs/sites/domains, lister les ordinateurs dans les containers liés, et attribuer les droits à ces machines.
4. Avantage : fonctionne avec un utilisateur normal et est discret ; inconvénient : ne voit que les droits poussés via GPO (les modifications locales sont manquées).

- **LSA RPC enumeration (bruyant, précis) :**
- Depuis un contexte avec admin local sur la cible, ouvrir la Local Security Policy et appeler `LsaEnumerateAccountsWithUserRight` pour chaque privilege/logon right afin d'énumérer les principals assignés via RPC.
- Avantage : capture les droits définis localement ou en dehors du GPO ; inconvénient : trafic réseau bruyant et besoin d'un compte admin sur chaque hôte.

**Exemple de chemin d'abus mis en évidence par ces edges :** `CanRDP` ➜ host where your user also has `SeBackupPrivilege` ➜ start an elevated shell to avoid filtered tokens ➜ use backup semantics to read `SAM` and `SYSTEM` hives despite restrictive DACLs ➜ exfiltrate and run `secretsdump.py` offline to recover the local Administrator NT hash for lateral movement/privilege escalation.

### Prioriser le Kerberoasting avec BloodHound

Utilisez le contexte du graphe pour garder le Kerberoasting ciblé :

1. Effectuez une collecte une fois avec un collector compatible ADWS et travaillez hors ligne :
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importez le ZIP, marquez le principal compromis comme owned, et exécutez les requêtes intégrées (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) pour faire remonter les comptes SPN avec des droits admin/infra.
3. Priorisez les SPNs par blast radius ; vérifiez `pwdLastSet`, `lastLogon`, et les types de chiffrement autorisés avant le cracking.
4. Demandez seulement les tickets sélectionnés, craquez hors ligne, puis re-interrogez BloodHound avec le nouvel accès :
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

[PingCastle](https://www.pingcastle.com/documentation/) effectue un **health-check** d'Active Directory et génère un rapport HTML avec une notation des risques.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Références

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
