# BloodHound & Autres outils d'énumération Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE : Cette page regroupe certains des utilitaires les plus utiles pour **énumérer** et **visualiser** les relations Active Directory.  Pour la collecte via le canal discret **Active Directory Web Services (ADWS)**, consultez la référence ci‑dessous.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) est un outil avancé de visualisation et d'édition d'Active Directory qui permet :

* Navigation GUI dans l'arborescence de l'annuaire
* Édition des attributs d'objets et des descripteurs de sécurité
* Création / comparaison de snapshots pour analyse hors ligne

### Utilisation rapide

1. Lancez l'outil et connectez-vous à `dc01.corp.local` avec n'importe quels identifiants de domaine.
2. Créez un snapshot hors ligne via `File ➜ Create Snapshot`.
3. Comparez deux snapshots via `File ➜ Compare` pour repérer les dérives de permissions.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrait un large ensemble d'artefacts d'un domaine (ACLs, GPOs, trusts, CA templates …) et produit un **rapport Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualisation de graphes)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) utilise la théorie des graphes + Neo4j pour révéler des relations de privilèges cachées dans les AD sur site et Azure AD.

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
Les collecteurs génèrent du JSON qui est ingéré via la GUI de BloodHound.

---

## Prioriser le Kerberoasting avec BloodHound

Le contexte du graphe est essentiel pour éviter un roasting bruyant et indiscriminé. Un flux de travail léger :

1. **Collecter tout une seule fois** en utilisant un collecteur compatible ADWS (par ex. RustHound-CE) afin de pouvoir travailler hors ligne et répéter les chemins sans toucher de nouveau au DC :
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Importer le ZIP, marquer le principal compromis comme owned**, puis exécuter des requêtes intégrées telles que *Kerberoastable Users* et *Shortest Paths to Domain Admins*. Cela met instantanément en évidence les comptes portant un SPN avec des appartenances à des groupes utiles (Exchange, IT, comptes de service tier0, etc.).
3. **Prioriser selon le rayon d'impact** – concentrez-vous sur les SPN qui contrôlent l'infrastructure partagée ou qui ont des droits d'administrateur, et vérifiez `pwdLastSet`, `lastLogon`, et les types de chiffrement autorisés avant de consacrer des cycles de cracking.
4. **Demandez uniquement les tickets qui vous intéressent**. Des outils comme NetExec peuvent cibler des `sAMAccountName`s sélectionnés afin que chaque requête LDAP ROAST ait une justification claire:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, puis re-interroger immédiatement BloodHound pour planifier le post-exploitation avec les nouveaux privilèges.

Cette approche maintient un rapport signal/bruit élevé, réduit le volume détectable (pas de requêtes SPN massives) et garantit que chaque cracked ticket se traduit par des étapes significatives de privilege escalation.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) énumère **Group Policy Objects** et met en évidence les erreurs de configuration.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) effectue un **contrôle de santé** d'Active Directory et génère un rapport HTML avec un score de risque.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Références

- [HackTheBox Mirage: Chaînage de NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, et Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
