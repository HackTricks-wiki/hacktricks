# BloodHound & Autres Outils d'Énumération Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> REMARQUE : Cette page regroupe certaines des utilitaires les plus utiles pour **énumérer** et **visualiser** les relations Active Directory. Pour la collecte via le canal **Active Directory Web Services (ADWS)** furtif, consultez la référence ci-dessus.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) est un **visualiseur et éditeur AD** avancé qui permet :

* Navigation GUI dans l'arborescence du répertoire
* Édition des attributs d'objet et des descripteurs de sécurité
* Création / comparaison de snapshots pour une analyse hors ligne

### Utilisation rapide

1. Démarrez l'outil et connectez-vous à `dc01.corp.local` avec des identifiants de domaine.
2. Créez un snapshot hors ligne via `Fichier ➜ Créer un snapshot`.
3. Comparez deux snapshots avec `Fichier ➜ Comparer` pour repérer les dérives de permissions.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrait un grand ensemble d'artefacts d'un domaine (ACL, GPO, trusts, modèles CA…) et produit un **rapport Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualisation graphique)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) utilise la théorie des graphes + Neo4j pour révéler des relations de privilèges cachées dans AD sur site et Azure AD.

### Déploiement (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collecteurs

* `SharpHound.exe` / `Invoke-BloodHound` – variante native ou PowerShell
* `AzureHound` – énumération Azure AD
* **SoaPy + BOFHound** – collecte ADWS (voir le lien en haut)

#### Modes communs de SharpHound
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Les collecteurs génèrent du JSON qui est ingéré via l'interface BloodHound.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) énumère les **Group Policy Objects** et met en évidence les erreurs de configuration.
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
{{#include ../../banners/hacktricks-training.md}}
