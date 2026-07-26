# BloodHound et autres outils d’énumération Active Directory

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE : Cette page regroupe certains des utilitaires les plus utiles pour **énumérer** et **visualiser** les relations Active Directory. Pour la collecte via le canal furtif **Active Directory Web Services (ADWS)**, consultez la référence ci-dessus.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) est un **visualiseur et éditeur AD** avancé qui permet :

* Navigation dans l’arborescence de l’annuaire via une GUI
* Modification des attributs des objets et des descripteurs de sécurité
* Création et comparaison de snapshots pour une analyse hors ligne

### Utilisation rapide

1. Démarrez l’outil et connectez-vous à `dc01.corp.local` avec n’importe quels identifiants de domaine.
2. Créez un snapshot hors ligne via `File ➜ Create Snapshot`.
3. Comparez deux snapshots avec `File ➜ Compare` afin de repérer les dérives de permissions.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrait un vaste ensemble d’artefacts d’un domaine (ACL, GPO, relations d’approbation, modèles d’autorité de certification …) et génère un **rapport Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualisation de graphes)

[BloodHound](https://github.com/SpecterOps/BloodHound) utilise la théorie des graphes pour révéler les relations de privilèges cachées au sein d’AD on-prem, d’Entra ID et de toute donnée supplémentaire de la surface d’attaque que vous ingérez via OpenGraph.

### Déploiement (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collecteurs

* `SharpHound.exe` / `Invoke-BloodHound` – variante native ou PowerShell
* `RustHound-CE` – collecteur CE multiplateforme pour Linux, macOS et Windows
* `NetExec --bloodhound` – collecte LDAP rapide depuis Linux
* `AzureHound` – énumération d’Entra ID
* **SoaPy + BOFHound** – collecte via ADWS (voir le lien en haut)

> BloodHound CE `v8+` a modifié le format de sortie du collecteur lors de l’intégration d’OpenGraph. Après une mise à niveau depuis BloodHound legacy ou d’anciennes installations CE, relancez la découverte avec les collecteurs actuels avant d’importer les données.

#### Modes courants de SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Les collecteurs génèrent du JSON qui est ingéré via la GUI de BloodHound.

#### SharpHound depuis un hôte Windows qui n’est pas joint au domaine

Si votre VM d’opérateur n’est pas jointe au domaine cible, configurez le DNS vers un DC, démarrez un shell **network-only**, vérifiez que vous pouvez voir `SYSVOL`/`NETLOGON` sur un DC, puis effectuez la collecte sur le domaine distant :
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
C’est utile pour des jump boxes jetables ou des postes de travail d’opérateur qui ne doivent pas être joints au domaine.

#### Collecte multiplateforme depuis Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` est un choix par défaut adapté lorsque vous voulez une sortie compatible avec CE depuis un hôte non-Windows. `NetExec` est pratique lorsque vous l'utilisez déjà pour la validation LDAP ou le spraying et que vous voulez importer rapidement un graphe. Pour les jeux de données non-AD, BloodHound OpenGraph peut être étendu avec des collectors tels que [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### ADPathFinder (priorisation des chemins OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) s'appuie sur BloodHound CE/OpenGraph lorsque le graphe est trop volumineux pour effectuer des pivots manuellement. Au lieu de demander uniquement si un principal peut atteindre une cible, il calcule les chemins les plus courts entre de nombreux utilisateurs et ordinateurs disposant de faibles privilèges et des objets à forte valeur, regroupe les chemins qui réutilisent les mêmes arêtes et met en évidence le point de blocage partagé qui doit être corrigé en premier.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Avec les données de `MSSQLHound` et `ConfigManBearPig` importées, un même constat peut relier [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) et [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), au lieu de les traiter comme des pistes distinctes. Exemple de chemin commun :
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Suivez le **contexte de sécurité effectif** à chaque arête. Un chemin devient critique pour le domaine dès qu'une transition s'exécute avec une identité de domaine privilégiée, même s'il partait d'un utilisateur normal.
- Les résultats regroupés sont idéaux pour une **remédiation des choke points** : supprimer une permission d'impersonation SQL, une confiance de linked-server, un chemin d'abus de certificate-template ou une affectation SCCM peut faire disparaître de nombreux shortest paths d'un coup.
- Repriorisez les résultats « medium » avec le **contexte du graphe**. La signature SMB désactivée, l'exposition de WebClient, les erreurs de delegation ou les serveurs SQL relayables via NTLM méritent une priorité plus élevée lorsque le nœud compromis possède des chemins ultérieurs vers des Domain Admins, des Domain Controllers, des CAs ou des serveurs de site SCCM.
- Si vous disposez également de la sortie `NTDS.dit` et d'un potfile hashcat, `--pwd` corrèle les mots de passe crackés avec les propriétés BloodHound afin de distinguer rapidement la réutilisation ordinaire de mots de passe des credentials crackés associés à des comptes privilégiés, Kerberoastable, AS-REP roastable ou pertinents pour les chemins.

### Collecte des privilèges et des droits de logon

Les **privilèges de token** Windows (par ex. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) peuvent contourner les vérifications DACL ; leur cartographie à l'échelle du domaine révèle donc des arêtes locales de LPE que les graphes fondés uniquement sur les ACL ne voient pas. Les **droits de logon** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` et leurs équivalents `SeDeny*`) sont appliqués par LSA avant même qu'un token existe, et les refus sont prioritaires ; ils contrôlent donc concrètement le mouvement latéral (logon RDP/SMB, scheduled task/service).

**Exécutez les collectors avec élévation** lorsque cela est possible : UAC crée un token filtré pour les administrateurs interactifs (via `NtFilterToken`), en supprimant les privilèges sensibles et en marquant les SID d'administration comme deny-only. Si vous énumérez les privilèges depuis un shell non élevé, les privilèges à forte valeur seront invisibles et BloodHound n'ingérera pas les arêtes.

Deux stratégies complémentaires de collecte SharpHound existent désormais :

- **Analyse GPO/SYSVOL (stealthy, low-privilege) :**
1. Énumérer les GPO via LDAP (`(objectCategory=groupPolicyContainer)`) et lire chaque `gPCFileSysPath`.
2. Récupérer `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` depuis SYSVOL et analyser la section `[Privilege Rights]`, qui associe les noms des privilèges/droits de logon aux SID.
3. Résoudre les liens GPO via `gPLink` sur les OU/sites/domaines, lister les ordinateurs dans les conteneurs liés et attribuer ces droits à ces machines.
4. Avantage : fonctionne avec un utilisateur normal et reste discret ; inconvénient : ne voit que les droits déployés via GPO (les modifications locales sont ignorées).

- **Énumération LSA RPC (bruyante, précise) :**
- Depuis un contexte disposant des droits d'administrateur local sur la cible, ouvrir la Local Security Policy et appeler `LsaEnumerateAccountsWithUserRight` pour chaque privilège/droit de logon afin d'énumérer les principaux assignés via RPC.
- Avantage : capture les droits définis localement ou en dehors des GPO ; inconvénient : trafic réseau bruyant et nécessité de disposer des droits d'administrateur sur chaque hôte.

**Exemple de chemin d'abus révélé par ces arêtes :** `CanRDP` ➜ hôte sur lequel votre utilisateur possède également `SeBackupPrivilege` ➜ démarrer un shell élevé pour éviter les tokens filtrés ➜ utiliser la backup semantics pour lire les ruches `SAM` et `SYSTEM` malgré des DACL restrictives ➜ exfiltrer les données et exécuter `secretsdump.py` offline afin de récupérer le hash NT de l'Administrator local pour le mouvement latéral/l'escalade de privilèges.

### Prioriser le Kerberoasting avec BloodHound

Utilisez le contexte du graphe pour cibler le roasting :

1. Effectuez une seule collecte avec un collector compatible ADWS et travaillez offline :
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importez le ZIP, marquez le principal compromis comme owned et exécutez les requêtes intégrées (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) afin de faire ressortir les comptes SPN disposant de droits d'administration ou d'infrastructure.
3. Priorisez les SPN selon leur blast radius ; vérifiez `pwdLastSet`, `lastLogon` et les types de chiffrement autorisés avant le cracking.
4. Demandez uniquement les tickets sélectionnés, crackez-les offline, puis interrogez à nouveau BloodHound avec le nouvel accès :
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

[PingCastle](https://www.pingcastle.com/documentation/) effectue un **health-check** d’Active Directory et génère un rapport HTML avec une évaluation des risques.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Références

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: OpenGraph Attack Path Mapping in BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
