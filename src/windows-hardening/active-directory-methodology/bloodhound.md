# BloodHound et autres outils d'énumération Active Directory

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE : Cette page regroupe certains des utilitaires les plus utiles pour **énumérer** et **visualiser** les relations Active Directory. Pour la collecte via le canal furtif **Active Directory Web Services (ADWS)**, consultez la référence ci-dessus.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) est un **visualiseur et éditeur AD** avancé qui permet :

* Navigation dans l'arborescence de l'annuaire via une GUI
* Modification des attributs des objets et des descripteurs de sécurité
* Création et comparaison de snapshots pour une analyse offline

### Utilisation rapide

1. Démarrez l'outil et connectez-vous à `dc01.corp.local` avec n'importe quelles credentials de domaine.
2. Créez un snapshot offline via `File ➜ Create Snapshot`.
3. Comparez deux snapshots avec `File ➜ Compare` pour détecter les dérives de permissions.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrait un vaste ensemble d'artefacts d'un domaine (ACLs, GPOs, trusts, modèles de CA …) et produit un **rapport Excel**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (visualisation de graphes)

[BloodHound](https://github.com/SpecterOps/BloodHound) utilise la théorie des graphes pour révéler les relations de privilèges cachées au sein d’AD on-prem, d’Entra ID et de toute donnée supplémentaire liée à la surface d’attaque que vous ingérez via OpenGraph.<sup>[[1]](#references)</sup>

### Déploiement (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collecteurs

* `SharpHound.exe` / `Invoke-BloodHound` – variante native ou PowerShell
* `RustHound-CE` – collector CE cross-platform pour Linux, macOS et Windows
* `NetExec --bloodhound` – collecte rapide pilotée par LDAP depuis Linux
* `AzureHound` – énumération d’Entra ID
* **SoaPy + BOFHound** – collecte via ADWS (voir le lien en haut)

> BloodHound CE `v8+` a modifié le format de sortie du collector avec l’arrivée d’OpenGraph. Après une mise à niveau depuis BloodHound legacy ou d’anciennes installations CE, relancez la découverte avec les collectors actuels avant d’importer les données.<sup>[[1]](#references)</sup>

#### Modes courants de SharpHound
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Les collecteurs génèrent des fichiers JSON qui sont ingérés via l’interface graphique de BloodHound.

#### SharpHound depuis un hôte Windows non joint au domaine

Si votre VM d’opérateur n’est pas jointe au domaine cible, configurez le DNS vers un DC, démarrez un shell **network-only**, vérifiez que vous pouvez voir `SYSVOL`/`NETLOGON` sur un DC, puis effectuez la collecte sur le domaine distant :
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
Ceci est utile pour les jump boxes jetables ou les postes de travail d’opérateur qui ne doivent pas être joints au domaine.

#### Collecte multiplateforme depuis Linux/macOS
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` est un bon choix par défaut lorsque vous voulez une sortie compatible avec CE depuis un hôte non-Windows.<sup>[[2]](#references)</sup> `NetExec` est pratique lorsque vous l'utilisez déjà pour la validation LDAP ou le spraying et que vous voulez un import rapide dans le graphe. Pour les jeux de données non-AD, BloodHound OpenGraph peut être étendu avec des collectors tels que [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).<sup>[[1]](#references)</sup>

### ADPathFinder (priorisation des chemins OpenGraph)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder) s'appuie sur BloodHound CE/OpenGraph lorsque le graphe est trop volumineux pour effectuer manuellement les pivots. Au lieu de seulement déterminer si un principal peut atteindre une cible, il calcule les chemins les plus courts depuis de nombreux utilisateurs et ordinateurs à faibles privilèges vers des objets à forte valeur, regroupe les chemins qui réutilisent les mêmes arêtes et met en évidence le point de congestion commun qui doit être corrigé en premier.<sup>[[4]](#references)</sup>
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
Avec les données de `MSSQLHound` et `ConfigManBearPig` importées, un finding peut relier [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md) et [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md), au lieu de les traiter comme des pistes distinctes.<sup>[[4]](#references)</sup> Exemple de chemin partagé :
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- Suivez le **contexte de sécurité effectif** à chaque arête. Un chemin devient critique pour le domaine dès qu’une transition s’exécute en tant qu’identité de domaine privilégiée, même s’il a commencé avec un utilisateur normal.
- Les résultats groupés sont idéaux pour la **remédiation des points d’étranglement** : supprimer une permission d’impersonation SQL, une confiance de linked-server, un chemin d’abus de certificate-template ou une affectation SCCM peut faire disparaître de nombreux shortest paths en une seule fois.
- Repriorisez les résultats « moyens » avec le **contexte du graphe**. La signature SMB désactivée, l’exposition de WebClient, les erreurs de delegation ou les serveurs SQL relayables via NTLM méritent une priorité supérieure lorsque le nœud compromis dispose de chemins ultérieurs vers les Domain Admins, les Domain Controllers, les CAs ou les serveurs de site SCCM.
- Si vous disposez également d’une sortie `NTDS.dit` et d’un potfile hashcat, `--pwd` corrèle les mots de passe crackés avec les propriétés BloodHound afin de distinguer rapidement la réutilisation ordinaire de mots de passe des credentials crackés sur des comptes privilégiés, Kerberoastable, AS-REP roastable ou pertinents pour les chemins.

### Collecte des privilèges et des droits de logon

Les **privilèges de token** Windows (p. ex. `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) peuvent contourner les vérifications DACL. Leur cartographie à l’échelle du domaine révèle donc des arêtes locales de LPE que les graphes limités aux ACL ne détectent pas. Les **droits de logon** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` et leurs équivalents `SeDeny*`) sont appliqués par LSA avant même l’existence d’un token, et les refus sont prioritaires. Ils contrôlent donc directement le mouvement latéral (logon RDP/SMB, scheduled task ou service).<sup>[[3]](#references)</sup>

**Exécutez les collectors avec des privilèges élevés** lorsque cela est possible : UAC crée un token filtré pour les administrateurs interactifs (via `NtFilterToken`), en supprimant les privilèges sensibles et en marquant les SIDs administrateurs comme deny-only. Si vous énumérez les privilèges depuis un shell non élevé, les privilèges importants seront invisibles et BloodHound n’ingérera pas les arêtes.<sup>[[3]](#references)</sup>

Deux stratégies complémentaires de collecte SharpHound existent désormais :<sup>[[3]](#references)</sup>

- **Analyse de GPO/SYSVOL (furtive, avec peu de privilèges) :**
1. Énumérer les GPO via LDAP (`(objectCategory=groupPolicyContainer)`) et lire chaque `gPCFileSysPath`.
2. Récupérer `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` depuis SYSVOL et analyser la section `[Privilege Rights]`, qui associe les noms des privilèges/droits de logon aux SIDs.
3. Résoudre les liens GPO via `gPLink` sur les OUs/sites/domaines, lister les ordinateurs des conteneurs liés et attribuer ces droits aux machines concernées.
4. Avantage : fonctionne avec un utilisateur normal et reste discret ; inconvénient : ne voit que les droits appliqués via GPO (les modifications locales sont ignorées).

- **Énumération LSA RPC (bruyante, précise) :**
- Depuis un contexte disposant des droits d’administrateur local sur la cible, ouvrir la Local Security Policy et appeler `LsaEnumerateAccountsWithUserRight` pour chaque privilège/droit de logon afin d’énumérer les principaux assignés via RPC.
- Avantage : capture les droits définis localement ou en dehors des GPO ; inconvénient : trafic réseau bruyant et privilèges d’administrateur requis sur chaque hôte.

**Exemple de chemin d’abus révélé par ces arêtes :** `CanRDP` ➜ hôte sur lequel votre utilisateur dispose également de `SeBackupPrivilege` ➜ démarrer un shell élevé pour éviter les tokens filtrés ➜ utiliser les backup semantics pour lire les ruches `SAM` et `SYSTEM` malgré des DACL restrictives ➜ exfiltrer les données et exécuter `secretsdump.py` offline afin de récupérer le NT hash de l’Administrator local pour le mouvement latéral ou l’élévation de privilèges.<sup>[[3]](#references)</sup>

### Prioriser le Kerberoasting avec BloodHound

Utilisez le contexte du graphe pour cibler le roasting :

1. Effectuer une seule collecte avec un collector compatible ADWS et travailler offline :
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. Importer le ZIP, marquer le principal compromis comme owned et exécuter les requêtes intégrées (*Kerberoastable Users*, *Shortest Paths to Domain Admins*) afin de faire ressortir les comptes SPN disposant de droits d’administration ou d’infrastructure.
3. Prioriser les SPN selon leur blast radius ; examiner `pwdLastSet`, `lastLogon` et les types de chiffrement autorisés avant le cracking.
4. Demander uniquement les tickets sélectionnés, les cracker offline, puis réinterroger BloodHound avec le nouvel accès :
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

[PingCastle](https://www.pingcastle.com/documentation/) effectue un **contrôle de l'état** d'Active Directory et génère un rapport HTML avec une notation des risques.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Références

- [1] [BloodHound Community Edition v8 se lance avec OpenGraph : les chemins d’attaque liés aux identités au-delà d’Active Directory et d’Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [2] [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [3] [Au-delà des ACL : cartographier les chemins d’escalade de privilèges Windows avec BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [4] [ADPathFinder : cartographie des chemins d’attaque OpenGraph dans BloodHound CE](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
