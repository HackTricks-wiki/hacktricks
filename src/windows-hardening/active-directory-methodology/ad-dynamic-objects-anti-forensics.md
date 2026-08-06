# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mécanismes et bases de la détection

- Tout objet créé avec la classe auxiliaire **`dynamicObject`** acquiert **`entryTTL`** (compte à rebours en secondes) et **`msDS-Entry-Time-To-Die`** (expiration absolue). Lorsque **`entryTTL`** atteint 0, le **Garbage Collector** le supprime sans tombstone ni Recycle Bin, effaçant le créateur et les horodatages et empêchant sa récupération.
- **`entryTTL` est un attribut opérationnel/construit** : demandez-le explicitement dans les requêtes LDAP. Le TTL peut être actualisé en mettant à jour **`entryTTL`** avant son expiration ou via l’OID LDAP de rafraîchissement du TTL **`1.3.6.1.4.1.1466.101.119.1`**.
- Les valeurs minimales et par défaut du TTL sont appliquées dans **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documente **86400s** comme TTL par défaut et **900s** comme TTL minimal valide par défaut ; les deux prennent en charge des valeurs comprises entre **1s et 1 an**. Les objets dynamiques ne sont **pas pris en charge dans les partitions Configuration/Schema**.
- Il n’existe **aucune conversion static→dynamic** ni phase tombstone après expiration. Les équipes IR ne peuvent pas compter sur les contrôles des objets supprimés ou sur Recycle Bin ; elles doivent capturer l’objet actif et ses métadonnées avant sa suppression par le GC.
- Le rafraîchissement dépend de la réplica : si le TTL est renouvelé trop près de son expiration, une autre réplica accessible en écriture ou le GC peut toujours supprimer localement l’objet avant la réplication du rafraîchissement. Les TTL très courts sont donc plus efficaces lorsque l’attaquant sait quel DC traitera l’abus, tandis que les défenseurs devraient interroger **tous les naming contexts / replicas** pendant le triage.
- La suppression peut être retardée de quelques minutes sur les DC ayant une courte durée de fonctionnement (<24h), laissant une étroite fenêtre de réponse pour interroger/sauvegarder les attributs. Détectez ce comportement en **déclenchant des alertes sur les nouveaux objets contenant `entryTTL`/`msDS-Entry-Time-To-Die`** et en les corrélant avec les SID orphelins/liens rompus.<sup>[[1]](#references)</sup>

## Énumération rapide / Triage en direct

- Interrogez **tous les `namingContexts` depuis RootDSE**, et pas uniquement le domaine NC. Un abus des objets dynamiques peut se trouver dans **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ou dans des partitions applicatives.
- Tant que l’objet est encore actif, exportez immédiatement les **métadonnées de réplication** ainsi que tous les attributs liés/ACL. Après expiration, il peut ne rester que des **valeurs `gPLink` rompues, des SID orphelins ou des réponses DNS mises en cache**.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Évasion MAQ avec des ordinateurs qui s’auto-suppriment

- La valeur par défaut **`ms-DS-MachineAccountQuota` = 10** permet à tout utilisateur authentifié de créer des ordinateurs. Ajouter `dynamicObject` lors de la création permet à l’ordinateur de s’auto-supprimer et de **libérer le slot de quota**, tout en effaçant les traces.
- Modification de Powermad dans `New-MachineAccount` (liste objectClass) :
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Si le TTL demandé est **inférieur à `DynamicObjectMinTTL`**, prévoir un ajustement ou un rejet côté serveur selon le chemin de création ; dans de nombreux domaines, le seuil effectif est de **900s** et le fallback/la valeur par défaut reste **86400s**. ADUC peut masquer `entryTTL`, mais les requêtes LDP/LDAP le révèlent.
- Tant que l’objet existe, les defenders peuvent toujours retrouver le créateur non privilégié via **`msDS-CreatorSID`** sur l’objet ordinateur. Une fois l’ordinateur dynamic expiré, cette attribution disparaît avec l’objet.<sup>[[1]](#references)</sup>

## Appartenance furtive au groupe primaire

- Créer un **dynamic security group**, puis définir le **`primaryGroupID`** d’un utilisateur sur le RID de ce groupe afin d’obtenir une appartenance effective qui **n’apparaît pas dans `memberOf`**, mais qui est prise en compte par Kerberos et les access tokens.<sup>[[1]](#references)</sup>
- L’expiration du TTL **supprime le groupe malgré la protection contre la suppression du groupe primaire**, laissant à l’utilisateur un **`primaryGroupID`** corrompu pointant vers un RID inexistant, sans tombstone permettant d’enquêter sur l’origine du privilège.
- Le reporting dépend de l’outil : **`Get-ADGroupMember` / `net group`** résolvent généralement l’appartenance dérivée du groupe primaire, tandis que **`memberOf`** et **`Get-ADGroup -Properties member`** ne la résolvent pas. Pour davantage de tradecraft sur `primaryGroupID`, voir [cette autre page sur DCShadow et l’abus de PGID](dcshadow.md).
- Pour les cibles **non protégées par AdminSDHolder**, les attackers peuvent associer l’astuce du dynamic group à un **DACL deny sur la lecture de `primaryGroupID`** (ou de l’attribut `member` du groupe) afin de masquer le lien à de nombreux workflows LDAP/PowerShell, même avant l’expiration du groupe.<sup>[[2]](#references)</sup>

## Pollution de SID orphelins dans AdminSDHolder

- Ajouter des ACE pour un **dynamic user/group à courte durée de vie** dans **`CN=AdminSDHolder,CN=System,...`**. Après l’expiration du TTL, le SID devient **non résolvable (« Unknown SID »)** dans l’ACL du template, et **SDProp (~60 min)** propage ce SID orphelin à tous les objets Tier-0 protégés.
- Les investigations forensics perdent l’attribution, car le principal a disparu (aucun DN d’objet supprimé). Surveiller les **nouveaux principals dynamic + les SID orphelins apparaissant soudainement dans les ACL AdminSDHolder/privilégiées**.<sup>[[1]](#references)</sup>

## Exécution de dynamic GPO avec des traces qui s’auto-détruisent

- Créer un objet **`groupPolicyContainer` dynamic** avec un **`gPCFileSysPath`** malveillant (par exemple un partage SMB à la GPODDITY), puis le **lier via `gPLink`** à une OU cible.
- Les clients traitent la policy et récupèrent le contenu depuis le SMB de l’attaquant. À l’expiration du TTL, l’objet GPO (ainsi que `gPCFileSysPath`) disparaît ; seul un GUID de **`gPLink` cassé** subsiste, supprimant les preuves LDAP du payload exécuté.
- Cette méthode est plus propre sur le plan opérationnel qu’un nettoyage classique **de type GPODDITY** : au lieu de restaurer vous-même le `gPCFileSysPath` d’origine, AD supprime automatiquement le GPC malveillant à l’expiration du timer.<sup>[[1]](#references)</sup>

## Redirection DNS AD-Integrated éphémère

- Les enregistrements DNS AD sont des objets **`dnsNode`** dans **DomainDnsZones/ForestDnsZones**. Les créer comme **dynamic objects** permet une redirection temporaire d’hôte (capture de credentials/MITM). Les clients mettent en cache la réponse A/AAAA malveillante ; l’enregistrement s’auto-supprime ensuite, de sorte que la zone paraît propre (DNS Manager peut nécessiter un rechargement de la zone pour actualiser l’affichage).
- Detection : déclencher une alerte pour **tout enregistrement DNS portant `dynamicObject`/`entryTTL`** via les replication/event logs ; les enregistrements transitoires apparaissent rarement dans les logs DNS standard.<sup>[[1]](#references)</sup>

## Lacune de delta-sync hybride Entra ID (Note)

- Entra Connect delta sync s’appuie sur les **tombstones** pour détecter les suppressions. Un **utilisateur on-prem dynamic** peut être synchronisé vers Entra ID, expirer, puis être supprimé sans tombstone ; le delta sync ne supprimera pas le compte cloud, laissant un **utilisateur Entra actif orphelin** jusqu’à ce qu’un **initial/full sync** ou un nettoyage cloud manuel soit forcé.<sup>[[1]](#references)</sup>

## Références

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
