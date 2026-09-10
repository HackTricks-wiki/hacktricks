# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mécanismes et notions de base de la détection

- Tout objet créé avec la classe auxiliaire **`dynamicObject`** reçoit **`entryTTL`** (compte à rebours en secondes) et **`msDS-Entry-Time-To-Die`** (expiration absolue). Lorsque `entryTTL` atteint 0 **et que l'objet n'a aucun descendant**, le Garbage Collector le supprime sans tombstone/recycle-bin, effaçant le créateur et les timestamps et empêchant sa récupération.<sup>[[4]](#references)</sup>
- **`entryTTL` est un attribut opérationnel/construit** : demandez-le explicitement dans les requêtes LDAP. Le TTL peut être actualisé en mettant à jour `entryTTL` avant son expiration ou via l'OID LDAP de refresh TTL **`1.3.6.1.4.1.1466.101.119.1`**.
- Les valeurs min/default du TTL sont des AVA à l'échelle de la forêt dans **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`** : `DynamicObjectMinTTLSeconds=<seconds>` et `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft documente **86400s** comme TTL par défaut et **900s** comme durée minimale valide par défaut ; la plage du schéma `entryTTL` est de **1 à 31557600s** (une seconde à un an).<sup>[[3]](#references)</sup> Les dynamic objects ne sont **pas pris en charge dans les partitions Configuration/Schema**.
- Il n'existe **aucune conversion statique→dynamique** ni phase tombstone après expiration. Les équipes IR ne peuvent pas compter sur les contrôles des objets supprimés ni sur la Recycle Bin ; elles doivent capturer l'objet actif et ses métadonnées avant que le GC ne le supprime.
- Le refresh dépend de la **réplica** : si le TTL est renouvelé trop près de son expiration, une autre réplica writable ou le GC peut tout de même supprimer localement l'objet avant la réplication du refresh. Les TTL très courts sont donc particulièrement efficaces lorsque l'attaquant sait quel DC traitera l'abus, tandis que les défenseurs doivent interroger **tous les naming contexts / replicas** pendant le triage.
- La suppression peut prendre quelques minutes sur des DC dont la durée de fonctionnement est courte (<24h), laissant une fenêtre de réponse étroite pour interroger/sauvegarder les attributs. Détectez ce comportement en **déclenchant une alerte sur les nouveaux objets portant `entryTTL`/`msDS-Entry-Time-To-Die`** et en corrélant ces événements avec les orphan SIDs/liens cassés.<sup>[[1]](#references)</sup>

### Cas particuliers liés au graphe d'expiration et au nettoyage des références

- Chaque descendant d'un dynamic object doit lui-même être dynamique. Un parent dynamique expiré n'est collecté par le garbage collector qu'après être devenu une feuille ; si un descendant possède un `msDS-Entry-Time-To-Die` ultérieur, le DC repousse l'expiration du parent au-delà de l'expiration maximale des descendants. Par conséquent, un sous-arbre dynamique writable peut **maintenir/prolonger un parent qui semble sur le point de disparaître** : énumérez tout son sous-arbre et n'utilisez pas le `entryTTL` observé du parent comme échéance de nettoyage.<sup>[[4]](#references)</sup>
- Le nettoyage à l'expiration tient compte des **schema links**. Les replicas suppriment les valeurs d'attributs liés qui font référence à l'objet dynamique supprimé, mais conservent les valeurs non liées. Attendez-vous à ce que les appartenances ordinaires forward/back-link soient nettoyées, tandis que les références de type entier/SID/chaîne, telles que `primaryGroupID`, les SID intégrés dans `nTSecurityDescriptor` ou le texte `gPLink`, puissent survivre comme résidus forensiques.<sup>[[4]](#references)</sup>

## Énumération rapide / Triage en direct

- Interrogez **tous les `namingContexts` depuis RootDSE**, et pas uniquement le domaine NC. Un abus de dynamic objects peut se trouver dans **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ou dans des partitions applicatives.
- Tant que l'objet est encore actif, exportez immédiatement les **métadonnées de réplication** ainsi que tous les attributs liés/ACL. Après l'expiration, il ne peut rester que des **valeurs `gPLink` cassées, des orphan SIDs ou des réponses DNS mises en cache**.<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Évasion du MAQ avec des ordinateurs auto-supprimés

- La valeur par défaut de **`ms-DS-MachineAccountQuota` = 10** permet à tout utilisateur authentifié de créer des ordinateurs. Ajouter `dynamicObject` lors de la création permet à l’ordinateur de s’auto-supprimer et de **libérer le slot de quota** tout en effaçant les traces.
- Modification de Powermad dans `New-MachineAccount` (liste `objectClass`) :
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Si le TTL demandé est **inférieur à `DynamicObjectMinTTL`**, le serveur peut l’ajuster ou rejeter la requête selon le chemin de création ; dans de nombreux domaines, la limite effective est de **900s** et la valeur de repli/par défaut reste **86400s**. ADUC peut masquer `entryTTL`, mais les requêtes LDP/LDAP le révèlent.
- Tant que l’objet existe, les défenseurs peuvent encore retrouver le créateur non privilégié via **`msDS-CreatorSID`** sur l’objet ordinateur. Une fois l’ordinateur dynamique expiré, cette attribution disparaît avec l’objet.<sup>[[1]](#references)</sup>

## Appartenance furtive au groupe principal

- Créer un **dynamic security group**, puis définir le **`primaryGroupID`** d’un utilisateur sur le RID de ce groupe afin d’obtenir une appartenance effective qui **n’apparaît pas dans `memberOf`**, mais qui est prise en compte par Kerberos/les access tokens.<sup>[[1]](#references)</sup>
- L’expiration du TTL **supprime le groupe malgré la protection contre la suppression du groupe principal**, laissant à l’utilisateur un **`primaryGroupID`** corrompu pointant vers un RID inexistant, sans tombstone permettant d’enquêter sur l’origine du privilège.
- Le reporting dépend des outils : **`Get-ADGroupMember` / `net group`** résolvent généralement l’appartenance dérivée du groupe principal, tandis que **`memberOf`** et **`Get-ADGroup -Properties member`** ne le font pas. Pour davantage de tradecraft concernant `primaryGroupID`, voir [cette autre page sur DCShadow et l’abus de PGID](dcshadow.md).
- Pour les cibles **non protégées par AdminSDHolder**, les attaquants peuvent associer cette technique de dynamic group à un **DACL deny** sur la lecture de **`primaryGroupID`** (ou de l’attribut `member` du groupe) afin de masquer le lien à de nombreux workflows LDAP/PowerShell, même avant l’expiration du groupe.<sup>[[2]](#references)</sup>

## Pollution d’AdminSDHolder par des SID orphelins

- Ajouter des ACE pour un **dynamic user/group à courte durée de vie** à **`CN=AdminSDHolder,CN=System,...`**. Après l’expiration du TTL, le SID devient **non résolvable (« Unknown SID »)** dans l’ACL modèle, et **SDProp (~60 min)** propage ce SID orphelin à tous les objets Tier-0 protégés.
- Les investigations forensiques perdent l’attribution, car le principal a disparu (aucun DN d’objet supprimé). Surveiller les **nouveaux principals dynamiques + l’apparition soudaine de SID orphelins sur AdminSDHolder/dans les ACL privilégiées**.<sup>[[1]](#references)</sup>

## Exécution via un GPO dynamique avec traces auto-détruites

- Créer un objet **`groupPolicyContainer` dynamique** avec un **`gPCFileSysPath`** malveillant (par exemple un partage SMB à la manière de GPODDITY), puis le **lier via `gPLink`** à une OU cible.
- Les clients traitent la policy et récupèrent le contenu depuis le SMB de l’attaquant. Lorsque le TTL expire, l’objet GPO (ainsi que `gPCFileSysPath`) disparaît ; seul un GUID **`gPLink`** cassé subsiste, supprimant les preuves LDAP du payload exécuté.
- Cette méthode est plus propre sur le plan opérationnel que le nettoyage classique de type **GPODDITY** : au lieu de restaurer vous-même le `gPCFileSysPath` d’origine, AD supprime automatiquement le GPC malveillant à l’expiration du timer.<sup>[[1]](#references)</sup> Voir [Abus de la persistence via ACL](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) pour les détails du protocole et des outils, plutôt que de les dupliquer ici.

## Redirection DNS intégrée à AD éphémère

- Les enregistrements DNS AD sont des objets **`dnsNode`** dans **DomainDnsZones/ForestDnsZones**. Les créer comme **dynamic objects** permet une redirection temporaire d’hôtes (capture de credentials/MITM). Les clients mettent en cache la réponse A/AAAA malveillante ; l’enregistrement s’auto-supprime ensuite afin que la zone semble propre (DNS Manager peut nécessiter un rechargement de zone pour actualiser l’affichage).
- Détection : déclencher une alerte pour **tout enregistrement DNS contenant `dynamicObject`/`entryTTL`** via les logs de réplication/événements ; les enregistrements transitoires apparaissent rarement dans les logs DNS standards.<sup>[[1]](#references)</sup>

## Écart de delta-sync hybride Entra ID (note)

- La delta sync d’Entra Connect s’appuie sur les **tombstones** pour détecter les suppressions. Un **utilisateur on-prem dynamique** peut être synchronisé vers Entra ID, expirer et être supprimé sans tombstone ; la delta sync ne supprimera pas le compte cloud, laissant un **utilisateur Entra actif orphelin** jusqu’à l’exécution d’une **initial/full sync** ou au déclenchement d’un nettoyage manuel dans le cloud.<sup>[[1]](#references)</sup>



## References

- [1] [Objets dynamiques dans Active Directory : la menace furtive](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Aventures autour du comportement, du reporting et de l’exploitation des groupes principaux](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Configuration des limites de TTL](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS] : exigences relatives à DynamicObject](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
