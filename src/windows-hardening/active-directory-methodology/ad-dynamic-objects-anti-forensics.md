# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mécanismes & bases de détection

- Tout objet créé avec la classe auxiliaire **`dynamicObject`** obtient **`entryTTL`** (compte à rebours en secondes) et **`msDS-Entry-Time-To-Die`** (expiration absolue). Lorsque `entryTTL` atteint 0, le **Garbage Collector le supprime sans tombstone/recycle-bin**, effaçant le créateur/les horodatages et empêchant toute récupération.
- **`entryTTL` est un attribut opérationnel/construit** : demandez-le explicitement dans les requêtes LDAP. Le TTL peut être renouvelé soit en mettant à jour `entryTTL` avant l’expiration, soit via l’OID de refresh TTL LDAP **`1.3.6.1.4.1.1466.101.119.1`**.
- Les TTL min/défaut sont imposés dans **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft documente **86400s** comme TTL par défaut et **900s** comme TTL minimum valide par défaut ; les deux prennent en charge **1s–1y**. Les dynamic objects sont **non pris en charge dans les partitions Configuration/Schema**.
- Il n’existe **aucune conversion statique→dynamique** et aucune phase de tombstone après expiration. Les équipes IR ne peuvent pas s’appuyer sur les contrôles des objets supprimés ni sur le Recycle Bin ; elles doivent capturer l’objet/les métadonnées en direct avant que GC ne le supprime.
- Le refresh est **sensible à la réplication** : si le TTL est renouvelé trop près de l’expiration, un autre replica inscriptible ou GC peut encore supprimer l’objet localement avant que le refresh ne se réplique. Les TTL très courts fonctionnent donc mieux lorsque l’attaquant sait quel DC servira l’abus, tandis que les défenseurs devraient interroger **tous les naming contexts / replicas** pendant le triage.
- La suppression peut être retardée de quelques minutes sur les DC avec une courte durée de fonctionnement (<24h), laissant une courte fenêtre de réponse pour interroger/sauvegarder les attributs. Détectez cela en **alertant sur les nouveaux objets portant `entryTTL`/`msDS-Entry-Time-To-Die`** et en corrélant avec des SID orphelins/des liens cassés.

## Énumération rapide / Triage en direct

- Interrogez **tous les `namingContexts` depuis RootDSE**, pas seulement le domaine NC. L’abus dynamic peut vivre dans **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ou dans des partitions d’application.
- Tant que l’objet est encore vivant, exportez immédiatement les **métadonnées de réplication** et tous les attributs liés/ACLs. Après expiration, il ne vous restera peut-être que des **valeurs `gPLink` cassées, des SID orphelins ou des réponses DNS mises en cache**.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion avec Self-Deleting Computers

- Le **`ms-DS-MachineAccountQuota` = 10** par défaut permet à tout utilisateur authentifié de créer des computers. Ajoutez `dynamicObject` lors de la création pour que le computer s’auto-supprime et **libère la slot de quota** tout en effaçant les preuves.
- Ajustement Powermad dans `New-MachineAccount` (objectClass list) :
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Si le TTL demandé est **inférieur à `DynamicObjectMinTTL`**, attendez-vous à un ajustement côté serveur ou à un rejet selon le chemin de création ; dans beaucoup de domaines, le plancher effectif est **900s** et le fallback/default reste **86400s**. ADUC peut masquer `entryTTL`, mais les requêtes LDP/LDAP le révèlent.
- Tant que l’objet existe, les défenseurs peuvent encore récupérer le créateur non privilégié via **`msDS-CreatorSID`** sur l’objet computer. Une fois le dynamic computer expiré, cette attribution disparaît avec l’objet.

## Stealth Primary Group Membership

- Créez un **dynamic security group**, puis définissez le **`primaryGroupID`** d’un user sur le RID de ce groupe pour obtenir une appartenance effective qui **n’apparaît pas dans `memberOf`** mais est prise en compte dans Kerberos/access tokens.
- L’expiration du TTL **supprime le groupe malgré la protection de suppression du primary-group**, laissant au user un **`primaryGroupID`** corrompu pointant vers un RID inexistant et aucun tombstone pour enquêter sur la manière dont le privilège a été accordé.
- Le reporting dépend de l’outil : **`Get-ADGroupMember` / `net group`** résolvent généralement l’appartenance dérivée du primary-group, tandis que **`memberOf`** et **`Get-ADGroup -Properties member`** ne le font pas. Pour un tradecraft plus large autour de **`primaryGroupID`**, voir [this other page about DCShadow and PGID abuse](dcshadow.md).
- Pour les cibles **non protégées par AdminSDHolder**, les attaquants peuvent combiner l’astuce du dynamic-group avec un **DACL deny sur la lecture de `primaryGroupID`** (ou de l’attribut `member` du groupe) afin de masquer le lien à de nombreux workflows LDAP/PowerShell même avant l’expiration du groupe.

## AdminSDHolder Orphan-SID Pollution

- Ajoutez des ACE pour un **short-lived dynamic user/group** à **`CN=AdminSDHolder,CN=System,...`**. Après expiration du TTL, le SID devient **non résoluble (“Unknown SID”)** dans l’ACL modèle, et **SDProp (~60 min)** propage ce SID orphelin à travers tous les objets protégés Tier-0.
- Les forensics perdent l’attribution parce que le principal a disparu (pas de DN d’objet supprimé). Surveillez les **nouveaux dynamic principals + les SID orphelins soudains sur AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution avec Self-Destructing Evidence

- Créez un objet **dynamic `groupPolicyContainer`** avec un **`gPCFileSysPath`** malveillant (par ex. un partage SMB à la manière de GPODDITY) et **linkez-le via `gPLink`** à une OU cible.
- Les clients traitent la policy et récupèrent le contenu depuis le SMB de l’attaquant. Quand le TTL expire, l’objet GPO (et `gPCFileSysPath`) disparaît ; seul un **GUID `gPLink`** cassé reste, supprimant la preuve LDAP du payload exécuté.
- C’est opérationnellement plus propre que le nettoyage classique à la **GPODDITY-style** : au lieu de restaurer vous-même le `gPCFileSysPath` original, AD supprime automatiquement le GPC malveillant une fois le timer expiré.

## Ephemeral AD-Integrated DNS Redirection

- Les enregistrements DNS AD sont des objets **`dnsNode`** dans **DomainDnsZones/ForestDnsZones**. Les créer comme **dynamic objects** permet une redirection temporaire de host (credential capture/MITM). Les clients mettent en cache la réponse A/AAAA malveillante ; l’enregistrement se supprime ensuite tout seul, donc la zone semble propre (DNS Manager peut nécessiter un reload de zone pour rafraîchir l’affichage).
- Détection : alertez sur **tout enregistrement DNS portant `dynamicObject`/`entryTTL`** via les logs de réplication/événements ; les enregistrements transitoires apparaissent rarement dans les logs DNS standards.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync s’appuie sur des **tombstones** pour détecter les suppressions. Un **dynamic on-prem user** peut se synchroniser vers Entra ID, expirer et être supprimé sans tombstone — delta sync ne supprimera pas le cloud account, laissant un **orphaned active Entra user** jusqu’à ce qu’un **initial/full sync** ou un nettoyage manuel du cloud soit forcé.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
