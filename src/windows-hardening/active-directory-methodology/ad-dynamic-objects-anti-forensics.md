# Objets dynamiques AD (dynamicObject) — anti-forensique

{{#include ../../banners/hacktricks-training.md}}

## Principes & détection de base

- Tout objet créé avec la classe auxiliaire **`dynamicObject`** reçoit **`entryTTL`** (compte à rebours en secondes) et **`msDS-Entry-Time-To-Die`** (expiration absolue). Lorsque `entryTTL` atteint 0, le **Garbage Collector le supprime sans tombstone/recycle-bin**, effaçant le créateur/les horodatages et empêchant la récupération.
- Le TTL peut être rafraîchi en mettant à jour `entryTTL`; les minima/valeurs par défaut sont appliqués dans **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (supporte 1s–1an mais par défaut souvent 86,400s/24h). Les objets dynamiques ne sont **pas supportés dans les partitions Configuration/Schema**.
- La suppression peut avoir un délai de quelques minutes sur les DCs avec un uptime court (<24h), laissant une fenêtre étroite pour interroger/sauvegarder les attributs. Détecter en **alertant sur les nouveaux objets comportant `entryTTL`/`msDS-Entry-Time-To-Die`** et en corrélant avec des SIDs orphelins/liaisons cassées.

## MAQ Evasion with Self-Deleting Computers

- La valeur par défaut **`ms-DS-MachineAccountQuota` = 10** permet à tout utilisateur authentifié de créer des ordinateurs. Ajouter `dynamicObject` lors de la création pour que l’ordinateur s’auto-supprime et **libère la place du quota** tout en effaçant les traces.
- Powermad tweak inside `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Un TTL court (ex. 60s) échoue souvent pour les utilisateurs standard; AD revient à **`DynamicObjectDefaultTTL`** (ex. 86,400s). ADUC peut masquer `entryTTL`, mais les requêtes LDP/LDAP le révèlent.

## Appartenance furtive au groupe primaire

- Créez un **dynamic security group**, puis définissez le **`primaryGroupID`** d’un utilisateur sur le RID de ce groupe pour obtenir une appartenance effective qui **n’apparaît pas dans `memberOf`** mais est prise en compte dans les tokens Kerberos / d’accès.
- L’expiration du TTL **supprime le groupe malgré la protection contre la suppression du groupe primaire**, laissant l’utilisateur avec un `primaryGroupID` corrompu pointant vers un RID inexistant et sans tombstone pour enquêter sur l’origine du privilège.

## Pollution par SID orphelin via AdminSDHolder

- Ajouter des ACEs pour un **utilisateur/groupe dynamic à courte durée de vie** dans **`CN=AdminSDHolder,CN=System,...`**. Après l’expiration du TTL, le SID devient **non résolvable (“Unknown SID”)** dans l’ACL modèle, et **SDProp (~60 min)** propage ce SID orphelin sur tous les objets protégés de niveau Tier-0.
- La forensique perd l’imputabilité car le principal a disparu (pas de DN d’objet supprimé). Surveillez les **nouveaux principals dynamiques + apparitions soudaines de SIDs orphelins sur AdminSDHolder/ACLs privilégiés**.

## Exécution de GPO dynamique avec preuves auto-destructrices

- Créez un objet **dynamic `groupPolicyContainer`** avec un **`gPCFileSysPath`** malveillant (ex. partage SMB à la GPODDITY) et **liiez-le via `gPLink`** à une OU cible.
- Les clients appliquent la stratégie et récupèrent le contenu depuis le SMB de l’attaquant. Quand le TTL expire, l’objet GPO (et `gPCFileSysPath`) disparaît ; il ne reste qu’un GUID de **`gPLink`** cassé, supprimant la preuve LDAP du payload exécuté.

## Redirection DNS AD-intégrée éphémère

- Les enregistrements DNS AD sont des objets **`dnsNode`** dans **DomainDnsZones/ForestDnsZones**. Les créer comme **dynamic objects** permet une redirection hôte temporaire (capture d’identifiants/MITM). Les clients mettent en cache la réponse A/AAAA malveillante ; l’enregistrement s’auto-supprime ensuite, donnant l’impression d’une zone propre (DNS Manager peut nécessiter un rechargement de zone pour rafraîchir la vue).
- Détection : alerter sur **tout enregistrement DNS portant `dynamicObject`/`entryTTL`** via les logs de réplication/événements ; les enregistrements transitoires apparaissent rarement dans les logs DNS standards.

## Lacune Delta-Sync Entra ID hybride (Note)

- Le delta sync d’Entra Connect s’appuie sur les **tombstones** pour détecter les suppressions. Un **dynamic on-prem user** peut se synchroniser vers Entra ID, expirer et être supprimé sans tombstone — le delta sync ne supprimera pas le compte cloud, laissant un **utilisateur Entra actif orphelin** jusqu’à ce qu’un **full sync** manuel soit forcé.

## Références

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
