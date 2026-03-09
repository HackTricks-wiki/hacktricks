# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mécanique et principes de détection

- Tout objet créé avec la classe auxiliaire **`dynamicObject`** obtient **`entryTTL`** (compte à rebours en secondes) et **`msDS-Entry-Time-To-Die`** (expiration absolue). Quand `entryTTL` atteint 0, le **Garbage Collector le supprime sans tombstone/recycle-bin**, effaçant créateur/timestamps et empêchant la récupération.
- Le TTL peut être rafraîchi en mettant à jour `entryTTL` ; des valeurs min/default sont appliquées dans **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (supporte 1s–1y mais est souvent réglé par défaut sur 86 400s/24h). Les objets dynamiques sont **non supportés dans les partitions Configuration/Schema**.
- La suppression peut prendre quelques minutes sur des DCs ayant une uptime courte (<24h), laissant une fenêtre étroite pour interroger/sauvegarder les attributs. Détecter en **alertant sur les nouveaux objets portant `entryTTL`/`msDS-Entry-Time-To-Die`** et en corrélant avec des SIDs orphelins/liens brisés.

## MAQ Evasion with Self-Deleting Computers

- Le paramètre par défaut **`ms-DS-MachineAccountQuota` = 10** permet à tout utilisateur authentifié de créer des computers. Ajouter `dynamicObject` lors de la création permet à la machine de s’auto-supprimer et **libérer la slot MAQ** tout en effaçant les preuves.
- Tweak Powermad dans `New-MachineAccount` (liste objectClass) :
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Un TTL court (ex. 60s) échoue souvent pour des utilisateurs standard ; AD retombe sur **`DynamicObjectDefaultTTL`** (exemple : 86 400s). ADUC peut masquer `entryTTL`, mais LDP/LDAP le révèle.

## Stealth Primary Group Membership

- Créez un **groupe de sécurité dynamique**, puis définissez le **`primaryGroupID`** d’un utilisateur sur le RID de ce groupe pour obtenir une appartenance effective qui **n’apparaît pas dans `memberOf`** mais est prise en compte dans les tickets Kerberos / tokens d’accès.
- À l’expiration du TTL, le groupe est **supprimé malgré la protection contre la suppression du primary-group**, laissant l’utilisateur avec un `primaryGroupID` corrompu pointant vers un RID inexistant et sans tombstone pour enquêter sur l’origine du privilège.

## AdminSDHolder Orphan-SID Pollution

- Ajoutez des ACEs pour un **user/group dynamique de courte durée** à **`CN=AdminSDHolder,CN=System,...`**. Après l’expiration du TTL, le SID devient **irrésolvable (“Unknown SID”)** dans l’ACL modèle, et **SDProp (~60 min)** propage ce SID orphelin sur tous les objets protégés Tier-0.
- La forensique perd l’attribution parce que le principal a disparu (pas de DN d’objet supprimé). Surveillez les **nouveaux principals dynamiques + apparition soudaine de SIDs orphelins sur AdminSDHolder/ACLs privilégiées**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Créez un objet **`groupPolicyContainer` dynamique** avec un `gPCFileSysPath` malveillant (ex. partage SMB à la GPODDITY) et **liez-le via `gPLink`** à une OU cible.
- Les clients appliquent la policy et tirent le contenu depuis le SMB de l’attaquant. Quand le TTL expire, l’objet GPO (et `gPCFileSysPath`) disparaît ; il ne reste qu’un GUID de `gPLink` brisé, supprimant les preuves LDAP de la payload exécutée.

## Ephemeral AD-Integrated DNS Redirection

- Les enregistrements AD DNS sont des objets **`dnsNode`** dans **DomainDnsZones/ForestDnsZones**. Les créer comme **dynamic objects** permet une redirection temporaire d’hôtes (credential capture/MITM). Les clients cachent la réponse A/AAAA malveillante ; l’enregistrement s’auto-supprime ensuite et la zone semble propre (DNS Manager peut nécessiter un reload de zone pour rafraîchir l’affichage).
- Détection : alerter sur **tout enregistrement DNS portant `dynamicObject`/`entryTTL`** via la réplication/logs d’événements ; les enregistrements transitoires apparaissent rarement dans les logs DNS standards.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync se base sur les **tombstones** pour détecter les suppressions. Un **user on-prem dynamique** peut syncer vers Entra ID, expirer et être supprimé sans tombstone — le delta sync ne supprimera pas le compte cloud, laissant un **user Entra orphelin et actif** jusqu’à forçage d’un **full sync** manuel.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
