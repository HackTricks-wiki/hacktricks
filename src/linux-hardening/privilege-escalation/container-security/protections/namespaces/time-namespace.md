# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

Le time namespace virtualise des horloges sélectionnées, en particulier **`CLOCK_MONOTONIC`** et **`CLOCK_BOOTTIME`**. C'est un namespace plus récent et plus spécialisé que les namespaces mount, PID, network ou user, et c'est rarement la première chose à laquelle un opérateur pense lorsqu'il s'agit de durcir des conteneurs. Néanmoins, il fait partie de la famille moderne des namespaces et mérite d'être compris conceptuellement.

L'objectif principal est de permettre à un processus d'observer des offsets contrôlés pour certaines horloges sans modifier la vue temporelle globale de l'hôte. Cela est utile pour les workflows checkpoint/restore, les tests déterministes et certains comportements runtime avancés. Ce n'est généralement pas un contrôle d'isolation majeur au même titre que les namespaces mount ou user, mais il contribue néanmoins à rendre l'environnement du processus plus autonome.

## Laboratoire

Si le noyau de l'hôte et l'espace utilisateur le prennent en charge, vous pouvez inspecter le namespace avec:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
La prise en charge varie selon les versions du noyau et des outils, donc cette page sert surtout à comprendre le mécanisme plutôt qu'à s'attendre à ce qu'il soit visible dans tous les environnements de laboratoire.

### Décalages temporels

Les time namespaces de Linux virtualisent des offsets pour `CLOCK_MONOTONIC` et `CLOCK_BOOTTIME`. Les offsets actuels par namespace sont exposés via `/proc/<pid>/timens_offsets`, qui, sur les noyaux compatibles, peuvent aussi être modifiés par un processus disposant de `CAP_SYS_TIME` à l'intérieur du namespace concerné :
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Le fichier contient des deltas en nanosecondes. Ajuster `monotonic` de deux jours modifie les observations de type uptime à l'intérieur de cet espace de noms sans changer l'horloge murale de l'hôte.

### Options d'aide pour `unshare`

Les versions récentes de `util-linux` fournissent des options pratiques qui écrivent automatiquement les décalages :
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Ces flags sont principalement une amélioration de l'utilisabilité, mais ils facilitent aussi la reconnaissance de la fonctionnalité dans la documentation et lors des tests.

## Utilisation à l'exécution

Les time namespaces sont plus récents et moins largement utilisés que les mount ou PID namespaces. OCI Runtime Specification v1.1 a ajouté un support explicite pour le namespace `time` et le champ `linux.timeOffsets`, et les versions récentes de `runc` implémentent cette partie du modèle. Un fragment OCI minimal ressemble à :
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Cela importe car cela transforme le time namespacing d'un primitif noyau de niche en quelque chose que les runtimes peuvent demander de façon portable.

## Impact sur la sécurité

Il y a moins d'histoires classiques d'évasion centrées sur le time namespace que sur d'autres types de namespace. Le risque ici n'est généralement pas que le time namespace permette directement une évasion, mais que les lecteurs l'ignorent complètement et manquent ainsi la manière dont des runtimes avancés peuvent façonner le comportement des processus. Dans des environnements spécialisés, des vues d'horloge altérées peuvent affecter le checkpoint/restore, l'observability ou les hypothèses forensic.

## Abus

Il n'existe généralement pas de breakout primitive directe ici, mais un comportement d'horloge altéré peut quand même être utile pour comprendre l'environnement d'exécution et identifier des fonctionnalités avancées des runtimes :
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Si vous comparez deux processus, les différences ici peuvent aider à expliquer des comportements de timing étranges, des artefacts de checkpoint/restore, ou des incohérences de journalisation spécifiques à l'environnement.

Impact :

- presque toujours de la reconnaissance ou de la compréhension de l'environnement
- utile pour expliquer des anomalies de journalisation, de temps de fonctionnement ou de checkpoint/restore
- n'est normalement pas, en soi, un mécanisme direct de container-escape

La nuance importante d'abus est que les namespaces temporels ne virtualisent pas `CLOCK_REALTIME`, donc ils ne permettent pas, à eux seuls, à un attaquant de falsifier l'horloge système de l'hôte ou de casser directement les vérifications d'expiration des certificats à l'échelle du système. Leur valeur réside surtout dans la confusion de la logique basée sur le temps monotone, la reproduction de bugs spécifiques à l'environnement, ou la compréhension du comportement d'exécution avancé.

## Vérifications

Ces vérifications visent principalement à confirmer si l'environnement d'exécution utilise un namespace temporel privé.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Ce qui est intéressant ici :

- Dans de nombreux environnements, ces valeurs ne mèneront pas nécessairement à une vulnérabilité de sécurité immédiate, mais elles indiquent si une fonctionnalité runtime spécialisée est en jeu.
- Si vous comparez deux processus, des différences ici peuvent expliquer des problèmes de timing ou des comportements de checkpoint/restore déroutants.

Pour la plupart des container breakouts, le time namespace n'est pas le premier contrôle que vous examinerez. Néanmoins, une section complète sur container-security devrait le mentionner, car il fait partie du modèle moderne du kernel et est parfois pertinent dans des scénarios runtime avancés.
