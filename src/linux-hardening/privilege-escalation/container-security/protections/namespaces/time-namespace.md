# Espace de noms temporel

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

Le time namespace virtualise certaines horloges sélectionnées, en particulier **`CLOCK_MONOTONIC`** et **`CLOCK_BOOTTIME`**. C'est un espace de noms plus récent et plus spécialisé que les espaces de noms mount, PID, network ou user, et ce n'est pas souvent la première chose à laquelle un opérateur pense lorsqu'on parle de durcissement des conteneurs. Cela dit, il fait partie de la famille moderne des espaces de noms et mérite d'être compris sur le plan conceptuel.

Le but principal est de permettre à un processus d'observer des décalages contrôlés pour certaines horloges sans modifier la vue temporelle globale de l'hôte. Ceci est utile pour les workflows checkpoint/restore, les tests déterministes et certains comportements runtime avancés. Ce n'est généralement pas un contrôle d'isolation phare de la même manière que les espaces de noms mount ou user, mais il contribue néanmoins à rendre l'environnement du processus plus autonome.

## Laboratoire

Si le kernel hôte et l'espace utilisateur le prennent en charge, vous pouvez inspecter l'espace de noms avec:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Le support varie selon les versions du noyau et des outils ; cette page vise donc davantage à expliquer le mécanisme qu'à supposer qu'il soit visible dans tous les environnements de laboratoire.

### Décalages temporels

Les time namespaces sous Linux virtualisent les décalages pour `CLOCK_MONOTONIC` et `CLOCK_BOOTTIME`. Les décalages actuels par namespace sont exposés via `/proc/<pid>/timens_offsets`, qui, sur les noyaux compatibles, peuvent aussi être modifiés par un processus détenant `CAP_SYS_TIME` dans le namespace concerné :
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Le fichier contient des deltas en nanosecondes. Ajuster `monotonic` de deux jours modifie les observations de type uptime à l'intérieur de ce namespace sans changer l'horloge système de l'hôte.

### `unshare` Helper Flags

Les versions récentes de `util-linux` fournissent des options pratiques qui écrivent automatiquement les décalages :
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Ces flags améliorent surtout l'ergonomie, mais ils facilitent également l'identification de la fonctionnalité dans la documentation et les tests.

## Runtime Usage

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
Cela importe parce que cela transforme le time namespacing d'une primitive du noyau de niche en quelque chose que les runtimes peuvent demander de façon portable.

## Security Impact

Il y a moins d'histoires classiques d'escape centrées sur le time namespace que sur d'autres types de namespace. Le risque ici n'est généralement pas que le time namespace permette directement une escape, mais que les lecteurs l'ignorent complètement et manquent ainsi la façon dont des runtimes avancés peuvent façonner le comportement des processus. Dans des environnements spécialisés, des vues d'horloge altérées peuvent affecter checkpoint/restore, observability, ou les hypothèses médico-légales.

## Abuse

Il n'existe généralement pas de primitive d'escape directe ici, mais un comportement d'horloge altéré peut néanmoins être utile pour comprendre l'environnement d'exécution et identifier des fonctionnalités avancées des runtimes :
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Si vous comparez deux processus, les différences ici peuvent aider à expliquer des comportements de timing étranges, des artefacts de checkpoint/restore, ou des divergences de journalisation spécifiques à l'environnement.

Impact :

- presque toujours reconnaissance ou compréhension de l'environnement
- utile pour expliquer des anomalies de journalisation, de temps d'activité ou de checkpoint/restore
- normalement pas un mécanisme direct de container-escape en soi

La nuance importante en matière d'abus est que les time namespaces ne virtualisent pas `CLOCK_REALTIME`, donc ils ne permettent pas, à eux seuls, à un attaquant de falsifier l'horloge système de l'hôte ou de contourner directement les vérifications d'expiration des certificats à l'échelle du système. Leur valeur réside surtout dans la perturbation de la logique basée sur le temps monotone, la reproduction de bugs spécifiques à l'environnement, ou la compréhension du comportement d'exécution avancé.

## Vérifications
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Ce qui est intéressant ici :

- Dans de nombreux environnements, ces valeurs n'entraîneront pas immédiatement une anomalie de sécurité, mais elles indiquent si une fonctionnalité runtime spécialisée est en jeu.
- Si vous comparez deux processus, les différences ici peuvent expliquer un timing confus ou un comportement de checkpoint/restore.

Pour la plupart des container breakouts, le time namespace n'est pas le premier contrôle que vous examinerez. Cependant, une section container-security complète devrait l'évoquer, car il fait partie du modèle kernel moderne et peut parfois avoir de l'importance dans des scénarios runtime avancés.
{{#include ../../../../../banners/hacktricks-training.md}}
