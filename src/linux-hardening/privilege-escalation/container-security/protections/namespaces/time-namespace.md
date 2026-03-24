# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

The time namespace virtualizes selected clocks, especially **`CLOCK_MONOTONIC`** and **`CLOCK_BOOTTIME`**. It is a newer and more specialized namespace than mount, PID, network, or user namespaces, and it is rarely the first thing an operator thinks about when discussing container hardening. Even so, it is part of the modern namespace family and worth understanding conceptually.

The main purpose is to let a process observe controlled offsets for certain clocks without changing the host's global time view. This is useful for checkpoint/restore workflows, deterministic testing, and some advanced runtime behavior. It is not usually a headline isolation control in the same way as mount or user namespaces, but it still contributes to making the process environment more self-contained.

## Lab

Si le noyau de l'hôte et l'espace utilisateur le prennent en charge, vous pouvez inspecter le namespace avec:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Le support varie selon les versions du noyau et des outils ; cette page vise donc davantage à expliquer le mécanisme qu'à supposer qu'il soit visible dans tous les environnements de laboratoire.

### Décalages temporels

Les time namespaces Linux virtualisent les décalages pour `CLOCK_MONOTONIC` et `CLOCK_BOOTTIME`. Les décalages actuels par namespace sont exposés via `/proc/<pid>/timens_offsets`, qui, sur les noyaux compatibles, peuvent également être modifiés par un processus détenant `CAP_SYS_TIME` à l'intérieur du namespace concerné :
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Le fichier contient des deltas en nanosecondes. Ajuster `monotonic` de deux jours modifie les observations de type uptime à l'intérieur de ce namespace sans changer l'horloge système de l'hôte.

### Options d'aide pour `unshare`

Les versions récentes de `util-linux` fournissent des flags pratiques qui écrivent automatiquement les offsets :
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Ces flags sont principalement une amélioration de l'ergonomie, mais ils facilitent aussi la reconnaissance de la fonctionnalité dans la documentation et les tests.

## Usage à l'exécution

Les Time namespaces sont plus récents et moins universellement sollicités que les mount ou PID namespaces. OCI Runtime Specification v1.1 a ajouté la prise en charge explicite du `time` namespace et du champ `linux.timeOffsets`, et les versions récentes de `runc` implémentent cette partie du modèle. Un fragment OCI minimal ressemble à :
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
Cela importe car cela transforme l'espace de noms temporel, qui était un primitif noyau de niche, en quelque chose que les runtimes peuvent demander de manière portable.

## Impact sur la sécurité

Il y a moins d'histoires classiques d'évasion centrées sur l'espace de noms temporel que sur d'autres types d'espaces de noms. Le risque ici n'est généralement pas que l'espace de noms temporel permette directement une évasion, mais que les lecteurs l'ignorent complètement et manquent ainsi de voir comment des runtimes avancés peuvent façonner le comportement des processus. Dans des environnements spécialisés, une vue modifiée de l'horloge peut affecter le checkpoint/restore, l'observabilité ou les hypothèses forensiques.

## Abus

Il n'existe généralement pas de primitive d'évasion directe ici, mais un comportement d'horloge modifié peut néanmoins être utile pour comprendre l'environnement d'exécution et identifier des fonctionnalités avancées des runtimes :
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
Si vous comparez deux processus, les différences ici peuvent aider à expliquer des comportements temporels étranges, des artefacts de checkpoint/restore, ou des discordances de logging spécifiques à l'environnement.

Impact :

- presque toujours de la reconnaissance ou de la compréhension de l'environnement
- utile pour expliquer des anomalies de logging, d'uptime ou de checkpoint/restore
- pas normalement un mécanisme direct de container-escape en soi

La nuance importante est que les time namespaces ne virtualisent pas `CLOCK_REALTIME`, donc ils ne permettent pas, à eux seuls, à un attaquant de falsifier l'horloge système de l'hôte ou de contourner directement les vérifications d'expiration des certificats à l'échelle du système. Leur intérêt réside principalement dans la perturbation de la logique basée sur l'horloge monotone, la reproduction de bugs spécifiques à l'environnement, ou la compréhension d'un comportement d'exécution avancé.

## Checks

Ces vérifications visent principalement à confirmer si le runtime utilise ou non un time namespace privé.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Ce qui est intéressant ici :

- Dans de nombreux environnements, ces valeurs n'entraîneront pas une constatation de sécurité immédiate, mais elles indiquent si une fonctionnalité d'exécution spécialisée est en jeu.
- Si vous comparez deux processus, des différences ici peuvent expliquer des comportements de timing confus ou du checkpoint/restore.

Pour la plupart des container breakouts, le time namespace n'est pas le premier contrôle que vous examinerez. Néanmoins, une section complète sur container-security devrait le mentionner car il fait partie du modèle moderne du noyau et a parfois de l'importance dans des scénarios runtime avancés.
{{#include ../../../../../banners/hacktricks-training.md}}
