# Namespace temporel

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Le namespace temporel virtualise certaines horloges de type monotonic au lieu de l’horloge murale de l’hôte. En pratique, cela signifie des offsets privés pour **`CLOCK_MONOTONIC`** et **`CLOCK_BOOTTIME`**, ainsi que pour les vues étroitement liées **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** et **`CLOCK_BOOTTIME_ALARM`**. Il ne virtualise pas **`CLOCK_REALTIME`** : `date` et la logique d’expiration des certificats observent donc toujours l’horloge murale de l’hôte, sauf si un autre mécanisme intervient.

L’objectif principal est de permettre à un processus d’observer des offsets contrôlés du temps écoulé sans modifier la vue temporelle globale de l’hôte. Cela est utile pour les workflows de checkpoint/restore, les tests déterministes et les comportements avancés du runtime. Il ne s’agit généralement pas d’un contrôle d’isolation majeur au même titre que les mount ou user namespaces, mais il contribue néanmoins à rendre l’environnement du processus plus autonome.

D’un point de vue offensif, ce namespace est généralement plus pertinent pour la **reconnaissance, le timer skew et la compréhension du runtime** que pour un breakout direct. Il reste toutefois important, car un nombre croissant de container runtimes et de workflows de checkpoint/restore peuvent désormais le demander explicitement.

## Lab

Si le kernel et l’espace utilisateur de l’hôte le prennent en charge, vous pouvez inspecter le namespace avec :
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Le support varie selon les versions du kernel et des outils. Cette page vise donc davantage à comprendre le mécanisme qu'à s'attendre à ce qu'il soit visible dans chaque environnement de lab. L'observation importante est que `date` devrait toujours refléter l'horloge murale de l'hôte, tandis que les valeurs basées sur monotonic/boottime sont celles qui changent lorsque des offsets non nuls sont configurés.

### Nuance de création

Les time namespaces sont légèrement inhabituels par rapport aux mount, PID ou network namespaces :

- `unshare(CLONE_NEWTIME)` crée un nouveau time namespace pour les **futurs processus enfants**.
- La tâche appelante reste dans son time namespace actuel.
- `/proc/<pid>/ns/time_for_children` est donc souvent plus intéressant que `/proc/<pid>/ns/time` lors du debugging de la configuration d'un runtime.

La fenêtre d'écriture est également particulière. Les offsets dans `/proc/<pid>/timens_offsets` doivent être écrits avant que le nouveau time namespace soit entièrement peuplé de tâches en cours d'exécution ; en pratique, les runtimes effectuent cette opération pendant la courte fenêtre de configuration située entre la création du namespace et le démarrage du payload final. Lorsqu'une tâche y est déjà en cours d'exécution, les écritures ultérieures échouent avec `EACCES`. C'est pourquoi les runtimes bas niveau traitent la configuration du time namespace comme une étape précoce du bootstrap, au lieu d'essayer de modifier les offsets depuis un processus de container déjà démarré.

### Time Offsets

Les time namespaces Linux exposent les offsets propres à chaque namespace via `/proc/<pid>/timens_offsets`. Le format est un ensemble de noms ou d'IDs d'horloges, accompagné de deltas en secondes/nanosecondes relatifs au time namespace initial.

En pratique, le workflow le plus fiable côté utilisateur consiste à laisser `unshare` écrire ces offsets à votre place :
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Le point important n’est pas la syntaxe exacte de la commande, mais le comportement : un container peut observer une vue de type uptime différente sans modifier l’horloge murale de l’hôte.

### Flags d’aide de `unshare`

Les versions récentes de `util-linux` fournissent des flags pratiques qui écrivent automatiquement les offsets lors de la création du namespace :
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Ces flags constituent principalement une amélioration de l'utilisabilité, mais ils facilitent également l'identification de la fonctionnalité dans la documentation, les test harnesses et les wrappers d'exécution.

## Utilisation à l'exécution

Les time namespaces sont plus récents et moins systématiquement utilisés que les mount ou PID namespaces. OCI Runtime Specification v1.1 a ajouté une prise en charge explicite du namespace `time` et du champ `linux.timeOffsets`, et les runtimes modernes peuvent intégrer ces données au flux d'initialisation du kernel. Un fragment OCI minimal ressemble à ceci :
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
Ceci est important, car cela transforme le time namespacing, auparavant une primitive du kernel assez spécialisée, en quelque chose que les runtimes peuvent demander de manière portable. Cela explique également pourquoi les composants internes des runtimes ont besoin d'une étape explicite de synchronisation : l'offset doit être écrit dans `/proc/<pid>/timens_offsets` avant que le payload du container n'entre complètement dans le nouvel espace de noms.

Les stacks de checkpoint/restore tels que CRIU sont l'une des principales raisons concrètes de l'existence de cette fonctionnalité. Sans time namespaces, la restauration d'une workload suspendue ferait avancer les horloges monotonic et boot-time de la durée pendant laquelle la workload est restée suspendue.

## Impact sur la sécurité

Il existe moins de récits classiques de breakout centrés sur le time namespace que sur d'autres types d'espaces de noms. Le risque ne vient généralement pas du fait que le time namespace permette directement une escape, mais plutôt du fait que les lecteurs l'ignorent complètement et ne voient donc pas comment des runtimes avancés peuvent modifier le comportement des processus.

Dans des environnements spécialisés, des vues monotonic ou boottime modifiées peuvent affecter :

- le comportement des timeouts et des retries
- les watchdogs et la logique des leases
- le comportement de `timerfd`, `nanosleep` et `clock_nanosleep`
- la forensics liée au checkpoint/restore
- la télémétrie du temps écoulé et les heuristiques basées sur l'uptime

Ainsi, même s'il s'agit rarement du premier namespace que vous abusez, il peut tout à fait expliquer un comportement temporel « impossible » pendant un assessment.

## Abuse

Il n'existe généralement pas de primitive de breakout directe ici, mais un comportement modifié de l'horloge peut tout de même être utile pour comprendre l'environnement d'exécution, identifier des fonctionnalités avancées du runtime et repérer une logique basée sur des timers mesurés par rapport à des horloges monotonic plutôt qu'à l'heure réelle :
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Si vous comparez deux processus, les différences à ce niveau peuvent aider à expliquer des comportements temporels inhabituels, des artefacts de checkpoint/restore ou des incohérences de journalisation propres à l’environnement.

Angles pratiques pertinents pour un attacker :

- perturber la logique de backoff, de sleep ou de watchdog implémentée avec des horloges monotonic
- expliquer pourquoi `/proc/uptime` et les comportements pilotés par des timers ne correspondent pas aux attentes de l’horloge système de l’hôte
- reconnaître les workflows CRIU/checkpoint-restore et autres fonctionnalités avancées du runtime
- repérer les environnements dans lesquels rejoindre le namespace temporel d’une cible avec `nsenter -T -t <pid> -- ...` peut reproduire le comportement des timers propres au container à des fins de debugging ou de post-exploitation

Impact :

- presque toujours lié à la reconnaissance ou à la compréhension de l’environnement
- utile pour expliquer les anomalies de journalisation, d’uptime ou de checkpoint/restore
- utile pour analyser les sleep, retries et timers basés sur le temps monotonic
- ne constitue normalement pas, à lui seul, un mécanisme direct de container escape

La nuance importante concernant l’abus est que les time namespaces ne virtualisent pas `CLOCK_REALTIME` ; ils ne permettent donc pas, à eux seuls, à un attacker de falsifier l’horloge système de l’hôte ni de contourner directement les vérifications d’expiration des certificats à l’échelle du système. Leur intérêt réside principalement dans la perturbation de la logique basée sur le temps monotonic, la reproduction de bugs propres à un environnement ou la compréhension du comportement avancé du runtime.

## Vérifications

Ces vérifications visent principalement à confirmer si le runtime utilise effectivement un namespace temporel privé et s’il a réellement défini des offsets non nuls.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
Ce qui est intéressant ici :

- Dans de nombreux environnements, ces valeurs ne conduiront pas à une faille de sécurité immédiate, mais elles indiquent si une fonctionnalité spécialisée du runtime est utilisée.
- Si `time_for_children` diffère de `time`, l'appelant a peut-être préparé un namespace temporel réservé aux enfants, dans lequel il n'est pas lui-même entré.
- Si `date` correspond à celle de l'hôte, mais que les valeurs basées sur le temps monotone ou le temps depuis le démarrage (`boottime`) diffèrent, vous êtes probablement face à un namespacing du temps plutôt qu'à une manipulation de l'horloge système.
- Si vous comparez deux processus, ces différences peuvent expliquer des problèmes de timing ou un comportement déroutant de checkpoint/restore.

Pour la plupart des container breakouts, le namespace temporel ne sera pas le premier mécanisme que vous examinerez. Toutefois, une section complète sur la sécurité des conteneurs devrait le mentionner, car il fait partie du modèle moderne du kernel et peut parfois être important dans des scénarios avancés liés au runtime.

## Références

- [Page de manuel Linux `time_namespaces(7)`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
