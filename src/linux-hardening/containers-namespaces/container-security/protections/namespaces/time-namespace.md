# Espace de noms temporel

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d’ensemble

L’espace de noms temporel virtualise certains clocks de type monotonic au lieu de l’horloge murale de l’hôte. En pratique, cela signifie des offsets privés pour **`CLOCK_MONOTONIC`** et **`CLOCK_BOOTTIME`**, ainsi que pour les vues étroitement associées **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** et **`CLOCK_BOOTTIME_ALARM`**. Il ne virtualise pas **`CLOCK_REALTIME`** ; `date` et la logique d’expiration des certificats observent donc toujours l’horloge murale de l’hôte, sauf si un autre mécanisme intervient.<sup>[[1]](#references)</sup>

L’objectif principal est de permettre à un processus d’observer des offsets contrôlés du temps écoulé sans modifier la vue temporelle globale de l’hôte. Cela est utile pour les workflows de checkpoint/restore, les tests déterministes et les comportements avancés du runtime. Il ne s’agit généralement pas d’un contrôle d’isolation majeur, au même titre que les namespaces mount ou user, mais il contribue malgré tout à rendre l’environnement du processus plus autonome.

D’un point de vue offensif, cet espace de noms est généralement plus pertinent pour la **reconnaissance, le décalage des timers et la compréhension du runtime** que pour un breakout direct. Il reste toutefois important, car davantage de container runtimes et de workflows de checkpoint/restore peuvent désormais le demander explicitement.

## Labo

Si le kernel de l’hôte et l’espace utilisateur le prennent en charge, vous pouvez inspecter l’espace de noms avec :
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
La prise en charge varie selon les versions du kernel et des outils. Cette page vise donc davantage à comprendre le mécanisme qu'à s'attendre à ce qu'il soit visible dans tous les environnements de lab. L'observation importante est que `date` devrait toujours refléter l'horloge murale de l'hôte, tandis que les valeurs basées sur monotonic/boottime sont celles qui changent lorsque des offsets non nuls sont configurés.

### Nuance de création

Les time namespaces sont légèrement inhabituels par rapport aux mount, PID ou network namespaces :<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` crée un nouveau time namespace pour les **futurs processus enfants**.
- La tâche appelante reste dans son time namespace actuel.
- `/proc/<pid>/ns/time_for_children` est donc souvent plus intéressant que `/proc/<pid>/ns/time` lors du debugging de la configuration du runtime.

La fenêtre d'écriture est également spéciale. Les offsets dans `/proc/<pid>/timens_offsets` doivent être écrits avant que le nouveau time namespace soit entièrement peuplé de tâches en cours d'exécution ; en pratique, les runtimes effectuent cette opération pendant la courte fenêtre de configuration située entre la création du namespace et le démarrage du payload final. Une fois qu'une tâche y est déjà en cours d'exécution, les écritures ultérieures échouent avec `EACCES`. C'est pourquoi les runtimes bas niveau traitent la configuration du time namespace comme une étape précoce du bootstrap, au lieu d'essayer de modifier les offsets depuis un processus de container déjà démarré.<sup>[[1]](#references)</sup>

### Offsets temporels

Les time namespaces Linux exposent les offsets propres à chaque namespace via `/proc/<pid>/timens_offsets`. Le format consiste en un ensemble de noms ou d'IDs d'horloges, ainsi qu'en deltas de secondes/nanosecondes relatifs au time namespace initial.<sup>[[1]](#references)</sup>

En pratique, le workflow côté utilisateur le plus fiable consiste à laisser `unshare` écrire ces offsets à votre place :
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
Le point important n’est pas la syntaxe exacte de la commande, mais le comportement : un conteneur peut observer une vue différente, similaire à la durée depuis le démarrage, sans modifier l’horloge système de l’hôte.

### Options d’assistance de `unshare`

Les versions récentes de `util-linux` fournissent des options pratiques qui écrivent automatiquement les décalages lors de la création du namespace :
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Ces flags constituent principalement une amélioration de l'ergonomie, mais ils facilitent également l'identification de cette fonctionnalité dans la documentation, les test harnesses et les wrappers runtime.

## Utilisation au runtime

Les time namespaces sont plus récents et moins largement utilisés que les mount ou PID namespaces. OCI Runtime Specification v1.1 a ajouté une prise en charge explicite du namespace `time` et du champ `linux.timeOffsets`, et les runtimes modernes peuvent intégrer ces données au flux de bootstrap du kernel. Un fragment OCI minimal ressemble à ceci :
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
Cela importe, car cela transforme le time namespacing, qui était une primitive de kernel de niche, en une fonctionnalité que les runtimes peuvent demander de manière portable. Cela explique également pourquoi les composants internes des runtimes ont besoin d'une étape explicite de synchronisation : l'offset doit être écrit dans `/proc/<pid>/timens_offsets` avant que le payload du container n'entre complètement dans le nouveau namespace.

Les stacks de checkpoint/restore telles que CRIU sont l'une des principales raisons concrètes de l'existence de cette fonctionnalité. Sans time namespaces, la restauration d'un workload suspendu ferait avancer les horloges monotonic et boot-time de la durée pendant laquelle le workload est resté suspendu.<sup>[[2]](#references)</sup>

## Impact sur la sécurité

Il existe moins de récits classiques de breakout centrés sur le time namespace que sur d'autres types de namespaces. Le risque ne vient généralement pas du fait que le time namespace permette directement une escape, mais plutôt du fait que les lecteurs l'ignorent complètement et ne voient donc pas comment des runtimes avancés peuvent modifier le comportement des processus.

Dans des environnements spécialisés, des vues modifiées des horloges monotonic ou boottime peuvent affecter :

- le comportement des timeouts et des retries
- les watchdogs et la logique des leases
- le comportement de `timerfd`, `nanosleep` et `clock_nanosleep`
- les investigations forensics liées au checkpoint/restore
- la télémétrie du temps écoulé et les heuristiques fondées sur l'uptime

Ainsi, même s'il s'agit rarement du premier namespace que vous exploitez, il peut tout à fait expliquer des comportements temporels « impossibles » pendant un assessment.

## Abuse

Il n'existe généralement pas de primitive de breakout directe ici, mais un comportement modifié des horloges peut tout de même être utile pour comprendre l'environnement d'exécution, identifier des fonctionnalités avancées des runtimes et repérer une logique fondée sur des timers mesurés par rapport à des horloges monotonic plutôt qu'à l'heure murale :
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
Si vous comparez deux processus, les différences ici peuvent aider à expliquer des comportements temporels inhabituels, des artefacts de checkpoint/restore ou des divergences de logs spécifiques à l'environnement.

Angles pratiques pertinents pour un attacker :

- perturber la logique de backoff, de sleep ou de watchdog implémentée avec des horloges monotonic
- expliquer pourquoi `/proc/uptime` et le comportement piloté par les timers diffèrent des attentes concernant l'horloge système de l'hôte
- identifier les workflows CRIU/checkpoint-restore et autres fonctionnalités runtime avancées
- repérer les environnements où rejoindre le time namespace d'une cible avec `nsenter -T -t <pid> -- ...` peut reproduire le comportement des timers local au container à des fins de debugging ou de post-exploitation

Impact :

- presque toujours lié à la reconnaissance ou à la compréhension de l'environnement
- utile pour expliquer les anomalies de logs, d'uptime ou de checkpoint/restore
- utile pour analyser les sleep, retries et timers basés sur le temps monotonic
- ne constitue normalement pas, à lui seul, un mécanisme direct de container-escape

La nuance importante concernant l'abus est que les time namespaces ne virtualisent pas `CLOCK_REALTIME`. Ils ne permettent donc pas, à eux seuls, à un attacker de falsifier l'horloge système de l'hôte ni de contourner directement les vérifications d'expiration des certificats à l'échelle du système. Leur intérêt réside principalement dans la perturbation d'une logique basée sur le temps monotonic, la reproduction de bugs spécifiques à l'environnement ou la compréhension de comportements runtime avancés.

## Vérifications

Ces vérifications visent principalement à confirmer si le runtime utilise effectivement un time namespace privé et s'il a défini des offsets non nuls.
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

- Dans de nombreux environnements, ces valeurs ne conduiront pas à une constatation de sécurité immédiate, mais elles indiquent si une fonctionnalité spécialisée du runtime est utilisée.
- Si `time_for_children` diffère de `time`, l'appelant a peut-être préparé un namespace temporel réservé aux processus enfants dans lequel il n'est pas lui-même entré.
- Si `date` correspond à l'hôte, mais que les valeurs basées sur monotonic/boottime sont différentes, vous observez probablement un time namespacing plutôt qu'une falsification de l'horloge système.
- Si vous comparez deux processus, ces différences peuvent expliquer un comportement déroutant concernant le timing ou le checkpoint/restore.

Pour la plupart des container breakouts, le namespace temporel ne sera pas le premier contrôle que vous examinerez. Toutefois, une section complète consacrée à la container-security devrait le mentionner, car il fait partie du modèle moderne du kernel et peut occasionnellement avoir de l'importance dans des scénarios avancés de runtime.

## Références

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
