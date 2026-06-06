# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Le time namespace virtualise des clocks monotonic-style sélectionnées au lieu du wall clock de l’hôte. En pratique, cela signifie des offsets privés pour **`CLOCK_MONOTONIC`** et **`CLOCK_BOOTTIME`**, ainsi que les vues étroitement liées **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** et **`CLOCK_BOOTTIME_ALARM`**. Il ne virtualise pas **`CLOCK_REALTIME`**, donc `date` et la logique d’expiration des certificats observent toujours le wall clock de l’hôte, sauf si un autre mécanisme interfère.

Le but principal est de permettre à un processus d’observer des offsets d’écoulement du temps contrôlés sans modifier la vue globale du temps de l’hôte. C’est utile pour les workflows de checkpoint/restore, les tests déterministes et les comportements avancés du runtime. Ce n’est généralement pas un contrôle d’isolation phare comme mount ou user namespaces, mais cela contribue quand même à rendre l’environnement du processus plus autonome.

D’un point de vue offensif, ce namespace est généralement plus pertinent pour la **reconnaissance, le timer skew et la compréhension du runtime** que pour une breakout directe. Cela dit, il compte parce que de plus en plus de container runtimes et de workflows de checkpoint/restore peuvent désormais le demander explicitement.

## Lab

Si le kernel de l’hôte et userspace le prennent en charge, vous pouvez inspecter le namespace avec :
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
La prise en charge varie selon la version du kernel et des outils, donc cette page vise surtout à comprendre le mécanisme plutôt qu’à s’attendre à le voir dans chaque environnement de lab. L’observation importante est que `date` doit toujours refléter l’horloge murale de l’hôte, tandis que les valeurs basées sur monotonic/boottime sont celles qui changent lorsque des offsets non nuls sont configurés.

### Creation Nuance

Les time namespaces sont légèrement inhabituels par rapport aux mount, PID ou network namespaces :

- `unshare(CLONE_NEWTIME)` crée un nouveau time namespace pour les **future children**.
- Le task appelant reste dans son time namespace actuel.
- `/proc/<pid>/ns/time_for_children` est donc souvent plus intéressant que `/proc/<pid>/ns/time` lors du debug du runtime setup.

La fenêtre d’écriture est aussi particulière. Les offsets dans `/proc/<pid>/timens_offsets` doivent être écrits avant que le nouveau time namespace soit entièrement peuplé avec des tasks en cours d’exécution ; en pratique, les runtimes font cela pendant la courte fenêtre de setup entre la création du namespace et le démarrage du payload final. Une fois qu’un task y est déjà en cours d’exécution, les écritures ultérieures échouent avec `EACCES`. C’est pourquoi les low-level runtimes gèrent le setup du time-namespace comme une étape de bootstrap initiale au lieu d’essayer de patcher les offsets depuis l’intérieur d’un process de container déjà démarré.

### Time Offsets

Les Linux time namespaces exposent les offsets par-namespace via `/proc/<pid>/timens_offsets`. Le format est un ensemble de noms ou d’IDs d’horloges, plus des deltas en secondes/nanosecondes par rapport au time namespace initial.

En pratique, le workflow côté utilisateur le plus fiable consiste à laisser `unshare` écrire ces offsets pour vous :
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

### `unshare` Helper Flags

Les versions récentes de `util-linux` fournissent des flags de commodité qui écrivent automatiquement les offsets pendant la création du namespace :
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Ces flags constituent surtout une amélioration de l’utilisabilité, mais ils facilitent aussi la reconnaissance de la fonctionnalité dans la documentation, les test harnesses et les runtime wrappers.

## Runtime Usage

Les time namespaces sont plus récents et moins universellement utilisés que les mount ou PID namespaces. OCI Runtime Specification v1.1 a ajouté une prise en charge explicite du namespace `time` et du champ `linux.timeOffsets`, et les runtimes modernes peuvent mapper ces données dans le flux de bootstrap du kernel. Un fragment OCI minimal ressemble à :
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
Cela compte parce que cela transforme le time namespacing d’un primitive noyau de niche en quelque chose que les runtimes peuvent demander de manière portable. Cela explique aussi pourquoi les mécanismes internes du runtime ont besoin d’une étape explicite de synchronisation : l’offset doit être écrit dans `/proc/<pid>/timens_offsets` avant que le payload du container n’entre complètement dans le nouveau namespace.

Les stacks de checkpoint/restore comme CRIU sont l’une des principales raisons concrètes pour lesquelles cela existe. Sans time namespaces, restaurer une charge de travail en pause ferait sauter les horloges monotonic et boot-time du temps pendant lequel la charge de travail est restée suspendue.

## Security Impact

Il existe moins d’histoires classiques de breakout centrées sur le time namespace que sur d’autres types de namespace. Ici, le risque n’est généralement pas que le time namespace permette directement une escape, mais que les lecteurs l’ignorent complètement et passent ainsi à côté de la façon dont des runtimes avancés peuvent façonner le comportement des processus.

Dans des environnements spécialisés, des vues modifiées de monotonic ou boottime peuvent affecter :

- le comportement des timeout et des retry
- les watchdogs et la logique de lease
- le comportement de `timerfd`, `nanosleep`, et `clock_nanosleep`
- la forensic de checkpoint/restore
- la télémétrie de temps écoulé et les heuristiques basées sur l’uptime

Donc, même si ce n’est rarement le premier namespace que vous abusez, cela peut tout à fait expliquer un comportement de timing « impossible » pendant un assessment.

## Abuse

Il n’existe généralement pas de primitive directe de breakout ici, mais un comportement d’horloge modifié peut quand même être utile pour comprendre l’environnement d’exécution, identifier des fonctionnalités avancées du runtime, et repérer une logique basée sur des timer mesurée par rapport à des horloges monotonic plutôt qu’au temps de l’horloge murale :
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
Si vous comparez deux processus, les différences ici peuvent aider à expliquer un comportement de timing étrange, des artefacts de checkpoint/restore, ou des décalages de logging spécifiques à l’environnement.

Angles pratiques pertinents pour un attaquant :

- brouiller la logique de backoff, sleep ou watchdog implémentée avec des horloges monotonic
- expliquer pourquoi `/proc/uptime` et le comportement piloté par des timers divergent des attentes basées sur l’horloge murale côté host
- reconnaître les workflows CRIU/checkpoint-restore et d’autres fonctionnalités runtime avancées
- repérer les environnements où rejoindre un target time namespace avec `nsenter -T -t <pid> -- ...` peut reproduire le comportement local des timers du container pour du debugging ou du post-exploitation

Impact :

- presque toujours de la reconnaissance ou de la compréhension de l’environnement
- utile pour expliquer des anomalies de logging, d’uptime ou de checkpoint/restore
- utile pour analyser des sleeps, retries et timers basés sur monotonic-time
- normalement pas un mécanisme direct de container-escape à lui seul

La nuance importante d’abus est que les time namespaces ne virtualisent pas `CLOCK_REALTIME`, donc ils ne permettent pas à eux seuls à un attaquant de falsifier l’horloge murale du host ou de casser directement les vérifications d’expiration de certificat à l’échelle du système. Leur intérêt est surtout de perturber la logique basée sur monotonic-time, de reproduire des bugs spécifiques à l’environnement, ou de comprendre un comportement runtime avancé.

## Checks

Ces checks servent surtout à confirmer si le runtime utilise ou non un time namespace privé, et s’il a réellement défini des offsets non nuls.
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
What is interesting here:

- Dans many environments, ces values ne conduiront pas à un security finding immédiat, mais elles vous indiquent si une specialized runtime feature est en play.
- Si `time_for_children` differs de `time`, le caller a peut-être préparé un child-only time namespace qu’il n’a pas lui-même entered.
- Si `date` matches l’host mais les valeurs basées sur monotonic/boottime ne le font pas, vous regardez probablement du time namespacing plutôt qu’une wall-clock tampering.
- Si vous comparez deux processes, les differences ici peuvent expliquer un timing confus ou un comportement de checkpoint/restore.

For most container breakouts, le time namespace n’est pas le premier control que vous investiguerez. Still, une complete container-security section should mention it because it is part of the modern kernel model and occasionally matters in advanced runtime scenarios.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
