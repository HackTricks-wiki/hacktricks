# Espace de noms cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms cgroup ne remplace pas les cgroups et n'applique pas lui-même des limites de ressources. Il modifie plutôt **la façon dont la hiérarchie des cgroups apparaît** au processus. Autrement dit, il virtualise l'information sur les chemins cgroup visibles afin que la charge de travail voie une vue limitée au conteneur plutôt que la hiérarchie complète de l'hôte.

C'est principalement une fonctionnalité de réduction de visibilité et d'information. Elle aide à rendre l'environnement autonome et à révéler moins sur l'agencement des cgroups de l'hôte. Cela peut sembler modeste, mais c'est important : une visibilité inutile sur la structure de l'hôte peut faciliter la reconnaissance et simplifier des chaînes d'exploitation dépendantes de l'environnement.

## Fonctionnement

Sans espace de noms cgroup privé, un processus peut voir des chemins cgroup relatifs à l'hôte qui exposent plus de la hiérarchie de la machine que nécessaire. Avec un espace de noms cgroup privé, `/proc/self/cgroup` et les observations associées deviennent plus localisées à la vue du conteneur. C'est particulièrement utile dans les stacks d'exécution modernes qui souhaitent que la charge de travail voie un environnement plus propre, moins révélateur de l'hôte.

## Laboratoire

Vous pouvez inspecter un espace de noms cgroup avec :
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
Et comparez le comportement à l'exécution avec :
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Le changement concerne surtout ce que le processus peut voir, pas si le cgroup enforcement existe.

## Impact sur la sécurité

Le cgroup namespace est mieux compris comme une **visibility-hardening layer**. Pris isolément, il n'empêchera pas un container breakout si le container a des cgroup mounts en écriture, des capabilities larges, ou un environnement cgroup v1 dangereux. Cependant, si le host cgroup namespace est partagé, le processus apprend davantage sur l'organisation du système et peut trouver plus facile d'aligner les host-relative cgroup paths avec d'autres observations.

Donc, même si ce namespace n'est généralement pas la vedette des writeups de container breakout, il contribue néanmoins à l'objectif plus large de minimiser le host information leakage.

## Abus

La valeur d'abus immédiate est essentiellement reconnaissance. Si le host cgroup namespace est partagé, comparez les chemins visibles et cherchez des détails de hiérarchie révélateurs de l'hôte :
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Si des chemins cgroup accessibles en écriture sont également exposés, combinez cette visibilité avec une recherche d'interfaces héritées dangereuses :
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Le namespace lui-même donne rarement un escape instantané, mais il facilite souvent la cartographie de l'environnement avant de tester des primitives d'abus basées sur les cgroup.

### Exemple complet : cgroup Namespace partagé + cgroup v1 modifiable en écriture

Le cgroup namespace seul n'est généralement pas suffisant pour un escape. L'escalade pratique survient lorsque des chemins cgroup révélant l'hôte sont combinés avec des interfaces cgroup v1 modifiables en écriture :
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si ces fichiers sont accessibles et modifiables, pivotez immédiatement vers le flux complet d'exploitation `release_agent` depuis [cgroups.md](../cgroups.md). L'impact est l'exécution de code sur l'hôte depuis l'intérieur du conteneur.

Sans interfaces cgroup modifiables, l'impact est généralement limité à la reconnaissance.

## Vérifications

Le but de ces commandes est de voir si le processus a une vue privée de l'espace de noms cgroup ou s'il voit plus de la hiérarchie de l'hôte qu'il n'en a réellement besoin.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- Si l'identifiant de l'espace de noms correspond à un processus hôte qui vous intéresse, il se peut que l'espace de noms cgroup soit partagé.
- Les chemins révélant l'hôte dans `/proc/self/cgroup` sont utiles pour la reconnaissance même lorsqu'ils ne sont pas directement exploitables.
- Si les montages cgroup sont aussi accessibles en écriture, la question de la visibilité devient beaucoup plus importante.

L'espace de noms cgroup doit être traité comme une couche de durcissement de la visibilité plutôt que comme un mécanisme principal de prévention d'évasion. Exposer inutilement la structure cgroup de l'hôte augmente la valeur de reconnaissance pour l'attaquant.
