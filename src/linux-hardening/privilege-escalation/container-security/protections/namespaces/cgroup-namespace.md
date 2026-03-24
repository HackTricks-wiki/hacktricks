# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

Le cgroup namespace ne remplace pas les cgroups et n'applique pas lui-même des limites de ressources. Il modifie plutôt **la manière dont la hiérarchie cgroup apparaît** au processus. Autrement dit, il virtualise les informations de chemin cgroup visibles afin que la charge de travail voie une vue limitée au conteneur plutôt que la hiérarchie complète de l'hôte.

C'est principalement une fonctionnalité de visibilité et de réduction d'information. Elle aide à donner l'apparence d'un environnement autonome et révèle moins la structure cgroup de l'hôte. Cela peut sembler modeste, mais c'est important : une visibilité inutile sur la structure de l'hôte peut faciliter la reconnaissance et simplifier des chaînes d'exploitation dépendantes de l'environnement.

## Fonctionnement

Sans un cgroup namespace privé, un processus peut voir des chemins cgroup relatifs à l'hôte qui exposent plus de la hiérarchie de la machine que nécessaire. Avec un cgroup namespace privé, `/proc/self/cgroup` et les observations associées deviennent plus localisées à la vue du conteneur. Ceci est particulièrement utile dans les stacks runtime modernes qui veulent que la charge de travail voie un environnement plus propre, qui révèle moins l'hôte.

## Laboratoire

Vous pouvez inspecter un cgroup namespace avec :
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
Le changement concerne surtout ce que le processus peut voir, pas l'existence de cgroup enforcement.

## Impact sur la sécurité

Le cgroup namespace est mieux compris comme une **couche de durcissement de la visibilité**. Pris isolément, il n'empêchera pas un breakout si le container dispose de writable cgroup mounts, de broad capabilities, ou d'un environnement cgroup v1 dangereux. Cependant, si le host cgroup namespace est partagé, le processus en apprend davantage sur l'organisation du système et peut trouver plus facile d'aligner host-relative cgroup paths avec d'autres observations.

Ainsi, bien que ce namespace ne soit généralement pas la vedette des container breakout writeups, il contribue néanmoins à l'objectif plus large de minimiser la host information leakage.

## Abus

La valeur d'abus immédiate est surtout de la reconnaissance. Si le host cgroup namespace est partagé, comparez les chemins visibles et cherchez des détails hiérarchiques révélateurs du host :
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
Le namespace lui-même donne rarement un escape instantané, mais il facilite souvent la cartographie de l'environnement avant de tester des cgroup-based abuse primitives.

### Exemple complet : Shared cgroup Namespace + Writable cgroup v1

Le cgroup namespace seul n'est généralement pas suffisant pour un escape. L'escalade pratique se produit lorsque des host-revealing cgroup paths sont combinés avec des writable cgroup v1 interfaces :
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si ces fichiers sont accessibles et inscriptibles, pivotez immédiatement vers le flux d'exploitation complet `release_agent` depuis [cgroups.md](../cgroups.md). L'impact est l'exécution de code sur l'hôte depuis l'intérieur du conteneur.

Sans interfaces cgroup accessibles en écriture, l'impact se limite généralement à la reconnaissance.

## Checks

Le but de ces commandes est de vérifier si le processus dispose d'une vue privée de l'espace de noms cgroup ou s'il obtient plus d'informations sur la hiérarchie de l'hôte que nécessaire.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Ce qui est intéressant ici :

- Si l'identifiant de namespace correspond à un host process qui vous intéresse, le cgroup namespace peut être partagé.
- Les chemins révélant le host dans `/proc/self/cgroup` sont utiles pour la reconnaissance même s'ils ne sont pas directement exploitables.
- Si les cgroup mounts sont aussi en écriture, la question de visibilité devient beaucoup plus importante.

Le cgroup namespace doit être traité comme une couche de durcissement de la visibilité plutôt que comme un escape-prevention mechanism primaire. Exposer inutilement la host cgroup structure augmente la valeur de reconnaissance pour l'attaquant.
{{#include ../../../../../banners/hacktricks-training.md}}
