# Espace de noms cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

L'espace de noms cgroup ne remplace pas les cgroups et n'applique pas lui-même des limites de ressources. Au lieu de cela, il modifie **la façon dont la hiérarchie cgroup apparaît** au processus. Autrement dit, il virtualise les informations de chemin cgroup visibles afin que le workload voie une vue limitée au container plutôt que la hiérarchie complète de l'hôte.

C'est principalement une fonctionnalité de visibilité et de réduction d'information. Elle aide à faire paraître l'environnement autonome et révèle moins sur la disposition cgroup de l'hôte. Cela peut sembler modeste, mais c'est important : une visibilité inutile sur la structure de l'hôte peut faciliter la reconnaissance et simplifier des chaînes d'exploitation dépendantes de l'environnement.

## Fonctionnement

Sans espace de noms cgroup privé, un processus peut voir des chemins cgroup relatifs à l'hôte qui exposent plus de la hiérarchie de la machine que nécessaire. Avec un espace de noms cgroup privé, `/proc/self/cgroup` et les observations associées deviennent plus localisées à la vue du container. Ceci est particulièrement utile dans les stacks runtime modernes qui veulent que le workload voie un environnement plus épuré et moins révélateur de l'hôte.

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
Le changement concerne principalement ce que le processus peut voir, et non pas l'existence du cgroup enforcement.

## Security Impact

The cgroup namespace is best understood as a **couche de durcissement de la visibilité**. By itself it will not stop a breakout if the container has writable cgroup mounts, broad capabilities, or a dangerous cgroup v1 environment. However, if the host cgroup namespace is shared, the process learns more about how the system is organized and may find it easier to line up host-relative cgroup paths with other observations.

So while this namespace is not usually the star of container breakout writeups, it still contributes to the broader goal of minimizing host information leakage.

## Abuse

The immediate abuse value is mostly reconnaissance. If the host cgroup namespace is shared, compare the visible paths and look for host-revealing hierarchy details:
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
Le namespace lui-même donne rarement un escape instantané, mais il rend souvent l'environnement plus facile à cartographier avant de tester les cgroup-based abuse primitives.

### Exemple complet: Shared cgroup Namespace + Writable cgroup v1

Le cgroup namespace seul n'est généralement pas suffisant pour un escape. L'escalade pratique se produit lorsque des host-revealing cgroup paths sont combinés avec des writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si ces fichiers sont accessibles et modifiables, basculez immédiatement vers le flux d'exploitation complet `release_agent` depuis [cgroups.md](../cgroups.md). L'impact est une exécution de code sur l'hôte depuis l'intérieur du conteneur.

Sans interfaces cgroup modifiables, l'impact se limite généralement à la reconnaissance.

## Vérifications

Le but de ces commandes est de vérifier si le processus a une vue privée du cgroup namespace ou s'il en apprend davantage sur la hiérarchie de l'hôte que strictement nécessaire.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- Si l'identifiant du namespace correspond à un processus hôte qui vous intéresse, le cgroup namespace peut être partagé.
- Les chemins révélant l'hôte dans `/proc/self/cgroup` sont utiles pour la reconnaissance même lorsqu'ils ne sont pas directement exploitables.
- Si cgroup mounts sont aussi inscriptibles, la question de la visibilité devient beaucoup plus importante.

Le cgroup namespace doit être traité comme une couche de durcissement de visibilité plutôt que comme un mécanisme principal de prévention des escapes. L'exposition inutile de la structure cgroup de l'hôte ajoute de la valeur de reconnaissance pour l'attaquant.
{{#include ../../../../../banners/hacktricks-training.md}}
