# Namespace cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Présentation

Le cgroup namespace ne remplace pas les cgroups et n'impose pas lui-même de limites de ressources. Il modifie plutôt **la manière dont la hiérarchie des cgroups apparaît** au processus. Autrement dit, il virtualise les informations de chemin des cgroups afin que le workload dispose d'une vue limitée au container, plutôt que de voir l'ensemble de la hiérarchie de l'hôte.

Il s'agit principalement d'une fonctionnalité de visibilité et de réduction des informations. Elle contribue à donner l'impression que l'environnement est autonome et révèle moins d'informations sur la structure des cgroups de l'hôte. Cela peut sembler limité, mais cela reste important, car une visibilité inutile sur la structure de l'hôte peut faciliter la reconnaissance et simplifier les chaînes d'exploitation dépendantes de l'environnement.

## Fonctionnement

Sans cgroup namespace privé, un processus peut voir des chemins de cgroups relatifs à l'hôte, révélant une partie plus importante de la hiérarchie de la machine que nécessaire. Avec un cgroup namespace privé, `/proc/self/cgroup` et les observations associées deviennent plus spécifiques à la vue du container. Cela est particulièrement utile dans les stacks de runtime modernes qui veulent que le workload dispose d'un environnement plus propre et révélant moins d'informations sur l'hôte.

La virtualisation affecte également `/proc/<pid>/mountinfo`, et pas seulement `/proc/<pid>/cgroup`. Lorsque vous lisez un autre processus depuis une perspective différente de cgroup namespace, les chemins situés en dehors de la racine de votre namespace sont affichés avec des composants `../` en tête, ce qui constitue un indice pratique indiquant que vous observez au-dessus de votre subtree délégué. Un détail utile pour les labs et le post-exploitation est qu'un cgroup namespace fraîchement créé nécessite souvent un **remount de cgroupfs depuis l'intérieur de ce namespace** avant que `mountinfo` reflète correctement la nouvelle racine. Sinon, vous pouvez toujours voir une racine de montage telle que `/..`, ce qui signifie que le montage hérité expose encore une vue basée sur la racine d'un ancêtre, même si le namespace lui-même a déjà changé.<sup>[[1]](#references)</sup>

## Lab

Vous pouvez inspecter un cgroup namespace avec :
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Si vous voulez que `mountinfo` affiche plus clairement la nouvelle racine du cgroup namespace, remontez le système de fichiers cgroup depuis le nouveau namespace, puis comparez à nouveau :
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Et comparez le comportement à l’exécution avec :
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Le changement concerne principalement ce que le processus peut voir, et non l'existence ou non d'un enforcement cgroup.

## Impact sur la sécurité

Le cgroup namespace doit être compris comme une **couche de hardening de la visibilité**. À lui seul, il n'empêchera pas un breakout si le container dispose de mounts cgroup inscriptibles, de capabilities étendues ou d'un environnement cgroup v1 dangereux. Cependant, si le cgroup namespace de l'hôte est partagé, le processus en apprend davantage sur l'organisation du système et peut plus facilement faire correspondre les chemins cgroup relatifs à l'hôte avec d'autres observations.

Sur **cgroup v2**, le namespace devient un peu plus important, car les règles de délégation sont plus strictes. Si la hiérarchie est montée avec `nsdelegate`, le kernel considère les cgroup namespaces comme des limites de délégation : les fichiers de contrôle des ancêtres sont censés rester hors de portée du delegatee, et les écritures à la racine du namespace sont limitées à des fichiers compatibles avec la délégation, tels que `cgroup.procs`, `cgroup.threads` et `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Cela ne fait toujours pas du namespace une primitive d'escape à lui seul, mais modifie ce qu'un workload compromis peut inspecter et l'endroit où il peut créer des sous-cgroups en toute sécurité.

Ainsi, même si ce namespace n'est généralement pas la vedette des writeups de container breakout, il contribue tout de même à l'objectif plus large de réduire les leaks d'informations sur l'hôte et de limiter la délégation cgroup.

## Abuse

La valeur immédiate pour l'abuse concerne principalement la reconnaissance. Si le cgroup namespace de l'hôte est partagé, comparez les chemins visibles et recherchez les détails de hiérarchie révélant l'hôte :
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Si des chemins cgroup accessibles en écriture sont également exposés, combinez cette visibilité avec une recherche d’interfaces legacy dangereuses :
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Le namespace lui-même permet rarement une évasion immédiate, mais il facilite souvent la cartographie de l’environnement avant de tester les primitives d’abus basées sur les cgroups.

Une vérification rapide de la réalité du runtime aide également à prioriser le chemin d’attaque. Docker expose `--cgroupns=host|private`, tandis que Podman prend en charge `host`, `private`, `container:<id>` et `ns:<path>`. Avec Podman, spécifiquement, la valeur par défaut est généralement **`host` avec cgroup v1** et **`private` avec cgroup v2**. Ainsi, le simple fait d’identifier la version du cgroup indique déjà quelle posture du namespace est la plus probable, avant même d’inspecter la configuration OCI complète.

### Recon v2 moderne : s’agit-il d’un sous-arbre délégué ?

Sur les hôtes modernes, la question intéressante n’est souvent pas `release_agent`, mais plutôt de savoir si le processus actuel se trouve dans un sous-arbre **cgroup v2** délégué, avec suffisamment de visibilité ou de droits d’écriture pour créer des groupes imbriqués :
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interprétation utile :

- `cgroup2fs` signifie que vous êtes dans la hiérarchie unifiée v2 ; les chaînes classiques `release_agent` propres à v1 ne devraient donc plus être votre première hypothèse.
- `cgroup.controllers` indique quels contrôleurs sont disponibles depuis le parent et, par conséquent, vers quels contrôleurs le sous-arbre actuel pourrait potentiellement s’étendre pour ses enfants.
- `cgroup.subtree_control` indique quels contrôleurs sont effectivement activés pour les descendants.
- `cgroup.events` expose `populated=0/1`, ce qui est pratique pour surveiller si un sous-arbre est devenu vide, mais ce n’est **pas une primitive d’exécution de code sur l’hôte** comme `release_agent` de v1.

Si vous disposez déjà de suffisamment de privilèges pour inspecter directement le namespace d’un autre processus, comparez les vues avec :
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Exemple complet : Shared cgroup Namespace + Writable cgroup v1

Le cgroup namespace seul ne suffit généralement pas pour effectuer un escape. L’escalade pratique se produit lorsque des chemins cgroup révélant l’hôte sont combinés à des interfaces cgroup v1 en écriture :
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si ces fichiers sont accessibles et inscriptibles, passez immédiatement au flux complet d’exploitation de `release_agent` décrit dans [cgroups.md](../cgroups.md). L’impact est une exécution de code sur l’hôte depuis l’intérieur du container.

Sans interfaces cgroup inscriptibles, l’impact se limite généralement à la reconnaissance.

## Vérifications

Le but de ces commandes est de déterminer si le processus dispose d’une vue privée du namespace cgroup ou s’il apprend davantage sur la hiérarchie de l’hôte que nécessaire.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Ce qui est intéressant ici :

- Si l’identifiant du namespace correspond à un processus de l’hôte qui vous intéresse, le cgroup namespace peut être partagé.
- Les chemins révélant l’hôte dans `/proc/self/cgroup` ou les entrées enracinées sur les ancêtres dans `mountinfo` sont utiles pour la reconnaissance, même lorsqu’ils ne sont pas directement exploitables.
- Si `cgroup2fs` est utilisé, concentrez-vous sur la délégation, les contrôleurs visibles et les sous-arborescences accessibles en écriture, plutôt que de supposer que les anciennes primitives v1 existent toujours.
- Si les montages cgroup sont également accessibles en écriture, la question de la visibilité devient bien plus importante.

Le cgroup namespace doit être considéré comme une couche de renforcement de la visibilité plutôt que comme un mécanisme principal de prévention des évasions. Exposer inutilement la structure cgroup de l’hôte apporte une valeur supplémentaire pour la reconnaissance de l’attaquant.

## Références

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
