# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Le cgroup namespace ne remplace pas les cgroups et n’impose pas lui-même de limites de ressources. À la place, il modifie **la façon dont la hiérarchie cgroup apparaît** au processus. En d’autres termes, il virtualise les informations visibles du chemin cgroup afin que le workload voie une vue limitée au container plutôt que la hiérarchie complète du host.

Il s’agit principalement d’une fonctionnalité de visibilité et de réduction d’informations. Elle aide à faire paraître l’environnement autonome et révèle moins de choses sur la disposition des cgroups du host. Cela peut sembler modeste, mais c’est tout de même important, car une visibilité inutile sur la structure du host peut aider la reconnaissance et simplifier les chaînes d’exploit dépendantes de l’environnement.

## Operation

Sans cgroup namespace privé, un processus peut voir des chemins cgroup relatifs au host qui exposent une plus grande partie de la hiérarchie de la machine que nécessaire. Avec un cgroup namespace privé, `/proc/self/cgroup` et les observations associées deviennent plus localisés à la vue propre au container. C’est particulièrement utile dans les stacks de runtime modernes qui veulent que le workload voie un environnement plus propre et moins révélateur du host.

La virtualisation affecte aussi `/proc/<pid>/mountinfo`, pas seulement `/proc/<pid>/cgroup`. Lorsque vous lisez un autre processus depuis une perspective de cgroup-namespace différente, les chemins en dehors de la racine de votre namespace sont affichés avec des composants `../` en tête, ce qui est un indice pratique que vous regardez au-dessus de votre sous-arbre délégué. Une nuance utile pour les labs et le post-exploitation est qu’un cgroup namespace nouvellement créé nécessite souvent un **cgroupfs remount depuis l’intérieur de ce namespace** avant que `mountinfo` reflète proprement la nouvelle racine. Sinon, vous pouvez encore voir une racine de montage comme `/..`, ce qui signifie que le montage hérité expose toujours une vue enracinée sur un ancêtre, même si le namespace lui-même a déjà changé.

## Lab

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Si vous voulez que `mountinfo` affiche plus clairement la nouvelle racine du cgroup-namespace, remontez le système de fichiers cgroup depuis l’intérieur du nouveau namespace, puis comparez à nouveau :
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Et comparez le comportement à l'exécution avec :
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Le changement concerne surtout ce que le processus peut voir, et non l’existence ou non de l’application des cgroup.

## Security Impact

Le cgroup namespace se comprend surtout comme une **couche de renforcement de la visibilité**. À lui seul, il n’empêchera pas une breakout si le container a des montages cgroup en écriture, des capacités larges, ou un environnement cgroup v1 dangereux. Cependant, si le cgroup namespace de l’hôte est partagé, le processus apprend davantage sur l’organisation du système et peut plus facilement faire correspondre des chemins cgroup relatifs à l’hôte avec d’autres observations.

Sur **cgroup v2**, le namespace devient un peu plus important parce que les règles de délégation sont plus strictes. Si la hiérarchie est montée avec `nsdelegate`, le kernel traite les cgroup namespaces comme des limites de délégation : les fichiers de contrôle des ancêtres sont censés rester hors de portée du delegatee, et les écritures à la racine du namespace sont limitées aux fichiers sûrs pour la délégation, comme `cgroup.procs`, `cgroup.threads` et `cgroup.subtree_control`. Cela ne fait toujours pas du namespace un primitive d’évasion à lui seul, mais cela change ce qu’une workload compromise peut inspecter et où elle peut créer en toute sécurité des sous-cgroups.

Donc, même si ce namespace n’est généralement pas la vedette des writeups de container breakout, il contribue quand même à l’objectif plus large de minimiser la fuite d’informations de l’hôte et de contraindre la délégation cgroup.

## Abuse

La valeur d’abuse immédiate est surtout la reconnaissance. Si le cgroup namespace de l’hôte est partagé, comparez les chemins visibles et cherchez des détails de hiérarchie révélant l’hôte :
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Si des chemins cgroup inscriptibles sont aussi exposés, combinez cette visibilité avec une recherche d'interfaces legacy dangereuses :
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Le namespace lui-même donne rarement un escape instantané, mais il rend souvent l’environnement plus facile à cartographier avant de tester des primitives d’abus basées sur cgroup.

Un rapide contrôle de la réalité d’exécution aide aussi à prioriser la voie d’attaque. Docker expose `--cgroupns=host|private`, tandis que Podman prend en charge `host`, `private`, `container:<id>`, et `ns:<path>`. Sur Podman en particulier, la valeur par défaut est généralement **`host` sur cgroup v1** et **`private` sur cgroup v2**, donc identifier simplement la version de cgroup vous indique déjà quelle posture de namespace est la plus probable avant même d’inspecter la configuration OCI complète.

### Modern v2 Recon: Is This A Delegated Subtree?

Sur les hôtes modernes, la question intéressante n’est souvent pas `release_agent`, mais plutôt de savoir si le processus courant se trouve dans un sous-arbre **cgroup v2** délégué avec suffisamment de visibilité ou d’accès en écriture pour construire des groupes imbriqués :
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interprétation utile :

- `cgroup2fs` signifie que vous êtes dans la hiérarchie unifiée v2, donc les chaînes `release_agent` classiques propres à v1 ne devraient plus être votre premier réflexe.
- `cgroup.controllers` montre quels controllers sont disponibles depuis le parent et donc vers quoi le sous-arbre actuel pourrait potentiellement se déployer vers des enfants.
- `cgroup.subtree_control` montre quels controllers sont réellement activés pour les descendants.
- `cgroup.events` expose `populated=0/1`, ce qui est pratique pour surveiller si un sous-arbre est devenu vide, mais ce n’est **pas** un primitive d’exécution de code sur l’hôte comme `release_agent` de v1.

Si vous avez déjà suffisamment de privilèges pour inspecter directement le namespace d’un autre processus, comparez les vues avec :
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Exemple complet : Namespace cgroup partagé + cgroup v1 inscriptible

Le cgroup namespace seul ne suffit généralement pas pour s’échapper. L’escalade pratique se produit lorsque des chemins cgroup révélant l’hôte sont combinés avec des interfaces cgroup v1 inscriptibles :
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Si ces fichiers sont accessibles et inscriptibles, pivotez immédiatement vers le flux d’exploitation complet de `release_agent` depuis [cgroups.md](../cgroups.md). L’impact est l’exécution de code sur l’hôte depuis l’intérieur du conteneur.

Sans interfaces cgroup inscriptibles, l’impact est généralement limité à la reconnaissance.

## Checks

Le but de ces commandes est de voir si le process a une vue de namespace cgroup privée ou s’il apprend davantage sur la hiérarchie de l’hôte qu’il n’en a vraiment besoin.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Ce qui est intéressant ici :

- Si l’identifiant de namespace correspond à un processus hôte qui vous intéresse, le cgroup namespace peut être partagé.
- Les chemins révélant l’hôte dans `/proc/self/cgroup` ou les entrées enracinées sur l’ancêtre dans `mountinfo` sont utiles pour la reconnaissance même lorsqu’ils ne sont pas directement exploitables.
- Si `cgroup2fs` est utilisé, concentrez-vous sur la délégation, les contrôleurs visibles et les sous-arbres inscriptibles plutôt que de supposer que les anciens primitives v1 existent encore.
- Si les montages cgroup sont aussi inscriptibles, la question de la visibilité devient encore plus importante.

Le cgroup namespace doit être considéré comme une couche de durcissement de la visibilité plutôt que comme un mécanisme principal de prévention d’évasion. Exposer inutilement la structure cgroup de l’hôte ajoute de la valeur de reconnaissance pour l’attaquant.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
