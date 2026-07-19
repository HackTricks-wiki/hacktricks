# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Les namespaces sont une fonctionnalité du kernel qui fait qu’un container ressemble à « sa propre machine », même s’il ne s’agit en réalité que d’un arbre de processus de l’hôte. Ils ne créent pas de nouveau kernel et ne virtualisent pas tout, mais ils permettent au kernel de présenter différentes vues de certaines ressources à différents groupes de processus. C’est le cœur de l’illusion du container : le workload voit un système de fichiers, une table des processus, une stack réseau, un hostname, des ressources IPC et un modèle d’identités utilisateur/groupe qui semblent locaux, alors que le système sous-jacent est partagé.

C’est pourquoi les namespaces sont le premier concept que la plupart des gens rencontrent lorsqu’ils apprennent le fonctionnement des containers. En même temps, ils sont l’un des concepts les plus souvent mal compris, car les lecteurs supposent souvent que « possède des namespaces » signifie « est isolé de manière sûre ». En réalité, un namespace n’isole que la classe spécifique de ressources pour laquelle il a été conçu. Un processus peut avoir un namespace PID privé et rester dangereux parce qu’il dispose d’un bind mount de l’hôte accessible en écriture. Il peut avoir un namespace réseau privé et rester dangereux parce qu’il conserve `CAP_SYS_ADMIN` et s’exécute sans seccomp. Les namespaces sont fondamentaux, mais ils ne constituent qu’une seule couche de la boundary finale.

## Types de namespaces

Les containers Linux s’appuient généralement sur plusieurs types de namespaces à la fois. Le **namespace mount** fournit au processus une table de montages distincte et donc une vue contrôlée du système de fichiers. Le **namespace PID** modifie la visibilité et la numérotation des processus afin que le workload voie son propre arbre de processus. Le **namespace réseau** isole les interfaces, les routes, les sockets et l’état du firewall. Le **namespace IPC** isole l’IPC SysV et les files de messages POSIX. Le **namespace UTS** isole le hostname et le nom de domaine NIS. Le **namespace user** remappe les identifiants utilisateur et groupe afin que root dans le container ne signifie pas nécessairement root sur l’hôte. Le **namespace cgroup** virtualise la hiérarchie cgroup visible, et le **namespace time** virtualise certaines horloges dans les kernels récents.

Chacun de ces namespaces répond à un problème différent. C’est pourquoi l’analyse pratique de la sécurité des containers consiste souvent à vérifier **quels namespaces sont isolés** et **lesquels ont été délibérément partagés avec l’hôte**.

## Partage des namespaces de l’hôte

De nombreux container breakouts ne commencent pas par une vulnérabilité du kernel. Ils commencent par un opérateur qui affaiblit délibérément le modèle d’isolation. Les exemples `--pid=host`, `--network=host` et `--userns=host` sont des **flags CLI de type Docker/Podman** utilisés ici comme exemples concrets de partage de namespaces de l’hôte. D’autres runtimes expriment la même idée différemment. Dans Kubernetes, les équivalents apparaissent généralement sous la forme de paramètres du Pod tels que `hostPID: true`, `hostNetwork: true` ou `hostIPC: true`. Dans les stacks de runtime de plus bas niveau telles que containerd ou CRI-O, le même comportement est souvent obtenu via la configuration runtime OCI générée plutôt que par un flag exposé à l’utilisateur portant le même nom. Dans tous ces cas, le résultat est similaire : le workload ne reçoit plus la vue par défaut des namespaces isolés.

C’est pourquoi les revues des namespaces ne doivent jamais s’arrêter à « le processus se trouve dans un namespace ». La question importante est de savoir si le namespace est privé au container, partagé avec des containers frères ou rejoint directement celui de l’hôte. Dans Kubernetes, la même idée apparaît avec des flags tels que `hostPID`, `hostNetwork` et `hostIPC`. Les noms changent selon les plateformes, mais le modèle de risque reste le même : un namespace partagé avec l’hôte rend les privilèges restants du container et l’état de l’hôte qui lui est accessible beaucoup plus significatifs.

## Inspection

La vue d’ensemble la plus simple est :
```bash
ls -l /proc/self/ns
```
Chaque entrée est un lien symbolique avec un identifiant semblable à un inode. Si deux processus pointent vers le même identifiant d’espace de noms, ils se trouvent dans le même espace de noms de ce type. Cela fait de `/proc` un emplacement très utile pour comparer le processus actuel à d’autres processus intéressants sur la machine.

Ces commandes rapides suffisent souvent pour commencer :
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
À partir de là, l’étape suivante consiste à comparer le processus du conteneur avec les processus de l’hôte ou des conteneurs voisins, puis à déterminer si un namespace est réellement privé ou non.

### Énumération des instances de namespace depuis l’hôte

Lorsque vous disposez déjà d’un accès à l’hôte et que vous souhaitez déterminer combien de namespaces distincts d’un type donné existent, `/proc` fournit rapidement un inventaire :
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Si vous souhaitez déterminer quels processus appartiennent à un identifiant d'espace de noms spécifique, remplacez `readlink` par `ls -l` et utilisez `grep` pour rechercher le numéro de l'espace de noms cible :
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ces commandes sont utiles, car elles permettent de déterminer si un hôte exécute une seule workload isolée, plusieurs workloads isolées, ou un mélange d'instances de namespaces partagées et privées.

### Entrer dans le namespace d'une cible

Lorsque l'appelant dispose de privilèges suffisants, `nsenter` est la méthode standard pour rejoindre le namespace d'un autre processus :
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
Le but de regrouper ces formes n’est pas que chaque assessment nécessite de toutes les utiliser, mais que le post-exploitation spécifique aux namespaces devient souvent beaucoup plus simple lorsque l’opérateur connaît la syntaxe d’entrée exacte au lieu de se souvenir uniquement de la forme applicable à tous les namespaces.

## Pages

Les pages suivantes expliquent chaque namespace plus en détail :

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

À mesure que vous les lisez, gardez deux idées à l’esprit. Premièrement, chaque namespace isole un seul type de vue. Deuxièmement, un namespace privé n’est utile que si le reste du modèle de privilèges permet encore à cette isolation de rester effective.

## Valeurs par défaut des runtimes

| Runtime / plateforme | Configuration des namespaces par défaut | Affaiblissement manuel courant |
| --- | --- | --- |
| Docker Engine | Nouveaux namespaces mount, PID, network, IPC et UTS par défaut ; les user namespaces sont disponibles, mais ne sont pas activés par défaut dans les configurations rootful standard | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nouveaux namespaces par défaut ; Podman rootless utilise automatiquement un user namespace ; les valeurs par défaut du cgroup namespace dépendent de la version des cgroups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Les Pods ne partagent **pas** les PID, le réseau ou l’IPC de l’hôte par défaut ; le réseau du Pod est privé au Pod, et non à chaque container individuel ; les user namespaces sont opt-in via `spec.hostUsers: false` sur les clusters pris en charge | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omission de l’opt-in du user namespace, paramètres de workload privileged |
| containerd / CRI-O sous Kubernetes | Suivent généralement les valeurs par défaut des Pods Kubernetes | identique à la ligne Kubernetes ; les spécifications CRI/OCI directes peuvent également demander des jonctions aux namespaces de l’hôte |

La principale règle de portabilité est simple : le **concept** de partage des namespaces de l’hôte est commun aux runtimes, mais la **syntaxe** est spécifique à chaque runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
