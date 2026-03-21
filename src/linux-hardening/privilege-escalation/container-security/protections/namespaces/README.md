# Espaces de noms

{{#include ../../../../../banners/hacktricks-training.md}}

Les namespaces sont une fonctionnalité du noyau qui fait qu'un conteneur donne l'impression d'être "sa propre machine" alors qu'il s'agit en réalité d'un simple arbre de processus de l'hôte. Ils ne créent pas un nouveau noyau et ne virtualisent pas tout, mais ils permettent au noyau de présenter des vues différentes de ressources sélectionnées à différents groupes de processus. C'est le cœur de l'illusion du conteneur : la charge de travail voit un système de fichiers, une table des processus, une pile réseau, un nom d'hôte, des ressources IPC et un modèle d'identité utilisateur/groupe qui semblent locaux, même si le système sous-jacent est partagé.

C'est pourquoi les namespaces sont le premier concept que la plupart des gens rencontrent lorsqu'ils apprennent comment fonctionnent les conteneurs. En même temps, ce sont l'un des concepts les plus souvent mal compris, car les lecteurs supposent souvent que "has namespaces" signifie "est correctement isolé". En réalité, un namespace n'isole que la classe spécifique de ressources pour laquelle il a été conçu. Un processus peut avoir un PID namespace privé et rester dangereux parce qu'il a un bind mount hôte en écriture. Il peut avoir un network namespace privé et rester dangereux parce qu'il conserve `CAP_SYS_ADMIN` et s'exécute sans seccomp. Les namespaces sont fondamentaux, mais ils ne constituent qu'une couche dans la frontière finale.

## Namespace Types

Linux containers s'appuient couramment sur plusieurs types de namespaces en même temps. Le **mount namespace** donne au processus une table de montages séparée et donc une vue contrôlée du système de fichiers. Le **PID namespace** modifie la visibilité et la numérotation des processus afin que la charge de travail voie son propre arbre de processus. Le **network namespace** isole les interfaces, les routes, les sockets et l'état du pare-feu. Le **IPC namespace** isole SysV IPC et les files de messages POSIX. Le **UTS namespace** isole le nom d'hôte et le nom de domaine NIS. Le **user namespace** remappe les UID et GID afin que root à l'intérieur du conteneur ne signifie pas nécessairement root sur l'hôte. Le **cgroup namespace** virtualise la hiérarchie de cgroups visible, et le **time namespace** virtualise certaines horloges dans les noyaux plus récents.

Chacun de ces namespaces résout un problème différent. C'est pourquoi l'analyse pratique de la sécurité des conteneurs consiste souvent à vérifier **quels namespaces sont isolés** et **lesquels ont été délibérément partagés avec l'hôte**.

## Host Namespace Sharing

De nombreuses évasions de conteneur ne commencent pas par une vulnérabilité du noyau. Elles commencent par un opérateur affaiblissant délibérément le modèle d'isolation. Les exemples `--pid=host`, `--network=host` et `--userns=host` sont des **Docker/Podman-style CLI flags** utilisés ici comme exemples concrets de partage de namespace avec l'hôte. D'autres runtimes expriment la même idée différemment. Dans Kubernetes, les équivalents apparaissent généralement comme des paramètres de Pod tels que `hostPID: true`, `hostNetwork: true` ou `hostIPC: true`. Dans des piles runtime de plus bas niveau comme containerd ou CRI-O, le même comportement est souvent obtenu via la configuration runtime OCI générée plutôt que par un flag orienté utilisateur du même nom. Dans tous ces cas, le résultat est similaire : la charge de travail ne reçoit plus la vue de namespace isolée par défaut.

C'est pourquoi les revues de namespaces ne doivent jamais s'arrêter à "le processus est dans un namespace quelconque". La question importante est de savoir si le namespace est privé au conteneur, partagé avec des conteneurs frères, ou rejoint directement à l'hôte. Dans Kubernetes, la même idée apparaît avec des flags tels que `hostPID`, `hostNetwork` et `hostIPC`. Les noms changent entre les plateformes, mais le pattern de risque est le même : un namespace partagé avec l'hôte rend les privilèges restants du conteneur et l'état hôte accessible beaucoup plus significatifs.

## Inspection

La vue d'ensemble la plus simple est :
```bash
ls -l /proc/self/ns
```
Chaque entrée est un lien symbolique avec un identifiant de type inode. Si deux processus pointent vers le même identifiant de namespace, ils se trouvent dans le même namespace de ce type. Cela fait de `/proc` un endroit très utile pour comparer le processus courant avec d'autres processus intéressants sur la machine.

Ces commandes rapides suffisent souvent pour commencer :
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
À partir de là, l'étape suivante consiste à comparer le container process avec les processus de l'host ou des processus voisins et à déterminer si un namespace est effectivement privé ou non.

### Énumération des instances de namespace depuis le host

Lorsque vous avez déjà un accès au host et que vous voulez comprendre combien de namespace distincts d'un type donné existent, `/proc` fournit un inventaire rapide :
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
Si vous voulez trouver quels processus appartiennent à un identifiant de namespace spécifique, passez de `readlink` à `ls -l` et faites un grep pour le numéro de namespace cible :
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ces commandes sont utiles parce qu'elles vous permettent de déterminer si un hôte exécute une seule charge de travail isolée, plusieurs charges de travail isolées, ou un mélange d'instances d'espaces de noms partagées et privées.

### Entrer dans un espace de noms cible

Lorsque le processus appelant dispose des privilèges suffisants, `nsenter` est la méthode standard pour rejoindre l'espace de noms d'un autre processus :
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
Le but de lister ces formes ensemble n'est pas que chaque évaluation nécessite toutes, mais que le post-exploitation spécifique aux namespaces devient souvent bien plus simple lorsque l'opérateur connaît la syntaxe d'entrée exacte au lieu de ne se souvenir que de la forme all-namespaces.

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

En les lisant, gardez deux idées en tête. Premièrement, chaque namespace isole seulement un type de vue. Deuxièmement, un namespace privé n'est utile que si le reste du modèle de privilèges rend toujours cette isolation pertinente.

## Runtime Defaults

| Runtime / platform | Posture par défaut des namespaces | Affaiblissements manuels courants |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

La règle de portabilité principale est simple : le **concept** de partage des namespaces de l'hôte est commun aux runtimes, mais la **syntax** est spécifique au runtime.
