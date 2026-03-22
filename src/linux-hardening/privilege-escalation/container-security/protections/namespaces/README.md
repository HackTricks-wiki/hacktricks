# Espaces de noms

{{#include ../../../../../banners/hacktricks-training.md}}

Les namespaces sont la fonctionnalité du kernel qui donne l'impression qu'un conteneur est "sa propre machine" alors qu'il n'est en réalité qu'un arbre de processus de l'hôte. Ils ne créent pas un nouveau kernel et ils ne virtualisent pas tout, mais ils permettent au kernel de présenter des vues différentes de ressources sélectionnées à différents groupes de processus. C'est le cœur de l'illusion du conteneur : la charge de travail voit un système de fichiers, une table des processus, une pile réseau, un hostname, des ressources IPC et un modèle d'identité utilisateur/groupe qui semblent locaux, même si le système sous-jacent est partagé.

C'est pourquoi les espaces de noms sont le premier concept que la plupart des gens rencontrent quand ils apprennent le fonctionnement des conteneurs. En même temps, ils font partie des concepts les plus souvent mal compris parce que les lecteurs supposent souvent que "a des namespaces" signifie "est correctement isolé". En réalité, un espace de noms n'isole que la catégorie spécifique de ressources pour laquelle il a été conçu. Un processus peut avoir un espace de noms PID privé et rester dangereux parce qu'il a un bind mount host en écriture. Il peut avoir un espace de noms réseau privé et rester dangereux parce qu'il conserve `CAP_SYS_ADMIN` et s'exécute sans seccomp. Les namespaces sont fondamentaux, mais ils ne constituent qu'une couche dans la frontière finale.

## Types d'espaces de noms

Les conteneurs Linux reposent couramment sur plusieurs types d'espaces de noms en même temps. L'**espace de noms de montage** donne au processus une table de montage séparée et donc une vue contrôlée du système de fichiers. L'**espace de noms PID** change la visibilité et la numérotation des processus pour que la charge de travail voie son propre arbre de processus. L'**espace de noms réseau** isole les interfaces, routes, sockets et l'état du pare-feu. L'**espace de noms IPC** isole SysV IPC et les files de messages POSIX. L'**espace de noms UTS** isole le hostname et le NIS domain name. L'**espace de noms utilisateur** remappe les IDs utilisateur et groupe de sorte que root à l'intérieur du conteneur ne signifie pas forcément root sur l'hôte. L'**espace de noms cgroup** virtualise la hiérarchie de cgroup visible, et l'**espace de noms time** virtualise des horloges sélectionnées dans les kernels plus récents.

Chacun de ces espaces de noms résout un problème différent. C'est pourquoi l'analyse pratique de la sécurité des conteneurs revient souvent à vérifier **quels espaces de noms sont isolés** et **lesquels ont été délibérément partagés avec l'hôte**.

## Partage d'espaces de noms avec l'hôte

Beaucoup d'évasions de conteneur ne commencent pas par une vulnérabilité du kernel. Elles commencent par un opérateur qui affaiblit délibérément le modèle d'isolation. Les exemples `--pid=host`, `--network=host` et `--userns=host` sont des **options CLI de style Docker/Podman** utilisées ici comme exemples concrets de partage d'espaces de noms avec l'hôte. D'autres runtimes expriment la même idée différemment. Dans Kubernetes, les équivalents apparaissent généralement comme des paramètres de Pod tels que `hostPID: true`, `hostNetwork: true`, ou `hostIPC: true`. Dans des piles runtime de bas niveau comme containerd ou CRI-O, le même comportement est souvent atteint via la configuration OCI runtime générée plutôt que via un flag utilisateur du même nom. Dans tous ces cas, le résultat est similaire : la charge de travail ne reçoit plus la vue par défaut d'un espace de noms isolé.

C'est pourquoi les revues d'espaces de noms ne doivent jamais s'arrêter à "le processus est dans un certain espace de noms". La question importante est de savoir si l'espace de noms est privé au conteneur, partagé avec des conteneurs frères, ou directement rejoint à l'hôte. Dans Kubernetes, la même idée apparaît avec des flags tels que `hostPID`, `hostNetwork` et `hostIPC`. Les noms changent selon les plateformes, mais le modèle de risque est le même : un espace de noms partagé avec l'hôte rend les privilèges restants du conteneur et l'état de l'hôte accessible beaucoup plus significatifs.

## Inspection

Le survol le plus simple est :
```bash
ls -l /proc/self/ns
```
Chaque entrée est un lien symbolique avec un identifiant de type inode. Si deux processus pointent vers le même identifiant de namespace, ils appartiennent au même namespace de ce type. Cela fait de `/proc` un endroit très utile pour comparer le processus courant avec d'autres processus intéressants sur la machine.

Ces commandes rapides suffisent souvent pour commencer :
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
À partir de là, l'étape suivante consiste à comparer le processus du conteneur avec les processus de l'hôte ou des processus voisins et à déterminer si un namespace est réellement privé ou non.

### Énumération des instances de namespace depuis l'hôte

Lorsque vous avez déjà un accès à l'hôte et que vous souhaitez savoir combien d'instances distinctes d'un type de namespace existent, `/proc` fournit un inventaire rapide :
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
Si vous voulez trouver quels processus appartiennent à un identifiant de namespace spécifique, passez de `readlink` à `ls -l` et utilisez `grep` pour le numéro de namespace cible :
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ces commandes sont utiles car elles vous permettent de déterminer si un hôte exécute une seule workload isolée, plusieurs workloads isolés, ou un mélange d'instances avec des namespaces partagés et privés.

### Entrer dans un namespace cible

Lorsque l'appelant dispose des privilèges suffisants, `nsenter` est la méthode standard pour rejoindre le namespace d'un autre processus :
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
Le but de lister ces formes ensemble n'est pas que chaque évaluation en nécessite toutes, mais que la post-exploitation spécifique aux namespaces devient souvent beaucoup plus facile une fois que l'opérateur connaît la syntaxe d'entrée exacte au lieu de se souvenir uniquement de la forme all-namespaces.

## Pages

Les pages suivantes expliquent chaque namespace en détail :

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

En les lisant, gardez deux idées en tête. Premièrement, chaque namespace isole uniquement un type de vue. Deuxièmement, un namespace privé n'est utile que si le reste du modèle de privilèges rend toujours cette isolation significative.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

The main portability rule is simple: the **concept** of host namespace sharing is common across runtimes, but the **syntax** is runtime-specific.
{{#include ../../../../../banners/hacktricks-training.md}}
