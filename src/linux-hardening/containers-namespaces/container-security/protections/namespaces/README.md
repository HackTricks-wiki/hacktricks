# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Les namespaces sont une fonctionnalité du kernel qui donne l'impression qu'un container est « sa propre machine », alors qu'il ne s'agit en réalité que d'une simple arborescence de processus sur l'hôte. Ils ne créent pas de nouveau kernel et ne virtualisent pas tout, mais ils permettent au kernel de présenter différentes vues de certaines ressources à différents groupes de processus. C'est le cœur de l'illusion du container : la charge de travail voit un système de fichiers, une table des processus, une pile réseau, un hostname, des ressources IPC et un modèle d'identité utilisateur/groupe qui semblent locaux, même si le système sous-jacent est partagé.

C'est pourquoi les namespaces sont le premier concept que la plupart des personnes découvrent lorsqu'elles apprennent le fonctionnement des containers. En même temps, ils font partie des concepts les plus souvent mal compris, car les lecteurs supposent souvent que « disposer de namespaces » signifie « être isolé de manière sécurisée ». En réalité, un namespace n'isole que la classe spécifique de ressources pour laquelle il a été conçu. Un processus peut disposer d'un namespace PID privé et rester dangereux parce qu'il possède un bind mount hôte accessible en écriture. Il peut disposer d'un namespace réseau privé et rester dangereux parce qu'il conserve `CAP_SYS_ADMIN` et s'exécute sans seccomp. Les namespaces sont fondamentaux, mais ils ne constituent qu'une seule couche de la boundary finale.

## Types de namespaces

Les containers Linux s'appuient généralement sur plusieurs types de namespaces en même temps. Le **mount namespace** fournit au processus une table de montages distincte et donc une vue contrôlée du système de fichiers. Le **PID namespace** modifie la visibilité et la numérotation des processus afin que la charge de travail voie sa propre arborescence de processus. Le **network namespace** isole les interfaces, les routes, les sockets et l'état du firewall. Le **IPC namespace** isole l'IPC SysV et les files de messages POSIX. Le **UTS namespace** isole le hostname et le nom de domaine NIS. Le **user namespace** remappe les identifiants utilisateur et groupe afin que root dans le container ne signifie pas nécessairement root sur l'hôte. Le **cgroup namespace** virtualise la hiérarchie cgroup visible, et le **time namespace** virtualise certaines horloges dans les kernels plus récents.

Chacun de ces namespaces résout un problème différent. C'est pourquoi l'analyse pratique de la sécurité des containers consiste souvent à vérifier **quels namespaces sont isolés** et **lesquels ont été délibérément partagés avec l'hôte**.

## Partage des namespaces de l'hôte

De nombreux container breakouts ne commencent pas par une vulnérabilité du kernel. Ils commencent par un opérateur qui affaiblit délibérément le modèle d'isolation. Les exemples `--pid=host`, `--network=host` et `--userns=host` sont des **flags CLI de type Docker/Podman** utilisés ici comme exemples concrets de partage de namespaces de l'hôte. D'autres runtimes expriment la même idée différemment. Dans Kubernetes, les équivalents apparaissent généralement sous forme de paramètres du Pod tels que `hostPID: true`, `hostNetwork: true` ou `hostIPC: true`. Dans les stacks de runtime de plus bas niveau comme containerd ou CRI-O, le même comportement est souvent obtenu via la configuration runtime OCI générée plutôt qu'au moyen d'un flag destiné à l'utilisateur et portant le même nom. Dans tous ces cas, le résultat est similaire : la charge de travail ne reçoit plus la vue par défaut des namespaces isolés.

C'est pourquoi les audits des namespaces ne doivent jamais s'arrêter à « le processus se trouve dans un namespace ». La question importante est de savoir si le namespace est privé au container, partagé avec des containers frères ou rejoint directement celui de l'hôte. Dans Kubernetes, la même idée apparaît avec des flags tels que `hostPID`, `hostNetwork` et `hostIPC`. Les noms changent selon les plateformes, mais le risk pattern reste le même : un namespace hôte partagé rend les privilèges restants du container et l'état de l'hôte auquel il peut accéder beaucoup plus significatifs.

## Inspection

L'aperçu le plus simple est le suivant :
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
À partir de là, l’étape suivante consiste à comparer le processus du container avec les processus du host ou des containers voisins, puis à déterminer si un namespace est réellement privé ou non.

### Énumération des instances de namespace depuis le host

Lorsque vous avez déjà accès au host et que vous souhaitez comprendre combien de namespaces distincts d’un type donné existent, `/proc` fournit rapidement un inventaire :
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
Si vous souhaitez déterminer quels processus appartiennent à un identifiant de namespace spécifique, remplacez `readlink` par `ls -l` et utilisez grep pour rechercher le numéro du namespace cible :
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ces commandes sont utiles, car elles permettent de déterminer si un hôte exécute une charge de travail isolée, plusieurs charges de travail isolées, ou un mélange d’instances de namespace partagées et privées.

### Entrer dans un namespace cible

Lorsque l’appelant dispose de privilèges suffisants, `nsenter` est la méthode standard pour rejoindre le namespace d’un autre processus :
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
Le but de regrouper ces formes n’est pas que chaque assessment ait besoin de toutes, mais que le post-exploitation spécifique aux namespaces devient souvent beaucoup plus simple une fois que l’opérateur connaît la syntaxe d’entrée exacte, au lieu de se souvenir uniquement de la forme all-namespaces.

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

À mesure que vous les lisez, gardez deux idées à l’esprit. Premièrement, chaque namespace n’isole qu’un seul type de vue. Deuxièmement, un namespace privé n’est utile que si le reste du modèle de privilèges permet toujours à cette isolation de rester effective.

## Valeurs par défaut des runtimes

| Runtime / plateforme | Configuration par défaut des namespaces | Affaiblissement manuel courant |
| --- | --- | --- |
| Docker Engine | Nouveaux namespaces mount, PID, network, IPC et UTS par défaut ; les user namespaces sont disponibles, mais ne sont pas activés par défaut dans les configurations rootful standard | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nouveaux namespaces par défaut ; Podman rootless utilise automatiquement un user namespace ; les valeurs par défaut du cgroup namespace dépendent de la version de cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Les Pods ne partagent **pas** les PID, le network ou l’IPC de l’hôte par défaut ; le networking d’un Pod est privé au Pod, et non à chaque container individuel ; les user namespaces sont opt-in via `spec.hostUsers: false` sur les clusters compatibles | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omission de l’opt-in des user namespaces, paramètres de workload privileged |
| containerd / CRI-O sous Kubernetes | Suivent généralement les valeurs par défaut des Pods Kubernetes | identique à la ligne Kubernetes ; les spécifications CRI/OCI directes peuvent également demander des jonctions aux namespaces de l’hôte |

La principale règle de portabilité est simple : le **concept** de partage des namespaces de l’hôte est commun aux runtimes, mais la **syntaxe** dépend du runtime.

{{#include ../../../../../banners/hacktricks-training.md}}
