# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

**seccomp** est le mécanisme qui permet au kernel d'appliquer un filtre aux syscalls qu'un processus peut invoquer. Dans les environnements containerisés, seccomp est normalement utilisé en mode filtre afin que le processus ne soit pas simplement marqué comme « restreint » de manière vague, mais soit soumis à une politique concrète concernant les syscalls. Cela est important, car de nombreux container breakouts nécessitent d'atteindre des interfaces très spécifiques du kernel. Si le processus ne peut pas invoquer avec succès les syscalls concernés, une grande catégorie d'attaques disparaît avant même que les subtilités liées aux namespaces ou aux capabilities n'entrent en jeu.

Le modèle mental clé est simple : les namespaces déterminent **ce que le processus peut voir**, les capabilities déterminent **quelles actions privilégiées le processus est théoriquement autorisé à tenter**, et seccomp détermine **si le kernel acceptera seulement le point d'entrée du syscall correspondant à l'action tentée**. C'est pourquoi seccomp empêche fréquemment des attaques qui sembleraient autrement possibles en se basant uniquement sur les capabilities.

## Impact sur la sécurité

Une grande partie de la surface d'attaque dangereuse du kernel n'est accessible qu'au moyen d'un ensemble relativement restreint de syscalls. Parmi les exemples qui reviennent régulièrement dans le hardening des containers figurent `mount`, `unshare`, `clone` ou `clone3` avec certains flags, `bpf`, `ptrace`, `keyctl` et `perf_event_open`. Un attaquant capable d'atteindre ces syscalls peut être en mesure de créer de nouveaux namespaces, de manipuler des sous-systèmes du kernel ou d'interagir avec une surface d'attaque dont un container applicatif normal n'a absolument pas besoin.

C'est pourquoi les profils seccomp par défaut des runtimes sont si importants. Ils ne constituent pas simplement une « défense supplémentaire ». Dans de nombreux environnements, ils font la différence entre un container capable d'exploiter une large partie des fonctionnalités du kernel et un container limité à une surface de syscalls plus proche de ce dont l'application a réellement besoin.

## Modes et construction des filtres

seccomp disposait historiquement d'un mode strict dans lequel seul un très petit ensemble de syscalls restait disponible, mais le mode pertinent pour les runtimes de containers modernes est le mode filtre de seccomp, souvent appelé **seccomp-bpf**. Dans ce modèle, le kernel évalue un programme de filtrage qui décide si un syscall doit être autorisé, refusé avec un errno, intercepté, journalisé ou s'il faut tuer le processus.<sup>[[1]](#references)</sup> Les runtimes de containers utilisent ce mécanisme, car il est suffisamment expressif pour bloquer de larges catégories de syscalls dangereux tout en autorisant le fonctionnement normal des applications.

Deux exemples de bas niveau sont utiles, car ils rendent le mécanisme concret plutôt que magique. Le mode strict illustre l'ancien modèle dans lequel « seul un ensemble minimal de syscalls subsiste » :
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
Le dernier `open` entraîne l'arrêt du processus, car il ne fait pas partie de l'ensemble minimal du strict mode.

Un exemple de filtre libseccomp montre plus clairement le modèle de policy moderne :
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Ce type de policy correspond à ce que la plupart des lecteurs devraient imaginer lorsqu’ils pensent aux profils seccomp runtime.

## Lab

Une manière simple de confirmer que seccomp est actif dans un container est la suivante :
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Vous pouvez également essayer une opération que les profils par défaut restreignent généralement :
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Si le container s’exécute sous un profil seccomp par défaut normal, les opérations de type `unshare` sont souvent bloquées. Il s’agit d’une démonstration utile, car elle montre que même si l’outil userspace existe dans l’image, le chemin du kernel dont il a besoin peut tout de même être indisponible.
Si le container s’exécute sous un profil seccomp par défaut normal, les opérations de type `unshare` sont souvent bloquées, même lorsque l’outil userspace existe dans l’image.

Pour inspecter plus généralement l’état du processus, exécutez :
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Utilisation au runtime

Docker prend en charge les profils seccomp par défaut et personnalisés, et permet aux administrateurs de les désactiver avec `--security-opt seccomp=unconfined`.<sup>[[2]](#references)</sup> Podman offre une prise en charge similaire et associe souvent seccomp à une exécution rootless, ce qui constitue une configuration par défaut très pertinente. Kubernetes expose seccomp via la configuration des workloads, où `RuntimeDefault` constitue généralement une base saine et où `Unconfined` doit être considéré comme une exception nécessitant une justification, plutôt que comme une simple option de commodité.<sup>[[3]](#references)</sup>

Dans les environnements basés sur containerd et CRI-O, le chemin exact est plus complexe, mais le principe reste le même : le moteur ou l'orchestrateur de niveau supérieur décide de ce qui doit se produire, puis le runtime installe finalement la policy seccomp résultante pour le processus du container. Le résultat dépend toujours de la configuration finale du runtime transmise au kernel.

### Exemple de policy personnalisée

Docker et les moteurs similaires peuvent charger un profil seccomp personnalisé au format JSON. Voici un exemple minimal qui refuse `chmod` tout en autorisant toutes les autres opérations :
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Appliqué avec :
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
La commande échoue avec `Operation not permitted`, ce qui démontre que la restriction provient de la syscall policy plutôt que des seules permissions ordinaires sur les fichiers. En matière de hardening réel, les allowlists sont généralement plus solides que des valeurs par défaut permissives accompagnées d'une petite blacklist.

## Misconfigurations

L'erreur la plus grossière consiste à définir seccomp sur **unconfined** parce qu'une application a échoué avec la policy par défaut. C'est courant lors du troubleshooting et très dangereux comme correctif permanent. Une fois le filtre supprimé, de nombreux primitives de breakout basés sur des syscalls redeviennent accessibles, en particulier lorsque des capabilities puissantes ou le partage de namespaces de l'hôte sont également présents.

Un autre problème fréquent est l'utilisation d'un **custom permissive profile** copié depuis un blog ou une workaround interne, sans avoir été soigneusement vérifié. Les équipes conservent parfois presque tous les syscalls dangereux simplement parce que le profile a été conçu autour de « empêcher l'application de casser » plutôt que de « n'accorder que ce dont l'application a réellement besoin ». Une troisième idée reçue consiste à supposer que seccomp est moins important pour les containers non-root. En réalité, une grande partie de la surface d'attaque du kernel reste pertinente même lorsque le processus n'est pas UID 0.

## Abuse

Si seccomp est absent ou fortement affaibli, un attacker peut être capable d'invoquer des syscalls de création de namespaces, d'étendre la surface d'attaque du kernel accessible via `bpf` ou `perf_event_open`, d'abuser de `keyctl`, ou de combiner ces chemins de syscalls avec des capabilities dangereuses telles que `CAP_SYS_ADMIN`. Dans de nombreuses attaques réelles, seccomp n'est pas le seul contrôle manquant, mais son absence raccourcit considérablement le chemin d'exploitation, car elle supprime l'une des rares défenses capables de bloquer un syscall risqué avant même que le reste du modèle de privilege n'entre en jeu.

Le test pratique le plus utile consiste à essayer les familles exactes de syscalls que les profiles par défaut bloquent généralement. Si elles fonctionnent soudainement, la posture de sécurité du container a fortement changé :
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Si `CAP_SYS_ADMIN` ou une autre capability puissante est présente, vérifiez si seccomp est la seule barrière manquante avant un abuse basé sur mount :
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Sur certaines cibles, l’objectif immédiat n’est pas une full escape, mais la collecte d’informations et l’élargissement de la surface d’attaque du kernel. Ces commandes permettent de déterminer si des chemins de syscalls particulièrement sensibles sont accessibles :
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Si seccomp est absent et que le container est également privilégié à d'autres égards, c'est à ce moment qu'il est pertinent de passer aux techniques d'évasion plus spécifiques déjà documentées dans les pages legacy sur l'évasion des containers.

### Exemple complet : seccomp était le seul élément qui bloquait `unshare`

Sur de nombreuses cibles, l'effet pratique de la suppression de seccomp est que les appels système de création de namespaces ou de montage commencent soudainement à fonctionner. Si le container possède également `CAP_SYS_ADMIN`, la séquence suivante peut devenir possible :
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
À lui seul, ce n'est pas encore un host escape, mais cela démontre que seccomp était la barrière empêchant l'exploitation liée aux mounts.

### Exemple complet : seccomp désactivé + `release_agent` de cgroup v1

Si seccomp est désactivé et que le container peut monter des hiérarchies cgroup v1, la technique `release_agent` de la section sur les cgroups devient accessible :
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Ce n’est pas un exploit limité à seccomp. Le point est qu’une fois que seccomp est en mode unconfined, les chaînes d’évasion nécessitant de nombreux syscalls, qui étaient auparavant bloquées, peuvent commencer à fonctionner exactement comme décrites.

## Vérifications

L’objectif de ces vérifications est de déterminer si seccomp est actif, si `no_new_privs` l’accompagne et si la configuration du runtime indique que seccomp est explicitement désactivé.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Ce qui est intéressant ici :

- Une valeur `Seccomp` non nulle signifie que le filtrage est actif ; `0` signifie généralement qu'aucune protection seccomp n'est active.
- Si les options de sécurité du runtime incluent `seccomp=unconfined`, le workload a perdu l'une de ses défenses les plus utiles au niveau des syscall.
- `NoNewPrivs` n'est pas seccomp en soi, mais la présence des deux indique généralement une posture de hardening plus rigoureuse que l'absence des deux.

Si un container possède déjà des mounts suspects, des capabilities étendues ou des namespaces partagés avec l'hôte, et que seccomp est également en mode unconfined, cette combinaison doit être considérée comme un signal majeur d'escalade. Le container n'est peut-être toujours pas trivialement exploitable, mais le nombre de points d'entrée du kernel accessibles à l'attaquant a fortement augmenté.

## Defaults du runtime

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Généralement activé par défaut | Utilise le profil seccomp par défaut intégré de Docker, sauf remplacement | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Généralement activé par défaut | Applique le profil seccomp par défaut du runtime, sauf remplacement | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Non garanti par défaut** | Si `securityContext.seccompProfile` n'est pas défini, le default est `Unconfined`, sauf si le kubelet active `--seccomp-default` ; `RuntimeDefault` ou `Localhost` doivent sinon être définis explicitement | `securityContext.seccompProfile.type: Unconfined`, laisser seccomp non défini sur les clusters sans `seccompDefault`, `privileged: true` |
| containerd / CRI-O sous Kubernetes | Suit les paramètres du nœud et du Pod Kubernetes | Le profil du runtime est utilisé lorsque Kubernetes demande `RuntimeDefault` ou lorsque le default seccomp du kubelet est activé | Identique à la ligne Kubernetes ; la configuration directe CRI/OCI peut également omettre complètement seccomp |

Le comportement de Kubernetes est celui qui surprend le plus souvent les opérateurs. Dans de nombreux clusters, seccomp reste absent tant que le Pod ne le demande pas ou que le kubelet n'est pas configuré pour utiliser `RuntimeDefault` par défaut.<sup>[[3]](#references)</sup>

## Références

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
