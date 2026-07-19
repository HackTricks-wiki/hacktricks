# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d’ensemble

**seccomp** est le mécanisme qui permet au kernel d’appliquer un filtre aux syscalls qu’un processus peut invoquer. Dans les environnements conteneurisés, seccomp est normalement utilisé en mode filtre afin que le processus ne soit pas simplement marqué comme « restreint » de manière vague, mais qu’il soit soumis à une policy concrète concernant les syscalls. Cela est important, car de nombreux container breakouts nécessitent d’atteindre des interfaces très spécifiques du kernel. Si le processus ne peut pas invoquer correctement les syscalls concernés, une grande catégorie d’attaques disparaît avant même que les subtilités liées aux namespaces ou aux capabilities n’entrent en jeu.

Le modèle mental essentiel est simple : les namespaces déterminent **ce que le processus peut voir**, les capabilities déterminent **quelles actions privilégiées le processus est théoriquement autorisé à tenter**, et seccomp détermine **si le kernel acceptera seulement le point d’entrée du syscall correspondant à l’action tentée**. C’est pourquoi seccomp empêche fréquemment des attaques qui sembleraient autrement possibles en se basant uniquement sur les capabilities.

## Impact sur la sécurité

Une grande partie de la surface dangereuse du kernel n’est accessible qu’au moyen d’un ensemble relativement restreint de syscalls. Parmi les exemples qui reviennent régulièrement dans le hardening des conteneurs figurent `mount`, `unshare`, `clone` ou `clone3` avec certains flags, `bpf`, `ptrace`, `keyctl` et `perf_event_open`. Un attaquant capable d’atteindre ces syscalls peut être en mesure de créer de nouveaux namespaces, de manipuler des sous-systèmes du kernel ou d’interagir avec une attack surface dont un conteneur d’application normal n’a absolument pas besoin.

C’est pourquoi les profiles seccomp par défaut des runtimes sont si importants. Ils ne constituent pas simplement une « défense supplémentaire ». Dans de nombreux environnements, ils font la différence entre un conteneur capable d’exercer une grande partie des fonctionnalités du kernel et un conteneur limité à une surface de syscalls plus proche de ce dont l’application a réellement besoin.

## Modes et construction des filtres

seccomp disposait historiquement d’un mode strict dans lequel seul un très petit ensemble de syscalls restait disponible, mais le mode pertinent pour les runtimes de conteneurs modernes est le mode filtre seccomp, souvent appelé **seccomp-bpf**. Dans ce modèle, le kernel évalue un programme de filtrage qui décide si un syscall doit être autorisé, refusé avec un errno, intercepté, journalisé ou entraîner l’arrêt du processus. Les runtimes de conteneurs utilisent ce mécanisme, car il est suffisamment expressif pour bloquer de larges catégories de syscalls dangereux tout en permettant le fonctionnement normal des applications.

Deux exemples de bas niveau sont utiles, car ils rendent le mécanisme concret plutôt que magique. Le mode strict illustre l’ancien modèle selon lequel « seul un ensemble minimal de syscalls subsiste » :
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
Le dernier appel à `open` entraîne la terminaison du processus, car il ne fait pas partie de l’ensemble minimal du strict mode.

Un exemple de filtre libseccomp illustre plus clairement le modèle de politiques moderne :
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
C’est ce style de policy que la plupart des lecteurs devraient avoir en tête lorsqu’ils pensent aux profils seccomp d’exécution.

## Labo

Une manière simple de confirmer que seccomp est actif dans un container est la suivante :
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Vous pouvez également essayer une opération que les profils par défaut restreignent généralement :
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Si le conteneur s’exécute sous un profil seccomp par défaut normal, les opérations de type `unshare` sont souvent bloquées. C’est une démonstration utile, car elle montre que même si l’outil userspace existe dans l’image, le chemin du kernel dont il a besoin peut tout de même être indisponible.
Si le conteneur s’exécute sous un profil seccomp par défaut normal, les opérations de type `unshare` sont souvent bloquées, même lorsque l’outil userspace existe dans l’image.

Pour inspecter plus généralement l’état du processus, exécutez :
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Utilisation à l’exécution

Docker prend en charge les profils seccomp par défaut et personnalisés, et permet aux administrateurs de les désactiver avec `--security-opt seccomp=unconfined`. Podman offre une prise en charge similaire et associe souvent seccomp à une exécution rootless, avec une configuration par défaut très pertinente. Kubernetes expose seccomp via la configuration des workloads, où `RuntimeDefault` constitue généralement une base saine et où `Unconfined` doit être traité comme une exception nécessitant une justification, plutôt que comme une simple option de commodité.

Dans les environnements basés sur containerd et CRI-O, le chemin exact comporte davantage de niveaux, mais le principe reste le même : le moteur ou l’orchestrateur de niveau supérieur décide de ce qui doit se produire, puis le runtime installe finalement la policy seccomp résultante pour le processus du conteneur. Le résultat dépend toujours de la configuration finale du runtime transmise au kernel.

### Exemple de policy personnalisée

Docker et les moteurs similaires peuvent charger un profil seccomp personnalisé au format JSON. Voici un exemple minimal qui refuse `chmod` tout en autorisant le reste :
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
La commande échoue avec `Operation not permitted`, ce qui démontre que la restriction provient de la syscall policy plutôt que des seules permissions de fichiers ordinaires. Dans un hardening réel, les allowlists sont généralement plus robustes que des valeurs par défaut permissives accompagnées d'une petite blacklist.

## Misconfigurations

L'erreur la plus grossière consiste à définir seccomp sur **unconfined** parce qu'une application a échoué avec la policy par défaut. C'est courant lors du troubleshooting et très dangereux comme solution permanente. Une fois le filtre supprimé, de nombreux primitives de breakout basées sur les syscalls redeviennent accessibles, en particulier lorsque de puissantes capabilities ou un partage des namespaces de l'hôte sont également présents.

Un autre problème fréquent est l'utilisation d'un **custom permissive profile** copié depuis un blog ou une solution de contournement interne sans avoir été soigneusement reviewé. Les équipes conservent parfois presque tous les syscalls dangereux simplement parce que le profile a été conçu autour de « empêcher l'application de casser » plutôt que de « n'accorder que ce dont l'application a réellement besoin ». Une troisième idée fausse consiste à supposer que seccomp est moins important pour les containers non-root. En réalité, une grande partie de la surface d'attaque du kernel reste pertinente même lorsque le processus n'est pas UID 0.

## Abuse

Si seccomp est absent ou fortement affaibli, un attaquant peut être capable d'invoquer des syscalls de création de namespaces, d'étendre la surface d'attaque du kernel accessible via `bpf` ou `perf_event_open`, d'abuser de `keyctl`, ou de combiner ces chemins de syscalls avec des capabilities dangereuses telles que `CAP_SYS_ADMIN`. Dans de nombreuses attaques réelles, seccomp n'est pas le seul contrôle manquant, mais son absence raccourcit considérablement le chemin d'exploitation, car elle supprime l'une des rares défenses capables de bloquer un syscall risqué avant même que le reste du modèle de privilèges n'entre en jeu.

Le test pratique le plus utile consiste à essayer les familles exactes de syscalls que les profiles par défaut bloquent généralement. S'ils fonctionnent soudainement, la posture de sécurité du container a beaucoup changé :
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Si `CAP_SYS_ADMIN` ou une autre capacité puissante est présente, vérifiez si seccomp est la seule barrière manquante avant un abus via `mount` :
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Sur certaines cibles, l’objectif immédiat n’est pas le full escape, mais la collecte d’informations et l’élargissement de la surface d’attaque du kernel. Ces commandes permettent de déterminer si des chemins d’appels système particulièrement sensibles sont accessibles :
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Si seccomp est absent et que le container est également privilégié d’autres manières, c’est à ce moment qu’il est pertinent de passer aux techniques d’évasion plus spécifiques déjà documentées dans les anciennes pages sur les container escapes.

### Exemple complet : seccomp était le seul élément qui bloquait `unshare`

Sur de nombreuses cibles, l’effet pratique de la suppression de seccomp est que les syscalls de création de namespaces ou de montage commencent soudainement à fonctionner. Si le container dispose également de `CAP_SYS_ADMIN`, la séquence suivante peut devenir possible :
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

Si seccomp est désactivé et que le conteneur peut monter des hiérarchies cgroup v1, la technique `release_agent` de la section cgroups devient accessible :
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
Ce n’est pas un exploit limité à seccomp. Le point est qu’une fois seccomp non restreint, les chaînes de breakout gourmandes en syscalls qui étaient auparavant bloquées peuvent commencer à fonctionner exactement comme elles sont écrites.

## Vérifications

L’objectif de ces vérifications est de déterminer si seccomp est actif, si `no_new_privs` l’accompagne, et si la configuration du runtime indique que seccomp est explicitement désactivé.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Ce qui est intéressant ici :

- Une valeur `Seccomp` non nulle signifie qu'un filtrage est actif ; `0` signifie généralement qu'aucune protection seccomp n'est activée.
- Si les options de sécurité du runtime incluent `seccomp=unconfined`, le workload a perdu l'une de ses défenses les plus utiles au niveau des syscalls.
- `NoNewPrivs` n'est pas seccomp en lui-même, mais la présence des deux indique généralement une posture de hardening plus rigoureuse que l'absence des deux.

Si un container possède déjà des mounts suspects, des capabilities étendues ou des namespaces de l'hôte partagés, et que seccomp est également unconfined, cette combinaison doit être considérée comme un signal majeur d'escalade. Le container n'est peut-être toujours pas trivialement exploitable, mais le nombre de points d'entrée du kernel disponibles pour l'attaquant a fortement augmenté.

## Defaults du runtime

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Généralement activé par défaut | Utilise le profil seccomp par défaut intégré de Docker, sauf s'il est remplacé | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Généralement activé par défaut | Applique le profil seccomp par défaut du runtime, sauf s'il est remplacé | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Non garanti par défaut** | Si `securityContext.seccompProfile` n'est pas défini, la valeur par défaut est `Unconfined`, sauf si le kubelet active `--seccomp-default` ; `RuntimeDefault` ou `Localhost` doivent sinon être définis explicitement | `securityContext.seccompProfile.type: Unconfined`, laisser seccomp non défini sur les clusters sans `seccompDefault`, `privileged: true` |
| containerd / CRI-O sous Kubernetes | Suit les paramètres du nœud et du Pod Kubernetes | Le profil du runtime est utilisé lorsque Kubernetes demande `RuntimeDefault` ou lorsque le defaulting seccomp du kubelet est activé | Même comportement que la ligne Kubernetes ; la configuration directe CRI/OCI peut également omettre complètement seccomp |

Le comportement de Kubernetes est celui qui surprend le plus souvent les opérateurs. Dans de nombreux clusters, seccomp reste désactivé tant que le Pod ne le demande pas ou que le kubelet n'est pas configuré pour utiliser `RuntimeDefault` par défaut.
{{#include ../../../../banners/hacktricks-training.md}}
