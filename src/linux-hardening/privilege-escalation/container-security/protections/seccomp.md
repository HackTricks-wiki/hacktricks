# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Aperçu

**seccomp** est le mécanisme qui permet au noyau d'appliquer un filtre aux syscalls qu'un processus peut invoquer. Dans les environnements conteneurisés, seccomp est normalement utilisé en mode filtre de sorte que le processus n'est pas simplement marqué « restreint » de façon vague, mais est soumis à une politique de syscalls concrète. Cela a de l'importance parce que de nombreuses évasions de conteneur exigent d'atteindre des interfaces noyau très spécifiques. Si le processus ne peut pas invoquer avec succès les syscalls pertinents, une grande classe d'attaques disparaît avant même que toute nuance de namespaces ou de capabilities ne devienne pertinente.

Le modèle mental clé est simple : namespaces décident **ce que le processus peut voir**, capabilities décident **quelles actions privilégiées le processus est nominalement autorisé à tenter**, et seccomp décide **si le noyau acceptera même le point d'entrée syscall pour l'action tentée**. C'est pourquoi seccomp empêche fréquemment des attaques qui, basées uniquement sur les capabilities, sembleraient autrement possibles.

## Impact sur la sécurité

Une grande partie de la surface dangereuse du noyau n'est accessible que via un ensemble relativement restreint de syscalls. Des exemples qui reviennent souvent dans le hardening des conteneurs incluent `mount`, `unshare`, `clone` ou `clone3` avec certains flags, `bpf`, `ptrace`, `keyctl`, et `perf_event_open`. Un attaquant capable d'atteindre ces syscalls peut être en mesure de créer de nouveaux namespaces, de manipuler des sous-systèmes du noyau, ou d'interagir avec une surface d'attaque dont un conteneur applicatif normal n'a absolument pas besoin.

C'est pourquoi les profils seccomp par défaut du runtime sont si importants. Ils ne sont pas simplement une « défense supplémentaire ». Dans de nombreux environnements, ils font la différence entre un conteneur qui peut exploiter une large portion des fonctionnalités du noyau et un conteneur cantonné à une surface de syscalls plus proche de ce dont l'application a réellement besoin.

## Modes et construction des filtres

seccomp disposait historiquement d'un mode strict dans lequel seul un petit ensemble de syscalls restait disponible, mais le mode pertinent pour les runtimes modernes de conteneurs est le seccomp filter mode, souvent appelé seccomp-bpf. Dans ce modèle, le noyau évalue un programme de filtre qui décide si un syscall doit être autorisé, refusé avec un errno, trapped, journalisé, ou provoquer la terminaison du processus. Les runtimes de conteneurs utilisent ce mécanisme parce qu'il est suffisamment expressif pour bloquer de larges classes de syscalls dangereux tout en permettant le comportement normal des applications.

Deux exemples bas niveau sont utiles car ils rendent le mécanisme concret plutôt que magique. Le mode strict illustre l'ancien modèle « seule une surface minimale de syscalls survit » :
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
Le dernier `open` provoque la terminaison du processus car il ne fait pas partie de l'ensemble minimal du mode strict.

Un exemple de filtre libseccomp illustre le modèle de politique moderne plus clairement :
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
Ce style de politique est ce que la plupart des lecteurs devraient imaginer lorsqu'ils pensent aux runtime seccomp profiles.

## Laboratoire

Un moyen simple de confirmer que seccomp est actif dans un container est :
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Vous pouvez également essayer une opération que les profils par défaut restreignent couramment :
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Si le conteneur s'exécute sous un profil seccomp par défaut normal, les opérations de type `unshare` sont souvent bloquées. C'est une démonstration utile car elle montre que même si l'outil userspace existe à l'intérieur de l'image, le chemin du kernel dont il a besoin peut rester inaccessible.
Si le conteneur s'exécute sous un profil seccomp par défaut normal, les opérations de type `unshare` sont souvent bloquées même lorsque l'outil userspace existe à l'intérieur de l'image.

Pour inspecter l'état du processus de manière plus générale, exécutez :
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Utilisation à l'exécution

Docker prend en charge à la fois les profils seccomp par défaut et personnalisés et permet aux administrateurs de les désactiver avec `--security-opt seccomp=unconfined`. Podman offre un support similaire et associe souvent seccomp à l'exécution rootless dans une posture par défaut très sensée. Kubernetes expose seccomp via la configuration des workloads, où `RuntimeDefault` est généralement la base saine et `Unconfined` doit être traité comme une exception nécessitant une justification plutôt que comme un interrupteur de commodité.

Dans les environnements basés sur containerd et CRI-O, le chemin exact est plus en couches, mais le principe reste le même : le moteur ou l'orchestrateur de niveau supérieur décide de ce qui doit se produire, et le runtime finit par installer la politique seccomp résultante pour le processus du conteneur. Le résultat dépend toujours de la configuration finale du runtime qui atteint le kernel.

### Exemple de politique personnalisée

Docker et les moteurs similaires peuvent charger un profil seccomp personnalisé depuis du JSON. Un exemple minimal qui refuse `chmod` tout en autorisant tout le reste ressemble à ceci :
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
La commande échoue avec `Operation not permitted`, ce qui démontre que la restriction provient de la politique de syscall plutôt que des seules permissions de fichier. Dans un durcissement réel, les allowlists sont généralement plus strictes que des paramètres par défaut permissifs accompagnés d'une petite blacklist.

## Mauvaises configurations

La pire erreur est de régler seccomp sur **unconfined** parce qu'une application a échoué sous la politique par défaut. C'est courant lors du troubleshooting et très dangereux comme correctif permanent. Une fois le filtre supprimé, de nombreux breakout primitives basés sur des syscall redeviennent accessibles, en particulier lorsque des capabilities puissantes ou le partage de host namespace sont également présents.

Un autre problème fréquent est l'utilisation d'un **custom permissive profile** copié depuis un blog ou une solution interne sans revue approfondie. Les équipes conservent parfois presque tous les syscalls dangereux simplement parce que le profile a été conçu pour "empêcher l'application de planter" plutôt que pour "n'accorder que ce dont l'application a réellement besoin". Une troisième idée reçue est de supposer que seccomp est moins important pour les conteneurs non-root. En réalité, une grande partie de la surface d'attaque du noyau reste pertinente même lorsque le processus n'est pas UID 0.

## Abus

Si seccomp est absent ou fortement affaibli, un attaquant peut être capable d'invoquer des syscalls de création de namespace, d'étendre la surface d'attaque du noyau accessible via `bpf` ou `perf_event_open`, d'abuser de `keyctl`, ou de combiner ces chemins de syscall avec des capabilities dangereuses telles que `CAP_SYS_ADMIN`. Dans de nombreuses attaques réelles, seccomp n'est pas le seul contrôle manquant, mais son absence raccourcit considérablement le chemin d'exploitation parce qu'elle supprime l'une des rares défenses pouvant arrêter un syscall risqué avant que le reste du modèle de privilèges n'entre en jeu.

Le test pratique le plus utile est d'essayer précisément les familles de syscall que les profils par défaut bloquent habituellement. S'ils fonctionnent soudainement, la posture du conteneur a beaucoup changé :
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Si `CAP_SYS_ADMIN` ou une autre capability puissante est présente, testez si seccomp est la seule barrière manquante avant mount-based abuse :
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Sur certaines cibles, l'objectif immédiat n'est pas un full escape mais de l'information gathering et l'expansion de la kernel attack-surface. Ces commandes permettent de déterminer si des chemins de syscall particulièrement sensibles sont accessibles :
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Si seccomp est absent et que le container est également privilégié d'autres manières, c'est alors qu'il est pertinent de pivot into the more specific breakout techniques already documented in the legacy container-escape pages.

### Exemple complet : seccomp était la seule chose bloquant `unshare`

Sur de nombreuses cibles, l'effet pratique de la suppression de seccomp est que namespace-creation or mount syscalls se mettent soudainement à fonctionner. Si le container dispose également de `CAP_SYS_ADMIN`, la séquence suivante peut devenir possible :
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
Pris isolément, ce n'est pas encore un host escape, mais cela montre que seccomp était la barrière empêchant l'exploitation liée au mount.

### Exemple complet : seccomp désactivé + cgroup v1 `release_agent`

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
Ce n'est pas un seccomp-only exploit. L'idée est que, une fois que seccomp n'est plus confiné, les syscall-heavy breakout chains qui étaient auparavant bloquées peuvent commencer à fonctionner exactement telles qu'écrites.

## Vérifications

Le but de ces vérifications est de déterminer si seccomp est actif, si `no_new_privs` l'accompagne, et si la configuration du runtime montre que seccomp est explicitement désactivé.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Ce qui est intéressant ici :

- Une valeur non nulle `Seccomp` signifie que le filtrage est actif ; `0` signifie généralement pas de protection seccomp.
- Si les options de sécurité du runtime incluent `seccomp=unconfined`, la charge de travail a perdu l'une de ses défenses les plus utiles au niveau des syscalls.
- `NoNewPrivs` n'est pas seccomp en soi, mais voir les deux ensemble indique généralement une posture de hardening plus prudente que de ne voir aucun des deux.

Si un container a déjà des montages suspects, des capabilities larges ou des host namespaces partagés, et que seccomp est aussi unconfined, cette combinaison doit être considérée comme un signal majeur d'escalade. Le container peut toujours ne pas être trivialement compromis, mais le nombre de points d'entrée du kernel disponibles pour l'attaquant a fortement augmenté.

## Runtime Defaults

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Généralement activé par défaut | Utilise le profile seccomp par défaut intégré de Docker sauf si surchargé | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Généralement activé par défaut | Applique le profile seccomp par défaut du runtime sauf si surchargé | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Pas garanti par défaut** | Si `securityContext.seccompProfile` n'est pas défini, la valeur par défaut est `Unconfined` sauf si le kubelet active `--seccomp-default`; `RuntimeDefault` ou `Localhost` doivent sinon être définis explicitement | `securityContext.seccompProfile.type: Unconfined`, laisser seccomp non défini sur des clusters sans `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Suit les paramètres node et Pod de Kubernetes | Le profil runtime est utilisé lorsque Kubernetes demande `RuntimeDefault` ou lorsque le kubelet a le seccomp defaulting activé | Même que la ligne Kubernetes ; la configuration CRI/OCI directe peut aussi omettre seccomp entièrement |

Le comportement de Kubernetes est celui qui surprend le plus souvent les opérateurs. Dans de nombreux clusters, seccomp est encore absent à moins que le Pod ne le demande ou que le kubelet soit configuré pour définir par défaut `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
