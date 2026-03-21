# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

**seccomp** est le mécanisme qui permet au noyau d'appliquer un filtre aux syscalls qu'un processus peut invoquer. Dans les environnements conteneurisés, seccomp est normalement utilisé en mode filtre de sorte que le processus n'est pas simplement marqué "restricted" de manière vague, mais est plutôt soumis à une politique de syscalls concrète. Cela a de l'importance parce que de nombreuses échappées de container nécessitent d'atteindre des interfaces noyau très spécifiques. Si le processus ne peut pas invoquer avec succès les syscalls pertinents, une grande classe d'attaques disparaît avant même que toute nuance de namespaces ou de capabilities ne devienne pertinente.

Le modèle mental clé est simple : namespaces décident **ce que le processus peut voir**, capabilities décident **quelles actions privilégiées le processus est nominalement autorisé à tenter**, et seccomp décide **si le noyau acceptera même le point d'entrée syscall pour l'action tentée**. C'est pourquoi seccomp empêche fréquemment des attaques qui paraîtraient possibles si l'on se basait uniquement sur les capabilities.

## Security Impact

Beaucoup de surface dangereuse du noyau n'est accessible que via un ensemble relativement restreint de syscalls. Des exemples qui comptent régulièrement dans le hardening des containers incluent `mount`, `unshare`, `clone` ou `clone3` avec des flags particuliers, `bpf`, `ptrace`, `keyctl`, et `perf_event_open`. Un attaquant qui peut atteindre ces syscalls peut être capable de créer de nouveaux namespaces, manipuler des sous-systèmes du noyau, ou interagir avec une surface d'attaque dont un container applicatif normal n'a absolument pas besoin.

C'est pourquoi les profiles seccomp runtime par défaut sont si importants. Ils ne sont pas simplement une "extra defense". Dans de nombreux environnements, ils font la différence entre un container qui peut exercer une large portion des fonctionnalités du noyau et un autre qui est contraint à une surface de syscalls plus proche de ce dont l'application a réellement besoin.

## Modes And Filter Construction

seccomp disposait historiquement d'un strict mode dans lequel seul un jeu minimal de syscalls restait disponible, mais le mode pertinent pour les runtimes conteneur modernes est le mode filtre seccomp, souvent appelé **seccomp-bpf**. Dans ce modèle, le noyau évalue un programme de filtre qui décide si un syscall doit être autorisé, refusé avec un errno, piégé, journalisé, ou provoquer la mort du processus. Les runtimes de containers utilisent ce mécanisme car il est suffisamment expressif pour bloquer de larges classes de syscalls dangereux tout en permettant le comportement normal des applications.

Deux exemples bas niveau sont utiles parce qu'ils rendent le mécanisme concret plutôt que magique. Strict mode démontre l'ancien modèle "only a minimal syscall set survives" :
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
Le dernier `open` provoque la terminaison du processus car il ne fait pas partie de l'ensemble minimal de strict mode.

Un exemple de filtre libseccomp illustre plus clairement le modèle de politique moderne :
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
Ce type de politique est ce que la plupart des lecteurs devraient s'imaginer lorsqu'ils pensent aux profils seccomp à l'exécution.

## Lab

Une façon simple de confirmer que seccomp est actif dans un conteneur est:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Vous pouvez également essayer une opération que les profils par défaut restreignent couramment :
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Si le conteneur s'exécute sous un profil seccomp par défaut, les opérations de type `unshare` sont souvent bloquées. C'est une démonstration utile car elle montre que même si l'outil userspace existe dans l'image, le chemin noyau dont il a besoin peut néanmoins être indisponible.
Si le conteneur s'exécute sous un profil seccomp par défaut, les opérations de type `unshare` sont souvent bloquées même lorsque l'outil userspace existe dans l'image.

Pour inspecter l'état du processus de manière plus générale, exécutez :
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Utilisation à l'exécution

Docker prend en charge à la fois les profils seccomp par défaut et personnalisés et permet aux administrateurs de les désactiver avec `--security-opt seccomp=unconfined`. Podman offre un support similaire et associe souvent seccomp à l'exécution sans root dans une posture par défaut très sensée. Kubernetes expose seccomp via la configuration des workloads, où `RuntimeDefault` est généralement la valeur de base sensée et `Unconfined` doit être traité comme une exception nécessitant une justification plutôt qu'un simple commutateur de commodité.

Dans les environnements basés sur containerd et CRI-O, le chemin exact est plus stratifié, mais le principe est le même : le moteur ou l'orchestrateur de niveau supérieur décide de ce qui doit se passer, et le runtime installe finalement la politique seccomp résultante pour le processus du conteneur. Le résultat dépend toujours de la configuration finale du runtime qui atteint le noyau.

### Exemple de politique personnalisée

Docker et des moteurs similaires peuvent charger un profil seccomp personnalisé depuis du JSON. Un exemple minimal qui refuse `chmod` tout en autorisant tout le reste ressemble à ceci :
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
Il manque le contenu à traduire. Veuillez coller ici le texte (ou le passage du fichier src/linux-hardening/privilege-escalation/container-security/protections/seccomp.md) que vous voulez que je traduise en français.
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
La commande échoue avec `Operation not permitted`, ce qui montre que la restriction provient de la politique de syscall plutôt que des seules permissions de fichier ordinaires. Dans un hardening réel, les allowlists sont généralement plus strictes que des valeurs par défaut permissives accompagnées d'une petite blacklist.

## Misconfigurations

La plus grosse erreur est de définir seccomp sur **unconfined** parce qu'une application a échoué avec la politique par défaut. C'est courant lors du dépannage et très dangereux comme correctif permanent. Une fois le filtre supprimé, de nombreuses primitives d'évasion basées sur des syscalls redeviennent accessibles, surtout si des capabilities puissantes ou le partage du host namespace sont également présents.

Un autre problème fréquent est l'utilisation d'un **custom permissive profile** copié depuis un blog ou un contournement interne sans révision attentive. Les équipes conservent parfois presque tous les syscalls dangereux simplement parce que le profile a été conçu pour « empêcher l'app de casser » plutôt que pour « n'accorder que ce dont l'app a réellement besoin ». Une troisième idée reçue est de supposer que seccomp est moins important pour les containers non-root. En réalité, une grande partie de la kernel attack surface reste pertinente même lorsque le processus n'est pas UID 0.

## Abuse

Si seccomp est absent ou gravement affaibli, un attaquant peut être en mesure d'invoquer des syscalls de création de namespace, d'élargir la kernel attack surface accessible via `bpf` ou `perf_event_open`, d'abuser de `keyctl`, ou de combiner ces chemins de syscall avec des capabilities dangereuses telles que `CAP_SYS_ADMIN`. Dans de nombreuses attaques réelles, seccomp n'est pas le seul contrôle manquant, mais son absence raccourcit considérablement la chaîne d'exploitation parce qu'elle supprime l'une des rares défenses capables d'arrêter un syscall risqué avant que le reste du modèle de privilèges n'intervienne.

Le test pratique le plus utile est d'essayer les familles de syscall exactes que les default profiles bloquent habituellement. S'ils fonctionnent soudainement, la posture du container a beaucoup changé :
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Si `CAP_SYS_ADMIN` ou une autre capability puissante est présente, vérifiez si seccomp est la seule barrière manquante avant mount-based abuse :
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Sur certaines cibles, la valeur immédiate n'est pas un full escape mais information gathering et kernel attack-surface expansion. Ces commandes aident à déterminer si des chemins syscall particulièrement sensibles sont accessibles :
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Si seccomp est absent et que le conteneur est par ailleurs privilégié, c'est alors pertinent de passer aux techniques de breakout plus spécifiques déjà documentées dans les pages legacy container-escape.

### Exemple complet : seccomp était la seule chose bloquant `unshare`

Sur de nombreuses cibles, l'effet pratique de la suppression de seccomp est que les syscalls de création de namespace ou de mount se mettent soudainement à fonctionner. Si le conteneur dispose également de `CAP_SYS_ADMIN`, la séquence suivante peut devenir possible :
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
En soi, ce n'est pas encore une host escape, mais cela démontre que seccomp était la barrière empêchant l'exploitation liée au mount.

### Exemple complet : seccomp désactivé + cgroup v1 `release_agent`

Si seccomp est désactivé et que le conteneur peut monter des hiérarchies cgroup v1, la technique `release_agent` de la section cgroups devient accessible:
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
Ce n'est pas un exploit uniquement basé sur seccomp. L'idée est que, une fois seccomp non confiné, les syscall-heavy breakout chains qui étaient auparavant bloquées peuvent commencer à fonctionner exactement telles qu'écrites.

## Vérifications

Le but de ces vérifications est de déterminer si seccomp est actif, si `no_new_privs` l'accompagne, et si la configuration d'exécution indique que seccomp est explicitement désactivé.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Points intéressants :

- Une valeur non nulle de `Seccomp` signifie que le filtrage est actif ; `0` signifie généralement qu'il n'y a pas de protection seccomp.
- Si les options de sécurité du runtime incluent `seccomp=unconfined`, la charge de travail a perdu l'une de ses défenses les plus utiles au niveau des syscalls.
- `NoNewPrivs` n'est pas seccomp en soi, mais voir les deux ensemble indique généralement une posture de durcissement plus prudente que de ne voir aucun des deux.

Si un container présente déjà des montages suspects, des capabilities larges, ou des namespaces d'hôte partagés, et que seccomp est également unconfined, cette combinaison doit être considérée comme un signal d'escalade majeur. Le container peut encore ne pas être trivialement compromettable, mais le nombre de points d'entrée du kernel accessibles à l'attaquant a fortement augmenté.

## Paramètres d'exécution par défaut

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Généralement activé par défaut | Utilise le profil seccomp par défaut intégré à Docker sauf s'il est surchargé | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Généralement activé par défaut | Applique le profil seccomp par défaut du runtime sauf s'il est surchargé | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Pas garanti par défaut** | Si `securityContext.seccompProfile` n'est pas défini, la valeur par défaut est `Unconfined` à moins que le kubelet n'active `--seccomp-default` ; `RuntimeDefault` ou `Localhost` doivent sinon être définis explicitement | `securityContext.seccompProfile.type: Unconfined`, laisser seccomp non défini sur des clusters sans `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Suit les paramètres du nœud et du Pod Kubernetes | Le profil du runtime est utilisé lorsque Kubernetes demande `RuntimeDefault` ou quand le kubelet active le paramétrage par défaut de seccomp | Identique à la ligne Kubernetes ; la configuration CRI/OCI directe peut aussi omettre totalement seccomp |

Le comportement de Kubernetes est celui qui surprend le plus souvent les opérateurs. Dans de nombreux clusters, seccomp est encore absent à moins que le Pod ne le demande ou que le kubelet ne soit configuré pour définir `RuntimeDefault` comme valeur par défaut.
