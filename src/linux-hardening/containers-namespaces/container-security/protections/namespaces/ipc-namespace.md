# Espace de noms IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d’ensemble

L’espace de noms IPC isole les **objets IPC System V** et les **files de messages POSIX**. Cela inclut les segments de mémoire partagée, les sémaphores et les files de messages qui seraient autrement visibles par des processus sans lien sur l’hôte. En pratique, cela empêche un container de se connecter facilement à des objets IPC appartenant à d’autres workloads ou à l’hôte.

Comparé aux espaces de noms mount, PID ou user, l’espace de noms IPC est souvent moins abordé, mais cela ne signifie pas qu’il est sans importance. La mémoire partagée et les mécanismes IPC associés peuvent contenir des états très utiles. Si l’espace de noms IPC de l’hôte est exposé, le workload peut obtenir une visibilité sur des objets ou des données de coordination inter-processus qui n’étaient jamais destinés à franchir la limite du container.

## Fonctionnement

Lorsque le runtime crée un espace de noms IPC isolé, le processus dispose de son propre ensemble d’identifiants IPC isolés. Cela signifie que des commandes telles que `ipcs` n’affichent que les objets disponibles dans cet espace de noms. Si le container rejoint à la place l’espace de noms IPC de l’hôte, ces objets font partie d’une vue globale partagée.

Cela est particulièrement important dans les environnements où les applications ou les services utilisent largement la mémoire partagée. Même lorsque le container ne peut pas s’échapper directement via IPC uniquement, l’espace de noms peut leak des informations ou permettre des interférences entre processus qui facilitent considérablement une attaque ultérieure.

## Lab

Vous pouvez créer un espace de noms IPC privé avec :
```bash
sudo unshare --ipc --fork bash
ipcs
```
Et comparez le comportement à l’exécution avec :
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Utilisation à l’exécution

Docker et Podman isolent l’IPC par défaut. Kubernetes attribue généralement au Pod son propre namespace IPC, partagé entre les conteneurs du même Pod, mais pas par défaut avec l’hôte. Le partage de l’IPC de l’hôte est possible, mais il doit être considéré comme une réduction significative de l’isolation, et non comme une simple option d’exécution.

## Mauvaises configurations

L’erreur évidente consiste à utiliser `--ipc=host` ou `hostIPC: true`. Cela peut être fait pour assurer la compatibilité avec des logiciels legacy ou par commodité, mais cela modifie considérablement le modèle de confiance. Un autre problème récurrent est de simplement négliger l’IPC, car il semble moins préoccupant que le PID de l’hôte ou le networking de l’hôte. En réalité, si le workload gère des browsers, des bases de données, des workloads scientifiques ou d’autres logiciels qui utilisent intensivement la mémoire partagée, la surface d’attaque IPC peut être particulièrement pertinente.

## Abuse

Lorsque l’IPC de l’hôte est partagé, un attaquant peut inspecter ou perturber les objets de mémoire partagée, obtenir de nouvelles informations sur le comportement de l’hôte ou des workloads voisins, ou combiner les informations obtenues avec la visibilité des processus et des capabilities de type ptrace. Le partage de l’IPC constitue souvent une faiblesse auxiliaire plutôt que le chemin complet vers un breakout, mais les faiblesses auxiliaires sont importantes, car elles raccourcissent et stabilisent les attack chains réelles.

La première étape utile consiste à énumérer les objets IPC effectivement visibles :
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Si l’espace de noms IPC de l’hôte est partagé, de grands segments de mémoire partagée ou des propriétaires d’objets intéressants peuvent révéler immédiatement le comportement de l’application :
```bash
ipcs -m -p
ipcs -q -p
```
Dans certains environnements, le contenu de `/dev/shm` lui-même peut faire leak des noms de fichiers, des artefacts ou des tokens qu’il vaut la peine de vérifier :
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Le partage IPC ne donne que rarement instantanément les privilèges root sur l’hôte à lui seul, mais il peut exposer des données et des canaux de coordination qui facilitent grandement les attaques ultérieures contre les processus.

### Exemple complet : récupération de secrets dans `/dev/shm`

Le cas d’abus complet le plus réaliste est le vol de données plutôt qu’une évasion directe. Si l’IPC de l’hôte ou une architecture de mémoire partagée étendue est exposé, des artefacts sensibles peuvent parfois être récupérés directement :
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impact :

- extraction de secrets ou de données de session laissés dans la mémoire partagée
- informations sur les applications actuellement actives sur l’hôte
- meilleur ciblage pour des attaques ultérieures basées sur le PID namespace ou `ptrace`

Le partage IPC doit donc être considéré comme un **amplificateur d’attaque** plutôt que comme une primitive autonome d’évasion de l’hôte.

## Vérifications

Ces commandes permettent de déterminer si la workload dispose d’une vue IPC privée, si des objets significatifs de mémoire partagée ou de messages sont visibles, et si `/dev/shm` lui-même expose des artefacts utiles.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Ce qui est intéressant ici :

- Si `ipcs -a` révèle des objets appartenant à des utilisateurs ou services inattendus, le namespace n’est peut-être pas aussi isolé qu’il devrait l’être.
- Les segments de mémoire partagée volumineux ou inhabituels méritent souvent d’être examinés plus en détail.
- Un montage `/dev/shm` étendu n’est pas automatiquement un bug, mais dans certains environnements, il leak des noms de fichiers, des artefacts et des secrets temporaires.

IPC reçoit rarement autant d’attention que les types de namespace plus importants, mais dans les environnements qui l’utilisent intensivement, le partager avec l’hôte constitue clairement une décision de sécurité.
{{#include ../../../../../banners/hacktricks-training.md}}
