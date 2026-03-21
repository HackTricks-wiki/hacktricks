# Espace de noms IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms IPC isole **System V IPC objects** et **POSIX message queues**. Cela inclut les segments de mémoire partagée, les sémaphores et les files de messages qui seraient autrement visibles entre des processus non liés sur l'hôte. En pratique, cela empêche un conteneur de s'attacher de manière opportuniste aux objets IPC appartenant à d'autres workloads ou à l'hôte.

Comparé aux mount, PID ou user namespaces, l'espace de noms IPC est moins souvent abordé, mais cela ne doit pas être confondu avec de l'irrélevance. La mémoire partagée et les mécanismes IPC associés peuvent contenir des états très utiles. Si l'espace de noms IPC de l'hôte est exposé, le workload peut gagner en visibilité sur des objets de coordination inter-processus ou des données qui n'avaient jamais vocation à franchir la frontière du conteneur.

## Fonctionnement

Lorsque le runtime crée un nouvel espace de noms IPC, le processus obtient son propre ensemble isolé d'identifiants IPC. Cela signifie que des commandes telles que `ipcs` n'affichent que les objets disponibles dans cet espace de noms. Si le conteneur rejoint plutôt l'espace de noms IPC de l'hôte, ces objets font partie d'une vue globale partagée.

Ceci est particulièrement important dans des environnements où des applications ou des services utilisent intensivement la mémoire partagée. Même lorsque le conteneur ne peut pas s'échapper directement via l'IPC seul, l'espace de noms peut leak des informations ou permettre des interférences inter-processus qui facilitent notablement une attaque ultérieure.

## Laboratoire

Vous pouvez créer un espace de noms IPC privé avec :
```bash
sudo unshare --ipc --fork bash
ipcs
```
Et comparez le comportement à l'exécution avec :
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Utilisation à l'exécution

Docker et Podman isolent l'IPC par défaut. Kubernetes donne généralement au Pod son propre namespace IPC, partagé par les containers du même Pod mais pas, par défaut, avec l'hôte. Le partage de l'IPC de l'hôte est possible, mais il doit être considéré comme une réduction significative de l'isolation plutôt que comme une option mineure d'exécution.

## Mauvaises configurations

L'erreur évidente est `--ipc=host` ou `hostIPC: true`. Cela peut être fait pour compatibilité avec des logiciels legacy ou par commodité, mais cela change substantiellement le modèle de confiance. Un autre problème récurrent est de simplement négliger l'IPC parce que cela paraît moins dramatique que host PID ou host networking. En réalité, si la charge de travail gère des navigateurs, bases de données, charges de calcul scientifiques ou d'autres logiciels qui utilisent intensivement la mémoire partagée, la surface IPC peut être très pertinente.

## Abus

Lorsque l'IPC de l'hôte est partagé, un attaquant peut inspecter ou interférer avec les objets de mémoire partagée, obtenir de nouvelles informations sur le comportement de l'hôte ou des workloads voisins, ou combiner les informations recueillies avec la visibilité des processus et des capacités de type ptrace. Le partage d'IPC est souvent une faiblesse de support plutôt que le chemin complet de breakout, mais ces faiblesses de support comptent car elles raccourcissent et stabilisent les chaînes d'attaque réelles.

La première étape utile est d'énumérer quels objets IPC sont visibles :
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Si l'IPC namespace de l'hôte est partagé, de grands segments de mémoire partagée ou des propriétaires d'objets intéressants peuvent révéler immédiatement le comportement des applications :
```bash
ipcs -m -p
ipcs -q -p
```
Dans certains environnements, le contenu de `/dev/shm` lui-même leak des filenames, artifacts ou tokens qui valent la peine d'être vérifiés :
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Le partage d'IPC ne donne que rarement un host root instantané en lui-même, mais il peut exposer des données et des canaux de coordination qui rendent les attaques ultérieures sur des processus beaucoup plus faciles.

### Exemple complet : récupération de secrets dans `/dev/shm`

Le cas d'abus le plus réaliste consiste au vol de données plutôt qu'à une évasion directe. Si l'IPC de l'hôte ou un vaste agencement de mémoire partagée est exposé, des artefacts sensibles peuvent parfois être récupérés directement :
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impact :

- extraction de secrets ou de matériel de session laissé dans la mémoire partagée
- aperçu des applications actuellement actives sur l'hôte
- meilleur ciblage pour des attaques ultérieures basées sur PID-namespace ou ptrace

Le partage IPC est donc mieux compris comme un **amplificateur d'attaque** que comme une primitive d'évasion d'hôte autonome.

## Vérifications

Ces commandes visent à déterminer si la charge de travail dispose d'une vue IPC privée, si des objets significatifs de mémoire partagée ou de messages sont visibles, et si `/dev/shm` expose lui-même des artefacts utiles.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Ce qui est intéressant ici :

- Si `ipcs -a` révèle des objets appartenant à des utilisateurs ou services inattendus, le namespace pourrait ne pas être aussi isolé que prévu.
- Les segments de mémoire partagée volumineux ou inhabituels valent souvent la peine d'être examinés.
- Un montage large de `/dev/shm` n'est pas automatiquement un bug, mais dans certains environnements il leak des noms de fichiers, des artefacts et des secrets transitoires.

IPC reçoit rarement autant d'attention que les types de namespace plus importants, mais dans les environnements qui l'utilisent intensivement, le partager avec l'hôte est clairement une décision de sécurité.
