# Espace de noms IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'IPC namespace isole **System V IPC objects** et **POSIX message queues**. Cela inclut les segments de mémoire partagée, les sémaphores et les files de messages qui seraient autrement visibles par des processus non liés sur l'hôte. En termes pratiques, cela empêche un container de s'attacher de manière opportuniste à des objets IPC appartenant à d'autres workloads ou à l'hôte.

Comparé aux mount, PID, or user namespaces, l'IPC namespace est souvent moins discuté, mais cela ne doit pas être confondu avec de l'irrélevance. La mémoire partagée et les mécanismes IPC associés peuvent contenir des états très utiles. Si le host IPC namespace est exposé, le workload peut gagner en visibilité sur des objets de coordination inter-processus ou des données qui n'étaient jamais destinées à franchir la frontière du container.

## Fonctionnement

Lorsque le runtime crée un nouvel IPC namespace, le processus obtient son propre ensemble isolé d'identifiants IPC. Cela signifie que des commandes telles que `ipcs` n'affichent que les objets disponibles dans ce namespace. Si le container rejoint à la place le host IPC namespace, ces objets font partie d'une vue globale partagée.

Ceci est particulièrement important dans des environnements où des applications ou des services utilisent intensivement la mémoire partagée. Même lorsque le container ne peut pas directement s'échapper via l'IPC seul, le namespace may leak des informations ou permettre des interférences inter-processus qui facilitent de manière significative une attaque ultérieure.

## Lab

Vous pouvez créer un IPC namespace privé avec :
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

Docker et Podman isolent l'IPC par défaut. Kubernetes donne typiquement au Pod son propre IPC namespace, partagé par les conteneurs du même Pod mais pas, par défaut, avec l'hôte. Le partage de l'IPC de l'hôte est possible, mais il doit être considéré comme une réduction significative de l'isolation plutôt qu'une simple option d'exécution.

## Mauvaises configurations

L'erreur évidente est `--ipc=host` ou `hostIPC: true`. Cela peut être fait pour la compatibilité avec des logiciels legacy ou par commodité, mais cela change substantiellement le modèle de confiance. Un autre problème récurrent est tout simplement d'ignorer l'IPC parce que cela semble moins dramatique que le PID de l'hôte ou le réseau de l'hôte. En réalité, si la charge de travail traite des navigateurs, des bases de données, des charges de travail scientifiques, ou d'autres logiciels qui utilisent intensivement la mémoire partagée, la surface IPC peut être très pertinente.

## Abus

Lorsque l'IPC de l'hôte est partagé, un attaquant peut inspecter ou interférer avec des objets de mémoire partagée, obtenir de nouvelles informations sur le comportement de l'hôte ou des charges de travail voisines, ou combiner les informations apprises avec la visibilité des processus et des capacités de type ptrace. Le partage de l'IPC est souvent une faiblesse de soutien plutôt que le chemin complet d'évasion, mais les faiblesses de soutien comptent parce qu'elles raccourcissent et stabilisent les chaînes d'attaque réelles.

La première étape utile est d'énumérer quels objets IPC sont visibles :
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Si le namespace IPC de l'hôte est partagé, de grands segments de mémoire partagée ou des propriétaires d'objets intéressants peuvent révéler immédiatement le comportement de l'application :
```bash
ipcs -m -p
ipcs -q -p
```
Dans certains environnements, le contenu de `/dev/shm` leak des filenames, artifacts ou tokens qui valent la peine d'être vérifiés :
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Le partage d'IPC donne rarement un host root instantané en soi, mais il peut exposer des canaux de données et de coordination qui facilitent grandement les attaques ultérieures contre des processus.

### Exemple complet : `/dev/shm` Récupération de secrets

Le cas d'abus complet le plus réaliste est le vol de données plutôt que l'échappement direct. Si l'IPC de l'hôte ou un vaste agencement de mémoire partagée est exposé, des artefacts sensibles peuvent parfois être récupérés directement:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impact :

- extraction de secrets ou de données de session laissées dans shared memory
- aperçu des applications actuellement actives sur l'hôte
- un meilleur ciblage pour de futures attaques PID-namespace ou ptrace-based

Le partage IPC doit donc être considéré davantage comme un **attack amplifier** que comme un host-escape primitive autonome.

## Vérifications

Ces commandes visent à répondre à la question de savoir si le workload a une vue IPC privée, si des shared-memory ou message objects significatifs sont visibles, et si `/dev/shm` expose lui-même des artefacts utiles.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- Si `ipcs -a` révèle des objets appartenant à des utilisateurs ou services inattendus, le namespace peut ne pas être aussi isolé qu'attendu.
- Les segments de mémoire partagée volumineux ou inhabituels méritent souvent d'être examinés.
- Un montage étendu de `/dev/shm` n'est pas automatiquement un bug, mais dans certains environnements il leaks des noms de fichiers, des artefacts et des secrets transitoires.

IPC reçoit rarement autant d'attention que les types de namespace plus importants, mais dans les environnements qui l'utilisent intensivement, le partager avec l'hôte reste une décision de sécurité.
{{#include ../../../../../banners/hacktricks-training.md}}
