# Espace de noms IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

L'espace de noms IPC isole **System V IPC objects** et **POSIX message queues**. Cela inclut les segments de mémoire partagée, les sémaphores et les files de messages qui seraient sinon visibles entre des processus non liés sur l'hôte. En pratique, cela empêche un conteneur de se connecter de manière occasionnelle aux objets IPC appartenant à d'autres charges de travail ou à l'hôte.

Comparé aux espaces de noms mount, PID ou user, l'espace de noms IPC est souvent moins discuté, mais cela ne doit pas être confondu avec de l'irrélevance. La mémoire partagée et les mécanismes IPC associés peuvent contenir des états très utiles. Si l'espace de noms IPC de l'hôte est exposé, la charge de travail peut obtenir de la visibilité sur des objets de coordination inter-processus ou des données qui n'étaient jamais destinées à franchir la frontière du conteneur.

## Fonctionnement

Lorsque le runtime crée un nouvel espace de noms IPC, le processus obtient son propre ensemble isolé d'identifiants IPC. Cela signifie que des commandes telles que `ipcs` n'affichent que les objets disponibles dans cet espace de noms. Si le conteneur rejoint plutôt l'espace de noms IPC de l'hôte, ces objets font partie d'une vue globale partagée.

Cela est particulièrement important dans les environnements où les applications ou les services utilisent intensivement la mémoire partagée. Même lorsque le conteneur ne peut pas s'échapper directement via IPC seul, l'espace de noms peut leak des informations ou permettre des interférences entre processus qui facilitent de façon significative une attaque ultérieure.

## Lab

Vous pouvez créer un espace de noms IPC privé avec :
```bash
sudo unshare --ipc --fork bash
ipcs
```
Et comparez le comportement d'exécution avec :
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Utilisation à l'exécution

Docker et Podman isolent l'IPC par défaut. Kubernetes donne généralement au Pod son propre IPC namespace, partagé par les conteneurs du même Pod mais pas, par défaut, avec l'hôte. Le partage de l'IPC avec l'hôte est possible, mais il doit être considéré comme une réduction significative de l'isolation plutôt que comme une simple option runtime mineure.

## Mauvaises configurations

L'erreur évidente est `--ipc=host` ou `hostIPC: true`. Cela peut être fait pour la compatibilité avec des logiciels legacy ou par commodité, mais cela change substantiellement le modèle de confiance. Un autre problème récurrent est de simplement négliger l'IPC parce que cela semble moins dramatique que host PID ou host networking. En réalité, si la charge de travail gère des navigateurs, des bases de données, des workloads scientifiques ou d'autres logiciels utilisant intensivement la mémoire partagée, la surface d'IPC peut être très pertinente.

## Abus

Lorsque l'IPC de l'hôte est partagé, un attaquant peut inspecter ou interférer avec des objets de mémoire partagée, obtenir de nouvelles informations sur le comportement de l'hôte ou d'une charge de travail voisine, ou combiner les informations ainsi apprises avec la visibilité des processus et des capacités de type ptrace. Le partage de l'IPC est souvent une faiblesse d'accompagnement plutôt que le chemin complet d'évasion, mais ces faiblesses d'accompagnement sont importantes car elles raccourcissent et stabilisent les chaînes d'attaque réelles.

La première étape utile est d'énumérer quels objets IPC sont visibles :
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Si le host IPC namespace est partagé, de grands segments de shared-memory ou des propriétaires d'objets intéressants peuvent révéler immédiatement le comportement de l'application :
```bash
ipcs -m -p
ipcs -q -p
```
Dans certains environnements, le contenu de `/dev/shm` leak des filenames, artifacts ou tokens qu'il vaut la peine de vérifier :
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Le partage IPC donne rarement, à lui seul, un root instantané de l'hôte, mais il peut exposer des canaux de données et de coordination qui facilitent considérablement des attaques de processus ultérieures.

### Exemple complet : récupération de secrets dans `/dev/shm`

Le cas d'abus complet le plus réaliste est le vol de données plutôt qu'une escape directe. Si l'IPC de l'hôte ou une configuration étendue de shared-memory est exposée, des artefacts sensibles peuvent parfois être récupérés directement :
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impact :

- extraction de secrets ou de matériel de session laissé dans la mémoire partagée
- aperçu des applications actuellement actives sur l'hôte
- meilleur ciblage pour de futures attaques basées sur PID-namespace ou ptrace

Le partage IPC est donc mieux compris comme un **amplificateur d'attaque** plutôt que comme une primitive autonome d'évasion d'hôte.

## Vérifications

Ces commandes visent à répondre à la question de savoir si la charge de travail dispose d'une vue IPC privée, si des objets de mémoire partagée ou de message significatifs sont visibles, et si `/dev/shm` expose lui-même des artefacts utiles.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Ce qui est intéressant ici :

- Si `ipcs -a` révèle des objets appartenant à des utilisateurs ou services inattendus, le namespace peut ne pas être aussi isolé qu'escompté.
- Les segments de mémoire partagée volumineux ou inhabituels valent souvent la peine d'être investigués.
- Un montage large de `/dev/shm` n'est pas automatiquement un bug, mais dans certains environnements il leaks des noms de fichiers, des artefacts et des secrets transitoires.

IPC reçoit rarement autant d'attention que les types de namespace plus importants, mais dans les environnements qui l'utilisent intensivement, le partager avec l'hôte est clairement une décision de sécurité.
{{#include ../../../../../banners/hacktricks-training.md}}
