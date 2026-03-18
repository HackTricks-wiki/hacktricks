# Espace de noms utilisateur

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Références

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Informations de base

Un user namespace est une fonctionnalité du noyau Linux qui **fournit l'isolation des mappages d'IDs utilisateur et groupe**, permettant à chaque user namespace d'avoir son **propre ensemble d'IDs utilisateur et groupe**. Cette isolation permet aux processus s'exécutant dans différents user namespaces d'**avoir des privilèges et une propriété différents**, même s'ils partagent numériquement les mêmes IDs utilisateur et groupe.

Les user namespaces sont particulièrement utiles dans la containerisation, où chaque container devrait avoir son propre ensemble indépendant d'IDs utilisateur et groupe, permettant une meilleure sécurité et isolation entre les containers et le système hôte.

### Fonctionnement :

1. Lorsqu'un nouvel user namespace est créé, il **commence avec un ensemble vide de mappages d'IDs utilisateur et groupe**. Cela signifie que tout processus s'exécutant dans le nouvel user namespace **n'aura initialement aucun privilège en dehors du namespace**.
2. Des mappages d'ID peuvent être établis entre les IDs utilisateur et groupe du nouveau namespace et ceux du namespace parent (ou hôte). Cela **permet aux processus du nouveau namespace d'avoir des privilèges et une propriété correspondant aux IDs utilisateur et groupe du namespace parent**. Cependant, les mappages d'ID peuvent être restreints à des plages et des sous-ensembles spécifiques d'IDs, permettant un contrôle fin des privilèges accordés aux processus du nouveau namespace.
3. Dans un user namespace, **les processus peuvent avoir des privilèges root complets (UID 0) pour les opérations à l'intérieur du namespace**, tout en ayant des privilèges limités à l'extérieur du namespace. Cela permet **aux containers de s'exécuter avec des capacités similaires à root à l'intérieur de leur propre namespace sans disposer des privilèges root complets sur le système hôte**.
4. Les processus peuvent se déplacer entre les namespaces en utilisant l'appel système `setns()` ou créer de nouveaux namespaces en utilisant les appels système `unshare()` ou `clone()` avec le flag `CLONE_NEWUSER`. Lorsqu'un processus se déplace vers un nouveau namespace ou en crée un, il commencera à utiliser les mappages d'IDs utilisateur et groupe associés à ce namespace.

## Laboratoire:

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Erreur : bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Explication du problème** :

- Le noyau Linux permet à un processus de créer de nouveaux namespaces via l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouveau PID namespace (appelé le processus "unshare") n'entre pas dans le nouveau namespace ; seuls ses processus enfants y entrent.
- L'exécution de %unshare -p /bin/bash% lance `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants sont dans le PID namespace d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouveau namespace devient PID 1. Lorsque ce processus se termine, il déclenche le nettoyage du namespace s'il n'y a pas d'autres processus, car PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactivera alors l'allocation de PID dans ce namespace.

2. **Conséquence** :

- La sortie de PID 1 dans un nouveau namespace entraîne le nettoyage du drapeau `PIDNS_HASH_ADDING`. Cela a pour conséquence que la fonction `alloc_pid` échoue à allouer un nouveau PID lors de la création d'un nouveau processus, produisant l'erreur "Cannot allocate memory".

3. **Solution** :
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option force `unshare` à fork un nouveau processus après avoir créé le nouveau PID namespace.
- L'exécution de %unshare -fp /bin/bash% garantit que la commande `unshare` elle-même devient PID 1 dans le nouveau namespace. `/bin/bash` et ses processus enfants sont alors correctement contenus dans ce nouveau namespace, évitant la sortie prématurée de PID 1 et permettant l'allocation normale des PID.

En veillant à ce que `unshare` s'exécute avec le drapeau `-f`, le nouveau PID namespace est maintenu correctement, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation de mémoire.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Pour utiliser user namespace, le daemon Docker doit être démarré avec **`--userns-remap=default`**(sur ubuntu 14.04, cela peut être fait en modifiant `/etc/default/docker` puis en exécutant `sudo service docker restart`)

### Vérifier dans quel namespace se trouve votre processus
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Il est possible de vérifier la table de mappage des utilisateurs depuis le conteneur docker avec :
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ou depuis l'hôte avec :
```bash
cat /proc/<pid>/uid_map
```
### Trouver tous les espaces de noms utilisateur
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrer dans un User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
De plus, vous pouvez seulement **entrer dans un autre espace de noms de processus si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/user`).

### Créer un nouvel espace de noms utilisateur (avec mappages)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Règles de mappage UID/GID non privilégié

Lorsque le processus écrivant dans `uid_map`/`gid_map` **n'a pas CAP_SETUID/CAP_SETGID dans l'espace de noms utilisateur parent**, le noyau applique des règles plus strictes : une **seule correspondance** est autorisée pour l'UID/GID effectif de l'appelant, et pour `gid_map` vous **devez d'abord désactiver `setgroups(2)`** en écrivant `deny` dans `/proc/<pid>/setgroups`.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

ID-mapped Mounts **attach a user namespace mapping to a mount**, donc la propriété des fichiers est remappée lorsqu'elle est accédée via ce mount. Cela est couramment utilisé par les container runtimes (surtout rootless) pour **partager des chemins hôtes sans `chown` récursif**, tout en appliquant la traduction UID/GID du user namespace.

D'un point de vue offensif, **si vous pouvez créer un mount namespace et détenir `CAP_SYS_ADMIN` à l'intérieur de votre user namespace**, et que le système de fichiers supporte les ID-mapped mounts, vous pouvez remapper les *vues* de propriété des bind mounts. Cela **ne change pas la propriété sur le disque**, mais cela peut faire apparaître des fichiers autrement non modifiables comme appartenant à votre UID/GID mappé au sein du namespace.

### Récupération des capacités

Dans le cas des user namespaces, **lorsqu'un nouveau user namespace est créé, le processus qui entre dans le namespace reçoit un ensemble complet de capabilities au sein de ce namespace**. Ces capabilities permettent au processus d'effectuer des opérations privilégiées telles que **le montage** des **filesystems**, la création de périphériques ou le changement de propriétaire de fichiers, mais **uniquement dans le contexte de son user namespace**.

Par exemple, lorsque vous avez la capability `CAP_SYS_ADMIN` dans un user namespace, vous pouvez effectuer des opérations qui exigent normalement cette capability, comme monter des filesystems, mais seulement dans le contexte de votre user namespace. Les opérations effectuées avec cette capability n'affecteront pas le système hôte ni les autres namespaces.

> [!WARNING]
> Donc, même si obtenir un nouveau processus dans un nouveau User namespace **vous rendra toutes les capabilities** (CapEff: 000001ffffffffff), vous ne pouvez en réalité **utiliser que celles liées au namespace** (par exemple mount) et pas toutes. Donc, cela seul n'est pas suffisant pour s'échapper d'un conteneur Docker.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Références

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
