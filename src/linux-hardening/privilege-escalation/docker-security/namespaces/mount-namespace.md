# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Un mount namespace est une fonctionnalité du noyau Linux qui fournit une isolation des points de montage du système de fichiers vus par un groupe de processus. Chaque mount namespace a son propre ensemble de points de montage du système de fichiers, et **les modifications des points de montage dans un namespace n'affectent pas les autres namespaces**. Cela signifie que les processus s'exécutant dans différents mount namespaces peuvent avoir des vues différentes de la hiérarchie du système de fichiers.

Les mount namespaces sont particulièrement utiles dans la conteneurisation, où chaque conteneur doit avoir son propre système de fichiers et sa propre configuration, isolés des autres conteneurs et du système hôte.

### How it works:

1. Lorsqu'un nouveau mount namespace est créé, il est initialisé avec une **copie des points de montage de son namespace parent**. Cela signifie qu'à la création, le nouveau namespace partage la même vue du système de fichiers que son parent. Cependant, toute modification ultérieure des points de montage au sein du namespace n'affectera pas le parent ou d'autres namespaces.
2. Lorsqu'un processus modifie un point de montage dans son namespace, comme monter ou démonter un système de fichiers, la **modification est locale à ce namespace** et n'affecte pas les autres namespaces. Cela permet à chaque namespace d'avoir sa propre hiérarchie de système de fichiers indépendante.
3. Les processus peuvent se déplacer entre les namespaces en utilisant l'appel système `setns()`, ou créer de nouveaux namespaces en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWNS`. Lorsqu'un processus se déplace vers un nouveau namespace ou en crée un, il commencera à utiliser les points de montage associés à ce namespace.
4. **Les descripteurs de fichiers et les inodes sont partagés entre les namespaces**, ce qui signifie que si un processus dans un namespace a un descripteur de fichier ouvert pointant vers un fichier, il peut **transmettre ce descripteur de fichier** à un processus dans un autre namespace, et **les deux processus accéderont au même fichier**. Cependant, le chemin du fichier peut ne pas être le même dans les deux namespaces en raison des différences dans les points de montage.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage a une **vue précise et isolée des informations sur les processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash : fork : Impossible d'allouer de la mémoire</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur se produit en raison de la façon dont Linux gère les nouveaux namespaces PID (identifiant de processus). Les détails clés et la solution sont décrits ci-dessous :

1. **Explication du problème** :

- Le noyau Linux permet à un processus de créer de nouveaux namespaces en utilisant l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouveau namespace PID (appelé le processus "unshare") n'entre pas dans le nouveau namespace ; seuls ses processus enfants le font.
- L'exécution de `%unshare -p /bin/bash%` démarre `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants se trouvent dans le namespace PID d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouveau namespace devient PID 1. Lorsque ce processus se termine, il déclenche le nettoyage du namespace s'il n'y a pas d'autres processus, car PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactivera alors l'allocation de PID dans ce namespace.

2. **Conséquence** :

- La sortie de PID 1 dans un nouveau namespace entraîne le nettoyage du drapeau `PIDNS_HASH_ADDING`. Cela entraîne l'échec de la fonction `alloc_pid` à allouer un nouveau PID lors de la création d'un nouveau processus, produisant l'erreur "Impossible d'allouer de la mémoire".

3. **Solution** :
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option permet à `unshare` de créer un nouveau processus après avoir créé le nouveau namespace PID.
- L'exécution de `%unshare -fp /bin/bash%` garantit que la commande `unshare` elle-même devient PID 1 dans le nouveau namespace. `/bin/bash` et ses processus enfants sont alors en toute sécurité contenus dans ce nouveau namespace, empêchant la sortie prématurée de PID 1 et permettant une allocation normale de PID.

En veillant à ce que `unshare` s'exécute avec le drapeau `-f`, le nouveau namespace PID est correctement maintenu, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation de mémoire.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifiez dans quel espace de noms se trouve votre processus
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Trouver tous les espaces de noms de montage
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Entrer dans un espace de noms de montage
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Aussi, vous ne pouvez **entrer dans un autre espace de noms de processus que si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/mnt`).

Parce que de nouveaux montages ne sont accessibles qu'au sein de l'espace de noms, il est possible qu'un espace de noms contienne des informations sensibles qui ne peuvent être accessibles que depuis celui-ci.

### Monter quelque chose
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Références

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
