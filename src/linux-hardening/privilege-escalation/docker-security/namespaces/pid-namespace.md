# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

Le namespace PID (Process IDentifier) est une fonctionnalité du noyau Linux qui fournit une isolation des processus en permettant à un groupe de processus d'avoir leur propre ensemble de PIDs uniques, séparés des PIDs dans d'autres namespaces. Cela est particulièrement utile dans la conteneurisation, où l'isolation des processus est essentielle pour la sécurité et la gestion des ressources.

Lorsqu'un nouveau namespace PID est créé, le premier processus dans ce namespace se voit attribuer le PID 1. Ce processus devient le processus "init" du nouveau namespace et est responsable de la gestion des autres processus au sein du namespace. Chaque processus subséquent créé dans le namespace aura un PID unique dans ce namespace, et ces PIDs seront indépendants des PIDs dans d'autres namespaces.

Du point de vue d'un processus au sein d'un namespace PID, il ne peut voir que les autres processus dans le même namespace. Il n'est pas conscient des processus dans d'autres namespaces et ne peut pas interagir avec eux en utilisant des outils de gestion de processus traditionnels (par exemple, `kill`, `wait`, etc.). Cela fournit un niveau d'isolation qui aide à prévenir les interférences entre les processus.

### Comment ça fonctionne :

1. Lorsqu'un nouveau processus est créé (par exemple, en utilisant l'appel système `clone()`), le processus peut être assigné à un nouveau namespace PID ou à un namespace existant. **Si un nouveau namespace est créé, le processus devient le processus "init" de ce namespace**.
2. Le **noyau** maintient une **correspondance entre les PIDs dans le nouveau namespace et les PIDs correspondants** dans le namespace parent (c'est-à-dire le namespace à partir duquel le nouveau namespace a été créé). Cette correspondance **permet au noyau de traduire les PIDs lorsque cela est nécessaire**, par exemple lors de l'envoi de signaux entre des processus dans différents namespaces.
3. **Les processus au sein d'un namespace PID ne peuvent voir et interagir qu'avec d'autres processus dans le même namespace**. Ils ne sont pas conscients des processus dans d'autres namespaces, et leurs PIDs sont uniques dans leur namespace.
4. Lorsqu'un **namespace PID est détruit** (par exemple, lorsque le processus "init" du namespace se termine), **tous les processus au sein de ce namespace sont terminés**. Cela garantit que toutes les ressources associées au namespace sont correctement nettoyées.

## Laboratoire :

### Créer différents Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Erreur : bash : fork : Impossible d'allouer de la mémoire</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur se produit en raison de la façon dont Linux gère les nouveaux espaces de noms PID (Process ID). Les détails clés et la solution sont décrits ci-dessous :

1. **Explication du problème** :

- Le noyau Linux permet à un processus de créer de nouveaux espaces de noms en utilisant l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouvel espace de noms PID (appelé le processus "unshare") n'entre pas dans le nouvel espace de noms ; seuls ses processus enfants le font.
- L'exécution de `%unshare -p /bin/bash%` démarre `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants se trouvent dans l'espace de noms PID d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouvel espace de noms devient PID 1. Lorsque ce processus se termine, il déclenche le nettoyage de l'espace de noms s'il n'y a pas d'autres processus, car PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactivera alors l'allocation de PID dans cet espace de noms.

2. **Conséquence** :

- La sortie de PID 1 dans un nouvel espace de noms entraîne le nettoyage du drapeau `PIDNS_HASH_ADDING`. Cela entraîne l'échec de la fonction `alloc_pid` à allouer un nouveau PID lors de la création d'un nouveau processus, produisant l'erreur "Impossible d'allouer de la mémoire".

3. **Solution** :
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option permet à `unshare` de créer un nouveau processus après avoir créé le nouvel espace de noms PID.
- L'exécution de `%unshare -fp /bin/bash%` garantit que la commande `unshare` elle-même devient PID 1 dans le nouvel espace de noms. `/bin/bash` et ses processus enfants sont alors en toute sécurité contenus dans ce nouvel espace de noms, empêchant la sortie prématurée de PID 1 et permettant une allocation normale de PID.

En veillant à ce que `unshare` s'exécute avec le drapeau `-f`, le nouvel espace de noms PID est correctement maintenu, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation de mémoire.

</details>

En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage a une **vue précise et isolée des informations sur les processus spécifiques à cet espace de noms**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifiez dans quel espace de noms se trouve votre processus
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Trouver tous les espaces de noms PID
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Notez que l'utilisateur root du namespace PID initial (par défaut) peut voir tous les processus, même ceux dans de nouveaux espaces de noms PID, c'est pourquoi nous pouvons voir tous les espaces de noms PID.

### Entrer dans un espace de noms PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Lorsque vous entrez dans un espace de noms PID depuis l'espace de noms par défaut, vous pourrez toujours voir tous les processus. Et le processus de cet espace de noms PID pourra voir le nouveau bash dans l'espace de noms PID.

De plus, vous ne pouvez **entrer dans un autre espace de noms PID de processus que si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/pid`)

## Références

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
