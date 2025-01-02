# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

Un cgroup namespace est une fonctionnalité du noyau Linux qui fournit **l'isolation des hiérarchies de cgroup pour les processus s'exécutant dans un namespace**. Les cgroups, abréviation de **control groups**, sont une fonctionnalité du noyau qui permet d'organiser les processus en groupes hiérarchiques pour gérer et appliquer **des limites sur les ressources système** comme le CPU, la mémoire et l'I/O.

Bien que les cgroup namespaces ne soient pas un type de namespace séparé comme les autres que nous avons discutés précédemment (PID, mount, réseau, etc.), ils sont liés au concept d'isolation de namespace. **Les cgroup namespaces virtualisent la vue de la hiérarchie cgroup**, de sorte que les processus s'exécutant dans un cgroup namespace ont une vue différente de la hiérarchie par rapport aux processus s'exécutant sur l'hôte ou dans d'autres namespaces.

### Comment ça fonctionne :

1. Lorsqu'un nouveau cgroup namespace est créé, **il commence avec une vue de la hiérarchie cgroup basée sur le cgroup du processus créateur**. Cela signifie que les processus s'exécutant dans le nouveau cgroup namespace ne verront qu'un sous-ensemble de l'ensemble de la hiérarchie cgroup, limité à l'arborescence cgroup enracinée au cgroup du processus créateur.
2. Les processus au sein d'un cgroup namespace **verront leur propre cgroup comme la racine de la hiérarchie**. Cela signifie que, du point de vue des processus à l'intérieur du namespace, leur propre cgroup apparaît comme la racine, et ils ne peuvent pas voir ou accéder aux cgroups en dehors de leur propre sous-arborescence.
3. Les cgroup namespaces ne fournissent pas directement d'isolation des ressources ; **ils ne fournissent que l'isolation de la vue de la hiérarchie cgroup**. **Le contrôle et l'isolation des ressources sont toujours appliqués par les sous-systèmes cgroup** (par exemple, cpu, mémoire, etc.) eux-mêmes.

Pour plus d'informations sur les CGroups, consultez :

{{#ref}}
../cgroups.md
{{#endref}}

## Laboratoire :

### Créer différents Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage a une **vue précise et isolée des informations sur les processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash : fork : Impossible d'allouer de la mémoire</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur est rencontrée en raison de la façon dont Linux gère les nouveaux namespaces PID (identifiant de processus). Les détails clés et la solution sont décrits ci-dessous :

1. **Explication du problème** :

- Le noyau Linux permet à un processus de créer de nouveaux namespaces en utilisant l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouveau namespace PID (appelé le processus "unshare") n'entre pas dans le nouveau namespace ; seuls ses processus enfants le font.
- L'exécution de `%unshare -p /bin/bash%` démarre `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants se trouvent dans l'espace de noms PID d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouveau namespace devient PID 1. Lorsque ce processus se termine, il déclenche le nettoyage du namespace s'il n'y a pas d'autres processus, car PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactivera alors l'allocation de PID dans ce namespace.

2. **Conséquence** :

- La sortie de PID 1 dans un nouveau namespace entraîne le nettoyage du drapeau `PIDNS_HASH_ADDING`. Cela entraîne l'échec de la fonction `alloc_pid` à allouer un nouveau PID lors de la création d'un nouveau processus, produisant l'erreur "Impossible d'allouer de la mémoire".

3. **Solution** :
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option permet à `unshare` de forker un nouveau processus après avoir créé le nouveau namespace PID.
- L'exécution de `%unshare -fp /bin/bash%` garantit que la commande `unshare` elle-même devient PID 1 dans le nouveau namespace. `/bin/bash` et ses processus enfants sont alors en toute sécurité contenus dans ce nouveau namespace, empêchant la sortie prématurée de PID 1 et permettant une allocation normale de PID.

En veillant à ce que `unshare` s'exécute avec le drapeau `-f`, le nouveau namespace PID est correctement maintenu, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation de mémoire.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Vérifiez dans quel espace de noms se trouve votre processus
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Trouver tous les espaces de noms CGroup
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrez dans un espace de noms CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Aussi, vous ne pouvez **entrer dans un autre espace de noms de processus que si vous êtes root**. Et vous **ne pouvez pas** **entrer** dans un autre espace de noms **sans un descripteur** pointant vers celui-ci (comme `/proc/self/ns/cgroup`).

## Références

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
