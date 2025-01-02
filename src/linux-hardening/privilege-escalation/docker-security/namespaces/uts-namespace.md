# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

Un namespace UTS (UNIX Time-Sharing System) est une fonctionnalité du noyau Linux qui fournit l'**isolement de deux identifiants système** : le **nom d'hôte** et le **nom de domaine NIS** (Network Information Service). Cet isolement permet à chaque namespace UTS d'avoir son **propre nom d'hôte et son nom de domaine NIS indépendants**, ce qui est particulièrement utile dans les scénarios de conteneurisation où chaque conteneur doit apparaître comme un système séparé avec son propre nom d'hôte.

### Comment ça fonctionne :

1. Lorsqu'un nouveau namespace UTS est créé, il commence avec une **copie du nom d'hôte et du nom de domaine NIS de son namespace parent**. Cela signifie qu'à la création, le nouveau namespace **partage les mêmes identifiants que son parent**. Cependant, tout changement ultérieur du nom d'hôte ou du nom de domaine NIS au sein du namespace n'affectera pas les autres namespaces.
2. Les processus au sein d'un namespace UTS **peuvent changer le nom d'hôte et le nom de domaine NIS** en utilisant les appels système `sethostname()` et `setdomainname()`, respectivement. Ces changements sont locaux au namespace et n'affectent pas les autres namespaces ou le système hôte.
3. Les processus peuvent se déplacer entre les namespaces en utilisant l'appel système `setns()` ou créer de nouveaux namespaces en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWUTS`. Lorsqu'un processus se déplace vers un nouveau namespace ou en crée un, il commencera à utiliser le nom d'hôte et le nom de domaine NIS associés à ce namespace.

## Laboratoire :

### Créer différents Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage a une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

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
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Trouver tous les espaces de noms UTS
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrer dans un namespace UTS
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
