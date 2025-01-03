# DDexec / EverythingExec

{{#include ../../../banners/hacktricks-training.md}}

## Contexte

Dans Linux, pour exécuter un programme, il doit exister en tant que fichier, il doit être accessible d'une manière ou d'une autre à travers la hiérarchie du système de fichiers (c'est juste ainsi que fonctionne `execve()`). Ce fichier peut résider sur le disque ou dans la RAM (tmpfs, memfd) mais vous avez besoin d'un chemin de fichier. Cela a rendu très facile de contrôler ce qui est exécuté sur un système Linux, cela facilite la détection des menaces et des outils de l'attaquant ou de les empêcher d'essayer d'exécuter quoi que ce soit de leur part (_e. g._ ne pas permettre aux utilisateurs non privilégiés de placer des fichiers exécutables n'importe où).

Mais cette technique est là pour changer tout cela. Si vous ne pouvez pas démarrer le processus que vous voulez... **alors vous détournez un déjà existant**.

Cette technique vous permet de **contourner des techniques de protection courantes telles que lecture seule, noexec, liste blanche de noms de fichiers, liste blanche de hachages...**

## Dépendances

Le script final dépend des outils suivants pour fonctionner, ils doivent être accessibles dans le système que vous attaquez (par défaut, vous les trouverez tous partout) :
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## La technique

Si vous êtes capable de modifier arbitrairement la mémoire d'un processus, alors vous pouvez le prendre en charge. Cela peut être utilisé pour détourner un processus déjà existant et le remplacer par un autre programme. Nous pouvons y parvenir soit en utilisant l'appel système `ptrace()` (ce qui nécessite d'avoir la capacité d'exécuter des appels système ou d'avoir gdb disponible sur le système), soit, plus intéressant, en écrivant dans `/proc/$pid/mem`.

Le fichier `/proc/$pid/mem` est une correspondance un-à-un de l'ensemble de l'espace d'adresses d'un processus (_e. g._ de `0x0000000000000000` à `0x7ffffffffffff000` en x86-64). Cela signifie que lire ou écrire dans ce fichier à un décalage `x` est équivalent à lire ou modifier le contenu à l'adresse virtuelle `x`.

Maintenant, nous avons quatre problèmes de base à affronter :

- En général, seul root et le propriétaire du programme du fichier peuvent le modifier.
- ASLR.
- Si nous essayons de lire ou d'écrire à une adresse non mappée dans l'espace d'adresses du programme, nous obtiendrons une erreur d'E/S.

Ces problèmes ont des solutions qui, bien qu'elles ne soient pas parfaites, sont bonnes :

- La plupart des interprètes de shell permettent la création de descripteurs de fichiers qui seront ensuite hérités par les processus enfants. Nous pouvons créer un fd pointant vers le fichier `mem` du shell avec des permissions d'écriture... donc les processus enfants qui utilisent ce fd pourront modifier la mémoire du shell.
- ASLR n'est même pas un problème, nous pouvons vérifier le fichier `maps` du shell ou tout autre fichier du procfs afin d'obtenir des informations sur l'espace d'adresses du processus.
- Donc, nous devons `lseek()` sur le fichier. Depuis le shell, cela ne peut pas être fait à moins d'utiliser le fameux `dd`.

### Plus en détail

Les étapes sont relativement faciles et ne nécessitent aucune expertise particulière pour les comprendre :

- Analyser le binaire que nous voulons exécuter et le chargeur pour découvrir quels mappages ils nécessitent. Ensuite, créer un "shell"code qui effectuera, de manière générale, les mêmes étapes que le noyau lors de chaque appel à `execve()` :
- Créer lesdits mappages.
- Lire les binaires dans ceux-ci.
- Configurer les permissions.
- Enfin, initialiser la pile avec les arguments pour le programme et placer le vecteur auxiliaire (nécessaire au chargeur).
- Sauter dans le chargeur et le laisser faire le reste (charger les bibliothèques nécessaires au programme).
- Obtenir à partir du fichier `syscall` l'adresse à laquelle le processus retournera après l'appel système qu'il exécute.
- Écraser cet endroit, qui sera exécutable, avec notre shellcode (à travers `mem`, nous pouvons modifier des pages non écrites).
- Passer le programme que nous voulons exécuter à l'entrée standard du processus (sera `read()` par ledit "shell"code).
- À ce stade, il appartient au chargeur de charger les bibliothèques nécessaires pour notre programme et d'y sauter.

**Découvrez l'outil sur** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Il existe plusieurs alternatives à `dd`, dont l'une, `tail`, est actuellement le programme par défaut utilisé pour `lseek()` à travers le fichier `mem` (ce qui était le seul but d'utiliser `dd`). Ces alternatives sont :
```bash
tail
hexdump
cmp
xxd
```
En définissant la variable `SEEKER`, vous pouvez changer le seeker utilisé, _e. g._ :
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Si vous trouvez un autre seeker valide non implémenté dans le script, vous pouvez toujours l'utiliser en définissant la variable `SEEKER_ARGS` :
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloquez cela, EDRs.

## Références

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../banners/hacktricks-training.md}}
