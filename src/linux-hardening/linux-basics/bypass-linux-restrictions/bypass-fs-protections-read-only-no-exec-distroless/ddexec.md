# DDexec / EverythingExec

## Context

Sous Linux, pour exécuter un programme, celui-ci doit exister en tant que fichier et être accessible d'une manière ou d'une autre via la hiérarchie du système de fichiers (c'est simplement ainsi que fonctionne `execve()`). Ce fichier peut se trouver sur le disque ou en RAM (tmpfs, memfd), mais vous avez besoin d'un chemin de fichier. Cela a rendu très facile le contrôle de ce qui est exécuté sur un système Linux, la détection des threats et des tools de l'attaquant, ou encore la prévention de toute tentative d'exécution de leur part (_p. ex._ en empêchant les utilisateurs non privilégiés de placer des fichiers exécutables n'importe où).

Mais cette technique est là pour changer tout cela. Si vous ne pouvez pas démarrer le processus que vous voulez... **alors vous en détournez un qui existe déjà**.

Cette technique permet de **bypasser des techniques de protection courantes telles que read-only, noexec, file-name whitelisting et hash whitelisting**.<sup>[[1]](#references)</sup>

## Dependencies

Le script final dépend des tools suivants pour fonctionner ; ils doivent être accessibles sur le système que vous attaquez (par défaut, vous les trouverez partout) :
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

Si vous êtes capable de modifier arbitrairement la mémoire d’un processus, vous pouvez en prendre le contrôle. Cela peut être utilisé pour détourner un processus existant et le remplacer par un autre programme. Nous pouvons y parvenir soit en utilisant l’appel système `ptrace()` (ce qui nécessite de pouvoir exécuter des appels système ou de disposer de gdb sur le système), soit, de manière plus intéressante, en écrivant dans `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Le fichier `/proc/$pid/mem` est une correspondance un-à-un de l’espace d’adressage entier d’un processus (_p. ex._ de `0x0000000000000000` à `0x7ffffffffffff000` sur x86-64). Cela signifie que lire ou écrire dans ce fichier à un offset `x` revient respectivement à lire ou modifier le contenu situé à l’adresse virtuelle `x`.

Nous devons maintenant faire face à quatre problèmes fondamentaux :

- En général, seuls root et le propriétaire du programme peuvent le modifier.
- ASLR.
- Si nous essayons de lire ou d’écrire à une adresse qui n’est pas mappée dans l’espace d’adressage du programme, nous obtenons une erreur d’E/S.

Ces problèmes ont des solutions qui, bien qu’elles ne soient pas parfaites, sont efficaces :

- La plupart des interpréteurs de shell permettent de créer des descripteurs de fichiers qui seront ensuite hérités par les processus enfants. Nous pouvons créer un fd pointant vers le fichier `mem` du shell avec des permissions d’écriture... ainsi, les processus enfants qui utilisent ce fd pourront modifier la mémoire du shell.
- ASLR n’est même pas un problème : nous pouvons consulter le fichier `maps` du shell ou tout autre fichier de procfs afin d’obtenir des informations sur l’espace d’adressage du processus.
- Nous devons donc effectuer un `lseek()` dans le fichier. Depuis le shell, cela ne peut pas être fait sans utiliser le fameux `dd`.

### Plus en détail

Les étapes sont relativement simples et ne nécessitent aucune expertise particulière pour être comprises :<sup>[[1]](#references)</sup>

- Analyser le binaire que nous voulons exécuter ainsi que le loader afin de déterminer les mappings dont ils ont besoin. Puis créer un « shell »code qui effectuera, de manière générale, les mêmes étapes que celles réalisées par le kernel lors de chaque appel à `execve()` :
- Créer les mappings en question.
- Lire les binaires dans ceux-ci.
- Configurer les permissions.
- Enfin, initialiser la stack avec les arguments du programme et placer le vecteur auxiliaire (nécessaire au loader).
- Sauter dans le loader et le laisser effectuer le reste (charger les bibliothèques nécessaires au programme).
- Obtenir à partir du fichier `syscall` l’adresse à laquelle le processus retournera après l’appel système qu’il est en train d’exécuter.
- Écraser cet emplacement, qui sera exécutable, avec notre shellcode (avec `mem`, nous pouvons modifier des pages non inscriptibles).
- Transmettre le programme que nous voulons exécuter à l’entrée standard du processus (il sera `read()` par ledit « shell »code).
- À ce stade, il revient au loader de charger les bibliothèques nécessaires à notre programme et d’y accéder.

**Consultez l’outil sur** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Il existe plusieurs alternatives à `dd`, dont `tail`, qui est actuellement le programme utilisé par défaut pour effectuer le `lseek()` dans le fichier `mem` (ce qui était l’unique raison d’utiliser `dd`). Ces alternatives sont :<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
En définissant la variable `SEEKER`, vous pouvez modifier le seeker utilisé, _p. ex._ :
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Si vous trouvez un autre seeker valide qui n’est pas implémenté dans le script, vous pouvez tout de même l’utiliser en définissant la variable `SEEKER_ARGS` :
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloquez ceci, EDR.

## References

- [1] [DDexec : Une technique pour exécuter des fichiers binaires sans fichier et furtivement sous Linux](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
