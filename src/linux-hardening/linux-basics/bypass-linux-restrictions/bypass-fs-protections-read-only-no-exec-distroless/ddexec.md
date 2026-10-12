# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linux exécute normalement les programmes à partir de fichiers exécutables stockés sur disque ou en mémoire. Il peut identifier un exécutable par son chemin ou son descripteur de fichier ; un chemin de fichier classique n’est donc pas toujours nécessaire.<sup>[[2]](#references)</sup>

DDexec / EverythingExec utilise la mémoire d’un **processus déjà en cours d’exécution**. La page [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) traite de l’exécution à partir de fichiers anonymes ainsi que de la détection et de la collecte forensique associées ; la [présentation des contournements en mémoire](index.html#memory-bypasses) renvoie également à MemExec et Memdlopen.<sup>[[1]](#references)</sup>

Cette technique permet de **contourner des protections courantes comme le mode lecture seule, noexec, la liste blanche des noms de fichiers et la liste blanche des hash**.<sup>[[1]](#references)</sup>

## Dépendances

Le script final nécessite les outils suivants pour fonctionner. Ils doivent être accessibles sur le système que vous attaquez (par défaut, vous les trouverez partout) :

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

Si vous êtes en mesure de modifier arbitrairement la mémoire d’un processus, vous pouvez en prendre le contrôle. Cela peut servir à détourner un processus existant et à le remplacer par un autre programme. Nous pouvons y parvenir soit en utilisant l’appel système `ptrace()` (ce qui nécessite de pouvoir exécuter des appels système ou d’avoir gdb disponible sur le système), soit, plus intéressant encore, en écrivant dans `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Le fichier `/proc/$pid/mem` est une correspondance un à un avec l’intégralité de l’espace d’adressage d’un processus (_p. ex._, de `0x0000000000000000` à `0x7ffffffffffff000` sur x86-64). Cela signifie que lire ou écrire dans ce fichier à l’offset `x` revient à lire ou à modifier le contenu situé à l’adresse virtuelle `x`.

Nous devons maintenant faire face à quatre problèmes fondamentaux :

- En général, seuls root et le propriétaire du fichier peuvent le modifier.
- ASLR.
- Si nous essayons de lire ou d’écrire à une adresse qui n’est pas mappée dans l’espace d’adressage du programme, nous obtiendrons une erreur d’E/S.

Ces problèmes ont des solutions qui, bien qu’imparfaites, sont efficaces :

- La plupart des interpréteurs de shell permettent de créer des descripteurs de fichiers qui seront ensuite hérités par les processus enfants. Nous pouvons créer un fd pointant vers le fichier `mem` du shell avec des permissions en écriture... ainsi, les processus enfants qui utilisent ce fd pourront modifier la mémoire du shell.
- L’ASLR ne pose même pas problème : nous pouvons consulter le fichier `maps` du shell ou tout autre fichier de procfs afin d’obtenir des informations sur l’espace d’adressage du processus.
- Nous devons donc utiliser `lseek()` dans le fichier. Depuis le shell, c’est impossible sans utiliser le fameux `dd`.

### Plus en détail

Les étapes sont relativement simples et ne nécessitent aucune expertise particulière pour être comprises :<sup>[[1]](#references)</sup>

- Analyser le binaire que nous voulons exécuter et le chargeur pour déterminer les mappages dont ils ont besoin. Puis créer un « shell »code qui effectuera, en gros, les mêmes étapes que le noyau lors de chaque appel à `execve()` :
  - Créer les mappages en question.
  - Y lire les binaires.
  - Configurer les permissions.
  - Enfin, initialiser la pile avec les arguments du programme et y placer le vecteur auxiliaire (dont le chargeur a besoin).
  - Sauter dans le chargeur et le laisser faire le reste (charger les bibliothèques nécessaires au programme).
- Récupérer dans le fichier `syscall` l’adresse à laquelle le processus reprendra son exécution après l’appel système en cours.
- Écraser cette adresse, qui sera exécutable, avec notre shellcode (via `mem`, nous pouvons modifier des pages non inscriptibles).
- Transmettre le programme que nous voulons exécuter sur l’entrée standard du processus (il sera `read()` par ledit « shell »code).
- À ce stade, le chargeur se charge de charger les bibliothèques nécessaires au programme et d’y sauter.

**Découvrez l’outil sur** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Il existe plusieurs alternatives à `dd`, dont `tail`, qui est actuellement le programme utilisé par défaut pour effectuer `lseek()` dans le fichier `mem` (c’était la seule raison d’utiliser `dd`). Ces alternatives sont :<sup>[[1]](#references)</sup>

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

Si vous trouvez un autre seeker valide qui n'est pas implémenté dans le script, vous pouvez tout de même l'utiliser en définissant la variable `SEEKER_ARGS` :

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Bloquez ça, EDRs.

## References

- [1] [DDexec : une technique pour exécuter des fichiers binaires sans fichier et furtivement sous Linux](https://github.com/arget13/DDexec)
- [2] [execveat(2) — page de manuel Linux](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
