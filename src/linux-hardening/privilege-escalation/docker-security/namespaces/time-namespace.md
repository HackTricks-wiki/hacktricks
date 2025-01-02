# Espace de Temps

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de Base

L'espace de temps dans Linux permet des décalages par espace de noms pour les horloges monotoniques et de démarrage du système. Il est couramment utilisé dans les conteneurs Linux pour changer la date/heure à l'intérieur d'un conteneur et ajuster les horloges après la restauration d'un point de contrôle ou d'un instantané.

## Laboratoire :

### Créer différents Espaces de Noms

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage a une **vue précise et isolée des informations sur les processus spécifiques à ce namespace**.

<details>

<summary>Erreur : bash : fork : Impossible d'allouer de la mémoire</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur est rencontrée en raison de la façon dont Linux gère les nouveaux namespaces PID (Process ID). Les détails clés et la solution sont décrits ci-dessous :

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
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Trouver tous les espaces de noms temporels
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrez dans un espace de noms temporel
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
