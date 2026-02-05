# Espace de noms UTS

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

Un espace de noms UTS (UNIX Time-Sharing System) est une fonctionnalité du noyau Linux qui fournit une **isolation de deux identifiants système** : le **hostname** et le **NIS** (Network Information Service) nom de domaine. Cette isolation permet à chaque espace de noms UTS d'avoir **son propre hostname indépendant et nom de domaine NIS**, ce qui est particulièrement utile dans les scénarios de containerisation où chaque container doit apparaître comme un système séparé avec son propre hostname.

### Comment ça marche :

1. Lorsqu'un nouvel espace de noms UTS est créé, il démarre avec une **copie du hostname et du nom de domaine NIS de son espace parent**. Cela signifie qu'à la création, le nouvel espace de noms **partage les mêmes identifiants que son parent**. Cependant, tout changement ultérieur du hostname ou du nom de domaine NIS à l'intérieur de l'espace de noms n'affectera pas les autres espaces de noms.
2. Les processus au sein d'un espace de noms UTS **peuvent changer le hostname et le nom de domaine NIS** en utilisant les appels système `sethostname()` et `setdomainname()`, respectivement. Ces changements sont locaux à l'espace de noms et n'affectent pas les autres espaces de noms ni le système hôte.
3. Les processus peuvent se déplacer entre les espaces de noms en utilisant l'appel système `setns()` ou créer de nouveaux espaces de noms en utilisant les appels système `unshare()` ou `clone()` avec le drapeau `CLONE_NEWUTS`. Lorsqu'un processus se déplace vers un nouvel espace de noms ou en crée un, il commencera à utiliser le hostname et le nom de domaine NIS associés à cet espace de noms.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous vous assurez que le nouveau namespace de montage dispose d'une **vue précise et isolée des informations de processus propres à ce namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur survient en raison de la façon dont Linux gère les nouveaux espaces de noms PID (Process ID). Les points clés et la solution sont exposés ci‑dessous :

1. **Explication du problème** :

- Le noyau Linux permet à un processus de créer de nouveaux namespaces via l'appel système `unshare`. Toutefois, le processus qui initie la création d'un nouvel espace de noms PID (appelé processus "unshare") n'entre pas dans le nouvel namespace ; seuls ses processus enfants y entrent.
- Lancer `%unshare -p /bin/bash%` démarre `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants restent dans le namespace PID d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouveau namespace devient PID 1. Quand ce processus se termine, il déclenche le nettoyage du namespace s'il n'y a pas d'autres processus, car PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactivera alors l'allocation de PID dans cet espace de noms.

2. **Conséquence** :

- La sortie de PID 1 dans un nouveau namespace entraîne le nettoyage du flag `PIDNS_HASH_ADDING`. Cela fait échouer la fonction `alloc_pid` lors de l'attribution d'un nouveau PID au moment de créer un processus, produisant l'erreur "Cannot allocate memory".

3. **Solution**:
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option force `unshare` à fork un nouveau processus après la création du nouvel espace de noms PID.
- Exécuter `%unshare -fp /bin/bash%` garantit que la commande `unshare` elle‑même devient PID 1 dans le nouveau namespace. `/bin/bash` et ses processus enfants sont alors correctement contenus dans ce nouveau namespace, empêchant la sortie prématurée de PID 1 et permettant l'allocation normale des PID.

En veillant à ce que `unshare` s'exécute avec le flag `-f`, le nouvel espace de noms PID est correctement maintenu, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation de mémoire.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifier dans quel namespace se trouve votre processus
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
### Entrer dans un UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Abuser du partage UTS de l'hôte

Si un conteneur est lancé avec `--uts=host`, il rejoint le namespace UTS de l'hôte au lieu d'en obtenir un isolé. Avec des capacités telles que `--cap-add SYS_ADMIN`, du code dans le conteneur peut changer le hostname/NIS de l'hôte via `sethostname()`/`setdomainname()` :
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Changer le host name peut altérer les logs/alerts, perturber la découverte du cluster ou casser les configs TLS/SSH qui pin le hostname.

### Détecter les containers partageant UTS avec le host
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
