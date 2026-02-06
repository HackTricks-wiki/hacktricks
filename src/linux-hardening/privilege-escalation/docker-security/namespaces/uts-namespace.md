# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

A UTS (UNIX Time-Sharing System) namespace est une fonctionnalité du kernel Linux qui fournit i**solement de deux identifiants système** : le **hostname** et le **NIS** (Network Information Service) domain name. Cet isolement permet à chaque UTS namespace d'avoir son **propre hostname et NIS domain name indépendants**, ce qui est particulièrement utile dans des scénarios de containerization où chaque container doit apparaître comme un système séparé avec son propre hostname.

### Comment ça fonctionne :

1. Lorsqu'un nouveau UTS namespace est créé, il démarre avec une **copie du hostname et du NIS domain name depuis son namespace parent**. Cela signifie qu'à la création, le nouveau namespace **partage les mêmes identifiants que son parent**. Cependant, toute modification ultérieure du hostname ou du NIS domain name à l'intérieur du namespace n'affectera pas les autres namespaces.
2. Les processus à l'intérieur d'un UTS namespace **peuvent changer le hostname et le NIS domain name** en utilisant les appels système `sethostname()` et `setdomainname()`, respectivement. Ces changements sont locaux au namespace et n'affectent pas les autres namespaces ni le système hôte.
3. Les processus peuvent se déplacer entre namespaces en utilisant l'appel système `setns()` ou créer de nouveaux namespaces en utilisant les appels système `unshare()` ou `clone()` avec le flag `CLONE_NEWUTS`. Lorsqu'un processus se déplace vers un nouveau namespace ou en crée un, il commencera à utiliser le hostname et le NIS domain name associés à ce namespace.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
En montant une nouvelle instance du système de fichiers `/proc` si vous utilisez le paramètre `--mount-proc`, vous garantissez que le nouveau mount namespace a une **vue précise et isolée des informations de processus spécifiques à ce namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

Lorsque `unshare` est exécuté sans l'option `-f`, une erreur survient en raison de la façon dont Linux gère les nouveaux PID (Process ID) namespaces. Les détails clés et la solution sont exposés ci‑dessous :

1. **Explication du problème** :

- Le noyau Linux permet à un processus de créer de nouveaux namespaces en utilisant l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouveau PID namespace (désigné comme le processus "unshare") n'entre pas dans le nouveau namespace ; seuls ses processus enfants y entrent.
- L'exécution de %unshare -p /bin/bash% lance `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants restent dans le PID namespace d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouveau namespace devient PID 1. Quand ce processus se termine, il déclenche le nettoyage du namespace s'il n'y a pas d'autres processus, car PID 1 a le rôle particulier d'adopter les processus orphelins. Le noyau Linux désactivera alors l'allocation de PID dans ce namespace.

2. **Conséquence** :

- La sortie de PID 1 dans un nouveau namespace entraîne le nettoyage du drapeau `PIDNS_HASH_ADDING`. Cela fait échouer la fonction `alloc_pid` lors de l'allocation d'un nouveau PID à la création d'un processus, produisant l'erreur "Cannot allocate memory".

3. **Solution**:
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option force `unshare` à forker un nouveau processus après la création du nouveau PID namespace.
- L'exécution de %unshare -fp /bin/bash% garantit que la commande `unshare` elle‑même devient PID 1 dans le nouveau namespace. `/bin/bash` et ses processus enfants sont alors correctement contenus dans ce nouveau namespace, évitant la sortie prématurée de PID 1 et permettant une allocation normale des PID.

En vous assurant que `unshare` s'exécute avec le flag `-f`, le nouveau PID namespace est correctement maintenu, permettant à `/bin/bash` et à ses sous‑processus de fonctionner sans rencontrer l'erreur d'allocation mémoire.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifiez dans quel namespace se trouve votre processus
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Trouver tous les UTS namespaces
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

Si un conteneur est démarré avec `--uts=host`, il rejoint l'espace de noms UTS de l'hôte au lieu d'en obtenir un isolé. Avec des capacités telles que `--cap-add SYS_ADMIN`, du code dans le conteneur peut changer le nom d'hôte/NIS de l'hôte via `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Changer le nom d'hôte peut altérer les logs/alertes, perturber la découverte du cluster ou casser les configurations TLS/SSH qui verrouillent le nom d'hôte.

### Détecter les conteneurs partageant l'UTS avec l'hôte
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
