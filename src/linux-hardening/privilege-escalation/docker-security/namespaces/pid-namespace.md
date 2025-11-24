# Espace de noms PID

{{#include ../../../../banners/hacktricks-training.md}}

## Informations de base

L'espace de noms PID (identifiant de processus) est une fonctionnalité du noyau Linux qui fournit une isolation des processus en permettant à un groupe de processus d'avoir son propre jeu de PIDs uniques, séparé des PIDs dans d'autres espaces de noms. Ceci est particulièrement utile en containerisation, où l'isolation des processus est essentielle pour la sécurité et la gestion des ressources.

Lorsqu'un nouvel espace de noms PID est créé, le premier processus dans cet espace se voit attribuer le PID 1. Ce processus devient le "init" process du nouvel espace de noms et est responsable de la gestion des autres processus au sein de l'espace de noms. Chaque processus créé ensuite dans l'espace de noms aura un PID unique dans cet espace, et ces PIDs seront indépendants des PIDs dans les autres espaces de noms.

Du point de vue d'un processus dans un espace de noms PID, il ne peut voir que les autres processus du même espace de noms. Il n'est pas au courant des processus dans d'autres espaces de noms, et il ne peut pas interagir avec eux en utilisant les outils classiques de gestion de processus (par ex., `kill`, `wait`, etc.). Cela fournit un niveau d'isolation qui aide à empêcher les processus d'interférer les uns avec les autres.

### Comment ça fonctionne :

1. Lorsqu'un nouveau processus est créé (par ex., en utilisant l'appel système `clone()`), le processus peut être affecté à un espace de noms PID nouveau ou existant. **Si un nouvel espace de noms est créé, le processus devient le "init" process de cet espace de noms**.
2. Le **noyau** maintient une **correspondance entre les PIDs dans le nouvel espace de noms et les PIDs correspondants** dans l'espace de noms parent (c'est-à-dire l'espace de noms à partir duquel le nouvel espace a été créé). Cette correspondance **permet au noyau de traduire les PIDs lorsque nécessaire**, par exemple lors de l'envoi de signaux entre des processus dans des espaces de noms différents.
3. **Les processus au sein d'un espace de noms PID ne peuvent voir et interagir qu'avec d'autres processus du même espace de noms**. Ils ne sont pas au courant des processus dans d'autres espaces de noms, et leurs PIDs sont uniques au sein de leur espace de noms.
4. Lorsque **un espace de noms PID est détruit** (par ex., lorsque le "init" process de l'espace de noms se termine), **tous les processus de cet espace de noms sont terminés**. Cela garantit que toutes les ressources associées à l'espace de noms sont correctement nettoyées.

## Laboratoire :

### Créer différents espaces de noms

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- Le noyau Linux permet à un processus de créer de nouveaux namespaces via l'appel système `unshare`. Cependant, le processus qui initie la création d'un nouveau namespace PID (appelé le processus "unshare") n'entre pas dans le nouveau namespace ; seuls ses processus enfants le font.
- Lancer %unshare -p /bin/bash% démarre `/bin/bash` dans le même processus que `unshare`. Par conséquent, `/bin/bash` et ses processus enfants sont dans le namespace PID d'origine.
- Le premier processus enfant de `/bin/bash` dans le nouveau namespace devient PID 1. Lorsque ce processus se termine, il déclenche le nettoyage du namespace s'il n'y a pas d'autres processus, puisque PID 1 a le rôle spécial d'adopter les processus orphelins. Le noyau Linux désactivera alors l'allocation de PID dans ce namespace.

2. **Consequence**:

- La sortie de PID 1 dans un nouveau namespace entraîne le nettoyage du flag `PIDNS_HASH_ADDING`. Cela fait que la fonction `alloc_pid` échoue à allouer un nouveau PID lors de la création d'un nouveau processus, produisant l'erreur "Cannot allocate memory".

3. **Solution**:
- Le problème peut être résolu en utilisant l'option `-f` avec `unshare`. Cette option fait que `unshare` fork un nouveau processus après avoir créé le nouveau namespace PID.
- Lancer %unshare -fp /bin/bash% garantit que la commande `unshare` elle-même devient PID 1 dans le nouveau namespace. `/bin/bash` et ses processus enfants sont alors correctement contenus dans ce nouveau namespace, empêchant la sortie prématurée de PID 1 et permettant une allocation normale des PID.

En veillant à ce que `unshare` s'exécute avec le flag `-f`, le nouveau namespace PID est correctement maintenu, permettant à `/bin/bash` et à ses sous-processus de fonctionner sans rencontrer l'erreur d'allocation mémoire.

</details>

By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Vérifier dans quel namespace se trouve votre processus
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Trouver tous les PID namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Notez que l'utilisateur root du PID namespace initial (par défaut) peut voir tous les processus, y compris ceux qui se trouvent dans de nouveaux PID namespaces, c'est pourquoi nous pouvons voir tous les PID namespaces.

### Entrer dans un PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

Also, you can only **enter in another process PID namespace if you are root**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/pid`)

## Notes récentes d'exploitation

### CVE-2025-31133: abus de `maskedPaths` pour atteindre les PIDs de l'hôte

runc ≤1.2.7 allowed attackers that control container images or `runc exec` workloads to replace the container-side `/dev/null` just before the runtime masked sensitive procfs entries. When the race succeeds, `/dev/null` can be turned into a symlink pointing at any host path (for example `/proc/sys/kernel/core_pattern`), so the new container PID namespace suddenly inherits read/write access to host-global procfs knobs even though it never left its own namespace. Once `core_pattern` or `/proc/sysrq-trigger` is writable, generating a coredump or triggering SysRq yields code execution or denial of service in the host PID namespace.

Workflow pratique :

1. Construisez un OCI bundle dont le rootfs remplace `/dev/null` par un lien vers le chemin de l'hôte souhaité (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Démarrez le container avant le correctif pour que runc monte par bind la cible procfs de l'hôte par-dessus le lien.
3. À l'intérieur du namespace du container, écrivez dans le fichier procfs désormais exposé (par ex., pointez `core_pattern` vers un helper de reverse shell) et faites planter n'importe quel processus pour forcer le kernel de l'hôte à exécuter votre helper dans le contexte PID 1.

Vous pouvez rapidement auditer si un bundle masque les bons fichiers avant de le démarrer :
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Si le runtime manque une entrée de masquage attendue (ou la saute parce que `/dev/null` a disparu), considérez le container comme ayant potentiellement une visibilité sur les PID de l'hôte.

### Injection de namespace avec `insject`

Le `insject` de NCC Group se charge comme une payload LD_PRELOAD qui s'accroche à une étape tardive du programme cible (par défaut `main`) et effectue une série d'appels `setns()` après `execve()`. Cela vous permet de vous attacher depuis l'hôte (ou un autre container) dans le PID namespace de la victime *après* que son runtime se soit initialisé, en préservant sa vue `/proc/<pid>` sans avoir à copier des binaires dans le filesystem du container. Parce que `insject` peut différer la jonction du PID namespace jusqu'à ce qu'il fork, vous pouvez garder un thread dans le namespace hôte (avec CAP_SYS_PTRACE) tandis qu'un autre thread s'exécute dans le PID namespace cible, créant des primitives puissantes de debugging ou offensives.

Exemple d'utilisation :
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Points clés à retenir lors de l'abus ou de la défense contre namespace injection :

- Utilisez `-S/--strict` pour forcer `insject` à arrêter si des threads existent déjà ou si les namespace joins échouent ; sinon vous risquez de laisser des threads partiellement migrés chevauchant les espaces PID du host et du container.
- N'attachez jamais d'outils qui détiennent encore des writable host file descriptors sauf si vous rejoignez aussi le mount namespace — sinon tout processus à l'intérieur du PID namespace peut ptrace votre helper et réutiliser ces descriptors pour altérer les host resources.

## Références

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
