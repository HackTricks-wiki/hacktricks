# Espace de noms PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms PID contrôle la façon dont les processus sont numérotés et quels processus sont visibles. C'est pourquoi un conteneur peut avoir son propre PID 1 même s'il n'est pas une vraie machine. À l'intérieur de l'espace de noms, la charge de travail voit ce qui ressemble à un arbre de processus local. À l'extérieur de l'espace de noms, l'hôte voit toujours les vrais PIDs de l'hôte et l'ensemble du paysage des processus.

Du point de vue de la sécurité, l'espace de noms PID est important parce que la visibilité des processus est précieuse. Une fois qu'une charge de travail peut voir les processus de l'hôte, elle peut être capable d'observer les noms de service, les arguments de ligne de commande, les secrets passés dans les arguments des processus, l'état dérivé de l'environnement via `/proc`, et des cibles potentielles pour entrer dans d'autres namespaces. Si elle peut faire plus que simplement voir ces processus — par exemple envoyer des signaux ou utiliser ptrace dans les bonnes conditions — le problème devient beaucoup plus sérieux.

## Fonctionnement

Un nouvel espace de noms PID commence avec sa propre numérotation interne des processus. Le premier processus créé à l'intérieur devient PID 1 du point de vue de l'espace de noms, ce qui signifie aussi qu'il reçoit des sémantiques particulières de type init pour les enfants orphelins et le comportement des signaux. Cela explique beaucoup d'oddities liées aux processus init, au ramassage des zombies, et pourquoi de petits wrappers init sont parfois utilisés dans les conteneurs.

La leçon de sécurité importante est qu'un processus peut sembler isolé parce qu'il ne voit que son propre arbre de PID, mais cette isolation peut être délibérément levée. Docker expose cela via `--pid=host`, tandis que Kubernetes le fait via `hostPID: true`. Une fois que le conteneur rejoint l'espace de noms PID de l'hôte, la charge de travail voit directement les processus de l'hôte, et de nombreuses voies d'attaque ultérieures deviennent beaucoup plus réalistes.

## Laboratoire

Pour créer un espace de noms PID manuellement:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Le shell voit maintenant une vue de processus privée. Le `--mount-proc` flag est important car il monte une instance de procfs qui correspond au nouveau PID namespace, ce qui rend la liste des processus cohérente de l'intérieur.

Pour comparer le comportement du container :
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La différence est immédiate et facile à comprendre, ce qui fait de ce laboratoire un bon premier exercice pour les lecteurs.

## Utilisation à l'exécution

Les conteneurs normaux dans Docker, Podman, containerd et CRI-O obtiennent leur propre espace de noms PID. Les Pods Kubernetes reçoivent généralement aussi une vue PID isolée, sauf si la charge de travail demande explicitement le partage du PID de l'hôte. Les environnements LXC/Incus reposent sur la même primitive du noyau, bien que les cas d'utilisation de system-container puissent exposer des arbres de processus plus compliqués et encourager davantage de raccourcis de débogage.

La même règle s'applique partout : si le runtime choisit de ne pas isoler l'espace de noms PID, il s'agit d'une réduction délibérée de la frontière du conteneur.

## Mauvaises configurations

La mauvaise configuration canonique est le partage du PID de l'hôte. Les équipes le justifient souvent pour le débogage, la supervision ou la commodité de gestion des services, mais cela doit toujours être traité comme une exception de sécurité significative. Même si le conteneur n'a pas de primitive d'écriture immédiate sur les processus de l'hôte, la simple visibilité peut révéler beaucoup sur le système. Une fois que des capacités telles que `CAP_SYS_PTRACE` ou un accès utile à procfs sont ajoutées, le risque s'amplifie significativement.

Une autre erreur consiste à supposer que parce que la charge de travail ne peut pas tuer ou ptrace les processus de l'hôte par défaut, le partage du PID de l'hôte est donc sans danger. Cette conclusion ignore la valeur de l'énumération, la disponibilité de cibles d'entrée dans des namespaces, et la façon dont la visibilité des PID se combine avec d'autres contrôles affaiblis.

## Abus

Si l'espace de noms PID de l'hôte est partagé, un attaquant peut inspecter les processus de l'hôte, collecter les arguments des processus, identifier des services intéressants, localiser des PIDs candidats pour `nsenter`, ou combiner la visibilité des processus avec des privilèges liés à ptrace pour interférer avec la charge de travail de l'hôte ou des workloads voisins. Dans certains cas, voir simplement le bon processus de longue durée suffit à remodeler le reste du plan d'attaque.

La première étape pratique est toujours de confirmer que les processus de l'hôte sont réellement visibles:
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
Si `nsenter` est disponible et que vous disposez des privilèges suffisants, testez si un processus hôte visible peut être utilisé comme pont de namespace :
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Même lorsque l'accès est bloqué, le partage des PID de l'hôte est déjà précieux car il révèle l'organisation des services, les composants d'exécution et les processus privilégiés candidats à cibler ensuite.

La visibilité des PID de l'hôte rend aussi l'abus des descripteurs de fichiers plus réaliste. Si un processus privilégié de l'hôte ou une charge de travail voisine a un fichier ou un socket sensible ouvert, l'attaquant peut être en mesure d'inspecter `/proc/<pid>/fd/` et de réutiliser ce descripteur selon la propriété, les options de montage de procfs et le modèle de service ciblé.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ces commandes sont utiles car elles permettent de déterminer si `hidepid=1` ou `hidepid=2` réduit la visibilité inter-processus et si des descripteurs manifestement intéressants tels que des fichiers secrets ouverts, des logs ou des Unix sockets sont visibles.

### Exemple complet : host PID + `nsenter`

Le partage du host PID devient un host escape direct lorsque le processus dispose également de privilèges suffisants pour rejoindre les namespaces de l'hôte :
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si la commande réussit, le processus du container s'exécute désormais dans les namespaces mount, UTS, network, IPC et PID de l'host. L'impact est une compromission immédiate de l'host.

Même lorsque `nsenter` lui-même est absent, le même résultat peut être obtenu via le binaire de l'host si le host filesystem est monté :
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notes récentes d'exécution

Certaines attaques liées au PID namespace ne sont pas des mauvaises configurations classiques `hostPID: true`, mais des bugs d'implémentation au runtime concernant la manière dont les protections de procfs sont appliquées lors de la mise en place du container.

#### `maskedPaths` race to host procfs

Dans des versions vulnérables de `runc`, des attaquants capables de contrôler l'image du container ou la charge `runc exec` pouvaient provoquer une condition de course pendant la phase de masquage en remplaçant le `/dev/null` côté container par un lien symbolique vers un chemin procfs sensible tel que `/proc/sys/kernel/core_pattern`. Si la course réussissait, le masked-path bind mount pouvait aboutir sur la mauvaise cible et exposer des réglages procfs globaux de l'hôte au nouveau container.

Commande utile de vérification:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Ceci est important car l'impact final peut être le même qu'une exposition directe de procfs : `core_pattern` ou `sysrq-trigger` inscriptibles, suivis de host code execution ou de denial of service.

#### Namespace injection with `insject`

Les outils d'Namespace injection tels que `insject` montrent que l'interaction avec le PID-namespace n'exige pas toujours d'entrer préalablement dans le namespace cible avant la création du processus. Un helper peut s'y attacher ensuite, utiliser `setns()`, et exécuter tout en conservant la visibilité dans l'espace PID cible :
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ce type de technique importe principalement pour le débogage avancé, les outils offensifs et les workflows de post-exploitation où le contexte de namespace doit être rejoint après que le runtime a déjà initialisé la charge de travail.

### Modèles d'abus de FD connexes

Deux modèles méritent d'être explicitement signalés lorsque les PIDs de l'hôte sont visibles. Premièrement, un processus privilégié peut garder un descripteur de fichier sensible ouvert après un `execve()` parce qu'il n'a pas été marqué `O_CLOEXEC`. Deuxièmement, des services peuvent transmettre des descripteurs de fichier via des sockets Unix à l'aide de `SCM_RIGHTS`. Dans les deux cas l'objet intéressant n'est plus le pathname, mais le handle déjà ouvert qu'un processus de moindre privilège peut hériter ou recevoir.

Cela importe dans le travail sur des containers car le handle peut pointer vers `docker.sock`, un journal privilégié, un fichier secret de l'hôte, ou un autre objet de grande valeur même lorsque le chemin lui-même n'est pas directement accessible depuis le système de fichiers du container.

## Vérifications

Le but de ces commandes est de déterminer si le processus dispose d'une vue PID privée ou s'il peut déjà énumérer un ensemble de processus beaucoup plus vaste.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Qu'est-ce qui est intéressant ici :

- Si la liste des processus contient des services évidents de l'hôte, le partage des PID de l'hôte est probablement déjà en cours.
- Ne voir qu'une petite arborescence locale du container est le comportement normal ; voir `systemd`, `dockerd`, ou des daemons non liés ne l'est pas.
- Une fois que les PID de l'hôte sont visibles, même les informations de processus en lecture seule deviennent de la reconnaissance utile.

Si vous découvrez un container exécuté avec le partage des PID de l'hôte, ne le traitez pas comme une différence cosmétique. C'est un changement majeur dans ce que la charge de travail peut observer et potentiellement affecter.
{{#include ../../../../../banners/hacktricks-training.md}}
