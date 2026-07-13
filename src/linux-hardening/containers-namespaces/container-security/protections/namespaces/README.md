# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces are the kernel feature that makes a container feel like "its own machine" even though it is really just a host process tree. They do not create a new kernel and they do not virtualize everything, but they do let the kernel present different views of selected resources to different groups of processes. That is the core of the container illusion: the workload sees a filesystem, process table, network stack, hostname, IPC resources, and user/group identity model that appear local, even though the underlying system is shared.

This is why namespaces are the first concept most people encounter when they learn how containers work. At the same time, they are one of the most commonly misunderstood concepts because readers often assume that "has namespaces" means "is safely isolated". In reality, a namespace only isolates the specific class of resources it was designed for. A process can have a private PID namespace and still be dangerous because it has a writable host bind mount. It can have a private network namespace and still be dangerous because it retains `CAP_SYS_ADMIN` and runs without seccomp. Namespaces are foundational, but they are only one layer in the final boundary.

## Namespace Types

Linux containers commonly rely on several namespace types at the same time. The **mount namespace** gives the process a separate mount table and therefore a controlled filesystem view. The **PID namespace** changes process visibility and numbering so the workload sees its own process tree. The **network namespace** isolates interfaces, routes, sockets, and firewall state. The **IPC namespace** isolates SysV IPC and POSIX message queues. The **UTS namespace** isolates hostname and NIS domain name. The **user namespace** remaps user and group IDs so that root inside the container does not necessarily mean root on the host. The **cgroup namespace** virtualizes the visible cgroup hierarchy, and the **time namespace** virtualizes selected clocks in newer kernels.

Each of these namespaces solves a different problem. This is why practical container security analysis often comes down to checking **which namespaces are isolated** and **which ones have been deliberately shared with the host**.

## Host Namespace Sharing

Many container breakouts do not begin with a kernel vulnerability. They begin with an operator deliberately weakening the isolation model. The examples `--pid=host`, `--network=host`, and `--userns=host` are **Docker/Podman-style CLI flags** used here as concrete examples of host namespace sharing. Other runtimes express the same idea differently. In Kubernetes the equivalents usually appear as Pod settings such as `hostPID: true`, `hostNetwork: true`, or `hostIPC: true`. In lower-level runtime stacks such as containerd or CRI-O, the same behavior is often reached through the generated OCI runtime configuration rather than through a user-facing flag with the same name. In all of these cases, the result is similar: the workload no longer receives the default isolated namespace view.

This is why namespace reviews should never stop at "the process is in some namespace". The important question is whether the namespace is private to the container, shared with sibling containers, or joined directly to the host. In Kubernetes the same idea appears with flags such as `hostPID`, `hostNetwork`, and `hostIPC`. The names change between platforms, but the risk pattern is the same: a shared host namespace makes the container's remaining privileges and reachable host state much more meaningful.

## Inspection

The simplest overview is:

```bash
ls -l /proc/self/ns
```

Each entry is a symbolic link with an inode-like identifier. If two processes point to the same namespace identifier, they are in the same namespace of that type. That makes `/proc` a very useful place to compare the current process with other interesting processes on the machine.

These quick commands are often enough to start:

```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```

From there, the next step is to compare the container process with host or neighboring processes and determine whether a namespace is actually private or not.

### Enumerating Namespace Instances From The Host

When you already have host access and want to understand how many distinct namespaces of a given type exist, `/proc` gives a quick inventory:

```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```

If you want to find which processes belong to one specific namespace identifier, switch from `readlink` to `ls -l` and grep for the target namespace number:

```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```

These commands are useful because they let you answer whether a host is running one isolated workload, many isolated workloads, or a mixture of shared and private namespace instances.

### Entering A Target Namespace

When the caller has sufficient privilege, `nsenter` is the standard way to join another process's namespace:

```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```

The point of listing these forms together is not that every assessment needs all of them, but that namespace-specific post-exploitation often becomes much easier once the operator knows the exact entry syntax instead of remembering only the all-namespaces form.

## Pages

The following pages explain each namespace in more detail:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

As you read them, keep two ideas in mind. First, each namespace isolates only one kind of view. Second, a private namespace is useful only if the rest of the privilege model still makes that isolation meaningful.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

The main portability rule is simple: the **concept** of host namespace sharing is common across runtimes, but the **syntax** is runtime-specific.
{{#include ../../../../../banners/hacktricks-training.md}}
